"""Narrow test-only captured fixtures for I0/S1 reserve regressions.

The normal launcher runs each original TestCase with its setup and cleanups.
This helper grants no scientific, custody, execution or release authority.
"""
from functools import wraps
from contextlib import contextmanager
import hashlib
import importlib
import io
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scientist_one.resources import ResourceConfig
from scientist_one.security import canonical_json_bytes

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_MARKER = ".prepared-resource-fixture"
_SELECTION_MARKER = ".prepared-resource-case.json"
_WRAPPER_MODULE = "tests.test_prepared_resource_case"
_WRAPPER_ID = _WRAPPER_MODULE + ".PreparedResourceCaseTests.test_original_case"
_NESTED_PROTOCOL = "SCIENTIST_ONE_PREPARED_RESOURCE_CASE_V1="
_WORKER_PROTOCOL = "SCIENTIST_ONE_CAPTURED_TEST_MODULE_V1="
_RESERVE_CLASS = "tests.test_resource_backed_simulated_reserve.ResourceBackedSimulatedReserveTests"
_BOUNDARY_ID = (
    "tests.test_resource_backed_simulated_reserve_boundary."
    "ResourceBackedReserveScientificBoundaryTests."
    "test_real_resource_backed_reserve_cannot_authorize_scientific_family"
)
_RESERVE_METHODS = frozenset((
    "test_real_initialization_then_first_reservation_has_exact_parent_and_seal",
    "test_completed_replay_is_zero_delta_and_native_I_lower_replay_is_finite",
    "test_explicit_none_does_not_upgrade_or_discover_I",
    "test_window_two_refuses_before_new_or_existing_orphan_return",
    "test_wrong_initialization_identity_and_run_refuse",
    "test_deleted_external_initialization_does_not_reinitialize",
    "test_advanced_external_without_local_projection_refuses",
    "test_exact_S_orphan_recovers_no_new_external_head_or_artifact",
    "test_orphan_with_deleted_external_head_remains_unresolved",
    "test_orphan_with_advanced_external_head_remains_unresolved",
    "test_historical_S_read_is_not_external_currentness_or_new_allocation",
    "test_I_correction_is_not_ignored_by_later_S_read",
    "test_outer_I_aliases_do_not_receive_native_I_exemption",
    "test_v2_schema_only_alias_and_copied_event_refuse",
    "test_substituted_fourth_parent_does_not_rebind_initialization",
    "test_postpublication_external_advance_is_detected_and_evidence_retained",
    "test_native_v2_event_copy_cannot_consume_another_slot",
    "test_malformed_external_chain_has_public_reservation_refusal_type",
    "test_owned_protocol_and_contract_cannot_be_substituted",
    "test_v2_aliases_still_trigger_negative_scientific_guard",
    "test_completed_existing_return_rechecks_late_external_advance",
))
_ALLOWED_IDS = frozenset(_RESERVE_CLASS + "." + name for name in _RESERVE_METHODS) | {_BOUNDARY_ID}
_BASE_MODULES = {
    "tests", "tests.test_resource_prepared_cases",
    "tests.test_resource_backed_simulated_reserve", "tests.test_simulated_resource",
    "tests.test_scientific_design", "tests.test_protocol_contract_crosswalk",
    "tests.test_scientific_core", _WRAPPER_MODULE,
}
_BOUNDARY_MODULES = {
    "tests.test_resource_backed_simulated_reserve_boundary",
    "tests.test_simulated_reserve_scientific_boundary",
    "tests.test_scientific_execution_authority", "tests.test_simulated_reserve",
}
_INITIALIZATION_CLASS = "tests.test_simulated_resource.SimulatedResourceTests"
_INITIALIZATION_METHODS = frozenset((
    'test_actual_initialization_fixed_budget_and_native_external_checkpoint',
    'test_exact_idempotence_preserves_native_file_identity',
    'test_inventory_real_producer_idempotence',
    'test_alternate_run_and_paths_refuse_without_authority',
    'test_actual_legacy_ten_cannot_reset_to_forty',
    'test_native_external_capacity_never_creates_seventeenth',
    'test_source_and_config_drift_refuse_before_external_advancement',
    'test_real_non_point_four_config_refuses',
    'test_wrong_source_digest_refuses',
    'test_external_write_failure_before_and_after_native_commit',
    'test_artifact_failure_recovers_original_external_state',
    'test_event_failure_recovers_exact_artifact_suffix',
    'test_post_append_failure_is_idempotently_readable',
    'test_prior_event_zero_slot_refuses_before_external_write',
    'test_native_record_alias_refuses_before_external_write',
    'test_orphan_recovery_refuses_new_registry_work',
    'test_recovery_source_drift_retains_original_time',
    'test_completed_extra_event_refuses_but_historical_selected_pair_replays',
    'test_complete_record_alias_refuses',
    'test_original_state_cannot_be_rebound_to_other_protocol',
    'test_native_text_selectors_reject_subclass_overrides',
    'test_actual_configuration_capacity_rejects_before_external_publication',
    'test_actual_inventory_partial_write_recovers_original_first_record',
    'test_actual_initialization_correction_refuses',
    'test_actual_inventory_native_metadata_substitution_refuses',
    'test_actual_extra_artifact_write_is_detected_by_final_pair',
    'test_actual_extra_ledger_write_is_detected_by_final_pair',
    'test_actual_external_extra_stage_is_detected_without_refund',
    'test_raw_external_byte_substitution_refuses_without_rewrite',
    'test_inventory_marker_command_cannot_be_reused_by_renamed_initial_record',
    'test_matching_prose_does_not_select_authority',
    'test_historical_config_replay_does_not_read_later_live_bytes',
    'test_renamed_inventory_schema_alias_refuses_before_external_write',
    'test_valid_caller_input_hashes_do_not_override_native_source_provenance',
    'test_protocol_fraction_must_match_actual_fixed_config_before_publication',
    'test_historical_outer_selection_consumes_each_initialization_alias',
    'test_last_live_inventory_read_cannot_hide_native_source_metadata_drift',
    'test_last_external_read_cannot_hide_native_source_metadata_drift',
    'test_selected_history_allows_later_unrelated_work_without_granting_it_authority',
    'test_selected_initialization_marker_containers_and_reference_events_refuse',
))
_INITIALIZATION_IDS = frozenset(_INITIALIZATION_CLASS + "." + name
                                for name in _INITIALIZATION_METHODS)
_ALLOWED_IDS = _ALLOWED_IDS | _INITIALIZATION_IDS
_INITIALIZATION_MODULES = {
    "tests", "tests.test_resource_prepared_cases", "tests.test_simulated_resource",
    "tests.test_scientific_design", "tests.test_protocol_contract_crosswalk",
    "tests.test_scientific_core", _WRAPPER_MODULE,
}
_REPEATED = {
    "test_real_non_point_four_config_refuses": ("fraction_03",),
    "test_actual_configuration_capacity_rejects_before_external_publication": ("large_config",),
    "test_actual_inventory_partial_write_recovers_original_first_record": ("freeze_false",),
    "test_valid_caller_input_hashes_do_not_override_native_source_provenance": ("freeze_false",),
    "test_protocol_fraction_must_match_actual_fixed_config_before_publication": ("protocol_03",),
    "test_historical_outer_selection_consumes_each_initialization_alias": (
        "nested-null-event", "native-event-copy", "schema-record"),
    "test_selected_initialization_marker_containers_and_reference_events_refuse": (
        "schema-list", "schema-map", "typed-map", "origin-only", "command-only",
        "event-prefix-only", "event-typed-list", "event-record-reference"),
}
_DRIFT_SOURCE = "test_source_and_config_drift_refuse_before_external_advancement"
_DRIFT_ORPHAN = "test_recovery_source_drift_retains_original_time"
_HISTORICAL_CONFIG = "test_historical_config_replay_does_not_read_later_live_bytes"
_INERT_SOURCE = "src/scientist_one/bookkeeping_fixture.py"
_INERT_BYTES = b"# Bookkeeping inventory, not executed science.\n"
_CONFIG = "configs/resource_limits.json"
_LATER_CONFIG = b'{"validity_reserve_fraction":0.3}\n'
_CHARGE_CLASS = "tests.test_simulated_confirmatory_charge.SimulatedConfirmatoryChargeTests"
_CHARGE_METHODS = frozenset((
    'test_native_first_charge_is_eight_units_and_exact_external_ledger_join',
    'test_completed_replay_never_restores_recharges_or_observes_time',
    'test_public_S_consumes_only_completed_Q_and_private_replay_is_finite',
    'test_external_failure_before_write_leaves_original_sources',
    'test_external_only_interruption_recovers_exact_state_without_new_charge',
    'test_artifact_prewrite_interruption_recovers_external_only',
    'test_record_only_interruption_is_unreadable_then_recovers_exact_suffix',
    'test_artifact_postwrite_interruption_retains_exact_orphan',
    'test_event_postwrite_interruption_is_completed_idempotency',
    'test_actual_S_record_without_event_cannot_be_charged',
    'test_wrong_identity_run_and_legacy_or_window_two_requests_refuse',
    'test_live_config_source_and_reservation_correction_refuse',
    'test_completed_requires_live_source_but_historical_Q_remains_accounting',
    'test_preflight_capacity_refuses_before_external_advance',
    'test_prospective_event_failure_is_before_external_advance',
    'test_outer_I_S_Q_corrections_are_never_refunds',
    'test_renamed_Q_schema_and_shared_profile_aliases_refuse',
    'test_malformed_Q_marker_refuses',
    'test_copied_Q_event_does_not_consume_another_slot',
    'test_substituted_Q_metadata_is_not_full_owned_exemption',
    'test_external_Q_deleted_or_later_head_cannot_be_recharged',
    'test_external_Q_noncanonical_bytes_fail_native_reader_without_local_delta',
    'test_orphan_recovery_refuses_after_extra_source',
    'test_event_only_Q_alias_refuses_before_external_advance',
    'test_oversized_renamed_Q_schema_aliases_are_unresolved',
    'test_oversized_renamed_I_schema_aliases_are_unresolved',
    'test_actual_contract_successor_refuses_new_charge',
    'test_direct_historical_I_census_is_bounded_and_allows_small_unrelated_notes',
    'test_complete_Q_historical_reader_is_not_permission_after_later_note',
    'test_invalid_membership_debit_is_refused_before_external_advance',
    'test_external_read_after_final_live_inventory_detects_late_external_advance',
    'test_paired_source_drift_after_current_contract_read_refuses',
    'test_current_Q_external_head_drift_after_event_is_detected_without_refund',
    'test_final_live_inventory_read_detects_source_drift_after_read',
))
_CHARGE_IDS = frozenset(_CHARGE_CLASS + "." + name for name in _CHARGE_METHODS)
_ALLOWED_IDS = _ALLOWED_IDS | _CHARGE_IDS
_PHASED_IDS = _INITIALIZATION_IDS | _CHARGE_IDS
_CHARGE_REPEATED = {
    "test_actual_S_record_without_event_cannot_be_charged": ("S_orphan",),
    "test_outer_I_S_Q_corrections_are_never_refunds": ("I", "S", "Q"),
    "test_renamed_Q_schema_and_shared_profile_aliases_refuse": ("marker_0", "marker_1", "marker_2"),
    "test_oversized_renamed_Q_schema_aliases_are_unresolved": ("well_formed", "malformed"),
    "test_oversized_renamed_I_schema_aliases_are_unresolved": ("well_formed", "malformed"),
    "test_direct_historical_I_census_is_bounded_and_allows_small_unrelated_notes": (
        "inert-above", "alias-above", "inert-at-bound"),
}
_CHARGE_SOURCE = "test_live_config_source_and_reservation_correction_refuse"
_CHARGE_COMPLETED = "test_completed_requires_live_source_but_historical_Q_remains_accounting"
_OBSERVATION_CLASS = "tests.test_simulated_observation.SimulatedObservationTests"
_OBSERVATION_METHODS = frozenset((
    'test_T_preflight_reserves_known_files_and_bounded_observation_before_external_advance',
    'test_actual_native_positive_whole_flow_and_exact_accounting_repeat',
    'test_completed_idempotency_never_releases_recharges_or_observes_clock',
    'test_clean_seal_before_receipt_failure_can_finish_once',
    'test_exact_preparation_record_orphan_recovers_event_only',
    'test_native_wrong_reason_refuses_before_started_or_release',
    'test_native_wrong_validity_snapshot_refuses_before_started',
    'test_native_wrong_started_resource_reference_refuses_before_append',
    'test_native_before_release_failure_retains_started_and_never_retries',
    'test_native_after_release_failure_retains_pending_and_never_retries',
    'test_native_before_terminal_failure_never_retries',
    'test_native_after_terminal_failure_recovers_without_original_guard_claim',
    'test_real_native_terminal_without_J_is_observation_only_recovery',
    'test_J_record_only_orphan_recovers_exact_event_without_new_capture',
    'test_J_event_postwrite_failure_is_completed_zero_delta',
    'test_passive_S_and_historical_Q_consume_full_completed_owner',
    'test_extra_renamed_observation_alias_is_not_skipped',
    'test_corrected_started_refuses_without_refund',
    'test_current_source_drift_refuses_before_new_attempt',
    'test_later_external_head_refuses_before_new_attempt',
    'test_capacity_refuses_before_native_seal',
    'test_native_noncanonical_journal_bytes_refuse_observation',
    'test_observation_orphan_after_source_delta_cannot_recover',
    'test_duplicate_native_requester_policy_normalization_is_not_J_authority',
    'test_bool_native_release_count_normalization_is_not_J_authority',
    'test_native_result_hash_is_not_membership_recomputation',
    'test_native_release_requester_must_belong_to_exact_policy',
    'test_failed_native_terminal_is_retained_and_never_retried',
    'test_final_live_inventory_external_drift_is_detected_before_J_event',
    'test_live_current_contract_source_pair_drift_refuses_before_started',
    'test_current_resource_configuration_drift_refuses_observation',
    'test_actual_current_contract_successor_refuses_attempt',
    'test_generic_recovery_must_refuse_new_profile_namespace',
    'test_generic_recovery_before_preparation_denies_without_registry',
    'test_generic_recovery_actual_run_under_alternate_path_denies',
    'test_generic_recovery_expected_run_denies_unrelated_malformed_path',
    'test_generic_recovery_canonical_malformed_first_event_does_not_quarantine',
    'test_generic_recovery_canonical_truncated_tail_is_never_repaired',
    'test_receipt_clock_before_actual_SEAL_must_not_publish_unowned_receipt',
    'test_native_SEAL_clock_before_Q_must_not_leave_irrecoverable_SEAL',
    'test_actual_run_tree_rollback_to_completed_Q_cannot_release_same_units_twice',
    'test_T_external_before_failure_does_not_consume_attempt',
    'test_T_external_after_failure_burns_attempt_without_local_record',
    'test_T_artifact_before_failure_burns_attempt',
    'test_T_artifact_after_failure_burns_record_orphan',
    'test_T_event_before_failure_burns_record_orphan',
    'test_T_event_after_failure_never_manufactures_started_on_restart',
    'test_STARTED_before_failure_leaves_external_attempt_consumed',
    'test_STARTED_after_failure_never_retries_native_release',
    'test_started_before_release_and_run_tree_rollback_still_burns_attempt',
    'test_owner_first_seal_clock_before_Q_refuses_before_provider_storage',
    'test_exact_digest_locators_refuse_subclasses_bool_and_nonhex_before_and_after_J',
    'test_T_correction_is_not_attempt_refund_or_observation_authority',
    'test_renamed_T_alias_is_not_passive_permission',
    'test_J_orphan_completes_at_exact_record_event_caps_after_wall_budget',
    'test_fresh_J_disk_margin_includes_exact_artifact_metadata',
    'test_preparation_attempt_J_aliases_refuse_before_allocation_only_S_publication',
    'test_preparation_attempt_J_aliases_before_I_refuse_before_resource_backed_S_publication',
    'test_later_schema_words_in_untyped_prose_do_not_select_authority',
    'test_constructor_created_empty_journal_can_finish_one_preparation',
    'test_native_after_SEAL_interruption_can_finish_exact_preparation',
    'test_native_partial_SEAL_interruption_is_retained_and_refused',
    'test_bare_observation_event_prefixes_refuse_before_allocation_only_S_publication',
))
_OBSERVATION_IDS = frozenset(_OBSERVATION_CLASS + "." + name for name in _OBSERVATION_METHODS)
_ALLOWED_IDS = _ALLOWED_IDS | _OBSERVATION_IDS
_PHASED_IDS = _PHASED_IDS | _OBSERVATION_IDS
_OBSERVATION_MODULES = _INITIALIZATION_MODULES | {
    "tests.test_simulated_observation", "tests.test_simulated_reserve",
}
_OBSERVATION_SOURCE = "test_current_source_drift_refuses_before_new_attempt"
_OBSERVATION_MATRIX = "test_preparation_attempt_J_aliases_before_I_refuse_before_resource_backed_S_publication"
_OBSERVATION_CONFIG = "test_current_resource_configuration_drift_refuses_observation"
_OBSERVATION_VARIANTS = tuple(prefix + "-" + form for prefix in ("P", "T", "J")
                              for form in ("renamed", "malformed", "metadata"))
_OBSERVATION_OWNER_SOURCE = "src/scientist_one/holdout.py"
_OBSERVATION_READBACK = "SCIENTIST_ONE_PREPARED_OBSERVATION_READBACK_V1="
_OBSERVED_CLASSES = {
    'tests.test_observed_contract_v2.ObservedContractV2Tests': frozenset(('test_actual_J_A_C_P_sequence_derives_exposure_without_confirmation', 'test_explicit_empty_null_list_duplicate_or_non_native_selector_never_downgrades', 'test_post_observation_parent_rewrite_and_backdated_child_refuse', 'test_posthoc_secondary_addition_positive_and_preplanned_addition_negative', 'test_completed_history_after_append_uses_sealed_J_not_live_current_inputs', 'test_completed_retry_cannot_omit_or_change_observation_selection', 'test_later_correction_to_each_native_dependency_refuses_selected_outer_replay', 'test_v2_codec_requires_exact_schema_and_non_evidentiary_observation', 'test_later_renamed_slot_alias_refuses_but_ordinary_prose_reference_does_not', 'test_null_amendment_event_key_is_not_an_unrelated_later_reference')),
    'tests.test_observed_contract_v2_adversarial.ObservedContractV2AdversarialTests': frozenset(('test_renamed_unknown_payload_version_targeting_same_slot_refuses', 'test_renamed_unknown_artifact_version_targeting_same_slot_refuses', 'test_mapping_publication_key_with_only_same_J_reference_refuses', 'test_exhausted_disk_reserve_refuses_before_A_C_event_writes', 'test_empty_mapping_key_cannot_hide_sibling_same_J_publication_alias', 'test_exhausted_artifact_budget_refuses_before_A_C_event_writes', 'test_empty_mapping_cannot_hide_event_prefix_and_owned_J_reference')),
    'tests.test_observed_contract_v2_budget.ObservedContractV2BudgetTests': frozenset(('test_metadata_bytes_are_reserved_before_first_A_write', 'test_budget_loss_before_locked_publication_is_rechecked_without_writes', 'test_A_C_orphan_completes_only_event_after_work_wall_budget_expired', 'test_native_resource_contention_and_capacity_errors_are_typed_A_refusals')),
    'tests.test_observed_contract_v2_orphans.ObservedContractV2OrphanTests': frozenset(('test_a_only_v2_orphan_recovers_exactly_and_is_idempotent', 'test_a_plus_c_v2_orphan_recovers_exactly_and_is_idempotent', 'test_v2_orphan_refuses_competing_source_event_and_child_metadata', 'test_v2_orphan_refuses_actual_native_journal_inode_drift', 'test_completed_v2_replay_ignores_unrelated_later_registry_append')),
    'tests.test_observed_amendment.ObservedAmendmentTests': frozenset(('test_default_amendment_after_actual_J_never_publishes_unseen', 'test_default_amendment_after_run_rollback_cannot_ignore_external_attempt', 'test_preobservation_Q_amendment_keeps_existing_v1_wire', 'test_completed_v1_replay_uses_sealed_population_not_current_external_tail', 'test_current_amendment_serializes_native_attempt_before_candidate_publication', 'test_pre_I_absent_external_storage_keeps_default_amendment', 'test_post_Q_absent_or_wrong_kind_external_storage_refuses', 'test_default_v1_refuses_renamed_null_malformed_and_metadata_attempt_aliases', 'test_unsealed_history_does_not_read_later_record_only_attempt_alias', 'test_untyped_marker_prose_and_large_unrelated_data_do_not_change_v1')),
    'tests.test_observed_amendment_orphans.OrphanGuardTests': frozenset(('test_a_only_native_registry_orphan_recovers_without_repeat_charge', 'test_a_plus_c_native_registry_orphan_recovers_without_repeat_charge', 'test_a_only_orphan_after_retained_t_refuses_without_mutation', 'test_a_plus_c_orphan_after_retained_t_refuses_without_mutation')),
}
_OBSERVED_IDS = frozenset(cls + "." + name for cls, names in _OBSERVED_CLASSES.items() for name in names)
_ALLOWED_IDS = _ALLOWED_IDS | _OBSERVED_IDS
_PHASED_IDS = _PHASED_IDS | _OBSERVED_IDS
_OBSERVED_BASE = "tests.test_observed_contract_v2.ObservedContractV2Tests"
_OBSERVED_ORPHAN_MATRIX = ("tests.test_observed_contract_v2_orphans.ObservedContractV2OrphanTests."
                         "test_v2_orphan_refuses_competing_source_event_and_child_metadata")
_OBSERVED_COMPONENT_ID = ("tests.test_observed_amendment.ObservedAmendmentTests."
                          "test_pre_I_absent_external_storage_keeps_default_amendment")
_OBSERVED_VARIANTS = ("source", "event", "orphan-metadata")
_OBSERVED_BINDING = "SCIENTIST_ONE_PREPARED_OBSERVED_BINDING_V1="
_OBSERVED_COMPONENT = "SCIENTIST_ONE_PREPARED_OBSERVED_COMPONENT_V1="

_SECOND_CLASSES = {
    'tests.test_observed_second_reserve_current.ObservedSecondReserveTests': frozenset(('test_actual_J_A_P_S2_disjoint_members_with_no_new_debit_or_release', 'test_completed_replay_and_retry_are_pure_historical', 'test_exact_selectors_wrong_ancestors_and_third_window_refuse', 'test_actual_best_of_n_A2_P2_is_not_supported_S2', 'test_interruption_before_artifact_has_no_allocation_delta', 'test_interruption_after_actual_artifact_recovers_exact_orphan', 'test_interruption_before_event_retains_record_and_can_finish_once', 'test_fresh_native_readers_complete_exact_record_only_orphan_once', 'test_interruption_after_actual_event_is_completed_historical_retry', 'test_orphan_refuses_unknown_source_delta_without_reassignment', 'test_event_only_slot_refuses_before_publication_and_lower_public_S_read', 'test_global_count_and_ledger_byte_caps_refuse_before_artifact', 'test_real_disk_scalar_margin_includes_new_native_metadata', 'test_orphan_event_only_capacity_needs_no_new_metadata_or_experiment', 'test_renamed_v3_alias_before_publication_refuses_closed_source', 'test_unknown_or_renamed_outer_after_S2_refuses_both_public_readers', 'test_later_dependency_correction_refuses_outer_not_sealed_history', 'test_live_configuration_source_external_and_custody_drift_refuse_new_S2', 'test_real_late_registry_CAS_drift_refuses_before_S2_artifact', 'test_actual_replaced_native_journal_inode_refuses_new_S2', 'test_postwrite_custody_drift_refuses_return_but_preserves_allocation', 'test_post_static_registry_append_fails_final_paired_CAS_with_allocation_retained', 'test_new_regression_S_binding_consumer_rejects_invalid_entries', 'test_new_regression_pre_I_extra_source_refuses_without_publication', 'test_new_regression_late_S2_added_input_refuses_with_allocation_retained')),
    'tests.test_observed_second_reserve_current.ObservedSecondReserveMarkerTests': frozenset(('test_v3_metadata_only_markers_refuse_before_legacy_I_or_S_publication',)),
}
_SECOND_IDS = frozenset(c + '.' + n for c, names in _SECOND_CLASSES.items() for n in names)
_SECOND_DRIFT = 'tests.test_observed_second_reserve_current.ObservedSecondReserveTests.test_live_configuration_source_external_and_custody_drift_refuse_new_S2'
_SECOND_MARKER = 'tests.test_observed_second_reserve_current.ObservedSecondReserveMarkerTests.test_v3_metadata_only_markers_refuse_before_legacy_I_or_S_publication'
_SECOND_CONSUMER = 'tests.test_observed_second_reserve_current.ObservedSecondReserveTests.test_new_regression_S_binding_consumer_rejects_invalid_entries'
_SECOND_PRODUCER = 'tests.test_observed_second_reserve_current.ObservedSecondReserveTests.test_new_regression_pre_I_extra_source_refuses_without_publication'
_SECOND_LATE = 'tests.test_observed_second_reserve_current.ObservedSecondReserveTests.test_new_regression_late_S2_added_input_refuses_with_allocation_retained'
_SECOND_PRE_I = frozenset((_SECOND_CONSUMER, _SECOND_PRODUCER))
_SECOND_NEW = _SECOND_PRE_I | {_SECOND_LATE}
_ALLOWED_IDS = _ALLOWED_IDS | _SECOND_IDS
_PHASED_IDS = _PHASED_IDS | _SECOND_IDS
_SECOND_REPORT = 'SCIENTIST_ONE_PREPARED_SECOND26_CASE_V1='
_SECOND_TRANSITION = 'SCIENTIST_ONE_PREPARED_SECOND26_TRANSITION_V1='
_SECOND_MAPPING = 'SCIENTIST_ONE_PREPARED_SECOND26_MAPPING_V1='

_ACTIVE = None


def _selection(test_id):
    if test_id not in _ALLOWED_IDS:
        raise AssertionError("unknown prepared resource case")
    return test_id.rsplit(".", 2)


def _modules(test_id):
    _selection(test_id)
    if test_id in _SECOND_IDS:
        return _OBSERVATION_MODULES | {'tests.test_observed_second_reserve_current', 'tests.test_observed_contract_v2', 'tests.test_resource_backed_simulated_reserve'}
    if test_id in _OBSERVED_IDS:
        return _observed_modules(test_id)
    if test_id in _OBSERVATION_IDS:
        return _OBSERVATION_MODULES
    if test_id in _CHARGE_IDS:
        return _BASE_MODULES | {"tests.test_simulated_confirmatory_charge"}
    if test_id in _INITIALIZATION_IDS:
        return _INITIALIZATION_MODULES
    return _BASE_MODULES | (_BOUNDARY_MODULES if test_id == _BOUNDARY_ID else set())


def _module_path(name):
    return "tests/__init__.py" if name == "tests" else name.replace(".", "/") + ".py"


def prepared_resource_case(method):
    """Dispatch original outer IDs; explicit phases cover refactored cases."""
    @wraps(method)
    def dispatched(self):
        _selection(self.id())
        if _ACTIVE is None:
            if self.id() in _SECOND_IDS:
                _run_second_case(self.id())
            elif self.id() in _OBSERVED_IDS:
                _run_observed_case(self.id())
            elif self.id() in _OBSERVATION_IDS:
                _run_observation_case(self.id())
            elif self.id() in _CHARGE_IDS:
                _run_charge_case(self.id())
            elif self.id() in _INITIALIZATION_IDS:
                _run_initialization_case(self.id())
            else:
                _run_prepared_child(self.id())
        else:
            if self.id() != _ACTIVE["test_id"]:
                raise AssertionError("child attempted another original test body")
            if _ACTIVE.get("phase") != "default_setup":
                method(self)
    return dispatched


def prepared_reserve_tests(cls):
    if cls.__module__ + "." + cls.__name__ != _RESERVE_CLASS:
        raise AssertionError("prepared reserve decorator used by another class")
    discovered = {name for name in vars(cls) if name.startswith("test_")}
    if discovered != _RESERVE_METHODS:
        raise AssertionError("prepared reserve method inventory changed")
    original_setup = cls.setUp

    @wraps(original_setup)
    def setup(self):
        # Unselected helper instances (normally methodName='runTest') retain
        # their original behavior; only selected parent tests defer setup.
        if _ACTIVE is not None or self.id() not in _ALLOWED_IDS:
            original_setup(self)

    cls.setUp = setup
    for name in _RESERVE_METHODS:
        setattr(cls, name, prepared_resource_case(getattr(cls, name)))
    return cls


def prepared_initialization_root(case, *, config, freeze, protocol_fraction):
    """Supply an existing physical root only to one accepted child fixture.

    Outside this narrow dispatcher the original initialization helper is
    unchanged. The guard is accidental-test-misuse protection, not authority.
    """
    if _ACTIVE is None:
        return None
    if _observed_active() and _ACTIVE.get("component_case") is case:
        return _uninventoried_component_root(case, config=config, freeze=freeze,
                                             protocol_fraction=protocol_fraction)
    expected_config, expected_freeze, expected_fraction = _prepare_options(_ACTIVE.get("phase"), _ACTIVE["test_id"])
    if (type(case).__module__ != "tests.test_simulated_resource"
            or type(case).__name__ != "SimulatedResourceTests"
            or type(config) is not type(expected_config) or config != expected_config
            or freeze is not expected_freeze
            or type(protocol_fraction) is not type(expected_fraction)
            or protocol_fraction != expected_fraction
            or _ACTIVE["initializations"] != 0):
        raise AssertionError("prepared resource child requires its one exact initialization")
    root = _ACTIVE["root"]
    if root != Path.cwd().resolve(strict=True) or root != _PROJECT_ROOT:
        raise AssertionError("prepared fixture differs from captured cwd")
    _ACTIVE["initializations"] += 1
    return root


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
            or path.relative_to(root).as_posix() in {_MARKER, _SELECTION_MARKER}
        )
    }


def _prepare(root, test_id, phase=None):
    _selection(test_id)
    root.mkdir()
    for directory in ("src/scientist_one", "scripts", "tests", "configs",
                      "fixtures/calibration", "reports"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for source in (_PROJECT_ROOT / "src/scientist_one").glob("*.py"):
        shutil.copyfile(source, root / "src/scientist_one" / source.name)
    shutil.copyfile(_PROJECT_ROOT / "scripts/scientist_one_cli.py",
                    root / "scripts/scientist_one_cli.py")
    for name in _modules(test_id) - {_WRAPPER_MODULE}:
        relative = _module_path(name)
        shutil.copyfile(_PROJECT_ROOT / relative, root / relative)
    calibration = "fixtures/calibration/calibration_cases.json"
    shutil.copyfile(_PROJECT_ROOT / calibration, root / calibration)
    (root / "configs/resource_limits.json").write_bytes(
        canonical_json_bytes((_prepare_options(phase, test_id)[0] or ResourceConfig()).to_dict()) + b"\n"
    )
    if test_id in _PHASED_IDS:
        if (root / _INERT_SOURCE).exists():
            raise AssertionError("inert fixture would overwrite an installed source")
        (root / _INERT_SOURCE).write_bytes(_INERT_BYTES)
    (root / _MARKER).write_text("prepared-root-fixture-20260920\n", encoding="utf-8")
    (root / _SELECTION_MARKER).write_text(
        json.dumps(_selection_data(test_id, phase), sort_keys=True), encoding="utf-8"
    )
    (root / _module_path(_WRAPPER_MODULE)).write_text(
        "import unittest\n"
        "from tests.test_resource_prepared_cases import run_original_case\n\n"
        "class PreparedResourceCaseTests(unittest.TestCase):\n"
        "    def test_original_case(self):\n"
        f"        run_original_case({test_id!r})\n", encoding="utf-8",
    )
    generated = {_MARKER, _SELECTION_MARKER, "configs/resource_limits.json",
                 _module_path(_WRAPPER_MODULE)}
    if test_id in _PHASED_IDS:
        generated.add(_INERT_SOURCE)
    for relative, identity in _snapshot(root).items():
        path = root / relative
        if path.is_symlink() or path.stat().st_nlink != 1:
            raise AssertionError("prepared input is not a unique regular file")
        if relative not in generated and identity[0] != (_PROJECT_ROOT / relative).read_bytes():
            raise AssertionError("prepared copy differs from original input")


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
        if test_id in _PHASED_IDS:
            expected = expected | {"phase", "request_data"}
        schema = "prepared-resource-case/v1"
    else:
        expected = common | {"module_name", "module_sha256", "elapsed_seconds",
                             "loaded_test_modules", "project_source_attestation",
                             "test_source_attestation"}
        schema = "captured-test-module/v1"
    if set(value) != expected or value["schema_version"] != schema:
        raise AssertionError("prepared child report schema mismatch")


def run_original_case(test_id):
    """Run one original case or explicitly mapped refactored lifecycle phase."""
    global _ACTIVE
    module_name, class_name, method = _selection(test_id)
    root = Path.cwd().resolve(strict=True)
    selection = json.loads((root / _SELECTION_MARKER).read_text(encoding="utf-8"))
    phase = selection.get("phase")
    request = selection.get("request_data")
    resume = test_id in _PHASED_IDS and _is_resume(test_id, phase)
    if selection != _selection_data(test_id, phase, request):
        raise AssertionError("unrecognized prepared selection data")
    if (_ACTIVE is not None or root != _PROJECT_ROOT or root.name != "ScientistOne"
            or not root.parent.name.startswith("prepared-resource-child-")
            or root.parent.parent != Path(tempfile.gettempdir()).resolve()
            or (not resume and ((root / "runs").exists()
                or (root / ".scientist-one-build/resource-authority").exists()))
            or (resume and not (root / "runs").is_dir())):
        raise AssertionError("original case requires its owned prepared child or explicit continuation")
    _ACTIVE = {"root": root, "test_id": test_id, "initializations": 0,
               "phase": phase, "request_data": request, "emitted_request": None}
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
            "schema_version": "prepared-resource-case/v1", "test_ids": [case.id()],
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
        if test_id in _PHASED_IDS:
            report.update(phase=phase, request_data=_ACTIVE["emitted_request"])
        print(_NESTED_PROTOCOL + json.dumps(report, sort_keys=True), flush=True)
        if _ACTIVE["initializations"] != (0 if resume else 1):
            raise AssertionError("original phase preparation count differs from its mapping")
        _require_success(report, test_id=test_id, nested=True)
        if test_id in _OBSERVED_IDS:
            _finish_observed_case(test_id)
        if test_id in _SECOND_IDS:
            _finish_second_case(test_id)
    finally:
        _ACTIVE = None


def _text(value):
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else (value or "")


def _run_prepared_child(test_id):
    with tempfile.TemporaryDirectory(prefix="prepared-resource-child-") as directory:
        root = Path(directory) / "ScientistOne"
        _prepare(root, test_id)
        return _capture_prepared_child(root, test_id)


def _capture_prepared_child(root, test_id, phase=None):
    before = _snapshot(root)
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "scripts/scientist_one_cli.py",
             "__captured-test-module__", _WRAPPER_MODULE], cwd=root,
            check=False, capture_output=True, text=True, timeout=180,
        )
    except subprocess.TimeoutExpired as exc:
        print("SCIENTIST_ONE_PREPARED_RESOURCE_RAW_V1=" + json.dumps({
            "test_id": test_id, "phase": phase, "timed_out": True,
            "stdout": _text(exc.stdout), "stderr": _text(exc.stderr),
        }, sort_keys=True), flush=True)
        raise AssertionError("captured resource child timed out") from exc
    # Retain raw nested reports before validation or cleanup, including every
    # child failure. This is test evidence, never scientific authority.
    print("SCIENTIST_ONE_PREPARED_RESOURCE_RAW_V1=" + json.dumps({
        "test_id": test_id, "phase": phase, "timed_out": False, "returncode": completed.returncode,
        "stdout": completed.stdout, "stderr": completed.stderr,
    }, sort_keys=True), flush=True)
    after = _snapshot(root)
    _verify_input_delta(test_id, phase, before, after)
    if completed.returncode != 0 or completed.stderr:
        raise AssertionError("captured resource child failed; raw reports retained above")
    lines = completed.stdout.splitlines()
    reports = []
    for protocol in (_NESTED_PROTOCOL, _WORKER_PROTOCOL):
        matches = [line[len(protocol):] for line in lines if line.startswith(protocol)]
        if len(matches) != 1:
            raise AssertionError(f"child must emit exactly one {protocol}: {completed.stdout}")
        reports.append(json.loads(matches[0]))
    nested, worker = reports
    _require_success(nested, test_id=test_id, nested=True)
    if test_id in _PHASED_IDS and nested["phase"] != phase:
        raise AssertionError("nested original phase differs")
    _require_success(worker, test_id=_WRAPPER_ID, nested=False)
    if (worker["module_name"] != _WRAPPER_MODULE
            or worker["module_sha256"] != hashlib.sha256(before[_module_path(_WRAPPER_MODULE)][0]).hexdigest()
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
    expected_modules = _modules(test_id)
    if (type(loaded) is not list or len(loaded) != len(expected_modules)
            or any(type(e) is not dict or set(e) != {"module_name", "sha256"} for e in loaded)
            or {e["module_name"] for e in loaded} != expected_modules):
        raise AssertionError("child loaded test closure differs")
    for entry in loaded:
        if entry["sha256"] != hashlib.sha256(before[_module_path(entry["module_name"])][0]).hexdigest():
            raise AssertionError("child loaded test identity differs")
    if test_id in _SECOND_IDS:
        _verify_second_case(root, test_id, phase, nested, lines)
    if test_id in _OBSERVED_IDS:
        _verify_observed_binding(root, test_id, phase, nested, lines)
    if test_id in _OBSERVATION_IDS:
        _verify_observation_readback(root, test_id, phase, nested, lines)
    print("SCIENTIST_ONE_PREPARED_RESOURCE_VALIDATION_V1=" + json.dumps({
        "schema_version": "prepared-resource-validation/v1",
        "test_id": test_id, "phase": phase, "controlled_inputs_verified": True,
        "worker_and_original_case_verified": True,
    }, sort_keys=True), flush=True)
    return nested


def _prepare_options(phase, test_id=None):
    # Exact ID scoping: existing I/S/Q options and callers are unchanged.
    if test_id in _SECOND_IDS:
        if test_id in _SECOND_PRE_I:
            return None, False, None
        if test_id == _SECOND_MARKER:
            return None, True, None
        return _observation_config(), False, None
    if test_id in _OBSERVED_IDS:
        return _observation_config(), False, None
    if test_id in _OBSERVATION_IDS:
        return _observation_config(), phase in _OBSERVATION_VARIANTS, None
    if phase == "fraction_03":
        return ResourceConfig(validity_reserve_fraction=0.3), True, None
    if phase == "large_config":
        return ResourceConfig(schema_version="x" * (1024 * 1024 - 2000)), True, None
    if phase == "freeze_false":
        return None, False, None
    if phase == "protocol_03":
        return None, True, 0.3
    return None, True, None


def _phases(test_id):
    _selection(test_id)
    if test_id in _SECOND_IDS:
        return _second_phases(test_id)
    if test_id in _OBSERVED_IDS:
        return _observed_phases(test_id)
    if test_id in _OBSERVATION_IDS:
        return _observation_phases(test_id)
    if test_id in _CHARGE_IDS:
        return _charge_phases(test_id)
    if test_id not in _INITIALIZATION_IDS:
        return (None,)
    method = test_id.rsplit(".", 1)[1]
    if method in _REPEATED:
        return ("default_setup",) + _REPEATED[method]
    if method == _DRIFT_SOURCE:
        return ("seed", "source_drift", "config_drift")
    if method == _DRIFT_ORPHAN:
        return ("seed", "orphan_source_drift")
    return ("case",)


def _is_resume(test_id, phase):
    if test_id in _SECOND_IDS:
        return _second_resume(test_id, phase)
    if test_id in _OBSERVATION_IDS:
        return test_id.endswith("." + _OBSERVATION_SOURCE) and phase == "source_drift"
    if test_id in _CHARGE_IDS:
        return _charge_is_resume(test_id, phase)
    method = test_id.rsplit(".", 1)[1]
    return ((method == _DRIFT_SOURCE and phase in {"source_drift", "config_drift"})
            or (method == _DRIFT_ORPHAN and phase == "orphan_source_drift"))


def _validate_request(request, *, orphan):
    # These are selectors emitted by the genuine seed, never substituted
    # inventory/artifact/ledger authority. The production initializer resolves
    # every selector against the unchanged genuine registry itself.
    if type(request) is not dict or set(request) != {"args", "external_files"}:
        raise AssertionError("invalid initialization request data")
    args = request["args"]
    keys = {"expected_run_id", "protocol_artifact_sha256", "contract_artifact_sha256",
            "population_artifact_sha256", "frozen_source_inventory_artifact_sha256",
            "frozen_configuration_inventory_artifact_sha256"}
    if type(args) is not dict or set(args) != keys:
        raise AssertionError("initialization request selector set differs")
    if type(args["expected_run_id"]) is not str or not args["expected_run_id"]:
        raise AssertionError("initialization request lacks its actual run")
    for key in keys - {"expected_run_id"}:
        value = args[key]
        if (type(value) is not str or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)):
            raise AssertionError("initialization request contains a non-digest selector")
    files = request["external_files"]
    if not orphan:
        if files is not None:
            raise AssertionError("no-orphan request unexpectedly carries external files")
        return
    if type(files) is not list or len(files) != 1:
        raise AssertionError("orphan request must retain the genuine first file")
    for entry in files:
        if (type(entry) is not dict or set(entry) != {"name", "bytes_hex", "inode", "mtime_ns"}
                or type(entry["name"]) is not str
                or Path(entry["name"]).name != entry["name"]
                or not entry["name"].endswith(".json")
                or type(entry["bytes_hex"]) is not str
                or type(entry["inode"]) is not int or entry["inode"] <= 0
                or type(entry["mtime_ns"]) is not int or entry["mtime_ns"] <= 0):
            raise AssertionError("orphan request file tuple differs")
        raw = bytes.fromhex(entry["bytes_hex"])
        if not raw or raw.hex() != entry["bytes_hex"]:
            raise AssertionError("orphan request bytes are not exact hexadecimal")


def _selection_data(test_id, phase, request=None):
    if phase not in _phases(test_id):
        raise AssertionError("phase is outside the exact original case mapping")
    if test_id in _SECOND_IDS:
        if _second_resume(test_id, phase):
            _second_validate_request(request)
        elif request is not None:
            raise AssertionError('fresh second26 cannot receive authority or selectors')
        return {'test_id': test_id, 'phase': phase, 'request_data': request}
    if test_id in _OBSERVED_IDS:
        if request is not None:
            raise AssertionError("observed40 fresh phases cannot receive authority or selectors")
        return {"test_id": test_id, "phase": phase, "request_data": None}
    if test_id in _OBSERVATION_IDS:
        if _is_resume(test_id, phase):
            _validate_observation_request(request)
        elif request is not None:
            raise AssertionError("fresh observation phase cannot receive prior selectors")
        return {"test_id": test_id, "phase": phase, "request_data": request}
    if test_id in _CHARGE_IDS:
        if _charge_is_resume(test_id, phase):
            _validate_charge_request(request, completed=test_id.endswith("." + _CHARGE_COMPLETED))
        elif request is not None:
            raise AssertionError("fresh charge phase cannot receive prior selectors")
        return {"test_id": test_id, "phase": phase, "request_data": request}
    if test_id not in _INITIALIZATION_IDS:
        if request is not None:
            raise AssertionError("existing reserve case cannot receive staged input")
        return {"test_id": test_id}
    if _is_resume(test_id, phase):
        _validate_request(request, orphan=phase == "orphan_source_drift")
    elif request is not None:
        raise AssertionError("fresh phase cannot receive prior selectors")
    return {"test_id": test_id, "phase": phase, "request_data": request}


def prepared_initialization_tests(cls):
    if cls.__module__ + "." + cls.__name__ != _INITIALIZATION_CLASS:
        raise AssertionError("initialization decorator used by another class")
    discovered = {name for name in vars(cls) if name.startswith("test_")}
    if discovered != _INITIALIZATION_METHODS:
        raise AssertionError("original initialization method inventory changed")
    original_setup = cls.setUp

    @wraps(original_setup)
    def setup(self):
        if _ACTIVE is not None or self.id() not in _INITIALIZATION_IDS:
            original_setup(self)

    cls.setUp = setup
    for name in _INITIALIZATION_METHODS:
        setattr(cls, name, prepared_resource_case(getattr(cls, name)))
    return cls


def prepared_initialization_setup(case):
    if _ACTIVE is None or _ACTIVE["test_id"] not in _INITIALIZATION_IDS:
        return False
    if case.id() != _ACTIVE["test_id"]:
        raise AssertionError("setup does not belong to selected original case")
    phase = _ACTIVE["phase"]
    if _is_resume(case.id(), phase):
        # Reopen the SAME owned project, with real artifacts/ledger untouched.
        # Deliberately do not call prepare, register inventories or mint new IDs.
        from scientist_one.artifacts import ArtifactRegistry
        from scientist_one.ledger import EventLedger
        from scientist_one import simulated_resource
        case.root = _ACTIVE["root"]
        case.args = dict(_ACTIVE["request_data"]["args"])
        case.run = simulated_resource.canonical_simulated_resource_run_id()
        if case.args["expected_run_id"] != case.run:
            raise AssertionError("seed's genuine run differs from native run")
        case.registry = ArtifactRegistry(case.root, Path("runs") / case.run / "registry")
        case.ledger = EventLedger(case.root, Path("runs") / case.run / "events.jsonl")
        return True
    if phase not in {"case", "seed", "default_setup"}:
        config, freeze, fraction = _prepare_options(phase)
        case.prepare(config, freeze=freeze, protocol_fraction=fraction)
        return True
    return False


def initialization_phase():
    if _ACTIVE is None or _ACTIVE["test_id"] not in _INITIALIZATION_IDS:
        raise AssertionError("refactored initialization case requires normal child capture")
    return _ACTIVE["phase"]


def initialization_shapes(shapes):
    phase = initialization_phase()
    expected = _REPEATED[_ACTIVE["test_id"].rsplit(".", 1)[1]]
    if shapes != expected or phase not in shapes:
        raise AssertionError("original subtest shape inventory changed")
    return (phase,)


def emit_initialization_request(case, *, external_files=None):
    if initialization_phase() != "seed" or case.id() != _ACTIVE["test_id"]:
        raise AssertionError("only genuine seed may emit request selectors")
    if _ACTIVE["emitted_request"] is not None:
        raise AssertionError("seed emitted twice")
    files = None if external_files is None else [
        {"name": name, "bytes_hex": raw.hex(), "inode": inode, "mtime_ns": mtime}
        for name, raw, inode, mtime in external_files
    ]
    request = {"args": dict(case.args), "external_files": files}
    _validate_request(request, orphan=case.id().endswith("." + _DRIFT_ORPHAN))
    _ACTIVE["emitted_request"] = request


def original_external_files():
    if initialization_phase() != "orphan_source_drift":
        raise AssertionError("orphan tuple requested by another phase")
    return tuple((entry["name"], bytes.fromhex(entry["bytes_hex"]),
                  entry["inode"], entry["mtime_ns"])
                 for entry in _ACTIVE["request_data"]["external_files"])


def _verify_input_delta(test_id, phase, before, after):
    if test_id == _OBSERVATION_CLASS + "." + _OBSERVATION_CONFIG and phase == "case":
        if set(before) != set(after):
            raise AssertionError("observation config drift changed controlled path set")
        for path in before:
            if path != _CONFIG and before[path] != after[path]:
                raise AssertionError("observation config drift changed another input")
        old, new = before[_CONFIG], after[_CONFIG]
        expected = canonical_json_bytes(_observation_config().to_dict()) + b"\n"
        if (old[0] != expected or new[0] != expected + b"\n"
                or new[3] != len(expected) + 1
                or (old[1], old[2], old[6], old[7]) != (new[1], new[2], new[6], new[7])):
            raise AssertionError("observation config drift differs from exact original append")
        print("SCIENTIST_ONE_PREPARED_OBSERVATION_CONFIG_V1=" + json.dumps({
            "schema_version": "prepared-observation-config/v1", "test_id": test_id,
            "phase": phase, "path": _CONFIG,
            "before": {"bytes_hex": old[0].hex(), "identity": list(old[1:])},
            "after": {"bytes_hex": new[0].hex(), "identity": list(new[1:])},
        }, sort_keys=True), flush=True)
        return
    if test_id == _INITIALIZATION_CLASS + "." + _HISTORICAL_CONFIG and phase == "case":
        if set(before) != set(after):
            raise AssertionError("historical replay changed controlled path set")
        for path in before:
            if path != _CONFIG and before[path] != after[path]:
                raise AssertionError("historical replay changed a non-config input")
        old, new = before[_CONFIG], after[_CONFIG]
        # Only this named disposable config's exact original write is allowed.
        # All source/test/launcher/fixture identities remain immutable.
        if (old[0] != canonical_json_bytes(ResourceConfig().to_dict()) + b"\n"
                or new[0] != _LATER_CONFIG or new[3] != len(_LATER_CONFIG)
                or (old[1], old[2], old[6], old[7]) != (new[1], new[2], new[6], new[7])):
            raise AssertionError("historical replay differs from exact config mutation")
    elif after != before:
        raise AssertionError("child changed controlled input bytes, identities or path set")


def _external_files_on_disk(root, run):
    base = root / ".scientist-one-build/resource-authority" / run
    return tuple((path.name, path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                 for path in sorted(base.glob("*.json")))


def _run_initialization_case(test_id):
    phases = _phases(test_id)
    completed_phases = []
    method = test_id.rsplit(".", 1)[1]
    if method in {_DRIFT_SOURCE, _DRIFT_ORPHAN}:
        with tempfile.TemporaryDirectory(prefix="prepared-resource-child-") as directory:
            root = Path(directory) / "ScientistOne"
            _prepare(root, test_id, "seed")
            seed = _capture_prepared_child(root, test_id, "seed")
            request = seed["request_data"]
            _validate_request(request, orphan=method == _DRIFT_ORPHAN)
            completed_phases.append("seed")
            original_files = _external_files_on_disk(root, request["args"]["expected_run_id"])
            if method == _DRIFT_ORPHAN:
                emitted_files = tuple((e["name"], bytes.fromhex(e["bytes_hex"]),
                                       e["inode"], e["mtime_ns"])
                                      for e in request["external_files"])
                if original_files != emitted_files:
                    raise AssertionError("retained orphan request differs from actual files")
            elif original_files != ():
                raise AssertionError("source/config seed unexpectedly advanced external state")
            for phase in phases[1:]:
                relative = _CONFIG if phase == "config_drift" else _INERT_SOURCE
                path = root / relative
                original_bytes = path.read_bytes()
                # Parent-only writes take place between completed captures.
                # This is precisely the mutation and restoration in the old
                # source/config loop; orphan used write_text('# changed\\n').
                changed = b"# changed\n" if phase == "orphan_source_drift" else original_bytes + b" \n"
                try:
                    path.write_bytes(changed)
                    (root / _SELECTION_MARKER).write_text(
                        json.dumps(_selection_data(test_id, phase, request), sort_keys=True),
                        encoding="utf-8",
                    )
                    report = _capture_prepared_child(root, test_id, phase)
                    if report["request_data"] is not None:
                        raise AssertionError("refusal phase attempted to emit another seed")
                    if _external_files_on_disk(root, request["args"]["expected_run_id"]) != original_files:
                        raise AssertionError("refusal phase changed original external file tuple")
                    completed_phases.append(phase)
                finally:
                    # The original orphan test had no restoration. Its parent
                    # owns disposable cleanup; preserve that final changed byte
                    # state until cleanup rather than changing it again.
                    if method == _DRIFT_SOURCE:
                        path.write_bytes(original_bytes)
    else:
        # Default setup is preserved as its own complete TestCase lifecycle.
        # Every original subsequent prepare gets a fresh physical captured root.
        for phase in phases:
            with tempfile.TemporaryDirectory(prefix="prepared-resource-child-") as directory:
                root = Path(directory) / "ScientistOne"
                _prepare(root, test_id, phase)
                report = _capture_prepared_child(root, test_id, phase)
                if report["request_data"] is not None:
                    raise AssertionError("ordinary phase emitted unexpected request selectors")
                completed_phases.append(phase)
    if tuple(completed_phases) != phases:
        raise AssertionError("not all original lifecycle/scenario phases passed")
    print("SCIENTIST_ONE_PREPARED_INITIALIZATION_MAPPING_V1=" + json.dumps({
        "schema_version": "prepared-initialization-mapping/v1", "test_id": test_id,
        "completed_phases": completed_phases,
        "all_nested_reports_and_original_assertions_required": True,
        "lifecycle": "explicit-captured-phases" if len(phases) > 1 else "one-captured-case",
    }, sort_keys=True), flush=True)


def _charge_phases(test_id):
    if test_id not in _CHARGE_IDS:
        raise AssertionError("not an original charge case")
    method = test_id.rsplit(".", 1)[1]
    if method in _CHARGE_REPEATED:
        return ("default_setup",) + _CHARGE_REPEATED[method]
    if method == _CHARGE_SOURCE:
        return ("seed", "config_drift", "source_drift", "S_correction")
    if method == _CHARGE_COMPLETED:
        return ("seed", "completed_source_drift")
    return ("case",)


def _charge_is_resume(test_id, phase):
    method = test_id.rsplit(".", 1)[1]
    return ((method == _CHARGE_SOURCE and phase in {"config_drift", "source_drift", "S_correction"})
            or (method == _CHARGE_COMPLETED and phase == "completed_source_drift"))


def prepared_charge_tests(cls):
    if cls.__module__ + "." + cls.__name__ != _CHARGE_CLASS:
        raise AssertionError("charge decorator used by another class")
    if {name for name in vars(cls) if name.startswith("test_")} != _CHARGE_METHODS:
        raise AssertionError("original charge method inventory changed")
    original_setup = cls.setUp

    @wraps(original_setup)
    def setup(self):
        if _ACTIVE is not None or self.id() not in _CHARGE_IDS:
            original_setup(self)

    cls.setUp = setup
    for name in _CHARGE_METHODS:
        setattr(cls, name, prepared_resource_case(getattr(cls, name)))
    return cls


def charge_phase():
    if _ACTIVE is None or _ACTIVE["test_id"] not in _CHARGE_IDS:
        return None
    return _ACTIVE["phase"]


def charge_variants(values):
    phase = charge_phase()
    if phase is None:
        raise AssertionError("refactored charge loop requires its captured child")
    method = _ACTIVE["test_id"].rsplit(".", 1)[1]
    phases = _CHARGE_REPEATED[method]
    if type(values) is not tuple or len(values) != len(phases) or phase not in phases:
        raise AssertionError("original charge variant inventory differs")
    # The test retains its complete original tuple (including marker dictionaries).
    # Static mapping checks exact tuple ASTs, and every ordinal is required once.
    return (values[phases.index(phase)],)


def _validate_charge_request(request, *, completed):
    if type(request) is not dict or set(request) != {
        "args", "initialization_artifact_sha256", "initialization_record_hash",
        "reservation_artifact_sha256", "reservation_record_hash",
        "charge_artifact_sha256", "charge_record_hash",
    }:
        raise AssertionError("charge continuation request has wrong selector fields")
    _validate_request({"args": request["args"], "external_files": None}, orphan=False)
    for key in set(request) - {"args"}:
        value = request[key]
        if key in {"charge_artifact_sha256", "charge_record_hash"} and not completed:
            if value is not None:
                raise AssertionError("S-only seed unexpectedly supplies a Q selector")
        elif (type(value) is not str or len(value) != 64
              or any(c not in "0123456789abcdef" for c in value)):
            raise AssertionError("charge continuation selector is not an actual digest")


def emit_charge_request(case, *, result=None):
    if charge_phase() != "seed" or case.id() != _ACTIVE["test_id"]:
        raise AssertionError("only genuine charge seed can emit request selectors")
    if _ACTIVE["emitted_request"] is not None:
        raise AssertionError("charge seed emitted twice")
    request = {
        "args": dict(case.case.args),
        "initialization_artifact_sha256": case.fixture.initialization.record.sha256,
        "initialization_record_hash": case.fixture.initialization.record.record_hash,
        "reservation_artifact_sha256": case.reservation.record.sha256,
        "reservation_record_hash": case.reservation.record.record_hash,
        "charge_artifact_sha256": None if result is None else result.record.sha256,
        "charge_record_hash": None if result is None else result.record.record_hash,
    }
    _validate_charge_request(request, completed=case.id().endswith("." + _CHARGE_COMPLETED))
    _ACTIVE["emitted_request"] = request


def prepared_charge_setup(case):
    phase = charge_phase()
    if phase is None or not _charge_is_resume(_ACTIVE["test_id"], phase):
        return False
    if case.id() != _ACTIVE["test_id"]:
        raise AssertionError("continuation setup belongs to another original case")
    from scientist_one.artifacts import ArtifactRegistry
    from scientist_one.ledger import EventLedger
    from scientist_one import simulated_resource as resource
    from scientist_one import simulated_reserve as reserve
    from tests import test_simulated_resource as initial_fixtures
    from tests import test_resource_backed_simulated_reserve as reserve_fixtures

    request = _ACTIVE["request_data"]
    initial_case = initial_fixtures.SimulatedResourceTests()
    initial_case.root = _ACTIVE["root"]
    initial_case.run = resource.canonical_simulated_resource_run_id()
    if request["args"]["expected_run_id"] != initial_case.run:
        raise AssertionError("seed's actual run differs from canonical run")
    initial_case.args = dict(request["args"])
    initial_case.registry = ArtifactRegistry(initial_case.root, Path("runs") / initial_case.run / "registry")
    initial_case.ledger = EventLedger(initial_case.root, Path("runs") / initial_case.run / "events.jsonl")
    registry, ledger = initial_case.registry, initial_case.ledger
    # These are the complete current, real validated snapshots. No prefix is
    # synthesized, narrowed or deserialized from request data.
    before = initial_case.snapshot(), initial_case.files()
    pair = before[0]
    if request["charge_artifact_sha256"] is not None:
        result = resource._require_simulated_confirmatory_charge_at_snapshot(
            registry, ledger, expected_run_id=initial_case.run,
            charge_artifact_sha256=request["charge_artifact_sha256"],
            registry_snapshot=pair[0], ledger_snapshot=pair[1],
        )
        initialization, reservation = result.initialization, result.reservation
        if result.record.record_hash != request["charge_record_hash"] or result.record.sha256 != request["charge_artifact_sha256"]:
            raise AssertionError("historical Q differs from seed's genuine record identity")
        case._prepared_original_charge = result
    else:
        initialization = resource._require_simulated_resource_initialization_at_snapshot(
            registry, ledger, expected_run_id=initial_case.run,
            initialization_artifact_sha256=request["initialization_artifact_sha256"],
            registry_snapshot=pair[0], ledger_snapshot=pair[1],
        )
        reservation = reserve._require_simulated_confirmatory_reserve_at_snapshot(
            registry, ledger, expected_run_id=initial_case.run,
            reservation_artifact_sha256=request["reservation_artifact_sha256"],
            registry_snapshot=pair[0], ledger_snapshot=pair[1],
        )
    if (initialization.record.sha256 != request["initialization_artifact_sha256"]
            or initialization.record.record_hash != request["initialization_record_hash"]
            or reservation.record.sha256 != request["reservation_artifact_sha256"]
            or reservation.record.record_hash != request["reservation_record_hash"]):
        raise AssertionError("historical I/S differs from seed's genuine record identities")
    actual_args = {
        "expected_run_id": initial_case.run,
        "protocol_artifact_sha256": initialization.protocol_record.sha256,
        "contract_artifact_sha256": initialization.contract_record.sha256,
        "population_artifact_sha256": initialization.population_record.sha256,
        "frozen_source_inventory_artifact_sha256": initialization.frozen_source_inventory_record.sha256,
        "frozen_configuration_inventory_artifact_sha256": initialization.frozen_configuration_inventory_record.sha256,
    }
    if actual_args != request["args"]:
        raise AssertionError("historical initialization differs from actual seed request")
    if (initial_case.snapshot(), initial_case.files()) != before:
        raise AssertionError("historical publication rehydration wrote owned state")

    initial_case.contract = initialization.contract
    initial_case.contract_record = initialization.contract_record
    initial_case.protocol = initialization.protocol
    initial_case.protocol_record = initialization.protocol_record
    initial_case.population = initialization.population_record
    initial_case.source = initialization.frozen_source_inventory_record
    initial_case.configuration = initialization.frozen_configuration_inventory_record
    fixture = reserve_fixtures.ResourceBackedSimulatedReserveTests()
    fixture.case = initial_case
    fixture.root = initial_case.root
    fixture.registry, fixture.ledger = registry, ledger
    fixture.initialization = initialization
    fixture.addCleanup(initial_case.doCleanups)
    case.fixture, case.case = fixture, initial_case
    case.registry, case.ledger = registry, ledger
    case.reservation = reservation
    case.addCleanup(fixture.doCleanups)
    print("SCIENTIST_ONE_PREPARED_CHARGE_READBACK_V1=" + json.dumps({
        "schema_version": "prepared-charge-readback/v1", "test_id": case.id(),
        "phase": phase, "request_data": request,
        "complete_actual_pair": True, "readback_zero_delta": True,
        "registry_count": pair[0].count, "ledger_event_count": pair[1].event_count,
        "ledger_head_hash": pair[1].head_hash,
    }, sort_keys=True), flush=True)
    return True


def original_charge_result(case):
    if charge_phase() != "completed_source_drift" or case.id() != _ACTIVE["test_id"]:
        raise AssertionError("original Q requested by another phase")
    return case._prepared_original_charge


def _run_charge_case(test_id):
    phases = _charge_phases(test_id)
    method = test_id.rsplit(".", 1)[1]
    completed_phases = []
    if method in {_CHARGE_SOURCE, _CHARGE_COMPLETED}:
        with tempfile.TemporaryDirectory(prefix="prepared-resource-child-") as directory:
            root = Path(directory) / "ScientistOne"
            _prepare(root, test_id, "seed")
            seed = _capture_prepared_child(root, test_id, "seed")
            request = seed["request_data"]
            _validate_charge_request(request, completed=method == _CHARGE_COMPLETED)
            completed_phases.append("seed")
            external = _external_files_on_disk(root, request["args"]["expected_run_id"])
            expected_count = 2 if method == _CHARGE_COMPLETED else 1
            if len(external) != expected_count:
                raise AssertionError("charge seed does not have its actual external prefix")
            for phase in phases[1:]:
                path = None
                if phase in {"config_drift", "source_drift", "completed_source_drift"}:
                    path = root / (_CONFIG if phase == "config_drift" else _INERT_SOURCE)
                    original_bytes = path.read_bytes()
                    suffix = b"# changed after Q\n" if phase == "completed_source_drift" else b" \n"
                try:
                    # Only these exact inert inputs change, between completed
                    # children; real artifacts, ledger and authority stay put.
                    if path is not None:
                        path.write_bytes(original_bytes + suffix)
                    (root / _SELECTION_MARKER).write_text(
                        json.dumps(_selection_data(test_id, phase, request), sort_keys=True),
                        encoding="utf-8",
                    )
                    report = _capture_prepared_child(root, test_id, phase)
                    if report["request_data"] is not None:
                        raise AssertionError("resumed charge phase emitted another seed")
                    if _external_files_on_disk(root, request["args"]["expected_run_id"]) != external:
                        raise AssertionError("charge refusal changed the seed's external file tuple")
                    completed_phases.append(phase)
                finally:
                    if path is not None and method == _CHARGE_SOURCE:
                        path.write_bytes(original_bytes)
    else:
        for phase in phases:
            with tempfile.TemporaryDirectory(prefix="prepared-resource-child-") as directory:
                root = Path(directory) / "ScientistOne"
                _prepare(root, test_id, phase)
                report = _capture_prepared_child(root, test_id, phase)
                if report["request_data"] is not None:
                    raise AssertionError("ordinary charge phase emitted seed selectors")
                completed_phases.append(phase)
    if tuple(completed_phases) != phases:
        raise AssertionError("not every original charge scenario phase passed")
    print("SCIENTIST_ONE_PREPARED_CHARGE_MAPPING_V1=" + json.dumps({
        "schema_version": "prepared-charge-mapping/v1", "test_id": test_id,
        "completed_phases": completed_phases,
        "all_nested_reports_and_original_assertions_required": True,
        "lifecycle": "explicit-captured-phases" if len(phases) > 1 else "one-captured-case",
    }, sort_keys=True), flush=True)


def _observation_config():
    return ResourceConfig(memory_soft_fraction=0.98, memory_hard_fraction=0.99,
                          minimum_free_disk_bytes=1, minimum_free_disk_fraction=0.01)


def _observation_phases(test_id):
    if test_id not in _OBSERVATION_IDS:
        raise AssertionError("not an original observation case")
    method = test_id.rsplit(".", 1)[1]
    if method == _OBSERVATION_MATRIX:
        return ("default_setup",) + _OBSERVATION_VARIANTS
    if method == _OBSERVATION_SOURCE:
        return ("seed", "source_drift")
    return ("case",)


def prepared_observation_tests(cls):
    if cls.__module__ + "." + cls.__name__ != _OBSERVATION_CLASS:
        raise AssertionError("observation decorator used by another class")
    if {name for name in vars(cls) if name.startswith("test_")} != _OBSERVATION_METHODS:
        raise AssertionError("original observation method inventory changed")
    original_setup = cls.setUp

    @wraps(original_setup)
    def setup(self):
        if _ACTIVE is not None or self.id() not in _OBSERVATION_IDS:
            original_setup(self)

    cls.setUp = setup
    for name in _OBSERVATION_METHODS:
        setattr(cls, name, prepared_resource_case(getattr(cls, name)))
    return cls


def observation_phase():
    if _ACTIVE is None or _ACTIVE["test_id"] not in _OBSERVATION_IDS:
        return None
    return _ACTIVE["phase"]


def _observation_selected_case(case):
    if _second_active() and _second_resume(_ACTIVE["test_id"], second_phase()):
        _second_observation_access(case)
        return
    if _observed_active():
        _require_observed_observation(case)
        return
    if observation_phase() is None or case.id() != _ACTIVE["test_id"]:
        raise AssertionError("observation helper requires its selected captured case")


def owned_observation_root(root):
    return ((observation_phase() is not None or _observed_bound_root(root)) and root == _ACTIVE["root"]
            and root == Path.cwd().resolve(strict=True) and root == _PROJECT_ROOT
            and root.name == "ScientistOne"
            and root.parent.name.startswith("prepared-resource-child-")
            and root.parent.parent == Path(tempfile.gettempdir()).resolve()
            and not (root / _MARKER).is_symlink()
            and (root / _MARKER).read_bytes() == b"prepared-root-fixture-20260920\n")


def verify_observation_loaded_sources(root, modules):
    expected = ("holdout", "recovery", "orchestrator", "simulated_observation",
                "simulated_resource", "simulated_reserve")
    if not owned_observation_root(root) or tuple(m.__name__.rsplit(".", 1)[-1] for m in modules) != expected:
        raise AssertionError("observation loaded source inventory differs")
    for module, name in zip(modules, expected):
        target = root / "src/scientist_one" / (name + ".py")
        if target.is_symlink() or Path(module.__file__).resolve(strict=True) != target:
            raise AssertionError("observation owner was not loaded from actual captured root")


def observation_schemas(values):
    from scientist_one import simulated_observation as observation
    expected = (observation.PREPARATION_SCHEMA, observation.ATTEMPT_SCHEMA, observation.OBSERVATION_SCHEMA)
    phase = observation_phase()
    if (_ACTIVE["test_id"] != _OBSERVATION_CLASS + "." + _OBSERVATION_MATRIX
            or type(values) is not tuple or values != expected or phase not in _OBSERVATION_VARIANTS):
        raise AssertionError("observation matrix schema inventory differs")
    return (values[("P", "T", "J").index(phase.split("-")[0])],)


def observation_forms(values):
    phase = observation_phase()
    if (_ACTIVE is None or _ACTIVE["test_id"] != _OBSERVATION_CLASS + "." + _OBSERVATION_MATRIX
            or type(values) is not tuple or values != ("renamed", "malformed", "metadata")
            or phase not in _OBSERVATION_VARIANTS):
        raise AssertionError("observation matrix form inventory differs")
    return (phase.split("-")[1],)


def _observation_relative(value):
    if (type(value) is not str or not value or Path(value).is_absolute()
            or Path(value).as_posix() != value or ".." in Path(value).parts):
        raise AssertionError("observation measurement path is not a native relative path")
    return Path(value)


def _observation_file(root, relative):
    path = root / _observation_relative(relative)
    if path.resolve(strict=True) != path or not path.is_file():
        raise AssertionError("observation file is not the same contained physical file")
    stat = path.stat()
    if stat.st_nlink != 1:
        raise AssertionError("observation measurement file has another hardlink")
    raw = path.read_bytes()
    return {"bytes_hex": raw.hex(), "device": stat.st_dev, "inode": stat.st_ino,
            "size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
            "ctime_ns": stat.st_ctime_ns, "mode": stat.st_mode, "nlink": stat.st_nlink}


def _validate_observation_request(request):
    keys = {"expected_run_id", "preparation_artifact_sha256", "preparation_record_hash",
            "charge_artifact_sha256", "charge_record_hash", "journal_relative_path", "journal_file", "pair_measurement"}
    if type(request) is not dict or set(request) != keys:
        raise AssertionError("observation seed request schema differs")
    if (type(request["expected_run_id"]) is not str or not request["expected_run_id"]
            or Path(request["expected_run_id"]).name != request["expected_run_id"]
            or request["expected_run_id"] in {".", ".."}):
        raise AssertionError("observation seed run is not a native run name")
    for key in keys - {"expected_run_id", "journal_relative_path", "journal_file", "pair_measurement"}:
        value = request[key]
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise AssertionError("observation seed selector is not an actual digest")
    _observation_relative(request["journal_relative_path"])
    entry = request["journal_file"]
    numeric = {"device", "inode", "size", "mtime_ns", "ctime_ns", "mode", "nlink"}
    if (type(entry) is not dict or set(entry) != numeric | {"bytes_hex"}
            or any(type(entry[k]) is not int or entry[k] < 0 for k in numeric)
            or entry["inode"] == 0 or entry["nlink"] != 1 or type(entry["bytes_hex"]) is not str):
        raise AssertionError("observation journal measurement schema differs")
    raw = bytes.fromhex(entry["bytes_hex"])
    if raw.hex() != entry["bytes_hex"] or len(raw) != entry["size"]:
        raise AssertionError("observation journal measurement bytes differ")
    pair = request["pair_measurement"]
    if (type(pair) is not dict or set(pair) != {"registry_count", "ledger_event_count", "ledger_head_hash"}
            or any(type(pair[k]) is not int or pair[k] <= 0 for k in ("registry_count", "ledger_event_count"))
            or type(pair["ledger_head_hash"]) is not str or len(pair["ledger_head_hash"]) != 64
            or any(c not in "0123456789abcdef" for c in pair["ledger_head_hash"])):
        raise AssertionError("observation pair measurement schema differs")


def emit_observation_request(case, prep):
    _observation_selected_case(case)
    if (case.id() != _OBSERVATION_CLASS + "." + _OBSERVATION_SOURCE
            or observation_phase() != "seed" or _ACTIVE["emitted_request"] is not None):
        raise AssertionError("only genuine observation seed can emit selectors once")
    from scientist_one import simulated_observation as observation
    relative = Path(observation._journal_path(case.charge)).as_posix()
    pair = case.case.snapshot()
    request = {
        "expected_run_id": case.case.run,
        "preparation_artifact_sha256": prep.record.sha256,
        "preparation_record_hash": prep.record.record_hash,
        "charge_artifact_sha256": case.charge.record.sha256,
        "charge_record_hash": case.charge.record.record_hash,
        "journal_relative_path": relative,
        "journal_file": _observation_file(case.root, relative),
        "pair_measurement": {"registry_count": pair[0].count,
                             "ledger_event_count": pair[1].event_count,
                             "ledger_head_hash": pair[1].head_hash},
    }
    _validate_observation_request(request)
    _ACTIVE["emitted_request"] = request


def prepared_observation_setup(case):
    if _observed_active():
        _bind_observed_observation(case)
        return False
    phase = observation_phase()
    if phase is None:
        return False
    _observation_selected_case(case)
    from tests import test_simulated_resource as initial_fixtures
    if phase in _OBSERVATION_VARIANTS:
        case.case = initial_fixtures.SimulatedResourceTests()
        case.case.prepare(_observation_config(), freeze=True)
        case.addCleanup(case.case.doCleanups)
        case.registry, case.ledger, case.root = case.case.registry, case.case.ledger, case.case.root
        return True
    if not _is_resume(case.id(), phase):
        return False
    from scientist_one.artifacts import ArtifactRegistry
    from scientist_one.ledger import EventLedger
    from scientist_one import simulated_resource as resource
    request = _ACTIVE["request_data"]
    _validate_observation_request(request)
    initial_case = initial_fixtures.SimulatedResourceTests()
    initial_case.root = _ACTIVE["root"]
    initial_case.run = resource.canonical_simulated_resource_run_id()
    if request["expected_run_id"] != initial_case.run:
        raise AssertionError("observation seed run differs from genuine native run")
    before = _observation_state(initial_case.root, request)
    # Actual complete on-disk owners only. No P/Q/I object or snapshot is
    # deserialized, narrowed, refrozen or manufactured for this refusal.
    initial_case.registry = ArtifactRegistry(initial_case.root, Path("runs") / initial_case.run / "registry")
    initial_case.ledger = EventLedger(initial_case.root, Path("runs") / initial_case.run / "events.jsonl")
    case.case, case.root = initial_case, initial_case.root
    case.registry, case.ledger = initial_case.registry, initial_case.ledger
    case.addCleanup(initial_case.doCleanups)
    if _observation_file(case.root, request["journal_relative_path"]) != request["journal_file"]:
        raise AssertionError("same-root journal differs from seed's actual measurement")
    pair = initial_case.snapshot()
    actual_pair = {"registry_count": pair[0].count, "ledger_event_count": pair[1].event_count,
                   "ledger_head_hash": pair[1].head_hash}
    if actual_pair != request["pair_measurement"]:
        raise AssertionError("complete actual pair differs from seed's measured counts/head")
    if _observation_state(case.root, request) != before:
        raise AssertionError("observation continuation reopen changed actual state")
    print(_OBSERVATION_READBACK + json.dumps({
        "schema_version": "prepared-observation-readback/v1", "test_id": case.id(),
        "phase": phase, "request_data": request,
        "registry_count": pair[0].count, "ledger_event_count": pair[1].event_count,
        "ledger_head_hash": pair[1].head_hash, "state_files": _observation_measurements(before),
    }, sort_keys=True), flush=True)
    return True


def observation_request(case):
    _observation_selected_case(case)
    if not _is_resume(case.id(), observation_phase()):
        raise AssertionError("observation selectors requested outside continuation")
    request = _ACTIVE["request_data"]
    return {"expected_run_id": request["expected_run_id"],
            "preparation_artifact_sha256": request["preparation_artifact_sha256"]}


def observation_journal_path(case):
    _observation_selected_case(case)
    if _second_active() and _second_resume(_ACTIVE["test_id"], second_phase()):
        return _observation_relative(_ACTIVE["request_data"]["journal_relative_path"])
    if _observed_active():
        # These fresh phases always retain their genuine Q-derived path.
        return None
    if not _is_resume(case.id(), observation_phase()):
        return None
    # Measurement path only. The genuine public owner separately resolves P.
    return _observation_relative(_ACTIVE["request_data"]["journal_relative_path"])


def _observation_state(root, request):
    run = request["expected_run_id"]
    bases = (root / "runs" / run, root / ".scientist-one-build/resource-authority" / run)
    paths = {path for base in bases for path in base.rglob("*") if path.is_file()}
    paths.add(root / _observation_relative(request["journal_relative_path"]))
    # Complete actual registry/ledger run tree, external authority tree, and
    # native journal file. File tuples are observations, never replay authority.
    return {path.relative_to(root).as_posix(): _observation_file(root, path.relative_to(root).as_posix())
            for path in sorted(paths)}


def _observation_measurements(files):
    return {name: {**{key: value for key, value in entry.items() if key != "bytes_hex"},
                   "sha256": hashlib.sha256(bytes.fromhex(entry["bytes_hex"])).hexdigest()}
            for name, entry in files.items()}


def _verify_observation_readback(root, test_id, phase, nested, lines):
    records = [json.loads(line[len(_OBSERVATION_READBACK):])
               for line in lines if line.startswith(_OBSERVATION_READBACK)]
    if not _is_resume(test_id, phase):
        if records:
            raise AssertionError("fresh observation phase emitted continuation readback")
        if phase == "seed":
            _validate_observation_request(nested["request_data"])
        elif nested["request_data"] is not None:
            raise AssertionError("ordinary observation phase emitted seed selectors")
        return
    selection = json.loads((root / _SELECTION_MARKER).read_text(encoding="utf-8"))
    request = selection["request_data"]
    _validate_observation_request(request)
    keys = {"schema_version", "test_id", "phase", "request_data", "registry_count",
            "ledger_event_count", "ledger_head_hash", "state_files"}
    if len(records) != 1 or type(records[0]) is not dict or set(records[0]) != keys:
        raise AssertionError("observation continuation readback schema differs")
    report = records[0]
    _validate_observation_request(report["request_data"])
    if (report["schema_version"] != "prepared-observation-readback/v1"
            or report["test_id"] != test_id or report["phase"] != phase
            or report["request_data"] != request or nested["request_data"] is not None
            or type(report["registry_count"]) is not int or report["registry_count"] <= 0
            or type(report["ledger_event_count"]) is not int or report["ledger_event_count"] <= 0
            or type(report["ledger_head_hash"]) is not str or len(report["ledger_head_hash"]) != 64
            or any(c not in "0123456789abcdef" for c in report["ledger_head_hash"])
            or {key: report[key] for key in request["pair_measurement"]} != request["pair_measurement"]
            or canonical_json_bytes(report["state_files"]) != canonical_json_bytes(
                _observation_measurements(_observation_state(root, request)))):
        raise AssertionError("observation continuation readback does not join retained actual state")


def _run_observation_case(test_id):
    phases = _observation_phases(test_id)
    completed_phases = []
    if test_id.endswith("." + _OBSERVATION_SOURCE):
        with tempfile.TemporaryDirectory(prefix="prepared-resource-child-") as directory:
            root = Path(directory) / "ScientistOne"
            _prepare(root, test_id, "seed")
            seed = _capture_prepared_child(root, test_id, "seed")
            request = seed["request_data"]
            _validate_observation_request(request)
            if _observation_file(root, request["journal_relative_path"]) != request["journal_file"]:
                raise AssertionError("seed journal does not join actual retained file")
            state = _observation_state(root, request)
            inputs = _snapshot(root)
            completed_phases.append("seed")
            path = root / _OBSERVATION_OWNER_SOURCE
            path.write_bytes(inputs[_OBSERVATION_OWNER_SOURCE][0] + b"\n# drift\n")
            (root / _SELECTION_MARKER).write_text(
                json.dumps(_selection_data(test_id, "source_drift", request), sort_keys=True), encoding="utf-8")
            changed = _snapshot(root)
            if set(changed) != set(inputs):
                raise AssertionError("parent source drift changed input path set")
            for relative in inputs:
                if relative not in {_OBSERVATION_OWNER_SOURCE, _SELECTION_MARKER} and inputs[relative] != changed[relative]:
                    raise AssertionError("parent source drift changed another input")
            old, new = inputs[_OBSERVATION_OWNER_SOURCE], changed[_OBSERVATION_OWNER_SOURCE]
            if (new[0] != old[0] + b"\n# drift\n" or new[3] != len(new[0])
                    or (old[1], old[2], old[6], old[7]) != (new[1], new[2], new[6], new[7])
                    or _observation_state(root, request) != state):
                raise AssertionError("parent did not preserve exact same-root drift boundary")
            report = _capture_prepared_child(root, test_id, "source_drift")
            if report["request_data"] is not None or _observation_state(root, request) != state:
                raise AssertionError("observation refusal changed actual seed state")
            completed_phases.append("source_drift")
            print("SCIENTIST_ONE_PREPARED_OBSERVATION_TRANSITION_V1=" + json.dumps({
                "schema_version": "prepared-observation-transition/v1", "test_id": test_id,
                "phases": list(phases), "request_data": request,
                "source_path": _OBSERVATION_OWNER_SOURCE,
                "source_before": {"sha256": hashlib.sha256(old[0]).hexdigest(), "identity": list(old[1:])},
                "source_after": {"sha256": hashlib.sha256(new[0]).hexdigest(), "identity": list(new[1:])},
                "state_files": _observation_measurements(state),
            }, sort_keys=True), flush=True)
            # Original case did not restore the comment. Cleanup owns this root.
    else:
        for phase in phases:
            with tempfile.TemporaryDirectory(prefix="prepared-resource-child-") as directory:
                root = Path(directory) / "ScientistOne"
                _prepare(root, test_id, phase)
                report = _capture_prepared_child(root, test_id, phase)
                if report["request_data"] is not None:
                    raise AssertionError("ordinary observation phase emitted selectors")
                completed_phases.append(phase)
    if tuple(completed_phases) != phases:
        raise AssertionError("not every original observation phase passed")
    print("SCIENTIST_ONE_PREPARED_OBSERVATION_MAPPING_V1=" + json.dumps({
        "schema_version": "prepared-observation-mapping/v1", "test_id": test_id,
        "completed_phases": completed_phases,
        "all_nested_reports_and_original_assertions_required": True,
        "lifecycle": "explicit-captured-phases" if len(phases) > 1 else "one-captured-case",
    }, sort_keys=True), flush=True)


def _observed_active():
    return _second_fresh_observed() or (_ACTIVE is not None and _ACTIVE["test_id"] in _OBSERVED_IDS)


def _observed_phases(test_id):
    if test_id not in _OBSERVED_IDS:
        raise AssertionError("not an observed40 original case")
    return _OBSERVED_VARIANTS if test_id == _OBSERVED_ORPHAN_MATRIX else ("case",)


def _observed_modules(test_id):
    if test_id not in _OBSERVED_IDS:
        raise AssertionError("not an observed40 module closure")
    module = test_id.rsplit(".", 2)[0]
    result = _OBSERVATION_MODULES | {module}
    if module in {"tests.test_observed_contract_v2_adversarial", "tests.test_observed_contract_v2_budget"}:
        result = result | {"tests.test_observed_contract_v2"}
    if module == "tests.test_observed_amendment":
        result = result | {"tests.test_evaluation_contract_amendment"}
    return result


def _observed_setup_ids(test_id):
    if test_id in _SECOND_IDS:
        if not _second_fresh_observed() or _ACTIVE['test_id'] != test_id:
            raise AssertionError('second26 observed setup outside fresh S2 phase')
        return [_OBSERVED_BASE + '.runTest']
    if test_id not in _OBSERVED_IDS:
        raise AssertionError("not an observed40 setup binding")
    result = [test_id]
    if test_id.rsplit(".", 2)[0] in {"tests.test_observed_contract_v2_adversarial", "tests.test_observed_contract_v2_budget"}:
        result.append(_OBSERVED_BASE + ".runTest")
    return result


def _exact_fixture_class(case, class_name):
    module, name = class_name.rsplit(".", 1)
    loaded = sys.modules.get(module)
    return loaded is not None and type(case) is getattr(loaded, name, None)


def prepared_observed_tests(cls):
    name = cls.__module__ + "." + cls.__name__
    if name not in _OBSERVED_CLASSES:
        raise AssertionError("observed decorator used by another class")
    if {key for key in vars(cls) if key.startswith("test_")} != _OBSERVED_CLASSES[name]:
        raise AssertionError("observed40 original method inventory changed")
    original_setup = cls.setUp

    @wraps(original_setup)
    def setup(self):
        if _ACTIVE is None and self.id() in _OBSERVED_IDS:
            return
        if _observed_active():
            expected = _observed_setup_ids(_ACTIVE["test_id"])
            entered = _ACTIVE.setdefault("observed_setups", [])
            if (len(entered) >= len(expected) or self.id() != expected[len(entered)]
                    or not _exact_fixture_class(self, expected[len(entered)].rsplit(".", 1)[0])):
                raise AssertionError("observed setup differs from exact outer/nested class binding")
            entered.append(self.id())
        original_setup(self)

    cls.setUp = setup
    for method in _OBSERVED_CLASSES[name]:
        setattr(cls, method, prepared_resource_case(getattr(cls, method)))
    return cls


def _bind_observed_observation(case):
    if (not _observed_active() or not _exact_fixture_class(case, _OBSERVATION_CLASS)
            or case.id() != _OBSERVATION_CLASS + ".runTest"
            or _ACTIVE.get("observed_setups") != _observed_setup_ids(_ACTIVE["test_id"])
            or _ACTIVE.get("observed_fixture") is not None or _ACTIVE["initializations"] != 0):
        raise AssertionError("observation fixture is not the one declared nested owner")
    _ACTIVE["observed_fixture"] = case


def _require_observed_observation(case):
    if (not _observed_active() or _ACTIVE.get("observed_fixture") is not case
            or not _exact_fixture_class(case, _OBSERVATION_CLASS)
            or case.id() != _OBSERVATION_CLASS + ".runTest"
            or getattr(case, "root", None) != _ACTIVE["root"]
            or _ACTIVE["initializations"] != 1):
        raise AssertionError("observation access is not bound to the genuine selected fixture")


def _observed_bound_root(root):
    return (_observed_active() and _ACTIVE.get("observed_fixture") is not None
            and getattr(_ACTIVE["observed_fixture"], "root", None) == root == _ACTIVE["root"]
            and _ACTIVE.get("observed_setups") == _observed_setup_ids(_ACTIVE["test_id"])
            and _ACTIVE["initializations"] == 1)


def verify_observed_amendment_source(registry, module):
    if not _observed_active():
        raise AssertionError("observed A source check requires its captured outer owner")
    root = _ACTIVE["root"]
    target = root / "src/scientist_one/evaluation_contract_amendment.py"
    if (not owned_observation_root(root) or registry.policy.root != root
            or module.__name__ != "scientist_one.evaluation_contract_amendment"
            or target.is_symlink() or Path(module.__file__).resolve(strict=True) != target):
        raise AssertionError("actual A owner is not the prepared captured source")


def observed_orphan_variants(values):
    if (not _observed_active() or _ACTIVE["test_id"] != _OBSERVED_ORPHAN_MATRIX
            or _ACTIVE["phase"] not in _OBSERVED_VARIANTS
            or type(values) is not tuple or len(values) != 3
            or any(type(item) is not tuple or len(item) != 2 for item in values)
            or tuple(item[0] for item in values) != _OBSERVED_VARIANTS):
        raise AssertionError("original observed orphan mutation tuple differs")
    index = _OBSERVED_VARIANTS.index(_ACTIVE["phase"])
    return ((index, values[index]),)


def _uninventoried_component_root(case, *, config, freeze, protocol_fraction):
    if (not _observed_active() or _ACTIVE["test_id"] != _OBSERVED_COMPONENT_ID
            or _ACTIVE["phase"] != "case" or _ACTIVE.get("component_case") is not case
            or not _exact_fixture_class(case, _INITIALIZATION_CLASS)
            or case.id() != _INITIALIZATION_CLASS + ".runTest"
            or config is not None or freeze is not False or protocol_fraction is not None
            or _ACTIVE["initializations"] != 1 or _ACTIVE.get("component_prepares", 0) != 0
            or hasattr(case, "root") or case._cleanups):
        raise AssertionError("only the exact uninitialized component prepare is permitted")
    _ACTIVE["component_prepares"] = 1
    # This one original freeze=False call creates its own ordinary component
    # temp root. It neither supplies nor replaces the captured I project.
    return None


@contextmanager
def prepared_uninventoried_component(owner, case):
    if (not _observed_active() or _ACTIVE["test_id"] != _OBSERVED_COMPONENT_ID
            or owner.id() != _OBSERVED_COMPONENT_ID or _ACTIVE["phase"] != "case"
            or not _exact_fixture_class(owner, _OBSERVED_COMPONENT_ID.rsplit(".", 1)[0])
            or not _exact_fixture_class(case, _INITIALIZATION_CLASS)
            or case.id() != _INITIALIZATION_CLASS + ".runTest"
            or _ACTIVE.get("component_consumed", False)
            or _ACTIVE.get("component_case") is not None or _ACTIVE["initializations"] != 1
            or sum(cleanup[0] == case.doCleanups for cleanup in owner._cleanups) != 1):
        raise AssertionError("uninitialized component context is outside its exact original call")
    _require_observed_observation(owner.case)
    _ACTIVE["component_consumed"] = True
    _ACTIVE["component_case"] = case
    try:
        # The original prepare and all four original assertions/publication
        # remain inside this context, using the genuine Q fixture's request.
        yield
        root = case.root
        if (root == _ACTIVE["root"] or not root.name.startswith("simulated-resource-test-")
                or root.parent != Path(tempfile.gettempdir()).resolve()
                or root.resolve(strict=True) != root or Path.cwd().resolve(strict=True) != _ACTIVE["root"]
                or _ACTIVE["initializations"] != 1 or _ACTIVE.get("component_prepares") != 1
                or len(case._cleanups) != 1
                or sum(cleanup[0] == case.doCleanups for cleanup in owner._cleanups) != 1
                or any(hasattr(case, key) for key in ("args", "source", "configuration"))
                or (root / ".scientist-one-build/resource-authority").exists()
                or case.contract_record.sha256 != owner.case.reservation.contract_record.sha256):
            raise AssertionError("component no longer matches original non-inventory fixture")
        inputs = _snapshot(root)
        expected = {
            _INERT_SOURCE: _INERT_BYTES,
            "scripts/scientist_one_cli.py": b"# Inventory-only inert launcher fixture.\n",
            _CONFIG: canonical_json_bytes(ResourceConfig().to_dict()) + b"\n",
        }
        if (set(inputs) != set(expected)
                or any(inputs[name][0] != raw for name, raw in expected.items())):
            raise AssertionError("component contains something other than its original inert inputs")
        for module in tuple(sys.modules.values()):
            value = getattr(module, "__file__", None)
            if type(value) is str and Path(value).resolve().is_relative_to(root):
                raise AssertionError("an executing module was loaded from the uninventoried component")
        pair = case.snapshot()
        report = {
            "schema_version": "prepared-observed-component/v1", "test_id": owner.id(),
            "phase": _ACTIVE["phase"], "captured_root": str(_ACTIVE["root"]),
            "component_root": str(root), "component_prepares": 1, "captured_prepares": 1,
            "contract_artifact_sha256": case.contract_record.sha256,
            "comparison_contract_artifact_sha256": owner.case.reservation.contract_record.sha256,
            "external_storage_exists": False,
            "inputs": {name: {"sha256": hashlib.sha256(entry[0]).hexdigest(), "identity": list(entry[1:])}
                       for name, entry in inputs.items()},
            "registry_records": [{"sha256": record.sha256, "record_hash": record.record_hash,
                                  "logical_type": record.logical_type, "schema_version": record.schema_version}
                                 for record in pair[0].records],
            "ledger_event_count": pair[1].event_count, "ledger_head_hash": pair[1].head_hash,
        }
        _ACTIVE["component_report"] = report
        print(_OBSERVED_COMPONENT + json.dumps(report, sort_keys=True), flush=True)
    finally:
        _ACTIVE["component_case"] = None


def _finish_observed_case(test_id):
    if not _observed_active() or test_id != _ACTIVE["test_id"]:
        raise AssertionError("observed binding finish belongs to another case")
    case = _ACTIVE.get("observed_fixture")
    _require_observed_observation(case)
    report = _ACTIVE.get("component_report")
    expected_component = test_id == _OBSERVED_COMPONENT_ID
    if (_ACTIVE.get("component_prepares", 0) != int(expected_component)
            or _ACTIVE.get("component_case") is not None
            or (report is not None) != expected_component):
        raise AssertionError("observed component count or completion differs")
    if report is not None and Path(report["component_root"]).exists():
        raise AssertionError("original registered component cleanup did not remove its owned root")
    print(_OBSERVED_BINDING + json.dumps({
        "schema_version": "prepared-observed-binding/v1", "test_id": test_id,
        "phase": _ACTIVE["phase"], "captured_root": str(_ACTIVE["root"]),
        "setup_ids": _ACTIVE["observed_setups"] + [case.id()],
        "captured_prepares": _ACTIVE["initializations"],
        "component_prepares": _ACTIVE.get("component_prepares", 0),
        "component_root": None if report is None else report["component_root"],
        "component_cleanup_verified": expected_component,
    }, sort_keys=True), flush=True)


def _verify_observed_binding(root, test_id, phase, nested, lines):
    bindings = [json.loads(line[len(_OBSERVED_BINDING):]) for line in lines if line.startswith(_OBSERVED_BINDING)]
    components = [json.loads(line[len(_OBSERVED_COMPONENT):]) for line in lines if line.startswith(_OBSERVED_COMPONENT)]
    needs_component = test_id == _OBSERVED_COMPONENT_ID
    keys = {"schema_version", "test_id", "phase", "captured_root", "setup_ids", "captured_prepares",
            "component_prepares", "component_root", "component_cleanup_verified"}
    if len(bindings) != 1 or type(bindings[0]) is not dict or set(bindings[0]) != keys:
        raise AssertionError("observed binding report schema differs")
    binding = bindings[0]
    if (nested["request_data"] is not None or binding["schema_version"] != "prepared-observed-binding/v1"
            or binding["test_id"] != test_id or binding["phase"] != phase
            or binding["captured_root"] != str(root)
            or binding["setup_ids"] != _observed_setup_ids(test_id) + [_OBSERVATION_CLASS + ".runTest"]
            or type(binding["captured_prepares"]) is not int or binding["captured_prepares"] != 1
            or type(binding["component_prepares"]) is not int or binding["component_prepares"] != int(needs_component)
            or binding["component_cleanup_verified"] is not needs_component
            or len(components) != int(needs_component)):
        raise AssertionError("observed binding does not join its exact selected phase")
    if not needs_component:
        if binding["component_root"] is not None:
            raise AssertionError("ordinary observed phase reports an unselected component")
        return
    report = components[0]
    component_keys = {"schema_version", "test_id", "phase", "captured_root", "component_root",
        "component_prepares", "captured_prepares", "contract_artifact_sha256", "comparison_contract_artifact_sha256",
        "external_storage_exists", "inputs", "registry_records", "ledger_event_count", "ledger_head_hash"}
    if type(report) is not dict or set(report) != component_keys:
        raise AssertionError("observed component report schema differs")
    if (report["schema_version"] != "prepared-observed-component/v1" or report["test_id"] != test_id
            or report["phase"] != phase or report["captured_root"] != str(root)
            or type(report["component_root"]) is not str or report["component_root"] != binding["component_root"]
            or report["external_storage_exists"] is not False
            or any(type(report[k]) is not int or report[k] != 1 for k in ("captured_prepares", "component_prepares"))
            or report["contract_artifact_sha256"] != report["comparison_contract_artifact_sha256"]):
        raise AssertionError("observed component report does not join original semantics")
    component_root = Path(report["component_root"])
    if (component_root == root or not component_root.is_absolute()
            or not component_root.name.startswith("simulated-resource-test-")
            or component_root.parent != Path(tempfile.gettempdir()).resolve() or component_root.exists()):
        raise AssertionError("observed component is not a cleaned independent owned root")
    for key in ("contract_artifact_sha256", "comparison_contract_artifact_sha256", "ledger_head_hash"):
        value = report[key]
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise AssertionError("observed component measured digest is invalid")
    if type(report["ledger_event_count"]) is not int or report["ledger_event_count"] != 1:
        raise AssertionError("original pre-I v1 component must have exactly its amendment event")
    expected_inputs = {_INERT_SOURCE: _INERT_BYTES,
        "scripts/scientist_one_cli.py": b"# Inventory-only inert launcher fixture.\n",
        _CONFIG: canonical_json_bytes(ResourceConfig().to_dict()) + b"\n"}
    if type(report["inputs"]) is not dict or set(report["inputs"]) != set(expected_inputs):
        raise AssertionError("observed component inert input set differs")
    for path, raw in expected_inputs.items():
        entry = report["inputs"][path]
        if (type(entry) is not dict or set(entry) != {"sha256", "identity"}
                or entry["sha256"] != hashlib.sha256(raw).hexdigest()
                or type(entry["identity"]) is not list or len(entry["identity"]) != 7
                or any(type(value) is not int or value < 0 for value in entry["identity"])
                or entry["identity"][1] == 0 or entry["identity"][2] != len(raw)
                or entry["identity"][6] != 1):
            raise AssertionError("observed component inert file measurement differs")
    records = report["registry_records"]
    if type(records) is not list or not records:
        raise AssertionError("observed component lacks real registry record measurements")
    for record in records:
        if (type(record) is not dict or set(record) != {"sha256", "record_hash", "logical_type", "schema_version"}
                or any(type(record[k]) is not str or not record[k] for k in record)):
            raise AssertionError("observed component registry measurement schema differs")
        for key in ("sha256", "record_hash"):
            if len(record[key]) != 64 or any(c not in "0123456789abcdef" for c in record[key]):
                raise AssertionError("observed component registry digest differs")
    if report["contract_artifact_sha256"] not in {r["sha256"] for r in records}:
        raise AssertionError("observed component contract is absent from its actual registry observations")


def _run_observed_case(test_id):
    phases = _observed_phases(test_id)
    completed, roots = [], []
    for phase in phases:
        with tempfile.TemporaryDirectory(prefix="prepared-resource-child-") as directory:
            root = Path(directory) / "ScientistOne"
            if str(root) in roots:
                raise AssertionError("observed variants reused a physical root name")
            _prepare(root, test_id, phase)
            report = _capture_prepared_child(root, test_id, phase)
            if report["request_data"] is not None:
                raise AssertionError("fresh observed phase emitted replacement selectors or authority")
            completed.append(phase)
            roots.append(str(root))
    if tuple(completed) != phases:
        raise AssertionError("not all original observed scenario phases passed")
    print("SCIENTIST_ONE_PREPARED_OBSERVED_MAPPING_V1=" + json.dumps({
        "schema_version": "prepared-observed-mapping/v1", "test_id": test_id,
        "completed_phases": completed, "captured_roots": roots,
        "all_nested_reports_and_original_assertions_required": True,
        "lifecycle": "three-fresh-original-variants" if test_id == _OBSERVED_ORPHAN_MATRIX else "one-captured-case",
    }, sort_keys=True), flush=True)


# Exact current second-reserve successor; old observed205 branches stay separate.
def _second_active():
    return _ACTIVE is not None and _ACTIVE['test_id'] in _SECOND_IDS


def _second_fresh_observed():
    return (_second_active() and _ACTIVE['test_id'] not in _SECOND_PRE_I
            and _ACTIVE['test_id'] != _SECOND_MARKER and not _second_resume(_ACTIVE['test_id'], _ACTIVE['phase']))


def _second_phases(test_id):
    if test_id == _SECOND_DRIFT:
        return ('seed', 'config_drift', 'source_drift', 'journal_drift', 'external_drift')
    if test_id == _SECOND_MARKER:
        return ('v3_allocation_I', 'v3_resource', 'event_v3_allocation_I', 'event_v3_resource')
    if test_id == _SECOND_LATE:
        return ('source_addition', 'config_addition')
    return ('case',)


def _second_resume(test_id, phase):
    return test_id == _SECOND_DRIFT and phase in _second_phases(test_id)[1:]


def second_phase():
    if not _second_active():
        raise AssertionError('second26 helper outside exact captured case')
    return _ACTIVE['phase']


def prepared_second_tests(cls):
    name = cls.__module__ + '.' + cls.__name__
    if name not in _SECOND_CLASSES or {n for n in vars(cls) if n.startswith('test_')} != _SECOND_CLASSES[name]:
        raise AssertionError('second26 exact method inventory differs')
    original_setup = cls.setUp
    @wraps(original_setup)
    def setup(self):
        if _ACTIVE is None and self.id() in _SECOND_IDS:
            return
        if not _second_active() or self.id() != _ACTIVE['test_id'] or not _exact_fixture_class(self, name):
            raise AssertionError('second26 outer setup class/ID differs')
        if _ACTIVE.get('second_outer') is not None:
            raise AssertionError('second26 repeated outer setup')
        _ACTIVE['second_outer'] = self
        original_setup(self)
    cls.setUp = setup
    for method in _SECOND_CLASSES[name]:
        setattr(cls, method, prepared_resource_case(getattr(cls, method)))
    return cls


def second_setup(case):
    if not _second_active() or _ACTIVE.get('second_outer') is not case:
        raise AssertionError('second26 setup belongs to another instance')
    if _second_resume(case.id(), second_phase()):
        _second_rehydrate(case)
        return True
    if case.id() in _SECOND_PRE_I:
        from tests import test_simulated_resource as initial
        case.pre_i = initial.SimulatedResourceTests()
        case.addCleanup(case.pre_i.doCleanups)
        case.pre_i.prepare(freeze=False)
        case.root, case.registry, case.ledger = case.pre_i.root, case.pre_i.registry, case.pre_i.ledger
        _ACTIVE['second_pre_i'] = case.pre_i
        return True
    return False


def _second_digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise AssertionError('second26 selector is not an exact digest')


def _second_validate_request(request):
    if type(request) is not dict or set(request) != {'args', 'journal_relative_path', 'pair_measurement'}:
        raise AssertionError('second26 seed schema differs')
    args = request['args']
    keys = {'expected_run_id', 'protocol_artifact_sha256', 'contract_artifact_sha256',
            'population_artifact_sha256', 'window_index', 'initialization_artifact_sha256',
            'prior_reservation_artifact_sha256', 'prior_observation_artifact_sha256'}
    if type(args) is not dict or set(args) != keys or type(args['window_index']) is not int or args['window_index'] != 2:
        raise AssertionError('second26 request selector set differs')
    from scientist_one import simulated_resource as resource
    if type(args['expected_run_id']) is not str or args['expected_run_id'] != resource.canonical_simulated_resource_run_id():
        raise AssertionError('second26 seed run differs from real canonical owner')
    for key in keys - {'expected_run_id', 'window_index'}:
        _second_digest(args[key])
    _observation_relative(request['journal_relative_path'])
    pair = request['pair_measurement']
    if type(pair) is not dict or set(pair) != {'records', 'events', 'head'}:
        raise AssertionError('second26 pair measurements differ')
    if any(type(pair[k]) is not list or not pair[k] for k in ('records', 'events')):
        raise AssertionError('second26 pair lacks full identities')
    for value in pair['records'] + pair['events'] + [pair['head']]:
        _second_digest(value)


def _second_pair(pair):
    return {'records': [r.record_hash for r in pair[0].records],
            'events': [e.event_hash for e in pair[1].events], 'head': pair[1].head_hash}


def _second_state(root, request):
    return _observation_state(root, {'expected_run_id': request['args']['expected_run_id'],
                                    'journal_relative_path': request['journal_relative_path']})


def emit_second_seed(case):
    from scientist_one import simulated_observation as observation
    if case.id() != _SECOND_DRIFT or second_phase() != 'seed' or _ACTIVE['emitted_request'] is not None:
        raise AssertionError('second26 seed is not unique')
    request = {'args': case.request(), 'journal_relative_path': Path(observation._journal_path(case.case.charge)).as_posix(),
               'pair_measurement': _second_pair(case.case.case.snapshot())}
    _second_validate_request(request)
    _ACTIVE['emitted_request'] = request


def _second_rehydrate(case):
    from scientist_one.artifacts import ArtifactRegistry
    from scientist_one.ledger import EventLedger
    from scientist_one import simulated_reserve as reserve
    from tests import test_simulated_resource as initial
    from tests import test_simulated_observation as observed
    request = _ACTIVE['request_data']
    _second_validate_request(request)
    root, args = _ACTIVE['root'], request['args']
    before = _second_state(root, request)
    base = initial.SimulatedResourceTests()
    base.root, base.run = root, args['expected_run_id']
    base.registry = ArtifactRegistry(root, Path('runs') / base.run / 'registry')
    base.ledger = EventLedger(root, Path('runs') / base.run / 'events.jsonl')
    pair = base.snapshot()
    if _second_pair(pair) != request['pair_measurement']:
        raise AssertionError('second26 complete pair changed from seed')
    # This existing real owner descends the COMPLETE actual P2/A2/J1 pair.
    # Any owner-internal sealed prefixes are its own contract, never fixture DTOs.
    sources, revision, j = reserve._observed_second_sources(base.registry, base.ledger, pair,
        run_id=base.run, protocol_sha=args['protocol_artifact_sha256'],
        contract_sha=args['contract_artifact_sha256'], population_sha=args['population_artifact_sha256'],
        initialization_sha=args['initialization_artifact_sha256'],
        prior_reservation_sha=args['prior_reservation_artifact_sha256'],
        prior_observation_sha=args['prior_observation_artifact_sha256'])
    fixture = observed.SimulatedObservationTests()
    fixture.case, fixture.root = base, root
    fixture.registry, fixture.ledger = base.registry, base.ledger
    fixture.charge = j.preparation.charge
    fixture.initialization, fixture.reservation = fixture.charge.initialization, fixture.charge.reservation
    case.case, case.root, case.registry, case.ledger = fixture, root, base.registry, base.ledger
    case.j, case.revision, case.amendment = j, revision, revision.amendment_publication
    case.addCleanup(fixture.doCleanups)
    fixture.addCleanup(base.doCleanups)
    _ACTIVE['second_resumed_fixture'] = fixture
    if case.request() != args or _second_state(root, request) != before or base.snapshot() != pair:
        raise AssertionError('second26 readback changed state or selected different genuine owners')
    _ACTIVE['second_readback'] = {'request_data': request, 'state_files': before,
                                'pair_measurement': _second_pair(pair)}


def _second_observation_access(case):
    if (not _second_active() or not _second_resume(_ACTIVE['test_id'], second_phase())
            or _ACTIVE.get('second_resumed_fixture') is not case
            or not _exact_fixture_class(case, _OBSERVATION_CLASS)
            or case.id() != _OBSERVATION_CLASS + '.runTest' or case.root != _ACTIVE['root']
            or _ACTIVE['initializations'] != 0):
        raise AssertionError('second26 continuation is not its exact genuine fixture')


def second_drift_path(case):
    if not _second_active() or case.id() != _SECOND_DRIFT or not _second_resume(case.id(), second_phase()):
        raise AssertionError('second26 drift diagnostic outside exact continuation')
    request = _ACTIVE['request_data']
    paths = {'config_drift': case.root / _CONFIG,
             'source_drift': case.root / 'src/scientist_one/simulated_reserve.py',
             'journal_drift': case.root / request['journal_relative_path']}
    if second_phase() == 'external_drift':
        return sorted((case.root / '.scientist-one-build/resource-authority' / request['args']['expected_run_id']).glob('*.json'))[-1]
    return paths[second_phase()]


def second_marker_schemas(values):
    if _ACTIVE['test_id'] != _SECOND_MARKER or values != ('sim-reserve/v3', 'sim-reserve-event/v3'):
        raise AssertionError('second26 marker schemas differ')
    return (values[int(second_phase().startswith('event_'))],)


def second_marker_kinds(values):
    expected = ('allocation-only-S1', 'I', 'resource-S1')
    if _ACTIVE['test_id'] != _SECOND_MARKER or tuple(v[0] for v in values) != expected:
        raise AssertionError('second26 marker kinds differ')
    names = ('tests.test_simulated_reserve.SimulatedReserveTests', _INITIALIZATION_CLASS, _RESERVE_CLASS)
    for (_, cls), name in zip(values, names):
        module, attr = name.rsplit('.', 1)
        if cls is not getattr(sys.modules[module], attr):
            raise AssertionError('second26 marker fixture class differs')
    return values[:2] if second_phase().endswith('allocation_I') else values[2:]


def second_marker_fixture(fixture, kind):
    if _ACTIVE['test_id'] != _SECOND_MARKER:
        raise AssertionError('second26 marker root outside marker ID')
    rows = _ACTIVE.setdefault('second_marker_roots', [])
    root = Path(fixture.root).resolve(strict=True)
    if kind == 'allocation-only-S1':
        if (root == _ACTIVE['root'] or root.parent != Path(tempfile.gettempdir()).resolve()
                or not root.name.startswith('simulated-reserve-') or _ACTIVE['initializations'] != 0
                or len(fixture._cleanups) != 1):
            raise AssertionError('second26 allocation component is not independent')
    elif root != _ACTIVE['root'] or _ACTIVE['initializations'] != 1:
        raise AssertionError('second26 marker I root is not captured')
    rows.append({'kind': kind, 'root': str(root), 'fixture_id': fixture.id()})


def second_evidence(kind, value):
    if not _second_active() or _ACTIVE['test_id'] not in _SECOND_NEW:
        raise AssertionError('new regression evidence outside new exact IDs')
    # Round-trip keeps this record measurement-only and JSON bounded in shape.
    _ACTIVE.setdefault('second_evidence', []).append({'kind': kind, 'data': json.loads(json.dumps(value, sort_keys=True))})


def second_inputs(root):
    if not _second_active() or root != _ACTIVE['root']:
        raise AssertionError('second26 input measurement outside owned root')
    return _snapshot(root)


def second_state(root, run, journal=None):
    bases = (root / 'runs' / run, root / '.scientist-one-build/resource-authority' / run)
    paths = {p for base in bases for p in base.rglob('*') if p.is_file()}
    if journal is not None:
        paths.add(root / _observation_relative(journal))
    return {p.relative_to(root).as_posix(): _observation_file(root, p.relative_to(root).as_posix()) for p in sorted(paths)}


@contextmanager
def second_added_input(root, phase):
    paths = {'pre_I': ('src/scientist_one/_new_regression_pre_i_extra_source.py', b'# inert pre-I negative\n'),
             'source_addition': ('src/scientist_one/_new_regression_late_s2_extra_source.py', b'# inert late S2 negative\n'),
             'config_addition': ('configs/new_regression_late_s2_extra_input.json', b'{"inert_new_regression":true}\n')}
    if ((_ACTIVE['test_id'] == _SECOND_PRODUCER and phase != 'pre_I')
            or (_ACTIVE['test_id'] == _SECOND_LATE and phase != second_phase())
            or _ACTIVE['test_id'] not in {_SECOND_PRODUCER, _SECOND_LATE}):
        raise AssertionError('added input outside exact new regression phase')
    relative, raw = paths[phase]
    path = root / relative
    before = second_inputs(root)
    if path.exists() or path.is_symlink():
        raise AssertionError('new inert input must be absent')
    with path.open('xb') as stream:
        stream.write(raw)
    created = _observation_file(root, relative)
    try:
        yield {'path': relative, 'file': created, 'before': before}
    finally:
        # A cleanup error chains the primary outcome; never delete a substitute.
        if _observation_file(root, relative) != created or bytes.fromhex(created['bytes_hex']) != raw:
            raise AssertionError('new inert input replaced or changed before owned cleanup')
        path.unlink()
        if path.exists() or path.is_symlink() or second_inputs(root) != before:
            raise AssertionError('new inert input cleanup did not preserve captured originals')


def second_fault_measurement(root, fault):
    current = second_inputs(root)
    if (set(current) != set(fault['before']) | {fault['path']}
            or any(current[p] != v for p, v in fault['before'].items())
            or _observation_file(root, fault['path']) != fault['file']):
        raise AssertionError('added input changed original files or another path')
    return {'path': fault['path'], 'file': fault['file'], 'original_inputs_unchanged': True}


def _finish_second_case(test_id):
    phase = second_phase()
    owner = _ACTIVE.get('second_outer')
    if owner is None or owner.id() != test_id:
        raise AssertionError('second26 exact outer binding absent')
    setup_ids = [test_id]
    if _second_fresh_observed():
        _require_observed_observation(owner.case)
        if _ACTIVE['observed_setups'] != [_OBSERVED_BASE + '.runTest']:
            raise AssertionError('second26 nested A setup differs')
        setup_ids += _ACTIVE['observed_setups'] + [owner.case.id()]
    elif test_id in _SECOND_PRE_I:
        if _ACTIVE.get('second_pre_i') is not owner.pre_i or not _exact_fixture_class(owner.pre_i, _INITIALIZATION_CLASS):
            raise AssertionError('second26 pre-I binding differs')
        setup_ids += [owner.pre_i.id()]
    elif _second_resume(test_id, phase):
        _second_observation_access(owner.case)
    markers = _ACTIVE.get('second_marker_roots', [])
    expected_kinds = (['allocation-only-S1', 'I'] if phase.endswith('allocation_I') else ['resource-S1']) if test_id == _SECOND_MARKER else []
    if [r['kind'] for r in markers] != expected_kinds:
        raise AssertionError('second26 marker branch census differs')
    for row in markers:
        if row['kind'] == 'allocation-only-S1' and Path(row['root']).exists():
            raise AssertionError('second26 original component cleanup did not run')
    evidence = _ACTIVE.get('second_evidence', [])
    expected = (['consumer'] * 5 if test_id == _SECOND_CONSUMER else ['producer'] if test_id == _SECOND_PRODUCER else ['late'] if test_id == _SECOND_LATE else [])
    if [r['kind'] for r in evidence] != expected:
        raise AssertionError('second26 new-control evidence incomplete')
    report = {'schema_version': 'prepared-second26-case/v1', 'test_id': test_id, 'phase': phase,
              'root': str(_ACTIVE['root']), 'setup_ids': setup_ids, 'prepares': _ACTIVE['initializations'],
              'markers': markers, 'readback': _ACTIVE.get('second_readback'), 'evidence': evidence}
    print(_SECOND_REPORT + json.dumps(report, sort_keys=True), flush=True)


def _verify_second_case(root, test_id, phase, nested, lines):
    reports = [json.loads(s[len(_SECOND_REPORT):]) for s in lines if s.startswith(_SECOND_REPORT)]
    keys = {'schema_version', 'test_id', 'phase', 'root', 'setup_ids', 'prepares', 'markers', 'readback', 'evidence'}
    if len(reports) != 1 or type(reports[0]) is not dict or set(reports[0]) != keys:
        raise AssertionError('second26 retained case schema differs')
    r = reports[0]
    resumed = _second_resume(test_id, phase)
    setup_ids = [test_id]
    if test_id in _SECOND_PRE_I:
        setup_ids += [_INITIALIZATION_CLASS + '.runTest']
    elif test_id != _SECOND_MARKER and not resumed:
        setup_ids += [_OBSERVED_BASE + '.runTest', _OBSERVATION_CLASS + '.runTest']
    if (r['schema_version'] != 'prepared-second26-case/v1' or r['test_id'] != test_id or r['phase'] != phase
            or r['root'] != str(root) or r['setup_ids'] != setup_ids
            or type(r['prepares']) is not int or r['prepares'] != int(not resumed)
            or type(r['markers']) is not list or type(r['evidence']) is not list):
        raise AssertionError('second26 report binding differs')
    if resumed:
        request = json.loads((root / _SELECTION_MARKER).read_text())['request_data']
        _second_validate_request(request)
        readback = r['readback']
        if (type(readback) is not dict or set(readback) != {'request_data', 'state_files', 'pair_measurement'}
                or readback['request_data'] != request or readback['pair_measurement'] != request['pair_measurement']
                or readback['state_files'] != _second_state(root, request) or nested['request_data'] is not None):
            raise AssertionError('second26 readback does not join complete retained actual state')
    elif r['readback'] is not None:
        raise AssertionError('fresh second26 emitted continuation readback')
    if test_id == _SECOND_DRIFT and phase == 'seed':
        _second_validate_request(nested['request_data'])
    elif nested['request_data'] is not None:
        raise AssertionError('nonseed second26 emitted request selectors')
    expected_kinds = (['allocation-only-S1', 'I'] if phase.endswith('allocation_I') else ['resource-S1']) if test_id == _SECOND_MARKER else []
    if [m.get('kind') for m in r['markers']] != expected_kinds:
        raise AssertionError('second26 marker phase join differs')
    for m in r['markers']:
        if type(m) is not dict or set(m) != {'kind', 'root', 'fixture_id'}:
            raise AssertionError('second26 marker schema differs')
        expected_fixture = {'allocation-only-S1': 'tests.test_simulated_reserve.SimulatedReserveTests.runTest',
                            'I': _INITIALIZATION_CLASS + '.runTest', 'resource-S1': _RESERVE_CLASS + '.runTest'}
        if m['fixture_id'] != expected_fixture[m['kind']]:
            raise AssertionError('second26 marker fixture ID does not join class')
        if m['kind'] == 'allocation-only-S1':
            p = Path(m['root'])
            if p == root or p.parent != Path(tempfile.gettempdir()).resolve() or not p.name.startswith('simulated-reserve-') or p.exists():
                raise AssertionError('second26 component cleanup does not join')
        elif m['root'] != str(root):
            raise AssertionError('second26 marker capture root differs')
    expected = (['consumer'] * 5 if test_id == _SECOND_CONSUMER else ['producer'] if test_id == _SECOND_PRODUCER else ['late'] if test_id == _SECOND_LATE else [])
    if [e.get('kind') for e in r['evidence']] != expected:
        raise AssertionError('second26 evidence phase count differs')
    for e in r['evidence']:
        if type(e) is not dict or set(e) != {'kind', 'data'} or type(e['data']) is not dict:
            raise AssertionError('second26 evidence schema differs')
        _verify_second_evidence(e, phase)
        from scientist_one import simulated_resource as resource
        if e['data']['state_files'] != second_state(root, resource.canonical_simulated_resource_run_id(), e['data'].get('journal_path')):
            raise AssertionError('second26 evidence does not join retained actual file state')
        from scientist_one.artifacts import ArtifactRegistry
        from scientist_one.ledger import EventLedger
        run = resource.canonical_simulated_resource_run_id()
        stable = second_state(root, run, e['data'].get('journal_path'))
        actual_pair = (ArtifactRegistry(root, Path('runs') / run / 'registry').verify_all(raise_on_error=True),
                       EventLedger(root, Path('runs') / run / 'events.jsonl').assert_valid())
        if e['data']['pair'] != _second_pair(actual_pair) or second_state(root, run, e['data'].get('journal_path')) != stable:
            raise AssertionError('second26 evidence pair or zero-write parent readback differs')
    if test_id == _SECOND_CONSUMER and [e['data']['variant'] for e in r['evidence']] != ['non-list', 'missing', 'duplicate', 'digest', 'size']:
        raise AssertionError('second26 consumer variant order differs')


def _verify_second_evidence(e, phase):
    d = e['data']
    keys = ({'variant', 'cause', 'state_unchanged', 'pair', 'state_files'} if e['kind'] == 'consumer' else
            {'cause', 'fault', 'state_unchanged', 'cleanup_verified', 'pair', 'state_files'} if e['kind'] == 'producer' else
            {'cause', 'fault', 'order', 'pair', 'record', 'event', 'external', 'journal', 'journal_path', 'state_files', 'cleanup_verified'})
    if set(d) != keys or type(d['cause']) is not list or any(type(s) is not str for s in d['cause']):
        raise AssertionError('second26 exact new-evidence shape differs')
    pair = d['pair']
    if type(pair) is not dict or set(pair) != {'records', 'events', 'head'} or any(type(pair[k]) is not list for k in ('records', 'events')):
        raise AssertionError('second26 measured native pair schema differs')
    for digest in pair['records'] + pair['events']:
        _second_digest(digest)
    if pair['head'] is not None:
        _second_digest(pair['head'])
    if type(d['state_files']) is not dict:
        raise AssertionError('second26 actual file evidence differs')
    for path, value in d['state_files'].items():
        _observation_relative(path)
        _second_file_schema(value)
    if e['kind'] == 'consumer':
        if d['variant'] not in ('non-list', 'missing', 'duplicate', 'digest', 'size') or d['state_unchanged'] is not True:
            raise AssertionError('second26 consumer evidence differs')
        expected = ('simulated evaluator source inventory is invalid' if d['variant'] == 'non-list' else
                    'frozen source inventory does not uniquely bind observed second reserve owner' if d['variant'] in {'missing', 'duplicate'} else
                    'observed second reserve owner implementation differs from the frozen inventory')
        if d['cause'] != [expected]:
            raise AssertionError('second26 direct consumer refusal cause differs')
        return
    f = d['fault']
    if type(f) is not dict or set(f) != {'path', 'file', 'original_inputs_unchanged'} or f['original_inputs_unchanged'] is not True or d['cleanup_verified'] is not True:
        raise AssertionError('second26 additive fault or cleanup evidence differs')
    expected_path = ('src/scientist_one/_new_regression_pre_i_extra_source.py' if e['kind'] == 'producer' else
                     'src/scientist_one/_new_regression_late_s2_extra_source.py' if phase == 'source_addition' else
                     'configs/new_regression_late_s2_extra_input.json')
    expected_cause = 'live source/configuration inventory differs from frozen bytes' if phase == 'config_addition' else 'captured source attestation does not cover the source inventory'
    if f['path'] != expected_path or expected_cause not in d['cause']:
        raise AssertionError('second26 fault path or actual cause differs')
    _second_file_schema(f['file'])
    expected_bytes = (b'# inert pre-I negative\n' if e['kind'] == 'producer' else
                      b'# inert late S2 negative\n' if phase == 'source_addition' else b'{"inert_new_regression":true}\n')
    if f['file']['bytes_hex'] != expected_bytes.hex():
        raise AssertionError('second26 inert added bytes differ')
    if e['kind'] == 'producer' and d['state_unchanged'] is not True:
        raise AssertionError('second26 producer advanced state')
    if e['kind'] == 'late':
        if d['order'] != ['static-readback', 'resource-contention', 'custody-contention', 'fault-created', 'public-refusal']:
            raise AssertionError('second26 late causal order differs')
        for key in ('record', 'event'):
            _second_digest(d[key])
        if d['record'] not in pair['records'] or not pair['events'] or d['event'] != pair['events'][-1]:
            raise AssertionError('second26 retained S2 identities are absent from native pair')
        _observation_relative(d['journal_path'])
        _second_file_schema(d['journal'])
        if d['state_files'].get(d['journal_path']) != d['journal'] or type(d['external']) is not list:
            raise AssertionError('second26 retained journal or external list differs')
        for entry in d['external']:
            if type(entry) is not dict or set(entry) != {'name', 'bytes_hex', 'inode', 'mtime_ns'}:
                raise AssertionError('second26 external evidence schema differs')
            matches = [v for p, v in d['state_files'].items() if p.startswith('.scientist-one-build/resource-authority/') and Path(p).name == entry['name']]
            if len(matches) != 1 or any(matches[0][k] != entry[k] for k in ('bytes_hex', 'inode', 'mtime_ns')):
                raise AssertionError('second26 external evidence does not join real files')


def _second_file_schema(value):
    numbers = {'device', 'inode', 'size', 'mtime_ns', 'ctime_ns', 'mode', 'nlink'}
    if (type(value) is not dict or set(value) != numbers | {'bytes_hex'}
            or any(type(value[k]) is not int or value[k] < 0 for k in numbers)
            or value['inode'] == 0 or value['nlink'] != 1 or value['mode'] & 0o170000 != 0o100000
            or type(value['bytes_hex']) is not str):
        raise AssertionError('second26 file observation schema differs')
    raw = bytes.fromhex(value['bytes_hex'])
    if raw.hex() != value['bytes_hex'] or len(raw) != value['size']:
        raise AssertionError('second26 file bytes differ from measurement')


def _run_second_case(test_id):
    phases, completed, roots = _second_phases(test_id), [], []
    try:
        if test_id == _SECOND_DRIFT:
            with tempfile.TemporaryDirectory(prefix='prepared-resource-child-') as directory:
                root = Path(directory) / 'ScientistOne'
                roots.append(str(root))
                _prepare(root, test_id, 'seed')
                request = _capture_prepared_child(root, test_id, 'seed')['request_data']
                _second_validate_request(request)
                completed.append('seed')
                tail = sorted((root / '.scientist-one-build/resource-authority' / request['args']['expected_run_id']).glob('*.json'))[-1]
                paths = [root / _CONFIG, root / 'src/scientist_one/simulated_reserve.py',
                         root / request['journal_relative_path'], tail]
                for phase, path in zip(phases[1:], paths):
                    raw = path.read_bytes()
                    old = _observation_file(root, path.relative_to(root).as_posix())
                    changed = None
                    inputs_before = _snapshot(root)
                    state_before = _second_state(root, request)
                    relative = path.relative_to(root).as_posix()
                    try:
                        path.write_bytes(raw + b' ')
                        changed = _observation_file(root, path.relative_to(root).as_posix())
                        if bytes.fromhex(changed['bytes_hex']) != raw + b' ' or any(changed[k] != old[k] for k in ('device', 'inode', 'mode', 'nlink')):
                            raise AssertionError('second26 parent drift differs from original bytes/identity')
                        (root / _SELECTION_MARKER).write_text(json.dumps(_selection_data(test_id, phase, request), sort_keys=True))
                        state = _second_state(root, request)
                        inputs_after = _snapshot(root)
                        if (set(inputs_before) != set(inputs_after) or set(state_before) != set(state)
                                or any(inputs_after[k] != v for k, v in inputs_before.items() if k not in {relative, _SELECTION_MARKER})
                                or any(state[k] != v for k, v in state_before.items() if k != relative)):
                            raise AssertionError('second26 parent changed another input or durable file')
                        _capture_prepared_child(root, test_id, phase)
                        if _second_state(root, request) != state:
                            raise AssertionError('second26 negative changed actual retained state')
                        completed.append(phase)
                    finally:
                        path.write_bytes(raw)
                        restored = _observation_file(root, path.relative_to(root).as_posix())
                        if restored['bytes_hex'] != raw.hex() or any(restored[k] != old[k] for k in ('device', 'inode', 'mode', 'nlink')):
                            raise AssertionError('second26 original byte restoration failed')
                        print(_SECOND_TRANSITION + json.dumps({'schema_version': 'prepared-second26-transition/v1',
                            'test_id': test_id, 'phase': phase, 'path': path.relative_to(root).as_posix(),
                            'before': old, 'fault': changed, 'restored': restored,
                            'state_before': state_before, 'state_restored': _second_state(root, request)}, sort_keys=True), flush=True)
        else:
            for phase in phases:
                with tempfile.TemporaryDirectory(prefix='prepared-resource-child-') as directory:
                    root = Path(directory) / 'ScientistOne'
                    roots.append(str(root))
                    _prepare(root, test_id, phase)
                    _capture_prepared_child(root, test_id, phase)
                    completed.append(phase)
    finally:
        print(_SECOND_MAPPING + json.dumps({'schema_version': 'prepared-second26-mapping/v1', 'test_id': test_id,
            'required_phases': list(phases), 'completed_phases': completed, 'fresh_roots': roots,
            'all_phases_complete': tuple(completed) == phases}, sort_keys=True), flush=True)
    if tuple(completed) != phases:
        raise AssertionError('second26 required phases incomplete')
