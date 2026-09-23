"""Bounded native S1/Q1 preparation, one attempt, and J1 observation.

This owner records an actual NON_INDEPENDENT architecture-control execution.
Neither its receipt nor its observation is scientific or freshness authority.
Historical replay follows sealed prefixes; current use additionally rechecks
the native external accounting tail, current contract and original live files.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
import math
import os
import threading

from . import holdout as native
from . import simulated_resource as accounting
from .artifacts import ArtifactRecord, ArtifactRegistry, RegistryValidationResult
from .errors import UnsafeSerializationError
from .ledger import EventLedger, LedgerEvent, LedgerValidationResult
from .models import MacroState, utc_now
from .protocol import StudyVersion
from .recovery import (
    RecoveryManager, FreshCustodyEvidence, RegisteredArtifactSelector,
    SimulatedReserveRevealSelection, _ResolvedConfirmatoryAdmission,
)
from .resources import ResourceController, ValidityBudget, ValidityBudgetSnapshot, conservative_disk_reserve
from .roles import Role
from .security import canonical_json_bytes, safe_json_loads, sha256_bytes
from .simulated_reserve import (
    SIMULATED_RESERVE_PROFILE, MAX_SIMULATED_RESERVE_BYTES,
    MAX_SIMULATED_RESERVE_SCAN_BYTES, _source_pair, _one, _sha, _time, _markers,
)
from .evaluation_contract_amendment import (
    _registry_record_map, _registry_map_fingerprint,
)


PREPARATION_SCHEMA = "sim-reserve-preparation/v1"
PREPARATION_EVENT_SCHEMA = "sim-reserve-preparation-event/v1"
OBSERVATION_SCHEMA = "sim-reserve-observation/v1"
OBSERVATION_EVENT_SCHEMA = "sim-reserve-observation-event/v1"
STARTED_SCHEMA = "sim-reserve-started/v1"
ATTEMPT_SCHEMA = "sim-reserve-attempt/v1"
ATTEMPT_EVENT_SCHEMA = "sim-reserve-attempt-event/v1"
ATTEMPT_KEY = "simulated_reserve_attempt"
ATTEMPT_LOGICAL_PREFIX = "resource_runtime_simulated_attempt."
PREPARATION_KEY = "simulated_reserve_preparation"
OBSERVATION_KEY = "simulated_reserve_observation"
STARTED_KEY = "simulated_reserve_started"
REQUESTER = "source-owned-simulated-reserve-v1"
REASON = "one non-evidentiary resource-backed simulated reserve attempt"
_PREP_KIND = "SIMULATED_RESERVE_PREPARATION"
_J_KIND = "SIMULATED_RESERVE_OBSERVATION"
_PREP_TYPE = "fresh_custody_receipt"
_J_TYPE = "simulated_reserve_observation"
_ORIGIN = "source-owned simulated reserve native observation"
_COMMAND = ("scientist-one", "observe-simulated-reserve")
_PREP_PREFIX = "sim-reserve-preparation-"
_J_PREFIX = "sim-reserve-observation-"
_START_PREFIX = "sim-reserve-started-"
_ATTEMPT_PREFIX = "sim-reserve-attempt-"
_MARKERS = frozenset((
    PREPARATION_SCHEMA, PREPARATION_EVENT_SCHEMA, OBSERVATION_SCHEMA,
    OBSERVATION_EVENT_SCHEMA, STARTED_SCHEMA, PREPARATION_KEY,
    OBSERVATION_KEY, STARTED_KEY, _PREP_KIND, _J_KIND, _J_TYPE,
    ATTEMPT_SCHEMA, ATTEMPT_EVENT_SCHEMA, ATTEMPT_KEY,
    "SIMULATED_RESERVE_ATTEMPT_CONSUMPTION",
))
_SCOPE = {
    "evidence_class": "NON_EVIDENTIARY",
    "independence": "NON_INDEPENDENT",
    "scientific_authority": False,
    "freshness_authority": False,
    "confirmatory_claims_valid": False,
    "e4_authority": False,
    "execution_attestation": False,
    "host_attestation": False,
    "rollback_scope": "RUN_TREE_ONLY_NOT_WHOLE_PROJECT",
}
_INVALID_REASON = "simulated architecture-control release is non-evidentiary"
_CAPTURE_MODES = (
    "NATIVE_RELEASE_RETURNED_THEN_OBSERVED",
    "RECOVERED_TERMINAL_OBSERVATION_NO_ORIGINAL_GUARD_EXIT_CLAIM",
)


class SimulatedObservationError(ValueError):
    """An exact native preparation/attempt/observation cannot be owned."""


@dataclass(frozen=True, slots=True)
class SimulatedReservePreparation:
    record: ArtifactRecord
    event: LedgerEvent
    event_index: int
    charge: accounting.SimulatedConfirmatoryCharge
    custody_journal_bytes: bytes
    custody_journal_identity_sha256: str
    registry_snapshot: RegistryValidationResult
    ledger_snapshot: LedgerValidationResult


@dataclass(frozen=True, slots=True)
class SimulatedReserveObservation:
    record: ArtifactRecord
    event: LedgerEvent
    event_index: int
    preparation: SimulatedReservePreparation
    attempt: SimulatedReserveAttempt
    started_event: LedgerEvent
    custody_journal_bytes: bytes
    custody_journal_identity_sha256: str
    capture_mode: str
    result_bytes: bytes
    registry_snapshot: RegistryValidationResult
    ledger_snapshot: LedgerValidationResult


@dataclass(frozen=True, slots=True)
class SimulatedReserveAttempt:
    record: ArtifactRecord
    event: LedgerEvent
    event_index: int
    preparation: SimulatedReservePreparation
    requested_at: str
    external_authority_bytes: bytes
    external_authority_sha256: str


_raw = accounting._raw


def _source_fields(pair):
    count, fingerprint = _registry_map_fingerprint(pair[0].records)
    return {
        "source_registry_identities": [list(item) for item in _registry_record_map(pair[0].records)],
        "source_registry_count": count,
        "source_registry_fingerprint": fingerprint,
        "source_ledger_event_count": pair[1].event_count,
        "source_ledger_head_hash": pair[1].head_hash,
    }


def _external(q, attempt=None):
    values = tuple(safe_json_loads(raw) for raw in (
        q.initialization.external_authority_bytes, q.external_authority_bytes,
    ))
    return values + ((safe_json_loads(attempt.external_authority_bytes),) if attempt is not None else ())


def _inventories(registry, q):
    i = q.initialization
    return tuple(accounting._inventory(registry, q.registry_snapshot.records, record, index, live=False)
                 for index, record in enumerate((i.frozen_source_inventory_record, i.frozen_configuration_inventory_record)))


def _evaluator_binding(registry, q):
    source, config = _inventories(registry, q)
    spec = native.ConfirmatoryEvaluatorSpec()
    entries = [item for item in source["entries"] if item["path"] == spec.implementation_path]
    if len(entries) != 1:
        raise SimulatedObservationError("frozen source inventory must bind the native evaluator")
    return {
        **asdict(spec),
        "implementation_sha256": entries[0]["sha256"],
        "source_inventory_sha256": source["aggregate_sha256"],
        "configuration_inventory_sha256": config["aggregate_sha256"],
    }


def _journal_path(q):
    # Existing native project custody namespace survives run-tree rollback.
    # Whole-project rollback remains explicitly unsupported.
    return Path(".scientist-one-build/custody") / accounting.canonical_simulated_resource_run_id() / (q.reservation.record.sha256 + ".jsonl")


def _provider(registry, q, *, existing):
    return native.SimulatedHoldoutCustody(
        authorized_requesters=(REQUESTER,), journal_root=registry.policy.root,
        journal_path=_journal_path(q), require_existing_journal=existing,
        nonblocking=True,
    )


def _provider_identity(provider, registry, q):
    if (
        type(provider) is not native.SimulatedHoldoutCustody
        or provider._journal_root != registry.policy.root
        or provider.journal_path != registry.policy.root / _journal_path(q)
        or provider._authorized_requesters != frozenset((REQUESTER,))
        or provider._journal_root_identity != accounting._named_directory_identity(registry.policy.root)
        or provider.independence is not native.CustodyIndependence.NON_INDEPENDENT
        or provider.custody_label != "SIMULATED_NON_INDEPENDENT"
    ):
        raise SimulatedObservationError("custody is not the exact native fixed-policy S namespace")


def _seal_fields(registry, q):
    binding = _evaluator_binding(registry, q)
    return {
        "split_manifest_hash": q.reservation.split_manifest_hash,
        "protocol_hash": q.reservation.protocol.sha256,
        "code_hash": binding["source_inventory_sha256"],
        "configuration_hash": binding["configuration_inventory_sha256"],
        "pre_unblinding_interpretation_hash": q.reservation.contract_record.sha256,
    }


def _native_journal(registry, q, raw, *, terminal=False, started=None):
    """Use both native owners, then close native normalization aliases."""
    if type(raw) is not bytes or len(raw) > accounting._MAX_BYTES:
        raise SimulatedObservationError("selected custody bytes exceed the closed publication bound")
    restored = native.SimulatedHoldoutCustody(authorized_requesters=(REQUESTER,))
    events = native.SimulatedHoldoutCustody._parse_journal_bytes(restored, raw)
    expected_types = ("SEAL", "RELEASE", "EVALUATION_SUCCEEDED") if terminal else ("SEAL",)
    if tuple(item.event_type for item in events) != expected_types or b"".join(_raw(item.to_dict()) for item in events) != raw:
        raise SimulatedObservationError("custody is not the exact canonical native event sequence")
    native.SimulatedHoldoutCustody._restore_from_events(restored, events)
    first = events[0].payload
    seal = first.get("seal")
    if (
        type(seal) is not dict
        or type(seal.get("authorized_access_limit")) is not int
        or seal["authorized_access_limit"] != 1
        or first.get("authorized_requesters") != [REQUESTER]
    ):
        raise SimulatedObservationError("native seal requester policy or integer limit is noncanonical")
    expected_seal = native.HoldoutSeal(
        **_seal_fields(registry, q),
        holdout_identity_hash=q.reservation.evaluator_payload_sha256,
        sealed_at=seal["sealed_at"],
        custody_independence=native.CustodyIndependence.NON_INDEPENDENT,
    )
    if _raw(first) != _raw({"seal": native._enum_dict(expected_seal), "authorized_requesters": [REQUESTER]}):
        raise SimulatedObservationError("native seal differs from full Q/S/P/C/I sources")
    if _time(expected_seal.sealed_at) < _time(q.record.created_at):
        raise SimulatedObservationError("native seal predates Q")
    status = restored._status_locked()
    if not terminal:
        if (status.revealed or status.invalidated or status.confirmatory_claims_valid
                or status.authorized_access_count != 0 or status.violation_reasons):
            raise SimulatedObservationError("preparation custody is not clean SEAL-only state")
        return events, status, None
    if type(started) is not LedgerEvent:
        raise SimulatedObservationError("terminal custody lacks exact STARTED")
    record, release, authority = (events[1].payload[name] for name in ("record", "release", "authority"))
    if any(type(item.get("authorized_access_count")) is not int or item["authorized_access_count"] != 1 for item in (record, release)):
        raise SimulatedObservationError("native release count must be exact integer one")
    when = release["released_at"]
    if (
        release["requester"] != REQUESTER or release["reason"] != REASON
        or record["requester"] != REQUESTER or record["reason"] != REASON
        or when != started.timestamp or _time(when) < _time(expected_seal.sealed_at)
        or authority != _release_binding(registry, q, started)
        or events[2].payload["evaluator_binding"] != _evaluator_binding(registry, q)
    ):
        raise SimulatedObservationError("native release and terminal bindings differ from selected STARTED")
    # Recompute with the actual native implementation's conversion and summation
    # order; no estimator, caller result or manufactured successful owner.
    payload = safe_json_loads(q.reservation.evaluator_payload)
    groups = {}
    for name in ("control", "treatment"):
        values = payload[name]
        if type(values) is not list or len(values) != 4 or any(type(x) not in (int, float) or not math.isfinite(float(x)) for x in values):
            raise SimulatedObservationError("selected S evaluator payload is invalid")
        groups[name] = [float(item) for item in values]
    c = sum(groups["control"]) / len(groups["control"])
    t = sum(groups["treatment"]) / len(groups["treatment"])
    result = {"schema_version": "1.0", "kind": "SIMULATED_TWO_GROUP_MEAN_DIFFERENCE", "control_mean": c, "treatment_mean": t, "primary_estimate": t-c, "n_control": 4, "n_treatment": 4}
    if _raw(events[2].payload["result"]) != _raw(result) or events[2].payload["result_sha256"] != sha256_bytes(canonical_json_bytes(result)):
        raise SimulatedObservationError("native aggregate does not recompute from exact S membership")
    if (not status.revealed or not status.invalidated or status.confirmatory_claims_valid is not False
            or type(status.authorized_access_count) is not int or status.authorized_access_count != 1
            or status.violation_reasons != (_INVALID_REASON,)):
        raise SimulatedObservationError("terminal status has a different invalidation or scientific claim")
    return events, status, result


def _snapshot(registry, q, provider, snapshot, *, terminal=False, started=None):
    _provider_identity(provider, registry, q)
    if type(snapshot) is not native.HoldoutAdmissionSnapshot:
        raise SimulatedObservationError("custody snapshot must be native")
    events, status, result = _native_journal(registry, q, snapshot.journal_bytes, terminal=terminal, started=started)
    if (
        snapshot.journal_sha256 != sha256_bytes(snapshot.journal_bytes)
        or snapshot.journal_head_hash != events[-1].event_hash
        or snapshot.seal != provider._seal
        or snapshot.seal.seal_hash != native.HoldoutSeal(**events[0].payload["seal"]).seal_hash
        or snapshot.custody_label != "SIMULATED_NON_INDEPENDENT"
        or not snapshot.status.durable_journal
        or replace(snapshot.status, durable_journal=False) != status
    ):
        raise SimulatedObservationError("native snapshot projection differs from replayed bytes")
    return result


def _binding_fields(registry, q):
    s, i = q.reservation, q.initialization
    return {
        "accounting_sha256": q.record.sha256, "accounting_record_hash": q.record.record_hash,
        "reservation_sha256": s.record.sha256, "reservation_identity": s.record.record_hash,
        "protocol_sha256": s.protocol_record.sha256, "protocol_identity": s.protocol_record.record_hash,
        "contract_sha256": s.contract_record.sha256, "contract_identity": s.contract_record.record_hash,
        "runtime_origin_sha256": i.record.sha256, "runtime_origin_identity": i.record.record_hash,
        "population_sha256": s.population_record.sha256, "population_identity": s.population_record.record_hash,
        "source_inventory_sha256": i.frozen_source_inventory_record.sha256,
        "source_inventory_identity": i.frozen_source_inventory_record.record_hash,
        "configuration_inventory_sha256": i.frozen_configuration_inventory_record.sha256,
        "configuration_inventory_identity": i.frozen_configuration_inventory_record.record_hash,
        "window_index": s.window_index, "member_ids": list(s.member_ids),
        "member_row_sha256s": list(s.member_row_sha256s),
        "evaluator_payload_sha256": s.evaluator_payload_sha256,
        "split_manifest_hash": s.split_manifest_hash,
        "evaluator_binding": _evaluator_binding(registry, q),
        "interpretation_anchor": "EXACT_FROZEN_EVALUATION_CONTRACT_ARTIFACT",
        "interpretation_anchor_sha256": s.contract_record.sha256,
        "protocol_rules_retained": True,
        "external_tail_sha256": q.external_authority_sha256,
        "external_sequence": 1, "charged_units": 8,
        "validity_total_units": 40, "confirmatory_reserve": 16,
    }


def _prep_body(registry, ledger, source, q, journal, identity, at):
    events, _status, _result = _native_journal(registry, q, journal)
    _chronology(source, at)
    if _time(at) < _time(events[0].payload["seal"]["sealed_at"]):
        raise SimulatedObservationError("preparation clock predates the actual native SEAL")
    accounting.validate_sha256(identity, "custody identity")
    return {
        "schema_version": PREPARATION_SCHEMA, "kind": _PREP_KIND,
        "profile": SIMULATED_RESERVE_PROFILE,
        "ledger_run_id": accounting.canonical_simulated_resource_run_id(),
        "registry_path": registry.base_path.as_posix(), "ledger_path": ledger.relative_path.as_posix(),
        "recorded_at": at, **_source_fields(source), **_binding_fields(registry, q),
        "custody_journal_path": _journal_path(q).as_posix(),
        "custody_journal_utf8": journal.decode("utf-8"),
        "custody_journal_sha256": sha256_bytes(journal),
        "custody_journal_identity_sha256": identity,
        "release_authority": False, **_SCOPE,
    }


def _plan(registry, value, parents):
    prep = value["schema_version"] == PREPARATION_SCHEMA
    return replace(accounting._plan(registry, value, at=value["recorded_at"], logical_type=_PREP_TYPE if prep else _J_TYPE, parents=parents),
                   schema_version=value["schema_version"], origin=_ORIGIN,
                   creation_command=_COMMAND, record_hash=None)


def _event(value, record, q, source):
    prep = value["schema_version"] == PREPARATION_SCHEMA
    binding = value["evaluator_binding"]
    return LedgerEvent.create(
        run_id=value["ledger_run_id"], event_id=(_PREP_PREFIX if prep else _J_PREFIX) + q.reservation.record.sha256[:40],
        timestamp=value["recorded_at"], actor_role=Role.ORCHESTRATOR,
        state_before=MacroState.CALIBRATE, requested_state_after=MacroState.CALIBRATE,
        artifact_hashes=(record.sha256,), code_version=binding["source_inventory_sha256"],
        configuration_hash=binding["configuration_inventory_sha256"],
        reason="bound clean native simulated custody after accounting" if prep else "observed actual non-evidentiary native simulated evaluation",
        prior_event_hash=source[1].head_hash, event_type="CHECKPOINT",
        metadata={"artifact_types": [record.logical_type], "artifact_record_hashes": [record.record_hash],
                  PREPARATION_KEY if prep else OBSERVATION_KEY: {
                      "schema_version": PREPARATION_EVENT_SCHEMA if prep else OBSERVATION_EVENT_SCHEMA,
                      "selected_sha256": record.sha256, "selected_record_hash": record.record_hash,
                      "profile": SIMULATED_RESERVE_PROFILE, **_SCOPE}},
    )


def _append_pair(source, record, event=None):
    events = source[1].events + ((event,) if event is not None else ())
    return RegistryValidationResult(True, (*source[0].records, record)), LedgerValidationResult(
        True, events=events, head_hash=events[-1].event_hash if events else None,
        valid_prefix_bytes=sum(len(_raw(item.to_dict())) for item in events))


def _same_pair(pair, expected):
    return set(pair[0].records) == set(expected[0].records) and pair[1] == expected[1]


def _chronology(pair, at):
    if any(_time(item.created_at) > _time(at) for item in pair[0].records) or any(_time(item.timestamp) > _time(at) for item in pair[1].events):
        raise SimulatedObservationError("publication predates its exact sources")


def _prep_reconstruct(registry, ledger, pair, record):
    value = accounting._selected_json(registry, pair[0].records, record)
    source = _source_pair(pair, value)
    q = accounting._require_simulated_confirmatory_charge_at_snapshot(
        registry, ledger, expected_run_id=accounting.canonical_simulated_resource_run_id(),
        charge_artifact_sha256=value["accounting_sha256"], registry_snapshot=source[0], ledger_snapshot=source[1])
    qvalue = accounting._selected_json(registry, source[0].records, q.record)
    if not _same_pair(source, _append_pair(_source_pair(source, qvalue), q.record, q.event)):
        raise SimulatedObservationError("preparation must seal the complete original post-Q pair")
    journal = value["custody_journal_utf8"].encode("utf-8")
    expected = _prep_body(registry, ledger, source, q, journal, value["custody_journal_identity_sha256"], value["recorded_at"])
    _chronology(source, value["recorded_at"])
    if _time(value["recorded_at"]) < _time(_native_journal(registry, q, journal)[0][0].payload["seal"]["sealed_at"]):
        raise SimulatedObservationError("preparation predates the actual native SEAL")
    parents = tuple(item.sha256 for item in (q.record, q.reservation.record, q.reservation.protocol_record, q.reservation.contract_record, q.initialization.record))
    if _raw(value) != _raw(expected) or record != _plan(registry, value, parents) or record in source[0].records:
        raise SimulatedObservationError("preparation closed payload or provenance differs")
    event = _event(value, record, q, source)
    return source, SimulatedReservePreparation(record, event, source[1].event_count, q, journal, value["custody_journal_identity_sha256"], *pair)


def _attempt_body(registry, source, prep, at):
    """Consumption of one attempt, not another validity charge or release."""
    q = prep.charge
    _chronology(source, at)
    _native_journal(registry, q, prep.custody_journal_bytes)
    return {
        "schema_version": ATTEMPT_SCHEMA,
        "kind": "SIMULATED_RESERVE_ATTEMPT_CONSUMPTION",
        "profile": SIMULATED_RESERVE_PROFILE,
        "ledger_run_id": accounting.canonical_simulated_resource_run_id(),
        "registry_path": registry.base_path.as_posix(),
        "ledger_path": (Path("runs") / accounting.canonical_simulated_resource_run_id() / "events.jsonl").as_posix(),
        "recorded_at": at, **_source_fields(source), **_binding_fields(registry, q),
        "preparation_sha256": prep.record.sha256,
        "preparation_record_hash": prep.record.record_hash,
        "custody_journal_path": _journal_path(q).as_posix(),
        "custody_seal_journal_utf8": prep.custody_journal_bytes.decode("utf-8"),
        "custody_journal_identity_sha256": prep.custody_journal_identity_sha256,
        "requester": REQUESTER, "reason": REASON, "requested_at": at,
        "runtime_state": q.runtime_state.to_dict(),
        "previous_external_authority_sha256": q.external_authority_sha256,
        "previous_external_sequence": 1,
        "attempt_consumed": True, "additional_validity_units": 0,
        "existing_attempt_policy": "OBSERVATION_OR_RECONCILIATION_ONLY_NEVER_RELEASE",
        "release_authority": False, **_SCOPE,
    }


def _attempt_authority(value, q):
    envelope = {
        "schema_version": "1.0", "kind": "RESOURCE_RUNTIME_AUTHORITY",
        "run_id": accounting.canonical_simulated_resource_run_id(), "sequence": 2,
        "logical_type": ATTEMPT_LOGICAL_PREFIX + q.reservation.record.sha256,
        "state_sha256": sha256_bytes(_raw(value)), "state": value,
        "prior_authority_sha256": q.external_authority_sha256,
    }
    if len(_raw(envelope)) > accounting._MAX_BYTES:
        raise SimulatedObservationError("attempt external envelope exceeds native capacity")
    return envelope


def _attempt_plan(registry, source, prep, at):
    q = prep.charge
    value = _attempt_body(registry, source, prep, at)
    record = replace(accounting._plan(registry, value, at=at,
        logical_type=ATTEMPT_LOGICAL_PREFIX + q.reservation.record.sha256,
        parents=(q.record.sha256, prep.record.sha256, q.reservation.record.sha256)),
        schema_version=ATTEMPT_SCHEMA, origin=_ORIGIN, creation_command=_COMMAND, record_hash=None)
    envelope = _attempt_authority(value, q)
    binding = _evaluator_binding(registry, q)
    event = LedgerEvent.create(
        run_id=accounting.canonical_simulated_resource_run_id(),
        event_id=_ATTEMPT_PREFIX + q.reservation.record.sha256[:40], timestamp=at,
        actor_role=Role.ORCHESTRATOR, state_before=MacroState.CALIBRATE,
        requested_state_after=MacroState.CALIBRATE, event_type="CHECKPOINT",
        artifact_hashes=(record.sha256,), code_version=binding["source_inventory_sha256"],
        configuration_hash=binding["configuration_inventory_sha256"],
        reason="consumed one simulated attempt durably without additional validity charge",
        prior_event_hash=source[1].head_hash,
        metadata={"artifact_types": [record.logical_type], "artifact_record_hashes": [record.record_hash],
                  "resource_authority_checkpoint": accounting._resource_authority_descriptors_for((*_external(q), envelope))[-1],
                  ATTEMPT_KEY: {"schema_version": ATTEMPT_EVENT_SCHEMA, "profile": SIMULATED_RESERVE_PROFILE,
                                "selected_sha256": record.sha256, "selected_record_hash": record.record_hash,
                                "attempt_consumed": True, "additional_validity_units": 0, **_SCOPE}},
    )
    external_raw = _raw(envelope)
    return value, SimulatedReserveAttempt(record, event, source[1].event_count, prep, at,
                                          external_raw, sha256_bytes(external_raw))


def _post_preparation(prep):
    q = prep.charge
    return _append_pair((q.registry_snapshot, q.ledger_snapshot), prep.record, prep.event)


def _attempt_reconstruct(registry, ledger, pair, record):
    value = accounting._selected_json(registry, pair[0].records, record)
    source = _source_pair(pair, value)
    lower_source, prep = _prep_reconstruct(registry, ledger, source, _one(source[0].records, value["preparation_sha256"]))
    if not _same_pair(source, _append_pair(lower_source, prep.record, prep.event)):
        raise SimulatedObservationError("attempt preimage is not exact completed preparation")
    expected, attempt = _attempt_plan(registry, source, prep, value["requested_at"])
    state = accounting.ResourceRuntimeState.from_mapping(value["runtime_state"])
    accounting._validate_monotonic_runtime_states((prep.charge.runtime_state, state))
    if (_raw(value) != _raw(expected) or record != attempt.record
            or state.to_dict() != prep.charge.runtime_state.to_dict()):
        raise SimulatedObservationError("attempt changed its full sealed sources or Q accounting state")
    return source, attempt


def _started(registry, prep, at, attempt=None):
    q = prep.charge
    _time(at)
    if _time(at) < _time(prep.record.created_at):
        raise SimulatedObservationError("STARTED predates preparation")
    if attempt is None:
        _value, attempt = _attempt_plan(registry, _post_preparation(prep), prep, at)
    if attempt.requested_at != at or attempt.preparation.record != prep.record:
        raise SimulatedObservationError("STARTED differs from the exact consumed attempt")
    binding = _evaluator_binding(registry, q)
    return LedgerEvent.create(
        run_id=accounting.canonical_simulated_resource_run_id(), event_id=_START_PREFIX + q.reservation.record.sha256[:40],
        timestamp=at, actor_role=Role.ORCHESTRATOR,
        state_before=MacroState.CALIBRATE, requested_state_after=MacroState.CALIBRATE,
        artifact_hashes=(attempt.record.sha256,), code_version=binding["source_inventory_sha256"], configuration_hash=binding["configuration_inventory_sha256"],
        reason=REASON, prior_event_hash=attempt.event.event_hash, event_type="CHECKPOINT",
        metadata={"artifact_types": [attempt.record.logical_type], "artifact_record_hashes": [attempt.record.record_hash],
                  "resource_authority_checkpoint": accounting._resource_authority_descriptors_for(_external(q, attempt))[-1],
                  "evidence_class": "ARCHITECTURE_CONTROL", "execution_kind": "SIMULATED_ARCHITECTURE_CONTROL_STARTED",
                  STARTED_KEY: {"schema_version": STARTED_SCHEMA, "profile": SIMULATED_RESERVE_PROFILE,
                                "preparation_sha256": prep.record.sha256, "preparation_record_hash": prep.record.record_hash,
                                "requester": REQUESTER, "reason": REASON, "requested_at": at,
                                "evaluator_binding": binding, "scientific_authority": False}},
    )


def _release_binding(registry, q, started):
    binding = _evaluator_binding(registry, q)
    return {
        "schema_version": "1.0", "evidence_class": "ARCHITECTURE_CONTROL",
        "ledger_run_id": accounting.canonical_simulated_resource_run_id(),
        "protocol_hash": q.reservation.protocol.sha256,
        "code_hash": binding["source_inventory_sha256"],
        "configuration_hash": binding["configuration_inventory_sha256"],
        "split_manifest_hash": q.reservation.split_manifest_hash,
        "blind_interpretation_hash": q.reservation.contract_record.sha256,
        "resource_authority_sha256": started.artifact_hashes[0],
        "evaluator_implementation_sha256": binding["implementation_sha256"],
        "started_event_id": started.event_id, "started_event_hash": started.event_hash,
    }


def _j_body(registry, ledger, source, prep, attempt, started, journal, identity, mode, at):
    events, status, result = _native_journal(registry, prep.charge, journal, terminal=True, started=started)
    if mode not in _CAPTURE_MODES or identity != prep.custody_journal_identity_sha256 or not journal.startswith(prep.custody_journal_bytes):
        raise SimulatedObservationError("J observation differs from the exact prepared custody identity/prefix")
    _chronology(source, at)
    if _time(at) < _time(started.timestamp):
        raise SimulatedObservationError("J predates actual release")
    return {
        "schema_version": OBSERVATION_SCHEMA, "kind": _J_KIND, "profile": SIMULATED_RESERVE_PROFILE,
        "ledger_run_id": accounting.canonical_simulated_resource_run_id(),
        "registry_path": registry.base_path.as_posix(), "ledger_path": ledger.relative_path.as_posix(),
        "recorded_at": at, **_source_fields(source), **_binding_fields(registry, prep.charge),
        "attempt_sha256": attempt.record.sha256, "attempt_record_hash": attempt.record.record_hash,
        "external_tail_sha256": attempt.external_authority_sha256, "external_sequence": 2,
        "preparation_sha256": prep.record.sha256, "preparation_record_hash": prep.record.record_hash,
        "started_event_id": started.event_id, "started_event_hash": started.event_hash,
        "custody_journal_path": _journal_path(prep.charge).as_posix(),
        "custody_journal_utf8": journal.decode("utf-8"), "custody_journal_sha256": sha256_bytes(journal),
        "custody_journal_identity_sha256": identity, "custody_journal_head_hash": events[-1].event_hash,
        "capture_mode": mode, "original_release_guard_exit_observed": mode == _CAPTURE_MODES[0],
        "native_release_id": status.release_event.release_id,
        "native_authorized_access_count": 1, "native_violation_reasons": [_INVALID_REASON],
        "aggregate_result": result, "aggregate_result_sha256": sha256_bytes(canonical_json_bytes(result)),
        "release_authority": False, **_SCOPE,
    }


def _selected_markers(value):
    keys, _refs, schemas, types = _markers(value)
    return bool((keys | schemas | types) & _MARKERS)


def _history_candidates(registry, pair):
    """Bounded selection, not permission: every selected candidate needs owner."""
    records, events, scanned = [], [], 0
    for record in pair[0].records:
        scanned += record.size
        if record.size > MAX_SIMULATED_RESERVE_BYTES or scanned > MAX_SIMULATED_RESERVE_SCAN_BYTES:
            raise SimulatedObservationError("observation outer census exceeds complete scan bound")
        raw = registry.get_bytes(record.sha256)
        selected = record.schema_version in _MARKERS or record.logical_type == _J_TYPE or record.logical_type.startswith(ATTEMPT_LOGICAL_PREFIX) or record.origin == _ORIGIN or record.creation_command == _COMMAND
        try:
            value = safe_json_loads(raw, max_bytes=MAX_SIMULATED_RESERVE_BYTES, max_items=100_000)
        except (ValueError, UnsafeSerializationError):
            selected |= any(canonical_json_bytes(marker) in raw for marker in _MARKERS)
        else:
            selected |= _selected_markers(value)
        if selected:
            records.append(record)
    for index, event in enumerate(pair[1].events):
        if event.event_id.startswith((_PREP_PREFIX, _J_PREFIX, _START_PREFIX, _ATTEMPT_PREFIX)) or _selected_markers(event.metadata):
            events.append((index, event))
    return tuple(records), tuple(events)


def _has_history(registry, pair):
    records, events = _history_candidates(registry, pair)
    return bool(records or events)


def _history(registry, ledger, pair, *, allow_orphan=False):
    """Finite prep -> sealed post-Q -> Q/S/I, then exact outer native suffix.

    No later owner is discovered in a lower source replay. Exact total-pair
    equality also rejects corrections, renamed aliases, missing historical
    sources and unrelated deltas; it is never a filtered today's population.
    """
    records, _events = _history_candidates(registry, pair)
    preparations = [item for item in records if item.schema_version == PREPARATION_SCHEMA]
    if len(preparations) != 1:
        raise SimulatedObservationError("history lacks one exact preparation owner")
    source, prep = _prep_reconstruct(registry, ledger, pair, preparations[0])
    after_p = _append_pair(source, prep.record, prep.event)
    if _same_pair(pair, _append_pair(source, prep.record)):
        if allow_orphan:
            return prep, None, None, None, "PREPARATION_ORPHAN"
        raise SimulatedObservationError("preparation publication event is missing")
    if _same_pair(pair, after_p):
        return prep, None, None, None, "PREPARED"
    attempts = [item for item in records if item.schema_version == ATTEMPT_SCHEMA]
    if len(attempts) != 1:
        raise SimulatedObservationError("history lacks one exact attempt-consumption owner")
    t_source, attempt = _attempt_reconstruct(registry, ledger, pair, attempts[0])
    if not _same_pair(t_source, after_p):
        raise SimulatedObservationError("attempt belongs to a different preparation prefix")
    after_t = _append_pair(after_p, attempt.record, attempt.event)
    if _same_pair(pair, _append_pair(after_p, attempt.record)):
        if allow_orphan:
            return prep, attempt, None, None, "ATTEMPT_ORPHAN"
        raise SimulatedObservationError("attempt is consumed but its checkpoint is missing")
    if _same_pair(pair, after_t):
        return prep, attempt, None, None, "ATTEMPTED"
    index = after_t[1].event_count
    if index >= pair[1].event_count:
        raise SimulatedObservationError("history has an unsupported post-preparation record")
    started = pair[1].events[index]
    if started != _started(registry, prep, started.timestamp, attempt):
        raise SimulatedObservationError("history does not own the exact single native STARTED")
    after_start = (after_t[0], LedgerValidationResult(True, events=(*after_t[1].events, started), head_hash=started.event_hash,
                     valid_prefix_bytes=after_t[1].valid_prefix_bytes + len(_raw(started.to_dict()))))
    if _same_pair(pair, after_start):
        return prep, attempt, started, None, "STARTED"
    observations = [item for item in records if item.schema_version == OBSERVATION_SCHEMA]
    if len(observations) != 1:
        raise SimulatedObservationError("history has no exact single J owner")
    record = observations[0]
    value = accounting._selected_json(registry, pair[0].records, record)
    jsource = _source_pair(pair, value)
    if not _same_pair(jsource, after_start):
        raise SimulatedObservationError("J sealed source is not exact preparation plus STARTED")
    journal = value["custody_journal_utf8"].encode("utf-8")
    expected = _j_body(registry, ledger, jsource, prep, attempt, started, journal, value["custody_journal_identity_sha256"], value["capture_mode"], value["recorded_at"])
    parents = (prep.record.sha256, attempt.record.sha256, prep.charge.record.sha256, prep.charge.reservation.record.sha256)
    if _raw(value) != _raw(expected) or record != _plan(registry, value, parents):
        raise SimulatedObservationError("J closed payload or native record differs")
    event = _event(value, record, prep.charge, jsource)
    complete = _append_pair(jsource, record, event)
    state = "COMPLETE"
    if not _same_pair(pair, complete):
        if allow_orphan and _same_pair(pair, _append_pair(jsource, record)):
            state = "OBSERVATION_ORPHAN"
        else:
            raise SimulatedObservationError("J outer population contains an unowned alias, correction or delta")
    j = SimulatedReserveObservation(record, event, jsource[1].event_count, prep, attempt, started, journal,
            value["custody_journal_identity_sha256"], value["capture_mode"], _raw(value["aggregate_result"]), *pair)
    return prep, attempt, started, j, state


def _require_native_observation_pair(ledger, registry_snapshot, ledger_snapshot):
    """Validate selected DTO shape and canonical ledger bytes, without live IO."""
    if (
        type(registry_snapshot) is not RegistryValidationResult
        or registry_snapshot.valid is not True
        or type(registry_snapshot.records) is not tuple
        or len(registry_snapshot.records) > accounting.MAX_REGISTRY_RECORDS
        or any(type(record) is not ArtifactRecord for record in registry_snapshot.records)
        or type(registry_snapshot.errors) is not tuple or registry_snapshot.errors
        or type(registry_snapshot.orphan_paths) is not tuple or registry_snapshot.orphan_paths
        or type(ledger_snapshot) is not LedgerValidationResult
        or ledger_snapshot.valid is not True
        or type(ledger_snapshot.events) is not tuple
        or len(ledger_snapshot.events) > accounting.MAX_LEDGER_EVENTS
        or any(type(event) is not LedgerEvent for event in ledger_snapshot.events)
        or type(ledger_snapshot.valid_prefix_bytes) is not int
        or ledger_snapshot.error is not None or ledger_snapshot.error_line is not None
        or ledger_snapshot.recoverable_truncated_tail is not False
    ):
        raise SimulatedObservationError("observation requires exact valid native selected snapshots")
    if ledger_snapshot.events:
        _sha(ledger_snapshot.head_hash)
    elif ledger_snapshot.head_hash is not None:
        raise SimulatedObservationError("empty selected observation ledger has a head")
    _registry_record_map(registry_snapshot.records)
    raw = b"".join(_raw(event.to_dict()) for event in ledger_snapshot.events)
    if len(raw) > accounting.MAX_LEDGER_BYTES or ledger._validate_bytes(raw) != ledger_snapshot:
        raise SimulatedObservationError("selected observation ledger projection is not exact native replay")
    return registry_snapshot, ledger_snapshot


def _require_simulated_reserve_observation_at_snapshot(
    registry, ledger, *, expected_run_id, observation_artifact_sha256,
    registry_snapshot, ledger_snapshot,
):
    """Own a complete sealed post-J1 pair; never grant current admission.

    Current contract, external tail, controller and durable custody are purposely
    not consulted. Higher owners must supply and own this exact lower prefix.
    """
    accounting._paths(registry, ledger, expected_run_id)
    _sha(observation_artifact_sha256)
    pair = _require_native_observation_pair(ledger, registry_snapshot, ledger_snapshot)
    if any(event.run_id != expected_run_id for event in pair[1].events):
        raise SimulatedObservationError("selected observation ledger belongs to another run")
    _prep, _attempt, _started_event, result, state = _history(registry, ledger, pair)
    if state != "COMPLETE" or result is None or result.record != _one(pair[0].records, observation_artifact_sha256):
        raise SimulatedObservationError("selected observation is not the exact complete J1 owner")
    return result


@contextmanager
def _observed_terminal_custody_guard(
    registry, ledger, *, expected_run_id, observation_artifact_sha256,
    registry_snapshot, ledger_snapshot,
):
    """Retain only the native terminal-custody facts of a fully owned J1.

    Callers own the outer native project-resource lifetime, current source pair,
    contract and exact external chain. This helper supplies none of those
    permissions and accepts no external-tail override or authority DTO.
    """
    observation = _require_simulated_reserve_observation_at_snapshot(
        registry, ledger, expected_run_id=expected_run_id,
        observation_artifact_sha256=observation_artifact_sha256,
        registry_snapshot=registry_snapshot, ledger_snapshot=ledger_snapshot,
    )
    q = observation.preparation.charge
    owner_pid, owner_thread = os.getpid(), threading.get_ident()
    provider = _provider(registry, q, existing=True)
    events, _status, _result = _native_journal(registry, q, observation.custody_journal_bytes,
                                            terminal=True, started=observation.started_event)
    with provider.admission_guard(nonblocking=True,
            expected_journal_head_hash=events[-1].event_hash,
            expected_journal_identity_sha256=observation.custody_journal_identity_sha256) as snapshot:
        _snapshot(registry, q, provider, snapshot, terminal=True, started=observation.started_event)
        if (snapshot.journal_bytes != observation.custody_journal_bytes
                or snapshot.journal_identity_sha256 != observation.custody_journal_identity_sha256):
            raise SimulatedObservationError("observed amendment custody differs from its full J1 owner")
        active = True
        def preflight():
            if not active or os.getpid() != owner_pid or threading.get_ident() != owner_thread:
                raise SimulatedObservationError("observed amendment guard is expired or belongs to another process/thread")
        def custody_recheck():
            preflight()
            _provider_identity(provider, registry, q)
            # The original native guard retains its locked descriptor. This
            # independent require-existing descriptor takes no flock and is
            # closed only, never unlocked or used for release/publication.
            descriptor = provider._open_journal()
            try:
                if provider._journal_identity_hash(descriptor) != snapshot.journal_identity_sha256:
                    raise SimulatedObservationError("observed amendment journal identity changed")
                if provider._verify_locked_journal_identity(descriptor) != snapshot.journal_bytes:
                    raise SimulatedObservationError("observed amendment journal bytes changed")
                if provider._journal_identity_hash(descriptor) != snapshot.journal_identity_sha256:
                    raise SimulatedObservationError("observed amendment journal identity changed during read")
            finally:
                os.close(descriptor)
        try:
            yield observation, custody_recheck
        finally:
            active = False


@contextmanager
def _observed_amendment_admission_guard(
    registry, ledger, *, expected_run_id, observation_artifact_sha256,
    registry_snapshot, ledger_snapshot, current_pair,
):
    """Retain native J1 resource/custody while the A owner owns its exact delta.

    Root's amendment owner must prove current_pair is the sealed source or only
    its deterministically verified A/A+C orphan suffix. This guard does not own
    amendment semantics, current C, or authorize any unverified output family.
    The yielded source-owned final check must run under the caller's native
    registry/ledger locks on both exact prewrite and exact postwrite pairs.
    """
    root, run_id = accounting._paths(registry, ledger, expected_run_id)
    _sha(observation_artifact_sha256)
    if type(current_pair) is not tuple or len(current_pair) != 2:
        raise SimulatedObservationError("amendment admission requires an exact native current pair")
    _require_native_observation_pair(ledger, *current_pair)
    owner_pid, owner_thread = os.getpid(), threading.get_ident()
    with accounting._project_resource_execution_lock(
        root, expected_root_identity=accounting._named_directory_identity(root), nonblocking=True,
    ):
        observation = _require_simulated_reserve_observation_at_snapshot(
            registry, ledger, expected_run_id=run_id,
            observation_artifact_sha256=observation_artifact_sha256,
            registry_snapshot=registry_snapshot, ledger_snapshot=ledger_snapshot,
        )
        q, attempt = observation.preparation.charge, observation.attempt
        if accounting._pair(registry, ledger) != current_pair:
            raise SimulatedObservationError("amendment current source pair changed before admission")
        accounting._charge_live_sources(registry, q)
        source, _config = _inventories(registry, q)
        manager = RecoveryManager(root)
        for path in ("src/scientist_one/holdout.py", "src/scientist_one/recovery.py", "src/scientist_one/simulated_observation.py"):
            RecoveryManager._validated_live_source_implementation(manager, source, path=path, label="observed amendment native source")
        expected_external = _external(q, attempt)
        if accounting._read_resource_authority_records(root, run_id) != expected_external:
            raise SimulatedObservationError("observed amendment requires the exact native T1 tail")
        _budget(q)
        with _observed_terminal_custody_guard(
            registry, ledger, expected_run_id=run_id,
            observation_artifact_sha256=observation_artifact_sha256,
            registry_snapshot=registry_snapshot, ledger_snapshot=ledger_snapshot,
        ) as (held_observation, custody_recheck):
            if held_observation != observation:
                raise SimulatedObservationError("observed amendment sealed J1 changed before custody entry")
            active = True
            def preflight():
                if not active or os.getpid() != owner_pid or threading.get_ident() != owner_thread:
                    raise SimulatedObservationError("observed amendment guard is expired or belongs to another process/thread")
            def final_check(expected_pair, registry_guard, ledger_guard):
                preflight()
                if type(expected_pair) is not tuple or len(expected_pair) != 2:
                    raise SimulatedObservationError("amendment final check requires an exact native pair")
                _require_native_observation_pair(ledger, *expected_pair)
                if any(event.run_id != run_id for event in expected_pair[1].events):
                    raise SimulatedObservationError("amendment final pair belongs to another run")
                accounting._validate_resource_authority_ledger_for(expected_external, expected_pair[1].events)
                custody_recheck()
                _final(registry, ledger, expected_pair, q, registry_guard, ledger_guard, attempt)
                custody_recheck()
                # Recheck both current owners and native external after the last
                # actual custody read. Advisory locks cannot prevent arbitrary
                # same-principal mutation; detected drift always refuses.
                if (registry._verify_all_locked(registry_guard, raise_on_error=True),
                        ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))) != expected_pair:
                    raise SimulatedObservationError("amendment paired source changed after custody recheck")
                if accounting._read_resource_authority_records(root, run_id) != expected_external:
                    raise SimulatedObservationError("amendment external tail changed after custody recheck")
                registry._verify_mutation_namespace(registry_guard)
                ledger._verify_lock_namespace(ledger_guard)
            try:
                with _locks(registry, ledger) as (registry_guard, ledger_guard):
                    final_check(current_pair, registry_guard, ledger_guard)
                yield observation, final_check
            finally:
                active = False


def _passive_charge(registry, ledger, pair, digest):
    _sha(digest)
    prep, _attempt, _started_event, _j, _state = _history(registry, ledger, pair)
    if prep.charge.record.sha256 != digest:
        raise SimulatedObservationError("selected charge belongs to a different observation")
    return replace(prep.charge, registry_snapshot=pair[0], ledger_snapshot=pair[1])


def _passive_reservation(registry, ledger, pair, digest):
    _sha(digest)
    prep, _attempt, _started_event, _j, _state = _history(registry, ledger, pair)
    if prep.charge.reservation.record.sha256 != digest:
        raise SimulatedObservationError("selected S belongs to a different observation")
    return replace(prep.charge.reservation, registry_snapshot=pair[0], ledger_snapshot=pair[1])


def _budget(q):
    state, config = q.runtime_state, q.initialization.config
    budget = ValidityBudget(state.validity_total_units, config.validity_reserve_fraction,
                            exploratory_used=state.exploratory_used, confirmatory_used=state.confirmatory_used).snapshot()
    if budget != ValidityBudgetSnapshot(40, 24, 16, 0, 8) or q.reservation.window_index != 1:
        raise SimulatedObservationError("native Q1 budget is not forty total, sixteen reserve and eight charged")
    return budget


def _live(registry, ledger, pair, q, *, attempt=None, capacity=0, new_attempt=False,
          reserve_records=0, reserve_events=0, ledger_capacity=0):
    accounting._charge_live_sources(registry, q)
    accounting._charge_current_contract(registry, ledger, pair, q.reservation)
    if accounting._read_resource_authority_records(registry.policy.root, accounting.canonical_simulated_resource_run_id()) != _external(q, attempt):
        raise SimulatedObservationError("current native external tail differs; existing T never authorizes release")
    accounting._validate_resource_authority_ledger_for(_external(q, attempt), pair[1].events)
    _budget(q)
    source, _config = _inventories(registry, q)
    manager = RecoveryManager(registry.policy.root)
    for path in ("src/scientist_one/holdout.py", "src/scientist_one/recovery.py", "src/scientist_one/simulated_observation.py"):
        RecoveryManager._validated_live_source_implementation(manager, source, path=path, label="native simulated observation owner")
    if (pair[0].count + reserve_records > accounting.MAX_REGISTRY_RECORDS
            or pair[1].event_count + reserve_events > accounting.MAX_LEDGER_EVENTS
            or pair[1].valid_prefix_bytes + ledger_capacity > accounting.MAX_LEDGER_BYTES):
        raise SimulatedObservationError("native publication lacks exact prospective capacity")
    if capacity or new_attempt:
        controller = ResourceController.from_runtime_state(q.initialization.config, registry.policy.root, q.runtime_state)
        if new_attempt:
            decision = controller.evaluate(estimated_artifact_bytes=capacity, requested_experiments=1, requested_cpu_workers=1)
            if not decision.allowed:
                raise SimulatedObservationError("native resource admission refuses: " + ", ".join(decision.reasons))
        else:
            # Finishing an observation is not a new experiment. Preserve disk
            # and artifact bounds without requiring more wall/stall/CPU budget.
            total, free, error = controller._probe_disk()
            config = q.initialization.config
            if (error is not None or total is None or free is None
                    or controller.artifact_usage() + capacity >= config.maximum_artifact_bytes
                    or free - capacity <= conservative_disk_reserve(total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)):
                raise SimulatedObservationError("native observation bookkeeping lacks disk or artifact capacity")


@contextmanager
def _locks(registry, ledger):
    rg = registry._open_mutation_lock()
    try:
        lg = ledger._open_lock()
        try:
            yield rg, lg
        finally:
            ledger._unlock(lg)
    finally:
        registry._unlock_mutation(rg)


def _final(registry, ledger, pair, q, rg, lg, attempt=None):
    accounting._charge_final_locked(registry, ledger, accounting.canonical_simulated_resource_run_id(), pair, _external(q, attempt), q, rg, lg)


def _publish(registry, ledger, pair, q, record, value, event, *, attempt=None):
    missing = record not in pair[0].records
    payload_raw, metadata_raw, event_raw = _raw(value), _raw(record.to_dict()), _raw(event.to_dict())
    # The native registry publishes both immutable payload and metadata files.
    # These new-profile bounds also reserve a finite future J at fresh T.
    if any(len(raw) > accounting._MAX_BYTES for raw in (payload_raw, metadata_raw, event_raw)):
        raise SimulatedObservationError("publication payload, metadata or event exceeds its bounded capacity")
    if pair[0].count + int(missing) > accounting.MAX_REGISTRY_RECORDS or pair[1].event_count + 1 > accounting.MAX_LEDGER_EVENTS or pair[1].valid_prefix_bytes + len(_raw(event.to_dict())) > accounting.MAX_LEDGER_BYTES:
        raise SimulatedObservationError("publication exceeds native paired capacity")
    _live(registry, ledger, pair, q, attempt=attempt,
          capacity=(len(payload_raw) + len(metadata_raw) if missing else 0) + len(event_raw),
          reserve_records=int(missing), reserve_events=1, ledger_capacity=len(event_raw))
    with _locks(registry, ledger) as (rg, lg):
        _final(registry, ledger, pair, q, rg, lg, attempt)
        raw = ledger._read_raw_locked(lg)
        prospective = ledger._validate_bytes(raw + _raw(event.to_dict()))
        if not prospective.valid or prospective.events != (*pair[1].events, event):
            raise SimulatedObservationError("prospective publication is not one valid native append")
        accounting._validate_resource_authority_ledger_for(_external(q, attempt), prospective.events)
        if missing and accounting._put(registry, rg, record, _raw(value)) != record:
            raise SimulatedObservationError("artifact publication differs")
        def build(snapshot):
            if snapshot != pair[1]:
                raise SimulatedObservationError("publication ledger CAS failed")
            return event
        if ledger._append_locked(lg, build) != event:
            raise SimulatedObservationError("publication event differs")
        after = (registry._verify_all_locked(rg, raise_on_error=True), ledger._validate_bytes(ledger._read_raw_locked(lg)))
        if set(after[0].records) != {*pair[0].records, record} or after[1] != prospective:
            raise SimulatedObservationError("publication changed outside the exact suffix")
        _final(registry, ledger, after, q, rg, lg, attempt)
    return after


def prepare_simulated_reserve_reveal(registry, ledger, *, expected_run_id, reservation_artifact_sha256, charge_artifact_sha256):
    """Seal S1 once and bind clean custody after exact completed accounting."""
    root, run_id = accounting._paths(registry, ledger, expected_run_id)
    _sha(reservation_artifact_sha256)
    _sha(charge_artifact_sha256)
    with accounting._project_resource_execution_lock(root, expected_root_identity=accounting._named_directory_identity(root), nonblocking=True):
        pair = accounting._pair(registry, ledger)
        if _has_history(registry, pair):
            prep, attempt, started, j, state = _history(registry, ledger, pair, allow_orphan=True)
            q = prep.charge
            if state not in ("PREPARED", "PREPARATION_ORPHAN"):
                raise SimulatedObservationError("attempt or observation already exists; preparation is not retry permission")
        else:
            q = accounting._require_charge_locked(registry, ledger, run_id, charge_artifact_sha256)
            prep = None
        if q.record.sha256 != charge_artifact_sha256 or q.reservation.record.sha256 != reservation_artifact_sha256:
            raise SimulatedObservationError("preparation selectors do not join exact Q and S")
        _live(registry, ledger, pair, q, capacity=accounting._MAX_BYTES,
              reserve_records=int(prep is None), reserve_events=int(prep is None or state == "PREPARATION_ORPHAN"),
              ledger_capacity=accounting._MAX_BYTES if prep is None else 0)
        # Check the prospective owner clock before a new provider can create
        # storage or native SEAL. A restored clean SEAL retains its exact time.
        first_sealed_at = utc_now()
        _chronology((q.registry_snapshot, q.ledger_snapshot), first_sealed_at)
        provider = _provider(registry, q, existing=prep is not None)
        _provider_identity(provider, registry, q)
        # Native SEAL is durable before receipt publication. Restart may finish
        # this exact clean SEAL, but never a different journal or touched state.
        sealed_at = provider._seal.sealed_at if provider._seal is not None else first_sealed_at
        _chronology((q.registry_snapshot, q.ledger_snapshot), sealed_at)
        native.SimulatedHoldoutCustody.seal(provider, q.reservation.evaluator_payload,
            **_seal_fields(registry, q), sealed_at=sealed_at, nonblocking=True)
        with provider.admission_guard(nonblocking=True) as snapshot:
            _snapshot(registry, q, provider, snapshot)
            if prep is not None:
                if snapshot.journal_bytes != prep.custody_journal_bytes or snapshot.journal_identity_sha256 != prep.custody_journal_identity_sha256:
                    raise SimulatedObservationError("prepared native custody identity or bytes changed")
                if state == "PREPARED":
                    with _locks(registry, ledger) as (rg, lg):
                        _final(registry, ledger, pair, q, rg, lg)
                    return prep
                value = accounting._selected_json(registry, pair[0].records, prep.record)
                record, event = prep.record, prep.event
            else:
                value = _prep_body(registry, ledger, pair, q, snapshot.journal_bytes, snapshot.journal_identity_sha256, utc_now())
                parents = tuple(item.sha256 for item in (q.record, q.reservation.record, q.reservation.protocol_record, q.reservation.contract_record, q.initialization.record))
                record = _plan(registry, value, parents)
                event = _event(value, record, q, pair)
            after = _publish(registry, ledger, pair, q, record, value, event)
            return _history(registry, ledger, after)[0]


def _admit_simulated_reserve_locked(manager, *, ledger_path, study_version, fresh_custody_evidence,
        reveal_authority, artifact_registry, custody_provider, validity_snapshot, start_event,
        _locked_session, _execution_class, custody_record=None, _native_requester=None,
        _native_reason=None, _native_requested_at=None, _native_evaluator_spec=None):
    """Called by the exact native admission dispatcher, never a release primitive."""
    native._require_simulated_reserve_resource_binding(_locked_session, custody_provider, manager.project_root)
    registry = artifact_registry
    if type(manager) is not RecoveryManager or type(registry) is not ArtifactRegistry or type(reveal_authority) is not SimulatedReserveRevealSelection:
        raise SimulatedObservationError("admission requires exact native manager, registry and selectors")
    ledger = EventLedger(manager.project_root, ledger_path)
    accounting._paths(registry, ledger, accounting.canonical_simulated_resource_run_id())
    pair = accounting._pair(registry, ledger)
    prep, prior_attempt, started, j, state = _history(registry, ledger, pair)
    q = prep.charge
    if state != "PREPARED" or prior_attempt is not None or started is not None or j is not None or custody_record is not None:
        raise SimulatedObservationError("only untouched prepared S1 may append STARTED; no retries")
    if (
        _execution_class is not native.RevealExecutionClass.SIMULATED_ARCHITECTURE_CONTROL
        or type(study_version) is not StudyVersion or study_version != StudyVersion(q.reservation.protocol)
        or type(fresh_custody_evidence) is not FreshCustodyEvidence
        or fresh_custody_evidence != FreshCustodyEvidence(prep.record.sha256, prep.record.record_hash, prep.event.event_id)
        or reveal_authority != SimulatedReserveRevealSelection(RegisteredArtifactSelector(q.reservation.record.sha256, q.reservation.record.record_hash), RegisteredArtifactSelector(q.record.sha256, q.record.record_hash))
        or type(validity_snapshot) is not ValidityBudgetSnapshot or validity_snapshot != _budget(q)
        or any(type(getattr(validity_snapshot, name)) is not int for name in asdict(validity_snapshot))
        or type(start_event) is not LedgerEvent or start_event != _started(registry, prep, start_event.timestamp)
        or type(_native_requester) is not str or _native_requester != REQUESTER
        or type(_native_reason) is not str or _native_reason != REASON
        or type(_native_requested_at) is not str or _native_requested_at != start_event.timestamp
        or type(_native_evaluator_spec) is not native.ConfirmatoryEvaluatorSpec
        or _native_evaluator_spec != native.ConfirmatoryEvaluatorSpec()
    ):
        raise SimulatedObservationError("native admission inputs differ from closed preparation ownership")
    _snapshot(registry, q, custody_provider, _locked_session.snapshot)
    if (_locked_session.snapshot.journal_bytes != prep.custody_journal_bytes
            or _locked_session.snapshot.journal_identity_sha256 != prep.custody_journal_identity_sha256
            or custody_provider._payload != q.reservation.evaluator_payload):
        raise SimulatedObservationError("locked native payload or custody differs from exact preparation")
    value, attempt = _attempt_plan(registry, pair, prep, start_event.timestamp)
    if start_event != _started(registry, prep, start_event.timestamp, attempt):
        raise SimulatedObservationError("STARTED does not bind the exact prospective T")
    # Exact bytes for the known T/STARTED suffix, plus conservative hard bounds
    # for future J payload/metadata/event and this profile's 1MiB native journal.
    # The journal bound includes its existing SEAL, deliberately over-reserving
    # rather than predicting or manufacturing a successful native terminal.
    # This is a conservative logical-byte allowance, not filesystem allocation.
    attempt_bytes = (len(attempt.external_authority_bytes) + len(_raw(value))
                     + len(_raw(attempt.record.to_dict()))
                     + len(_raw(attempt.event.to_dict())) + len(_raw(start_event.to_dict())))
    _live(registry, ledger, pair, q,
          capacity=attempt_bytes + 4 * accounting._MAX_BYTES,
          new_attempt=True, reserve_records=2, reserve_events=3,
          ledger_capacity=accounting._MAX_BYTES + len(_raw(attempt.event.to_dict())) + len(_raw(start_event.to_dict())))
    if _time(start_event.timestamp) > _time(utc_now()):
        raise SimulatedObservationError("STARTED cannot use a future release clock")
    with _locks(registry, ledger) as (rg, lg):
        _final(registry, ledger, pair, q, rg, lg)
        raw = ledger._read_raw_locked(lg)
        prospective_t = ledger._validate_bytes(raw + _raw(attempt.event.to_dict()))
        prospective = ledger._validate_bytes(raw + _raw(attempt.event.to_dict()) + _raw(start_event.to_dict()))
        if (not prospective_t.valid or prospective_t.events != (*pair[1].events, attempt.event)
                or not prospective.valid or prospective.events != (*pair[1].events, attempt.event, start_event)
                or prospective.event_count > accounting.MAX_LEDGER_EVENTS or prospective.valid_prefix_bytes > accounting.MAX_LEDGER_BYTES):
            raise SimulatedObservationError("T/STARTED prospective appends are invalid or exceed capacity")
        accounting._validate_resource_authority_ledger_for(_external(q, attempt), prospective_t.events)
        accounting._validate_resource_authority_ledger_for(_external(q, attempt), prospective.events)
        # This is the only fresh-consumption path. Every check and both local
        # prospective appends precede the irreversible external advance. An
        # existing external T, including an orphan, can never enter here.
        if accounting._persist_resource_authority_for(registry.policy.root,
                accounting.canonical_simulated_resource_run_id(), attempt.record.logical_type, value
                ) != safe_json_loads(attempt.external_authority_bytes):
            raise SimulatedObservationError("native external attempt publication differs")
        if accounting._put(registry, rg, attempt.record, _raw(value)) != attempt.record:
            raise SimulatedObservationError("native attempt artifact publication differs")
        def build_attempt(snapshot):
            if snapshot != pair[1]:
                raise SimulatedObservationError("attempt checkpoint CAS failed")
            return attempt.event
        if ledger._append_locked(lg, build_attempt) != attempt.event:
            raise SimulatedObservationError("native attempt checkpoint publication differs")
        after_t = (registry._verify_all_locked(rg, raise_on_error=True), ledger._validate_bytes(ledger._read_raw_locked(lg)))
        if set(after_t[0].records) != {*pair[0].records, attempt.record} or after_t[1] != prospective_t:
            raise SimulatedObservationError("attempt checkpoint readback changed outside its exact delta")
        _final(registry, ledger, after_t, q, rg, lg, attempt)
        def build(snapshot):
            if snapshot != prospective_t:
                raise SimulatedObservationError("STARTED paired CAS failed")
            return start_event
        if ledger._append_locked(lg, build) != start_event:
            raise SimulatedObservationError("native STARTED append differs")
        after = (registry._verify_all_locked(rg, raise_on_error=True), ledger._validate_bytes(ledger._read_raw_locked(lg)))
        if after != (after_t[0], prospective):
            raise SimulatedObservationError("STARTED native readback differs")
        _final(registry, ledger, after, q, rg, lg, attempt)
    binding = _release_binding(registry, q, start_event)
    return _ResolvedConfirmatoryAdmission(
        protocol_hash=binding["protocol_hash"], code_hash=binding["code_hash"],
        evaluator_implementation_sha256=binding["evaluator_implementation_sha256"],
        configuration_hash=binding["configuration_hash"], split_manifest_hash=binding["split_manifest_hash"],
        blind_interpretation_hash=binding["blind_interpretation_hash"], ledger_run_id=binding["ledger_run_id"],
        resource_authority_sha256=binding["resource_authority_sha256"], started_event_id=start_event.event_id,
        started_event_hash=start_event.event_hash)


def _capture(registry, ledger, pair, prep, attempt, started, provider, mode, existing=None):
    q = prep.charge
    with provider.admission_guard(nonblocking=True) as snapshot:
        _snapshot(registry, q, provider, snapshot, terminal=True, started=started)
        if existing is not None:
            if snapshot.journal_bytes != existing.custody_journal_bytes or snapshot.journal_identity_sha256 != existing.custody_journal_identity_sha256:
                raise SimulatedObservationError("J terminal observation differs from current native custody")
            if pair[1].events[-1] == existing.event:
                _live(registry, ledger, pair, q, attempt=attempt)
                with _locks(registry, ledger) as (rg, lg):
                    _final(registry, ledger, pair, q, rg, lg, attempt)
                return existing
            value = accounting._selected_json(registry, pair[0].records, existing.record)
            record, event = existing.record, existing.event
        else:
            value = _j_body(registry, ledger, pair, prep, attempt, started, snapshot.journal_bytes, snapshot.journal_identity_sha256, mode, utc_now())
            record = _plan(registry, value, (prep.record.sha256, attempt.record.sha256, q.record.sha256, q.reservation.record.sha256))
            event = _event(value, record, q, pair)
        after = _publish(registry, ledger, pair, q, record, value, event, attempt=attempt)
        return _history(registry, ledger, after)[3]


def run_simulated_reserve_observation(registry, ledger, *, expected_run_id, preparation_artifact_sha256):
    """One actual guarded native attempt, or observation-only terminal recovery.

    A retained STARTED without the valid terminal never re-enters release.
    The native wrapper must return through every guard before first J capture.
    """
    root, run_id = accounting._paths(registry, ledger, expected_run_id)
    _sha(preparation_artifact_sha256)
    # Inspect under the native project lock, then let the actual native wrapper
    # reacquire and independently CAS the entire preparation before STARTED.
    with accounting._project_resource_execution_lock(root, expected_root_identity=accounting._named_directory_identity(root), nonblocking=True):
        pair = accounting._pair(registry, ledger)
        prep, attempt, started, j, state = _history(registry, ledger, pair, allow_orphan=True)
        if prep.record.sha256 != preparation_artifact_sha256 or state in ("PREPARATION_ORPHAN", "ATTEMPT_ORPHAN", "ATTEMPTED"):
            raise SimulatedObservationError("selected preparation is absent or incomplete")
        q = prep.charge
        _live(registry, ledger, pair, q, attempt=attempt)
        provider = _provider(registry, q, existing=True)
        if state != "PREPARED":
            return _capture(registry, ledger, pair, prep, attempt, started, provider, _CAPTURE_MODES[1], j)
        native.SimulatedHoldoutCustody.seal(provider, q.reservation.evaluator_payload, **_seal_fields(registry, q),
            sealed_at=provider._seal.sealed_at, nonblocking=True)
        started = _started(registry, prep, utc_now())
    manager = RecoveryManager(root)
    # No caller booleans, result, runtime, evaluator callback or scientific
    # review artifact crosses this path. Native admission rederives all fields.
    native_result = RecoveryManager.run_non_evidentiary_simulated_fixture(
        manager, ledger_path=ledger.relative_path, study_version=StudyVersion(q.reservation.protocol),
        fresh_custody_evidence=FreshCustodyEvidence(prep.record.sha256, prep.record.record_hash, prep.event.event_id),
        reveal_authority=SimulatedReserveRevealSelection(RegisteredArtifactSelector(q.reservation.record.sha256, q.reservation.record.record_hash), RegisteredArtifactSelector(q.record.sha256, q.record.record_hash)),
        artifact_registry=registry, custody_provider=provider, validity_snapshot=_budget(q), start_event=started,
        evaluator_spec=native.ConfirmatoryEvaluatorSpec(), requester=REQUESTER, reason=REASON, requested_at=started.timestamp,
    )
    with accounting._project_resource_execution_lock(root, expected_root_identity=accounting._named_directory_identity(root), nonblocking=True):
        pair = accounting._pair(registry, ledger)
        owned_p, owned_attempt, owned_start, existing, state = _history(registry, ledger, pair, allow_orphan=True)
        if owned_p.record != prep.record or owned_start != started or state != "STARTED" or existing is not None:
            raise SimulatedObservationError("native release returned after a different local suffix")
        observation = _capture(registry, ledger, pair, owned_p, owned_attempt, owned_start, provider, _CAPTURE_MODES[0])
        expected = safe_json_loads(observation.result_bytes)
        if native_result[0].release_id != safe_json_loads(registry.get_bytes(observation.record.sha256))["native_release_id"] or _raw(native_result[1]) != _raw(expected):
            raise SimulatedObservationError("returned native release result differs from J")
        return observation


def require_simulated_reserve_observation(registry, ledger, *, expected_run_id, observation_artifact_sha256):
    """Require completed J1 plus current exact native custody/accounting inputs."""
    root, _run = accounting._paths(registry, ledger, expected_run_id)
    _sha(observation_artifact_sha256)
    with accounting._project_resource_execution_lock(root, expected_root_identity=accounting._named_directory_identity(root), nonblocking=True):
        pair = accounting._pair(registry, ledger)
        prep, attempt, started, j, state = _history(registry, ledger, pair)
        if state != "COMPLETE" or j.record.sha256 != observation_artifact_sha256:
            raise SimulatedObservationError("selected J is not exact completed observation")
        return _capture(registry, ledger, pair, prep, attempt, started, _provider(registry, prep.charge, existing=True), j.capture_mode, j)
