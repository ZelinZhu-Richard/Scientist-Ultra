"""Pinned, non-evidentiary resource initialization and confirmatory accounting.

The external native resource chain retains the original initialization across
run-tree rollback. This is not whole-project rollback protection, independent
custody, scientific freshness, or proof that inventoried code was executed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import re

from .artifacts import (
    ArtifactRecord,
    ArtifactRegistry,
    RegistryValidationResult,
    MAX_REGISTRY_RECORDS,
)
from .evaluation_contract_amendment import (
    _registry_record_map,
    _registry_map_fingerprint,
    _require_current_evaluation_contract_lineage,
)
from .errors import UnsafeSerializationError
from .ledger import (
    EventLedger,
    LedgerEvent,
    LedgerValidationResult,
    MAX_LEDGER_BYTES,
    MAX_LEDGER_EVENTS,
)
from .models import MacroState, utc_now, validate_sha256
from .orchestrator import (
    _project_resource_execution_lock,
    _named_directory_identity,
    _persist_resource_authority_for,
    _read_resource_authority_records,
    _resource_authority_descriptors_for,
    _source_inventory,
    _configuration_inventory,
    _require_frozen_inventory_payload,
    _validate_monotonic_runtime_states,
    _validate_resource_authority_ledger_for,
)
from .protocol import ResearchProtocol
from .resources import (
    ResourceConfig,
    ResourceController,
    ResourceRuntimeState,
    resource_config_sha256,
)
from .roles import Role
from .scientific_design import (
    EvaluationContract,
    _locked_checked_result_authority_snapshot,
)
from .security import (
    canonical_json_bytes,
    safe_json_loads,
    sha256_bytes,
    read_confined_bytes,
    secure_directory,
)
from .simulated_reserve import (
    SIMULATED_RESERVE_PROFILE,
    _pinned_population,
    _sources,
    _source_pair,
    _validate_inventory,
    _one,
    _time,
    _markers,
    SimulatedReservePublication,
    RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA,
    MAX_SIMULATED_RESERVE_BYTES,
    _require_simulated_confirmatory_reserve_at_snapshot,
)


SIMULATED_RESOURCE_INITIAL_SCHEMA = "sim-resource-initial/v1"
SIMULATED_RESOURCE_INITIAL_EVENT_SCHEMA = "sim-resource-initial-event/v1"
SIMULATED_RESOURCE_INITIAL_EVENT_KEY = "simulated_resource_initialization"
SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE = "resource_runtime_initial"
SIMULATED_RESOURCE_INITIAL_ORIGIN = "source-owned simulated resource initialization"
SIMULATED_RESOURCE_INVENTORY_ORIGIN = (
    "source-owned simulated resource initialization inventory"
)
SIMULATED_RESOURCE_INITIAL_COMMAND = ("scientist-one", "initialize-simulated-resource")
_EVENT_PREFIX = "sim-resource-initial-"
_MAX_BYTES = 1024 * 1024
_INVENTORIES = (
    ("frozen_source_inventory", "FROZEN_SOURCE_INVENTORY", None, _source_inventory),
    (
        "frozen_configuration_inventory",
        "FROZEN_CONFIGURATION_INVENTORY",
        "configs/resource_limits.json",
        _configuration_inventory,
    ),
)
_SCOPE = {
    "evidence_class": "NON_EVIDENTIARY",
    "independence": "NON_INDEPENDENT",
    "scientific_authority": False,
    "release_authority": False,
    "execution_attestation": False,
    "freshness_authority": False,
    "e4_authority": False,
    "rollback_scope": "RUN_TREE_ONLY_NOT_WHOLE_PROJECT",
}


class SimulatedResourceError(ValueError):
    """The closed simulated initialization cannot be established."""


@dataclass(frozen=True, slots=True)
class SimulatedResourceInitialization:
    record: ArtifactRecord
    event: LedgerEvent
    event_index: int
    protocol_record: ArtifactRecord
    protocol: ResearchProtocol
    contract_record: ArtifactRecord
    contract: EvaluationContract
    population_record: ArtifactRecord
    frozen_source_inventory_record: ArtifactRecord
    frozen_configuration_inventory_record: ArtifactRecord
    config: ResourceConfig
    runtime_state_bytes: bytes
    external_authority_bytes: bytes
    external_authority_sha256: str
    source_registry_identities: tuple[tuple[str, str], ...]
    source_registry_count: int
    source_registry_fingerprint: str
    source_ledger_event_count: int
    source_ledger_head_hash: str | None
    registry_snapshot: RegistryValidationResult
    ledger_snapshot: LedgerValidationResult

    @property
    def runtime_state(self) -> ResourceRuntimeState:
        # Native state's worker_crashes is a mutable mapping. Return a detached
        # typed projection; authoritative bytes in this result stay immutable.
        return ResourceRuntimeState.from_mapping(
            safe_json_loads(self.runtime_state_bytes)
        )


def _raw(value):
    return canonical_json_bytes(value) + b"\n"


def canonical_simulated_resource_run_id() -> str:
    population_sha = sha256_bytes(_raw(_pinned_population()))
    identity = sha256_bytes(
        canonical_json_bytes(
            {
                "profile": SIMULATED_RESERVE_PROFILE,
                "population_artifact_sha256": population_sha,
            }
        )
    )
    return "sim-reserve-" + identity[:48]


def _paths(registry, ledger=None, run_id=None):
    canonical = canonical_simulated_resource_run_id()
    native_path = type(Path())
    if (
        type(registry) is not ArtifactRegistry
        or type(registry.base_path) is not native_path
        or type(registry.policy.root) is not native_path
        or registry.base_path != Path("runs") / canonical / "registry"
    ):
        raise SimulatedResourceError(
            "initialization requires its canonical native registry"
        )
    if ledger is not None and (
        type(ledger) is not EventLedger
        or type(ledger.relative_path) is not native_path
        or type(ledger.policy.root) is not native_path
        or ledger.policy.root != registry.policy.root
        or ledger.relative_path != Path("runs") / canonical / "events.jsonl"
        or type(run_id) is not str
        or run_id != canonical
    ):
        raise SimulatedResourceError(
            "initialization requires its canonical run and ledger"
        )
    return registry.policy.root, canonical


def _pair(registry, ledger, *, ensure=False):
    return _locked_checked_result_authority_snapshot(
        registry, ledger, ensure_storage=ensure
    )


def _plan(
    registry,
    value,
    *,
    at,
    logical_type=SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE,
    parents=(),
    inventory=False,
):
    raw = _raw(value)
    if len(raw) > _MAX_BYTES:
        raise SimulatedResourceError(
            "initialization object exceeds native record capacity"
        )
    safe_json_loads(raw, max_bytes=_MAX_BYTES)
    digest = sha256_bytes(raw)
    return ArtifactRecord(
        sha256=digest,
        path=registry._object_relative(digest).as_posix(),
        relative_path=registry._object_relative(digest).as_posix(),
        metadata_path=registry._metadata_relative(digest).as_posix(),
        logical_type=logical_type,
        schema_version="1.0" if inventory else SIMULATED_RESOURCE_INITIAL_SCHEMA,
        mime_type="application/json",
        size=len(raw),
        origin=SIMULATED_RESOURCE_INVENTORY_ORIGIN
        if inventory
        else SIMULATED_RESOURCE_INITIAL_ORIGIN,
        creator_role=Role.ORCHESTRATOR,
        creation_command=SIMULATED_RESOURCE_INITIAL_COMMAND,
        parent_artifacts=parents,
        validation_result="PASS",
        frozen=True,
        created_at=at,
    )


def _put(registry, guard, record, raw):
    return registry._put_bytes_locked(
        guard,
        raw,
        logical_type=record.logical_type,
        origin=record.origin,
        creator_role=record.creator_role,
        creation_command=record.creation_command,
        parent_artifacts=record.parent_artifacts,
        schema_version=record.schema_version,
        mime_type=record.mime_type,
        validation_result="PASS",
        frozen=True,
        created_at=record.created_at,
    )


def _selected_json(registry, records, record):
    # Existing lock-free selected-byte owner checks exact metadata, SHA, size,
    # confined path and native file identities without widening the population.
    from .seed_reporting import _selected_payload_bytes

    if record.size > _MAX_BYTES:
        raise SimulatedResourceError("selected initialization source exceeds capacity")
    raw = _selected_payload_bytes(registry, records, record)
    value = safe_json_loads(raw, max_bytes=_MAX_BYTES)
    if type(value) is not dict or raw != _raw(value):
        raise SimulatedResourceError(
            "selected initialization source is not canonical JSON"
        )
    return value


def _inventory(registry, records, record, index, *, live):
    name, kind, required, owner = _INVENTORIES[index]
    value = _selected_json(registry, records, record)
    _require_frozen_inventory_payload(value, kind=kind, required_path=required)
    if record != _plan(
        registry, value, at=record.created_at, logical_type=name, inventory=True
    ):
        raise SimulatedResourceError("initialization inventory provenance differs")
    if live and owner(registry.policy.root) != value:
        raise SimulatedResourceError(
            "live source/configuration inventory differs from frozen bytes"
        )
    return value


def _inventory_slots(registry, records):
    """Select native metadata/body aliases before trusting a family hint."""
    from .seed_reporting import _selected_payload_bytes

    names = {item[0] for item in _INVENTORIES}
    kinds = {item[1]: item[0] for item in _INVENTORIES}
    result = {name: [] for name in names}
    for record in records:
        selected = {record.logical_type} & names
        if record.size <= _MAX_BYTES:
            raw = _selected_payload_bytes(registry, records, record)
            try:
                value = safe_json_loads(raw)
            except ValueError:
                if any(
                    canonical_json_bytes(marker) in raw for marker in (*names, *kinds)
                ):
                    raise SimulatedResourceError(
                        "malformed inventory alias is unresolved"
                    )
                value = None
            _keys, _refs, schemas, types = _markers(value)
            selected.update(names.intersection(types))
            selected.update(kinds[kind] for kind in schemas.intersection(kinds))
        if record.origin == SIMULATED_RESOURCE_INVENTORY_ORIGIN and not selected:
            raise SimulatedResourceError("inventory producer alias has no exact family")
        if len(selected) > 1:
            raise SimulatedResourceError(
                "inventory alias has conflicting family markers"
            )
        for name in selected:
            result[name].append(record)
    return {key: tuple(value) for key, value in result.items()}


def register_simulated_resource_initial_inventories(
    registry: ArtifactRegistry,
) -> tuple[ArtifactRecord, ArtifactRecord]:
    """Freeze actual files; no execution attestation or resource authority."""
    root, _run = _paths(registry)
    with _project_resource_execution_lock(
        root, expected_root_identity=_named_directory_identity(root)
    ):
        before = registry.verify_all(raise_on_error=True)
        slots = _inventory_slots(registry, before.records)
        values = tuple(owner(root) for _name, _kind, _required, owner in _INVENTORIES)
        planned = []
        for index, (name, _kind, _required, _owner) in enumerate(_INVENTORIES):
            digest = sha256_bytes(_raw(values[index]))
            matches = tuple(
                dict.fromkeys(
                    (
                        *slots[name],
                        *(
                            record
                            for record in before.records
                            if record.sha256 == digest
                        ),
                    )
                )
            )
            if len(matches) > 1:
                raise SimulatedResourceError(
                    "initialization inventory slot is ambiguous"
                )
            at = matches[0].created_at if matches else utc_now()
            record = _plan(
                registry, values[index], at=at, logical_type=name, inventory=True
            )
            if matches and matches != (record,):
                raise SimulatedResourceError(
                    "initialization inventory slot cannot be rebound"
                )
            planned.append(record)
        missing = tuple(record for record in planned if record not in before.records)
        if before.count + len(missing) > MAX_REGISTRY_RECORDS:
            raise SimulatedResourceError(
                "inventory publication exceeds registry capacity"
            )
        guard = registry._open_mutation_lock()
        try:
            if registry._verify_all_locked(guard, raise_on_error=True) != before:
                raise SimulatedResourceError(
                    "inventory population changed before publication"
                )
            if tuple(owner(root) for _n, _k, _p, owner in _INVENTORIES) != values:
                raise SimulatedResourceError(
                    "inventory files changed before publication"
                )
            for record, value in zip(planned, values, strict=True):
                if (
                    record in missing
                    and _put(registry, guard, record, _raw(value)) != record
                ):
                    raise SimulatedResourceError(
                        "inventory publication metadata changed"
                    )
            after = registry._verify_all_locked(guard, raise_on_error=True)
            if (
                set(after.records) != {*before.records, *planned}
                or tuple(owner(root) for _n, _k, _p, owner in _INVENTORIES) != values
            ):
                raise SimulatedResourceError("inventory publication readback changed")
        finally:
            registry._unlock_mutation(guard)
        return tuple(planned)


def _sources_for(registry, ledger, pair, request, *, live):
    if pair[1].events:
        raise SimulatedResourceError("initialization source prefix must be empty")
    sources = _sources(
        registry,
        ledger,
        pair,
        run_id=canonical_simulated_resource_run_id(),
        protocol_sha=request["protocol_artifact_sha256"],
        contract_sha=request["contract_artifact_sha256"],
        population_sha=request["population_artifact_sha256"],
        index=1,
        prior_sha=None,
    )
    _validate_inventory(registry, ledger, pair, allowed=(), source_owners=sources[9])
    inventory_records = tuple(
        _one(pair[0].records, request[key])
        for key in (
            "frozen_source_inventory_artifact_sha256",
            "frozen_configuration_inventory_artifact_sha256",
        )
    )
    inventories = tuple(
        _inventory(registry, pair[0].records, record, index, live=live)
        for index, record in enumerate(inventory_records)
    )
    slots = _inventory_slots(registry, pair[0].records)
    for index, (name, _kind, _path, _owner) in enumerate(_INVENTORIES):
        if slots[name] != (inventory_records[index],):
            raise SimulatedResourceError(
                "initialization inventory has an ambiguous native slot"
            )
    return sources, inventory_records, inventories


def _config(root, inventories, encoded=None):
    if encoded is None:
        raw = read_confined_bytes(
            root,
            "configs/resource_limits.json",
            reject_hardlinks=True,
            max_bytes=_MAX_BYTES,
        )
        if raw is None:
            raise SimulatedResourceError("resource configuration disappeared")
    else:
        if type(encoded) is not str:
            raise SimulatedResourceError("captured configuration bytes are malformed")
        raw = encoded.encode("utf-8", errors="strict")
    entry = next(
        item
        for item in inventories[1]["entries"]
        if item["path"] == "configs/resource_limits.json"
    )
    if len(raw) > _MAX_BYTES or (sha256_bytes(raw), len(raw)) != (
        entry["sha256"],
        entry["size"],
    ):
        raise SimulatedResourceError(
            "resource config bytes differ from frozen inventory"
        )
    config = ResourceConfig.from_mapping(safe_json_loads(raw))
    if config.validity_reserve_fraction != 0.4:
        raise SimulatedResourceError(
            "pinned resource initialization requires fraction 0.4"
        )
    return config, raw.decode("utf-8", errors="strict")


def _body(
    registry,
    ledger,
    source,
    request,
    sources,
    inventories,
    config,
    configuration_utf8,
    state,
    at,
):
    count, fingerprint = _registry_map_fingerprint(source[0].records)
    return {
        "schema_version": SIMULATED_RESOURCE_INITIAL_SCHEMA,
        "kind": "SIMULATED_RESOURCE_INITIALIZATION",
        "profile": SIMULATED_RESERVE_PROFILE,
        "ledger_run_id": canonical_simulated_resource_run_id(),
        "registry_path": registry.base_path.as_posix(),
        "ledger_path": ledger.relative_path.as_posix(),
        "recorded_at": at,
        **request,
        "protocol_record_hash": sources[0].record_hash,
        "protocol_sha256": sources[1].sha256,
        "contract_record_hash": sources[2].record_hash,
        "contract_sha256": sources[3].sha256,
        "population_record_hash": sources[4].record_hash,
        "frozen_source_inventory_record_hash": inventories[0].record_hash,
        "frozen_configuration_inventory_record_hash": inventories[1].record_hash,
        "source_registry_identities": [
            list(item) for item in _registry_record_map(source[0].records)
        ],
        "source_registry_count": count,
        "source_registry_fingerprint": fingerprint,
        "source_ledger_event_count": 0,
        "source_ledger_head_hash": None,
        "resource_config": config.to_dict(),
        "resource_config_sha256": resource_config_sha256(config),
        "resource_configuration_utf8": configuration_utf8,
        "runtime_state": state.to_dict(),
        "validity_total_units": 40,
        "validity_reserve_fraction": 0.4,
        **_SCOPE,
    }


_REQUEST_KEYS = (
    "protocol_artifact_sha256",
    "contract_artifact_sha256",
    "population_artifact_sha256",
    "frozen_source_inventory_artifact_sha256",
    "frozen_configuration_inventory_artifact_sha256",
)


def _request(value):
    result = {key: value[key] for key in _REQUEST_KEYS}
    for digest in result.values():
        if type(digest) is not str:
            raise SimulatedResourceError("initialization identity must be native text")
        validate_sha256(digest, "initialization source")
    return result


def _authority(value):
    result = {
        "schema_version": "1.0",
        "kind": "RESOURCE_RUNTIME_AUTHORITY",
        "run_id": canonical_simulated_resource_run_id(),
        "sequence": 0,
        "logical_type": SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE,
        "state_sha256": sha256_bytes(_raw(value)),
        "state": value,
        "prior_authority_sha256": None,
    }
    if len(_raw(result)) > _MAX_BYTES:
        raise SimulatedResourceError(
            "initialization external envelope exceeds native capacity"
        )
    return result


def _event(value, record, inventory_values):
    authority = _authority(value)
    descriptor = _resource_authority_descriptors_for((authority,))[0]
    return LedgerEvent.create(
        run_id=value["ledger_run_id"],
        event_id=_EVENT_PREFIX + record.sha256[:40],
        timestamp=value["recorded_at"],
        actor_role=Role.ORCHESTRATOR,
        state_before=MacroState.CALIBRATE,
        requested_state_after=MacroState.CALIBRATE,
        artifact_hashes=(record.sha256,),
        code_version=inventory_values[0]["aggregate_sha256"],
        configuration_hash=inventory_values[1]["aggregate_sha256"],
        dataset_identifiers=(),
        random_seeds=(),
        evaluator_outputs=(),
        reason="initialized forty simulated accounting units without release or scientific authority",
        prior_event_hash=None,
        event_type="CHECKPOINT",
        metadata={
            "artifact_types": [record.logical_type],
            "artifact_record_hashes": [record.record_hash],
            "resource_authority_checkpoint": descriptor,
            SIMULATED_RESOURCE_INITIAL_EVENT_KEY: {
                "schema_version": SIMULATED_RESOURCE_INITIAL_EVENT_SCHEMA,
                "initialization_artifact_sha256": record.sha256,
                "initialization_record_hash": record.record_hash,
                "profile": SIMULATED_RESERVE_PROFILE,
                **_SCOPE,
            },
        },
    )


def _candidate_records(registry, records):
    selected = []
    reserved = {
        SIMULATED_RESOURCE_INITIAL_SCHEMA,
        SIMULATED_RESOURCE_INITIAL_EVENT_SCHEMA,
        "SIMULATED_RESOURCE_INITIALIZATION",
    }
    for record in records:
        native = (
            record.logical_type.startswith("resource_runtime_")
            or record.schema_version in reserved
            or record.origin == SIMULATED_RESOURCE_INITIAL_ORIGIN
            or (
                record.creation_command == SIMULATED_RESOURCE_INITIAL_COMMAND
                and record.logical_type not in {item[0] for item in _INVENTORIES}
            )
        )
        if record.size <= _MAX_BYTES:
            from .seed_reporting import _selected_payload_bytes

            raw = _selected_payload_bytes(registry, records, record)
            try:
                value = safe_json_loads(raw)
            except ValueError:
                if any(
                    canonical_json_bytes(marker) in raw
                    for marker in (
                        *reserved,
                        SIMULATED_RESOURCE_INITIAL_EVENT_KEY,
                        SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE,
                    )
                ):
                    raise SimulatedResourceError(
                        "malformed initialization alias is unresolved"
                    )
                value = None
            keys, _refs, schemas, types = _markers(value)
            native |= bool(
                reserved.intersection(schemas)
                or keys.intersection(
                    {
                        SIMULATED_RESOURCE_INITIAL_EVENT_KEY,
                        "resource_authority_checkpoint",
                        "resource_authority_chain",
                    }
                )
                or any(item.startswith("resource_runtime_") for item in types)
            )
        if native:
            selected.append(record)
    return tuple(selected)


def _reconstruct(registry, ledger, pair, value, *, live):
    request = _request(value)
    source = _source_pair(pair, value)
    sources, inventory_records, inventory_values = _sources_for(
        registry, ledger, source, request, live=live
    )
    config, configuration_utf8 = _config(
        registry.policy.root, inventory_values, value["resource_configuration_utf8"]
    )
    if sources[1].validity_reserve_fraction != config.validity_reserve_fraction:
        raise SimulatedResourceError(
            "protocol reserve fraction differs from the pinned resource configuration"
        )
    if live and _config(registry.policy.root, inventory_values) != (
        config,
        configuration_utf8,
    ):
        raise SimulatedResourceError("live resource config differs from original bytes")
    state = ResourceRuntimeState.from_mapping(value["runtime_state"])
    if (
        state.run_id != canonical_simulated_resource_run_id()
        or state.config_sha256 != resource_config_sha256(config)
        or state.validity_total_units != 40
        or state.exploratory_used != 0
        or state.confirmatory_used != 0
        or state.worker_crashes
        or state.wall_elapsed_seconds != 0
        or state.checkpoint_elapsed_seconds != 0
        or state.progress_elapsed_seconds != 0
        or state.wall_started_at_epoch_seconds <= 0
        or state.wall_started_at_epoch_seconds != state.wall_observed_at_epoch_seconds
    ):
        raise SimulatedResourceError(
            "initialization is not the exact original zero-use state"
        )
    at = value["recorded_at"]
    if any(_time(record.created_at) > _time(at) for record in source[0].records):
        raise SimulatedResourceError("initialization timestamp predates its sources")
    if state.wall_started_at_epoch_seconds > _time(at).timestamp():
        raise SimulatedResourceError(
            "initialization state clock exceeds its publication"
        )
    expected = _body(
        registry,
        ledger,
        source,
        request,
        sources,
        inventory_records,
        config,
        configuration_utf8,
        state,
        at,
    )
    if _raw(expected) != _raw(value):
        raise SimulatedResourceError("initialization closed payload is substituted")
    record = _plan(registry, value, at=at, parents=tuple(request.values()))
    event = _event(value, record, inventory_values)
    return source, sources, inventory_records, config, record, event


def _result(pair, value, sources, inventories, config, record, event):
    authority_raw = _raw(_authority(value))
    return SimulatedResourceInitialization(
        record,
        event,
        0,
        *sources[:5],
        *inventories,
        config,
        _raw(value["runtime_state"]),
        authority_raw,
        sha256_bytes(authority_raw),
        tuple(tuple(item) for item in value["source_registry_identities"]),
        value["source_registry_count"],
        value["source_registry_fingerprint"],
        0,
        None,
        *pair,
    )


def _initialization_payload_selected(value, references):
    """Finite I markers; the shared reserve profile alone is not an I marker."""
    keys, refs, schemas, types = _markers(value)
    return bool(
        keys.intersection(
            {
                SIMULATED_RESOURCE_INITIAL_EVENT_KEY,
                "initialization_artifact_sha256",
                "initialization_record_hash",
            }
        )
        or schemas.intersection(
            {
                SIMULATED_RESOURCE_INITIAL_SCHEMA,
                SIMULATED_RESOURCE_INITIAL_EVENT_SCHEMA,
                "SIMULATED_RESOURCE_INITIALIZATION",
            }
        )
        or SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE in types
        or references.intersection(refs)
    )


def _consume_initialization_selection(registry, pair, *, record, event, inventories):
    """Check the supplied OUTER selection, not merely the sealed pre-I map.

    This is not a later-stage authority parser. Other resource families and
    native parent-I ancestry alone do not identify another initialization.
    Explicit I publication markers or unsupported I-reference events do.
    """
    from .seed_reporting import _selected_payload_bytes

    references = frozenset((record.sha256, record.record_hash))
    raw_markers = (
        SIMULATED_RESOURCE_INITIAL_SCHEMA,
        SIMULATED_RESOURCE_INITIAL_EVENT_SCHEMA,
        SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE,
        SIMULATED_RESOURCE_INITIAL_EVENT_KEY,
        "SIMULATED_RESOURCE_INITIALIZATION",
        "initialization_artifact_sha256",
        "initialization_record_hash",
    )
    for candidate in pair[0].records:
        if candidate == record or candidate in inventories:
            continue
        # Full historical ownership cannot silently omit an unconsumed object.
        # Reuse S's existing bounded census; I/Q publication remains1MiB.
        if candidate.size > MAX_SIMULATED_RESERVE_BYTES:
            raise SimulatedResourceError(
                "selected initialization history exceeds complete alias scan capacity"
            )
        selected = (
            candidate.logical_type == SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE
            or candidate.schema_version in raw_markers[:2]
            or candidate.origin == SIMULATED_RESOURCE_INITIAL_ORIGIN
            or candidate.creation_command == SIMULATED_RESOURCE_INITIAL_COMMAND
        )
        if candidate.size <= MAX_SIMULATED_RESERVE_BYTES:
            raw = _selected_payload_bytes(registry, pair[0].records, candidate)
            try:
                value = safe_json_loads(
                    raw, max_bytes=MAX_SIMULATED_RESERVE_BYTES, max_items=100_000
                )
            except (ValueError, UnsafeSerializationError):
                selected |= any(
                    canonical_json_bytes(marker) in raw for marker in raw_markers
                )
            else:
                selected |= _initialization_payload_selected(value, references)
        if selected:
            raise SimulatedResourceError(
                "selected history contains an unconsumed initialization record alias"
            )
    for index, candidate in enumerate(pair[1].events):
        if index == 0 and candidate == event:
            continue
        if (
            candidate.event_id.startswith(_EVENT_PREFIX)
            or candidate.event_id == event.event_id
            or references.intersection(candidate.artifact_hashes)
            or _initialization_payload_selected(candidate.metadata, references)
        ):
            raise SimulatedResourceError(
                "selected history contains an unconsumed initialization event alias"
            )


def _require_simulated_resource_initialization_at_snapshot(
    registry,
    ledger,
    *,
    expected_run_id,
    initialization_artifact_sha256,
    registry_snapshot,
    ledger_snapshot,
):
    """Full historical I owner; no live tail, external/currentness or permission."""
    _paths(registry, ledger, expected_run_id)
    if type(initialization_artifact_sha256) is not str:
        raise SimulatedResourceError(
            "historical initialization identity must be native text"
        )
    validate_sha256(
        initialization_artifact_sha256, "historical initialization artifact"
    )
    if (
        type(registry_snapshot) is not RegistryValidationResult
        or type(ledger_snapshot) is not LedgerValidationResult
        or not registry_snapshot.valid
        or not ledger_snapshot.valid
    ):
        raise SimulatedResourceError(
            "historical initialization requires valid native selected sources"
        )
    pair = registry_snapshot, ledger_snapshot
    record = _one(registry_snapshot.records, initialization_artifact_sha256)
    value = _selected_json(registry, registry_snapshot.records, record)
    source, sources, inventories, config, expected, event = _reconstruct(
        registry, ledger, pair, value, live=False
    )
    if (
        record in source[0].records
        or record != expected
        or not ledger_snapshot.events
        or ledger_snapshot.events[0] != event
    ):
        raise SimulatedResourceError("initialization record or event zero differs")
    if any(
        item.supersedes_event_id == event.event_id for item in ledger_snapshot.events
    ):
        raise SimulatedResourceError(
            "corrected initialization has no current-use authority"
        )
    _consume_initialization_selection(
        registry, pair, record=record, event=event, inventories=inventories
    )
    return _result(pair, value, sources, inventories, config, record, event)


def _require_locked(registry, ledger, run_id, digest):
    before = _pair(registry, ledger)
    result = _require_simulated_resource_initialization_at_snapshot(
        registry,
        ledger,
        expected_run_id=run_id,
        initialization_artifact_sha256=digest,
        registry_snapshot=before[0],
        ledger_snapshot=before[1],
    )
    value = _selected_json(registry, before[0].records, result.record)
    source, *_rest = _reconstruct(registry, ledger, before, value, live=True)
    external = _read_resource_authority_records(registry.policy.root, run_id)
    if (
        external != (_authority(value),)
        or before[1].events != (result.event,)
        or set(before[0].records) != {*source[0].records, result.record}
        or _candidate_records(registry, before[0].records) != (result.record,)
    ):
        raise SimulatedResourceError(
            "initialization current population or external head differs"
        )
    # One final registry -> ledger critical section binds the same paired
    # population, live inventories and external head. The project lock remains
    # outermost; no public source owner is entered under these inner locks.
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            final = (
                registry._verify_all_locked(registry_guard, raise_on_error=True),
                ledger._validate_bytes(ledger._read_raw_locked(ledger_guard)),
            )
            if (
                final != before
                or _read_resource_authority_records(registry.policy.root, run_id)
                != external
            ):
                raise SimulatedResourceError("initialization readback changed")
            for index, inventory_record in enumerate(
                (
                    result.frozen_source_inventory_record,
                    result.frozen_configuration_inventory_record,
                )
            ):
                _inventory(
                    registry, source[0].records, inventory_record, index, live=True
                )
            final_external = _read_resource_authority_records(
                registry.policy.root, run_id
            )
            final = (
                registry._verify_all_locked(registry_guard, raise_on_error=True),
                ledger._validate_bytes(ledger._read_raw_locked(ledger_guard)),
            )
            if final != before or final_external != external:
                raise SimulatedResourceError(
                    "initialization sources changed during final live readback"
                )
            registry._verify_mutation_namespace(registry_guard)
            ledger._verify_lock_namespace(ledger_guard)
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    return result


def require_simulated_resource_initialization(
    registry, ledger, *, expected_run_id, initialization_artifact_sha256
):
    root, _run = _paths(registry, ledger, expected_run_id)
    if type(initialization_artifact_sha256) is not str:
        raise SimulatedResourceError("initialization identity must be native text")
    validate_sha256(initialization_artifact_sha256, "initialization artifact")
    with _project_resource_execution_lock(
        root, expected_root_identity=_named_directory_identity(root)
    ):
        return _require_locked(
            registry, ledger, expected_run_id, initialization_artifact_sha256
        )


def initialize_simulated_resource_authority(
    registry,
    ledger,
    *,
    expected_run_id,
    protocol_artifact_sha256,
    contract_artifact_sha256,
    population_artifact_sha256,
    frozen_source_inventory_artifact_sha256,
    frozen_configuration_inventory_artifact_sha256,
):
    """External-first native I0; recover only its exact missing local suffix."""
    request = _request(locals())
    root, run_id = _paths(registry, ledger, expected_run_id)
    with _project_resource_execution_lock(
        root, expected_root_identity=_named_directory_identity(root)
    ):
        before = _pair(registry, ledger, ensure=True)
        relative = Path(".scientist-one-build/resource-authority") / run_id
        secure_directory(root, relative, create=True)
        external = _read_resource_authority_records(root, run_id)
        candidates = _candidate_records(registry, before[0].records)
        if external:
            if (
                len(external) != 1
                or external[0]["logical_type"]
                != SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE
            ):
                raise SimulatedResourceError(
                    "initialization cannot replace an existing external history"
                )
            value = external[0]["state"]
            if (
                value.get("schema_version") != SIMULATED_RESOURCE_INITIAL_SCHEMA
                or _request(value) != request
            ):
                raise SimulatedResourceError(
                    "external initialization belongs to a different profile or request"
                )
            source, sources, inventories, config, record, event = _reconstruct(
                registry, ledger, before, value, live=True
            )
            if candidates not in ((), (record,)) or external != (_authority(value),):
                raise SimulatedResourceError(
                    "initialization external/local state differs"
                )
            if before[1].events:
                return _require_locked(registry, ledger, run_id, record.sha256)
            if set(before[0].records) != {*source[0].records, *candidates}:
                raise SimulatedResourceError(
                    "initialization orphan cannot recover after source drift"
                )
        else:
            if candidates or before[1].events:
                raise SimulatedResourceError(
                    "local prior work cannot create a new external initialization"
                )
            source = before
            sources, inventories, inventory_values = _sources_for(
                registry, ledger, source, request, live=True
            )
            config, configuration_utf8 = _config(root, inventory_values)
            state = ResourceController(
                config, root, validity_budget_units=40, run_id=run_id
            ).export_state()
            value = _body(
                registry,
                ledger,
                source,
                request,
                sources,
                inventories,
                config,
                configuration_utf8,
                state,
                utc_now(),
            )
            source, sources, inventories, config, record, event = _reconstruct(
                registry, ledger, before, value, live=True
            )
        current = _require_current_evaluation_contract_lineage(
            registry,
            ledger,
            expected_run_id=run_id,
            contract_artifact_sha256=contract_artifact_sha256,
        )
        if (current.registry_snapshot, current.ledger_snapshot) != before:
            raise SimulatedResourceError(
                "initialization current-contract sources changed"
            )
        planned_authority = _authority(value)
        event_raw = _raw(event.to_dict())
        missing = record not in before[0].records
        if (
            before[0].count + int(missing) > MAX_REGISTRY_RECORDS
            or before[1].event_count + 1 > MAX_LEDGER_EVENTS
            or before[1].valid_prefix_bytes + len(event_raw) > MAX_LEDGER_BYTES
        ):
            raise SimulatedResourceError(
                "initialization lacks paired publication capacity"
            )
        registry_guard = registry._open_mutation_lock()
        try:
            ledger_guard = ledger._open_lock()
            try:
                locked = (
                    registry._verify_all_locked(registry_guard, raise_on_error=True),
                    ledger._validate_bytes(ledger._read_raw_locked(ledger_guard)),
                )
                if (
                    locked != before
                    or _read_resource_authority_records(root, run_id) != external
                ):
                    raise SimulatedResourceError(
                        "initialization paired/external preimage changed"
                    )
                prospective = ledger._validate_bytes(
                    ledger._read_raw_locked(ledger_guard) + event_raw
                )
                if not prospective.valid or prospective.events != (
                    *before[1].events,
                    event,
                ):
                    raise SimulatedResourceError(
                        "initialization prospective event is not one exact append"
                    )
                # Recheck actual files while holding the pair; these helpers do
                # not acquire registry/ledger locks or invoke public owners.
                for index, inventory in enumerate(inventories):
                    _inventory(registry, source[0].records, inventory, index, live=True)
                persisted = _persist_resource_authority_for(
                    root, run_id, SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE, value
                )
                if persisted != planned_authority:
                    raise SimulatedResourceError(
                        "initialization external advancement differs"
                    )
                if (
                    missing
                    and _put(registry, registry_guard, record, _raw(value)) != record
                ):
                    raise SimulatedResourceError(
                        "initialization artifact publication differs"
                    )

                def build(snapshot):
                    if snapshot != before[1]:
                        raise SimulatedResourceError(
                            "initialization ledger changed during commit"
                        )
                    return event

                if ledger._append_locked(ledger_guard, build) != event:
                    raise SimulatedResourceError(
                        "initialization event publication differs"
                    )
                after = (
                    registry._verify_all_locked(registry_guard, raise_on_error=True),
                    ledger._validate_bytes(ledger._read_raw_locked(ledger_guard)),
                )
                if (
                    set(after[0].records) != {*before[0].records, record}
                    or after[1] != prospective
                    or _read_resource_authority_records(root, run_id)
                    != (planned_authority,)
                ):
                    raise SimulatedResourceError(
                        "initialization readback is not the exact planned delta"
                    )
            finally:
                ledger._unlock(ledger_guard)
        finally:
            registry._unlock_mutation(registry_guard)
        return _require_locked(registry, ledger, run_id, record.sha256)


SIMULATED_CONFIRMATORY_CHARGE_SCHEMA = "sim-resource-charge/v1"
SIMULATED_CONFIRMATORY_CHARGE_EVENT_SCHEMA = "sim-resource-charge-event/v1"
OBSERVED_SECOND_CONFIRMATORY_CHARGE_SCHEMA = "sim-resource-charge/v2"
OBSERVED_SECOND_CONFIRMATORY_CHARGE_EVENT_SCHEMA = "sim-resource-charge-event/v2"
SIMULATED_CONFIRMATORY_CHARGE_EVENT_KEY = "simulated_confirmatory_charge"
SIMULATED_CONFIRMATORY_CHARGE_LOGICAL_PREFIX = "resource_runtime_confirmatory_charge."
SIMULATED_CONFIRMATORY_CHARGE_ORIGIN = (
    "source-owned simulated confirmatory resource charge"
)
SIMULATED_CONFIRMATORY_CHARGE_COMMAND = (
    "scientist-one",
    "charge-simulated-confirmatory-reserve",
)
_CHARGE_EVENT_PREFIX = "sim-resource-charge-"
_CHARGE_KIND = "SIMULATED_CONFIRMATORY_RESOURCE_CHARGE"
_CHARGE_SCOPE = {**_SCOPE, "host_attestation": False}
_CHARGE_MARKERS = frozenset(
    {
        SIMULATED_CONFIRMATORY_CHARGE_SCHEMA,
        SIMULATED_CONFIRMATORY_CHARGE_EVENT_SCHEMA,
        OBSERVED_SECOND_CONFIRMATORY_CHARGE_SCHEMA,
        OBSERVED_SECOND_CONFIRMATORY_CHARGE_EVENT_SCHEMA,
        SIMULATED_CONFIRMATORY_CHARGE_EVENT_KEY,
        _CHARGE_KIND,
        "charge_artifact_sha256",
        "charge_record_hash",
    }
)


@dataclass(frozen=True, slots=True)
class SimulatedConfirmatoryCharge:
    record: ArtifactRecord
    event: LedgerEvent
    event_index: int
    reservation: SimulatedReservePublication
    initialization: SimulatedResourceInitialization
    runtime_state_bytes: bytes
    external_authority_bytes: bytes
    external_authority_sha256: str
    source_registry_identities: tuple[tuple[str, str], ...]
    source_ledger_event_count: int
    source_ledger_head_hash: str | None
    registry_snapshot: RegistryValidationResult
    ledger_snapshot: LedgerValidationResult

    @property
    def runtime_state(self) -> ResourceRuntimeState:
        return ResourceRuntimeState.from_mapping(
            safe_json_loads(self.runtime_state_bytes)
        )


def _charge_family(reservation_sha):
    if type(reservation_sha) is not str:
        raise SimulatedResourceError("charge reservation identity must be native text")
    validate_sha256(reservation_sha, "charge reservation")
    return SIMULATED_CONFIRMATORY_CHARGE_LOGICAL_PREFIX + reservation_sha


def _charge_payload_selected(value, references=frozenset()):
    keys, refs, schemas, types = _markers(value)
    return bool(
        keys.intersection(_CHARGE_MARKERS)
        or schemas.intersection(_CHARGE_MARKERS)
        or any(_charge_schema_selected(item) for item in schemas)
        or references.intersection(refs)
        or any(
            item == "resource_runtime_confirmatory_charge"
            or item.startswith(SIMULATED_CONFIRMATORY_CHARGE_LOGICAL_PREFIX)
            for item in types
        )
    )


def _charge_schema_selected(value):
    return isinstance(value, str) and value.startswith(("sim-resource-charge/", "sim-resource-charge-event/"))


def _charge_malformed_schema_selected(raw):
    # Bounded malformed JSON only: match a complete quoted reserved schema
    # token, not an arbitrary substring of ordinary explanatory prose.
    return re.search(rb'"sim-resource-charge(?:-event)?/[^\"]*"', raw) is not None


def _charge_candidates(registry, records):
    """Select every Q publication alias, never just the expected family suffix."""
    from .seed_reporting import _selected_payload_bytes

    selected = []
    for record in records:
        candidate = (
            record.logical_type == "resource_runtime_confirmatory_charge"
            or record.logical_type.startswith(
                SIMULATED_CONFIRMATORY_CHARGE_LOGICAL_PREFIX
            )
            or record.schema_version in _CHARGE_MARKERS
            or _charge_schema_selected(record.schema_version)
            or record.origin == SIMULATED_CONFIRMATORY_CHARGE_ORIGIN
            or record.creation_command == SIMULATED_CONFIRMATORY_CHARGE_COMMAND
        )
        # Native Q publication is at most1MiB. Its alias census retains S's
        # existing2MiB scan bound, so oversized renamed Q cannot disappear.
        if record.size <= MAX_SIMULATED_RESERVE_BYTES:
            raw = _selected_payload_bytes(registry, records, record)
            try:
                value = safe_json_loads(
                    raw, max_bytes=MAX_SIMULATED_RESERVE_BYTES, max_items=100_000
                )
            except (ValueError, UnsafeSerializationError):
                candidate |= any(
                    canonical_json_bytes(marker) in raw for marker in _CHARGE_MARKERS
                )
                candidate |= _charge_malformed_schema_selected(raw)
            else:
                candidate |= _charge_payload_selected(value)
        if candidate:
            selected.append(record)
    return tuple(selected)


def _charge_sources(registry, ledger, source, reservation_sha):
    reservation = _require_simulated_confirmatory_reserve_at_snapshot(
        registry,
        ledger,
        expected_run_id=canonical_simulated_resource_run_id(),
        reservation_artifact_sha256=reservation_sha,
        registry_snapshot=source[0],
        ledger_snapshot=source[1],
    )
    if (
        reservation.record.schema_version != RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA
        or reservation.window_index != 1
        or len(reservation.record.parent_artifacts) != 4
    ):
        raise SimulatedResourceError(
            "Q1 requires the completed resource-backed first reservation"
        )
    initialization = _require_simulated_resource_initialization_at_snapshot(
        registry,
        ledger,
        expected_run_id=canonical_simulated_resource_run_id(),
        initialization_artifact_sha256=reservation.record.parent_artifacts[3],
        registry_snapshot=source[0],
        ledger_snapshot=source[1],
    )
    sealed_s = _source_pair(
        source, _selected_json(registry, source[0].records, reservation.record)
    )
    if (
        set(source[0].records) != {*sealed_s[0].records, reservation.record}
        or source[1].events != (*sealed_s[1].events, reservation.event)
        or len(reservation.member_ids) != 8
        or initialization.record not in sealed_s[0].records
    ):
        raise SimulatedResourceError(
            "Q1 preimage is not the exact original I then S population"
        )
    return reservation, initialization


def _charge_body(registry, ledger, source, reservation, initialization, state, at):
    initial_value = _selected_json(registry, source[0].records, initialization.record)
    count, fingerprint = _registry_map_fingerprint(source[0].records)
    return {
        "schema_version": SIMULATED_CONFIRMATORY_CHARGE_SCHEMA,
        "kind": _CHARGE_KIND,
        "profile": SIMULATED_RESERVE_PROFILE,
        "ledger_run_id": canonical_simulated_resource_run_id(),
        "registry_path": registry.base_path.as_posix(),
        "ledger_path": ledger.relative_path.as_posix(),
        "recorded_at": at,
        "reservation_artifact_sha256": reservation.record.sha256,
        "reservation_record_hash": reservation.record.record_hash,
        "window_index": reservation.window_index,
        "member_ids": list(reservation.member_ids),
        "member_row_sha256s": list(reservation.member_row_sha256s),
        "evaluator_payload_sha256": reservation.evaluator_payload_sha256,
        "split_manifest_hash": reservation.split_manifest_hash,
        "previous_runtime_artifact_sha256": initialization.record.sha256,
        "previous_runtime_record_hash": initialization.record.record_hash,
        "previous_external_authority_sha256": initialization.external_authority_sha256,
        "previous_external_sequence": 0,
        "frozen_source_inventory_artifact_sha256": initialization.frozen_source_inventory_record.sha256,
        "frozen_source_inventory_record_hash": initialization.frozen_source_inventory_record.record_hash,
        "frozen_configuration_inventory_artifact_sha256": initialization.frozen_configuration_inventory_record.sha256,
        "frozen_configuration_inventory_record_hash": initialization.frozen_configuration_inventory_record.record_hash,
        "source_registry_identities": [
            list(item) for item in _registry_record_map(source[0].records)
        ],
        "source_registry_count": count,
        "source_registry_fingerprint": fingerprint,
        "source_ledger_event_count": source[1].event_count,
        "source_ledger_head_hash": source[1].head_hash,
        "resource_config": initialization.config.to_dict(),
        "resource_config_sha256": resource_config_sha256(initialization.config),
        "resource_configuration_utf8": initial_value["resource_configuration_utf8"],
        "runtime_state": state.to_dict(),
        "charged_units": len(reservation.member_ids),
        "confirmatory_used_before": initialization.runtime_state.confirmatory_used,
        "confirmatory_used_after": state.confirmatory_used,
        "validity_total_units": initialization.runtime_state.validity_total_units,
        "validity_reserve_fraction": initialization.config.validity_reserve_fraction,
        **_CHARGE_SCOPE,
    }


def _charge_plan(registry, value, initialization, reservation):
    return replace(
        _plan(
            registry,
            value,
            at=value["recorded_at"],
            logical_type=_charge_family(reservation.record.sha256),
            parents=(initialization.record.sha256, reservation.record.sha256),
        ),
        schema_version=SIMULATED_CONFIRMATORY_CHARGE_SCHEMA,
        origin=SIMULATED_CONFIRMATORY_CHARGE_ORIGIN,
        creation_command=SIMULATED_CONFIRMATORY_CHARGE_COMMAND,
        record_hash=None,
    )


def _charge_authority(value, initialization):
    result = {
        "schema_version": "1.0",
        "kind": "RESOURCE_RUNTIME_AUTHORITY",
        "run_id": canonical_simulated_resource_run_id(),
        "sequence": 1,
        "logical_type": _charge_family(value["reservation_artifact_sha256"]),
        "state_sha256": sha256_bytes(_raw(value)),
        "state": value,
        "prior_authority_sha256": initialization.external_authority_sha256,
    }
    if len(_raw(result)) > _MAX_BYTES:
        raise SimulatedResourceError("charge external envelope exceeds native capacity")
    return result


def _charge_event(registry, source, value, record, initialization):
    inventories = tuple(
        _inventory(registry, source[0].records, item, index, live=False)
        for index, item in enumerate(
            (
                initialization.frozen_source_inventory_record,
                initialization.frozen_configuration_inventory_record,
            )
        )
    )
    authority = _charge_authority(value, initialization)
    descriptor = _resource_authority_descriptors_for(
        (safe_json_loads(initialization.external_authority_bytes), authority)
    )[-1]
    return LedgerEvent.create(
        run_id=value["ledger_run_id"],
        event_id=_CHARGE_EVENT_PREFIX + value["reservation_artifact_sha256"][:40],
        timestamp=value["recorded_at"],
        actor_role=Role.ORCHESTRATOR,
        state_before=MacroState.CALIBRATE,
        requested_state_after=MacroState.CALIBRATE,
        artifact_hashes=(record.sha256,),
        code_version=inventories[0]["aggregate_sha256"],
        configuration_hash=inventories[1]["aggregate_sha256"],
        dataset_identifiers=(),
        random_seeds=(),
        evaluator_outputs=(),
        reason="charged eight reserved simulated accounting units without execution, release or scientific authority",
        prior_event_hash=source[1].head_hash,
        event_type="CHECKPOINT",
        metadata={
            "artifact_types": [record.logical_type],
            "artifact_record_hashes": [record.record_hash],
            "resource_authority_checkpoint": descriptor,
            SIMULATED_CONFIRMATORY_CHARGE_EVENT_KEY: {
                "schema_version": SIMULATED_CONFIRMATORY_CHARGE_EVENT_SCHEMA,
                "charge_artifact_sha256": record.sha256,
                "charge_record_hash": record.record_hash,
                "reservation_artifact_sha256": value["reservation_artifact_sha256"],
                "reservation_record_hash": value["reservation_record_hash"],
                "profile": SIMULATED_RESERVE_PROFILE,
                "window_index": value["window_index"],
                "charged_units": value["charged_units"],
                **_CHARGE_SCOPE,
            },
        },
    )


def _reconstruct_charge(registry, ledger, pair, value):
    source = _source_pair(pair, value)
    reservation, initialization = _charge_sources(
        registry, ledger, source, value["reservation_artifact_sha256"]
    )
    state = ResourceRuntimeState.from_mapping(value["runtime_state"])
    previous = initialization.runtime_state
    _validate_monotonic_runtime_states((previous, state))
    if (
        state.confirmatory_used
        != previous.confirmatory_used + len(reservation.member_ids)
        or state.exploratory_used != previous.exploratory_used
        or state.worker_crashes != previous.worker_crashes
        or state.checkpoint_elapsed_seconds != previous.checkpoint_elapsed_seconds
        or state.progress_elapsed_seconds != previous.progress_elapsed_seconds
        or state.validity_total_units != 40
        or initialization.config.validity_reserve_fraction != 0.4
        or state.confirmatory_used > 16
    ):
        raise SimulatedResourceError("charge is not the exact native membership debit")
    at = value["recorded_at"]
    if (
        any(_time(item.created_at) > _time(at) for item in source[0].records)
        or any(_time(item.timestamp) > _time(at) for item in source[1].events)
        or state.wall_observed_at_epoch_seconds > _time(at).timestamp()
    ):
        raise SimulatedResourceError("charge clock predates its state or sources")
    expected = _charge_body(
        registry, ledger, source, reservation, initialization, state, at
    )
    if _raw(value) != _raw(expected):
        raise SimulatedResourceError("charge closed payload differs from owned sources")
    record = _charge_plan(registry, value, initialization, reservation)
    if record in source[0].records:
        raise SimulatedResourceError("charge occurs in its own sealed preimage")
    event = _charge_event(registry, source, value, record, initialization)
    return source, reservation, initialization, record, event


def _charge_result(pair, value, reservation, initialization, record, event):
    authority_raw = _raw(_charge_authority(value, initialization))
    return SimulatedConfirmatoryCharge(
        record,
        event,
        value["source_ledger_event_count"],
        reservation,
        initialization,
        _raw(value["runtime_state"]),
        authority_raw,
        sha256_bytes(authority_raw),
        tuple(tuple(item) for item in value["source_registry_identities"]),
        value["source_ledger_event_count"],
        value["source_ledger_head_hash"],
        *pair,
    )


def _consume_charge_selection(registry, ledger, pair, result, *, completed):
    """Full selected I/S/Q census, independent of later live permission."""
    from .simulated_reserve import _validate_inventory

    initialization = _require_simulated_resource_initialization_at_snapshot(
        registry,
        ledger,
        expected_run_id=canonical_simulated_resource_run_id(),
        initialization_artifact_sha256=result.initialization.record.sha256,
        registry_snapshot=pair[0],
        ledger_snapshot=pair[1],
    )
    local = tuple(item for item in pair[0].records if item == result.record)
    if _charge_candidates(registry, pair[0].records) != local:
        raise SimulatedResourceError(
            "selected charge history has an unconsumed record alias"
        )
    references = frozenset((result.record.sha256, result.record.record_hash))
    for index, event in enumerate(pair[1].events):
        if completed and (index, event) == (result.event_index, result.event):
            continue
        if (
            event.event_id.startswith(_CHARGE_EVENT_PREFIX)
            or event.supersedes_event_id
            in {result.event.event_id, result.reservation.event.event_id}
            or references.intersection(event.artifact_hashes)
            or _charge_payload_selected(event.metadata, references)
        ):
            raise SimulatedResourceError(
                "selected charge history has an unconsumed event alias or correction"
            )
    # Record-only Q is permitted solely for exact external-first recovery below.
    # It is omitted from this S census only after full closed reconstruction.
    selected_pair = pair
    if local and not completed:
        selected_pair = (
            RegistryValidationResult(
                True, tuple(item for item in pair[0].records if item != result.record)
            ),
            pair[1],
        )
    _validate_inventory(
        registry,
        ledger,
        selected_pair,
        allowed=(result.reservation,),
        source_owners=(
            (
                result.reservation.protocol_record,
                result.reservation.contract_record,
                result.reservation.population_record,
                result.reservation.record,
            ),
            (result.reservation.event,),
        ),
        initialization=initialization,
        charges=(result,) if completed else (),
    )


def _require_simulated_confirmatory_charge_at_snapshot(
    registry,
    ledger,
    *,
    expected_run_id,
    charge_artifact_sha256,
    registry_snapshot,
    ledger_snapshot,
):
    """Historical Q replay is finite; it never restores or charges a controller."""
    _paths(registry, ledger, expected_run_id)
    if (
        type(registry_snapshot) is not RegistryValidationResult
        or type(ledger_snapshot) is not LedgerValidationResult
        or not registry_snapshot.valid
        or not ledger_snapshot.valid
        or any(event.run_id != expected_run_id for event in ledger_snapshot.events)
    ):
        raise SimulatedResourceError("charge requires valid native selected snapshots")
    pair = registry_snapshot, ledger_snapshot
    from .simulated_reserve import _sha
    from .simulated_observation import _has_history, _passive_charge

    _sha(charge_artifact_sha256)
    if _has_second_charge(registry, pair):
        return _second_charge_outer_charge(registry, ledger, pair, expected_run_id, charge_artifact_sha256)
    if _has_history(registry, pair):
        return _passive_charge(registry, ledger, pair, charge_artifact_sha256)
    record = _one(pair[0].records, charge_artifact_sha256)
    value = _selected_json(registry, pair[0].records, record)
    source, reservation, initialization, expected, event = _reconstruct_charge(
        registry, ledger, pair, value
    )
    index = source[1].event_count
    if (
        record != expected
        or index >= pair[1].event_count
        or pair[1].events[index] != event
    ):
        raise SimulatedResourceError(
            "charge lacks its exact record and publication event"
        )
    result = _charge_result(pair, value, reservation, initialization, record, event)
    _consume_charge_selection(registry, ledger, pair, result, completed=True)
    return result


def _completed_charges_for_reservation(registry, ledger, pair, reservation_sha):
    """Public S's passive outer consumer; no lower source/population auto lookup."""
    result = tuple(
        _require_simulated_confirmatory_charge_at_snapshot(
            registry,
            ledger,
            expected_run_id=canonical_simulated_resource_run_id(),
            charge_artifact_sha256=record.sha256,
            registry_snapshot=pair[0],
            ledger_snapshot=pair[1],
        )
        for record in _charge_candidates(registry, pair[0].records)
    )
    if len(result) > 1 or any(
        item.reservation.record.sha256 != reservation_sha for item in result
    ):
        raise SimulatedResourceError("reservation outer charge belongs to another slot")
    consumed = tuple((item.event_index, item.event) for item in result)
    selected = tuple(
        (index, event)
        for index, event in enumerate(pair[1].events)
        if event.event_id.startswith(_CHARGE_EVENT_PREFIX)
        or _charge_payload_selected(event.metadata)
    )
    if selected != consumed:
        raise SimulatedResourceError(
            "reservation outer charge event lacks its exact full owner"
        )
    return result


def _charge_live_sources(registry, result):
    initialization = result.initialization
    inventories = tuple(
        _inventory(registry, result.registry_snapshot.records, record, index, live=True)
        for index, record in enumerate(
            (
                initialization.frozen_source_inventory_record,
                initialization.frozen_configuration_inventory_record,
            )
        )
    )
    initial = _selected_json(
        registry, result.registry_snapshot.records, initialization.record
    )
    if _config(registry.policy.root, inventories) != (
        initialization.config,
        initial["resource_configuration_utf8"],
    ):
        raise SimulatedResourceError(
            "charge live configuration differs from original bytes"
        )


def _charge_current_contract(registry, ledger, pair, reservation):
    current = _require_current_evaluation_contract_lineage(
        registry,
        ledger,
        expected_run_id=canonical_simulated_resource_run_id(),
        contract_artifact_sha256=reservation.contract_record.sha256,
    )
    if (current.registry_snapshot, current.ledger_snapshot) != pair:
        raise SimulatedResourceError("charge current-contract sources changed")


def _charge_final_locked(registry, ledger, run_id, pair, external, result, rg, lg):
    def check():
        # Live inventory reads may themselves race. Recheck BOTH owners and the
        # external chain only after the last live read, without widening sources.
        observed_external = _read_resource_authority_records(
            registry.policy.root, run_id
        )
        observed_pair = (
            registry._verify_all_locked(rg, raise_on_error=True),
            ledger._validate_bytes(ledger._read_raw_locked(lg)),
        )
        if observed_pair != pair or observed_external != external:
            raise SimulatedResourceError(
                "charge paired or external source changed during final readback"
            )

    check()
    _charge_live_sources(registry, result)
    check()
    registry._verify_mutation_namespace(rg)
    ledger._verify_lock_namespace(lg)


def _require_charge_locked(registry, ledger, run_id, digest):
    before = _pair(registry, ledger)
    result = _require_simulated_confirmatory_charge_at_snapshot(
        registry,
        ledger,
        expected_run_id=run_id,
        charge_artifact_sha256=digest,
        registry_snapshot=before[0],
        ledger_snapshot=before[1],
    )
    value = _selected_json(registry, before[0].records, result.record)
    source = _source_pair(before, value)
    external = (
        safe_json_loads(result.initialization.external_authority_bytes),
        safe_json_loads(result.external_authority_bytes),
    )
    if (
        set(before[0].records) != {*source[0].records, result.record}
        or before[1].events != (*source[1].events, result.event)
        or _read_resource_authority_records(registry.policy.root, run_id) != external
    ):
        raise SimulatedResourceError(
            "charge current population or external head differs"
        )
    _validate_resource_authority_ledger_for(external, before[1].events)
    _charge_current_contract(registry, ledger, before, result.reservation)
    rg = registry._open_mutation_lock()
    try:
        lg = ledger._open_lock()
        try:
            _charge_final_locked(
                registry, ledger, run_id, before, external, result, rg, lg
            )
        finally:
            ledger._unlock(lg)
    finally:
        registry._unlock_mutation(rg)
    return result


def require_simulated_confirmatory_charge(
    registry,
    ledger,
    *,
    expected_run_id,
    charge_artifact_sha256,
):
    """Require current Q1 accounting, original live inputs and exact external head."""
    root, run_id = _paths(registry, ledger, expected_run_id)
    _charge_family(charge_artifact_sha256)
    selected = _one(_pair(registry, ledger)[0].records, charge_artifact_sha256)
    if selected.schema_version == OBSERVED_SECOND_CONFIRMATORY_CHARGE_SCHEMA:
        return _require_second_charge_current(registry, ledger, run_id, charge_artifact_sha256)
    with _project_resource_execution_lock(
        root, expected_root_identity=_named_directory_identity(root)
    ):
        return _require_charge_locked(registry, ledger, run_id, charge_artifact_sha256)


def charge_simulated_confirmatory_reserve(
    registry,
    ledger,
    *,
    expected_run_id,
    reservation_artifact_sha256,
):
    """Debit S1 once, external first; recover only its identical local suffix."""
    root, run_id = _paths(registry, ledger, expected_run_id)
    family = _charge_family(reservation_artifact_sha256)
    from .simulated_reserve import OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA

    selected = _one(_pair(registry, ledger)[0].records, reservation_artifact_sha256)
    if selected.schema_version == OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA:
        return _charge_second_reserve(registry, ledger, run_id, reservation_artifact_sha256)
    with _project_resource_execution_lock(
        root, expected_root_identity=_named_directory_identity(root)
    ):
        before = _pair(registry, ledger)
        external = _read_resource_authority_records(root, run_id)
        if len(external) == 2 and external[-1]["logical_type"] == family:
            value = external[-1]["state"]
            source, reservation, initialization, record, event = _reconstruct_charge(
                registry, ledger, before, value
            )
            if reservation.record.sha256 != reservation_artifact_sha256:
                raise SimulatedResourceError(
                    "external charge belongs to another reservation"
                )
            planned = _charge_authority(value, initialization)
            if external != (
                safe_json_loads(initialization.external_authority_bytes),
                planned,
            ):
                raise SimulatedResourceError(
                    "charge external history differs from original I/Q"
                )
            index = source[1].event_count
            if index < before[1].event_count and before[1].events[index] == event:
                return _require_charge_locked(registry, ledger, run_id, record.sha256)
            if before[1] != source[1] or set(before[0].records) not in (
                set(source[0].records),
                {*source[0].records, record},
            ):
                raise SimulatedResourceError(
                    "charge orphan cannot recover after source drift"
                )
        else:
            if len(external) != 1 or _charge_candidates(registry, before[0].records):
                raise SimulatedResourceError(
                    "new charge requires exact original I external head"
                )
            source = before
            reservation, initialization = _charge_sources(
                registry, ledger, source, reservation_artifact_sha256
            )
            if external != (safe_json_loads(initialization.external_authority_bytes),):
                raise SimulatedResourceError(
                    "new charge external I differs from original authority"
                )
            _charge_current_contract(registry, ledger, before, reservation)
            # Only a genuinely new Q runs native accounting and observes time.
            controller = ResourceController.from_runtime_state(
                initialization.config, root, initialization.runtime_state
            )
            controller.charge_validity("CONFIRMATORY", len(reservation.member_ids))
            state = controller.observe_wall_time()
            value = _charge_body(
                registry, ledger, source, reservation, initialization, state, utc_now()
            )
            source, reservation, initialization, record, event = _reconstruct_charge(
                registry, ledger, before, value
            )
            planned = _charge_authority(value, initialization)
        result = _charge_result(
            before, value, reservation, initialization, record, event
        )
        _consume_charge_selection(registry, ledger, before, result, completed=False)
        _charge_current_contract(registry, ledger, before, reservation)
        _charge_live_sources(registry, result)
        event_raw = _raw(event.to_dict())
        missing = record not in before[0].records
        if (
            before[0].count + int(missing) > MAX_REGISTRY_RECORDS
            or before[1].event_count + 1 > MAX_LEDGER_EVENTS
            or before[1].valid_prefix_bytes + len(event_raw) > MAX_LEDGER_BYTES
            or len(external) > 2
        ):
            raise SimulatedResourceError(
                "charge lacks paired or external publication capacity"
            )
        expected_external = (
            safe_json_loads(initialization.external_authority_bytes),
            planned,
        )
        _validate_resource_authority_ledger_for(
            expected_external, (*before[1].events, event)
        )
        rg = registry._open_mutation_lock()
        try:
            lg = ledger._open_lock()
            try:
                _charge_final_locked(
                    registry, ledger, run_id, before, external, result, rg, lg
                )
                raw = ledger._read_raw_locked(lg)
                prospective = ledger._validate_bytes(raw + event_raw)
                if not prospective.valid or prospective.events != (
                    *before[1].events,
                    event,
                ):
                    raise SimulatedResourceError(
                        "charge prospective event is not one exact valid append"
                    )
                if (
                    _persist_resource_authority_for(root, run_id, family, value)
                    != planned
                ):
                    raise SimulatedResourceError("charge external advance differs")
                if missing and _put(registry, rg, record, _raw(value)) != record:
                    raise SimulatedResourceError("charge artifact publication differs")

                def build(snapshot):
                    if snapshot != before[1]:
                        raise SimulatedResourceError(
                            "charge ledger changed during commit"
                        )
                    return event

                if ledger._append_locked(lg, build) != event:
                    raise SimulatedResourceError("charge event publication differs")
                after = (
                    registry._verify_all_locked(rg, raise_on_error=True),
                    ledger._validate_bytes(ledger._read_raw_locked(lg)),
                )
                if (
                    set(after[0].records) != {*before[0].records, record}
                    or after[1] != prospective
                ):
                    raise SimulatedResourceError(
                        "charge publication changed outside its exact delta"
                    )
                _charge_final_locked(
                    registry, ledger, run_id, after, expected_external, result, rg, lg
                )
            finally:
                ledger._unlock(lg)
        finally:
            registry._unlock_mutation(rg)
        return _require_charge_locked(registry, ledger, run_id, record.sha256)


def _second_charge_sources(registry, ledger, source, reservation_sha):
    """Own COMPLETE S2 -> P2/A2 -> sealed COMPLETE J1 -> T1/Q1/S1/I."""
    from . import simulated_observation as observation
    from . import simulated_reserve as reserve

    reservation, revision, observed = reserve._require_observed_second_at_snapshot(
        registry, ledger, source, canonical_simulated_resource_run_id(), reservation_sha)
    q1, attempt = observed.preparation.charge, observed.attempt
    prior = ResourceRuntimeState.from_mapping(
        safe_json_loads(attempt.external_authority_bytes)["state"]["runtime_state"])
    _validate_monotonic_runtime_states((q1.initialization.runtime_state, q1.runtime_state, prior))
    observation._budget(q1)
    if (prior.to_dict() != q1.runtime_state.to_dict()
            or prior.confirmatory_used != 8 or prior.exploratory_used != 0
            or reservation.window_index != 2 or len(reservation.member_ids) != 8
            or set(reservation.member_ids) & set(q1.reservation.member_ids)):
        raise SimulatedResourceError("Q2 requires exact T1 accounting and disjoint S2")
    return reservation, revision, observed, prior


def _second_charge_body(registry, ledger, source, reservation, observed, prior, state, at):
    q1, attempt = observed.preparation.charge, observed.attempt
    initial = q1.initialization
    value = _charge_body(registry, ledger, source, reservation, initial, state, at)
    value.update({
        "schema_version": OBSERVED_SECOND_CONFIRMATORY_CHARGE_SCHEMA,
        "previous_runtime_artifact_sha256": attempt.record.sha256,
        "previous_runtime_record_hash": attempt.record.record_hash,
        "previous_external_authority_sha256": attempt.external_authority_sha256,
        "previous_external_sequence": 2,
        "original_resource_epoch_artifact_sha256": initial.record.sha256,
        "original_resource_epoch_record_hash": initial.record.record_hash,
        "prior_reservation_artifact_sha256": q1.reservation.record.sha256,
        "prior_charge_artifact_sha256": q1.record.sha256,
        "prior_charge_record_hash": q1.record.record_hash,
        "prior_observation_artifact_sha256": observed.record.sha256,
        "prior_observation_record_hash": observed.record.record_hash,
        "prior_observation_event_hash": observed.event.event_hash,
        "confirmatory_used_before": prior.confirmatory_used,
    })
    return value


def _second_charge_authority(value, observed):
    envelope = {
        "schema_version": "1.0", "kind": "RESOURCE_RUNTIME_AUTHORITY",
        "run_id": canonical_simulated_resource_run_id(), "sequence": 3,
        "logical_type": _charge_family(value["reservation_artifact_sha256"]),
        "state_sha256": sha256_bytes(_raw(value)), "state": value,
        "prior_authority_sha256": observed.attempt.external_authority_sha256,
    }
    if len(_raw(envelope)) > _MAX_BYTES:
        raise SimulatedResourceError("Q2 external envelope exceeds native capacity")
    return envelope


def _second_charge_plan(registry, source, value, reservation, observed):
    from . import simulated_observation as observation

    record = replace(_plan(registry, value, at=value["recorded_at"],
        logical_type=_charge_family(reservation.record.sha256),
        parents=(observed.attempt.record.sha256, reservation.record.sha256)),
        schema_version=OBSERVED_SECOND_CONFIRMATORY_CHARGE_SCHEMA,
        origin=SIMULATED_CONFIRMATORY_CHARGE_ORIGIN,
        creation_command=SIMULATED_CONFIRMATORY_CHARGE_COMMAND, record_hash=None)
    q1 = observed.preparation.charge
    inventories = observation._inventories(registry, q1)
    external = (*observation._external(q1, observed.attempt), _second_charge_authority(value, observed))
    event = LedgerEvent.create(
        run_id=value["ledger_run_id"],
        event_id=_CHARGE_EVENT_PREFIX + reservation.record.sha256[:40],
        timestamp=value["recorded_at"], actor_role=Role.ORCHESTRATOR,
        state_before=MacroState.CALIBRATE, requested_state_after=MacroState.CALIBRATE,
        artifact_hashes=(record.sha256,), code_version=inventories[0]["aggregate_sha256"],
        configuration_hash=inventories[1]["aggregate_sha256"],
        dataset_identifiers=(), random_seeds=(), evaluator_outputs=(),
        reason="charged the disjoint second eight simulated units cumulatively without execution, release or scientific authority",
        prior_event_hash=source[1].head_hash, event_type="CHECKPOINT",
        metadata={
            "artifact_types": [record.logical_type], "artifact_record_hashes": [record.record_hash],
            "resource_authority_checkpoint": _resource_authority_descriptors_for(external)[-1],
            SIMULATED_CONFIRMATORY_CHARGE_EVENT_KEY: {
                "schema_version": OBSERVED_SECOND_CONFIRMATORY_CHARGE_EVENT_SCHEMA,
                "charge_artifact_sha256": record.sha256, "charge_record_hash": record.record_hash,
                "reservation_artifact_sha256": reservation.record.sha256,
                "reservation_record_hash": reservation.record.record_hash,
                "previous_runtime_artifact_sha256": observed.attempt.record.sha256,
                "previous_runtime_record_hash": observed.attempt.record.record_hash,
                "profile": SIMULATED_RESERVE_PROFILE, "window_index": 2,
                "charged_units": 8, "confirmatory_used_before": 8, "confirmatory_used_after": 16,
                **_CHARGE_SCOPE,
            },
        },
    )
    return record, event, external


def _reconstruct_second_charge(registry, ledger, pair, value):
    from . import simulated_observation as observation

    source = _source_pair(pair, value)
    reservation, revision, observed, previous = _second_charge_sources(
        registry, ledger, source, value["reservation_artifact_sha256"])
    initial = observed.preparation.charge.initialization
    state = ResourceRuntimeState.from_mapping(value["runtime_state"])
    _validate_monotonic_runtime_states((previous, state))
    if (state.confirmatory_used != 16 or state.exploratory_used != previous.exploratory_used
            or state.worker_crashes != previous.worker_crashes
            or state.checkpoint_elapsed_seconds != previous.checkpoint_elapsed_seconds
            or state.progress_elapsed_seconds != previous.progress_elapsed_seconds
            or state.validity_total_units != 40 or initial.config.validity_reserve_fraction != 0.4
            or state.wall_elapsed_seconds >= initial.config.maximum_wall_clock_seconds
            or state.wall_elapsed_seconds - state.progress_elapsed_seconds >= initial.config.stall_timeout_seconds):
        raise SimulatedResourceError("Q2 is not the bounded cumulative native second debit")
    at = value["recorded_at"]
    observation._chronology(source, at)
    if state.wall_observed_at_epoch_seconds > _time(at).timestamp():
        raise SimulatedResourceError("Q2 timestamp predates its native runtime observation")
    expected = _second_charge_body(registry, ledger, source, reservation, observed, previous, state, at)
    if _raw(value) != _raw(expected):
        raise SimulatedResourceError("Q2 closed payload differs from full S2/T1 sources")
    record, event, external = _second_charge_plan(registry, source, value, reservation, observed)
    if record in source[0].records:
        raise SimulatedResourceError("Q2 occurs in its own sealed preimage")
    return source, reservation, revision, observed, record, event, external


def _second_charge_result(pair, value, reservation, observed, record, event):
    authority = _raw(_second_charge_authority(value, observed))
    return SimulatedConfirmatoryCharge(
        record, event, value["source_ledger_event_count"], reservation,
        observed.preparation.charge.initialization, _raw(value["runtime_state"]),
        authority, sha256_bytes(authority),
        tuple(tuple(item) for item in value["source_registry_identities"]),
        value["source_ledger_event_count"], value["source_ledger_head_hash"], *pair,
    )


def _require_second_charge_at_snapshot(registry, ledger, pair, run_id, digest):
    """Pure complete Q2 ownership; never restores a controller or live custody."""
    from . import simulated_observation as observation
    from . import simulated_reserve as reserve

    _paths(registry, ledger, run_id)
    reserve._sha(digest)
    reserve._observed_second_pair(ledger, pair)
    record = _one(pair[0].records, digest)
    value = _selected_json(registry, pair[0].records, record)
    if record.schema_version != OBSERVED_SECOND_CONFIRMATORY_CHARGE_SCHEMA:
        raise SimulatedResourceError("selected Q2 artifact has a different schema")
    source, reservation, _revision, observed, expected, event, external = _reconstruct_second_charge(
        registry, ledger, pair, value)
    if record != expected or not observation._same_pair(pair, observation._append_pair(source, record, event)):
        raise SimulatedResourceError("Q2 has an unowned orphan, alias, correction or delta")
    _validate_resource_authority_ledger_for(external, pair[1].events)
    return _second_charge_result(pair, value, reservation, observed, record, event), observed


def _has_second_charge(registry, pair):
    """Negative routing selection, never an authority or family exemption."""
    old = {SIMULATED_CONFIRMATORY_CHARGE_SCHEMA, SIMULATED_CONFIRMATORY_CHARGE_EVENT_SCHEMA}
    def selected(value):
        return any(_charge_schema_selected(item) and item not in old for item in _markers(value)[2])
    for record in _charge_candidates(registry, pair[0].records):
        if _charge_schema_selected(record.schema_version) and record.schema_version not in old:
            return True
        if record.size <= MAX_SIMULATED_RESERVE_BYTES:
            from .seed_reporting import _selected_payload_bytes
            raw = _selected_payload_bytes(registry, pair[0].records, record)
            try:
                value = safe_json_loads(raw, max_bytes=MAX_SIMULATED_RESERVE_BYTES, max_items=100_000)
            except (ValueError, UnsafeSerializationError):
                if _charge_malformed_schema_selected(raw):
                    return True
            else:
                if selected(value):
                    return True
    return any(selected(event.metadata) for event in pair[1].events)


def _second_charge_outer(registry, ledger, pair, run_id):
    records = tuple(record for record in pair[0].records
                    if record.schema_version == OBSERVED_SECOND_CONFIRMATORY_CHARGE_SCHEMA)
    if len(records) != 1:
        raise SimulatedResourceError("higher Q2 population lacks one exact closed owner")
    return _require_second_charge_at_snapshot(registry, ledger, pair, run_id, records[0].sha256)


def _second_charge_outer_charge(registry, ledger, pair, run_id, digest):
    _charge_family(digest)
    result, observed = _second_charge_outer(registry, ledger, pair, run_id)
    if digest == result.record.sha256:
        return result
    prior = observed.preparation.charge
    if digest != prior.record.sha256:
        raise SimulatedResourceError("Q2 does not own the selected historical charge")
    return replace(prior, registry_snapshot=pair[0], ledger_snapshot=pair[1])


def _second_charge_outer_reservation(registry, ledger, pair, run_id, digest):
    _charge_family(digest)
    result, observed = _second_charge_outer(registry, ledger, pair, run_id)
    for reservation in (result.reservation, observed.preparation.charge.reservation):
        if digest == reservation.record.sha256:
            return replace(reservation, registry_snapshot=pair[0], ledger_snapshot=pair[1])
    raise SimulatedResourceError("Q2 does not own the selected reservation")


def _second_charge_live_sources(registry, result, observed):
    from . import simulated_observation as observation
    from .recovery import RecoveryManager

    _charge_live_sources(registry, result)
    inventory, _config_inventory = observation._inventories(registry, observed.preparation.charge)
    manager = RecoveryManager(registry.policy.root)
    for name in ("simulated_resource", "simulated_reserve", "simulated_observation", "holdout", "recovery"):
        RecoveryManager._validated_live_source_implementation(manager, inventory,
            path="src/scientist_one/" + name + ".py", label="observed second charge source")


def _second_charge_capacity(registry, pair, result, external, *, missing_record, missing_external):
    from .resources import conservative_disk_reserve

    payload = result.record.size if missing_record else 0
    metadata = len(_raw(result.record.to_dict())) if missing_record else 0
    event = len(_raw(result.event.to_dict()))
    envelope = len(_raw(external[-1])) if missing_external else 0
    required = payload + metadata + event + envelope
    if (pair[0].count + int(missing_record) > MAX_REGISTRY_RECORDS
            or pair[1].event_count + 1 > MAX_LEDGER_EVENTS
            or pair[1].valid_prefix_bytes + event > MAX_LEDGER_BYTES
            or metadata > _MAX_BYTES or event > _MAX_BYTES
            or len(external) != 4
            or sum(item.size for item in pair[0].records) + payload > 32 * _MAX_BYTES):
        raise SimulatedResourceError("Q2 lacks exact bounded publication capacity")
    config = result.initialization.config
    controller = ResourceController.from_runtime_state(config, registry.policy.root, result.runtime_state)
    total, free, error = controller._probe_disk()
    if (error is not None or total is None or free is None
            or controller.artifact_usage() + required >= config.maximum_artifact_bytes
            or free - required <= conservative_disk_reserve(total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)):
        raise SimulatedResourceError("Q2 bookkeeping lacks exact disk or artifact capacity")


def _second_charge_final(registry, ledger, pair, external, result, rg, lg, custody_recheck):
    custody_recheck()
    _charge_final_locked(registry, ledger, canonical_simulated_resource_run_id(), pair, external, result, rg, lg)
    custody_recheck()
    if ((registry._verify_all_locked(rg, raise_on_error=True),
            ledger._validate_bytes(ledger._read_raw_locked(lg))) != pair
            or _read_resource_authority_records(registry.policy.root, canonical_simulated_resource_run_id()) != external):
        raise SimulatedResourceError("Q2 pair or external changed after final custody read")
    registry._verify_mutation_namespace(rg)
    ledger._verify_lock_namespace(lg)


def _require_second_charge_current(registry, ledger, run_id, digest):
    from . import simulated_observation as observation

    root, _run_id = _paths(registry, ledger, run_id)
    with _project_resource_execution_lock(root, expected_root_identity=_named_directory_identity(root), nonblocking=True):
        pair = _pair(registry, ledger)
        result, observed = _require_second_charge_at_snapshot(registry, ledger, pair, run_id, digest)
        external = (*observation._external(observed.preparation.charge, observed.attempt),
                    safe_json_loads(result.external_authority_bytes))
        _second_charge_live_sources(registry, result, observed)
        if _read_resource_authority_records(root, run_id) != external:
            raise SimulatedResourceError("current Q2 requires the exact four-stage external tail")
        with observation._observed_terminal_custody_guard(registry, ledger, expected_run_id=run_id,
                observation_artifact_sha256=observed.record.sha256,
                registry_snapshot=observed.registry_snapshot, ledger_snapshot=observed.ledger_snapshot) as (held, custody_recheck):
            if held != observed:
                raise SimulatedResourceError("Q2 terminal custody belongs to another sealed J1")
            with observation._locks(registry, ledger) as (rg, lg):
                _validate_resource_authority_ledger_for(external, pair[1].events)
                _second_charge_final(registry, ledger, pair, external, result, rg, lg, custody_recheck)
            return result


def _charge_second_reserve(registry, ledger, run_id, reservation_sha):
    from .artifacts import ArtifactError
    from .holdout import HoldoutCustodyError
    from .ledger import LedgerError
    from .orchestrator import OrchestrationError
    from .resources import ResourceLimitError

    try:
        return _charge_second_reserve_locked(registry, ledger, run_id, reservation_sha)
    except SimulatedResourceError:
        raise
    except (ArtifactError, HoldoutCustodyError, LedgerError, OrchestrationError,
            ResourceLimitError, ValueError, OSError, TypeError, KeyError) as exc:
        # A native failure can follow any durable external/artifact/event write.
        # Preserve exact suffixes; refusal never promises universal zero writes.
        raise SimulatedResourceError("observed second charge publication refused") from exc


def _charge_second_reserve_locked(registry, ledger, run_id, reservation_sha):
    """Debit only a genuinely new second window; exact suffix recovery is not work."""
    from . import simulated_observation as observation
    from . import simulated_reserve as reserve

    root, _run_id = _paths(registry, ledger, run_id)
    family = _charge_family(reservation_sha)
    with _project_resource_execution_lock(root, expected_root_identity=_named_directory_identity(root), nonblocking=True):
        before = _pair(registry, ledger)
        reserve._observed_second_pair(ledger, before)
        actual_external = _read_resource_authority_records(root, run_id)
        existing_external = len(actual_external) == 4 and actual_external[-1]["logical_type"] == family
        if existing_external:
            value = actual_external[-1]["state"]
            source, reservation, _revision, observed, record, event, expected_external = _reconstruct_second_charge(
                registry, ledger, before, value)
            if reservation.record.sha256 != reservation_sha or actual_external != expected_external:
                raise SimulatedResourceError("external Q2 does not own this exact S2/T1 source")
        else:
            if len(actual_external) != 3:
                raise SimulatedResourceError("new Q2 requires the exact immediate T1 tail")
            source = before
            reservation, _revision, observed, previous = _second_charge_sources(registry, ledger, source, reservation_sha)
        prior_external = observation._external(observed.preparation.charge, observed.attempt)
        if actual_external != (expected_external if existing_external else prior_external):
            raise SimulatedResourceError("Q2 external chain differs from original I/Q1/T1")
        # Local phase is derived from exact pair equality, not an allow-orphan
        # flag. An external-only Q2 cannot require its still-missing event yet.
        complete = observation._append_pair(source, record, event) if existing_external else None
        completed = existing_external and observation._same_pair(before, complete)
        if existing_external and not completed and not any(observation._same_pair(before, pair) for pair in
                (source, observation._append_pair(source, record))):
            raise SimulatedResourceError("Q2 can recover only its identical original local suffix")
        _validate_resource_authority_ledger_for(prior_external, source[1].events)
        q1 = observed.preparation.charge
        _second_charge_live_sources(registry, q1, observed)
        with observation._observed_terminal_custody_guard(registry, ledger, expected_run_id=run_id,
                observation_artifact_sha256=observed.record.sha256,
                registry_snapshot=observed.registry_snapshot, ledger_snapshot=observed.ledger_snapshot) as (held, custody_recheck):
            if held != observed:
                raise SimulatedResourceError("Q2 sealed J1 changed at terminal custody entry")
            if not existing_external:
                # Only this branch admits and charges new validity work. The
                # projected post-charge payload is not fabricated in advance.
                controller = ResourceController.from_runtime_state(q1.initialization.config, root, previous)
                decision = controller.evaluate(validity_stage="CONFIRMATORY", validity_units=8,
                                               requested_experiments=0, requested_cpu_workers=0)
                if not decision.allowed:
                    raise SimulatedResourceError("new Q2 native admission refuses: " + ", ".join(decision.reasons))
                controller.charge_validity("CONFIRMATORY", 8)
                state = controller.observe_wall_time()
                value = _second_charge_body(registry, ledger, source, reservation, observed, previous, state, utc_now())
                source, reservation, _revision, observed, record, event, expected_external = _reconstruct_second_charge(
                    registry, ledger, before, value)
                complete = observation._append_pair(source, record, event)
            result = _second_charge_result(before, value, reservation, observed, record, event)
            _second_charge_live_sources(registry, result, observed)
            _validate_resource_authority_ledger_for(expected_external, complete[1].events)
            if completed:
                result = _require_second_charge_at_snapshot(registry, ledger, before, run_id, record.sha256)[0]
                with observation._locks(registry, ledger) as (rg, lg):
                    _second_charge_final(registry, ledger, before, expected_external, result, rg, lg, custody_recheck)
                return result
            missing = record not in before[0].records
            _second_charge_capacity(registry, before, result, expected_external,
                                    missing_record=missing, missing_external=not existing_external)
            with observation._locks(registry, ledger) as (rg, lg):
                _second_charge_capacity(registry, before, result, expected_external,
                                        missing_record=missing, missing_external=not existing_external)
                _second_charge_final(registry, ledger, before, actual_external, result, rg, lg, custody_recheck)
                prospective = ledger._validate_bytes(ledger._read_raw_locked(lg) + _raw(event.to_dict()))
                if prospective != complete[1]:
                    raise SimulatedResourceError("Q2 prospective ledger is not its exact single append")
                _validate_resource_authority_ledger_for(expected_external, prospective.events)
                if _persist_resource_authority_for(root, run_id, family, value) != expected_external[-1]:
                    raise SimulatedResourceError("Q2 native external publication differs")
                if missing and _put(registry, rg, record, _raw(value)) != record:
                    raise SimulatedResourceError("Q2 native artifact publication differs")
                def build(snapshot):
                    if snapshot != before[1]:
                        raise SimulatedResourceError("Q2 ledger changed during commit")
                    return event
                if ledger._append_locked(lg, build) != event:
                    raise SimulatedResourceError("Q2 native event publication differs")
                after = (registry._verify_all_locked(rg, raise_on_error=True),
                         ledger._validate_bytes(ledger._read_raw_locked(lg)))
                if not observation._same_pair(after, complete):
                    raise SimulatedResourceError("Q2 changed outside its exact publication suffix")
                _second_charge_final(registry, ledger, after, expected_external, result, rg, lg, custody_recheck)
            # Native artifact readers take their own registry guards. Release
            # only R/L for full replay, retaining the native outer lifetimes.
            result = _require_second_charge_at_snapshot(registry, ledger, after, run_id, record.sha256)[0]
            with observation._locks(registry, ledger) as (rg, lg):
                _second_charge_final(registry, ledger, after, expected_external, result, rg, lg, custody_recheck)
            return result
