"""Source-owned operational BEST_OF_N bookkeeping; never scientific authority.

The descriptor entry point is deliberately below contract-lineage admission:
it consumes only the caller-selected registry population and event prefix.
The public execution/report owners additionally replay the real freeze owners
and the exact builtin backend. Scientific exposure hooks are required before
enabling this profile in a product workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from fractions import Fraction
import math
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from .artifacts import (
    MAX_ARTIFACT_PARENTS,
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
)
from .errors import PathSecurityError, ValidationError
from .evaluation_contract_amendment import (
    _registry_map_fingerprint,
    _registry_record_map,
    _require_evaluation_contract_family_before_design,
    _require_registry_record_map,
    _spec_candidate,
)
from .experiments import (
    EvidenceClass,
    ExperimentError,
    LocalMacBackend,
    SeedRunResult,
    SeedRunStatus,
    plan_adaptive_execution,
)
from .ledger import MAX_LEDGER_BYTES, MAX_LEDGER_EVENTS, EventLedger, LedgerEvent
from .local_terminal_observation import (
    LOCAL_TERMINAL_CAPTURE_METADATA_KEY,
    LOCAL_TERMINAL_CAPTURE_PROFILE,
    LOCAL_TERMINAL_MAX_JSON_BYTES,
    LOCAL_TERMINAL_MAX_FILE_BYTES,
    LOCAL_TERMINAL_MAX_SOURCE_BYTES,
    LOCAL_TERMINAL_OBSERVATION_SCHEMA,
    LocalTerminalObservation,
)
from .models import freeze_json, thaw_json, utc_now, validate_identifier
from .roles import Role
from .scientific_design import (
    EvaluationContractFreezeGateReceipt,
    ExperimentStage,
    MetricDirection,
    ReportingRegime,
    _locked_checked_result_authority_snapshot,
    _parse_checked_frozen_run_spec,
    _timeline_state,
    require_evaluation_contract_freeze_gate_receipt,
    require_frozen_evaluation_contract,
    _timeline_binding,
    _require_frozen_evaluation_contract_descriptor,
)
from .security import (
    DEFAULT_MAX_JSON_DEPTH,
    DEFAULT_MAX_JSON_ITEMS,
    canonical_json_bytes,
    read_confined_bytes,
    safe_json_loads,
    sha256_bytes,
    open_confined_directory_fd,
    validate_command,
)


OPERATIONAL_SEED_POLICY_METADATA_KEY = "operational_seed_reporting"
OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE = "operational_seed_admission"
LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE = "local_terminal_observation"
OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE = "operational_best_of_n_report"
OPERATIONAL_SEED_ADMISSION_EVENT_KEY = "operational_seed_admission"
OPERATIONAL_BEST_OF_N_REPORT_EVENT_KEY = "operational_best_of_n_report"
OPERATIONAL_SELECTION_RULE = "PRIMARY_METRIC_DIRECTION_THEN_SEED_ORDER_V1"
OPERATIONAL_RETRY_RULE = "ONCE_ONLY_IF_NOT_INVOKED_QUEUE_TIMEOUT_V1"
OPERATIONAL_PROFILE_ID = "EXPLORATORY_CPU_BEST_OF_N_V1"
MAX_OPERATIONAL_REPORT_BYTES = 4 * 1024 * 1024
MAX_OPERATIONAL_SEEDS = 128
_POLICY_SCHEMA = "OPERATIONAL_BEST_OF_N_POLICY_V1"
_SCOPE = "OPERATIONAL_ONLY_NO_SCIENTIFIC_AUTHORITY"
_SCHEMAS = {
    OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE: "op-seed-admission/v1",
    LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE: "local-terminal/v1",
    OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE: "op-best-of-n/v1",
}
_EVENT_KEYS = {
    OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE: OPERATIONAL_SEED_ADMISSION_EVENT_KEY,
    OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE: OPERATIONAL_BEST_OF_N_REPORT_EVENT_KEY,
}
_COMMAND = ("scientist-one", "operational-best-of-n")
_ORIGIN = "source-owned operational BEST_OF_N"
_FLAGS = {
    "scientific_evidence": False,
    "result_validity_authorized": False,
    "independent_execution_attested": False,
    "representative_mean_authorized": False,
    "statistical_inference_authorized": False,
}
_SOURCE_KEYS = {
    "ledger_run_id",
    "cohort_id",
    "attempt",
    "contract_artifact_sha256",
    "contract_record_hash",
    "frozen_run_spec_artifact_sha256",
    "frozen_run_spec_record_hash",
    "frozen_run_spec_sha256",
    "input_artifact_sha256s",
    "input_artifact_record_hashes",
    "dataset_id",
    "split_id",
    "seed_order",
    "execution_run_id",
    "job_id",
    "submission_idempotency_key",
    "policy",
}
_BASE_KEYS = {
    "schema_version",
    "profile_id",
    "authority_scope",
    "recorded_at",
    "source_binding",
    "source_registry_record_identities",
    "source_registry_record_count",
    "source_registry_record_map_fingerprint",
    "source_ledger_event_count",
    "source_ledger_head_hash",
    *_FLAGS,
}
_ADMISSION_KEYS = _BASE_KEYS | {
    "initial_freeze_receipt_artifact_sha256",
    "retry_freeze_receipt_artifact_sha256",
    "previous_admission_artifact_sha256",
    "previous_terminal_artifact_sha256",
    "runtime_job_namespace_observed_absent",
}
_REPORT_KEYS = _BASE_KEYS | {
    "admission_artifact_sha256s",
    "terminal_artifact_sha256s",
    "planned_n",
    "seed_order",
    "attempts",
    "observed_numeric_distribution",
    "numeric_distribution_complete",
    "eligible_distribution",
    "selected",
    "selection_rule",
    "primary_metric",
    "population_scope",
}


class OperationalSeedReportingError(ValidationError):
    """The operational source closure is unsupported, incomplete or changed."""


def _metadata_selectors(value):
    """Bounded structural hints only; no value here establishes authority."""
    budget = DEFAULT_MAX_JSON_ITEMS
    pending = [(value, 0, False)]
    keys, strings, mappings, families = set(), set(), [], set()
    while pending:
        current, depth, family_field = pending.pop()
        budget -= 1
        if budget < 0 or depth > DEFAULT_MAX_JSON_DEPTH:
            _fail("operational marker selector exceeds canonical JSON bounds")
        if isinstance(current, Mapping):
            keys.update(current)
            mappings.append(current)
            if family_field:
                # A malformed typed-field mapping cannot hide a reserved
                # family by moving its literal from a value into a key.
                families.update(current)
            pending.extend(
                (
                    item,
                    depth + 1,
                    family_field or key in {"artifact_types", "logical_type"},
                )
                for key, item in current.items()
            )
        elif isinstance(current, (tuple, list)):
            pending.extend((item, depth + 1, family_field) for item in current)
        elif type(current) is str:
            strings.add(current)
            if family_field:
                families.add(current)
    return frozenset(keys), frozenset(strings), tuple(mappings), frozenset(families)


@dataclass(frozen=True)
class _EventSelectors:
    index: int
    event: LedgerEvent
    keys: frozenset[str]
    strings: frozenset[str]
    mappings: tuple[Mapping, ...]
    references: frozenset[str]
    families: frozenset[str]


def _snapshot_event_selectors(events):
    """Enumerate exactly the supplied prefix once, without live owner calls."""
    if (
        type(events) is not tuple
        or len(events) > MAX_LEDGER_EVENTS
        or any(type(event) is not LedgerEvent for event in events)
    ):
        _fail("event selectors require a bounded exact native event tuple")
    result = []
    for index, event in enumerate(events):
        keys, strings, mappings, families = _metadata_selectors(event.metadata)
        result.append(
            _EventSelectors(
                index,
                event,
                keys,
                strings,
                mappings,
                strings | frozenset(event.artifact_hashes),
                families,
            )
        )
    return tuple(result)


def _operational_event_selected(selector, identities):
    return bool(
        selector.keys.intersection(_EVENT_KEYS.values())
        or selector.families.intersection(_SCHEMAS)
        or selector.event.event_id.startswith("evt-op-seed-")
        or selector.strings.intersection(
            {*_SCHEMAS.values(), LOCAL_TERMINAL_OBSERVATION_SCHEMA}
        )
        or selector.references.intersection(identities)
    )


def _selected_payload_bytes(registry, records, record):
    """Read one exact selected record without entering registry/ledger locks.

    The negative hook is also called from paired publication critical sections.
    Its caller owns the source snapshot and final CAS; these confined reads bind
    only that snapshot's metadata/content and cannot enumerate a live tail.
    """
    if record not in records:
        _fail("payload selector record is outside the selected population")
    object_path = (registry.objects_path / record.sha256[:2] / record.sha256).as_posix()
    metadata_path = (
        registry.metadata_path / record.sha256[:2] / f"{record.sha256}.json"
    ).as_posix()
    if (
        record.path != object_path
        or record.relative_path != object_path
        or record.metadata_path != metadata_path
    ):
        _fail("selected payload record has a nonnative metadata/content path")

    def namespace_identity():
        root = os.stat(registry.policy.root, follow_symlinks=False)
        base = open_confined_directory_fd(
            registry.policy.root, registry.base_path, create=False
        )
        try:
            metadata = os.fstat(base)
            if (root.st_dev, root.st_ino) != registry._root_identity or (
                metadata.st_dev,
                metadata.st_ino,
            ) != registry._base_identity:
                _fail("selected payload registry namespace identity changed")
            return root.st_ctime_ns, metadata.st_ctime_ns
        finally:
            os.close(base)

    def fingerprint(metadata):
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    def read_selected_file(path, limit):
        relative = Path(path)
        parent = open_confined_directory_fd(
            registry.policy.root, relative.parent, create=False
        )
        descriptor = None
        try:
            parent_identity = fingerprint(os.fstat(parent))
            before = os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > limit
            ):
                _fail("selected payload is not a private bounded regular file")
            # NONBLOCK prevents a FIFO substitution between stat/open from
            # hanging a publication critical section. It has no regular-file
            # semantic effect; fstat and named identity are still required.
            descriptor = os.open(
                relative.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=parent,
            )
            if fingerprint(os.fstat(descriptor)) != fingerprint(before):
                _fail("selected payload changed while opening")
            chunks, total = [], 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, limit - total + 1))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    _fail("selected payload exceeds its exact byte bound")
            if (
                fingerprint(os.fstat(descriptor)) != fingerprint(before)
                or fingerprint(
                    os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
                )
                != fingerprint(before)
                or fingerprint(os.fstat(parent)) != parent_identity
            ):
                _fail("selected payload file or directory changed while reading")
            named_parent = open_confined_directory_fd(
                registry.policy.root, relative.parent, create=False
            )
            try:
                if fingerprint(os.fstat(named_parent)) != parent_identity:
                    _fail("selected payload directory path changed while reading")
            finally:
                os.close(named_parent)
            return b"".join(chunks)
        except OSError as exc:
            raise OperationalSeedReportingError(
                "selected payload cannot be read safely"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)

    namespace_before = namespace_identity()
    expected_metadata = _raw(record.to_dict())
    metadata = read_selected_file(metadata_path, len(expected_metadata))
    if metadata != expected_metadata:
        _fail("selected payload metadata bytes differ from the supplied record")
    raw = read_selected_file(object_path, record.size)
    if raw is None or len(raw) != record.size or sha256_bytes(raw) != record.sha256:
        _fail("selected payload content bytes differ from the supplied record")
    if (
        read_selected_file(metadata_path, len(expected_metadata)) != expected_metadata
        or namespace_identity() != namespace_before
    ):
        _fail("selected payload namespace or metadata changed while reading")
    return raw


def _payload_family_hint(registry, records, record):
    """Bounded payload selectors cannot be hidden by a wrong MIME/family."""
    if record.size > LOCAL_TERMINAL_MAX_JSON_BYTES:
        return None
    raw = _selected_payload_bytes(registry, records, record)
    if not raw.lstrip().startswith(b"{"):
        return None
    schemas = {
        _SCHEMAS[
            OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE
        ]: OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE,
        _SCHEMAS[
            OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
        ]: OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE,
        LOCAL_TERMINAL_OBSERVATION_SCHEMA: LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE,
    }
    try:
        value = safe_json_loads(raw, max_bytes=LOCAL_TERMINAL_MAX_JSON_BYTES)
    except ValidationError:
        matches = [
            family
            for schema, family in schemas.items()
            if canonical_json_bytes(schema) in raw
        ]
        if len(set(matches)) > 1:
            _fail("malformed operational payload contains competing family selectors")
        return matches[0] if matches else None
    schema = value.get("schema_version") if isinstance(value, dict) else None
    return schemas.get(schema) if type(schema) is str else None


def reject_operational_seed_exposure(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    events: tuple[LedgerEvent, ...],
    *,
    complete_registry_population: bool,
) -> None:
    """Conservatively reject reserved/possible exposure in a selected snapshot.

    No execution or results-seen assertion follows from this rejection. An
    unsealed legacy history can inspect only its selected event prefix. A
    current or sealed population additionally includes record-only progress.
    This negative guard never calls any scientific or operational owner.
    """
    if (
        type(registry) is not ArtifactRegistry
        or type(records) is not tuple
        or type(events) is not tuple
        or type(complete_registry_population) is not bool
    ):
        _fail("operational exposure guard requires exact selected native inputs")
    _registry_record_map(records)
    by_sha = {record.sha256: record for record in records}
    by_record_hash = {record.record_hash: record for record in records}

    def reserved(record):
        return (
            record.logical_type in _SCHEMAS
            or record.schema_version in _SCHEMAS.values()
            or record.origin.startswith(_ORIGIN)
            or record.creation_command == _COMMAND
        )

    reserved_records = {r.sha256: r for r in records if reserved(r)}
    reserved_record_hashes = {r.record_hash for r in reserved_records.values()}

    for selector in _snapshot_event_selectors(events):
        referenced = {
            by_sha[value] if value in by_sha else by_record_hash[value]
            for value in selector.references
            if value in by_sha or value in by_record_hash
        }
        if _operational_event_selected(
            selector, set(reserved_records) | reserved_record_hashes
        ) or any(
            _payload_family_hint(registry, records, record) is not None
            for record in referenced
            if not reserved(record)
        ):
            _fail(
                "operational dispatch reservation or possible exposure forbids scientific freshness"
            )
    if complete_registry_population and any(reserved(record) for record in records):
        _fail(
            "operational record-only reservation or possible exposure forbids scientific freshness"
        )
    if complete_registry_population and any(
        _payload_family_hint(registry, records, record) is not None
        for record in records
    ):
        _fail(
            "operational payload alias or unresolved capture forbids scientific freshness"
        )


@dataclass(frozen=True)
class OperationalSeedProgress:
    """Passive structural progress, not executed/result-seen authority."""

    admission_record: ArtifactRecord
    source_binding: Mapping[str, Any]
    source_registry_record_identities: tuple[tuple[str, str], ...]
    source_ledger_event_count: int
    source_ledger_head_hash: str | None
    admission_event: LedgerEvent | None
    admission_event_index: int | None
    terminal_record: ArtifactRecord | None
    terminal_observation: LocalTerminalObservation | None
    report_records: tuple[ArtifactRecord, ...] = ()
    progress_kind: str = "DISPATCH_RESERVED_OR_UNRESOLVED"


@dataclass(frozen=True)
class OperationalBestOfNPublication:
    report_record: ArtifactRecord
    report_event: LedgerEvent
    report: Mapping[str, Any]
    admission_records: tuple[ArtifactRecord, ...]
    terminal_records: tuple[ArtifactRecord, ...]


def operational_seed_policy(
    cohort_id: str, attempt_run_ids: tuple[str, str]
) -> dict[str, Any]:
    validate_identifier(cohort_id, "operational cohort ID")
    if type(attempt_run_ids) is not tuple or len(attempt_run_ids) != 2:
        raise OperationalSeedReportingError(
            "exactly two prospective attempt IDs are required"
        )
    for name in attempt_run_ids:
        validate_identifier(name, "operational attempt ID")
    if attempt_run_ids[0] == attempt_run_ids[1]:
        raise OperationalSeedReportingError("retry must have a distinct frozen run ID")
    return {
        "schema_version": _POLICY_SCHEMA,
        "profile_id": OPERATIONAL_PROFILE_ID,
        "cohort_id": cohort_id,
        "attempt_run_ids": list(attempt_run_ids),
        "selection_rule": OPERATIONAL_SELECTION_RULE,
        "metric_source": "SEED_RESULT_METRIC_IS_CONTRACT_PRIMARY_V1",
        "retry_rule": OPERATIONAL_RETRY_RULE,
    }


def _raw(value: Any) -> bytes:
    return canonical_json_bytes(thaw_json(value)) + b"\n"


def _fail(message: str) -> None:
    raise OperationalSeedReportingError(message)


def _context(registry: ArtifactRegistry, ledger: EventLedger, run_id: str):
    validate_identifier(run_id, "operational ledger run ID")
    if (
        type(registry) is not ArtifactRegistry
        or type(ledger) is not EventLedger
        or registry.policy.root != ledger.policy.root
        or registry.base_path.as_posix() != f"runs/{run_id}/registry"
        or ledger.relative_path.as_posix() != f"runs/{run_id}/events.jsonl"
    ):
        _fail("operational registry/ledger do not name one exact run")
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    if any(event.run_id != run_id for event in before[1].events):
        _fail("operational ledger contains another run")
    return before


def _record(registry, records, digest):
    selected = next((record for record in records if record.sha256 == digest), None)
    if selected is None:
        _fail("operational source is absent from the selected population")
    registry.verify(digest, raise_on_error=True)
    if registry.get_metadata(digest) != selected:
        _fail("operational source metadata changed")
    return selected


def _policy(spec):
    value = thaw_json(spec.metadata.get(OPERATIONAL_SEED_POLICY_METADATA_KEY))
    if not isinstance(value, dict):
        _fail("operational seed policy is absent")
    expected = operational_seed_policy(
        value.get("cohort_id"), tuple(value.get("attempt_run_ids", ()))
    )
    if _raw(value) != _raw(expected) or spec.seed_policy != OPERATIONAL_SELECTION_RULE:
        _fail("operational seed policy is not the exact closed profile")
    if (
        type(spec.attempt) is not int
        or spec.attempt not in (1, 2)
        or spec.run_id != value["attempt_run_ids"][spec.attempt - 1]
        or spec.retry_of_run_id
        != (None if spec.attempt == 1 else value["attempt_run_ids"][0])
        or set(spec.metadata)
        != {
            "evaluation_split",
            LOCAL_TERMINAL_CAPTURE_METADATA_KEY,
            OPERATIONAL_SEED_POLICY_METADATA_KEY,
        }
        or thaw_json(spec.metadata[LOCAL_TERMINAL_CAPTURE_METADATA_KEY])
        != dict(LOCAL_TERMINAL_CAPTURE_PROFILE)
        or not 1 <= len(spec.seeds) <= MAX_OPERATIONAL_SEEDS
        or spec.required_ablations
        or spec.evidence_class is not EvidenceClass.NON_EVIDENTIARY
    ):
        _fail("unsupported operational attempt scope")
    return value


def _source_binding(registry, records, spec_record, run_id):
    _record(registry, records, spec_record.sha256)
    _policy(
        _parse_checked_frozen_run_spec(
            safe_json_loads(registry.get_bytes(spec_record.sha256))
        )
    )
    native = _spec_candidate(registry, spec_record, {r.sha256: r for r in records})
    spec = native.spec
    policy = _policy(spec)
    slot = {
        "ledger_run_id": run_id,
        "cohort_id": policy["cohort_id"],
        "attempt": spec.attempt,
    }
    return {
        **slot,
        "contract_artifact_sha256": native.contract_record.sha256,
        "contract_record_hash": native.contract_record.record_hash,
        "frozen_run_spec_artifact_sha256": spec_record.sha256,
        "frozen_run_spec_record_hash": spec_record.record_hash,
        "frozen_run_spec_sha256": spec.sha256,
        "input_artifact_sha256s": list(native.input_artifact_sha256s),
        "input_artifact_record_hashes": list(native.input_artifact_record_hashes),
        "dataset_id": native.projection.dataset_id,
        "split_id": spec.metadata["evaluation_split"],
        "seed_order": list(spec.seeds),
        "execution_run_id": spec.run_id,
        "job_id": f"local-{spec.sha256[:20]}",
        "submission_idempotency_key": "op-seed-"
        + sha256_bytes(canonical_json_bytes(slot))[:40],
        "policy": policy,
    }


def _parents(body, family):
    if family == OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE:
        if body["source_binding"]["attempt"] == 1:
            return (
                body["initial_freeze_receipt_artifact_sha256"],
                body["retry_freeze_receipt_artifact_sha256"],
            )
        return (
            body["retry_freeze_receipt_artifact_sha256"],
            body["previous_admission_artifact_sha256"],
            body["previous_terminal_artifact_sha256"],
        )
    return tuple(
        digest
        for pair in zip(
            body["admission_artifact_sha256s"],
            body["terminal_artifact_sha256s"],
            strict=True,
        )
        for digest in pair
    )


def _origin(family, binding):
    return f"{_ORIGIN} {family} {binding['ledger_run_id']}:{binding['cohort_id']}:{binding['attempt']}"


def _planned_record(registry, body, family):
    data = _raw(body)
    if len(data) > MAX_OPERATIONAL_REPORT_BYTES:
        _fail("operational publication exceeds its closed byte capacity")
    digest = sha256_bytes(data)
    path = registry._object_relative(digest).as_posix()
    return ArtifactRecord(
        sha256=digest,
        path=path,
        relative_path=path,
        metadata_path=registry._metadata_relative(digest).as_posix(),
        logical_type=family,
        schema_version=_SCHEMAS[family],
        mime_type="application/json",
        size=len(data),
        origin=_origin(family, body["source_binding"]),
        creator_role=Role.EXPERIMENT_RUNNER,
        creation_command=_COMMAND,
        parent_artifacts=_parents(body, family),
        validation_result="PASS",
        frozen=True,
        created_at=body["recorded_at"],
    )


def _read_body(registry, records, record, family):
    _record(registry, records, record.sha256)
    data = registry.get_bytes(record.sha256)
    value = safe_json_loads(data, max_bytes=MAX_OPERATIONAL_REPORT_BYTES)
    keys = (
        _ADMISSION_KEYS
        if family == OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE
        else _REPORT_KEYS
    )
    if (
        type(value) is not dict
        or set(value) != keys
        or value["schema_version"] != _SCHEMAS[family]
        or value["profile_id"] != OPERATIONAL_PROFILE_ID
        or value["authority_scope"] != _SCOPE
        or any(value[name] is not flag for name, flag in _FLAGS.items())
        or type(value["source_binding"]) is not dict
        or set(value["source_binding"]) != _SOURCE_KEYS
        or _raw(value) != data
    ):
        _fail("operational artifact has a noncanonical closed schema")
    if _planned_record(registry, value, family) != record:
        _fail("operational artifact metadata or parents differ")
    return value


def _source_prefix(records, events, body):
    source = _require_registry_record_map(
        records,
        source_record_map=tuple(
            tuple(p) for p in body["source_registry_record_identities"]
        ),
        source_record_count=body["source_registry_record_count"],
        source_record_map_fingerprint=body["source_registry_record_map_fingerprint"],
    )
    count = body["source_ledger_event_count"]
    if type(count) is not int or not 0 <= count <= len(events):
        _fail("operational source ledger prefix count is invalid")
    selected = events[:count]
    head = selected[-1].event_hash if selected else None
    if head != body["source_ledger_head_hash"]:
        _fail("operational source ledger prefix changed")
    return source, selected


def _event_id(body, family):
    b = body["source_binding"]
    slot = {"run_id": b["ledger_run_id"], "cohort_id": b["cohort_id"]}
    if family == OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE:
        slot["attempt"] = b["attempt"]
    return (
        "evt-op-seed-"
        + sha256_bytes(canonical_json_bytes({"family": family, **slot}))[:40]
    )


def _event(body, record, events):
    b = body["source_binding"]
    key = _EVENT_KEYS[record.logical_type]
    return LedgerEvent.create(
        run_id=b["ledger_run_id"],
        event_id=_event_id(body, record.logical_type),
        timestamp=body["recorded_at"],
        actor_role=Role.EXPERIMENT_RUNNER,
        state_before=_timeline_state(events),
        requested_state_after=_timeline_state(events),
        artifact_hashes=(record.sha256,),
        code_version="sha256:" + b["input_artifact_sha256s"][0],
        configuration_hash=b["input_artifact_sha256s"][2],
        dataset_identifiers=(b["dataset_id"], b["split_id"]),
        random_seeds=tuple(b["seed_order"]),
        evaluator_outputs=(),
        reason="recorded operational seed bookkeeping without scientific authority",
        prior_event_hash=body["source_ledger_head_hash"],
        event_type="CHECKPOINT",
        metadata={
            "artifact_types": [record.logical_type],
            "artifact_record_hashes": [record.record_hash],
            key: {
                "schema_version": _SCHEMAS[record.logical_type],
                "profile_id": OPERATIONAL_PROFILE_ID,
                "ledger_run_id": b["ledger_run_id"],
                "cohort_id": b["cohort_id"],
                "attempt": b["attempt"],
                "artifact_sha256": record.sha256,
                "artifact_record_hash": record.record_hash,
                "frozen_run_spec_artifact_sha256": b["frozen_run_spec_artifact_sha256"],
                "authority_scope": _SCOPE,
            },
        },
    )


def _matching_events(events, body, record, *, selectors=None):
    key = _EVENT_KEYS[record.logical_type]
    b = body["source_binding"]
    matches = []
    for selector in (
        _snapshot_event_selectors(events) if selectors is None else selectors
    ):
        index, event = selector.index, selector.event
        raw = event.metadata.get(key)
        hint = isinstance(raw, Mapping) and (
            raw.get("ledger_run_id"),
            raw.get("cohort_id"),
        ) == (b["ledger_run_id"], b["cohort_id"])
        if hint and record.logical_type == OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE:
            hint = raw.get("attempt") == b["attempt"]
        related = (
            event.event_id == _event_id(body, record.logical_type)
            or record.sha256 in event.artifact_hashes
            or bool(
                selector.references.intersection({record.sha256, record.record_hash})
            )
            or isinstance(raw, Mapping)
            and (
                raw.get("artifact_sha256") == record.sha256
                or raw.get("artifact_record_hash") == record.record_hash
            )
        )
        if hint or related:
            if key not in event.metadata or not isinstance(raw, Mapping):
                _fail("related operational event binding is absent or malformed")
            matches.append((index, event))
    if len(matches) > 1:
        _fail("operational event slot is ambiguous")
    if matches:
        index, event = matches[0]
        if index != body["source_ledger_event_count"] or _raw(event.to_dict()) != _raw(
            _event(body, record, events[:index]).to_dict()
        ):
            _fail("operational checkpoint differs from exact publication")
        if any(
            e.event_type == "CORRECTION" and e.supersedes_event_id == event.event_id
            for e in events
        ):
            _fail("operational checkpoint was corrected")
    return tuple(matches)


def _owned_records(registry, records, family):
    result = []
    for record in records:
        related = (
            record.logical_type == family
            or record.schema_version == _SCHEMAS[family]
            or record.origin.startswith(f"{_ORIGIN} {family} ")
            or record.logical_type not in _SCHEMAS
            and _payload_family_hint(registry, records, record) == family
        )
        if not related:
            continue
        if record.logical_type != family:
            _fail("operational family alias has substituted metadata")
        if family != LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE:
            _read_body(registry, records, record, family)
        result.append(record)
    return tuple(result)


def _freeze_descriptor(registry, records, events, receipt_sha):
    """Exact receipt/D/population structure, without reopening family authority."""
    record = _record(registry, records, receipt_sha)
    raw = registry.get_bytes(receipt_sha)
    receipt = EvaluationContractFreezeGateReceipt.from_dict(safe_json_loads(raw))
    if (
        record.logical_type != "evaluation_contract_freeze_gate_receipt"
        or record.schema_version != "1.0"
        or record.creator_role is not Role.CLAIM_VERIFIER
        or record.origin
        != "registry-ledger prospective evaluation-contract freeze verification"
        or record.creation_command
        != ("scientist-one", "verify-evaluation-contract-freeze")
        or record.mime_type != "application/json"
        or not record.frozen
        or record.validation_result != "PASS"
        or raw != _raw(receipt.to_dict())
    ):
        _fail("operational freeze receipt descriptor is not source-owned")
    spec_record = _record(registry, records, receipt.frozen_run_spec_artifact_sha256)
    _policy(
        _parse_checked_frozen_run_spec(
            safe_json_loads(registry.get_bytes(spec_record.sha256))
        )
    )
    native = _spec_candidate(registry, spec_record, {r.sha256: r for r in records})
    expected_receipt = replace(
        receipt,
        ledger_path=f"runs/{receipt.run_id}/events.jsonl",
        object_id=native.projection.contract_id,
        contract_version=native.projection.version,
        hypothesis_id=native.spec.hypothesis_id,
        experiment_id=native.spec.experiment_id,
        stage=ExperimentStage(native.spec.phase.value),
    )
    if _raw(receipt.to_dict()) != _raw(expected_receipt.to_dict()):
        _fail("operational freeze receipt changes its declared design identity")
    sources = (native.contract_record, *native.plan_records, spec_record)
    index = receipt.design_freeze_event_index
    if (
        type(index) is not int
        or not 0 <= index < len(events)
        or record.parent_artifacts != tuple(r.sha256 for r in sources)
        or receipt.contract_artifact_sha256 != native.contract_record.sha256
        or receipt.contract_record_hash != native.contract_record.record_hash
        or receipt.contract_sha256 != native.projection.contract_sha256
        or receipt.frozen_run_spec_record_hash != spec_record.record_hash
        or receipt.frozen_run_spec_sha256 != native.spec.sha256
        or receipt.experiment_plan_artifact_sha256s
        != tuple(r.sha256 for r in native.plan_records)
        or receipt.experiment_plan_record_hashes
        != tuple(r.record_hash for r in native.plan_records)
    ):
        _fail("operational freeze receipt native source identities differ")
    event = events[index]
    metadata = thaw_json(event.metadata)
    population = metadata.get("evaluation_contract_design_population")
    if type(population) is not dict or set(population) != {
        "schema_version",
        "source_registry_record_map",
        "source_registry_record_count",
        "source_registry_record_map_fingerprint",
        "source_ledger_event_count",
        "source_ledger_head_hash",
    }:
        _fail("operational profile requires the actual sealed design population")
    if (
        population["schema_version"] != "evaluation-contract-design-population/v1"
        or type(population["source_ledger_event_count"]) is not int
        or population["source_ledger_event_count"] != index
        or population["source_ledger_head_hash"] != event.prior_event_hash
    ):
        _fail("operational design population prefix differs")
    sealed = _require_registry_record_map(
        records,
        source_record_map=tuple(
            tuple(p) for p in population["source_registry_record_map"]
        ),
        source_record_count=population["source_registry_record_count"],
        source_record_map_fingerprint=population[
            "source_registry_record_map_fingerprint"
        ],
    )
    sealed_by_sha = {r.sha256: r for r in sealed}
    if any(sealed_by_sha.get(r.sha256) != r for r in sources) or any(
        p not in sealed_by_sha for r in sealed for p in r.parent_artifacts
    ):
        _fail("operational design population omits source ancestry")
    expected_metadata = {
        "artifact_types": [r.logical_type for r in sources],
        "artifact_record_hashes": [r.record_hash for r in sources],
        "scientific_timeline": _timeline_binding(
            kind="DESIGN_FROZEN",
            contract_record=native.contract_record,
            projection=native.projection,
            plan_records=native.plan_records,
            spec_record=spec_record,
            spec=native.spec,
            manifest_record=None,
            design_event=None,
        ),
        "evaluation_contract_design_population": population,
    }
    if (
        event.run_id != receipt.run_id
        or event.event_id != receipt.design_freeze_event_id
        or event.event_hash != receipt.design_freeze_event_hash
        or event.prior_event_hash != (events[index - 1].event_hash if index else None)
        or event.event_type != "CHECKPOINT"
        or event.actor_role is not Role.PROTOCOL_DESIGNER
        or event.artifact_hashes != tuple(r.sha256 for r in sources)
        or event.code_version != "sha256:" + native.spec.code_sha256
        or event.configuration_hash != native.spec.configuration_sha256
        or event.dataset_identifiers
        != (native.projection.dataset_id, native.spec.metadata["evaluation_split"])
        or event.random_seeds != native.spec.seeds
        or event.evaluator_outputs
        or event.state_before != event.requested_state_after
        or event.reason
        != "froze exact contract, per-seed plans, and run spec before submission"
        or _raw(metadata) != _raw(expected_metadata)
        or any(
            e.event_type == "CORRECTION" and e.supersedes_event_id == event.event_id
            for e in events
        )
    ):
        _fail("operational receipt does not bind the exact selected design event")
    return receipt, native


def operational_seed_progress_descriptors(
    registry: ArtifactRegistry,
    *,
    records: tuple[ArtifactRecord, ...],
    events: tuple[LedgerEvent, ...],
) -> tuple[OperationalSeedProgress, ...]:
    """Replay only the caller's selected population; never perform admission.

    An A-only descriptor is reserved/unresolved, even if its event is absent.
    Native T refines observed bookkeeping but confers no fresh-data exemption.
    This function never calls a full contract, freeze, admission or report owner.
    """
    if (
        type(registry) is not ArtifactRegistry
        or type(records) is not tuple
        or type(events) is not tuple
    ):
        _fail("passive progress requires exact selected native tuples")
    _registry_record_map(records)
    for record in records:
        if (
            record.origin.startswith(_ORIGIN) or record.creation_command == _COMMAND
        ) and record.logical_type not in _SCHEMAS:
            _fail("reserved operational owner metadata is attached to another family")
    admissions = _owned_records(
        registry, records, OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE
    )
    terminals = _owned_records(registry, records, LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE)
    reports = _owned_records(
        registry, records, OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
    )
    selectors = _snapshot_event_selectors(events)
    identities = {
        identity
        for record in (*admissions, *terminals, *reports)
        for identity in (record.sha256, record.record_hash)
    }
    selected_event_indices = {
        item.index
        for item in selectors
        if _operational_event_selected(item, identities)
    }
    consumed_event_indices = set()

    def consume(matches):
        for index, _event_value in matches:
            if index in consumed_event_indices:
                _fail("reserved operational event was consumed by multiple artifacts")
            consumed_event_indices.add(index)

    result = []
    seen_slots = set()
    consumed_terminals = set()
    for admission in admissions:
        body = _read_body(
            registry, records, admission, OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE
        )
        source_records, _prefix = _source_prefix(records, events, body)
        if admission.sha256 in {r.sha256 for r in source_records}:
            _fail("admission appears in its own prospective source population")
        b = body["source_binding"]
        spec_record = _record(
            registry, source_records, b["frozen_run_spec_artifact_sha256"]
        )
        if _raw(b) != _raw(
            _source_binding(registry, source_records, spec_record, b["ledger_run_id"])
        ):
            _fail("admission source descriptor differs from native spec")
        for parent in admission.parent_artifacts:
            _record(registry, source_records, parent)
        for receipt_key in (
            "initial_freeze_receipt_artifact_sha256",
            "retry_freeze_receipt_artifact_sha256",
        ):
            receipt, _native = _freeze_descriptor(
                registry, source_records, _prefix, body[receipt_key]
            )
            if receipt.run_id != b["ledger_run_id"]:
                _fail("admission freeze receipt names another ledger run")
        slot = (b["ledger_run_id"], b["cohort_id"], b["attempt"])
        if slot in seen_slots:
            _fail("operational admission slot is ambiguous")
        seen_slots.add(slot)
        matches = _matching_events(events, body, admission, selectors=selectors)
        consume(matches)
        archive = None
        observation = None
        for terminal in terminals:
            raw = registry.get_bytes(terminal.sha256)
            native = LocalTerminalObservation.from_bytes(raw)
            related = (
                admission.sha256 in terminal.parent_artifacts
                or native.spec_sha256 == b["frozen_run_spec_sha256"]
                or native.job_id == b["job_id"]
            )
            if not related:
                continue
            _record(registry, records, terminal.sha256)
            if (
                archive is not None
                or not matches
                or terminal.parent_artifacts != (admission.sha256,)
            ):
                _fail(
                    "terminal archive is ambiguous or lacks exact completed admission"
                )
            if (
                terminal.schema_version != _SCHEMAS[LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE]
                or terminal.creator_role is not Role.EXPERIMENT_RUNNER
                or terminal.creation_command != _COMMAND
                or terminal.origin != _origin(LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE, b)
                or terminal.mime_type != "application/json"
                or not terminal.frozen
                or terminal.validation_result != "PASS"
                or native.spec_sha256 != b["frozen_run_spec_sha256"]
                or native.job_id != b["job_id"]
                or native.submission_idempotency_key != b["submission_idempotency_key"]
            ):
                _fail("terminal archive native admission binding differs")
            frozen = next(
                (f for f in native.files if f.path == "frozen-run-spec.json"), None
            )
            if frozen is None or frozen.payload != registry.get_bytes(
                spec_record.sha256
            ):
                _fail("terminal archive does not preserve exact frozen spec bytes")
            archive, observation = terminal, native
            consumed_terminals.add(terminal.sha256)
        related_reports = []
        for report in reports:
            rb = _read_body(
                registry, records, report, OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
            )
            if admission.sha256 in rb["admission_artifact_sha256s"]:
                _source_prefix(records, events, rb)
                related_reports.append(report)
        result.append(
            OperationalSeedProgress(
                admission,
                freeze_json(b),
                tuple(tuple(p) for p in body["source_registry_record_identities"]),
                body["source_ledger_event_count"],
                body["source_ledger_head_hash"],
                matches[0][1] if matches else None,
                matches[0][0] if matches else None,
                archive,
                observation,
                tuple(related_reports),
            )
        )
    if consumed_terminals != {record.sha256 for record in terminals}:
        _fail("terminal archive lacks its selected admission source")
    for report in reports:
        rb = _read_body(
            registry, records, report, OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
        )
        consume(_matching_events(events, rb, report, selectors=selectors))
        selected = tuple(
            p
            for p in result
            if p.admission_record.sha256 in rb["admission_artifact_sha256s"]
        )
        selected = tuple(sorted(selected, key=lambda p: p.source_binding["attempt"]))
        if not selected or _raw(rb["source_binding"]) != _raw(
            selected[0].source_binding
        ):
            _fail("report alias substitutes its admitted source cohort")
        sources = []
        for p in selected:
            sr = _record(
                registry, records, p.source_binding["frozen_run_spec_artifact_sha256"]
            )
            native = _spec_candidate(registry, sr, {r.sha256: r for r in records})
            _cr, _wrapper, contract = _require_frozen_evaluation_contract_descriptor(
                registry, contract_artifact_sha256=native.contract_record.sha256
            )
            sources.append((None, None, contract, sr, native.spec))
        projection = _report_projection(selected, sources)
        if any(_raw(rb[key]) != _raw(value) for key, value in projection.items()):
            _fail("passive report is not the exact native attempt projection")
    if selected_event_indices != consumed_event_indices:
        _fail(
            "reserved operational event population contains an unmatched native checkpoint"
        )
    return tuple(
        sorted(
            result,
            key=lambda p: (
                p.source_binding["ledger_run_id"],
                p.source_binding["cohort_id"],
                p.source_binding["attempt"],
            ),
        )
    )


def _base(before, binding, family, timestamp=None):
    count, fingerprint = _registry_map_fingerprint(before[0].records)
    return {
        "schema_version": _SCHEMAS[family],
        "profile_id": OPERATIONAL_PROFILE_ID,
        "authority_scope": _SCOPE,
        "recorded_at": timestamp or utc_now(),
        "source_binding": thaw_json(binding),
        **_FLAGS,
        "source_registry_record_identities": [
            list(pair) for pair in _registry_record_map(before[0].records)
        ],
        "source_registry_record_count": count,
        "source_registry_record_map_fingerprint": fingerprint,
        "source_ledger_event_count": before[1].event_count,
        "source_ledger_head_hash": before[1].head_hash,
    }


def _commit(registry, ledger, before, body, family, existing=None, precommit=None):
    planned = _planned_record(registry, body, family)
    missing = int(existing is None)
    event = _event(body, planned, before[1].events)
    if (
        before[0].count + missing > MAX_REGISTRY_RECORDS
        or before[1].event_count + 1 > MAX_LEDGER_EVENTS
        or before[1].valid_prefix_bytes + len(_raw(event.to_dict())) > MAX_LEDGER_BYTES
        or len(planned.parent_artifacts) > MAX_ARTIFACT_PARENTS
    ):
        _fail("operational publication exceeds registry/ledger capacity")
    if existing is not None and existing != planned:
        _fail("operational orphan metadata differs")
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        _fail("operational sources changed during preflight")
    rg = registry._open_mutation_lock()
    try:
        lg = ledger._open_lock()
        try:
            locked_ledger_bytes = ledger._read_raw_locked(lg)
            actual = (
                registry._verify_all_locked(rg, raise_on_error=True),
                ledger._validate_bytes(locked_ledger_bytes),
            )
            if actual != before:
                _fail("operational sources changed before publication CAS")
            if precommit is not None:
                precommit()
            if type(event) is not LedgerEvent:
                _fail("operational publication requires one exact native event")
            event_bytes = _raw(event.to_dict())
            detached_event = LedgerEvent.from_dict(safe_json_loads(event_bytes))
            prospective = ledger._validate_bytes(locked_ledger_bytes + event_bytes)
            if (
                detached_event != event
                or _raw(detached_event.to_dict()) != event_bytes
                or detached_event.prior_event_hash != before[1].head_hash
                or any(e.event_id == detached_event.event_id for e in before[1].events)
                or not prospective.valid
                or prospective.event_count != before[1].event_count + 1
                or prospective.events != (*before[1].events, detached_event)
                or prospective.head_hash != detached_event.event_hash
                or prospective.valid_prefix_bytes
                != len(locked_ledger_bytes) + len(event_bytes)
            ):
                _fail(
                    "prospective operational checkpoint is not one exact valid append"
                )
            event = detached_event
            record = existing
            if record is None:
                record = registry._put_bytes_locked(
                    rg,
                    _raw(body),
                    logical_type=family,
                    schema_version=planned.schema_version,
                    mime_type=planned.mime_type,
                    origin=planned.origin,
                    creator_role=planned.creator_role,
                    creation_command=planned.creation_command,
                    parent_artifacts=planned.parent_artifacts,
                    validation_result=planned.validation_result,
                    frozen=True,
                    created_at=planned.created_at,
                )
            if record != planned:
                _fail("operational record changed during publication")

            def build(current):
                if current != before[1]:
                    _fail("operational ledger changed inside commit")
                return event

            appended = ledger._append_locked(lg, build)
            if appended != event:
                _fail("operational event changed during publication")
            registry._verify_mutation_namespace(rg)
            final_records = registry._verify_all_locked(rg, raise_on_error=True)
            final_ledger = ledger._validate_bytes(ledger._read_raw_locked(lg))
            expected_records = {r.sha256: r for r in before[0].records}
            expected_records[record.sha256] = record
            if {
                r.sha256: r for r in final_records.records
            } != expected_records or final_ledger.events != (*before[1].events, event):
                _fail("operational publication changed outside its exact delta")
            return record, event
        finally:
            ledger._unlock(lg)
    finally:
        registry._unlock_mutation(rg)


def _full_sources(registry, ledger, run_id, first_sha, retry_sha, backend):
    before = _context(registry, ledger, run_id)
    if type(backend) is not LocalMacBackend or backend._root != registry.policy.root:
        _fail("operational execution requires the exact co-rooted builtin backend")
    resolved = []
    for digest in (first_sha, retry_sha):
        record = _record(registry, before[0].records, digest)
        value = safe_json_loads(registry.get_bytes(digest))
        receipt = EvaluationContractFreezeGateReceipt.from_dict(value)
        contract = require_frozen_evaluation_contract(
            registry, contract_artifact_sha256=receipt.contract_artifact_sha256
        )
        receipt = require_evaluation_contract_freeze_gate_receipt(
            registry,
            ledger,
            receipt_artifact_sha256=digest,
            expected_run_id=run_id,
            expected_contract_id=contract.contract_id,
        )
        _freeze_descriptor(registry, before[0].records, before[1].events, digest)
        spec_record = _record(
            registry, before[0].records, receipt.frozen_run_spec_artifact_sha256
        )
        spec = _parse_checked_frozen_run_spec(
            safe_json_loads(registry.get_bytes(spec_record.sha256))
        )
        _policy(spec)
        backend._terminal_profile(spec)
        if (
            contract.seed_reporting.regime is not ReportingRegime.BEST_OF_N
            or contract.seed_reporting.seeds != spec.seeds
            or type(contract.seed_reporting.best_of_n) is not int
            or contract.seed_reporting.best_of_n != len(spec.seeds)
            or contract.seed_reporting.selection_policy != OPERATIONAL_SELECTION_RULE
            or contract.seed_reporting.technical_retry_rule != OPERATIONAL_RETRY_RULE
            or contract.ablations
            or contract.compute_budget.max_runs < len(spec.seeds) * 2
        ):
            _fail("frozen contract does not bind this operational population/policy")
        resolved.append((record, receipt, contract, spec_record, spec))
    first, second = resolved
    if (
        first[2] != second[2]
        or first[4].attempt != 1
        or second[4]
        != replace(
            first[4],
            run_id=_policy(first[4])["attempt_run_ids"][1],
            attempt=2,
            retry_of_run_id=first[4].run_id,
        )
    ):
        _fail("retry is not the exact prospectively fixed attempt")
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        _fail("full frozen source closure changed during replay")
    return tuple(resolved)


def _queue_retry(native):
    return (
        native.state == "FAILED"
        and native.reason == "LOCAL_QUEUE_TIMEOUT"
        and native.invocation_count == 0
        and native.proven_popen_launch_count == 0
        and native.launch_observation == "NOT_INVOKED"
        and native.returncode is None
        and native.timed_out is None
        and native.accepted_manifest_sha256 is None
        and all(f.role == "source" or f.status == "MISSING" for f in native.files)
        and not any(
            f.path == "terminal-dispatch-intent.json" or f.role == "output"
            for f in native.files
        )
    )


def _archive(registry, ledger, run_id, admission, backend, spec):
    before = _context(registry, ledger, run_id)
    descriptors = operational_seed_progress_descriptors(
        registry, records=before[0].records, events=before[1].events
    )
    item = next(p for p in descriptors if p.admission_record == admission)
    if item.admission_event is None:
        _fail("terminal cannot be archived before complete admission")
    native = backend.recover_terminal_observation(
        spec, idempotency_key=item.source_binding["submission_idempotency_key"]
    )
    if item.terminal_record is not None:
        if native != item.terminal_observation:
            _fail("native terminal differs from archived capture")
        return item.terminal_record, native
    data = native.payload
    digest = sha256_bytes(data)
    if (
        before[0].count + 1 > MAX_REGISTRY_RECORDS
        or len(data) > LOCAL_TERMINAL_MAX_JSON_BYTES
    ):
        _fail("terminal archive capacity unavailable")
    if any(r.sha256 == digest for r in before[0].records):
        _fail("native terminal content already has other metadata")
    rg = registry._open_mutation_lock()
    try:
        lg = ledger._open_lock()
        try:
            if (
                registry._verify_all_locked(rg, raise_on_error=True),
                ledger._validate_bytes(ledger._read_raw_locked(lg)),
            ) != before:
                _fail("terminal archive sources changed before CAS")
            if backend.collect_terminal_observation(native.job_id) != native:
                _fail("terminal changed before archival")
            record = registry._put_bytes_locked(
                rg,
                data,
                logical_type=LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE,
                schema_version=_SCHEMAS[LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE],
                mime_type="application/json",
                origin=_origin(
                    LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE, item.source_binding
                ),
                creator_role=Role.EXPERIMENT_RUNNER,
                creation_command=_COMMAND,
                parent_artifacts=(admission.sha256,),
                validation_result="PASS",
                frozen=True,
                created_at=None,
            )
            registry._verify_mutation_namespace(rg)
            if ledger._validate_bytes(ledger._read_raw_locked(lg)) != before[1]:
                _fail("terminal archival changed ledger")
            return record, native
        finally:
            ledger._unlock(lg)
    finally:
        registry._unlock_mutation(rg)


def _cohort(descriptors, binding):
    return tuple(
        p
        for p in descriptors
        if (p.source_binding["ledger_run_id"], p.source_binding["cohort_id"])
        == (binding["ledger_run_id"], binding["cohort_id"])
    )


def _reject_scientific_overlap(registry, records, events, *, native_design_events):
    if (
        type(native_design_events) is not tuple
        or len(native_design_events) != 2
        or any(type(event) is not LedgerEvent for event in native_design_events)
        or len({event.event_hash for event in native_design_events}) != 2
    ):
        _fail("initial operational profile requires both exact native design events")
    protected = {
        "experiment_output_manifest",
        "aggregate_experiment_result",
        "statistical_analysis",
        "scientific_dataset_acquisition_plan",
        "scientific_dataset_manifest",
        "scientific_dataset_usage_proposal",
        "scientific_dataset_usage",
        "scientific_dataset_authority",
        "scientific_dataset_split_authority",
        "scientific_dataset_statistical_use_proposal",
        "scientific_dataset_statistical_use_authority",
        "scientific_execution_preparation",
        "scientific_execution_plan",
        "scientific_execution_input_binding",
        "frozen_protocol",
        "frozen_confirmatory_split",
        "fresh_custody_receipt",
        "custody_record",
        "scientific_confirmatory_protocol_binding",
        "scientific_confirmatory_timeline_receipt_v2",
        "confirmatory_timeline_receipt",
        "confirmation_reveal_gate_receipt",
        "research_state.run",
        "research_state.result",
        "research_state.statistical_test",
        "scientific_execution_authority",
        "scientific_execution_activity",
        "scientific_execution_environment",
        "scientific_execution_isolation_attestation",
        "backend_execution_attestation",
        "scientific_result_state_projection",
        "scientific_statistical_state_projection",
        "scientific_result_promotion_authority",
        "scientific_result_promotion_authority_v3",
        "scientific_result_state_bundle_completion",
        # This first profile intentionally excludes even draft canonical
        # Dataset/Split coexistence. That is a policy limit, not a claim that
        # every such object represents a protected resource.
        "research_state.dataset",
        "research_state.split",
    }
    protected_schemas = {
        "SCIENTIST_ONE_OUTPUT_MANIFEST_V1",
        "checked-superiority-aggregate/v1",
        "checked-superiority-statistics/v1",
        "scientific-execution-plan/v1",
        "scientific-execution-input-binding/v1",
        "scientific-execution-preparation/v1",
        "scientific-protocol-revision/v1",
        "scientific-dataset-acquisition-plan/v1",
        "scientific-dataset-manifest/v2",
        "scientific-dataset-usage-proposal/v2",
        "scientific-dataset-usage/v2",
        "scientific-dataset-authority/v2",
        "scientific-dataset-split-authority/v1",
        "scientific-experiment-dataset/v1",
        "scientific-dataset-source/v1",
        "scientific-dataset-sampling-source/v1",
        "scientific_execution_authority/v1",
        "SCIENTIST_ONE_SCIENTIFIC_EXECUTION_AUTHORITY_V2",
        "SCIENTIST_ONE_EXECUTION_ACTIVITY_V1",
        "scientific-execution-environment/v1",
        "scientific-execution-isolation-attestation/v1",
        "backend-execution-attestation-envelope/v1",
        "backend-execution-attestation-envelope/v2",
        *(
            f"scientific-dataset-statistical-use-{kind}/v{version}"
            for kind in ("proposal", "authority")
            for version in (1, 2)
        ),
    }
    protected_commands = {
        "prepare-scientific-execution",
        "record-scientific-protocol-revision",
        "plan-scientific-dataset-acquisition",
        "manifest-audited-scientific-dataset",
        "propose-scientific-dataset-usage",
        "verify-scientific-dataset-usage",
        "authorize-audited-scientific-dataset",
        "project-scientific-experiment-dataset",
        "freeze-scientific-dataset-splits",
        "propose-dataset-statistical-use",
        "authorize-dataset-statistical-use",
        "verify-scientific-execution",
        "capture-scientific-execution-activity",
    }

    def protected_value(value):
        if not isinstance(value, Mapping):
            return False
        return (
            type(value.get("schema_version")) is str
            and value["schema_version"] in protected_schemas
            or type(value.get("kind")) is str
            and value["kind"]
            in {
                "FROZEN_SYNTHETIC_PROTOCOL",
                "FROZEN_CONFIRMATORY_SPLIT",
                "SIMULATED_HOLDOUT_CUSTODY",
                "RESULT_OBSERVED",
            }
            or type(value.get("object_type")) is str
            and value["object_type"]
            in {"Run", "Result", "StatisticalTest", "Dataset", "Split"}
            or value.get("policy_id") == "scientific-dataset-pinned-json/v1"
            or value.get("adapter_id") == "scientist-one-scientific-dataset-json-v1"
        )

    protected_event_keys = {
        "scientific_execution_preparation",
        "scientific_protocol_revision",
        "fresh_custody",
        "scientific_confirmatory_protocol_binding",
        "scientific_confirmatory_timeline",
        "scientific_dataset_acquisition_plan",
        "scientific_dataset_split",
        "dataset_statistical_use_proposal",
        "dataset_statistical_use_authority",
        "scientific_execution_authority",
        "scientific_execution_authority_publication",
        "scientific_result_state_projection",
        "scientific_result_promotion",
    }
    protected_event_schemas = {
        "protocol-revision-event/v1",
        "scientific-dataset-acquisition-plan-event/v1",
        "scientific-dataset-authority-event/v2",
        "scientific-dataset-split-event/v1",
        "scientific-experiment-dataset/v1",
        "scientific-execution-prepared-event/v1",
        "scientific-execution-attested-event/v1",
        "scientific-execution-attested-event/v2",
        "scientific-execution-authority-publication/v1",
        "scientific-confirmatory-protocol-binding-event/v1",
        "scientific-confirmatory-timeline-publication/v2",
        "scientific-result-state-projection-event/v1",
        "scientific-result-promotion-authority-event/v3",
        *(
            f"scientific-dataset-statistical-use-{kind}-event/v{version}"
            for kind in ("proposal", "authority")
            for version in (1, 2)
        ),
    }

    for selector in _snapshot_event_selectors(events):
        event = selector.event
        if "scientific_timeline" in selector.keys or any(
            value.get("schema_version") == "scientific-timeline-event/v1"
            for value in selector.mappings
        ):
            # Only the two D events already bound by the fully replayed F0/F1
            # owners are supported here. Extra otherwise-valid designs are
            # unsupported multi-design coexistence, not proven protected
            # exposure or scientific invalidity. Copies/nested fragments do
            # not inherit a native event's historical design exemption.
            expected = next(
                (
                    candidate
                    for candidate in native_design_events
                    if candidate.event_id == event.event_id
                    and candidate.event_hash == event.event_hash
                ),
                None,
            )
            value = event.metadata.get("scientific_timeline")
            if (
                expected is None
                or _raw(expected.to_dict()) != _raw(event.to_dict())
                or not isinstance(value, Mapping)
                or value.get("schema_version") != "scientific-timeline-event/v1"
                or value.get("kind") != "DESIGN_FROZEN"
                or "output_manifest_artifact_sha256" not in value
                or value["output_manifest_artifact_sha256"] is not None
            ):
                _fail(
                    "unsupported additional or incomplete scientific timeline in this operational profile"
                )
        if (
            event.event_type in {"CONFIRMATORY_STARTED", "CONFIRMATORY_COMPLETED"}
            or selector.keys.intersection(protected_event_keys)
            or selector.strings.intersection(protected_event_schemas)
            or selector.families.intersection(protected)
            or any(
                family.startswith("experiment_output.") for family in selector.families
            )
            or any(
                value.get("research_state_operation")
                in {"MATERIALIZED", "SUPERSEDED", "BUNDLE_COMPLETE"}
                for value in selector.mappings
            )
            or event.event_id.startswith(
                (
                    "scientific-dataset-",
                    "scientific-experiment-dataset-",
                    "dataset-statistical-use-proposal-",
                    "dataset-statistical-use-authority-",
                )
            )
            or any(protected_value(value) for value in selector.mappings)
        ):
            _fail(
                "operational profile cannot coexist with protected/scientific event progress"
            )
    for record in records:
        shared_spec_marker = (
            record.logical_type == "frozen_run_spec"
            or record.origin
            == "run spec frozen after scientific-plan admission and before execution"
            or record.creation_command == ("scientist-one", "freeze-run-spec")
        )
        if shared_spec_marker and record.logical_type != "frozen_run_spec":
            _fail("shared native run-spec metadata appears under a wrong family")
        if (
            record.logical_type in protected
            or record.logical_type.startswith("experiment_output.")
            or record.schema_version in protected_schemas
            or record.creation_command
            in {("scientist-one", command) for command in protected_commands}
            or record.origin
            == "source-owned prospective scientific execution preparation"
            or record.origin
            in {
                "exact manifest bytes captured by the local backend",
                "deterministically aggregated synthetic development result",
                "deterministic paired statistical audit over subject-level fixture outcomes",
            }
            or record.creation_command
            == ("scientist-one", "research-os-fixture", "capture-output-manifest")
            or record.origin.startswith(
                (
                    "append-only scientific protocol revision ",
                    "audited scientific experiment Dataset projection ",
                    "research-state:Run:",
                    "research-state:Result:",
                    "research-state:StatisticalTest:",
                    "prospective scientific Dataset acquisition ",
                    "audited external scientific dataset manifest ",
                    "non-authoritative audited Dataset usage proposal ",
                    "audited-review public license basis ",
                    "audited external scientific dataset authority ",
                    "deterministic scientific Dataset split ",
                    "prospective Dataset statistical-use proposal ",
                    "evidence-supported Dataset statistical-use authority ",
                    "source-owned independently attested scientific execution",
                    "backend-captured exhaustive scientific execution activity",
                )
            )
        ):
            _record(registry, records, record.sha256)
            _fail(
                "operational isolated-disabled profile forbids run-wide protected/scientific coexistence"
            )
        # A wrong MIME label cannot hide an explicit bounded source schema.
        # Oversized JSON cannot be declared unrelated in this closed profile.
        if record.size <= LOCAL_TERMINAL_MAX_JSON_BYTES:
            raw = registry.get_bytes(record.sha256)
            try:
                value = safe_json_loads(raw)
            except ValidationError:
                if raw.lstrip().startswith(b"{") and any(
                    canonical_json_bytes(schema) in raw
                    for schema in protected_schemas
                    | {"SCIENTIST_ONE_FROZEN_RUN_SPEC_V1"}
                ):
                    _fail(
                        "malformed payload contains a protected/native-spec schema marker"
                    )
                value = None
            if (
                isinstance(value, dict)
                and value.get("schema_version") == "SCIENTIST_ONE_FROZEN_RUN_SPEC_V1"
                and record.logical_type != "frozen_run_spec"
            ):
                _fail("shared native run-spec payload appears under a wrong family")
            if protected_value(value):
                _fail(
                    "operational profile found protected payload under an aliased family"
                )
        else:
            _fail("operational profile cannot classify an oversized source inventory")
        if record.logical_type != "frozen_run_spec":
            continue
        candidate = _parse_checked_frozen_run_spec(
            safe_json_loads(registry.get_bytes(record.sha256))
        )
        if candidate.evidence_class is EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE:
            _fail("operational admission overlaps already frozen scientific execution")
        _policy(candidate)
        native = _spec_candidate(registry, record, {r.sha256: r for r in records})
        if native.spec.evidence_class is EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE:
            _fail("operational admission overlaps already frozen scientific execution")


def _namespace_absent(backend, specs):
    try:
        parent = open_confined_directory_fd(
            backend._root, ".scientist-one-build/experiments/local-mac", create=False
        )
    except PathSecurityError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return
        raise
    try:
        for spec in specs:
            try:
                os.stat(
                    f"local-{spec.sha256[:20]}", dir_fd=parent, follow_symlinks=False
                )
            except FileNotFoundError:
                continue
            _fail("operational runtime job namespace already exists")
    finally:
        os.close(parent)


def _runtime_preflight(backend, spec, paths):
    backend._terminal_profile(spec)
    backend._validate_local_profile(spec)
    plan = plan_adaptive_execution(
        spec.compute_profile,
        spec.resource_estimate,
        observed_available_memory_bytes=backend._observed_available_memory_bytes,
        pending_tasks=len(spec.seeds),
        bytes_per_sample=spec.bytes_per_sample,
        worker_overhead_bytes=spec.worker_overhead_bytes,
        concurrency_cap=backend._maximum_concurrency_cap,
    )
    validate_command(
        spec.argv,
        allowed_executables=backend._allowed_executables,
        root=backend._root,
        allowed_python_modules=(),
    )
    backend._validate_required_target(spec)
    normalized = backend._normalize_execution_input_paths(spec, paths)
    total = 0
    for kind, path in normalized.items():
        raw = read_confined_bytes(
            backend._root,
            path,
            reject_hardlinks=True,
            max_bytes=LOCAL_TERMINAL_MAX_FILE_BYTES,
        )
        if raw is None or sha256_bytes(raw) != getattr(spec, kind + "_sha256"):
            _fail("prospective operational input bytes differ from frozen sources")
        total += len(raw)
    total += sum(
        len(_raw(value))
        for value in (spec.to_dict(), plan.to_dict(), backend._execution_mode_payload())
    )
    if total + 16 * 1024 > LOCAL_TERMINAL_MAX_SOURCE_BYTES:
        _fail("prospective operational source bytes exceed capture capacity")


def _admit(registry, ledger, run_id, sources, attempt, backend, paths, previous=None):
    before = _context(registry, ledger, run_id)
    selected = sources[attempt - 1]
    spec = selected[4]
    binding = _source_binding(registry, before[0].records, selected[3], run_id)
    descriptors = operational_seed_progress_descriptors(
        registry, records=before[0].records, events=before[1].events
    )
    cohort = _cohort(descriptors, binding)
    if any(p.source_binding["attempt"] == attempt for p in cohort):
        _fail("existing admission must be recovered, never redispatched")
    if any(p.report_records for p in cohort):
        _fail("final report already closes this operational cohort")
    if attempt == 1:
        native_design_events = []
        for source in sources:
            receipt, native = _freeze_descriptor(
                registry, before[0].records, before[1].events, source[0].sha256
            )
            if (
                _raw(receipt.to_dict()) != _raw(source[1].to_dict())
                or native.spec != source[4]
            ):
                _fail(
                    "initial native design differs from its fully replayed freeze owner"
                )
            native_design_events.append(
                before[1].events[receipt.design_freeze_event_index]
            )
        _reject_scientific_overlap(
            registry,
            before[0].records,
            before[1].events,
            native_design_events=tuple(native_design_events),
        )
        # F0/F1 replay establishes historical design validity. Only this first
        # admission additionally asks the existing owner about the CURRENT
        # contract/input family, before our own reservation creates exposure.
        family = _require_evaluation_contract_family_before_design(
            registry,
            ledger,
            expected_run_id=run_id,
            contract_artifact_sha256=binding["contract_artifact_sha256"],
            input_artifact_sha256s=tuple(binding["input_artifact_sha256s"]),
            design_event_index=before[1].event_count,
        )
        if (family.registry_snapshot, family.ledger_snapshot) != before:
            _fail("initial operational contract-family snapshot changed")
    elif (
        previous is None
        or previous.terminal_observation is None
        or not _queue_retry(previous.terminal_observation)
    ):
        _fail("retry lacks exact proven-not-invoked queue failure")
    namespace_specs = (
        tuple(source[4] for source in sources) if attempt == 1 else (spec,)
    )
    for prospective in namespace_specs:
        _runtime_preflight(backend, prospective, paths)
    _namespace_absent(backend, namespace_specs)
    body = {
        **_base(before, binding, OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE),
        "initial_freeze_receipt_artifact_sha256": sources[0][0].sha256,
        "retry_freeze_receipt_artifact_sha256": sources[1][0].sha256,
        "previous_admission_artifact_sha256": previous.admission_record.sha256
        if previous
        else None,
        "previous_terminal_artifact_sha256": previous.terminal_record.sha256
        if previous
        else None,
        "runtime_job_namespace_observed_absent": True,
    }
    admission, _event_record = _commit(
        registry,
        ledger,
        before,
        body,
        OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE,
        precommit=lambda: _namespace_absent(backend, namespace_specs),
    )
    try:
        backend.submit(
            spec,
            idempotency_key=binding["submission_idempotency_key"],
            input_artifact_paths=paths,
        )
    except Exception:
        # Only a genuine terminal marker can close an exceptional invocation.
        # Failure of this replay leaves the admission unresolved, never retried.
        backend.recover_terminal_observation(
            spec, idempotency_key=binding["submission_idempotency_key"]
        )
    return _archive(registry, ledger, run_id, admission, backend, spec)


def _attempt_projection(native, spec):
    rows = []
    complete = True
    raw = next((f.payload for f in native.files if f.role == "manifest"), None)
    value = None
    if raw is not None:
        try:
            value = safe_json_loads(raw)
        except ValidationError:
            complete = False
    claims = value.get("seed_results") if isinstance(value, dict) else None
    if not isinstance(claims, list) or len(claims) > MAX_OPERATIONAL_SEEDS:
        claims = []
        complete = False
    for index, claim in enumerate(claims):
        try:
            if type(claim) is not dict or set(claim) != {
                "seed",
                "status",
                "metric",
                "artifact_sha256",
                "reason",
            }:
                raise ValueError("unknown row schema")
            row = SeedRunResult(**claim)
            if type(claim["metric"]) is bool:
                raise ValueError("noncanonical row")
            _raw(row.to_dict())
        except (TypeError, ValueError, ValidationError, ExperimentError, UnicodeError):
            complete = False
            continue
        eligible = (
            native.state == "SUCCEEDED"
            and native.accepted_manifest_sha256 is not None
            and row.status
            in {SeedRunStatus.SUCCESS, SeedRunStatus.NEGATIVE, SeedRunStatus.NULL}
        )
        rows.append({"row_index": index, **row.to_dict(), "eligible": eligible})
    seeds = tuple(row["seed"] for row in rows)
    coverage = (
        "DECLARED_SEEDS_MATCH_PLAN"
        if complete and len(seeds) == len(spec.seeds) and set(seeds) == set(spec.seeds)
        else "PARTIAL_OR_INVALID"
        if claims
        else "UNOBSERVED"
    )
    if coverage != "DECLARED_SEEDS_MATCH_PLAN":
        for row in rows:
            row["eligible"] = False
    return {
        "attempt": spec.attempt,
        "execution_run_id": spec.run_id,
        "state": native.state,
        "reason": native.reason,
        "invocation_count": native.invocation_count,
        "proven_popen_launch_count": native.proven_popen_launch_count,
        "launch_observation": native.launch_observation,
        "seed_coverage": coverage,
        "manifest_admission": "NATIVE_ACCEPTED"
        if native.accepted_manifest_sha256 is not None
        else "NOT_ACCEPTED",
        "numeric_distribution_complete": complete,
        "seed_rows": rows,
    }


def _report_projection(cohort, sources):
    attempts = []
    eligible = []
    observed = []
    for progress in cohort:
        if progress.admission_event is None or progress.terminal_observation is None:
            _fail("operational attempt population is unresolved")
        spec = sources[progress.source_binding["attempt"] - 1][4]
        attempt = _attempt_projection(progress.terminal_observation, spec)
        attempts.append(attempt)
        for row in attempt["seed_rows"]:
            if row["metric"] is not None:
                observed.append(row["metric"])
            if row["eligible"]:
                eligible.append(
                    {
                        "attempt": spec.attempt,
                        "seed": row["seed"],
                        "metric": row["metric"],
                        "row_index": row["row_index"],
                    }
                )
    metric = sources[0][2].primary_metric
    seed_order = sources[0][4].seeds

    def quality(row):
        value = row["metric"]
        if not math.isfinite(value):
            _fail("nonfinite observed metric")
        if metric.direction is MetricDirection.HIGHER_IS_BETTER:
            primary = -Fraction(value)
        elif metric.direction is MetricDirection.LOWER_IS_BETTER:
            primary = Fraction(value)
        else:
            primary = abs(Fraction(value) - Fraction(metric.target_value))
        return primary, seed_order.index(row["seed"])

    return {
        "admission_artifact_sha256s": [p.admission_record.sha256 for p in cohort],
        "terminal_artifact_sha256s": [p.terminal_record.sha256 for p in cohort],
        "planned_n": len(seed_order),
        "seed_order": list(seed_order),
        "attempts": attempts,
        "observed_numeric_distribution": observed,
        "numeric_distribution_complete": all(
            a["numeric_distribution_complete"] for a in attempts
        ),
        "eligible_distribution": [r["metric"] for r in eligible],
        "selected": min(eligible, key=quality) if eligible else None,
        "selection_rule": OPERATIONAL_SELECTION_RULE,
        "primary_metric": {
            "metric_id": metric.metric_id,
            "definition": metric.definition,
            "unit": metric.unit.value,
            "direction": metric.direction.value,
            "target_value": metric.target_value,
        },
        "population_scope": "FROZEN_COHORT_AND_REGISTERED_ATTEMPTS_ONLY",
    }


def _read_chain(registry, ledger, run_id, initial_sha, backend):
    before = _context(registry, ledger, run_id)
    initial = _record(registry, before[0].records, initial_sha)
    body = _read_body(
        registry, before[0].records, initial, OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE
    )
    if body["source_binding"]["attempt"] != 1:
        _fail("recovery requires the initial admission")
    sources = _full_sources(
        registry,
        ledger,
        run_id,
        body["initial_freeze_receipt_artifact_sha256"],
        body["retry_freeze_receipt_artifact_sha256"],
        backend,
    )
    _repair_admission_orphans(registry, ledger, run_id, sources, backend)
    before = _context(registry, ledger, run_id)
    descriptors = operational_seed_progress_descriptors(
        registry, records=before[0].records, events=before[1].events
    )
    cohort = _cohort(descriptors, body["source_binding"])
    if not cohort or cohort[0].admission_record != initial or len(cohort) > 2:
        _fail("operational attempt chain differs")
    for index, progress in enumerate(cohort):
        if (
            progress.source_binding["attempt"] != index + 1
            or progress.admission_event is None
        ):
            _fail("operational admission is incomplete or selective")
        ab = _read_body(
            registry,
            before[0].records,
            progress.admission_record,
            OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE,
        )
        if (
            ab["initial_freeze_receipt_artifact_sha256"] != sources[0][0].sha256
            or ab["retry_freeze_receipt_artifact_sha256"] != sources[1][0].sha256
            or progress.source_binding
            != freeze_json(
                _source_binding(registry, before[0].records, sources[index][3], run_id)
            )
            or ab["runtime_job_namespace_observed_absent"] is not True
            or any(
                s[1].design_freeze_event_index >= cohort[0].admission_event_index
                for s in sources
            )
        ):
            _fail("operational admission changes its prospective sources")
        if index == 0:
            if (
                ab["previous_admission_artifact_sha256"] is not None
                or ab["previous_terminal_artifact_sha256"] is not None
            ):
                _fail("initial admission has retrospective parents")
        else:
            previous = cohort[index - 1]
            if (
                previous.terminal_observation is None
                or not _queue_retry(previous.terminal_observation)
                or ab["previous_admission_artifact_sha256"]
                != previous.admission_record.sha256
                or ab["previous_terminal_artifact_sha256"]
                != previous.terminal_record.sha256
            ):
                _fail("technical retry was not source-authorized")
        _archive(
            registry,
            ledger,
            run_id,
            progress.admission_record,
            backend,
            sources[index][4],
        )
    current = _context(registry, ledger, run_id)
    cohort = _cohort(
        operational_seed_progress_descriptors(
            registry, records=current[0].records, events=current[1].events
        ),
        body["source_binding"],
    )
    if len(cohort) == 1 and _queue_retry(cohort[0].terminal_observation):
        _fail("prospective queue retry is pending; recovery never dispatches")
    return current, cohort, sources


def _repair_admission_orphans(registry, ledger, run_id, sources, backend):
    """Finish only exact record/event publication; never dispatch recovered A."""
    before = _context(registry, ledger, run_id)
    descriptors = operational_seed_progress_descriptors(
        registry, records=before[0].records, events=before[1].events
    )
    binding = _source_binding(registry, before[0].records, sources[0][3], run_id)
    for item in _cohort(descriptors, binding):
        if item.admission_event is not None:
            continue
        body = _read_body(
            registry,
            before[0].records,
            item.admission_record,
            OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE,
        )
        if (
            body["initial_freeze_receipt_artifact_sha256"] != sources[0][0].sha256
            or body["retry_freeze_receipt_artifact_sha256"] != sources[1][0].sha256
            or _registry_record_map(
                tuple(r for r in before[0].records if r != item.admission_record)
            )
            != tuple(tuple(p) for p in body["source_registry_record_identities"])
            or before[1].event_count != body["source_ledger_event_count"]
            or before[1].head_hash != body["source_ledger_head_hash"]
        ):
            _fail("admission orphan cannot recover after source drift")
        _namespace_absent(backend, (sources[item.source_binding["attempt"] - 1][4],))
        _commit(
            registry,
            ledger,
            before,
            body,
            OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE,
            item.admission_record,
        )
        return


def recover_operational_best_of_n(
    registry,
    ledger,
    *,
    expected_run_id,
    initial_admission_artifact_sha256,
    backend,
) -> OperationalBestOfNPublication:
    before, cohort, sources = _read_chain(
        registry, ledger, expected_run_id, initial_admission_artifact_sha256, backend
    )
    binding = cohort[0].source_binding
    projection = _report_projection(cohort, sources)
    reports = _owned_records(
        registry, before[0].records, OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
    )
    selected = []
    for record in reports:
        body = _read_body(
            registry,
            before[0].records,
            record,
            OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE,
        )
        b = body["source_binding"]
        if (b["ledger_run_id"], b["cohort_id"]) == (
            binding["ledger_run_id"],
            binding["cohort_id"],
        ):
            selected.append((record, body))
    if len(selected) > 1:
        _fail("final report slot is ambiguous")
    existing = None
    if selected:
        existing, body = selected[0]
        if _raw(body["source_binding"]) != _raw(binding) or any(
            _raw(body[key]) != _raw(value) for key, value in projection.items()
        ):
            _fail("report differs from complete source-owned attempt replay")
        source_records, prefix = _source_prefix(
            before[0].records, before[1].events, body
        )
        if any(
            d not in {r.sha256 for r in source_records}
            for d in existing.parent_artifacts
        ):
            _fail("report sources were not in its publication population")
        matches = _matching_events(before[1].events, body, existing)
        if matches:
            if _context(registry, ledger, expected_run_id) != before:
                _fail(
                    "completed operational report source population changed during replay"
                )
            return OperationalBestOfNPublication(
                existing,
                matches[0][1],
                freeze_json(body),
                tuple(p.admission_record for p in cohort),
                tuple(p.terminal_record for p in cohort),
            )
        remaining = tuple(r for r in before[0].records if r != existing)
        if (
            _registry_record_map(remaining)
            != tuple(tuple(p) for p in body["source_registry_record_identities"])
            or len(prefix) != before[1].event_count
        ):
            _fail("report orphan cannot recover after source drift")
    else:
        body = {
            **_base(before, binding, OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE),
            **projection,
        }
    record, event = _commit(
        registry,
        ledger,
        before,
        body,
        OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE,
        existing,
    )
    return OperationalBestOfNPublication(
        record,
        event,
        freeze_json(body),
        tuple(p.admission_record for p in cohort),
        tuple(p.terminal_record for p in cohort),
    )


def execute_operational_best_of_n(
    registry,
    ledger,
    *,
    expected_run_id,
    initial_freeze_receipt_artifact_sha256,
    retry_freeze_receipt_artifact_sha256,
    backend,
    input_artifact_paths,
) -> OperationalBestOfNPublication:
    sources = _full_sources(
        registry,
        ledger,
        expected_run_id,
        initial_freeze_receipt_artifact_sha256,
        retry_freeze_receipt_artifact_sha256,
        backend,
    )
    before = _context(registry, ledger, expected_run_id)
    binding = _source_binding(
        registry, before[0].records, sources[0][3], expected_run_id
    )
    descriptors = operational_seed_progress_descriptors(
        registry, records=before[0].records, events=before[1].events
    )
    cohort = _cohort(descriptors, binding)
    if cohort:
        initial_body = _read_body(
            registry,
            before[0].records,
            cohort[0].admission_record,
            OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE,
        )
        if (
            initial_body["initial_freeze_receipt_artifact_sha256"]
            != sources[0][0].sha256
            or initial_body["retry_freeze_receipt_artifact_sha256"]
            != sources[1][0].sha256
        ):
            _fail("existing cohort belongs to another exact freeze request")
        _repair_admission_orphans(registry, ledger, expected_run_id, sources, backend)
        before = _context(registry, ledger, expected_run_id)
        cohort = _cohort(
            operational_seed_progress_descriptors(
                registry, records=before[0].records, events=before[1].events
            ),
            binding,
        )
    if not cohort:
        _admit(
            registry, ledger, expected_run_id, sources, 1, backend, input_artifact_paths
        )
        before = _context(registry, ledger, expected_run_id)
        cohort = _cohort(
            operational_seed_progress_descriptors(
                registry, records=before[0].records, events=before[1].events
            ),
            binding,
        )
    initial = cohort[0]
    if initial.admission_event is None:
        _fail("incomplete initial admission cannot dispatch")
    _archive(
        registry,
        ledger,
        expected_run_id,
        initial.admission_record,
        backend,
        sources[0][4],
    )
    before = _context(registry, ledger, expected_run_id)
    cohort = _cohort(
        operational_seed_progress_descriptors(
            registry, records=before[0].records, events=before[1].events
        ),
        binding,
    )
    if len(cohort) == 1 and _queue_retry(cohort[0].terminal_observation):
        _admit(
            registry,
            ledger,
            expected_run_id,
            sources,
            2,
            backend,
            input_artifact_paths,
            cohort[0],
        )
    return recover_operational_best_of_n(
        registry,
        ledger,
        expected_run_id=expected_run_id,
        initial_admission_artifact_sha256=initial.admission_record.sha256,
        backend=backend,
    )


def require_operational_best_of_n_report(
    registry,
    ledger,
    *,
    expected_run_id,
    report_artifact_sha256,
    backend,
) -> OperationalBestOfNPublication:
    before = _context(registry, ledger, expected_run_id)
    record = _record(registry, before[0].records, report_artifact_sha256)
    body = _read_body(
        registry, before[0].records, record, OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
    )
    if not _matching_events(before[1].events, body, record):
        _fail("required report is not completely published")
    result = recover_operational_best_of_n(
        registry,
        ledger,
        expected_run_id=expected_run_id,
        initial_admission_artifact_sha256=body["admission_artifact_sha256s"][0],
        backend=backend,
    )
    if (
        result.report_record != record
        or _locked_checked_result_authority_snapshot(registry, ledger) != before
    ):
        _fail("required report differs or replay wrote state")
    return result
