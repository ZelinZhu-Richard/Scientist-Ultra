"""Source-owned allocation of two public known-answer simulation windows.

Reservations consume membership forever, including record-only publication
orphans. They do not release data, charge a resource journal, supply a scientific
reserve, establish blinding/independence, or confer any evaluator/E4 authority.
The existing registry and ledger are the only provenance stores.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from contextlib import nullcontext
from datetime import datetime
from typing import Any, Mapping

from .artifacts import (
    ArtifactRecord,
    ArtifactRegistry,
    RegistryValidationResult,
    MAX_REGISTRY_RECORDS,
)
from .calibration import (
    CALIBRATION_FIXTURE_SHA256,
    canonical_json_sha256,
    load_calibration_cases,
)
from .errors import (
    ArtifactError,
    LedgerError,
    UnsafeSerializationError,
    ValidationError,
)
from .evaluation_contract_amendment import (
    _registry_record_map,
    _registry_map_fingerprint,
    _require_registry_record_map,
    _require_current_evaluation_contract_lineage,
    _require_no_completed_contract_successor_before,
    _contract_identity_roots,
    _resolve_lineage,
)
from .ledger import (
    EventLedger,
    LedgerEvent,
    LedgerValidationResult,
    MAX_LEDGER_BYTES,
    MAX_LEDGER_EVENTS,
)
from .models import utc_now, validate_identifier, validate_sha256
from .protocol import ResearchProtocol
from .roles import Role
from .scientific_design import (
    EvaluationContract,
    ReportingRegime,
    _locked_checked_result_authority_snapshot,
    _require_scientific_protocol_contract_crosswalk,
    _timeline_state,
)
from .scientific_protocol_revision import (
    _parse_legacy_protocol,
    _validate_publication_at_snapshot,
    require_scientific_protocol_revision,
)
from .security import canonical_json_bytes, safe_json_loads, sha256_bytes


SIMULATED_RESERVE_POPULATION_LOGICAL_TYPE = "simulated_reserve_population"
SIMULATED_RESERVE_POPULATION_SCHEMA = "sim-reserve-pop/v1"
SIMULATED_RESERVE_SCHEMA = "sim-reserve/v1"
SIMULATED_RESERVE_EVENT_SCHEMA = "sim-reserve-event/v1"
RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA = "sim-reserve/v2"
RESOURCE_BACKED_SIMULATED_RESERVE_EVENT_SCHEMA = "sim-reserve-event/v2"
OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA = "sim-reserve/v3"
OBSERVED_SECOND_SIMULATED_RESERVE_EVENT_SCHEMA = "sim-reserve-event/v3"
SIMULATED_RESERVE_EVENT_KEY = "simulated_confirmatory_reserve"
SIMULATED_RESERVE_PROFILE = "PINNED_CAL_TRUE_NULL_TWO_WINDOWS_V1"
SIMULATED_RESERVE_CASE_ID = "cal-true-null-v1"
SIMULATED_RESERVE_CASE_SHA256 = (
    "a4427436f98e924cd68e90cc7918699ee5daaa2a499e559fc2a47918e18f832d"
)
MAX_SIMULATED_RESERVE_BYTES = 2 * 1024 * 1024
MAX_SIMULATED_RESERVE_SCAN_BYTES = 32 * 1024 * 1024
_POPULATION_ORIGIN = "source-owned pinned public simulated reserve population"
_RESERVE_ORIGIN = "source-owned irreversible simulated confirmatory reservation"
_POPULATION_COMMAND = ("scientist-one", "register-simulated-reserve-population")
_RESERVE_COMMAND = ("scientist-one", "reserve-simulated-confirmatory-window")
_RESERVE_TYPE = "frozen_confirmatory_split"
_EVENT_PREFIX = "sim-reserve-"
_SIMULATED_SCHEMAS = frozenset(
    {
        SIMULATED_RESERVE_SCHEMA,
        SIMULATED_RESERVE_POPULATION_SCHEMA,
        SIMULATED_RESERVE_EVENT_SCHEMA,
        RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA,
        RESOURCE_BACKED_SIMULATED_RESERVE_EVENT_SCHEMA,
        OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA,
        OBSERVED_SECOND_SIMULATED_RESERVE_EVENT_SCHEMA,
        "sim-resource-charge/v2",
        "sim-resource-charge-event/v2",
        SIMULATED_RESERVE_PROFILE,
    }
)
_SIMULATED_RAW_MARKERS = _SIMULATED_SCHEMAS | {
    SIMULATED_RESERVE_EVENT_KEY,
    SIMULATED_RESERVE_POPULATION_LOGICAL_TYPE,
}
# Native source-owner selectors for the allocator's closed coexistence census.
# These are refusal signals, not proof of observed results or scientific use.
# P/A/S are admitted only by exact fully replayed record/event identities below.
_PRIOR_WORK_FAMILIES = frozenset(
    {
        "frozen_protocol",
        "frozen_run_spec",
        "frozen_confirmatory_split",
        "evaluation_contract_amendment",
        "fresh_custody_receipt",
        "simulated_reserve_observation",
        "custody_record",
        "resource_runtime_confirmatory_charge",
        "resource_runtime_confirmatory_completion",
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
        "scientific_confirmatory_protocol_binding",
        "scientific_confirmatory_timeline_receipt_v2",
        "confirmatory_timeline_receipt",
        "confirmation_reveal_gate_receipt",
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
        "research_state.run",
        "research_state.result",
        "research_state.statistical_test",
        # Even draft canonical Dataset/Split coexistence is unsupported in this
        # first allocator; this is not a claim all drafts are protected resources.
        "research_state.dataset",
        "research_state.split",
    }
)
_PRIOR_WORK_KEYS = frozenset(
    {
        "scientific_timeline",
        "fresh_custody",
        "scientific_protocol_revision",
        "scientific_execution_preparation",
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
        "simulated_custody_observation",
        "simulated_confirmatory_charge",
        "simulated_reserve_preparation",
        "simulated_reserve_attempt",
        "simulated_reserve_started",
        "simulated_reserve_observation",
    }
)
_PRIOR_WORK_SCHEMAS = frozenset(
    {
        "SCIENTIST_ONE_FROZEN_RUN_SPEC_V1",
        "SCIENTIST_ONE_OUTPUT_MANIFEST_V1",
        "scientific-timeline-event/v1",
        "scientific-timeline-receipt/v1",
        "FROZEN_SYNTHETIC_PROTOCOL",
        "FROZEN_CONFIRMATORY_SPLIT",
        "SIMULATED_HOLDOUT_CUSTODY",
        "SIMULATED_ARCHITECTURE_CONTROL_STARTED",
        "sim-resource-charge/v2",
        "sim-resource-charge-event/v2",
        # Negative-only later-owner markers must refuse before I/S publication,
        # not first become visible through the outer passive readback dispatch.
        "sim-reserve-preparation/v1",
        "sim-reserve-preparation-event/v1",
        "sim-reserve-attempt/v1",
        "sim-reserve-attempt-event/v1",
        "sim-reserve-started/v1",
        "sim-reserve-observation/v1",
        "sim-reserve-observation-event/v1",
        "SIMULATED_RESERVE_PREPARATION",
        "SIMULATED_RESERVE_ATTEMPT_CONSUMPTION",
        "SIMULATED_RESERVE_OBSERVATION",
        "RESULT_OBSERVED",
        "Run",
        "Result",
        "StatisticalTest",
        "Dataset",
        "Split",
        "checked-superiority-aggregate/v1",
        "checked-superiority-statistics/v1",
        "scientific-protocol-revision/v1",
        "protocol-revision-event/v1",
        "evaluation-contract-amendment/v1",
        "eval-contract-amendment/v1",
        "scientific-execution-plan/v1",
        "scientific-execution-input-binding/v1",
        "scientific-execution-preparation/v1",
        "scientific-execution-prepared-event/v1",
        "scientific-execution-attested-event/v1",
        "scientific-execution-attested-event/v2",
        "scientific-execution-authority-publication/v1",
        "scientific_execution_authority/v1",
        "SCIENTIST_ONE_SCIENTIFIC_EXECUTION_AUTHORITY_V2",
        "SCIENTIST_ONE_EXECUTION_ACTIVITY_V1",
        "scientific-execution-environment/v1",
        "scientific-execution-isolation-attestation/v1",
        "backend-execution-attestation-envelope/v1",
        "backend-execution-attestation-envelope/v2",
        "scientific-dataset-acquisition-plan/v1",
        "scientific-dataset-acquisition-plan-event/v1",
        "scientific-dataset-manifest/v2",
        "scientific-dataset-usage-proposal/v2",
        "scientific-dataset-usage/v2",
        "scientific-dataset-authority/v2",
        "scientific-dataset-authority-event/v2",
        "scientific-dataset-split-authority/v1",
        "scientific-dataset-split-event/v1",
        "scientific-experiment-dataset/v1",
        "scientific-dataset-source/v1",
        "scientific-dataset-sampling-source/v1",
        "scientific-dataset-pinned-json/v1",
        "scientist-one-scientific-dataset-json-v1",
        "scientific-confirmatory-protocol-binding-event/v1",
        "scientific-confirmatory-timeline-publication/v2",
        "scientific-result-state-projection-event/v1",
        "scientific-result-promotion-authority-event/v3",
        *(
            f"scientific-dataset-statistical-use-{kind}{suffix}/v{version}"
            for kind in ("proposal", "authority")
            for suffix in ("", "-event")
            for version in (1, 2)
        ),
    }
)
_PRIOR_WORK_COMMANDS = frozenset(
    ("scientist-one", command)
    for command in (
        "freeze-run-spec",
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
        "observe-simulated-reserve",
    )
)
_PRIOR_WORK_ORIGINS = (
    "run spec frozen after scientific-plan admission and before execution",
    "source-owned prospective scientific execution preparation",
    "exact manifest bytes captured by the local backend",
    "deterministically aggregated synthetic development result",
    "deterministic paired statistical audit over subject-level fixture outcomes",
    "append-only scientific protocol revision ",
    "audited scientific experiment Dataset projection ",
    "research-state:Run:",
    "research-state:Result:",
    "research-state:StatisticalTest:",
    "research-state:Dataset:",
    "research-state:Split:",
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
    "source-owned simulated reserve native observation",
)
_PRIOR_WORK_RAW_MARKERS = (
    _SIMULATED_RAW_MARKERS
    | _PRIOR_WORK_KEYS
    | _PRIOR_WORK_SCHEMAS
    | _PRIOR_WORK_FAMILIES
)
_SCOPE = {
    "evidence_class": "NON_EVIDENTIARY",
    "custody_independence": "NON_INDEPENDENT",
    "scientific_evidence": False,
    "scientific_freshness_authorized": False,
    "result_validity_authorized": False,
    "blinding_authorized": False,
    "release_authorized": False,
    "e4_authorized": False,
    "public_known_answer_fixture": True,
}


class SimulatedReserveError(ValidationError):
    """Pinned simulated allocation is missing, conflicting or unresolved."""


@dataclass(frozen=True, slots=True)
class SimulatedReservePublication:
    record: ArtifactRecord
    event: LedgerEvent
    event_index: int
    protocol_record: ArtifactRecord
    protocol: ResearchProtocol
    contract_record: ArtifactRecord
    contract: EvaluationContract
    population_record: ArtifactRecord
    window_index: int
    member_ids: tuple[str, ...]
    member_row_sha256s: tuple[str, ...]
    evaluator_payload: bytes
    evaluator_payload_sha256: str
    split_manifest_hash: str
    source_registry_identities: tuple[tuple[str, str], ...]
    source_ledger_event_count: int
    source_ledger_head_hash: str | None
    registry_snapshot: RegistryValidationResult
    ledger_snapshot: LedgerValidationResult


def _sha(value: Any) -> str:
    if type(value) is not str:
        raise SimulatedReserveError("reserve artifact identity must be native text")
    validate_sha256(value, "reserve artifact identity")
    return value


def _time(value: Any) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise SimulatedReserveError("reserve timestamp must be UTC")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.utcoffset() is None or result.utcoffset().total_seconds() != 0:
        raise SimulatedReserveError("reserve timestamp offset is invalid")
    return result


def _context(registry, ledger, run_id, *, ensure=False):
    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise SimulatedReserveError("reserve requires exact native registry and ledger")
    validate_identifier(run_id, "simulated reserve run ID")
    pair = _locked_checked_result_authority_snapshot(
        registry, ledger, ensure_storage=ensure
    )
    if any(event.run_id != run_id for event in pair[1].events):
        raise SimulatedReserveError("reserve ledger belongs to another run")
    return pair


def _json(registry, record):
    if record.size > MAX_SIMULATED_RESERVE_BYTES:
        raise SimulatedReserveError("reserve object exceeds its bounded codec")
    raw = registry.get_bytes(record.sha256)
    value = safe_json_loads(
        raw, max_bytes=MAX_SIMULATED_RESERVE_BYTES, max_items=100_000
    )
    if type(value) is not dict or raw != canonical_json_bytes(value) + b"\n":
        raise SimulatedReserveError("reserve object is not exact canonical JSON")
    return value


def _pinned_population():
    cases = tuple(
        case
        for case in load_calibration_cases()
        if case.case_id == SIMULATED_RESERVE_CASE_ID
    )
    if (
        len(cases) != 1
        or canonical_json_sha256(cases[0].to_dict()) != SIMULATED_RESERVE_CASE_SHA256
    ):
        raise SimulatedReserveError("pinned calibration case identity changed")
    case = cases[0].to_dict()
    rows = case["payload"]["observations"]
    ids = tuple(f"{group}{index:02}" for group in ("c", "t") for index in range(1, 9))
    if len(rows) != 16 or tuple(row["unit_id"] for row in rows) != ids:
        raise SimulatedReserveError("pinned calibration member population changed")
    return {
        "schema_version": SIMULATED_RESERVE_POPULATION_SCHEMA,
        "profile": SIMULATED_RESERVE_PROFILE,
        "population_id": "pinned-cal-true-null-16-v1",
        "fixture_file_sha256": CALIBRATION_FIXTURE_SHA256,
        "case_id": SIMULATED_RESERVE_CASE_ID,
        "case_sha256": SIMULATED_RESERVE_CASE_SHA256,
        "allocation_rule": "CONTROL_01_04_TREATMENT_01_04_THEN_05_08_V1",
        "population_units": 16,
        "window_units": 8,
        "window_count": 2,
        "members": [
            {
                "member_id": row["unit_id"],
                "row": row,
                "row_sha256": sha256_bytes(canonical_json_bytes(row)),
            }
            for row in rows
        ],
        **_SCOPE,
    }


def _plan_record(registry, value, *, population=False, parents=(), at):
    raw = canonical_json_bytes(value) + b"\n"
    if not 0 < len(raw) <= MAX_SIMULATED_RESERVE_BYTES:
        raise SimulatedReserveError("reserve publication exceeds its byte bound")
    safe_json_loads(raw, max_bytes=MAX_SIMULATED_RESERVE_BYTES, max_items=100_000)
    digest = sha256_bytes(raw)
    return ArtifactRecord(
        sha256=digest,
        path=registry._object_relative(digest).as_posix(),
        relative_path=registry._object_relative(digest).as_posix(),
        metadata_path=registry._metadata_relative(digest).as_posix(),
        logical_type=SIMULATED_RESERVE_POPULATION_LOGICAL_TYPE
        if population
        else _RESERVE_TYPE,
        schema_version=SIMULATED_RESERVE_POPULATION_SCHEMA
        if population
        else value["schema_version"],
        mime_type="application/json",
        size=len(raw),
        origin=_POPULATION_ORIGIN if population else _RESERVE_ORIGIN,
        creator_role=Role.PROTOCOL_DESIGNER,
        creation_command=_POPULATION_COMMAND if population else _RESERVE_COMMAND,
        parent_artifacts=parents,
        validation_result="PASS",
        frozen=True,
        created_at=at,
    )


def _put_locked(registry, guard, record, raw):
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


def _markers(value):
    """Bounded structural selectors; ordinary matching prose is not authority."""
    keys, strings, schemas, types = set(), set(), set(), set()
    work = [(value, 0, False, False, False)]
    count = 0
    while work:
        node, depth, typed, referenced, semantic = work.pop()
        count += 1
        if count > 250_000 or depth > 64:
            raise SimulatedReserveError("reserve alias selector exceeds its bound")
        if isinstance(node, Mapping):
            for key, item in node.items():
                keys.add(key)
                if typed and isinstance(key, str):
                    types.add(key)
                if referenced and isinstance(key, str):
                    strings.add(key)
                if semantic and isinstance(key, str):
                    schemas.add(key)
                work.append(
                    (
                        item,
                        depth + 1,
                        typed or key in {"artifact_types", "logical_type"},
                        referenced
                        or key
                        in {
                            "reservation_artifact_sha256",
                            "reservation_record_hash",
                            "population_artifact_sha256",
                            "population_record_hash",
                            "artifact_sha256",
                            "artifact_record_hash",
                            "artifact_hashes",
                            "artifact_record_hashes",
                            "parent_artifacts",
                        },
                        semantic
                        or key
                        in {
                            "schema_version",
                            "kind",
                            "profile",
                            "execution_kind",
                            "object_type",
                            "policy_id",
                            "adapter_id",
                        },
                    )
                )
        elif isinstance(node, (tuple, list)):
            work.extend((item, depth + 1, typed, referenced, semantic) for item in node)
        elif isinstance(node, str):
            if referenced:
                strings.add(node)
            if typed:
                types.add(node)
            if semantic:
                schemas.add(node)
    return keys, strings, schemas, types


def _new_simulated_markers(value):
    from .simulated_resource import _charge_schema_selected

    keys, _references, schemas, types = _markers(value)
    return bool(
        SIMULATED_RESERVE_EVENT_KEY in keys
        or schemas.intersection(_SIMULATED_SCHEMAS)
        or any(_charge_schema_selected(item) for item in schemas)
        or SIMULATED_RESERVE_POPULATION_LOGICAL_TYPE in types
    )


def _new_simulated_record_metadata(record):
    from .simulated_resource import _charge_schema_selected

    # The frozen_confirmatory_split family and legacy split kind are shared
    # with older scientific design owners. They do not select this new profile.
    return (
        record.logical_type == SIMULATED_RESERVE_POPULATION_LOGICAL_TYPE
        or record.schema_version in _SIMULATED_SCHEMAS
        or _charge_schema_selected(record.schema_version)
        or record.origin in {_POPULATION_ORIGIN, _RESERVE_ORIGIN}
        or record.creation_command in {_POPULATION_COMMAND, _RESERVE_COMMAND}
    )


def _malformed_markers(raw, markers):
    from .simulated_resource import _charge_malformed_schema_selected

    # Only malformed bounded serialization reaches this conservative path.
    # Valid prose strings are classified structurally by _markers instead.
    return (any(canonical_json_bytes(marker) in raw for marker in markers)
            or _charge_malformed_schema_selected(raw))


def _selected_json_hint(
    registry, records, record, *, malformed_markers=_SIMULATED_RAW_MARKERS
):
    # Reuse the existing confined, exact metadata/content, no-lock byte owner.
    # This helper never enumerates records or opens registry mutation locks.
    from .seed_reporting import _selected_payload_bytes

    if record.size > MAX_SIMULATED_RESERVE_BYTES:
        raise SimulatedReserveError("selected reserve alias exceeds scan capacity")
    try:
        raw = _selected_payload_bytes(registry, records, record)
    except (ValidationError, OSError) as exc:
        raise SimulatedReserveError(
            "selected reserve alias bytes are unavailable"
        ) from exc
    try:
        return safe_json_loads(
            raw, max_bytes=MAX_SIMULATED_RESERVE_BYTES, max_items=100_000
        )
    except (UnsafeSerializationError, ValidationError):
        if _malformed_markers(raw, malformed_markers):
            raise SimulatedReserveError("malformed selected simulated reserve alias")
        return None


def reject_simulated_reserve_exposure(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    events: tuple[LedgerEvent, ...],
    *,
    complete_registry_population: bool,
) -> None:
    """Negative-only profile coexistence guard on caller-selected sources.

    A public known-answer population is not scientific exposure/blinding proof.
    This first profile conservatively cannot coexist with prospective scientific
    design. Legacy unsealed history inspects only its event prefix and records
    referenced there; later record-only population cannot poison earlier D.
    No live snapshot, public owner, J/Q replay, or mutation lock is entered.
    """
    if (
        type(registry) is not ArtifactRegistry
        or type(records) is not tuple
        or type(events) is not tuple
        or type(complete_registry_population) is not bool
        or any(type(record) is not ArtifactRecord for record in records)
        or any(type(event) is not LedgerEvent for event in events)
    ):
        raise SimulatedReserveError(
            "simulated exposure requires native snapshot inputs"
        )
    _registry_record_map(records)
    by_identity = {
        identity: record
        for record in records
        for identity in (record.sha256, record.record_hash)
    }
    selected = set(records) if complete_registry_population else set()
    for event in events:
        if event.event_id.startswith(_EVENT_PREFIX) or _new_simulated_markers(
            event.metadata
        ):
            raise SimulatedReserveError(
                "simulated reserve profile forbids scientific coexistence"
            )
        references = set(event.artifact_hashes) | _markers(event.metadata)[1]
        selected.update(by_identity[item] for item in references if item in by_identity)
    for record in selected:
        # Valid new-profile payloads cannot exceed2MiB. Metadata still selects
        # oversized aliases, but unrelated scientific data has no new aggregate
        # or individual allocator-capacity constraint in this negative guard.
        if _new_simulated_record_metadata(record) or (
            record.size <= MAX_SIMULATED_RESERVE_BYTES
            and _new_simulated_markers(_selected_json_hint(registry, records, record))
        ):
            raise SimulatedReserveError(
                "simulated reserve profile forbids scientific coexistence"
            )


def _candidate_records(registry, records, *, initialization=None, charges=()):
    if charges:
        from .simulated_resource import SimulatedConfirmatoryCharge

        if any(
            type(item) is not SimulatedConfirmatoryCharge or item.record not in records
            for item in charges
        ):
            raise SimulatedReserveError(
                "reservation census lacks its full-owned charge record"
            )
    if initialization is not None:
        from .simulated_resource import SimulatedResourceInitialization

        if (
            type(initialization) is not SimulatedResourceInitialization
            or initialization.record not in records
        ):
            raise SimulatedReserveError(
                "reservation census lacks its full-owned selected I record"
            )
    from .simulated_resource import _charge_candidates

    owned_charges = tuple(item.record for item in charges)
    if any(record not in owned_charges for record in _charge_candidates(registry, records)):
        raise SimulatedReserveError("unowned charge schema or publication cannot precede I/S")
    populations, reserves = [], []
    scanned = 0
    for record in records:
        metadata_pop = (
            record.logical_type == SIMULATED_RESERVE_POPULATION_LOGICAL_TYPE
            or record.schema_version == SIMULATED_RESERVE_POPULATION_SCHEMA
            or record.origin == _POPULATION_ORIGIN
            or record.creation_command == _POPULATION_COMMAND
        )
        metadata_res = (
            record.logical_type == _RESERVE_TYPE
            or record.schema_version
            in {
                SIMULATED_RESERVE_SCHEMA,
                SIMULATED_RESERVE_EVENT_SCHEMA,
                RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA,
                RESOURCE_BACKED_SIMULATED_RESERVE_EVENT_SCHEMA,
                OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA,
                OBSERVED_SECOND_SIMULATED_RESERVE_EVENT_SCHEMA,
            }
            or record.origin == _RESERVE_ORIGIN
            or record.creation_command == _RESERVE_COMMAND
        )
        scanned += record.size
        if (
            record.size > MAX_SIMULATED_RESERVE_BYTES
            or scanned > MAX_SIMULATED_RESERVE_SCAN_BYTES
        ):
            raise SimulatedReserveError(
                "reserve inventory exceeds the complete bounded scan profile"
            )
        raw = registry.get_bytes(record.sha256)
        if any(record == item.record for item in charges):
            # The public outer reader supplies only full historical Q owners.
            # Lower source/population replay never discovers or skips Q itself.
            continue
        if initialization is not None and record == initialization.record:
            # Only the exact full-owned I object is exempt; its bytes still
            # count against the original complete-population scan bounds.
            continue
        value = None
        if record.size <= MAX_SIMULATED_RESERVE_BYTES:
            try:
                value = safe_json_loads(
                    raw, max_bytes=MAX_SIMULATED_RESERVE_BYTES, max_items=100_000
                )
            except (UnsafeSerializationError, ValidationError):
                if _malformed_markers(
                    raw, _SIMULATED_RAW_MARKERS | {SIMULATED_RESERVE_CASE_SHA256}
                ):
                    raise SimulatedReserveError(
                        "malformed reserved population or window alias"
                    )
        keys, _strings, schemas, types = _markers(value)
        pop = (
            metadata_pop
            or SIMULATED_RESERVE_POPULATION_SCHEMA in schemas
            or SIMULATED_RESERVE_POPULATION_LOGICAL_TYPE in types
        )
        res = (
            metadata_res
            or SIMULATED_RESERVE_SCHEMA in schemas
            or SIMULATED_RESERVE_EVENT_SCHEMA in schemas
            or RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA in schemas
            or RESOURCE_BACKED_SIMULATED_RESERVE_EVENT_SCHEMA in schemas
            or OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA in schemas
            or OBSERVED_SECOND_SIMULATED_RESERVE_EVENT_SCHEMA in schemas
            or _RESERVE_TYPE in types
            or SIMULATED_RESERVE_EVENT_KEY in keys
            or "FROZEN_CONFIRMATORY_SPLIT" in schemas
            or (SIMULATED_RESERVE_PROFILE in schemas and not pop)
        )
        if pop and res:
            raise SimulatedReserveError("population and reservation aliases conflict")
        if pop:
            if record.logical_type != SIMULATED_RESERVE_POPULATION_LOGICAL_TYPE:
                raise SimulatedReserveError("population alias has substituted metadata")
            populations.append(record)
        if res:
            if record.logical_type != _RESERVE_TYPE:
                raise SimulatedReserveError(
                    "reservation alias has substituted metadata"
                )
            payload = _json(registry, record)
            if (
                payload.get("schema_version")
                not in {
                    SIMULATED_RESERVE_SCHEMA,
                    RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA,
                }
                or type(payload.get("window_index")) is not int
                or payload["window_index"] not in (1, 2)
                or (
                    payload.get("schema_version")
                    == RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA
                    and payload["window_index"] != 1
                )
            ):
                raise SimulatedReserveError(
                    "unknown prior reservation or legacy migration"
                )
            reserves.append((record, payload))
    return tuple(populations), tuple(reserves)


def _require_population(registry, record, records, *, initialization=None):
    expected = _pinned_population()
    if _json(registry, record) != expected or record != _plan_record(
        registry, expected, population=True, at=record.created_at
    ):
        raise SimulatedReserveError("population is not the exact pinned native source")
    populations, _reserves = _candidate_records(
        registry, records, initialization=initialization
    )
    if populations != (record,):
        raise SimulatedReserveError("population slot is absent, competing or ambiguous")
    return expected


def register_simulated_reserve_population(registry: ArtifactRegistry) -> ArtifactRecord:
    """Freeze the exact existing public fixture population without new evidence."""
    if type(registry) is not ArtifactRegistry:
        raise SimulatedReserveError("population requires exact native registry")
    before = registry.verify_all(raise_on_error=True)
    value = _pinned_population()
    populations, _ = _candidate_records(registry, before.records)
    if populations:
        if len(populations) != 1:
            raise SimulatedReserveError("competing simulated population")
        _require_population(registry, populations[0], before.records)
        if registry.verify_all(raise_on_error=True) != before:
            raise SimulatedReserveError("population changed during readback")
        return populations[0]
    at = utc_now()
    record = _plan_record(registry, value, population=True, at=at)
    guard = registry._open_mutation_lock()
    try:
        if (
            registry._verify_all_locked(guard, raise_on_error=True) != before
            or before.count >= MAX_REGISTRY_RECORDS
        ):
            raise SimulatedReserveError(
                "population registry changed or has no capacity"
            )
        committed = _put_locked(
            registry, guard, record, canonical_json_bytes(value) + b"\n"
        )
        after = registry._verify_all_locked(guard, raise_on_error=True)
        if committed != record or set(after.records) != {*before.records, record}:
            raise SimulatedReserveError(
                "population publication changed outside its exact delta"
            )
        registry._verify_mutation_namespace(guard)
    finally:
        registry._unlock_mutation(guard)
    return record


def _one(records, digest):
    _sha(digest)
    candidates = tuple(record for record in records if record.sha256 == digest)
    if len(candidates) != 1:
        raise SimulatedReserveError("reserve source is absent from selected snapshot")
    return candidates[0]


def _source_pair(current, value):
    identities = value.get("source_registry_identities")
    if type(identities) is not list or any(
        type(item) is not list or len(item) != 2 for item in identities
    ):
        raise SimulatedReserveError("reserve sealed source map is malformed")
    records = _require_registry_record_map(
        current[0].records,
        source_record_map=tuple(tuple(item) for item in identities),
        source_record_count=value.get("source_registry_count"),
        source_record_map_fingerprint=value.get("source_registry_fingerprint"),
    )
    count = value.get("source_ledger_event_count")
    if type(count) is not int or not 0 <= count <= len(current[1].events):
        raise SimulatedReserveError("reserve sealed event prefix is missing")
    events = current[1].events[:count]
    head = events[-1].event_hash if events else None
    if head != value.get("source_ledger_head_hash"):
        raise SimulatedReserveError("reserve sealed event head changed")
    record_ids = {record.sha256 for record in records}
    if any(
        digest not in record_ids for event in events for digest in event.artifact_hashes
    ):
        raise SimulatedReserveError(
            "reserve sealed population omits ledger source artifacts"
        )
    return RegistryValidationResult(True, records), LedgerValidationResult(
        valid=True,
        events=events,
        head_hash=head,
        valid_prefix_bytes=sum(
            len(canonical_json_bytes(event.to_dict())) + 1 for event in events
        ),
    )


def _window(population, index):
    numbers = range(1, 5) if index == 1 else range(5, 9)
    ids = tuple(f"{group}{number:02}" for group in ("c", "t") for number in numbers)
    by_id = {member["member_id"]: member for member in population["members"]}
    members = tuple(by_id[identity] for identity in ids)
    payload = canonical_json_bytes(
        {
            "control": [member["row"]["outcome"] for member in members[:4]],
            "treatment": [member["row"]["outcome"] for member in members[4:]],
        }
    )
    return ids, tuple(member["row_sha256"] for member in members), payload


def _protocol_revision_at_snapshot(registry, ledger, *, record, pair):
    # Full protocol and amendment owners, confined to the selected historical
    # pair. Unsupported legacy dependencies that widen live must fail closed.
    return _validate_publication_at_snapshot(
        registry,
        ledger,
        record=record,
        registry_snapshot=pair[0],
        ledger_snapshot=pair[1],
        require_snapshot_local_dependencies=True,
    )


def _sources(
    registry,
    ledger,
    pair,
    *,
    run_id,
    protocol_sha,
    contract_sha,
    population_sha,
    index,
    prior_sha,
    initialization=None,
):
    records = pair[0].records
    protocol_record, contract_record, population_record = (
        _one(records, digest) for digest in (protocol_sha, contract_sha, population_sha)
    )
    population = _require_population(
        registry, population_record, records, initialization=initialization
    )
    lineage = _resolve_lineage(
        registry,
        ledger,
        contract_artifact_sha256=contract_sha,
        expected_run_id=run_id,
        registry_snapshot=pair[0],
        ledger_snapshot=pair[1],
        require_snapshot_local_dependencies=True,
    )
    contract = lineage.contracts[-1]
    if _contract_identity_roots(
        registry, records, selected_contract_id=contract.contract_id
    ) != frozenset({lineage.contract_records[0].sha256}):
        raise SimulatedReserveError(
            "reservation history contains competing contract roots"
        )
    _require_no_completed_contract_successor_before(
        registry,
        ledger,
        selected_record=contract_record,
        expected_run_id=run_id,
        registry_snapshot=pair[0],
        ledger_snapshot=pair[1],
        design_event_index=pair[1].event_count,
        complete_source_population=True,
    )
    if contract.seed_reporting.regime is not ReportingRegime.ALL_SEEDS:
        raise SimulatedReserveError(
            "simulated reserve requires existing ALL_SEEDS semantics"
        )
    previous = None
    revision = None
    if index == 1:
        if prior_sha is not None or len(lineage.contract_records) != 1:
            raise SimulatedReserveError(
                "first window requires parentless initial contract lineage"
            )
        protocol = _parse_legacy_protocol(registry, protocol_record)
        if protocol.study_version != 1 or protocol.parent_protocol_hash is not None:
            raise SimulatedReserveError(
                "first window requires an exact initial native protocol"
            )
    else:
        if prior_sha is None:
            raise SimulatedReserveError(
                "second window requires its exact predecessor reservation"
            )
        previous = _require_simulated_confirmatory_reserve_at_snapshot(
            registry,
            ledger,
            expected_run_id=run_id,
            reservation_artifact_sha256=prior_sha,
            registry_snapshot=pair[0],
            ledger_snapshot=pair[1],
        )
        revision = _protocol_revision_at_snapshot(
            registry, ledger, record=protocol_record, pair=pair
        )
        protocol = revision.protocol
        if (
            previous.window_index != 1
            or previous.population_record != population_record
            or previous.protocol_record != revision.parent_protocol_record
            or previous.protocol != revision.parent_protocol
            or previous.contract_record
            != revision.amendment_publication.parent_contract_record
            or contract_record != revision.amendment_publication.contract_record
            or contract != revision.amendment_publication.child_contract
            or len(lineage.contract_records) != 2
            or protocol.study_version != 2
            or previous.event_index >= revision.amendment_publication.event_index
            or (previous.record.sha256, previous.record.record_hash)
            not in revision.amendment_publication.authority.source_registry_record_identities
        ):
            raise SimulatedReserveError(
                "second window is not the exact S1/P1 -> amended C2/P2 lineage"
            )
    _require_scientific_protocol_contract_crosswalk(protocol, contract)
    ids, hashes, payload = _window(population, index)
    if previous and set(ids) & set(previous.member_ids):
        raise SimulatedReserveError("simulated reservation members overlap")
    return (
        protocol_record,
        protocol,
        contract_record,
        contract,
        population_record,
        ids,
        hashes,
        payload,
        previous,
        (
            tuple(
                {
                    protocol_record,
                    population_record,
                    *lineage.contract_records,
                    *(item.amendment_record for item in lineage.publications),
                    *((previous.protocol_record, previous.record) if previous else ()),
                }
            ),
            tuple(item.event for item in lineage.publications)
            + ((revision.event,) if revision else ())
            + ((previous.event,) if previous else ()),
        ),
    )


def _body(ledger, pair, sources, *, run_id, index, at, initialization=None):
    p_record, protocol, c_record, contract, pop, ids, hashes, payload, previous = (
        sources[:9]
    )
    source_count, fingerprint = _registry_map_fingerprint(pair[0].records)
    split = sha256_bytes(
        canonical_json_bytes(
            {
                "profile": SIMULATED_RESERVE_PROFILE,
                "population_artifact_sha256": pop.sha256,
                "protocol_sha256": protocol.sha256,
                "contract_sha256": contract.sha256,
                "window_index": index,
                "member_ids": ids,
                "member_row_sha256s": hashes,
            }
        )
    )
    return {
        "schema_version": SIMULATED_RESERVE_SCHEMA
        if initialization is None
        else RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA,
        "kind": "FROZEN_CONFIRMATORY_SPLIT",
        "profile": SIMULATED_RESERVE_PROFILE,
        "ledger_run_id": run_id,
        "ledger_path": ledger.relative_path.as_posix(),
        "recorded_at": at,
        "window_index": index,
        "reservation_units": 8,
        "allocation_consumed_on_record_publication": True,
        "study_id": protocol.study_id,
        "study_version": protocol.study_version,
        "split_id": contract.dataset.confirmatory_split_id,
        "role": "holdout",
        "split_manifest_hash": split,
        "population_artifact_sha256": pop.sha256,
        "population_record_hash": pop.record_hash,
        "protocol_artifact_sha256": p_record.sha256,
        "protocol_record_hash": p_record.record_hash,
        "protocol_sha256": protocol.sha256,
        "contract_artifact_sha256": c_record.sha256,
        "contract_record_hash": c_record.record_hash,
        "contract_sha256": contract.sha256,
        "prior_reservation_artifact_sha256": previous.record.sha256
        if previous
        else None,
        "prior_reservation_record_hash": previous.record.record_hash
        if previous
        else None,
        "member_ids": list(ids),
        "member_row_sha256s": list(hashes),
        "evaluator_payload_sha256": sha256_bytes(payload),
        "evaluator_payload_size": len(payload),
        "evaluator_profile": "SIMULATED_TWO_GROUP_MEAN_DIFFERENCE_V1",
        "source_registry_identities": [
            list(item) for item in _registry_record_map(pair[0].records)
        ],
        "source_registry_count": source_count,
        "source_registry_fingerprint": fingerprint,
        "source_ledger_event_count": pair[1].event_count,
        "source_ledger_head_hash": pair[1].head_hash,
        **_SCOPE,
    }


def _parents(sources, *, initialization=None):
    return (
        sources[4].sha256,
        sources[0].sha256,
        sources[2].sha256,
        *((initialization.record.sha256,) if initialization is not None else ()),
        *((sources[8].record.sha256,) if sources[8] else ()),
    )


def _event(value, record, source):
    slot = sha256_bytes(
        canonical_json_bytes(
            {
                "run_id": value["ledger_run_id"],
                "population": value["population_artifact_sha256"],
                "window_index": value["window_index"],
            }
        )
    )
    return LedgerEvent.create(
        run_id=value["ledger_run_id"],
        event_id=_EVENT_PREFIX + slot[:40],
        timestamp=value["recorded_at"],
        actor_role=Role.PROTOCOL_DESIGNER,
        state_before=_timeline_state(source.events),
        requested_state_after=_timeline_state(source.events),
        artifact_hashes=(record.sha256,),
        code_version="sha256:" + value["protocol_artifact_sha256"],
        configuration_hash=value["contract_sha256"],
        dataset_identifiers=(),
        random_seeds=(),
        evaluator_outputs=(),
        reason="reserved eight public simulated row units without scientific or release authority",
        prior_event_hash=source.head_hash,
        event_type="CHECKPOINT",
        metadata={
            "artifact_types": [_RESERVE_TYPE],
            "artifact_record_hashes": [record.record_hash],
            SIMULATED_RESERVE_EVENT_KEY: {
                "schema_version": SIMULATED_RESERVE_EVENT_SCHEMA
                if value["schema_version"] == SIMULATED_RESERVE_SCHEMA
                else (OBSERVED_SECOND_SIMULATED_RESERVE_EVENT_SCHEMA
                      if value["schema_version"] == OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA
                      else RESOURCE_BACKED_SIMULATED_RESERVE_EVENT_SCHEMA),
                "reservation_artifact_sha256": record.sha256,
                "reservation_record_hash": record.record_hash,
                "population_artifact_sha256": value["population_artifact_sha256"],
                "window_index": value["window_index"],
                "reservation_units": 8,
                "evidence_class": "NON_EVIDENTIARY",
            },
        },
    )


def _reserved_events(events, references=frozenset()):
    selected = []
    for index, event in enumerate(events):
        keys, strings, schemas, types = _markers(event.metadata)
        if (
            event.event_id.startswith(_EVENT_PREFIX)
            or _new_simulated_markers(event.metadata)
            or "FROZEN_CONFIRMATORY_SPLIT" in schemas
            or _RESERVE_TYPE in types
            or references.intersection((*event.artifact_hashes, *strings))
        ):
            selected.append((index, event))
    return tuple(selected)


def _require_consumed_reservation_events(
    registry, pair, reservations, *, initialization=None, charges=()
):
    """Check slots without recursively reopening later reservations' sources."""
    consumed = (
        [(initialization.event_index, initialization.event)]
        if initialization is not None
        else []
    )
    consumed.extend((item.event_index, item.event) for item in charges)
    references = frozenset(
        identity
        for record in (
            *(record for record, _ in reservations),
            *(
                record
                for record in pair[0].records
                if record.logical_type == SIMULATED_RESERVE_POPULATION_LOGICAL_TYPE
            ),
        )
        for identity in (record.sha256, record.record_hash)
    )
    for record, value in reservations:
        source = _source_pair(pair, value)
        expected = _event(value, record, source[1])
        index = source[1].event_count
        if index < pair[1].event_count and pair[1].events[index] == expected:
            consumed.append((index, expected))
        elif any(
            record.sha256 in event.artifact_hashes
            for _, event in _reserved_events(pair[1].events, references)
        ):
            raise SimulatedReserveError(
                "reservation is referenced by a substituted publication event"
            )
        # A record-only orphan remains consumed membership, never a fresh slot.
    if _reserved_events(pair[1].events, references) != tuple(
        sorted(consumed, key=lambda item: item[0])
    ):
        raise SimulatedReserveError(
            "unmatched reserved publication event or schema alias"
        )


def _validate_inventory(
    registry, ledger, pair, *, allowed, source_owners, initialization=None, charges=()
):
    """All reservations occupy units; only the exact supported prefix is usable."""
    _populations, reservations = _candidate_records(
        registry, pair[0].records, initialization=initialization, charges=charges
    )
    _require_consumed_reservation_events(
        registry, pair, reservations, initialization=initialization, charges=charges
    )
    expected = {item.record.sha256: item for item in allowed}
    if {record.sha256 for record, _ in reservations} != set(expected):
        raise SimulatedReserveError(
            "reserved population has unknown, orphaned or competing windows"
        )
    for record, payload in reservations:
        item = expected[record.sha256]
        if payload["window_index"] != item.window_index:
            raise SimulatedReserveError("reservation window alias changed")
    expected_events = tuple(
        sorted(
            (
                ((initialization.event_index, initialization.event),)
                if initialization is not None
                else ()
            )
            + tuple((item.event_index, item.event) for item in allowed)
            + tuple((item.event_index, item.event) for item in charges),
            key=lambda item: item[0],
        )
    )
    if _reserved_events(pair[1].events) != expected_events:
        raise SimulatedReserveError(
            "reservation event population is incomplete or competing"
        )
    if initialization is not None:
        source_owners = (
            (*source_owners[0], initialization.record),
            (*source_owners[1], initialization.event),
        )
    if charges:
        source_owners = (
            (*source_owners[0], *(item.record for item in charges)),
            (*source_owners[1], *(item.event for item in charges)),
        )
    _reject_prior_experiment_coexistence(registry, pair, source_owners=source_owners)


def _prior_work_markers(value):
    from .simulated_resource import _charge_schema_selected

    keys, _references, hints, types = _markers(value)
    return bool(
        keys.intersection(_PRIOR_WORK_KEYS)
        or hints.intersection(_PRIOR_WORK_SCHEMAS)
        or any(_charge_schema_selected(item) for item in hints)
        or types.intersection(_PRIOR_WORK_FAMILIES)
        or any(family.startswith(("experiment_output.", "resource_runtime_simulated_attempt.")) for family in types)
    )


def _reject_prior_experiment_coexistence(registry, pair, *, source_owners):
    """The closed simulated allocator cannot coexist with prior native F/D.

    This is a run-local unsupported-coexistence rule, not a scientific claim
    that the prior work actually read these public fixture rows.
    """
    from .seed_reporting import reject_operational_seed_exposure
    from .simulated_resource import _charge_schema_selected

    reject_operational_seed_exposure(
        registry,
        pair[0].records,
        pair[1].events,
        complete_registry_population=True,
    )
    owned_records, owned_events = source_owners
    for event in pair[1].events:
        if event in owned_events:
            continue
        if (
            _prior_work_markers(event.metadata)
            or event.event_type in {"CONFIRMATORY_STARTED", "CONFIRMATORY_COMPLETED"}
            or event.event_id.startswith(
                (
                    "scientific-dataset-",
                    "scientific-experiment-dataset-",
                    "dataset-statistical-use-proposal-",
                    "dataset-statistical-use-authority-",
                )
            )
        ):
            raise SimulatedReserveError(
                "unowned prior native work or custody is unsupported"
            )
    for record in pair[0].records:
        if record in owned_records:
            continue
        if (
            record.logical_type in _PRIOR_WORK_FAMILIES
            or record.logical_type.startswith(("experiment_output.", "resource_runtime_simulated_attempt."))
            or record.schema_version in _PRIOR_WORK_SCHEMAS
            or _charge_schema_selected(record.schema_version)
            or record.origin.startswith(_PRIOR_WORK_ORIGINS)
            or record.creation_command in _PRIOR_WORK_COMMANDS
            or record.creation_command
            == ("scientist-one", "research-os-fixture", "capture-output-manifest")
        ):
            raise SimulatedReserveError(
                "unowned prior native work metadata is unsupported"
            )
        value = _selected_json_hint(
            registry,
            pair[0].records,
            record,
            malformed_markers=_PRIOR_WORK_RAW_MARKERS,
        )
        if _prior_work_markers(value):
            raise SimulatedReserveError(
                "unowned prior native work alias is unsupported"
            )


def _initialization_at_snapshot(registry, ledger, pair, *, run_id, digest):
    # S alone resolves I. I's own replay reuses _sources on its sealed pre-I
    # event-count-zero population with initialization=None: no recursive lookup.
    from .simulated_resource import (
        _require_simulated_resource_initialization_at_snapshot,
    )

    return _require_simulated_resource_initialization_at_snapshot(
        registry,
        ledger,
        expected_run_id=run_id,
        initialization_artifact_sha256=_sha(digest),
        registry_snapshot=pair[0],
        ledger_snapshot=pair[1],
    )


def _require_initialization_source(pair, sources, initialization):
    if initialization is None:
        return
    expected_ids = set(initialization.source_registry_identities) | {
        (initialization.record.sha256, initialization.record.record_hash)
    }
    if (
        initialization.event_index != 0
        or pair[1].events != (initialization.event,)
        or set(_registry_record_map(pair[0].records)) != expected_ids
        or sources[:5]
        != (
            initialization.protocol_record,
            initialization.protocol,
            initialization.contract_record,
            initialization.contract,
            initialization.population_record,
        )
    ):
        raise SimulatedReserveError(
            "resource-backed first reservation differs from exact original I/P/C/pop sources"
        )


def _require_initial_external(registry, initialization):
    from .orchestrator import _read_resource_authority_records, OrchestrationError

    try:
        records = _read_resource_authority_records(
            registry.policy.root, initialization.runtime_state.run_id
        )
    except OrchestrationError as exc:
        raise SimulatedReserveError(
            "resource-backed reservation external history is missing, malformed or unsafe"
        ) from exc
    if (
        len(records) != 1
        or canonical_json_bytes(records[0]) + b"\n"
        != initialization.external_authority_bytes
    ):
        raise SimulatedReserveError(
            "resource-backed reservation requires the exact original external I head"
        )


def _require_at_snapshot(
    registry,
    ledger,
    *,
    expected_run_id,
    reservation_artifact_sha256,
    registry_snapshot,
    ledger_snapshot,
    check_current_slots=True,
):
    pair = registry_snapshot, ledger_snapshot
    _sha(reservation_artifact_sha256)
    if check_current_slots:
        from .simulated_resource import _has_second_charge, _second_charge_outer_reservation

        if _has_second_charge(registry, pair):
            return _second_charge_outer_reservation(
                registry, ledger, pair, expected_run_id, reservation_artifact_sha256)
    if _one(pair[0].records, reservation_artifact_sha256).schema_version == OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA:
        return _require_observed_second_at_snapshot(
            registry, ledger, pair, expected_run_id, reservation_artifact_sha256
        )[0]
    if check_current_slots:
        if any(record.schema_version == OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA for record in pair[0].records):
            return _observed_second_outer_reservation(
                registry, ledger, pair, expected_run_id, reservation_artifact_sha256
            )
        from .simulated_observation import _has_history, _passive_reservation

        if _has_history(registry, pair):
            return _passive_reservation(
                registry, ledger, pair, reservation_artifact_sha256
            )
    record = _one(registry_snapshot.records, reservation_artifact_sha256)
    value = _json(registry, record)
    if (
        value.get("schema_version")
        not in {SIMULATED_RESERVE_SCHEMA, RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA}
        or value.get("ledger_run_id") != expected_run_id
        or value.get("ledger_path") != ledger.relative_path.as_posix()
        or type(value.get("window_index")) is not int
        or value["window_index"] not in (1, 2)
        or (
            value.get("schema_version") == RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA
            and value["window_index"] != 1
        )
    ):
        raise SimulatedReserveError("reservation profile or run binding differs")
    initialization = None
    if value["schema_version"] == RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA:
        if len(record.parent_artifacts) != 4:
            raise SimulatedReserveError(
                "resource-backed reservation has no exact fourth I parent"
            )
        initialization = _initialization_at_snapshot(
            registry,
            ledger,
            pair,
            run_id=expected_run_id,
            digest=record.parent_artifacts[3],
        )
    source = _source_pair(pair, value)
    if record in source[0].records:
        raise SimulatedReserveError(
            "reservation cannot occur in its own source preimage"
        )
    sources = _sources(
        registry,
        ledger,
        source,
        run_id=expected_run_id,
        protocol_sha=value.get("protocol_artifact_sha256"),
        contract_sha=value.get("contract_artifact_sha256"),
        population_sha=value.get("population_artifact_sha256"),
        index=value["window_index"],
        prior_sha=value.get("prior_reservation_artifact_sha256"),
        initialization=initialization,
    )
    _require_initialization_source(source, sources, initialization)
    previous = sources[8]
    _validate_inventory(
        registry,
        ledger,
        source,
        allowed=(previous,) if previous else (),
        source_owners=sources[9],
        initialization=initialization,
    )
    expected = _body(
        ledger,
        source,
        sources,
        run_id=expected_run_id,
        index=value["window_index"],
        at=value.get("recorded_at"),
        initialization=initialization,
    )
    if value != expected or record != _plan_record(
        registry,
        expected,
        parents=_parents(sources, initialization=initialization),
        at=value["recorded_at"],
    ):
        raise SimulatedReserveError(
            "reservation bytes or native metadata differ from owned sources"
        )
    at = _time(record.created_at)
    if any(_time(item.created_at) > at for item in source[0].records) or any(
        _time(item.timestamp) > at for item in source[1].events
    ):
        raise SimulatedReserveError("reservation predates its source population")
    event = _event(value, record, source[1])
    index = source[1].event_count
    if index >= len(ledger_snapshot.events) or ledger_snapshot.events[index] != event:
        raise SimulatedReserveError("reservation lacks its exact publication event")
    if any(
        item.supersedes_event_id == event.event_id for item in ledger_snapshot.events
    ):
        raise SimulatedReserveError(
            "corrected reservation still consumes units but has no use authority"
        )
    if check_current_slots:
        from .simulated_resource import _completed_charges_for_reservation

        charges = _completed_charges_for_reservation(
            registry, ledger, pair, record.sha256
        )
        _populations, all_reserves = _candidate_records(
            registry,
            registry_snapshot.records,
            initialization=initialization,
            charges=charges,
        )
        _require_consumed_reservation_events(
            registry, pair, all_reserves, initialization=initialization, charges=charges
        )
        if tuple(
            item
            for item, payload in all_reserves
            if payload["window_index"] == value["window_index"]
        ) != (record,):
            raise SimulatedReserveError(
                "reservation window has competing native or alias records"
            )
        if tuple(
            (i, item)
            for i, item in _reserved_events(ledger_snapshot.events)
            if item.event_id == event.event_id or record.sha256 in item.artifact_hashes
        ) != ((index, event),):
            raise SimulatedReserveError("reservation event slot has a competing alias")
    return SimulatedReservePublication(
        record,
        event,
        index,
        *sources[:5],
        value["window_index"],
        sources[5],
        sources[6],
        sources[7],
        sha256_bytes(sources[7]),
        value["split_manifest_hash"],
        _registry_record_map(source[0].records),
        source[1].event_count,
        source[1].head_hash,
        registry_snapshot,
        ledger_snapshot,
    )


def _require_simulated_confirmatory_reserve_at_snapshot(
    registry,
    ledger,
    *,
    expected_run_id,
    reservation_artifact_sha256,
    registry_snapshot,
    ledger_snapshot,
):
    """Historical full S owner for the lower native observation replay edge.

    Never reads a live population or calls currentness. The supplied snapshots
    must be the caller-owned sealed source population/prefix, not arbitrary
    narrowed evidence. Later reservations or consumption events are not replayed
    recursively here. This grants no permission for a new release or allocation.
    """
    if (
        type(registry) is not ArtifactRegistry
        or type(ledger) is not EventLedger
        or registry.policy.root != ledger.policy.root
        or type(registry_snapshot) is not RegistryValidationResult
        or type(ledger_snapshot) is not LedgerValidationResult
        or not registry_snapshot.valid
        or not ledger_snapshot.valid
        or any(event.run_id != expected_run_id for event in ledger_snapshot.events)
    ):
        raise SimulatedReserveError(
            "historical reserve requires exact selected native sources"
        )
    return _require_at_snapshot(
        registry,
        ledger,
        expected_run_id=expected_run_id,
        reservation_artifact_sha256=reservation_artifact_sha256,
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
        check_current_slots=False,
    )


def require_simulated_confirmatory_reserve(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_run_id: str,
    reservation_artifact_sha256: str,
) -> SimulatedReservePublication:
    """Read historical allocation without selecting a current contract or releasing data."""
    try:
        before = _context(registry, ledger, expected_run_id)
        result = _require_at_snapshot(
            registry,
            ledger,
            expected_run_id=expected_run_id,
            reservation_artifact_sha256=reservation_artifact_sha256,
            registry_snapshot=before[0],
            ledger_snapshot=before[1],
        )
        if _context(registry, ledger, expected_run_id) != before:
            raise SimulatedReserveError("reservation sources changed during readback")
        return result
    except SimulatedReserveError:
        raise
    except (
        ArtifactError,
        LedgerError,
        ValidationError,
        UnsafeSerializationError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        raise SimulatedReserveError("reservation source replay failed") from exc


def register_simulated_confirmatory_reserve(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_run_id: str,
    protocol_artifact_sha256: str,
    contract_artifact_sha256: str,
    population_artifact_sha256: str,
    window_index: int,
    prior_reservation_artifact_sha256: str | None = None,
    initialization_artifact_sha256: str | None = None,
    prior_observation_artifact_sha256: str | None = None,
) -> SimulatedReservePublication:
    """Commit one irreversible pinned allocation; no custody observation or release."""
    try:
        if prior_observation_artifact_sha256 is not None:
            return _register_observed_second(
                registry, ledger, expected_run_id=expected_run_id,
                protocol_artifact_sha256=protocol_artifact_sha256,
                contract_artifact_sha256=contract_artifact_sha256,
                population_artifact_sha256=population_artifact_sha256,
                window_index=window_index,
                prior_reservation_artifact_sha256=prior_reservation_artifact_sha256,
                initialization_artifact_sha256=initialization_artifact_sha256,
                prior_observation_artifact_sha256=prior_observation_artifact_sha256,
            )
        context = nullcontext()
        if initialization_artifact_sha256 is not None:
            if (
                type(window_index) is not int
                or window_index != 1
                or prior_reservation_artifact_sha256 is not None
            ):
                raise SimulatedReserveError(
                    "resource-backed window two requires an unimplemented native observation/amendment lifecycle"
                )
            from .orchestrator import (
                _project_resource_execution_lock,
                _named_directory_identity,
            )
            from .simulated_resource import _paths

            _sha(initialization_artifact_sha256)
            root, _run = _paths(registry, ledger, expected_run_id)
            context = _project_resource_execution_lock(
                root, expected_root_identity=_named_directory_identity(root)
            )
        with context:
            return _register(
                registry,
                ledger,
                expected_run_id=expected_run_id,
                protocol_artifact_sha256=protocol_artifact_sha256,
                contract_artifact_sha256=contract_artifact_sha256,
                population_artifact_sha256=population_artifact_sha256,
                window_index=window_index,
                prior_reservation_artifact_sha256=prior_reservation_artifact_sha256,
                initialization_artifact_sha256=initialization_artifact_sha256,
            )
    except SimulatedReserveError:
        raise
    except (
        ArtifactError,
        LedgerError,
        ValidationError,
        UnsafeSerializationError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        raise SimulatedReserveError("reservation publication failed") from exc


def _register(
    registry,
    ledger,
    *,
    expected_run_id,
    protocol_artifact_sha256,
    contract_artifact_sha256,
    population_artifact_sha256,
    window_index,
    prior_reservation_artifact_sha256,
    initialization_artifact_sha256=None,
):
    if type(window_index) is not int or window_index not in (1, 2):
        raise SimulatedReserveError(
            "simulated window must be the exact integer one or two"
        )
    if initialization_artifact_sha256 is not None and (
        window_index != 1 or prior_reservation_artifact_sha256 is not None
    ):
        raise SimulatedReserveError(
            "resource-backed window two requires an unimplemented native observation/amendment lifecycle"
        )
    for digest in (
        protocol_artifact_sha256,
        contract_artifact_sha256,
        population_artifact_sha256,
    ):
        _sha(digest)
    if prior_reservation_artifact_sha256 is not None:
        _sha(prior_reservation_artifact_sha256)
    before = _context(registry, ledger, expected_run_id, ensure=True)
    initialization = (
        _initialization_at_snapshot(
            registry,
            ledger,
            before,
            run_id=expected_run_id,
            digest=initialization_artifact_sha256,
        )
        if initialization_artifact_sha256 is not None
        else None
    )
    if initialization is not None:
        _require_initial_external(registry, initialization)
    _pops, reserves = _candidate_records(
        registry, before[0].records, initialization=initialization
    )
    slots = tuple(
        (record, value)
        for record, value in reserves
        if value["window_index"] == window_index
    )
    if len(slots) > 1:
        raise SimulatedReserveError(
            "reservation window is already ambiguously occupied"
        )
    existing = slots[0] if slots else None
    request_fields = {
        "schema_version": SIMULATED_RESERVE_SCHEMA
        if initialization is None
        else RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA,
        "protocol_artifact_sha256": protocol_artifact_sha256,
        "contract_artifact_sha256": contract_artifact_sha256,
        "population_artifact_sha256": population_artifact_sha256,
        "window_index": window_index,
        "prior_reservation_artifact_sha256": prior_reservation_artifact_sha256,
    }
    if existing:
        record, value = existing
        if initialization is not None and record.parent_artifacts != (
            population_artifact_sha256,
            protocol_artifact_sha256,
            contract_artifact_sha256,
            initialization.record.sha256,
        ):
            raise SimulatedReserveError(
                "occupied reservation has a different exact I parent"
            )
        if any(value.get(key) != item for key, item in request_fields.items()):
            raise SimulatedReserveError("occupied reservation cannot be reassigned")
        if any(
            record.sha256 in event.artifact_hashes
            for _, event in _reserved_events(before[1].events)
        ):
            result = require_simulated_confirmatory_reserve(
                registry,
                ledger,
                expected_run_id=expected_run_id,
                reservation_artifact_sha256=record.sha256,
            )
            if initialization is not None:
                _require_initial_external(registry, initialization)
                if _context(registry, ledger, expected_run_id) != before:
                    raise SimulatedReserveError(
                        "resource-backed reservation replay changed"
                    )
            return result
        source = _source_pair(before, value)
        if (
            _registry_record_map(
                tuple(item for item in before[0].records if item != record)
            )
            != _registry_record_map(source[0].records)
            or before[1] != source[1]
        ):
            raise SimulatedReserveError(
                "reservation orphan cannot recover after source drift"
            )
        at = value.get("recorded_at")
    else:
        source, at = before, utc_now()
    current = _require_current_evaluation_contract_lineage(
        registry,
        ledger,
        expected_run_id=expected_run_id,
        contract_artifact_sha256=contract_artifact_sha256,
    )
    if (current.registry_snapshot, current.ledger_snapshot) != before:
        raise SimulatedReserveError(
            "current contract readback differs from reservation preflight"
        )
    if window_index == 2:
        require_scientific_protocol_revision(
            registry,
            ledger,
            expected_run_id=expected_run_id,
            protocol_artifact_sha256=protocol_artifact_sha256,
        )
    sources = _sources(
        registry,
        ledger,
        source,
        run_id=expected_run_id,
        protocol_sha=protocol_artifact_sha256,
        contract_sha=contract_artifact_sha256,
        population_sha=population_artifact_sha256,
        index=window_index,
        prior_sha=prior_reservation_artifact_sha256,
        initialization=initialization,
    )
    _require_initialization_source(source, sources, initialization)
    _validate_inventory(
        registry,
        ledger,
        source,
        allowed=(sources[8],) if sources[8] else (),
        source_owners=sources[9],
        initialization=initialization,
    )
    value = _body(
        ledger,
        source,
        sources,
        run_id=expected_run_id,
        index=window_index,
        at=at,
        initialization=initialization,
    )
    record = _plan_record(
        registry, value, parents=_parents(sources, initialization=initialization), at=at
    )
    if existing and existing != (record, value):
        raise SimulatedReserveError(
            "reservation orphan differs from exact source reconstruction"
        )
    if any(_time(item.created_at) > _time(at) for item in source[0].records) or any(
        _time(item.timestamp) > _time(at) for item in source[1].events
    ):
        raise SimulatedReserveError("reservation publication clock predates sources")
    event = _event(value, record, source[1])
    raw = canonical_json_bytes(value) + b"\n"
    event_raw = canonical_json_bytes(event.to_dict()) + b"\n"
    if (
        before[0].count + int(existing is None) > MAX_REGISTRY_RECORDS
        or before[1].event_count + 1 > MAX_LEDGER_EVENTS
        or before[1].valid_prefix_bytes + len(event_raw) > MAX_LEDGER_BYTES
    ):
        raise SimulatedReserveError(
            "reservation publication lacks registry/ledger capacity"
        )
    if _context(registry, ledger, expected_run_id) != before:
        raise SimulatedReserveError("reservation sources changed during preflight")
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            locked_registry = registry._verify_all_locked(
                registry_guard, raise_on_error=True
            )
            ledger_raw = ledger._read_raw_locked(ledger_guard)
            locked_ledger = ledger._validate_bytes(ledger_raw)
            if (locked_registry, locked_ledger) != before:
                raise SimulatedReserveError("reservation sources changed before commit")
            if initialization is not None:
                _require_initial_external(registry, initialization)
            prospective = ledger._validate_bytes(ledger_raw + event_raw)
            if not prospective.valid or prospective.events != (
                *locked_ledger.events,
                event,
            ):
                raise SimulatedReserveError(
                    "reservation prospective event is not one valid append"
                )
            committed = (
                record
                if existing
                else _put_locked(registry, registry_guard, record, raw)
            )

            def build(current):
                if current != locked_ledger:
                    raise SimulatedReserveError(
                        "reservation ledger changed during commit"
                    )
                return event

            appended = ledger._append_locked(ledger_guard, build)
            if initialization is not None:
                _require_initial_external(registry, initialization)
            after = (
                registry._verify_all_locked(registry_guard, raise_on_error=True),
                ledger._validate_bytes(ledger._read_raw_locked(ledger_guard)),
            )
            if (
                committed != record
                or appended != event
                or after[1] != prospective
                or set(after[0].records) != {*before[0].records, record}
            ):
                raise SimulatedReserveError(
                    "reservation commit changed outside exact planned delta"
                )
            registry._verify_mutation_namespace(registry_guard)
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    result = require_simulated_confirmatory_reserve(
        registry,
        ledger,
        expected_run_id=expected_run_id,
        reservation_artifact_sha256=record.sha256,
    )
    if initialization is not None:
        _require_initial_external(registry, initialization)
        if _context(registry, ledger, expected_run_id) != (
            result.registry_snapshot,
            result.ledger_snapshot,
        ):
            raise SimulatedReserveError(
                "resource-backed reservation final readback changed"
            )
    return result


def _observed_second_pair(ledger, pair):
    """Bound the complete selected population, never a filtered census."""
    from .simulated_observation import _require_native_observation_pair

    if type(pair) is not tuple or len(pair) != 2:
        raise SimulatedReserveError("observed second reserve requires a native pair")
    _require_native_observation_pair(ledger, *pair)
    if (any(record.size > MAX_SIMULATED_RESERVE_BYTES for record in pair[0].records)
            or sum(record.size for record in pair[0].records) > MAX_SIMULATED_RESERVE_SCAN_BYTES):
        raise SimulatedReserveError("observed second reserve exceeds its complete scan bound")


def _observed_second_sources(
    registry, ledger, pair, *, run_id, protocol_sha, contract_sha, population_sha,
    initialization_sha, prior_reservation_sha, prior_observation_sha,
):
    """Strictly descend P2 -> A2 -> sealed COMPLETE J1 -> S1/Q1/I.

    The old allocation-only second-window source path and I-only first-window
    guards deliberately remain separate. No higher population is fed to S1/J1.
    """
    from . import evaluation_contract_amendment as amendments
    from . import scientific_protocol_revision as protocols
    from . import simulated_observation as observation
    from . import simulated_resource as accounting

    accounting._paths(registry, ledger, run_id)
    for digest in (protocol_sha, contract_sha, population_sha, initialization_sha,
                   prior_reservation_sha, prior_observation_sha):
        _sha(digest)
    _observed_second_pair(ledger, pair)
    revision = _protocol_revision_at_snapshot(
        registry, ledger, record=_one(pair[0].records, protocol_sha), pair=pair,
    )
    amendment = revision.amendment_publication
    authority = amendment.authority
    if (authority.schema_version != amendments.EVALUATION_CONTRACT_OBSERVED_AMENDMENT_SCHEMA
            or len(authority.observed_controls) != 1
            or authority.observed_controls[0].observation_artifact_sha256 != prior_observation_sha
            or authority.visible_results
            or authority.amendment.results_already_seen is not True
            or authority.amendment.requires_new_confirmatory_reserve is not True
            or revision.authority.results_seen_at_amendment is not True
            or revision.authority.requires_new_confirmatory_reserve_at_amendment is not True):
        raise SimulatedReserveError("second reserve requires the exact observed A2/P2 lineage")
    jpair = (
        RegistryValidationResult(True, amendments._sealed_registry_records(pair[0], authority)),
        amendments._source_ledger_prefix(pair[1], authority),
    )
    observed = observation._require_simulated_reserve_observation_at_snapshot(
        registry, ledger, expected_run_id=run_id,
        observation_artifact_sha256=prior_observation_sha,
        registry_snapshot=jpair[0], ledger_snapshot=jpair[1],
    )
    charge = observed.preparation.charge
    initial, previous = charge.initialization, charge.reservation
    contract, protocol = amendment.child_contract, revision.protocol
    if (previous.record.sha256 != prior_reservation_sha
            or initial.record.sha256 != initialization_sha
            or previous.record.schema_version != RESOURCE_BACKED_SIMULATED_RESERVE_SCHEMA
            or previous.window_index != 1
            or previous.record.parent_artifacts != (
                previous.population_record.sha256, previous.protocol_record.sha256,
                previous.contract_record.sha256, initial.record.sha256)
            or previous.population_record.sha256 != population_sha
            or previous.protocol_record != revision.parent_protocol_record
            or previous.protocol != revision.parent_protocol
            or previous.contract_record != amendment.parent_contract_record
            or previous.contract != amendment.parent_contract
            or amendment.contract_record.sha256 != contract_sha
            or protocol.study_version != 2 or previous.protocol.study_version != 1
            or contract.seed_reporting.regime is not ReportingRegime.ALL_SEEDS):
        raise SimulatedReserveError("observed second reserve substituted original I/S1 or successor P2/C2")
    observation._budget(charge)
    # These equalities own every record/event, not merely the required parents.
    after_a = observation._append_pair(jpair, amendment.amendment_record)
    after_a = observation._append_pair(after_a, amendment.contract_record, amendment.event)
    psource = (
        RegistryValidationResult(True, protocols._source_records(pair[0], revision.authority)),
        protocols._source_ledger_prefix(pair[1], revision.authority),
    )
    if (not observation._same_pair(psource, after_a)
            or not observation._same_pair(pair, observation._append_pair(
                after_a, revision.protocol_record, revision.event))):
        raise SimulatedReserveError("pre-S2 population is not exact J1 plus A2/C2/P2")
    lineage = _resolve_lineage(
        registry, ledger, contract_artifact_sha256=contract_sha, expected_run_id=run_id,
        registry_snapshot=pair[0], ledger_snapshot=pair[1],
        require_snapshot_local_dependencies=True,
    )
    if (lineage.contract_records != (previous.contract_record, amendment.contract_record)
            or lineage.contracts[-1] != contract):
        raise SimulatedReserveError("observed second reserve has a competing contract lineage")
    _require_no_completed_contract_successor_before(
        registry, ledger, selected_record=amendment.contract_record, expected_run_id=run_id,
        registry_snapshot=pair[0], ledger_snapshot=pair[1],
        design_event_index=pair[1].event_count, complete_source_population=True,
    )
    _require_scientific_protocol_contract_crosswalk(protocol, contract)
    population = _pinned_population()
    if _json(registry, previous.population_record) != population:
        raise SimulatedReserveError("observed second reserve population changed")
    ids, hashes, payload = _window(population, 2)
    if set(ids) & set(previous.member_ids) or len(ids) != 8:
        raise SimulatedReserveError("observed second reserve is not the disjoint pinned window")
    sources = (revision.protocol_record, protocol, amendment.contract_record, contract,
               previous.population_record, ids, hashes, payload, previous)
    return sources, revision, observed


def _observed_second_plan(registry, ledger, pair, sources, revision, observed, at):
    from . import simulated_observation as observation

    observation._chronology(pair, at)
    charge, amendment = observed.preparation.charge, revision.amendment_publication
    initial = charge.initialization
    value = _body(ledger, pair, sources, run_id=initial.runtime_state.run_id,
                  index=2, at=at, initialization=initial)
    value.update({
        "schema_version": OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA,
        "initialization_artifact_sha256": initial.record.sha256,
        "initialization_record_hash": initial.record.record_hash,
        "prior_observation_artifact_sha256": observed.record.sha256,
        "prior_observation_record_hash": observed.record.record_hash,
        "prior_observation_event_hash": observed.event.event_hash,
        "prior_charge_artifact_sha256": charge.record.sha256,
        "prior_charge_record_hash": charge.record.record_hash,
        "prior_attempt_artifact_sha256": observed.attempt.record.sha256,
        "prior_attempt_record_hash": observed.attempt.record.record_hash,
        "amendment_artifact_sha256": amendment.amendment_record.sha256,
        "amendment_record_hash": amendment.amendment_record.record_hash,
        "disjoint_from_prior_reservation": True,
        "native_confirmatory_units_already_used": 8,
        "additional_validity_units": 0,
        "resource_charge_authorized": False,
        "execution_attestation_authorized": False,
        "host_attestation_authorized": False,
    })
    parents = (*_parents(sources, initialization=initial), observed.record.sha256,
               amendment.amendment_record.sha256)
    record = _plan_record(registry, value, parents=parents, at=at)
    old_event = _event(value, record, pair[1])
    event = replace(old_event, event_hash=None, metadata={
        "artifact_types": [_RESERVE_TYPE], "artifact_record_hashes": [record.record_hash],
        SIMULATED_RESERVE_EVENT_KEY: {
            **dict(old_event.metadata[SIMULATED_RESERVE_EVENT_KEY]),
            "schema_version": OBSERVED_SECOND_SIMULATED_RESERVE_EVENT_SCHEMA,
            "initialization_artifact_sha256": initial.record.sha256,
            "prior_reservation_artifact_sha256": sources[8].record.sha256,
            "prior_observation_artifact_sha256": observed.record.sha256,
            "amendment_artifact_sha256": amendment.amendment_record.sha256,
            "additional_validity_units": 0,
        },
    })
    return value, record, event


def _require_observed_second_at_snapshot(registry, ledger, pair, run_id, digest):
    """Complete selected S2 replay, without current C/resource/custody IO."""
    from . import simulated_observation as observation
    from . import simulated_resource as accounting

    accounting._paths(registry, ledger, run_id)
    _observed_second_pair(ledger, pair)
    record = _one(pair[0].records, digest)
    value = _json(registry, record)
    if (value.get("schema_version") != OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA
            or type(value.get("window_index")) is not int or value["window_index"] != 2):
        raise SimulatedReserveError("selected observed second reserve wire differs")
    source = _source_pair(pair, value)
    if record in source[0].records:
        raise SimulatedReserveError("S2 cannot appear in its own source pair")
    sources, revision, observed = _observed_second_sources(
        registry, ledger, source, run_id=run_id,
        protocol_sha=value.get("protocol_artifact_sha256"),
        contract_sha=value.get("contract_artifact_sha256"),
        population_sha=value.get("population_artifact_sha256"),
        initialization_sha=value.get("initialization_artifact_sha256"),
        prior_reservation_sha=value.get("prior_reservation_artifact_sha256"),
        prior_observation_sha=value.get("prior_observation_artifact_sha256"),
    )
    expected, planned, event = _observed_second_plan(
        registry, ledger, source, sources, revision, observed, value.get("recorded_at"))
    if (canonical_json_bytes(value) != canonical_json_bytes(expected) or record != planned
            or not observation._same_pair(pair, observation._append_pair(source, record, event))):
        raise SimulatedReserveError("observed S2 has an unowned orphan, alias, correction or delta")
    result = SimulatedReservePublication(
        record, event, source[1].event_count, *sources[:5], 2, sources[5], sources[6], sources[7],
        sha256_bytes(sources[7]), value["split_manifest_hash"], _registry_record_map(source[0].records),
        source[1].event_count, source[1].head_hash, pair[0], pair[1],
    )
    return result, revision, observed


def _observed_second_outer_reservation(registry, ledger, pair, run_id, digest):
    records = tuple(record for record in pair[0].records
                    if record.schema_version == OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA)
    if len(records) != 1:
        raise SimulatedReserveError("observed S2 outer slot is ambiguous")
    second, _revision, observed = _require_observed_second_at_snapshot(
        registry, ledger, pair, run_id, records[0].sha256)
    if digest == second.record.sha256:
        return second
    previous = observed.preparation.charge.reservation
    if digest != previous.record.sha256:
        raise SimulatedReserveError("observed S2 does not own this lower reservation")
    return replace(previous, registry_snapshot=pair[0], ledger_snapshot=pair[1])


def _observed_second_capacity(registry, observed, pair, record, event, *, missing):
    from .resources import ResourceController, conservative_disk_reserve

    payload_bytes = record.size if missing else 0
    metadata_bytes = len(canonical_json_bytes(record.to_dict())) + 1 if missing else 0
    event_bytes = len(canonical_json_bytes(event.to_dict())) + 1
    required = payload_bytes + metadata_bytes + event_bytes
    if (pair[0].count + int(missing) > MAX_REGISTRY_RECORDS
            or pair[1].event_count + 1 > MAX_LEDGER_EVENTS
            or pair[1].valid_prefix_bytes + event_bytes > MAX_LEDGER_BYTES
            or event_bytes > MAX_SIMULATED_RESERVE_BYTES
            or metadata_bytes > MAX_SIMULATED_RESERVE_BYTES
            or sum(item.size for item in pair[0].records) + payload_bytes > MAX_SIMULATED_RESERVE_SCAN_BYTES):
        raise SimulatedReserveError("observed S2 lacks bounded native publication capacity")
    charge = observed.preparation.charge
    config = charge.initialization.config
    controller = ResourceController.from_runtime_state(config, registry.policy.root, charge.runtime_state)
    total, free, error = controller._probe_disk()
    if (error is not None or total is None or free is None
            or controller.artifact_usage() + required >= config.maximum_artifact_bytes
            or free - required <= conservative_disk_reserve(
                total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)):
        raise SimulatedReserveError("observed S2 bookkeeping lacks disk or artifact capacity")


def _register_observed_second(registry, ledger, **request):
    from .holdout import HoldoutCustodyError
    from .orchestrator import OrchestrationError
    from .recovery import ConfirmatoryRerunError
    from .resources import ResourceLimitError

    try:
        return _register_observed_second_locked_sources(registry, ledger, **request)
    except SimulatedReserveError:
        raise
    except (ArtifactError, LedgerError, ValidationError, HoldoutCustodyError,
            OrchestrationError, ConfirmatoryRerunError, ResourceLimitError,
            OSError, ValueError, TypeError, KeyError) as exc:
        # A native failure may follow a durable record write. Preserve that
        # exact allocation orphan; refusal is not a promise of zero disk writes.
        raise SimulatedReserveError("observed second reserve publication refused") from exc


def _register_observed_second_locked_sources(
    registry, ledger, *, expected_run_id, protocol_artifact_sha256,
    contract_artifact_sha256, population_artifact_sha256, window_index,
    prior_reservation_artifact_sha256, initialization_artifact_sha256,
    prior_observation_artifact_sha256,
):
    """Consume membership in the retained append-only registry only.

    This S record adds no rollback-resistant resource debit or attempt marker.
    Q2/T2 must supply those protections before any second observation is allowed.
    """
    from . import simulated_observation as observation
    from . import simulated_resource as accounting

    accounting._paths(registry, ledger, expected_run_id)
    if type(window_index) is not int or window_index != 2:
        raise SimulatedReserveError("observed allocation supports only exact window two")
    selectors = dict(run_id=expected_run_id, protocol_sha=protocol_artifact_sha256,
        contract_sha=contract_artifact_sha256, population_sha=population_artifact_sha256,
        initialization_sha=initialization_artifact_sha256,
        prior_reservation_sha=prior_reservation_artifact_sha256,
        prior_observation_sha=prior_observation_artifact_sha256)
    for key, digest in selectors.items():
        if key != "run_id":
            _sha(digest)
    before = _context(registry, ledger, expected_run_id)
    _observed_second_pair(ledger, before)
    candidates = tuple(record for record in before[0].records
                       if record.schema_version == OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA)
    if len(candidates) > 1:
        raise SimulatedReserveError("observed second window is irreversibly ambiguous")
    existing = candidates[0] if candidates else None
    old = _json(registry, existing) if existing else None
    source = _source_pair(before, old) if existing else before
    sources, revision, observed = _observed_second_sources(registry, ledger, source, **selectors)
    value, record, event = _observed_second_plan(
        registry, ledger, source, sources, revision, observed,
        old.get("recorded_at") if existing else utc_now())
    if existing and (existing != record or canonical_json_bytes(old) != canonical_json_bytes(value)):
        raise SimulatedReserveError("occupied S2 cannot be reassigned or reinterpreted")
    complete = observation._append_pair(source, record, event)
    if existing and observation._same_pair(before, complete):
        result = _require_observed_second_at_snapshot(
            registry, ledger, before, expected_run_id, record.sha256)[0]
        if _context(registry, ledger, expected_run_id) != before:
            raise SimulatedReserveError("completed S2 changed during historical readback")
        return result
    if existing and not observation._same_pair(before, observation._append_pair(source, record)):
        raise SimulatedReserveError("S2 orphan can finish only on its exact original source pair")
    # S, not the native fact guard, owns the entire P2/S2 suffix above sealed J.
    # Current C2 follows from that exact complete source and its selected lineage.
    with observation._observed_amendment_admission_guard(
        registry, ledger, expected_run_id=expected_run_id,
        observation_artifact_sha256=observed.record.sha256,
        registry_snapshot=observed.registry_snapshot,
        ledger_snapshot=observed.ledger_snapshot, current_pair=before,
    ) as (held_observed, final_check):
        if held_observed.record != observed.record:
            raise SimulatedReserveError("held J differs from the full S2 source owner")
        from .recovery import RecoveryManager
        source_inventory, _config_inventory = observation._inventories(
            registry, observed.preparation.charge)
        RecoveryManager._validated_live_source_implementation(
            RecoveryManager(registry.policy.root), source_inventory,
            path="src/scientist_one/simulated_reserve.py", label="observed second reserve owner")
        replayed = _observed_second_sources(registry, ledger, source, **selectors)
        if _observed_second_plan(registry, ledger, source, *replayed, value["recorded_at"]) != (value, record, event):
            raise SimulatedReserveError("S2 source reconstruction changed under native custody")
        _observed_second_capacity(registry, observed, before, record, event, missing=existing is None)
        with observation._locks(registry, ledger) as (registry_guard, ledger_guard):
            _observed_second_capacity(registry, observed, before, record, event, missing=existing is None)
            final_check(before, registry_guard, ledger_guard)
            raw = ledger._read_raw_locked(ledger_guard)
            prospective = ledger._validate_bytes(raw + canonical_json_bytes(event.to_dict()) + b"\n")
            if not prospective.valid or prospective.events != (*before[1].events, event):
                raise SimulatedReserveError("S2 prospective event is not an exact native append")
            accounting._validate_resource_authority_ledger_for(
                observation._external(observed.preparation.charge, observed.attempt), prospective.events)
            if existing is None and _put_locked(registry, registry_guard, record, canonical_json_bytes(value) + b"\n") != record:
                raise SimulatedReserveError("S2 artifact publication differs from its plan")
            def build(snapshot):
                if snapshot != before[1]:
                    raise SimulatedReserveError("S2 publication ledger CAS failed")
                return event
            if ledger._append_locked(ledger_guard, build) != event:
                raise SimulatedReserveError("S2 event publication differs from its plan")
            after = (registry._verify_all_locked(registry_guard, raise_on_error=True),
                     ledger._validate_bytes(ledger._read_raw_locked(ledger_guard)))
            if not observation._same_pair(after, complete):
                raise SimulatedReserveError("S2 publication changed beyond its exact planned suffix")
            final_check(after, registry_guard, ledger_guard)
        # Full static readers own their own native registry locks. Keep the
        # outer native resource/custody guards, release only R/L for readback,
        # then reacquire R/L for an exact final CAS after the last source read.
        result = _require_observed_second_at_snapshot(
            registry, ledger, after, expected_run_id, record.sha256)[0]
        with observation._locks(registry, ledger) as (registry_guard, ledger_guard):
            final_check(after, registry_guard, ledger_guard)
        return result
