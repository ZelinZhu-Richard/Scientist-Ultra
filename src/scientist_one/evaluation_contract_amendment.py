"""Persisted, append-only Evaluation Contract amendment lineage.

This module records a changed contract without treating the change record as
confirmation, a fresh protected reserve, or scientific result authority.  It
uses the existing artifact registry and event ledger and deliberately relies
on the strict descriptor parsers in :mod:`scientist_one.scientific_design`.
The lineage replay is backward-only so a child contract never has to validate
itself recursively through the public contract owner.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields
from datetime import datetime
import hashlib
import os
from pathlib import Path
import re
from typing import Any, Mapping

from .artifacts import (
    MAX_ARTIFACT_PARENTS,
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
    RegistryValidationResult,
)
from .dataset_statistical_use import (
    DATASET_BOUNDED_MEAN_AUTHORITY_SCHEMA_VERSION,
    DATASET_STATISTICAL_USE_AUTHORITY_LOGICAL_TYPE,
)
from .errors import (
    ArtifactError,
    LedgerError,
    PathSecurityError,
    UnsafeSerializationError,
    ValidationError,
)
from .experiments import (
    ExperimentError,
    _scientific_statistical_use_context,
    resolve_scientific_method_definition_binding,
)
from .ledger import (
    MAX_LEDGER_BYTES,
    MAX_LEDGER_EVENTS,
    EventLedger,
    LedgerEvent,
    LedgerValidationResult,
)
from .models import utc_now, validate_identifier, validate_sha256
from .roles import Role
from .scientific_design import (
    MAX_CHECKED_SUPERIORITY_BYTES,
    EvaluationContract,
    EvaluationContractAmendment,
    HypothesisRole,
    HypothesisStatus,
    HypothesisTiming,
    ScientificDesignError,
    ScientificPromotionError,
    _CONTRACT_AMENDABLE_FIELDS,
    _event_metadata_value,
    _evaluation_contract_artifact_schema,
    _evaluation_contract_schema,
    _evaluation_contract_value,
    _load_checked_superiority_artifact,
    _locked_checked_result_authority_snapshot,
    _parse_checked_frozen_run_spec,
    _require_exact_timeline_event,
    _require_frozen_experiment_plans,
    _require_frozen_evaluation_contract_descriptor,
    _require_temporal_manifest,
    _require_temporal_contract_descriptor,
    _resolve_registered_scientific_visibility,
    _timeline_binding,
    _timeline_state,
    _validate_temporal_spec_binding,
)
from .security import canonical_json_bytes, safe_json_loads, sha256_bytes


EVALUATION_CONTRACT_AMENDMENT_SCHEMA = "evaluation-contract-amendment/v1"
EVALUATION_CONTRACT_AMENDMENT_ARTIFACT_SCHEMA = "eval-contract-amendment/v1"
EVALUATION_CONTRACT_OBSERVED_AMENDMENT_SCHEMA = "evaluation-contract-amendment/v2"
EVALUATION_CONTRACT_OBSERVED_AMENDMENT_ARTIFACT_SCHEMA = "eval-contract-amendment/v2"
EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE = "evaluation_contract_amendment"
EVALUATION_CONTRACT_AMENDMENT_SCOPE = "APPEND_ONLY_CONTRACT_CHANGE_RECORD_ONLY"
EVALUATION_CONTRACT_AMENDMENT_EVENT_KEY = "evaluation_contract_amendment"

_AMENDMENT_ORIGIN = "append-only evaluation contract amendment authority"
_AMENDMENT_COMMAND = ("scientist-one", "record-evaluation-contract-amendment")
_CONTRACT_ORIGIN = "canonical frozen evaluation contract authority"
_CONTRACT_COMMAND = ("scientist-one", "freeze-evaluation-contract")
_EVENT_REASON = "recorded an append-only evaluation contract change without confirmation authority"
_MAX_AMENDMENT_BYTES = MAX_CHECKED_SUPERIORITY_BYTES
_MAX_AMENDMENT_JSON_ITEMS = 80_000
_MAX_CONTRACT_BYTES = MAX_CHECKED_SUPERIORITY_BYTES
_MAX_CONTRACT_JSON_ITEMS = 50_000
_MAX_CONTRACT_ID_HINT_BYTES = _MAX_CONTRACT_BYTES
_MAX_LINEAGE_DEPTH = 64
_OBSERVATION_OMITTED = object()


class EvaluationContractAmendmentError(ScientificPromotionError):
    """The persisted amendment lineage is absent, stale, or ambiguous."""


# Negative selectors, never observation authority. Preparation, S/Q, their
# shared profile/origin/command and legacy execution kinds are NOT selectors.
_SIMULATED_ATTEMPT_MARKERS = frozenset({
    "sim-reserve-attempt/v1", "sim-reserve-attempt-event/v1",
    "sim-reserve-started/v1", "sim-reserve-observation/v1",
    "sim-reserve-observation-event/v1", "simulated_reserve_attempt",
    "simulated_reserve_started", "simulated_reserve_observation",
    "SIMULATED_RESERVE_ATTEMPT_CONSUMPTION", "SIMULATED_RESERVE_OBSERVATION",
})
_SIMULATED_ATTEMPT_FAMILY = "resource_runtime_simulated_attempt."
_SIMULATED_ATTEMPT_EVENT_PREFIXES = (
    "sim-reserve-attempt-", "sim-reserve-started-", "sim-reserve-observation-",
)
_SIMULATED_RUN_PATTERN = re.compile(r"sim-reserve-[0-9a-f]{48}\Z")


def _simulated_attempt_markers(value):
    from .simulated_reserve import _markers

    keys, _references, schemas, types = _markers(value)
    return bool((keys | schemas | types) & _SIMULATED_ATTEMPT_MARKERS) or any(
        item.startswith(_SIMULATED_ATTEMPT_FAMILY) for item in types
    )


def reject_simulated_reserve_attempt_exposure(
    registry, records, events, *, complete_registry_population,
):
    """Refuse possible T/STARTED/J in only the selected historical sources.

    A complete population includes record-only progress. Unsealed legacy
    history inspects only its event prefix and referenced records. This is the
    existing bounded per-payload selector policy, not a new aggregate/data-size
    restriction or proof of absence in arbitrary large unrelated data files.
    No live owner, external tail, fixture or mutation lock is consulted.
    """
    from .simulated_reserve import (
        MAX_SIMULATED_RESERVE_BYTES, SimulatedReserveError,
        _markers, _selected_json_hint,
    )

    if (
        type(registry) is not ArtifactRegistry or type(records) is not tuple
        or type(events) is not tuple or type(complete_registry_population) is not bool
        or any(type(record) is not ArtifactRecord for record in records)
        or any(type(event) is not LedgerEvent for event in events)
    ):
        raise EvaluationContractAmendmentError("attempt exposure needs exact snapshot inputs")
    _registry_record_map(records)
    by_identity = {key: record for record in records for key in (record.sha256, record.record_hash)}
    selected = set(records) if complete_registry_population else set()
    try:
        for event in events:
            if event.event_id.startswith(_SIMULATED_ATTEMPT_EVENT_PREFIXES) or _simulated_attempt_markers(event.metadata):
                raise EvaluationContractAmendmentError("simulated attempt or observation requires explicit versioned amendment authority")
            refs = set(event.artifact_hashes) | _markers(event.metadata)[1]
            selected.update(by_identity[key] for key in refs if key in by_identity)
        for record in selected:
            if (
                record.logical_type == "simulated_reserve_observation"
                or record.logical_type.startswith(_SIMULATED_ATTEMPT_FAMILY)
                or record.schema_version in _SIMULATED_ATTEMPT_MARKERS
                or (
                    record.size <= MAX_SIMULATED_RESERVE_BYTES
                    and _simulated_attempt_markers(_selected_json_hint(
                        registry, records, record,
                        malformed_markers=_SIMULATED_ATTEMPT_MARKERS,
                    ))
                )
            ):
                raise EvaluationContractAmendmentError("simulated attempt or observation requires explicit versioned amendment authority")
    except SimulatedReserveError as exc:
        raise EvaluationContractAmendmentError("simulated attempt exposure selector is unresolved") from exc


def _simulated_current_namespace(registry, ledger, run_id):
    """Reserve native namespace syntax without loading calibration content."""
    names = {run_id} if type(run_id) is str and _SIMULATED_RUN_PATTERN.fullmatch(run_id) else set()
    for path in (registry.base_path, ledger.relative_path):
        if type(path) is type(Path()) and len(path.parts) >= 2 and path.parts[0] == "runs" and _SIMULATED_RUN_PATTERN.fullmatch(path.parts[1]):
            names.add(path.parts[1])
    if not names:
        return None
    if len(names) != 1:
        raise EvaluationContractAmendmentError("simulated amendment namespace identities conflict")
    selected = next(iter(names))
    if (
        type(run_id) is not str or run_id != selected
        or type(registry.base_path) is not type(Path())
        or type(ledger.relative_path) is not type(Path())
        or registry.base_path != Path("runs") / selected / "registry"
        or ledger.relative_path != Path("runs") / selected / "events.jsonl"
    ):
        raise EvaluationContractAmendmentError("simulated amendment requires its exact run/registry/ledger namespace")
    return selected


def _pre_attempt_external_chain(registry, run_id, pair):
    """Negative-only native I/Q closure; never decode wrapped stages as runtime."""
    from .orchestrator import (
        _read_resource_authority_records, _validate_resource_authority_ledger_for,
    )
    from .security import open_confined_directory_fd
    from .seed_reporting import _selected_payload_bytes
    from .simulated_reserve import MAX_SIMULATED_RESERVE_BYTES, _markers, _selected_json_hint
    from .simulated_resource import _charge_schema_selected

    resource_records = tuple(record for record in pair[0].records if record.logical_type.startswith("resource_runtime_"))
    local_commitment = bool(resource_records)
    original_charge_schemas = frozenset({"sim-resource-charge/v1", "sim-resource-charge-event/v1"})
    commitment_markers = frozenset({
        "sim-resource-initial/v1", "sim-resource-initial-event/v1",
        "sim-resource-charge/v1", "sim-resource-charge-event/v1",
        "sim-resource-charge/v2", "sim-resource-charge-event/v2",
        "simulated_resource_initialization", "simulated_confirmatory_charge",
        "resource_authority_checkpoint", "resource_authority_chain",
    })
    for event in pair[1].events:
        keys, _refs, schemas, types = _markers(event.metadata)
        if any(_charge_schema_selected(item) and item not in original_charge_schemas for item in schemas):
            raise EvaluationContractAmendmentError("unsupported simulated charge schema forbids unseen amendment")
        local_commitment |= bool((keys | schemas | types) & commitment_markers) or any(
            _charge_schema_selected(item) for item in schemas)
    for record in pair[0].records:
        if _charge_schema_selected(record.schema_version) and record.schema_version not in original_charge_schemas:
            raise EvaluationContractAmendmentError("unsupported simulated charge schema forbids unseen amendment")
        local_commitment |= record.schema_version in commitment_markers or _charge_schema_selected(record.schema_version)
        if record.size <= MAX_SIMULATED_RESERVE_BYTES:
            keys, _refs, schemas, types = _markers(_selected_json_hint(
                registry, pair[0].records, record, malformed_markers=commitment_markers,
            ))
            if any(_charge_schema_selected(item) and item not in original_charge_schemas for item in schemas):
                raise EvaluationContractAmendmentError("unsupported simulated charge schema forbids unseen amendment")
            local_commitment |= bool((keys | schemas | types) & commitment_markers) or any(
                _charge_schema_selected(item) for item in schemas)
    relative = Path(".scientist-one-build/resource-authority") / run_id
    try:
        descriptor = open_confined_directory_fd(registry.policy.root, relative, create=False)
    except PathSecurityError as exc:
        # The confined traversal preserves the precise ENOENT in its context.
        # Links, wrong-kind, permissions and native-reader failures never mean
        # an empty authority. Post-I/Q absent storage is never accepted.
        if type(exc.__context__) is FileNotFoundError and not local_commitment:
            return ()
        raise EvaluationContractAmendmentError("simulated external authority is absent or unsafe") from exc
    else:
        os.close(descriptor)
    chain = _read_resource_authority_records(registry.policy.root, run_id)
    if len(chain) > 2:
        raise EvaluationContractAmendmentError("simulated external attempt or unsupported successor forbids unseen amendment")
    for index, entry in enumerate(chain):
        expected_schema = "sim-resource-initial/v1" if index == 0 else "sim-resource-charge/v1"
        expected_family = (entry["logical_type"] == "resource_runtime_initial" if index == 0
                           else entry["logical_type"].startswith("resource_runtime_confirmatory_charge."))
        if not expected_family or entry["state"].get("schema_version") != expected_schema:
            raise EvaluationContractAmendmentError("simulated external authority has unsupported pre-attempt stages")
        record = next((item for item in resource_records if item.sha256 == entry["state_sha256"]), None)
        if record is None or record.logical_type != entry["logical_type"] or _selected_payload_bytes(registry, pair[0].records, record) != canonical_json_bytes(entry["state"]) + b"\n":
            raise EvaluationContractAmendmentError("simulated external authority is not locally bound")
    if {entry["state_sha256"] for entry in chain} != {record.sha256 for record in resource_records} or (local_commitment and not chain):
        raise EvaluationContractAmendmentError("simulated resource commitment is incomplete or ambiguous")
    _validate_resource_authority_ledger_for(chain, pair[1].events)
    return chain


@contextmanager
def _current_simulated_amendment_guard(registry, ledger, run_id, pair):
    selected = _simulated_current_namespace(registry, ledger, run_id)
    if selected is None:
        yield None
        return
    from .orchestrator import (
        OrchestrationError, _named_directory_identity, _project_resource_execution_lock,
    )
    from .simulated_reserve import SimulatedReserveError

    try:
        with _project_resource_execution_lock(
            registry.policy.root,
            expected_root_identity=_named_directory_identity(registry.policy.root),
            nonblocking=True,
        ):
            yield selected, _pre_attempt_external_chain(registry, selected, pair)
    except (OrchestrationError, PathSecurityError, SimulatedReserveError) as exc:
        raise EvaluationContractAmendmentError("simulated amendment current resource boundary refused") from exc


def _recheck_simulated_amendment_external(registry, pair, current_guard):
    if current_guard is not None:
        run_id, original = current_guard
        if _pre_attempt_external_chain(registry, run_id, pair) != original:
            raise EvaluationContractAmendmentError("simulated external authority changed before amendment publication")


def _exact_dict(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise EvaluationContractAmendmentError(
            f"{label} is incomplete or contains unknown fields"
        )
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str:
        raise EvaluationContractAmendmentError(f"{label} must be native text")
    try:
        return validate_identifier(value, label)
    except ValidationError as exc:
        raise EvaluationContractAmendmentError(f"invalid {label}") from exc


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str:
        raise EvaluationContractAmendmentError(f"{label} must be native text")
    try:
        return validate_sha256(value, label)
    except ValidationError as exc:
        raise EvaluationContractAmendmentError(f"invalid {label}") from exc


def _bounded_text(value: Any, label: str, *, maximum: int = 8192) -> str:
    if type(value) is not str or not value.strip() or len(value) > maximum:
        raise EvaluationContractAmendmentError(
            f"{label} must be non-empty bounded native text"
        )
    return value


def _utc(value: Any, label: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise EvaluationContractAmendmentError(f"{label} must be UTC")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvaluationContractAmendmentError(f"{label} is malformed") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise EvaluationContractAmendmentError(f"{label} must be UTC")
    return parsed


def _record_hash(record: ArtifactRecord) -> str:
    if record.record_hash is None:  # pragma: no cover - ArtifactRecord guarantees it
        raise EvaluationContractAmendmentError("artifact metadata hash is absent")
    return record.record_hash


@dataclass(frozen=True, slots=True)
class EvaluationContractVisibleResult:
    """One fully replayed result-visibility checkpoint relevant to a family."""

    contract_artifact_sha256: str
    contract_record_hash: str
    frozen_run_spec_artifact_sha256: str
    frozen_run_spec_record_hash: str
    input_artifact_sha256s: tuple[str, str, str, str]
    input_artifact_record_hashes: tuple[str, str, str, str]
    output_manifest_artifact_sha256: str
    output_manifest_record_hash: str
    experiment_id: str
    hypothesis_id: str
    design_event_id: str
    design_event_hash: str
    design_event_index: int
    result_event_id: str
    result_event_hash: str
    result_event_index: int
    correction_event_ids: tuple[str, ...] = ()
    correction_event_hashes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "contract_artifact_sha256",
            "contract_record_hash",
            "frozen_run_spec_artifact_sha256",
            "frozen_run_spec_record_hash",
            "output_manifest_artifact_sha256",
            "output_manifest_record_hash",
            "design_event_hash",
            "result_event_hash",
        ):
            _sha256(getattr(self, name), name)
        for name in (
            "experiment_id",
            "hypothesis_id",
            "design_event_id",
            "result_event_id",
        ):
            _identifier(getattr(self, name), name)
        if (
            type(self.input_artifact_sha256s) is not tuple
            or len(self.input_artifact_sha256s) != 4
            or type(self.input_artifact_record_hashes) is not tuple
            or len(self.input_artifact_record_hashes) != 4
        ):
            raise EvaluationContractAmendmentError(
                "visible result must bind exactly four input identities"
            )
        for digest in self.input_artifact_sha256s:
            _sha256(digest, "visible input artifact SHA-256")
        for digest in self.input_artifact_record_hashes:
            _sha256(digest, "visible input artifact record hash")
        for name in ("design_event_index", "result_event_index"):
            value = getattr(self, name)
            if type(value) is not int or value < 0 or value >= MAX_LEDGER_EVENTS:
                raise EvaluationContractAmendmentError(
                    f"{name} must be a bounded non-negative integer"
                )
        if self.design_event_index >= self.result_event_index:
            raise EvaluationContractAmendmentError(
                "visible result must follow its design checkpoint"
            )
        if (
            type(self.correction_event_ids) is not tuple
            or type(self.correction_event_hashes) is not tuple
            or len(self.correction_event_ids) != len(self.correction_event_hashes)
        ):
            raise EvaluationContractAmendmentError(
                "visible result correction identities are malformed"
            )
        for value in self.correction_event_ids:
            _identifier(value, "correction event ID")
        for value in self.correction_event_hashes:
            _sha256(value, "correction event hash")
        if len(set(self.correction_event_ids)) != len(self.correction_event_ids):
            raise EvaluationContractAmendmentError(
                "visible result correction identities are duplicated"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_artifact_sha256": self.contract_artifact_sha256,
            "contract_record_hash": self.contract_record_hash,
            "frozen_run_spec_artifact_sha256": self.frozen_run_spec_artifact_sha256,
            "frozen_run_spec_record_hash": self.frozen_run_spec_record_hash,
            "input_artifact_sha256s": list(self.input_artifact_sha256s),
            "input_artifact_record_hashes": list(self.input_artifact_record_hashes),
            "output_manifest_artifact_sha256": self.output_manifest_artifact_sha256,
            "output_manifest_record_hash": self.output_manifest_record_hash,
            "experiment_id": self.experiment_id,
            "hypothesis_id": self.hypothesis_id,
            "design_event_id": self.design_event_id,
            "design_event_hash": self.design_event_hash,
            "design_event_index": self.design_event_index,
            "result_event_id": self.result_event_id,
            "result_event_hash": self.result_event_hash,
            "result_event_index": self.result_event_index,
            "correction_event_ids": list(self.correction_event_ids),
            "correction_event_hashes": list(self.correction_event_hashes),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "EvaluationContractVisibleResult":
        fields_ = {
            "contract_artifact_sha256",
            "contract_record_hash",
            "frozen_run_spec_artifact_sha256",
            "frozen_run_spec_record_hash",
            "input_artifact_sha256s",
            "input_artifact_record_hashes",
            "output_manifest_artifact_sha256",
            "output_manifest_record_hash",
            "experiment_id",
            "hypothesis_id",
            "design_event_id",
            "design_event_hash",
            "design_event_index",
            "result_event_id",
            "result_event_hash",
            "result_event_index",
            "correction_event_ids",
            "correction_event_hashes",
        }
        current = _exact_dict(value, fields_, "visible result")
        try:
            return cls(
                **{
                    **current,
                    "input_artifact_sha256s": tuple(current["input_artifact_sha256s"]),
                    "input_artifact_record_hashes": tuple(
                        current["input_artifact_record_hashes"]
                    ),
                    "correction_event_ids": tuple(current["correction_event_ids"]),
                    "correction_event_hashes": tuple(
                        current["correction_event_hashes"]
                    ),
                }
            )
        except (TypeError, ValueError) as exc:
            raise EvaluationContractAmendmentError(
                "visible result is malformed"
            ) from exc


def _amendment_value(value: Any) -> EvaluationContractAmendment:
    keys = {field.name for field in fields(EvaluationContractAmendment)}
    current = _exact_dict(value, keys, "contract amendment")
    try:
        return EvaluationContractAmendment(
            **{
                **current,
                "affected_experiment_ids": tuple(current["affected_experiment_ids"]),
                "changed_fields": tuple(current["changed_fields"]),
            }
        )
    except (ScientificDesignError, TypeError, ValueError) as exc:
        raise EvaluationContractAmendmentError(
            "contract amendment is malformed"
        ) from exc


@dataclass(frozen=True, slots=True)
class EvaluationContractObservedControl:
    """Exact locator descriptor; trust requires complete sealed J replay.

    An observed architecture control is never a scientific result manifest.
    Recording exposure does not grant confirmation or independent authority.
    """

    observation_artifact_sha256: str
    observation_record_hash: str
    observation_event_id: str
    observation_event_hash: str
    observation_event_index: int
    observed_at: str
    observation_schema_version: str = "sim-reserve-observation/v1"
    evidence_class: str = "NON_EVIDENTIARY"
    independence: str = "NON_INDEPENDENT"
    scientific_authority: bool = False

    def __post_init__(self):
        for name in ("observation_artifact_sha256", "observation_record_hash", "observation_event_hash"):
            _sha256(getattr(self, name), name)
        _identifier(self.observation_event_id, "observation event ID")
        _utc(self.observed_at, "observed-control timestamp")
        if (type(self.observation_event_index) is not int
                or not 0 <= self.observation_event_index < MAX_LEDGER_EVENTS
                or type(self.observation_schema_version) is not str
                or self.observation_schema_version != "sim-reserve-observation/v1"
                or type(self.evidence_class) is not str
                or self.evidence_class != "NON_EVIDENTIARY"
                or type(self.independence) is not str
                or self.independence != "NON_INDEPENDENT"
                or self.scientific_authority is not False):
            raise EvaluationContractAmendmentError("unsupported observed-control descriptor")

    def to_dict(self):
        return {field.name: getattr(self, field.name) for field in fields(self)}

    @classmethod
    def from_dict(cls, value):
        current = _exact_dict(value, {field.name for field in fields(cls)}, "observed control")
        return cls(**current)


def _observation_request(value):
    if value is _OBSERVATION_OMITTED:
        return None
    if type(value) is not tuple or len(value) != 1:
        raise EvaluationContractAmendmentError("observed amendment requires exactly one explicit observation SHA-256")
    _sha256(value[0], "observed amendment selector")
    return value


def _amendment_artifact_schema(authority):
    return (EVALUATION_CONTRACT_OBSERVED_AMENDMENT_ARTIFACT_SCHEMA
            if authority.schema_version == EVALUATION_CONTRACT_OBSERVED_AMENDMENT_SCHEMA
            else EVALUATION_CONTRACT_AMENDMENT_ARTIFACT_SCHEMA)


@dataclass(frozen=True, slots=True)
class EvaluationContractAmendmentAuthority:
    schema_version: str
    scope: str
    ledger_run_id: str
    ledger_path: str
    amendment: EvaluationContractAmendment
    parent_contract_artifact_sha256: str
    parent_contract_record_hash: str
    child_contract_artifact_sha256: str
    child_contract_sha256: str
    child_contract_payload_schema: str
    child_contract_artifact_schema: str
    child_evidence_artifact_sha256s: tuple[str, ...]
    child_evidence_artifact_record_hashes: tuple[str, ...]
    lineage_root_contract_artifact_sha256: str
    lineage_root_contract_record_hash: str
    lineage_depth: int
    visible_results: tuple[EvaluationContractVisibleResult, ...]
    source_ledger_event_count: int
    source_ledger_head_hash: str | None
    source_registry_record_identities: tuple[tuple[str, str], ...]
    source_registry_record_count: int
    source_registry_record_map_fingerprint: str
    confirmation_authorized: bool = False
    observed_controls: tuple[EvaluationContractObservedControl, ...] = ()

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version not in (
            EVALUATION_CONTRACT_AMENDMENT_SCHEMA, EVALUATION_CONTRACT_OBSERVED_AMENDMENT_SCHEMA,
        ):
            raise EvaluationContractAmendmentError(
                "unsupported Evaluation Contract amendment schema"
            )
        if (type(self.observed_controls) is not tuple
                or not all(type(item) is EvaluationContractObservedControl for item in self.observed_controls)
                or len(self.observed_controls) != int(self.schema_version == EVALUATION_CONTRACT_OBSERVED_AMENDMENT_SCHEMA)
                or (self.observed_controls and self.visible_results)):
            raise EvaluationContractAmendmentError("amendment observation inventory differs from its exact wire version")
        if self.scope != EVALUATION_CONTRACT_AMENDMENT_SCOPE:
            raise EvaluationContractAmendmentError(
                "Evaluation Contract amendment scope is not change-record-only"
            )
        _identifier(self.ledger_run_id, "amendment ledger run ID")
        _bounded_text(self.ledger_path, "amendment ledger path", maximum=1024)
        if type(self.amendment) is not EvaluationContractAmendment:
            raise EvaluationContractAmendmentError(
                "amendment authority requires the exact amendment DTO"
            )
        for name in (
            "parent_contract_artifact_sha256",
            "parent_contract_record_hash",
            "child_contract_artifact_sha256",
            "child_contract_sha256",
            "lineage_root_contract_artifact_sha256",
            "lineage_root_contract_record_hash",
            "source_registry_record_map_fingerprint",
        ):
            _sha256(getattr(self, name), name)
        for name in (
            "child_contract_payload_schema",
            "child_contract_artifact_schema",
        ):
            _bounded_text(getattr(self, name), name, maximum=64)
        if (
            type(self.child_evidence_artifact_sha256s) is not tuple
            or type(self.child_evidence_artifact_record_hashes) is not tuple
            or len(self.child_evidence_artifact_sha256s)
            != len(self.child_evidence_artifact_record_hashes)
            or len(self.child_evidence_artifact_sha256s) > MAX_ARTIFACT_PARENTS - 1
        ):
            raise EvaluationContractAmendmentError(
                "child evidence identities exceed the exact parent bound"
            )
        if len(set(self.child_evidence_artifact_sha256s)) != len(
            self.child_evidence_artifact_sha256s
        ):
            raise EvaluationContractAmendmentError(
                "child evidence artifact identities are duplicated"
            )
        for value in self.child_evidence_artifact_sha256s:
            _sha256(value, "child evidence artifact SHA-256")
        for value in self.child_evidence_artifact_record_hashes:
            _sha256(value, "child evidence artifact record hash")
        if type(self.lineage_depth) is not int or not 1 <= self.lineage_depth <= _MAX_LINEAGE_DEPTH:
            raise EvaluationContractAmendmentError(
                "amendment lineage depth exceeds the supported bound"
            )
        if (
            type(self.visible_results) is not tuple
            or len(self.visible_results) > MAX_ARTIFACT_PARENTS - 1
            or not all(type(item) is EvaluationContractVisibleResult for item in self.visible_results)
        ):
            raise EvaluationContractAmendmentError(
                "amendment visible-result inventory is malformed or oversized"
            )
        manifests = tuple(
            item.output_manifest_artifact_sha256 for item in self.visible_results
        )
        if len(set(manifests)) != len(manifests):
            raise EvaluationContractAmendmentError(
                "amendment visible-result manifests are duplicated"
            )
        if type(self.source_ledger_event_count) is not int or not 0 <= self.source_ledger_event_count <= MAX_LEDGER_EVENTS:
            raise EvaluationContractAmendmentError(
                "amendment source ledger count is invalid"
            )
        if self.source_ledger_event_count == 0:
            if self.source_ledger_head_hash is not None:
                raise EvaluationContractAmendmentError(
                    "empty amendment source ledger has a head hash"
                )
        else:
            _sha256(self.source_ledger_head_hash, "amendment source ledger head")
        if (
            type(self.source_registry_record_identities) is not tuple
            or not 1
            <= len(self.source_registry_record_identities)
            <= MAX_REGISTRY_RECORDS
        ):
            raise EvaluationContractAmendmentError(
                "amendment source registry identity map is invalid"
            )
        for identity in self.source_registry_record_identities:
            if type(identity) is not tuple or len(identity) != 2:
                raise EvaluationContractAmendmentError(
                    "amendment source registry identity is malformed"
                )
            _sha256(identity[0], "source registry artifact SHA-256")
            _sha256(identity[1], "source registry artifact record hash")
        if self.source_registry_record_identities != tuple(
            sorted(self.source_registry_record_identities)
        ) or len({item[0] for item in self.source_registry_record_identities}) != len(
            self.source_registry_record_identities
        ):
            raise EvaluationContractAmendmentError(
                "amendment source registry identities are unordered or duplicated"
            )
        expected_fingerprint = sha256_bytes(
            canonical_json_bytes(
                [list(identity) for identity in self.source_registry_record_identities]
            )
        )
        if (
            type(self.source_registry_record_count) is not int
            or self.source_registry_record_count
            != len(self.source_registry_record_identities)
            or self.source_registry_record_map_fingerprint != expected_fingerprint
        ):
            raise EvaluationContractAmendmentError(
                "amendment source registry count or fingerprint is invalid"
            )
        if self.confirmation_authorized is not False:
            raise EvaluationContractAmendmentError(
                "an Evaluation Contract amendment cannot grant confirmation"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scope": self.scope,
            "ledger_run_id": self.ledger_run_id,
            "ledger_path": self.ledger_path,
            "amendment": {
                field.name: (
                    list(getattr(self.amendment, field.name))
                    if field.name in {"affected_experiment_ids", "changed_fields"}
                    else getattr(self.amendment, field.name)
                )
                for field in fields(EvaluationContractAmendment)
            },
            "parent_contract_artifact_sha256": self.parent_contract_artifact_sha256,
            "parent_contract_record_hash": self.parent_contract_record_hash,
            "child_contract_artifact_sha256": self.child_contract_artifact_sha256,
            "child_contract_sha256": self.child_contract_sha256,
            "child_contract_payload_schema": self.child_contract_payload_schema,
            "child_contract_artifact_schema": self.child_contract_artifact_schema,
            "child_evidence_artifact_sha256s": list(
                self.child_evidence_artifact_sha256s
            ),
            "child_evidence_artifact_record_hashes": list(
                self.child_evidence_artifact_record_hashes
            ),
            "lineage_root_contract_artifact_sha256": (
                self.lineage_root_contract_artifact_sha256
            ),
            "lineage_root_contract_record_hash": self.lineage_root_contract_record_hash,
            "lineage_depth": self.lineage_depth,
            "visible_results": [item.to_dict() for item in self.visible_results],
            "source_ledger_event_count": self.source_ledger_event_count,
            "source_ledger_head_hash": self.source_ledger_head_hash,
            "source_registry_record_identities": [
                list(identity) for identity in self.source_registry_record_identities
            ],
            "source_registry_record_count": self.source_registry_record_count,
            "source_registry_record_map_fingerprint": (
                self.source_registry_record_map_fingerprint
            ),
            "confirmation_authorized": self.confirmation_authorized,
            **({"observed_controls": [item.to_dict() for item in self.observed_controls]}
               if self.schema_version == EVALUATION_CONTRACT_OBSERVED_AMENDMENT_SCHEMA else {}),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "EvaluationContractAmendmentAuthority":
        keys = {field.name for field in fields(cls)}
        if type(value) is dict and value.get("schema_version") == EVALUATION_CONTRACT_AMENDMENT_SCHEMA:
            keys.remove("observed_controls")
        current = _exact_dict(value, keys, "Evaluation Contract amendment authority")
        try:
            return cls(
                **{
                    **current,
                    "amendment": _amendment_value(current["amendment"]),
                    "child_evidence_artifact_sha256s": tuple(
                        current["child_evidence_artifact_sha256s"]
                    ),
                    "child_evidence_artifact_record_hashes": tuple(
                        current["child_evidence_artifact_record_hashes"]
                    ),
                    "visible_results": tuple(
                        EvaluationContractVisibleResult.from_dict(item)
                        for item in current["visible_results"]
                    ),
                    "observed_controls": tuple(
                        EvaluationContractObservedControl.from_dict(item)
                        for item in current.get("observed_controls", ())
                    ),
                    "source_registry_record_identities": tuple(
                        tuple(identity)
                        for identity in current["source_registry_record_identities"]
                    ),
                }
            )
        except (TypeError, ValueError) as exc:
            raise EvaluationContractAmendmentError(
                "Evaluation Contract amendment authority is malformed"
            ) from exc

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict()) + b"\n"


@dataclass(frozen=True, slots=True)
class EvaluationContractAmendmentPublication:
    authority: EvaluationContractAmendmentAuthority
    amendment_record: ArtifactRecord
    contract_record: ArtifactRecord
    parent_contract_record: ArtifactRecord
    parent_contract: EvaluationContract
    child_contract: EvaluationContract
    event: LedgerEvent
    event_index: int
    lineage_contract_records: tuple[ArtifactRecord, ...]
    lineage_amendment_records: tuple[ArtifactRecord, ...]


@dataclass(frozen=True, slots=True)
class EvaluationContractFamilyAdmission:
    """Private freeze-hook result; it is not confirmation authority."""

    contract_record: ArtifactRecord
    contract: EvaluationContract
    lineage_contract_records: tuple[ArtifactRecord, ...]
    lineage_amendment_records: tuple[ArtifactRecord, ...]
    selected_amendment_artifact_sha256: str | None
    exact_input_artifact_sha256s: tuple[str, str, str, str]
    exact_input_artifact_record_hashes: tuple[str, str, str, str]
    visible_ancestor_manifest_artifact_sha256s: tuple[str, ...]
    requires_new_confirmatory_reserve: bool
    confirmation_authorized: bool
    registry_snapshot: RegistryValidationResult
    ledger_snapshot: LedgerValidationResult


@dataclass(frozen=True, slots=True)
class EvaluationContractLineageReplay:
    """Full immutable child-lineage replay for root-owned consumer hooks."""

    contract_record: ArtifactRecord
    contract: EvaluationContract
    lineage_contract_records: tuple[ArtifactRecord, ...]
    lineage_amendment_records: tuple[ArtifactRecord, ...]
    selected_amendment_artifact_sha256: str | None
    registry_snapshot: RegistryValidationResult
    ledger_snapshot: LedgerValidationResult | None


@dataclass(frozen=True, slots=True)
class _ContractLineage:
    contract_records: tuple[ArtifactRecord, ...]
    contracts: tuple[EvaluationContract, ...]
    publications: tuple[EvaluationContractAmendmentPublication, ...]


def _registry_record_map(
    records: tuple[ArtifactRecord, ...],
) -> tuple[tuple[str, str], ...]:
    """Return the bounded canonical native registry-population preimage."""

    if type(records) is not tuple or not all(
        type(record) is ArtifactRecord for record in records
    ):
        raise EvaluationContractAmendmentError(
            "registry record population must be an exact ArtifactRecord tuple"
        )
    if len(records) > MAX_REGISTRY_RECORDS:
        raise EvaluationContractAmendmentError(
            "registry record map exceeds the supported bound"
        )
    identities = tuple(
        (record.sha256, _record_hash(record))
        for record in sorted(records, key=lambda item: item.sha256)
    )
    if len({identity[0] for identity in identities}) != len(identities):
        raise EvaluationContractAmendmentError(
            "registry record map contains duplicated artifact identities"
        )
    return identities


def _registry_map_fingerprint(
    records: tuple[ArtifactRecord, ...],
) -> tuple[int, str]:
    identities = _registry_record_map(records)
    return len(identities), sha256_bytes(
        canonical_json_bytes([list(identity) for identity in identities])
    )


def _require_registry_record_map(
    records: tuple[ArtifactRecord, ...],
    *,
    source_record_map: tuple[tuple[str, str], ...],
    source_record_count: int,
    source_record_map_fingerprint: str,
) -> tuple[ArtifactRecord, ...]:
    """Resolve an exact sealed population from a later append-only snapshot."""

    if (
        type(source_record_map) is not tuple
        or not all(type(identity) is tuple and len(identity) == 2 for identity in source_record_map)
        or not 1 <= len(source_record_map) <= MAX_REGISTRY_RECORDS
    ):
        raise EvaluationContractAmendmentError(
            "sealed registry record map is malformed or empty"
        )
    for artifact_sha256, record_hash in source_record_map:
        _sha256(artifact_sha256, "sealed registry artifact SHA-256")
        _sha256(record_hash, "sealed registry artifact record hash")
    if source_record_map != tuple(sorted(source_record_map)) or len(
        {identity[0] for identity in source_record_map}
    ) != len(source_record_map):
        raise EvaluationContractAmendmentError(
            "sealed registry record map is unordered or duplicated"
        )
    expected_fingerprint = sha256_bytes(
        canonical_json_bytes([list(identity) for identity in source_record_map])
    )
    if (
        type(source_record_count) is not int
        or source_record_count != len(source_record_map)
        or source_record_map_fingerprint != expected_fingerprint
    ):
        raise EvaluationContractAmendmentError(
            "sealed registry record map count or fingerprint differs"
        )
    if type(records) is not tuple or not all(
        type(record) is ArtifactRecord for record in records
    ):
        raise EvaluationContractAmendmentError(
            "current registry population must be an exact ArtifactRecord tuple"
        )
    current = {record.sha256: record for record in records}
    sealed: list[ArtifactRecord] = []
    for artifact_sha256, record_hash in source_record_map:
        record = current.get(artifact_sha256)
        if record is None or _record_hash(record) != record_hash:
            raise EvaluationContractAmendmentError(
                "amendment sealed registry source is missing or changed"
            )
        sealed.append(record)
    resolved = tuple(sealed)
    sealed_hashes = {record.sha256 for record in resolved}
    if any(
        parent_sha256 not in sealed_hashes
        for record in resolved
        for parent_sha256 in record.parent_artifacts
    ):
        raise EvaluationContractAmendmentError(
            "sealed registry record map is not parent-closed"
        )
    return resolved


def _sealed_registry_records(
    snapshot: RegistryValidationResult,
    authority: EvaluationContractAmendmentAuthority,
) -> tuple[ArtifactRecord, ...]:
    return _require_registry_record_map(
        snapshot.records,
        source_record_map=authority.source_registry_record_identities,
        source_record_count=authority.source_registry_record_count,
        source_record_map_fingerprint=(
            authority.source_registry_record_map_fingerprint
        ),
    )


def _input_binding(
    registry: ArtifactRegistry,
    input_artifact_sha256s: tuple[str, str, str, str],
) -> tuple[tuple[str, str, str, str], tuple[str, str, str, str]]:
    if type(input_artifact_sha256s) is not tuple or len(input_artifact_sha256s) != 4:
        raise EvaluationContractAmendmentError(
            "contract family requires exactly four ordered input artifacts"
        )
    records: list[ArtifactRecord] = []
    for digest in input_artifact_sha256s:
        _sha256(digest, "contract family input artifact")
        try:
            record = registry.get_metadata(digest)
            registry.verify(digest, raise_on_error=True)
        except (ArtifactError, ValidationError) as exc:
            raise EvaluationContractAmendmentError(
                "contract family input artifact is absent or corrupt"
            ) from exc
        records.append(record)
    return input_artifact_sha256s, tuple(  # type: ignore[return-value]
        _record_hash(record) for record in records
    )


def _read_amendment_record(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
) -> EvaluationContractAmendmentAuthority:
    if (
        record.logical_type != EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE
        or record.schema_version not in (
            EVALUATION_CONTRACT_AMENDMENT_ARTIFACT_SCHEMA,
            EVALUATION_CONTRACT_OBSERVED_AMENDMENT_ARTIFACT_SCHEMA,
        )
        or record.mime_type != "application/json"
        or record.origin != _AMENDMENT_ORIGIN
        or record.creator_role is not Role.PROTOCOL_DESIGNER
        or record.creation_command != _AMENDMENT_COMMAND
        or record.validation_result != "PASS"
        or not record.frozen
        or not 0 < record.size <= _MAX_AMENDMENT_BYTES
    ):
        raise EvaluationContractAmendmentError(
            "Evaluation Contract amendment artifact metadata is not source-owned"
        )
    try:
        raw = registry.get_bytes(record.sha256)
        value = safe_json_loads(
            raw,
            max_bytes=_MAX_AMENDMENT_BYTES,
            max_items=_MAX_AMENDMENT_JSON_ITEMS,
        )
    except (ArtifactError, UnsafeSerializationError, ValidationError) as exc:
        raise EvaluationContractAmendmentError(
            "Evaluation Contract amendment artifact is unreadable"
        ) from exc
    authority = EvaluationContractAmendmentAuthority.from_dict(value)
    if raw != authority.canonical_bytes() or record.schema_version != _amendment_artifact_schema(authority):
        raise EvaluationContractAmendmentError(
            "Evaluation Contract amendment artifact is not canonical"
        )
    return authority


def _all_amendment_records(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
) -> tuple[tuple[ArtifactRecord, EvaluationContractAmendmentAuthority], ...]:
    return tuple(
        (record, _read_amendment_record(registry, record))
        for record in records
        if record.logical_type == EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE
    )


def _slot_matches(
    authority: EvaluationContractAmendmentAuthority,
    *,
    amendment_id: str,
    parent_contract_artifact_sha256: str,
    child_contract_artifact_sha256: str,
    contract_id: str,
    to_version: int,
) -> bool:
    amendment = authority.amendment
    return (
        amendment.amendment_id == amendment_id
        or authority.parent_contract_artifact_sha256
        == parent_contract_artifact_sha256
        or authority.child_contract_artifact_sha256
        == child_contract_artifact_sha256
        or (amendment.contract_id == contract_id and amendment.to_version == to_version)
    )


def _event_slot_matches(
    value: Mapping[str, Any],
    *,
    amendment_id: str,
    parent_contract_artifact_sha256: str,
    child_contract_artifact_sha256: str,
    amendment_artifact_sha256: str | None,
) -> bool:
    return (
        value.get("amendment_id") == amendment_id
        or value.get("parent_contract_artifact_sha256")
        == parent_contract_artifact_sha256
        or value.get("child_contract_artifact_sha256")
        == child_contract_artifact_sha256
        or (
            amendment_artifact_sha256 is not None
            and value.get("amendment_artifact_sha256")
            == amendment_artifact_sha256
        )
    )


def _amendment_event_binding(
    authority: EvaluationContractAmendmentAuthority,
    amendment_record: ArtifactRecord,
    child_record: ArtifactRecord,
) -> dict[str, Any]:
    return {
        "schema_version": authority.schema_version,
        "scope": EVALUATION_CONTRACT_AMENDMENT_SCOPE,
        "amendment_id": authority.amendment.amendment_id,
        "parent_contract_artifact_sha256": (
            authority.parent_contract_artifact_sha256
        ),
        "parent_contract_record_hash": authority.parent_contract_record_hash,
        "amendment_artifact_sha256": amendment_record.sha256,
        "amendment_artifact_record_hash": _record_hash(amendment_record),
        "child_contract_artifact_sha256": child_record.sha256,
        "child_contract_record_hash": _record_hash(child_record),
        "source_ledger_event_count": authority.source_ledger_event_count,
        "source_ledger_head_hash": authority.source_ledger_head_hash,
        "confirmation_authorized": False,
        **({"observed_controls": [item.to_dict() for item in authority.observed_controls]}
           if authority.schema_version == EVALUATION_CONTRACT_OBSERVED_AMENDMENT_SCHEMA else {}),
    }


def _event_id(authority: EvaluationContractAmendmentAuthority) -> str:
    slot = {
        "run_id": authority.ledger_run_id,
        "amendment_id": authority.amendment.amendment_id,
        "parent": authority.parent_contract_artifact_sha256,
        "child": authority.child_contract_artifact_sha256,
    }
    return "evt-contract-amendment-" + sha256_bytes(canonical_json_bytes(slot))[:24]


def _build_event(
    authority: EvaluationContractAmendmentAuthority,
    amendment_record: ArtifactRecord,
    child_record: ArtifactRecord,
    source_ledger: LedgerValidationResult,
) -> LedgerEvent:
    binding = _amendment_event_binding(authority, amendment_record, child_record)
    return LedgerEvent.create(
        run_id=authority.ledger_run_id,
        event_id=_event_id(authority),
        timestamp=authority.amendment.recorded_at,
        actor_role=Role.PROTOCOL_DESIGNER,
        state_before=_timeline_state(source_ledger.events),
        requested_state_after=_timeline_state(source_ledger.events),
        artifact_hashes=(amendment_record.sha256, child_record.sha256),
        code_version=f"sha256:{authority.parent_contract_artifact_sha256}",
        configuration_hash=authority.child_contract_sha256,
        dataset_identifiers=(),
        random_seeds=(),
        evaluator_outputs=(),
        reason=_EVENT_REASON,
        prior_event_hash=source_ledger.head_hash,
        event_type="CHECKPOINT",
        metadata={
            "artifact_types": [
                EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE,
                "evaluation_contract",
            ],
            "artifact_record_hashes": [
                _record_hash(amendment_record),
                _record_hash(child_record),
            ],
            EVALUATION_CONTRACT_AMENDMENT_EVENT_KEY: binding,
        },
    )


def _matching_events(
    events: tuple[LedgerEvent, ...],
    *,
    amendment_id: str,
    parent_contract_artifact_sha256: str,
    child_contract_artifact_sha256: str,
    amendment_artifact_sha256: str | None,
) -> tuple[tuple[int, LedgerEvent], ...]:
    matches: list[tuple[int, LedgerEvent]] = []
    related_hashes = {child_contract_artifact_sha256}
    if amendment_artifact_sha256 is not None:
        related_hashes.add(amendment_artifact_sha256)
    for index, event in enumerate(events):
        metadata = _event_metadata_value(event)
        raw = metadata.get(EVALUATION_CONTRACT_AMENDMENT_EVENT_KEY)
        references_related = bool(related_hashes.intersection(event.artifact_hashes))
        if raw is None:
            # Later design/result owners legitimately retain an amended contract
            # (and may include its A parent in a complete source closure).  Mere
            # artifact reference is therefore not a second publication attempt.
            continue
        if not isinstance(raw, Mapping):
            raise EvaluationContractAmendmentError(
                "Evaluation Contract amendment event binding is malformed"
            )
        if _event_slot_matches(
            raw,
            amendment_id=amendment_id,
            parent_contract_artifact_sha256=parent_contract_artifact_sha256,
            child_contract_artifact_sha256=child_contract_artifact_sha256,
            amendment_artifact_sha256=amendment_artifact_sha256,
        ) or references_related:
            matches.append((index, event))
    return tuple(matches)


def _require_uncorrected_amendment_event(
    events: tuple[LedgerEvent, ...],
    *,
    publication_event_id: str,
) -> None:
    superseded = {publication_event_id}
    for event in events:
        if event.event_type != "CORRECTION" or event.supersedes_event_id not in superseded:
            continue
        superseded.add(event.event_id)
        raise EvaluationContractAmendmentError(
            "Evaluation Contract amendment publication was corrected"
        )


@dataclass(frozen=True, slots=True)
class _NativeSpecProgress:
    """Acyclic structural replay of one native frozen run specification."""

    spec_record: ArtifactRecord
    spec: Any
    contract_record: ArtifactRecord
    projection: Any
    plan_records: tuple[ArtifactRecord, ...]
    input_artifact_sha256s: tuple[str, str, str, str]
    input_artifact_record_hashes: tuple[str, str, str, str]


@dataclass(frozen=True, slots=True)
class _NativeResultProgress:
    """Structurally complete native manifest progress, not scientific authority."""

    contract_record: ArtifactRecord
    spec_record: ArtifactRecord
    spec: Any
    projection: Any
    plan_records: tuple[ArtifactRecord, ...]
    manifest_record: ArtifactRecord
    output_records: tuple[ArtifactRecord, ...]
    input_artifact_sha256s: tuple[str, str, str, str]
    input_artifact_record_hashes: tuple[str, str, str, str]


def _require_source_record(
    registry: ArtifactRegistry,
    records_by_sha: Mapping[str, ArtifactRecord],
    record: ArtifactRecord,
    *,
    label: str,
) -> ArtifactRecord:
    """Require one live immutable record to be in the caller-owned source map."""

    if records_by_sha.get(record.sha256) != record:
        raise EvaluationContractAmendmentError(
            f"{label} is absent or changed in the source snapshot"
        )
    try:
        registry.verify(record.sha256, raise_on_error=True)
        current = registry.get_metadata(record.sha256)
    except (ArtifactError, ValidationError) as exc:
        raise EvaluationContractAmendmentError(
            f"{label} is absent or corrupt"
        ) from exc
    if current != record:
        raise EvaluationContractAmendmentError(
            f"{label} metadata changed after source selection"
        )
    return record


def _spec_candidate(
    registry: ArtifactRegistry,
    spec_record: ArtifactRecord,
    records_by_sha: Mapping[str, ArtifactRecord],
) -> _NativeSpecProgress:
    """Replay the native spec envelope without entering scientific admission.

    This validates the exact contract descriptor, ordered frozen plans, the
    two optional native middle bindings, and all four immutable inputs.  It
    deliberately does not invoke the full run-spec owner: that owner re-enters
    contract-amendment and statistical-use authority and would create a cycle
    while classifying pre-amendment result visibility.
    """

    try:
        checked_record, value = _load_checked_superiority_artifact(
            registry,
            spec_record.sha256,
            logical_type="frozen_run_spec",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        spec = _parse_checked_frozen_run_spec(value)
    except ScientificDesignError as exc:
        raise EvaluationContractAmendmentError(
            "cannot classify a malformed native frozen run spec"
        ) from exc
    if checked_record != spec_record or not spec_record.parent_artifacts:
        raise EvaluationContractAmendmentError(
            "native frozen run spec has no exact contract parent"
        )
    _require_source_record(
        registry,
        records_by_sha,
        spec_record,
        label="native frozen run spec",
    )
    contract_record = records_by_sha.get(spec_record.parent_artifacts[0])
    if contract_record is None or contract_record.logical_type != "evaluation_contract":
        raise EvaluationContractAmendmentError(
            "native frozen run spec contract parent is absent or substituted"
        )
    try:
        raw_contract_record, _wrapper, contract = (
            _require_frozen_evaluation_contract_descriptor(
                registry,
                contract_artifact_sha256=contract_record.sha256,
            )
        )
        temporal_contract_record, projection = _require_temporal_contract_descriptor(
            registry,
            contract_record.sha256,
            contract=contract,
        )
    except ScientificDesignError as exc:
        raise EvaluationContractAmendmentError(
            "native frozen run spec contract descriptor is malformed"
        ) from exc
    if raw_contract_record != contract_record or temporal_contract_record != contract_record:
        raise EvaluationContractAmendmentError(
            "native frozen run spec contract descriptor changed"
        )
    _require_source_record(
        registry,
        records_by_sha,
        contract_record,
        label="native frozen run spec contract",
    )

    plan_count = len(spec.seeds)
    minimum_parent_count = 1 + plan_count + 4
    if len(spec_record.parent_artifacts) < minimum_parent_count:
        raise EvaluationContractAmendmentError(
            "native frozen run spec omits ordered plan or input parents"
        )
    plan_hashes = spec_record.parent_artifacts[1 : 1 + plan_count]
    try:
        plans, plan_records = _require_frozen_experiment_plans(
            registry,
            contract_record=contract_record,
            projection=projection,
            plan_artifact_sha256s=plan_hashes,
        )
        _validate_temporal_spec_binding(projection, plans, spec)
    except ScientificDesignError as exc:
        raise EvaluationContractAmendmentError(
            "native frozen run spec plan binding is malformed"
        ) from exc
    for record in plan_records:
        _require_source_record(
            registry,
            records_by_sha,
            record,
            label="native frozen experiment plan",
        )

    middle_records: list[ArtifactRecord] = []
    try:
        method_binding = resolve_scientific_method_definition_binding(
            registry,
            spec=spec,
        )
        statistical_context = _scientific_statistical_use_context(registry, spec)
    except (ExperimentError, ArtifactError, ValidationError) as exc:
        raise EvaluationContractAmendmentError(
            "native frozen run spec optional source binding is malformed"
        ) from exc
    if method_binding is not None:
        method_record = records_by_sha.get(
            method_binding.method_definition_artifact_sha256
        )
        if (
            method_record is None
            or _record_hash(method_record)
            != method_binding.method_definition_record_hash
        ):
            raise EvaluationContractAmendmentError(
                "native frozen run spec Method source is absent or substituted"
            )
        middle_records.append(
            _require_source_record(
                registry,
                records_by_sha,
                method_record,
                label="native frozen run spec Method source",
            )
        )
    if statistical_context is not None:
        statistical_digest = statistical_context[2]
        statistical_record_hash = statistical_context[3]
        statistical_record = records_by_sha.get(statistical_digest)
        if statistical_record is None:
            raise EvaluationContractAmendmentError(
                "native frozen run spec statistical-use source is absent"
            )
        try:
            checked_statistical_record, _value = _load_checked_superiority_artifact(
                registry,
                statistical_digest,
                logical_type=DATASET_STATISTICAL_USE_AUTHORITY_LOGICAL_TYPE,
                creator_role=Role.CLAIM_VERIFIER,
                schema_version=DATASET_BOUNDED_MEAN_AUTHORITY_SCHEMA_VERSION,
            )
        except ScientificDesignError as exc:
            raise EvaluationContractAmendmentError(
                "native frozen run spec statistical-use source is malformed"
            ) from exc
        if (
            checked_statistical_record != statistical_record
            or _record_hash(statistical_record) != statistical_record_hash
        ):
            raise EvaluationContractAmendmentError(
                "native frozen run spec statistical-use source is substituted"
            )
        middle_records.append(
            _require_source_record(
                registry,
                records_by_sha,
                statistical_record,
                label="native frozen run spec statistical-use source",
            )
        )

    input_hashes = (
        spec.code_sha256,
        spec.data_sha256,
        spec.configuration_sha256,
        spec.evaluator_sha256,
    )
    input_records: list[ArtifactRecord] = []
    for digest in input_hashes:
        record = records_by_sha.get(digest)
        if record is None:
            raise EvaluationContractAmendmentError(
                "native frozen run spec input is absent from the source snapshot"
            )
        input_records.append(
            _require_source_record(
                registry,
                records_by_sha,
                record,
                label="native frozen run spec input",
            )
        )
    expected_parents = (
        contract_record.sha256,
        *(record.sha256 for record in plan_records),
        *(record.sha256 for record in middle_records),
        *input_hashes,
    )
    if spec_record.parent_artifacts != expected_parents:
        raise EvaluationContractAmendmentError(
            "native frozen run spec has substituted or reordered source parents"
        )
    return _NativeSpecProgress(
        spec_record=spec_record,
        spec=spec,
        contract_record=contract_record,
        projection=projection,
        plan_records=plan_records,
        input_artifact_sha256s=input_hashes,
        input_artifact_record_hashes=tuple(
            _record_hash(record) for record in input_records
        ),  # type: ignore[arg-type]
    )


def _lineage_spec_candidates(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    *,
    lineage_contract_records: tuple[ArtifactRecord, ...],
) -> tuple[_NativeSpecProgress, ...]:
    by_sha = {record.sha256: record for record in records}
    lineage = {record.sha256 for record in lineage_contract_records}
    return tuple(
        _spec_candidate(registry, record, by_sha)
        for record in records
        if record.logical_type == "frozen_run_spec"
        and record.parent_artifacts[:1]
        and record.parent_artifacts[0] in lineage
    )


def _require_native_result_progress_descriptor(
    registry: ArtifactRegistry,
    *,
    manifest_record: ArtifactRecord,
    records_by_sha: Mapping[str, ArtifactRecord],
) -> _NativeResultProgress:
    """Replay one complete native manifest envelope before classifying it.

    The result proves structural progress and immutable custody only.  It does
    not establish execution success, statistical validity, confirmation, or
    scientific evidence eligibility.
    """

    if (
        manifest_record.logical_type != "experiment_output_manifest"
        or len(manifest_record.parent_artifacts) != 1
    ):
        raise EvaluationContractAmendmentError(
            "native result manifest has malformed provenance"
        )
    spec_record = records_by_sha.get(manifest_record.parent_artifacts[0])
    if spec_record is None or spec_record.logical_type != "frozen_run_spec":
        raise EvaluationContractAmendmentError(
            "native result manifest lacks its exact frozen run spec"
        )
    selected = _spec_candidate(registry, spec_record, records_by_sha)
    try:
        checked_manifest, _manifest, output_records = _require_temporal_manifest(
            registry,
            spec_record=selected.spec_record,
            spec=selected.spec,
            manifest_artifact_sha256=manifest_record.sha256,
        )
    except ScientificDesignError as exc:
        raise EvaluationContractAmendmentError(
            "native result manifest or output custody is malformed"
        ) from exc
    if checked_manifest != manifest_record:
        raise EvaluationContractAmendmentError(
            "native result manifest metadata changed after source selection"
        )
    _require_source_record(
        registry,
        records_by_sha,
        manifest_record,
        label="native result manifest",
    )
    for output_record in output_records:
        _require_source_record(
            registry,
            records_by_sha,
            output_record,
            label="native result output",
        )
    return _NativeResultProgress(
        contract_record=selected.contract_record,
        spec_record=selected.spec_record,
        spec=selected.spec,
        projection=selected.projection,
        plan_records=selected.plan_records,
        manifest_record=manifest_record,
        output_records=output_records,
        input_artifact_sha256s=selected.input_artifact_sha256s,
        input_artifact_record_hashes=selected.input_artifact_record_hashes,
    )


def _require_native_result_event_descriptor(
    registry: ArtifactRegistry,
    records_by_sha: Mapping[str, ArtifactRecord],
    events: tuple[LedgerEvent, ...],
    *,
    result_index: int,
    progress: _NativeResultProgress,
) -> None:
    """Require the native timeline bindings for one observed-result event."""

    event = events[result_index]
    claimed = _event_metadata_value(event).get("scientific_timeline")
    if not isinstance(claimed, Mapping):
        raise EvaluationContractAmendmentError(
            "result-visibility event lacks its native timeline binding"
        )
    design_event_id = claimed.get("design_freeze_event_id")
    design_candidates = tuple(
        (index, candidate)
        for index, candidate in enumerate(events)
        if candidate.event_id == design_event_id
    )
    if len(design_candidates) != 1:
        raise EvaluationContractAmendmentError(
            "result-visibility event lacks one exact design-freeze event"
        )
    design_index, design_event = design_candidates[0]
    design_artifacts = (
        progress.contract_record,
        *progress.plan_records,
        progress.spec_record,
    )
    design_binding = _timeline_binding(
        kind="DESIGN_FROZEN",
        contract_record=progress.contract_record,
        projection=progress.projection,
        plan_records=progress.plan_records,
        spec_record=progress.spec_record,
        spec=progress.spec,
        manifest_record=None,
        design_event=None,
    )
    result_artifacts = (progress.manifest_record, *progress.output_records)
    result_binding = _timeline_binding(
        kind="RESULT_OBSERVED",
        contract_record=progress.contract_record,
        projection=progress.projection,
        plan_records=progress.plan_records,
        spec_record=progress.spec_record,
        spec=progress.spec,
        manifest_record=progress.manifest_record,
        design_event=design_event,
    )
    try:
        design_source_records = _require_exact_timeline_event(
            design_event,
            event_type="CHECKPOINT",
            actor_role=Role.PROTOCOL_DESIGNER,
            artifact_records=design_artifacts,
            binding=design_binding,
            registry=registry,
            events=events,
        )
        _require_exact_timeline_event(
            event,
            event_type="CHECKPOINT",
            actor_role=Role.EXPERIMENT_RUNNER,
            artifact_records=result_artifacts,
            binding=result_binding,
        )
    except ScientificDesignError as exc:
        raise EvaluationContractAmendmentError(
            "result-visibility event has malformed native source bindings"
        ) from exc
    if design_source_records is not None and any(
        records_by_sha.get(record.sha256) != record
        for record in design_source_records
    ):
        raise EvaluationContractAmendmentError(
            "result-visibility design population escapes the source snapshot"
        )
    first_result_reference = min(
        (
            index
            for index, candidate in enumerate(events)
            if set(candidate.artifact_hashes).intersection(
                record.sha256 for record in result_artifacts
            )
        ),
        default=-1,
    )
    if design_index >= result_index or first_result_reference != result_index:
        raise EvaluationContractAmendmentError(
            "result-visibility event is not the first post-design source reference"
        )


def _correction_chain(
    events: tuple[LedgerEvent, ...],
    *,
    design_event_id: str,
    result_event_id: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    selected = {design_event_id, result_event_id}
    corrections: list[LedgerEvent] = []
    for event in events:
        if event.event_type == "CORRECTION" and event.supersedes_event_id in selected:
            selected.add(event.event_id)
            corrections.append(event)
    if any(event.event_hash is None for event in corrections):  # pragma: no cover
        raise EvaluationContractAmendmentError("correction event hash is absent")
    return (
        tuple(event.event_id for event in corrections),
        tuple(str(event.event_hash) for event in corrections),
    )


def _visible_result(
    registry: ArtifactRegistry,
    records_by_sha: Mapping[str, ArtifactRecord],
    events: tuple[LedgerEvent, ...],
    *,
    progress: _NativeResultProgress,
    result_index: int,
) -> EvaluationContractVisibleResult:
    spec_record = progress.spec_record
    spec = progress.spec
    contract_record = progress.contract_record
    manifest_record = progress.manifest_record
    try:
        resolved = _resolve_registered_scientific_visibility(
            registry,
            events[: result_index + 1],
            contract_record=contract_record,
            manifest_record=manifest_record,
        )
    except ScientificDesignError as exc:
        raise EvaluationContractAmendmentError(
            "related registered result fails full visibility replay"
        ) from exc
    corrections = _correction_chain(
        events,
        design_event_id=resolved.design_event.event_id,
        result_event_id=resolved.result_event.event_id,
    )
    return EvaluationContractVisibleResult(
        contract_artifact_sha256=contract_record.sha256,
        contract_record_hash=_record_hash(contract_record),
        frozen_run_spec_artifact_sha256=spec_record.sha256,
        frozen_run_spec_record_hash=_record_hash(spec_record),
        input_artifact_sha256s=progress.input_artifact_sha256s,
        input_artifact_record_hashes=progress.input_artifact_record_hashes,
        output_manifest_artifact_sha256=manifest_record.sha256,
        output_manifest_record_hash=_record_hash(manifest_record),
        experiment_id=spec.experiment_id,
        hypothesis_id=spec.hypothesis_id,
        design_event_id=resolved.design_event.event_id,
        design_event_hash=str(resolved.design_event.event_hash),
        design_event_index=resolved.design_event_index,
        result_event_id=resolved.result_event.event_id,
        result_event_hash=str(resolved.result_event.event_hash),
        result_event_index=resolved.result_event_index,
        correction_event_ids=corrections[0],
        correction_event_hashes=corrections[1],
    )


def _event_visible_results(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    events: tuple[LedgerEvent, ...],
    *,
    lineage_contract_records: tuple[ArtifactRecord, ...],
    related_input_bindings: frozenset[
        tuple[tuple[str, str, str, str], tuple[str, str, str, str]]
    ] = frozenset(),
    progress_by_manifest: dict[str, _NativeResultProgress] | None = None,
) -> tuple[EvaluationContractVisibleResult, ...]:
    by_sha = {record.sha256: record for record in records}
    lineage_hashes = {record.sha256 for record in lineage_contract_records}
    progress_cache = (
        {} if progress_by_manifest is None else progress_by_manifest
    )
    visible: list[EvaluationContractVisibleResult] = []
    seen_manifests: set[str] = set()
    for result_index, event in enumerate(events):
        timeline = _event_metadata_value(event).get("scientific_timeline")
        if not isinstance(timeline, Mapping) or timeline.get("kind") != "RESULT_OBSERVED":
            continue
        manifest_sha = timeline.get("output_manifest_artifact_sha256")
        spec_sha = timeline.get("frozen_run_spec_artifact_sha256")
        contract_sha = timeline.get("contract_artifact_sha256")
        if not all(type(item) is str for item in (manifest_sha, spec_sha, contract_sha)):
            raise EvaluationContractAmendmentError(
                "result-visibility event lacks classifiable source selectors"
            )
        manifest_record = by_sha.get(str(manifest_sha))
        spec_record = by_sha.get(str(spec_sha))
        contract_record = by_sha.get(str(contract_sha))
        if (
            manifest_record is None
            or spec_record is None
            or contract_record is None
            or manifest_record.logical_type != "experiment_output_manifest"
            or spec_record.logical_type != "frozen_run_spec"
            or contract_record.logical_type != "evaluation_contract"
        ):
            raise EvaluationContractAmendmentError(
                "result-visibility event source descriptors are absent"
            )
        progress = progress_cache.get(manifest_record.sha256)
        if progress is None:
            progress = _require_native_result_progress_descriptor(
                registry,
                manifest_record=manifest_record,
                records_by_sha=by_sha,
            )
            progress_cache[manifest_record.sha256] = progress
        if (
            progress.spec_record != spec_record
            or progress.contract_record != contract_record
        ):
            raise EvaluationContractAmendmentError(
                "result-visibility event substitutes its spec or contract descriptor"
            )
        _require_native_result_event_descriptor(
            registry,
            by_sha,
            events,
            result_index=result_index,
            progress=progress,
        )
        if manifest_record.sha256 in seen_manifests:
            raise EvaluationContractAmendmentError(
                "native manifest has multiple visibility events"
            )
        seen_manifests.add(manifest_record.sha256)
        related = contract_record.sha256 in lineage_hashes or (
            progress.input_artifact_sha256s,
            progress.input_artifact_record_hashes,
        ) in related_input_bindings
        if not related:
            continue
        visible.append(
            _visible_result(
                registry,
                by_sha,
                events,
                progress=progress,
                result_index=result_index,
            )
        )
    visible.sort(
        key=lambda item: (item.result_event_index, item.output_manifest_artifact_sha256)
    )
    if len(visible) > MAX_ARTIFACT_PARENTS - 1:
        raise EvaluationContractAmendmentError(
            "complete result visibility exceeds amendment parent capacity"
        )
    return tuple(visible)


def _derive_visible_results(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    events: tuple[LedgerEvent, ...],
    *,
    lineage_contract_records: tuple[ArtifactRecord, ...],
    explicit_input_binding: (
        tuple[tuple[str, str, str, str], tuple[str, str, str, str]] | None
    ) = None,
    complete_current_registry: bool,
) -> tuple[EvaluationContractVisibleResult, ...]:
    """Derive event visibility, optionally proving no current unlogged result.

    Historical replay consumes only the sealed event prefix and its exact
    descriptors.  Current admission additionally inventories related manifest
    records so an output registered before its event fails incomplete.  This
    avoids letting later unrelated/backdated records poison old history.
    """

    from .seed_reporting import (
        OperationalSeedReportingError,
        reject_operational_seed_exposure,
    )

    reject_simulated_reserve_attempt_exposure(
        registry, records, events,
        complete_registry_population=complete_current_registry,
    )

    # The closed operational profile is not read-isolated. It cannot supply a
    # manifest-shaped scientific visibility receipt, or prove other run-local
    # resources were unread. Use only this caller's historical population:
    # unsealed legacy D has a current registry but only a historical event
    # prefix, so registry-only descendants cannot become pre-D observations.
    try:
        reject_operational_seed_exposure(
            registry, records, events,
            complete_registry_population=complete_current_registry,
        )
    except OperationalSeedReportingError as exc:
        raise EvaluationContractAmendmentError(
            "operational reservation or possible exposure requires an unsupported scientific amendment"
        ) from exc

    anchor_bindings: set[
        tuple[tuple[str, str, str, str], tuple[str, str, str, str]]
    ] = set()
    if explicit_input_binding is not None:
        anchor_bindings.add(explicit_input_binding)
    if complete_current_registry:
        lineage_specs = _lineage_spec_candidates(
            registry,
            records,
            lineage_contract_records=lineage_contract_records,
        )
        anchor_bindings.update(
            (
                item.input_artifact_sha256s,
                item.input_artifact_record_hashes,
            )
            for item in lineage_specs
        )
    progress_by_manifest: dict[str, _NativeResultProgress] = {}
    visible = _event_visible_results(
        registry,
        records,
        events,
        lineage_contract_records=lineage_contract_records,
        related_input_bindings=frozenset(anchor_bindings),
        progress_by_manifest=progress_by_manifest,
    )
    if not complete_current_registry:
        return visible
    by_sha = {record.sha256: record for record in records}
    lineage_hashes = {record.sha256 for record in lineage_contract_records}
    visible_by_manifest = {
        item.output_manifest_artifact_sha256: item for item in visible
    }
    for manifest_record in records:
        if manifest_record.logical_type != "experiment_output_manifest":
            continue
        frozen_parents = tuple(
            by_sha[digest]
            for digest in manifest_record.parent_artifacts
            if digest in by_sha and by_sha[digest].logical_type == "frozen_run_spec"
        )
        if len(manifest_record.parent_artifacts) != 1:
            if frozen_parents:
                raise EvaluationContractAmendmentError(
                    "native result manifest has malformed provenance"
                )
            continue
        spec_record = by_sha.get(manifest_record.parent_artifacts[0])
        if spec_record is None or spec_record.logical_type != "frozen_run_spec":
            # Other subsystems may use the generic manifest logical type with
            # one namespaced, non-native run-spec parent.
            continue
        progress = progress_by_manifest.get(manifest_record.sha256)
        if progress is None:
            progress = _require_native_result_progress_descriptor(
                registry,
                manifest_record=manifest_record,
                records_by_sha=by_sha,
            )
            progress_by_manifest[manifest_record.sha256] = progress
        related = progress.contract_record.sha256 in lineage_hashes or (
            progress.input_artifact_sha256s,
            progress.input_artifact_record_hashes,
        ) in anchor_bindings
        if related and manifest_record.sha256 not in visible_by_manifest:
            raise EvaluationContractAmendmentError(
                "current related result manifest lacks one exact visibility event"
            )
    return visible


def _changed_fields(
    parent: EvaluationContract,
    child: EvaluationContract,
) -> tuple[str, ...]:
    return tuple(
        name
        for name in sorted(_CONTRACT_AMENDABLE_FIELDS)
        if getattr(parent, name) != getattr(child, name)
    )


def _derive_observed_controls(registry, ledger, *, run_id, selectors, pair, parent_lineage):
    """Own the one closed J1 source pair before deriving exposure flags."""
    from .simulated_observation import (
        SimulatedObservationError,
        _require_simulated_reserve_observation_at_snapshot,
    )

    if (type(selectors) is not tuple or len(selectors) != 1
            or len(parent_lineage.contract_records) != 1 or parent_lineage.publications):
        raise EvaluationContractAmendmentError("observed amendment supports only the original completed J1 parent")
    _sha256(selectors[0], "observed amendment selector")
    try:
        observed = _require_simulated_reserve_observation_at_snapshot(
            registry, ledger, expected_run_id=run_id,
            observation_artifact_sha256=selectors[0],
            registry_snapshot=pair[0], ledger_snapshot=pair[1],
        )
    except (SimulatedObservationError, ValueError, ArtifactError, LedgerError) as exc:
        raise EvaluationContractAmendmentError("observed amendment lacks one complete sealed native observation") from exc
    reservation = observed.preparation.charge.reservation
    if (reservation.contract_record != parent_lineage.contract_records[-1]
            or reservation.contract != parent_lineage.contracts[-1]):
        raise EvaluationContractAmendmentError("observed amendment names a different observed parent contract")
    descriptor = EvaluationContractObservedControl(
        observation_artifact_sha256=observed.record.sha256,
        observation_record_hash=_record_hash(observed.record),
        observation_event_id=observed.event.event_id,
        observation_event_hash=observed.event.event_hash,
        observation_event_index=observed.event_index,
        observed_at=observed.record.created_at,
    )
    return (descriptor,)


def _amendment_sources(registry, ledger, *, run_id, parent_lineage, pair, selectors):
    if selectors is None:
        return _derive_visible_results(
            registry, pair[0].records, pair[1].events,
            lineage_contract_records=parent_lineage.contract_records,
            complete_current_registry=True,
        ), ()
    # Full J ownership proves the complete pair is the supported closed profile.
    # Never filter observed artifacts out and feed a false-empty scientific view
    # to the v1 owner; that owner intentionally refuses possible native exposure.
    return (), _derive_observed_controls(
        registry, ledger, run_id=run_id, selectors=selectors, pair=pair,
        parent_lineage=parent_lineage,
    )


def _affected_experiments(
    parent: EvaluationContract,
    child: EvaluationContract,
    visible_results: tuple[EvaluationContractVisibleResult, ...],
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                *(item.planned_experiment for item in parent.hypothesis_register.hypotheses),
                *(item.planned_experiment for item in child.hypothesis_register.hypotheses),
                *(item.experiment_id for item in visible_results),
            }
        )
    )


def _require_post_observation_hypotheses(
    parent: EvaluationContract,
    child: EvaluationContract,
) -> None:
    parent_register = parent.hypothesis_register
    child_register = child.hypothesis_register
    parent_hypotheses = parent_register.hypotheses
    if (
        child_register.hypotheses[: len(parent_hypotheses)] != parent_hypotheses
        or child_register.promotion_history != parent_register.promotion_history
    ):
        raise EvaluationContractAmendmentError(
            "post-observation amendment cannot rewrite, remove, reorder, or promote an existing hypothesis"
        )
    new_hypotheses = child_register.hypotheses[len(parent_hypotheses) :]
    for hypothesis in new_hypotheses:
        if (
            hypothesis.role is not HypothesisRole.SECONDARY
            or hypothesis.timing is not HypothesisTiming.POST_HOC
            or hypothesis.formed_after_observation is not True
            or hypothesis.status is not HypothesisStatus.UNTESTED
            or hypothesis.result_evidence_ids
        ):
            raise EvaluationContractAmendmentError(
                "new post-observation hypotheses must be additive, SECONDARY, POST_HOC, and UNTESTED"
            )


def _validate_transition(
    parent: EvaluationContract,
    child: EvaluationContract,
    *,
    amendment_id: str,
    author_id: str,
    reason: str,
    recorded_at: str,
    visible_results: tuple[EvaluationContractVisibleResult, ...],
    observed_controls: tuple[EvaluationContractObservedControl, ...] = (),
) -> EvaluationContractAmendment:
    if type(parent) is not EvaluationContract or type(child) is not EvaluationContract:
        raise EvaluationContractAmendmentError(
            "amendment requires exact typed parent and child contracts"
        )
    _identifier(amendment_id, "amendment ID")
    _identifier(author_id, "amendment author ID")
    _bounded_text(reason, "amendment reason")
    if parent.contract_id != child.contract_id:
        raise EvaluationContractAmendmentError(
            "contract identity cannot be renamed through an amendment"
        )
    if child.version != parent.version + 1:
        raise EvaluationContractAmendmentError(
            "amended contract must advance exactly one numeric version"
        )
    if child.results_seen_at_freeze is not False:
        raise EvaluationContractAmendmentError(
            "child contract cannot claim that results were unseen through a true flag"
        )
    if child.frozen_by != author_id:
        raise EvaluationContractAmendmentError(
            "child contract frozen_by differs from the amendment author"
        )
    if _utc(child.frozen_at, "child declared freeze time") > _utc(
        recorded_at, "amendment publication time"
    ):
        raise EvaluationContractAmendmentError(
            "child declared freeze time is later than amendment publication"
        )
    changed = _changed_fields(parent, child)
    if not changed:
        raise EvaluationContractAmendmentError(
            "an amendment must record at least one changed contract field"
        )
    if (type(observed_controls) is not tuple
            or len(observed_controls) > 1
            or any(type(item) is not EvaluationContractObservedControl for item in observed_controls)
            or (observed_controls and visible_results)):
        raise EvaluationContractAmendmentError("transition mixes unsupported observation sources")
    results_seen = bool(visible_results or observed_controls)
    if results_seen:
        _require_post_observation_hypotheses(parent, child)
    if observed_controls and any(
        _utc(child.frozen_at, "child declared freeze time") < _utc(item.observed_at, "observed-control timestamp")
        for item in observed_controls
    ):
        raise EvaluationContractAmendmentError("observed amendment child freeze predates its completed observation")
    return EvaluationContractAmendment(
        amendment_id=amendment_id,
        parent_contract_sha256=parent.sha256,
        contract_id=parent.contract_id,
        from_version=parent.version,
        to_version=child.version,
        recorded_at=recorded_at,
        author_id=author_id,
        reason=reason,
        affected_experiment_ids=_affected_experiments(
            parent, child, visible_results
        ),
        changed_fields=changed,
        results_already_seen=results_seen,
        requires_new_confirmatory_reserve=results_seen,
    )


def _child_bytes(child: EvaluationContract) -> bytes:
    data = canonical_json_bytes(
        {
            "schema_version": _evaluation_contract_schema(child),
            "evaluation_contract": _evaluation_contract_value(child),
        }
    ) + b"\n"
    if not 0 < len(data) <= _MAX_CONTRACT_BYTES:
        raise EvaluationContractAmendmentError(
            "amended contract exceeds artifact byte capacity"
        )
    try:
        safe_json_loads(
            data,
            max_bytes=_MAX_CONTRACT_BYTES,
            max_items=_MAX_CONTRACT_JSON_ITEMS,
        )
    except (UnsafeSerializationError, ValidationError) as exc:
        raise EvaluationContractAmendmentError(
            "amended contract exceeds the frozen-contract parser capacity"
        ) from exc
    return data


def _planned_record(
    registry: ArtifactRegistry,
    data: bytes,
    *,
    logical_type: str,
    origin: str,
    creator_role: Role,
    command: tuple[str, ...],
    parents: tuple[str, ...],
    schema_version: str,
    created_at: str,
) -> ArtifactRecord:
    digest = hashlib.sha256(data).hexdigest()
    return ArtifactRecord(
        sha256=digest,
        path=registry._object_relative(digest).as_posix(),
        relative_path=registry._object_relative(digest).as_posix(),
        metadata_path=registry._metadata_relative(digest).as_posix(),
        logical_type=logical_type,
        schema_version=schema_version,
        mime_type="application/json",
        size=len(data),
        origin=origin,
        creator_role=creator_role,
        creation_command=command,
        parent_artifacts=parents,
        validation_result="PASS",
        frozen=True,
        created_at=created_at,
    )


def _source_ledger_prefix(
    ledger_snapshot: LedgerValidationResult,
    authority: EvaluationContractAmendmentAuthority,
) -> LedgerValidationResult:
    count = authority.source_ledger_event_count
    if len(ledger_snapshot.events) < count:
        raise EvaluationContractAmendmentError(
            "amendment source ledger prefix is missing"
        )
    events = ledger_snapshot.events[:count]
    head = events[-1].event_hash if events else None
    if head != authority.source_ledger_head_hash:
        raise EvaluationContractAmendmentError(
            "amendment source ledger prefix head differs"
        )
    prefix_bytes = sum(len(canonical_json_bytes(event.to_dict())) + 1 for event in events)
    return LedgerValidationResult(
        valid=True,
        events=events,
        head_hash=head,
        valid_prefix_bytes=prefix_bytes,
    )


def _record_is_exact(
    snapshot: RegistryValidationResult,
    planned: ArtifactRecord,
) -> ArtifactRecord | None:
    existing = next(
        (record for record in snapshot.records if record.sha256 == planned.sha256),
        None,
    )
    if existing is not None and existing != planned:
        raise EvaluationContractAmendmentError(
            "amendment publication bytes occupy another metadata identity"
        )
    return existing


def _source_chronology(
    records: tuple[ArtifactRecord, ...],
    events: tuple[LedgerEvent, ...],
    *,
    timestamp: str,
) -> None:
    boundary = _utc(timestamp, "amendment publication timestamp")
    if any(_utc(record.created_at, "amendment source record timestamp") > boundary for record in records):
        raise EvaluationContractAmendmentError(
            "amendment publication predates one of its exact sources"
        )
    if any(_utc(event.timestamp, "amendment source event timestamp") > boundary for event in events):
        raise EvaluationContractAmendmentError(
            "amendment publication predates its sealed ledger prefix"
        )


def _authority_for_sources(
    *,
    run_id: str,
    ledger: EventLedger,
    amendment: EvaluationContractAmendment,
    parent_record: ArtifactRecord,
    child: EvaluationContract,
    child_artifact_sha256: str,
    child_evidence_records: tuple[ArtifactRecord, ...],
    parent_lineage: _ContractLineage,
    visible_results: tuple[EvaluationContractVisibleResult, ...],
    source_ledger: LedgerValidationResult,
    source_registry_record_identities: tuple[tuple[str, str], ...],
    source_registry_record_count: int,
    source_registry_record_map_fingerprint: str,
    observed_controls: tuple[EvaluationContractObservedControl, ...] = (),
) -> EvaluationContractAmendmentAuthority:
    root_record = parent_lineage.contract_records[0]
    return EvaluationContractAmendmentAuthority(
        schema_version=(EVALUATION_CONTRACT_OBSERVED_AMENDMENT_SCHEMA if observed_controls
                        else EVALUATION_CONTRACT_AMENDMENT_SCHEMA),
        scope=EVALUATION_CONTRACT_AMENDMENT_SCOPE,
        ledger_run_id=run_id,
        ledger_path=ledger.relative_path.as_posix(),
        amendment=amendment,
        parent_contract_artifact_sha256=parent_record.sha256,
        parent_contract_record_hash=_record_hash(parent_record),
        child_contract_artifact_sha256=child_artifact_sha256,
        child_contract_sha256=child.sha256,
        child_contract_payload_schema=_evaluation_contract_schema(child),
        child_contract_artifact_schema=_evaluation_contract_artifact_schema(child),
        child_evidence_artifact_sha256s=tuple(
            record.sha256 for record in child_evidence_records
        ),
        child_evidence_artifact_record_hashes=tuple(
            _record_hash(record) for record in child_evidence_records
        ),
        lineage_root_contract_artifact_sha256=root_record.sha256,
        lineage_root_contract_record_hash=_record_hash(root_record),
        lineage_depth=len(parent_lineage.publications) + 1,
        visible_results=visible_results,
        observed_controls=observed_controls,
        source_ledger_event_count=source_ledger.event_count,
        source_ledger_head_hash=source_ledger.head_hash,
        source_registry_record_identities=source_registry_record_identities,
        source_registry_record_count=source_registry_record_count,
        source_registry_record_map_fingerprint=(
            source_registry_record_map_fingerprint
        ),
        confirmation_authorized=False,
    )


def _validate_static_publication(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    authority_record: ArtifactRecord,
    authority: EvaluationContractAmendmentAuthority,
    child_record: ArtifactRecord,
    child: EvaluationContract,
    parent_lineage: _ContractLineage,
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
) -> EvaluationContractAmendmentPublication:
    parent_record = parent_lineage.contract_records[-1]
    parent = parent_lineage.contracts[-1]
    if authority.observed_controls:
        _reject_observed_amendment_aliases(registry, authority_record, authority, registry_snapshot, ledger_snapshot)
    if authority.ledger_path != ledger.relative_path.as_posix():
        raise EvaluationContractAmendmentError(
            "amendment names another exact ledger path"
        )
    if authority.parent_contract_artifact_sha256 != parent_record.sha256:
        raise EvaluationContractAmendmentError(
            "amendment names another parent contract"
        )
    if authority.parent_contract_record_hash != _record_hash(parent_record):
        raise EvaluationContractAmendmentError(
            "amendment parent contract metadata changed"
        )
    if authority.child_contract_artifact_sha256 != child_record.sha256:
        raise EvaluationContractAmendmentError(
            "amendment names another child contract"
        )
    if authority.child_contract_sha256 != child.sha256:
        raise EvaluationContractAmendmentError(
            "amendment child contract content changed"
        )
    child_evidence_records = tuple(
        registry.get_metadata(digest)
        for digest in authority.child_evidence_artifact_sha256s
    )
    if tuple(_record_hash(record) for record in child_evidence_records) != (
        authority.child_evidence_artifact_record_hashes
    ):
        raise EvaluationContractAmendmentError(
            "amendment child evidence metadata changed"
        )
    if any(
        record.logical_type
        in {"evaluation_contract", EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE}
        for record in child_evidence_records
    ):
        raise EvaluationContractAmendmentError(
            "child evidence cannot smuggle a second contract lineage"
        )
    if child_record.parent_artifacts != (
        authority_record.sha256,
        *authority.child_evidence_artifact_sha256s,
    ):
        raise EvaluationContractAmendmentError(
            "amended contract has substituted or reordered evidence parents"
        )
    if (
        child_record.logical_type != "evaluation_contract"
        or child_record.origin != _CONTRACT_ORIGIN
        or child_record.creator_role is not Role.PROTOCOL_DESIGNER
        or child_record.creation_command != _CONTRACT_COMMAND
        or child_record.schema_version != authority.child_contract_artifact_schema
        or child_record.mime_type != "application/json"
        or child_record.validation_result != "PASS"
        or not child_record.frozen
        or child_record.created_at != authority.amendment.recorded_at
        or registry.get_bytes(child_record.sha256) != _child_bytes(child)
    ):
        raise EvaluationContractAmendmentError(
            "amended contract wrapper or metadata differs from canonical frozen semantics"
        )
    if (
        authority.child_contract_payload_schema != _evaluation_contract_schema(child)
        or authority.child_contract_artifact_schema
        != _evaluation_contract_artifact_schema(child)
        or authority.lineage_root_contract_artifact_sha256
        != parent_lineage.contract_records[0].sha256
        or authority.lineage_root_contract_record_hash
        != _record_hash(parent_lineage.contract_records[0])
        or authority.lineage_depth != len(parent_lineage.publications) + 1
    ):
        raise EvaluationContractAmendmentError(
            "amendment lineage root, depth, or child schema changed"
        )
    source_ledger = _source_ledger_prefix(ledger_snapshot, authority)
    sealed_records = _sealed_registry_records(registry_snapshot, authority)
    sealed_hashes = {record.sha256 for record in sealed_records}
    if authority_record.sha256 in sealed_hashes or child_record.sha256 in sealed_hashes:
        raise EvaluationContractAmendmentError(
            "amendment outputs cannot appear in their prepublication source map"
        )
    required_sealed_hashes = {
        *(record.sha256 for record in parent_lineage.contract_records),
        *(item.amendment_record.sha256 for item in parent_lineage.publications),
        *authority.child_evidence_artifact_sha256s,
        *(item.output_manifest_artifact_sha256 for item in authority.visible_results),
        *(item.observation_artifact_sha256 for item in authority.observed_controls),
    }
    if not required_sealed_hashes.issubset(sealed_hashes):
        raise EvaluationContractAmendmentError(
            "amendment sealed registry map omits a required historical source"
        )
    visible, observed_controls = _amendment_sources(
        registry, ledger, run_id=authority.ledger_run_id,
        parent_lineage=parent_lineage,
        pair=(RegistryValidationResult(valid=True, records=sealed_records), source_ledger),
        selectors=(tuple(item.observation_artifact_sha256 for item in authority.observed_controls)
                   if authority.schema_version == EVALUATION_CONTRACT_OBSERVED_AMENDMENT_SCHEMA else None),
    )
    expected_amendment = _validate_transition(
        parent,
        child,
        amendment_id=authority.amendment.amendment_id,
        author_id=authority.amendment.author_id,
        reason=authority.amendment.reason,
        recorded_at=authority.amendment.recorded_at,
        visible_results=visible,
        observed_controls=observed_controls,
    )
    if (authority.amendment != expected_amendment or authority.visible_results != visible
            or authority.observed_controls != observed_controls):
        raise EvaluationContractAmendmentError(
            "amendment meaning differs from full historical source replay"
        )
    if observed_controls:
        # The sealed edge stays backward-only. Its enclosing selected population
        # must not conceal a later correction to any of J's owned dependencies.
        dependency_ids = {event.event_id for event in source_ledger.events}
        if any(event.event_type == "CORRECTION" and event.supersedes_event_id in dependency_ids
               for event in ledger_snapshot.events[authority.source_ledger_event_count:]):
            raise EvaluationContractAmendmentError("an observed-control dependency was corrected")
    expected_parents = (
        parent_record.sha256,
        *(item.output_manifest_artifact_sha256 for item in visible),
        *(item.observation_artifact_sha256 for item in observed_controls),
    )
    if (
        authority_record.parent_artifacts != expected_parents
        or authority_record.created_at != authority.amendment.recorded_at
    ):
        raise EvaluationContractAmendmentError(
            "amendment artifact has substituted source parents or timestamp"
        )
    relevant_records = (
        *parent_lineage.contract_records,
        *(item.amendment_record for item in parent_lineage.publications),
        *child_evidence_records,
        *(registry.get_metadata(item.output_manifest_artifact_sha256) for item in visible),
        *(registry.get_metadata(item.observation_artifact_sha256) for item in observed_controls),
    )
    _source_chronology(
        tuple(record for record in relevant_records if isinstance(record, ArtifactRecord)),
        source_ledger.events,
        timestamp=authority.amendment.recorded_at,
    )
    matches = _matching_events(
        ledger_snapshot.events,
        amendment_id=authority.amendment.amendment_id,
        parent_contract_artifact_sha256=parent_record.sha256,
        child_contract_artifact_sha256=child_record.sha256,
        amendment_artifact_sha256=authority_record.sha256,
    )
    if len(matches) != 1:
        raise EvaluationContractAmendmentError(
            "amendment requires one exact publication event"
        )
    event_index, event = matches[0]
    _require_uncorrected_amendment_event(
        ledger_snapshot.events,
        publication_event_id=event.event_id,
    )
    if event_index != authority.source_ledger_event_count:
        raise EvaluationContractAmendmentError(
            "amendment event does not immediately follow its sealed source prefix"
        )
    expected_event = _build_event(
        authority, authority_record, child_record, source_ledger
    )
    if event != expected_event:
        raise EvaluationContractAmendmentError(
            "amendment publication event is stale or substituted"
        )
    slot_records = tuple(
        record
        for record, candidate in _all_amendment_records(
            registry, registry_snapshot.records
        )
        if _slot_matches(
            candidate,
            amendment_id=authority.amendment.amendment_id,
            parent_contract_artifact_sha256=parent_record.sha256,
            child_contract_artifact_sha256=child_record.sha256,
            contract_id=authority.amendment.contract_id,
            to_version=authority.amendment.to_version,
        )
    )
    if slot_records != (authority_record,):
        raise EvaluationContractAmendmentError(
            "amendment lineage slot is competing or ambiguous"
        )
    child_records = tuple(
        record
        for record in registry_snapshot.records
        if record.logical_type == "evaluation_contract"
        and record.parent_artifacts[:1] == (authority_record.sha256,)
    )
    if child_records != (child_record,):
        raise EvaluationContractAmendmentError(
            "amendment has a missing or competing child contract"
        )
    return EvaluationContractAmendmentPublication(
        authority=authority,
        amendment_record=authority_record,
        contract_record=child_record,
        parent_contract_record=parent_record,
        parent_contract=parent,
        child_contract=child,
        event=event,
        event_index=event_index,
        lineage_contract_records=(*parent_lineage.contract_records, child_record),
        lineage_amendment_records=(
            *(item.amendment_record for item in parent_lineage.publications),
            authority_record,
        ),
    )


def _resolve_lineage(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    contract_artifact_sha256: str,
    expected_run_id: str,
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
    visited: frozenset[str] = frozenset(),
    require_snapshot_local_dependencies: bool = False,
) -> _ContractLineage:
    if require_snapshot_local_dependencies and (
        any(
            record.logical_type in {"frozen_run_spec", "experiment_output_manifest"}
            for record in registry_snapshot.records
        )
        or any(
            "scientific_timeline" in _event_metadata_value(event)
            for event in ledger_snapshot.events
        )
    ):
        # A false empty visible_results field must not enter live manifest
        # dependencies before its later full semantic mismatch is detected.
        # The closed simulated profile does not support that coexistence.
        raise EvaluationContractAmendmentError(
            "sealed-only amendment replay does not support scientific timeline populations"
        )
    if len(visited) >= _MAX_LINEAGE_DEPTH:
        raise EvaluationContractAmendmentError(
            "Evaluation Contract amendment lineage exceeds its depth bound"
        )
    record, _wrapper, contract = _require_frozen_evaluation_contract_descriptor(
        registry, contract_artifact_sha256=contract_artifact_sha256
    )
    if next(
        (
            item
            for item in registry_snapshot.records
            if item.sha256 == record.sha256
        ),
        None,
    ) != record:
        raise EvaluationContractAmendmentError(
            "contract descriptor is absent from the selected registry population"
        )
    temporal_record, _projection = _require_temporal_contract_descriptor(
        registry, record.sha256, contract=contract
    )
    if temporal_record != record:
        raise EvaluationContractAmendmentError(
            "contract descriptor changed during amendment replay"
        )
    parent_records = tuple(
        registry.get_metadata(digest) for digest in record.parent_artifacts
    )
    reserved = tuple(
        item
        for item in parent_records
        if item.logical_type
        in {"evaluation_contract", EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE}
    )
    first_parent = parent_records[0]
    if first_parent.logical_type != EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE:
        if reserved:
            raise EvaluationContractAmendmentError(
                "genesis contract cannot hide a contract or amendment parent"
            )
        return _ContractLineage((record,), (contract,), ())
    if reserved != (first_parent,):
        raise EvaluationContractAmendmentError(
            "amended contract has a misplaced or competing lineage parent"
        )
    if first_parent.sha256 in visited:
        raise EvaluationContractAmendmentError(
            "Evaluation Contract amendment lineage contains a cycle"
        )
    authority = _read_amendment_record(registry, first_parent)
    if require_snapshot_local_dependencies and authority.visible_results:
        # Legacy manifest owners still resolve live temporal/statistical
        # dependencies. Never enter them from a promised sealed-only edge.
        raise EvaluationContractAmendmentError(
            "sealed-only amendment replay does not support legacy manifest observations"
        )
    if next(
        (
            item
            for item in registry_snapshot.records
            if item.sha256 == first_parent.sha256
        ),
        None,
    ) != first_parent:
        raise EvaluationContractAmendmentError(
            "amendment parent is absent from the selected registry population"
        )
    if authority.ledger_run_id != expected_run_id:
        raise EvaluationContractAmendmentError(
            "Evaluation Contract amendment belongs to another ledger run"
        )
    parent_lineage = _resolve_lineage(
        registry,
        ledger,
        contract_artifact_sha256=authority.parent_contract_artifact_sha256,
        expected_run_id=expected_run_id,
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
        visited=visited | {first_parent.sha256},
        require_snapshot_local_dependencies=require_snapshot_local_dependencies,
    )
    publication = _validate_static_publication(
        registry,
        ledger,
        authority_record=first_parent,
        authority=authority,
        child_record=record,
        child=contract,
        parent_lineage=parent_lineage,
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
    )
    return _ContractLineage(
        publication.lineage_contract_records,
        (*parent_lineage.contracts, contract),
        (*parent_lineage.publications, publication),
    )


def _require_evaluation_contract_amendment_at_snapshot(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
    amendment_artifact_sha256: str,
    expected_run_id: str,
    expected_child_contract_artifact_sha256: str | None = None,
    require_snapshot_local_dependencies: bool = True,
) -> EvaluationContractAmendmentPublication:
    """Full replay inside an already owned exact source population.

    Historical consumers must supply their verified sealed map and prefix.
    By default legacy manifest dependencies that still resolve live owners
    are refused; current public readers retain their existing full replay.
    The caller owns the enclosing current-pair readback/CAS. This is not
    new-use authority.
    """

    _sha256(amendment_artifact_sha256, "amendment artifact SHA-256")
    expected_run_id = _identifier(expected_run_id, "expected amendment run ID")
    if expected_child_contract_artifact_sha256 is not None:
        _sha256(
            expected_child_contract_artifact_sha256,
            "expected amended contract artifact SHA-256",
        )
    if (
        type(registry_snapshot) is not RegistryValidationResult
        or type(ledger_snapshot) is not LedgerValidationResult
        or not registry_snapshot.valid
        or not ledger_snapshot.valid
        or any(event.run_id != expected_run_id for event in ledger_snapshot.events)
    ):
        raise EvaluationContractAmendmentError(
            "amendment requires a valid exact selected source population"
        )
    record = next(
        (
            item
            for item in registry_snapshot.records
            if item.sha256 == amendment_artifact_sha256
        ),
        None,
    )
    if record is None:
        raise EvaluationContractAmendmentError(
            "Evaluation Contract amendment artifact is absent"
        )
    authority = _read_amendment_record(registry, record)
    if authority.ledger_run_id != expected_run_id:
        raise EvaluationContractAmendmentError(
            "Evaluation Contract amendment names another run"
        )
    if (
        expected_child_contract_artifact_sha256 is not None
        and authority.child_contract_artifact_sha256
        != expected_child_contract_artifact_sha256
    ):
        raise EvaluationContractAmendmentError(
            "Evaluation Contract amendment names another child"
        )
    lineage = _resolve_lineage(
        registry,
        ledger,
        contract_artifact_sha256=authority.child_contract_artifact_sha256,
        expected_run_id=expected_run_id,
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
        require_snapshot_local_dependencies=require_snapshot_local_dependencies,
    )
    matches = tuple(
        publication
        for publication in lineage.publications
        if publication.amendment_record == record
    )
    if len(matches) != 1:
        raise EvaluationContractAmendmentError(
            "amendment is not the exact child lineage edge"
        )
    return matches[0]


def require_evaluation_contract_amendment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    amendment_artifact_sha256: str,
    expected_run_id: str,
    expected_child_contract_artifact_sha256: str | None = None,
) -> EvaluationContractAmendmentPublication:
    """Fully replay one completed amendment against its sealed source prefix."""

    _sha256(amendment_artifact_sha256, "amendment artifact SHA-256")
    expected_run_id = _identifier(expected_run_id, "expected amendment run ID")
    if expected_child_contract_artifact_sha256 is not None:
        _sha256(
            expected_child_contract_artifact_sha256,
            "expected amended contract artifact SHA-256",
        )
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    publication = _require_evaluation_contract_amendment_at_snapshot(
        registry,
        ledger,
        registry_snapshot=before[0],
        ledger_snapshot=before[1],
        amendment_artifact_sha256=amendment_artifact_sha256,
        expected_run_id=expected_run_id,
        expected_child_contract_artifact_sha256=(
            expected_child_contract_artifact_sha256
        ),
        require_snapshot_local_dependencies=False,
    )
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        raise EvaluationContractAmendmentError(
            "amendment sources changed during full readback"
        )
    return publication


def _raw_contract_root(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
    *,
    visited: frozenset[str] = frozenset(),
) -> ArtifactRecord:
    if len(visited) >= _MAX_LINEAGE_DEPTH:
        raise EvaluationContractAmendmentError(
            "contract identity lineage exceeds the supported depth"
        )
    parents = tuple(registry.get_metadata(digest) for digest in record.parent_artifacts)
    first = parents[0]
    reserved = tuple(
        item
        for item in parents
        if item.logical_type
        in {"evaluation_contract", EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE}
    )
    if first.logical_type != EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE:
        if reserved:
            raise EvaluationContractAmendmentError(
                "genesis contract contains a reserved lineage parent"
            )
        return record
    if reserved != (first,) or first.sha256 in visited:
        raise EvaluationContractAmendmentError(
            "contract contains an ambiguous amendment lineage"
        )
    authority = _read_amendment_record(registry, first)
    if authority.child_contract_artifact_sha256 != record.sha256:
        raise EvaluationContractAmendmentError(
            "amendment parent does not name its exact child contract"
        )
    parent_record, _wrapper, _contract = _require_frozen_evaluation_contract_descriptor(
        registry,
        contract_artifact_sha256=authority.parent_contract_artifact_sha256,
    )
    return _raw_contract_root(
        registry,
        parent_record,
        visited=visited | {first.sha256},
    )


def _contract_id_hint(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
) -> str | None:
    """Read only the bounded identity selector before strict contract parsing.

    Unrelated malformed contract-shaped artifacts must not make a historical
    family unreadable.  Conversely, once a native contract ID selects the
    current family, the strict descriptor owner below must reject every
    malformed wrapper or metadata alias rather than silently skipping it.
    """

    if (
        record.logical_type != "evaluation_contract"
        or not 0 < record.size <= _MAX_CONTRACT_ID_HINT_BYTES
    ):
        return None
    try:
        value = safe_json_loads(
            registry.get_bytes(record.sha256),
            max_bytes=_MAX_CONTRACT_ID_HINT_BYTES,
            max_items=_MAX_CONTRACT_JSON_ITEMS,
        )
    except (ArtifactError, UnsafeSerializationError, ValidationError):
        return None
    if type(value) is not dict:
        return None
    payload = value.get("evaluation_contract")
    if type(payload) is not dict:
        return None
    contract_id = payload.get("contract_id")
    return contract_id if type(contract_id) is str else None


def _contract_identity_roots(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    *,
    selected_contract_id: str,
) -> frozenset[str]:
    roots: set[str] = set()
    for candidate_record in records:
        if candidate_record.logical_type != "evaluation_contract":
            continue
        if _contract_id_hint(registry, candidate_record) != selected_contract_id:
            continue
        try:
            checked, _wrapper, candidate = (
                _require_frozen_evaluation_contract_descriptor(
                    registry,
                    contract_artifact_sha256=candidate_record.sha256,
                )
            )
        except ScientificDesignError as exc:
            raise EvaluationContractAmendmentError(
                "related contract descriptor is malformed"
            ) from exc
        if checked != candidate_record or candidate.contract_id != selected_contract_id:
            raise EvaluationContractAmendmentError(
                "related contract descriptor changed during identity replay"
            )
        roots.add(_raw_contract_root(registry, candidate_record).sha256)
    return frozenset(roots)


def _require_evaluation_contract_child_lineage(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_run_id: str,
    contract_artifact_sha256: str,
) -> EvaluationContractLineageReplay:
    """Full child-lineage owner for consumers that already possess a ledger.

    This never selects a latest descendant.  A historical parent remains
    readable after a valid child publication, while a second unamended root
    with the same contract identity is rejected as ambiguous.
    """

    expected_run_id = _identifier(expected_run_id, "expected contract-lineage run ID")
    _sha256(contract_artifact_sha256, "contract-lineage artifact SHA-256")
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    if any(event.run_id != expected_run_id for event in before[1].events):
        raise EvaluationContractAmendmentError(
            "contract-lineage ledger names another run"
        )
    lineage = _resolve_lineage(
        registry,
        ledger,
        contract_artifact_sha256=contract_artifact_sha256,
        expected_run_id=expected_run_id,
        registry_snapshot=before[0],
        ledger_snapshot=before[1],
    )
    selected_root = lineage.contract_records[0]
    selected_id = lineage.contracts[-1].contract_id
    roots = _contract_identity_roots(
        registry,
        before[0].records,
        selected_contract_id=selected_id,
    )
    if roots != frozenset({selected_root.sha256}):
        raise EvaluationContractAmendmentError(
            "contract identity has competing unamended roots"
        )
    after = _locked_checked_result_authority_snapshot(registry, ledger)
    if after != before:
        raise EvaluationContractAmendmentError(
            "contract lineage changed during full readback"
        )
    selected_publication = lineage.publications[-1] if lineage.publications else None
    return EvaluationContractLineageReplay(
        contract_record=lineage.contract_records[-1],
        contract=lineage.contracts[-1],
        lineage_contract_records=lineage.contract_records,
        lineage_amendment_records=tuple(
            item.amendment_record for item in lineage.publications
        ),
        selected_amendment_artifact_sha256=(
            selected_publication.amendment_record.sha256
            if selected_publication is not None
            else None
        ),
        registry_snapshot=before[0],
        ledger_snapshot=before[1],
    )


def _require_evaluation_contract_registry_lineage(
    registry: ArtifactRegistry,
    *,
    contract_artifact_sha256: str,
) -> EvaluationContractLineageReplay:
    """Replay a contract lineage for registry-only legacy consumers.

    An amended child carries the exact confined ledger path and run identity
    in its first amendment parent.  That persisted selector is the only basis
    for constructing a ledger here.  A genuine genesis contract has no such
    selector: it receives only reject-only same-ID root disambiguation and no
    invented ledger or amendment authority.
    """

    if type(registry) is not ArtifactRegistry:
        raise EvaluationContractAmendmentError(
            "registry-only contract lineage requires exact ArtifactRegistry"
        )
    _sha256(contract_artifact_sha256, "registry-only contract artifact SHA-256")
    try:
        before = registry.verify_all(raise_on_error=True)
    except ArtifactError as exc:
        raise EvaluationContractAmendmentError(
            "registry-only contract lineage snapshot is unavailable"
        ) from exc
    selected_record = next(
        (
            record
            for record in before.records
            if record.sha256 == contract_artifact_sha256
        ),
        None,
    )
    if selected_record is None:
        raise EvaluationContractAmendmentError(
            "registry-only contract artifact is absent"
        )
    checked, _wrapper, contract = _require_frozen_evaluation_contract_descriptor(
        registry,
        contract_artifact_sha256=contract_artifact_sha256,
    )
    if checked != selected_record:
        raise EvaluationContractAmendmentError(
            "registry-only contract descriptor changed during replay"
        )
    parents = tuple(
        registry.get_metadata(digest) for digest in selected_record.parent_artifacts
    )
    reserved = tuple(
        record
        for record in parents
        if record.logical_type
        in {"evaluation_contract", EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE}
    )
    first_parent = parents[0]
    if first_parent.logical_type == EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE:
        if reserved != (first_parent,):
            raise EvaluationContractAmendmentError(
                "amended contract has a misplaced or competing lineage parent"
            )
        authority = _read_amendment_record(registry, first_parent)
        if (
            authority.child_contract_artifact_sha256 != selected_record.sha256
            or authority.amendment.contract_id != contract.contract_id
        ):
            raise EvaluationContractAmendmentError(
                "amendment parent does not select this exact child identity"
            )
        try:
            registry.policy.resolve(
                authority.ledger_path,
                must_exist=True,
                expected_kind="file",
                reject_hardlinks=True,
            )
            ledger = EventLedger(registry.policy.root, authority.ledger_path)
        except (LedgerError, ValidationError) as exc:
            raise EvaluationContractAmendmentError(
                "persisted amendment ledger path is unavailable or unsafe"
            ) from exc
        return _require_evaluation_contract_child_lineage(
            registry,
            ledger,
            expected_run_id=authority.ledger_run_id,
            contract_artifact_sha256=selected_record.sha256,
        )
    if reserved:
        raise EvaluationContractAmendmentError(
            "genesis contract cannot hide a contract or amendment parent"
        )
    roots = _contract_identity_roots(
        registry,
        before.records,
        selected_contract_id=contract.contract_id,
    )
    if roots != frozenset({selected_record.sha256}):
        raise EvaluationContractAmendmentError(
            "contract identity has competing unamended roots"
        )
    try:
        after = registry.verify_all(raise_on_error=True)
    except ArtifactError as exc:
        raise EvaluationContractAmendmentError(
            "registry-only contract lineage exit snapshot is unavailable"
        ) from exc
    if after != before:
        raise EvaluationContractAmendmentError(
            "registry-only contract lineage changed during readback"
        )
    return EvaluationContractLineageReplay(
        contract_record=selected_record,
        contract=contract,
        lineage_contract_records=(selected_record,),
        lineage_amendment_records=(),
        selected_amendment_artifact_sha256=None,
        registry_snapshot=before,
        ledger_snapshot=None,
    )


def _existing_amendment_slot(
    registry: ArtifactRegistry,
    snapshot: RegistryValidationResult,
    *,
    amendment_id: str,
    parent_contract_artifact_sha256: str,
    child_contract_artifact_sha256: str,
    contract_id: str,
    to_version: int,
) -> tuple[ArtifactRecord, EvaluationContractAmendmentAuthority] | None:
    matches = tuple(
        (record, authority)
        for record, authority in _all_amendment_records(registry, snapshot.records)
        if _slot_matches(
            authority,
            amendment_id=amendment_id,
            parent_contract_artifact_sha256=parent_contract_artifact_sha256,
            child_contract_artifact_sha256=child_contract_artifact_sha256,
            contract_id=contract_id,
            to_version=to_version,
        )
    )
    if len(matches) > 1:
        raise EvaluationContractAmendmentError(
            "Evaluation Contract amendment slot is ambiguous"
        )
    return matches[0] if matches else None


def _matches_observation_request(authority, selectors):
    if selectors is None:
        return authority.schema_version == EVALUATION_CONTRACT_AMENDMENT_SCHEMA and not authority.observed_controls
    return (authority.schema_version == EVALUATION_CONTRACT_OBSERVED_AMENDMENT_SCHEMA
            and tuple(item.observation_artifact_sha256 for item in authority.observed_controls) == selectors)


def _amendment_schema_family(value):
    return type(value) is str and value.startswith(("evaluation-contract-amendment/", "eval-contract-amendment/"))


def _observed_alias_shape(value, authority):
    """Recognize selected publication-shaped references, not prose mentions."""
    selected = targeted = False
    pending = [value]
    targets = {
        "amendment_id": authority.amendment.amendment_id,
        "parent_contract_artifact_sha256": authority.parent_contract_artifact_sha256,
        "child_contract_artifact_sha256": authority.child_contract_artifact_sha256,
        "observation_artifact_sha256": authority.observed_controls[0].observation_artifact_sha256,
    }
    while pending:
        item = pending.pop()
        if type(item) is dict:
            selected |= _amendment_schema_family(item.get("schema_version"))
            targeted |= any(type(item.get(key)) is str and item[key] == expected for key, expected in targets.items())
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    return selected, targeted


def _reject_observed_amendment_aliases(registry, authority_record, authority, registry_snapshot, ledger_snapshot):
    """Selected-outer negative census, never recursive future-owner replay.

    Unrelated untyped files over A's existing 4 MiB codec cap are unclassified,
    not trusted and not a reason to impose a new global historical size limit.
    New-use J/S owners independently require their complete closed populations.
    """
    target_hashes = (authority_record.sha256, authority.parent_contract_artifact_sha256,
                     authority.child_contract_artifact_sha256,
                     authority.observed_controls[0].observation_artifact_sha256)
    for record in registry_snapshot.records:
        if record == authority_record:
            continue
        metadata_selected = _amendment_schema_family(record.schema_version) or record.logical_type == EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE
        if not 0 < record.size <= _MAX_AMENDMENT_BYTES:
            if metadata_selected:
                raise EvaluationContractAmendmentError("selected observed-amendment alias exceeds its codec bound")
            continue
        raw = registry.get_bytes(record.sha256)
        try:
            value = safe_json_loads(raw, max_bytes=_MAX_AMENDMENT_BYTES, max_items=_MAX_AMENDMENT_JSON_ITEMS)
        except (UnsafeSerializationError, ValueError):
            schema_selected = any(prefix in raw for prefix in (b'"evaluation-contract-amendment/', b'"eval-contract-amendment/'))
            targeted = (any(canonical_json_bytes(digest) in raw for digest in target_hashes)
                        or (b'"amendment_id"' in raw and canonical_json_bytes(authority.amendment.amendment_id) in raw))
        else:
            schema_selected, targeted = _observed_alias_shape(value, authority)
        if (metadata_selected or schema_selected) and targeted:
            raise EvaluationContractAmendmentError("renamed or malformed observed-amendment slot alias")
    related = set(target_hashes)
    for event in ledger_snapshot.events:
        metadata = _event_metadata_value(event)
        if EVALUATION_CONTRACT_AMENDMENT_EVENT_KEY in metadata:
            if not isinstance(metadata[EVALUATION_CONTRACT_AMENDMENT_EVENT_KEY], Mapping):
                raise EvaluationContractAmendmentError("observed-amendment publication key is null or malformed")
            if event.event_id == _event_id(authority):
                continue  # Common owner still requires the exact full event.
        # An empty binding cannot hide a selected sibling or event-ID/reference
        # alias. Classify the complete metadata independently of key presence.
        selected, targeted = _observed_alias_shape(metadata, authority)
        if ((selected and targeted)
                or event.event_id == _event_id(authority)
                or (event.event_id.startswith("evt-contract-amendment-") and related.intersection(event.artifact_hashes))):
            raise EvaluationContractAmendmentError("observed-amendment publication alias lacks its exact binding")


@contextmanager
def _amendment_publication_guard(registry, ledger, run_id, before, *, selectors,
                                 existing_authority, existing_authority_record,
                                 child_sha256, parent_lineage):
    if selectors is None:
        with _current_simulated_amendment_guard(registry, ledger, run_id, before) as guard:
            yield guard, None, None
        return
    from .simulated_observation import SimulatedObservationError, _observed_amendment_admission_guard
    from .simulated_resource import SimulatedResourceError
    from .holdout import HoldoutCustodyError
    from .orchestrator import OrchestrationError
    from .recovery import ConfirmatoryRerunError
    from .resources import ResourceConfigError, ResourceLimitError

    source_records = before[0].records
    if existing_authority is not None:
        if not _matches_observation_request(existing_authority, selectors):
            raise EvaluationContractAmendmentError("incomplete amendment observation request differs")
        source_records = tuple(record for record in source_records
                               if record.sha256 not in {existing_authority_record.sha256, child_sha256})
        if (_registry_record_map(source_records) != existing_authority.source_registry_record_identities
                or before[1].event_count != existing_authority.source_ledger_event_count
                or before[1].head_hash != existing_authority.source_ledger_head_hash):
            raise EvaluationContractAmendmentError("observed amendment orphan source pair changed")
    source_pair = (RegistryValidationResult(valid=True, records=source_records), before[1])
    try:
        with _observed_amendment_admission_guard(
            registry, ledger, expected_run_id=run_id,
            observation_artifact_sha256=selectors[0],
            registry_snapshot=source_pair[0], ledger_snapshot=source_pair[1],
            current_pair=before,
        ) as (observed, final_check):
            from .recovery import RecoveryManager
            # Require A's source file in the original inventory. This verifies
            # source bytes, not an execution or host attestation.
            from .simulated_observation import _inventories
            source, _config = _inventories(registry, observed.preparation.charge)
            RecoveryManager._validated_live_source_implementation(
                RecoveryManager(registry.policy.root), source,
                path="src/scientist_one/evaluation_contract_amendment.py",
                label="observed amendment owner",
            )
            _derive_observed_controls(registry, ledger, run_id=run_id, selectors=selectors,
                                      pair=source_pair, parent_lineage=parent_lineage)
            if observed.preparation.charge.reservation.contract_record != parent_lineage.contract_records[-1]:
                raise EvaluationContractAmendmentError("current observation belongs to another amendment parent")
            _require_no_completed_contract_successor_before(
                registry, ledger, selected_record=parent_lineage.contract_records[-1],
                expected_run_id=run_id, registry_snapshot=source_pair[0], ledger_snapshot=source_pair[1],
                design_event_index=source_pair[1].event_count, complete_source_population=True,
            )
            yield None, final_check, observed
    except (SimulatedObservationError, PathSecurityError, SimulatedResourceError,
            HoldoutCustodyError, OrchestrationError, ConfirmatoryRerunError,
            ResourceConfigError, ResourceLimitError) as exc:
        raise EvaluationContractAmendmentError("observed amendment current custody/resource boundary refused") from exc


def _observed_amendment_bookkeeping_capacity(registry, observation, required_bytes):
    """Reserve actual missing publication files, not new experiment authority.

    Completed history never calls this helper. A/C orphan completion pays only
    for its absent payload/metadata files and event, without a new validity
    debit, experiment allowance, wall/stall requirement or reset.
    """
    from .resources import ResourceController, conservative_disk_reserve

    if type(required_bytes) is not int or required_bytes <= 0:
        raise EvaluationContractAmendmentError("observed amendment publication estimate is invalid")
    charge = observation.preparation.charge
    config = charge.initialization.config
    controller = ResourceController.from_runtime_state(config, registry.policy.root, charge.runtime_state)
    total, free, error = controller._probe_disk()
    if (error is not None or total is None or free is None
            or controller.artifact_usage() + required_bytes >= config.maximum_artifact_bytes
            or free - required_bytes <= conservative_disk_reserve(
                total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)):
        raise EvaluationContractAmendmentError("observed amendment bookkeeping lacks disk or artifact capacity")


def register_evaluation_contract_amendment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    amendment_id: str,
    parent_contract_artifact_sha256: str,
    child_contract: EvaluationContract,
    author_id: str,
    reason: str,
    child_evidence_parent_artifact_sha256s: tuple[str, ...] = (),
    observation_artifact_sha256s: Any = _OBSERVATION_OMITTED,
) -> EvaluationContractAmendmentPublication:
    """Record and atomically pair one amendment, child contract, and event.

    Exact A-only and A+C crash prefixes can be resumed only while the complete
    source registry map and sealed ledger prefix remain byte-for-byte stable.
    Completed history remains replayable after unrelated later appends.
    """

    observation_selectors = _observation_request(observation_artifact_sha256s)
    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise EvaluationContractAmendmentError(
            "amendment registration requires exact registry and ledger"
        )
    if registry.policy.root != ledger.policy.root:
        raise EvaluationContractAmendmentError(
            "amendment registry and ledger roots differ"
        )
    run_id = _identifier(run_id, "amendment run ID")
    amendment_id = _identifier(amendment_id, "amendment ID")
    author_id = _identifier(author_id, "amendment author ID")
    reason = _bounded_text(reason, "amendment reason")
    _sha256(parent_contract_artifact_sha256, "parent contract artifact SHA-256")
    if type(child_contract) is not EvaluationContract:
        raise EvaluationContractAmendmentError(
            "child contract must be the exact EvaluationContract type"
        )
    if (
        type(child_evidence_parent_artifact_sha256s) is not tuple
        or len(child_evidence_parent_artifact_sha256s) > MAX_ARTIFACT_PARENTS - 1
        or len(set(child_evidence_parent_artifact_sha256s))
        != len(child_evidence_parent_artifact_sha256s)
    ):
        raise EvaluationContractAmendmentError(
            "child evidence parents must be a unique bounded tuple"
        )
    child_raw = _child_bytes(child_contract)
    child_sha256 = hashlib.sha256(child_raw).hexdigest()
    before = _locked_checked_result_authority_snapshot(
        registry, ledger, ensure_storage=True
    )
    if any(event.run_id != run_id for event in before[1].events):
        raise EvaluationContractAmendmentError(
            "amendment ledger contains another run identity"
        )
    parent_lineage = _resolve_lineage(
        registry,
        ledger,
        contract_artifact_sha256=parent_contract_artifact_sha256,
        expected_run_id=run_id,
        registry_snapshot=before[0],
        ledger_snapshot=before[1],
    )
    parent_record = parent_lineage.contract_records[-1]
    parent = parent_lineage.contracts[-1]
    child_evidence_records = []
    by_sha = {record.sha256: record for record in before[0].records}
    for digest in child_evidence_parent_artifact_sha256s:
        _sha256(digest, "child evidence parent")
        record = by_sha.get(digest)
        if record is None:
            raise EvaluationContractAmendmentError(
                "child evidence parent is absent from the entry snapshot"
            )
        if record.logical_type in {
            "evaluation_contract",
            EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE,
        }:
            raise EvaluationContractAmendmentError(
                "child evidence cannot create a competing contract lineage"
            )
        child_evidence_records.append(record)
    child_evidence = tuple(child_evidence_records)
    slot = _existing_amendment_slot(
        registry,
        before[0],
        amendment_id=amendment_id,
        parent_contract_artifact_sha256=parent_record.sha256,
        child_contract_artifact_sha256=child_sha256,
        contract_id=child_contract.contract_id,
        to_version=child_contract.version,
    )
    existing_authority_record = slot[0] if slot else None
    existing_authority = slot[1] if slot else None
    existing_child_record = by_sha.get(child_sha256)
    event_matches = _matching_events(
        before[1].events,
        amendment_id=amendment_id,
        parent_contract_artifact_sha256=parent_record.sha256,
        child_contract_artifact_sha256=child_sha256,
        amendment_artifact_sha256=(
            existing_authority_record.sha256
            if existing_authority_record is not None
            else None
        ),
    )
    if existing_authority is not None and existing_child_record is not None and event_matches:
        publication = require_evaluation_contract_amendment(
            registry,
            ledger,
            amendment_artifact_sha256=existing_authority_record.sha256,
            expected_run_id=run_id,
            expected_child_contract_artifact_sha256=child_sha256,
        )
        if (
            publication.child_contract != child_contract
            or publication.authority.amendment.author_id != author_id
            or publication.authority.amendment.reason != reason
            or publication.authority.child_evidence_artifact_sha256s
            != child_evidence_parent_artifact_sha256s
            or not _matches_observation_request(publication.authority, observation_selectors)
        ):
            raise EvaluationContractAmendmentError(
                "completed amendment slot belongs to another request"
            )
        return publication
    with _amendment_publication_guard(
        registry, ledger, run_id, before, selectors=observation_selectors,
        existing_authority=existing_authority, existing_authority_record=existing_authority_record,
        child_sha256=child_sha256, parent_lineage=parent_lineage,
    ) as (current_guard, observed_final_check, owned_observation):
        if event_matches:
            raise EvaluationContractAmendmentError(
                "amendment event exists without the complete exact record pair"
            )
        if existing_authority is None:
            if existing_child_record is not None:
                raise EvaluationContractAmendmentError(
                    "child contract bytes already occupy another lineage"
                )
            recorded_at = utc_now()
            source_records = before[0].records
            source_ledger = before[1]
            source_identities = _registry_record_map(source_records)
            source_count, source_fingerprint = _registry_map_fingerprint(source_records)
        else:
            recorded_at = existing_authority.amendment.recorded_at
            excluded = {existing_authority_record.sha256, child_sha256}
            source_records = tuple(
                record for record in before[0].records if record.sha256 not in excluded
            )
            source_identities = _registry_record_map(source_records)
            source_count, source_fingerprint = _registry_map_fingerprint(source_records)
            if (
                source_identities
                != existing_authority.source_registry_record_identities
                or source_count != existing_authority.source_registry_record_count
                or source_fingerprint
                != existing_authority.source_registry_record_map_fingerprint
                or before[1].event_count
                != existing_authority.source_ledger_event_count
                or before[1].head_hash != existing_authority.source_ledger_head_hash
            ):
                raise EvaluationContractAmendmentError(
                    "incomplete amendment cannot recover after source exposure or drift"
                )
            source_ledger = before[1]
        visible, observed_controls = _amendment_sources(
            registry, ledger, run_id=run_id, parent_lineage=parent_lineage,
            pair=(RegistryValidationResult(valid=True, records=source_records), source_ledger),
            selectors=observation_selectors,
        )
        amendment = _validate_transition(
            parent,
            child_contract,
            amendment_id=amendment_id,
            author_id=author_id,
            reason=reason,
            recorded_at=recorded_at,
            visible_results=visible,
            observed_controls=observed_controls,
        )
        authority = _authority_for_sources(
            run_id=run_id,
            ledger=ledger,
            amendment=amendment,
            parent_record=parent_record,
            child=child_contract,
            child_artifact_sha256=child_sha256,
            child_evidence_records=child_evidence,
            parent_lineage=parent_lineage,
            visible_results=visible,
            source_ledger=source_ledger,
            source_registry_record_identities=source_identities,
            source_registry_record_count=source_count,
            source_registry_record_map_fingerprint=source_fingerprint,
            observed_controls=observed_controls,
        )
        if existing_authority is not None and existing_authority != authority:
            raise EvaluationContractAmendmentError(
                "incomplete amendment differs from fresh exact source replay"
            )
        authority_raw = authority.canonical_bytes()
        if not 0 < len(authority_raw) <= _MAX_AMENDMENT_BYTES:
            raise EvaluationContractAmendmentError(
                "Evaluation Contract amendment exceeds byte capacity"
            )
        safe_json_loads(
            authority_raw,
            max_bytes=_MAX_AMENDMENT_BYTES,
            max_items=_MAX_AMENDMENT_JSON_ITEMS,
        )
        authority_record = _planned_record(
            registry,
            authority_raw,
            logical_type=EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE,
            origin=_AMENDMENT_ORIGIN,
            creator_role=Role.PROTOCOL_DESIGNER,
            command=_AMENDMENT_COMMAND,
            parents=(
                parent_record.sha256,
                *(item.output_manifest_artifact_sha256 for item in visible),
                *(item.observation_artifact_sha256 for item in observed_controls),
            ),
            schema_version=_amendment_artifact_schema(authority),
            created_at=recorded_at,
        )
        child_record = _planned_record(
            registry,
            child_raw,
            logical_type="evaluation_contract",
            origin=_CONTRACT_ORIGIN,
            creator_role=Role.PROTOCOL_DESIGNER,
            command=_CONTRACT_COMMAND,
            parents=(authority_record.sha256, *child_evidence_parent_artifact_sha256s),
            schema_version=_evaluation_contract_artifact_schema(child_contract),
            created_at=recorded_at,
        )
        exact_existing_authority = _record_is_exact(before[0], authority_record)
        exact_existing_child = _record_is_exact(before[0], child_record)
        if exact_existing_authority != existing_authority_record:
            raise EvaluationContractAmendmentError(
                "amendment orphan metadata differs from its deterministic preflight"
            )
        if existing_child_record is not None and exact_existing_child is None:
            raise EvaluationContractAmendmentError(
                "amended contract bytes occupy another metadata identity"
            )
        records_needed = int(exact_existing_authority is None) + int(
            exact_existing_child is None
        )
        if before[0].count + records_needed > MAX_REGISTRY_RECORDS:
            raise EvaluationContractAmendmentError(
                "amendment registry capacity is insufficient"
            )
        if before[1].event_count + 1 > MAX_LEDGER_EVENTS:
            raise EvaluationContractAmendmentError(
                "amendment ledger event capacity is insufficient"
            )
        _source_chronology(
            (
                *parent_lineage.contract_records,
                *(item.amendment_record for item in parent_lineage.publications),
                *child_evidence,
                *(registry.get_metadata(item.output_manifest_artifact_sha256) for item in visible),
                *(registry.get_metadata(item.observation_artifact_sha256) for item in observed_controls),
            ),
            source_ledger.events,
            timestamp=recorded_at,
        )
        event = _build_event(authority, authority_record, child_record, source_ledger)
        event_line = canonical_json_bytes(event.to_dict()) + b"\n"
        if before[1].valid_prefix_bytes + len(event_line) > MAX_LEDGER_BYTES:
            raise EvaluationContractAmendmentError(
                "amendment ledger byte capacity is insufficient"
            )
        publication_bytes = len(event_line)
        if exact_existing_authority is None:
            publication_bytes += len(authority_raw) + len(canonical_json_bytes(authority_record.to_dict()) + b"\n")
        if exact_existing_child is None:
            publication_bytes += len(child_raw) + len(canonical_json_bytes(child_record.to_dict()) + b"\n")
        if owned_observation is not None:
            _observed_amendment_bookkeeping_capacity(registry, owned_observation, publication_bytes)
        registry_guard = registry._open_mutation_lock()
        try:
            ledger_guard = ledger._open_lock()
            try:
                locked_registry = registry._verify_all_locked(
                    registry_guard, raise_on_error=True
                )
                locked_ledger = ledger._validate_bytes(
                    ledger._read_raw_locked(ledger_guard)
                )
                if (locked_registry, locked_ledger) != before or not locked_ledger.valid:
                    raise EvaluationContractAmendmentError(
                        "amendment sources changed before commit"
                    )
                _recheck_simulated_amendment_external(registry, before, current_guard)
                if observed_final_check is not None:
                    prospective = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard) + event_line)
                    if not prospective.valid or prospective.events != (*before[1].events, event):
                        raise EvaluationContractAmendmentError("observed amendment prospective event is invalid")
                    _observed_amendment_bookkeeping_capacity(registry, owned_observation, publication_bytes)
                    observed_final_check(before, registry_guard, ledger_guard)
                committed_authority = exact_existing_authority
                if committed_authority is None:
                    committed_authority = registry._put_bytes_locked(
                        registry_guard,
                        authority_raw,
                        logical_type=authority_record.logical_type,
                        origin=authority_record.origin,
                        creator_role=authority_record.creator_role,
                        creation_command=authority_record.creation_command,
                        parent_artifacts=authority_record.parent_artifacts,
                        schema_version=authority_record.schema_version,
                        mime_type=authority_record.mime_type,
                        validation_result=authority_record.validation_result,
                        frozen=authority_record.frozen,
                        created_at=authority_record.created_at,
                    )
                committed_child = exact_existing_child
                if committed_child is None:
                    committed_child = registry._put_bytes_locked(
                        registry_guard,
                        child_raw,
                        logical_type=child_record.logical_type,
                        origin=child_record.origin,
                        creator_role=child_record.creator_role,
                        creation_command=child_record.creation_command,
                        parent_artifacts=child_record.parent_artifacts,
                        schema_version=child_record.schema_version,
                        mime_type=child_record.mime_type,
                        validation_result=child_record.validation_result,
                        frozen=child_record.frozen,
                        created_at=child_record.created_at,
                    )
                if committed_authority != authority_record or committed_child != child_record:
                    raise EvaluationContractAmendmentError(
                        "amendment record pair changed during commit"
                    )

                def build(current: LedgerValidationResult) -> LedgerEvent:
                    if current != locked_ledger:
                        raise EvaluationContractAmendmentError(
                            "amendment ledger changed during commit"
                        )
                    return event

                appended = ledger._append_locked(ledger_guard, build)
                if appended != event:
                    raise EvaluationContractAmendmentError(
                        "amendment event changed during commit"
                    )
                registry._verify_mutation_namespace(registry_guard)
                final_registry = registry._verify_all_locked(
                    registry_guard, raise_on_error=True
                )
                final_ledger = ledger._validate_bytes(
                    ledger._read_raw_locked(ledger_guard)
                )
                expected_records = {record.sha256: record for record in before[0].records}
                expected_records[authority_record.sha256] = authority_record
                expected_records[child_record.sha256] = child_record
                if (
                    {record.sha256: record for record in final_registry.records}
                    != expected_records
                    or final_registry.count != before[0].count + records_needed
                    or not final_ledger.valid
                    or final_ledger.event_count != before[1].event_count + 1
                    or final_ledger.events[-1] != event
                ):
                    raise EvaluationContractAmendmentError(
                        "amendment commit changed outside its exact record/event delta"
                    )
                if observed_final_check is not None:
                    observed_final_check((final_registry, final_ledger), registry_guard, ledger_guard)
            finally:
                ledger._unlock(ledger_guard)
        finally:
            registry._unlock_mutation(registry_guard)
        publication = require_evaluation_contract_amendment(
            registry,
            ledger,
            amendment_artifact_sha256=authority_record.sha256,
            expected_run_id=run_id,
            expected_child_contract_artifact_sha256=child_record.sha256,
        )
        if publication.authority != authority:
            raise EvaluationContractAmendmentError(
                "amendment publication differs from full readback"
            )
        return publication


def _completed_child_publications_before(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    parent_record: ArtifactRecord,
    expected_run_id: str,
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
    design_event_index: int,
    complete_source_population: bool,
) -> tuple[EvaluationContractAmendmentPublication, ...]:
    publications = []
    for record, authority in _all_amendment_records(
        registry, registry_snapshot.records
    ):
        if authority.parent_contract_artifact_sha256 != parent_record.sha256:
            continue
        event_matches = _matching_events(
            ledger_snapshot.events,
            amendment_id=authority.amendment.amendment_id,
            parent_contract_artifact_sha256=parent_record.sha256,
            child_contract_artifact_sha256=(
                authority.child_contract_artifact_sha256
            ),
            amendment_artifact_sha256=record.sha256,
        )
        if not event_matches:
            if complete_source_population:
                raise EvaluationContractAmendmentError(
                    "current contract family contains an incomplete child amendment"
                )
            # A legacy historical design has no registry-population witness.
            # It can classify only admissions present in its owned event prefix;
            # a later A/A+C record must not retroactively poison that history.
            continue
        if len(event_matches) != 1:
            raise EvaluationContractAmendmentError(
                "contract child admission event is ambiguous"
            )
        lineage = _resolve_lineage(
            registry,
            ledger,
            contract_artifact_sha256=authority.child_contract_artifact_sha256,
            expected_run_id=expected_run_id,
            registry_snapshot=registry_snapshot,
            ledger_snapshot=ledger_snapshot,
        )
        match = next(
            item for item in lineage.publications if item.amendment_record == record
        )
        if match.event_index < design_event_index:
            publications.append(match)
    return tuple(publications)


def _require_no_completed_contract_successor_before(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    selected_record: ArtifactRecord,
    expected_run_id: str,
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
    design_event_index: int,
    complete_source_population: bool,
) -> None:
    """Keep the existing successor/incomplete-publication rule in one owner."""

    competing_children = _completed_child_publications_before(
        registry,
        ledger,
        parent_record=selected_record,
        expected_run_id=expected_run_id,
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
        design_event_index=design_event_index,
        complete_source_population=complete_source_population,
    )
    if competing_children:
        raise EvaluationContractAmendmentError(
            "selected contract was superseded before this design point"
        )


def _require_current_evaluation_contract_lineage(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_run_id: str,
    contract_artifact_sha256: str,
) -> EvaluationContractLineageReplay:
    """Read an exact lineage only if its selected contract is current now.

    Historical readability is not permission for new use. This companion reuses
    the design owner's complete successor rule without inventing a design or
    four experiment inputs. It grants no exposure, reserve, custody, execution
    or scientific authority. A future publisher must still compare the returned
    pair under its commit locks and independently validate those other inputs.
    """

    expected_run_id = _identifier(expected_run_id, "expected current-lineage run ID")
    _sha256(contract_artifact_sha256, "current contract artifact SHA-256")
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    lineage = _require_evaluation_contract_child_lineage(
        registry,
        ledger,
        expected_run_id=expected_run_id,
        contract_artifact_sha256=contract_artifact_sha256,
    )
    if (lineage.registry_snapshot, lineage.ledger_snapshot) != before:
        raise EvaluationContractAmendmentError(
            "current contract lineage changed during full readback"
        )
    _require_no_completed_contract_successor_before(
        registry,
        ledger,
        selected_record=lineage.contract_record,
        expected_run_id=expected_run_id,
        registry_snapshot=before[0],
        ledger_snapshot=before[1],
        design_event_index=before[1].event_count,
        complete_source_population=True,
    )
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        raise EvaluationContractAmendmentError(
            "current contract lineage changed during full readback"
        )
    return lineage


def _require_evaluation_contract_family_before_design(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_run_id: str,
    contract_artifact_sha256: str,
    input_artifact_sha256s: tuple[str, str, str, str],
    design_event_index: int,
    sealed_design_source_records: tuple[ArtifactRecord, ...] | None = None,
) -> EvaluationContractFamilyAdmission:
    """Reopen one complete family and exact prior visibility before design.

    This private hook records no state and grants no confirmatory reserve.  The
    caller must compare the returned paired snapshot under the registry-to-
    ledger commit locks before publishing DESIGN_FROZEN.
    """

    expected_run_id = _identifier(expected_run_id, "expected contract-family run ID")
    _sha256(contract_artifact_sha256, "contract-family artifact SHA-256")
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    if (
        type(design_event_index) is not int
        or not 0 <= design_event_index <= before[1].event_count
    ):
        raise EvaluationContractAmendmentError(
            "contract-family design event index is out of range"
        )
    if any(event.run_id != expected_run_id for event in before[1].events):
        raise EvaluationContractAmendmentError(
            "contract-family ledger names another run"
        )
    design_events = before[1].events[:design_event_index]
    design_ledger_snapshot = LedgerValidationResult(
        valid=True,
        events=design_events,
        head_hash=(design_events[-1].event_hash if design_events else None),
        valid_prefix_bytes=sum(
            len(canonical_json_bytes(event.to_dict())) + 1
            for event in design_events
        ),
    )
    if sealed_design_source_records is None:
        design_registry_snapshot = before[0]
    else:
        source_map = _registry_record_map(sealed_design_source_records)
        source_count, source_fingerprint = _registry_map_fingerprint(
            sealed_design_source_records
        )
        resolved_design_records = _require_registry_record_map(
            before[0].records,
            source_record_map=source_map,
            source_record_count=source_count,
            source_record_map_fingerprint=source_fingerprint,
        )
        if resolved_design_records != tuple(sorted(
            sealed_design_source_records,
            key=lambda record: record.sha256,
        )):
            raise EvaluationContractAmendmentError(
                "sealed design source records differ from live registry metadata"
            )
        design_registry_snapshot = RegistryValidationResult(
            valid=True,
            records=resolved_design_records,
        )
    complete_source_population = (
        sealed_design_source_records is not None
        or design_event_index == before[1].event_count
    )
    from .simulated_reserve import (
        SimulatedReserveError,
        reject_simulated_reserve_exposure,
    )

    try:
        reject_simulated_reserve_exposure(
            registry,
            design_registry_snapshot.records,
            design_ledger_snapshot.events,
            complete_registry_population=complete_source_population,
        )
    except SimulatedReserveError as exc:
        raise EvaluationContractAmendmentError(
            "simulated reservation or possible exposure cannot authorize scientific design"
        ) from exc
    lineage = _resolve_lineage(
        registry,
        ledger,
        contract_artifact_sha256=contract_artifact_sha256,
        expected_run_id=expected_run_id,
        registry_snapshot=design_registry_snapshot,
        ledger_snapshot=design_ledger_snapshot,
    )
    if (
        sealed_design_source_records is None
        and design_event_index != before[1].event_count
        and lineage.publications
    ):
        raise EvaluationContractAmendmentError(
            "historical amended contract requires a sealed design source map"
        )
    for publication in lineage.publications:
        if publication.event_index >= design_event_index:
            raise EvaluationContractAmendmentError(
                "amended contract was published only after the selected design point"
            )
    selected_record = lineage.contract_records[-1]
    _require_no_completed_contract_successor_before(
        registry,
        ledger,
        selected_record=selected_record,
        expected_run_id=expected_run_id,
        registry_snapshot=design_registry_snapshot,
        ledger_snapshot=design_ledger_snapshot,
        design_event_index=design_event_index,
        complete_source_population=complete_source_population,
    )
    input_binding = _input_binding(registry, input_artifact_sha256s)
    design_records_by_sha = {
        record.sha256: record for record in design_registry_snapshot.records
    }
    if any(
        digest not in design_records_by_sha
        or _record_hash(design_records_by_sha[digest]) != record_hash
        for digest, record_hash in zip(*input_binding)
    ):
        raise EvaluationContractAmendmentError(
            "sealed design population omits an exact contract-family input"
        )
    visible = _derive_visible_results(
        registry,
        design_registry_snapshot.records,
        design_ledger_snapshot.events,
        lineage_contract_records=lineage.contract_records,
        explicit_input_binding=input_binding,
        complete_current_registry=complete_source_population,
    )
    lineage_hashes = {record.sha256 for record in lineage.contract_records}
    if any(item.contract_artifact_sha256 not in lineage_hashes for item in visible):
        raise EvaluationContractAmendmentError(
            "visible same-input result belongs to a contract outside this lineage"
        )
    selected_publication = lineage.publications[-1] if lineage.publications else None
    if visible:
        if selected_publication is None:
            raise EvaluationContractAmendmentError(
                "result-visible input family requires persisted amendment lineage"
            )
        recorded = {
            item.output_manifest_artifact_sha256
            for item in selected_publication.authority.visible_results
        }
        current = {item.output_manifest_artifact_sha256 for item in visible}
        if recorded != current:
            raise EvaluationContractAmendmentError(
                "new result exposure occurred after the selected amendment"
            )
    after = _locked_checked_result_authority_snapshot(registry, ledger)
    if after != before:
        raise EvaluationContractAmendmentError(
            "contract-family sources changed during admission replay"
        )
    return EvaluationContractFamilyAdmission(
        contract_record=selected_record,
        contract=lineage.contracts[-1],
        lineage_contract_records=lineage.contract_records,
        lineage_amendment_records=tuple(
            item.amendment_record for item in lineage.publications
        ),
        selected_amendment_artifact_sha256=(
            selected_publication.amendment_record.sha256
            if selected_publication is not None
            else None
        ),
        exact_input_artifact_sha256s=input_binding[0],
        exact_input_artifact_record_hashes=input_binding[1],
        visible_ancestor_manifest_artifact_sha256s=tuple(
            item.output_manifest_artifact_sha256 for item in visible
        ),
        requires_new_confirmatory_reserve=bool(visible),
        confirmation_authorized=False,
        registry_snapshot=before[0],
        ledger_snapshot=before[1],
    )
