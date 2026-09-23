"""Persisted, non-authorizing scientific protocol revision lineage.

This module binds one exact next :class:`ResearchProtocol` to an already
published Evaluation Contract amendment.  It records prospective history only:
the record does not provide fresh data, custody, reserve, execution, result, or
confirmation authority.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime
import hashlib
from pathlib import Path
from typing import Any, Mapping

from .artifacts import (
    MAX_ARTIFACT_PARENTS,
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
    RegistryValidationResult,
)
from .errors import (
    ArtifactError,
    LedgerError,
    UnsafeSerializationError,
    ValidationError,
)
from .evaluation_contract_amendment import (
    EvaluationContractAmendmentError,
    EvaluationContractAmendmentPublication,
    _registry_map_fingerprint,
    _registry_record_map,
    _require_registry_record_map,
    require_evaluation_contract_amendment,
    _require_evaluation_contract_amendment_at_snapshot,
)
from .ledger import (
    MAX_LEDGER_BYTES,
    MAX_LEDGER_EVENTS,
    EventLedger,
    LedgerEvent,
    LedgerValidationResult,
)
from .models import utc_now, validate_identifier, validate_sha256
from .protocol import ResearchProtocol
from .roles import Role
from .scientific_design import (
    MAX_CHECKED_SUPERIORITY_BYTES,
    ScientificPromotionError,
    _locked_checked_result_authority_snapshot,
    _parse_scientific_confirmatory_protocol,
    _require_scientific_protocol_contract_crosswalk,
    _timeline_state,
)
from .security import canonical_json_bytes, safe_json_loads, sha256_bytes


SCIENTIFIC_PROTOCOL_REVISION_PAYLOAD_SCHEMA = "scientific-protocol-revision/v1"
SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA = "2.0"
SCIENTIFIC_PROTOCOL_REVISION_PROFILE_ID = "AMENDED_EVALUATION_CONTRACT_PROTOCOL"
SCIENTIFIC_PROTOCOL_REVISION_SCOPE = "PROSPECTIVE_PROTOCOL_REVISION_ONLY"
SCIENTIFIC_PROTOCOL_REVISION_EVENT_SCHEMA = "protocol-revision-event/v1"
SCIENTIFIC_PROTOCOL_REVISION_EVENT_KEY = "scientific_protocol_revision"

_LOGICAL_TYPE = "frozen_protocol"
_ORIGIN_PREFIX = "append-only scientific protocol revision"
_COMMAND = ("scientist-one", "record-scientific-protocol-revision")
_EVENT_REASON = (
    "recorded an exact next scientific protocol without confirmation authority"
)
_LEGACY_PROTOCOL_SCHEMA = "1.0"
_LEGACY_WRAPPER_KEYS = {
    "kind",
    "frozen",
    "protocol",
    "protocol_sha256",
    "baseline_equivalence",
    "blind_patterns",
    "reproduction_tolerance",
}
_PROTOCOL_CONTROLLER_FIELDS = frozenset(
    {"study_version", "parent_protocol_hash", "revision_reason"}
)
_PROTOCOL_FIELDS = frozenset(field.name for field in fields(ResearchProtocol))
_MAX_REVISION_BYTES = MAX_CHECKED_SUPERIORITY_BYTES
_MAX_REVISION_JSON_ITEMS = 100_000
_MAX_PROTOCOL_DEPTH = 64


class ScientificProtocolRevisionError(ScientificPromotionError):
    """One protocol revision publication is absent, malformed, or competing."""


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str:
        raise ScientificProtocolRevisionError(f"{label} must be native text")
    try:
        return validate_identifier(value, label)
    except ValidationError as exc:
        raise ScientificProtocolRevisionError(f"invalid {label}") from exc


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str:
        raise ScientificProtocolRevisionError(f"{label} must be native text")
    try:
        return validate_sha256(value, label)
    except ValidationError as exc:
        raise ScientificProtocolRevisionError(f"invalid {label}") from exc


def _text(value: Any, label: str, *, maximum: int = 8192) -> str:
    if type(value) is not str or not value.strip() or len(value) > maximum:
        raise ScientificProtocolRevisionError(
            f"{label} must be non-empty bounded native text"
        )
    return value


def _record_hash(record: ArtifactRecord) -> str:
    if type(record) is not ArtifactRecord or record.record_hash is None:
        raise ScientificProtocolRevisionError("protocol source record hash is absent")
    return _sha256(record.record_hash, "protocol source record hash")


def _utc(value: Any, label: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ScientificProtocolRevisionError(f"{label} must be UTC")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScientificProtocolRevisionError(f"{label} is malformed") from exc
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ScientificProtocolRevisionError(f"{label} must be UTC")
    return parsed


def _ledger_path(value: Any) -> str:
    value = _text(value, "protocol revision ledger path", maximum=1024)
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ScientificProtocolRevisionError(
            "protocol revision ledger path is not confined"
        )
    return path.as_posix()


def _protocol_changed_fields(
    parent: ResearchProtocol,
    child: ResearchProtocol,
) -> tuple[str, ...]:
    if type(parent) is not ResearchProtocol or type(child) is not ResearchProtocol:
        raise ScientificProtocolRevisionError(
            "protocol delta requires exact ResearchProtocol values"
        )
    parent_value = parent.canonical_dict
    child_value = child.canonical_dict
    return tuple(
        sorted(
            name
            for name in _PROTOCOL_FIELDS - _PROTOCOL_CONTROLLER_FIELDS
            if parent_value[name] != child_value[name]
        )
    )


def _require_canonical_protocol(
    protocol: ResearchProtocol,
    *,
    label: str,
) -> ResearchProtocol:
    """Re-run the complete native protocol constructor over bounded JSON."""

    if type(protocol) is not ResearchProtocol:
        raise ScientificProtocolRevisionError(
            f"{label} must be the exact ResearchProtocol type"
        )
    try:
        raw = canonical_json_bytes(protocol.canonical_dict)
        if not 0 < len(raw) <= _MAX_REVISION_BYTES:
            raise ScientificProtocolRevisionError(
                f"{label} exceeds the protocol byte bound"
            )
        value = safe_json_loads(
            raw,
            max_bytes=_MAX_REVISION_BYTES,
            max_items=_MAX_REVISION_JSON_ITEMS,
        )
        reparsed = _parse_scientific_confirmatory_protocol(value)
    except ScientificProtocolRevisionError:
        raise
    except (
        ScientificPromotionError,
        UnsafeSerializationError,
        ValidationError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise ScientificProtocolRevisionError(
            f"{label} is not a valid canonical ResearchProtocol"
        ) from exc
    if (
        reparsed != protocol
        or reparsed.sha256 != protocol.sha256
        or raw != canonical_json_bytes(reparsed.canonical_dict)
    ):
        raise ScientificProtocolRevisionError(
            f"{label} does not exactly round-trip through its canonical schema"
        )
    return reparsed


@dataclass(frozen=True, slots=True)
class ScientificProtocolRevisionAuthority:
    """Frozen protocol revision facts; never confirmation authority."""

    schema_version: str
    profile_id: str
    authority_scope: str
    ledger_run_id: str
    ledger_path: str
    recorded_at: str
    amendment_id: str
    amendment_artifact_sha256: str
    amendment_record_hash: str
    amendment_author_id: str
    amendment_reason: str
    amendment_changed_contract_fields: tuple[str, ...]
    parent_contract_artifact_sha256: str
    parent_contract_record_hash: str
    parent_contract_semantic_sha256: str
    child_contract_artifact_sha256: str
    child_contract_record_hash: str
    child_contract_semantic_sha256: str
    parent_protocol_artifact_sha256: str
    parent_protocol_record_hash: str
    parent_protocol_semantic_sha256: str
    protocol: ResearchProtocol
    protocol_semantic_sha256: str
    changed_protocol_fields: tuple[str, ...]
    results_seen_at_amendment: bool
    requires_new_confirmatory_reserve_at_amendment: bool
    source_ledger_event_count: int
    source_ledger_head_hash: str
    source_registry_record_identities: tuple[tuple[str, str], ...]
    source_registry_record_count: int
    source_registry_record_map_fingerprint: str
    confirmation_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            self.schema_version != SCIENTIFIC_PROTOCOL_REVISION_PAYLOAD_SCHEMA
            or self.profile_id != SCIENTIFIC_PROTOCOL_REVISION_PROFILE_ID
            or self.authority_scope != SCIENTIFIC_PROTOCOL_REVISION_SCOPE
            or self.confirmation_authorized is not False
        ):
            raise ScientificProtocolRevisionError(
                "protocol revision authority exceeds its closed prospective scope"
            )
        for name in (
            "ledger_run_id",
            "amendment_id",
            "amendment_author_id",
        ):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(self, "ledger_path", _ledger_path(self.ledger_path))
        _utc(self.recorded_at, "protocol revision recorded_at")
        _text(self.amendment_reason, "protocol revision amendment reason")
        for name in (
            "amendment_artifact_sha256",
            "amendment_record_hash",
            "parent_contract_artifact_sha256",
            "parent_contract_record_hash",
            "parent_contract_semantic_sha256",
            "child_contract_artifact_sha256",
            "child_contract_record_hash",
            "child_contract_semantic_sha256",
            "parent_protocol_artifact_sha256",
            "parent_protocol_record_hash",
            "parent_protocol_semantic_sha256",
            "protocol_semantic_sha256",
            "source_ledger_head_hash",
            "source_registry_record_map_fingerprint",
        ):
            _sha256(getattr(self, name), name)
        if type(self.protocol) is not ResearchProtocol:
            raise ScientificProtocolRevisionError(
                "protocol revision requires exact ResearchProtocol"
            )
        if self.protocol.sha256 != self.protocol_semantic_sha256:
            raise ScientificProtocolRevisionError(
                "protocol revision semantic hash differs from its protocol"
            )
        if (
            type(self.amendment_changed_contract_fields) is not tuple
            or any(type(item) is not str for item in self.amendment_changed_contract_fields)
            or self.amendment_changed_contract_fields
            != tuple(sorted(set(self.amendment_changed_contract_fields)))
            or not self.amendment_changed_contract_fields
        ):
            raise ScientificProtocolRevisionError(
                "protocol revision amendment field inventory is invalid"
            )
        if (
            type(self.changed_protocol_fields) is not tuple
            or any(
                type(item) is not str
                or item not in _PROTOCOL_FIELDS - _PROTOCOL_CONTROLLER_FIELDS
                for item in self.changed_protocol_fields
            )
            or self.changed_protocol_fields
            != tuple(sorted(set(self.changed_protocol_fields)))
        ):
            raise ScientificProtocolRevisionError(
                "protocol revision changed-field inventory is invalid"
            )
        if (
            type(self.results_seen_at_amendment) is not bool
            or type(self.requires_new_confirmatory_reserve_at_amendment) is not bool
            or self.results_seen_at_amendment
            != self.requires_new_confirmatory_reserve_at_amendment
        ):
            raise ScientificProtocolRevisionError(
                "protocol revision amendment-time exposure flags are invalid"
            )
        if (
            type(self.source_ledger_event_count) is not int
            or isinstance(self.source_ledger_event_count, bool)
            or not 1 <= self.source_ledger_event_count <= MAX_LEDGER_EVENTS
        ):
            raise ScientificProtocolRevisionError(
                "protocol revision source ledger count is invalid"
            )
        identities = self.source_registry_record_identities
        if (
            type(identities) is not tuple
            or not 1 <= len(identities) <= MAX_REGISTRY_RECORDS
            or any(
                type(identity) is not tuple
                or len(identity) != 2
                or type(identity[0]) is not str
                or type(identity[1]) is not str
                for identity in identities
            )
        ):
            raise ScientificProtocolRevisionError(
                "protocol revision sealed registry map is malformed"
            )
        for artifact_sha256, record_hash in identities:
            _sha256(artifact_sha256, "sealed protocol source artifact SHA-256")
            _sha256(record_hash, "sealed protocol source record hash")
        if (
            identities != tuple(sorted(identities))
            or len({identity[0] for identity in identities}) != len(identities)
            or type(self.source_registry_record_count) is not int
            or isinstance(self.source_registry_record_count, bool)
            or self.source_registry_record_count != len(identities)
            or self.source_registry_record_map_fingerprint
            != sha256_bytes(
                canonical_json_bytes([list(identity) for identity in identities])
            )
        ):
            raise ScientificProtocolRevisionError(
                "protocol revision sealed registry map differs from its count or fingerprint"
            )

    @property
    def direct_source_artifact_sha256s(self) -> tuple[str, str, str, str]:
        return (
            self.parent_protocol_artifact_sha256,
            self.parent_contract_artifact_sha256,
            self.child_contract_artifact_sha256,
            self.amendment_artifact_sha256,
        )

    @property
    def direct_source_record_hashes(self) -> tuple[str, str, str, str]:
        return (
            self.parent_protocol_record_hash,
            self.parent_contract_record_hash,
            self.child_contract_record_hash,
            self.amendment_record_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "authority_scope": self.authority_scope,
            "ledger_run_id": self.ledger_run_id,
            "ledger_path": self.ledger_path,
            "recorded_at": self.recorded_at,
            "amendment_id": self.amendment_id,
            "amendment_artifact_sha256": self.amendment_artifact_sha256,
            "amendment_record_hash": self.amendment_record_hash,
            "amendment_author_id": self.amendment_author_id,
            "amendment_reason": self.amendment_reason,
            "amendment_changed_contract_fields": list(
                self.amendment_changed_contract_fields
            ),
            "parent_contract_artifact_sha256": (
                self.parent_contract_artifact_sha256
            ),
            "parent_contract_record_hash": self.parent_contract_record_hash,
            "parent_contract_semantic_sha256": (
                self.parent_contract_semantic_sha256
            ),
            "child_contract_artifact_sha256": self.child_contract_artifact_sha256,
            "child_contract_record_hash": self.child_contract_record_hash,
            "child_contract_semantic_sha256": self.child_contract_semantic_sha256,
            "parent_protocol_artifact_sha256": (
                self.parent_protocol_artifact_sha256
            ),
            "parent_protocol_record_hash": self.parent_protocol_record_hash,
            "parent_protocol_semantic_sha256": (
                self.parent_protocol_semantic_sha256
            ),
            "protocol": self.protocol.canonical_dict,
            "protocol_semantic_sha256": self.protocol_semantic_sha256,
            "changed_protocol_fields": list(self.changed_protocol_fields),
            "results_seen_at_amendment": self.results_seen_at_amendment,
            "requires_new_confirmatory_reserve_at_amendment": (
                self.requires_new_confirmatory_reserve_at_amendment
            ),
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
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ScientificProtocolRevisionAuthority":
        expected = {field.name for field in fields(cls)}
        if type(value) is not dict or set(value) != expected:
            raise ScientificProtocolRevisionError(
                "protocol revision payload is incomplete or contains unknown fields"
            )
        try:
            protocol = _parse_scientific_confirmatory_protocol(value["protocol"])
            return cls(
                **{
                    **value,
                    "protocol": protocol,
                    "amendment_changed_contract_fields": tuple(
                        value["amendment_changed_contract_fields"]
                    ),
                    "changed_protocol_fields": tuple(value["changed_protocol_fields"]),
                    "source_registry_record_identities": tuple(
                        tuple(identity)
                        for identity in value["source_registry_record_identities"]
                    ),
                }
            )
        except ScientificProtocolRevisionError:
            raise
        except Exception as exc:
            raise ScientificProtocolRevisionError(
                "protocol revision payload is malformed"
            ) from exc

    def canonical_bytes(self) -> bytes:
        data = canonical_json_bytes(self.to_dict()) + b"\n"
        if not 0 < len(data) <= _MAX_REVISION_BYTES:
            raise ScientificProtocolRevisionError(
                "protocol revision payload exceeds its byte bound"
            )
        try:
            safe_json_loads(
                data,
                max_bytes=_MAX_REVISION_BYTES,
                max_items=_MAX_REVISION_JSON_ITEMS,
            )
        except (UnsafeSerializationError, ValidationError) as exc:
            raise ScientificProtocolRevisionError(
                "protocol revision payload exceeds its parser bound"
            ) from exc
        return data


@dataclass(frozen=True, slots=True)
class ScientificProtocolRevisionPublication:
    authority: ScientificProtocolRevisionAuthority
    protocol_record: ArtifactRecord
    protocol: ResearchProtocol
    parent_protocol_record: ArtifactRecord
    parent_protocol: ResearchProtocol
    amendment_publication: EvaluationContractAmendmentPublication
    event: LedgerEvent
    event_index: int


@dataclass(frozen=True, slots=True)
class _ProtocolDescriptor:
    record: ArtifactRecord
    protocol: ResearchProtocol
    publication: ScientificProtocolRevisionPublication | None


def _load_protocol_json(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
) -> tuple[bytes, dict[str, Any]]:
    if (
        type(record) is not ArtifactRecord
        or record.logical_type != _LOGICAL_TYPE
        or record.creator_role is not Role.PROTOCOL_DESIGNER
        or record.mime_type != "application/json"
        or record.validation_result != "PASS"
        or record.frozen is not True
        or not 0 < record.size <= _MAX_REVISION_BYTES
    ):
        raise ScientificProtocolRevisionError(
            "frozen protocol record metadata is invalid"
        )
    try:
        raw = registry.get_bytes(record.sha256)
        value = safe_json_loads(
            raw,
            max_bytes=_MAX_REVISION_BYTES,
            max_items=_MAX_REVISION_JSON_ITEMS,
        )
    except (ArtifactError, UnsafeSerializationError, ValidationError) as exc:
        raise ScientificProtocolRevisionError(
            "frozen protocol bytes are unavailable or malformed"
        ) from exc
    if type(value) is not dict:
        raise ScientificProtocolRevisionError("frozen protocol wrapper must be an object")
    if raw != canonical_json_bytes(value) + b"\n":
        raise ScientificProtocolRevisionError(
            "frozen protocol wrapper is not exact canonical JSON"
        )
    return raw, value


def _parse_legacy_protocol(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
) -> ResearchProtocol:
    _raw, value = _load_protocol_json(registry, record)
    if (
        record.schema_version != _LEGACY_PROTOCOL_SCHEMA
        or record.parent_artifacts
        or set(value) != _LEGACY_WRAPPER_KEYS
        or value.get("kind") != "FROZEN_SYNTHETIC_PROTOCOL"
        or value.get("frozen") is not True
        or type(value.get("protocol")) is not dict
    ):
        raise ScientificProtocolRevisionError(
            "legacy predecessor is not the exact parentless frozen protocol profile"
        )
    try:
        protocol = _parse_scientific_confirmatory_protocol(value["protocol"])
    except ScientificPromotionError as exc:
        raise ScientificProtocolRevisionError(
            "legacy predecessor protocol is malformed"
        ) from exc
    if value.get("protocol_sha256") != protocol.sha256:
        raise ScientificProtocolRevisionError(
            "legacy predecessor semantic hash is substituted"
        )
    return protocol


def _read_revision_authority(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
) -> ScientificProtocolRevisionAuthority:
    raw, value = _load_protocol_json(registry, record)
    if record.schema_version != SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA:
        raise ScientificProtocolRevisionError(
            "protocol revision artifact schema is unsupported"
        )
    authority = ScientificProtocolRevisionAuthority.from_dict(value)
    if raw != authority.canonical_bytes():
        raise ScientificProtocolRevisionError(
            "protocol revision wire differs from its canonical authority"
        )
    return authority


def _record_in_snapshot(
    snapshot: RegistryValidationResult,
    artifact_sha256: str,
) -> ArtifactRecord:
    matches = tuple(
        record for record in snapshot.records if record.sha256 == artifact_sha256
    )
    if len(matches) != 1:
        raise ScientificProtocolRevisionError(
            "protocol revision source is absent or ambiguous"
        )
    return matches[0]


def _source_ledger_prefix(
    snapshot: LedgerValidationResult,
    authority: ScientificProtocolRevisionAuthority,
) -> LedgerValidationResult:
    count = authority.source_ledger_event_count
    if len(snapshot.events) < count:
        raise ScientificProtocolRevisionError(
            "protocol revision source ledger prefix is missing"
        )
    events = snapshot.events[:count]
    head_hash = events[-1].event_hash if events else None
    if head_hash != authority.source_ledger_head_hash:
        raise ScientificProtocolRevisionError(
            "protocol revision source ledger head differs"
        )
    return LedgerValidationResult(
        valid=True,
        events=events,
        head_hash=head_hash,
        valid_prefix_bytes=sum(
            len(canonical_json_bytes(event.to_dict())) + 1 for event in events
        ),
    )


def _planned_record(
    registry: ArtifactRegistry,
    authority: ScientificProtocolRevisionAuthority,
) -> ArtifactRecord:
    data = authority.canonical_bytes()
    digest = hashlib.sha256(data).hexdigest()
    return ArtifactRecord(
        sha256=digest,
        path=registry._object_relative(digest).as_posix(),
        relative_path=registry._object_relative(digest).as_posix(),
        metadata_path=registry._metadata_relative(digest).as_posix(),
        logical_type=_LOGICAL_TYPE,
        schema_version=SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA,
        mime_type="application/json",
        size=len(data),
        origin=(
            f"{_ORIGIN_PREFIX} "
            f"{authority.protocol.study_id}:{authority.protocol.study_version}"
        ),
        creator_role=Role.PROTOCOL_DESIGNER,
        creation_command=_COMMAND,
        parent_artifacts=authority.direct_source_artifact_sha256s,
        validation_result="PASS",
        frozen=True,
        created_at=authority.recorded_at,
    )


def _protocol_slot(
    run_id: str,
    protocol: ResearchProtocol,
) -> tuple[str, str, int]:
    return run_id, protocol.study_id, protocol.study_version


def _protocol_hint(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
) -> tuple[str | None, int | None, str | None] | None:
    if (
        record.logical_type != _LOGICAL_TYPE
        or not 0 < record.size <= _MAX_REVISION_BYTES
    ):
        return None
    # Ownership selection precedes metadata validation: a wrong MIME label
    # cannot hide an explicit semantic output identity in bounded JSON bytes.
    # Selected records still undergo full canonical/metadata validation below.
    try:
        value = safe_json_loads(
            registry.get_bytes(record.sha256),
            max_bytes=_MAX_REVISION_BYTES,
            max_items=_MAX_REVISION_JSON_ITEMS,
        )
    except (ArtifactError, UnsafeSerializationError, ValidationError):
        return None
    if type(value) is not dict:
        return None
    semantic_sha256 = value.get("protocol_semantic_sha256")
    if type(semantic_sha256) is not str:
        semantic_sha256 = None
    protocol = value.get("protocol")
    if type(protocol) is not dict:
        return None, None, semantic_sha256
    study_id = protocol.get("study_id")
    version = protocol.get("study_version")
    if type(study_id) is not str:
        study_id = None
    if type(version) is not int or isinstance(version, bool):
        version = None
    return study_id, version, semantic_sha256


def _related_malformed_record(
    record: ArtifactRecord,
    *,
    authority: ScientificProtocolRevisionAuthority,
    protocol_semantic_hint: str | None,
) -> bool:
    parents = set(record.parent_artifacts)
    same_lineage_core = {
        authority.parent_protocol_artifact_sha256,
        authority.child_contract_artifact_sha256,
        authority.amendment_artifact_sha256,
    }
    return (
        record.logical_type == _LOGICAL_TYPE
        and (
            record.parent_artifacts == authority.direct_source_artifact_sha256s
            or same_lineage_core.issubset(parents)
            or record.origin
            == f"{_ORIGIN_PREFIX} {authority.protocol.study_id}:{authority.protocol.study_version}"
            or protocol_semantic_hint == authority.protocol_semantic_sha256
        )
    )


def _slot_records(
    registry: ArtifactRegistry,
    snapshot: RegistryValidationResult,
    *,
    authority: ScientificProtocolRevisionAuthority,
) -> tuple[ArtifactRecord, ...]:
    expected_hint = (authority.protocol.study_id, authority.protocol.study_version)
    result: list[ArtifactRecord] = []
    for record in snapshot.records:
        if record.logical_type != _LOGICAL_TYPE:
            continue
        hint = _protocol_hint(registry, record)
        semantic_hint = hint[2] if hint is not None else None
        related = _related_malformed_record(
            record,
            authority=authority,
            protocol_semantic_hint=semantic_hint,
        )
        if hint is None or hint[:2] != expected_hint:
            if related:
                raise ScientificProtocolRevisionError(
                    "related protocol revision slot record is malformed"
                )
            continue
        # A same study/version protocol is a shared-slot candidate regardless
        # of whether it is legacy or revised.
        if record.schema_version == SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA:
            _read_revision_authority(registry, record)
        else:
            _parse_legacy_protocol(registry, record)
        result.append(record)
    return tuple(result)


def _event_binding(
    authority: ScientificProtocolRevisionAuthority,
    record: ArtifactRecord,
) -> dict[str, Any]:
    return {
        "schema_version": SCIENTIFIC_PROTOCOL_REVISION_EVENT_SCHEMA,
        "profile_id": SCIENTIFIC_PROTOCOL_REVISION_PROFILE_ID,
        "authority_scope": SCIENTIFIC_PROTOCOL_REVISION_SCOPE,
        "ledger_run_id": authority.ledger_run_id,
        "study_id": authority.protocol.study_id,
        "study_version": authority.protocol.study_version,
        "protocol_artifact_sha256": record.sha256,
        "protocol_record_hash": _record_hash(record),
        "protocol_semantic_sha256": authority.protocol_semantic_sha256,
        "parent_protocol_artifact_sha256": (
            authority.parent_protocol_artifact_sha256
        ),
        "parent_protocol_record_hash": authority.parent_protocol_record_hash,
        "parent_protocol_semantic_sha256": (
            authority.parent_protocol_semantic_sha256
        ),
        "parent_contract_artifact_sha256": (
            authority.parent_contract_artifact_sha256
        ),
        "parent_contract_record_hash": authority.parent_contract_record_hash,
        "child_contract_artifact_sha256": authority.child_contract_artifact_sha256,
        "child_contract_record_hash": authority.child_contract_record_hash,
        "amendment_artifact_sha256": authority.amendment_artifact_sha256,
        "amendment_record_hash": authority.amendment_record_hash,
        "amendment_id": authority.amendment_id,
        "results_seen_at_amendment": authority.results_seen_at_amendment,
        "requires_new_confirmatory_reserve_at_amendment": (
            authority.requires_new_confirmatory_reserve_at_amendment
        ),
        "source_ledger_event_count": authority.source_ledger_event_count,
        "source_ledger_head_hash": authority.source_ledger_head_hash,
        "confirmation_authorized": False,
    }


def _event_id(authority: ScientificProtocolRevisionAuthority) -> str:
    slot = {
        "run_id": authority.ledger_run_id,
        "study_id": authority.protocol.study_id,
        "study_version": authority.protocol.study_version,
    }
    return "evt-scientific-protocol-revision-" + sha256_bytes(
        canonical_json_bytes(slot)
    )[:24]


def _build_event(
    authority: ScientificProtocolRevisionAuthority,
    record: ArtifactRecord,
    source: LedgerValidationResult,
) -> LedgerEvent:
    return LedgerEvent.create(
        run_id=authority.ledger_run_id,
        event_id=_event_id(authority),
        timestamp=authority.recorded_at,
        actor_role=Role.PROTOCOL_DESIGNER,
        state_before=_timeline_state(source.events),
        requested_state_after=_timeline_state(source.events),
        artifact_hashes=(record.sha256,),
        code_version=f"sha256:{authority.parent_protocol_artifact_sha256}",
        configuration_hash=authority.child_contract_semantic_sha256,
        dataset_identifiers=(),
        random_seeds=authority.protocol.seed_policy.seeds,
        evaluator_outputs=(),
        reason=_EVENT_REASON,
        prior_event_hash=source.head_hash,
        event_type="CHECKPOINT",
        metadata={
            "artifact_types": [_LOGICAL_TYPE],
            "artifact_record_hashes": [_record_hash(record)],
            SCIENTIFIC_PROTOCOL_REVISION_EVENT_KEY: _event_binding(
                authority, record
            ),
        },
    )


def _event_slot_hint(raw: Any) -> tuple[str, str, int] | None:
    if not isinstance(raw, Mapping):
        return None
    run_id = raw.get("ledger_run_id")
    study_id = raw.get("study_id")
    version = raw.get("study_version")
    if (
        type(run_id) is not str
        or type(study_id) is not str
        or type(version) is not int
        or isinstance(version, bool)
    ):
        return None
    return run_id, study_id, version


def _matching_events(
    events: tuple[LedgerEvent, ...],
    *,
    authority: ScientificProtocolRevisionAuthority,
    record: ArtifactRecord | None,
) -> tuple[tuple[int, LedgerEvent], ...]:
    expected = _protocol_slot(authority.ledger_run_id, authority.protocol)
    expected_event_id = _event_id(authority)
    # A predecessor's own publication event legitimately references the
    # predecessor protocol, which is a direct source of this next revision.
    # The candidate output identities (not predecessor identities), or this
    # slot's deterministic event ID, identify renamed publication attempts.
    related_hashes = {record.sha256} if record is not None else set()
    matches: list[tuple[int, LedgerEvent]] = []
    for index, event in enumerate(events):
        if SCIENTIFIC_PROTOCOL_REVISION_EVENT_KEY not in event.metadata:
            if event.event_id == expected_event_id:
                raise ScientificProtocolRevisionError(
                    "protocol revision event ID is present without its typed binding"
                )
            continue
        raw = event.metadata[SCIENTIFIC_PROTOCOL_REVISION_EVENT_KEY]
        hint = _event_slot_hint(raw)
        references_related = bool(
            related_hashes.intersection(event.artifact_hashes)
        )
        binding_names_output = bool(
            isinstance(raw, Mapping)
            and (
                raw.get("protocol_semantic_sha256")
                == authority.protocol_semantic_sha256
                or (
                    record is not None
                    and (
                        raw.get("protocol_artifact_sha256") == record.sha256
                        or raw.get("protocol_record_hash") == _record_hash(record)
                    )
                )
            )
        )
        if (
            hint != expected
            and not references_related
            and not binding_names_output
            and event.event_id != expected_event_id
        ):
            continue
        if not isinstance(raw, Mapping):
            raise ScientificProtocolRevisionError(
                "protocol revision event binding is malformed"
            )
        matches.append((index, event))
    return tuple(matches)


def _source_records(
    snapshot: RegistryValidationResult,
    authority: ScientificProtocolRevisionAuthority,
) -> tuple[ArtifactRecord, ...]:
    try:
        return _require_registry_record_map(
            snapshot.records,
            source_record_map=authority.source_registry_record_identities,
            source_record_count=authority.source_registry_record_count,
            source_record_map_fingerprint=(
                authority.source_registry_record_map_fingerprint
            ),
        )
    except EvaluationContractAmendmentError as exc:
        raise ScientificProtocolRevisionError(
            "protocol revision sealed registry population is invalid"
        ) from exc


def _source_record(
    source_records: tuple[ArtifactRecord, ...],
    artifact_sha256: str,
    record_hash: str,
) -> ArtifactRecord:
    matches = tuple(
        record
        for record in source_records
        if record.sha256 == artifact_sha256 and _record_hash(record) == record_hash
    )
    if len(matches) != 1:
        raise ScientificProtocolRevisionError(
            "protocol revision sealed source identity is absent or substituted"
        )
    return matches[0]


def _full_amendment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    authority: ScientificProtocolRevisionAuthority,
    source: LedgerValidationResult,
    *,
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
    require_snapshot_local_dependencies: bool,
) -> EvaluationContractAmendmentPublication:
    try:
        publication = _require_evaluation_contract_amendment_at_snapshot(
            registry,
            ledger,
            registry_snapshot=registry_snapshot,
            ledger_snapshot=ledger_snapshot,
            require_snapshot_local_dependencies=require_snapshot_local_dependencies,
            amendment_artifact_sha256=authority.amendment_artifact_sha256,
            expected_run_id=authority.ledger_run_id,
            expected_child_contract_artifact_sha256=(
                authority.child_contract_artifact_sha256
            ),
        )
    except (EvaluationContractAmendmentError, ArtifactError, LedgerError) as exc:
        raise ScientificProtocolRevisionError(
            "protocol revision amendment source is invalid"
        ) from exc
    amendment = publication.authority.amendment
    if (
        publication.amendment_record.sha256
        != authority.amendment_artifact_sha256
        or _record_hash(publication.amendment_record)
        != authority.amendment_record_hash
        or publication.parent_contract_record.sha256
        != authority.parent_contract_artifact_sha256
        or _record_hash(publication.parent_contract_record)
        != authority.parent_contract_record_hash
        or publication.parent_contract.sha256
        != authority.parent_contract_semantic_sha256
        or publication.contract_record.sha256
        != authority.child_contract_artifact_sha256
        or _record_hash(publication.contract_record)
        != authority.child_contract_record_hash
        or publication.child_contract.sha256
        != authority.child_contract_semantic_sha256
        or amendment.amendment_id != authority.amendment_id
        or amendment.author_id != authority.amendment_author_id
        or amendment.reason != authority.amendment_reason
        or amendment.changed_fields
        != authority.amendment_changed_contract_fields
        or amendment.results_already_seen != authority.results_seen_at_amendment
        or amendment.requires_new_confirmatory_reserve
        != authority.requires_new_confirmatory_reserve_at_amendment
        or not 0 <= publication.event_index < len(source.events)
        or source.events[publication.event_index] != publication.event
    ):
        raise ScientificProtocolRevisionError(
            "protocol revision differs from its exact amendment source"
        )
    return publication


def _validate_protocol_pair(
    authority: ScientificProtocolRevisionAuthority,
    parent_protocol: ResearchProtocol,
    amendment: EvaluationContractAmendmentPublication,
    *,
    parent_publication: ScientificProtocolRevisionPublication | None,
) -> None:
    protocol = authority.protocol
    if (
        parent_protocol.sha256 != authority.parent_protocol_semantic_sha256
        or protocol.study_id != parent_protocol.study_id
        or protocol.study_version != parent_protocol.study_version + 1
        or protocol.parent_protocol_hash != parent_protocol.sha256
        or protocol.revision_reason != amendment.authority.amendment.reason
        or _protocol_changed_fields(parent_protocol, protocol)
        != authority.changed_protocol_fields
    ):
        raise ScientificProtocolRevisionError(
            "protocol revision does not exactly extend its predecessor and amendment"
        )
    if parent_publication is not None and (
        parent_publication.amendment_publication.contract_record
        != amendment.parent_contract_record
        or parent_publication.amendment_publication.child_contract
        != amendment.parent_contract
    ):
        raise ScientificProtocolRevisionError(
            "protocol revision crosses an unrelated Evaluation Contract family"
        )
    try:
        _require_scientific_protocol_contract_crosswalk(
            parent_protocol, amendment.parent_contract
        )
        _require_scientific_protocol_contract_crosswalk(
            protocol, amendment.child_contract
        )
    except ScientificPromotionError as exc:
        raise ScientificProtocolRevisionError(
            "protocol revision contract crosswalk is invalid"
        ) from exc


def _require_protocol_publication_chronology(
    authority: ScientificProtocolRevisionAuthority,
    *,
    parent_protocol_record: ArtifactRecord,
    parent_publication: ScientificProtocolRevisionPublication | None,
    amendment: EvaluationContractAmendmentPublication,
    source: LedgerValidationResult,
) -> None:
    """Require every fixed publication source to precede the new record.

    This pure check is used both before the first write and during full static
    replay.  Record-only recovery therefore reuses the orphan's native
    timestamp rather than inventing a later timestamp that could hide drift.
    """

    if (
        parent_publication is not None
        and parent_publication.event_index >= amendment.event_index
    ):
        raise ScientificProtocolRevisionError(
            "protocol predecessor was published only after its contract amendment"
        )
    publication_time = _utc(
        authority.recorded_at, "protocol revision publication timestamp"
    )
    if any(
        _utc(source_record.created_at, "protocol revision source timestamp")
        > publication_time
        for source_record in (
            parent_protocol_record,
            amendment.parent_contract_record,
            amendment.contract_record,
            amendment.amendment_record,
        )
    ) or any(
        _utc(event.timestamp, "protocol revision source event timestamp")
        > publication_time
        for event in source.events
    ):
        raise ScientificProtocolRevisionError(
            "protocol revision publication predates one of its exact sources"
        )


def _resolve_protocol_descriptor(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    record: ArtifactRecord,
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
    visited: frozenset[str],
    require_snapshot_local_dependencies: bool = False,
) -> _ProtocolDescriptor:
    if len(visited) >= _MAX_PROTOCOL_DEPTH or record.sha256 in visited:
        raise ScientificProtocolRevisionError(
            "protocol revision lineage is cyclic or exceeds its depth bound"
        )
    _raw, value = _load_protocol_json(registry, record)
    if value.get("schema_version") == SCIENTIFIC_PROTOCOL_REVISION_PAYLOAD_SCHEMA:
        publication = _validate_publication_at_snapshot(
            registry,
            ledger,
            record=record,
            registry_snapshot=registry_snapshot,
            ledger_snapshot=ledger_snapshot,
            visited=visited | {record.sha256},
            require_snapshot_local_dependencies=require_snapshot_local_dependencies,
        )
        return _ProtocolDescriptor(record, publication.protocol, publication)
    protocol = _parse_legacy_protocol(registry, record)
    return _ProtocolDescriptor(record, protocol, None)


def _validate_publication_at_snapshot(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    record: ArtifactRecord,
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
    visited: frozenset[str] = frozenset(),
    require_snapshot_local_dependencies: bool = False,
) -> ScientificProtocolRevisionPublication:
    authority = _read_revision_authority(registry, record)
    if (
        authority.ledger_path != ledger.relative_path.as_posix()
        or authority.ledger_run_id == ""
        or any(
            event.run_id != authority.ledger_run_id
            for event in ledger_snapshot.events
        )
        or record != _planned_record(registry, authority)
        or record.parent_artifacts != authority.direct_source_artifact_sha256s
    ):
        raise ScientificProtocolRevisionError(
            "protocol revision record metadata or ledger path is substituted"
        )
    source_records = _source_records(registry_snapshot, authority)
    source = _source_ledger_prefix(ledger_snapshot, authority)
    parent_protocol_record = _source_record(
        source_records,
        authority.parent_protocol_artifact_sha256,
        authority.parent_protocol_record_hash,
    )
    _source_record(
        source_records,
        authority.parent_contract_artifact_sha256,
        authority.parent_contract_record_hash,
    )
    _source_record(
        source_records,
        authority.child_contract_artifact_sha256,
        authority.child_contract_record_hash,
    )
    _source_record(
        source_records,
        authority.amendment_artifact_sha256,
        authority.amendment_record_hash,
    )
    parent_descriptor = _resolve_protocol_descriptor(
        registry,
        ledger,
        record=parent_protocol_record,
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
        visited=visited,
        require_snapshot_local_dependencies=require_snapshot_local_dependencies,
    )
    amendment = _full_amendment(
        registry,
        ledger,
        authority,
        source,
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
        require_snapshot_local_dependencies=require_snapshot_local_dependencies,
    )
    if (
        (
            parent_protocol_record.sha256,
            _record_hash(parent_protocol_record),
        )
        not in amendment.authority.source_registry_record_identities
    ):
        raise ScientificProtocolRevisionError(
            "protocol predecessor was not in the amendment's sealed source population"
        )
    _validate_protocol_pair(
        authority,
        parent_descriptor.protocol,
        amendment,
        parent_publication=parent_descriptor.publication,
    )
    _require_protocol_publication_chronology(
        authority,
        parent_protocol_record=parent_protocol_record,
        parent_publication=parent_descriptor.publication,
        amendment=amendment,
        source=source,
    )
    events = _matching_events(
        ledger_snapshot.events,
        authority=authority,
        record=record,
    )
    if len(events) != 1:
        raise ScientificProtocolRevisionError(
            "protocol revision requires one exact publication event"
        )
    event_index, event = events[0]
    if (
        event_index != authority.source_ledger_event_count
        or event != _build_event(authority, record, source)
        or any(
            later.event_type == "CORRECTION"
            and later.supersedes_event_id == event.event_id
            for later in ledger_snapshot.events[event_index + 1 :]
        )
    ):
        raise ScientificProtocolRevisionError(
            "protocol revision publication event is stale or corrected"
        )
    slots = _slot_records(registry, registry_snapshot, authority=authority)
    if slots != (record,):
        raise ScientificProtocolRevisionError(
            "protocol revision study/version slot is competing or ambiguous"
        )
    return ScientificProtocolRevisionPublication(
        authority=authority,
        protocol_record=record,
        protocol=authority.protocol,
        parent_protocol_record=parent_protocol_record,
        parent_protocol=parent_descriptor.protocol,
        amendment_publication=amendment,
        event=event,
        event_index=event_index,
    )


def _authority_from_sources(
    *,
    expected_run_id: str,
    ledger: EventLedger,
    recorded_at: str,
    amendment: EvaluationContractAmendmentPublication,
    parent_protocol_record: ArtifactRecord,
    parent_protocol: ResearchProtocol,
    protocol: ResearchProtocol,
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
) -> ScientificProtocolRevisionAuthority:
    amendment_value = amendment.authority.amendment
    if ledger_snapshot.head_hash is None or ledger_snapshot.event_count < 1:
        raise ScientificProtocolRevisionError(
            "protocol revision requires a non-empty amendment ledger prefix"
        )
    source_count, source_fingerprint = _registry_map_fingerprint(
        registry_snapshot.records
    )
    return ScientificProtocolRevisionAuthority(
        schema_version=SCIENTIFIC_PROTOCOL_REVISION_PAYLOAD_SCHEMA,
        profile_id=SCIENTIFIC_PROTOCOL_REVISION_PROFILE_ID,
        authority_scope=SCIENTIFIC_PROTOCOL_REVISION_SCOPE,
        ledger_run_id=expected_run_id,
        ledger_path=ledger.relative_path.as_posix(),
        recorded_at=recorded_at,
        amendment_id=amendment_value.amendment_id,
        amendment_artifact_sha256=amendment.amendment_record.sha256,
        amendment_record_hash=_record_hash(amendment.amendment_record),
        amendment_author_id=amendment_value.author_id,
        amendment_reason=amendment_value.reason,
        amendment_changed_contract_fields=amendment_value.changed_fields,
        parent_contract_artifact_sha256=amendment.parent_contract_record.sha256,
        parent_contract_record_hash=_record_hash(amendment.parent_contract_record),
        parent_contract_semantic_sha256=amendment.parent_contract.sha256,
        child_contract_artifact_sha256=amendment.contract_record.sha256,
        child_contract_record_hash=_record_hash(amendment.contract_record),
        child_contract_semantic_sha256=amendment.child_contract.sha256,
        parent_protocol_artifact_sha256=parent_protocol_record.sha256,
        parent_protocol_record_hash=_record_hash(parent_protocol_record),
        parent_protocol_semantic_sha256=parent_protocol.sha256,
        protocol=protocol,
        protocol_semantic_sha256=protocol.sha256,
        changed_protocol_fields=_protocol_changed_fields(parent_protocol, protocol),
        results_seen_at_amendment=amendment_value.results_already_seen,
        requires_new_confirmatory_reserve_at_amendment=(
            amendment_value.requires_new_confirmatory_reserve
        ),
        source_ledger_event_count=ledger_snapshot.event_count,
        source_ledger_head_hash=ledger_snapshot.head_hash,
        source_registry_record_identities=_registry_record_map(
            registry_snapshot.records
        ),
        source_registry_record_count=source_count,
        source_registry_record_map_fingerprint=source_fingerprint,
        confirmation_authorized=False,
    )


def register_scientific_protocol_revision(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_run_id: str,
    amendment_artifact_sha256: str,
    parent_protocol_artifact_sha256: str,
    protocol: ResearchProtocol,
) -> ScientificProtocolRevisionPublication:
    """Atomically publish one exact next protocol linked to a real amendment."""

    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ScientificProtocolRevisionError(
            "protocol revision registration requires exact registry and ledger"
        )
    if registry.policy.root != ledger.policy.root:
        raise ScientificProtocolRevisionError(
            "protocol revision registry and ledger roots differ"
        )
    expected_run_id = _identifier(expected_run_id, "protocol revision run ID")
    _sha256(amendment_artifact_sha256, "amendment artifact SHA-256")
    _sha256(parent_protocol_artifact_sha256, "parent protocol artifact SHA-256")
    if type(protocol) is not ResearchProtocol:
        raise ScientificProtocolRevisionError(
            "protocol revision requires exact ResearchProtocol"
        )
    protocol = _require_canonical_protocol(
        protocol, label="protocol revision candidate"
    )
    before = _locked_checked_result_authority_snapshot(
        registry, ledger, ensure_storage=True
    )
    if any(event.run_id != expected_run_id for event in before[1].events):
        raise ScientificProtocolRevisionError(
            "protocol revision ledger contains another run"
        )
    try:
        amendment = require_evaluation_contract_amendment(
            registry,
            ledger,
            amendment_artifact_sha256=amendment_artifact_sha256,
            expected_run_id=expected_run_id,
        )
    except (EvaluationContractAmendmentError, ArtifactError, LedgerError) as exc:
        raise ScientificProtocolRevisionError(
            "protocol revision requires one full persisted amendment"
        ) from exc
    parent_protocol_record = _record_in_snapshot(
        before[0], parent_protocol_artifact_sha256
    )
    parent_descriptor = _resolve_protocol_descriptor(
        registry,
        ledger,
        record=parent_protocol_record,
        registry_snapshot=before[0],
        ledger_snapshot=before[1],
        visited=frozenset(),
    )
    if (
        parent_protocol_record.sha256,
        _record_hash(parent_protocol_record),
    ) not in amendment.authority.source_registry_record_identities:
        raise ScientificProtocolRevisionError(
            "protocol predecessor was not frozen before the amendment"
        )
    candidate = _authority_from_sources(
        expected_run_id=expected_run_id,
        ledger=ledger,
        recorded_at=utc_now(),
        amendment=amendment,
        parent_protocol_record=parent_protocol_record,
        parent_protocol=parent_descriptor.protocol,
        protocol=protocol,
        registry_snapshot=before[0],
        ledger_snapshot=before[1],
    )
    _validate_protocol_pair(
        candidate,
        parent_descriptor.protocol,
        amendment,
        parent_publication=parent_descriptor.publication,
    )
    slots = _slot_records(registry, before[0], authority=candidate)
    existing: ArtifactRecord | None = None
    if slots:
        if len(slots) != 1:
            raise ScientificProtocolRevisionError(
                "protocol revision study/version slot is ambiguous"
            )
        existing = slots[0]
        if existing.schema_version != SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA:
            raise ScientificProtocolRevisionError(
                "protocol revision study/version slot is occupied"
            )
        existing_authority = _read_revision_authority(registry, existing)
        completed = _matching_events(
            before[1].events,
            authority=existing_authority,
            record=existing,
        )
        if completed:
            publication = require_scientific_protocol_revision(
                registry,
                ledger,
                expected_run_id=expected_run_id,
                protocol_artifact_sha256=existing.sha256,
                expected_amendment_artifact_sha256=amendment_artifact_sha256,
            )
            if (
                publication.authority.protocol != protocol
                or publication.parent_protocol_record != parent_protocol_record
            ):
                raise ScientificProtocolRevisionError(
                    "completed protocol revision slot belongs to another request"
                )
            return publication
        # Exact record-only recovery must use its native timestamp and sealed
        # source population; a newly built candidate cannot overwrite history.
        candidate = _authority_from_sources(
            expected_run_id=expected_run_id,
            ledger=ledger,
            recorded_at=existing_authority.recorded_at,
            amendment=amendment,
            parent_protocol_record=parent_protocol_record,
            parent_protocol=parent_descriptor.protocol,
            protocol=protocol,
            registry_snapshot=RegistryValidationResult(
                valid=True,
                records=tuple(
                    record
                    for record in before[0].records
                    if record.sha256 != existing.sha256
                ),
            ),
            ledger_snapshot=before[1],
        )
        if candidate != existing_authority or _planned_record(registry, candidate) != existing:
            raise ScientificProtocolRevisionError(
                "incomplete protocol revision differs from exact recovery sources"
            )
        if (
            _registry_record_map(
                tuple(
                    record
                    for record in before[0].records
                    if record.sha256 != existing.sha256
                )
            )
            != existing_authority.source_registry_record_identities
            or before[1].event_count
            != existing_authority.source_ledger_event_count
            or before[1].head_hash != existing_authority.source_ledger_head_hash
        ):
            raise ScientificProtocolRevisionError(
                "incomplete protocol revision cannot recover after source drift"
            )
    candidate_source = _source_ledger_prefix(before[1], candidate)
    _require_protocol_publication_chronology(
        candidate,
        parent_protocol_record=parent_protocol_record,
        parent_publication=parent_descriptor.publication,
        amendment=amendment,
        source=candidate_source,
    )
    planned = _planned_record(registry, candidate)
    if existing is not None and existing != planned:
        raise ScientificProtocolRevisionError(
            "protocol revision orphan metadata differs from preflight"
        )
    events = _matching_events(before[1].events, authority=candidate, record=planned)
    if events:
        raise ScientificProtocolRevisionError(
            "protocol revision event exists without its exact complete record"
        )
    missing_record = int(existing is None)
    if before[0].count + missing_record > MAX_REGISTRY_RECORDS:
        raise ScientificProtocolRevisionError(
            "protocol revision registry capacity is insufficient"
        )
    if before[1].event_count + 1 > MAX_LEDGER_EVENTS:
        raise ScientificProtocolRevisionError(
            "protocol revision ledger event capacity is insufficient"
        )
    if len(planned.parent_artifacts) != 4 or len(planned.parent_artifacts) > MAX_ARTIFACT_PARENTS:
        raise ScientificProtocolRevisionError(
            "protocol revision direct source closure is invalid"
        )
    event = _build_event(candidate, planned, before[1])
    event_line = canonical_json_bytes(event.to_dict()) + b"\n"
    if before[1].valid_prefix_bytes + len(event_line) > MAX_LEDGER_BYTES:
        raise ScientificProtocolRevisionError(
            "protocol revision ledger byte capacity is insufficient"
        )
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        raise ScientificProtocolRevisionError(
            "protocol revision sources changed during preflight"
        )
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
                raise ScientificProtocolRevisionError(
                    "protocol revision sources changed before commit"
                )
            committed = existing
            if committed is None:
                committed = registry._put_bytes_locked(
                    registry_guard,
                    candidate.canonical_bytes(),
                    logical_type=planned.logical_type,
                    origin=planned.origin,
                    creator_role=planned.creator_role,
                    creation_command=planned.creation_command,
                    parent_artifacts=planned.parent_artifacts,
                    schema_version=planned.schema_version,
                    mime_type=planned.mime_type,
                    validation_result=planned.validation_result,
                    frozen=planned.frozen,
                    created_at=planned.created_at,
                )
            if committed != planned:
                raise ScientificProtocolRevisionError(
                    "protocol revision commit produced another record identity"
                )

            def build(current: LedgerValidationResult) -> LedgerEvent:
                if current != locked_ledger:
                    raise ScientificProtocolRevisionError(
                        "protocol revision ledger changed during commit"
                    )
                return event

            committed_event = ledger._append_locked(ledger_guard, build)
            committed_registry = registry._verify_all_locked(
                registry_guard, raise_on_error=True
            )
            committed_ledger = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            if (
                committed_registry.count != before[0].count + missing_record
                or committed_ledger.event_count != before[1].event_count + 1
                or committed_event != event
            ):
                raise ScientificProtocolRevisionError(
                    "protocol revision publication commit is incomplete"
                )
            registry._verify_mutation_namespace(registry_guard)
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    return require_scientific_protocol_revision(
        registry,
        ledger,
        expected_run_id=expected_run_id,
        protocol_artifact_sha256=planned.sha256,
        expected_amendment_artifact_sha256=amendment_artifact_sha256,
    )


def require_scientific_protocol_revision(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_run_id: str,
    protocol_artifact_sha256: str,
    expected_amendment_artifact_sha256: str | None = None,
) -> ScientificProtocolRevisionPublication:
    """Fully replay one protocol revision against its sealed source history."""

    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ScientificProtocolRevisionError(
            "protocol revision readback requires exact registry and ledger"
        )
    if registry.policy.root != ledger.policy.root:
        raise ScientificProtocolRevisionError(
            "protocol revision registry and ledger roots differ"
        )
    expected_run_id = _identifier(expected_run_id, "protocol revision run ID")
    _sha256(protocol_artifact_sha256, "protocol revision artifact SHA-256")
    if expected_amendment_artifact_sha256 is not None:
        _sha256(
            expected_amendment_artifact_sha256,
            "expected amendment artifact SHA-256",
        )
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    if any(event.run_id != expected_run_id for event in before[1].events):
        raise ScientificProtocolRevisionError(
            "protocol revision ledger contains another run"
        )
    record = _record_in_snapshot(before[0], protocol_artifact_sha256)
    publication = _validate_publication_at_snapshot(
        registry,
        ledger,
        record=record,
        registry_snapshot=before[0],
        ledger_snapshot=before[1],
    )
    if publication.authority.ledger_run_id != expected_run_id:
        raise ScientificProtocolRevisionError(
            "protocol revision belongs to another run"
        )
    if (
        expected_amendment_artifact_sha256 is not None
        and publication.authority.amendment_artifact_sha256
        != expected_amendment_artifact_sha256
    ):
        raise ScientificProtocolRevisionError(
            "protocol revision names another amendment"
        )
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        raise ScientificProtocolRevisionError(
            "protocol revision sources changed during readback"
        )
    return publication


__all__ = [
    "SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA",
    "SCIENTIFIC_PROTOCOL_REVISION_EVENT_KEY",
    "SCIENTIFIC_PROTOCOL_REVISION_EVENT_SCHEMA",
    "SCIENTIFIC_PROTOCOL_REVISION_PAYLOAD_SCHEMA",
    "SCIENTIFIC_PROTOCOL_REVISION_PROFILE_ID",
    "SCIENTIFIC_PROTOCOL_REVISION_SCOPE",
    "ScientificProtocolRevisionAuthority",
    "ScientificProtocolRevisionError",
    "ScientificProtocolRevisionPublication",
    "register_scientific_protocol_revision",
    "require_scientific_protocol_revision",
]
