"""Holdout custody contracts and a one-shot local simulated adapter.

``SimulatedHoldoutCustody`` is useful for deterministic tests only.  It is
always labeled ``NON_INDEPENDENT`` because the local process can ultimately
inspect both the adapter and its payload.  The interfaces at the bottom of the
module define, but do not pretend to implement, human and service custody.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import threading
from typing import Any, Iterator

from .errors import PathSecurityError, ScientistOneError, ValidationError
from .security import (
    canonical_json_bytes,
    canonical_root,
    open_confined_directory_fd,
    resolve_confined,
    safe_json_loads,
    secure_directory,
)


class HoldoutCustodyError(ScientistOneError):
    """Base failure for custody operations."""


class HoldoutPreconditionError(HoldoutCustodyError, ValidationError):
    """A reveal was requested before all frozen artifacts existed."""


class HoldoutAccessViolation(HoldoutCustodyError):
    """Unauthorized or accidental access invalidated confirmatory use."""


class HoldoutAlreadyRevealed(HoldoutCustodyError):
    """The one authorized reveal was already consumed."""


class HoldoutJournalError(HoldoutCustodyError):
    """The durable custody journal is missing, corrupt, or inconsistent."""


class CustodyIndependence(StrEnum):
    NON_INDEPENDENT = "NON_INDEPENDENT"
    HUMAN_INDEPENDENT = "HUMAN_INDEPENDENT"
    SERVICE_INDEPENDENT = "SERVICE_INDEPENDENT"


class AccessOutcome(StrEnum):
    RELEASED = "RELEASED"
    DENIED_PRECONDITION = "DENIED_PRECONDITION"
    UNAUTHORIZED_VIOLATION = "UNAUTHORIZED_VIOLATION"
    ACCIDENTAL_ACCESS_VIOLATION = "ACCIDENTAL_ACCESS_VIOLATION"


class RevealExecutionClass(StrEnum):
    SCIENTIFIC_CONFIRMATION = "SCIENTIFIC_CONFIRMATION"
    SIMULATED_ARCHITECTURE_CONTROL = "SIMULATED_ARCHITECTURE_CONTROL"


_JOURNAL_SCHEMA_VERSION = "1.0"
_JOURNAL_GENESIS_HASH = "0" * 64
_MAX_JOURNAL_BYTES = 16 * 1024 * 1024
_MAX_JOURNAL_EVENTS = 10_000
_RELEASE_AUTHORITY_KEYS = frozenset(
    {
        "schema_version",
        "evidence_class",
        "ledger_run_id",
        "protocol_hash",
        "code_hash",
        "configuration_hash",
        "split_manifest_hash",
        "blind_interpretation_hash",
        "resource_authority_sha256",
        "evaluator_implementation_sha256",
        "started_event_id",
        "started_event_hash",
    }
)
_SIMULATED_EVALUATOR_ID = "SIMULATED_TWO_GROUP_MEAN_DIFFERENCE_V1"
_SIMULATED_EVALUATOR_IMPLEMENTATION_PATH = "src/scientist_one/holdout.py"
_SIMULATED_EVALUATOR_INPUT_SCHEMA_SHA256 = hashlib.sha256(
    canonical_json_bytes(
        {
            "type": "object",
            "required": ["control", "treatment"],
            "additionalProperties": False,
            "group_size": 4,
            "items": "finite_number",
        }
    )
).hexdigest()
_SIMULATED_EVALUATOR_RESULT_SCHEMA_SHA256 = hashlib.sha256(
    canonical_json_bytes(
        {
            "schema_version": "1.0",
            "kind": "SIMULATED_TWO_GROUP_MEAN_DIFFERENCE",
            "fields": [
                "control_mean",
                "n_control",
                "n_treatment",
                "primary_estimate",
                "treatment_mean",
            ],
        }
    )
).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _nonempty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HoldoutCustodyError(f"{field_name} must be a non-empty string")
    return value.strip()


def _sha256(value: str, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise HoldoutCustodyError(f"{field_name} must be lowercase SHA-256 hex")
    return value


def _content_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _object_hash(value: Any) -> str:
    payload = asdict(value)
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _enum_dict(value: Any) -> dict[str, Any]:
    result = asdict(value)
    for key, item in tuple(result.items()):
        if isinstance(item, StrEnum):
            result[key] = item.value
    return result


def _release_authority(
    value: object,
    *,
    seal: "HoldoutSeal | None" = None,
) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != _RELEASE_AUTHORITY_KEYS:
        raise HoldoutJournalError("custody RELEASE authority schema is invalid")
    if value.get("schema_version") != "1.0":
        raise HoldoutJournalError("custody RELEASE authority version is invalid")
    for name in (
        "protocol_hash",
        "code_hash",
        "configuration_hash",
        "split_manifest_hash",
        "blind_interpretation_hash",
        "resource_authority_sha256",
        "evaluator_implementation_sha256",
        "started_event_hash",
    ):
        _sha256(value.get(name), f"custody RELEASE {name}")
    _nonempty(value.get("ledger_run_id"), "custody RELEASE ledger_run_id")
    _nonempty(value.get("started_event_id"), "custody RELEASE started_event_id")
    if value.get("evidence_class") not in {
        "SCIENTIFIC_EVIDENCE",
        "ARCHITECTURE_CONTROL",
    }:
        raise HoldoutJournalError("custody RELEASE evidence class is invalid")
    if seal is not None:
        evidence_class = value.get("evidence_class")
        if (
            evidence_class == "SCIENTIFIC_EVIDENCE"
            and seal.custody_independence
            not in {
                CustodyIndependence.HUMAN_INDEPENDENT,
                CustodyIndependence.SERVICE_INDEPENDENT,
            }
        ) or (
            evidence_class == "ARCHITECTURE_CONTROL"
            and seal.custody_independence
            is not CustodyIndependence.NON_INDEPENDENT
        ):
            raise HoldoutJournalError(
                "custody RELEASE evidence class differs from provider independence"
            )
    if seal is not None and (
        value.get("protocol_hash") != seal.protocol_hash
        or value.get("code_hash") != seal.code_hash
        or value.get("configuration_hash") != seal.configuration_hash
        or value.get("split_manifest_hash") != seal.split_manifest_hash
        or value.get("blind_interpretation_hash")
        != seal.pre_unblinding_interpretation_hash
    ):
        raise HoldoutJournalError("custody RELEASE authority differs from its seal")
    return {str(key): str(item) for key, item in value.items()}


@dataclass(frozen=True, slots=True)
class ConfirmatoryEvaluatorSpec:
    """Closed simulated evaluator selection; it carries no executable code."""

    evaluator_id: str = _SIMULATED_EVALUATOR_ID
    implementation_path: str = _SIMULATED_EVALUATOR_IMPLEMENTATION_PATH
    input_schema_sha256: str = _SIMULATED_EVALUATOR_INPUT_SCHEMA_SHA256
    result_schema_sha256: str = _SIMULATED_EVALUATOR_RESULT_SCHEMA_SHA256

    def __post_init__(self) -> None:
        if (
            self.evaluator_id != _SIMULATED_EVALUATOR_ID
            or self.implementation_path
            != _SIMULATED_EVALUATOR_IMPLEMENTATION_PATH
            or self.input_schema_sha256
            != _SIMULATED_EVALUATOR_INPUT_SCHEMA_SHA256
            or self.result_schema_sha256
            != _SIMULATED_EVALUATOR_RESULT_SCHEMA_SHA256
        ):
            raise HoldoutCustodyError(
                "simulated confirmatory evaluator spec is not repository-owned"
            )


def _evaluation_terminal_payload(
    value: object,
    *,
    release: "HoldoutRelease",
    authority: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "release_id",
        "outcome",
        "evaluator_binding",
        "result",
        "result_sha256",
    }:
        raise HoldoutJournalError("custody evaluation terminal schema is invalid")
    outcome = value.get("outcome")
    binding = value.get("evaluator_binding")
    result_sha256 = value.get("result_sha256")
    result = value.get("result")
    if (
        value.get("release_id") != release.release_id
        or outcome not in {"SUCCEEDED", "FAILED"}
        or not isinstance(binding, dict)
        or set(binding)
        != {
            "evaluator_id",
            "implementation_path",
            "implementation_sha256",
            "source_inventory_sha256",
            "configuration_inventory_sha256",
            "input_schema_sha256",
            "result_schema_sha256",
        }
        or binding.get("evaluator_id") != _SIMULATED_EVALUATOR_ID
        or binding.get("implementation_path")
        != _SIMULATED_EVALUATOR_IMPLEMENTATION_PATH
        or binding.get("implementation_sha256")
        != authority["evaluator_implementation_sha256"]
        or binding.get("source_inventory_sha256") != authority["code_hash"]
        or binding.get("configuration_inventory_sha256")
        != authority["configuration_hash"]
        or binding.get("input_schema_sha256")
        != _SIMULATED_EVALUATOR_INPUT_SCHEMA_SHA256
        or binding.get("result_schema_sha256")
        != _SIMULATED_EVALUATOR_RESULT_SCHEMA_SHA256
        or (outcome == "FAILED" and (result_sha256 is not None or result is not None))
    ):
        raise HoldoutJournalError("custody evaluation terminal binding is invalid")
    if outcome == "SUCCEEDED":
        normalized_result = _closed_evaluator_result(result)
        expected_result_sha256 = hashlib.sha256(
            canonical_json_bytes(normalized_result)
        ).hexdigest()
        if result_sha256 != expected_result_sha256:
            raise HoldoutJournalError(
                "custody evaluation terminal result digest is invalid"
            )
    else:
        normalized_result = None
    return {
        "release_id": release.release_id,
        "outcome": outcome,
        "evaluator_binding": dict(binding),
        "result": normalized_result,
        "result_sha256": result_sha256,
    }


def _closed_evaluator_result(value: object) -> dict[str, Any]:
    """Validate the complete canonical aggregate persisted after evaluation."""

    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "kind",
        "control_mean",
        "treatment_mean",
        "primary_estimate",
        "n_control",
        "n_treatment",
    }:
        raise HoldoutJournalError("custody evaluator result schema is invalid")
    control = value.get("control_mean")
    treatment = value.get("treatment_mean")
    estimate = value.get("primary_estimate")
    if (
        value.get("schema_version") != "1.0"
        or value.get("kind") != "SIMULATED_TWO_GROUP_MEAN_DIFFERENCE"
        or any(
            type(item) is not float
            or not math.isfinite(float(item))
            for item in (control, treatment, estimate)
        )
        or type(value.get("n_control")) is not int
        or value.get("n_control") != 4
        or type(value.get("n_treatment")) is not int
        or value.get("n_treatment") != 4
        or float(estimate) != float(treatment) - float(control)
    ):
        raise HoldoutJournalError("custody evaluator result content is invalid")
    return dict(value)


@dataclass(frozen=True, slots=True)
class CustodyJournalEvent:
    event_index: int
    event_type: str
    payload: dict[str, Any]
    prior_event_hash: str
    event_hash: str
    schema_version: str = _JOURNAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.event_index, bool) or not isinstance(self.event_index, int) or self.event_index < 0:
            raise HoldoutJournalError("custody journal event index is invalid")
        if self.event_type not in {
            "SEAL",
            "ACCESS",
            "RELEASE",
            "EVALUATION_SUCCEEDED",
            "EVALUATION_FAILED",
        }:
            raise HoldoutJournalError("custody journal event type is invalid")
        if not isinstance(self.payload, dict):
            raise HoldoutJournalError("custody journal event payload must be an object")
        _sha256(self.prior_event_hash, "prior_event_hash")
        _sha256(self.event_hash, "event_hash")
        if self.schema_version != _JOURNAL_SCHEMA_VERSION:
            raise HoldoutJournalError("unsupported custody journal schema")

    @property
    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_index": self.event_index,
            "event_type": self.event_type,
            "payload": self.payload,
            "prior_event_hash": self.prior_event_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict, "event_hash": self.event_hash}


@dataclass(frozen=True, slots=True)
class HoldoutSeal:
    holdout_identity_hash: str
    split_manifest_hash: str
    protocol_hash: str
    code_hash: str
    configuration_hash: str
    pre_unblinding_interpretation_hash: str
    sealed_at: str
    custody_independence: CustodyIndependence
    authorized_access_limit: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.custody_independence, CustodyIndependence):
            try:
                object.__setattr__(
                    self,
                    "custody_independence",
                    CustodyIndependence(self.custody_independence),
                )
            except (TypeError, ValueError) as exc:
                raise HoldoutCustodyError("invalid custody independence") from exc
        for name in (
            "holdout_identity_hash",
            "split_manifest_hash",
            "protocol_hash",
            "code_hash",
            "configuration_hash",
            "pre_unblinding_interpretation_hash",
        ):
            _sha256(getattr(self, name), name)
        _nonempty(self.sealed_at, "sealed_at")
        if self.authorized_access_limit != 1:
            raise HoldoutCustodyError("confirmatory custody permits exactly one authorized reveal")

    @property
    def seal_hash(self) -> str:
        return _object_hash(self)


@dataclass(frozen=True, slots=True)
class HoldoutAccessRecord:
    event_id: str
    requested_at: str
    requester: str
    reason: str
    authorized: bool
    outcome: AccessOutcome
    authorized_access_count: int
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, AccessOutcome):
            try:
                object.__setattr__(self, "outcome", AccessOutcome(self.outcome))
            except (TypeError, ValueError) as exc:
                raise HoldoutCustodyError("invalid access outcome") from exc
        _sha256(self.event_id, "event_id")
        _nonempty(self.requested_at, "requested_at")
        _nonempty(self.requester, "requester")
        _nonempty(self.reason, "reason")
        if not isinstance(self.authorized, bool):
            raise HoldoutCustodyError("authorized must be boolean")
        if (
            isinstance(self.authorized_access_count, bool)
            or not isinstance(self.authorized_access_count, int)
            or self.authorized_access_count < 0
            or self.authorized_access_count > 1
        ):
            raise HoldoutCustodyError("authorized_access_count must be zero or one")
        _nonempty(self.detail, "access detail")


@dataclass(frozen=True, slots=True)
class HoldoutRelease:
    release_id: str
    released_at: str
    requester: str
    reason: str
    seal_hash: str
    holdout_identity_hash: str
    authorized_access_count: int

    def __post_init__(self) -> None:
        for name in ("release_id", "seal_hash", "holdout_identity_hash"):
            _sha256(getattr(self, name), name)
        _nonempty(self.released_at, "released_at")
        _nonempty(self.requester, "requester")
        _nonempty(self.reason, "reason")
        if self.authorized_access_count != 1:
            raise HoldoutCustodyError("the only valid release has authorized_access_count one")


def _access_record_id(index: int, record: HoldoutAccessRecord) -> str:
    body = {
        "index": index,
        "requested_at": record.requested_at,
        "requester": record.requester,
        "reason": record.reason,
        "authorized": record.authorized,
        "outcome": record.outcome.value,
        "authorized_access_count": record.authorized_access_count,
        "detail": record.detail,
    }
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _release_id(release: HoldoutRelease) -> str:
    body = {
        "seal_hash": release.seal_hash,
        "released_at": release.released_at,
        "requester": release.requester,
        "reason": release.reason,
        "authorized_access_count": release.authorized_access_count,
    }
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ReleasedHoldout:
    release: HoldoutRelease
    content: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.content, bytes):
            raise HoldoutCustodyError("released holdout content must be bytes")
        if _content_hash(self.content) != self.release.holdout_identity_hash:
            raise HoldoutCustodyError("released content does not match holdout identity")


@dataclass(frozen=True, slots=True)
class CustodyStatus:
    custody_independence: CustodyIndependence
    sealed: bool
    revealed: bool
    invalidated: bool
    confirmatory_claims_valid: bool
    authorized_access_count: int
    violation_reasons: tuple[str, ...]
    release_event: HoldoutRelease | None
    durable_journal: bool = False
    journal_head_hash: str | None = None


@dataclass(frozen=True, slots=True)
class HoldoutAdmissionSnapshot:
    """Provider-owned live custody state and bytes from one locked journal fd."""

    seal: HoldoutSeal
    status: CustodyStatus
    journal_head_hash: str
    custody_label: str
    journal_bytes: bytes = field(repr=False)
    journal_sha256: str
    journal_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.seal, HoldoutSeal):
            raise HoldoutJournalError("custody admission snapshot lacks a typed seal")
        if not isinstance(self.status, CustodyStatus):
            raise HoldoutJournalError("custody admission snapshot lacks typed status")
        _sha256(self.journal_head_hash, "custody admission journal head")
        _sha256(self.journal_sha256, "custody admission journal bytes")
        _sha256(
            self.journal_identity_sha256,
            "custody admission stable journal identity",
        )
        _nonempty(self.custody_label, "custody admission label")
        if not isinstance(self.journal_bytes, bytes) or not self.journal_bytes:
            raise HoldoutJournalError("custody admission requires non-empty journal bytes")
        if len(self.journal_bytes) > _MAX_JOURNAL_BYTES:
            raise HoldoutJournalError("custody admission journal bytes exceed the size limit")
        if _content_hash(self.journal_bytes) != self.journal_sha256:
            raise HoldoutJournalError("custody admission journal byte hash mismatch")
        if not self.journal_bytes.endswith(b"\n"):
            raise HoldoutJournalError("custody admission journal bytes are incomplete")
        try:
            last_event = safe_json_loads(
                self.journal_bytes.splitlines()[-1],
                max_bytes=_MAX_JOURNAL_BYTES,
            )
        except Exception as exc:
            raise HoldoutJournalError(
                "custody admission journal tail is malformed"
            ) from exc
        if (
            not isinstance(last_event, dict)
            or last_event.get("event_hash") != self.journal_head_hash
        ):
            raise HoldoutJournalError(
                "custody admission journal bytes do not bind their head"
            )
        if not self.status.durable_journal:
            raise HoldoutJournalError("custody admission requires a durable journal")
        if self.status.journal_head_hash != self.journal_head_hash:
            raise HoldoutJournalError("custody admission status is not bound to its journal head")
        if not self.status.sealed or self.status.custody_independence is not self.seal.custody_independence:
            raise HoldoutJournalError("custody admission status does not match its seal")

    @property
    def seal_hash(self) -> str:
        return self.seal.seal_hash

    @property
    def protocol_hash(self) -> str:
        return self.seal.protocol_hash

    @property
    def authorized_access_count(self) -> int:
        return self.status.authorized_access_count

    @property
    def durable_journal(self) -> bool:
        return self.status.durable_journal

    @property
    def sealed(self) -> bool:
        return self.status.sealed

    @property
    def revealed(self) -> bool:
        return self.status.revealed

    @property
    def invalidated(self) -> bool:
        return self.status.invalidated

    @property
    def confirmatory_claims_valid(self) -> bool:
        return self.status.confirmatory_claims_valid

    @property
    def code_hash(self) -> str:
        return self.seal.code_hash

    @property
    def configuration_hash(self) -> str:
        return self.seal.configuration_hash

    @property
    def split_manifest_hash(self) -> str:
        return self.seal.split_manifest_hash

    @property
    def pre_unblinding_interpretation_hash(self) -> str:
        return self.seal.pre_unblinding_interpretation_hash

    @property
    def holdout_identity_hash(self) -> str:
        return self.seal.holdout_identity_hash

    @property
    def journal_size(self) -> int:
        return len(self.journal_bytes)


# Compatibility name for provider consumers that use custody terminology.
CustodyAdmissionSnapshot = HoldoutAdmissionSnapshot


class HoldoutRevealSession(ABC):
    """Provider-owned, lock-scoped ability to append one custody RELEASE.

    This is deliberately an internal primitive rather than scientific reveal
    authority.  A caller must enter through the registry/ledger coordinator,
    which alone may invoke ``_release`` after resolving its evidence.  Provider
    implementations retain their journal lock for the complete lifetime of the
    session and reject use after the context closes.
    """

    @property
    @abstractmethod
    def snapshot(self) -> HoldoutAdmissionSnapshot:
        raise NotImplementedError

    @abstractmethod
    def _release(
        self,
        *,
        coordinator: object,
        ledger_path: str | os.PathLike[str],
        study_version: object,
        fresh_custody_evidence: object,
        reveal_authority: object,
        artifact_registry: object,
        custody_provider: object,
        validity_snapshot: object,
        start_event: object,
        evaluator_spec: ConfirmatoryEvaluatorSpec,
        execution_class: RevealExecutionClass,
        requester: str,
        reason: str,
        requested_at: str | None = None,
        custody_record: object | None = None,
    ) -> tuple[HoldoutRelease, Any]:
        """Validate, append RELEASE, and evaluate while this session is live."""

        raise NotImplementedError


class HoldoutCustody(ABC):
    """Provider-neutral boundary for confirmatory holdout access."""

    independence: CustodyIndependence

    @abstractmethod
    def seal(self, holdout_content: bytes, **frozen_hashes: str) -> HoldoutSeal:
        raise NotImplementedError

    @abstractmethod
    def record_violation(self, *, requester: str, reason: str, occurred_at: str | None = None) -> None:
        raise NotImplementedError

    @property
    @abstractmethod
    def status(self) -> CustodyStatus:
        raise NotImplementedError

    @abstractmethod
    def admission_guard(
        self,
        *,
        expected_journal_head_hash: str | None = None,
        expected_journal_identity_sha256: str | None = None,
    ) -> Any:
        """Return a context manager retaining the provider's live-state lock."""

        raise NotImplementedError

    @abstractmethod
    def _reveal_admission_guard(
        self,
        *,
        expected_journal_head_hash: str | None = None,
        expected_journal_identity_sha256: str | None = None,
    ) -> Any:
        """Internal provider-owned session for one verified RELEASE append."""

        raise NotImplementedError


_SIMULATED_RESERVE_REVEAL_PROFILE = "SIMULATED_RESOURCE_BACKED_RELEASE_V1"


@dataclass(slots=True)
class _SimulatedReserveResourceBinding:
    """Native guard lifetime, not caller-supplied release authority.

    The supported entry points cannot borrow another project's lock or reuse
    an expired session. Arbitrary mutation of trusted Python remains outside
    this same-process boundary, as for the native session itself.
    """

    provider: object
    project_root: Path
    project_root_identity: tuple[int, int]
    process_id: int = field(default_factory=os.getpid)
    thread_id: int = field(default_factory=threading.get_ident)
    profile: str = _SIMULATED_RESERVE_REVEAL_PROFILE
    active: bool = True


def _require_simulated_reserve_resource_binding(session, provider, project_root):
    """Reject borrowed, expired or cross-thread/fork sessions before any use."""
    from .orchestrator import _named_directory_identity

    binding = getattr(session, "_simulated_reserve_resource_binding", None)
    if (
        type(provider) is not SimulatedHoldoutCustody
        or type(session) is not _SimulatedRevealSession
        or session._provider is not provider
        or session._active is not True
        or type(binding) is not _SimulatedReserveResourceBinding
        or binding.active is not True
        or binding.profile != _SIMULATED_RESERVE_REVEAL_PROFILE
        or binding.process_id != os.getpid()
        or binding.thread_id != threading.get_ident()
        or binding.provider is not provider
        or binding.project_root != project_root
        or binding.project_root != provider._journal_root
        or binding.project_root_identity != provider._journal_root_identity
        or _named_directory_identity(project_root) != binding.project_root_identity
    ):
        raise HoldoutAccessViolation(
            "simulated reserve admission lacks its live native resource-bound session"
        )
    return binding


class _SimulatedRevealSession(HoldoutRevealSession):
    """Descriptor-bound session created only by ``SimulatedHoldoutCustody``."""

    def __init__(
        self,
        provider: "SimulatedHoldoutCustody",
        descriptor: int,
        snapshot: HoldoutAdmissionSnapshot,
        initial_events: tuple[CustodyJournalEvent, ...],
        initial_journal_bytes: bytes,
    ) -> None:
        self._provider = provider
        self._descriptor = descriptor
        self._snapshot = snapshot
        self._initial_events = initial_events
        self._initial_journal_bytes = initial_journal_bytes
        self._expected_events = initial_events
        self._expected_journal_bytes = initial_journal_bytes
        self._active = True
        self._attempted = False
        self._release_record: HoldoutRelease | None = None
        self._release_authority: dict[str, str] | None = None
        self._evaluation_outcome: str | None = None
        self._evaluation_terminal_payload: dict[str, Any] | None = None

    @property
    def snapshot(self) -> HoldoutAdmissionSnapshot:
        return self._snapshot

    @property
    def _expected_bytes(self) -> bytes:
        return self._expected_journal_bytes

    @property
    def _expected_event_sequence(self) -> tuple[CustodyJournalEvent, ...]:
        return self._expected_events

    @property
    def _observed_release(self) -> HoldoutRelease | None:
        return self._release_record

    @property
    def _observed_release_authority(self) -> dict[str, str] | None:
        return self._release_authority

    @property
    def _observed_evaluation_outcome(self) -> str | None:
        return self._evaluation_outcome

    @property
    def _observed_evaluation_terminal(self) -> dict[str, Any] | None:
        return self._evaluation_terminal_payload

    def _release(
        self,
        *,
        coordinator: object,
        ledger_path: str | os.PathLike[str],
        study_version: object,
        fresh_custody_evidence: object,
        reveal_authority: object,
        artifact_registry: object,
        custody_provider: object,
        validity_snapshot: object,
        start_event: object,
        evaluator_spec: ConfirmatoryEvaluatorSpec,
        execution_class: RevealExecutionClass,
        requester: str,
        reason: str,
        requested_at: str | None = None,
        custody_record: object | None = None,
    ) -> tuple[HoldoutRelease, Any]:
        from .recovery import SimulatedReserveRevealSelection

        if (
            type(reveal_authority) is SimulatedReserveRevealSelection
            or hasattr(self, "_simulated_reserve_resource_binding")
        ):
            # Negative lifetime gate before consuming the session or entering
            # capture-finally: a refused child/thread must not read the shared
            # journal descriptor, even when it supplies a legacy selector.
            _require_simulated_reserve_resource_binding(
                self, self._provider, self._provider._journal_root
            )
        if not self._active:
            raise HoldoutJournalError("custody reveal session is no longer active")
        if self._attempted:
            raise HoldoutAlreadyRevealed("custody reveal session was already consumed")
        self._attempted = True
        try:
            release, result = self._provider._run_confirmatory_locked(
                self._descriptor,
                self,
                coordinator=coordinator,
                ledger_path=ledger_path,
                study_version=study_version,
                fresh_custody_evidence=fresh_custody_evidence,
                reveal_authority=reveal_authority,
                artifact_registry=artifact_registry,
                custody_provider=custody_provider,
                validity_snapshot=validity_snapshot,
                start_event=start_event,
                evaluator_spec=evaluator_spec,
                execution_class=execution_class,
                requester=requester,
                reason=reason,
                requested_at=requested_at,
                custody_record=custody_record,
            )
            return release, result
        finally:
            if self._snapshot.status.release_event is None:
                self._release_record = self._provider._release
                authority = self._provider._release_authority
                self._release_authority = (
                    dict(authority) if authority is not None else None
                )
                self._evaluation_outcome = self._provider._evaluation_outcome
                terminal = self._provider._evaluation_terminal_payload
                self._evaluation_terminal_payload = (
                    dict(terminal) if terminal is not None else None
                )
            # Capture only the mutation performed by the provider primitive.
            # The enclosing guard later proves that no additional journal event
            # appeared before the lock was released.
            self._expected_journal_bytes = self._provider._read_journal_bytes_locked(
                self._descriptor
            )
            self._expected_events = self._provider._parse_journal_bytes(
                self._expected_journal_bytes
            )

    def _close(self) -> None:
        self._active = False


class SimulatedHoldoutCustody(HoldoutCustody):
    """One-shot local adapter for tests, explicitly not independent custody."""

    independence = CustodyIndependence.NON_INDEPENDENT
    custody_label = "SIMULATED_NON_INDEPENDENT"

    def __init__(
        self,
        authorized_requesters: tuple[str, ...],
        *,
        journal_root: str | os.PathLike[str] | None = None,
        journal_path: str | os.PathLike[str] | None = None,
        require_existing_journal: bool = False,
        nonblocking: bool = False,
    ) -> None:
        if type(nonblocking) is not bool:
            raise HoldoutJournalError("custody nonblocking mode must be exact boolean")
        if not isinstance(authorized_requesters, tuple) or not authorized_requesters:
            raise HoldoutCustodyError("authorized_requesters must be a non-empty tuple")
        normalized = tuple(_nonempty(value, "authorized_requester") for value in authorized_requesters)
        if len(set(normalized)) != len(normalized):
            raise HoldoutCustodyError("authorized_requesters must be unique")
        self._authorized_requesters = frozenset(normalized)
        self._seal: HoldoutSeal | None = None
        self._payload: bytes | None = None
        self._release: HoldoutRelease | None = None
        self._release_authority: dict[str, str] | None = None
        self._evaluation_outcome: str | None = None
        self._evaluation_terminal_payload: dict[str, Any] | None = None
        self._records: list[HoldoutAccessRecord] = []
        self._violations: list[str] = []
        self._authorized_access_count = 0
        self._lock = threading.RLock()
        self._journal_root: Path | None = None
        self._journal_relative: Path | None = None
        self._journal_head_hash: str | None = None
        self._journal_root_identity: tuple[int, int] | None = None
        if not isinstance(require_existing_journal, bool):
            raise HoldoutJournalError("require_existing_journal must be boolean")
        if require_existing_journal and journal_root is None:
            raise HoldoutJournalError(
                "require_existing_journal needs a durable journal path"
            )
        self._require_existing_journal = require_existing_journal
        if (journal_root is None) != (journal_path is None):
            raise HoldoutJournalError("journal_root and journal_path must be supplied together")
        if journal_root is not None and journal_path is not None:
            root = canonical_root(journal_root)
            raw_path = Path(journal_path)
            if raw_path.is_absolute():
                try:
                    relative = raw_path.relative_to(root)
                except ValueError as exc:
                    raise PathSecurityError("custody journal is outside the project root") from exc
            else:
                relative = raw_path
            if not relative.parts or relative.name in {"", ".", ".."}:
                raise PathSecurityError("custody journal filename is invalid")
            secure_directory(
                root,
                relative.parent,
                create=not require_existing_journal,
            )
            resolve_confined(
                root,
                relative,
                must_exist=require_existing_journal,
                expected_kind="file",
                reject_hardlinks=True,
            )
            self._journal_root = root
            self._journal_relative = relative
            root_metadata = os.stat(root, follow_symlinks=False)
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise PathSecurityError("custody journal root is not a directory")
            self._journal_root_identity = (
                root_metadata.st_dev,
                root_metadata.st_ino,
            )
            with self._journal_guard(nonblocking=nonblocking):
                pass

    @property
    def durable(self) -> bool:
        return self._journal_root is not None

    @property
    def journal_path(self) -> Path | None:
        if self._journal_root is None or self._journal_relative is None:
            return None
        return self._journal_root / self._journal_relative

    def _open_journal(self) -> int:
        if self._journal_root is None or self._journal_relative is None:
            raise HoldoutJournalError("durable journal is not configured")
        directory_fd = open_confined_directory_fd(
            self._journal_root,
            self._journal_relative.parent,
            create=False,
        )
        try:
            flags = (
                os.O_RDWR
                | os.O_APPEND
                | (0 if self._require_existing_journal else os.O_CREAT)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                descriptor = os.open(self._journal_relative.name, flags, 0o600, dir_fd=directory_fd)
            except OSError as exc:
                raise PathSecurityError("custody journal cannot be opened safely") from exc
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                os.close(descriptor)
                raise PathSecurityError("custody journal must be a non-hard-linked regular file")
            os.fsync(directory_fd)
            return descriptor
        finally:
            os.close(directory_fd)

    def _open_namespace_lock(self, *, nonblocking: bool = False) -> int:
        """Lock the stable project-root namespace before resolving the journal."""

        if type(nonblocking) is not bool:
            raise HoldoutJournalError("custody nonblocking mode must be exact boolean")
        if self._journal_root is None or self._journal_root_identity is None:
            raise HoldoutJournalError("durable journal is not configured")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(self._journal_root, flags)
        except OSError as exc:
            raise PathSecurityError("custody namespace cannot be opened safely") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino) != self._journal_root_identity
            ):
                raise PathSecurityError("custody namespace identity changed")
            fcntl.flock(
                descriptor, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
            )
            self._verify_namespace_lock_identity(descriptor)
            return descriptor
        except BaseException as exc:
            os.close(descriptor)
            if nonblocking and isinstance(exc, BlockingIOError):
                raise HoldoutJournalError("custody namespace lock unavailable") from exc
            raise

    def _verify_namespace_lock_identity(self, descriptor: int) -> None:
        if self._journal_root is None or self._journal_root_identity is None:
            raise HoldoutJournalError("durable journal is not configured")
        held = os.fstat(descriptor)
        try:
            named = os.stat(self._journal_root, follow_symlinks=False)
        except OSError as exc:
            raise HoldoutJournalError("custody namespace name changed") from exc
        if (
            not stat.S_ISDIR(held.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or (held.st_dev, held.st_ino) != self._journal_root_identity
            or (named.st_dev, named.st_ino) != self._journal_root_identity
        ):
            raise HoldoutJournalError("custody namespace no longer denotes its locked root")

    def _journal_identity_hash(self, descriptor: int) -> str:
        if self._journal_root_identity is None:
            raise HoldoutJournalError("durable journal root identity is unavailable")
        held = os.fstat(descriptor)
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "root_device": self._journal_root_identity[0],
                    "root_inode": self._journal_root_identity[1],
                    "journal_device": held.st_dev,
                    "journal_inode": held.st_ino,
                }
            )
        ).hexdigest()

    def _read_journal_bytes_locked(self, descriptor: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_JOURNAL_BYTES - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_JOURNAL_BYTES:
                raise HoldoutJournalError("custody journal exceeds its size limit")
        return b"".join(chunks)

    def _parse_journal_bytes(self, content: bytes) -> tuple[CustodyJournalEvent, ...]:
        if not content:
            return ()
        if not content.endswith(b"\n"):
            raise HoldoutJournalError("custody journal has an incomplete final event")
        lines = content.splitlines()
        if len(lines) > _MAX_JOURNAL_EVENTS:
            raise HoldoutJournalError("custody journal exceeds its event limit")
        events: list[CustodyJournalEvent] = []
        prior = _JOURNAL_GENESIS_HASH
        expected_keys = {
            "schema_version",
            "event_index",
            "event_type",
            "payload",
            "prior_event_hash",
            "event_hash",
        }
        for index, line in enumerate(lines):
            try:
                value = safe_json_loads(line, max_bytes=_MAX_JOURNAL_BYTES)
            except Exception as exc:
                raise HoldoutJournalError("custody journal contains invalid JSON") from exc
            if not isinstance(value, dict) or set(value) != expected_keys:
                raise HoldoutJournalError("custody journal event schema is invalid")
            try:
                event = CustodyJournalEvent(**value)
            except (TypeError, ValueError) as exc:
                raise HoldoutJournalError("custody journal event is malformed") from exc
            if event.event_index != index or event.prior_event_hash != prior:
                raise HoldoutJournalError("custody journal sequence or hash link is invalid")
            computed = hashlib.sha256(canonical_json_bytes(event.unsigned_dict)).hexdigest()
            if computed != event.event_hash:
                raise HoldoutJournalError("custody journal event hash mismatch")
            events.append(event)
            prior = event.event_hash
        return tuple(events)

    def _read_journal_locked(self, descriptor: int) -> tuple[CustodyJournalEvent, ...]:
        return self._parse_journal_bytes(self._read_journal_bytes_locked(descriptor))

    def _verify_locked_journal_identity(self, descriptor: int) -> bytes:
        """Prove the configured name still denotes the locked, verified inode."""

        if self._journal_root is None or self._journal_relative is None:
            raise HoldoutJournalError("durable journal is not configured")
        content = self._read_journal_bytes_locked(descriptor)
        events = self._parse_journal_bytes(content)
        head = events[-1].event_hash if events else None
        if head != self._journal_head_hash:
            raise HoldoutJournalError("custody journal head changed during the locked operation")
        held = os.fstat(descriptor)
        if (
            not stat.S_ISREG(held.st_mode)
            or held.st_nlink != 1
            or held.st_size != len(content)
        ):
            raise HoldoutJournalError("locked custody journal identity is unsafe")
        directory_fd = open_confined_directory_fd(
            self._journal_root,
            self._journal_relative.parent,
            create=False,
        )
        try:
            try:
                named = os.stat(
                    self._journal_relative.name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise HoldoutJournalError(
                    "custody journal name changed during the locked operation"
                ) from exc
            if (
                not stat.S_ISREG(named.st_mode)
                or named.st_nlink != 1
                or (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino)
                or named.st_size != held.st_size
            ):
                raise HoldoutJournalError(
                    "custody journal name no longer denotes the locked file"
                )
        finally:
            os.close(directory_fd)
        return content

    def _restore_from_events(self, events: tuple[CustodyJournalEvent, ...]) -> None:
        prior_payload = self._payload
        self._seal = None
        self._release = None
        self._release_authority = None
        self._evaluation_outcome = None
        self._evaluation_terminal_payload = None
        self._records = []
        self._violations = []
        self._authorized_access_count = 0
        self._journal_head_hash = events[-1].event_hash if events else None
        for event in events:
            payload = event.payload
            if event.event_type == "SEAL":
                if self._seal is not None or event.event_index != 0:
                    raise HoldoutJournalError("custody journal contains duplicate or misplaced seal")
                if set(payload) != {"seal", "authorized_requesters"}:
                    raise HoldoutJournalError("custody seal event payload is invalid")
                requesters = payload["authorized_requesters"]
                if not isinstance(requesters, list) or frozenset(requesters) != self._authorized_requesters:
                    raise HoldoutJournalError("custody journal requester policy mismatch")
                try:
                    self._seal = HoldoutSeal(**payload["seal"])
                except (TypeError, ValueError) as exc:
                    raise HoldoutJournalError("custody seal event is malformed") from exc
                if self._seal.custody_independence is not self.independence:
                    raise HoldoutJournalError(
                        "custody seal differs from provider independence"
                    )
                continue
            if self._seal is None:
                raise HoldoutJournalError("custody journal records access before seal")
            if event.event_type == "ACCESS":
                if set(payload) != {"record", "violation_reason"}:
                    raise HoldoutJournalError("custody access event payload is invalid")
                try:
                    record = HoldoutAccessRecord(**payload["record"])
                except (TypeError, ValueError) as exc:
                    raise HoldoutJournalError("custody access record is malformed") from exc
                violation = payload["violation_reason"]
                if (
                    record.event_id != _access_record_id(len(self._records), record)
                    or record.authorized is not False
                    or record.outcome
                    not in {
                        AccessOutcome.UNAUTHORIZED_VIOLATION,
                        AccessOutcome.ACCIDENTAL_ACCESS_VIOLATION,
                    }
                    or not isinstance(violation, str)
                    or not violation.strip()
                    or record.authorized_access_count
                    != self._authorized_access_count
                ):
                    raise HoldoutJournalError(
                        "custody ACCESS semantics or identity are invalid"
                    )
                if record.outcome is AccessOutcome.UNAUTHORIZED_VIOLATION:
                    expected_detail = (
                        "requester is not authorized by the sealed custody policy"
                    )
                    if (
                        self._release is not None
                        or record.authorized_access_count != 0
                        or record.detail != expected_detail
                        or violation != expected_detail
                    ):
                        raise HoldoutJournalError(
                            "custody unauthorized ACCESS binding is invalid"
                        )
                elif (
                    record.detail
                    != "reported access invalidates this holdout for confirmatory claims"
                    or violation != record.reason
                ):
                    raise HoldoutJournalError(
                        "custody accidental ACCESS binding is invalid"
                    )
                self._records.append(record)
                # Invalidation derives from the typed violation outcome.  The
                # text is an exact, non-optional explanation, never authority.
                self._violations.append(violation.strip())
            elif event.event_type == "RELEASE":
                if self._release is not None or set(payload) != {
                    "record",
                    "release",
                    "authority",
                }:
                    raise HoldoutJournalError("custody journal contains an invalid duplicate release")
                try:
                    record = HoldoutAccessRecord(**payload["record"])
                    release = HoldoutRelease(**payload["release"])
                    authority = _release_authority(
                        payload["authority"],
                        seal=self._seal,
                    )
                except (TypeError, ValueError) as exc:
                    raise HoldoutJournalError("custody release event is malformed") from exc
                expected_release_detail = (
                    "single authorized confirmatory reveal"
                    if authority["evidence_class"] == "SCIENTIFIC_EVIDENCE"
                    else "single non-evidentiary simulated fixture release"
                )
                if (
                    record.outcome is not AccessOutcome.RELEASED
                    or record.authorized is not True
                    or record.authorized_access_count != 1
                    or record.event_id != _access_record_id(len(self._records), record)
                    or record.detail != expected_release_detail
                    or release.authorized_access_count != 1
                    or release.release_id != _release_id(release)
                    or record.requested_at != release.released_at
                    or record.requester != release.requester
                    or record.reason != release.reason
                    or release.seal_hash != self._seal.seal_hash
                    or release.holdout_identity_hash != self._seal.holdout_identity_hash
                    or self._violations
                ):
                    raise HoldoutJournalError("custody release does not bind the sealed holdout")
                self._records.append(record)
                self._release = release
                self._release_authority = authority
                self._authorized_access_count = 1
            elif event.event_type in {
                "EVALUATION_SUCCEEDED",
                "EVALUATION_FAILED",
            }:
                expected_outcome = event.event_type.removeprefix("EVALUATION_")
                if (
                    self._release is None
                    or self._release_authority is None
                    or self._evaluation_outcome is not None
                    or event.event_index == 0
                    or events[event.event_index - 1].event_type != "RELEASE"
                ):
                    raise HoldoutJournalError(
                        "custody evaluation terminal event is invalid"
                    )
                terminal = _evaluation_terminal_payload(
                    payload,
                    release=self._release,
                    authority=self._release_authority,
                )
                if terminal["outcome"] != expected_outcome:
                    raise HoldoutJournalError(
                        "custody evaluation terminal outcome is inconsistent"
                    )
                self._evaluation_outcome = expected_outcome
                self._evaluation_terminal_payload = terminal
            else:
                raise HoldoutJournalError("custody journal event order is invalid")
        if events and self._seal is None:
            raise HoldoutJournalError("custody journal lacks a seal")
        if (
            prior_payload is not None
            and self._seal is not None
            and self._release is None
            and _content_hash(prior_payload) == self._seal.holdout_identity_hash
        ):
            self._payload = prior_payload
        else:
            self._payload = None

    @contextmanager
    def _process_guard(self, *, nonblocking: bool = False) -> Iterator[None]:
        """Keep the original process lock; the new profile must not wait on it."""
        if type(nonblocking) is not bool:
            raise HoldoutJournalError("custody nonblocking mode must be exact boolean")
        owner_pid = os.getpid()
        acquired = self._lock.acquire(blocking=not nonblocking)
        if not acquired:
            raise HoldoutJournalError("custody process lock unavailable")
        try:
            yield
        finally:
            if nonblocking and os.getpid() != owner_pid:
                raise HoldoutJournalError("inherited custody process guard cannot exit as owner")
            self._lock.release()

    @contextmanager
    def _journal_guard(self, *, nonblocking: bool = False) -> Iterator[int | None]:
        if type(nonblocking) is not bool:
            raise HoldoutJournalError("custody nonblocking mode must be exact boolean")
        owner_pid = os.getpid()
        if not self.durable:
            yield None
            return
        namespace_descriptor = self._open_namespace_lock(nonblocking=nonblocking)
        descriptor: int | None = None
        journal_locked = False
        try:
            descriptor = self._open_journal()
            try:
                fcntl.flock(
                    descriptor, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
                )
            except BlockingIOError as exc:
                if nonblocking:
                    raise HoldoutJournalError("custody journal lock unavailable") from exc
                raise
            journal_locked = True
            events = self._read_journal_locked(descriptor)
            self._restore_from_events(events)
            yield descriptor
        finally:
            inherited = nonblocking and os.getpid() != owner_pid
            try:
                if inherited:
                    # Inherited descriptors share both locks and seek position.
                    # Close our copies without reading or issuing LOCK_UN.
                    raise HoldoutJournalError("inherited custody journal guard cannot exit as owner")
                if journal_locked:
                    self._verify_locked_journal_identity(descriptor)
                self._verify_namespace_lock_identity(namespace_descriptor)
            finally:
                try:
                    if journal_locked and not inherited:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                    try:
                        if not inherited:
                            fcntl.flock(namespace_descriptor, fcntl.LOCK_UN)
                    finally:
                        os.close(namespace_descriptor)

    def _append_journal_locked(
        self,
        descriptor: int | None,
        event_type: str,
        payload: dict[str, Any],
    ) -> CustodyJournalEvent | None:
        if descriptor is None:
            return None
        events = self._read_journal_locked(descriptor)
        disk_head = events[-1].event_hash if events else None
        if disk_head != self._journal_head_hash:
            raise HoldoutJournalError("custody journal changed during the locked operation")
        event_index = len(events)
        prior_hash = self._journal_head_hash or _JOURNAL_GENESIS_HASH
        unsigned = {
            "schema_version": _JOURNAL_SCHEMA_VERSION,
            "event_index": event_index,
            "event_type": event_type,
            "payload": payload,
            "prior_event_hash": prior_hash,
        }
        event = CustodyJournalEvent(
            **unsigned,
            event_hash=hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
        )
        encoded = canonical_json_bytes(event.to_dict()) + b"\n"
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise HoldoutJournalError("custody journal append made no progress")
            view = view[written:]
        os.fsync(descriptor)
        self._journal_head_hash = event.event_hash
        return event

    def verify_journal(self) -> str | None:
        """Reload and validate the complete durable custody hash chain."""

        with self._lock, self._journal_guard():
            return self._journal_head_hash

    def _status_locked(self) -> CustodyStatus:
        terminal_violation: str | None = None
        if self._release is not None and self._evaluation_outcome is None:
            terminal_violation = "confirmatory evaluation is incomplete after release"
        elif self._release is not None and self._evaluation_outcome == "FAILED":
            terminal_violation = "confirmatory evaluation failed after release"
        elif (
            self._release is not None
            and self._release_authority is not None
            and self._release_authority.get("evidence_class")
            != "SCIENTIFIC_EVIDENCE"
        ):
            terminal_violation = (
                "simulated architecture-control release is non-evidentiary"
            )
        elif (
            self._release is not None
            and self._release_authority is not None
            and self._release_authority.get("evidence_class")
            == "SCIENTIFIC_EVIDENCE"
            and (
                self._seal is None
                or self.independence
                not in {
                    CustodyIndependence.HUMAN_INDEPENDENT,
                    CustodyIndependence.SERVICE_INDEPENDENT,
                }
                or self._seal.custody_independence is not self.independence
            )
        ):
            terminal_violation = "scientific release lacks independent custody"
        violations = tuple(self._violations) + (
            (terminal_violation,) if terminal_violation is not None else ()
        )
        invalidated = bool(violations)
        return CustodyStatus(
            custody_independence=self.independence,
            sealed=self._seal is not None,
            revealed=self._release is not None,
            invalidated=invalidated,
            confirmatory_claims_valid=(
                self._release is not None
                and self._evaluation_outcome == "SUCCEEDED"
                and self._release_authority is not None
                and self._release_authority.get("evidence_class")
                == "SCIENTIFIC_EVIDENCE"
                and self._seal is not None
                and self._seal.custody_independence
                in {
                    CustodyIndependence.HUMAN_INDEPENDENT,
                    CustodyIndependence.SERVICE_INDEPENDENT,
                }
                and self._seal.custody_independence is self.independence
                and not invalidated
            ),
            authorized_access_count=self._authorized_access_count,
            violation_reasons=violations,
            release_event=self._release,
            durable_journal=self.durable,
            journal_head_hash=self._journal_head_hash,
        )

    @contextmanager
    def admission_guard(
        self,
        *,
        expected_journal_head_hash: str | None = None,
        expected_journal_identity_sha256: str | None = None,
        nonblocking: bool = False,
    ) -> Iterator[HoldoutAdmissionSnapshot]:
        """Yield freshly verified custody state while retaining both locks.

        Security-sensitive admission must perform its receipt/ledger checks
        inside this context.  The in-process lock prevents another thread from
        recording access, and the exclusive journal lock prevents another
        adapter or process from appending an ACCESS/RELEASE event until the
        admission decision completes.
        """

        owner_pid = os.getpid()
        if not self.durable:
            raise HoldoutJournalError("custody admission requires a durable journal")
        if expected_journal_head_hash is not None:
            _sha256(expected_journal_head_hash, "expected_journal_head_hash")
        if expected_journal_identity_sha256 is not None:
            _sha256(
                expected_journal_identity_sha256,
                "expected_journal_identity_sha256",
            )
        with self._process_guard(nonblocking=nonblocking), self._journal_guard(
            nonblocking=nonblocking
        ) as descriptor:
            if descriptor is None:
                raise HoldoutJournalError("custody admission requires a durable journal")
            if self._seal is None or self._journal_head_hash is None:
                raise HoldoutJournalError("custody admission requires a durable seal")
            if (
                expected_journal_head_hash is not None
                and self._journal_head_hash != expected_journal_head_hash
            ):
                raise HoldoutJournalError(
                    "custody journal head differs from its immutable external anchor"
                )
            journal_identity_sha256 = self._journal_identity_hash(descriptor)
            if (
                expected_journal_identity_sha256 is not None
                and journal_identity_sha256
                != expected_journal_identity_sha256
            ):
                raise HoldoutJournalError(
                    "custody journal identity differs from its immutable external anchor"
                )
            journal_bytes = self._verify_locked_journal_identity(descriptor)
            snapshot = HoldoutAdmissionSnapshot(
                seal=self._seal,
                status=self._status_locked(),
                journal_head_hash=self._journal_head_hash,
                custody_label=self.custody_label,
                journal_bytes=journal_bytes,
                journal_sha256=_content_hash(journal_bytes),
                journal_identity_sha256=journal_identity_sha256,
            )
            yield snapshot
            if nonblocking and os.getpid() != owner_pid:
                raise HoldoutJournalError("inherited custody observation cannot exit as owner")
            if self._verify_locked_journal_identity(descriptor) != journal_bytes:
                raise HoldoutJournalError(
                    "custody journal bytes changed during admission"
                )
            if self._journal_identity_hash(descriptor) != journal_identity_sha256:
                raise HoldoutJournalError(
                    "custody journal identity changed during admission"
                )

    @contextmanager
    def _reveal_admission_guard(
        self,
        *,
        expected_journal_head_hash: str | None = None,
        expected_journal_identity_sha256: str | None = None,
        simulated_reserve_project_root: Path | None = None,
    ) -> Iterator[HoldoutRevealSession]:
        """Retain the original custody guard under optional native resource lock.

        Only the resource-backed simulated profile selects the outer lock.
        This does not authorize release: the native coordinator still derives
        all contract, reservation, accounting and preparation bindings.
        """
        if simulated_reserve_project_root is None:
            with self._custody_reveal_admission_guard(
                expected_journal_head_hash=expected_journal_head_hash,
                expected_journal_identity_sha256=expected_journal_identity_sha256,
            ) as session:
                yield session
            return

        from .orchestrator import (
            _named_directory_identity,
            _project_resource_execution_lock,
        )

        root = simulated_reserve_project_root
        if (
            type(self) is not SimulatedHoldoutCustody
            or type(root) is not type(Path())
            or root != self._journal_root
            or self._journal_root_identity is None
            or _named_directory_identity(root) != self._journal_root_identity
        ):
            raise HoldoutJournalError(
                "simulated reserve resource lock must bind this native custody root"
            )
        with _project_resource_execution_lock(
            root,
            expected_root_identity=self._journal_root_identity,
            nonblocking=True,
        ):
            binding = _SimulatedReserveResourceBinding(
                self, root, self._journal_root_identity
            )
            try:
                with self._custody_reveal_admission_guard(
                    expected_journal_head_hash=expected_journal_head_hash,
                    expected_journal_identity_sha256=expected_journal_identity_sha256,
                    nonblocking=True,
                ) as session:
                    if type(session) is not _SimulatedRevealSession:
                        raise HoldoutJournalError(
                            "simulated reserve requires the exact native custody session"
                        )
                    session._simulated_reserve_resource_binding = binding
                    yield session
            finally:
                # The binding survives every custody exit check, including
                # journal/namespace checks, but never outlives the resource lock.
                binding.active = False

    @contextmanager
    def _custody_reveal_admission_guard(
        self,
        *,
        expected_journal_head_hash: str | None = None,
        expected_journal_identity_sha256: str | None = None,
        nonblocking: bool = False,
    ) -> Iterator[HoldoutRevealSession]:
        """Yield the internal RELEASE primitive while retaining both locks.

        Unlike the observational ``admission_guard``, this context permits one
        mutation made by the yielded provider session.  Its exit check proves
        that the observed journal is byte-for-byte the captured result of that
        attempt and, on success, that exactly one RELEASE extends the anchored
        journal.  It never treats arbitrary journal advancement as acceptable.
        """

        owner_pid = os.getpid()
        if not self.durable:
            raise HoldoutJournalError("custody reveal admission requires a durable journal")
        if expected_journal_head_hash is not None:
            _sha256(expected_journal_head_hash, "expected_journal_head_hash")
        if expected_journal_identity_sha256 is not None:
            _sha256(
                expected_journal_identity_sha256,
                "expected_journal_identity_sha256",
            )
        with self._process_guard(nonblocking=nonblocking), self._journal_guard(
            nonblocking=nonblocking
        ) as descriptor:
            if descriptor is None:
                raise HoldoutJournalError(
                    "custody reveal admission requires a durable journal"
                )
            if self._seal is None or self._journal_head_hash is None:
                raise HoldoutJournalError(
                    "custody reveal admission requires a durable seal"
                )
            if (
                expected_journal_head_hash is not None
                and self._journal_head_hash != expected_journal_head_hash
            ):
                raise HoldoutJournalError(
                    "custody journal head differs from its immutable external anchor"
                )
            journal_identity_sha256 = self._journal_identity_hash(descriptor)
            if (
                expected_journal_identity_sha256 is not None
                and journal_identity_sha256
                != expected_journal_identity_sha256
            ):
                raise HoldoutJournalError(
                    "custody journal identity differs from its immutable external anchor"
                )
            journal_bytes = self._verify_locked_journal_identity(descriptor)
            initial_events = self._parse_journal_bytes(journal_bytes)
            snapshot = HoldoutAdmissionSnapshot(
                seal=self._seal,
                status=self._status_locked(),
                journal_head_hash=self._journal_head_hash,
                custody_label=self.custody_label,
                journal_bytes=journal_bytes,
                journal_sha256=_content_hash(journal_bytes),
                journal_identity_sha256=journal_identity_sha256,
            )
            session = _SimulatedRevealSession(
                self,
                descriptor,
                snapshot,
                initial_events,
                journal_bytes,
            )
            try:
                yield session
            finally:
                session._close()
                if nonblocking and os.getpid() != owner_pid:
                    raise HoldoutJournalError("inherited custody reveal cannot exit as owner")
                observed_bytes = self._verify_locked_journal_identity(descriptor)
                observed_events = self._parse_journal_bytes(observed_bytes)
                expected_events = session._expected_event_sequence
                if (
                    observed_bytes != session._expected_bytes
                    or observed_events != expected_events
                    or expected_events[: len(initial_events)] != initial_events
                ):
                    raise HoldoutJournalError(
                        "custody journal changed outside the locked reveal primitive"
                    )
                release = session._observed_release
                if release is not None:
                    suffix = expected_events[len(initial_events) :]
                    if (
                        len(suffix) not in {1, 2}
                        or suffix[0].event_type != "RELEASE"
                        or suffix[0].prior_event_hash
                        != snapshot.journal_head_hash
                    ):
                        raise HoldoutJournalError(
                            "custody reveal did not append exactly one RELEASE first"
                        )
                    release_payload = suffix[0].payload.get("release")
                    authority_payload = suffix[0].payload.get("authority")
                    if (
                        not isinstance(release_payload, dict)
                        or release_payload.get("release_id")
                        != release.release_id
                        or release_payload.get("seal_hash") != snapshot.seal_hash
                        or release_payload.get("holdout_identity_hash")
                        != snapshot.holdout_identity_hash
                        or authority_payload
                        != session._observed_release_authority
                    ):
                        raise HoldoutJournalError(
                            "custody RELEASE differs from the locked session result"
                        )
                    outcome = session._observed_evaluation_outcome
                    if outcome is None:
                        if len(suffix) != 1:
                            raise HoldoutJournalError(
                                "pending custody evaluation appended a terminal event"
                            )
                    else:
                        if (
                            outcome not in {"SUCCEEDED", "FAILED"}
                            or len(suffix) != 2
                            or suffix[1].event_type != f"EVALUATION_{outcome}"
                            or suffix[1].prior_event_hash != suffix[0].event_hash
                            or suffix[1].payload
                            != session._observed_evaluation_terminal
                        ):
                            raise HoldoutJournalError(
                                "custody evaluation terminal differs from its RELEASE"
                            )
                elif session._attempted:
                    if len(expected_events) not in {
                        len(initial_events),
                        len(initial_events) + 1,
                    } or (
                        len(expected_events) == len(initial_events) + 1
                        and expected_events[-1].event_type != "ACCESS"
                    ):
                        raise HoldoutJournalError(
                            "failed custody reveal appended an unexpected journal mutation"
                        )
                elif expected_events != initial_events:
                    raise HoldoutJournalError(
                        "unused custody reveal session changed its journal"
                    )
                if self._journal_identity_hash(descriptor) != journal_identity_sha256:
                    raise HoldoutJournalError(
                        "custody journal identity changed during reveal admission"
                    )

    def admission_snapshot(self) -> HoldoutAdmissionSnapshot:
        """Return an observational live snapshot; admission must use the guard."""

        with self.admission_guard() as snapshot:
            return snapshot

    def seal(
        self,
        holdout_content: bytes,
        *,
        split_manifest_hash: str,
        protocol_hash: str,
        code_hash: str,
        configuration_hash: str,
        pre_unblinding_interpretation_hash: str,
        sealed_at: str | None = None,
        expected_holdout_identity_hash: str | None = None,
        nonblocking: bool = False,
    ) -> HoldoutSeal:
        if not isinstance(holdout_content, bytes) or not holdout_content:
            raise HoldoutCustodyError("holdout_content must be non-empty bytes")
        with self._process_guard(nonblocking=nonblocking), self._journal_guard(
            nonblocking=nonblocking
        ) as journal:
            identity = _content_hash(holdout_content)
            if expected_holdout_identity_hash is not None:
                _sha256(expected_holdout_identity_hash, "expected_holdout_identity_hash")
                if identity != expected_holdout_identity_hash:
                    raise HoldoutCustodyError("holdout content does not match expected identity")
            if self._seal is not None:
                supplied = {
                    "holdout_identity_hash": identity,
                    "split_manifest_hash": split_manifest_hash,
                    "protocol_hash": protocol_hash,
                    "code_hash": code_hash,
                    "configuration_hash": configuration_hash,
                    "pre_unblinding_interpretation_hash": pre_unblinding_interpretation_hash,
                }
                mismatch = tuple(
                    name for name, value in supplied.items() if value != getattr(self._seal, name)
                )
                if sealed_at is not None and sealed_at != self._seal.sealed_at:
                    mismatch += ("sealed_at",)
                if mismatch:
                    raise HoldoutCustodyError(
                        "custody reseal does not match durable seal: " + ", ".join(mismatch)
                    )
                if self._release is None:
                    self._payload = bytes(holdout_content)
                return self._seal
            seal = HoldoutSeal(
                holdout_identity_hash=identity,
                split_manifest_hash=split_manifest_hash,
                protocol_hash=protocol_hash,
                code_hash=code_hash,
                configuration_hash=configuration_hash,
                pre_unblinding_interpretation_hash=pre_unblinding_interpretation_hash,
                sealed_at=sealed_at or _now(),
                custody_independence=self.independence,
            )
            self._append_journal_locked(
                journal,
                "SEAL",
                {
                    "seal": _enum_dict(seal),
                    "authorized_requesters": sorted(self._authorized_requesters),
                },
            )
            self._seal = seal
            self._payload = bytes(holdout_content)
            return seal

    def _make_record(
        self,
        *,
        requested_at: str,
        requester: str,
        reason: str,
        authorized: bool,
        outcome: AccessOutcome,
        detail: str,
        authorized_access_count: int | None = None,
    ) -> HoldoutAccessRecord:
        count = (
            self._authorized_access_count
            if authorized_access_count is None
            else authorized_access_count
        )
        body = {
            "index": len(self._records),
            "requested_at": requested_at,
            "requester": requester,
            "reason": reason,
            "authorized": authorized,
            "outcome": outcome.value,
            "authorized_access_count": count,
            "detail": detail,
        }
        record = HoldoutAccessRecord(
            event_id=hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            requested_at=requested_at,
            requester=requester,
            reason=reason,
            authorized=authorized,
            outcome=outcome,
            authorized_access_count=count,
            detail=detail,
        )
        return record

    def _run_confirmatory_locked(
        self,
        journal: int,
        session: HoldoutRevealSession,
        *,
        coordinator: object,
        ledger_path: str | os.PathLike[str],
        study_version: object,
        fresh_custody_evidence: object,
        reveal_authority: object,
        artifact_registry: object,
        custody_provider: object,
        validity_snapshot: object,
        start_event: object,
        evaluator_spec: ConfirmatoryEvaluatorSpec,
        execution_class: RevealExecutionClass,
        requester: str,
        reason: str,
        requested_at: str | None = None,
        custody_record: object | None = None,
    ) -> tuple[HoldoutRelease, Any]:
        """Run the exact content validator before this provider can RELEASE.

        There is no minted token, issuer, callback, or caller-supplied hash
        shortcut.  Even a direct caller holding the live session must provide
        the complete typed authority, which is independently re-resolved before
        STARTED is appended.  RELEASE remains evaluation-pending until a second
        fsynced terminal event is appended under this same custody lock.
        """

        from .recovery import (
            RecoveryManager,
            SimulatedReserveRevealSelection,
            _ResolvedConfirmatoryAdmission,
        )

        if isinstance(journal, bool) or not isinstance(journal, int) or journal < 0:
            raise HoldoutJournalError("locked reveal requires a durable journal descriptor")
        if (
            type(session) is not _SimulatedRevealSession
            or session._provider is not self
            or session._descriptor != journal
            or session._active is not True
            or custody_provider is not self
        ):
            raise HoldoutAccessViolation(
                "locked reveal session does not belong to this custody provider"
            )
        if type(coordinator) is not RecoveryManager:
            raise HoldoutAccessViolation("confirmatory coordinator type is invalid")
        if (
            type(reveal_authority) is SimulatedReserveRevealSelection
            or hasattr(session, "_simulated_reserve_resource_binding")
        ):
            # A caller can transfer a session without mutating private fields.
            # Reject foreign lifetime/thread use before the native requester
            # policy could append an ACCESS record, not just before STARTED.
            _require_simulated_reserve_resource_binding(
                session, self, coordinator.project_root
            )
        if type(evaluator_spec) is not ConfirmatoryEvaluatorSpec:
            raise HoldoutPreconditionError(
                "confirmatory evaluator must be the closed repository-owned spec"
            )
        if not isinstance(execution_class, RevealExecutionClass):
            raise HoldoutPreconditionError("reveal execution class must be typed")
        if execution_class is RevealExecutionClass.SCIENTIFIC_CONFIRMATION:
            raise HoldoutAccessViolation(
                "simulated custody cannot authorize scientific confirmation"
            )
        requester = _nonempty(requester, "requester")
        reason = _nonempty(reason, "reason")
        when = requested_at or _now()
        _nonempty(when, "requested_at")
        if self._seal is None or self._payload is None:
            if self._release is not None:
                raise HoldoutAlreadyRevealed("confirmatory holdout was already revealed")
            raise HoldoutPreconditionError("holdout has not been sealed")
        if self._violations:
            raise HoldoutAccessViolation("holdout was invalidated before reveal")
        if self._release is not None or self._authorized_access_count:
            raise HoldoutAlreadyRevealed("confirmatory holdout was already revealed")
        if requester not in self._authorized_requesters:
            detail = "requester is not authorized by the sealed custody policy"
            record = self._make_record(
                requested_at=when,
                requester=requester,
                reason=reason,
                authorized=False,
                outcome=AccessOutcome.UNAUTHORIZED_VIOLATION,
                detail=detail,
            )
            self._append_journal_locked(
                journal,
                "ACCESS",
                {"record": _enum_dict(record), "violation_reason": detail},
            )
            self._records.append(record)
            self._violations.append(detail)
            raise HoldoutAccessViolation(detail)

        native_request_arguments = (
            {
                "_native_requester": requester,
                "_native_reason": reason,
                "_native_requested_at": when,
                "_native_evaluator_spec": evaluator_spec,
            }
            if type(reveal_authority) is SimulatedReserveRevealSelection
            else {}
        )
        admission = RecoveryManager._admit_confirmatory_locked(
            coordinator,
            ledger_path=ledger_path,
            study_version=study_version,
            fresh_custody_evidence=fresh_custody_evidence,
            reveal_authority=reveal_authority,
            artifact_registry=artifact_registry,
            custody_provider=custody_provider,
            validity_snapshot=validity_snapshot,
            start_event=start_event,
            _locked_session=session,
            _execution_class=execution_class,
            custody_record=custody_record,
            **native_request_arguments,
        )
        if type(admission) is not _ResolvedConfirmatoryAdmission:
            raise HoldoutAccessViolation("confirmatory admission result type is invalid")
        supplied = {
            "protocol_hash": admission.protocol_hash,
            "code_hash": admission.code_hash,
            "configuration_hash": admission.configuration_hash,
            "split_manifest_hash": admission.split_manifest_hash,
            "pre_unblinding_interpretation_hash": admission.blind_interpretation_hash,
        }
        if any(value != getattr(self._seal, name) for name, value in supplied.items()):
            raise HoldoutAccessViolation(
                "resolved reveal authority differs from the sealed holdout"
            )
        authority = _release_authority(
            {
                "schema_version": "1.0",
                "evidence_class": (
                    "SCIENTIFIC_EVIDENCE"
                    if execution_class
                    is RevealExecutionClass.SCIENTIFIC_CONFIRMATION
                    else "ARCHITECTURE_CONTROL"
                ),
                "ledger_run_id": admission.ledger_run_id,
                "protocol_hash": admission.protocol_hash,
                "code_hash": admission.code_hash,
                "configuration_hash": admission.configuration_hash,
                "split_manifest_hash": admission.split_manifest_hash,
                "blind_interpretation_hash": admission.blind_interpretation_hash,
                "resource_authority_sha256": admission.resource_authority_sha256,
                "evaluator_implementation_sha256": (
                    admission.evaluator_implementation_sha256
                ),
                "started_event_id": admission.started_event_id,
                "started_event_hash": admission.started_event_hash,
            },
            seal=self._seal,
        )
        record = self._make_record(
            requested_at=when,
            requester=requester,
            reason=reason,
            authorized=True,
            outcome=AccessOutcome.RELEASED,
            detail=(
                "single authorized confirmatory reveal"
                if execution_class
                is RevealExecutionClass.SCIENTIFIC_CONFIRMATION
                else "single non-evidentiary simulated fixture release"
            ),
            authorized_access_count=1,
        )
        release_body = {
            "seal_hash": self._seal.seal_hash,
            "released_at": when,
            "requester": requester,
            "reason": reason,
            "authorized_access_count": 1,
        }
        release = HoldoutRelease(
            release_id=hashlib.sha256(
                json.dumps(release_body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            released_at=when,
            requester=requester,
            reason=reason,
            seal_hash=self._seal.seal_hash,
            holdout_identity_hash=self._seal.holdout_identity_hash,
            authorized_access_count=1,
        )
        payload = self._payload
        if payload is None:
            raise HoldoutJournalError("sealed payload is unavailable for the durable reveal")
        self._append_journal_locked(
            journal,
            "RELEASE",
            {
                "record": _enum_dict(record),
                "release": _enum_dict(release),
                "authority": authority,
            },
        )
        self._records.append(record)
        self._authorized_access_count = 1
        self._payload = None
        self._release = release
        self._release_authority = authority
        self._evaluation_outcome = None
        self._evaluation_terminal_payload = None
        evaluator_binding = {
            "evaluator_id": evaluator_spec.evaluator_id,
            "implementation_path": evaluator_spec.implementation_path,
            "implementation_sha256": admission.evaluator_implementation_sha256,
            "source_inventory_sha256": admission.code_hash,
            "configuration_inventory_sha256": admission.configuration_hash,
            "input_schema_sha256": evaluator_spec.input_schema_sha256,
            "result_schema_sha256": evaluator_spec.result_schema_sha256,
        }
        try:
            # No caller-supplied or replaceable evaluator callable receives the
            # sealed bytes.  Admission has just rebound this exact module file
            # to the frozen source inventory before this inline implementation
            # interprets the payload.
            fixture = safe_json_loads(payload, max_bytes=1024 * 1024)
            if not isinstance(fixture, dict) or set(fixture) != {
                "control",
                "treatment",
            }:
                raise HoldoutCustodyError(
                    "sealed simulated confirmatory payload schema is invalid"
                )
            groups: dict[str, list[float]] = {}
            for name in ("control", "treatment"):
                raw = fixture.get(name)
                if (
                    not isinstance(raw, list)
                    or len(raw) != 4
                    or any(
                        isinstance(item, bool)
                        or not isinstance(item, (int, float))
                        or not math.isfinite(float(item))
                        for item in raw
                    )
                ):
                    raise HoldoutCustodyError(
                        "sealed simulated confirmatory group schema is invalid"
                    )
                groups[name] = [float(item) for item in raw]
            control_mean = sum(groups["control"]) / len(groups["control"])
            treatment_mean = sum(groups["treatment"]) / len(groups["treatment"])
            result = {
                "schema_version": "1.0",
                "kind": "SIMULATED_TWO_GROUP_MEAN_DIFFERENCE",
                "control_mean": control_mean,
                "treatment_mean": treatment_mean,
                "primary_estimate": treatment_mean - control_mean,
                "n_control": len(groups["control"]),
                "n_treatment": len(groups["treatment"]),
            }
        except BaseException as exc:
            failed_terminal = {
                "release_id": release.release_id,
                "outcome": "FAILED",
                "evaluator_binding": evaluator_binding,
                "result": None,
                "result_sha256": None,
            }
            try:
                self._append_journal_locked(
                    journal,
                    "EVALUATION_FAILED",
                    failed_terminal,
                )
            except BaseException as terminal_exc:
                raise HoldoutJournalError(
                    "confirmatory evaluation failed and terminal invalidation is pending"
                ) from terminal_exc
            self._evaluation_outcome = "FAILED"
            self._evaluation_terminal_payload = failed_terminal
            raise HoldoutCustodyError("confirmatory evaluator failed after RELEASE") from exc
        succeeded_terminal = {
            "release_id": release.release_id,
            "outcome": "SUCCEEDED",
            "evaluator_binding": evaluator_binding,
            "result": result,
            "result_sha256": hashlib.sha256(canonical_json_bytes(result)).hexdigest(),
        }
        self._append_journal_locked(
            journal,
            "EVALUATION_SUCCEEDED",
            succeeded_terminal,
        )
        self._evaluation_outcome = "SUCCEEDED"
        self._evaluation_terminal_payload = succeeded_terminal
        return release, result

    def record_violation(
        self,
        *,
        requester: str,
        reason: str,
        occurred_at: str | None = None,
    ) -> None:
        """Record an accidental/out-of-band access and invalidate claims."""

        requester = _nonempty(requester, "requester")
        reason = _nonempty(reason, "reason")
        when = occurred_at or _now()
        with self._lock, self._journal_guard() as journal:
            record = self._make_record(
                requested_at=when,
                requester=requester,
                reason=reason,
                authorized=False,
                outcome=AccessOutcome.ACCIDENTAL_ACCESS_VIOLATION,
                detail="reported access invalidates this holdout for confirmatory claims",
            )
            self._append_journal_locked(
                journal,
                "ACCESS",
                {"record": _enum_dict(record), "violation_reason": reason},
            )
            self._records.append(record)
            self._violations.append(reason)

    @property
    def seal_record(self) -> HoldoutSeal | None:
        with self._lock, self._journal_guard():
            return self._seal

    @property
    def access_records(self) -> tuple[HoldoutAccessRecord, ...]:
        with self._lock, self._journal_guard():
            return tuple(self._records)

    @property
    def status(self) -> CustodyStatus:
        with self._lock, self._journal_guard():
            return self._status_locked()

    def assert_confirmatory_claims_valid(self) -> None:
        status = self.status
        if not status.confirmatory_claims_valid:
            raise HoldoutAccessViolation(
                "holdout is not eligible for confirmatory claims: it is unrevealed or invalidated"
            )

class HumanControlledHoldoutCustody(HoldoutCustody, ABC):
    """Future adapter contract; an actual human attestation is mandatory."""

    independence = CustodyIndependence.HUMAN_INDEPENDENT

    @abstractmethod
    def verify_human_attestation(self, attestation_id: str) -> bool:
        raise NotImplementedError


class IndependentServiceHoldoutCustody(HoldoutCustody, ABC):
    """Future remote/service contract; no local implementation is implied."""

    independence = CustodyIndependence.SERVICE_INDEPENDENT

    @abstractmethod
    def verify_service_attestation(self, attestation: bytes) -> bool:
        raise NotImplementedError


__all__ = [
    "HoldoutCustodyError",
    "HoldoutPreconditionError",
    "HoldoutAccessViolation",
    "HoldoutAlreadyRevealed",
    "CustodyIndependence",
    "AccessOutcome",
    "RevealExecutionClass",
    "HoldoutSeal",
    "HoldoutAccessRecord",
    "HoldoutRelease",
    "ReleasedHoldout",
    "ConfirmatoryEvaluatorSpec",
    "CustodyStatus",
    "HoldoutAdmissionSnapshot",
    "CustodyAdmissionSnapshot",
    "HoldoutRevealSession",
    "HoldoutCustody",
    "SimulatedHoldoutCustody",
    "HumanControlledHoldoutCustody",
    "IndependentServiceHoldoutCustody",
]
