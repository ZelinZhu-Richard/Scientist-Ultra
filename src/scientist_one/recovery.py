"""Fail-closed restart validation and confined partial-write quarantine.

Recovery treats the append-only ledger as authoritative.  Cached state and
checkpoint modification times are never trusted.  A confirmatory run or
holdout access observed anywhere in the validated ledger/custody record is an
irreversible fact: missing output does not authorize a confirmatory rerun.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Callable, Iterable, Mapping, Never, Sequence

from .artifacts import (
    ArtifactRecord,
    ArtifactRegistry,
    MAX_ARTIFACT_OBJECT_BYTES,
    MAX_REGISTRY_RECORDS,
)
from .errors import PathSecurityError, UnsafeSerializationError
from .holdout import (
    ConfirmatoryEvaluatorSpec,
    CustodyAdmissionSnapshot,
    HoldoutRelease,
    RevealExecutionClass,
)
from .ledger import EventLedger, LedgerEvent
from .models import MacroState
from .security import (
    atomic_write_bytes,
    open_confined_directory_fd,
    read_confined_bytes,
    safe_json_loads,
    secure_directory,
)
from .state_machine import StateController, validate_legacy_transition_prefix

try:  # Scientist-One's supported runtime is POSIX/macOS.
    import fcntl
except ImportError:  # pragma: no cover - fail closed on unsupported platforms
    fcntl = None  # type: ignore[assignment]


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
RESOURCE_AUTHORITY_NAME_PATTERN = re.compile(
    r"^(?P<sequence>[0-9]{4})-(?P<digest>[0-9a-f]{64})\.json$"
)
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CONFIRMATION_REVEAL_GATE_RECEIPT_LOGICAL_TYPE = (
    "confirmation_reveal_gate_receipt"
)
CONFIRMATION_REVEAL_GATE_RECEIPT_SCHEMA_VERSION = "1.0"
CONFIRMATION_REVEAL_EVIDENCE_ARCHITECTURE_CONTROL = "ARCHITECTURE_CONTROL"
CONFIRMATION_REVEAL_EVIDENCE_SCIENTIFIC = "SCIENTIFIC_EVIDENCE"
CONFIRMATION_REVEAL_STATUS_BLOCKED_NON_INDEPENDENT = (
    "BLOCKED_NON_INDEPENDENT_CUSTODY"
)
CONFIRMATION_REVEAL_STATUS_VERIFIED_INDEPENDENT = (
    "VERIFIED_INDEPENDENT_CUSTODY"
)
GENESIS_HASHES = {None}
INCOMPLETE_SUFFIXES = (".partial", ".incomplete", ".tmp")
CURRENT_CHECKPOINT_SCHEMA = "1.0"
MAX_CHECKPOINT_ENTRIES = 10_000
MAX_CHECKPOINT_SELECTION_BYTES = 64 * 1024**2


class RecoveryError(RuntimeError):
    """Base class for unsafe or invalid recovery state."""


class LedgerValidationError(RecoveryError):
    pass


class ArtifactValidationError(RecoveryError):
    pass


class ConfirmatoryRerunError(RecoveryError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def event_digest(event: Mapping[str, object]) -> str:
    canonical = {key: value for key, value in event.items() if key != "event_hash"}
    return hashlib.sha256(canonical_json_bytes(canonical)).hexdigest()


def checkpoint_digest(checkpoint: Mapping[str, object]) -> str:
    canonical = {key: value for key, value in checkpoint.items() if key != "checkpoint_hash"}
    return hashlib.sha256(canonical_json_bytes(canonical)).hexdigest()


def _confirmatory_start_preserves_head(
    event: Mapping[str, object],
    *,
    ledger_head_state: object,
    scientific: bool,
) -> bool:
    """Validate a STARTED marker without granting it transition semantics."""

    before = event.get("state_before")
    after = event.get("requested_state_after")
    if (
        not isinstance(before, str)
        or before != after
        or before != ledger_head_state
    ):
        return False
    if scientific:
        return before == MacroState.CONFIRM.value
    return before in {state.value for state in MacroState}


@dataclass(frozen=True)
class LedgerValidationResult:
    valid: bool
    events: tuple[Mapping[str, object], ...]
    head_hash: str | None
    run_id: str | None
    error: str | None = None
    error_line: int | None = None
    recoverable_truncated_tail: bool = False
    valid_prefix_bytes: int = 0
    tail_bytes: int = 0
    source_sha256: str | None = None
    source_size: int | None = None
    source_device: int | None = None
    source_inode: int | None = None

    @property
    def event_count(self) -> int:
        return len(self.events)


@dataclass(frozen=True)
class ArtifactIssue:
    index: int
    path: str | None
    code: str
    detail: str
    frozen: bool


@dataclass(frozen=True)
class ArtifactValidationResult:
    valid: bool
    records_validated: int
    records: tuple[Mapping[str, object], ...]
    issues: tuple[ArtifactIssue, ...] = ()

    @property
    def has_frozen_failure(self) -> bool:
        return any(issue.frozen for issue in self.issues)


@dataclass(frozen=True)
class QuarantineRecord:
    original_relative_path: str
    quarantine_relative_path: str
    reason: str
    size_bytes: int
    sha256: str
    metadata_relative_path: str


@dataclass(frozen=True)
class CheckpointSelection:
    path: str
    checkpoint: Mapping[str, object]
    ledger_event_index: int


@dataclass(frozen=True)
class FreshCustodyEvidence:
    """Selectors for a frozen receipt; live state comes only from its provider."""

    receipt_artifact_sha256: str
    artifact_record_hash: str
    ledger_event_id: str

    def __post_init__(self) -> None:
        for name in ("receipt_artifact_sha256", "artifact_record_hash"):
            value = getattr(self, name)
            if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
                raise RecoveryError(f"fresh custody {name} must be SHA-256")
        if not isinstance(self.ledger_event_id, str) or not self.ledger_event_id:
            raise RecoveryError("fresh custody ledger_event_id must be non-empty")


@dataclass(frozen=True)
class RegisteredArtifactSelector:
    """Exact content and metadata identity for one registered artifact."""

    artifact_sha256: str
    artifact_record_hash: str

    def __post_init__(self) -> None:
        for name in ("artifact_sha256", "artifact_record_hash"):
            value = getattr(self, name)
            if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
                raise RecoveryError(f"reveal authority {name} must be SHA-256")


@dataclass(frozen=True)
class SimulatedReserveRevealSelection:
    """Exact S/Q locators for the non-evidentiary native reserve profile.

    This is not a second release authority. The native locked coordinator
    replays both records and their complete contract/accounting dependencies.
    """

    reservation: RegisteredArtifactSelector
    resource_charge: RegisteredArtifactSelector

    def __post_init__(self) -> None:
        for name in ("reservation", "resource_charge"):
            selector = getattr(self, name)
            if type(selector) is not RegisteredArtifactSelector or any(
                type(getattr(selector, field)) is not str
                or SHA256_PATTERN.fullmatch(getattr(selector, field)) is None
                for field in ("artifact_sha256", "artifact_record_hash")
            ):
                raise RecoveryError("simulated reserve selector must be exact native identity")


@dataclass(frozen=True)
class ConfirmatoryRevealAuthority:
    """Selectors whose registered contents must authorize one reveal.

    Values here are locators, never attestations.  The coordinator re-resolves
    every record, payload, parent edge, and ledger binding while custody is
    locked, then derives the hashes supplied to the provider seal.
    """

    protocol: RegisteredArtifactSelector
    source_inventory: RegisteredArtifactSelector
    configuration_inventory: RegisteredArtifactSelector
    split_manifest: RegisteredArtifactSelector
    blind_interpretation: RegisteredArtifactSelector
    midrun_review: RegisteredArtifactSelector
    resource_charge: RegisteredArtifactSelector
    resource_charge_ledger_event_id: str
    confirmatory_validity_units: int

    def __post_init__(self) -> None:
        for name in (
            "protocol",
            "source_inventory",
            "configuration_inventory",
            "split_manifest",
            "blind_interpretation",
            "midrun_review",
            "resource_charge",
        ):
            if not isinstance(getattr(self, name), RegisteredArtifactSelector):
                raise RecoveryError(f"reveal authority {name} selector is invalid")
        if (
            not isinstance(self.resource_charge_ledger_event_id, str)
            or not self.resource_charge_ledger_event_id
        ):
            raise RecoveryError("resource charge ledger event ID must be non-empty")
        if (
            isinstance(self.confirmatory_validity_units, bool)
            or not isinstance(self.confirmatory_validity_units, int)
            or self.confirmatory_validity_units <= 0
        ):
            raise RecoveryError("confirmatory validity units must be a positive integer")


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise RecoveryError(f"invalid {label}")
    return value


def confirmation_reveal_gate_object_id(
    run_id: str,
    study_id: str,
    study_version: int,
) -> str:
    """Return the exact opaque HumanGate object ID for one reveal boundary."""

    _identifier(run_id, "confirmation reveal run ID")
    _identifier(study_id, "confirmation reveal study ID")
    if (
        isinstance(study_version, bool)
        or not isinstance(study_version, int)
        or study_version < 1
    ):
        raise RecoveryError("confirmation reveal study version must be positive")
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "run_id": run_id,
                "study_id": study_id,
                "study_version": study_version,
            }
        )
    ).hexdigest()
    return f"confirmation-reveal-{digest}"


@dataclass(frozen=True)
class ConfirmationRevealGateReceipt:
    """Artifact-only replay result for the exact pre-reveal boundary.

    The typed contract can represent future HUMAN_INDEPENDENT or
    SERVICE_INDEPENDENT evidence only when a source-owned resolver supplies an
    exact external attestation.  This module's only implemented producer is
    simulated and NON_INDEPENDENT, so it always emits blocked architecture-
    control evidence and cannot be promoted merely by changing a label.
    """

    receipt_id: str
    run_id: str
    ledger_path: str
    object_id: str
    study_id: str
    study_version: int
    started_event_id: str
    started_event_hash: str
    started_event_index: int
    custody_independence: str
    custody_journal_head_hash: str
    custody_journal_identity_sha256: str
    evidence_class: str
    verification_status: str
    external_custody_attestation_sha256: str | None
    fresh_custody_evidence: FreshCustodyEvidence
    reveal_authority: ConfirmatoryRevealAuthority

    def __post_init__(self) -> None:
        for name in (
            "receipt_id",
            "run_id",
            "object_id",
            "study_id",
            "started_event_id",
        ):
            _identifier(getattr(self, name), name)
        if not isinstance(self.ledger_path, str) or not self.ledger_path:
            raise RecoveryError("confirmation reveal ledger path is invalid")
        if Path(self.ledger_path).is_absolute() or ".." in Path(self.ledger_path).parts:
            raise RecoveryError("confirmation reveal ledger path is unsafe")
        if (
            isinstance(self.study_version, bool)
            or not isinstance(self.study_version, int)
            or self.study_version < 1
            or isinstance(self.started_event_index, bool)
            or not isinstance(self.started_event_index, int)
            or self.started_event_index < 0
        ):
            raise RecoveryError("confirmation reveal receipt indexes are invalid")
        for name in (
            "started_event_hash",
            "custody_journal_head_hash",
            "custody_journal_identity_sha256",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
                raise RecoveryError(f"confirmation reveal {name} must be SHA-256")
        if self.custody_independence == "NON_INDEPENDENT":
            if (
                self.evidence_class
                != CONFIRMATION_REVEAL_EVIDENCE_ARCHITECTURE_CONTROL
                or self.verification_status
                != CONFIRMATION_REVEAL_STATUS_BLOCKED_NON_INDEPENDENT
                or self.external_custody_attestation_sha256 is not None
            ):
                raise RecoveryError(
                    "non-independent confirmation reveal evidence cannot be promoted"
                )
        elif self.custody_independence in {
            "HUMAN_INDEPENDENT",
            "SERVICE_INDEPENDENT",
        }:
            if (
                self.evidence_class
                != CONFIRMATION_REVEAL_EVIDENCE_SCIENTIFIC
                or self.verification_status
                != CONFIRMATION_REVEAL_STATUS_VERIFIED_INDEPENDENT
                or not isinstance(
                    self.external_custody_attestation_sha256,
                    str,
                )
                or SHA256_PATTERN.fullmatch(
                    self.external_custody_attestation_sha256
                )
                is None
            ):
                raise RecoveryError(
                    "independent confirmation reveal evidence lacks an external attestation"
                )
        else:
            raise RecoveryError("confirmation reveal custody independence is invalid")
        if not isinstance(self.fresh_custody_evidence, FreshCustodyEvidence):
            raise RecoveryError("confirmation reveal fresh-custody selector is invalid")
        if not isinstance(self.reveal_authority, ConfirmatoryRevealAuthority):
            raise RecoveryError("confirmation reveal authority selector is invalid")
        if self.object_id != confirmation_reveal_gate_object_id(
            self.run_id,
            self.study_id,
            self.study_version,
        ):
            raise RecoveryError("confirmation reveal object ID is not canonical")

    @property
    def scientific_gate_passed(self) -> bool:
        return (
            self.custody_independence
            in {"HUMAN_INDEPENDENT", "SERVICE_INDEPENDENT"}
            and self.evidence_class
            == CONFIRMATION_REVEAL_EVIDENCE_SCIENTIFIC
            and self.verification_status
            == CONFIRMATION_REVEAL_STATUS_VERIFIED_INDEPENDENT
            and self.external_custody_attestation_sha256 is not None
        )

    @staticmethod
    def _selector_dict(selector: RegisteredArtifactSelector) -> dict[str, str]:
        return {
            "artifact_sha256": selector.artifact_sha256,
            "artifact_record_hash": selector.artifact_record_hash,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": CONFIRMATION_REVEAL_GATE_RECEIPT_SCHEMA_VERSION,
            "receipt_id": self.receipt_id,
            "run_id": self.run_id,
            "ledger_path": self.ledger_path,
            "object_id": self.object_id,
            "study_id": self.study_id,
            "study_version": self.study_version,
            "started_event_id": self.started_event_id,
            "started_event_hash": self.started_event_hash,
            "started_event_index": self.started_event_index,
            "custody_independence": self.custody_independence,
            "custody_journal_head_hash": self.custody_journal_head_hash,
            "custody_journal_identity_sha256": (
                self.custody_journal_identity_sha256
            ),
            "evidence_class": self.evidence_class,
            "verification_status": self.verification_status,
            "external_custody_attestation_sha256": (
                self.external_custody_attestation_sha256
            ),
            "fresh_custody_evidence": {
                "receipt_artifact_sha256": (
                    self.fresh_custody_evidence.receipt_artifact_sha256
                ),
                "artifact_record_hash": (
                    self.fresh_custody_evidence.artifact_record_hash
                ),
                "ledger_event_id": self.fresh_custody_evidence.ledger_event_id,
            },
            "reveal_authority": {
                name: self._selector_dict(getattr(self.reveal_authority, name))
                for name in (
                    "protocol",
                    "source_inventory",
                    "configuration_inventory",
                    "split_manifest",
                    "blind_interpretation",
                    "midrun_review",
                    "resource_charge",
                )
            }
            | {
                "resource_charge_ledger_event_id": (
                    self.reveal_authority.resource_charge_ledger_event_id
                ),
                "confirmatory_validity_units": (
                    self.reveal_authority.confirmatory_validity_units
                ),
            },
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ConfirmationRevealGateReceipt":
        expected = set(cls.__dataclass_fields__) | {"schema_version"}
        if set(value) != expected or value.get("schema_version") != (
            CONFIRMATION_REVEAL_GATE_RECEIPT_SCHEMA_VERSION
        ):
            raise RecoveryError("confirmation reveal receipt schema is invalid")
        fresh = value.get("fresh_custody_evidence")
        authority = value.get("reveal_authority")
        if not isinstance(fresh, Mapping) or set(fresh) != {
            "receipt_artifact_sha256",
            "artifact_record_hash",
            "ledger_event_id",
        }:
            raise RecoveryError("confirmation reveal fresh-custody schema is invalid")
        selector_names = (
            "protocol",
            "source_inventory",
            "configuration_inventory",
            "split_manifest",
            "blind_interpretation",
            "midrun_review",
            "resource_charge",
        )
        if not isinstance(authority, Mapping) or set(authority) != {
            *selector_names,
            "resource_charge_ledger_event_id",
            "confirmatory_validity_units",
        }:
            raise RecoveryError("confirmation reveal authority schema is invalid")
        selectors: dict[str, RegisteredArtifactSelector] = {}
        for name in selector_names:
            item = authority.get(name)
            if not isinstance(item, Mapping) or set(item) != {
                "artifact_sha256",
                "artifact_record_hash",
            }:
                raise RecoveryError("confirmation reveal selector schema is invalid")
            selectors[name] = RegisteredArtifactSelector(
                str(item["artifact_sha256"]),
                str(item["artifact_record_hash"]),
            )
        try:
            arguments = {
                name: value[name]
                for name in cls.__dataclass_fields__
                if name not in {"fresh_custody_evidence", "reveal_authority"}
            }
            arguments["fresh_custody_evidence"] = FreshCustodyEvidence(
                str(fresh["receipt_artifact_sha256"]),
                str(fresh["artifact_record_hash"]),
                str(fresh["ledger_event_id"]),
            )
            arguments["reveal_authority"] = ConfirmatoryRevealAuthority(
                **selectors,
                resource_charge_ledger_event_id=str(
                    authority["resource_charge_ledger_event_id"]
                ),
                confirmatory_validity_units=authority["confirmatory_validity_units"],
            )
            return cls(**arguments)
        except (KeyError, TypeError, ValueError) as exc:
            raise RecoveryError("confirmation reveal receipt is malformed") from exc


@dataclass(frozen=True)
class _ResolvedConfirmatoryAdmission:
    """Content-derived provider inputs after STARTED is durably re-read."""

    protocol_hash: str
    code_hash: str
    evaluator_implementation_sha256: str
    configuration_hash: str
    split_manifest_hash: str
    blind_interpretation_hash: str
    ledger_run_id: str
    resource_authority_sha256: str
    started_event_id: str
    started_event_hash: str


class ResumeAction(str, Enum):
    START_FRESH = "START_FRESH"
    RESUME_FROM_LEDGER = "RESUME_FROM_LEDGER"
    RESUME_FROM_CHECKPOINT = "RESUME_FROM_CHECKPOINT"
    SKIP_COMPLETED = "SKIP_COMPLETED"
    START_NEW_STUDY = "START_NEW_STUDY"
    NEW_STUDY_REQUIRED = "NEW_STUDY_REQUIRED"
    STOP_SECURITY = "STOP_SECURITY"
    STOP_SCIENTIFIC_INVALIDITY = "STOP_SCIENTIFIC_INVALIDITY"


@dataclass(frozen=True)
class RecoveryReport:
    action: ResumeAction
    reasons: tuple[str, ...]
    ledger_valid: bool
    ledger_event_count: int
    ledger_head_hash: str | None
    artifacts_valid: bool
    artifact_issues: tuple[ArtifactIssue, ...]
    quarantined: tuple[QuarantineRecord, ...]
    checkpoint: CheckpointSelection | None
    derived_state: str | None
    confirmatory_touched: bool
    confirmatory_completed: bool
    new_study_protocol_accepted: bool = False
    replay_event_count: int = 0

    @property
    def resumable(self) -> bool:
        return self.action in {
            ResumeAction.START_FRESH,
            ResumeAction.RESUME_FROM_LEDGER,
            ResumeAction.RESUME_FROM_CHECKPOINT,
            ResumeAction.START_NEW_STUDY,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action.value,
            "reasons": list(self.reasons),
            "ledger_valid": self.ledger_valid,
            "ledger_event_count": self.ledger_event_count,
            "ledger_head_hash": self.ledger_head_hash,
            "artifacts_valid": self.artifacts_valid,
            "artifact_issues": [asdict(issue) for issue in self.artifact_issues],
            "quarantined": [asdict(record) for record in self.quarantined],
            "checkpoint": (
                {
                    "path": self.checkpoint.path,
                    "ledger_event_index": self.checkpoint.ledger_event_index,
                    "checkpoint": dict(self.checkpoint.checkpoint),
                }
                if self.checkpoint
                else None
            ),
            "derived_state": self.derived_state,
            "confirmatory_touched": self.confirmatory_touched,
            "confirmatory_completed": self.confirmatory_completed,
            "new_study_protocol_accepted": self.new_study_protocol_accepted,
            "replay_event_count": self.replay_event_count,
        }


class RecoveryManager:
    """Validate, quarantine, and derive a safe resume plan within one root."""

    def __init__(
        self,
        project_root: str | os.PathLike[str],
        *,
        maximum_ledger_bytes: int = 64 * 1024**2,
        maximum_metadata_bytes: int = 16 * 1024**2,
        maximum_artifact_bytes: int = MAX_ARTIFACT_OBJECT_BYTES,
        maximum_scan_entries: int = 100_000,
        maximum_quarantine_candidates: int = 10_000,
        maximum_checkpoint_entries: int = MAX_CHECKPOINT_ENTRIES,
        maximum_checkpoint_selection_bytes: int = MAX_CHECKPOINT_SELECTION_BYTES,
        ledger_validator: Callable[[Path], LedgerValidationResult] | None = None,
        artifact_validator: Callable[[object], ArtifactValidationResult] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        root = Path(project_root)
        if not root.exists() or not root.is_dir() or root.is_symlink():
            raise RecoveryError("project_root must be an existing non-symlink directory")
        self.project_root = root.resolve()
        if self.project_root == Path(self.project_root.anchor):
            raise RecoveryError("project_root cannot be a filesystem root")
        home = Path.home().resolve()
        if self.project_root in {home, home / "dev", Path("/Users")}:
            raise RecoveryError("project_root cannot be a home or broad development directory")
        if isinstance(maximum_ledger_bytes, bool) or not isinstance(maximum_ledger_bytes, int):
            raise RecoveryError("maximum_ledger_bytes must be an integer")
        if maximum_ledger_bytes <= 0:
            raise RecoveryError("maximum_ledger_bytes must be positive")
        self.maximum_ledger_bytes = maximum_ledger_bytes
        if isinstance(maximum_metadata_bytes, bool) or not isinstance(maximum_metadata_bytes, int):
            raise RecoveryError("maximum_metadata_bytes must be an integer")
        if maximum_metadata_bytes <= 0:
            raise RecoveryError("maximum_metadata_bytes must be positive")
        self.maximum_metadata_bytes = maximum_metadata_bytes
        if isinstance(maximum_artifact_bytes, bool) or not isinstance(
            maximum_artifact_bytes, int
        ):
            raise RecoveryError("maximum_artifact_bytes must be an integer")
        if not 0 < maximum_artifact_bytes <= MAX_ARTIFACT_OBJECT_BYTES:
            raise RecoveryError("maximum_artifact_bytes exceeds the bounded registry contract")
        self.maximum_artifact_bytes = maximum_artifact_bytes
        for name, value in (
            ("maximum_scan_entries", maximum_scan_entries),
            ("maximum_quarantine_candidates", maximum_quarantine_candidates),
            ("maximum_checkpoint_entries", maximum_checkpoint_entries),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise RecoveryError(f"{name} must be a positive integer")
        self.maximum_scan_entries = maximum_scan_entries
        self.maximum_quarantine_candidates = maximum_quarantine_candidates
        self.maximum_checkpoint_entries = maximum_checkpoint_entries
        if (
            isinstance(maximum_checkpoint_selection_bytes, bool)
            or not isinstance(maximum_checkpoint_selection_bytes, int)
            or not 0
            < maximum_checkpoint_selection_bytes
            <= MAX_CHECKPOINT_SELECTION_BYTES
        ):
            raise RecoveryError(
                "maximum_checkpoint_selection_bytes must be a positive integer "
                f"no greater than {MAX_CHECKPOINT_SELECTION_BYTES}"
            )
        self.maximum_checkpoint_selection_bytes = maximum_checkpoint_selection_bytes
        self._ledger_validator = ledger_validator
        self._artifact_validator = artifact_validator
        self._now = now or (lambda: datetime.now(timezone.utc))

    def _relative_path(self, raw_path: str | os.PathLike[str]) -> Path:
        raw = Path(raw_path)
        if any(part in {"", ".."} for part in raw.parts) or "\x00" in os.fspath(raw):
            raise RecoveryError("path traversal or malformed path is prohibited")
        if raw.is_absolute():
            try:
                relative = raw.relative_to(self.project_root)
            except ValueError as exc:
                raise RecoveryError("path escapes project_root") from exc
        else:
            relative = raw
        if not relative.parts or relative.name in {"", ".", ".."}:
            raise RecoveryError("recovery path is empty or malformed")
        return relative

    def _read_regular_bytes(
        self, path: Path, *, maximum_bytes: int
    ) -> tuple[bytes, os.stat_result]:
        """Read one immutable file identity without following links."""

        relative = self._relative_path(path)
        directory_fd: int | None = None
        descriptor: int | None = None
        try:
            directory_fd = open_confined_directory_fd(
                self.project_root, relative.parent, create=False
            )
            descriptor = os.open(
                relative.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
            ):
                raise RecoveryError(f"recovery input is not a private regular file: {path}")
            if opened.st_size > maximum_bytes:
                raise RecoveryError(f"recovery input exceeds size limit: {path}")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(maximum_bytes + 1)
            after = os.fstat(descriptor)
            if len(data) > maximum_bytes:
                raise RecoveryError(f"recovery input exceeds size limit: {path}")
            if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise RecoveryError(f"recovery input changed while being read: {path}")
            return data, opened
        except (OSError, PathSecurityError) as exc:
            raise RecoveryError(f"cannot read recovery input safely {path}: {exc}") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory_fd is not None:
                os.close(directory_fd)

    def validate_ledger(
        self,
        ledger_path: str | os.PathLike[str],
        *,
        _bypass_injected_validator: bool = False,
    ) -> LedgerValidationResult:
        path = self.project_root / self._relative_path(ledger_path)
        if self._ledger_validator is not None and not _bypass_injected_validator:
            result = self._ledger_validator(path)
            if not isinstance(result, LedgerValidationResult):
                raise LedgerValidationError(
                    "injected ledger validator returned an invalid result"
                )
            return result
        try:
            data, opened_info = self._read_regular_bytes(
                path, maximum_bytes=self.maximum_ledger_bytes
            )
        except RecoveryError as exc:
            return LedgerValidationResult(False, (), None, None, f"LEDGER_READ_FAILED:{exc}")
        source_sha256 = hashlib.sha256(data).hexdigest()
        if not data:
            return LedgerValidationResult(True, (), None, None, valid_prefix_bytes=0)

        lines = data.splitlines(keepends=True)
        events: list[Mapping[str, object]] = []
        event_ids: set[str] = set()
        event_hashes: set[str] = set()
        run_id: str | None = None
        previous_hash: str | None = None
        offset = 0
        for line_number, encoded in enumerate(lines, start=1):
            line_start = offset
            offset += len(encoded)
            has_terminator = encoded.endswith((b"\n", b"\r"))
            payload = encoded.rstrip(b"\r\n")
            if not payload:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "EMPTY_LEDGER_LINE",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            if len(encoded) > self.maximum_metadata_bytes:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "LEDGER_EVENT_SIZE_LIMIT_EXCEEDED",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            try:
                parsed = safe_json_loads(payload, max_bytes=self.maximum_metadata_bytes)
            except (UnicodeDecodeError, UnsafeSerializationError, ValueError, RecursionError) as exc:
                recoverable = line_number == len(lines) and not has_terminator and bool(events)
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    f"MALFORMED_LEDGER_JSON:{exc}",
                    line_number,
                    recoverable_truncated_tail=recoverable,
                    valid_prefix_bytes=line_start,
                    tail_bytes=len(data) - line_start,
                    source_sha256=source_sha256,
                    source_size=opened_info.st_size,
                    source_device=opened_info.st_dev,
                    source_inode=opened_info.st_ino,
                )
            if line_number == len(lines) and not has_terminator:
                # A fully parseable event without its trailing newline is
                # ambiguous, not an unambiguously partial append.  Never erase
                # a potentially irreversible confirmatory-start event.
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "AMBIGUOUS_FINAL_EVENT_WITHOUT_NEWLINE",
                    line_number,
                    recoverable_truncated_tail=False,
                    valid_prefix_bytes=line_start,
                    tail_bytes=len(data) - line_start,
                    source_sha256=source_sha256,
                    source_size=opened_info.st_size,
                    source_device=opened_info.st_dev,
                    source_inode=opened_info.st_ino,
                )
            if not isinstance(parsed, dict):
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "LEDGER_EVENT_NOT_OBJECT",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            raw_claimed_hash = parsed.get("event_hash")
            if not isinstance(raw_claimed_hash, str) or not SHA256_PATTERN.fullmatch(
                raw_claimed_hash
            ):
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "INVALID_EVENT_HASH",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            try:
                raw_actual_hash = event_digest(parsed)
            except (TypeError, ValueError) as exc:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    f"UNCANONICALIZABLE_EVENT:{exc}",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            if not hmac.compare_digest(raw_actual_hash, raw_claimed_hash):
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "EVENT_HASH_MISMATCH",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            # The authoritative ledger model is the versioned schema contract;
            # recovery must not accept a weaker event than normal execution.
            try:
                from .ledger import LedgerEvent

                typed_event = LedgerEvent.from_dict(parsed)
                parsed = typed_event.to_dict()
            except Exception as exc:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    f"INVALID_EVENT_SCHEMA:{type(exc).__name__}",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            event_id = typed_event.event_id
            current_run_id = typed_event.run_id
            claimed_hash = typed_event.event_hash
            prior_hash = typed_event.prior_event_hash
            if not isinstance(event_id, str) or not event_id:
                error = "MISSING_EVENT_ID"
            elif event_id in event_ids:
                error = "DUPLICATE_EVENT_ID"
            elif claimed_hash in event_hashes:
                error = "DUPLICATE_EVENT_HASH"
            elif not isinstance(current_run_id, str) or not current_run_id:
                error = "MISSING_RUN_ID"
            elif run_id is not None and current_run_id != run_id:
                error = "RUN_ID_CHANGED"
            elif not isinstance(claimed_hash, str) or not SHA256_PATTERN.fullmatch(claimed_hash):
                error = "INVALID_EVENT_HASH"
            elif line_number == 1 and prior_hash not in GENESIS_HASHES:
                error = "INVALID_GENESIS_PRIOR_HASH"
            elif line_number > 1 and prior_hash != previous_hash:
                error = "BROKEN_HASH_CHAIN"
            elif events and typed_event.state_before.value != str(
                events[-1].get("requested_state_after")
            ):
                error = "STATE_CONTINUITY_MISMATCH"
            elif (
                typed_event.event_type == "CORRECTION"
                and typed_event.supersedes_event_id not in event_ids
            ):
                error = "INVALID_SUPERSEDED_EVENT"
            else:
                try:
                    actual_hash = event_digest(parsed)
                except (TypeError, ValueError) as exc:
                    error = f"UNCANONICALIZABLE_EVENT:{exc}"
                else:
                    error = None if hmac.compare_digest(actual_hash, claimed_hash) else "EVENT_HASH_MISMATCH"
            if error:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    error,
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            event_ids.add(event_id)
            event_hashes.add(claimed_hash)
            run_id = current_run_id
            previous_hash = claimed_hash
            events.append(parsed)
        first_metadata = events[0].get("metadata") if events else None
        if isinstance(first_metadata, Mapping) and first_metadata.get(
            "initialization"
        ) is True:
            try:
                validate_legacy_transition_prefix(events)
            except (TypeError, ValueError) as exc:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    f"INVALID_LEGACY_TRANSITION_AUTHORITY:{exc}",
                    len(events),
                    valid_prefix_bytes=0,
                )
        return LedgerValidationResult(
            True,
            tuple(events),
            previous_hash,
            run_id,
            valid_prefix_bytes=len(data),
        )

    def _write_sidecar(
        self,
        target: Path,
        *,
        original: str,
        reason: str,
        size: int,
        digest: str,
    ) -> Path:
        target_relative = self._relative_path(target)
        sidecar_relative = target_relative.with_name(target_relative.name + ".metadata.json")
        sidecar = self.project_root / sidecar_relative
        payload = {
            "schema_version": "1.0",
            "timestamp": self._now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "original_relative_path": original,
            "quarantine_relative_path": target_relative.as_posix(),
            "reason": reason,
            "size_bytes": size,
            "sha256": digest,
        }
        try:
            existing = read_confined_bytes(
                self.project_root,
                sidecar_relative,
                reject_hardlinks=True,
                max_bytes=self.maximum_metadata_bytes,
                missing_ok=True,
            )
            if existing is not None:
                parsed = safe_json_loads(existing, max_bytes=self.maximum_metadata_bytes)
                if not isinstance(parsed, Mapping):
                    raise RecoveryError("quarantine sidecar is not an object")
                old_semantic = dict(parsed)
                new_semantic = dict(payload)
                old_semantic.pop("timestamp", None)
                new_semantic.pop("timestamp", None)
                if old_semantic != new_semantic:
                    raise RecoveryError("quarantine sidecar collision")
                return sidecar
            serialized = (
                json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"
            ).encode("utf-8")
            return atomic_write_bytes(
                self.project_root,
                sidecar_relative,
                serialized,
                immutable=True,
                create_parents=True,
            )
        except (PathSecurityError, UnsafeSerializationError) as exc:
            raise RecoveryError(f"cannot write quarantine sidecar safely: {exc}") from exc

    def _quarantine_move(
        self,
        source: Path,
        *,
        category: str,
        reason: str,
        expected_source: tuple[str, int, int, int] | None = None,
    ) -> tuple[QuarantineRecord, bool]:
        """Copy one pinned identity and publish a logical quarantine tombstone.

        Portable POSIX APIs cannot conditionally unlink a name only if it still
        denotes a previously verified inode.  Recovery therefore never removes
        the source name: the immutable copy plus sidecar is the quarantine
        authority, and a later replacement inode remains untouched.
        """

        source_relative = self._relative_path(source)
        destination_relative = Path(".scientist-one-build") / "quarantine" / category
        secure_directory(self.project_root, destination_relative, create=True)
        try:
            source_fd = open_confined_directory_fd(
                self.project_root, source_relative.parent, create=False
            )
            destination_fd = open_confined_directory_fd(
                self.project_root, destination_relative, create=False
            )
        except PathSecurityError as exc:
            raise RecoveryError(f"confined quarantine path is unsafe: {exc}") from exc
        file_descriptor: int | None = None
        try:
            file_descriptor = os.open(
                source_relative.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=source_fd,
            )
            info = os.fstat(file_descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RecoveryError("incomplete source is not a recoverable regular file")
            if info.st_size > self.maximum_artifact_bytes:
                raise RecoveryError("incomplete source exceeds the bounded quarantine contract")
            digest_state = hashlib.sha256()
            while chunk := os.read(file_descriptor, 1024 * 1024):
                digest_state.update(chunk)
            digest = digest_state.hexdigest()
            if expected_source is not None and (
                digest,
                info.st_size,
                info.st_dev,
                info.st_ino,
            ) != expected_source:
                raise RecoveryError(
                    "incomplete source differs from the validated repair input"
                )
            source_key = hashlib.sha256(source_relative.as_posix().encode("utf-8")).hexdigest()
            destination_name = (
                f"{source_relative.name}.{source_key[:12]}.{digest[:16]}.quarantine"
            )
            target_relative = destination_relative / destination_name
            sidecar_relative = target_relative.with_name(
                target_relative.name + ".metadata.json"
            )
            try:
                prior_sidecar = read_confined_bytes(
                    self.project_root,
                    sidecar_relative,
                    reject_hardlinks=True,
                    max_bytes=self.maximum_metadata_bytes,
                    missing_ok=True,
                )
            except PathSecurityError as exc:
                raise RecoveryError(
                    f"cannot inspect quarantine tombstone safely: {exc}"
                ) from exc
            try:
                target_info = os.stat(
                    destination_name, dir_fd=destination_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                target_info = None
            if target_info is not None and (
                not stat.S_ISREG(target_info.st_mode)
                or target_info.st_nlink != 1
                or target_info.st_size != info.st_size
            ):
                raise RecoveryError("quarantine destination collision")
            current = os.stat(source_relative.name, dir_fd=source_fd, follow_symlinks=False)
            if (
                current.st_dev,
                current.st_ino,
                current.st_size,
                current.st_mtime_ns,
                current.st_ctime_ns,
            ) != (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            ):
                raise RecoveryError("incomplete source changed before quarantine")
            os.lseek(file_descriptor, 0, os.SEEK_SET)
            final_digest = hashlib.sha256()
            while chunk := os.read(file_descriptor, 1024 * 1024):
                final_digest.update(chunk)
            final_info = os.fstat(file_descriptor)
            if (
                final_digest.hexdigest() != digest
                or final_info.st_size != info.st_size
                or final_info.st_mtime_ns != info.st_mtime_ns
                or final_info.st_ctime_ns != info.st_ctime_ns
            ):
                raise RecoveryError("incomplete source changed while quarantine was prepared")
            target_descriptor: int | None = None
            try:
                if target_info is None:
                    target_descriptor = os.open(
                        destination_name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=destination_fd,
                    )
                    os.lseek(file_descriptor, 0, os.SEEK_SET)
                    copied_digest = hashlib.sha256()
                    copied_size = 0
                    while chunk := os.read(file_descriptor, 1024 * 1024):
                        view = memoryview(chunk)
                        while view:
                            written = os.write(target_descriptor, view)
                            if written <= 0:
                                raise OSError("short quarantine copy")
                            view = view[written:]
                        copied_digest.update(chunk)
                        copied_size += len(chunk)
                    os.fsync(target_descriptor)
                    if copied_size != info.st_size or copied_digest.hexdigest() != digest:
                        raise RecoveryError("source changed during quarantine copy")
                else:
                    target_descriptor = os.open(
                        destination_name,
                        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=destination_fd,
                    )
                    copied_digest = hashlib.sha256()
                    copied_size = 0
                    while chunk := os.read(target_descriptor, 1024 * 1024):
                        copied_digest.update(chunk)
                        copied_size += len(chunk)
                    if copied_size != info.st_size or copied_digest.hexdigest() != digest:
                        raise RecoveryError("existing quarantine copy is corrupt")
            finally:
                if target_descriptor is not None:
                    os.close(target_descriptor)
            os.fsync(destination_fd)
            current = os.stat(source_relative.name, dir_fd=source_fd, follow_symlinks=False)
            os.lseek(file_descriptor, 0, os.SEEK_SET)
            source_digest = hashlib.sha256()
            while chunk := os.read(file_descriptor, 1024 * 1024):
                source_digest.update(chunk)
            if (
                (current.st_dev, current.st_ino, current.st_size)
                != (info.st_dev, info.st_ino, info.st_size)
                or source_digest.hexdigest() != digest
            ):
                raise RecoveryError("incomplete source changed before quarantine commit")
            sidecar = self._write_sidecar(
                self.project_root / target_relative,
                original=source_relative.as_posix(),
                reason=reason,
                size=info.st_size,
                digest=digest,
            )
            current = os.stat(
                source_relative.name, dir_fd=source_fd, follow_symlinks=False
            )
            os.lseek(file_descriptor, 0, os.SEEK_SET)
            committed_source_digest = hashlib.sha256()
            while chunk := os.read(file_descriptor, 1024 * 1024):
                committed_source_digest.update(chunk)
            final_info = os.fstat(file_descriptor)
            if (
                (current.st_dev, current.st_ino)
                != (info.st_dev, info.st_ino)
                or committed_source_digest.hexdigest() != digest
                or final_info.st_size != info.st_size
                or final_info.st_mtime_ns != info.st_mtime_ns
                or final_info.st_ctime_ns != info.st_ctime_ns
            ):
                raise RecoveryError(
                    "incomplete source changed while quarantine was committed"
                )
            os.fsync(destination_fd)
            return (
                QuarantineRecord(
                    source_relative.as_posix(),
                    target_relative.as_posix(),
                    reason,
                    info.st_size,
                    digest,
                    self._relative_path(sidecar).as_posix(),
                ),
                prior_sidecar is None,
            )
        except (OSError, PathSecurityError) as exc:
            if isinstance(exc, RecoveryError):
                raise
            raise RecoveryError(f"confined quarantine move failed: {exc}") from exc
        finally:
            if file_descriptor is not None:
                os.close(file_descriptor)
            os.close(source_fd)
            os.close(destination_fd)

    def _open_ledger_lock(self, path: Path) -> int:
        if fcntl is None:
            raise LedgerValidationError("safe ledger locking is unavailable")
        relative = self._relative_path(path)
        directory_descriptor: int | None = None
        lock_descriptor: int | None = None
        try:
            directory_descriptor = open_confined_directory_fd(
                self.project_root,
                relative.parent,
                create=False,
            )
            lock_name = f".{relative.name}.lock"
            lock_descriptor = os.open(
                lock_name,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_descriptor,
            )
            info = os.fstat(lock_descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise LedgerValidationError("ledger lock is not a private regular file")
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            return lock_descriptor
        except (OSError, LedgerValidationError) as exc:
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            if isinstance(exc, LedgerValidationError):
                raise
            raise LedgerValidationError(f"cannot acquire ledger repair lock: {exc}") from exc
        finally:
            if directory_descriptor is not None:
                os.close(directory_descriptor)

    @staticmethod
    def _close_ledger_lock(descriptor: int) -> None:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    def repair_truncated_ledger(
        self, ledger_path: str | os.PathLike[str], result: LedgerValidationResult | None = None
    ) -> tuple[LedgerValidationResult, QuarantineRecord]:
        path = self.project_root / self._relative_path(ledger_path)
        # An injected validator may itself use EventLedger and therefore the
        # same per-ledger flock.  Invoke it before taking the repair lock, then
        # compare its complete observation with an intrinsic validation made
        # under the lock.  Any intervening write changes that intrinsic
        # signature and fails closed without recursively acquiring the lock.
        reported = self.validate_ledger(path)
        lock_descriptor = self._open_ledger_lock(path)
        try:
            intrinsic = self.validate_ledger(
                path, _bypass_injected_validator=True
            )
            if (
                not reported.recoverable_truncated_tail
                or not intrinsic.recoverable_truncated_tail
            ):
                raise LedgerValidationError(
                    "ledger no longer has an unambiguously truncated final append"
                )
            if result is not None:
                expected_signature = (
                    result.event_count,
                    result.head_hash,
                    result.run_id,
                    result.error,
                    result.error_line,
                    result.recoverable_truncated_tail,
                    result.valid_prefix_bytes,
                    result.tail_bytes,
                )
                reported_signature = (
                    reported.event_count,
                    reported.head_hash,
                    reported.run_id,
                    reported.error,
                    reported.error_line,
                    reported.recoverable_truncated_tail,
                    reported.valid_prefix_bytes,
                    reported.tail_bytes,
                )
                if expected_signature != reported_signature:
                    raise LedgerValidationError(
                        "ledger changed after validation; stale repair result rejected"
                    )
            if (
                reported.event_count,
                reported.head_hash,
                reported.run_id,
                reported.valid_prefix_bytes,
            ) != (
                intrinsic.event_count,
                intrinsic.head_hash,
                intrinsic.run_id,
                intrinsic.valid_prefix_bytes,
            ) or tuple(reported.events) != tuple(intrinsic.events):
                raise LedgerValidationError(
                    "ledger validators disagree on the recoverable prefix"
                )
            # The injected validator is authoritative only for ledger-event
            # semantics.  Some adapters intentionally do not materialize raw
            # tail bytes or source identity.  The intrinsic validation and
            # descriptor-bound read made under this repair lock remain the
            # sole authority for those file-level facts.
            validation = intrinsic
            data, info = self._read_regular_bytes(
                path, maximum_bytes=self.maximum_ledger_bytes
            )
            digest = hashlib.sha256(data).hexdigest()
            intrinsic_source = (
                intrinsic.source_sha256,
                intrinsic.source_size,
                intrinsic.source_device,
                intrinsic.source_inode,
            )
            if any(value is None for value in intrinsic_source):
                raise LedgerValidationError(
                    "intrinsic ledger validation omitted source identity"
                )
            if (digest, len(data), info.st_dev, info.st_ino) != intrinsic_source:
                raise LedgerValidationError(
                    "ledger identity or content changed after intrinsic validation"
                )
            if result is not None and result.source_sha256 is not None:
                if (
                    digest != result.source_sha256
                    or len(data) != result.source_size
                    or info.st_dev != result.source_device
                    or info.st_ino != result.source_inode
                ):
                    raise LedgerValidationError(
                        "ledger identity or content changed after validation"
                    )
            if validation.valid_prefix_bytes <= 0:
                raise LedgerValidationError("cannot repair a ledger with no valid event prefix")
            record, _newly_quarantined = self._quarantine_move(
                path,
                category="ledger",
                reason="TRUNCATED_FINAL_LEDGER_APPEND",
                expected_source=(digest, len(data), info.st_dev, info.st_ino),
            )
            directory_fd: int | None = None
            ledger_fd: int | None = None
            try:
                relative = self._relative_path(path)
                directory_fd = open_confined_directory_fd(
                    self.project_root, relative.parent, create=False
                )
                ledger_fd = os.open(
                    relative.name,
                    os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                current = os.fstat(ledger_fd)
                named = os.stat(
                    relative.name, dir_fd=directory_fd, follow_symlinks=False
                )
                os.lseek(ledger_fd, 0, os.SEEK_SET)
                current_digest = hashlib.sha256()
                current_size = 0
                while chunk := os.read(ledger_fd, 1024 * 1024):
                    current_digest.update(chunk)
                    current_size += len(chunk)
                if (
                    (current.st_dev, current.st_ino)
                    != (named.st_dev, named.st_ino)
                    or (
                        current_digest.hexdigest(),
                        current_size,
                        current.st_dev,
                        current.st_ino,
                    )
                    != (digest, len(data), info.st_dev, info.st_ino)
                ):
                    raise LedgerValidationError(
                        "ledger identity changed before descriptor-bound repair"
                    )
                os.ftruncate(ledger_fd, validation.valid_prefix_bytes)
                os.fsync(ledger_fd)
                os.fsync(directory_fd)
                final = os.fstat(ledger_fd)
                final_named = os.stat(
                    relative.name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (
                    final.st_size != validation.valid_prefix_bytes
                    or (final.st_dev, final.st_ino)
                    != (final_named.st_dev, final_named.st_ino)
                ):
                    raise LedgerValidationError(
                        "repaired ledger name no longer denotes the repaired inode"
                    )
            except (OSError, PathSecurityError) as exc:
                raise LedgerValidationError(
                    f"cannot restore validated ledger prefix safely: {exc}"
                ) from exc
            finally:
                if ledger_fd is not None:
                    os.close(ledger_fd)
                if directory_fd is not None:
                    os.close(directory_fd)
            repaired_intrinsic = self.validate_ledger(
                path, _bypass_injected_validator=True
            )
            if not repaired_intrinsic.valid:
                raise LedgerValidationError(
                    "repaired ledger prefix is invalid: "
                    f"{repaired_intrinsic.error}"
                )
        finally:
            self._close_ledger_lock(lock_descriptor)
        # Reapply any injected semantic validator only after releasing the
        # repair lock.  A legitimate concurrent append may extend the repaired
        # prefix, but it may not replace or alter that prefix.
        repaired = self.validate_ledger(path)
        if (
            not repaired.valid
            or repaired.run_id != repaired_intrinsic.run_id
            or repaired.event_count < repaired_intrinsic.event_count
            or tuple(repaired.events[: repaired_intrinsic.event_count])
            != tuple(repaired_intrinsic.events)
        ):
            raise LedgerValidationError(
                f"repaired ledger failed final validation: {repaired.error}"
            )
        return repaired, record

    def _load_artifact_records(self, registry: object) -> list[Mapping[str, object]]:
        try:
            from .artifacts import ArtifactRegistry
        except ImportError:  # pragma: no cover - package-internal dependency
            ArtifactRegistry = ()  # type: ignore[assignment,misc]
        if isinstance(registry, ArtifactRegistry):
            try:
                raw = [record.to_dict() for record in registry.list_records()]
            except Exception as exc:
                raise ArtifactValidationError(
                    f"artifact registry verification failed: {exc}"
                ) from exc
        elif isinstance(registry, (str, os.PathLike)):
            try:
                encoded = read_confined_bytes(
                    self.project_root,
                    self._relative_path(registry),
                    reject_hardlinks=True,
                    max_bytes=self.maximum_metadata_bytes,
                )
                if encoded is None:
                    raise PathSecurityError("artifact registry is absent")
                text = encoded.decode("utf-8")
            except (PathSecurityError, UnicodeDecodeError) as exc:
                raise ArtifactValidationError(f"cannot read artifact registry: {exc}") from exc
            try:
                raw = safe_json_loads(text, max_bytes=self.maximum_metadata_bytes)
            except (UnsafeSerializationError, ValueError, RecursionError):
                raw = []
                for number, line in enumerate(text.splitlines(), start=1):
                    if not line.strip():
                        raise ArtifactValidationError(f"empty artifact registry line {number}")
                    try:
                        raw.append(
                            safe_json_loads(line, max_bytes=self.maximum_metadata_bytes)
                        )
                    except (UnsafeSerializationError, ValueError, RecursionError) as exc:
                        raise ArtifactValidationError(
                            f"malformed artifact registry line {number}: {exc}"
                        ) from exc
        else:
            raw = registry
        if isinstance(raw, Mapping) and "artifacts" in raw:
            raw = raw["artifacts"]
        elif isinstance(raw, Mapping):
            raw = [raw]
        if (
            not isinstance(raw, list)
            or len(raw) > MAX_REGISTRY_RECORDS
            or any(not isinstance(item, Mapping) for item in raw)
        ):
            raise ArtifactValidationError("artifact registry must contain object records")
        return list(raw)

    def validate_artifacts(self, registry: object) -> ArtifactValidationResult:
        if self._artifact_validator is not None:
            result = self._artifact_validator(registry)
            if not isinstance(result, ArtifactValidationResult):
                issue = ArtifactIssue(
                    -1,
                    None,
                    "ARTIFACT_VALIDATOR_INVALID_RESULT",
                    "injected artifact validator returned an invalid result",
                    True,
                )
                return ArtifactValidationResult(False, 0, (), (issue,))
            return result
        try:
            records = self._load_artifact_records(registry)
        except (ArtifactValidationError, RecoveryError) as exc:
            issue = ArtifactIssue(-1, None, "REGISTRY_INVALID", str(exc), True)
            return ArtifactValidationResult(False, 0, (), (issue,))
        issues: list[ArtifactIssue] = []
        validated = 0
        seen_paths: set[Path] = set()
        for index, record in enumerate(records):
            if (
                "path" in record
                and "relative_path" in record
                and record.get("path") != record.get("relative_path")
            ):
                issues.append(
                    ArtifactIssue(
                        index,
                        str(record.get("path")),
                        "AMBIGUOUS_PATH_FIELDS",
                        "path and relative_path disagree",
                        True,
                    )
                )
                continue
            if (
                "sha256" in record
                and "hash" in record
                and record.get("sha256") != record.get("hash")
            ):
                issues.append(
                    ArtifactIssue(
                        index,
                        str(record.get("path", record.get("relative_path"))),
                        "AMBIGUOUS_HASH_FIELDS",
                        "sha256 and hash disagree",
                        True,
                    )
                )
                continue
            raw_path = record.get("path", record.get("relative_path"))
            expected = record.get("sha256", record.get("hash"))
            raw_frozen = record.get("frozen", False)
            if not isinstance(raw_frozen, bool):
                issues.append(
                    ArtifactIssue(
                        index,
                        str(raw_path) if raw_path is not None else None,
                        "INVALID_FROZEN_FLAG",
                        "frozen must be boolean",
                        True,
                    )
                )
                continue
            frozen = raw_frozen
            display = str(raw_path) if raw_path is not None else None
            if not isinstance(raw_path, str) or not raw_path:
                issues.append(ArtifactIssue(index, display, "MISSING_PATH", "path is required", frozen))
                continue
            if not isinstance(expected, str) or not SHA256_PATTERN.fullmatch(expected):
                issues.append(
                    ArtifactIssue(index, display, "INVALID_SHA256", "sha256 is required", frozen)
                )
                continue
            try:
                relative = self._relative_path(raw_path)
                content = read_confined_bytes(
                    self.project_root,
                    relative,
                    reject_hardlinks=True,
                    max_bytes=self.maximum_artifact_bytes,
                )
                if content is None:
                    raise PathSecurityError("artifact is absent")
            except (RecoveryError, PathSecurityError) as exc:
                issues.append(ArtifactIssue(index, display, "UNSAFE_OR_MISSING_PATH", str(exc), frozen))
                continue
            if relative in seen_paths:
                issues.append(
                    ArtifactIssue(
                        index,
                        display,
                        "DUPLICATE_ARTIFACT_PATH",
                        "artifact path appears more than once",
                        frozen,
                    )
                )
                continue
            seen_paths.add(relative)
            declared_size = record.get("size", record.get("size_bytes"))
            if declared_size is not None:
                if isinstance(declared_size, bool) or not isinstance(declared_size, int) or declared_size < 0:
                    issues.append(
                        ArtifactIssue(index, display, "INVALID_SIZE", "declared size is invalid", frozen)
                    )
                    continue
                if len(content) != declared_size:
                    issues.append(
                        ArtifactIssue(
                            index,
                            display,
                            "SIZE_MISMATCH",
                            f"expected {declared_size}, found {len(content)}",
                            frozen,
                        )
                    )
                    continue
            actual = hashlib.sha256(content).hexdigest()
            if not hmac.compare_digest(actual, expected):
                issues.append(
                    ArtifactIssue(index, display, "HASH_MISMATCH", f"expected {expected}, found {actual}", frozen)
                )
                continue
            validated += 1
        return ArtifactValidationResult(not issues, validated, tuple(records), tuple(issues))

    def _scan_incomplete(self, roots: Sequence[str | os.PathLike[str]]) -> list[Path]:
        found: list[Path] = []
        scanned_entries = 0
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        quarantine_relative = Path(".scientist-one-build/quarantine")
        for raw_root in roots:
            relative_root = self._relative_path(raw_root)
            try:
                current_fd = os.open(self.project_root, flags)
            except OSError as exc:
                raise RecoveryError("cannot pin project root for incomplete scan") from exc
            missing = False
            try:
                for component in relative_root.parts:
                    try:
                        next_fd = os.open(component, flags, dir_fd=current_fd)
                    except FileNotFoundError:
                        missing = True
                        break
                    except OSError as exc:
                        raise RecoveryError(
                            "incomplete-write scan root contains a link or non-directory"
                        ) from exc
                    os.close(current_fd)
                    current_fd = next_fd
                if missing:
                    continue
                stack: list[tuple[int, Path]] = [(current_fd, relative_root)]
                current_fd = -1
                try:
                    while stack:
                        directory_fd, directory_relative = stack.pop()
                        try:
                            try:
                                directory_relative.relative_to(quarantine_relative)
                            except ValueError:
                                pass
                            else:
                                continue
                            with os.scandir(directory_fd) as entries:
                                names = (entry.name for entry in entries)
                                for name in names:
                                    scanned_entries += 1
                                    if scanned_entries > self.maximum_scan_entries:
                                        raise RecoveryError(
                                            "incomplete-write scan entry limit exceeded"
                                        )
                                    if name in {"", ".", ".."} or "/" in name:
                                        raise RecoveryError(
                                            "incomplete-write tree contains an unsafe name"
                                        )
                                    try:
                                        info = os.stat(
                                            name, dir_fd=directory_fd, follow_symlinks=False
                                        )
                                    except OSError as exc:
                                        raise RecoveryError(
                                            f"cannot inspect incomplete-write entry: {exc}"
                                        ) from exc
                                    child_relative = directory_relative / name
                                    if stat.S_ISDIR(info.st_mode):
                                        try:
                                            child_fd = os.open(name, flags, dir_fd=directory_fd)
                                        except OSError as exc:
                                            raise RecoveryError(
                                                "incomplete-write directory changed or is unsafe"
                                            ) from exc
                                        stack.append((child_fd, child_relative))
                                    elif stat.S_ISREG(info.st_mode):
                                        if name.endswith(INCOMPLETE_SUFFIXES) or ".tmp." in name:
                                            found.append(self.project_root / child_relative)
                                            if len(found) > self.maximum_quarantine_candidates:
                                                raise RecoveryError(
                                                    "incomplete-write candidate limit exceeded"
                                                )
                                    elif stat.S_ISLNK(info.st_mode):
                                        continue
                                    else:
                                        raise RecoveryError(
                                            "incomplete-write tree contains a special file"
                                        )
                        finally:
                            os.close(directory_fd)
                finally:
                    for pending_fd, _ in stack:
                        os.close(pending_fd)
            finally:
                if current_fd >= 0:
                    os.close(current_fd)
        return found

    def quarantine_incomplete(
        self,
        candidates: Sequence[str | os.PathLike[str]] | None = None,
        *,
        scan_roots: Sequence[str | os.PathLike[str]] = (
            "artifacts",
            "runs",
            ".scientist-one-build/checkpoints",
        ),
        protected_paths: Iterable[str | os.PathLike[str]] = (),
    ) -> tuple[QuarantineRecord, ...]:
        paths = (
            [self.project_root / self._relative_path(item) for item in candidates]
            if candidates is not None
            else self._scan_incomplete(scan_roots)
        )
        if len(paths) > self.maximum_quarantine_candidates:
            raise RecoveryError("incomplete-write candidate limit exceeded")
        protected = {self._relative_path(item) for item in protected_paths}
        records: list[QuarantineRecord] = []
        for path in paths:
            relative_path = self._relative_path(path)
            name = relative_path.name
            if not (name.endswith(INCOMPLETE_SUFFIXES) or ".tmp." in name):
                raise RecoveryError(
                    "explicit quarantine candidates require a recognized incomplete-write name"
                )
            if relative_path in protected:
                # A registered, hash-valid artifact is authoritative evidence,
                # even if its producer chose an unfortunate temporary suffix.
                if candidates is not None:
                    raise RecoveryError(
                        "authoritative recovery input cannot be quarantined explicitly"
                    )
                continue
            try:
                record, newly_quarantined = self._quarantine_move(
                    self.project_root / relative_path,
                    category="partial",
                    reason="INCOMPLETE_WRITE",
                )
                if newly_quarantined:
                    records.append(record)
            except RecoveryError as exc:
                # Missing auto-discovered files are an ordinary concurrent
                # cleanup.  Explicit candidates are authoritative requests and
                # must fail closed when absent or unsafe.
                if candidates is None and "No such file" in str(exc):
                    continue
                raise
        return tuple(records)

    def create_checkpoint(
        self,
        payload: Mapping[str, object],
        *,
        checkpoint_dir: str | os.PathLike[str] = ".scientist-one-build/checkpoints",
    ) -> Path:
        required = ("run_id", "event_id", "ledger_head_hash", "state")
        if any(not isinstance(payload.get(key), str) or not payload.get(key) for key in required):
            raise RecoveryError(f"checkpoint requires non-empty fields: {', '.join(required)}")
        allowed_payload = {
            "schema_version",
            "checkpoint_id",
            "run_id",
            "event_id",
            "ledger_head_hash",
            "state",
            "artifact_hashes",
            "artifact_record_hashes",
            "resource_runtime_artifact",
            "created_at",
            "checkpoint_hash",
        }
        if any(not isinstance(key, str) or key not in allowed_payload for key in payload):
            raise RecoveryError("checkpoint contains unsupported or inline mutable state")
        if not SHA256_PATTERN.fullmatch(str(payload["ledger_head_hash"])):
            raise RecoveryError("checkpoint ledger_head_hash must be SHA-256")
        data = dict(payload)
        data.setdefault("schema_version", CURRENT_CHECKPOINT_SCHEMA)
        if data["schema_version"] != CURRENT_CHECKPOINT_SCHEMA:
            raise RecoveryError("unsupported checkpoint schema_version")
        data.setdefault("checkpoint_id", f"{payload['event_id']}-{str(payload['ledger_head_hash'])[:12]}")
        data.setdefault("artifact_hashes", {})
        data.setdefault("artifact_record_hashes", {})
        data.setdefault("resource_runtime_artifact", None)
        artifact_hashes = data["artifact_hashes"]
        artifact_record_hashes = data["artifact_record_hashes"]
        if not isinstance(artifact_hashes, Mapping) or not isinstance(
            artifact_record_hashes, Mapping
        ):
            raise RecoveryError("checkpoint artifact bindings must be logical-type maps")
        if set(artifact_hashes) != set(artifact_record_hashes):
            raise RecoveryError("checkpoint artifact binding keysets disagree")
        for logical_type, digest in artifact_hashes.items():
            if (
                not isinstance(logical_type, str)
                or not logical_type
                or not isinstance(digest, str)
                or not SHA256_PATTERN.fullmatch(digest)
                or not isinstance(artifact_record_hashes[logical_type], str)
                or not SHA256_PATTERN.fullmatch(str(artifact_record_hashes[logical_type]))
            ):
                raise RecoveryError("checkpoint artifact bindings are malformed")
        resource_name = data["resource_runtime_artifact"]
        if resource_name is not None and (
            not isinstance(resource_name, str)
            or not resource_name.startswith("resource_runtime_")
            or resource_name not in artifact_hashes
        ):
            raise RecoveryError("checkpoint resource runtime pointer is not artifact-bound")
        data.pop("checkpoint_hash", None)
        directory_relative = self._relative_path(checkpoint_dir)
        try:
            secure_directory(self.project_root, directory_relative, create=True)
        except PathSecurityError as exc:
            raise RecoveryError(f"checkpoint directory is unsafe: {exc}") from exc
        name = str(data["checkpoint_id"])
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise RecoveryError("checkpoint_id contains unsafe characters")
        destination_relative = directory_relative / f"{name}.json"
        destination = self.project_root / destination_relative
        try:
            existing_bytes = read_confined_bytes(
                self.project_root,
                destination_relative,
                reject_hardlinks=True,
                max_bytes=self.maximum_metadata_bytes,
                missing_ok=True,
            )
        except PathSecurityError as exc:
            raise RecoveryError(f"existing checkpoint cannot be read safely: {exc}") from exc
        if existing_bytes is not None:
            try:
                existing = safe_json_loads(
                    existing_bytes, max_bytes=self.maximum_metadata_bytes
                )
            except (UnsafeSerializationError, ValueError) as exc:
                raise RecoveryError(f"existing checkpoint is invalid: {exc}") from exc
            if not isinstance(existing, Mapping):
                raise RecoveryError("existing checkpoint is not a JSON object")
            existing_hash = existing.get("checkpoint_hash")
            if (
                not isinstance(existing_hash, str)
                or not SHA256_PATTERN.fullmatch(existing_hash)
                or not hmac.compare_digest(checkpoint_digest(existing), existing_hash)
            ):
                raise RecoveryError("existing checkpoint hash is invalid")
            semantic_existing = dict(existing)
            semantic_existing.pop("checkpoint_hash", None)
            if "created_at" not in data:
                semantic_existing.pop("created_at", None)
            if semantic_existing == data:
                return destination
            raise RecoveryError("checkpoint is immutable and already exists with different content")
        data.setdefault(
            "created_at", self._now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        try:
            data["checkpoint_hash"] = checkpoint_digest(data)
        except (TypeError, ValueError) as exc:
            raise RecoveryError(f"checkpoint is not canonical JSON data: {exc}") from exc
        try:
            serialized = (
                json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n"
            ).encode("utf-8")
            return atomic_write_bytes(
                self.project_root,
                destination_relative,
                serialized,
                immutable=True,
                create_parents=False,
            )
        except PathSecurityError as exc:
            raise RecoveryError(f"checkpoint cannot be published safely: {exc}") from exc

    def select_checkpoint(
        self,
        checkpoint_dir: str | os.PathLike[str],
        ledger: LedgerValidationResult,
        artifacts: ArtifactValidationResult | None = None,
        *,
        expected_run_id: str | None = None,
    ) -> CheckpointSelection | None:
        if not ledger.valid:
            raise LedgerValidationError("cannot select a checkpoint before ledger validation")
        if expected_run_id is not None and (
            not isinstance(expected_run_id, str)
            or IDENTIFIER_PATTERN.fullmatch(expected_run_id) is None
        ):
            raise LedgerValidationError(
                "checkpoint selection expected run ID is invalid"
            )
        checkpoint_run_id = (
            expected_run_id
            if expected_run_id is not None
            else ledger.run_id
        )
        if (
            expected_run_id is not None
            and ledger.run_id is not None
            and expected_run_id != ledger.run_id
        ):
            raise LedgerValidationError(
                "validated ledger belongs to another expected run"
            )
        directory_relative = self._relative_path(checkpoint_dir)
        event_index = {
            str(event["event_id"]): (index, str(event["event_hash"]), event)
            for index, event in enumerate(ledger.events)
        }
        known_artifact_hashes = {
            str(record.get("sha256", record.get("hash")))
            for record in (artifacts.records if artifacts else ())
            if isinstance(record.get("sha256", record.get("hash")), str)
        }
        known_record_hashes = {
            str(record.get("sha256", record.get("hash"))): record.get(
                "record_hash", record.get("registry_record_hash")
            )
            for record in (artifacts.records if artifacts else ())
            if isinstance(record.get("sha256", record.get("hash")), str)
        }
        selected: CheckpointSelection | None = None
        selected_semantic: Mapping[str, object] | None = None
        selected_conflict = False
        def checkpoint_stream():
            try:
                directory_fd = open_confined_directory_fd(
                    self.project_root, directory_relative, create=False
                )
            except PathSecurityError:
                return
            try:
                try:
                    checkpoint_names_list: list[str] = []
                    with os.scandir(directory_fd) as entries:
                        for entry in entries:
                            if len(checkpoint_names_list) >= self.maximum_checkpoint_entries:
                                raise RecoveryError(
                                    "checkpoint directory entry count exceeds safety limit"
                                )
                            checkpoint_names_list.append(entry.name)
                    checkpoint_names = tuple(sorted(checkpoint_names_list))
                except RecoveryError:
                    raise
                except OSError as exc:
                    raise RecoveryError(f"cannot enumerate checkpoints: {exc}") from exc

                # Admit the complete bounded workload before reading or retaining
                # any checkpoint body.  Metadata is small and the name count is
                # independently capped; checkpoint bytes are then streamed one
                # held descriptor at a time.
                checkpoint_entries: list[tuple[str, os.stat_result]] = []
                aggregate_bytes = 0
                for name in checkpoint_names:
                    if Path(name).suffix != ".json":
                        continue
                    try:
                        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError as exc:
                        raise RecoveryError(
                            "checkpoint entry cannot be inspected safely"
                        ) from exc
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise RecoveryError(
                            "checkpoint directory contains an unsafe JSON entry"
                        )
                    if info.st_size > self.maximum_metadata_bytes:
                        raise RecoveryError("checkpoint entry exceeds its per-file bound")
                    if (
                        aggregate_bytes
                        > self.maximum_checkpoint_selection_bytes - info.st_size
                    ):
                        raise RecoveryError(
                            "checkpoint selection exceeds its aggregate byte bound"
                        )
                    aggregate_bytes += info.st_size
                    checkpoint_entries.append((name, info))

                for name, info in checkpoint_entries:
                    descriptor: int | None = None
                    try:
                        descriptor = os.open(
                            name,
                            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=directory_fd,
                        )
                        opened = os.fstat(descriptor)
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or opened.st_nlink != 1
                            or (opened.st_dev, opened.st_ino)
                            != (info.st_dev, info.st_ino)
                            or opened.st_size != info.st_size
                        ):
                            raise RecoveryError("checkpoint entry changed after admission")
                        chunks: list[bytes] = []
                        total = 0
                        while True:
                            chunk = os.read(
                                descriptor,
                                min(
                                    1024 * 1024,
                                    self.maximum_metadata_bytes - total + 1,
                                ),
                            )
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > self.maximum_metadata_bytes:
                                raise RecoveryError(
                                    "checkpoint exceeds metadata size limit"
                                )
                            chunks.append(chunk)
                        after = os.fstat(descriptor)
                        if (
                            total != opened.st_size
                            or (
                                opened.st_size,
                                opened.st_mtime_ns,
                                opened.st_ctime_ns,
                            )
                            != (
                                after.st_size,
                                after.st_mtime_ns,
                                after.st_ctime_ns,
                            )
                        ):
                            raise RecoveryError("checkpoint changed while being read")
                        yield name, b"".join(chunks)
                    except OSError as exc:
                        raise RecoveryError("checkpoint cannot be opened safely") from exc
                    finally:
                        if descriptor is not None:
                            os.close(descriptor)
            finally:
                os.close(directory_fd)

        expected_schema_fields = {
            "schema_version",
            "checkpoint_id",
            "run_id",
            "event_id",
            "ledger_head_hash",
            "state",
            "artifact_hashes",
            "artifact_record_hashes",
            "resource_runtime_artifact",
            "created_at",
            "checkpoint_hash",
        }
        stream = checkpoint_stream()
        try:
            for name, encoded in stream:
                if Path(name).suffix != ".json":
                    continue
                try:
                    checkpoint = safe_json_loads(
                        encoded, max_bytes=self.maximum_metadata_bytes
                    )
                    if not isinstance(checkpoint, dict):
                        continue
                    checkpoint_fields = set(checkpoint)
                    if checkpoint_fields != expected_schema_fields:
                        continue
                    if checkpoint.get("schema_version") != CURRENT_CHECKPOINT_SCHEMA:
                        continue
                    claimed = checkpoint.get("checkpoint_hash")
                    if not isinstance(claimed, str) or not SHA256_PATTERN.fullmatch(claimed):
                        continue
                    if not hmac.compare_digest(checkpoint_digest(checkpoint), claimed):
                        continue
                    event_id = checkpoint.get("event_id", checkpoint.get("ledger_event_id"))
                    head_hash = checkpoint.get("ledger_head_hash", checkpoint.get("ledger_event_hash"))
                    candidate_run_id = checkpoint.get("run_id")
                    if (
                        not isinstance(candidate_run_id, str)
                        or IDENTIFIER_PATTERN.fullmatch(candidate_run_id) is None
                    ):
                        continue
                    if not isinstance(event_id, str) or not event_id:
                        continue
                    if not isinstance(head_hash, str) or not SHA256_PATTERN.fullmatch(head_hash):
                        continue
                    if not isinstance(checkpoint.get("state"), str) or not checkpoint.get("state"):
                        continue
                    hash_fields_valid = True
                    for key, value in checkpoint.items():
                        if key.endswith("_hash") and key not in {"checkpoint_hash"}:
                            if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
                                hash_fields_valid = False
                                break
                    if not hash_fields_valid:
                        continue
                    references = checkpoint.get("artifact_hashes")
                    checkpoint_record_hashes = checkpoint.get("artifact_record_hashes")
                    if not isinstance(references, Mapping) or not isinstance(
                        checkpoint_record_hashes, Mapping
                    ):
                        continue
                    if set(references) != set(checkpoint_record_hashes):
                        continue
                    if any(
                        not isinstance(key, str)
                        or not key
                        or not isinstance(value, str)
                        or not SHA256_PATTERN.fullmatch(value)
                        or not isinstance(checkpoint_record_hashes[key], str)
                        or not SHA256_PATTERN.fullmatch(str(checkpoint_record_hashes[key]))
                        for key, value in references.items()
                    ):
                        continue
                    resource_name = checkpoint.get("resource_runtime_artifact")
                    if resource_name is not None and (
                        not isinstance(resource_name, str)
                        or not resource_name.startswith("resource_runtime_")
                        or resource_name not in references
                    ):
                        continue
                    if checkpoint_run_id is None:
                        raise LedgerValidationError(
                            "an empty ledger has a valid durable checkpoint but no "
                            "trusted expected run identity; refusing a possible ledger "
                            "rollback"
                        )
                    if candidate_run_id != checkpoint_run_id:
                        continue
                    if event_id not in event_index:
                        raise LedgerValidationError(
                            "a valid same-run checkpoint references an event absent from the "
                            "validated ledger; refusing a possible ledger rollback"
                        )
                    index, actual_hash, bound_event = event_index[event_id]
                    if not hmac.compare_digest(head_hash, actual_hash):
                        raise LedgerValidationError(
                            "a valid same-run checkpoint conflicts with the validated ledger "
                            "head; refusing a possible ledger rewrite"
                        )
                    expected_state = self._derived_state(
                        ledger.events[: index + 1]
                    )
                    if expected_state is None or checkpoint.get("state") != expected_state:
                        continue
                    referenced_hashes = tuple(references.values())
                    if artifacts is not None and any(
                        value not in known_artifact_hashes for value in referenced_hashes
                    ):
                        continue
                    projected_hashes: dict[str, str] = {}
                    projected_record_hashes: dict[str, str] = {}
                    projection_valid = True
                    for event in ledger.events[: index + 1]:
                        event_hashes = event.get("artifact_hashes")
                        if not isinstance(event_hashes, (list, tuple)):
                            projection_valid = False
                            break
                        if not event_hashes:
                            continue
                        metadata = event.get("metadata")
                        artifact_types = (
                            metadata.get("artifact_types")
                            if isinstance(metadata, Mapping)
                            else None
                        )
                        record_hashes = (
                            metadata.get("artifact_record_hashes")
                            if isinstance(metadata, Mapping)
                            else None
                        )
                        if (
                            not isinstance(artifact_types, (list, tuple))
                            or not isinstance(record_hashes, (list, tuple))
                            or len(artifact_types) != len(event_hashes)
                            or len(record_hashes) != len(event_hashes)
                            or len(set(artifact_types)) != len(artifact_types)
                        ):
                            projection_valid = False
                            break
                        for logical_type, digest, record_hash in zip(
                            artifact_types, event_hashes, record_hashes, strict=True
                        ):
                            if (
                                not isinstance(logical_type, str)
                                or not logical_type
                                or not isinstance(digest, str)
                                or not SHA256_PATTERN.fullmatch(digest)
                                or not isinstance(record_hash, str)
                                or not SHA256_PATTERN.fullmatch(record_hash)
                                or artifacts is None
                                or known_record_hashes.get(digest) != record_hash
                            ):
                                projection_valid = False
                                break
                            projected_hashes[logical_type] = digest
                            projected_record_hashes[logical_type] = record_hash
                        if not projection_valid:
                            break
                    if (
                        not projection_valid
                        or dict(references) != projected_hashes
                        or dict(checkpoint_record_hashes) != projected_record_hashes
                    ):
                        continue
                    candidate = CheckpointSelection(
                        (directory_relative / name).as_posix(), checkpoint, index
                    )
                    semantic = dict(checkpoint)
                    for key in ("checkpoint_id", "checkpoint_hash", "created_at"):
                        semantic.pop(key, None)
                    if selected is None or index > selected.ledger_event_index:
                        selected = candidate
                        selected_semantic = semantic
                        selected_conflict = False
                    elif index == selected.ledger_event_index:
                        if semantic != selected_semantic:
                            selected_conflict = True
                except (
                    OSError,
                    PathSecurityError,
                    UnsafeSerializationError,
                    UnicodeDecodeError,
                    TypeError,
                    ValueError,
                ):
                    continue
        finally:
            stream.close()
        if selected is None:
            return None
        if selected_conflict:
            raise RecoveryError("multiple checkpoints ambiguously bind the same ledger event")
        return selected

    @staticmethod
    def _event_labels(event: Mapping[str, object]) -> set[str]:
        labels: set[str] = set()
        for key in (
            "stage",
            "state",
            "state_before",
            "state_after",
            "requested_state_after",
            "source_state",
            "destination_state",
            "event_type",
            "action",
            "status",
        ):
            value = event.get(key)
            if isinstance(value, str):
                labels.add(value.upper())
        return labels

    @staticmethod
    def _validate_custody_mapping(custody: Mapping[str, object] | None) -> None:
        if custody is None:
            return
        for key in ("access_count", "authorized_access_count", "holdout_access_count"):
            if key in custody:
                value = custody[key]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise RecoveryError(f"custody {key} must be a non-negative integer")
        for key in (
            "released",
            "revealed",
            "invalidated",
            "confirmatory_claims_valid",
            "confirmatory_completed",
        ):
            if key in custody and not isinstance(custody[key], bool):
                raise RecoveryError(f"custody {key} must be boolean")
        for key in (
            "protocol_hash",
            "holdout_identity_hash",
            "split_manifest_hash",
            "seal_hash",
            "journal_head_hash",
            "journal_identity_sha256",
        ):
            if key in custody:
                value = custody[key]
                if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
                    raise RecoveryError(f"custody {key} must be SHA-256")

    def _confirmatory_status(
        self,
        events: Sequence[Mapping[str, object]],
        custody: Mapping[str, object] | None,
    ) -> tuple[bool, bool]:
        touched = False
        completed = False
        for event in events:
            labels = self._event_labels(event)
            if any(
                label == "CONFIRMATORY_RUN"
                or label.startswith("CONFIRMATORY_")
                or label in {"HOLDOUT_RELEASE", "HOLDOUT_ACCESSED", "UNBLINDED"}
                for label in labels
            ):
                touched = True
            if any(
                ("HOLDOUT" in label and ("ACCESS" in label or "RELEASE" in label))
                or "ACCESS_VIOLATION" in label
                for label in labels
            ):
                touched = True
            downstream = any(
                label
                in {
                    "CONFIRMATORY_COMPLETED",
                    "CONFIRMATORY_RUN_COMPLETED",
                    "CLAIMS",
                    "VERIFY",
                    "WRITE",
                    "AUDIT",
                    "REPRODUCE",
                    "RELEASE",
                    "READY_FOR_HUMAN_REVIEW",
                    "NEGATIVE_RESULT",
                    "INCONCLUSIVE",
                }
                for label in labels
            ) or any(
                label.startswith("CONFIRMATORY_")
                and label.endswith(("COMPLETED", "SUCCEEDED", "FINISHED", "RESULT_RECORDED"))
                for label in labels
            )
            if downstream:
                touched = True
                completed = True
            for key in ("holdout_access_count", "authorized_access_count", "access_count"):
                access = event.get(key)
                if isinstance(access, int) and not isinstance(access, bool) and access > 0:
                    touched = True
            if event.get("release_event") is not None or event.get("unblinded") is True:
                touched = True
        if custody:
            for key in ("access_count", "authorized_access_count", "holdout_access_count"):
                access = custody.get(key, 0)
                if isinstance(access, int) and not isinstance(access, bool) and access > 0:
                    touched = True
            if custody.get("released") is True or custody.get("release_event") is not None:
                touched = True
            if custody.get("revealed") is True or custody.get("confirmatory_claims_valid") is True:
                touched = True
            if custody.get("invalidated") is True:
                touched = True
            if custody.get("confirmatory_completed") is True:
                touched = completed = True
        return touched, completed

    @staticmethod
    def _derived_state(events: Sequence[Mapping[str, object]]) -> str | None:
        if not events:
            return None
        initial = events[0].get("state_before")
        state = initial if isinstance(initial, str) and initial else None
        for event in events:
            if event.get("event_type") not in {"TRANSITION", "SECURITY_STOP"}:
                continue
            before = event.get("state_before")
            after = event.get("requested_state_after")
            if not isinstance(before, str) or not isinstance(after, str):
                continue
            if state is not None and before != state:
                return None
            state = after
        return state

    @staticmethod
    def _valid_new_study_protocol(
        protocol: object | None,
        custody: Mapping[str, object] | None,
    ) -> bool:
        try:
            from .protocol import StudyVersion, validate_protocol

            if not isinstance(protocol, StudyVersion):
                return False
            validate_protocol(protocol.protocol)
        except Exception:
            return False
        if protocol.version < 2 or protocol.reveal is not None:
            return False
        if protocol.requires_fresh_confirmatory_reserve is not True:
            return False
        parent_hash = protocol.protocol.parent_protocol_hash
        if (
            not isinstance(parent_hash, str)
            or not SHA256_PATTERN.fullmatch(parent_hash)
            or not protocol.protocol.revision_reason
            or protocol.protocol_hash == parent_hash
        ):
            return False
        if custody is None:
            return False
        old_protocol = custody.get("protocol_hash")
        if not isinstance(old_protocol, str) or parent_hash != old_protocol:
            return False
        old_study = custody.get("study_id")
        old_version = custody.get("study_version")
        if not isinstance(old_study, str) or old_study != protocol.study_id:
            return False
        if (
            isinstance(old_version, bool)
            or not isinstance(old_version, int)
            or old_version < 1
            or protocol.version != old_version + 1
        ):
            return False
        return True

    @staticmethod
    def _resolve_registered_reveal_artifact(
        artifact_registry: object,
        selector: RegisteredArtifactSelector,
        *,
        logical_type: str,
        creator_role: object,
        parents: Sequence[str] | None = None,
    ) -> tuple[object, Mapping[str, object]]:
        """Resolve one selector to verified metadata and bounded JSON bytes."""

        from .artifacts import ArtifactRecord, ArtifactRegistry

        if not isinstance(artifact_registry, ArtifactRegistry):
            raise ConfirmatoryRerunError("reveal authority requires an ArtifactRegistry")
        if not isinstance(selector, RegisteredArtifactSelector):
            raise ConfirmatoryRerunError("reveal authority selector type is invalid")
        try:
            record = artifact_registry.get_metadata(selector.artifact_sha256)
            encoded = artifact_registry.get_bytes(selector.artifact_sha256)
        except Exception as exc:
            raise ConfirmatoryRerunError(
                f"registered reveal artifact is unavailable: {logical_type}"
            ) from exc
        if not isinstance(record, ArtifactRecord) or (
            record.sha256 != selector.artifact_sha256
            or record.record_hash != selector.artifact_record_hash
            or record.logical_type != logical_type
            or record.schema_version != "1.0"
            or record.mime_type != "application/json"
            or record.creator_role is not creator_role
            or record.validation_result != "PASS"
            or record.frozen is not True
            or artifact_registry.verify(selector.artifact_sha256) is not True
            or (parents is not None and record.parent_artifacts != tuple(parents))
        ):
            raise ConfirmatoryRerunError(
                f"registered reveal artifact binding is invalid: {logical_type}"
            )
        try:
            payload = safe_json_loads(encoded, max_bytes=MAX_ARTIFACT_OBJECT_BYTES)
        except Exception as exc:
            raise ConfirmatoryRerunError(
                f"registered reveal artifact JSON is invalid: {logical_type}"
            ) from exc
        if not isinstance(payload, Mapping):
            raise ConfirmatoryRerunError(
                f"registered reveal artifact is not an object: {logical_type}"
            )
        return record, payload

    @staticmethod
    def _validated_inventory_hash(
        payload: Mapping[str, object], *, kind: str
    ) -> str:
        if set(payload) != {"schema_version", "kind", "entries", "aggregate_sha256"}:
            raise ConfirmatoryRerunError(f"{kind} schema is invalid")
        entries = payload.get("entries")
        aggregate = payload.get("aggregate_sha256")
        if (
            payload.get("schema_version") != "1.0"
            or payload.get("kind") != kind
            or not isinstance(entries, list)
            or not entries
            or len(entries) > MAX_REGISTRY_RECORDS
            or not isinstance(aggregate, str)
            or not SHA256_PATTERN.fullmatch(aggregate)
        ):
            raise ConfirmatoryRerunError(f"{kind} content is invalid")
        paths: list[str] = []
        for entry in entries:
            if (
                not isinstance(entry, Mapping)
                or set(entry) != {"path", "sha256", "size"}
                or not isinstance(entry.get("path"), str)
                or not entry.get("path")
                or Path(str(entry["path"])).is_absolute()
                or ".." in Path(str(entry["path"])).parts
                or not isinstance(entry.get("sha256"), str)
                or not SHA256_PATTERN.fullmatch(str(entry["sha256"]))
                or isinstance(entry.get("size"), bool)
                or not isinstance(entry.get("size"), int)
                or int(entry["size"]) < 0
            ):
                raise ConfirmatoryRerunError(f"{kind} entry is invalid")
            paths.append(str(entry["path"]))
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ConfirmatoryRerunError(f"{kind} entry order is invalid")
        if hashlib.sha256(canonical_json_bytes(entries) + b"\n").hexdigest() != aggregate:
            raise ConfirmatoryRerunError(f"{kind} aggregate hash is invalid")
        return aggregate

    def _validated_live_source_implementation(
        self,
        payload: Mapping[str, object],
        *,
        path: str,
        label: str,
    ) -> str:
        """Bind a loaded trust-boundary module to frozen live source bytes."""

        entries = payload.get("entries")
        if not isinstance(entries, list):
            raise ConfirmatoryRerunError(
                "simulated evaluator source inventory is invalid"
            )
        matches = [
            entry
            for entry in entries
            if isinstance(entry, Mapping)
            and entry.get("path") == path
        ]
        if len(matches) != 1:
            raise ConfirmatoryRerunError(
                f"frozen source inventory does not uniquely bind {label}"
            )
        entry = matches[0]
        try:
            encoded = read_confined_bytes(
                self.project_root,
                path,
                reject_hardlinks=True,
                max_bytes=4 * 1024 * 1024,
            )
        except Exception as exc:
            raise ConfirmatoryRerunError(
                f"{label} implementation cannot be re-read safely"
            ) from exc
        if encoded is None:
            raise ConfirmatoryRerunError(f"{label} implementation is absent")
        digest = hashlib.sha256(encoded).hexdigest()
        if entry.get("sha256") != digest or entry.get("size") != len(encoded):
            raise ConfirmatoryRerunError(
                f"{label} implementation differs from the frozen inventory"
            )
        return digest

    @staticmethod
    def _event_artifact_binding(
        event: Mapping[str, object],
    ) -> tuple[tuple[object, ...], tuple[object, ...], tuple[object, ...]]:
        hashes = event.get("artifact_hashes")
        metadata = event.get("metadata")
        types = metadata.get("artifact_types") if isinstance(metadata, Mapping) else None
        records = (
            metadata.get("artifact_record_hashes")
            if isinstance(metadata, Mapping)
            else None
        )
        if not all(isinstance(value, (list, tuple)) for value in (hashes, types, records)):
            raise ConfirmatoryRerunError("ledger artifact binding is malformed")
        normalized = (tuple(hashes), tuple(types), tuple(records))
        if not (
            len(normalized[0]) == len(normalized[1]) == len(normalized[2])
            and len(set(normalized[0])) == len(normalized[0])
        ):
            raise ConfirmatoryRerunError("ledger artifact binding is ambiguous")
        return normalized

    def _resource_authority_history(
        self,
        run_id: object,
    ) -> tuple[tuple[Mapping[str, object], ...], tuple[Mapping[str, object], ...]]:
        """Re-resolve the exact external monotonic resource chain."""

        if (
            not isinstance(run_id, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id)
        ):
            raise ConfirmatoryRerunError("ledger run ID is invalid for resource authority")
        relative = Path(".scientist-one-build/resource-authority") / run_id
        directory_fd: int | None = None
        try:
            directory_fd = open_confined_directory_fd(
                self.project_root,
                relative,
                create=False,
            )
            names: list[str] = []
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if (
                        not entry.is_file(follow_symlinks=False)
                        or RESOURCE_AUTHORITY_NAME_PATTERN.fullmatch(entry.name) is None
                    ):
                        raise ConfirmatoryRerunError(
                            "resource authority history contains an unsafe entry"
                        )
                    names.append(entry.name)
                    if len(names) > 16:
                        raise ConfirmatoryRerunError(
                            "resource authority history exceeds its bound"
                        )
        except (OSError, PathSecurityError) as exc:
            raise ConfirmatoryRerunError(
                "resource authority history is unavailable or unsafe"
            ) from exc
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
        if not names:
            raise ConfirmatoryRerunError("resource authority history is empty")

        records: list[Mapping[str, object]] = []
        descriptors: list[Mapping[str, object]] = []
        prior_digest: str | None = None
        for expected_sequence, name in enumerate(sorted(names)):
            match = RESOURCE_AUTHORITY_NAME_PATTERN.fullmatch(name)
            if match is None or int(match.group("sequence")) != expected_sequence:
                raise ConfirmatoryRerunError(
                    "resource authority sequence is not contiguous"
                )
            try:
                encoded = read_confined_bytes(
                    self.project_root,
                    relative / name,
                    reject_hardlinks=True,
                    max_bytes=1024 * 1024,
                )
                value = safe_json_loads(encoded, max_bytes=1024 * 1024)
            except Exception as exc:
                raise ConfirmatoryRerunError(
                    "resource authority record is unreadable"
                ) from exc
            if not isinstance(value, Mapping) or set(value) != {
                "schema_version",
                "kind",
                "run_id",
                "sequence",
                "logical_type",
                "state_sha256",
                "state",
                "prior_authority_sha256",
            }:
                raise ConfirmatoryRerunError(
                    "resource authority record schema is invalid"
                )
            canonical = canonical_json_bytes(value) + b"\n"
            digest = hashlib.sha256(canonical).hexdigest()
            state = value.get("state")
            logical_type = value.get("logical_type")
            state_hash = (
                hashlib.sha256(canonical_json_bytes(state) + b"\n").hexdigest()
                if isinstance(state, Mapping)
                else None
            )
            if (
                encoded != canonical
                or digest != match.group("digest")
                or value.get("schema_version") != "1.0"
                or value.get("kind") != "RESOURCE_RUNTIME_AUTHORITY"
                or value.get("run_id") != run_id
                or value.get("sequence") != expected_sequence
                or not isinstance(logical_type, str)
                or not logical_type.startswith("resource_runtime_")
                or value.get("state_sha256") != state_hash
                or value.get("prior_authority_sha256") != prior_digest
            ):
                raise ConfirmatoryRerunError(
                    "resource authority record binding is invalid"
                )
            records.append(value)
            descriptors.append(
                {
                    "sequence": expected_sequence,
                    "logical_type": logical_type,
                    "state_sha256": state_hash,
                    "authority_sha256": digest,
                    "prior_authority_sha256": prior_digest,
                }
            )
            prior_digest = digest
        return tuple(records), tuple(descriptors)

    @staticmethod
    def _valid_fresh_custody_evidence(
        evidence: object | None,
        protocol: object | None,
        events: Sequence[Mapping[str, object]],
        old_custody: Mapping[str, object] | None,
        artifact_registry: object | None,
        custody_provider: object | None,
        project_root: Path,
    ) -> bool:
        """Validate frozen receipt and current provider state under its guard.

        Caller-constructed snapshots are deliberately not accepted: the
        provider must reload and lock its durable journal for this check.
        """

        try:
            from .artifacts import ArtifactRecord, ArtifactRegistry
            from .holdout import (
                CustodyIndependence,
                CustodyStatus,
                HoldoutAdmissionSnapshot,
                HoldoutCustody,
                HoldoutSeal,
            )
            from .protocol import StudyVersion
            from .roles import Role

            if not isinstance(evidence, FreshCustodyEvidence):
                return False
            if not isinstance(protocol, StudyVersion):
                return False
            if not isinstance(artifact_registry, ArtifactRegistry):
                return False
            if artifact_registry.policy.root != project_root:
                return False
            if not isinstance(custody_provider, HoldoutCustody):
                return False
            record = artifact_registry.get_metadata(evidence.receipt_artifact_sha256)
            if not isinstance(record, ArtifactRecord):
                return False
            if (
                record.record_hash != evidence.artifact_record_hash
                or record.logical_type != "fresh_custody_receipt"
                or record.schema_version != "1.0"
                or record.mime_type != "application/json"
                or record.creator_role is not Role.HOLDOUT_CUSTODIAN
                or record.validation_result != "PASS"
                or record.frozen is not True
                or not record.parent_artifacts
                or artifact_registry.verify(evidence.receipt_artifact_sha256) is not True
            ):
                return False
            receipt_bytes = artifact_registry.get_bytes(evidence.receipt_artifact_sha256)
            if not isinstance(receipt_bytes, bytes):
                return False
            receipt = safe_json_loads(
                receipt_bytes, max_bytes=MAX_ARTIFACT_OBJECT_BYTES
            )
            if not isinstance(receipt, Mapping) or set(receipt) != {
                "schema_version",
                "study_id",
                "study_version",
                "seal",
                "status",
                "journal_head_hash",
                "journal_identity_sha256",
            }:
                return False
            if receipt.get("schema_version") != "1.0":
                return False
            receipt_head = receipt.get("journal_head_hash")
            receipt_identity = receipt.get("journal_identity_sha256")
            if (
                not isinstance(receipt_head, str)
                or not SHA256_PATTERN.fullmatch(receipt_head)
                or not isinstance(receipt_identity, str)
                or not SHA256_PATTERN.fullmatch(receipt_identity)
            ):
                return False
            raw_seal = receipt.get("seal")
            raw_status = receipt.get("status")
            if not isinstance(raw_seal, Mapping) or not isinstance(raw_status, Mapping):
                return False
            seal = HoldoutSeal(**dict(raw_seal))
            expected_status_keys = {
                "custody_independence",
                "sealed",
                "revealed",
                "invalidated",
                "confirmatory_claims_valid",
                "authorized_access_count",
                "violation_reasons",
                "release_event",
                "durable_journal",
                "journal_head_hash",
            }
            if set(raw_status) != expected_status_keys:
                return False
            status_value = dict(raw_status)
            status_value["custody_independence"] = CustodyIndependence(
                status_value["custody_independence"]
            )
            status_value["violation_reasons"] = tuple(
                status_value["violation_reasons"]
            )
            if status_value["release_event"] is not None:
                return False
            status = CustodyStatus(**status_value)
            with custody_provider.admission_guard(
                expected_journal_head_hash=receipt_head,
                expected_journal_identity_sha256=receipt_identity,
            ) as live:
                if not isinstance(live, HoldoutAdmissionSnapshot):
                    return False
                if receipt.get("study_id") != protocol.study_id or receipt.get(
                    "study_version"
                ) != protocol.version:
                    return False
                if (
                    receipt_head != live.journal_head_hash
                    or receipt_identity != live.journal_identity_sha256
                ):
                    return False
                if seal != live.seal or status != live.status:
                    return False
                if seal.protocol_hash != protocol.protocol_hash:
                    return False
                if not (
                    live.sealed is True
                    and live.revealed is False
                    and live.invalidated is False
                    and live.confirmatory_claims_valid is False
                    and isinstance(live.authorized_access_count, int)
                    and not isinstance(live.authorized_access_count, bool)
                    and live.authorized_access_count == 0
                    and live.durable_journal
                    and status.release_event is None
                ):
                    return False
                if old_custody is not None:
                    for key, fresh_value in (
                        ("holdout_identity_hash", live.holdout_identity_hash),
                        ("split_manifest_hash", live.split_manifest_hash),
                        ("seal_hash", live.seal_hash),
                    ):
                        old_value = old_custody.get(key)
                        if (
                            not isinstance(old_value, str)
                            or not SHA256_PATTERN.fullmatch(old_value)
                            or old_value == fresh_value
                        ):
                            return False
                bound_event = next(
                    (
                        event
                        for event in events
                        if event.get("event_id") == evidence.ledger_event_id
                    ),
                    None,
                )
                if bound_event is None:
                    return False
                if bound_event is not events[-1]:
                    return False
                if (
                    bound_event.get("actor_role") != "holdout_custodian"
                    or bound_event.get("event_type") != "CHECKPOINT"
                    or bound_event.get("configuration_hash")
                    != live.configuration_hash
                ):
                    return False
                if bound_event.get("code_version") != live.code_hash:
                    return False
                artifact_hashes = bound_event.get("artifact_hashes")
                if (
                    not isinstance(artifact_hashes, (list, tuple))
                    or evidence.receipt_artifact_sha256 not in artifact_hashes
                ):
                    return False
                metadata = bound_event.get("metadata")
                if not isinstance(metadata, Mapping):
                    return False
                artifact_types = metadata.get("artifact_types")
                record_hashes = metadata.get("artifact_record_hashes")
                if (
                    not isinstance(artifact_types, (list, tuple))
                    or not isinstance(record_hashes, (list, tuple))
                    or len(artifact_types) != len(artifact_hashes)
                    or len(record_hashes) != len(artifact_hashes)
                ):
                    return False
                receipt_index = artifact_hashes.index(evidence.receipt_artifact_sha256)
                if (
                    artifact_types[receipt_index] != "fresh_custody_receipt"
                    or record_hashes[receipt_index] != evidence.artifact_record_hash
                ):
                    return False
                binding = metadata.get("fresh_custody")
                if not isinstance(binding, Mapping):
                    return False
                expected_binding = {
                    "artifact_sha256": evidence.receipt_artifact_sha256,
                    "artifact_record_hash": evidence.artifact_record_hash,
                    "journal_head_hash": live.journal_head_hash,
                    "journal_identity_sha256": live.journal_identity_sha256,
                    "protocol_hash": protocol.protocol_hash,
                    "seal_hash": live.seal_hash,
                    "study_version": protocol.version,
                }
                if dict(binding) != expected_binding:
                    return False
                return True
        except Exception:
            return False

    def _read_optional_mapping(
        self, value: object | None
    ) -> Mapping[str, object] | None:
        if value is None or isinstance(value, Mapping):
            return value
        if is_dataclass(value) and not isinstance(value, type):
            converted = asdict(value)
            if isinstance(converted, Mapping):
                return converted
        if not isinstance(value, (str, os.PathLike)):
            raise RecoveryError("recovery metadata must be a mapping, dataclass, or path")
        try:
            encoded = read_confined_bytes(
                self.project_root,
                self._relative_path(value),
                reject_hardlinks=True,
                max_bytes=self.maximum_metadata_bytes,
            )
            if encoded is None:
                raise PathSecurityError("recovery metadata is absent")
            parsed = safe_json_loads(encoded, max_bytes=self.maximum_metadata_bytes)
        except (PathSecurityError, UnsafeSerializationError) as exc:
            raise RecoveryError(f"cannot parse recovery metadata safely: {exc}") from exc
        if not isinstance(parsed, Mapping):
            raise RecoveryError("recovery metadata must be a JSON object")
        return parsed

    def recover(
        self,
        *,
        ledger_path: str | os.PathLike[str],
        artifact_registry: object | None = None,
        checkpoint_dir: str | os.PathLike[str] = ".scientist-one-build/checkpoints",
        expected_run_id: str | None = None,
        custody_record: object | None = None,
        incomplete_paths: Sequence[str | os.PathLike[str]] | None = None,
        new_study_protocol: object | None = None,
        fresh_custody_evidence: FreshCustodyEvidence | None = None,
        custody_provider: object | None = None,
        repair_truncated_tail: bool = True,
    ) -> RecoveryReport:
        quarantined: list[QuarantineRecord] = []
        try:
            ledger = self.validate_ledger(ledger_path)
        except RecoveryError as exc:
            return RecoveryReport(
                ResumeAction.STOP_SECURITY,
                (f"LEDGER_VALIDATION_FAILED:{exc}",),
                False,
                0,
                None,
                False,
                (),
                (),
                None,
                None,
                False,
                False,
            )
        # Negative routing only: this fixed non-evidentiary profile has its own
        # exact preparation/attempt/observation owner. Generic CALIBRATE replay
        # must neither infer permission nor repair its interrupted publications.
        # Reserve the namespace syntactically. Negative routing must not load
        # calibration data or make unrelated legacy recovery depend on it.
        def simulated_namespace(value: object) -> bool:
            return type(value) is str and re.fullmatch(r"sim-reserve-[0-9a-f]{48}", value) is not None

        relative_ledger = self._relative_path(ledger_path)
        if (
            simulated_namespace(expected_run_id)
            or simulated_namespace(ledger.run_id)
            or (
                len(relative_ledger.parts) >= 2
                and relative_ledger.parts[0] == "runs"
                and simulated_namespace(relative_ledger.parts[1])
            )
        ):
            # These are conservative recorded markers, not verified execution.
            # Neither boolean assesses the external custody journal: False is
            # not proof of unseen custody or an uncompleted evaluation (e.g.
            # after run-tree rollback). Only the profile owner can assess it.
            marker_seen = any(
                str(event.get("event_id", "")).startswith((
                    "sim-reserve-attempt-", "sim-reserve-started-", "sim-reserve-observation-",
                ))
                or (
                    isinstance(event.get("metadata"), Mapping)
                    and (
                        event["metadata"].get("execution_kind") == "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
                        or bool(set(event["metadata"]) & {
                            "simulated_reserve_attempt", "simulated_reserve_started", "simulated_reserve_observation",
                        })
                    )
                )
                for event in ledger.events
            )
            return RecoveryReport(
                action=ResumeAction.STOP_SECURITY,
                reasons=("SIMULATED_RESERVE_REQUIRES_PROFILE_OWNER", "SIMULATED_RESERVE_CUSTODY_UNASSESSED"),
                ledger_valid=ledger.valid,
                ledger_event_count=ledger.event_count,
                ledger_head_hash=ledger.head_hash,
                artifacts_valid=False,
                artifact_issues=(),
                quarantined=(),
                checkpoint=None,
                derived_state=self._derived_state(ledger.events),
                confirmatory_touched=marker_seen,
                confirmatory_completed=False,
            )
        if not ledger.valid and ledger.recoverable_truncated_tail and repair_truncated_tail:
            try:
                ledger, record = self.repair_truncated_ledger(ledger_path, ledger)
                quarantined.append(record)
            except RecoveryError as exc:
                return RecoveryReport(
                    ResumeAction.STOP_SECURITY,
                    (f"LEDGER_REPAIR_FAILED:{exc}",),
                    False,
                    ledger.event_count,
                    ledger.head_hash,
                    False,
                    (),
                    tuple(quarantined),
                    None,
                    self._derived_state(ledger.events),
                    False,
                    False,
                )
        if not ledger.valid:
            return RecoveryReport(
                ResumeAction.STOP_SECURITY,
                (ledger.error or "LEDGER_INVALID",),
                False,
                ledger.event_count,
                ledger.head_hash,
                False,
                (),
                tuple(quarantined),
                None,
                self._derived_state(ledger.events),
                False,
                False,
            )

        derived = self._derived_state(ledger.events)
        persisted_stop_action = {
            "STOP_SECURITY": ResumeAction.STOP_SECURITY,
            "STOP_SCIENTIFIC_INVALIDITY": ResumeAction.STOP_SCIENTIFIC_INVALIDITY,
        }.get(derived)

        if artifact_registry is None:
            artifacts = ArtifactValidationResult(True, 0, ())
        else:
            artifacts = self.validate_artifacts(artifact_registry)
        if not artifacts.valid:
            action = persisted_stop_action or (
                ResumeAction.STOP_SECURITY
                if artifacts.has_frozen_failure
                else ResumeAction.STOP_SCIENTIFIC_INVALIDITY
            )
            reasons = tuple(issue.code for issue in artifacts.issues)
            if persisted_stop_action is not None:
                reasons = (f"PERSISTED_TERMINAL_STATE:{derived}", *reasons)
            return RecoveryReport(
                action,
                reasons,
                True,
                ledger.event_count,
                ledger.head_hash,
                False,
                artifacts.issues,
                tuple(quarantined),
                None,
                derived,
                False,
                False,
            )

        first_metadata = ledger.events[0].get("metadata") if ledger.events else None
        if isinstance(first_metadata, Mapping) and first_metadata.get(
            "initialization"
        ) is True:
            try:
                transition_receipts = validate_legacy_transition_prefix(
                    ledger.events
                )
                if transition_receipts:
                    if not isinstance(artifact_registry, ArtifactRegistry):
                        raise RecoveryError(
                            "legacy transition replay requires its exact ArtifactRegistry"
                        )
                    StateController(
                        initial_state=ledger.events[-1]["requested_state_after"],
                        artifact_registry=artifact_registry,
                        prior_receipts=transition_receipts,
                    )
            except Exception as exc:
                return RecoveryReport(
                    ResumeAction.STOP_SECURITY,
                    (f"LEGACY_TRANSITION_REPLAY_FAILED:{exc}",),
                    True,
                    ledger.event_count,
                    ledger.head_hash,
                    True,
                    (),
                    tuple(quarantined),
                    None,
                    derived,
                    False,
                    False,
                )

        protected = [self._relative_path(ledger_path).as_posix()]
        if isinstance(artifact_registry, (str, os.PathLike)):
            protected.append(self._relative_path(artifact_registry).as_posix())
        for record in artifacts.records:
            raw = record.get("path", record.get("relative_path"))
            if isinstance(raw, str):
                protected.append(raw)
        try:
            quarantined.extend(
                self.quarantine_incomplete(incomplete_paths, protected_paths=protected)
            )
            checkpoint = self.select_checkpoint(
                checkpoint_dir,
                ledger,
                artifacts if artifact_registry is not None else None,
                expected_run_id=expected_run_id,
            )
            custody = self._read_optional_mapping(custody_record)
            self._validate_custody_mapping(custody)
            revalidated = self.validate_ledger(ledger_path)
            if (
                not revalidated.valid
                or revalidated.head_hash != ledger.head_hash
                or revalidated.event_count != ledger.event_count
            ):
                raise RecoveryError("ledger changed during recovery planning")
            ledger = revalidated
            # New-study authorization is accepted only as the typed, validated
            # StudyVersion object; lossy provider-neutral mappings cannot grant
            # confirmatory execution authority.
            new_protocol = new_study_protocol
        except RecoveryError as exc:
            return RecoveryReport(
                ResumeAction.STOP_SECURITY,
                (f"RECOVERY_VALIDATION_FAILED:{exc}",),
                True,
                ledger.event_count,
                ledger.head_hash,
                True,
                (),
                tuple(quarantined),
                None,
                self._derived_state(ledger.events),
                False,
                False,
            )

        derived = self._derived_state(ledger.events)
        touched, completed = self._confirmatory_status(ledger.events, custody)
        persisted_stop_action = {
            "STOP_SECURITY": ResumeAction.STOP_SECURITY,
            "STOP_SCIENTIFIC_INVALIDITY": ResumeAction.STOP_SCIENTIFIC_INVALIDITY,
        }.get(derived)
        if persisted_stop_action is not None:
            return RecoveryReport(
                persisted_stop_action,
                (f"PERSISTED_TERMINAL_STATE:{derived}",),
                True,
                ledger.event_count,
                ledger.head_hash,
                True,
                (),
                tuple(quarantined),
                checkpoint,
                derived,
                touched,
                completed,
            )
        if touched:
            if self._valid_new_study_protocol(
                new_protocol, custody
            ) and self._valid_fresh_custody_evidence(
                fresh_custody_evidence,
                new_protocol,
                ledger.events,
                custody,
                artifact_registry,
                custody_provider,
                self.project_root,
            ):
                return RecoveryReport(
                    ResumeAction.START_NEW_STUDY,
                    ("DISTINCT_FROZEN_NEW_STUDY_PROTOCOL_ACCEPTED",),
                    True,
                    ledger.event_count,
                    ledger.head_hash,
                    True,
                    (),
                    tuple(quarantined),
                    None,
                    derived,
                    True,
                    completed,
                    True,
                )
            if completed:
                return RecoveryReport(
                    ResumeAction.SKIP_COMPLETED,
                    ("CONFIRMATORY_EVALUATION_ALREADY_COMPLETED", "CONFIRMATORY_RERUN_PROHIBITED"),
                    True,
                    ledger.event_count,
                    ledger.head_hash,
                    True,
                    (),
                    tuple(quarantined),
                    checkpoint,
                    derived,
                    True,
                    True,
                )
            return RecoveryReport(
                ResumeAction.NEW_STUDY_REQUIRED,
                ("CONFIRMATORY_OR_HOLDOUT_ACCESS_ALREADY_RECORDED", "CONFIRMATORY_RERUN_PROHIBITED"),
                True,
                ledger.event_count,
                ledger.head_hash,
                True,
                (),
                tuple(quarantined),
                checkpoint,
                derived,
                True,
                False,
            )

        if not ledger.events:
            action = ResumeAction.START_FRESH
            reasons = ("EMPTY_VALID_LEDGER",)
        elif checkpoint is not None:
            action = ResumeAction.RESUME_FROM_CHECKPOINT
            reasons = ("LAST_VALID_CHECKPOINT_SELECTED_BY_LEDGER_POSITION",)
        else:
            action = ResumeAction.RESUME_FROM_LEDGER
            reasons = ("NO_VALID_CHECKPOINT_REPLAY_LEDGER",)
        return RecoveryReport(
            action,
            reasons,
            True,
            ledger.event_count,
            ledger.head_hash,
            True,
            (),
            tuple(quarantined),
            checkpoint,
            derived,
            False,
            False,
            replay_event_count=(
                ledger.event_count - checkpoint.ledger_event_index - 1 if checkpoint else ledger.event_count
            ),
        )

    def _admit_confirmatory_locked(
        self,
        *,
        ledger_path: str | os.PathLike[str],
        study_version: object,
        fresh_custody_evidence: FreshCustodyEvidence,
        reveal_authority: ConfirmatoryRevealAuthority,
        artifact_registry: object,
        custody_provider: object,
        validity_snapshot: object,
        start_event: LedgerEvent,
        _locked_session: object,
        _execution_class: RevealExecutionClass,
        custody_record: object | None = None,
        _native_requester: str | None = None,
        _native_reason: str | None = None,
        _native_requested_at: str | None = None,
        _native_evaluator_spec: ConfirmatoryEvaluatorSpec | None = None,
    ) -> _ResolvedConfirmatoryAdmission:
        """Resolve authority and durably publish STARTED under custody lock.

        This method has no reveal primitive.  The exact simulated provider calls
        it from its locked session, then consumes only the returned content-
        derived hashes.  Calling it directly can never expose holdout bytes.
        """

        from .artifacts import ArtifactRegistry
        from .holdout import (
            CustodyIndependence,
            CustodyStatus,
            HoldoutAdmissionSnapshot,
            HoldoutCustody,
            HoldoutRevealSession,
            HoldoutSeal,
        )
        from .protocol import StudyVersion
        from .resources import ResourceRuntimeState, ValidityBudgetSnapshot
        from .roles import Role

        if type(reveal_authority) is SimulatedReserveRevealSelection:
            from .holdout import _require_simulated_reserve_resource_binding

            _require_simulated_reserve_resource_binding(
                _locked_session, custody_provider, self.project_root
            )
            if (
                type(self) is not RecoveryManager
                or type(artifact_registry) is not ArtifactRegistry
                or artifact_registry.policy.root != self.project_root
                or _execution_class is not RevealExecutionClass.SIMULATED_ARCHITECTURE_CONTROL
            ):
                raise ConfirmatoryRerunError(
                    "simulated reserve admission lacks its live native resource-bound session"
                )
            from .simulated_observation import _admit_simulated_reserve_locked

            return _admit_simulated_reserve_locked(
                self,
                ledger_path=ledger_path,
                study_version=study_version,
                fresh_custody_evidence=fresh_custody_evidence,
                reveal_authority=reveal_authority,
                artifact_registry=artifact_registry,
                custody_provider=custody_provider,
                validity_snapshot=validity_snapshot,
                start_event=start_event,
                _locked_session=_locked_session,
                _execution_class=_execution_class,
                custody_record=custody_record,
                _native_requester=_native_requester,
                _native_reason=_native_reason,
                _native_requested_at=_native_requested_at,
                _native_evaluator_spec=_native_evaluator_spec,
            )

        if not isinstance(study_version, StudyVersion):
            raise ConfirmatoryRerunError("confirmatory reveal requires a typed StudyVersion")
        if study_version.confirmatory_revealed:
            raise ConfirmatoryRerunError("StudyVersion is already marked as revealed")
        if not isinstance(fresh_custody_evidence, FreshCustodyEvidence):
            raise ConfirmatoryRerunError("fresh custody selector type is invalid")
        if not isinstance(reveal_authority, ConfirmatoryRevealAuthority):
            raise ConfirmatoryRerunError("confirmatory reveal authority type is invalid")
        if (
            not isinstance(artifact_registry, ArtifactRegistry)
            or artifact_registry.policy.root != self.project_root
        ):
            raise ConfirmatoryRerunError("reveal registry is not rooted at this project")
        if not isinstance(custody_provider, HoldoutCustody):
            raise ConfirmatoryRerunError("custody provider type is invalid")
        if not isinstance(validity_snapshot, ValidityBudgetSnapshot):
            raise ConfirmatoryRerunError("live validity-budget snapshot type is invalid")
        if not isinstance(start_event, LedgerEvent):
            raise ConfirmatoryRerunError("confirmatory STARTED event must be typed")
        if not isinstance(_locked_session, HoldoutRevealSession):
            raise ConfirmatoryRerunError("locked custody reveal session type is invalid")
        if (
            getattr(_locked_session, "_provider", None) is not custody_provider
            or getattr(_locked_session, "_active", None) is not True
        ):
            raise ConfirmatoryRerunError(
                "locked custody reveal session is not live for this provider"
            )
        if not isinstance(_execution_class, RevealExecutionClass):
            raise ConfirmatoryRerunError("reveal execution class must be typed")
        expected_start_type = (
            "CONFIRMATORY_STARTED"
            if _execution_class is RevealExecutionClass.SCIENTIFIC_CONFIRMATION
            else "CHECKPOINT"
        )
        expected_execution_kind = (
            "SCIENTIFIC_CONFIRMATION_STARTED"
            if _execution_class is RevealExecutionClass.SCIENTIFIC_CONFIRMATION
            else "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
        )
        expected_evidence_class = (
            "SCIENTIFIC_EVIDENCE"
            if _execution_class is RevealExecutionClass.SCIENTIFIC_CONFIRMATION
            else "ARCHITECTURE_CONTROL"
        )

        ledger = self.validate_ledger(
            ledger_path,
            _bypass_injected_validator=True,
        )
        if not ledger.valid:
            raise LedgerValidationError(ledger.error or "ledger is invalid")
        ledger_head_state = (
            ledger.events[-1].get("requested_state_after")
            if ledger.events
            else None
        )
        if (
            start_event.run_id != ledger.run_id
            or start_event.event_type != expected_start_type
            or start_event.prior_event_hash != ledger.head_hash
            or not _confirmatory_start_preserves_head(
                start_event.to_dict(),
                ledger_head_state=ledger_head_state,
                scientific=(
                    _execution_class
                    is RevealExecutionClass.SCIENTIFIC_CONFIRMATION
                ),
            )
        ):
            raise ConfirmatoryRerunError(
                "confirmatory STARTED must preserve the exact current ledger head; "
                "scientific confirmation additionally requires CONFIRM"
            )
        custody = self._read_optional_mapping(custody_record)
        self._validate_custody_mapping(custody)
        touched, _ = self._confirmatory_status(ledger.events, custody)
        if touched and not self._valid_new_study_protocol(study_version, custody):
            raise ConfirmatoryRerunError(
                "prior confirmatory access requires the exact next frozen StudyVersion"
            )
        if not touched and custody is not None:
            counts = (
                custody.get("access_count", 0),
                custody.get("authorized_access_count", 0),
                custody.get("holdout_access_count", 0),
            )
            if any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value != 0
                for value in counts
            ):
                raise ConfirmatoryRerunError("custody access status is invalid or nonzero")

        protocol_record, protocol_payload = self._resolve_registered_reveal_artifact(
            artifact_registry,
            reveal_authority.protocol,
            logical_type="frozen_protocol",
            creator_role=Role.PROTOCOL_DESIGNER,
            parents=(),
        )
        source_record, source_payload = self._resolve_registered_reveal_artifact(
            artifact_registry,
            reveal_authority.source_inventory,
            logical_type="frozen_source_inventory",
            creator_role=Role.ORCHESTRATOR,
            parents=(),
        )
        configuration_record, configuration_payload = (
            self._resolve_registered_reveal_artifact(
                artifact_registry,
                reveal_authority.configuration_inventory,
                logical_type="frozen_configuration_inventory",
                creator_role=Role.ORCHESTRATOR,
                parents=(),
            )
        )
        split_record, split_payload = self._resolve_registered_reveal_artifact(
            artifact_registry,
            reveal_authority.split_manifest,
            logical_type="frozen_confirmatory_split",
            creator_role=Role.PROTOCOL_DESIGNER,
            parents=(reveal_authority.protocol.artifact_sha256,),
        )
        blind_record, blind_payload = self._resolve_registered_reveal_artifact(
            artifact_registry,
            reveal_authority.blind_interpretation,
            logical_type="blind_interpretation",
            creator_role=Role.STATISTICIAN,
            parents=(
                reveal_authority.source_inventory.artifact_sha256,
                reveal_authority.configuration_inventory.artifact_sha256,
            ),
        )
        midrun_record, midrun_payload = self._resolve_registered_reveal_artifact(
            artifact_registry,
            reveal_authority.midrun_review,
            logical_type="midrun_review",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            parents=(
                reveal_authority.source_inventory.artifact_sha256,
                reveal_authority.configuration_inventory.artifact_sha256,
            ),
        )
        resource_record, resource_payload = self._resolve_registered_reveal_artifact(
            artifact_registry,
            reveal_authority.resource_charge,
            logical_type="resource_runtime_confirmatory_charge",
            creator_role=Role.ORCHESTRATOR,
        )
        if len(resource_record.parent_artifacts) != 1:  # type: ignore[attr-defined]
            raise ConfirmatoryRerunError(
                "confirmatory resource charge must extend one prior resource checkpoint"
            )
        receipt_selector = RegisteredArtifactSelector(
            fresh_custody_evidence.receipt_artifact_sha256,
            fresh_custody_evidence.artifact_record_hash,
        )
        receipt_record, receipt = self._resolve_registered_reveal_artifact(
            artifact_registry,
            receipt_selector,
            logical_type="fresh_custody_receipt",
            creator_role=Role.HOLDOUT_CUSTODIAN,
            parents=(
                reveal_authority.protocol.artifact_sha256,
                reveal_authority.blind_interpretation.artifact_sha256,
                reveal_authority.source_inventory.artifact_sha256,
                reveal_authority.configuration_inventory.artifact_sha256,
                reveal_authority.split_manifest.artifact_sha256,
                reveal_authority.midrun_review.artifact_sha256,
            ),
        )

        expected_protocol_keys = {
            "kind",
            "frozen",
            "protocol",
            "protocol_sha256",
            "baseline_equivalence",
            "blind_patterns",
            "reproduction_tolerance",
        }
        canonical_protocol = safe_json_loads(
            canonical_json_bytes(study_version.protocol.canonical_dict),
            max_bytes=MAX_ARTIFACT_OBJECT_BYTES,
        )
        if (
            set(protocol_payload) != expected_protocol_keys
            or protocol_payload.get("kind") != "FROZEN_SYNTHETIC_PROTOCOL"
            or protocol_payload.get("frozen") is not True
            or protocol_payload.get("protocol") != canonical_protocol
            or protocol_payload.get("protocol_sha256") != study_version.protocol_hash
        ):
            raise ConfirmatoryRerunError(
                "frozen protocol artifact does not encode the supplied StudyVersion"
            )
        code_hash = self._validated_inventory_hash(
            source_payload, kind="FROZEN_SOURCE_INVENTORY"
        )
        evaluator_implementation_sha256 = self._validated_live_source_implementation(
            source_payload,
            path="src/scientist_one/holdout.py",
            label="simulated evaluator",
        )
        self._validated_live_source_implementation(
            source_payload,
            path="src/scientist_one/recovery.py",
            label="confirmatory coordinator",
        )
        configuration_hash = self._validated_inventory_hash(
            configuration_payload, kind="FROZEN_CONFIGURATION_INVENTORY"
        )

        if set(split_payload) != {
            "schema_version",
            "kind",
            "study_id",
            "study_version",
            "split_id",
            "role",
            "split_manifest_hash",
        }:
            raise ConfirmatoryRerunError("confirmatory split artifact schema is invalid")
        split_id = split_payload.get("split_id")
        split_hash = split_payload.get("split_manifest_hash")
        expected_split_hash = (
            hashlib.sha256(
                canonical_json_bytes({"id": split_id, "role": "holdout"}) + b"\n"
            ).hexdigest()
            if isinstance(split_id, str) and split_id
            else None
        )
        if (
            split_payload.get("schema_version") != "1.0"
            or split_payload.get("kind") != "FROZEN_CONFIRMATORY_SPLIT"
            or split_payload.get("study_id") != study_version.study_id
            or split_payload.get("study_version") != study_version.version
            or split_payload.get("role") != "holdout"
            or split_id not in study_version.protocol.data_roles.holdout
            or split_hash != expected_split_hash
        ):
            raise ConfirmatoryRerunError("confirmatory split artifact is not study-bound")

        expected_inventory_parents = (
            reveal_authority.source_inventory.artifact_sha256,
            reveal_authority.configuration_inventory.artifact_sha256,
        )
        if set(blind_payload) != {
            "kind",
            "frozen_before_reveal",
            "source_inventory_sha256",
            "configuration_inventory_sha256",
            "patterns",
        }:
            raise ConfirmatoryRerunError("blind interpretation schema is invalid")
        blind_patterns = blind_payload.get("patterns")
        if (
            blind_payload.get("kind") != "FROZEN_BLIND_INTERPRETATION"
            or blind_payload.get("frozen_before_reveal") is not True
            or blind_payload.get("source_inventory_sha256")
            != expected_inventory_parents[0]
            or blind_payload.get("configuration_inventory_sha256")
            != expected_inventory_parents[1]
            or not isinstance(blind_patterns, Mapping)
            or not blind_patterns
            or any(
                not isinstance(key, str)
                or not key
                or not isinstance(value, str)
                or not value
                for key, value in blind_patterns.items()
            )
        ):
            raise ConfirmatoryRerunError("blind interpretation is not frozen and bound")

        if set(midrun_payload) != {
            "kind",
            "passed",
            "drift",
            "leakage",
            "baseline_equivalent",
            "validity_reserve_intact",
            "code_fingerprint",
            "configuration_sha256",
            "source_inventory_sha256",
            "configuration_inventory_sha256",
        } or (
            midrun_payload.get("kind") != "FROZEN_MIDRUN_REVIEW"
            or midrun_payload.get("passed") is not True
            or midrun_payload.get("drift") is not False
            or midrun_payload.get("leakage") is not False
            or midrun_payload.get("baseline_equivalent") is not True
            or midrun_payload.get("validity_reserve_intact") is not True
            or midrun_payload.get("code_fingerprint") != code_hash
            or midrun_payload.get("configuration_sha256") != configuration_hash
            or midrun_payload.get("source_inventory_sha256")
            != expected_inventory_parents[0]
            or midrun_payload.get("configuration_inventory_sha256")
            != expected_inventory_parents[1]
        ):
            raise ConfirmatoryRerunError("midrun review did not pass its frozen checks")

        try:
            resource_state = ResourceRuntimeState.from_mapping(resource_payload)
        except Exception as exc:
            raise ConfirmatoryRerunError(
                "confirmatory resource charge payload is invalid"
            ) from exc
        if resource_state.run_id != ledger.run_id:
            raise ConfirmatoryRerunError(
                "confirmatory resource charge belongs to a different ledger run"
            )
        resource_authority_records, resource_authority_descriptors = (
            self._resource_authority_history(ledger.run_id)
        )
        if len(resource_authority_records) < 2:
            raise ConfirmatoryRerunError(
                "confirmatory resource charge lacks a prior external authority"
            )
        authority_head = resource_authority_records[-1]
        authority_prior = resource_authority_records[-2]
        parent_hashes = tuple(resource_record.parent_artifacts)  # type: ignore[attr-defined]
        if (
            authority_head.get("logical_type")
            != "resource_runtime_confirmatory_charge"
            or authority_head.get("state") != resource_payload
            or authority_head.get("state_sha256")
            != reveal_authority.resource_charge.artifact_sha256
            or parent_hashes != (authority_prior.get("state_sha256"),)
        ):
            raise ConfirmatoryRerunError(
                "confirmatory resource artifact does not extend the external authority head"
            )
        try:
            parent_metadata = artifact_registry.get_metadata(parent_hashes[0])
            parent_selector = RegisteredArtifactSelector(
                parent_hashes[0],
                str(parent_metadata.record_hash),
            )
            _parent_record, parent_payload = self._resolve_registered_reveal_artifact(
                artifact_registry,
                parent_selector,
                logical_type=str(authority_prior["logical_type"]),
                creator_role=Role.ORCHESTRATOR,
            )
        except Exception as exc:
            raise ConfirmatoryRerunError(
                "prior resource artifact is unavailable or substituted"
            ) from exc
        if parent_payload != authority_prior.get("state"):
            raise ConfirmatoryRerunError(
                "prior resource artifact differs from external authority history"
            )
        snapshot_values = (
            validity_snapshot.total_units,
            validity_snapshot.exploratory_limit,
            validity_snapshot.confirmatory_reserve,
            validity_snapshot.exploratory_used,
            validity_snapshot.confirmatory_used,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in snapshot_values
        ):
            raise ConfirmatoryRerunError("validity-budget snapshot values are invalid")
        expected_exploratory_limit = math.floor(
            validity_snapshot.total_units
            * (1.0 - study_version.protocol.validity_reserve_fraction)
        )
        if (
            validity_snapshot.total_units <= 0
            or validity_snapshot.exploratory_limit != expected_exploratory_limit
            or validity_snapshot.confirmatory_reserve
            != validity_snapshot.total_units - expected_exploratory_limit
            or validity_snapshot.exploratory_used
            > validity_snapshot.exploratory_limit
            or validity_snapshot.confirmatory_used
            != reveal_authority.confirmatory_validity_units
            or validity_snapshot.confirmatory_used
            > validity_snapshot.confirmatory_reserve
            or resource_state.validity_total_units != validity_snapshot.total_units
            or resource_state.exploratory_used != validity_snapshot.exploratory_used
            or resource_state.confirmatory_used != validity_snapshot.confirmatory_used
        ):
            raise ConfirmatoryRerunError(
                "post-charge validity snapshot does not prove an untouched fresh reserve"
            )

        receipt_events = [
            (index, event)
            for index, event in enumerate(ledger.events)
            if event.get("event_id") == fresh_custody_evidence.ledger_event_id
        ]
        charge_events = [
            (index, event)
            for index, event in enumerate(ledger.events)
            if event.get("event_id")
            == reveal_authority.resource_charge_ledger_event_id
        ]
        if len(receipt_events) != 1 or len(charge_events) != 1:
            raise ConfirmatoryRerunError("reveal authority ledger selectors are not unique")
        receipt_index, receipt_event = receipt_events[0]
        charge_index, charge_event = charge_events[0]
        if receipt_index >= charge_index or charge_index != len(ledger.events) - 1:
            raise ConfirmatoryRerunError(
                "resource charge must be the final publication before confirmatory STARTED"
            )
        if any(
            event.get("event_type") == "CONFIRMATORY_STARTED"
            or (
                isinstance(event.get("metadata"), Mapping)
                and event["metadata"].get("execution_kind")  # type: ignore[union-attr]
                == "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
            )
            for event in ledger.events[receipt_index + 1 :]
        ):
            raise ConfirmatoryRerunError(
                "a competing confirmatory STARTED event follows the custody receipt"
            )
        if (
            receipt_event.get("event_type") != "CHECKPOINT"
            or receipt_event.get("actor_role") != Role.HOLDOUT_CUSTODIAN.value
            or receipt_event.get("code_version") != code_hash
            or receipt_event.get("configuration_hash") != configuration_hash
            or self._event_artifact_binding(receipt_event)
            != (
                (fresh_custody_evidence.receipt_artifact_sha256,),
                ("fresh_custody_receipt",),
                (fresh_custody_evidence.artifact_record_hash,),
            )
        ):
            raise ConfirmatoryRerunError("custody receipt ledger checkpoint is invalid")
        if (
            charge_event.get("event_type") != "CHECKPOINT"
            or charge_event.get("actor_role") != Role.ORCHESTRATOR.value
            or charge_event.get("code_version") != code_hash
            or charge_event.get("configuration_hash") != configuration_hash
            or self._event_artifact_binding(charge_event)
            != (
                (reveal_authority.resource_charge.artifact_sha256,),
                ("resource_runtime_confirmatory_charge",),
                (reveal_authority.resource_charge.artifact_record_hash,),
            )
        ):
            raise ConfirmatoryRerunError("confirmatory resource charge event is invalid")
        charge_metadata = charge_event.get("metadata")
        authority_checkpoint = (
            charge_metadata.get("resource_authority_checkpoint")
            if isinstance(charge_metadata, Mapping)
            else None
        )
        if (
            not isinstance(authority_checkpoint, Mapping)
            or dict(authority_checkpoint)
            != dict(resource_authority_descriptors[-1])
        ):
            raise ConfirmatoryRerunError(
                "resource charge event lacks its monotonic authority binding"
            )
        observed_resource_history: list[Mapping[str, object]] = []
        descriptor_keys = {
            "sequence",
            "logical_type",
            "state_sha256",
            "authority_sha256",
            "prior_authority_sha256",
        }
        for event in ledger.events:
            metadata = event.get("metadata")
            checkpoint = (
                metadata.get("resource_authority_checkpoint")
                if isinstance(metadata, Mapping)
                else None
            )
            if checkpoint is None:
                continue
            if not isinstance(checkpoint, Mapping) or set(checkpoint) != descriptor_keys:
                raise ConfirmatoryRerunError(
                    "ledger resource authority checkpoint schema is invalid"
                )
            observed_resource_history.append(dict(checkpoint))
        if tuple(observed_resource_history) != resource_authority_descriptors:
            raise ConfirmatoryRerunError(
                "external resource authority history is not exactly ledger-bound"
            )

        if set(receipt) != {
            "schema_version",
            "study_id",
            "study_version",
            "seal",
            "status",
            "journal_head_hash",
            "journal_identity_sha256",
        }:
            raise ConfirmatoryRerunError("fresh custody receipt schema is invalid")
        receipt_head = receipt.get("journal_head_hash")
        receipt_identity = receipt.get("journal_identity_sha256")
        if (
            receipt.get("schema_version") != "1.0"
            or receipt.get("study_id") != study_version.study_id
            or receipt.get("study_version") != study_version.version
            or not isinstance(receipt_head, str)
            or not SHA256_PATTERN.fullmatch(receipt_head)
            or not isinstance(receipt_identity, str)
            or not SHA256_PATTERN.fullmatch(receipt_identity)
            or not isinstance(receipt.get("seal"), Mapping)
            or not isinstance(receipt.get("status"), Mapping)
        ):
            raise ConfirmatoryRerunError("fresh custody receipt content is invalid")
        try:
            receipt_seal = HoldoutSeal(**dict(receipt["seal"]))  # type: ignore[arg-type]
            status_value = dict(receipt["status"])  # type: ignore[arg-type]
            if set(status_value) != {
                "custody_independence",
                "sealed",
                "revealed",
                "invalidated",
                "confirmatory_claims_valid",
                "authorized_access_count",
                "violation_reasons",
                "release_event",
                "durable_journal",
                "journal_head_hash",
            } or status_value.get("release_event") is not None:
                raise ValueError("receipt status schema")
            status_value["custody_independence"] = CustodyIndependence(
                status_value["custody_independence"]
            )
            status_value["violation_reasons"] = tuple(
                status_value["violation_reasons"]
            )
            receipt_status = CustodyStatus(**status_value)
        except Exception as exc:
            raise ConfirmatoryRerunError("fresh custody receipt types are invalid") from exc

        with nullcontext(_locked_session) as session:
            if not isinstance(session, HoldoutRevealSession):
                raise ConfirmatoryRerunError(
                    "custody provider did not return a locked reveal session"
                )
            live = session.snapshot
            if not isinstance(live, HoldoutAdmissionSnapshot):
                raise ConfirmatoryRerunError("custody session snapshot type is invalid")
            if (
                live.seal != receipt_seal
                or live.status != receipt_status
                or live.journal_head_hash != receipt_head
                or live.journal_identity_sha256 != receipt_identity
                or live.protocol_hash != study_version.protocol_hash
                or live.code_hash != code_hash
                or live.configuration_hash != configuration_hash
                or live.split_manifest_hash != split_hash
                or live.pre_unblinding_interpretation_hash
                != reveal_authority.blind_interpretation.artifact_sha256
                or live.sealed is not True
                or live.revealed is not False
                or live.invalidated is not False
                or live.authorized_access_count != 0
                or live.durable_journal is not True
            ):
                raise ConfirmatoryRerunError(
                    "live custody state does not match the resolved reveal authority"
                )
            if custody is not None:
                for key, fresh_value in (
                    ("holdout_identity_hash", live.holdout_identity_hash),
                    ("split_manifest_hash", live.split_manifest_hash),
                    ("seal_hash", live.seal_hash),
                ):
                    old_value = custody.get(key)
                    if (
                        not isinstance(old_value, str)
                        or not SHA256_PATTERN.fullmatch(old_value)
                        or old_value == fresh_value
                    ):
                        raise ConfirmatoryRerunError(
                            "child study did not receive distinct custody and reserve"
                        )
            fresh_binding = {
                "artifact_sha256": fresh_custody_evidence.receipt_artifact_sha256,
                "artifact_record_hash": fresh_custody_evidence.artifact_record_hash,
                "journal_head_hash": live.journal_head_hash,
                "journal_identity_sha256": live.journal_identity_sha256,
                "protocol_hash": study_version.protocol_hash,
                "seal_hash": live.seal_hash,
                "study_version": study_version.version,
            }
            receipt_metadata = receipt_event.get("metadata")
            if (
                not isinstance(receipt_metadata, Mapping)
                or receipt_metadata.get("fresh_custody") != fresh_binding
            ):
                raise ConfirmatoryRerunError(
                    "custody receipt event does not bind the live provider"
                )

            current = self.validate_ledger(
                ledger_path,
                _bypass_injected_validator=True,
            )
            if (
                not current.valid
                or current.event_count != ledger.event_count
                or current.head_hash != ledger.head_hash
                or current.events != ledger.events
            ):
                raise ConfirmatoryRerunError(
                    "ledger advanced or changed before confirmatory STARTED"
                )
            # This legacy entry point accepts arbitrary confined run paths.
            # Resolve their native paired population, not the Dataset-specific
            # canonical namespace. A non-isolated operational reservation is
            # possible exposure even when no result or ledger event exists.
            from .scientific_design import (
                ScientificDesignError,
                _locked_checked_result_authority_snapshot,
            )
            from .seed_reporting import (
                OperationalSeedReportingError,
                reject_operational_seed_exposure,
            )

            admission_ledger = EventLedger(
                self.project_root, self._relative_path(ledger_path),
            )
            try:
                registry_snapshot, ledger_snapshot = (
                    _locked_checked_result_authority_snapshot(
                        artifact_registry, admission_ledger,
                    )
                )
                if (
                    ledger_snapshot.event_count != current.event_count
                    or ledger_snapshot.head_hash != current.head_hash
                    or tuple(event.to_dict() for event in ledger_snapshot.events)
                    != current.events
                ):
                    raise ConfirmatoryRerunError(
                        "ledger advanced or changed before confirmatory STARTED"
                    )
                reject_operational_seed_exposure(
                    artifact_registry, registry_snapshot.records,
                    ledger_snapshot.events, complete_registry_population=True,
                )
            except OperationalSeedReportingError as exc:
                raise ConfirmatoryRerunError(
                    "operational reservation or possible exposure forbids confirmatory release"
                ) from exc
            except ScientificDesignError as exc:
                raise ConfirmatoryRerunError(
                    "confirmatory admission source snapshot is unavailable"
                ) from exc
            try:
                admission_ledger.append(start_event)
            except Exception as exc:
                raise ConfirmatoryRerunError(
                    "typed confirmatory STARTED event could not be appended"
                ) from exc
            admitted = self.validate_ledger(
                ledger_path,
                _bypass_injected_validator=True,
            )
            if (
                not admitted.valid
                or admitted.event_count != current.event_count + 1
                or not admitted.events
            ):
                raise ConfirmatoryRerunError(
                    "confirmatory admission did not append exactly one ledger event"
                )
            started = admitted.events[-1]
            expected_selectors = (
                ("frozen_protocol", reveal_authority.protocol),
                ("frozen_source_inventory", reveal_authority.source_inventory),
                (
                    "frozen_configuration_inventory",
                    reveal_authority.configuration_inventory,
                ),
                ("frozen_confirmatory_split", reveal_authority.split_manifest),
                ("blind_interpretation", reveal_authority.blind_interpretation),
                ("midrun_review", reveal_authority.midrun_review),
                (
                    "resource_runtime_confirmatory_charge",
                    reveal_authority.resource_charge,
                ),
                ("fresh_custody_receipt", receipt_selector),
            )
            expected_started_binding = (
                tuple(selector.artifact_sha256 for _, selector in expected_selectors),
                tuple(logical_type for logical_type, _ in expected_selectors),
                tuple(
                    selector.artifact_record_hash for _, selector in expected_selectors
                ),
            )
            started_metadata = started.get("metadata")
            if (
                started != start_event.to_dict()
                or started.get("run_id") != ledger.run_id
                or started.get("prior_event_hash") != current.head_hash
                or started.get("event_type") != expected_start_type
                or started.get("actor_role") != Role.ORCHESTRATOR.value
                or not _confirmatory_start_preserves_head(
                    started,
                    ledger_head_state=(
                        current.events[-1].get("requested_state_after")
                        if current.events
                        else None
                    ),
                    scientific=(
                        _execution_class
                        is RevealExecutionClass.SCIENTIFIC_CONFIRMATION
                    ),
                )
                or started.get("code_version") != code_hash
                or started.get("configuration_hash") != configuration_hash
                or self._event_artifact_binding(started) != expected_started_binding
                or not isinstance(started_metadata, Mapping)
                or started_metadata.get("fresh_custody") != fresh_binding
                or started_metadata.get("evidence_class")
                != expected_evidence_class
                or started_metadata.get("execution_kind")
                != expected_execution_kind
            ):
                raise ConfirmatoryRerunError(
                    "CONFIRMATORY_STARTED is not exactly bound to reveal authority"
                )
            started_resource_checkpoint = started_metadata.get(
                "resource_authority_checkpoint"
            )
            if started_resource_checkpoint != authority_checkpoint:
                raise ConfirmatoryRerunError(
                    "CONFIRMATORY_STARTED does not repeat the live resource authority"
                )

            started_event_id = started.get("event_id")
            started_event_hash = started.get("event_hash")
            if (
                not isinstance(started_event_id, str)
                or not started_event_id
                or not isinstance(started_event_hash, str)
                or not SHA256_PATTERN.fullmatch(started_event_hash)
            ):
                raise ConfirmatoryRerunError(
                    "CONFIRMATORY_STARTED identity is invalid after append"
                )
            return _ResolvedConfirmatoryAdmission(
                protocol_hash=study_version.protocol_hash,
                code_hash=code_hash,
                evaluator_implementation_sha256=(
                    evaluator_implementation_sha256
                ),
                configuration_hash=configuration_hash,
                split_manifest_hash=str(split_hash),
                blind_interpretation_hash=(
                    reveal_authority.blind_interpretation.artifact_sha256
                ),
                ledger_run_id=ledger.run_id,
                resource_authority_sha256=str(
                    resource_authority_descriptors[-1]["authority_sha256"]
                ),
                started_event_id=started_event_id,
                started_event_hash=started_event_hash,
            )

    def run_confirmatory_authorized(
        self,
        *,
        ledger_path: str | os.PathLike[str],
        study_version: object,
        fresh_custody_evidence: FreshCustodyEvidence,
        reveal_authority: ConfirmatoryRevealAuthority,
        artifact_registry: object,
        custody_provider: object,
        validity_snapshot: object,
        start_event: LedgerEvent,
        evaluator_spec: ConfirmatoryEvaluatorSpec,
        requester: str,
        reason: str,
        requested_at: str | None = None,
        custody_record: object | None = None,
    ) -> Never:
        """Require real independent custody; no such provider is implemented.

        Simulated custody can never enter this path.  A future implementation
        must consume a freshly replayed positive confirmation-reveal gate and
        external custody attestation inside the same provider admission and
        RELEASE locks.  Until that boundary exists, real confirmation remains
        explicitly UNTESTED rather than falling back to local custody.
        """

        from .holdout import CustodyIndependence, HoldoutCustody

        if not isinstance(custody_provider, HoldoutCustody):
            raise ConfirmatoryRerunError("custody provider type is invalid")
        if type(evaluator_spec) is not ConfirmatoryEvaluatorSpec:
            raise ConfirmatoryRerunError(
                "confirmatory evaluator must be the closed repository-owned spec"
            )
        if custody_provider.independence is CustodyIndependence.NON_INDEPENDENT:
            raise ConfirmatoryRerunError(
                "scientific confirmation rejects non-independent custody"
            )
        raise ConfirmatoryRerunError(
            "independent confirmation-reveal custody is UNTESTED"
        )

    def run_non_evidentiary_simulated_fixture(
        self,
        *,
        ledger_path: str | os.PathLike[str],
        study_version: object,
        fresh_custody_evidence: FreshCustodyEvidence,
        reveal_authority: ConfirmatoryRevealAuthority,
        artifact_registry: object,
        custody_provider: object,
        validity_snapshot: object,
        start_event: LedgerEvent,
        evaluator_spec: ConfirmatoryEvaluatorSpec,
        requester: str,
        reason: str,
        requested_at: str | None = None,
        custody_record: object | None = None,
    ) -> tuple[HoldoutRelease, dict[str, object]]:
        """Exercise simulated custody without creating scientific authority."""

        from .holdout import HoldoutRevealSession, SimulatedHoldoutCustody

        if type(custody_provider) is not SimulatedHoldoutCustody:
            raise ConfirmatoryRerunError(
                "non-evidentiary fixture execution requires simulated custody"
            )
        if type(evaluator_spec) is not ConfirmatoryEvaluatorSpec:
            raise ConfirmatoryRerunError(
                "fixture evaluator must be the closed repository-owned spec"
            )
        guard_arguments = (
            {"simulated_reserve_project_root": self.project_root}
            if type(reveal_authority) is SimulatedReserveRevealSelection
            else {}
        )
        with custody_provider._reveal_admission_guard(**guard_arguments) as session:
            if not isinstance(session, HoldoutRevealSession):
                raise ConfirmatoryRerunError(
                    "custody provider did not return a locked reveal session"
                )
            return session._release(
                coordinator=self,
                ledger_path=ledger_path,
                study_version=study_version,
                fresh_custody_evidence=fresh_custody_evidence,
                reveal_authority=reveal_authority,
                artifact_registry=artifact_registry,
                custody_provider=custody_provider,
                validity_snapshot=validity_snapshot,
                start_event=start_event,
                evaluator_spec=evaluator_spec,
                execution_class=(
                    RevealExecutionClass.SIMULATED_ARCHITECTURE_CONTROL
                ),
                requester=requester,
                reason=reason,
                requested_at=requested_at,
                custody_record=custody_record,
            )

    def assert_confirmatory_run_allowed(
        self,
        *,
        ledger_path: str | os.PathLike[str],
        custody_record: object | None = None,
        new_study_protocol: object | None = None,
        fresh_custody_evidence: FreshCustodyEvidence | None = None,
        artifact_registry: object | None = None,
        custody_provider: object | None = None,
    ) -> None:
        """Reject the retired admission-only API.

        Returning after STARTED but before RELEASE created a separable authority
        window.  Scientific confirmation now remains UNTESTED until an
        independent provider can consume its positive live gate under one
        locked transition; local fixture exercise has an explicitly separate
        non-evidentiary entry point.
        """

        raise ConfirmatoryRerunError(
            "admission-only confirmatory API is disabled"
        )

    # Names used by orchestration code and external callers.
    resume = recover
    validate_resume = recover


def _derive_confirmation_reveal_gate_receipt(
    registry: object,
    ledger: EventLedger,
    *,
    expected_run_id: str,
    fresh_custody_evidence: FreshCustodyEvidence,
    reveal_authority: ConfirmatoryRevealAuthority,
    started_event_id: str,
    receipt_id: str | None = None,
    expected_started_event_hash: str | None = None,
    expected_object_id: str | None = None,
) -> tuple[ConfirmationRevealGateReceipt, tuple[ArtifactRecord, ...]]:
    """Replay the exact artifact/ledger pre-reveal boundary without booleans."""

    from .artifacts import ArtifactRecord, ArtifactRegistry
    from .holdout import (
        CustodyIndependence,
        CustodyStatus,
        HoldoutSeal,
        SimulatedHoldoutCustody,
    )
    from .resources import ResourceRuntimeState
    from .roles import Role

    expected_run_id = _identifier(expected_run_id, "confirmation reveal run ID")
    started_event_id = _identifier(started_event_id, "confirmation STARTED event ID")
    if not isinstance(registry, ArtifactRegistry):
        raise ConfirmatoryRerunError(
            "confirmation reveal receipt requires an ArtifactRegistry"
        )
    if not isinstance(ledger, EventLedger) or ledger.policy.root != registry.policy.root:
        raise ConfirmatoryRerunError(
            "confirmation reveal receipt requires the exact rooted EventLedger"
        )
    if not isinstance(fresh_custody_evidence, FreshCustodyEvidence):
        raise ConfirmatoryRerunError("confirmation reveal fresh custody type is invalid")
    if not isinstance(reveal_authority, ConfirmatoryRevealAuthority):
        raise ConfirmatoryRerunError("confirmation reveal authority type is invalid")

    manager = RecoveryManager(registry.policy.root)
    protocol_record, protocol_payload = manager._resolve_registered_reveal_artifact(
        registry,
        reveal_authority.protocol,
        logical_type="frozen_protocol",
        creator_role=Role.PROTOCOL_DESIGNER,
        parents=(),
    )
    source_record, source_payload = manager._resolve_registered_reveal_artifact(
        registry,
        reveal_authority.source_inventory,
        logical_type="frozen_source_inventory",
        creator_role=Role.ORCHESTRATOR,
        parents=(),
    )
    configuration_record, configuration_payload = (
        manager._resolve_registered_reveal_artifact(
            registry,
            reveal_authority.configuration_inventory,
            logical_type="frozen_configuration_inventory",
            creator_role=Role.ORCHESTRATOR,
            parents=(),
        )
    )
    split_record, split_payload = manager._resolve_registered_reveal_artifact(
        registry,
        reveal_authority.split_manifest,
        logical_type="frozen_confirmatory_split",
        creator_role=Role.PROTOCOL_DESIGNER,
        parents=(reveal_authority.protocol.artifact_sha256,),
    )
    inventory_parents = (
        reveal_authority.source_inventory.artifact_sha256,
        reveal_authority.configuration_inventory.artifact_sha256,
    )
    blind_record, blind_payload = manager._resolve_registered_reveal_artifact(
        registry,
        reveal_authority.blind_interpretation,
        logical_type="blind_interpretation",
        creator_role=Role.STATISTICIAN,
        parents=inventory_parents,
    )
    midrun_record, midrun_payload = manager._resolve_registered_reveal_artifact(
        registry,
        reveal_authority.midrun_review,
        logical_type="midrun_review",
        creator_role=Role.SCIENTIFIC_REVIEWER,
        parents=inventory_parents,
    )
    resource_record, resource_payload = manager._resolve_registered_reveal_artifact(
        registry,
        reveal_authority.resource_charge,
        logical_type="resource_runtime_confirmatory_charge",
        creator_role=Role.ORCHESTRATOR,
    )
    receipt_selector = RegisteredArtifactSelector(
        fresh_custody_evidence.receipt_artifact_sha256,
        fresh_custody_evidence.artifact_record_hash,
    )
    receipt_record, receipt_payload = manager._resolve_registered_reveal_artifact(
        registry,
        receipt_selector,
        logical_type="fresh_custody_receipt",
        creator_role=Role.HOLDOUT_CUSTODIAN,
        parents=(
            reveal_authority.protocol.artifact_sha256,
            reveal_authority.blind_interpretation.artifact_sha256,
            reveal_authority.source_inventory.artifact_sha256,
            reveal_authority.configuration_inventory.artifact_sha256,
            reveal_authority.split_manifest.artifact_sha256,
            reveal_authority.midrun_review.artifact_sha256,
        ),
    )
    parents = (
        protocol_record,
        source_record,
        configuration_record,
        split_record,
        blind_record,
        midrun_record,
        resource_record,
        receipt_record,
    )

    if set(protocol_payload) != {
        "kind",
        "frozen",
        "protocol",
        "protocol_sha256",
        "baseline_equivalence",
        "blind_patterns",
        "reproduction_tolerance",
    }:
        raise ConfirmatoryRerunError("confirmation reveal protocol schema is invalid")
    protocol = protocol_payload.get("protocol")
    protocol_hash = protocol_payload.get("protocol_sha256")
    if not isinstance(protocol, Mapping):
        raise ConfirmatoryRerunError("confirmation reveal protocol content is invalid")
    computed_protocol_hash = hashlib.sha256(
        json.dumps(
            protocol,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()
    study_id = protocol.get("study_id")
    study_version = protocol.get("study_version")
    data_roles = protocol.get("data_roles")
    holdout_roles = data_roles.get("holdout") if isinstance(data_roles, Mapping) else None
    if (
        protocol_payload.get("kind") != "FROZEN_SYNTHETIC_PROTOCOL"
        or protocol_payload.get("frozen") is not True
        or protocol_hash != computed_protocol_hash
        or not isinstance(study_id, str)
        or IDENTIFIER_PATTERN.fullmatch(study_id) is None
        or isinstance(study_version, bool)
        or not isinstance(study_version, int)
        or study_version < 1
        or not isinstance(holdout_roles, list)
        or not holdout_roles
    ):
        raise ConfirmatoryRerunError("confirmation reveal protocol is not frozen")
    code_hash = manager._validated_inventory_hash(
        source_payload,
        kind="FROZEN_SOURCE_INVENTORY",
    )
    manager._validated_live_source_implementation(
        source_payload,
        path="src/scientist_one/holdout.py",
        label="confirmation reveal custodian",
    )
    manager._validated_live_source_implementation(
        source_payload,
        path="src/scientist_one/recovery.py",
        label="confirmation reveal coordinator",
    )
    configuration_hash = manager._validated_inventory_hash(
        configuration_payload,
        kind="FROZEN_CONFIGURATION_INVENTORY",
    )
    split_id = split_payload.get("split_id")
    split_hash = split_payload.get("split_manifest_hash")
    expected_split_hash = (
        hashlib.sha256(
            canonical_json_bytes({"id": split_id, "role": "holdout"}) + b"\n"
        ).hexdigest()
        if isinstance(split_id, str) and split_id
        else None
    )
    if (
        set(split_payload)
        != {
            "schema_version",
            "kind",
            "study_id",
            "study_version",
            "split_id",
            "role",
            "split_manifest_hash",
        }
        or split_payload.get("schema_version") != "1.0"
        or split_payload.get("kind") != "FROZEN_CONFIRMATORY_SPLIT"
        or split_payload.get("study_id") != study_id
        or split_payload.get("study_version") != study_version
        or split_payload.get("role") != "holdout"
        or split_id not in holdout_roles
        or split_hash != expected_split_hash
    ):
        raise ConfirmatoryRerunError("confirmation reveal split binding is invalid")
    if (
        set(blind_payload)
        != {
            "kind",
            "frozen_before_reveal",
            "source_inventory_sha256",
            "configuration_inventory_sha256",
            "patterns",
        }
        or blind_payload.get("kind") != "FROZEN_BLIND_INTERPRETATION"
        or blind_payload.get("frozen_before_reveal") is not True
        or blind_payload.get("source_inventory_sha256") != inventory_parents[0]
        or blind_payload.get("configuration_inventory_sha256")
        != inventory_parents[1]
        or not isinstance(blind_payload.get("patterns"), Mapping)
        or not blind_payload.get("patterns")
    ):
        raise ConfirmatoryRerunError("confirmation reveal blind binding is invalid")
    if (
        set(midrun_payload)
        != {
            "kind",
            "passed",
            "drift",
            "leakage",
            "baseline_equivalent",
            "validity_reserve_intact",
            "code_fingerprint",
            "configuration_sha256",
            "source_inventory_sha256",
            "configuration_inventory_sha256",
        }
        or midrun_payload.get("kind") != "FROZEN_MIDRUN_REVIEW"
        or midrun_payload.get("passed") is not True
        or midrun_payload.get("drift") is not False
        or midrun_payload.get("leakage") is not False
        or midrun_payload.get("baseline_equivalent") is not True
        or midrun_payload.get("validity_reserve_intact") is not True
        or midrun_payload.get("code_fingerprint") != code_hash
        or midrun_payload.get("configuration_sha256") != configuration_hash
        or midrun_payload.get("source_inventory_sha256") != inventory_parents[0]
        or midrun_payload.get("configuration_inventory_sha256")
        != inventory_parents[1]
    ):
        raise ConfirmatoryRerunError("confirmation reveal midrun binding is invalid")

    try:
        resource_state = ResourceRuntimeState.from_mapping(resource_payload)
    except Exception as exc:
        raise ConfirmatoryRerunError(
            "confirmation reveal resource charge is invalid"
        ) from exc
    if (
        resource_state.run_id != expected_run_id
        or resource_state.confirmatory_used
        != reveal_authority.confirmatory_validity_units
    ):
        raise ConfirmatoryRerunError(
            "confirmation reveal resource charge is run/budget mismatched"
        )
    authority_records, authority_descriptors = manager._resource_authority_history(
        expected_run_id
    )
    if len(authority_records) < 2:
        raise ConfirmatoryRerunError(
            "confirmation reveal resource history lacks a prior state"
        )
    authority_head = authority_records[-1]
    authority_prior = authority_records[-2]
    resource_parents = tuple(resource_record.parent_artifacts)
    if (
        authority_head.get("logical_type")
        != "resource_runtime_confirmatory_charge"
        or authority_head.get("state") != resource_payload
        or authority_head.get("state_sha256")
        != reveal_authority.resource_charge.artifact_sha256
        or resource_parents != (authority_prior.get("state_sha256"),)
    ):
        raise ConfirmatoryRerunError(
            "confirmation reveal resource authority binding is invalid"
        )

    if set(receipt_payload) != {
        "schema_version",
        "study_id",
        "study_version",
        "seal",
        "status",
        "journal_head_hash",
        "journal_identity_sha256",
    }:
        raise ConfirmatoryRerunError("confirmation reveal custody receipt is invalid")
    try:
        receipt_seal = HoldoutSeal(**dict(receipt_payload["seal"]))  # type: ignore[arg-type]
        status_value = dict(receipt_payload["status"])  # type: ignore[arg-type]
        if set(status_value) != {
            "custody_independence",
            "sealed",
            "revealed",
            "invalidated",
            "confirmatory_claims_valid",
            "authorized_access_count",
            "violation_reasons",
            "release_event",
            "durable_journal",
            "journal_head_hash",
        }:
            raise ValueError("custody status schema")
        status_value["custody_independence"] = CustodyIndependence(
            status_value["custody_independence"]
        )
        status_value["violation_reasons"] = tuple(status_value["violation_reasons"])
        receipt_status = CustodyStatus(**status_value)
    except Exception as exc:
        raise ConfirmatoryRerunError(
            "confirmation reveal custody receipt types are invalid"
        ) from exc
    receipt_head = receipt_payload.get("journal_head_hash")
    receipt_identity = receipt_payload.get("journal_identity_sha256")
    if (
        receipt_payload.get("schema_version") != "1.0"
        or receipt_payload.get("study_id") != study_id
        or receipt_payload.get("study_version") != study_version
        or not isinstance(receipt_head, str)
        or SHA256_PATTERN.fullmatch(receipt_head) is None
        or not isinstance(receipt_identity, str)
        or SHA256_PATTERN.fullmatch(receipt_identity) is None
        or receipt_seal.protocol_hash != protocol_hash
        or receipt_seal.code_hash != code_hash
        or receipt_seal.configuration_hash != configuration_hash
        or receipt_seal.split_manifest_hash != split_hash
        or receipt_seal.pre_unblinding_interpretation_hash
        != reveal_authority.blind_interpretation.artifact_sha256
        or receipt_status.custody_independence
        is not CustodyIndependence.NON_INDEPENDENT
        or receipt_status.sealed is not True
        or receipt_status.revealed is not False
        or receipt_status.invalidated is not False
        or receipt_status.confirmatory_claims_valid is not False
        or receipt_status.authorized_access_count != 0
        or receipt_status.violation_reasons != ()
        or receipt_status.release_event is not None
        or receipt_status.durable_journal is not True
        or receipt_status.journal_head_hash != receipt_head
    ):
        raise ConfirmatoryRerunError(
            "confirmation reveal custody is not exactly sealed and unrevealed"
        )

    # The immutable receipt is only an anchor.  Reopen the canonical current
    # journal under the simulated provider's namespace+journal locks so a
    # durable RELEASE cannot hide in the interval before custody_record is
    # materialized.  Future independent providers require their own exact
    # externally attested resolver; this local path never promotes them.
    def validate_live(live: object) -> None:
        if (
            not isinstance(live, CustodyAdmissionSnapshot)
            or live.seal != receipt_seal
            or live.status != receipt_status
            or live.journal_head_hash != receipt_head
            or live.journal_identity_sha256 != receipt_identity
            or live.sealed is not True
            or live.revealed is not False
            or live.invalidated is not False
            or live.authorized_access_count != 0
        ):
            raise ConfirmatoryRerunError(
                "confirmation reveal live custody is no longer pre-reveal"
            )

    journal_relative = (
        Path(".scientist-one-build/custody") / f"{expected_run_id}.jsonl"
    )
    try:
        live_provider = SimulatedHoldoutCustody(
            (Role.EXPERIMENT_RUNNER.value,),
            journal_root=registry.policy.root,
            journal_path=journal_relative,
            require_existing_journal=True,
        )
        with live_provider.admission_guard(
            expected_journal_head_hash=receipt_head,
            expected_journal_identity_sha256=receipt_identity,
        ) as live:
            validate_live(live)
    except ConfirmatoryRerunError:
        raise
    except Exception as exc:
        raise ConfirmatoryRerunError(
            "confirmation reveal live custody journal is absent, stale, or released"
        ) from exc

    validation = ledger.validate()
    if not validation.valid or not validation.events:
        raise ConfirmatoryRerunError("confirmation reveal ledger is invalid")
    events = tuple(event.to_dict() for event in validation.events)
    if any(event.get("run_id") != expected_run_id for event in events):
        raise ConfirmatoryRerunError("confirmation reveal ledger run is mismatched")
    started_matches = [
        (index, event)
        for index, event in enumerate(events)
        if event.get("event_id") == started_event_id
    ]
    if len(started_matches) != 1:
        raise ConfirmatoryRerunError("confirmation STARTED selector is not unique")
    started_index, started = started_matches[0]
    if started_index != len(events) - 1:
        raise ConfirmatoryRerunError(
            "confirmation reveal is no longer at the pre-reveal ledger boundary"
        )
    if sum(event.get("event_type") == "CONFIRMATORY_STARTED" for event in events) != 1:
        raise ConfirmatoryRerunError("confirmation STARTED publication is ambiguous")
    expected_selectors = (
        ("frozen_protocol", reveal_authority.protocol),
        ("frozen_source_inventory", reveal_authority.source_inventory),
        (
            "frozen_configuration_inventory",
            reveal_authority.configuration_inventory,
        ),
        ("frozen_confirmatory_split", reveal_authority.split_manifest),
        ("blind_interpretation", reveal_authority.blind_interpretation),
        ("midrun_review", reveal_authority.midrun_review),
        ("resource_runtime_confirmatory_charge", reveal_authority.resource_charge),
        ("fresh_custody_receipt", receipt_selector),
    )
    expected_binding = (
        tuple(selector.artifact_sha256 for _, selector in expected_selectors),
        tuple(name for name, _ in expected_selectors),
        tuple(selector.artifact_record_hash for _, selector in expected_selectors),
    )
    fresh_binding = {
        "artifact_sha256": fresh_custody_evidence.receipt_artifact_sha256,
        "artifact_record_hash": fresh_custody_evidence.artifact_record_hash,
        "journal_head_hash": receipt_head,
        "journal_identity_sha256": receipt_identity,
        "protocol_hash": protocol_hash,
        "seal_hash": receipt_seal.seal_hash,
        "study_version": study_version,
    }
    started_metadata = started.get("metadata")
    if (
        started.get("event_type") != "CONFIRMATORY_STARTED"
        or started.get("actor_role") != Role.ORCHESTRATOR.value
        or not _confirmatory_start_preserves_head(
            started,
            ledger_head_state=(
                events[started_index - 1].get("requested_state_after")
                if started_index > 0
                else None
            ),
            scientific=True,
        )
        or started.get("code_version") != code_hash
        or started.get("configuration_hash") != configuration_hash
        or manager._event_artifact_binding(started) != expected_binding
        or not isinstance(started_metadata, Mapping)
        or started_metadata.get("fresh_custody") != fresh_binding
        or started_metadata.get("evidence_class") != "SCIENTIFIC_EVIDENCE"
        or started_metadata.get("execution_kind")
        != "SCIENTIFIC_CONFIRMATION_STARTED"
        or started_metadata.get("resource_authority_checkpoint")
        != authority_descriptors[-1]
    ):
        raise ConfirmatoryRerunError(
            "confirmation STARTED does not bind the frozen reveal design"
        )
    started_hash = started.get("event_hash")
    if (
        not isinstance(started_hash, str)
        or SHA256_PATTERN.fullmatch(started_hash) is None
        or (
            expected_started_event_hash is not None
            and started_hash != expected_started_event_hash
        )
    ):
        raise ConfirmatoryRerunError("confirmation STARTED hash is invalid")

    receipt_events = [
        (index, event)
        for index, event in enumerate(events)
        if event.get("event_id") == fresh_custody_evidence.ledger_event_id
    ]
    charge_events = [
        (index, event)
        for index, event in enumerate(events)
        if event.get("event_id")
        == reveal_authority.resource_charge_ledger_event_id
    ]
    if len(receipt_events) != 1 or len(charge_events) != 1:
        raise ConfirmatoryRerunError(
            "confirmation reveal receipt/charge publication is ambiguous"
        )
    receipt_index, receipt_event = receipt_events[0]
    charge_index, charge_event = charge_events[0]
    if not (receipt_index < charge_index and charge_index + 1 == started_index):
        raise ConfirmatoryRerunError(
            "confirmation reveal publication order is invalid"
        )
    if (
        receipt_event.get("event_type") != "CHECKPOINT"
        or receipt_event.get("actor_role") != Role.HOLDOUT_CUSTODIAN.value
        or receipt_event.get("code_version") != code_hash
        or receipt_event.get("configuration_hash") != configuration_hash
        or manager._event_artifact_binding(receipt_event)
        != (
            (fresh_custody_evidence.receipt_artifact_sha256,),
            ("fresh_custody_receipt",),
            (fresh_custody_evidence.artifact_record_hash,),
        )
        or not isinstance(receipt_event.get("metadata"), Mapping)
        or receipt_event["metadata"].get("fresh_custody") != fresh_binding  # type: ignore[union-attr]
    ):
        raise ConfirmatoryRerunError(
            "confirmation reveal custodian publication is invalid"
        )
    if (
        charge_event.get("event_type") != "CHECKPOINT"
        or charge_event.get("actor_role") != Role.ORCHESTRATOR.value
        or charge_event.get("code_version") != code_hash
        or charge_event.get("configuration_hash") != configuration_hash
        or manager._event_artifact_binding(charge_event)
        != (
            (reveal_authority.resource_charge.artifact_sha256,),
            ("resource_runtime_confirmatory_charge",),
            (reveal_authority.resource_charge.artifact_record_hash,),
        )
        or not isinstance(charge_event.get("metadata"), Mapping)
        or charge_event["metadata"].get("resource_authority_checkpoint")  # type: ignore[union-attr]
        != authority_descriptors[-1]
    ):
        raise ConfirmatoryRerunError(
            "confirmation reveal coordinator charge publication is invalid"
        )
    observed_authority = []
    for event in events[:started_index]:
        metadata = event.get("metadata")
        checkpoint = (
            metadata.get("resource_authority_checkpoint")
            if isinstance(metadata, Mapping)
            else None
        )
        if checkpoint is not None:
            observed_authority.append(dict(checkpoint))
    if tuple(observed_authority) != authority_descriptors:
        raise ConfirmatoryRerunError(
            "confirmation reveal resource history is not exactly published"
        )

    for record in registry.list_records():
        if (
            isinstance(record, ArtifactRecord)
            and record.logical_type == "custody_record"
            and fresh_custody_evidence.receipt_artifact_sha256
            in record.parent_artifacts
        ):
            raise ConfirmatoryRerunError(
                "confirmation reveal custody has already been released"
            )

    object_id = confirmation_reveal_gate_object_id(
        expected_run_id,
        study_id,
        study_version,
    )
    if expected_object_id is not None and object_id != expected_object_id:
        raise ConfirmatoryRerunError(
            "confirmation reveal receipt names another gate object"
        )
    if receipt_id is None:
        receipt_id = "confirmation-reveal-receipt-" + hashlib.sha256(
            canonical_json_bytes(
                {
                    "run_id": expected_run_id,
                    "started_event_hash": started_hash,
                    "object_id": object_id,
                }
            )
        ).hexdigest()
    receipt_id = _identifier(receipt_id, "confirmation reveal receipt ID")
    return (
        ConfirmationRevealGateReceipt(
            receipt_id=receipt_id,
            run_id=expected_run_id,
            ledger_path=ledger.relative_path.as_posix(),
            object_id=object_id,
            study_id=study_id,
            study_version=study_version,
            started_event_id=started_event_id,
            started_event_hash=started_hash,
            started_event_index=started_index,
            custody_independence="NON_INDEPENDENT",
            custody_journal_head_hash=receipt_head,
            custody_journal_identity_sha256=receipt_identity,
            evidence_class=(
                CONFIRMATION_REVEAL_EVIDENCE_ARCHITECTURE_CONTROL
            ),
            verification_status=(
                CONFIRMATION_REVEAL_STATUS_BLOCKED_NON_INDEPENDENT
            ),
            external_custody_attestation_sha256=None,
            fresh_custody_evidence=fresh_custody_evidence,
            reveal_authority=reveal_authority,
        ),
        parents,
    )


def register_confirmation_reveal_gate_receipt(
    registry: object,
    ledger: EventLedger,
    *,
    expected_run_id: str,
    fresh_custody_evidence: FreshCustodyEvidence,
    reveal_authority: ConfirmatoryRevealAuthority,
    started_event_id: str,
) -> ArtifactRecord:
    """Register an exact blocked pre-reveal replay receipt.

    The STARTED event must already be the live ledger tail and custody must
    still be represented by its sealed/unrevealed fresh receipt.  No caller
    boolean or custody-independence label can make the v1 receipt pass.
    """

    from .artifacts import ArtifactRegistry
    from .roles import Role

    if not isinstance(registry, ArtifactRegistry):
        raise ConfirmatoryRerunError(
            "confirmation reveal receipt requires an ArtifactRegistry"
        )
    receipt, parents = _derive_confirmation_reveal_gate_receipt(
        registry,
        ledger,
        expected_run_id=expected_run_id,
        fresh_custody_evidence=fresh_custody_evidence,
        reveal_authority=reveal_authority,
        started_event_id=started_event_id,
    )
    record = registry.put_json(
        receipt.to_dict(),
        logical_type=CONFIRMATION_REVEAL_GATE_RECEIPT_LOGICAL_TYPE,
        origin="deterministic blocked pre-reveal custody-and-ledger replay",
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=("scientist-one", "verify-confirmation-reveal-gate"),
        parent_artifacts=tuple(item.sha256 for item in parents),
        schema_version=CONFIRMATION_REVEAL_GATE_RECEIPT_SCHEMA_VERSION,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )
    require_confirmation_reveal_gate_receipt(
        registry,
        ledger,
        receipt_artifact_sha256=record.sha256,
        expected_run_id=expected_run_id,
        expected_object_id=receipt.object_id,
    )
    return record


def require_confirmation_reveal_gate_receipt(
    registry: object,
    ledger: EventLedger,
    *,
    receipt_artifact_sha256: str,
    expected_run_id: str,
    expected_object_id: str,
) -> ConfirmationRevealGateReceipt:
    """Rehydrate and replay an exact confirmation-reveal gate receipt."""

    from .artifacts import ArtifactRecord, ArtifactRegistry
    from .roles import Role

    if not isinstance(registry, ArtifactRegistry):
        raise ConfirmatoryRerunError(
            "confirmation reveal receipt requires an ArtifactRegistry"
        )
    if (
        not isinstance(receipt_artifact_sha256, str)
        or SHA256_PATTERN.fullmatch(receipt_artifact_sha256) is None
    ):
        raise ConfirmatoryRerunError("confirmation reveal receipt hash is invalid")
    expected_run_id = _identifier(expected_run_id, "confirmation reveal run ID")
    expected_object_id = _identifier(
        expected_object_id,
        "confirmation reveal object ID",
    )
    try:
        record = registry.get_metadata(receipt_artifact_sha256)
        encoded = registry.get_bytes(receipt_artifact_sha256)
        value = safe_json_loads(encoded, max_bytes=MAX_ARTIFACT_OBJECT_BYTES)
    except Exception as exc:
        raise ConfirmatoryRerunError(
            "confirmation reveal receipt artifact is unavailable"
        ) from exc
    if (
        not isinstance(record, ArtifactRecord)
        or record.sha256 != receipt_artifact_sha256
        or record.logical_type != CONFIRMATION_REVEAL_GATE_RECEIPT_LOGICAL_TYPE
        or record.schema_version != CONFIRMATION_REVEAL_GATE_RECEIPT_SCHEMA_VERSION
        or record.mime_type != "application/json"
        or record.creator_role is not Role.CLAIM_VERIFIER
        or record.validation_result != "PASS"
        or record.frozen is not True
        or registry.verify(receipt_artifact_sha256) is not True
        or not isinstance(value, Mapping)
    ):
        raise ConfirmatoryRerunError(
            "confirmation reveal receipt artifact binding is invalid"
        )
    receipt = ConfirmationRevealGateReceipt.from_dict(value)
    if receipt.run_id != expected_run_id or receipt.object_id != expected_object_id:
        raise ConfirmatoryRerunError(
            "confirmation reveal receipt names another run or gate object"
        )
    expected, parents = _derive_confirmation_reveal_gate_receipt(
        registry,
        ledger,
        expected_run_id=receipt.run_id,
        fresh_custody_evidence=receipt.fresh_custody_evidence,
        reveal_authority=receipt.reveal_authority,
        started_event_id=receipt.started_event_id,
        receipt_id=receipt.receipt_id,
        expected_started_event_hash=receipt.started_event_hash,
        expected_object_id=receipt.object_id,
    )
    if receipt != expected:
        raise ConfirmatoryRerunError(
            "confirmation reveal receipt differs from live artifact replay"
        )
    if record.parent_artifacts != tuple(item.sha256 for item in parents):
        raise ConfirmatoryRerunError(
            "confirmation reveal receipt has substituted or reordered parents"
        )
    return receipt

__all__ = [
    "ArtifactIssue",
    "ArtifactValidationError",
    "ArtifactValidationResult",
    "CheckpointSelection",
    "ConfirmatoryRevealAuthority",
    "ConfirmatoryEvaluatorSpec",
    "ConfirmationRevealGateReceipt",
    "CONFIRMATION_REVEAL_GATE_RECEIPT_LOGICAL_TYPE",
    "CONFIRMATION_REVEAL_EVIDENCE_ARCHITECTURE_CONTROL",
    "CONFIRMATION_REVEAL_EVIDENCE_SCIENTIFIC",
    "CONFIRMATION_REVEAL_STATUS_BLOCKED_NON_INDEPENDENT",
    "CONFIRMATION_REVEAL_STATUS_VERIFIED_INDEPENDENT",
    "ConfirmatoryRerunError",
    "CustodyAdmissionSnapshot",
    "FreshCustodyEvidence",
    "RegisteredArtifactSelector",
    "LedgerValidationError",
    "LedgerValidationResult",
    "QuarantineRecord",
    "RecoveryError",
    "RecoveryManager",
    "RecoveryReport",
    "ResumeAction",
    "canonical_json_bytes",
    "checkpoint_digest",
    "event_digest",
    "confirmation_reveal_gate_object_id",
    "register_confirmation_reveal_gate_receipt",
    "require_confirmation_reveal_gate_receipt",
]
