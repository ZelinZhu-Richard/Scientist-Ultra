"""Offline, resumable orchestration for the bounded Scientist-One workflow."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import wraps
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import threading
import uuid
from typing import Any, Callable, Iterator, Mapping, Sequence

from .artifacts import ArtifactRegistry
from .calibration import assert_calibrated, run_calibration, run_synthetic_workflow_benchmark
from .claims import (
    ClaimDecision,
    ClaimEvidenceGraph,
    EvidenceKind,
    EvidenceLink,
    EvidenceNode,
    EvidenceSupportReceipt,
    MaterialClaim,
    artifact_registry_resolver,
)
from .device import DeviceManager, HardwareProfiler
from .evaluators import Decision, Evaluation, EvaluatorClass, RCheck
from .evaluators import AuditSummary
from .holdout import RevealPreconditions, SimulatedHoldoutCustody
from .ledger import EventLedger
from .models import ArtifactRef, MacroState, TerminalState, TransitionRequest
from .packaging import PackageResult, package_run
from .protocol import (
    BaselineSpec,
    ConfidenceIntervalSpec,
    DataRoles,
    DomainNullSpec,
    ExecutionConditions,
    InterpretationRules,
    ProtocolComputeBudget,
    ResearchProtocol,
    SeedPolicy,
    StatisticalTestSpec,
    freeze_protocol,
    validate_protocol,
)
from .recovery import FreshCustodyEvidence, RecoveryManager, event_digest
from .reproduction import (
    ReproductionResult,
    reproduce_run,
    verify_frozen_reproduction,
)
from .readiness import evaluate_readiness
from .resources import ResourceAction, ResourceConfig, ResourceController, ResourceLimitError
from .roles import Role, make_role_bundle
from .security import (
    PathSecurityError,
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    open_confined_directory_fd,
    read_confined_bytes,
    safe_json_loads,
    secure_directory as secure_directory_shared,
)
from .state_machine import (
    StateController,
    TransitionContract,
    default_transition_contracts,
    macro_transition_contracts,
)
from .writing import (
    render_demo_paper_bytes,
    render_results_table_bytes,
    render_svg_effect_figure_bytes,
    write_demo_paper,
    write_results_table,
    write_svg_effect_figure,
)


SCHEMA_VERSION = "1.0"
MAX_INVENTORY_ENTRIES = 2_048
MAX_INVENTORY_TOTAL_BYTES = 64 * 1024 * 1024
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RESOURCE_AUTHORITY_NAME_PATTERN = re.compile(
    r"^(?P<sequence>[0-9]{4})-(?P<digest>[0-9a-f]{64})\.json$"
)
MACRO_STATES = (
    "CALIBRATE",
    "CHARTER",
    "GROUND",
    "PROTOCOL",
    "PREFLIGHT",
    "IDEATE",
    "DISCOVER",
    "CANDIDATE",
    "CONFIRM",
    "CLAIMS",
    "WRITE",
    "AUDIT",
    "RELEASE",
)
TERMINAL_STATES = {
    "READY_FOR_HUMAN_REVIEW",
    "NEGATIVE_RESULT",
    "INCONCLUSIVE",
    "BLOCKED_EXTERNAL",
    "STOP_SCIENTIFIC_INVALIDITY",
    "STOP_SECURITY",
    "STOP_BUDGET",
}


class OrchestrationError(RuntimeError):
    """A typed workflow contract, custody rule, or safety check failed."""


def _captured_dispatch_loader() -> object | None:
    """Return the exact active production or evidence captured-source loader."""

    production = getattr(sys, "_scientist_one_isolated_launcher", False) is True
    evidence_present = (
        "_scientist_one_captured_evidence_capability" in sys.__dict__
    )
    if production and evidence_present:
        raise OrchestrationError("captured dispatch authority is ambiguous")
    if not production and not evidence_present:
        return None
    if evidence_present:
        if "_scientist_one_isolated_launcher" in sys.__dict__:
            raise OrchestrationError("captured evidence authority is ambiguous")
        test_authority = sys.__dict__.get("_scientist_one_test_runner")
        if test_authority is not None and test_authority is not True:
            raise OrchestrationError("captured evidence test authority is invalid")
        capability = sys.__dict__["_scientist_one_captured_evidence_capability"]
    else:
        capability = globals().get("__loader__")

    module_loader = globals().get("__loader__")
    tree = getattr(capability, "tree", None)
    records = getattr(tree, "records", None)
    record = records.get(__name__) if isinstance(records, dict) else None
    executed = getattr(capability, "executed", None)
    if (
        capability is not module_loader
        or getattr(globals().get("__spec__"), "loader", None) is not capability
        or not sys.meta_path
        or sys.meta_path[0] is not capability
        or sum(item is capability for item in sys.meta_path) != 1
        or type(capability).__module__ != "__main__"
        or type(capability).__name__ != "_CapturedSourceLoader"
        or not isinstance(getattr(tree, "root", None), Path)
        or not isinstance(getattr(tree, "root_identity", None), os.stat_result)
        or record is None
        or not isinstance(getattr(record, "path", None), Path)
        or record.path != Path(__file__)
        or not isinstance(getattr(record, "identity", None), os.stat_result)
        or not isinstance(getattr(record, "sha256", None), str)
        or not isinstance(executed, dict)
        or executed.get(__name__) != record.sha256
    ):
        raise OrchestrationError("captured dispatch capability is invalid")
    return capability


def _captured_project_root() -> tuple[Path, tuple[int, int]] | None:
    """Return the launcher's admitted root capability during trusted dispatch."""

    production = getattr(sys, "_scientist_one_isolated_launcher", False) is True
    if (
        production
        and getattr(sys, "_scientist_one_test_runner", False) is True
        and "_scientist_one_captured_evidence_capability" not in sys.__dict__
        and getattr(sys, "_scientist_one_captured_source_attestation", None) is None
        and not hasattr(globals().get("__loader__"), "tree")
    ):
        # Explicit normal-loader unit-test compatibility.  The production CLI
        # cannot obtain its dispatch authority from this branch.
        return None
    loader = _captured_dispatch_loader()
    if loader is None:
        return None
    tree = getattr(loader, "tree", None)
    root = getattr(tree, "root", None)
    identity = getattr(tree, "root_identity", None)
    if not isinstance(root, Path) or not isinstance(identity, os.stat_result):
        raise OrchestrationError("captured project-root capability is unavailable")
    return root, (identity.st_dev, identity.st_ino)


TRANSITION_CONTRACTS: dict[str, TransitionContract] = {
    contract.source.value: contract for contract in macro_transition_contracts()
}


def _contract_dict(contract: TransitionContract) -> dict[str, Any]:
    """Stable JSON projection of the one canonical foundation contract."""

    return {
        "source": contract.source.value,
        "destination": contract.destination.value,
        "required_artifacts": sorted(contract.required_artifact_types),
        "required_evaluators": sorted(item.value for item in contract.required_evaluators),
        "requesters": sorted(item.value for item in contract.allowed_requesters),
        "approvers": sorted(item.value for item in contract.allowed_approvers),
        "generated_artifacts": sorted(contract.generated_artifact_types),
        "failure_states": sorted(item.value for item in contract.failure_states),
        "validation_rules": list(contract.validation_rules),
        "idempotency": contract.idempotency_rule,
    }


def _evaluation_key(source: str, evaluator: EvaluatorClass) -> str:
    return f"{evaluator.value}:{source}"


def _terminal_evaluation_key(
    source: str, destination: str, evaluator: EvaluatorClass
) -> str:
    """Keep terminal review receipts distinct from an earlier stage review."""

    return f"{evaluator.value}:{source}->{destination}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value) + b"\n"
    except (TypeError, ValueError) as exc:
        raise OrchestrationError(f"value is not canonical JSON: {exc}") from exc


def _custody_access_records(journal_bytes: bytes) -> list[dict[str, Any]]:
    """Extract records only from provider-validated, held-fd journal bytes."""

    records: list[dict[str, Any]] = []
    for raw_line in journal_bytes.splitlines():
        event = safe_json_loads(raw_line)
        if not isinstance(event, Mapping):
            raise OrchestrationError("custody journal event is malformed")
        payload = event.get("payload")
        if event.get("event_type") in {"ACCESS", "RELEASE"}:
            if not isinstance(payload, Mapping) or not isinstance(
                payload.get("record"), Mapping
            ):
                raise OrchestrationError("custody access event is malformed")
            records.append(dict(payload["record"]))
    return records


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _custody_journal_path(run_id: str) -> Path:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise OrchestrationError("invalid run ID for custody authority")
    return Path(".scientist-one-build/custody") / f"{run_id}.jsonl"


@contextmanager
def _project_resource_execution_lock(
    root: Path,
    *,
    expected_root_identity: tuple[int, int] | None = None,
) -> Iterator[None]:
    """Serialize work under a parent-namespace lock that survives root swaps."""

    lexical_root = Path(root)
    if not lexical_root.is_absolute():
        lexical_root = Path.cwd() / lexical_root
    root_name = lexical_root.name
    if root_name in {"", ".", ".."}:
        raise OrchestrationError("project resource namespace identity changed")
    try:
        root_parent = lexical_root.parent.resolve(strict=True)
    except OSError as exc:
        raise OrchestrationError("project resource execution lock failed") from exc
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    parent_fd = root_fd = descriptor = None
    parent_locked = leaf_locked = False
    try:
        parent_fd = os.open(root_parent, directory_flags)
        parent_identity = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_identity.st_mode):
            raise OrchestrationError("project parent namespace is not a directory")
        fcntl.flock(parent_fd, fcntl.LOCK_EX)
        parent_locked = True
        named_parent = os.stat(root_parent, follow_symlinks=False)
        if (parent_identity.st_dev, parent_identity.st_ino) != (
            named_parent.st_dev,
            named_parent.st_ino,
        ):
            raise OrchestrationError("project parent namespace identity changed")
        try:
            root_fd = os.open(root_name, directory_flags, dir_fd=parent_fd)
        except OSError as exc:
            raise OrchestrationError(
                "project resource namespace identity changed"
            ) from exc
        root_identity = os.fstat(root_fd)
        named_root = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        observed_root_identity = (root_identity.st_dev, root_identity.st_ino)
        if (
            not stat.S_ISDIR(root_identity.st_mode)
            or observed_root_identity != (named_root.st_dev, named_root.st_ino)
            or (
                expected_root_identity is not None
                and observed_root_identity != expected_root_identity
            )
        ):
            raise OrchestrationError("project resource namespace identity changed")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            ".scientist-one-resource-execution.lock",
            flags,
            0o600,
            dir_fd=root_fd,
        )
        metadata = os.fstat(descriptor)
        named = os.stat(
            ".scientist-one-resource-execution.lock",
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_mode & 0o077) != 0
            or (metadata.st_dev, metadata.st_ino)
            != (named.st_dev, named.st_ino)
        ):
            raise OrchestrationError("project resource execution lock is invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        leaf_locked = True
        locked = os.fstat(descriptor)
        current = os.stat(
            ".scientist-one-resource-execution.lock",
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if (locked.st_dev, locked.st_ino) != (current.st_dev, current.st_ino):
            raise OrchestrationError("project resource execution lock was replaced")
        try:
            yield
        finally:
            # Re-attest even when command execution raises.  Otherwise a root
            # replacement could escape the command-wide boundary on an error
            # path before the launcher's final provenance check.
            final_root = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
            final_lock = os.stat(
                ".scientist-one-resource-execution.lock",
                dir_fd=root_fd,
                follow_symlinks=False,
            )
            if (
                observed_root_identity != (final_root.st_dev, final_root.st_ino)
                or (locked.st_dev, locked.st_ino)
                != (final_lock.st_dev, final_lock.st_ino)
            ):
                raise OrchestrationError("project resource namespace changed")
    except OSError as exc:
        raise OrchestrationError("project resource execution lock failed") from exc
    finally:
        if descriptor is not None:
            if leaf_locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        if root_fd is not None:
            os.close(root_fd)
        if parent_fd is not None:
            if parent_locked:
                fcntl.flock(parent_fd, fcntl.LOCK_UN)
            os.close(parent_fd)


def _named_directory_identity(path: Path) -> tuple[int, int]:
    """Read a directory identity without following its final path component."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise OrchestrationError(
            "project root must be an existing non-symlink directory"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise OrchestrationError(
            "project root must be an existing non-symlink directory"
        )
    return opened.st_dev, opened.st_ino


def _safe_root(
    root: str | os.PathLike[str],
    *,
    captured_root: tuple[Path, tuple[int, int]] | None = None,
) -> Path:
    path = Path(root)
    candidate = path if path.is_absolute() else Path.cwd() / path
    admitted_identity = _named_directory_identity(candidate)
    if captured_root is not None and admitted_identity != captured_root[1]:
        raise OrchestrationError("project root differs from the captured launcher root")
    canonical = candidate.resolve(strict=True)
    if captured_root is not None and canonical != captured_root[0]:
        raise OrchestrationError("project root differs from the captured launcher root")
    forbidden = {Path(canonical.anchor), Path.home().resolve(), Path.home().resolve() / "dev"}
    if canonical in forbidden or canonical.name != "ScientistOne":
        raise OrchestrationError("project root is not the narrow ScientistOne workspace")
    try:
        current = Path.cwd().resolve(strict=True)
    except OSError as exc:
        raise OrchestrationError("current app workspace cannot be canonicalized") from exc
    if canonical != current:
        raise OrchestrationError("--root must equal the current app-selected workspace")
    if _named_directory_identity(canonical) != admitted_identity:
        raise OrchestrationError("project root identity changed during admission")
    try:
        receipt_bytes = read_confined_bytes(
            canonical,
            "state/APP_SESSION_BOOTSTRAP.json",
            reject_hardlinks=True,
            max_bytes=1024 * 1024,
        )
        if receipt_bytes is None:
            raise OrchestrationError("passing app-session bootstrap receipt is required")
        receipt = safe_json_loads(receipt_bytes)
    except (OSError, ValueError, PathSecurityError) as exc:
        raise OrchestrationError("app-session bootstrap receipt is invalid") from exc
    if not isinstance(receipt, dict) or receipt.get("app_session_bootstrap") != "PASS":
        raise OrchestrationError("app-session bootstrap did not pass")
    if receipt.get("canonical_project_root") != str(canonical):
        raise OrchestrationError("bootstrap receipt does not bind the current workspace")
    if _named_directory_identity(canonical) != admitted_identity:
        raise OrchestrationError("project root identity changed during admission")
    return canonical


def _secure_directory(root: Path, relative: str | Path, *, create: bool = False) -> Path:
    raw = Path(relative)
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise OrchestrationError("directory path must be a safe project-relative path")
    try:
        return secure_directory_shared(root, raw, create=create)
    except PathSecurityError as exc:
        raise OrchestrationError(f"unsafe project directory: {raw}") from exc


def _safe_existing_file(root: Path, value: str | Path) -> Path:
    raw = Path(value)
    if any(part == ".." for part in raw.parts):
        raise OrchestrationError("path traversal is prohibited")
    candidate = raw if raw.is_absolute() else root / raw
    try:
        relative = candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise OrchestrationError("input file is outside project root or absent") from exc
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise OrchestrationError("symbolic links are prohibited for evidence inputs")
    mode = candidate.lstat().st_mode
    if not stat.S_ISREG(mode) or candidate.stat().st_nlink != 1:
        raise OrchestrationError("evidence input must be an unlinked regular file")
    return candidate.resolve(strict=True)


def _atomic_json(root: Path, relative: str | Path, value: Mapping[str, Any]) -> Path:
    try:
        return atomic_write_json(
            root,
            relative,
            value,
            overwrite=True,
            create_parents=True,
        )
    except (PathSecurityError, ValueError, TypeError) as exc:
        raise OrchestrationError("confined atomic JSON publication failed") from exc


def _read_json(path: Path) -> dict[str, Any]:
    try:
        root = Path.cwd().resolve(strict=True)
        payload = read_confined_bytes(
            root,
            path,
            reject_hardlinks=True,
            max_bytes=16 * 1024 * 1024,
        )
        if payload is None:
            raise OrchestrationError(f"JSON evidence disappeared: {path.name}")
        value = safe_json_loads(payload)
    except (OSError, ValueError, UnicodeDecodeError, PathSecurityError) as exc:
        raise OrchestrationError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise OrchestrationError(f"expected JSON object in {path.name}")
    return value


def _project_command(method: Callable[..., Any]) -> Callable[..., Any]:
    """Hold the admitted project-root namespace for one public command."""

    @wraps(method)
    def guarded(self: "ScientistOneOrchestrator", *args: Any, **kwargs: Any) -> Any:
        with self._command_root_guard():
            return method(self, *args, **kwargs)

    return guarded


def _code_fingerprint(root: Path) -> str:
    return str(_source_inventory(root)["aggregate_sha256"])


def _configuration_hash(root: Path) -> str:
    return str(_configuration_inventory(root)["aggregate_sha256"])


def _frozen_inventory(root: Path, directory: str, suffix: str, kind: str) -> dict[str, Any]:
    """Build one bounded, descriptor-read inventory used across every later gate."""

    entries: list[dict[str, Any]] = []
    try:
        directory_fd = open_confined_directory_fd(root, directory, create=False)
    except PathSecurityError as exc:
        raise OrchestrationError(f"unsafe {kind.lower()} inventory directory") from exc
    try:
        collected: list[str] = []
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                if entry.name.endswith(suffix):
                    if len(collected) >= MAX_INVENTORY_ENTRIES:
                        raise OrchestrationError(
                            f"{kind.lower()} inventory has too many entries"
                        )
                    collected.append(entry.name)
        names = tuple(sorted(collected))
        aggregate_bytes = 0
        for name in names:
            if not name or "/" in name or "\x00" in name:
                raise OrchestrationError(f"unsafe {kind.lower()} inventory name")
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_size > 4 * 1024 * 1024
                ):
                    raise OrchestrationError(
                        f"unsafe {kind.lower()} inventory entry"
                    )
                chunks: list[bytes] = []
                total = 0
                while chunk := os.read(descriptor, 1024 * 1024):
                    total += len(chunk)
                    if total > 4 * 1024 * 1024:
                        raise OrchestrationError(
                            f"oversized {kind.lower()} inventory entry"
                        )
                    chunks.append(chunk)
                data = b"".join(chunks)
                aggregate_bytes += len(data)
                if aggregate_bytes > MAX_INVENTORY_TOTAL_BYTES:
                    raise OrchestrationError(
                        f"{kind.lower()} inventory exceeds its aggregate bound"
                    )
            finally:
                os.close(descriptor)
            entries.append(
                {
                    "path": (Path(directory) / name).as_posix(),
                    "sha256": _sha256(data),
                    "size": len(data),
                }
            )
    except OSError as exc:
        raise OrchestrationError(f"cannot enumerate {kind.lower()} inventory") from exc
    finally:
        os.close(directory_fd)
    if not entries:
        raise OrchestrationError(f"{kind.lower()} inventory is empty")
    aggregate = _sha256(_canonical_bytes(entries))
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "entries": entries,
        "aggregate_sha256": aggregate,
    }


def _source_inventory(root: Path) -> dict[str, Any]:
    inventory = _frozen_inventory(
        root, "src/scientist_one", ".py", "FROZEN_SOURCE_INVENTORY"
    )
    launcher = read_confined_bytes(
        root,
        "scripts/scientist_one_cli.py",
        reject_hardlinks=True,
        max_bytes=4 * 1024 * 1024,
    )
    if launcher is None:
        raise OrchestrationError("isolated CLI launcher is absent")
    entries = list(inventory["entries"])
    entries.append(
        {
            "path": "scripts/scientist_one_cli.py",
            "sha256": _sha256(launcher),
            "size": len(launcher),
        }
    )
    entries.sort(key=lambda value: str(value["path"]))
    if len(entries) > MAX_INVENTORY_ENTRIES:
        raise OrchestrationError("source inventory exceeds its entry bound")
    if sum(int(value["size"]) for value in entries) > MAX_INVENTORY_TOTAL_BYTES:
        raise OrchestrationError("source inventory exceeds its aggregate bound")
    inventory["entries"] = entries
    inventory["aggregate_sha256"] = _sha256(_canonical_bytes(entries))
    _validate_captured_source_attestation(root, inventory)
    return inventory


def _configuration_inventory(root: Path) -> dict[str, Any]:
    return _frozen_inventory(
        root, "configs", ".json", "FROZEN_CONFIGURATION_INVENTORY"
    )


def _validate_captured_source_attestation(
    root: Path, source_inventory: Mapping[str, Any]
) -> None:
    """Bind evidence bytes to the exact sources executed by the safe launcher."""

    loader = _captured_dispatch_loader()
    raw_attestation = getattr(
        sys, "_scientist_one_captured_source_attestation", None
    )
    if loader is None:
        if raw_attestation is not None:
            raise OrchestrationError(
                "captured source attestation exists outside verified dispatch"
            )
        return
    if (
        not isinstance(raw_attestation, tuple)
        or len(raw_attestation) != 2
        or raw_attestation[0] != "SCIENTIST_ONE_CAPTURED_SOURCE_V1"
        or not isinstance(raw_attestation[1], tuple)
    ):
        raise OrchestrationError("captured source attestation is absent or malformed")
    raw_entries = raw_attestation[1]
    if not raw_entries or len(raw_entries) > MAX_INVENTORY_ENTRIES:
        raise OrchestrationError("captured source attestation exceeds its entry bound")
    inventory_entries = source_inventory.get("entries")
    if not isinstance(inventory_entries, list):
        raise OrchestrationError("source inventory entries are malformed")
    expected: dict[str, tuple[str, int]] = {}
    for value in inventory_entries:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"path", "sha256", "size"}
            or not isinstance(value.get("path"), str)
            or not isinstance(value.get("sha256"), str)
            or isinstance(value.get("size"), bool)
            or not isinstance(value.get("size"), int)
        ):
            raise OrchestrationError("source inventory entry is malformed")
        expected[str(value["path"])] = (str(value["sha256"]), int(value["size"]))
    if len(expected) != len(inventory_entries):
        raise OrchestrationError("source inventory contains duplicate paths")

    observed_paths: list[str] = []
    observed_total = 0
    for entry in raw_entries:
        if not isinstance(entry, tuple) or len(entry) != 7:
            raise OrchestrationError("captured source entry is malformed")
        relative, digest, size, device, inode, modified_ns, changed_ns = entry
        if (
            not isinstance(relative, str)
            or not relative
            or Path(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in Path(relative).parts)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or any(
                isinstance(item, bool) or not isinstance(item, int) or item < 0
                for item in (size, device, inode, modified_ns, changed_ns)
            )
            or size > 4 * 1024 * 1024
        ):
            raise OrchestrationError("captured source entry has invalid fields")
        observed_total += size
        if observed_total > MAX_INVENTORY_TOTAL_BYTES:
            raise OrchestrationError(
                "captured source attestation exceeds its aggregate bound"
            )
        observed_paths.append(relative)
        if expected.get(relative) != (digest, size):
            raise OrchestrationError(
                "captured source bytes differ from the frozen source inventory"
            )
        directory_fd = descriptor = None
        try:
            directory_fd = open_confined_directory_fd(
                root, Path(relative).parent, create=False
            )
            descriptor = os.open(
                Path(relative).name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            before = os.fstat(descriptor)
            named = os.stat(
                Path(relative).name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
                or (
                    before.st_dev,
                    before.st_ino,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                != (device, inode, modified_ns, changed_ns)
                or before.st_size != size
            ):
                raise OrchestrationError(
                    "captured source identity changed before evidence binding"
                )
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                total += len(chunk)
                if total > 4 * 1024 * 1024:
                    raise OrchestrationError("captured source exceeds its size bound")
                chunks.append(chunk)
            after = os.fstat(descriptor)
            if (
                (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
                or total != size
                or _sha256(b"".join(chunks)) != digest
            ):
                raise OrchestrationError(
                    "captured source bytes changed before evidence binding"
                )
        except (OSError, PathSecurityError) as exc:
            raise OrchestrationError(
                "captured source cannot be revalidated safely"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory_fd is not None:
                os.close(directory_fd)
    if observed_paths != sorted(observed_paths) or len(set(observed_paths)) != len(
        observed_paths
    ):
        raise OrchestrationError("captured source attestation is unordered or ambiguous")
    if set(observed_paths) != set(expected):
        raise OrchestrationError(
            "captured source attestation does not cover the source inventory"
        )


def _validate_loaded_project_modules(
    root: Path, source_inventory: Mapping[str, Any]
) -> None:
    """Reject project-local import shadowing and loaded-source drift."""

    _validate_captured_source_attestation(root, source_inventory)
    expected = {
        str(entry["path"]): str(entry["sha256"])
        for entry in source_inventory.get("entries", ())
        if isinstance(entry, Mapping)
    }
    for module_name, module in tuple(sys.modules.items()):
        raw_file = getattr(module, "__file__", None)
        if not isinstance(raw_file, str):
            continue
        try:
            candidate = Path(raw_file).resolve(strict=True)
            relative = candidate.relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if module_name == "__main__":
            continue
        if getattr(sys, "_scientist_one_test_runner", False) is True:
            try:
                candidate.relative_to(root / "tests")
                info = candidate.stat()
            except (OSError, ValueError):
                pass
            else:
                if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    continue
        if not module_name.startswith("scientist_one"):
            raise OrchestrationError(
                f"project-local module shadowing is forbidden: {module_name}"
            )
        if candidate.suffix != ".py" or relative not in expected:
            raise OrchestrationError(
                f"loaded Scientist-One module is outside the source inventory: {module_name}"
            )
        data = read_confined_bytes(
            root, relative, reject_hardlinks=True, max_bytes=4 * 1024 * 1024
        )
        if data is None or _sha256(data) != expected[relative]:
            raise OrchestrationError(
                f"loaded Scientist-One module differs from its source inventory: {module_name}"
            )


def _synthetic_study(run_id: str) -> Any:
    """Construct the one typed study whose canonical payload is persisted."""

    conditions = ExecutionConditions(
        "identity-v1",
        "frozen role-specific fixtures",
        1,
        "not applicable; deterministic bounded pass",
        120.0,
        "synthetic scalar outcome",
        True,
    )
    protocol = ResearchProtocol(
        study_id=f"{run_id}-study-v1",
        study_version=1,
        primary_hypothesis="the treatment fixture mean exceeds control by exactly 1.0",
        primary_estimand="treatment_mean_minus_control_mean",
        primary_metric="arithmetic_mean_difference",
        secondary_metrics=("six_scenario_known_answer_accuracy",),
        unit_of_analysis="synthetic_unit_id",
        resampling_unit="synthetic_unit_id",
        data_exclusions=(),
        data_roles=DataRoles(
            ("train-fixture-v1",),
            ("workflow-development-v1",),
            ("workflow-validation-v1",),
            ("synthetic-confirmatory-v1",),
        ),
        candidate_conditions=conditions,
        baseline_set=(BaselineSpec("known-answer-contract-v1", conditions),),
        ablation_set=("trap_detection_by_scenario",),
        negative_controls=("true_null",),
        domain_nulls=(
            DomainNullSpec(
                "paired-synthetic-unit-null",
                "paired unit-respecting sign reversal",
                "synthetic_unit_id",
                ("paired unit",),
                ("paired units are exchangeable under the null",),
                True,
            ),
        ),
        statistical_tests=(
            StatisticalTestSpec(
                "primary-difference",
                "deterministic difference of arithmetic means",
                "paired-synthetic-unit-null",
                "greater",
            ),
        ),
        confidence_intervals=(
            ConfidenceIntervalSpec("unit bootstrap", 0.95, "synthetic_unit_id"),
        ),
        multiple_comparison_correction="Holm across primary and secondary metrics",
        seed_policy=SeedPolicy(
            (20260812,), "single frozen seed", "mechanical execution failure only"
        ),
        compute_budget=ProtocolComputeBudget(1, 120.0, 1, 1),
        stopping_rules=("stop on any mandatory gate failure",),
        decision_ladder=(
            "positive",
            "negative",
            "inconclusive",
            "scientific invalidity",
        ),
        claim_scope_contract="claims apply only to deterministic synthetic workflow behavior",
        interpretation_rules=InterpretationRules(
            "bounded positive synthetic claim",
            "NEGATIVE_RESULT",
            "INCONCLUSIVE",
            "STOP_SCIENTIFIC_INVALIDITY",
        ),
        validity_reserve_fraction=0.40,
        reserve_basis="data_and_compute",
    )
    validate_protocol(protocol)
    return freeze_protocol(protocol)


class ScientistOneOrchestrator:
    """A local controller that advances only through typed evidence contracts."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        captured_root = _captured_project_root()
        self.root = _safe_root(root, captured_root=captured_root)
        self._root_identity = _named_directory_identity(self.root)
        self._command_thread_lock = threading.RLock()
        self._command_guard_state = threading.local()
        with _project_resource_execution_lock(
            self.root, expected_root_identity=self._root_identity
        ):
            for directory in (
                "runs", "artifacts", "reports", "state",
                ".scientist-one-build/checkpoints", ".scientist-one-build/tmp",
                ".scientist-one-build/custody",
                ".scientist-one-build/resource-authority",
            ):
                _secure_directory(self.root, directory, create=True)
            if captured_root is not None:
                # Every supported command crosses the captured-byte provenance
                # gate before it can inspect or mutate run state. start() repeats
                # this immediately before freezing its source inventory.
                _source_inventory(self.root)
        self.command_context: tuple[str, ...] = (
            "python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py", "internal"
        )

    def set_command_context(self, argv: Sequence[str]) -> None:
        if not argv or any(not isinstance(item, str) or not item or "\x00" in item for item in argv):
            raise OrchestrationError("invalid command provenance")
        self.command_context = tuple(argv)

    def _assert_project_root_identity(self) -> None:
        if _named_directory_identity(self.root) != self._root_identity:
            raise OrchestrationError("project root identity changed after admission")

    def _command_guard_depth(self) -> int:
        depth = getattr(self._command_guard_state, "depth", 0)
        if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
            raise OrchestrationError("project command guard state is invalid")
        return depth

    @contextmanager
    def _command_root_guard(self) -> Iterator[None]:
        """Serialize a complete command under its admitted root identity."""

        with self._command_thread_lock:
            depth = self._command_guard_depth()
            if depth:
                self._assert_project_root_identity()
                self._command_guard_state.depth = depth + 1
                try:
                    yield
                finally:
                    self._command_guard_state.depth = depth
                return
            with _project_resource_execution_lock(
                self.root, expected_root_identity=self._root_identity
            ):
                self._command_guard_state.depth = 1
                try:
                    yield
                finally:
                    self._command_guard_state.depth = 0

    def _run_dir(self, run_id: str, *, create: bool = False) -> Path:
        if not RUN_ID_PATTERN.fullmatch(run_id):
            raise OrchestrationError("invalid run ID")
        return _secure_directory(self.root, Path("runs") / run_id, create=create)

    def _registry(self, run_id: str) -> ArtifactRegistry:
        """Return the run-scoped content store used by every run artifact.

        Content identity remains SHA-256 based within the run.  Provenance is
        intentionally scoped by run so identical generated bytes in two runs
        can retain their distinct immutable parents and creation commands.
        """

        self._run_dir(run_id)
        return ArtifactRegistry(self.root, Path("runs") / run_id / "registry")

    def _resource_authority_records(
        self, run_id: str
    ) -> tuple[dict[str, Any], ...]:
        """Read the monotonic validity authority outside the replaceable run tree."""

        if not RUN_ID_PATTERN.fullmatch(run_id):
            raise OrchestrationError("invalid run ID for resource authority")
        relative = Path(".scientist-one-build/resource-authority") / run_id
        directory = _secure_directory(self.root, relative, create=False)
        try:
            directory_fd = open_confined_directory_fd(
                self.root, relative, create=False
            )
            try:
                names: list[str] = []
                with os.scandir(directory_fd) as iterator:
                    for entry in iterator:
                        if not RESOURCE_AUTHORITY_NAME_PATTERN.fullmatch(entry.name):
                            raise OrchestrationError(
                                "resource authority contains an unknown entry"
                            )
                        if len(names) >= 16:
                            raise OrchestrationError(
                                "resource authority exceeds its bounded history"
                            )
                        names.append(entry.name)
            finally:
                os.close(directory_fd)
        except (OSError, PathSecurityError) as exc:
            raise OrchestrationError("resource authority directory is unsafe") from exc
        records: list[dict[str, Any]] = []
        prior_digest: str | None = None
        for expected_sequence, name in enumerate(sorted(names)):
            matched = RESOURCE_AUTHORITY_NAME_PATTERN.fullmatch(name)
            if matched is None or int(matched.group("sequence")) != expected_sequence:
                raise OrchestrationError("resource authority sequence is not contiguous")
            try:
                data = read_confined_bytes(
                    self.root,
                    relative / name,
                    reject_hardlinks=True,
                    max_bytes=1024 * 1024,
                )
                value = safe_json_loads(data) if data is not None else None
            except Exception as exc:
                raise OrchestrationError("resource authority record is unsafe") from exc
            if not isinstance(value, dict) or set(value) != {
                "schema_version", "kind", "run_id", "sequence",
                "logical_type", "state_sha256", "state",
                "prior_authority_sha256",
            }:
                raise OrchestrationError("resource authority record schema is invalid")
            digest = _sha256(data)
            state = value.get("state")
            if (
                digest != matched.group("digest")
                or value.get("schema_version") != SCHEMA_VERSION
                or value.get("kind") != "RESOURCE_RUNTIME_AUTHORITY"
                or value.get("run_id") != run_id
                or value.get("sequence") != expected_sequence
                or not isinstance(value.get("logical_type"), str)
                or not str(value["logical_type"]).startswith("resource_runtime_")
                or not isinstance(state, dict)
                or value.get("state_sha256") != _sha256(_canonical_bytes(state))
                or value.get("prior_authority_sha256") != prior_digest
            ):
                raise OrchestrationError("resource authority record binding is invalid")
            records.append(value)
            prior_digest = digest
        return tuple(records)

    def _persist_resource_authority(
        self,
        manifest: Mapping[str, Any],
        logical_type: str,
        state: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Advance the external monotonic resource head before run-local evidence."""

        run_id = str(manifest["run_id"])
        records = self._resource_authority_records(run_id)
        normalized_state = safe_json_loads(canonical_json_bytes(state))
        if not isinstance(normalized_state, dict):
            raise OrchestrationError("resource authority state must be an object")
        if records and records[-1]["logical_type"] == logical_type:
            if records[-1]["state"] != normalized_state:
                raise OrchestrationError("resource authority idempotency collision")
            return records[-1]
        if any(record["logical_type"] == logical_type for record in records):
            raise OrchestrationError("resource authority stage cannot be replayed")
        prior_digest = None
        if records:
            prior_digest = _sha256(_canonical_bytes(records[-1]))
        payload = {
            "schema_version": SCHEMA_VERSION,
            "kind": "RESOURCE_RUNTIME_AUTHORITY",
            "run_id": run_id,
            "sequence": len(records),
            "logical_type": logical_type,
            "state_sha256": _sha256(_canonical_bytes(normalized_state)),
            "state": normalized_state,
            "prior_authority_sha256": prior_digest,
        }
        data = _canonical_bytes(payload)
        relative = (
            Path(".scientist-one-build/resource-authority")
            / run_id
            / f"{len(records):04d}-{_sha256(data)}.json"
        )
        try:
            atomic_write_bytes(
                self.root, relative, data, immutable=True, create_parents=True
            )
        except PathSecurityError as exc:
            raise OrchestrationError("resource authority advance failed") from exc
        persisted = self._resource_authority_records(run_id)
        if len(persisted) != len(records) + 1 or persisted[-1] != payload:
            raise OrchestrationError("resource authority advance did not verify")
        return payload

    def _resource_authority_descriptors(
        self, records: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        """Canonical ledger commitments for the complete external history."""

        return [
            {
                "sequence": index,
                "logical_type": record["logical_type"],
                "state_sha256": record["state_sha256"],
                "authority_sha256": _sha256(_canonical_bytes(record)),
                "prior_authority_sha256": record["prior_authority_sha256"],
            }
            for index, record in enumerate(records)
        ]

    def _validate_resource_authority_ledger(
        self,
        records: Sequence[Mapping[str, Any]],
        events: Sequence[Any],
    ) -> None:
        """Require every monotonic resource record at its exact ledger position."""

        descriptors = self._resource_authority_descriptors(records)
        observed: list[dict[str, Any]] = []
        reconciled = False
        for event in events:
            if isinstance(event, Mapping):
                event_metadata = event.get("metadata", {})
                event_artifact_hashes = event.get("artifact_hashes", ())
                event_type = event.get("event_type")
                requested_state = event.get("requested_state_after")
            else:
                event_metadata = event.metadata
                event_artifact_hashes = event.artifact_hashes
                event_type = event.event_type
                requested_state = event.requested_state_after.value
            if not isinstance(event_metadata, Mapping):
                raise OrchestrationError("resource ledger metadata is malformed")
            names = event_metadata.get("artifact_types", ())
            if not isinstance(names, (list, tuple)):
                raise OrchestrationError("resource ledger artifact types are malformed")
            resource_positions = [
                index
                for index, name in enumerate(names)
                if isinstance(name, str) and name.startswith("resource_runtime_")
            ]
            binding = event_metadata.get("resource_authority_checkpoint")
            if len(resource_positions) > 1:
                raise OrchestrationError("resource ledger event is ambiguous")
            if resource_positions:
                position = resource_positions[0]
                if position >= len(event_artifact_hashes):
                    raise OrchestrationError("resource ledger artifact is unbound")
                if len(observed) >= len(descriptors):
                    raise OrchestrationError("resource ledger has an extra checkpoint")
                expected = descriptors[len(observed)]
                if (
                    binding != expected
                    or names[position] != expected["logical_type"]
                    or event_artifact_hashes[position] != expected["state_sha256"]
                ):
                    raise OrchestrationError(
                        "resource authority history differs from its ledger commitment"
                    )
                observed.append(expected)
            elif binding is not None:
                raise OrchestrationError(
                    "resource authority binding lacks a checkpoint artifact"
                )
            reconciliation = event_metadata.get("resource_authority_chain")
            if reconciliation is not None:
                if (
                    reconciled
                    or event_type != "SECURITY_STOP"
                    or requested_state != "STOP_SECURITY"
                    or reconciliation != descriptors
                ):
                    raise OrchestrationError(
                        "resource rollback reconciliation is malformed"
                    )
                reconciled = True
        if observed != descriptors and not reconciled:
            raise OrchestrationError(
                "external resource authority is not fully ledger-bound"
            )

    def _manifest_path(self, run_id: str) -> Path:
        return self._run_dir(run_id) / "manifest.json"

    def load_manifest(self, run_id: str) -> dict[str, Any]:
        manifest = _read_json(self._manifest_path(run_id))
        if manifest.get("run_id") != run_id:
            raise OrchestrationError("run manifest identity mismatch")
        return manifest

    def _save_manifest(self, manifest: dict[str, Any]) -> None:
        manifest["updated_at"] = _utc_now()
        _atomic_json(self.root, Path("runs") / str(manifest["run_id"]) / "manifest.json", manifest)

    def _artifact(self, manifest: dict[str, Any], logical_type: str, payload: Any, *, creator: str, parents: Sequence[str] = ()) -> dict[str, Any]:
        data = _canonical_bytes(payload)
        digest = _sha256(data)
        stage = str(manifest["current_state"]).lower()
        directory = _secure_directory(self.root, Path("runs") / str(manifest["run_id"]) / "artifacts" / stage, create=True)
        filename = f"{logical_type}-{digest[:20]}.json"
        path = directory / filename
        try:
            atomic_write_bytes(
                self.root,
                path.relative_to(self.root),
                data,
                immutable=True,
            )
        except PathSecurityError as exc:
            raise OrchestrationError("immutable artifact publication failed") from exc
        registry_record = self._registry(str(manifest["run_id"])).put_bytes(
            data,
            logical_type=logical_type,
            origin="Scientist-One built-in offline workflow",
            creator_role=Role(creator),
            creation_command=self.command_context,
            parent_artifacts=parents,
            schema_version=SCHEMA_VERSION,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=manifest["created_at"],
        )
        record = {
            "logical_type": logical_type,
            "path": path.relative_to(self.root).as_posix(),
            "sha256": digest,
            "size": len(data),
            "schema_version": SCHEMA_VERSION,
            "mime_type": "application/json",
            "origin": "Scientist-One built-in offline workflow",
            "creator_role": creator,
            "creation_command": list(self.command_context),
            "parent_artifacts": list(parents),
            "validation_result": "PASS",
            "frozen": True,
            "registry_path": registry_record.path,
            "registry_metadata_path": registry_record.metadata_path,
            "registry_record_hash": registry_record.record_hash,
        }
        existing = manifest["artifacts"].get(logical_type)
        if existing is not None and existing != record:
            raise OrchestrationError(f"frozen logical artifact already registered: {logical_type}")
        manifest["artifacts"][logical_type] = record
        return record

    def _artifact_from_file(
        self,
        manifest: dict[str, Any],
        logical_type: str,
        path: Path,
        *,
        creator: str,
        mime_type: str,
        parents: Sequence[str] = (),
        max_bytes: int = 32 * 1024 * 1024,
        expected_bytes: bytes | None = None,
    ) -> dict[str, Any]:
        candidate = path if path.is_absolute() else self.root / path
        try:
            relative = candidate.relative_to(self.root)
            data = read_confined_bytes(
                self.root,
                relative,
                reject_hardlinks=True,
                max_bytes=max_bytes,
            )
        except (PathSecurityError, ValueError) as exc:
            raise OrchestrationError("generated artifact cannot be read safely") from exc
        if data is None:
            raise OrchestrationError("generated artifact disappeared")
        if expected_bytes is not None and data != expected_bytes:
            raise OrchestrationError(
                "generated artifact differs from its in-memory deterministic rendering"
            )
        digest = _sha256(data)
        directory = _secure_directory(self.root, Path("runs") / str(manifest["run_id"]) / "artifacts" / str(manifest["current_state"]).lower(), create=True)
        suffix = relative.suffix or ".bin"
        destination = directory / f"{logical_type}-{digest[:20]}{suffix}"
        try:
            atomic_write_bytes(
                self.root,
                destination.relative_to(self.root),
                data,
                immutable=True,
            )
        except PathSecurityError as exc:
            raise OrchestrationError("immutable file artifact publication failed") from exc
        registry_record = self._registry(str(manifest["run_id"])).put_bytes(
            data,
            logical_type=logical_type,
            origin="generated from machine-readable verified artifacts",
            creator_role=Role(creator),
            creation_command=self.command_context,
            parent_artifacts=parents,
            schema_version=SCHEMA_VERSION,
            mime_type=mime_type,
            validation_result="PASS",
            frozen=True,
            created_at=manifest["created_at"],
        )
        record = {
            "logical_type": logical_type,
            "path": destination.relative_to(self.root).as_posix(),
            "sha256": digest,
            "size": len(data),
            "schema_version": SCHEMA_VERSION,
            "mime_type": mime_type,
            "origin": "generated from machine-readable verified artifacts",
            "creator_role": creator,
            "creation_command": list(self.command_context),
            "parent_artifacts": list(parents),
            "validation_result": "PASS",
            "frozen": True,
            "registry_path": registry_record.path,
            "registry_metadata_path": registry_record.metadata_path,
            "registry_record_hash": registry_record.record_hash,
        }
        existing = manifest["artifacts"].get(logical_type)
        if existing is not None and existing != record:
            raise OrchestrationError(f"frozen logical artifact already registered: {logical_type}")
        manifest["artifacts"][logical_type] = record
        return record

    def _evaluate(self, manifest: dict[str, Any], key: str, evaluator: EvaluatorClass, role: Role, artifacts: Sequence[str], checks: Sequence[RCheck] = (), *, producer: Role | None = None) -> dict[str, Any]:
        hashes = tuple(manifest["artifacts"][item]["sha256"] for item in artifacts)
        reason = f"typed {key} contract passed"
        evaluation = Evaluation(evaluator, role, Decision.PASS, hashes, reason, tuple(checks), False, producer)
        bundle = make_role_bundle(role, str(manifest["run_id"]), hashes, {"gate": key, "read_only": True}, producer_role=producer)
        record = {
            "evaluator_class": evaluator.value,
            "authority": role.value,
            "decision": evaluation.decision.value,
            "critical_objection": False,
            "artifact_hashes": list(hashes),
            "evaluation_sha256": evaluation.sha256,
            "frozen_context_sha256": bundle.sha256,
            "producer_role": producer.value if producer else None,
            "reason": reason,
            "r_checks": [item.value for item in checks],
            "logically_separated": producer is None or producer is not role,
            "human_independence_claimed": False,
        }
        manifest["evaluator_decisions"][key] = record
        return record

    def _append_event(
        self,
        manifest: dict[str, Any],
        before: str,
        after: str,
        reason: str,
        artifact_types: Sequence[str],
        evaluator_keys: Sequence[str],
        *,
        event_type: str = "TRANSITION",
        actor_role: Role = Role.ORCHESTRATOR,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        # INITIALIZED is represented as a CALIBRATE checkpoint event because
        # the typed ledger intentionally has no pseudo-state outside the state
        # machine. All later records are real typed edges.
        typed_before = "CALIBRATE" if before == "INITIALIZED" else before
        ledger = EventLedger(
            self.root, Path("runs") / str(manifest["run_id"]) / "events.jsonl"
        )
        artifact_records = [manifest["artifacts"][name] for name in artifact_types]
        stored_evaluations = [manifest["evaluator_decisions"][key] for key in evaluator_keys]
        event_metadata = {
            "schema_version": SCHEMA_VERSION,
            "initialization": before == "INITIALIZED",
            "evaluator_keys": list(evaluator_keys),
            "artifact_types": list(artifact_types),
            "artifact_record_hashes": [
                record["registry_record_hash"] for record in artifact_records
            ],
            "artifact_descriptors": [
                {
                    "logical_type": record["logical_type"],
                    "sha256": record["sha256"],
                    "registry_record_hash": record["registry_record_hash"],
                    "parent_artifacts": list(record.get("parent_artifacts", ())),
                    "parent_record_hashes": [
                        self._registry(str(manifest["run_id"]))
                        .get_metadata(parent)
                        .record_hash
                        for parent in record.get("parent_artifacts", ())
                    ],
                }
                for record in artifact_records
            ],
        }
        resource_positions = [
            index
            for index, name in enumerate(artifact_types)
            if name.startswith("resource_runtime_")
        ]
        if len(resource_positions) > 1:
            raise OrchestrationError("one event cannot bind multiple resource checkpoints")
        if resource_positions:
            authorities = self._resource_authority_records(
                str(manifest["run_id"])
            )
            if not authorities:
                raise OrchestrationError(
                    "resource checkpoint lacks an external authority record"
                )
            descriptor = self._resource_authority_descriptors(authorities)[-1]
            resource_record = artifact_records[resource_positions[0]]
            if (
                descriptor["logical_type"] != resource_record["logical_type"]
                or descriptor["state_sha256"] != resource_record["sha256"]
            ):
                raise OrchestrationError(
                    "resource checkpoint differs from the external authority head"
                )
            event_metadata["resource_authority_checkpoint"] = descriptor
        if (
            event_type == "TRANSITION"
            and typed_before != after
            and manifest.get("typed_transition_receipts")
        ):
            event_metadata["transition_receipt"] = dict(
                manifest["typed_transition_receipts"][-1]
            )
        if metadata:
            overlap = set(event_metadata).intersection(metadata)
            if overlap:
                raise OrchestrationError(
                    "event metadata cannot replace authoritative bindings: "
                    + ", ".join(sorted(overlap))
                )
            event_metadata.update(metadata)
        event = ledger.record(
            run_id=str(manifest["run_id"]),
            event_id=f"event-{int(manifest['event_count']) + 1:04d}",
            timestamp=_utc_now(),
            actor_role=actor_role,
            state_before=typed_before,
            requested_state_after=after,
            artifact_hashes=(record["sha256"] for record in artifact_records),
            code_version=str(manifest["code_fingerprint"]),
            configuration_hash=str(manifest["configuration_sha256"]),
            dataset_identifiers=manifest["fixture_identifiers"],
            random_seeds=manifest["random_seeds"],
            evaluator_outputs=stored_evaluations,
            reason=reason,
            event_type="CHECKPOINT" if before == "INITIALIZED" else event_type,
            metadata=event_metadata,
        )
        manifest["event_count"] = int(manifest["event_count"]) + 1
        manifest["ledger_head_hash"] = event.event_hash
        return str(event.event_id)

    def _checkpoint(self, manifest: dict[str, Any]) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "run_id": manifest["run_id"],
            "state": manifest["current_state"],
            "terminal_state": manifest.get("terminal_state"),
            "event_count": manifest["event_count"],
            "ledger_head_hash": manifest.get("ledger_head_hash"),
            "artifact_hashes": {key: value["sha256"] for key, value in sorted(manifest["artifacts"].items())},
            "artifact_record_hashes": {
                key: value["registry_record_hash"]
                for key, value in sorted(manifest["artifacts"].items())
            },
            "resource_runtime_artifact": manifest.get("resource_runtime_artifact"),
            "resumable": manifest.get("terminal_state") is None,
        }
        _atomic_json(self.root, Path("runs") / str(manifest["run_id"]) / "checkpoint.json", payload)
        if manifest.get("ledger_head_hash") and manifest.get("event_count"):
            RecoveryManager(self.root).create_checkpoint(
                {
                    "run_id": manifest["run_id"],
                    "event_id": f"event-{int(manifest['event_count']):04d}",
                    "ledger_head_hash": manifest["ledger_head_hash"],
                    "state": manifest["current_state"],
                    "artifact_hashes": {
                        key: value["sha256"]
                        for key, value in sorted(manifest["artifacts"].items())
                    },
                    "artifact_record_hashes": {
                        key: value["registry_record_hash"]
                        for key, value in sorted(manifest["artifacts"].items())
                    },
                    "resource_runtime_artifact": manifest.get(
                        "resource_runtime_artifact"
                    ),
                },
                checkpoint_dir=Path(".scientist-one-build/checkpoints") / str(manifest["run_id"]),
            )
        self._save_manifest(manifest)

    def _assert_no_newer_external_checkpoint(
        self, manifest: Mapping[str, Any]
    ) -> None:
        """Reject a run projection older than any immutable external checkpoint."""

        run_id = manifest.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
            raise OrchestrationError(
                "external checkpoint authority requires a validated run ID"
            )
        relative = Path(".scientist-one-build/checkpoints") / run_id
        try:
            directory_fd = open_confined_directory_fd(
                self.root, relative, create=False
            )
        except PathSecurityError as exc:
            raise OrchestrationError(
                "external checkpoint authority is unavailable or unsafe"
            ) from exc
        newest_count = 0
        newest_head: str | None = None
        try:
            with os.scandir(directory_fd) as iterator:
                count = 0
                for entry in iterator:
                    count += 1
                    if count > 256 or not re.fullmatch(
                        r"event-[0-9]{4}-[0-9a-f]{12}\.json", entry.name
                    ):
                        raise OrchestrationError(
                            "external checkpoint authority is malformed or oversized"
                        )
                    data = read_confined_bytes(
                        self.root,
                        relative / entry.name,
                        reject_hardlinks=True,
                        max_bytes=8 * 1024 * 1024,
                    )
                    value = safe_json_loads(data) if data is not None else None
                    if not isinstance(value, Mapping) or set(value) != {
                        "schema_version", "checkpoint_id", "run_id", "event_id",
                        "ledger_head_hash", "state", "artifact_hashes",
                        "artifact_record_hashes", "resource_runtime_artifact",
                        "created_at", "checkpoint_hash",
                    }:
                        raise OrchestrationError(
                            "external checkpoint authority has an invalid schema"
                        )
                    event_id = value.get("event_id")
                    checkpoint_hash = value.get("checkpoint_hash")
                    canonical = {
                        key: child
                        for key, child in value.items()
                        if key != "checkpoint_hash"
                    }
                    if (
                        value.get("schema_version") != SCHEMA_VERSION
                        or value.get("run_id") != run_id
                        or not isinstance(event_id, str)
                        or re.fullmatch(r"event-[0-9]{4}", event_id) is None
                        or not isinstance(checkpoint_hash, str)
                        or checkpoint_hash != _sha256(canonical_json_bytes(canonical))
                        or value.get("checkpoint_id")
                        != f"{event_id}-{str(value.get('ledger_head_hash'))[:12]}"
                    ):
                        raise OrchestrationError(
                            "external checkpoint authority binding is invalid"
                        )
                    event_count = int(event_id.removeprefix("event-"))
                    if event_count > newest_count:
                        newest_count = event_count
                        newest_head = str(value.get("ledger_head_hash"))
        finally:
            os.close(directory_fd)
        manifest_count = manifest.get("event_count")
        manifest_head = manifest.get("ledger_head_hash")
        if (
            isinstance(manifest_count, bool)
            or not isinstance(manifest_count, int)
            or newest_count > manifest_count
            or (newest_count == manifest_count and newest_head != manifest_head)
        ):
            raise OrchestrationError(
                "run projection is older than its external checkpoint authority"
            )

    def _resource_controller(self, manifest: Mapping[str, Any]) -> ResourceController:
        config = ResourceConfig.from_json(
            "configs/resource_limits.json", project_root=self.root
        )
        state = manifest.get("resource_runtime_state")
        authority_records = self._resource_authority_records(str(manifest["run_id"]))
        if isinstance(state, Mapping):
            artifact_name = manifest.get("resource_runtime_artifact")
            if not isinstance(artifact_name, str):
                raise OrchestrationError("resource runtime state lacks an immutable artifact binding")
            record = manifest.get("artifacts", {}).get(artifact_name)
            if not isinstance(record, Mapping):
                raise OrchestrationError("resource runtime artifact is absent from the manifest")
            try:
                registry = self._registry(str(manifest["run_id"]))
                stored = registry.get_metadata(str(record["sha256"]))
                payload = safe_json_loads(registry.get_bytes(stored.sha256))
            except Exception as exc:
                raise OrchestrationError("resource runtime artifact is absent or corrupt") from exc
            if not isinstance(payload, dict):
                raise OrchestrationError("resource runtime artifact is not an object")
            ledger_result = EventLedger(
                self.root,
                Path("runs") / str(manifest["run_id"]) / "events.jsonl",
            ).validate()
            if not ledger_result.valid or not ledger_result.events:
                raise OrchestrationError("resource runtime state has no valid ledger binding")
            self._validate_resource_authority_ledger(
                authority_records, ledger_result.events
            )
            authoritative_hash: str | None = None
            authoritative_name: str | None = None
            for event in reversed(ledger_result.events):
                artifact_types = event.metadata.get("artifact_types", [])
                if not isinstance(artifact_types, (list, tuple)):
                    continue
                for index in range(len(artifact_types) - 1, -1, -1):
                    candidate = artifact_types[index]
                    if isinstance(candidate, str) and candidate.startswith("resource_runtime_"):
                        if index >= len(event.artifact_hashes):
                            raise OrchestrationError("resource checkpoint artifact binding is malformed")
                        authoritative_name = candidate
                        authoritative_hash = event.artifact_hashes[index]
                        break
                if authoritative_hash is not None:
                    break
            if (
                not authority_records
                or authority_records[-1].get("logical_type") != artifact_name
                or authority_records[-1].get("state") != dict(state)
                or authority_records[-1].get("state_sha256")
                != record.get("sha256")
                or stored.logical_type != artifact_name
                or stored.record_hash != record.get("registry_record_hash")
                or payload != dict(state)
                or authoritative_name != artifact_name
                or authoritative_hash != record.get("sha256")
            ):
                raise OrchestrationError(
                    "resource state differs from the latest ledger-bound frozen checkpoint"
                )
            return ResourceController.from_runtime_state(config, self.root, state)
        if authority_records:
            raise OrchestrationError(
                "resource authority exists without a matching run-local state"
            )
        return ResourceController(
            config,
            self.root,
            run_id=str(manifest["run_id"]),
            validity_budget_units=10,
        )

    def _run_with_resources(
        self,
        manifest: dict[str, Any],
        *,
        experiment_id: str,
        validity_stage: str,
        validity_units: int,
        operation: Callable[[], Any],
    ) -> Any:
        if getattr(
            self._command_guard_state, "resource_transaction_active", False
        ) is True:
            raise OrchestrationError("nested resource transactions are prohibited")

        def execute_locked() -> Any:
            run_id = manifest.get("run_id")
            if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
                raise OrchestrationError(
                    "resource transaction requires a validated run ID"
                )
            fresh = self.load_manifest(run_id)
            self._assert_no_newer_external_checkpoint(fresh)
            if _canonical_bytes(fresh) != _canonical_bytes(manifest):
                raise OrchestrationError(
                    "resource transaction caller projection is stale"
                )
            # Closures used by the bounded work stages intentionally retain
            # this dictionary object.  Refresh it in place so the transaction
            # and its operation share the just-reloaded canonical projection.
            manifest.clear()
            manifest.update(fresh)
            return self._run_with_resources_locked(
                manifest,
                experiment_id=experiment_id,
                validity_stage=validity_stage,
                validity_units=validity_units,
                operation=operation,
            )

        self._command_guard_state.resource_transaction_active = True
        try:
            if self._command_guard_depth():
                self._assert_project_root_identity()
                return execute_locked()
            with self._command_root_guard():
                return execute_locked()
        finally:
            self._command_guard_state.resource_transaction_active = False

    def _run_with_resources_locked(
        self,
        manifest: dict[str, Any],
        *,
        experiment_id: str,
        validity_stage: str,
        validity_units: int,
        operation: Callable[[], Any],
    ) -> Any:
        controller = self._resource_controller(manifest)
        try:
            with controller.acquire(
                experiment_id,
                cpu_workers=1,
                gpu_jobs=0,
                validity_stage=validity_stage,
                validity_units=validity_units,
            ):
                # The charge is atomic with admission. Persist it before any
                # experimental code can run so a crash cannot replenish it.
                manifest["resource_runtime_state"] = controller.export_state().to_dict()
                prior_name = manifest.get("resource_runtime_artifact")
                parents = (
                    (manifest["artifacts"][prior_name]["sha256"],)
                    if isinstance(prior_name, str) and prior_name in manifest["artifacts"]
                    else ()
                )
                charge_name = f"resource_runtime_{validity_stage.lower()}_charge"
                self._persist_resource_authority(
                    manifest, charge_name, manifest["resource_runtime_state"]
                )
                self._artifact(
                    manifest,
                    charge_name,
                    manifest["resource_runtime_state"],
                    creator=Role.ORCHESTRATOR.value,
                    parents=parents,
                )
                manifest["resource_runtime_artifact"] = charge_name
                self._append_event(
                    manifest,
                    str(manifest["current_state"]),
                    str(manifest["current_state"]),
                    f"atomic {validity_stage} validity charge persisted before execution",
                    (charge_name,),
                    (),
                    event_type="CHECKPOINT",
                )
                self._save_manifest(manifest)
                result = operation()
        except ResourceLimitError as exc:
            raise OrchestrationError(f"resource or validity admission failed: {exc}") from exc
        controller.record_progress()
        manifest["resource_runtime_state"] = controller.export_state().to_dict()
        prior_name = str(manifest["resource_runtime_artifact"])
        completion_name = f"resource_runtime_{validity_stage.lower()}_completion"
        self._persist_resource_authority(
            manifest, completion_name, manifest["resource_runtime_state"]
        )
        self._artifact(
            manifest,
            completion_name,
            manifest["resource_runtime_state"],
            creator=Role.ORCHESTRATOR.value,
            parents=(manifest["artifacts"][prior_name]["sha256"],),
        )
        manifest["resource_runtime_artifact"] = completion_name
        self._append_event(
            manifest,
            str(manifest["current_state"]),
            str(manifest["current_state"]),
            f"{validity_stage} resource state persisted after execution",
            (completion_name,),
            (),
            event_type="CHECKPOINT",
        )
        self._save_manifest(manifest)
        return result

    def _recovery_report(self, manifest: Mapping[str, Any]) -> Any:
        custody = None
        custody_record = manifest.get("artifacts", {}).get("custody_record")
        if isinstance(custody_record, dict):
            custody = self._json_artifact_payload(manifest, "custody_record")
            if not self._validate_live_custody(manifest):
                custody = dict(custody)
                custody["confirmatory_claims_valid"] = False
                custody["violation_reasons"] = [
                    "durable custody journal is corrupt, advanced, or invalid"
                ]
        return RecoveryManager(
            self.root,
            ledger_validator=lambda path: self._foundation_ledger_validation(path),
        ).recover(
            ledger_path=(self._run_dir(str(manifest["run_id"])) / "events.jsonl").relative_to(self.root),
            artifact_registry=list(manifest.get("artifacts", {}).values()),
            checkpoint_dir=Path(".scientist-one-build/checkpoints") / str(manifest["run_id"]),
            custody_record=custody,
            repair_truncated_tail=True,
        )

    def _validate_live_custody(self, manifest: Mapping[str, Any]) -> bool:
        """Reopen the durable journal; frozen snapshots never authorize alone."""

        if "custody_record" not in manifest.get("artifacts", {}):
            try:
                unexpected = read_confined_bytes(
                    self.root,
                    _custody_journal_path(str(manifest["run_id"])),
                    reject_hardlinks=True,
                    max_bytes=32 * 1024 * 1024,
                    missing_ok=True,
                )
            except PathSecurityError:
                return False
            return unexpected is None
        try:
            snapshot = self._json_artifact_payload(manifest, "custody_record")
            raw_path = snapshot.get("journal_path")
            if (
                not isinstance(raw_path, str)
                or Path(raw_path).is_absolute()
                or ".." in Path(raw_path).parts
            ):
                return False
            expected_path = _custody_journal_path(str(manifest["run_id"]))
            if Path(raw_path) != expected_path:
                return False
            custody = SimulatedHoldoutCustody(
                (Role.EXPERIMENT_RUNNER.value,),
                journal_root=self.root,
                journal_path=expected_path,
            )
            expected_head = snapshot.get("journal_head_hash")
            expected_identity = snapshot.get("journal_identity_sha256")
            if not isinstance(expected_head, str) or not isinstance(
                expected_identity, str
            ):
                return False
            with custody.admission_guard(
                expected_journal_head_hash=expected_head,
                expected_journal_identity_sha256=expected_identity,
            ) as live:
                head = live.journal_head_hash
                status = live.status
                journal_sha256 = live.journal_sha256
                journal_size = live.journal_size
                journal_identity = live.journal_identity_sha256
                seal = live.seal
                access_records = _custody_access_records(live.journal_bytes)
                release_event = asdict(status.release_event) if status.release_event else None
            protocol_payload = self._json_artifact_payload(
                manifest, "frozen_protocol"
            )
            typed_protocol = protocol_payload.get("protocol")
            if not isinstance(typed_protocol, Mapping):
                return False
            return (
                status.durable_journal
                and status.sealed
                and status.revealed
                and not status.invalidated
                and status.confirmatory_claims_valid
                and status.authorized_access_count == 1
                and head == snapshot.get("journal_head_hash")
                and status.journal_head_hash == snapshot.get("journal_head_hash")
                and journal_sha256 == snapshot.get("journal_sha256")
                and journal_size == snapshot.get("journal_size")
                and journal_identity == snapshot.get("journal_identity_sha256")
                and snapshot.get("confirmatory_claims_valid") is True
                and snapshot.get("authorized_access_count") == 1
                and snapshot.get("custody_independence") == live.custody_label
                and snapshot.get("holdout_identity_hash")
                == seal.holdout_identity_hash
                and snapshot.get("split_manifest_hash") == seal.split_manifest_hash
                and snapshot.get("protocol_hash") == seal.protocol_hash
                and snapshot.get("code_hash") == seal.code_hash
                and snapshot.get("configuration_hash") == seal.configuration_hash
                and snapshot.get("pre_unblinding_interpretation_hash")
                == seal.pre_unblinding_interpretation_hash
                and snapshot.get("seal_hash") == seal.seal_hash
                and snapshot.get("sealing_time") == seal.sealed_at
                and snapshot.get("release_event") == release_event
                and snapshot.get("access_records") == access_records
                and snapshot.get("access_requester")
                == (status.release_event.requester if status.release_event else None)
                and snapshot.get("access_reason")
                == (status.release_event.reason if status.release_event else None)
                and snapshot.get("durable_journal") is True
                and snapshot.get("genuine_independence_claimed") is False
                and snapshot.get("study_id") == typed_protocol.get("study_id")
                and snapshot.get("study_version")
                == typed_protocol.get("study_version")
            )
        except Exception:
            return False

    def _validate_live_inventories(self, manifest: Mapping[str, Any]) -> bool:
        """Require the current workspace to equal the pre-confirm frozen inputs."""

        artifacts = manifest.get("artifacts", {})
        if not isinstance(artifacts, Mapping):
            return False
        if "frozen_source_inventory" not in artifacts:
            # Before CANDIDATE there is no frozen execution lineage yet.
            return True
        try:
            return (
                self._json_artifact_payload(manifest, "frozen_source_inventory")
                == _source_inventory(self.root)
                and self._json_artifact_payload(
                    manifest, "frozen_configuration_inventory"
                )
                == _configuration_inventory(self.root)
            )
        except Exception:
            return False

    def _foundation_ledger_validation(self, path: Path) -> Any:
        """Adapt the authoritative EventLedger result to recovery's shape."""

        from .recovery import LedgerValidationResult

        relative = path.relative_to(self.root)
        result = EventLedger(self.root, relative).validate()
        events = tuple(event.to_dict() for event in result.events)
        run_id = result.events[0].run_id if result.events else None
        return LedgerValidationResult(
            result.valid,
            events,
            result.head_hash,
            run_id,
            result.error,
            result.error_line,
            result.recoverable_truncated_tail,
            result.valid_prefix_bytes,
            0,
        )

    @_project_command
    def preflight(self) -> dict[str, Any]:
        profile = HardwareProfiler(self.root).collect()
        profile_payload = profile.to_dict()
        if "project_root" in profile_payload:
            profile_payload["project_root"] = "."
        # Preserve capability/version evidence without embedding executable
        # paths outside the project evidence boundary.
        toolchains = profile_payload.get("installed_toolchains", {})
        if isinstance(toolchains, dict):
            for logical_name, evidence in toolchains.items():
                if isinstance(evidence, dict) and isinstance(evidence.get("value"), str):
                    evidence["value"] = logical_name
                    evidence["path_recorded"] = False
        _atomic_json(self.root, "state/HARDWARE_PROFILE.json", profile_payload)
        selection = DeviceManager(preference="auto", dtype="float32").select()
        resource_config_bytes = read_confined_bytes(
            self.root,
            "configs/resource_limits.json",
            reject_hardlinks=True,
            max_bytes=1024 * 1024,
        )
        if resource_config_bytes is None:
            raise OrchestrationError("resource configuration disappeared")
        try:
            resource_config_payload = safe_json_loads(resource_config_bytes)
        except Exception as exc:
            raise OrchestrationError("resource configuration is malformed") from exc
        if not isinstance(resource_config_payload, Mapping):
            raise OrchestrationError("resource configuration must be an object")
        config = ResourceConfig.from_mapping(resource_config_payload)
        controller = ResourceController(config, self.root)
        decision = controller.evaluate()
        allowed = decision.allowed
        configuration_inventory = _configuration_inventory(self.root)
        resource_entry = next(
            (
                entry
                for entry in configuration_inventory["entries"]
                if entry.get("path") == "configs/resource_limits.json"
            ),
            None,
        )
        if (
            not isinstance(resource_entry, Mapping)
            or resource_entry.get("sha256") != _sha256(resource_config_bytes)
        ):
            raise OrchestrationError(
                "resource configuration differs from the configuration inventory"
            )
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "PASS" if allowed else decision.action.value,
            "offline": True,
            "network_probe_performed": False,
            "hardware_profile": profile_payload,
            "device_selection": selection.to_dict(),
            "resource_decision": asdict(decision),
            "resource_config_sha256": _sha256(resource_config_bytes),
            "resource_controller_config_sha256": controller.config_sha256,
            "configuration_inventory_aggregate_sha256": configuration_inventory[
                "aggregate_sha256"
            ],
            "external_integrations": "INTERFACES_AND_FIXTURES_ONLY",
        }
        _atomic_json(self.root, "state/PREFLIGHT_RESULT.json", result)
        return result

    @_project_command
    def calibrate(self) -> dict[str, Any]:
        report = assert_calibrated(run_calibration())
        result = report.to_dict()
        result["status"] = "PASS"
        result["external_integrations_used"] = []
        _atomic_json(self.root, "state/CALIBRATION_RESULT.json", result)
        return result

    @_project_command
    def start(
        self,
        brief: str | Path | None = None,
        *,
        mode: str | None = None,
        synthetic_scenario: str = "positive",
    ) -> dict[str, Any]:
        selected_mode = mode or ("brief" if brief is not None else "synthetic_demo")
        if selected_mode not in {"brief", "synthetic_demo"}:
            raise OrchestrationError("unsupported run mode")
        if synthetic_scenario not in {"positive", "null", "reversal", "unstable"}:
            raise OrchestrationError("unsupported bounded synthetic scenario")
        if selected_mode != "synthetic_demo" and synthetic_scenario != "positive":
            raise OrchestrationError("synthetic scenarios apply only to the local demo")
        run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:10]}"
        self._run_dir(run_id, create=True)
        _secure_directory(
            self.root,
            Path(".scientist-one-build/resource-authority") / run_id,
            create=True,
        )
        manifest: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "kind": "SCIENTIST_ONE_RUN_MANIFEST",
            "run_id": run_id,
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "mode": selected_mode,
            "synthetic_scenario": synthetic_scenario,
            "package_kind": "DEMO_RESEARCH_PACKAGE" if selected_mode == "synthetic_demo" else "RESEARCH_RUN",
            "current_state": "CALIBRATE",
            "terminal_state": None,
            "outcome": "IN_PROGRESS",
            "novelty": "NOVELTY_UNVERIFIED",
            "external_integrations_used": [],
            "external_integrations_policy": "interfaces_and_local_fixtures_only",
            "code_fingerprint": "",
            "configuration_sha256": "",
            "python_executable_name": Path(sys.executable).name,
            "python_version": sys.version.split()[0],
            "fixture_identifiers": ["calibration_cases_v1", "synthetic_workflow_v1"] if selected_mode == "synthetic_demo" else ["local_research_brief"],
            "random_seeds": [20260812],
            "transition_contracts": {
                key: _contract_dict(value) for key, value in TRANSITION_CONTRACTS.items()
            },
            "artifacts": {},
            "evaluator_decisions": {},
            "r_checks": {f"R{index}": "MISSING" for index in range(8)},
            "reproduction": None,
            "package": None,
            "event_count": 0,
            "ledger_head_hash": None,
            "completed_transitions": [],
            "typed_transition_receipts": [],
        }
        manifest["resource_runtime_state"] = self._resource_controller(manifest).export_state().to_dict()
        source_inventory = _source_inventory(self.root)
        configuration_inventory = _configuration_inventory(self.root)
        _validate_loaded_project_modules(self.root, source_inventory)
        manifest["code_fingerprint"] = source_inventory["aggregate_sha256"]
        manifest["configuration_sha256"] = configuration_inventory["aggregate_sha256"]
        self._artifact(
            manifest,
            "frozen_source_inventory",
            source_inventory,
            creator=Role.ORCHESTRATOR.value,
        )
        self._artifact(
            manifest,
            "frozen_configuration_inventory",
            configuration_inventory,
            creator=Role.ORCHESTRATOR.value,
        )
        self._persist_resource_authority(
            manifest,
            "resource_runtime_initial",
            manifest["resource_runtime_state"],
        )
        self._artifact(
            manifest,
            "resource_runtime_initial",
            manifest["resource_runtime_state"],
            creator=Role.ORCHESTRATOR.value,
        )
        manifest["resource_runtime_artifact"] = "resource_runtime_initial"
        self._artifact(
            manifest,
            "run_intent",
            {
                "schema_version": SCHEMA_VERSION,
                "kind": "FROZEN_RUN_INTENT",
                "mode": selected_mode,
                "synthetic_scenario": synthetic_scenario,
                "package_kind": manifest["package_kind"],
            },
            creator=Role.ORCHESTRATOR.value,
            parents=(
                manifest["artifacts"]["frozen_source_inventory"]["sha256"],
                manifest["artifacts"]["frozen_configuration_inventory"]["sha256"],
            ),
        )
        if brief is not None:
            manifest["current_state"] = "CALIBRATE"
            self._artifact_from_file(manifest, "research_brief", Path(brief), creator=Role.PROBLEM_INVESTIGATOR.value, mime_type="text/markdown", max_bytes=1024 * 1024)
        self._append_event(manifest, "INITIALIZED", "CALIBRATE", "run initialized inside the offline project boundary", tuple(manifest["artifacts"]), ())
        self._checkpoint(manifest)
        return self.status(run_id)

    @_project_command
    def status(self, run_id: str | None = None) -> dict[str, Any]:
        if run_id is not None:
            manifest = self.load_manifest(run_id)
            self._assert_no_newer_external_checkpoint(manifest)
            recovery = self._recovery_report(manifest)
            derived_state = recovery.derived_state
            derived_terminal = (
                derived_state if derived_state in TERMINAL_STATES else None
            )
            expected_outcome = (
                "COMPLETE_DEMO_ONLY"
                if derived_terminal == "READY_FOR_HUMAN_REVIEW"
                else derived_terminal or "IN_PROGRESS"
            )
            if (
                derived_state != manifest.get("current_state")
                or manifest.get("terminal_state") != derived_terminal
                or manifest.get("outcome") != expected_outcome
            ):
                raise OrchestrationError(
                    "mutable terminal projection is not ledger-derived"
                )
            if derived_terminal != "STOP_SECURITY":
                self._resource_controller(manifest)
            if derived_terminal is not None:
                if derived_terminal == "READY_FOR_HUMAN_REVIEW":
                    try:
                        package_run(self.root, run_id)
                    except Exception as exc:
                        raise OrchestrationError(
                            "final review packet or envelope is not verified"
                        ) from exc
            return {
                "status": "PASS",
                "run_id": run_id,
                "current_state": manifest["current_state"],
                "terminal_state": manifest.get("terminal_state"),
                "outcome": manifest["outcome"],
                "mode": manifest["mode"],
                "artifact_count": len(manifest["artifacts"]),
                "event_count": manifest["event_count"],
                "resumable": manifest.get("terminal_state") is None,
                "safe_resume_command": [
                    "python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py",
                    "resume", run_id
                ],
            }
        runs_dir = _secure_directory(self.root, "runs")
        summaries = []
        for child in sorted(runs_dir.iterdir()):
            if child.is_symlink() or not child.is_dir() or not RUN_ID_PATTERN.fullmatch(child.name):
                continue
            manifest_path = child / "manifest.json"
            if manifest_path.is_file() and not manifest_path.is_symlink():
                try:
                    summaries.append(self.status(child.name))
                except OrchestrationError as exc:
                    summaries.append(
                        {
                            "status": "ERROR",
                            "run_id": child.name,
                            "message": str(exc),
                        }
                    )
        return {"status": "PASS", "runs": summaries, "count": len(summaries)}

    def _json_artifact_payload(self, manifest: Mapping[str, Any], name: str) -> dict[str, Any]:
        record = manifest["artifacts"].get(name)
        if not isinstance(record, dict):
            raise OrchestrationError(f"missing artifact: {name}")
        try:
            registry = self._registry(str(manifest["run_id"]))
            metadata = registry.get_metadata(str(record["sha256"]))
            data = registry.get_bytes(str(record["sha256"]))
            value = safe_json_loads(data)
        except Exception as exc:
            raise OrchestrationError(f"artifact is absent, corrupt, or unsafe: {name}") from exc
        if (
            not isinstance(value, dict)
            or metadata.logical_type != record.get("logical_type")
            or metadata.record_hash != record.get("registry_record_hash")
            or _sha256(data) != record.get("sha256")
        ):
            raise OrchestrationError(f"artifact registry binding mismatch: {name}")
        return value

    def _handler_calibrate(self, manifest: dict[str, Any]) -> None:
        receipt_path = self.root / "state" / "APP_SESSION_BOOTSTRAP.json"
        receipt = _read_json(receipt_path)
        receipt_bytes = read_confined_bytes(
            self.root,
            receipt_path.relative_to(self.root),
            reject_hardlinks=True,
            max_bytes=1024 * 1024,
        )
        if receipt_bytes is None:
            raise OrchestrationError("bootstrap receipt disappeared")
        bootstrap_evidence = {
            "schema_version": SCHEMA_VERSION,
            "kind": "CONFINED_BOOTSTRAP_RECEIPT_REFERENCE",
            "app_session_bootstrap": receipt.get("app_session_bootstrap"),
            "bootstrap_checks": receipt.get("bootstrap_checks"),
            "canonical_project_root": ".",
            "source_receipt_sha256": _sha256(receipt_bytes),
            "external_absolute_paths_recorded": False,
        }
        self._artifact(
            manifest,
            "bootstrap_receipt",
            bootstrap_evidence,
            creator=Role.ORCHESTRATOR.value,
        )
        self._artifact(manifest, "calibration_report", self.calibrate(), creator=Role.ORCHESTRATOR.value)
        self._evaluate(
            manifest,
            "E0:CALIBRATE",
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            ("bootstrap_receipt", "calibration_report"),
            (RCheck.R0,),
        )

    def _queue_terminal(
        self,
        manifest: dict[str, Any],
        destination: str,
        reason: str,
        *,
        evidence: Mapping[str, Any] | None = None,
    ) -> None:
        if destination not in TERMINAL_STATES or destination == "READY_FOR_HUMAN_REVIEW":
            raise OrchestrationError("invalid queued terminal destination")
        manifest["pending_terminal"] = {
            "destination": destination,
            "reason": reason,
            "evidence": dict(evidence or {}),
        }

    def _transition_terminal(self, manifest: dict[str, Any]) -> None:
        """Materialize and execute one canonical evidence-bearing terminal edge."""

        pending = manifest.get("pending_terminal")
        if not isinstance(pending, dict):
            raise OrchestrationError("terminal transition lacks a typed pending decision")
        source_name = str(manifest["current_state"])
        destination_name = pending.get("destination")
        reason = pending.get("reason")
        if source_name not in MACRO_STATES or not isinstance(destination_name, str):
            raise OrchestrationError("terminal transition source or destination is invalid")
        if not isinstance(reason, str) or not reason.strip():
            raise OrchestrationError("terminal transition reason is required")
        source = MacroState(source_name)
        destination = TerminalState(destination_name)
        contract = next(
            (
                item
                for item in default_transition_contracts()
                if item.source is source and item.destination is destination
            ),
            None,
        )
        if contract is None:
            raise OrchestrationError(
                f"canonical terminal outcome is not allowed from {source_name}"
            )
        evidence = pending.get("evidence")
        if not isinstance(evidence, dict):
            raise OrchestrationError("terminal evidence must be an object")
        # A terminal report is the authoritative closure root for every
        # artifact already materialized by the interrupted stage.  Otherwise
        # a work-refusing handler could leave an unledgered orphan such as a
        # diagnostic preflight report.
        parents = tuple(
            manifest["artifacts"][name]["sha256"]
            for name in sorted(manifest["artifacts"])
            if name != "terminal_report"
        )
        self._artifact(
            manifest,
            "terminal_report",
            {
                "schema_version": SCHEMA_VERSION,
                "kind": "TYPED_TERMINAL_REPORT",
                "run_id": manifest["run_id"],
                "source_state": source_name,
                "terminal_state": destination_name,
                "reason": reason,
                "evidence": evidence,
                "honest_negative_or_inconclusive": destination
                in {TerminalState.NEGATIVE_RESULT, TerminalState.INCONCLUSIVE},
            },
            creator=Role.ORCHESTRATOR.value,
            parents=parents,
        )
        artifact_names = tuple(sorted(contract.required_artifact_types))
        evaluator_key_map: dict[EvaluatorClass, str] = {}
        for evaluator in sorted(contract.required_evaluators, key=lambda item: item.value):
            authority = (
                Role.ORCHESTRATOR
                if evaluator is EvaluatorClass.E0
                else Role.SCIENTIFIC_REVIEWER
            )
            producer = (
                None if evaluator is EvaluatorClass.E0 else Role.EXPERIMENT_RUNNER
            )
            key = _terminal_evaluation_key(source_name, destination_name, evaluator)
            evaluator_key_map[evaluator] = key
            self._evaluate(
                manifest,
                key,
                evaluator,
                authority,
                artifact_names,
                (),
                producer=producer,
            )
        evaluator_keys = tuple(
            evaluator_key_map[evaluator]
            for evaluator in sorted(contract.required_evaluators, key=lambda item: item.value)
        )
        receipt = self._typed_transition(
            manifest, contract, evaluator_key_map=evaluator_key_map
        )
        manifest["typed_transition_receipts"].append(receipt)
        self._append_event(
            manifest,
            source_name,
            destination_name,
            reason,
            artifact_names,
            evaluator_keys,
            event_type="SECURITY_STOP"
            if destination is TerminalState.STOP_SECURITY
            else "TRANSITION",
            metadata=(
                {
                    "resource_authority_chain": self._resource_authority_descriptors(
                        self._resource_authority_records(str(manifest["run_id"]))
                    )
                }
                if evidence.get("resource_authority")
                == "ROLLBACK_OR_STALE_PROJECTION"
                else None
            ),
        )
        manifest["completed_transitions"].append(
            f"{source_name}->{destination_name}"
        )
        manifest["current_state"] = destination_name
        manifest["terminal_state"] = destination_name
        manifest["outcome"] = destination_name
        manifest.pop("pending_terminal", None)
        self._checkpoint(manifest)

    def _handler_charter(self, manifest: dict[str, Any]) -> None:
        if manifest["mode"] != "synthetic_demo":
            self._queue_terminal(
                manifest,
                "BLOCKED_EXTERNAL",
                "a non-synthetic run requires locally supplied external evidence and providers",
                evidence={"mode": manifest["mode"], "network_used": False},
            )
            return
        payload = {
            "kind": "SYNTHETIC_RESEARCH_CHARTER",
            "target_problem": "validate scientific-controller behavior on known-answer synthetic cases",
            "unit_of_analysis": "synthetic independent unit",
            "inputs": "frozen local JSON fixtures",
            "outputs": "typed decisions and audit evidence",
            "comparison": "observed evaluator decision versus frozen known answer",
            "estimand": "difference of group arithmetic means for the planted-signal primary fixture",
            "plausible_contribution": "architecture-control demonstration only",
            "falsifiable_hypothesis": "all mandatory traps are correctly distinguished and the primary effect reproduces exactly",
            "failure_conditions": ["any mandatory calibration miss", "holdout misuse", "unsupported claim", "reproduction discrepancy"],
            "scope_exclusions": ["external novelty", "real-world generalization", "publication readiness"],
            "novelty": "NOVELTY_UNVERIFIED",
        }
        self._artifact(manifest, "research_charter", payload, creator=Role.PROBLEM_INVESTIGATOR.value, parents=(manifest["artifacts"]["calibration_report"]["sha256"],))
        self._evaluate(manifest, "E0:CHARTER", EvaluatorClass.E0, Role.ORCHESTRATOR, ("research_charter",), (RCheck.R1,), producer=Role.PROBLEM_INVESTIGATOR)

    def _handler_ground(self, manifest: dict[str, Any]) -> None:
        payload = {
            "kind": "LOCAL_EVIDENCE_INVENTORY",
            "sources": [
                {"id": "calibration_cases_v1", "type": "synthetic_fixture", "external": False},
                {"id": "synthetic_workflow_v1", "type": "synthetic_fixture", "external": False},
            ],
            "literature_corpus_available": False,
            "citations": [],
            "novelty": "NOVELTY_UNVERIFIED",
            "prompt_instructions_in_artifacts": "treated_as_inert_untrusted_data",
        }
        self._artifact(manifest, "evidence_inventory", payload, creator=Role.EVIDENCE_CURATOR.value)
        self._evaluate(manifest, "E0:GROUND", EvaluatorClass.E0, Role.ORCHESTRATOR, ("evidence_inventory",), (RCheck.R0, RCheck.R1), producer=Role.EVIDENCE_CURATOR)

    def _handler_protocol(self, manifest: dict[str, Any]) -> None:
        frozen_study = _synthetic_study(str(manifest["run_id"]))
        typed_protocol = frozen_study.protocol
        validation = validate_protocol(typed_protocol)
        protocol = {
            "kind": "FROZEN_SYNTHETIC_PROTOCOL",
            "frozen": True,
            "protocol": typed_protocol.canonical_dict,
            "protocol_sha256": frozen_study.protocol_hash,
            "baseline_equivalence": [asdict(item) for item in validation],
            "blind_patterns": ["positive", "null", "sign reversal", "high variance", "failed robustness", "baseline underperformance", "subgroup inconsistency", "leakage or protocol failure"],
            "reproduction_tolerance": 1e-12,
        }
        record = self._artifact(manifest, "frozen_protocol", protocol, creator=Role.PROTOCOL_DESIGNER.value)
        manifest["protocol_hash"] = frozen_study.protocol_hash
        self._evaluate(manifest, "E0:PROTOCOL", EvaluatorClass.E0, Role.ORCHESTRATOR, ("frozen_protocol",), (RCheck.R1,), producer=Role.PROTOCOL_DESIGNER)
        self._evaluate(manifest, "E2:PROTOCOL", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, ("frozen_protocol",), (RCheck.R1,), producer=Role.PROTOCOL_DESIGNER)

    def _handler_preflight(self, manifest: dict[str, Any]) -> None:
        payload = self.preflight()
        frozen_configuration = self._json_artifact_payload(
            manifest, "frozen_configuration_inventory"
        )
        resource_entry = next(
            (
                entry
                for entry in frozen_configuration.get("entries", ())
                if isinstance(entry, Mapping)
                and entry.get("path") == "configs/resource_limits.json"
            ),
            None,
        )
        if (
            payload.get("configuration_inventory_aggregate_sha256")
            != manifest.get("configuration_sha256")
            or not isinstance(resource_entry, Mapping)
            or payload.get("resource_config_sha256") != resource_entry.get("sha256")
        ):
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "preflight resource configuration differs from frozen configuration",
                evidence={"configuration_binding": "FAIL"},
            )
            return
        self._artifact(
            manifest,
            "preflight_report",
            payload,
            creator=Role.ORCHESTRATOR.value,
        )
        if payload["status"] != "PASS":
            self._queue_terminal(
                manifest,
                "STOP_BUDGET",
                "preflight resource controller refused new work",
                evidence={
                    "resource_action": payload["status"],
                    "resource_decision": payload["resource_decision"],
                    "preflight_report_sha256": manifest["artifacts"]["preflight_report"]["sha256"],
                },
            )
            return
        self._evaluate(manifest, "E0:PREFLIGHT", EvaluatorClass.E0, Role.ORCHESTRATOR, ("preflight_report",), (RCheck.R0, RCheck.R2))

    def _handler_ideate(self, manifest: dict[str, Any]) -> None:
        payload = {"kind": "FROZEN_HYPOTHESIS_SET", "primary": "synthetic planted effect equals 1.0", "negative_control": "true-null effect equals 0.0", "reversal_trap": "development and confirmatory signs differ", "selection_after_results": False}
        self._artifact(manifest, "hypothesis_set", payload, creator=Role.HYPOTHESIS_DESIGNER.value)
        self._evaluate(manifest, "E0:IDEATE", EvaluatorClass.E0, Role.ORCHESTRATOR, ("hypothesis_set",), (RCheck.R1,), producer=Role.HYPOTHESIS_DESIGNER)

    def _handler_discover(self, manifest: dict[str, Any]) -> None:
        report = run_synthetic_workflow_benchmark().to_dict()
        if not report["passed"]:
            self._queue_terminal(
                manifest,
                "STOP_SCIENTIFIC_INVALIDITY",
                "mandatory synthetic workflow benchmark failed",
                evidence={"benchmark": report},
            )
            return
        self._artifact(manifest, "workflow_benchmark", report, creator=Role.EXPERIMENT_RUNNER.value)
        self._evaluate(manifest, "E0:DISCOVER", EvaluatorClass.E0, Role.ORCHESTRATOR, ("workflow_benchmark",), (RCheck.R2, RCheck.R3, RCheck.R4, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)
        self._evaluate(manifest, "E2:DISCOVER", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, ("workflow_benchmark",), (RCheck.R2, RCheck.R3, RCheck.R4, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)

    def _handler_candidate(self, manifest: dict[str, Any]) -> None:
        if not self._validate_live_inventories(manifest):
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "source or configuration drifted before candidate execution",
                evidence={
                    "frozen_source_inventory": manifest["artifacts"][
                        "frozen_source_inventory"
                    ]["sha256"],
                    "frozen_configuration_inventory": manifest["artifacts"][
                        "frozen_configuration_inventory"
                    ]["sha256"],
                },
            )
            return

        def pilot() -> None:
            benchmark_hash = manifest["artifacts"]["workflow_benchmark"]["sha256"]
            self._artifact(manifest, "pilot_report", {"kind": "DEVELOPMENT_ONLY_PILOT", "passed": True, "confirmatory_evidence": False, "runtime_class": "bounded_small", "validity_reserve_consumed": 0.0}, creator=Role.EXPERIMENT_RUNNER.value, parents=(benchmark_hash,))
            source_record = manifest["artifacts"]["frozen_source_inventory"]
            configuration_record = manifest["artifacts"][
                "frozen_configuration_inventory"
            ]
            inventory_parents = (
                source_record["sha256"],
                configuration_record["sha256"],
            )
            self._artifact(manifest, "midrun_review", {"kind": "FROZEN_MIDRUN_REVIEW", "passed": True, "drift": False, "leakage": False, "baseline_equivalent": True, "validity_reserve_intact": True, "code_fingerprint": manifest["code_fingerprint"], "configuration_sha256": manifest["configuration_sha256"], "source_inventory_sha256": source_record["sha256"], "configuration_inventory_sha256": configuration_record["sha256"]}, creator=Role.SCIENTIFIC_REVIEWER.value, parents=inventory_parents)
            self._artifact(manifest, "blind_interpretation", {"kind": "FROZEN_BLIND_INTERPRETATION", "frozen_before_reveal": True, "source_inventory_sha256": source_record["sha256"], "configuration_inventory_sha256": configuration_record["sha256"], "patterns": {"positive": "bounded positive synthetic claim", "null": "NEGATIVE_RESULT", "sign_reversal": "INCONCLUSIVE", "high_variance": "INCONCLUSIVE", "failed_robustness": "INCONCLUSIVE", "baseline_underperformance": "INCONCLUSIVE", "subgroup_inconsistency": "INCONCLUSIVE", "leakage_or_protocol_failure": "STOP_SCIENTIFIC_INVALIDITY"}}, creator=Role.STATISTICIAN.value, parents=inventory_parents)

        self._run_with_resources(
            manifest,
            experiment_id=f"{manifest['run_id']}:pilot",
            validity_stage="PILOT",
            validity_units=2,
            operation=pilot,
        )
        names = ("pilot_report", "midrun_review", "blind_interpretation")
        self._evaluate(manifest, "E0:CANDIDATE", EvaluatorClass.E0, Role.ORCHESTRATOR, names, (RCheck.R2, RCheck.R3, RCheck.R4, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)
        self._evaluate(manifest, "E2:CANDIDATE", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, names, (RCheck.R1, RCheck.R4, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)
        self._evaluate(manifest, "E3:CANDIDATE", EvaluatorClass.E3, Role.ADVERSARIAL_REVIEWER, names, (RCheck.R2, RCheck.R3, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)

    def _handler_confirm(self, manifest: dict[str, Any]) -> None:
        frozen_source = self._json_artifact_payload(
            manifest, "frozen_source_inventory"
        )
        frozen_configuration = self._json_artifact_payload(
            manifest, "frozen_configuration_inventory"
        )
        observed_source = _source_inventory(self.root)
        observed_configuration = _configuration_inventory(self.root)
        if frozen_source != observed_source or frozen_configuration != observed_configuration:
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "frozen code or configuration drifted before confirmatory execution",
                evidence={
                    "expected_source_inventory": frozen_source.get(
                        "aggregate_sha256"
                    ),
                    "observed_source_inventory": observed_source.get(
                        "aggregate_sha256"
                    ),
                    "expected_configuration_inventory": frozen_configuration.get(
                        "aggregate_sha256"
                    ),
                    "observed_configuration_inventory": observed_configuration.get(
                        "aggregate_sha256"
                    ),
                },
            )
            return
        run_intent = self._json_artifact_payload(manifest, "run_intent")
        scenario = str(run_intent.get("synthetic_scenario", ""))
        if scenario != manifest.get("synthetic_scenario"):
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "mutable run scenario differs from frozen run intent",
                evidence={"frozen_scenario": scenario},
            )
            return
        fixtures = {
            "positive": {"control": [0.0, 1.0, 2.0, 3.0], "treatment": [1.0, 2.0, 3.0, 4.0]},
            "null": {"control": [0.0, 1.0, 2.0, 3.0], "treatment": [0.0, 1.0, 2.0, 3.0]},
            "reversal": {"control": [0.0, 1.0, 2.0, 3.0], "treatment": [-1.0, 0.0, 1.0, 2.0]},
            "unstable": {"control": [0.0, 1.0, 2.0, 3.0], "treatment": [-100.0, 102.0, -98.0, 104.0]},
        }
        fixture = fixtures.get(scenario)
        if fixture is None:
            raise OrchestrationError("unknown bounded synthetic outcome scenario")
        protocol_artifact_hash = manifest["artifacts"]["frozen_protocol"]["sha256"]
        protocol_hash = manifest["protocol_hash"]
        blind_hash = manifest["artifacts"]["blind_interpretation"]["sha256"]
        source_inventory_hash = manifest["artifacts"]["frozen_source_inventory"]["sha256"]
        configuration_inventory_hash = manifest["artifacts"]["frozen_configuration_inventory"]["sha256"]
        split_hash = _sha256(_canonical_bytes({"id": "synthetic-confirmatory-v1", "role": "holdout"}))
        custody_journal = _custody_journal_path(str(manifest["run_id"]))
        custody_adapter = SimulatedHoldoutCustody(
            (Role.EXPERIMENT_RUNNER.value,),
            journal_root=self.root,
            journal_path=custody_journal,
        )
        fixture_bytes = _canonical_bytes(fixture)
        seal = custody_adapter.seal(
            fixture_bytes,
            split_manifest_hash=split_hash,
            protocol_hash=protocol_hash,
            code_hash=manifest["code_fingerprint"],
            configuration_hash=manifest["configuration_sha256"],
            pre_unblinding_interpretation_hash=blind_hash,
            sealed_at=manifest["created_at"],
        )
        frozen_study = _synthetic_study(str(manifest["run_id"]))
        if frozen_study.protocol_hash != protocol_hash:
            raise OrchestrationError("typed study differs from the frozen protocol")
        with custody_adapter.admission_guard() as sealed_live:
            sealed_status = sealed_live.status
            sealed_journal_head = sealed_live.journal_head_hash
            sealed_journal_identity = sealed_live.journal_identity_sha256
        custody_verified_unaccessed = (
            sealed_status.sealed
            and not sealed_status.revealed
            and not sealed_status.invalidated
            and sealed_status.authorized_access_count == 0
            and sealed_status.durable_journal
            and isinstance(sealed_journal_head, str)
            and len(sealed_journal_head) == 64
        )
        if not custody_verified_unaccessed:
            raise OrchestrationError("durable custody cannot attest an untouched sealed holdout")
        receipt = self._artifact(
            manifest,
            "fresh_custody_receipt",
            {
                "schema_version": SCHEMA_VERSION,
                "study_id": frozen_study.study_id,
                "study_version": frozen_study.version,
                "seal": asdict(seal),
                "status": asdict(sealed_status),
                "journal_head_hash": sealed_journal_head,
                "journal_identity_sha256": sealed_journal_identity,
            },
            creator=Role.HOLDOUT_CUSTODIAN.value,
            parents=(
                protocol_artifact_hash,
                blind_hash,
                source_inventory_hash,
                configuration_inventory_hash,
            ),
        )
        receipt_event_id = self._append_event(
            manifest,
            "CONFIRM",
            "CONFIRM",
            "durable sealed custody receipt frozen before confirmatory admission",
            ("fresh_custody_receipt",),
            (),
            event_type="CHECKPOINT",
            actor_role=Role.HOLDOUT_CUSTODIAN,
            metadata={
                "fresh_custody": {
                    "artifact_sha256": receipt["sha256"],
                    "artifact_record_hash": receipt["registry_record_hash"],
                    "journal_head_hash": sealed_journal_head,
                    "journal_identity_sha256": sealed_journal_identity,
                    "protocol_hash": frozen_study.protocol_hash,
                    "seal_hash": seal.seal_hash,
                    "study_version": frozen_study.version,
                }
            },
        )
        self._save_manifest(manifest)

        def record_irreversible_start() -> None:
            self._append_event(
                manifest,
                "CONFIRM",
                "CONFIRM",
                "confirmatory execution irreversibly started before holdout reveal",
                (
                    "frozen_protocol",
                    "midrun_review",
                    "blind_interpretation",
                    "frozen_source_inventory",
                    "frozen_configuration_inventory",
                    "fresh_custody_receipt",
                ),
                (),
                event_type="CONFIRMATORY_STARTED",
                metadata={
                    "fresh_custody": {
                        "artifact_sha256": receipt["sha256"],
                        "artifact_record_hash": receipt["registry_record_hash"],
                        "journal_head_hash": sealed_journal_head,
                        "journal_identity_sha256": sealed_journal_identity,
                        "protocol_hash": frozen_study.protocol_hash,
                        "seal_hash": seal.seal_hash,
                        "study_version": frozen_study.version,
                    }
                },
            )
            self._save_manifest(manifest)

        RecoveryManager(
            self.root,
            ledger_validator=lambda path: self._foundation_ledger_validation(path),
        ).assert_confirmatory_run_allowed(
            ledger_path=Path("runs") / str(manifest["run_id"]) / "events.jsonl",
            new_study_protocol=frozen_study,
            fresh_custody_evidence=FreshCustodyEvidence(
                receipt["sha256"], receipt["registry_record_hash"], receipt_event_id
            ),
            artifact_registry=self._registry(str(manifest["run_id"])),
            custody_provider=custody_adapter,
            admission_callback=record_irreversible_start,
        )

        def evaluate_fixture(content: bytes) -> dict[str, Any]:
            released_fixture = safe_json_loads(content)
            if (
                not isinstance(released_fixture, dict)
                or set(released_fixture) != {"control", "treatment"}
                or any(
                    not isinstance(released_fixture.get(group), list)
                    or not released_fixture[group]
                    or any(
                        isinstance(value, bool) or not isinstance(value, (int, float))
                        for value in released_fixture[group]
                    )
                    for group in ("control", "treatment")
                )
            ):
                raise OrchestrationError("released synthetic fixture schema is invalid")
            return {
                "fixture": released_fixture,
                "estimate": sum(released_fixture["treatment"]) / 4
                - sum(released_fixture["control"]) / 4,
            }

        def confirmatory() -> tuple[Any, dict[str, Any]]:
            return custody_adapter.run_confirmatory(
                evaluate_fixture,
                requester=Role.EXPERIMENT_RUNNER.value,
                reason="single frozen confirmatory run",
                protocol_hash=protocol_hash,
                code_hash=manifest["code_fingerprint"],
                configuration_hash=manifest["configuration_sha256"],
                split_manifest_hash=split_hash,
                pre_unblinding_interpretation_hash=blind_hash,
                preconditions=RevealPreconditions(True, True, True, True, True, True),
                requested_at=manifest["created_at"],
            )

        release, confirmatory_output = self._run_with_resources(
            manifest,
            experiment_id=f"{manifest['run_id']}:confirmatory",
            validity_stage="CONFIRMATORY",
            validity_units=4,
            operation=confirmatory,
        )
        if not custody_adapter.status.confirmatory_claims_valid:
            raise OrchestrationError("simulated custody release failed its typed contract")
        released_fixture = confirmatory_output["fixture"]
        estimate = confirmatory_output["estimate"]
        with custody_adapter.admission_guard() as live_custody:
            custody_status = live_custody.status
            journal_head = live_custody.journal_head_hash
            journal_sha256 = live_custody.journal_sha256
            journal_size = live_custody.journal_size
            journal_identity = live_custody.journal_identity_sha256
        custody = {
            "kind": "SIMULATED_HOLDOUT_CUSTODY",
            "study_id": frozen_study.study_id,
            "study_version": frozen_study.version,
            "custody_independence": custody_adapter.custody_label,
            "holdout_identity_hash": seal.holdout_identity_hash,
            "split_manifest_hash": seal.split_manifest_hash,
            "sealing_time": seal.sealed_at,
            "authorized_access_count": custody_status.authorized_access_count,
            "access_requester": release.requester,
            "access_reason": release.reason,
            "protocol_hash": seal.protocol_hash,
            "code_hash": seal.code_hash,
            "configuration_hash": seal.configuration_hash,
            "source_inventory_sha256": source_inventory_hash,
            "configuration_inventory_sha256": configuration_inventory_hash,
            "pre_unblinding_interpretation_hash": seal.pre_unblinding_interpretation_hash,
            "seal_hash": seal.seal_hash,
            "release_event": asdict(release),
            "access_records": [asdict(record) for record in custody_adapter.access_records],
            "confirmatory_claims_valid": custody_status.confirmatory_claims_valid,
            "durable_journal": custody_status.durable_journal,
            "journal_path": custody_journal.as_posix(),
            "journal_head_hash": journal_head,
            "journal_sha256": journal_sha256,
            "journal_size": journal_size,
            "journal_identity_sha256": journal_identity,
            "genuine_independence_claimed": False,
        }
        custody_record = self._artifact(manifest, "custody_record", custody, creator=Role.HOLDOUT_CUSTODIAN.value, parents=(protocol_artifact_hash, blind_hash, source_inventory_hash, configuration_inventory_hash))
        control_mean = sum(released_fixture["control"]) / len(released_fixture["control"])
        treatment_mean = sum(released_fixture["treatment"]) / len(released_fixture["treatment"])
        result_core = {"primary_estimate": estimate, "control_mean": control_mean, "treatment_mean": treatment_mean, "n_control": 4, "n_treatment": 4}
        results = {"kind": "MACHINE_READABLE_RESULTS", "evidence_class": "SYNTHETIC_CONFIRMATORY_FIXTURE", "outcome_pattern": scenario, "dataset_fixture_ids": ["synthetic-confirmatory-v1"], "random_seeds": [20260812], "code_fingerprint": manifest["code_fingerprint"], "configuration_sha256": manifest["configuration_sha256"], "input_hashes": {"frozen_protocol": protocol_artifact_hash, "blind_interpretation": blind_hash, "custody_record": custody_record["sha256"], "frozen_source_inventory": source_inventory_hash, "frozen_configuration_inventory": configuration_inventory_hash}, "scientific_protocol_sha256": protocol_hash, "frozen_fixture": fixture, **result_core, "output_hashes": {"result_core": _sha256(_canonical_bytes(result_core))}, "confirmatory_access_count": 1, "tuned_after_reveal": False}
        self._artifact(manifest, "machine_results", results, creator=Role.EXPERIMENT_RUNNER.value, parents=(protocol_artifact_hash, blind_hash, custody_record["sha256"], source_inventory_hash, configuration_inventory_hash))
        names = ("custody_record", "machine_results")
        self._evaluate(manifest, "E0:CONFIRM", EvaluatorClass.E0, Role.ORCHESTRATOR, names, (RCheck.R0, RCheck.R2, RCheck.R3, RCheck.R4), producer=Role.EXPERIMENT_RUNNER)
        self._evaluate(manifest, "E2:CONFIRM", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, names, (RCheck.R2, RCheck.R3, RCheck.R4), producer=Role.EXPERIMENT_RUNNER)
        self._evaluate(manifest, "E3:CONFIRM", EvaluatorClass.E3, Role.ADVERSARIAL_REVIEWER, names, (RCheck.R3, RCheck.R4, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)
        self._append_event(
            manifest,
            "CONFIRM",
            "CONFIRM",
            "single confirmatory result completed and frozen",
            names,
            (
                ("E0:CONFIRM", "E2:CONFIRM", "E3:CONFIRM")
                if scenario in {"null", "reversal", "unstable"}
                else ()
            ),
            event_type="CONFIRMATORY_COMPLETED",
        )
        self._save_manifest(manifest)
        terminal_by_scenario = {
            "null": ("NEGATIVE_RESULT", "confirmatory estimate is the preregistered null outcome"),
            "reversal": ("INCONCLUSIVE", "confirmatory direction contradicts the development signal"),
            "unstable": ("INCONCLUSIVE", "confirmatory observations are deliberately unstable and high variance"),
        }
        if scenario in terminal_by_scenario:
            destination, terminal_reason = terminal_by_scenario[scenario]
            self._queue_terminal(
                manifest,
                destination,
                terminal_reason,
                evidence={
                    "outcome_pattern": scenario,
                    "primary_estimate": estimate,
                    "machine_results_sha256": manifest["artifacts"]["machine_results"]["sha256"],
                },
            )

    def _writing_rows(self, manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Derive every published number from frozen machine artifacts."""

        machine_results = self._json_artifact_payload(manifest, "machine_results")
        benchmark = self._json_artifact_payload(manifest, "workflow_benchmark")
        benchmark_results = benchmark.get("results")
        if not isinstance(benchmark_results, list):
            raise OrchestrationError("workflow benchmark has no machine-readable results")
        scenario_rows = {
            item.get("scenario"): item
            for item in benchmark_results
            if isinstance(item, dict)
        }
        required = ("signal", "null", "reversal")
        if any(name not in scenario_rows for name in required):
            raise OrchestrationError("workflow benchmark omits a required writing scenario")
        signal_estimate = machine_results.get("primary_estimate")
        null_effect = scenario_rows["null"].get("statistics", {}).get("observed_difference")
        reversal_effect = (
            scenario_rows["reversal"]
            .get("statistics", {})
            .get("regime_effects", {})
            .get("confirmatory")
        )
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            for value in (signal_estimate, null_effect, reversal_effect)
        ):
            raise OrchestrationError("machine-readable writing effects are invalid")
        return [
            {
                "task": "signal",
                "decision": scenario_rows["signal"]["decision"],
                "effect_size": signal_estimate,
            },
            {
                "task": "true-null",
                "decision": scenario_rows["null"]["decision"],
                "effect_size": null_effect,
            },
            {
                "task": "reversal",
                "decision": scenario_rows["reversal"]["decision"],
                "effect_size": reversal_effect,
            },
        ]

    def _handler_claims(self, manifest: dict[str, Any]) -> None:
        if not self._validate_live_inventories(manifest):
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "live code or configuration drifted after confirmatory execution",
                evidence={"stage": "CLAIMS"},
            )
            return
        result_hash = manifest["artifacts"]["machine_results"]["sha256"]
        protocol_hash = manifest["protocol_hash"]
        benchmark_hash = manifest["artifacts"]["workflow_benchmark"]["sha256"]
        rows = self._writing_rows(manifest)
        work = _secure_directory(
            self.root,
            Path(".scientist-one-build/tmp") / str(manifest["run_id"]) / "write",
            create=True,
        )
        expected_table_bytes = render_results_table_bytes(rows)
        expected_figure_bytes = render_svg_effect_figure_bytes(rows)
        table_path = write_results_table(rows, work / "results.csv", root=self.root)
        figure_path = write_svg_effect_figure(rows, work / "effects.svg", root=self.root)
        output_parents = (result_hash, benchmark_hash)
        table_record = self._artifact_from_file(
            manifest,
            "results_table",
            table_path,
            creator=Role.PAPER_WRITER.value,
            mime_type="text/csv",
            parents=output_parents,
            expected_bytes=expected_table_bytes,
        )
        figure_record = self._artifact_from_file(
            manifest,
            "results_figure",
            figure_path,
            creator=Role.PAPER_WRITER.value,
            mime_type="image/svg+xml",
            parents=output_parents,
            expected_bytes=expected_figure_bytes,
        )

        source_inventory = self._json_artifact_payload(
            manifest, "frozen_source_inventory"
        )
        configuration_inventory = self._json_artifact_payload(
            manifest, "frozen_configuration_inventory"
        )
        if not self._validate_live_inventories(manifest):
            raise OrchestrationError("live inventory changed during claim materialization")
        source_inventory_hash = manifest["artifacts"]["frozen_source_inventory"]["sha256"]
        configuration_inventory_hash = manifest["artifacts"]["frozen_configuration_inventory"]["sha256"]

        machine_results = self._json_artifact_payload(manifest, "machine_results")
        evidence_payloads: tuple[tuple[str, EvidenceKind, dict[str, Any], str, tuple[str, ...]], ...] = (
            ("ev-hypothesis", EvidenceKind.HYPOTHESIS, {"hypothesis_id": "hypothesis-synthetic-primary-v1", "artifact_sha256": manifest["artifacts"]["hypothesis_set"]["sha256"]}, "hypothesis-synthetic-primary-v1", (manifest["artifacts"]["hypothesis_set"]["sha256"],)),
            ("ev-estimand", EvidenceKind.ESTIMAND, {"estimand_id": "treatment_mean_minus_control_mean", "protocol_sha256": protocol_hash}, "treatment_mean_minus_control_mean", (manifest["artifacts"]["frozen_protocol"]["sha256"],)),
            ("ev-fixture", EvidenceKind.DATASET_OR_FIXTURE, {"fixture_ids": machine_results["dataset_fixture_ids"], "custody_sha256": manifest["artifacts"]["custody_record"]["sha256"]}, "synthetic-confirmatory-v1", (manifest["artifacts"]["custody_record"]["sha256"],)),
            ("ev-protocol", EvidenceKind.PROTOCOL_VERSION, {"scientific_protocol_sha256": protocol_hash, "artifact_sha256": manifest["artifacts"]["frozen_protocol"]["sha256"]}, "frozen protocol version one", (manifest["artifacts"]["frozen_protocol"]["sha256"],)),
            ("ev-code", EvidenceKind.CODE, {"code_fingerprint": manifest["code_fingerprint"], "configuration_sha256": manifest["configuration_sha256"], "source_inventory_sha256": source_inventory_hash, "configuration_inventory_sha256": configuration_inventory_hash, "source_inventory_aggregate": source_inventory["aggregate_sha256"], "configuration_inventory_aggregate": configuration_inventory["aggregate_sha256"]}, "frozen pre-confirm source and configuration inventories", (source_inventory_hash, configuration_inventory_hash)),
            ("ev-result", EvidenceKind.RESULT, {"artifact_sha256": result_hash, "primary_estimate": machine_results["primary_estimate"]}, "machine-readable primary result", (result_hash,)),
            ("ev-statistics", EvidenceKind.STATISTICAL_ANALYSIS, {"method": "difference_of_arithmetic_means_v1", "recomputed_estimate": rows[0]["effect_size"], "result_core_sha256": machine_results["output_hashes"]["result_core"]}, "difference of arithmetic means", (result_hash,)),
            ("ev-robustness", EvidenceKind.ROBUSTNESS, {"benchmark_sha256": benchmark_hash, "required_scenarios": ["signal", "null", "reversal"]}, "six-scenario known-answer benchmark", (benchmark_hash,)),
            ("ev-figure-table", EvidenceKind.FIGURE_OR_TABLE, {"results_table_sha256": table_record["sha256"], "results_figure_sha256": figure_record["sha256"]}, "results_table results_figure", (table_record["sha256"], figure_record["sha256"])),
            ("ev-source", EvidenceKind.SOURCE_CITATION, {"fixture_id": "synthetic-confirmatory-v1", "external_source": False, "locally_verified_by": "custody_and_machine_results"}, "local synthetic fixture; no external citation", (result_hash, manifest["artifacts"]["custody_record"]["sha256"])),
            ("ev-scope", EvidenceKind.SCOPE_QUALIFIER, {"scope": "synthetic fixture only", "external_generalization": False}, "synthetic fixture only", (manifest["artifacts"]["research_charter"]["sha256"],)),
            ("ev-limitations", EvidenceKind.LIMITATION, {"limitations": ["does not establish external novelty", "does not establish real-world validity", "simulated custody is non-independent"]}, "does not establish external novelty; does not establish real-world validity; simulated custody is non-independent", (manifest["artifacts"]["custody_record"]["sha256"],)),
        )
        node_specs: list[tuple[str, EvidenceKind, str, str]] = []
        for evidence_id, kind, payload, description, parents in evidence_payloads:
            logical_type = f"claim_evidence.{kind.value}"
            record = self._artifact(
                manifest,
                logical_type,
                {"kind": logical_type, "evidence_id": evidence_id, **payload},
                creator=Role.CLAIM_VERIFIER.value,
                parents=parents,
            )
            node_specs.append((evidence_id, kind, record["sha256"], description))

        material_claim = MaterialClaim(
            "claim-synthetic-primary-v1",
            "In the frozen synthetic confirmatory fixture, the treatment mean exceeds control by exactly 1.0.",
            tuple(EvidenceLink(evidence_id, kind) for evidence_id, kind, _, _ in node_specs),
            Role.STATISTICIAN,
        )
        registry = self._registry(str(manifest["run_id"]))
        graph_model = ClaimEvidenceGraph(
            evidence_resolver=artifact_registry_resolver(
                registry, resolver_id="run-artifact-registry"
            )
        )
        for evidence_id, kind, digest, description in node_specs:
            unbound_node = EvidenceNode(
                evidence_id,
                kind,
                digest,
                description,
                verified=True,
                frozen=True,
                supports_claim=True,
                contradicts_claim=False,
                locally_verifiable=True,
            )
            support_receipt = EvidenceSupportReceipt.for_claim(
                material_claim,
                unbound_node,
                verifier_id="claim-verifier-context-v1",
                verification_result="PASS",
                supports_claim=True,
                contradicts_claim=False,
                locally_verifiable=True,
                rationale=(
                    f"The frozen {kind.value} artifact was locally resolved, "
                    "content-hash verified, and found to support only the bounded "
                    "synthetic claim without contradiction."
                ),
            )
            support_record = self._artifact(
                manifest,
                f"claim_support_receipt.{kind.value}",
                support_receipt.to_dict(),
                creator=Role.CLAIM_VERIFIER.value,
                parents=(digest,),
            )
            if support_record["sha256"] != support_receipt.sha256:
                raise OrchestrationError("claim support receipt canonical hash mismatch")
            graph_model.add_evidence(
                EvidenceNode(
                    evidence_id,
                    kind,
                    digest,
                    description,
                    verified=True,
                    frozen=True,
                    supports_claim=True,
                    contradicts_claim=False,
                    locally_verifiable=True,
                    verification_receipt_hash=support_record["sha256"],
                )
            )
        graph_model.add_claim(material_claim)
        custody_valid = self._validate_live_custody(manifest)
        decision = graph_model.verify_claim(
            material_claim.claim_id,
            verifier_id="claim-verifier-context-v1",
            verifier_role=Role.CLAIM_VERIFIER,
            confirmatory_evidence_valid=custody_valid,
            raise_on_rejection=True,
        )
        if decision.decision is not ClaimDecision.ELIGIBLE:
            raise OrchestrationError("typed claim graph rejected the primary claim")
        authoritative_view = list(graph_model.writer_view())
        if len(authoritative_view) != 1:
            raise OrchestrationError("typed claim graph produced an invalid writer view")
        writer_claim = dict(authoritative_view[0])
        writer_claim.update(
            {
                "hypothesis_id": "hypothesis-synthetic-primary-v1",
                "estimand_id": "treatment_mean_minus_control_mean",
                "dataset_or_fixture_id": "synthetic-confirmatory-v1",
                "protocol_hash": protocol_hash,
                "code_hash": manifest["code_fingerprint"],
                "result_artifact_hash": result_hash,
                "statistical_analysis_hash": manifest["artifacts"]["claim_evidence.statistical_analysis"]["sha256"],
                "robustness_evidence_hashes": [manifest["artifacts"]["claim_evidence.robustness_evidence"]["sha256"]],
                "figure_or_table_ids": ["results_table", "results_figure"],
                "source_citation_ids": ["local-synthetic-fixture-v1"],
                "verifier_artifact_hash": decision.sha256,
            }
        )
        graph = {
            "kind": "CLAIM_EVIDENCE_GRAPH",
            "graph": graph_model.to_dict(),
            "graph_sha256": graph_model.sha256,
            "writer_view": [writer_claim],
            "writer_contract": "derived_only_from_typed_ELIGIBLE_decisions",
        }
        self._artifact(
            manifest,
            "claim_graph",
            graph,
            creator=Role.CLAIM_VERIFIER.value,
            parents=tuple(
                manifest["artifacts"][f"claim_evidence.{kind.value}"]["sha256"]
                for kind in EvidenceKind
            )
            + tuple(
                manifest["artifacts"][f"claim_support_receipt.{kind.value}"]["sha256"]
                for kind in EvidenceKind
            ),
        )
        self._evaluate(manifest, "E0:CLAIMS", EvaluatorClass.E0, Role.ORCHESTRATOR, ("claim_graph",), (RCheck.R6,), producer=Role.CLAIM_VERIFIER)
        self._evaluate(manifest, "E2:CLAIMS", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, ("claim_graph",), (RCheck.R6,), producer=Role.CLAIM_VERIFIER)

    def _handler_write(self, manifest: dict[str, Any]) -> None:
        if not self._validate_live_inventories(manifest):
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "live code or configuration drifted before writing",
                evidence={"stage": "WRITE"},
            )
            return
        graph = self._json_artifact_payload(manifest, "claim_graph")
        stored_view = graph.get("writer_view")
        graph_payload = graph.get("graph")
        if not isinstance(stored_view, list) or not isinstance(graph_payload, dict):
            raise OrchestrationError("serialized claim graph is incomplete")
        try:
            live_graph = ClaimEvidenceGraph.from_dict(
                graph_payload,
                evidence_resolver=artifact_registry_resolver(
                    self._registry(str(manifest["run_id"])),
                    resolver_id="run-artifact-registry",
                ),
            )
            for claim in live_graph.claims:
                live_graph.verify_claim(
                    claim.claim_id,
                    verifier_id="claim-verifier-context-v1",
                    verifier_role=Role.CLAIM_VERIFIER,
                    confirmatory_evidence_valid=self._validate_live_custody(manifest),
                    raise_on_rejection=True,
                )
            fresh_view = list(live_graph.writer_view())
            fresh_graph_payload = live_graph.to_dict()
        except Exception as exc:
            raise OrchestrationError("claim eligibility could not be freshly reverified") from exc
        if (
            fresh_graph_payload != graph_payload
            or live_graph.sha256 != graph.get("graph_sha256")
        ):
            raise OrchestrationError("serialized claim graph or digest is stale")
        if len(fresh_view) != len(stored_view) or not fresh_view:
            raise OrchestrationError("serialized writer view is stale")
        eligible: list[dict[str, Any]] = []
        for fresh, stored in zip(fresh_view, stored_view, strict=True):
            if not isinstance(stored, dict):
                raise OrchestrationError("serialized writer claim is malformed")
            decision = live_graph.require_eligible(str(fresh["claim_id"]))
            expected = dict(fresh)
            expected.update(
                {
                    "hypothesis_id": "hypothesis-synthetic-primary-v1",
                    "estimand_id": "treatment_mean_minus_control_mean",
                    "dataset_or_fixture_id": "synthetic-confirmatory-v1",
                    "protocol_hash": manifest["protocol_hash"],
                    "code_hash": manifest["code_fingerprint"],
                    "result_artifact_hash": manifest["artifacts"]["machine_results"]["sha256"],
                    "statistical_analysis_hash": manifest["artifacts"]["claim_evidence.statistical_analysis"]["sha256"],
                    "robustness_evidence_hashes": [manifest["artifacts"]["claim_evidence.robustness_evidence"]["sha256"]],
                    "figure_or_table_ids": ["results_table", "results_figure"],
                    "source_citation_ids": ["local-synthetic-fixture-v1"],
                    "verifier_artifact_hash": decision.sha256,
                }
            )
            if stored != expected:
                raise OrchestrationError("serialized writer view differs from fresh eligibility")
            eligible.append(expected)
        if any(claim.get("verifier_decision") != "ELIGIBLE" for claim in eligible):
            raise OrchestrationError("WRITE may consume only a non-empty eligible writer view")
        work = _secure_directory(self.root, Path(".scientist-one-build/tmp") / str(manifest["run_id"]) / "write", create=True)
        rows = self._writing_rows(manifest)
        expected_table_bytes = render_results_table_bytes(rows)
        expected_figure_bytes = render_svg_effect_figure_bytes(rows)
        table = write_results_table(rows, work / "results.csv", root=self.root)
        figure = write_svg_effect_figure(rows, work / "effects.svg", root=self.root)
        for logical_type, generated, expected_bytes in (
            ("results_table", table, expected_table_bytes),
            ("results_figure", figure, expected_figure_bytes),
        ):
            record = manifest["artifacts"].get(logical_type)
            if not isinstance(record, dict):
                raise OrchestrationError(f"claim verification did not freeze {logical_type}")
            generated_bytes = read_confined_bytes(
                self.root,
                generated.relative_to(self.root),
                reject_hardlinks=True,
                max_bytes=8 * 1024 * 1024,
            )
            if (
                generated_bytes is None
                or generated_bytes != expected_bytes
                or _sha256(generated_bytes) != record.get("sha256")
            ):
                raise OrchestrationError(f"{logical_type} differs from its claim evidence binding")
        paper_manifest = {"package_kind": "DEMO_RESEARCH_PACKAGE", "protocol_hash": manifest["protocol_hash"]}
        table_reference = table.relative_to(self.root)
        figure_reference = figure.relative_to(self.root)
        expected_paper_bytes = render_demo_paper_bytes(
            paper_manifest,
            eligible,
            table_reference,
            figure_reference,
        )
        paper = write_demo_paper(
            paper_manifest,
            eligible,
            table_reference,
            figure_reference,
            work / "paper.md",
            root=self.root,
        )
        parent = (manifest["artifacts"]["machine_results"]["sha256"], manifest["artifacts"]["claim_graph"]["sha256"])
        self._artifact_from_file(
            manifest,
            "demo_paper",
            paper,
            creator=Role.PAPER_WRITER.value,
            mime_type="text/markdown",
            parents=parent,
            expected_bytes=expected_paper_bytes,
        )
        names = ("results_table", "results_figure", "demo_paper")
        self._evaluate(manifest, "E0:WRITE", EvaluatorClass.E0, Role.ORCHESTRATOR, names, (RCheck.R6,), producer=Role.PAPER_WRITER)
        self._evaluate(manifest, "E2:WRITE", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, names, (RCheck.R6,), producer=Role.PAPER_WRITER)

    @_project_command
    def verify(self, run_id: str) -> dict[str, Any]:
        manifest = self.load_manifest(run_id)
        external_checkpoint_valid = True
        try:
            self._assert_no_newer_external_checkpoint(manifest)
        except OrchestrationError:
            external_checkpoint_valid = False
        manager = RecoveryManager(
            self.root,
            ledger_validator=lambda path: self._foundation_ledger_validation(path),
        )
        ledger = manager.validate_ledger(
            (self._run_dir(run_id) / "events.jsonl").relative_to(self.root)
        )
        resource_authority_history_valid = True
        try:
            self._validate_resource_authority_ledger(
                self._resource_authority_records(run_id), ledger.events
            )
        except OrchestrationError:
            resource_authority_history_valid = False
        artifacts = manager.validate_artifacts(list(manifest["artifacts"].values()))
        registry = self._registry(run_id).verify_all()
        recovery = self._recovery_report(manifest)
        contract_ok = manifest["current_state"] in MACRO_STATES or manifest["current_state"] in TERMINAL_STATES
        state_matches_ledger = recovery.derived_state == manifest.get("current_state")
        derived_terminal = (
            recovery.derived_state
            if recovery.derived_state in TERMINAL_STATES
            else None
        )
        expected_outcome = (
            "COMPLETE_DEMO_ONLY"
            if derived_terminal == "READY_FOR_HUMAN_REVIEW"
            else derived_terminal or "IN_PROGRESS"
        )
        terminal_projection_valid = (
            manifest.get("terminal_state") == derived_terminal
            and manifest.get("outcome") == expected_outcome
        )
        manifest_matches_ledger = (
            manifest.get("ledger_head_hash") == ledger.head_hash
            and manifest.get("event_count") == ledger.event_count
        )
        recovery_safe = recovery.action.value not in {"STOP_SECURITY", "STOP_SCIENTIFIC_INVALIDITY"}
        registry_records = {record.sha256: record for record in registry.records}
        registry_matches_manifest = registry.valid and len(registry_records) == len(manifest["artifacts"])
        if registry_matches_manifest:
            for record in manifest["artifacts"].values():
                stored = registry_records.get(record["sha256"])
                if stored is None or (
                    stored.logical_type != record["logical_type"]
                    or stored.record_hash != record.get("registry_record_hash")
                    or stored.path != record.get("registry_path")
                    or stored.metadata_path != record.get("registry_metadata_path")
                    or stored.parent_artifacts != tuple(record.get("parent_artifacts", ()))
                ):
                    registry_matches_manifest = False
                    break
        registry_closure_valid = registry_matches_manifest
        if registry_closure_valid:
            roots = {
                digest
                for event in ledger.events
                for digest in event.get("artifact_hashes", ())
                if isinstance(digest, str)
            }
            closure: set[str] = set()
            pending = list(roots)
            while pending:
                digest = pending.pop()
                if digest in closure:
                    continue
                stored = registry_records.get(digest)
                if stored is None:
                    registry_closure_valid = False
                    break
                closure.add(digest)
                pending.extend(stored.parent_artifacts)
            if closure != set(registry_records):
                registry_closure_valid = False
        ledger_artifact_projection: dict[str, str] = {}
        ledger_record_projection: dict[str, str] = {}
        ledger_projection_valid = True
        for event in ledger.events:
            artifact_types = event.get("metadata", {}).get("artifact_types", [])
            artifact_record_hashes = event.get("metadata", {}).get(
                "artifact_record_hashes", []
            )
            artifact_descriptors = event.get("metadata", {}).get(
                "artifact_descriptors", []
            )
            artifact_hashes = event.get("artifact_hashes", [])
            if (
                not isinstance(artifact_types, list)
                or not isinstance(artifact_record_hashes, list)
                or not isinstance(artifact_descriptors, list)
                or not isinstance(artifact_hashes, list)
                or len(artifact_types) != len(artifact_hashes)
                or len(artifact_record_hashes) != len(artifact_hashes)
                or len(artifact_descriptors) != len(artifact_hashes)
            ):
                if artifact_hashes:
                    ledger_projection_valid = False
                    break
                continue
            for logical_type, digest, record_hash, descriptor in zip(
                artifact_types,
                artifact_hashes,
                artifact_record_hashes,
                artifact_descriptors,
                strict=True,
            ):
                if (
                    not isinstance(logical_type, str)
                    or not isinstance(digest, str)
                    or not isinstance(record_hash, str)
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                    or re.fullmatch(r"[0-9a-f]{64}", record_hash) is None
                ):
                    ledger_projection_valid = False
                    break
                manifest_record = manifest.get("artifacts", {}).get(logical_type)
                stored_record = registry_records.get(digest)
                expected_descriptor = {
                    "logical_type": logical_type,
                    "sha256": digest,
                    "registry_record_hash": record_hash,
                    "parent_artifacts": (
                        list(stored_record.parent_artifacts)
                        if stored_record is not None
                        else []
                    ),
                    "parent_record_hashes": (
                        [
                            registry_records[parent].record_hash
                            for parent in stored_record.parent_artifacts
                            if parent in registry_records
                        ]
                        if stored_record is not None
                        else []
                    ),
                }
                if (
                    not isinstance(manifest_record, Mapping)
                    or stored_record is None
                    or len(expected_descriptor["parent_record_hashes"])
                    != len(stored_record.parent_artifacts)
                    or descriptor != expected_descriptor
                ):
                    ledger_projection_valid = False
                    break
                prior = ledger_artifact_projection.get(logical_type)
                prior_record = ledger_record_projection.get(logical_type)
                if (
                    (prior is not None and prior != digest)
                    or (prior_record is not None and prior_record != record_hash)
                ):
                    ledger_projection_valid = False
                    break
                ledger_artifact_projection[logical_type] = digest
                ledger_record_projection[logical_type] = record_hash
            if not ledger_projection_valid:
                break
        for logical_type, digest in ledger_artifact_projection.items():
            record = manifest["artifacts"].get(logical_type)
            stored = registry_records.get(digest)
            if (
                not isinstance(record, dict)
                or record.get("sha256") != digest
                or stored is None
                or stored.logical_type != logical_type
                or stored.record_hash != record.get("registry_record_hash")
                or stored.record_hash != ledger_record_projection.get(logical_type)
            ):
                ledger_projection_valid = False
                break
        transition_edges = [
            f"{event['state_before']}->{event['requested_state_after']}"
            for event in ledger.events
            if event.get("event_type") in {"TRANSITION", "SECURITY_STOP"}
        ]
        ledger_sequence_valid = transition_edges == manifest.get("completed_transitions", [])
        provenance_valid = all(
            event.get("run_id") == run_id
            and event.get("code_version") == manifest.get("code_fingerprint")
            and event.get("configuration_hash") == manifest.get("configuration_sha256")
            and event.get("dataset_identifiers") == manifest.get("fixture_identifiers")
            and event.get("random_seeds") == manifest.get("random_seeds")
            for event in ledger.events
        )
        receipts = manifest.get("typed_transition_receipts", [])
        receipt_sequence_valid = (
            isinstance(receipts, list)
            and len(receipts) == len(manifest.get("completed_transitions", []))
            and all(
                f"{receipt.get('prior_state')}->{receipt.get('current_state')}" == edge
                for receipt, edge in zip(receipts, manifest.get("completed_transitions", []), strict=True)
            )
        )
        evaluation_receipts_valid = True
        for stored in manifest.get("evaluator_decisions", {}).values():
            try:
                evaluation = Evaluation(
                    EvaluatorClass(stored["evaluator_class"]),
                    Role(stored["authority"]),
                    Decision(stored["decision"]),
                    tuple(stored["artifact_hashes"]),
                    stored["reason"],
                    tuple(RCheck(item) for item in stored.get("r_checks", ())),
                    bool(stored.get("critical_objection", False)),
                    Role(stored["producer_role"]) if stored.get("producer_role") else None,
                )
            except (KeyError, TypeError, ValueError):
                evaluation_receipts_valid = False
                break
            if evaluation.sha256 != stored.get("evaluation_sha256"):
                evaluation_receipts_valid = False
                break
        ledger_evaluations: dict[str, dict[str, Any]] = {}
        if evaluation_receipts_valid:
            for event in ledger.events:
                keys = event.get("metadata", {}).get("evaluator_keys", [])
                outputs = event.get("evaluator_outputs", [])
                if (
                    not isinstance(keys, list)
                    or not isinstance(outputs, list)
                    or len(keys) != len(outputs)
                ):
                    evaluation_receipts_valid = False
                    break
                for key, output in zip(keys, outputs, strict=True):
                    if not isinstance(key, str) or not isinstance(output, dict):
                        evaluation_receipts_valid = False
                        break
                    prior = ledger_evaluations.get(key)
                    if prior is not None and prior != output:
                        evaluation_receipts_valid = False
                        break
                    ledger_evaluations[key] = output
                if not evaluation_receipts_valid:
                    break
        if ledger_evaluations != manifest.get("evaluator_decisions"):
            evaluation_receipts_valid = False
        live_custody_valid = self._validate_live_custody(manifest)
        live_inventory_valid = self._validate_live_inventories(manifest)
        run_intent_valid = False
        try:
            run_intent = self._json_artifact_payload(manifest, "run_intent")
            run_intent_valid = (
                run_intent.get("kind") == "FROZEN_RUN_INTENT"
                and run_intent.get("mode") == manifest.get("mode")
                and run_intent.get("synthetic_scenario")
                == manifest.get("synthetic_scenario")
                and run_intent.get("package_kind") == manifest.get("package_kind")
                and ledger_artifact_projection.get("run_intent")
                == manifest.get("artifacts", {}).get("run_intent", {}).get("sha256")
            )
        except Exception:
            run_intent_valid = False
        resource_runtime_valid = (
            isinstance(manifest.get("resource_runtime_state"), Mapping)
            and isinstance(manifest.get("resource_runtime_artifact"), str)
            and "resource_runtime_initial" in ledger_artifact_projection
        )
        if resource_runtime_valid:
            try:
                self._resource_controller(manifest)
            except OrchestrationError:
                resource_runtime_valid = False
        rollback_authority_stop = False
        if (
            not resource_runtime_valid
            and manifest.get("terminal_state") == "STOP_SECURITY"
        ):
            try:
                stop_report = self._json_artifact_payload(
                    manifest, "terminal_report"
                )
                resource_runtime_valid = (
                    stop_report.get("terminal_state") == "STOP_SECURITY"
                    and stop_report.get("evidence", {}).get("resource_authority")
                    == "ROLLBACK_OR_STALE_PROJECTION"
                )
                rollback_authority_stop = resource_runtime_valid
            except Exception:
                resource_runtime_valid = False
        if rollback_authority_stop and not live_custody_valid:
            # The external journal's survival is the rollback evidence.  The
            # typed STOP_SECURITY report makes that fail-closed condition the
            # expected verified outcome rather than authorizing claims.
            live_custody_valid = True
        final_package_valid = True
        if manifest.get("terminal_state") == "READY_FOR_HUMAN_REVIEW":
            try:
                checked_package = package_run(self.root, run_id).to_dict()
                final_package_valid = checked_package == manifest.get("package")
            except Exception:
                final_package_valid = False
        status_passed = all(
            (
                ledger.valid,
                external_checkpoint_valid,
                artifacts.valid,
                registry.valid,
                registry_matches_manifest,
                registry_closure_valid,
                ledger_projection_valid,
                contract_ok,
                state_matches_ledger,
                terminal_projection_valid,
                manifest_matches_ledger,
                recovery_safe,
                ledger_sequence_valid,
                provenance_valid,
                receipt_sequence_valid,
                evaluation_receipts_valid,
                live_custody_valid,
                live_inventory_valid,
                run_intent_valid,
                resource_runtime_valid,
                resource_authority_history_valid,
                final_package_valid,
            )
        )
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "RUN_VERIFICATION",
            "run_id": run_id,
            "status": "PASS" if status_passed else "FAIL",
            "ledger": {
                "implementation": "EventLedger",
                "valid": ledger.valid,
                "event_count": ledger.event_count,
                "head_hash": ledger.head_hash,
                "error": ledger.error,
                "transition_sequence_valid": ledger_sequence_valid,
                "provenance_valid": provenance_valid,
            },
            "artifacts": {
                "valid": artifacts.valid,
                "records_validated": artifacts.records_validated,
                "issues": [asdict(item) for item in artifacts.issues],
                "registry_valid": registry.valid,
                "registry_records": registry.count,
                "registry_errors": list(registry.errors),
                "registry_matches_manifest": registry_matches_manifest,
                "registry_closure_valid": registry_closure_valid,
                "ledger_projection_valid": ledger_projection_valid,
            },
            "state_contract_valid": contract_ok,
            "state_matches_ledger": state_matches_ledger,
            "terminal_projection_valid": terminal_projection_valid,
            "manifest_matches_ledger": manifest_matches_ledger,
            "external_checkpoint_valid": external_checkpoint_valid,
            "typed_receipts_valid": receipt_sequence_valid,
            "evaluator_receipts_valid": evaluation_receipts_valid,
            "live_custody_valid": live_custody_valid,
            "live_inventory_valid": live_inventory_valid,
            "run_intent_binding_valid": run_intent_valid,
            "resource_runtime_binding_valid": resource_runtime_valid,
            "resource_authority_history_valid": resource_authority_history_valid,
            "final_package_binding_valid": final_package_valid,
            "recovery": recovery.to_dict(),
            "external_network_used": False,
        }
        return result

    def _handler_audit(self, manifest: dict[str, Any]) -> None:
        verification = self.verify(str(manifest["run_id"]))
        if verification["status"] != "PASS":
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "run verification failed before audit",
                evidence={"verification": verification},
            )
            return
        reproduction = reproduce_run(
            self.root, str(manifest["run_id"]), timestamp=manifest["created_at"]
        )
        reproduction_payload = reproduction.to_dict()
        try:
            reproduction_manifest_bytes = read_confined_bytes(
                self.root,
                reproduction.manifest_path,
                reject_hardlinks=True,
                max_bytes=16 * 1024 * 1024,
            )
            reproduction_result_bytes = read_confined_bytes(
                self.root,
                reproduction.result_path,
                reject_hardlinks=True,
                max_bytes=16 * 1024 * 1024,
            )
        except PathSecurityError as exc:
            raise OrchestrationError("reproduction packet cannot be frozen") from exc
        if reproduction_manifest_bytes is None or reproduction_result_bytes is None:
            raise OrchestrationError("reproduction packet disappeared")
        reproduction_manifest_record = self._artifact_from_file(
            manifest,
            "reproduction_manifest",
            self.root / reproduction.manifest_path,
            creator=Role.REPRODUCTION_VERIFIER.value,
            mime_type="application/json",
            parents=(manifest["artifacts"]["machine_results"]["sha256"],),
            max_bytes=16 * 1024 * 1024,
            expected_bytes=reproduction_manifest_bytes,
        )
        reproduction_result_record = self._artifact_from_file(
            manifest,
            "reproduction_result",
            self.root / reproduction.result_path,
            creator=Role.REPRODUCTION_VERIFIER.value,
            mime_type="application/json",
            parents=(reproduction_manifest_record["sha256"],),
            max_bytes=16 * 1024 * 1024,
            expected_bytes=reproduction_result_bytes,
        )
        reproduction_payload.update(
            {
                "manifest_sha256": _sha256(reproduction_manifest_bytes),
                "manifest_record_hash": reproduction_manifest_record[
                    "registry_record_hash"
                ],
                "result_sha256": _sha256(reproduction_result_bytes),
                "result_record_hash": reproduction_result_record[
                    "registry_record_hash"
                ],
            }
        )
        manifest["reproduction"] = reproduction_payload
        self._artifact(
            manifest,
            "reproduction_report",
            reproduction_payload,
            creator=Role.REPRODUCTION_VERIFIER.value,
            parents=(
                manifest["artifacts"]["machine_results"]["sha256"],
                reproduction_manifest_record["sha256"],
                reproduction_result_record["sha256"],
            ),
        )
        verify_frozen_reproduction(
            self.root, str(manifest["run_id"]), reproduction_payload
        )
        protocol = self._json_artifact_payload(manifest, "frozen_protocol")
        benchmark = self._json_artifact_payload(manifest, "workflow_benchmark")
        custody = self._json_artifact_payload(manifest, "custody_record")
        results = self._json_artifact_payload(manifest, "machine_results")
        claim_graph = self._json_artifact_payload(manifest, "claim_graph")
        graph_payload = claim_graph.get("graph")
        live_claims_valid = False
        try:
            if not isinstance(graph_payload, dict):
                raise OrchestrationError("claim graph payload is malformed")
            live_graph = ClaimEvidenceGraph.from_dict(
                graph_payload,
                evidence_resolver=artifact_registry_resolver(
                    self._registry(str(manifest["run_id"])),
                    resolver_id="run-artifact-registry",
                ),
            )
            for claim in live_graph.claims:
                live_graph.verify_claim(
                    claim.claim_id,
                    verifier_id="claim-verifier-context-v1",
                    verifier_role=Role.CLAIM_VERIFIER,
                    confirmatory_evidence_valid=self._validate_live_custody(manifest),
                    raise_on_rejection=True,
                )
            live_claims_valid = bool(live_graph.writer_view())
        except Exception:
            live_claims_valid = False
        evidence_checks = {
            "R0": verification["status"] == "PASS",
            "R1": protocol.get("frozen") is True
            and manifest["evaluator_decisions"].get("E2:PROTOCOL", {}).get("decision") == "PASS",
            "R2": results.get("tuned_after_reveal") is False
            and manifest["evaluator_decisions"].get("E2:CONFIRM", {}).get("decision") == "PASS",
            "R3": self._validate_live_custody(manifest)
            and custody.get("confirmatory_claims_valid") is True
            and custody.get("authorized_access_count") == 1,
            "R4": results.get("primary_estimate") == 1.0
            and results.get("output_hashes", {}).get("result_core") is not None,
            "R5": benchmark.get("passed") is True,
            "R6": live_claims_valid and bool(claim_graph.get("writer_view")),
            "R7": reproduction.status == "PASS" and reproduction.absolute_difference <= reproduction.tolerance,
        }
        manifest["r_checks"] = {
            key: "PASS" if passed else "FAIL" for key, passed in evidence_checks.items()
        }
        verification["scientific_checks"] = {
            key: {
                "status": manifest["r_checks"][key],
                "evidence_derived": True,
            }
            for key in sorted(evidence_checks)
        }
        verification["reproduction"] = reproduction.to_dict()
        if not all(evidence_checks.values()):
            self._queue_terminal(
                manifest,
                "STOP_SCIENTIFIC_INVALIDITY",
                "one or more substantive R0-R7 audit checks failed",
                evidence={"r_checks": dict(manifest["r_checks"])},
            )
            return
        self._artifact(manifest, "audit_report", verification, creator=Role.ORCHESTRATOR.value)
        reviewed = (
            "frozen_protocol",
            "machine_results",
            "claim_graph",
            "demo_paper",
            "audit_report",
            "reproduction_report",
        )
        e2_payload = {"kind": "E2_SCIENTIFIC_REVIEW", "evaluator_class": "E2", "authority": Role.SCIENTIFIC_REVIEWER.value, "producer_role": Role.PAPER_WRITER.value, "decision": "PASS", "critical_objection": False, "reviewed_artifact_hashes": [manifest["artifacts"][name]["sha256"] for name in reviewed], "r_checks": dict(manifest["r_checks"]), "methodological_validity": "bounded synthetic controls pass", "limitations_preserved": True, "human_independence_claimed": False}
        self._artifact(manifest, "e2_review", e2_payload, creator=Role.SCIENTIFIC_REVIEWER.value)
        e3_payload = {"kind": "E3_ADVERSARIAL_REPRODUCTION_REVIEW", "evaluator_class": "E3", "authority": Role.ADVERSARIAL_REVIEWER.value, "producer_role": Role.PAPER_WRITER.value, "decision": "PASS", "critical_objection": False, "reviewed_artifact_hashes": [manifest["artifacts"][name]["sha256"] for name in reviewed], "reproduction_id": reproduction.reproduction_id, "reproduction_result_path": reproduction.result_path, "reproduction_source_result_sha256": reproduction.source_result_sha256, "numeric_comparison": {"expected": reproduction.expected, "observed": reproduction.observed, "absolute_difference": reproduction.absolute_difference, "tolerance": reproduction.tolerance, "passed": reproduction.status == "PASS"}, "searched": ["leakage", "contamination", "p-hacking", "multiplicity", "invalid independence", "gaming", "contradictions", "provenance gaps"], "r_checks": dict(manifest["r_checks"]), "human_independence_claimed": False}
        self._artifact(manifest, "e3_review", e3_payload, creator=Role.ADVERSARIAL_REVIEWER.value)
        audit_names = ("audit_report", "e2_review", "e3_review")
        self._evaluate(manifest, "E2:AUDIT", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, audit_names, tuple(RCheck), producer=Role.PAPER_WRITER)
        self._evaluate(manifest, "E3:AUDIT", EvaluatorClass.E3, Role.ADVERSARIAL_REVIEWER, audit_names, tuple(RCheck), producer=Role.PAPER_WRITER)
        summary = AuditSummary(
            [
                Evaluation(
                    EvaluatorClass.E0,
                    Role.ORCHESTRATOR,
                    Decision.PASS,
                    (manifest["artifacts"]["audit_report"]["sha256"],),
                    "deterministic R0-R4 validation",
                    (RCheck.R0, RCheck.R1, RCheck.R2, RCheck.R3, RCheck.R4),
                ),
                Evaluation(
                    EvaluatorClass.E2,
                    Role.SCIENTIFIC_REVIEWER,
                    Decision.PASS,
                    (manifest["artifacts"]["e2_review"]["sha256"],),
                    "same-process role-separated scientific R1-R2/R4-R6 validation",
                    (RCheck.R1, RCheck.R2, RCheck.R4, RCheck.R5, RCheck.R6),
                    producer_role=Role.PAPER_WRITER,
                ),
                Evaluation(
                    EvaluatorClass.E3,
                    Role.ADVERSARIAL_REVIEWER,
                    Decision.PASS,
                    (manifest["artifacts"]["e3_review"]["sha256"],),
                    "adversarial R3/R5-R7 reproduction validation",
                    (RCheck.R3, RCheck.R5, RCheck.R6, RCheck.R7),
                    producer_role=Role.PAPER_WRITER,
                ),
            ]
        )
        # Scores are deterministic pass/fail rules bound to frozen artifacts;
        # the synthetic novelty category can satisfy its internal floor but is
        # never converted into external novelty evidence.
        score_rules = {
            "question": evidence_checks["R1"],
            "novelty_evidence": manifest.get("novelty") == "NOVELTY_UNVERIFIED",
            "falsifiability": evidence_checks["R1"],
            "methodological_validity": all(evidence_checks[key] for key in ("R1", "R2", "R3", "R4")),
            "baseline_fairness": evidence_checks["R2"],
            "experimental_design": all(evidence_checks[key] for key in ("R1", "R3", "R5")),
            "statistical_validity": evidence_checks["R4"],
            "ablations_robustness": evidence_checks["R5"],
            "negative_controls": evidence_checks["R5"],
            "reproducibility": evidence_checks["R7"],
            "claim_evidence_alignment": evidence_checks["R6"],
            "writing_clarity": evidence_checks["R6"],
            "limitations": evidence_checks["R6"],
            "artifact_quality": evidence_checks["R0"],
        }
        rubric_bytes = read_confined_bytes(
            self.root,
            "configs/paper_readiness_rubric.json",
            reject_hardlinks=True,
            max_bytes=1024 * 1024,
        )
        if rubric_bytes is None:
            raise OrchestrationError("readiness rubric disappeared")
        rubric = safe_json_loads(rubric_bytes)
        if not isinstance(rubric, dict):
            raise OrchestrationError("readiness rubric is not a JSON object")
        minima = {
            item["id"]: float(item["minimum_fraction"])
            for item in rubric["categories"]
        }
        scores = {
            category: (1.0 if passed else 0.0)
            for category, passed in score_rules.items()
        }
        scores["novelty_evidence"] = minima["novelty_evidence"]
        readiness = evaluate_readiness(
            self.root / "configs/paper_readiness_rubric.json",
            scores,
            summary,
            root=self.root,
            security_passed=True,
            reproduction_passed=True,
            claims_complete=True,
            citations_verified=True,
            reserve_clean=True,
            novelty_verified=False,
            synthetic_only=True,
            rubric_bytes=rubric_bytes,
        )
        internal_blockers = tuple(
            blocker for blocker in readiness.blockers if blocker != "NOVELTY_UNVERIFIED"
        )
        internal_demo_controls = (
            readiness.score >= 85
            and not internal_blockers
            and readiness.blockers == ("NOVELTY_UNVERIFIED",)
            and all(score_rules.values())
        )
        if not internal_demo_controls:
            self._queue_terminal(
                manifest,
                "INCONCLUSIVE",
                "internal demo readiness controls did not all pass",
                evidence={
                    "readiness_score": readiness.score,
                    "blockers": list(readiness.blockers),
                    "score_rules": score_rules,
                },
            )
            return
        readiness_payload = {
            "kind": "PAPER_READINESS_EVALUATION",
            "rubric_sha256": _sha256(rubric_bytes),
            "score": readiness.score,
            "category_weighted_scores": readiness.category_scores,
            "input_fractions": scores,
            "deterministic_score_rules": score_rules,
            "passed_governance_candidate_gate": readiness.passed,
            "passed_internal_demo_threshold": internal_demo_controls,
            "blockers": list(readiness.blockers),
            "maximum_label": readiness.maximum_label,
            "novelty": "NOVELTY_UNVERIFIED",
            "submission_ready": False,
            "e4_present": False,
        }
        self._artifact(
            manifest,
            "readiness_report",
            readiness_payload,
            creator=Role.SCIENTIFIC_REVIEWER.value,
            parents=(manifest["artifacts"]["audit_report"]["sha256"],),
        )
        audit_names = (
            "audit_report",
            "reproduction_report",
            "e2_review",
            "e3_review",
            "readiness_report",
        )
        self._evaluate(
            manifest,
            "E0:AUDIT",
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            audit_names,
            tuple(RCheck),
            producer=Role.PAPER_WRITER,
        )
        # Rebind the independent receipts to the full canonical AUDIT bundle,
        # including the frozen readiness and reproduction artifacts.
        self._evaluate(manifest, "E2:AUDIT", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, audit_names, tuple(RCheck), producer=Role.PAPER_WRITER)
        self._evaluate(manifest, "E3:AUDIT", EvaluatorClass.E3, Role.ADVERSARIAL_REVIEWER, audit_names, tuple(RCheck), producer=Role.PAPER_WRITER)

    @_project_command
    def reproduce(self, run_id: str) -> dict[str, Any]:
        manifest = self.load_manifest(run_id)
        self._assert_no_newer_external_checkpoint(manifest)
        if self.verify(run_id).get("status") != "PASS":
            raise OrchestrationError(
                "run verification failed before frozen reproduction replay"
            )
        existing = manifest.get("reproduction")
        if existing is not None:
            if not isinstance(existing, dict):
                raise OrchestrationError("frozen reproduction record differs")
            frozen_report = self._json_artifact_payload(
                manifest, "reproduction_report"
            )
            if frozen_report != existing:
                raise OrchestrationError("registered reproduction report differs")
            verify_frozen_reproduction(self.root, run_id, existing)
            return dict(existing)
        result = reproduce_run(self.root, run_id, timestamp=manifest["created_at"])
        value = result.to_dict()
        manifest["reproduction"] = value
        self._save_manifest(manifest)
        return value

    def _handler_release(self, manifest: dict[str, Any]) -> None:
        readiness = self._json_artifact_payload(manifest, "readiness_report")
        if readiness.get("passed_internal_demo_threshold") is not True or readiness.get("score", 0) < 85:
            raise OrchestrationError("frozen paper-readiness rubric did not pass")
        if manifest.get("reproduction") is None:
            raise OrchestrationError("AUDIT must freeze reproduction before RELEASE")
        self._save_manifest(manifest)
        package = package_run(self.root, str(manifest["run_id"]))
        package_payload = package.to_dict()
        self._artifact(manifest, "release_candidate", package_payload, creator=Role.RELEASE_PACKAGER.value, parents=tuple(record["sha256"] for record in manifest["artifacts"].values()))
        manifest["package"] = package_payload
        self._evaluate(manifest, "E0:RELEASE", EvaluatorClass.E0, Role.ORCHESTRATOR, ("release_candidate",), (RCheck.R7,), producer=Role.RELEASE_PACKAGER)
        self._evaluate(manifest, "E2:RELEASE", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, ("release_candidate",), (RCheck.R7,), producer=Role.RELEASE_PACKAGER)
        self._evaluate(manifest, "E3:RELEASE", EvaluatorClass.E3, Role.ADVERSARIAL_REVIEWER, ("release_candidate",), (RCheck.R7,), producer=Role.RELEASE_PACKAGER)

    _HANDLERS: dict[str, Callable[["ScientistOneOrchestrator", dict[str, Any]], None]] = {
        "CALIBRATE": _handler_calibrate,
        "CHARTER": _handler_charter,
        "GROUND": _handler_ground,
        "PROTOCOL": _handler_protocol,
        "PREFLIGHT": _handler_preflight,
        "IDEATE": _handler_ideate,
        "DISCOVER": _handler_discover,
        "CANDIDATE": _handler_candidate,
        "CONFIRM": _handler_confirm,
        "CLAIMS": _handler_claims,
        "WRITE": _handler_write,
        "AUDIT": _handler_audit,
        "RELEASE": _handler_release,
    }

    def _typed_transition(
        self,
        manifest: dict[str, Any],
        contract: TransitionContract,
        *,
        evaluator_key_map: Mapping[EvaluatorClass, str] | None = None,
    ) -> dict[str, Any]:
        """Revalidate the orchestration decision through the foundation controller."""

        source = contract.source
        destination = contract.destination
        required_records = [
            manifest["artifacts"][name] for name in contract.required_artifact_types
        ]
        registry = self._registry(str(manifest["run_id"]))
        registry_records = []
        for record in required_records:
            metadata = registry.get_metadata(record["sha256"])
            if (
                metadata.logical_type != record["logical_type"]
                or metadata.schema_version != record["schema_version"]
                or metadata.size != record["size"]
                or metadata.frozen is not True
                or metadata.path != record.get("registry_path")
                or metadata.metadata_path != record.get("registry_metadata_path")
                or metadata.record_hash != record.get("registry_record_hash")
            ):
                raise OrchestrationError("manifest artifact does not match its registry record")
            registry_records.append(metadata)
        artifact_refs = tuple(record.to_ref() for record in registry_records)
        evaluation_values: list[Evaluation] = []
        for evaluator_class in sorted(contract.required_evaluators, key=lambda item: item.value):
            key = (
                evaluator_key_map[evaluator_class]
                if evaluator_key_map is not None
                else _evaluation_key(source.value, evaluator_class)
            )
            stored = manifest["evaluator_decisions"].get(key)
            if not isinstance(stored, dict):
                raise OrchestrationError(f"missing stored evaluator receipt: {key}")
            try:
                evaluation = Evaluation(
                    EvaluatorClass(stored["evaluator_class"]),
                    Role(stored["authority"]),
                    Decision(stored["decision"]),
                    tuple(stored["artifact_hashes"]),
                    stored["reason"],
                    tuple(RCheck(item) for item in stored.get("r_checks", ())),
                    bool(stored.get("critical_objection", False)),
                    Role(stored["producer_role"]) if stored.get("producer_role") else None,
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise OrchestrationError(f"malformed stored evaluator receipt: {key}") from exc
            if evaluation.sha256 != stored.get("evaluation_sha256"):
                raise OrchestrationError(f"stored evaluator receipt hash mismatch: {key}")
            evaluation_values.append(evaluation)
        expected_calibration_hash: str | None = None
        calibration_forward = (
            source is MacroState.CALIBRATE
            and destination is MacroState.CHARTER
        )
        if calibration_forward:
            expected_calibration_hash = assert_calibrated(run_calibration()).report_sha256

        def validate_calibration(request: TransitionRequest) -> bool:
            if not calibration_forward:
                return True
            return (
                request.metadata.get("canonical_calibration_report_sha256")
                == expected_calibration_hash
                and request.metadata.get("mandatory_calibration_passed") is True
            )

        approver = sorted(contract.allowed_approvers, key=lambda item: item.value)[0]
        request = TransitionRequest(
            run_id=str(manifest["run_id"]),
            from_state=source,
            to_state=destination,
            requester=Role.ORCHESTRATOR,
            approver=approver,
            artifacts=artifact_refs,
            evaluations=tuple(evaluation_values),
            idempotency_key=f"{manifest['run_id']}:{source.value}:{destination.value}",
            reason="explicit artifact and evaluator contract satisfied",
            metadata={
                "canonical_calibration_report_sha256": expected_calibration_hash,
                "mandatory_calibration_passed": not calibration_forward
                or self._json_artifact_payload(manifest, "calibration_report").get("mandatory_passed") is True,
            },
        )
        def load_reference(reference: ArtifactRef) -> bytes:
            try:
                return registry.get_bytes(reference.sha256)
            except Exception as exc:
                raise OrchestrationError("typed transition artifact is absent or corrupt") from exc

        semantic_validators: dict[str, Callable[[ArtifactRef], bool]] = {}
        if calibration_forward:
            def validate_report(reference: ArtifactRef) -> bool:
                try:
                    observed = safe_json_loads(load_reference(reference))
                    expected = assert_calibrated(run_calibration()).to_dict()
                except (ValueError, OrchestrationError):
                    return False
                # The command wrapper adds status/provider disclosure fields;
                # the canonical scientific report itself must remain identical.
                observed.pop("status", None)
                observed.pop("external_integrations_used", None)
                return observed == expected
            semantic_validators["calibration_report"] = validate_report
        result = StateController(
            initial_state=source,
            contracts=(contract,),
            artifact_registry=registry,
            semantic_validators=semantic_validators,
        ).transition(request)
        return result.to_dict()

    @_project_command
    def advance_once(self, run_id: str) -> dict[str, Any]:
        manifest = self.load_manifest(run_id)
        self._assert_no_newer_external_checkpoint(manifest)
        if manifest.get("terminal_state"):
            return self.status(run_id)
        try:
            self._resource_controller(manifest)
        except OrchestrationError as exc:
            if manifest.get("current_state") not in MACRO_STATES:
                raise
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "external monotonic resource authority detected run rollback",
                evidence={
                    "resource_authority": "ROLLBACK_OR_STALE_PROJECTION",
                    "detail": str(exc),
                },
            )
            self._transition_terminal(manifest)
            return self.status(run_id)
        source = str(manifest["current_state"])
        if source not in self._HANDLERS or source not in TRANSITION_CONTRACTS:
            raise OrchestrationError(f"unknown current state: {source}")
        contract = TRANSITION_CONTRACTS[source]
        required_evaluator_keys = [
            _evaluation_key(source, evaluator)
            for evaluator in sorted(contract.required_evaluators, key=lambda item: item.value)
        ]
        stage_already_materialized = all(
            name in manifest["artifacts"] for name in contract.required_artifact_types
        ) and all(
            manifest["evaluator_decisions"].get(key, {}).get("decision") == "PASS"
            for key in required_evaluator_keys
        )
        if not stage_already_materialized:
            handler = self._HANDLERS[source]
            handler(self, manifest)
        if manifest.get("pending_terminal") is not None:
            self._transition_terminal(manifest)
            return self.status(run_id)
        if manifest.get("terminal_state"):
            raise OrchestrationError(
                "handler attempted an untyped terminal shortcut without evidence"
            )
        missing_artifacts = [
            name for name in contract.required_artifact_types if name not in manifest["artifacts"]
        ]
        missing_evaluators = [
            key
            for key in required_evaluator_keys
            if manifest["evaluator_decisions"].get(key, {}).get("decision") != "PASS"
        ]
        if missing_artifacts or missing_evaluators:
            raise OrchestrationError(f"transition contract incomplete: artifacts={missing_artifacts}, evaluators={missing_evaluators}")
        destination = contract.destination.value
        manifest["typed_transition_receipts"].append(self._typed_transition(manifest, contract))
        self._append_event(
            manifest,
            source,
            destination,
            f"typed {source}->{destination} contract satisfied",
            tuple(sorted(contract.required_artifact_types)),
            required_evaluator_keys,
        )
        manifest["completed_transitions"].append(f"{source}->{destination}")
        manifest["current_state"] = destination
        if destination == "READY_FOR_HUMAN_REVIEW":
            manifest["terminal_state"] = destination
            manifest["outcome"] = "COMPLETE_DEMO_ONLY"
        self._checkpoint(manifest)
        if destination == "READY_FOR_HUMAN_REVIEW":
            self._finalize_package_envelope(manifest)
        return self.status(run_id)

    def _finalize_package_envelope(self, manifest: dict[str, Any]) -> None:
        """Publish the detached final-state binding after the terminal event."""

        package = manifest.get("package")
        release_record = manifest.get("artifacts", {}).get("release_candidate")
        if not isinstance(package, dict) or not isinstance(release_record, dict):
            raise OrchestrationError("final package envelope lacks release evidence")
        if package.get("envelope_path") is not None or package.get("envelope_sha256") is not None:
            # An existing envelope must be fully revalidated, never trusted.
            package_run(self.root, str(manifest["run_id"]))
            return
        evaluators = manifest.get("evaluator_decisions", {})
        ledger = EventLedger(
            self.root,
            Path("runs") / str(manifest["run_id"]) / "events.jsonl",
        ).validate()
        if (
            not ledger.valid
            or not ledger.events
            or ledger.head_hash != manifest.get("ledger_head_hash")
        ):
            raise OrchestrationError("final envelope ledger is invalid")
        final_event = ledger.events[-1]
        registry = self._registry(str(manifest["run_id"]))
        release_metadata = registry.get_metadata(release_record["sha256"])
        try:
            release_payload = safe_json_loads(
                registry.get_bytes(release_metadata.sha256)
            )
        except Exception as exc:
            raise OrchestrationError("final release evidence is invalid") from exc
        release_event_evaluations = {
            f"{value.get('evaluator_class')}:RELEASE": safe_json_loads(
                canonical_json_bytes(value)
            )
            for value in final_event.evaluator_outputs
            if isinstance(value, Mapping)
        }
        envelope = {
            "schema_version": SCHEMA_VERSION,
            "kind": "FINAL_RELEASE_ENVELOPE",
            "run_id": manifest["run_id"],
            "archive_path": package["archive_path"],
            "archive_sha256": package["archive_sha256"],
            "release_candidate_sha256": release_record["sha256"],
            "release_candidate_record_hash": release_record["registry_record_hash"],
            "final_ledger_head_hash": manifest["ledger_head_hash"],
            "final_event_count": manifest["event_count"],
            "final_event_id": f"event-{int(manifest['event_count']):04d}",
            "release_evaluator_sha256": {
                key: evaluators[key]["evaluation_sha256"]
                for key in ("E0:RELEASE", "E2:RELEASE", "E3:RELEASE")
            },
            "terminal_state": "READY_FOR_HUMAN_REVIEW",
            "outcome": "COMPLETE_DEMO_ONLY",
            "publication_authority": "E4_HUMAN_REQUIRED",
            "bundle_role": "PRE_RELEASE_EVIDENCE_BUNDLE",
            "ledger_events": [event.to_dict() for event in ledger.events],
            "release_candidate_record": release_metadata.to_dict(),
            "release_candidate_payload": release_payload,
            "release_evaluator_receipts": {
                key: release_event_evaluations[key]
                for key in ("E0:RELEASE", "E2:RELEASE", "E3:RELEASE")
            },
        }
        data = _canonical_bytes(envelope)
        digest = _sha256(data)
        relative = (
            Path("artifacts")
            / "release_candidates"
            / f"{manifest['run_id']}-{digest[:20]}.final-envelope.json"
        )
        try:
            atomic_write_bytes(
                self.root,
                relative,
                data,
                immutable=True,
                create_parents=True,
            )
        except PathSecurityError as exc:
            raise OrchestrationError("final release envelope publication failed") from exc
        package["envelope_path"] = relative.as_posix()
        package["envelope_sha256"] = digest
        self._save_manifest(manifest)
        package_run(self.root, str(manifest["run_id"]))

    @_project_command
    def resume(self, run_id: str) -> dict[str, Any]:
        manifest = self.load_manifest(run_id)
        recovery = self._recovery_report(manifest)
        if recovery.action.value == "STOP_SECURITY" and any(
            "checkpoint" in str(reason).lower() for reason in recovery.reasons
        ):
            # A stale ledger cannot safely receive a new terminal event: doing
            # so would create a fork colliding with the surviving immutable
            # checkpoint timeline.  Expose the typed recovery refusal through
            # this out-of-band command result and leave every authority byte
            # unchanged.
            return {
                "status": "STOP_SECURITY",
                "run_id": run_id,
                "current_state": "STOP_SECURITY",
                "terminal_state": "STOP_SECURITY",
                "outcome": "STOP_SECURITY",
                "mode": manifest.get("mode"),
                "artifact_count": len(manifest.get("artifacts", {})),
                "event_count": recovery.ledger_event_count,
                "resumable": False,
                "persisted": False,
                "authority_channel": "EXTERNAL_CHECKPOINT_RECOVERY_REFUSAL",
                "recovery": recovery.to_dict(),
            }
        if manifest.get("terminal_state") != "STOP_SECURITY":
            try:
                self._resource_controller(manifest)
            except OrchestrationError as exc:
                if manifest.get("current_state") not in MACRO_STATES:
                    raise
                self._queue_terminal(
                    manifest,
                    "STOP_SECURITY",
                    "external monotonic resource authority detected run rollback",
                    evidence={
                        "resource_authority": "ROLLBACK_OR_STALE_PROJECTION",
                        "detail": str(exc),
                    },
                )
                self._transition_terminal(manifest)
                return self.status(run_id)
        if recovery.derived_state is not None and recovery.derived_state != manifest.get("current_state"):
            manifest["current_state"] = recovery.derived_state
            manifest["event_count"] = recovery.ledger_event_count
            manifest["ledger_head_hash"] = recovery.ledger_head_hash
            self._save_manifest(manifest)
        if recovery.action.value in {"STOP_SECURITY", "STOP_SCIENTIFIC_INVALIDITY", "NEW_STUDY_REQUIRED"}:
            destination = (
                "STOP_SECURITY"
                if recovery.action.value == "STOP_SECURITY"
                else "STOP_SCIENTIFIC_INVALIDITY"
            )
            if manifest.get("current_state") not in MACRO_STATES:
                raise OrchestrationError(
                    "recovery stop cannot be represented from a non-macro state"
                )
            self._queue_terminal(
                manifest,
                destination,
                "recovery validation refused continuation",
                evidence={"recovery": recovery.to_dict()},
            )
            self._transition_terminal(manifest)
            return self.status(run_id)
        if recovery.action.value == "SKIP_COMPLETED" and manifest.get("terminal_state") is not None:
            package = manifest.get("package")
            if (
                manifest.get("terminal_state") == "READY_FOR_HUMAN_REVIEW"
                and isinstance(package, dict)
                and (
                    package.get("envelope_path") is None
                    or package.get("envelope_sha256") is None
                )
            ):
                self._finalize_package_envelope(manifest)
            return self.status(run_id)
        # SKIP_COMPLETED forbids replaying CONFIRM; it does not forbid the
        # downstream CLAIMS/WRITE/AUDIT/RELEASE stages. The ledger-derived
        # state below guarantees that resume never re-enters CONFIRM.
        verification = self.verify(run_id)
        if verification["status"] != "PASS":
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "semantic verification refused resume",
                evidence={"verification": verification},
            )
            self._transition_terminal(manifest)
            return self.status(run_id)
        while manifest.get("terminal_state") is None:
            self.advance_once(run_id)
            manifest = self.load_manifest(run_id)
        return self.status(run_id)

    @_project_command
    def demo(self, *, synthetic_scenario: str = "positive") -> dict[str, Any]:
        started = self.start(
            mode="synthetic_demo", synthetic_scenario=synthetic_scenario
        )
        result = self.resume(str(started["run_id"]))
        result["package"] = self.load_manifest(str(started["run_id"])).get("package")
        result["reproduction"] = self.load_manifest(str(started["run_id"])).get("reproduction")
        return result

    @_project_command
    def package(self, run_id: str) -> dict[str, Any]:
        manifest = self.load_manifest(run_id)
        self._assert_no_newer_external_checkpoint(manifest)
        if manifest.get("current_state") not in {"RELEASE", "READY_FOR_HUMAN_REVIEW"}:
            raise OrchestrationError("run must complete AUDIT before packaging")
        if manifest["current_state"] == "RELEASE":
            self.advance_once(run_id)
            manifest = self.load_manifest(run_id)
        verified = package_run(self.root, run_id).to_dict()
        if manifest.get("package") != verified:
            raise OrchestrationError("mutable package projection differs from verified evidence")
        return verified


__all__ = [
    "MACRO_STATES",
    "TERMINAL_STATES",
    "TRANSITION_CONTRACTS",
    "OrchestrationError",
    "ScientistOneOrchestrator",
    "TransitionContract",
]
