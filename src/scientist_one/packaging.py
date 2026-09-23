"""Deterministic release-candidate packaging for Scientist-One.

Packaging is intentionally not a release authority.  It creates an offline
review bundle whose metadata requires human E4 review.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping
import zipfile

from .artifacts import ArtifactRegistry
from .claims import EvidenceKind
from .domains import SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME
from .errors import ArtifactError, PathSecurityError, UnsafeSerializationError
from .evaluators import (
    Decision,
    Evaluation,
    EvaluatorClass,
    MAX_EVALUATION_ARTIFACT_HASHES,
    MAX_EVALUATION_REASON_BYTES,
    RCheck,
)
from .holdout import SimulatedHoldoutCustody
from .ledger import EventLedger, LedgerEvent, MAX_LEDGER_BYTES
from .models import MacroState
from .roles import Role
from .reproduction import (
    ARCHITECTURE_CONTROL_REPLAY_STATUS,
    ReproductionError,
    verify_frozen_architecture_control_reproduction,
    verify_frozen_reproduction,
)
from .security import (
    DEFAULT_MAX_JSON_BYTES,
    canonical_json_bytes,
    open_confined_directory_fd,
    read_confined_bytes,
    safe_json_loads,
    secure_directory,
    detect_secret_patterns,
)
from .state_machine import (
    LEGACY_EVALUATION_RECEIPT_KEYS,
    StateController,
    TransitionResult,
    legacy_evaluation_receipt,
    macro_transition_contracts,
    validate_legacy_transition_event_receipt,
    validate_legacy_transition_prefix,
)


RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RESOURCE_AUTHORITY_NAME_PATTERN = re.compile(
    r"^(?P<sequence>[0-9]{4})-(?P<digest>[0-9a-f]{64})\.json$"
)
# Assemble the private runtime basename from fragments so this frozen source
# file does not itself disclose the exact path that package boundaries reject.
_GATEWAY_TRUST_ROOT_NAME = "." + "gateway-execution-" + "authority.key"
_PRIVATE_TRUST_ROOT_BYTES = 32
CONCRETE_SECRET_BYTE_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(
        rb"(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)"
        rb"\s*[:=]\s*['\"]?[A-Za-z0-9_./+\-=]{16,}",
        re.IGNORECASE,
    ),
)
ABSOLUTE_PATH_BYTE_PATTERN = re.compile(
    # A slash immediately following ':' or another slash belongs to a URI
    # such as the fixed SVG namespace, not a local filesystem root.
    rb"(?<![A-Za-z0-9_/:])/+[A-Za-z0-9._~+@%=-]+"
    rb"(?:/+[A-Za-z0-9._~+@%=-]+)+"
)
TRUSTED_SOURCE_ABSOLUTE_REFERENCES = frozenset(
    {
        b"/etc/passwd",  # calibration trap fixture, never opened
        b"/usr/bin/env",  # isolated launcher shebang
        b"/usr/bin",  # minimal PATH used by the isolated local runner
        b"/usr/bin/git",  # native read-only Git history verifier
        b"/Library/Developer/CommandLineTools/usr/bin/git",  # pinned macOS Git
        b"/usr/bin/memory_pressure",
        b"/usr/bin/pmset",
        b"/usr/bin/python3",  # fixed interpreter for the bounded fixture
        b"/usr/bin/sandbox-exec",  # macOS REQUIRED isolation launcher
        b"/usr/bin/vm_stat",
        b"/usr/sbin/sysctl",
        b"/usr/sbin/system_profiler",
        b"/dev/null",  # isolated runner standard-input source
        # Audited HTTP route components, not local filesystem disclosures.
        b"/research-os-fixture/pmc",
        b"/v1/responses",
        b"/api/oai/v1/mh",  # PMC OAI route, not a local filesystem path
        # This appears only as the suffix of a project-relative f-string in
        # the packet verifier itself (``runs/{run_id}/artifacts/release``).
        b"/artifacts/release",
    }
)
MAX_PACKAGE_INPUT_BYTES = 256 * 1024 * 1024
MAX_PACKAGE_FILES = 10_000
MAX_INVENTORY_ENTRIES = 2_048
MAX_INVENTORY_TOTAL_BYTES = 64 * 1024 * 1024
ARTIFACT_PROJECTION_KEYS = {
    "logical_type", "path", "sha256", "size", "schema_version",
    "mime_type", "origin", "creator_role", "creation_command",
    "parent_artifacts", "validation_result", "frozen", "registry_path",
    "registry_metadata_path", "registry_record_hash",
}
ARTIFACT_INDEX_KEYS = {
    "member", "sha256", "logical_type", "frozen",
    "registry_record_hash", "parent_artifacts",
}
SOURCE_INDEX_KEYS = {"sha256", "size"}
SNAPSHOT_INDEX_KEYS = {"member", "sha256", "size", "inventory"}
RUN_MANIFEST_KEYS = {
    "schema_version", "kind", "run_id", "created_at", "updated_at",
    "mode", "synthetic_scenario", "package_kind", "current_state",
    "terminal_state", "outcome", "novelty", "external_integrations_used",
    "external_integrations_policy", "code_fingerprint",
    "configuration_sha256", "python_executable_name", "python_version",
    "fixture_identifiers", "random_seeds", "transition_contracts",
    "artifacts", "evaluator_decisions", "r_checks", "reproduction",
    "package", "event_count", "ledger_head_hash", "completed_transitions",
    "typed_transition_receipts", "resource_runtime_state",
    "resource_runtime_artifact", "protocol_hash",
}
EVALUATION_RECEIPT_KEYS = set(LEGACY_EVALUATION_RECEIPT_KEYS)
EVALUATION_R_CHECK_VALUES = frozenset(check.value for check in RCheck)


class PackagingError(RuntimeError):
    """Raised when a safe review bundle cannot be constructed."""


def _read_private_trust_root(
    registry: ArtifactRegistry,
    *,
    basename: str,
    label: str,
) -> bytes | None:
    """Read one private local key only to prove it is absent from output."""

    directory_fd: int | None = None
    descriptor: int | None = None
    try:
        directory_fd = open_confined_directory_fd(
            registry.policy.root,
            registry.base_path,
            create=False,
        )
        try:
            descriptor = os.open(
                basename,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return None
        metadata = os.fstat(descriptor)
        named = os.stat(
            basename,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_mode & 0o777) != 0o600
            or metadata.st_size != _PRIVATE_TRUST_ROOT_BYTES
            or identity != (named.st_dev, named.st_ino)
        ):
            raise PackagingError(f"{label} trust root is unsafe")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(
            descriptor,
            _PRIVATE_TRUST_ROOT_BYTES + 1 - total,
        ):
            chunks.append(chunk)
            total += len(chunk)
            if total > _PRIVATE_TRUST_ROOT_BYTES:
                raise PackagingError(f"{label} trust root has an invalid size")
        value = b"".join(chunks)
        final = os.fstat(descriptor)
        final_named = os.stat(
            basename,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        stable = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        final_stable = (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_nlink,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        )
        if (
            len(value) != _PRIVATE_TRUST_ROOT_BYTES
            or stable != final_stable
            or identity != (final_named.st_dev, final_named.st_ino)
        ):
            raise PackagingError(
                f"{label} trust root changed during secrecy check"
            )
        return value
    except PackagingError:
        raise
    except (OSError, PathSecurityError) as exc:
        raise PackagingError(
            f"{label} trust root cannot be checked safely"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)


def _read_gateway_trust_root(registry: ArtifactRegistry) -> bytes | None:
    """Read the private gateway key only to prove it is absent from output."""

    return _read_private_trust_root(
        registry,
        basename=_GATEWAY_TRUST_ROOT_NAME,
        label="gateway",
    )


def _read_scientific_domain_trust_root(
    registry: ArtifactRegistry,
) -> bytes | None:
    """Read the local domain-admission key only for boundary exclusion."""

    return _read_private_trust_root(
        registry,
        basename=SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME,
        label="scientific-domain",
    )


def _assert_gateway_trust_root_not_serialized(
    registry: ArtifactRegistry,
    members: Mapping[str, bytes],
) -> None:
    """Reject a packet or envelope that names or contains the private key."""

    roots = (
        (
            _GATEWAY_TRUST_ROOT_NAME,
            _read_gateway_trust_root(registry),
            "gateway",
        ),
        (
            SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME,
            _read_scientific_domain_trust_root(registry),
            "scientific-domain",
        ),
    )
    for basename, key_material, label in roots:
        path_marker = basename.encode("utf-8")
        serialized_key_forms: tuple[bytes, ...] = ()
        if key_material is not None:
            standard_b64 = base64.b64encode(key_material)
            urlsafe_b64 = base64.urlsafe_b64encode(key_material)
            serialized_key_forms = tuple(
                dict.fromkeys(
                    (
                        key_material,
                        key_material.hex().encode("ascii"),
                        key_material.hex().upper().encode("ascii"),
                        standard_b64,
                        standard_b64.rstrip(b"="),
                        urlsafe_b64,
                        urlsafe_b64.rstrip(b"="),
                    )
                )
            )
        for name, content in members.items():
            if (
                not isinstance(name, str)
                or not isinstance(content, bytes)
                or basename in name
                or path_marker in content
                or any(value in content for value in serialized_key_forms)
            ):
                raise PackagingError(
                    f"{label} trust root must not appear in a release boundary"
                )


def _custody_journal_path(run_id: str) -> Path:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise PackagingError("invalid run ID for custody authority")
    return Path(".scientist-one-build/custody") / f"{run_id}.jsonl"


def _resource_authority_bytes(
    root: Path, run_id: str, manifest: Mapping[str, Any]
) -> dict[str, bytes]:
    """Validate the external monotonic resource chain and return exact bytes."""

    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise PackagingError("invalid run ID for resource authority")
    relative = Path(".scientist-one-build/resource-authority") / run_id
    try:
        directory_fd = open_confined_directory_fd(root, relative, create=False)
        try:
            names: list[str] = []
            with os.scandir(directory_fd) as iterator:
                for entry in iterator:
                    if not RESOURCE_AUTHORITY_NAME_PATTERN.fullmatch(entry.name):
                        raise PackagingError(
                            "resource authority contains an unknown entry"
                        )
                    if len(names) >= 16:
                        raise PackagingError(
                            "resource authority exceeds its bounded history"
                        )
                    names.append(entry.name)
        finally:
            os.close(directory_fd)
    except (OSError, PathSecurityError) as exc:
        raise PackagingError("resource authority directory is unsafe") from exc
    result: dict[str, bytes] = {}
    prior_digest: str | None = None
    latest: Mapping[str, Any] | None = None
    for expected_sequence, name in enumerate(sorted(names)):
        match = RESOURCE_AUTHORITY_NAME_PATTERN.fullmatch(name)
        if match is None or int(match.group("sequence")) != expected_sequence:
            raise PackagingError("resource authority sequence is not contiguous")
        data = _confined_bytes(root, relative / name, max_bytes=1024 * 1024)
        try:
            value = safe_json_loads(data)
        except UnsafeSerializationError as exc:
            raise PackagingError("resource authority record is malformed") from exc
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version", "kind", "run_id", "sequence",
            "logical_type", "state_sha256", "state",
            "prior_authority_sha256",
        }:
            raise PackagingError("resource authority record schema is invalid")
        state = value.get("state")
        digest = _sha256(data)
        if (
            digest != match.group("digest")
            or value.get("schema_version") != "1.0"
            or value.get("kind") != "RESOURCE_RUNTIME_AUTHORITY"
            or value.get("run_id") != run_id
            or value.get("sequence") != expected_sequence
            or not isinstance(value.get("logical_type"), str)
            or not str(value["logical_type"]).startswith("resource_runtime_")
            or not isinstance(state, Mapping)
            or value.get("state_sha256") != _sha256(_canonical_json(state))
            or value.get("prior_authority_sha256") != prior_digest
        ):
            raise PackagingError("resource authority record binding is invalid")
        result[name] = data
        prior_digest = digest
        latest = value
    if (
        latest is None
        or latest.get("logical_type") != manifest.get("resource_runtime_artifact")
        or latest.get("state") != manifest.get("resource_runtime_state")
    ):
        raise PackagingError("run resource state is not the external authority head")
    return result


def _resource_authority_descriptors(
    authority: Mapping[str, bytes],
) -> list[dict[str, Any]]:
    descriptors: list[dict[str, Any]] = []
    for sequence, (name, data) in enumerate(sorted(authority.items())):
        try:
            value = safe_json_loads(data)
        except UnsafeSerializationError as exc:
            raise PackagingError("resource authority record is malformed") from exc
        if not isinstance(value, Mapping):
            raise PackagingError("resource authority record is not an object")
        descriptors.append(
            {
                "sequence": sequence,
                "logical_type": value.get("logical_type"),
                "state_sha256": value.get("state_sha256"),
                "authority_sha256": _sha256(data),
                "prior_authority_sha256": value.get("prior_authority_sha256"),
            }
        )
    return descriptors


def _validate_resource_authority_projection(
    events: Any,
    authority: Mapping[str, bytes],
) -> None:
    """Validate the complete ordered external authority against the ledger."""

    expected = _resource_authority_descriptors(authority)
    observed: list[dict[str, Any]] = []
    repeated_confirmatory_sequences: set[int] = set()
    reconciled = False
    for event in events:
        names = event.metadata.get("artifact_types", ())
        if not isinstance(names, (list, tuple)):
            raise PackagingError("resource ledger artifact types are malformed")
        positions = [
            index
            for index, name in enumerate(names)
            if isinstance(name, str) and name.startswith("resource_runtime_")
        ]
        binding = event.metadata.get("resource_authority_checkpoint")
        if len(positions) > 1:
            raise PackagingError("resource ledger event is ambiguous")
        if positions:
            position = positions[0]
            if position >= len(event.artifact_hashes):
                raise PackagingError("resource ledger checkpoint is unbound")
            scientific_repeat = (
                event.event_type == "CONFIRMATORY_STARTED"
                and event.metadata.get("evidence_class")
                != "ARCHITECTURE_CONTROL"
                and event.metadata.get("execution_kind")
                != "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
            )
            simulated_repeat = (
                event.event_type == "CHECKPOINT"
                and event.metadata.get("evidence_class")
                == "ARCHITECTURE_CONTROL"
                and event.metadata.get("execution_kind")
                == "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
            )
            repeat_state_is_valid = (
                scientific_repeat
                and event.state_before.value == "CONFIRM"
                and event.requested_state_after.value == "CONFIRM"
            ) or (
                simulated_repeat
                and event.state_before == event.requested_state_after
                and event.state_before.value
                in {state.value for state in MacroState}
            )
            repeated = (
                (scientific_repeat or simulated_repeat)
                and repeat_state_is_valid
                and bool(observed)
                and binding == observed[-1]
                and names[position] == observed[-1]["logical_type"]
                and event.artifact_hashes[position]
                == observed[-1]["state_sha256"]
            )
            if (scientific_repeat or simulated_repeat) and not repeated:
                raise PackagingError(
                    "reveal resource authority must repeat the immediately "
                    "preceding checkpoint with its exact execution class"
                )
            if repeated:
                sequence = int(observed[-1]["sequence"])
                if sequence in repeated_confirmatory_sequences:
                    raise PackagingError(
                        "confirmatory resource authority was repeated more than once"
                    )
                repeated_confirmatory_sequences.add(sequence)
            else:
                if len(observed) >= len(expected):
                    raise PackagingError("resource ledger checkpoint is unbound")
                descriptor = expected[len(observed)]
                if (
                    binding != descriptor
                    or names[position] != descriptor["logical_type"]
                    or event.artifact_hashes[position] != descriptor["state_sha256"]
                ):
                    raise PackagingError(
                        "resource authority differs from its ordered ledger projection"
                    )
                observed.append(descriptor)
        elif binding is not None:
            raise PackagingError("resource authority binding lacks an artifact")
        reconciliation = event.metadata.get("resource_authority_chain")
        if reconciliation is not None:
            if (
                reconciled
                or event.event_type != "SECURITY_STOP"
                or event.requested_state_after.value != "STOP_SECURITY"
                or reconciliation != expected
            ):
                raise PackagingError("resource authority reconciliation is malformed")
            reconciled = True
    if observed != expected and not reconciled:
        raise PackagingError("resource authority history is not fully ledger-bound")


def _manifest_projection_from_record(
    projected: Mapping[str, Any], metadata: Any
) -> dict[str, Any]:
    """Return the one exact run-manifest projection of an ArtifactRecord."""

    return {
        "logical_type": metadata.logical_type,
        "path": projected.get("path"),
        "sha256": metadata.sha256,
        "size": metadata.size,
        "schema_version": metadata.schema_version,
        "mime_type": metadata.mime_type,
        "origin": metadata.origin,
        "creator_role": metadata.creator_role.value,
        "creation_command": list(metadata.creation_command),
        "parent_artifacts": list(metadata.parent_artifacts),
        "validation_result": metadata.validation_result,
        "frozen": metadata.frozen,
        "registry_path": metadata.path,
        "registry_metadata_path": metadata.metadata_path,
        "registry_record_hash": metadata.record_hash,
    }


def _ledger_evaluator_projection(events: Any) -> dict[str, dict[str, Any]]:
    """Bind every evaluator key positionally to one exact typed output."""

    result: dict[str, dict[str, Any]] = {}
    contracts = {
        (contract.source.value, contract.destination.value): contract
        for contract in macro_transition_contracts()
    }
    for event in events:
        keys = event.metadata.get("evaluator_keys", ())
        outputs = event.evaluator_outputs
        if (
            not isinstance(keys, (list, tuple))
            or not isinstance(outputs, (list, tuple))
            or len(keys) != len(outputs)
        ):
            raise PackagingError("ledger evaluator key/output arity differs")
        if event.event_type in {"TRANSITION", "SECURITY_STOP"} and (
            event.state_before.value != event.requested_state_after.value
        ):
            contract = contracts.get(
                (event.state_before.value, event.requested_state_after.value)
            )
            if contract is None:
                raise PackagingError("ledger transition has no canonical evaluator contract")
            terminal = event.requested_state_after.value in {
                "NEGATIVE_RESULT", "INCONCLUSIVE", "BLOCKED_EXTERNAL",
                "STOP_SCIENTIFIC_INVALIDITY", "STOP_SECURITY", "STOP_BUDGET",
            }
            expected_keys = tuple(
                (
                    f"{evaluator.value}:{event.state_before.value}"
                    + (
                        f"->{event.requested_state_after.value}"
                        if terminal
                        else ""
                    )
                )
                for evaluator in sorted(
                    contract.required_evaluators, key=lambda item: item.value
                )
            )
            if tuple(keys) != expected_keys:
                raise PackagingError(
                    "ledger transition evaluator set differs from its contract"
                )
        elif keys or outputs:
            raise PackagingError(
                "non-transition ledger event contains evaluator outputs"
            )
        for key, raw_output in zip(keys, outputs, strict=True):
            if not isinstance(key, str) or not isinstance(raw_output, Mapping):
                raise PackagingError("ledger evaluator binding is malformed")
            if (
                len(raw_output) != len(EVALUATION_RECEIPT_KEYS)
                or set(raw_output) != EVALUATION_RECEIPT_KEYS
            ):
                raise PackagingError("ledger evaluator receipt is malformed")
            artifact_hashes = raw_output.get("artifact_hashes")
            reason = raw_output.get("reason")
            r_checks = raw_output.get("r_checks")
            if (
                not isinstance(artifact_hashes, (list, tuple))
                or len(artifact_hashes) > MAX_EVALUATION_ARTIFACT_HASHES
                or any(
                    not isinstance(digest, str)
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                    for digest in artifact_hashes
                )
                or not isinstance(reason, str)
                or len(reason) > MAX_EVALUATION_REASON_BYTES
                or not isinstance(r_checks, (list, tuple))
                or len(r_checks) > len(RCheck)
                or any(
                    not isinstance(check, str)
                    or check not in EVALUATION_R_CHECK_VALUES
                    for check in r_checks
                )
            ):
                raise PackagingError("ledger evaluator receipt is malformed")
            try:
                encoded_reason = reason.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise PackagingError("ledger evaluator receipt is malformed") from exc
            if (
                len(encoded_reason) > MAX_EVALUATION_REASON_BYTES
                or not reason.strip()
            ):
                raise PackagingError("ledger evaluator receipt is malformed")
            output = safe_json_loads(canonical_json_bytes(raw_output))
            expected_key = f"{output.get('evaluator_class')}:{event.state_before.value}"
            if event.requested_state_after.value in {
                "NEGATIVE_RESULT", "INCONCLUSIVE", "BLOCKED_EXTERNAL",
                "STOP_SCIENTIFIC_INVALIDITY", "STOP_SECURITY", "STOP_BUDGET",
            }:
                expected_key += f"->{event.requested_state_after.value}"
            terminal_event = event.requested_state_after.value in {
                "NEGATIVE_RESULT", "INCONCLUSIVE", "BLOCKED_EXTERNAL",
                "STOP_SCIENTIFIC_INVALIDITY", "STOP_SECURITY", "STOP_BUDGET",
            }
            if (
                set(output) != EVALUATION_RECEIPT_KEYS
                or key != expected_key
                or (key in result and not terminal_event)
            ):
                raise PackagingError("ledger evaluator key is duplicate or misplaced")
            try:
                evaluation = Evaluation(
                    evaluator_class=EvaluatorClass(output["evaluator_class"]),
                    actor_role=Role(output["authority"]),
                    decision=Decision(output["decision"]),
                    artifact_hashes=tuple(output["artifact_hashes"]),
                    reason=output["reason"],
                    r_checks=tuple(RCheck(item) for item in output["r_checks"]),
                    critical_objection=output["critical_objection"],
                    producer_role=(
                        Role(output["producer_role"])
                        if output["producer_role"]
                        else None
                    ),
                    run_id=output["run_id"],
                    gate_id=output["gate_id"],
                    frozen_context_sha256=output["frozen_context_sha256"],
                    human_independence_claimed=output[
                        "human_independence_claimed"
                    ],
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise PackagingError("ledger evaluator receipt is malformed") from exc
            if legacy_evaluation_receipt(evaluation) != output:
                raise PackagingError("ledger evaluator receipt hash mismatch")
            result[key] = output
    return result


@dataclass(frozen=True)
class PackageResult:
    run_id: str
    status: str
    package_kind: str
    review_state: str
    e4_required: bool
    archive_path: str
    archive_sha256: str
    file_count: int
    envelope_path: str | None = None
    envelope_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _verify_finalized_package(
    project_root: Path, run_id: str, manifest: Mapping[str, Any]
) -> PackageResult:
    """Verify the immutable pre-release ZIP and detached final ledger envelope."""

    if set(manifest) != RUN_MANIFEST_KEYS:
        raise PackagingError("final run manifest contains an unknown or missing field")
    registry = ArtifactRegistry(project_root, Path("runs") / run_id / "registry")
    live_resource_authority = _resource_authority_bytes(
        project_root, run_id, manifest
    )
    package = manifest.get("package")
    expected_fields = {
        "run_id",
        "status",
        "package_kind",
        "review_state",
        "e4_required",
        "archive_path",
        "archive_sha256",
        "file_count",
        "envelope_path",
        "envelope_sha256",
    }
    if not isinstance(package, Mapping) or set(package) != expected_fields:
        raise PackagingError("final package projection has an invalid schema")
    if (
        package.get("run_id") != run_id
        or package.get("status") != "PASS"
        or package.get("package_kind") != "DEMO_RESEARCH_PACKAGE"
        or package.get("review_state") != "READY_FOR_HUMAN_REVIEW"
        or package.get("e4_required") is not True
    ):
        raise PackagingError("final package projection has invalid governance labels")
    archive_path = package.get("archive_path")
    envelope_path = package.get("envelope_path")
    if not isinstance(archive_path, str) or not isinstance(envelope_path, str):
        raise PackagingError("final package paths are absent")
    expected_envelope_path = (
        f"artifacts/release_candidates/{run_id}-"
        f"{str(package.get('envelope_sha256'))[:20]}.final-envelope.json"
    )
    if envelope_path != expected_envelope_path:
        raise PackagingError("final package envelope path is non-canonical")
    archive = _confined_bytes(
        project_root, archive_path, max_bytes=MAX_PACKAGE_INPUT_BYTES
    )
    envelope_bytes = _confined_bytes(
        project_root, envelope_path, max_bytes=DEFAULT_MAX_JSON_BYTES
    )
    if (
        _sha256(archive) != package.get("archive_sha256")
        or _sha256(envelope_bytes) != package.get("envelope_sha256")
    ):
        raise PackagingError("final package or envelope digest mismatch")
    archive_members: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(archive), "r") as packet:
            infos = packet.infolist()
            if (
                len(infos) != package.get("file_count")
                or len(infos) > MAX_PACKAGE_FILES
                or len({info.filename for info in infos}) != len(infos)
            ):
                raise PackagingError("final archive member count is invalid")
            total = 0
            for info in infos:
                member = PurePosixPath(info.filename)
                if (
                    member.is_absolute()
                    or ".." in member.parts
                    or info.is_dir()
                    or info.file_size > MAX_PACKAGE_INPUT_BYTES
                ):
                    raise PackagingError("final archive has an unsafe member")
                total += info.file_size
                if total > MAX_PACKAGE_INPUT_BYTES:
                    raise PackagingError("final archive exceeds its aggregate bound")
                content = packet.read(info)
                if len(content) != info.file_size:
                    raise PackagingError("final archive member is truncated")
                archive_members[info.filename] = content
    except (OSError, zipfile.BadZipFile) as exc:
        raise PackagingError("final archive is unreadable") from exc
    _assert_gateway_trust_root_not_serialized(
        registry,
        {
            **archive_members,
            "DETACHED_FINAL_RELEASE_ENVELOPE.json": envelope_bytes,
        },
    )
    try:
        archived_release = safe_json_loads(
            archive_members.get("RELEASE_CANDIDATE.json", b"")
        )
    except UnsafeSerializationError as exc:
        raise PackagingError("archived release manifest is malformed") from exc
    if not isinstance(archived_release, Mapping):
        raise PackagingError("archived release manifest is absent")
    artifact_index = archived_release.get("artifact_index")
    source_index = archived_release.get("source_run_index")
    if not isinstance(artifact_index, Mapping) or not isinstance(source_index, Mapping):
        raise PackagingError("archived release indexes are malformed")
    expected_members = {"RELEASE_CANDIDATE.json"}
    for logical_type, entry in artifact_index.items():
        if (
            not isinstance(logical_type, str)
            or not isinstance(entry, Mapping)
            or set(entry) != ARTIFACT_INDEX_KEYS
        ):
            raise PackagingError("archived artifact index entry is malformed")
        member = entry.get("member")
        digest = entry.get("sha256")
        record_hash = entry.get("registry_record_hash")
        if (
            not isinstance(member, str)
            or member not in archive_members
            or _sha256(archive_members[member]) != digest
            or not isinstance(record_hash, str)
        ):
            raise PackagingError("archived evidence member differs from its index")
        metadata_members = [
            name
            for name in archive_members
            if name.startswith(f"registry/{logical_type}-") and name.endswith(".json")
        ]
        if len(metadata_members) != 1:
            raise PackagingError("archived registry metadata member is ambiguous")
        try:
            archived_metadata = safe_json_loads(
                archive_members[metadata_members[0]]
            )
        except UnsafeSerializationError as exc:
            raise PackagingError("archived registry metadata is malformed") from exc
        if (
            not isinstance(archived_metadata, Mapping)
            or archived_metadata.get("sha256") != digest
            or archived_metadata.get("record_hash") != record_hash
            or archived_metadata.get("logical_type")
            != entry.get("logical_type")
        ):
            raise PackagingError("archived registry metadata differs from its index")
        expected_members.update((member, metadata_members[0]))
    for name, entry in source_index.items():
        member = f"run/{name}"
        if (
            not isinstance(name, str)
            or not isinstance(entry, Mapping)
            or set(entry) != SOURCE_INDEX_KEYS
            or member not in archive_members
            or entry.get("size") != len(archive_members[member])
            or entry.get("sha256") != _sha256(archive_members[member])
        ):
            raise PackagingError("archived run-source member differs from its index")
        expected_members.add(member)
    archived_snapshot_index = archived_release.get("snapshot_index")
    if not isinstance(archived_snapshot_index, Mapping):
        raise PackagingError("archived source snapshot index is malformed")
    for source_path, entry in archived_snapshot_index.items():
        if (
            not isinstance(source_path, str)
            or not isinstance(entry, Mapping)
            or set(entry) != SNAPSHOT_INDEX_KEYS
        ):
            raise PackagingError("archived source snapshot entry is malformed")
        member = entry.get("member")
        if (
            member != f"snapshot/{source_path}"
            or member not in archive_members
            or entry.get("size") != len(archive_members[member])
            or entry.get("sha256") != _sha256(archive_members[member])
            or entry.get("inventory")
            not in {"frozen_source_inventory", "frozen_configuration_inventory"}
        ):
            raise PackagingError("archived source snapshot differs from its index")
        expected_members.add(str(member))
    reproduction_members = {
        name for name in archive_members if name.startswith("reproduction/")
    }
    if len(reproduction_members) != 2:
        raise PackagingError("archived reproduction packet is incomplete")
    expected_members.update(reproduction_members)
    if set(archive_members) != expected_members:
        raise PackagingError("final archive contains an unindexed or missing member")
    try:
        envelope = safe_json_loads(envelope_bytes)
    except UnsafeSerializationError as exc:
        raise PackagingError("final package envelope is malformed") from exc
    if not isinstance(envelope, Mapping):
        raise PackagingError("final package envelope must be an object")
    ledger = EventLedger(
        project_root, Path("runs") / run_id / "events.jsonl"
    ).validate()
    if (
        not ledger.valid
        or not ledger.events
        or ledger.head_hash != manifest.get("ledger_head_hash")
        or len(ledger.events) != manifest.get("event_count")
    ):
        raise PackagingError("final package ledger anchor is invalid")
    raw_receipts = manifest.get("typed_transition_receipts")
    try:
        ledger_receipts = validate_legacy_transition_prefix(
            event.to_dict() for event in ledger.events
        )
        if not isinstance(raw_receipts, list):
            raise ValueError("mutable transition receipts are not a list")
        parsed_receipts = tuple(
            TransitionResult.from_dict(value) for value in raw_receipts
        )
        if (
            tuple(receipt.to_dict() for receipt in parsed_receipts)
            != tuple(raw_receipts)
            or parsed_receipts != ledger_receipts
        ):
            raise ValueError("mutable receipts differ from the ledger")
        StateController(
            initial_state=ledger.events[-1].requested_state_after,
            artifact_registry=registry,
            prior_receipts=parsed_receipts,
        )
    except Exception as exc:
        raise PackagingError(
            "final transition history does not exactly replay"
        ) from exc
    _validate_resource_authority_projection(
        ledger.events, live_resource_authority
    )
    final_event = ledger.events[-1]
    if len(ledger.events) < 2:
        raise PackagingError("final ledger lacks a pre-release prefix")
    pre_release_manifest_bytes = archive_members.get(
        "run/FROZEN_SOURCE_RUN_MANIFEST.json"
    )
    archived_ledger_bytes = archive_members.get("run/events.jsonl")
    if pre_release_manifest_bytes is None or archived_ledger_bytes is None:
        raise PackagingError("final archive omits its frozen run provenance")
    try:
        pre_release_manifest = safe_json_loads(pre_release_manifest_bytes)
    except UnsafeSerializationError as exc:
        raise PackagingError("archived pre-release manifest is malformed") from exc
    if not isinstance(pre_release_manifest, Mapping):
        raise PackagingError("archived pre-release manifest is not an object")
    artifact_projection = manifest.get("artifacts")
    if not isinstance(artifact_projection, Mapping):
        raise PackagingError("final artifact projection is malformed")
    validation = registry.verify_all()
    records_by_hash = {record.sha256: record for record in validation.records}
    if not validation.valid or validation.count != len(artifact_projection):
        raise PackagingError("final registry is incomplete or corrupt")
    archived_custody_bytes = archive_members.get("run/custody.jsonl")
    custody_entry = artifact_index.get("custody_record")
    try:
        custody_record = (
            safe_json_loads(archive_members[str(custody_entry.get("member"))])
            if isinstance(custody_entry, Mapping)
            else None
        )
    except UnsafeSerializationError as exc:
        raise PackagingError("archived custody record is malformed") from exc
    if archived_custody_bytes is None or not isinstance(custody_record, Mapping):
        raise PackagingError("final archive omits custody evidence")
    protocol_entry = artifact_index.get("frozen_protocol")
    try:
        protocol_record = (
            safe_json_loads(archive_members[str(protocol_entry.get("member"))])
            if isinstance(protocol_entry, Mapping)
            else None
        )
    except UnsafeSerializationError as exc:
        raise PackagingError("archived frozen protocol is malformed") from exc
    if not isinstance(protocol_record, Mapping):
        raise PackagingError("final archive omits its frozen protocol")
    live_custody = SimulatedHoldoutCustody(
        (Role.EXPERIMENT_RUNNER.value,),
        journal_root=project_root,
        journal_path=_custody_journal_path(run_id),
    )
    with live_custody.admission_guard(
        expected_journal_head_hash=str(custody_record.get("journal_head_hash")),
        expected_journal_identity_sha256=str(
            custody_record.get("journal_identity_sha256")
        ),
    ) as custody_snapshot:
        live_custody_bytes = _validate_custody_snapshot(
            custody_record,
            protocol_record,
            str(artifact_projection["frozen_source_inventory"]["sha256"]),
            str(artifact_projection["frozen_configuration_inventory"]["sha256"]),
            str(manifest.get("protocol_hash")),
            str(manifest.get("code_fingerprint")),
            str(manifest.get("configuration_sha256")),
            live_custody,
            custody_snapshot,
            _custody_journal_path(run_id).as_posix(),
            artifact_records=artifact_projection,
            registry=registry,
            events=ledger.events,
        )
        if live_custody_bytes != archived_custody_bytes:
            raise PackagingError("live custody differs from the frozen final packet")
    expected_release_keys = {
        "schema_version", "kind", "run_id", "package_kind",
        "completion_label", "review_state", "publication_authority",
        "novelty", "synthetic_only", "external_integrations_used",
        "artifact_index", "source_run_index", "snapshot_index", "ledger_head_hash",
        "event_count", "code_fingerprint", "configuration_sha256",
        "r_checks", "evaluator_decisions", "reproduction", "limitations",
    }
    if (
        set(archived_release) != expected_release_keys
        or archived_release.get("schema_version") != "1.0"
        or archived_release.get("kind") != "SCIENTIST_ONE_RELEASE_CANDIDATE"
        or archived_release.get("run_id") != run_id
        or archived_release.get("package_kind") != "DEMO_RESEARCH_PACKAGE"
        or archived_release.get("completion_label") != "COMPLETE_DEMO_ONLY"
        or archived_release.get("review_state") != "READY_FOR_HUMAN_REVIEW"
        or archived_release.get("publication_authority") != "E4_HUMAN_REQUIRED"
        or archived_release.get("novelty") != "NOVELTY_UNVERIFIED"
        or archived_release.get("synthetic_only") is not True
        or archived_release.get("external_integrations_used") != []
        or archived_release.get("ledger_head_hash")
        != pre_release_manifest.get("ledger_head_hash")
        or archived_release.get("event_count")
        != pre_release_manifest.get("event_count")
        or archived_release.get("code_fingerprint")
        != pre_release_manifest.get("code_fingerprint")
        or archived_release.get("configuration_sha256")
        != pre_release_manifest.get("configuration_sha256")
        or archived_release.get("r_checks") != pre_release_manifest.get("r_checks")
        or archived_release.get("evaluator_decisions")
        != {
            key: {
                "decision": pre_release_manifest["evaluator_decisions"][key][
                    "decision"
                ],
                "authority": pre_release_manifest["evaluator_decisions"][key][
                    "authority"
                ],
            }
            for key in ("E0:AUDIT", "E2:AUDIT", "E3:AUDIT")
        }
        or archived_release.get("reproduction")
        != {
            key: pre_release_manifest["reproduction"][key]
            for key in (
                "status", "reproduction_id", "source_result_sha256"
            )
        }
    ):
        raise PackagingError("archived release manifest is not evidence-consistent")
    archived_artifacts = pre_release_manifest.get("artifacts")
    if not isinstance(archived_artifacts, Mapping) or set(artifact_index) != set(
        archived_artifacts
    ):
        raise PackagingError("archived artifact index is incomplete")
    for logical_type, entry in artifact_index.items():
        projected = archived_artifacts.get(logical_type)
        if (
            not isinstance(projected, Mapping)
            or entry.get("sha256") != projected.get("sha256")
            or entry.get("logical_type") != projected.get("logical_type")
            or entry.get("frozen") is not True
            or entry.get("registry_record_hash")
            != projected.get("registry_record_hash")
            or entry.get("parent_artifacts")
            != projected.get("parent_artifacts")
        ):
            raise PackagingError("archived artifact index differs from run evidence")
        metadata_member = next(
            name
            for name in archive_members
            if name.startswith(f"registry/{logical_type}-")
        )
        archived_metadata = safe_json_loads(archive_members[metadata_member])
        live_metadata = records_by_hash.get(str(projected.get("sha256")))
        if (
            live_metadata is None
            or archived_metadata != live_metadata.to_dict()
        ):
            raise PackagingError("archived registry record differs from live evidence")
    expected_source_names = {
        "FROZEN_SOURCE_RUN_MANIFEST.json", "events.jsonl",
        "checkpoint.json", "custody.jsonl",
    }
    expected_source_names.update(
        f"resource-authority/{name}" for name in live_resource_authority
    )
    if set(source_index) != expected_source_names:
        raise PackagingError("archived run-source index is incomplete")
    for name, content in live_resource_authority.items():
        if archive_members.get(f"run/resource-authority/{name}") != content:
            raise PackagingError(
                "archived resource authority differs from its live monotonic anchor"
            )
    frozen_reproduction = pre_release_manifest.get("reproduction")
    if not isinstance(frozen_reproduction, Mapping):
        raise PackagingError("archived run omits frozen reproduction evidence")
    expected_reproduction_members = {
        f"reproduction/{Path(str(frozen_reproduction[key])).name}"
        for key in ("manifest_path", "result_path")
    }
    if reproduction_members != expected_reproduction_members:
        raise PackagingError("archived reproduction members differ from frozen evidence")
    expected_snapshot_index: dict[str, dict[str, Any]] = {}
    for inventory_name, aggregate_name in (
        ("frozen_source_inventory", "code_fingerprint"),
        ("frozen_configuration_inventory", "configuration_sha256"),
    ):
        inventory_entry = artifact_index.get(inventory_name)
        if not isinstance(inventory_entry, Mapping):
            raise PackagingError(f"archived {inventory_name} is absent")
        inventory_bytes = archive_members.get(str(inventory_entry.get("member")))
        if inventory_bytes is None:
            raise PackagingError(f"archived {inventory_name} bytes are absent")
        inventory_payload, planned_snapshot, _ = _inventory_plan_from_bytes(
            project_root, inventory_bytes, inventory_name, require_live=True
        )
        if inventory_payload.get("aggregate_sha256") != pre_release_manifest.get(
            aggregate_name
        ):
            raise PackagingError(f"archived {inventory_name} aggregate is unbound")
        if set(expected_snapshot_index).intersection(planned_snapshot):
            raise PackagingError("archived source/configuration snapshots overlap")
        expected_snapshot_index.update(planned_snapshot)
    if dict(archived_snapshot_index) != expected_snapshot_index:
        raise PackagingError("archived snapshot index is not inventory-derived")
    try:
        archived_checkpoint = safe_json_loads(
            archive_members["run/checkpoint.json"]
        )
    except UnsafeSerializationError as exc:
        raise PackagingError("archived checkpoint is malformed") from exc
    expected_archived_checkpoint = {
        "schema_version": "1.0",
        "run_id": run_id,
        "state": pre_release_manifest.get("current_state"),
        "terminal_state": pre_release_manifest.get("terminal_state"),
        "event_count": pre_release_manifest.get("event_count"),
        "ledger_head_hash": pre_release_manifest.get("ledger_head_hash"),
        "artifact_hashes": {
            key: value["sha256"]
            for key, value in sorted(archived_artifacts.items())
        },
        "artifact_record_hashes": {
            key: value["registry_record_hash"]
            for key, value in sorted(archived_artifacts.items())
        },
        "resource_runtime_artifact": pre_release_manifest.get(
            "resource_runtime_artifact"
        ),
        "resumable": True,
    }
    if archived_checkpoint != expected_archived_checkpoint:
        raise PackagingError("archived checkpoint differs from its frozen run")
    expected_pre_release = safe_json_loads(canonical_json_bytes(manifest))
    expected_pre_release["updated_at"] = pre_release_manifest.get("updated_at")
    expected_pre_release["current_state"] = "RELEASE"
    expected_pre_release["terminal_state"] = None
    expected_pre_release["outcome"] = "IN_PROGRESS"
    expected_pre_release["package"] = None
    expected_pre_release["event_count"] = len(ledger.events) - 1
    expected_pre_release["ledger_head_hash"] = ledger.events[-2].event_hash
    expected_pre_release["completed_transitions"] = list(
        manifest.get("completed_transitions", ())[:-1]
    )
    expected_pre_release["typed_transition_receipts"] = list(
        manifest.get("typed_transition_receipts", ())[:-1]
    )
    expected_pre_release["artifacts"].pop("release_candidate", None)
    for key in ("E0:RELEASE", "E2:RELEASE", "E3:RELEASE"):
        expected_pre_release["evaluator_decisions"].pop(key, None)
    if dict(pre_release_manifest) != expected_pre_release:
        raise PackagingError("final mutable manifest differs from its frozen pre-release form")
    archived_prefix = EventLedger._validate_bytes(archived_ledger_bytes)
    if (
        not archived_prefix.valid
        or archived_prefix.head_hash != ledger.events[-2].event_hash
        or len(archived_prefix.events) != len(ledger.events) - 1
        or [event.to_dict() for event in archived_prefix.events]
        != [event.to_dict() for event in ledger.events[:-1]]
    ):
        raise PackagingError("archived ledger is not the exact final ledger prefix")
    terminal_receipts = manifest.get("typed_transition_receipts")
    if (
        manifest.get("current_state") != "READY_FOR_HUMAN_REVIEW"
        or manifest.get("terminal_state") != "READY_FOR_HUMAN_REVIEW"
        or manifest.get("outcome") != "COMPLETE_DEMO_ONLY"
        or manifest.get("novelty") != "NOVELTY_UNVERIFIED"
        or manifest.get("external_integrations_used") != []
        or manifest.get("completed_transitions", [])[-1:]
        != ["RELEASE->READY_FOR_HUMAN_REVIEW"]
        or not isinstance(terminal_receipts, list)
        or len(terminal_receipts) != len(manifest.get("completed_transitions", ()))
        or terminal_receipts[-1].get("prior_state") != "RELEASE"
        or terminal_receipts[-1].get("current_state")
        != "READY_FOR_HUMAN_REVIEW"
    ):
        raise PackagingError("final governance projection is not a typed terminal state")
    raw_final_receipt = terminal_receipts[-1]
    final_contract = next(
        (
            contract
            for contract in macro_transition_contracts()
            if contract.source.value == "RELEASE"
            and contract.destination.value == "READY_FOR_HUMAN_REVIEW"
        ),
        None,
    )
    try:
        final_receipt = TransitionResult.from_dict(raw_final_receipt)
        event_receipt = validate_legacy_transition_event_receipt(
            final_event.to_dict()
        )
    except (TypeError, ValueError) as exc:
        raise PackagingError("final typed transition receipt is malformed") from exc
    if (
        not isinstance(raw_final_receipt, Mapping)
        or final_receipt.to_dict() != dict(raw_final_receipt)
        or event_receipt != final_receipt
        or final_receipt.idempotency_key
        != f"{run_id}:RELEASE:READY_FOR_HUMAN_REVIEW"
        or final_receipt.replayed is not False
        or final_contract is None
        or final_receipt.generated_artifact_types
        != tuple(sorted(final_contract.generated_artifact_types))
        or safe_json_loads(
            canonical_json_bytes(final_event.metadata.get("transition_receipt"))
        )
        != dict(raw_final_receipt)
    ):
        raise PackagingError("final typed transition receipt differs from its contract")
    ledger_roots: set[str] = set()
    for event in ledger.events:
        types = event.metadata.get("artifact_types", ())
        record_hashes = event.metadata.get("artifact_record_hashes", ())
        descriptors = event.metadata.get("artifact_descriptors", ())
        if (
            not isinstance(types, (list, tuple))
            or not isinstance(record_hashes, (list, tuple))
            or not isinstance(descriptors, (list, tuple))
            or len(types) != len(event.artifact_hashes)
            or len(record_hashes) != len(event.artifact_hashes)
            or len(descriptors) != len(event.artifact_hashes)
        ):
            if event.artifact_hashes:
                raise PackagingError("final ledger artifact projection is malformed")
            continue
        for logical_type, digest, record_hash, descriptor in zip(
            types,
            event.artifact_hashes,
            record_hashes,
            descriptors,
            strict=True,
        ):
            projected = artifact_projection.get(logical_type)
            metadata = records_by_hash.get(digest)
            if (
                not isinstance(logical_type, str)
                or not isinstance(record_hash, str)
                or not isinstance(projected, Mapping)
                or projected.get("sha256") != digest
                or projected.get("registry_record_hash") != record_hash
                or metadata is None
                or metadata.logical_type != logical_type
                or metadata.record_hash != record_hash
            ):
                raise PackagingError("final ledger/manifest/registry binding differs")
            expected_descriptor = {
                "logical_type": logical_type,
                "sha256": digest,
                "registry_record_hash": record_hash,
                "parent_artifacts": list(metadata.parent_artifacts),
                "parent_record_hashes": [
                    records_by_hash[parent].record_hash
                    for parent in metadata.parent_artifacts
                    if parent in records_by_hash
                ],
            }
            if (
                len(expected_descriptor["parent_record_hashes"])
                != len(metadata.parent_artifacts)
                or safe_json_loads(canonical_json_bytes(descriptor))
                != expected_descriptor
            ):
                raise PackagingError("final ledger lacks recursive provenance binding")
            ledger_roots.add(digest)
    closure: set[str] = set()
    pending = list(ledger_roots)
    while pending:
        digest = pending.pop()
        if digest in closure:
            continue
        metadata = records_by_hash.get(digest)
        if metadata is None:
            raise PackagingError("final registry parent closure is incomplete")
        closure.add(digest)
        pending.extend(metadata.parent_artifacts)
    if closure != set(records_by_hash):
        raise PackagingError("final registry contains evidence outside the ledger closure")
    projected_hashes = {
        projected.get("sha256")
        for projected in artifact_projection.values()
        if isinstance(projected, Mapping)
        and isinstance(projected.get("sha256"), str)
    }
    if (
        len(projected_hashes) != len(artifact_projection)
        or projected_hashes != set(records_by_hash)
    ):
        raise PackagingError("final manifest artifact identities differ from registry")
    for logical_type, projected in artifact_projection.items():
        if not isinstance(projected, Mapping):
            raise PackagingError("final manifest artifact record is malformed")
        stored = records_by_hash.get(str(projected.get("sha256")))
        if stored is None:
            raise PackagingError("final manifest artifact is absent from registry")
        presentation_path = projected.get("path")
        if not isinstance(presentation_path, str):
            raise PackagingError("final manifest artifact path is malformed")
        presentation_bytes = _confined_bytes(
            project_root, presentation_path, max_bytes=32 * 1024 * 1024
        )
        if (
            len(presentation_bytes) != stored.size
            or _sha256(presentation_bytes) != stored.sha256
        ):
            raise PackagingError(
                "final presentation artifact differs from registry content"
            )
        expected_projection = {
            "logical_type": stored.logical_type,
            "path": presentation_path,
            "sha256": stored.sha256,
            "size": stored.size,
            "schema_version": stored.schema_version,
            "mime_type": stored.mime_type,
            "origin": stored.origin,
            "creator_role": stored.creator_role.value,
            "creation_command": list(stored.creation_command),
            "parent_artifacts": list(stored.parent_artifacts),
            "validation_result": stored.validation_result,
            "frozen": stored.frozen,
            "registry_path": stored.path,
            "registry_metadata_path": stored.metadata_path,
            "registry_record_hash": stored.record_hash,
        }
        if dict(projected) != expected_projection:
            raise PackagingError("final manifest artifact projection differs from registry")
    release_record = artifact_projection.get("release_candidate")
    if not isinstance(release_record, Mapping):
        raise PackagingError("final release-candidate artifact is absent")
    try:
        metadata = registry.get_metadata(str(release_record.get("sha256")))
        release_bytes = registry.get_bytes(metadata.sha256)
    except ArtifactError as exc:
        raise PackagingError("release-candidate registry evidence is invalid") from exc
    expected_release_path = (
        f"runs/{run_id}/artifacts/release/"
        f"release_candidate-{str(release_record.get('sha256'))[:20]}.json"
    )
    if release_record.get("path") != expected_release_path:
        raise PackagingError("release-candidate presentation path is non-canonical")
    try:
        release_payload = safe_json_loads(release_bytes)
    except UnsafeSerializationError as exc:
        raise PackagingError("release-candidate payload is malformed") from exc
    base_projection = dict(package)
    base_projection["envelope_path"] = None
    base_projection["envelope_sha256"] = None
    if (
        release_payload != base_projection
        or metadata.record_hash != release_record.get("registry_record_hash")
        or metadata.logical_type != "release_candidate"
        or metadata.sha256 not in final_event.artifact_hashes
    ):
        raise PackagingError("release candidate is not bound to the final projection")
    reproduction_record = artifact_projection.get("reproduction_report")
    if not isinstance(reproduction_record, Mapping):
        raise PackagingError("frozen reproduction report is absent")
    try:
        reproduction_bytes = registry.get_bytes(str(reproduction_record.get("sha256")))
        frozen_reproduction = safe_json_loads(reproduction_bytes)
    except (ArtifactError, UnsafeSerializationError) as exc:
        raise PackagingError("frozen reproduction report is invalid") from exc
    if frozen_reproduction != manifest.get("reproduction"):
        raise PackagingError("mutable reproduction projection differs from frozen evidence")
    run_intent_record = artifact_projection.get("run_intent")
    try:
        frozen_run_intent = (
            safe_json_loads(
                registry.get_bytes(str(run_intent_record.get("sha256")))
            )
            if isinstance(run_intent_record, Mapping)
            else None
        )
    except (ArtifactError, UnsafeSerializationError) as exc:
        raise PackagingError("frozen run intent is invalid") from exc
    if (
        not isinstance(frozen_run_intent, Mapping)
        or frozen_run_intent.get("mode") != manifest.get("mode")
        or frozen_run_intent.get("synthetic_scenario")
        != manifest.get("synthetic_scenario")
        or frozen_run_intent.get("package_kind") != manifest.get("package_kind")
    ):
        raise PackagingError("final mutable run intent differs from frozen evidence")
    event_types = final_event.metadata.get("artifact_types", ())
    event_records = final_event.metadata.get("artifact_record_hashes", ())
    try:
        release_index = final_event.artifact_hashes.index(metadata.sha256)
    except ValueError as exc:
        raise PackagingError("final event omits the release candidate") from exc
    if (
        final_event.event_type != "TRANSITION"
        or final_event.state_before.value != "RELEASE"
        or final_event.requested_state_after.value != "READY_FOR_HUMAN_REVIEW"
        or not isinstance(event_types, (list, tuple))
        or not isinstance(event_records, (list, tuple))
        or len(event_types) != len(final_event.artifact_hashes)
        or len(event_records) != len(final_event.artifact_hashes)
        or event_types[release_index] != "release_candidate"
        or event_records[release_index] != metadata.record_hash
    ):
        raise PackagingError("final release transition binding is malformed")
    evaluators = manifest.get("evaluator_decisions", {})
    full_ledger_evaluations = _ledger_evaluator_projection(ledger.events)
    if full_ledger_evaluations != evaluators:
        raise PackagingError("final evaluator projection differs from the ledger")
    evaluator_hashes = {
        key: evaluators.get(key, {}).get("evaluation_sha256")
        for key in ("E0:RELEASE", "E2:RELEASE", "E3:RELEASE")
    }
    event_evaluations = {
        key: full_ledger_evaluations[key]
        for key in final_event.metadata.get("evaluator_keys", ())
    }
    if any(
        not isinstance(event_evaluations.get(key), Mapping)
        or not isinstance(evaluators.get(key), Mapping)
        or dict(event_evaluations[key]) != dict(evaluators[key])
        or event_evaluations[key].get("evaluation_sha256") != digest
        for key, digest in evaluator_hashes.items()
    ):
        raise PackagingError("final release evaluator receipts differ from the ledger")
    expected_envelope = {
        "schema_version": "1.0",
        "kind": "FINAL_RELEASE_ENVELOPE",
        "run_id": run_id,
        "archive_path": archive_path,
        "archive_sha256": package["archive_sha256"],
        "release_candidate_sha256": metadata.sha256,
        "release_candidate_record_hash": metadata.record_hash,
        "final_ledger_head_hash": ledger.head_hash,
        "final_event_count": len(ledger.events),
        "final_event_id": final_event.event_id,
        "release_evaluator_sha256": evaluator_hashes,
        "terminal_state": "READY_FOR_HUMAN_REVIEW",
        "outcome": "COMPLETE_DEMO_ONLY",
        "publication_authority": "E4_HUMAN_REQUIRED",
        "bundle_role": "PRE_RELEASE_EVIDENCE_BUNDLE",
        "ledger_events": [event.to_dict() for event in ledger.events],
        "release_candidate_record": metadata.to_dict(),
        "release_candidate_payload": release_payload,
        "release_evaluator_receipts": {
            key: dict(event_evaluations[key])
            for key in ("E0:RELEASE", "E2:RELEASE", "E3:RELEASE")
        },
    }
    if dict(envelope) != expected_envelope:
        raise PackagingError("detached final release envelope does not match the ledger")
    detached_ledger_bytes = b"".join(
        canonical_json_bytes(event) + b"\n"
        for event in envelope["ledger_events"]
    )
    detached_validation = EventLedger._validate_bytes(detached_ledger_bytes)
    if (
        not detached_validation.valid
        or detached_validation.head_hash != envelope["final_ledger_head_hash"]
        or len(detached_validation.events) != envelope["final_event_count"]
    ):
        raise PackagingError("detached final release envelope is not self-verifying")
    with live_custody.admission_guard(
        expected_journal_head_hash=str(custody_record["journal_head_hash"]),
        expected_journal_identity_sha256=str(
            custody_record["journal_identity_sha256"]
        ),
    ) as final_custody_snapshot:
        final_custody_bytes = _validate_custody_snapshot(
            custody_record,
            protocol_record,
            str(artifact_projection["frozen_source_inventory"]["sha256"]),
            str(artifact_projection["frozen_configuration_inventory"]["sha256"]),
            str(manifest.get("protocol_hash")),
            str(manifest.get("code_fingerprint")),
            str(manifest.get("configuration_sha256")),
            live_custody,
            final_custody_snapshot,
            _custody_journal_path(run_id).as_posix(),
            artifact_records=artifact_projection,
            registry=registry,
            events=ledger.events,
        )
        if final_custody_bytes != archived_custody_bytes:
            raise PackagingError("final custody advanced during packet verification")
        return PackageResult(**dict(package))


def _canonical_json(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value) + b"\n"
    except UnsafeSerializationError as exc:
        raise PackagingError("release candidate is not safe canonical JSON") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _contract_projection(contract: Any) -> dict[str, Any]:
    return {
        "source": contract.source.value,
        "destination": contract.destination.value,
        "required_artifacts": sorted(contract.required_artifact_types),
        "required_evaluators": sorted(
            item.value for item in contract.required_evaluators
        ),
        "requesters": sorted(item.value for item in contract.allowed_requesters),
        "approvers": sorted(item.value for item in contract.allowed_approvers),
        "generated_artifacts": sorted(contract.generated_artifact_types),
        "failure_states": sorted(item.value for item in contract.failure_states),
        "validation_rules": list(contract.validation_rules),
        "idempotency": contract.idempotency_rule,
    }


def _read_json(path: Path, root: Path | None = None) -> dict[str, Any]:
    trust_root = root or path.parent
    try:
        canonical_root = trust_root.resolve(strict=True)
        candidate = path if path.is_absolute() else canonical_root / path
        relative = candidate.relative_to(canonical_root)
        payload = read_confined_bytes(
            canonical_root,
            relative,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
        if payload is None:
            raise PackagingError("JSON evidence disappeared")
        value = safe_json_loads(payload)
    except (OSError, ValueError, PathSecurityError, UnsafeSerializationError) as exc:
        raise PackagingError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise PackagingError(f"expected JSON object in {path.name}")
    return value


def _safe_run_dir(root: Path, run_id: str) -> Path:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise PackagingError("invalid run ID")
    try:
        return secure_directory(root, Path("runs") / run_id, create=False)
    except PathSecurityError as exc:
        raise PackagingError("unsafe run directory") from exc


def _confined_bytes(
    root: Path,
    raw: str | Path,
    *,
    max_bytes: int = 64 * 1024 * 1024,
) -> bytes:
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise PackagingError("review-packet path must be project-relative")
    try:
        payload = read_confined_bytes(
            root,
            relative,
            reject_hardlinks=True,
            max_bytes=max_bytes,
        )
    except PathSecurityError as exc:
        raise PackagingError("review-packet input is unsafe or absent") from exc
    if payload is None:
        raise PackagingError("review-packet input disappeared")
    return payload


def _artifact_bytes(root: Path, record: Mapping[str, Any]) -> tuple[str, bytes]:
    raw = record.get("path")
    expected = record.get("sha256")
    if not isinstance(raw, str) or not raw or Path(raw).is_absolute():
        raise PackagingError("artifact path must be project-relative")
    data = _confined_bytes(root, raw, max_bytes=32 * 1024 * 1024)
    if not isinstance(expected, str) or _sha256(data) != expected:
        raise PackagingError(f"artifact hash mismatch: {Path(raw).name}")
    return Path(raw).name, data


def _validate_ledger(
    data: bytes, run_id: str, expected_head: str, expected_count: int
) -> tuple[LedgerEvent, ...]:
    result = EventLedger._validate_bytes(data)
    if (
        not result.valid
        or len(result.events) != expected_count
        or result.head_hash != expected_head
        or any(event.run_id != run_id for event in result.events)
    ):
        raise PackagingError("event ledger does not match the frozen run manifest")
    return result.events


def _secure_directory(root: Path, path: Path, *, create: bool) -> Path:
    root = root.resolve(strict=True)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise PackagingError("package directory escapes project root") from exc
    current = root
    for component in relative.parts:
        if component in {"", ".", ".."}:
            raise PackagingError("unsafe package directory component")
        candidate = current / component
        try:
            candidate.lstat()
        except FileNotFoundError:
            if not create:
                raise PackagingError("package directory is absent")
            candidate.mkdir()
        if candidate.is_symlink() or not candidate.is_dir():
            raise PackagingError("package directory contains a link or non-directory")
        current = candidate
    resolved = current.resolve(strict=True)
    if root not in resolved.parents and resolved != root:
        raise PackagingError("package directory resolves outside root")
    return resolved


def _contains_forbidden_boundary_text(
    data: bytes, *, source_member: bool = False
) -> bool:
    """Reject secrets, invalid text, and unapproved absolute path disclosures."""

    if not isinstance(data, bytes):
        return True
    if any(pattern.search(data) for pattern in CONCRETE_SECRET_BYTE_PATTERNS):
        return True
    allowed = TRUSTED_SOURCE_ABSOLUTE_REFERENCES if source_member else frozenset()
    if any(match.group(0) not in allowed for match in ABSOLUTE_PATH_BYTE_PATTERN.finditer(data)):
        return True
    if re.search(rb"(?<![A-Za-z0-9_])[A-Za-z]:\\(?:[^\x00\r\n]+)", data):
        return True
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return bool(detect_secret_patterns(text))


def _inventory_matches_live(project_root: Path, payload: Mapping[str, Any]) -> bool:
    kind = payload.get("kind")
    if kind == "FROZEN_SOURCE_INVENTORY":
        directory, suffix = Path("src/scientist_one"), ".py"
    elif kind == "FROZEN_CONFIGURATION_INVENTORY":
        directory, suffix = Path("configs"), ".json"
    else:
        return False
    entries = payload.get("entries")
    if (
        payload.get("schema_version") != "1.0"
        or not isinstance(entries, list)
        or not entries
        or payload.get("aggregate_sha256")
        != _sha256(canonical_json_bytes(entries) + b"\n")
    ):
        return False
    observed: list[dict[str, Any]] = []
    try:
        directory_fd = open_confined_directory_fd(
            project_root, directory, create=False
        )
        try:
            collected: list[str] = []
            with os.scandir(directory_fd) as iterator:
                for entry in iterator:
                    if entry.name.endswith(suffix):
                        if len(collected) >= MAX_INVENTORY_ENTRIES:
                            return False
                        collected.append(entry.name)
            names = tuple(sorted(collected))
            directory_entries = [
                item
                for item in entries
                if isinstance(item, Mapping)
                and Path(str(item.get("path", ""))).parent == directory
            ]
            if names != tuple(Path(str(item.get("path", ""))).name for item in directory_entries):
                return False
            aggregate_bytes = 0
            for name in names:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    info = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                        or info.st_size > 4 * 1024 * 1024
                    ):
                        return False
                    chunks: list[bytes] = []
                    total = 0
                    while chunk := os.read(descriptor, 1024 * 1024):
                        total += len(chunk)
                        if total > 4 * 1024 * 1024:
                            return False
                        chunks.append(chunk)
                    data = b"".join(chunks)
                finally:
                    os.close(descriptor)
                observed.append(
                    {
                        "path": (directory / name).as_posix(),
                        "sha256": _sha256(data),
                        "size": len(data),
                    }
                )
                aggregate_bytes += len(data)
                if aggregate_bytes > MAX_INVENTORY_TOTAL_BYTES:
                    return False
        finally:
            os.close(directory_fd)
    except (OSError, PathSecurityError, TypeError, ValueError):
        return False
    if kind == "FROZEN_SOURCE_INVENTORY":
        try:
            launcher = _confined_bytes(
                project_root,
                "scripts/scientist_one_cli.py",
                max_bytes=4 * 1024 * 1024,
            )
        except PackagingError:
            return False
        observed.append(
            {
                "path": "scripts/scientist_one_cli.py",
                "sha256": _sha256(launcher),
                "size": len(launcher),
            }
        )
        observed.sort(key=lambda item: item["path"])
    return observed == entries


def _inventory_plan_from_bytes(
    project_root: Path,
    content: bytes,
    inventory_name: str,
    *,
    require_live: bool,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], int]:
    """Strictly parse one bounded inventory and derive its packet snapshot plan."""

    try:
        payload = safe_json_loads(content)
    except UnsafeSerializationError as exc:
        raise PackagingError(f"{inventory_name} is malformed") from exc
    expected_kind = (
        "FROZEN_SOURCE_INVENTORY"
        if inventory_name == "frozen_source_inventory"
        else "FROZEN_CONFIGURATION_INVENTORY"
    )
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version", "kind", "entries", "aggregate_sha256"
    }:
        raise PackagingError(f"{inventory_name} schema is malformed")
    entries = payload.get("entries")
    if (
        payload.get("schema_version") != "1.0"
        or payload.get("kind") != expected_kind
        or not isinstance(entries, list)
        or not entries
        or len(entries) > MAX_INVENTORY_ENTRIES
        or payload.get("aggregate_sha256")
        != _sha256(canonical_json_bytes(entries) + b"\n")
    ):
        raise PackagingError(f"{inventory_name} does not satisfy its frozen schema")
    snapshot: dict[str, dict[str, Any]] = {}
    total = 0
    previous = ""
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != {"path", "sha256", "size"}:
            raise PackagingError(f"{inventory_name} entry is malformed")
        path = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size")
        if (
            not isinstance(path, str)
            or Path(path).is_absolute()
            or ".." in Path(path).parts
            or path <= previous
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > 4 * 1024 * 1024
        ):
            raise PackagingError(f"{inventory_name} entry is unsafe")
        previous = path
        total += size
        if total > MAX_INVENTORY_TOTAL_BYTES:
            raise PackagingError(f"{inventory_name} exceeds its aggregate bound")
        snapshot[path] = {
            "member": f"snapshot/{path}",
            "sha256": digest,
            "size": size,
            "inventory": inventory_name,
        }
    if require_live and not _inventory_matches_live(project_root, payload):
        raise PackagingError(f"live workspace differs from {inventory_name}")
    return payload, snapshot, total


def _stored_zip_overhead(member_names: Any) -> int:
    """Sound non-ZIP64 overhead for the bounded ZIP_STORED packet."""

    names = tuple(member_names)
    if len(names) > MAX_PACKAGE_FILES:
        raise PackagingError("review packet contains too many files")
    try:
        return 22 + sum(76 + 2 * len(name.encode("utf-8")) for name in names)
    except (AttributeError, UnicodeEncodeError) as exc:
        raise PackagingError("review packet member name is invalid") from exc


def _validate_custody_snapshot(
    record: Mapping[str, Any],
    protocol_record: Mapping[str, Any],
    source_inventory_sha256: str,
    configuration_inventory_sha256: str,
    run_protocol_hash: str,
    run_code_fingerprint: str,
    run_configuration_sha256: str,
    provider: SimulatedHoldoutCustody,
    live: Any,
    expected_journal_path: str,
    *,
    artifact_records: Mapping[str, Any],
    registry: ArtifactRegistry,
    events: Any,
) -> bytes:
    """Validate the complete frozen custody projection inside the provider guard."""

    expected_keys = {
        "kind", "study_id", "study_version", "custody_independence",
        "holdout_identity_hash", "split_manifest_hash", "sealing_time",
        "authorized_access_count", "access_requester", "access_reason",
        "protocol_hash", "code_hash", "configuration_hash",
        "source_inventory_sha256", "configuration_inventory_sha256",
        "split_manifest_artifact_sha256", "midrun_review_sha256",
        "resource_charge_artifact_sha256",
        "resource_charge_ledger_event_id", "fresh_custody_receipt_sha256",
        "fresh_custody_receipt_event_id",
        "confirmatory_started_event_id", "confirmatory_validity_units",
        "pre_unblinding_interpretation_hash", "seal_hash", "release_event",
        "access_records", "confirmatory_claims_valid", "durable_journal",
        "journal_path", "journal_head_hash", "journal_sha256", "journal_size",
        "journal_identity_sha256", "genuine_independence_claimed",
        "evidence_class", "execution_kind", "scientific_evidence",
    }
    expected_roles = {
        "frozen_protocol": Role.PROTOCOL_DESIGNER,
        "frozen_source_inventory": Role.ORCHESTRATOR,
        "frozen_configuration_inventory": Role.ORCHESTRATOR,
        "frozen_confirmatory_split": Role.PROTOCOL_DESIGNER,
        "blind_interpretation": Role.STATISTICIAN,
        "midrun_review": Role.SCIENTIFIC_REVIEWER,
        "resource_runtime_confirmatory_charge": Role.ORCHESTRATOR,
        "fresh_custody_receipt": Role.HOLDOUT_CUSTODIAN,
        "custody_record": Role.HOLDOUT_CUSTODIAN,
    }

    def resolve_artifact(logical_type: str) -> tuple[Mapping[str, Any], Any]:
        projected = artifact_records.get(logical_type)
        if not isinstance(projected, Mapping) or set(projected) != ARTIFACT_PROJECTION_KEYS:
            raise PackagingError(
                f"custody authority artifact is absent or malformed: {logical_type}"
            )
        try:
            metadata = registry.get_metadata(str(projected.get("sha256")))
        except ArtifactError as exc:
            raise PackagingError(
                f"custody authority artifact is not registry-resolved: {logical_type}"
            ) from exc
        if (
            metadata.logical_type != logical_type
            or metadata.creator_role is not expected_roles[logical_type]
            or dict(projected)
            != _manifest_projection_from_record(projected, metadata)
        ):
            raise PackagingError(
                f"custody authority artifact projection is invalid: {logical_type}"
            )
        return projected, metadata

    resolved = {
        logical_type: resolve_artifact(logical_type)
        for logical_type in expected_roles
    }
    artifact_hashes = {
        logical_type: str(projected["sha256"])
        for logical_type, (projected, _) in resolved.items()
    }
    record_hashes = {
        logical_type: str(projected["registry_record_hash"])
        for logical_type, (projected, _) in resolved.items()
    }
    source_hash = artifact_hashes["frozen_source_inventory"]
    configuration_hash = artifact_hashes["frozen_configuration_inventory"]
    protocol_hash = artifact_hashes["frozen_protocol"]
    split_hash = artifact_hashes["frozen_confirmatory_split"]
    blind_hash = artifact_hashes["blind_interpretation"]
    midrun_hash = artifact_hashes["midrun_review"]
    charge_hash = artifact_hashes["resource_runtime_confirmatory_charge"]
    receipt_hash = artifact_hashes["fresh_custody_receipt"]
    if (
        tuple(resolved["frozen_protocol"][1].parent_artifacts) != ()
        or tuple(resolved["frozen_source_inventory"][1].parent_artifacts) != ()
        or tuple(resolved["frozen_configuration_inventory"][1].parent_artifacts)
        != ()
        or tuple(resolved["frozen_confirmatory_split"][1].parent_artifacts)
        != (protocol_hash,)
        or tuple(resolved["blind_interpretation"][1].parent_artifacts)
        != (source_hash, configuration_hash)
        or tuple(resolved["midrun_review"][1].parent_artifacts)
        != (source_hash, configuration_hash)
        or tuple(resolved["fresh_custody_receipt"][1].parent_artifacts)
        != (
            protocol_hash,
            blind_hash,
            source_hash,
            configuration_hash,
            split_hash,
            midrun_hash,
        )
        or tuple(resolved["custody_record"][1].parent_artifacts)
        != (
            protocol_hash,
            source_hash,
            configuration_hash,
            split_hash,
            blind_hash,
            midrun_hash,
            charge_hash,
            receipt_hash,
        )
    ):
        raise PackagingError("custody authority parent order is invalid")

    charge_parents = tuple(
        resolved["resource_runtime_confirmatory_charge"][1].parent_artifacts
    )
    if len(charge_parents) != 1:
        raise PackagingError("confirmatory resource charge parent is invalid")
    try:
        prior_charge_metadata = registry.get_metadata(charge_parents[0])
        prior_charge = safe_json_loads(registry.get_bytes(charge_parents[0]))
        charged = safe_json_loads(registry.get_bytes(charge_hash))
    except (ArtifactError, UnsafeSerializationError) as exc:
        raise PackagingError("confirmatory resource charge is unreadable") from exc
    validity_units = record.get("confirmatory_validity_units")
    if (
        prior_charge_metadata.logical_type
        != "resource_runtime_pilot_completion"
        or prior_charge_metadata.creator_role is not Role.ORCHESTRATOR
        or not isinstance(prior_charge, Mapping)
        or not isinstance(charged, Mapping)
        or isinstance(validity_units, bool)
        or not isinstance(validity_units, int)
        or validity_units <= 0
        or isinstance(prior_charge.get("confirmatory_used"), bool)
        or not isinstance(prior_charge.get("confirmatory_used"), int)
        or isinstance(charged.get("confirmatory_used"), bool)
        or not isinstance(charged.get("confirmatory_used"), int)
        or charged.get("confirmatory_used")
        != prior_charge.get("confirmatory_used") + validity_units
        or charged.get("exploratory_used") != prior_charge.get("exploratory_used")
        or charged.get("validity_total_units")
        != prior_charge.get("validity_total_units")
    ):
        raise PackagingError("confirmatory validity charge is inconsistent")

    event_by_id: dict[str, tuple[int, Any]] = {}
    for index, event in enumerate(events):
        event_id = getattr(event, "event_id", None)
        if not isinstance(event_id, str) or event_id in event_by_id:
            raise PackagingError("custody authority ledger identity is invalid")
        event_by_id[event_id] = (index, event)
    charge_event_id = record.get("resource_charge_ledger_event_id")
    receipt_event_id = record.get("fresh_custody_receipt_event_id")
    started_event_id = record.get("confirmatory_started_event_id")
    if (
        not isinstance(charge_event_id, str)
        or not isinstance(receipt_event_id, str)
        or not isinstance(started_event_id, str)
        or charge_event_id not in event_by_id
        or receipt_event_id not in event_by_id
        or started_event_id not in event_by_id
    ):
        raise PackagingError("custody authority event selector is invalid")
    receipt_index, receipt_event = event_by_id[receipt_event_id]
    charge_index, charge_event = event_by_id[charge_event_id]
    started_index, started_event = event_by_id[started_event_id]
    receipt_metadata = receipt_event.metadata
    charge_metadata = charge_event.metadata
    if (
        receipt_index >= charge_index
        or receipt_event.event_type != "CHECKPOINT"
        or receipt_event.actor_role is not Role.HOLDOUT_CUSTODIAN
        or receipt_event.state_before != receipt_event.requested_state_after
        or tuple(receipt_event.artifact_hashes) != (receipt_hash,)
        or tuple(receipt_metadata.get("artifact_types", ()))
        != ("fresh_custody_receipt",)
        or tuple(receipt_metadata.get("artifact_record_hashes", ()))
        != (record_hashes["fresh_custody_receipt"],)
    ):
        raise PackagingError("fresh custody receipt ledger binding is invalid")
    if (
        charge_index >= started_index
        or charge_event.event_type != "CHECKPOINT"
        or charge_event.actor_role is not Role.ORCHESTRATOR
        or charge_event.state_before != charge_event.requested_state_after
        or charge_event.requested_state_after
        != receipt_event.requested_state_after
        or tuple(charge_event.artifact_hashes) != (charge_hash,)
        or tuple(charge_metadata.get("artifact_types", ()))
        != ("resource_runtime_confirmatory_charge",)
        or tuple(charge_metadata.get("artifact_record_hashes", ()))
        != (record_hashes["resource_runtime_confirmatory_charge"],)
    ):
        raise PackagingError("confirmatory charge ledger binding is invalid")
    started_types = (
        "frozen_protocol",
        "frozen_source_inventory",
        "frozen_configuration_inventory",
        "frozen_confirmatory_split",
        "blind_interpretation",
        "midrun_review",
        "resource_runtime_confirmatory_charge",
        "fresh_custody_receipt",
    )
    started_metadata = started_event.metadata
    if (
        started_event.event_type != "CHECKPOINT"
        or started_event.actor_role is not Role.ORCHESTRATOR
        or started_event.state_before != started_event.requested_state_after
        or started_event.state_before.value
        not in {state.value for state in MacroState}
        or started_event.requested_state_after
        != charge_event.requested_state_after
        or started_metadata.get("evidence_class")
        != "ARCHITECTURE_CONTROL"
        or started_metadata.get("execution_kind")
        != "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
        or tuple(started_event.artifact_hashes)
        != tuple(artifact_hashes[name] for name in started_types)
        or tuple(started_metadata.get("artifact_types", ())) != started_types
        or tuple(started_metadata.get("artifact_record_hashes", ()))
        != tuple(record_hashes[name] for name in started_types)
    ):
        raise PackagingError(
            "simulated architecture-control STARTED ledger binding is invalid"
        )

    typed_protocol = protocol_record.get("protocol")
    status = live.status
    seal = live.seal
    release = status.release_event
    release_payload = asdict(release) if release is not None else None
    access_records: list[dict[str, Any]] = []
    for raw_line in live.journal_bytes.splitlines():
        try:
            event = safe_json_loads(raw_line)
        except UnsafeSerializationError as exc:
            raise PackagingError("held custody journal event is malformed") from exc
        payload = event.get("payload") if isinstance(event, Mapping) else None
        if isinstance(event, Mapping) and event.get("event_type") in {
            "ACCESS", "RELEASE"
        }:
            if not isinstance(payload, Mapping) or not isinstance(
                payload.get("record"), Mapping
            ):
                raise PackagingError("held custody access event is malformed")
            access_records.append(dict(payload["record"]))
    if (
        set(record) != expected_keys
        or record.get("kind") != "SIMULATED_HOLDOUT_CUSTODY"
        or not isinstance(typed_protocol, Mapping)
        or record.get("study_id") != typed_protocol.get("study_id")
        or record.get("study_version") != typed_protocol.get("study_version")
        or record.get("protocol_hash") != protocol_record.get("protocol_sha256")
        or record.get("protocol_hash") != run_protocol_hash
        or record.get("custody_independence") != live.custody_label
        or record.get("holdout_identity_hash") != seal.holdout_identity_hash
        or record.get("split_manifest_hash") != seal.split_manifest_hash
        or record.get("sealing_time") != seal.sealed_at
        or record.get("protocol_hash") != seal.protocol_hash
        or record.get("code_hash") != seal.code_hash
        or record.get("code_hash") != run_code_fingerprint
        or record.get("configuration_hash") != seal.configuration_hash
        or record.get("configuration_hash") != run_configuration_sha256
        or record.get("source_inventory_sha256") != source_inventory_sha256
        or record.get("configuration_inventory_sha256")
        != configuration_inventory_sha256
        or record.get("split_manifest_artifact_sha256") != split_hash
        or record.get("midrun_review_sha256") != midrun_hash
        or record.get("resource_charge_artifact_sha256") != charge_hash
        or record.get("fresh_custody_receipt_sha256") != receipt_hash
        or record.get("pre_unblinding_interpretation_hash")
        != seal.pre_unblinding_interpretation_hash
        or record.get("seal_hash") != seal.seal_hash
        or record.get("release_event") != release_payload
        or record.get("access_records") != access_records
        or release is None
        or record.get("access_requester") != release.requester
        or record.get("access_reason") != release.reason
        or record.get("authorized_access_count") != status.authorized_access_count
        or record.get("confirmatory_claims_valid") is not False
        or record.get("evidence_class") != "ARCHITECTURE_CONTROL"
        or record.get("execution_kind")
        != "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
        or record.get("scientific_evidence") is not False
        or record.get("durable_journal") is not True
        or record.get("journal_path") != expected_journal_path
        or record.get("journal_head_hash") != live.journal_head_hash
        or record.get("journal_sha256") != live.journal_sha256
        or record.get("journal_size") != live.journal_size
        or record.get("journal_identity_sha256")
        != live.journal_identity_sha256
        or record.get("genuine_independence_claimed") is not False
        or not status.sealed
        or not status.revealed
        or not status.invalidated
        or status.confirmatory_claims_valid
        or status.authorized_access_count != 1
        or tuple(status.violation_reasons)
        != ("simulated architecture-control release is non-evidentiary",)
    ):
        raise PackagingError("live custody differs from its frozen projection")
    return live.journal_bytes


def _read_regular_at(directory_fd: int, name: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PackagingError("package output is not an unlinked regular file")
        if metadata.st_size > 512 * 1024 * 1024:
            raise PackagingError("package output exceeds the archive size bound")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
            total += len(chunk)
            if total > 512 * 1024 * 1024:
                raise PackagingError("package output exceeds the archive size bound")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _publish_immutable(root: Path, destination: Path, data: bytes) -> None:
    root = root.resolve(strict=True)
    try:
        parent_relative = destination.parent.relative_to(root)
        directory_fd = open_confined_directory_fd(
            root, parent_relative, create=True
        )
    except (ValueError, PathSecurityError) as exc:
        raise PackagingError("package output directory is unsafe") from exc
    partial_name = (
        f".{destination.name}.{_sha256(data)[:16]}.{os.urandom(8).hex()}.partial"
    )
    descriptor: int | None = None
    try:
        try:
            existing = _read_regular_at(directory_fd, destination.name)
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise PackagingError("unsafe existing archive path") from exc
        if existing is not None:
            if existing != data:
                raise PackagingError("immutable archive collision")
            return
        write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(partial_name, write_flags, 0o600, dir_fd=directory_fd)
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise PackagingError("short package write")
            offset += written
        os.fsync(descriptor)
        held = os.fstat(descriptor)
        named = os.stat(partial_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(held.st_mode)
            or held.st_nlink != 1
            or (held.st_dev, held.st_ino, held.st_size)
            != (named.st_dev, named.st_ino, named.st_size)
        ):
            raise PackagingError("package partial identity changed before publication")
        try:
            os.link(
                partial_name,
                destination.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            if _read_regular_at(directory_fd, destination.name) != data:
                raise PackagingError("immutable archive collision")
        published_fd = os.open(
            destination.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        try:
            published = os.fstat(published_fd)
            if (
                (published.st_dev, published.st_ino, published.st_size)
                != (held.st_dev, held.st_ino, len(data))
            ):
                raise PackagingError("published archive identity differs from held bytes")
        finally:
            os.close(published_fd)
        os.unlink(partial_name, dir_fd=directory_fd)
        os.close(descriptor)
        descriptor = None
        final = _read_regular_at(directory_fd, destination.name)
        if final != data:
            raise PackagingError("published archive failed final byte verification")
        os.fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(partial_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def _zip_bytes(files: Mapping[str, bytes]) -> bytes:
    if len(files) > MAX_PACKAGE_FILES:
        raise PackagingError("review packet contains too many files")
    input_bytes = sum(len(content) for content in files.values())
    if input_bytes > MAX_PACKAGE_INPUT_BYTES:
        raise PackagingError("review packet exceeds the aggregate input bound")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(files):
            pure_name = PurePosixPath(name)
            if pure_name.is_absolute() or ".." in pure_name.parts:
                raise PackagingError("unsafe archive member name")
            info = zipfile.ZipInfo(pure_name.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, files[name])
            if buffer.tell() > MAX_PACKAGE_INPUT_BYTES:
                raise PackagingError("review archive exceeds the aggregate size bound")
    payload = buffer.getvalue()
    if len(payload) > MAX_PACKAGE_INPUT_BYTES:
        raise PackagingError("review archive exceeds the aggregate size bound")
    return payload


class _PacketFiles:
    """Bound packet growth before bytes are retained, not only before zipping."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.total = 0

    def reserve(self, size: int, *, members: int = 1) -> None:
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise PackagingError("review-packet member size is invalid")
        if len(self.files) + members > MAX_PACKAGE_FILES:
            raise PackagingError("review packet contains too many files")
        if self.total + size > MAX_PACKAGE_INPUT_BYTES:
            raise PackagingError("review packet exceeds the aggregate input bound")

    def add(self, name: str, content: bytes) -> None:
        if name in self.files:
            raise PackagingError("review packet contains a duplicate member")
        self.reserve(len(content))
        self.files[name] = content
        self.total += len(content)


def package_run(root: str | Path, run_id: str) -> PackageResult:
    """Create a deterministic, local-only human-review candidate archive."""

    project_root = Path(root).resolve(strict=True)
    _safe_run_dir(project_root, run_id)
    source_manifest_relative = Path("runs") / run_id / "manifest.json"
    source_manifest_bytes = _confined_bytes(
        project_root, source_manifest_relative, max_bytes=DEFAULT_MAX_JSON_BYTES
    )
    try:
        manifest = safe_json_loads(source_manifest_bytes)
    except UnsafeSerializationError as exc:
        raise PackagingError("source run manifest is malformed") from exc
    if not isinstance(manifest, dict):
        raise PackagingError("source run manifest must be an object")
    if manifest.get("run_id") != run_id:
        raise PackagingError("run manifest identity mismatch")
    if manifest.get("terminal_state") == "READY_FOR_HUMAN_REVIEW":
        return _verify_finalized_package(project_root, run_id, manifest)
    if (
        set(manifest) != RUN_MANIFEST_KEYS
        or manifest.get("schema_version") != "1.0"
        or manifest.get("kind") != "SCIENTIST_ONE_RUN_MANIFEST"
        or manifest.get("current_state") != "RELEASE"
        or manifest.get("terminal_state") is not None
        or manifest.get("outcome") != "IN_PROGRESS"
        or manifest.get("package") is not None
        or manifest.get("novelty") != "NOVELTY_UNVERIFIED"
        or manifest.get("external_integrations_used") != []
    ):
        raise PackagingError("pre-release run governance projection is invalid")
    if manifest.get("mode") != "synthetic_demo":
        raise PackagingError("only the verified local demo has a package adapter")
    evaluators = manifest.get("evaluator_decisions")
    r_checks = manifest.get("r_checks")
    reproduction = manifest.get("reproduction")
    if not isinstance(evaluators, dict):
        raise PackagingError("missing evaluator decisions")
    for required in ("E0:AUDIT", "E2:AUDIT", "E3:AUDIT"):
        decision = evaluators.get(required)
        if not isinstance(decision, dict) or decision.get("decision") != "PASS":
            raise PackagingError(f"blocking evaluator decision: {required}")
    if not isinstance(r_checks, dict) or not isinstance(reproduction, dict):
        raise PackagingError("reproduction controls are absent")
    reproduction_status = reproduction.get("status")
    if reproduction_status == "PASS":
        if any(r_checks.get(f"R{index}") != "PASS" for index in range(8)):
            raise PackagingError("all scientific R0-R7 checks must pass")
    elif reproduction_status == ARCHITECTURE_CONTROL_REPLAY_STATUS:
        expected_review_only_checks = {
            f"R{index}": (
                "UNTESTED" if index in {3, 7} else "PASS"
            )
            for index in range(8)
        }
        if r_checks != expected_review_only_checks:
            raise PackagingError(
                "architecture-control package must preserve R3/R7 as UNTESTED"
            )
    else:
        raise PackagingError("successful frozen replay is required")
    resource_authority = _resource_authority_bytes(project_root, run_id, manifest)

    artifact_records = manifest.get("artifacts")
    if not isinstance(artifact_records, dict):
        raise PackagingError("manifest has no artifacts")
    required_artifacts: set[str] = set()
    for contract in macro_transition_contracts():
        if contract.source.value == "RELEASE":
            continue
        required_artifacts.update(contract.required_artifact_types)
    required_artifacts.update(
        f"claim_evidence.{kind.value}" for kind in EvidenceKind
    )
    required_artifacts.update(
        f"claim_support_receipt.{kind.value}" for kind in EvidenceKind
    )
    registry = ArtifactRegistry(project_root, Path("runs") / run_id / "registry")
    # Admit the declared packet budget from bounded metadata before any
    # registry object is read by verify_all().  This prevents a many-object
    # registry from materializing an oversized packet merely to discover that
    # the aggregate cap was exceeded.
    canonical_source_manifest_bytes = _canonical_json(manifest)
    declared_total = len(canonical_source_manifest_bytes)
    declared_members = 0
    metadata_plans: dict[str, Any] = {}
    inventory_plans: dict[str, tuple[dict[str, Any], dict[str, dict[str, Any]], int]] = {}
    for logical_type, projected in artifact_records.items():
        if not isinstance(projected, Mapping) or set(projected) != ARTIFACT_PROJECTION_KEYS:
            raise PackagingError("malformed artifact record")
        size = projected.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise PackagingError("artifact declares an invalid size")
        if size > 32 * 1024 * 1024:
            raise PackagingError("artifact exceeds package evidence size bound")
        try:
            metadata_snapshot = registry.get_metadata(str(projected.get("sha256")))
        except ArtifactError as exc:
            raise PackagingError("artifact registry metadata is absent") from exc
        if (
            metadata_snapshot.logical_type != projected.get("logical_type")
            or dict(projected)
            != _manifest_projection_from_record(projected, metadata_snapshot)
        ):
            raise PackagingError(
                "declared artifact differs from registry metadata: "
                f"{logical_type}"
            )
        presentation = _confined_bytes(
            project_root,
            str(projected.get("path")),
            max_bytes=32 * 1024 * 1024,
        )
        if len(presentation) != size or _sha256(presentation) != metadata_snapshot.sha256:
            raise PackagingError("artifact presentation differs from registry content")
        metadata_size = len(_canonical_json(metadata_snapshot.to_dict()))
        if (
            declared_total + size + metadata_size > MAX_PACKAGE_INPUT_BYTES
            or declared_members + 2 > MAX_PACKAGE_FILES
        ):
            raise PackagingError("review packet exceeds its declared aggregate bound")
        declared_total += size + metadata_size
        declared_members += 2
        metadata_plans[logical_type] = metadata_snapshot
        if logical_type in {
            "frozen_source_inventory", "frozen_configuration_inventory"
        }:
            inventory_plans[logical_type] = _inventory_plan_from_bytes(
                project_root,
                presentation,
                logical_type,
                require_live=True,
            )
    preflight_ledger_bytes = _confined_bytes(
        project_root,
        Path("runs") / run_id / "events.jsonl",
        max_bytes=MAX_LEDGER_BYTES,
    )
    preflight_checkpoint_bytes = _confined_bytes(
        project_root,
        Path("runs") / run_id / "checkpoint.json",
        max_bytes=DEFAULT_MAX_JSON_BYTES,
    )
    preflight_reproduction_bytes: dict[str, bytes] = {}
    for key in ("manifest_path", "result_path"):
        raw_path = reproduction.get(key)
        if not isinstance(raw_path, str) or Path(raw_path).is_absolute():
            raise PackagingError("unsafe reproduction path")
        preflight_reproduction_bytes[key] = _confined_bytes(
            project_root, raw_path, max_bytes=DEFAULT_MAX_JSON_BYTES
        )
    custody_projection = artifact_records.get("custody_record")
    if not isinstance(custody_projection, Mapping):
        raise PackagingError("custody artifact projection is absent")
    preflight_custody_record_bytes = _confined_bytes(
        project_root,
        str(custody_projection.get("path")),
        max_bytes=DEFAULT_MAX_JSON_BYTES,
    )
    try:
        preflight_custody_record = safe_json_loads(
            preflight_custody_record_bytes
        )
    except UnsafeSerializationError as exc:
        raise PackagingError("custody artifact projection is malformed") from exc
    expected_custody_head = (
        preflight_custody_record.get("journal_head_hash")
        if isinstance(preflight_custody_record, Mapping)
        else None
    )
    expected_custody_identity = (
        preflight_custody_record.get("journal_identity_sha256")
        if isinstance(preflight_custody_record, Mapping)
        else None
    )
    if not isinstance(expected_custody_head, str) or not isinstance(
        expected_custody_identity, str
    ):
        raise PackagingError("custody artifact lacks a journal anchor")
    preflight_custody = SimulatedHoldoutCustody(
        (Role.EXPERIMENT_RUNNER.value,),
        journal_root=project_root,
        journal_path=_custody_journal_path(run_id),
    )
    with preflight_custody.admission_guard(
        expected_journal_head_hash=expected_custody_head,
        expected_journal_identity_sha256=expected_custody_identity,
    ) as live_custody:
        preflight_custody_bytes = live_custody.journal_bytes
        preflight_custody_identity = live_custody.journal_identity_sha256
        if preflight_custody_identity != expected_custody_identity:
            raise PackagingError("custody journal identity differs from its anchor")
    snapshot_plan: dict[str, dict[str, Any]] = {}
    snapshot_total = 0
    for inventory_name in (
        "frozen_source_inventory", "frozen_configuration_inventory"
    ):
        if inventory_name not in inventory_plans:
            raise PackagingError(f"{inventory_name} is absent")
        _, planned, total = inventory_plans[inventory_name]
        overlap = set(snapshot_plan).intersection(planned)
        if overlap:
            raise PackagingError("source/configuration inventories overlap")
        snapshot_plan.update(planned)
        snapshot_total += total
    planned_artifact_index: dict[str, dict[str, Any]] = {}
    for logical_type, metadata in sorted(metadata_plans.items()):
        projected = artifact_records[logical_type]
        suffix = Path(str(projected.get("path", "artifact.bin"))).suffix or ".bin"
        planned_artifact_index[logical_type] = {
            "member": (
                f"evidence/{logical_type}/"
                f"{logical_type}-{metadata.sha256[:20]}{suffix}"
            ),
            "sha256": metadata.sha256,
            "logical_type": metadata.logical_type,
            "frozen": metadata.frozen,
            "registry_record_hash": metadata.record_hash,
            "parent_artifacts": list(metadata.parent_artifacts),
        }
    planned_source_index = {
        "FROZEN_SOURCE_RUN_MANIFEST.json": {
            "sha256": _sha256(canonical_source_manifest_bytes),
            "size": len(canonical_source_manifest_bytes),
        },
        "events.jsonl": {
            "sha256": _sha256(preflight_ledger_bytes),
            "size": len(preflight_ledger_bytes),
        },
        "checkpoint.json": {
            "sha256": _sha256(preflight_checkpoint_bytes),
            "size": len(preflight_checkpoint_bytes),
        },
        "custody.jsonl": {
            "sha256": _sha256(preflight_custody_bytes),
            "size": len(preflight_custody_bytes),
        },
    }
    for name, content in sorted(resource_authority.items()):
        planned_source_index[f"resource-authority/{name}"] = {
            "sha256": _sha256(content),
            "size": len(content),
        }
    planned_release_manifest = {
        "schema_version": "1.0",
        "kind": "SCIENTIST_ONE_RELEASE_CANDIDATE",
        "run_id": run_id,
        "package_kind": "DEMO_RESEARCH_PACKAGE",
        "completion_label": "COMPLETE_DEMO_ONLY",
        "review_state": "READY_FOR_HUMAN_REVIEW",
        "publication_authority": "E4_HUMAN_REQUIRED",
        "novelty": "NOVELTY_UNVERIFIED",
        "synthetic_only": True,
        "external_integrations_used": [],
        "artifact_index": planned_artifact_index,
        "source_run_index": planned_source_index,
        "snapshot_index": snapshot_plan,
        "ledger_head_hash": manifest["ledger_head_hash"],
        "event_count": manifest["event_count"],
        "code_fingerprint": manifest["code_fingerprint"],
        "configuration_sha256": manifest["configuration_sha256"],
        "r_checks": {f"R{index}": r_checks[f"R{index}"] for index in range(8)},
        "evaluator_decisions": {
            key: {
                "decision": evaluators[key]["decision"],
                "authority": evaluators[key]["authority"],
            }
            for key in ("E0:AUDIT", "E2:AUDIT", "E3:AUDIT")
        },
        "reproduction": {
            "status": reproduction["status"],
            "reproduction_id": reproduction["reproduction_id"],
            "source_result_sha256": reproduction["source_result_sha256"],
        },
        "limitations": [
            "Synthetic fixtures do not establish external novelty or real-world validity.",
            "Local simulated custody is not independent custody.",
            "Publication and submission require a human E4 decision outside this package.",
        ],
    }
    planned_release_manifest_bytes = _canonical_json(planned_release_manifest)
    planned_names = []
    for logical_type, metadata in metadata_plans.items():
        projected = artifact_records[logical_type]
        suffix = Path(str(projected.get("path", "artifact.bin"))).suffix or ".bin"
        planned_names.append(
            f"evidence/{logical_type}/{logical_type}-{metadata.sha256[:20]}{suffix}"
        )
    planned_names.extend(
        f"registry/{logical_type}-{metadata.sha256[:16]}.json"
        for logical_type, metadata in metadata_plans.items()
    )
    planned_names.extend(
        f"run/resource-authority/{name}" for name in sorted(resource_authority)
    )
    planned_names.extend(value["member"] for value in snapshot_plan.values())
    planned_names.extend(
        (
            "run/FROZEN_SOURCE_RUN_MANIFEST.json", "run/events.jsonl",
            "run/checkpoint.json", "run/custody.jsonl",
            "RELEASE_CANDIDATE.json",
        )
    )
    planned_names.extend(
        f"reproduction/{Path(str(reproduction[key])).name}"
        for key in ("manifest_path", "result_path")
    )
    _assert_gateway_trust_root_not_serialized(
        registry,
        {name: b"" for name in planned_names},
    )
    declared_total += (
        len(preflight_ledger_bytes)
        + len(preflight_checkpoint_bytes)
        + sum(len(value) for value in preflight_reproduction_bytes.values())
        + len(preflight_custody_bytes)
        + sum(len(value) for value in resource_authority.values())
        + snapshot_total
        + len(planned_release_manifest_bytes)
        + _stored_zip_overhead(planned_names)
    )
    declared_members += len(snapshot_plan) + 7 + len(resource_authority)
    if (
        declared_total > MAX_PACKAGE_INPUT_BYTES
        or declared_members > MAX_PACKAGE_FILES
    ):
        raise PackagingError("review packet exceeds its declared aggregate bound")
    registry_validation = registry.verify_all()
    if not registry_validation.valid or registry_validation.count != len(artifact_records):
        raise PackagingError("run artifact registry is incomplete or corrupt")
    # Every registered artifact must be named by the immutable ledger.  This
    # rejects post-audit smuggling through extra manifest/registry records.
    ledger_preflight = preflight_ledger_bytes
    preflight_events = _validate_ledger(
        ledger_preflight,
        run_id,
        str(manifest.get("ledger_head_hash")),
        int(manifest.get("event_count", -1)),
    )
    _validate_resource_authority_projection(
        preflight_events, resource_authority
    )
    expected_contracts = {
        contract.source.value: _contract_projection(contract)
        for contract in macro_transition_contracts()
    }
    if manifest.get("transition_contracts") != expected_contracts:
        raise PackagingError("run transition contracts differ from canonical contracts")
    transition_events = [
        event
        for event in preflight_events
        if event.event_type == "TRANSITION"
        and event.state_before.value != event.requested_state_after.value
    ]
    expected_edges = [
        f"{event.state_before.value}->{event.requested_state_after.value}"
        for event in transition_events
    ]
    receipts = manifest.get("typed_transition_receipts")
    if (
        manifest.get("completed_transitions") != expected_edges
        or not isinstance(receipts, list)
        or len(receipts) != len(expected_edges)
    ):
        raise PackagingError("typed transition projection differs from the ledger")
    canonical_contracts_by_edge = {
        (contract.source.value, contract.destination.value): contract
        for contract in macro_transition_contracts()
    }
    try:
        ledger_receipts = validate_legacy_transition_prefix(
            event.to_dict() for event in preflight_events
        )
    except (TypeError, ValueError) as exc:
        raise PackagingError(
            "ledger is not a canonical context-bound transition prefix"
        ) from exc
    parsed_receipts: list[TransitionResult] = []
    for raw_receipt, event in zip(receipts, transition_events, strict=True):
        if not isinstance(raw_receipt, Mapping):
            raise PackagingError("typed transition receipt schema is malformed")
        try:
            receipt = TransitionResult.from_dict(raw_receipt)
        except ValueError as exc:
            raise PackagingError("typed transition receipt is malformed") from exc
        contract = canonical_contracts_by_edge.get(
            (event.state_before.value, event.requested_state_after.value)
        )
        if (
            receipt.to_dict() != dict(raw_receipt)
            or receipt.run_id != run_id
            or receipt.prior_state.value != event.state_before.value
            or receipt.current_state.value != event.requested_state_after.value
            or receipt.idempotency_key
            != f"{run_id}:{event.state_before.value}:{event.requested_state_after.value}"
            or receipt.replayed is not False
            or contract is None
            or receipt.generated_artifact_types
            != tuple(sorted(contract.generated_artifact_types))
            or safe_json_loads(
                canonical_json_bytes(event.metadata.get("transition_receipt"))
            )
            != dict(raw_receipt)
        ):
            raise PackagingError("typed transition receipt differs from its contract")
        parsed_receipts.append(receipt)
    if tuple(parsed_receipts) != ledger_receipts:
        raise PackagingError(
            "mutable transition receipts differ from exact ledger authority"
        )
    try:
        StateController(
            initial_state=preflight_events[-1].requested_state_after,
            artifact_registry=registry,
            prior_receipts=parsed_receipts,
        )
    except Exception as exc:
        raise PackagingError(
            "typed transition requests do not replay against frozen artifacts"
        ) from exc
    ledger_evaluations = _ledger_evaluator_projection(preflight_events)
    if manifest.get("evaluator_decisions") != ledger_evaluations:
        raise PackagingError("mutable evaluator decisions differ from the ledger")
    latest_resource_names = [
        name
        for event in preflight_events
        for name in event.metadata.get("artifact_types", ())
        if isinstance(name, str) and name.startswith("resource_runtime_")
    ]
    if (
        not latest_resource_names
        or manifest.get("resource_runtime_artifact") != latest_resource_names[-1]
    ):
        raise PackagingError("resource runtime pointer is not the latest ledger state")
    ledger_root_hashes: set[str] = set()
    for event in preflight_events:
        names = event.metadata.get("artifact_types", ())
        descriptors = event.metadata.get("artifact_descriptors", ())
        if (
            not isinstance(names, (list, tuple))
            or not isinstance(descriptors, (list, tuple))
            or len(names) != len(event.artifact_hashes)
            or len(descriptors) != len(event.artifact_hashes)
        ):
            raise PackagingError("ledger artifact projection is malformed")
        ledger_root_hashes.update(event.artifact_hashes)
    records_by_hash = {record.sha256: record for record in registry_validation.records}
    ledger_closure: set[str] = set()
    pending = list(ledger_root_hashes)
    while pending:
        digest = pending.pop()
        if digest in ledger_closure:
            continue
        record = records_by_hash.get(digest)
        if record is None:
            raise PackagingError("ledger parent closure is absent from the registry")
        ledger_closure.add(digest)
        pending.extend(record.parent_artifacts)
    manifest_hashes = {
        value.get("sha256")
        for value in artifact_records.values()
        if isinstance(value, Mapping)
    }
    if manifest_hashes != ledger_closure:
        raise PackagingError("manifest/registry contains evidence outside the ledger root")
    packet = _PacketFiles()
    files = packet.files
    artifact_index: dict[str, dict[str, Any]] = {}
    for logical_type, record in sorted(artifact_records.items()):
        if not isinstance(record, dict):
            raise PackagingError("malformed artifact record")
        try:
            metadata = registry.get_metadata(str(record.get("sha256")))
            if metadata.size > 32 * 1024 * 1024:
                raise PackagingError("artifact exceeds package evidence size bound")
            metadata_bytes = _canonical_json(metadata.to_dict())
            packet.reserve(metadata.size + len(metadata_bytes), members=2)
            content = read_confined_bytes(
                project_root,
                metadata.path,
                reject_hardlinks=True,
                max_bytes=32 * 1024 * 1024,
            )
        except (ArtifactError, PathSecurityError) as exc:
            raise PackagingError("artifact registry object is unsafe or corrupt") from exc
        if content is None:
            raise PackagingError("artifact registry object disappeared")
        if _contains_forbidden_boundary_text(content):
            raise PackagingError("artifact contains forbidden external path or secret material")
        if (
            dict(record) != _manifest_projection_from_record(record, metadata)
            or len(content) != metadata.size
            or _sha256(content) != metadata.sha256
            or not registry.verify(metadata.sha256)
        ):
            raise PackagingError("artifact registry metadata does not match run manifest")
        suffix = Path(str(record.get("path", "artifact.bin"))).suffix or ".bin"
        member = f"evidence/{logical_type}/{logical_type}-{metadata.sha256[:20]}{suffix}"
        packet.add(member, content)
        artifact_index[logical_type] = {
            "member": member,
            "sha256": record["sha256"],
            "logical_type": metadata.logical_type,
            "frozen": bool(record.get("frozen", False)),
            "registry_record_hash": metadata.record_hash,
            "parent_artifacts": list(metadata.parent_artifacts),
        }
        packet.add(
            f"registry/{logical_type}-{record['sha256'][:16]}.json",
            metadata_bytes,
        )

    snapshot_index: dict[str, dict[str, Any]] = {}
    for inventory_name in (
        "frozen_source_inventory",
        "frozen_configuration_inventory",
    ):
        member = artifact_index.get(inventory_name, {}).get("member")
        if not isinstance(member, str):
            raise PackagingError(f"{inventory_name} is absent from the packet")
        inventory_payload, planned_snapshot, _ = _inventory_plan_from_bytes(
            project_root, files[member], inventory_name, require_live=True
        )
        expected_aggregate = (
            manifest.get("code_fingerprint")
            if inventory_name == "frozen_source_inventory"
            else manifest.get("configuration_sha256")
        )
        if inventory_payload.get("aggregate_sha256") != expected_aggregate:
            raise PackagingError(
                f"{inventory_name} aggregate differs from run provenance"
            )
        entries = inventory_payload["entries"]
        for entry in entries:
            content = _confined_bytes(
                project_root,
                str(entry["path"]),
                max_bytes=4 * 1024 * 1024,
            )
            if (
                len(content) != entry.get("size")
                or _sha256(content) != entry.get("sha256")
            ):
                raise PackagingError(f"{inventory_name} snapshot entry changed")
            if _contains_forbidden_boundary_text(content, source_member=True):
                raise PackagingError(
                    f"{inventory_name} snapshot contains forbidden boundary material"
                )
            snapshot_member = f"snapshot/{entry['path']}"
            packet.add(snapshot_member, content)
            snapshot_index[str(entry["path"])] = {
                "member": snapshot_member,
                "sha256": entry["sha256"],
                "size": entry["size"],
                "inventory": inventory_name,
            }
        if {key: snapshot_index[key] for key in planned_snapshot} != planned_snapshot:
            raise PackagingError(f"{inventory_name} snapshot plan changed")

    resource_member = artifact_index.get(
        str(manifest.get("resource_runtime_artifact")), {}
    ).get("member")
    try:
        frozen_runtime = (
            safe_json_loads(files[resource_member])
            if isinstance(resource_member, str)
            else None
        )
    except UnsafeSerializationError as exc:
        raise PackagingError("latest resource runtime state is malformed") from exc
    if frozen_runtime != manifest.get("resource_runtime_state"):
        raise PackagingError("mutable resource runtime state differs from ledger evidence")

    reproduction_report_member = artifact_index.get("reproduction_report", {}).get("member")
    if not isinstance(reproduction_report_member, str):
        raise PackagingError("frozen reproduction report is absent")
    try:
        frozen_reproduction = safe_json_loads(files[reproduction_report_member])
    except UnsafeSerializationError as exc:
        raise PackagingError("frozen reproduction report is malformed") from exc
    if not isinstance(frozen_reproduction, dict) or frozen_reproduction != reproduction:
        raise PackagingError("mutable reproduction projection differs from frozen report")
    try:
        if (
            frozen_reproduction.get("status")
            == ARCHITECTURE_CONTROL_REPLAY_STATUS
        ):
            verify_frozen_architecture_control_reproduction(
                project_root, run_id, frozen_reproduction
            )
        else:
            verify_frozen_reproduction(project_root, run_id, frozen_reproduction)
    except ReproductionError as exc:
        raise PackagingError("frozen reproduction packet does not verify") from exc
    run_intent_member = artifact_index.get("run_intent", {}).get("member")
    try:
        run_intent = (
            safe_json_loads(files[run_intent_member])
            if isinstance(run_intent_member, str)
            else None
        )
    except UnsafeSerializationError as exc:
        raise PackagingError("frozen run intent is malformed") from exc
    if (
        not isinstance(run_intent, Mapping)
        or run_intent.get("kind") != "FROZEN_RUN_INTENT"
        or run_intent.get("mode") != manifest.get("mode")
        or run_intent.get("synthetic_scenario")
        != manifest.get("synthetic_scenario")
        or run_intent.get("package_kind") != manifest.get("package_kind")
    ):
        raise PackagingError("mutable run intent differs from frozen evidence")

    ledger_bytes = ledger_preflight
    ledger_events = _validate_ledger(
        ledger_bytes,
        run_id,
        str(manifest.get("ledger_head_hash")),
        int(manifest.get("event_count", -1)),
    )
    ledger_artifacts: dict[str, str] = {}
    ledger_record_hashes: dict[str, str] = {}
    for event in ledger_events:
        artifact_types = event.metadata.get("artifact_types", ())
        record_hashes = event.metadata.get("artifact_record_hashes", ())
        descriptors = event.metadata.get("artifact_descriptors", ())
        if (
            not isinstance(artifact_types, (list, tuple))
            or not isinstance(record_hashes, (list, tuple))
            or not isinstance(descriptors, (list, tuple))
            or len(artifact_types) != len(event.artifact_hashes)
            or len(record_hashes) != len(event.artifact_hashes)
            or len(descriptors) != len(event.artifact_hashes)
        ):
            if event.artifact_hashes:
                raise PackagingError("ledger artifact projection is malformed")
            continue
        for logical_type, digest, record_hash, descriptor in zip(
            artifact_types,
            event.artifact_hashes,
            record_hashes,
            descriptors,
            strict=True,
        ):
            if not isinstance(logical_type, str) or not isinstance(record_hash, str):
                raise PackagingError("ledger artifact type is malformed")
            prior = ledger_artifacts.get(logical_type)
            prior_record = ledger_record_hashes.get(logical_type)
            if (
                (prior is not None and prior != digest)
                or (prior_record is not None and prior_record != record_hash)
            ):
                raise PackagingError("ledger contains conflicting logical artifacts")
            ledger_artifacts[logical_type] = digest
            ledger_record_hashes[logical_type] = record_hash
            metadata = records_by_hash.get(digest)
            expected_descriptor = {
                "logical_type": logical_type,
                "sha256": digest,
                "registry_record_hash": record_hash,
                "parent_artifacts": list(metadata.parent_artifacts)
                if metadata is not None
                else [],
                "parent_record_hashes": [
                    records_by_hash[parent].record_hash
                    for parent in metadata.parent_artifacts
                    if parent in records_by_hash
                ]
                if metadata is not None
                else [],
            }
            try:
                normalized_descriptor = safe_json_loads(
                    canonical_json_bytes(descriptor)
                )
            except UnsafeSerializationError as exc:
                raise PackagingError("ledger artifact descriptor is malformed") from exc
            if (
                metadata is None
                or len(expected_descriptor["parent_record_hashes"])
                != len(metadata.parent_artifacts)
                or normalized_descriptor != expected_descriptor
            ):
                raise PackagingError("ledger does not bind recursive artifact provenance")
        if (
            event.code_version != manifest.get("code_fingerprint")
            or event.configuration_hash != manifest.get("configuration_sha256")
            or list(event.dataset_identifiers) != manifest.get("fixture_identifiers")
            or list(event.random_seeds) != manifest.get("random_seeds")
        ):
            raise PackagingError("ledger provenance differs from the run manifest")
    required_artifacts.update(
        name for name in ledger_artifacts if name.startswith("resource_runtime_")
    )
    missing = sorted(required_artifacts - set(artifact_records))
    if missing:
        raise PackagingError(
            "review packet is missing required frozen artifacts: " + ", ".join(missing)
        )
    for logical_type, digest in ledger_artifacts.items():
        record = artifact_records.get(logical_type)
        if (
            not isinstance(record, dict)
            or record.get("sha256") != digest
            or record.get("registry_record_hash")
            != ledger_record_hashes.get(logical_type)
        ):
            raise PackagingError(
                f"manifest omits or changes ledger-bound artifact: {logical_type}"
            )
    audit_report_member = artifact_index.get("audit_report", {}).get("member")
    if not isinstance(audit_report_member, str):
        raise PackagingError("frozen audit report is absent")
    try:
        audit_report = safe_json_loads(files[audit_report_member])
    except UnsafeSerializationError as exc:
        raise PackagingError("frozen audit report is malformed") from exc
    frozen_checks = (
        audit_report.get("scientific_checks")
        if isinstance(audit_report, dict)
        else None
    )
    expected_frozen_checks = {
        f"R{index}": (
            "UNTESTED"
            if reproduction_status == ARCHITECTURE_CONTROL_REPLAY_STATUS
            and index in {3, 7}
            else "PASS"
        )
        for index in range(8)
    }
    if not isinstance(frozen_checks, dict) or any(
        frozen_checks.get(f"R{index}", {}).get("status")
        != expected_frozen_checks[f"R{index}"]
        or frozen_checks.get(f"R{index}", {}).get("evidence_derived") is not True
        for index in range(8)
    ):
        raise PackagingError(
            "frozen audit report does not substantiate the declared R0-R7 classification"
        )
    if any(r_checks.get(f"R{index}") != frozen_checks[f"R{index}"]["status"] for index in range(8)):
        raise PackagingError("mutable R checks differ from frozen audit evidence")
    audit_transition = next(
        (
            event
            for event in reversed(ledger_events)
            if event.event_type == "TRANSITION"
            and event.state_before.value == "AUDIT"
            and event.requested_state_after.value == "RELEASE"
        ),
        None,
    )
    if audit_transition is None:
        raise PackagingError("ledger has no typed AUDIT to RELEASE transition")
    transition_evaluations = {
        f"{value.get('evaluator_class')}:AUDIT": safe_json_loads(
            canonical_json_bytes(value)
        )
        for value in audit_transition.evaluator_outputs
        if isinstance(value, Mapping)
    }
    for key in ("E0:AUDIT", "E2:AUDIT", "E3:AUDIT"):
        stored = evaluators.get(key)
        ledger_stored = transition_evaluations.get(key)
        if not isinstance(stored, dict) or not isinstance(ledger_stored, dict):
            raise PackagingError(f"ledger does not bind evaluator receipt: {key}")
        if set(stored) != EVALUATION_RECEIPT_KEYS or ledger_stored != stored:
            raise PackagingError(f"ledger evaluator receipt differs: {key}")
        try:
            evaluation = Evaluation(
                evaluator_class=EvaluatorClass(stored["evaluator_class"]),
                actor_role=Role(stored["authority"]),
                decision=Decision(stored["decision"]),
                artifact_hashes=tuple(stored["artifact_hashes"]),
                reason=stored["reason"],
                r_checks=tuple(RCheck(item) for item in stored["r_checks"]),
                critical_objection=stored["critical_objection"],
                producer_role=(
                    Role(stored["producer_role"])
                    if stored["producer_role"]
                    else None
                ),
                run_id=stored["run_id"],
                gate_id=stored["gate_id"],
                frozen_context_sha256=stored["frozen_context_sha256"],
                human_independence_claimed=stored[
                    "human_independence_claimed"
                ],
            )
        except Exception as exc:
            raise PackagingError(f"malformed evaluator receipt: {key}") from exc
        if legacy_evaluation_receipt(evaluation) != stored:
            raise PackagingError(f"evaluator receipt hash mismatch: {key}")

    checkpoint_bytes = preflight_checkpoint_bytes
    try:
        checkpoint = safe_json_loads(checkpoint_bytes)
    except UnsafeSerializationError as exc:
        raise PackagingError("run checkpoint is malformed") from exc
    expected_checkpoint = {
        "schema_version": "1.0",
        "run_id": run_id,
        "state": manifest.get("current_state"),
        "terminal_state": manifest.get("terminal_state"),
        "event_count": manifest.get("event_count"),
        "ledger_head_hash": manifest.get("ledger_head_hash"),
        "artifact_hashes": {
            key: value["sha256"]
            for key, value in sorted(artifact_records.items())
        },
        "artifact_record_hashes": {
            key: value["registry_record_hash"]
            for key, value in sorted(artifact_records.items())
        },
        "resource_runtime_artifact": manifest.get("resource_runtime_artifact"),
        "resumable": manifest.get("terminal_state") is None,
    }
    if checkpoint != expected_checkpoint:
        raise PackagingError("run checkpoint differs from the ledger-bound projection")
    custody_record_bytes = files[artifact_index["custody_record"]["member"]]
    custody_record = safe_json_loads(custody_record_bytes)
    if not isinstance(custody_record, dict):
        raise PackagingError("custody artifact is malformed")
    protocol_member = artifact_index.get("frozen_protocol", {}).get("member")
    try:
        protocol_record = (
            safe_json_loads(files[protocol_member])
            if isinstance(protocol_member, str)
            else None
        )
    except UnsafeSerializationError as exc:
        raise PackagingError("frozen protocol is malformed") from exc
    typed_protocol = (
        protocol_record.get("protocol")
        if isinstance(protocol_record, Mapping)
        else None
    )
    if (
        not isinstance(typed_protocol, Mapping)
        or custody_record.get("study_id") != typed_protocol.get("study_id")
        or custody_record.get("study_version")
        != typed_protocol.get("study_version")
        or custody_record.get("protocol_hash")
        != protocol_record.get("protocol_sha256")
        or manifest.get("protocol_hash") != protocol_record.get("protocol_sha256")
    ):
        raise PackagingError("custody lineage differs from the frozen study")
    custody = SimulatedHoldoutCustody(
        (Role.EXPERIMENT_RUNNER.value,),
        journal_root=project_root,
        journal_path=_custody_journal_path(run_id),
    )
    # The provider holds both its in-process lock and the durable journal lock
    # while we snapshot the exact bytes that enter the packet.  This prevents
    # an append/rollback ABA between journal validation and archive insertion.
    with custody.admission_guard(
        expected_journal_head_hash=str(custody_record.get("journal_head_hash")),
        expected_journal_identity_sha256=str(
            custody_record.get("journal_identity_sha256")
        ),
    ) as custody_snapshot:
        custody_bytes = _validate_custody_snapshot(
            custody_record,
            protocol_record,
            str(artifact_records["frozen_source_inventory"]["sha256"]),
            str(artifact_records["frozen_configuration_inventory"]["sha256"]),
            str(manifest.get("protocol_hash")),
            str(manifest.get("code_fingerprint")),
            str(manifest.get("configuration_sha256")),
            custody,
            custody_snapshot,
            _custody_journal_path(run_id).as_posix(),
            artifact_records=artifact_records,
            registry=registry,
            events=preflight_events,
        )
    packet_sources = {
        "FROZEN_SOURCE_RUN_MANIFEST.json": canonical_source_manifest_bytes,
        "events.jsonl": ledger_bytes,
        "checkpoint.json": checkpoint_bytes,
        "custody.jsonl": custody_bytes,
    }
    packet_sources.update(
        {
            f"resource-authority/{name}": content
            for name, content in sorted(resource_authority.items())
        }
    )
    source_index = {
        name: {"sha256": _sha256(content), "size": len(content)}
        for name, content in sorted(packet_sources.items())
    }
    for name, content in packet_sources.items():
        if _contains_forbidden_boundary_text(content):
            raise PackagingError("run packet contains forbidden external path or secret material")
        packet.add(f"run/{name}", content)

    reproduction_payloads: dict[str, dict[str, Any]] = {}
    reproduction_bytes: dict[str, bytes] = {}
    for key in ("manifest_path", "result_path"):
        raw = reproduction.get(key)
        if not isinstance(raw, str) or Path(raw).is_absolute():
            raise PackagingError("unsafe reproduction path")
        content = preflight_reproduction_bytes[key]
        try:
            parsed = safe_json_loads(content)
        except UnsafeSerializationError as exc:
            raise PackagingError("reproduction packet contains malformed JSON") from exc
        if not isinstance(parsed, dict):
            raise PackagingError("reproduction packet member must be an object")
        reproduction_payloads[key] = parsed
        reproduction_bytes[key] = content
        if _contains_forbidden_boundary_text(content):
            raise PackagingError("reproduction packet contains forbidden boundary material")
        packet.add(f"reproduction/{Path(raw).name}", content)
    frozen_reproduction_manifest = reproduction_payloads["manifest_path"]
    reproduction_result = reproduction_payloads["result_path"]
    reproduction_id = reproduction.get("reproduction_id")
    source_result_sha = reproduction.get("source_result_sha256")
    architecture_control_replay = (
        reproduction.get("status") == ARCHITECTURE_CONTROL_REPLAY_STATUS
    )
    expected_reproduction_manifest_kind = (
        "FROZEN_ARCHITECTURE_CONTROL_REPRODUCTION_MANIFEST"
        if architecture_control_replay
        else "FROZEN_REPRODUCTION_MANIFEST"
    )
    expected_reproduction_result_kind = (
        "ARCHITECTURE_CONTROL_REPRODUCTION_RESULT"
        if architecture_control_replay
        else "REPRODUCTION_RESULT"
    )
    expected_reproduction_status = (
        ARCHITECTURE_CONTROL_REPLAY_STATUS
        if architecture_control_replay
        else "PASS"
    )
    if (
        frozen_reproduction_manifest.get("kind")
        != expected_reproduction_manifest_kind
        or reproduction_result.get("kind") != expected_reproduction_result_kind
        or frozen_reproduction_manifest.get("run_id") != run_id
        or reproduction_result.get("run_id") != run_id
        or frozen_reproduction_manifest.get("reproduction_id") != reproduction_id
        or reproduction_result.get("reproduction_id") != reproduction_id
        or reproduction_result.get("status") != expected_reproduction_status
        or reproduction_result.get("source_result_sha256") != source_result_sha
        or reproduction_result.get("frozen_manifest_sha256")
        != _sha256(reproduction_bytes["manifest_path"])
        or reproduction.get("manifest_sha256")
        != _sha256(reproduction_bytes["manifest_path"])
        or reproduction.get("result_sha256")
        != _sha256(reproduction_bytes["result_path"])
        or artifact_records.get("reproduction_manifest", {}).get("sha256")
        != reproduction.get("manifest_sha256")
        or artifact_records.get("reproduction_manifest", {}).get(
            "registry_record_hash"
        )
        != reproduction.get("manifest_record_hash")
        or artifact_records.get("reproduction_result", {}).get("sha256")
        != reproduction.get("result_sha256")
        or artifact_records.get("reproduction_result", {}).get(
            "registry_record_hash"
        )
        != reproduction.get("result_record_hash")
        or frozen_reproduction_manifest.get("source_artifacts", {})
        .get("machine_results", {})
        .get("sha256")
        != source_result_sha
    ):
        raise PackagingError("reproduction manifest/result bindings are invalid")

    if (
        artifact_index != planned_artifact_index
        or source_index != planned_source_index
        or snapshot_index != snapshot_plan
    ):
        raise PackagingError("materialized packet indexes differ from pre-admission")
    release_manifest_bytes = planned_release_manifest_bytes
    packet.add("RELEASE_CANDIDATE.json", release_manifest_bytes)
    _assert_gateway_trust_root_not_serialized(registry, files)
    archive_bytes = _zip_bytes(files)
    digest = _sha256(archive_bytes)
    destination_dir = project_root / "artifacts" / "release_candidates"
    destination = destination_dir / f"{run_id}-{digest[:20]}.zip"
    with custody.admission_guard(
        expected_journal_head_hash=str(custody_record["journal_head_hash"]),
        expected_journal_identity_sha256=str(
            custody_record["journal_identity_sha256"]
        ),
    ) as final_custody_snapshot:
        _validate_custody_snapshot(
            custody_record,
            protocol_record,
            str(artifact_records["frozen_source_inventory"]["sha256"]),
            str(artifact_records["frozen_configuration_inventory"]["sha256"]),
            str(manifest.get("protocol_hash")),
            str(manifest.get("code_fingerprint")),
            str(manifest.get("configuration_sha256")),
            custody,
            final_custody_snapshot,
            _custody_journal_path(run_id).as_posix(),
            artifact_records=artifact_records,
            registry=registry,
            events=preflight_events,
        )
        _publish_immutable(project_root, destination, archive_bytes)
        return PackageResult(
            run_id=run_id,
            status="PASS",
            package_kind="DEMO_RESEARCH_PACKAGE",
            review_state="READY_FOR_HUMAN_REVIEW",
            e4_required=True,
            archive_path=destination.relative_to(project_root).as_posix(),
            archive_sha256=digest,
            file_count=len(files),
            envelope_path=None,
            envelope_sha256=None,
        )
