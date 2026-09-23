"""Bounded autonomous implementation through reviewed experiment templates.

The coding provider is advisory only.  It may select a reviewed template and
bounded numeric settings through a strict structured-output schema; it cannot
submit source, argv, paths, dependencies, shell syntax, or network policy.
Every proposal attempt and deterministic admission decision is captured in the
authoritative :class:`~scientist_one.artifacts.ArtifactRegistry`.

An admitted implementation is still not executable authority.  The supported
path revalidates its complete artifact graph, materializes the cataloged worker
at a content-derived path, freezes a non-evidentiary ``FrozenRunSpec``, and only
then submits it to ``LocalMacBackend``.  Model output never becomes scientific
evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import math
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .artifacts import ArtifactRecord, ArtifactRegistry
from .errors import ArtifactError, ValidationError
from .external import (
    AUDITED_LIVE_TRANSPORT_AUTHORITY,
    AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
    AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
    EGRESS_ATTEMPT_SCHEMA,
    EGRESS_BUDGET_SCHEMA,
    EGRESS_REQUEST_SCHEMA,
    EGRESS_RESPONSE_RECEIPT_SCHEMA,
    EgressPolicyError,
    UNVERIFIED_TRANSPORT_AUTHORITY,
    require_audited_live_transport_execution,
)
from .experiments import (
    CollectedRun,
    EvidenceClass,
    ExperimentPhase,
    FrozenRunSpec,
    LocalMacBackend,
    RunState,
    SubmissionReceipt,
)
from .ledger import EventLedger
from .models import thaw_json, validate_identifier, validate_sha256
from .providers import (
    ModelCapability,
    ModelInvocation,
    ModelResponseError,
    ModelResult,
    ModelRunStatus,
    validate_structured_output,
)
from .provider_verification import (
    ProviderExecutionProjection,
    ProviderVerificationError,
    ProviderVerifierContract,
    require_provider_verifier,
)
from .roles import Role
from .security import (
    atomic_write_bytes,
    canonical_json_bytes,
    read_confined_bytes,
    safe_json_loads,
    sha256_bytes,
)


PROPOSAL_SCHEMA_VERSION = "AUTONOMOUS_IMPLEMENTATION_PROPOSAL_V1"
ACTIONABLE_PROPOSAL_SCHEMA_VERSION = (
    "AUTONOMOUS_IMPLEMENTATION_ACTIONABLE_PROPOSAL_V1"
)
ACTION_SEMANTICS_SCHEMA_VERSION = "AUTONOMOUS_IMPLEMENTATION_ACTION_SEMANTICS_V1"
TEMPLATE_REVIEW_SCHEMA_VERSION = "AUTONOMOUS_IMPLEMENTATION_TEMPLATE_REVIEW_V1"
CATALOG_SCHEMA_VERSION = "AUTONOMOUS_IMPLEMENTATION_CATALOG_V1"
VALIDATION_SCHEMA_VERSION = "AUTONOMOUS_IMPLEMENTATION_VALIDATION_V1"
ACTION_VALIDATION_SCHEMA_VERSION = (
    "AUTONOMOUS_IMPLEMENTATION_ACTION_VALIDATION_V1"
)
PROVIDER_ADMISSION_LINK_SCHEMA_VERSION = (
    "AUTONOMOUS_IMPLEMENTATION_PROVIDER_ADMISSION_LINK_V1"
)
PROVIDER_NEUTRALITY_SCHEMA_VERSION = (
    "AUTONOMOUS_IMPLEMENTATION_PROVIDER_NEUTRALITY_V2"
)
LEGACY_WORKER_CONFIGURATION_SCHEMA_VERSION = (
    "AUTONOMOUS_IMPLEMENTATION_WORKER_CONFIG_V1"
)
WORKER_CONFIGURATION_SCHEMA_VERSION = "AUTONOMOUS_IMPLEMENTATION_WORKER_CONFIG_V2"
LEGACY_DESCRIPTOR_SCHEMA_VERSION = "AUTONOMOUS_IMPLEMENTATION_DESCRIPTOR_V1"
DESCRIPTOR_SCHEMA_VERSION = "AUTONOMOUS_IMPLEMENTATION_DESCRIPTOR_V2"
RUN_RECEIPT_SCHEMA_VERSION = "AUTONOMOUS_IMPLEMENTATION_RUN_RECEIPT_V1"
MAX_PARENT_EVIDENCE = 32
MAX_PROPOSAL_BYTES = 128 * 1024
MAX_PROVIDER_CUSTODY_BYTES = 2 * 1024 * 1024
MAX_PROVIDER_RESPONSE_BYTES = 8 * 1024 * 1024
PYTHON_EXECUTABLE = "/usr/bin/python3"
_AUTONOMOUS_PROMPT_TEMPLATE_ID = "bounded-implementation-proposal"
_AUTONOMOUS_PROMPT_TEMPLATE_VERSION = "1.0"
_AUTONOMOUS_PROMPT_TEMPLATE_HASH = sha256_bytes(
    b"bounded-implementation-proposal-v1"
)
_PROVIDER_SINGLETON_TYPES = frozenset(
    {
        "model_judged_instructions",
        "model_judged_input",
        "model_output_schema",
        "model_invocation",
        "model_provider_request_body",
        "model_provider_request_intent",
        "external_request",
        "external_response_receipt",
        "model_provider_response",
        "model_output",
    }
)
_PROVIDER_OPTIONAL_SINGLETON_TYPES = frozenset(
    {AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE}
)
_PROVIDER_GRAPH_TYPES = (
    _PROVIDER_SINGLETON_TYPES
    | _PROVIDER_OPTIONAL_SINGLETON_TYPES
    | {"external_response_raw"}
)
_BUILTIN_LOCAL_RUNNER = LocalMacBackend._run_subprocess
_BUILTIN_LOCAL_SUBMIT = LocalMacBackend.submit
_BUILTIN_LOCAL_RECONCILE = LocalMacBackend.reconcile
_BUILTIN_LOCAL_COLLECT = LocalMacBackend.collect
_BUILTIN_LOCAL_CALLABLES: Mapping[str, object] = MappingProxyType(
    {
        name: value
        for name, value in vars(LocalMacBackend).items()
        if callable(value)
    }
)


class AutonomousImplementationError(ValidationError):
    """The declarative implementation boundary failed closed."""


class AdmissionStatus(StrEnum):
    ADMITTED = "ADMITTED"
    REJECTED = "REJECTED"


class ReviewedWorkerTemplate(StrEnum):
    AFFINE_MEAN_V1 = "affine-mean-v1"
    THRESHOLD_RATE_V1 = "threshold-rate-v1"


_PARAMETER_LIMITS: Mapping[ReviewedWorkerTemplate, Mapping[str, tuple[float, float]]] = (
    MappingProxyType(
        {
            ReviewedWorkerTemplate.AFFINE_MEAN_V1: MappingProxyType(
                {"bias": (-10.0, 10.0), "scale": (0.1, 10.0)}
            ),
            ReviewedWorkerTemplate.THRESHOLD_RATE_V1: MappingProxyType(
                {"positive_weight": (0.1, 10.0), "threshold": (-100.0, 100.0)}
            ),
        }
    )
)


# The only substitution is an internal enum value, never provider-controlled
# text.  The worker intentionally uses only the Python standard library and a
# fixed input/output protocol.  It has no shell, subprocess, dependency, or
# network facility.
_WORKER_SOURCE = '''#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import sys


TEMPLATE_ID = "__REVIEWED_TEMPLATE_ID__"


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def fail(message):
    sys.stderr.write(message + "\\n")
    return 2


def required_fd(name):
    raw = os.environ.get(name)
    if raw is None or not raw.isascii() or not raw.isdigit():
        raise ValueError("trusted descriptor environment is incomplete")
    descriptor = int(raw)
    if descriptor < 3:
        raise ValueError("trusted descriptor is invalid")
    return descriptor


def read_held(descriptor, maximum_bytes):
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > maximum_bytes
    ):
        raise ValueError("held input is not a bounded private regular file")
    chunks = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    payload = b"".join(chunks)
    after = os.fstat(descriptor)
    stable = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if len(payload) != before.st_size or stable(after) != stable(before):
        raise ValueError("held input changed while being read")
    return payload


def write_new_at(directory_fd, name, payload):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError("no-follow output creation is unavailable")
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("new output is not a private regular file")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short output write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)


def main():
    if len(sys.argv) != 5 or sys.argv[1] != "--config" or sys.argv[3] != "--data":
        return fail("fixed worker arguments are required")
    try:
        job_directory_fd = required_fd("SCIENTIST_ONE_JOB_DIR_FD")
        code_fd = required_fd("SCIENTIST_ONE_INPUT_CODE_FD")
        config_fd = required_fd("SCIENTIST_ONE_INPUT_CONFIGURATION_FD")
        data_fd = required_fd("SCIENTIST_ONE_INPUT_DATA_FD")
        evaluator_fd = required_fd("SCIENTIST_ONE_INPUT_EVALUATOR_FD")
        code_bytes = read_held(code_fd, 2 * 1024 * 1024)
        config_bytes = read_held(config_fd, 2 * 1024 * 1024)
        data_bytes = read_held(data_fd, 2 * 1024 * 1024)
        evaluator_bytes = read_held(evaluator_fd, 2 * 1024 * 1024)
    except (OSError, ValueError):
        return fail("trusted held execution inputs are unavailable")
    try:
        config = json.loads(config_bytes.decode("utf-8"))
        data = json.loads(data_bytes.decode("utf-8"))
        evaluator = json.loads(evaluator_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return fail("worker input is not valid JSON")
    expected_config = {
        "schema_version",
        "experiment_id",
        "hypothesis_id",
        "implementation_id",
        "phase",
        "proposal_id",
        "proposal_artifact_sha256",
        "template_id",
        "template_version",
        "parameters",
        "parent_evidence_sha256s",
        "data_sha256",
        "evaluator_sha256",
        "seeds",
    }
    if not isinstance(config, dict) or set(config) != expected_config:
        return fail("worker configuration schema mismatch")
    if config["template_id"] != TEMPLATE_ID or config["template_version"] != "1.0":
        return fail("worker template binding mismatch")
    if hashlib.sha256(data_bytes).hexdigest() != config["data_sha256"]:
        return fail("worker data binding mismatch")
    if hashlib.sha256(evaluator_bytes).hexdigest() != config["evaluator_sha256"]:
        return fail("worker evaluator binding mismatch")
    if evaluator != {
        "direction": "HIGHER_IS_BETTER",
        "metric": "template_defined_scalar",
        "metric_id": "metric-autonomous-template-scalar",
    }:
        return fail("worker evaluator schema mismatch")
    if not isinstance(data, dict) or set(data) != {"values"}:
        return fail("fixture data schema mismatch")
    values = data["values"]
    if (
        not isinstance(values, list)
        or not 1 <= len(values) <= 256
        or any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            for value in values
        )
    ):
        return fail("fixture values must be finite bounded numbers")
    parameters = config["parameters"]
    if not isinstance(parameters, dict):
        return fail("worker parameters must be an object")
    if TEMPLATE_ID == "affine-mean-v1":
        if set(parameters) != {"bias", "scale"}:
            return fail("affine parameter schema mismatch")
        metric = (
            sum(float(value) for value in values) / len(values)
        ) * float(parameters["scale"]) + float(parameters["bias"])
    elif TEMPLATE_ID == "threshold-rate-v1":
        if set(parameters) != {"positive_weight", "threshold"}:
            return fail("threshold parameter schema mismatch")
        metric = (
            sum(float(value) >= float(parameters["threshold"]) for value in values)
            / len(values)
        ) * float(parameters["positive_weight"])
    else:
        return fail("unreviewed worker template")
    if not math.isfinite(metric):
        return fail("worker metric is non-finite")
    seeds = config["seeds"]
    if (
        not isinstance(seeds, list)
        or not seeds
        or any(isinstance(seed, bool) or not isinstance(seed, int) or seed < 0 for seed in seeds)
        or len(set(seeds)) != len(seeds)
    ):
        return fail("worker seed schema mismatch")
    try:
        run_id = os.environ["SCIENTIST_ONE_RUN_ID"]
        spec_sha256 = os.environ["SCIENTIST_ONE_SPEC_SHA256"]
    except KeyError:
        return fail("trusted execution environment is incomplete")
    artifacts = []
    seed_results = []
    for seed in seeds:
        payload = canonical(
            {
                "experiment_id": config["experiment_id"],
                "hypothesis_id": config["hypothesis_id"],
                "implementation_id": config["implementation_id"],
                "metric": metric,
                "phase": config["phase"],
                "proposal_artifact_sha256": config["proposal_artifact_sha256"],
                "seed": seed,
                "template_id": TEMPLATE_ID,
            }
        )
        name = "seed-" + str(seed) + ".json"
        try:
            write_new_at(job_directory_fd, name, payload)
        except (OSError, ValueError):
            return fail("exclusive seed output creation failed")
        digest = hashlib.sha256(payload).hexdigest()
        artifacts.append(
            {
                "path": name,
                "sha256": digest,
                "size": len(payload),
                "logical_type": "autonomous_variant_result",
            }
        )
        seed_results.append(
            {
                "seed": seed,
                "status": "SUCCESS",
                "metric": metric,
                "artifact_sha256": digest,
                "reason": None,
            }
        )
    manifest = {
        "schema_version": "SCIENTIST_ONE_OUTPUT_MANIFEST_V1",
        "run_id": run_id,
        "spec_sha256": spec_sha256,
        "code_sha256": hashlib.sha256(code_bytes).hexdigest(),
        "data_sha256": hashlib.sha256(data_bytes).hexdigest(),
        "configuration_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "evaluator_sha256": hashlib.sha256(evaluator_bytes).hexdigest(),
        "planned_seeds": seeds,
        "seed_results": seed_results,
        "artifacts": artifacts,
        "ablations": [],
    }
    try:
        write_new_at(
            job_directory_fd,
            "output-manifest.json",
            canonical(manifest) + b"\\n",
        )
    except (OSError, ValueError):
        return fail("exclusive manifest creation failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _render_worker(template_id: ReviewedWorkerTemplate) -> bytes:
    if not isinstance(template_id, ReviewedWorkerTemplate):
        raise AutonomousImplementationError("worker template must be a reviewed enum")
    return _WORKER_SOURCE.replace(
        "__REVIEWED_TEMPLATE_ID__", template_id.value
    ).encode("utf-8")


def _worker_sha256(template_id: ReviewedWorkerTemplate) -> str:
    return sha256_bytes(_render_worker(template_id))


# These hashes are the committed output of the separate closed-template review
# step.  Runtime code may consume the approval but may not silently mint a new
# approval for changed worker bytes.  Updating either value is therefore an
# explicit review-bearing source change visible to the project snapshot/audit.
_PINNED_REVIEWED_WORKER_SHA256S: Mapping[ReviewedWorkerTemplate, str] = (
    MappingProxyType(
        {
            ReviewedWorkerTemplate.AFFINE_MEAN_V1: (
                "dc4852e3a372ac5fb689bf16f3751c631c8ab24cf7ec556efe01655aa7debfef"
            ),
            ReviewedWorkerTemplate.THRESHOLD_RATE_V1: (
                "20c6a6fcbceacc4848f15c40b1f888a1a2dc17584fe386b72d9b497be9e0cf0a"
            ),
        }
    )
)


def _pinned_worker_sha256(template_id: ReviewedWorkerTemplate) -> str:
    expected = _PINNED_REVIEWED_WORKER_SHA256S[template_id]
    if _worker_sha256(template_id) != expected:
        raise AutonomousImplementationError(
            "closed worker bytes changed without a pinned independent review"
        )
    return expected


def _unique_digests(*collections: Sequence[str]) -> tuple[str, ...]:
    result: list[str] = []
    for collection in collections:
        for digest in collection:
            if digest not in result:
                result.append(digest)
    return tuple(result)


def template_review_payload(
    template_id: ReviewedWorkerTemplate | str,
) -> dict[str, Any]:
    """Return the exact payload a separate reviewer must approve and persist."""

    try:
        template = (
            template_id
            if isinstance(template_id, ReviewedWorkerTemplate)
            else ReviewedWorkerTemplate(template_id)
        )
    except (TypeError, ValueError) as exc:
        raise AutonomousImplementationError("unknown worker template") from exc
    return {
        "schema_version": TEMPLATE_REVIEW_SCHEMA_VERSION,
        "template_id": template.value,
        "template_version": "1.0",
        "worker_code_sha256": _pinned_worker_sha256(template),
        "verdict": "APPROVED",
        "review_scope": "deterministic_fixture_worker_no_shell_no_network",
        "shell_allowed": False,
        "network_allowed": False,
    }


@dataclass(frozen=True)
class ReviewedTemplate:
    template_id: ReviewedWorkerTemplate
    template_version: str
    worker_code_sha256: str
    parameter_limits: Mapping[str, tuple[float, float]]
    review_artifact_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.template_id, ReviewedWorkerTemplate):
            raise AutonomousImplementationError("template identity must be reviewed")
        if self.template_version != "1.0":
            raise AutonomousImplementationError("unknown template version")
        validate_sha256(self.worker_code_sha256, "reviewed worker SHA-256")
        validate_sha256(self.review_artifact_sha256, "template review SHA-256")
        expected = _PARAMETER_LIMITS[self.template_id]
        if dict(self.parameter_limits) != dict(expected):
            raise AutonomousImplementationError("template parameter limits changed")
        object.__setattr__(self, "parameter_limits", expected)
        if self.worker_code_sha256 != _pinned_worker_sha256(self.template_id):
            raise AutonomousImplementationError("reviewed worker source changed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id.value,
            "template_version": self.template_version,
            "worker_code_sha256": self.worker_code_sha256,
            "parameter_limits": {
                name: {"minimum": limits[0], "maximum": limits[1]}
                for name, limits in sorted(self.parameter_limits.items())
            },
            "review_artifact_sha256": self.review_artifact_sha256,
            "shell_allowed": False,
            "network_allowed": False,
        }


@dataclass(frozen=True)
class ReviewedImplementationCatalog:
    catalog_id: str
    catalog_version: str
    templates: tuple[ReviewedTemplate, ...]
    artifact: ArtifactRecord

    def __post_init__(self) -> None:
        validate_identifier(self.catalog_id, "implementation catalog ID")
        if self.catalog_version != "1.0":
            raise AutonomousImplementationError("unknown catalog version")
        if (
            not isinstance(self.templates, tuple)
            or len(self.templates) != len(ReviewedWorkerTemplate)
            or any(not isinstance(item, ReviewedTemplate) for item in self.templates)
            or {item.template_id for item in self.templates} != set(ReviewedWorkerTemplate)
        ):
            raise AutonomousImplementationError("catalog must contain the complete reviewed set")
        if not isinstance(self.artifact, ArtifactRecord):
            raise AutonomousImplementationError("catalog requires a persisted artifact")

    def template(self, template_id: ReviewedWorkerTemplate) -> ReviewedTemplate:
        for item in self.templates:
            if item.template_id is template_id:
                return item
        raise AutonomousImplementationError("template is not present in reviewed catalog")

    def proposal_schema(self) -> dict[str, Any]:
        return implementation_proposal_schema(self)


def _catalog_payload(
    catalog_id: str,
    templates: Sequence[ReviewedTemplate],
) -> dict[str, Any]:
    return {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "catalog_id": catalog_id,
        "catalog_version": "1.0",
        "templates": [item.to_dict() for item in templates],
        "generation_policy": "closed_deterministic_catalog_only",
        "provider_output_trust": "UNTRUSTED_NON_EVIDENTIARY",
        "execution_authority": "ADMITTED_FROZEN_RUN_SPEC_LOCAL_MAC_ONLY",
    }


def _review_record(
    registry: ArtifactRegistry,
    template: ReviewedWorkerTemplate,
    digest: str,
) -> ArtifactRecord:
    validate_sha256(digest, "template review SHA-256")
    if not registry.verify(digest):
        raise AutonomousImplementationError("template review artifact is absent or corrupt")
    record = registry.get_metadata(digest)
    if (
        record.logical_type != "autonomous_implementation.template_review"
        or record.creator_role
        not in {Role.SCIENTIFIC_REVIEWER, Role.ADVERSARIAL_REVIEWER}
        or record.validation_result != "PASS"
        or not record.frozen
    ):
        raise AutonomousImplementationError("template review lacks admitted review authority")
    try:
        payload = safe_json_loads(registry.get_bytes(digest), max_bytes=64 * 1024)
    except ValidationError as exc:
        raise AutonomousImplementationError("template review payload is malformed") from exc
    if payload != template_review_payload(template):
        raise AutonomousImplementationError("template review does not bind exact worker bytes")
    return record


def create_reviewed_catalog(
    registry: ArtifactRegistry,
    review_artifact_sha256s: Mapping[ReviewedWorkerTemplate | str, str],
    *,
    catalog_id: str = "bounded-experiment-workers",
) -> ReviewedImplementationCatalog:
    """Validate independent template reviews and persist the closed catalog."""

    if not isinstance(registry, ArtifactRegistry):
        raise AutonomousImplementationError("catalog requires ArtifactRegistry authority")
    if not isinstance(review_artifact_sha256s, Mapping):
        raise AutonomousImplementationError("catalog reviews must be a mapping")
    validate_identifier(catalog_id, "implementation catalog ID")
    normalized: dict[ReviewedWorkerTemplate, str] = {}
    try:
        for key, value in review_artifact_sha256s.items():
            template = key if isinstance(key, ReviewedWorkerTemplate) else ReviewedWorkerTemplate(key)
            if template in normalized:
                raise AutonomousImplementationError("duplicate template review")
            normalized[template] = value
    except (TypeError, ValueError) as exc:
        raise AutonomousImplementationError("catalog review mapping is invalid") from exc
    if set(normalized) != set(ReviewedWorkerTemplate):
        raise AutonomousImplementationError("every catalog template requires a review")
    templates: list[ReviewedTemplate] = []
    reviews: list[ArtifactRecord] = []
    for template_id in ReviewedWorkerTemplate:
        review = _review_record(registry, template_id, normalized[template_id])
        reviews.append(review)
        templates.append(
            ReviewedTemplate(
                template_id=template_id,
                template_version="1.0",
                worker_code_sha256=_pinned_worker_sha256(template_id),
                parameter_limits=_PARAMETER_LIMITS[template_id],
                review_artifact_sha256=review.sha256,
            )
        )
    payload = _catalog_payload(catalog_id, templates)
    artifact = registry.put_json(
        payload,
        logical_type="autonomous_implementation.template_catalog",
        origin="deterministic composition of independently reviewed worker templates",
        creator_role=Role.ORCHESTRATOR,
        creation_command=("scientist-one", "validate-implementation-catalog"),
        parent_artifacts=tuple(record.sha256 for record in reviews),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )
    return ReviewedImplementationCatalog(catalog_id, "1.0", tuple(templates), artifact)


def implementation_proposal_schema(
    catalog: ReviewedImplementationCatalog,
) -> dict[str, Any]:
    """Return the exact strict provider schema for declarative coding output."""

    if not isinstance(catalog, ReviewedImplementationCatalog):
        raise AutonomousImplementationError("proposal schema requires reviewed catalog")
    parameter_names = sorted(
        {name for template in catalog.templates for name in template.parameter_limits}
    )
    return {
        "type": "object",
        "properties": {
            "schema_version": {"type": "string", "enum": [PROPOSAL_SCHEMA_VERSION]},
            "proposal_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "implementation_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "template_id": {
                "type": "string",
                "enum": [item.template_id.value for item in catalog.templates],
            },
            "parameters": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "enum": parameter_names},
                        "value": {"type": "number", "minimum": -100.0, "maximum": 100.0},
                    },
                    "required": ["name", "value"],
                    "additionalProperties": False,
                },
                "minItems": 2,
                "maxItems": 2,
            },
            "parent_evidence_sha256s": {
                "type": "array",
                "items": {"type": "string", "minLength": 64, "maxLength": 64},
                "minItems": 1,
                "maxItems": MAX_PARENT_EVIDENCE,
            },
            "rationale": {"type": "string", "minLength": 1, "maxLength": 2048},
        },
        "required": [
            "schema_version",
            "proposal_id",
            "implementation_id",
            "template_id",
            "parameters",
            "parent_evidence_sha256s",
            "rationale",
        ],
        "additionalProperties": False,
    }


@dataclass(frozen=True)
class ImplementationProposal:
    proposal_id: str
    implementation_id: str
    template_id: ReviewedWorkerTemplate
    parameters: Mapping[str, float]
    parent_evidence_sha256s: tuple[str, ...]
    rationale: str

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        catalog: ReviewedImplementationCatalog,
    ) -> "ImplementationProposal":
        validate_structured_output(value, catalog.proposal_schema())
        try:
            validate_identifier(value["proposal_id"], "implementation proposal ID")
            validate_identifier(value["implementation_id"], "implementation ID")
            template_id = ReviewedWorkerTemplate(value["template_id"])
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise AutonomousImplementationError("proposal identities are invalid") from exc
        parameter_values: dict[str, float] = {}
        for item in value["parameters"]:
            name = item["name"]
            if name in parameter_values:
                raise AutonomousImplementationError("proposal parameter names must be unique")
            raw = item["value"]
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise AutonomousImplementationError("proposal parameters must be numeric")
            numeric = float(raw)
            if not math.isfinite(numeric):
                raise AutonomousImplementationError("proposal parameters must be finite")
            parameter_values[name] = numeric
        limits = catalog.template(template_id).parameter_limits
        if set(parameter_values) != set(limits):
            raise AutonomousImplementationError("proposal parameters do not match template")
        for name, numeric in parameter_values.items():
            minimum, maximum = limits[name]
            if not minimum <= numeric <= maximum:
                raise AutonomousImplementationError("proposal parameter exceeds reviewed limits")
        evidence = tuple(value["parent_evidence_sha256s"])
        if len(set(evidence)) != len(evidence):
            raise AutonomousImplementationError("proposal parent evidence must be unique")
        for digest in evidence:
            validate_sha256(digest, "proposal parent evidence SHA-256")
        rationale = value["rationale"]
        return cls(
            proposal_id=value["proposal_id"],
            implementation_id=value["implementation_id"],
            template_id=template_id,
            parameters=MappingProxyType(dict(sorted(parameter_values.items()))),
            parent_evidence_sha256s=evidence,
            rationale=rationale,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROPOSAL_SCHEMA_VERSION,
            "proposal_id": self.proposal_id,
            "implementation_id": self.implementation_id,
            "template_id": self.template_id.value,
            "parameters": [
                {"name": name, "value": value}
                for name, value in sorted(self.parameters.items())
            ],
            "parent_evidence_sha256s": list(self.parent_evidence_sha256s),
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ImplementationContext:
    experiment_id: str
    hypothesis_id: str
    data_artifact_sha256: str
    evaluator_artifact_sha256: str
    seeds: tuple[int, ...]
    phase: ExperimentPhase = ExperimentPhase.EXPLORATORY

    def __post_init__(self) -> None:
        validate_identifier(self.experiment_id, "implementation experiment ID")
        validate_identifier(self.hypothesis_id, "implementation hypothesis ID")
        validate_sha256(self.data_artifact_sha256, "implementation data SHA-256")
        validate_sha256(self.evaluator_artifact_sha256, "implementation evaluator SHA-256")
        if not isinstance(self.seeds, tuple):
            object.__setattr__(self, "seeds", tuple(self.seeds))
        if (
            not self.seeds
            or len(self.seeds) > 1_000
            or any(isinstance(seed, bool) or not isinstance(seed, int) or seed < 0 for seed in self.seeds)
            or len(set(self.seeds)) != len(self.seeds)
        ):
            raise AutonomousImplementationError("implementation seeds are invalid")
        if self.phase is not ExperimentPhase.EXPLORATORY:
            raise AutonomousImplementationError(
                "autonomous implementation admission is exploratory only"
            )


@dataclass(frozen=True)
class AdmittedImplementation:
    proposal: ImplementationProposal
    context: ImplementationContext
    provider_attempt_artifact: ArtifactRecord
    provider_admission_link: ArtifactRecord
    proposal_artifact: ArtifactRecord
    worker_code_artifact: ArtifactRecord
    configuration_artifact: ArtifactRecord
    validation_receipt: ArtifactRecord
    descriptor_artifact: ArtifactRecord
    catalog_artifact_sha256: str


@dataclass(frozen=True)
class ImplementationAdmission:
    """Admission result with compatibility fields kept advisory-only.

    On a successful admission, the historical top-level ``proposal_artifact``
    field is the provider-specific attempt and ``validation_receipt`` is the
    provider-admission link.  They preserve the complete advisory lineage; they
    are not actionable/core roots.  Core consumers must use
    ``actionable_proposal_artifact`` and ``action_validation_receipt`` (the same
    neutral records exposed by ``implementation.proposal_artifact`` and
    ``implementation.validation_receipt``).  Rejected admissions have no neutral
    roots and retain their rejection receipt in ``validation_receipt``.
    """

    status: AdmissionStatus
    reason_code: str
    # Compatibility name: provider-specific advisory attempt, never a core root.
    proposal_artifact: ArtifactRecord
    # On ADMITTED: provider-specific advisory admission link; otherwise rejection.
    validation_receipt: ArtifactRecord
    # Provider-neutral actionable root used by execution and scientific state.
    actionable_proposal_artifact: ArtifactRecord | None = None
    # Deterministic provider-neutral admission authority used by core consumers.
    action_validation_receipt: ArtifactRecord | None = None
    implementation: AdmittedImplementation | None = None

    @property
    def admitted(self) -> bool:
        return self.status is AdmissionStatus.ADMITTED

    @property
    def provider_attempt_artifact(self) -> ArtifactRecord:
        """Return the advisory provider attempt under an unambiguous name."""

        return self.proposal_artifact

    @property
    def provider_admission_link(self) -> ArtifactRecord | None:
        """Return the advisory admission link, which exists only on success."""

        return self.validation_receipt if self.admitted else None


@dataclass(frozen=True)
class PreparedImplementationRun:
    implementation: AdmittedImplementation
    spec: FrozenRunSpec
    spec_artifact: ArtifactRecord
    materialized_worker_path: str


@dataclass(frozen=True)
class ExecutedImplementationRun:
    prepared: PreparedImplementationRun
    submission: SubmissionReceipt
    collected: CollectedRun | None
    execution_receipt: ArtifactRecord


@dataclass(frozen=True)
class _ProviderCapture:
    instructions: ArtifactRecord
    input_text: ArtifactRecord
    output_schema: ArtifactRecord
    invocation: ArtifactRecord
    request_body: ArtifactRecord
    request_intent: ArtifactRecord
    external_request: ArtifactRecord
    raw_responses: tuple[ArtifactRecord, ...]
    response_receipt: ArtifactRecord
    transport_execution_authority: ArtifactRecord | None
    provider_response: ArtifactRecord
    output: ArtifactRecord

    @property
    def records(self) -> tuple[ArtifactRecord, ...]:
        return (
            self.instructions,
            self.input_text,
            self.output_schema,
            self.invocation,
            self.request_body,
            self.request_intent,
            self.external_request,
            *self.raw_responses,
            self.response_receipt,
            *(
                (self.transport_execution_authority,)
                if self.transport_execution_authority is not None
                else ()
            ),
            self.provider_response,
            self.output,
        )


class AutonomousImplementationController:
    """Persist, admit, prepare, and execute closed-catalog implementations."""

    def __setattr__(self, name: str, value: object) -> None:
        if name in {"_expected_run_id", "_authority_ledger"} and name in vars(self):
            raise AutonomousImplementationError(
                "live provider authority context is write-once"
            )
        object.__setattr__(self, name, value)

    @staticmethod
    def _live_authority_context_is_canonical(
        registry: ArtifactRegistry,
        ledger: EventLedger | None,
        run_id: str,
    ) -> bool:
        if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
            return False
        try:
            expected_namespace = Path("runs") / run_id
            expected_ledger_relative = expected_namespace / "events.jsonl"
            expected_ledger_path = registry.policy.root / expected_ledger_relative
            return bool(
                ledger.policy.root == registry.policy.root
                and registry.base_path == expected_namespace / "registry"
                and registry.objects_path == registry.base_path / "objects"
                and registry.metadata_path == registry.base_path / "metadata"
                and registry.quarantine_path == registry.base_path / "quarantine"
                and ledger.relative_path == expected_ledger_relative
                and ledger.path == expected_ledger_path
                and ledger.lock_path
                == expected_ledger_path.with_name(
                    f".{expected_ledger_path.name}.lock"
                )
            )
        except (AttributeError, TypeError, ValueError):
            return False

    def __init__(
        self,
        registry: ArtifactRegistry,
        catalog: ReviewedImplementationCatalog,
        *,
        expected_run_id: str | None = None,
        authority_ledger: EventLedger | None = None,
    ) -> None:
        if not isinstance(registry, ArtifactRegistry):
            raise AutonomousImplementationError("controller requires ArtifactRegistry")
        if not isinstance(catalog, ReviewedImplementationCatalog):
            raise AutonomousImplementationError("controller requires reviewed catalog")
        if not registry.verify(catalog.artifact.sha256):
            raise AutonomousImplementationError("catalog artifact is absent or corrupt")
        if registry.get_metadata(catalog.artifact.sha256) != catalog.artifact:
            raise AutonomousImplementationError("catalog artifact belongs to another registry")
        if (expected_run_id is None) != (authority_ledger is None):
            raise AutonomousImplementationError(
                "live provider authority requires both expected run ID and ledger"
            )
        if expected_run_id is not None:
            try:
                validate_identifier(expected_run_id, "expected provider authority run ID")
            except ValidationError as exc:
                raise AutonomousImplementationError(
                    "expected provider authority run ID is invalid"
                ) from exc
            if not self._live_authority_context_is_canonical(
                registry,
                authority_ledger,
                expected_run_id,
            ):
                raise AutonomousImplementationError(
                    "live provider authority requires the exact canonical paired run "
                    "registry and ledger"
                )
        self.registry = registry
        self.catalog = catalog
        self._expected_run_id = expected_run_id
        self._authority_ledger = authority_ledger
        self._validate_catalog()

    def _validate_catalog(self) -> None:
        """Re-resolve the complete pinned catalog and every review artifact."""

        artifact = self.catalog.artifact
        if (
            not self.registry.verify(artifact.sha256)
            or self.registry.get_metadata(artifact.sha256) != artifact
            or artifact.logical_type
            != "autonomous_implementation.template_catalog"
            or artifact.creator_role is not Role.ORCHESTRATOR
            or artifact.validation_result != "PASS"
            or not artifact.frozen
        ):
            raise AutonomousImplementationError("reviewed catalog metadata is invalid")
        review_hashes: list[str] = []
        for template in self.catalog.templates:
            reviewed = _review_record(
                self.registry,
                template.template_id,
                template.review_artifact_sha256,
            )
            review_hashes.append(reviewed.sha256)
            if template.worker_code_sha256 != _pinned_worker_sha256(
                template.template_id
            ):
                raise AutonomousImplementationError("catalog worker pin changed")
        if set(artifact.parent_artifacts) != set(review_hashes):
            raise AutonomousImplementationError("catalog omits a reviewed template parent")
        try:
            payload = safe_json_loads(
                self.registry.get_bytes(artifact.sha256),
                max_bytes=256 * 1024,
            )
        except (ArtifactError, ValidationError) as exc:
            raise AutonomousImplementationError("catalog payload is malformed") from exc
        if payload != _catalog_payload(self.catalog.catalog_id, self.catalog.templates):
            raise AutonomousImplementationError("catalog payload changed after review")

    def _available_parents(
        self,
        invocation: ModelInvocation,
        result: ModelResult,
    ) -> tuple[str, ...]:
        """Return the minimal authoritative proposal ancestry.

        Only the closed provider-custody vocabulary can become authority.  The
        exact judged instructions, input, and schema are intentionally raw
        custody records rather than parents of the redacted invocation, so an
        admitted proposal must retain those records directly as well as the
        transitive gateway graph.  Unrelated public ``ModelResult`` artifacts
        remain advisory and cannot be spliced into the admitted graph.
        """

        candidates = [*invocation.input_artifact_hashes]
        candidates.extend(
            record.sha256
            for record in result.artifacts
            if record.logical_type in _PROVIDER_GRAPH_TYPES
        )
        available: list[str] = []
        for digest in candidates:
            if digest not in available and self.registry.verify(digest):
                available.append(digest)
        return tuple(available)

    @staticmethod
    def _text_descriptor(value: str) -> dict[str, object]:
        encoded = value.encode("utf-8")
        return {
            "sha256": sha256_bytes(encoded),
            "size": len(encoded),
            "value_persisted": False,
        }

    @staticmethod
    def _provider_usage_valid(value: object) -> bool:
        if value is None:
            return True
        if not isinstance(value, Mapping):
            return False
        required = {"input_tokens", "output_tokens", "total_tokens"}
        allowed = required | {"input_tokens_details", "output_tokens_details"}
        if set(value) - allowed or not required.issubset(value):
            return False

        def count(candidate: object) -> int | None:
            if (
                isinstance(candidate, bool)
                or not isinstance(candidate, int)
                or not 0 <= candidate <= 10**12
            ):
                return None
            return candidate

        input_tokens = count(value.get("input_tokens"))
        output_tokens = count(value.get("output_tokens"))
        total_tokens = count(value.get("total_tokens"))
        if (
            input_tokens is None
            or output_tokens is None
            or total_tokens is None
            or total_tokens != input_tokens + output_tokens
        ):
            return False
        details_contracts = (
            (
                "input_tokens_details",
                {"cached_tokens", "cache_write_tokens"},
                {"cached_tokens"},
                input_tokens,
            ),
            (
                "output_tokens_details",
                {"reasoning_tokens"},
                {"reasoning_tokens"},
                output_tokens,
            ),
        )
        for field, detail_allowed, detail_required, parent_total in details_contracts:
            if field not in value:
                continue
            details = value[field]
            if (
                not isinstance(details, Mapping)
                or set(details) - detail_allowed
                or not detail_required.issubset(details)
            ):
                return False
            for detail_value in details.values():
                parsed = count(detail_value)
                if parsed is None or parsed > parent_total:
                    return False
        return True

    @staticmethod
    def _expected_provider_request_id(
        body: bytes,
        invocation_id: str,
        contract: ProviderVerifierContract,
    ) -> str:
        return contract.expected_request_id(body, invocation_id)

    def _provider_capture(
        self,
        records: Sequence[ArtifactRecord],
    ) -> _ProviderCapture | None:
        groups: dict[str, list[ArtifactRecord]] = {}
        for record in records:
            if (
                not isinstance(record, ArtifactRecord)
                or not self.registry.verify(record.sha256)
                or self.registry.get_metadata(record.sha256) != record
            ):
                return None
            groups.setdefault(record.logical_type, []).append(record)
        if any(len(groups.get(logical_type, ())) != 1 for logical_type in _PROVIDER_SINGLETON_TYPES):
            return None
        if any(
            len(groups.get(logical_type, ())) > 1
            for logical_type in _PROVIDER_OPTIONAL_SINGLETON_TYPES
        ):
            return None
        raw_records = tuple(groups.get("external_response_raw", ()))
        if not 1 <= len(raw_records) <= 8:
            return None

        def one(logical_type: str) -> ArtifactRecord:
            return groups[logical_type][0]

        capture = _ProviderCapture(
            instructions=one("model_judged_instructions"),
            input_text=one("model_judged_input"),
            output_schema=one("model_output_schema"),
            invocation=one("model_invocation"),
            request_body=one("model_provider_request_body"),
            request_intent=one("model_provider_request_intent"),
            external_request=one("external_request"),
            raw_responses=raw_records,
            response_receipt=one("external_response_receipt"),
            transport_execution_authority=(
                one(AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE)
                if groups.get(AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE)
                else None
            ),
            provider_response=one("model_provider_response"),
            output=one("model_output"),
        )
        expected_metadata = {
            "model_judged_instructions": (Role.ORCHESTRATOR, "text/plain"),
            "model_judged_input": (Role.ORCHESTRATOR, "text/plain"),
            "model_output_schema": (Role.ORCHESTRATOR, "application/json"),
            "model_invocation": (Role.ORCHESTRATOR, "application/json"),
            "model_provider_request_body": (Role.ORCHESTRATOR, "application/json"),
            "model_provider_request_intent": (Role.ORCHESTRATOR, "application/json"),
            "external_request": (Role.ORCHESTRATOR, "application/json"),
            "external_response_raw": (Role.EVIDENCE_CURATOR, "application/octet-stream"),
            "external_response_receipt": (Role.EVIDENCE_CURATOR, "application/json"),
            AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE: (
                Role.EVIDENCE_CURATOR,
                "application/json",
            ),
            "model_provider_response": (Role.ORCHESTRATOR, "application/json"),
            "model_output": (Role.ORCHESTRATOR, "application/json"),
        }
        for record in capture.records:
            role, mime_type = expected_metadata[record.logical_type]
            expected_schema = {
                "external_request": EGRESS_REQUEST_SCHEMA,
                "external_response_receipt": EGRESS_RESPONSE_RECEIPT_SCHEMA,
                AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE: (
                    AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA
                ),
            }.get(record.logical_type, "1.0")
            if (
                record.creator_role is not role
                or record.mime_type != mime_type
                or record.schema_version
                != expected_schema
                or record.validation_result != "PASS"
                or not record.frozen
            ):
                return None
        return capture

    def _provider_capture_projection(
        self,
        capture: _ProviderCapture,
        *,
        invocation: ModelInvocation | None = None,
        result: ModelResult | None = None,
        proposal_payload: Mapping[str, Any] | None = None,
    ) -> ProviderExecutionProjection | bool:
        """Rehydrate one supported provider graph into a neutral projection."""

        if (invocation is None) != (result is None):
            return False
        if invocation is None and proposal_payload is None:
            return False
        try:
            if any(
                record.parent_artifacts
                for record in (
                    capture.instructions,
                    capture.input_text,
                    capture.output_schema,
                    capture.request_body,
                    *capture.raw_responses,
                )
            ):
                return False
            instructions_bytes = self.registry.get_bytes(capture.instructions.sha256)
            input_bytes = self.registry.get_bytes(capture.input_text.sha256)
            schema_bytes = self.registry.get_bytes(capture.output_schema.sha256)
            body_bytes = self.registry.get_bytes(capture.request_body.sha256)
            if (
                len(instructions_bytes) > 64 * 1024
                or len(input_bytes) > 1024 * 1024
                or len(schema_bytes) > MAX_PROVIDER_CUSTODY_BYTES
                or len(body_bytes) > MAX_PROVIDER_CUSTODY_BYTES
            ):
                return False
            instructions = instructions_bytes.decode("utf-8")
            input_text = input_bytes.decode("utf-8")
            schema = safe_json_loads(schema_bytes, max_bytes=MAX_PROVIDER_CUSTODY_BYTES)
            if (
                not isinstance(schema, Mapping)
                or schema_bytes != canonical_json_bytes(schema)
            ):
                return False

            if invocation is not None:
                expected_invocation_id = invocation.invocation_id
                expected_provider_id = result.provider_id
                expected_capability = invocation.capability.value
                expected_model = invocation.model
                expected_inputs = list(invocation.input_artifact_hashes)
                expected_schema = thaw_json(invocation.output_schema)
                if (
                    instructions_bytes != invocation.instructions.encode("utf-8")
                    or input_bytes != invocation.input_text.encode("utf-8")
                    or schema_bytes != canonical_json_bytes(expected_schema)
                ):
                    return False
            else:
                assert proposal_payload is not None
                expected_invocation_id = proposal_payload.get("invocation_id")
                expected_provider_id = proposal_payload.get("provider_id")
                expected_capability = proposal_payload.get("capability")
                expected_model = proposal_payload.get("model_requested")
                expected_inputs = proposal_payload.get("declared_input_artifact_hashes")
                expected_schema = self.catalog.proposal_schema()
                if (
                    not isinstance(expected_invocation_id, str)
                    or not isinstance(expected_provider_id, str)
                    or expected_capability != ModelCapability.CODING.value
                    or not isinstance(expected_model, str)
                    or not isinstance(expected_inputs, list)
                    or schema_bytes != canonical_json_bytes(expected_schema)
                ):
                    return False

            try:
                validate_identifier(expected_invocation_id, "provider invocation ID")
                expected_model_bytes = expected_model.encode("utf-8")
                contract = require_provider_verifier(
                    expected_provider_id,
                    capture.invocation.schema_version,
                )
            except (
                AttributeError,
                ProviderVerificationError,
                TypeError,
                UnicodeEncodeError,
                ValidationError,
            ):
                return False
            if (
                not expected_model_bytes
                or len(expected_model_bytes) > 256
                or "\x00" in expected_model
                or not input_bytes
                or b"\x00" in instructions_bytes
                or b"\x00" in input_bytes
            ):
                return False
            captured_invocation = safe_json_loads(
                self.registry.get_bytes(capture.invocation.sha256),
                max_bytes=256 * 1024,
            )
            if not isinstance(captured_invocation, Mapping):
                return False
            max_output_tokens = captured_invocation.get("max_output_tokens")
            if (
                isinstance(max_output_tokens, bool)
                or not isinstance(max_output_tokens, int)
                or not 1 <= max_output_tokens <= 100_000
                or (
                    invocation is not None
                    and max_output_tokens != invocation.max_output_tokens
                )
            ):
                return False
            request_projection = contract.validate_and_project_request(
                body_bytes=body_bytes,
                retained_instructions=instructions,
                retained_input=input_text,
                retained_schema=expected_schema,
                invocation_id=expected_invocation_id,
                model_requested=expected_model,
                maximum_output_tokens=max_output_tokens,
            )
            expected_invocation_fields = {
                "schema_version",
                "kind",
                "invocation_id",
                "provider_id",
                "capability",
                "model",
                "prompt_template",
                "instructions",
                "input_text",
                "input_artifact_hashes",
                "output_schema",
                "max_output_tokens",
                "provider_tools",
                "scientific_evidence",
                "secret_values_persisted",
            }
            prompt = captured_invocation.get("prompt_template")
            expected_prompt = {
                "id": self._text_descriptor(_AUTONOMOUS_PROMPT_TEMPLATE_ID),
                "version": self._text_descriptor(
                    _AUTONOMOUS_PROMPT_TEMPLATE_VERSION
                ),
                "sha256": _AUTONOMOUS_PROMPT_TEMPLATE_HASH,
            }
            prompt_valid = prompt == expected_prompt
            if invocation is not None:
                prompt_valid = prompt_valid and prompt == {
                    "id": self._text_descriptor(invocation.prompt_template_id),
                    "version": self._text_descriptor(
                        invocation.prompt_template_version
                    ),
                    "sha256": invocation.prompt_template_hash,
                }
            if (
                set(captured_invocation) != expected_invocation_fields
                or captured_invocation.get("schema_version") != "1.0"
                or captured_invocation.get("kind") != "MODEL_INVOCATION"
                or captured_invocation.get("invocation_id")
                != self._text_descriptor(expected_invocation_id)
                or captured_invocation.get("provider_id") != expected_provider_id
                or captured_invocation.get("capability") != expected_capability
                or captured_invocation.get("model") != self._text_descriptor(expected_model)
                or not prompt_valid
                or captured_invocation.get("instructions")
                != self._text_descriptor(instructions)
                or captured_invocation.get("input_text") != self._text_descriptor(input_text)
                or captured_invocation.get("input_artifact_hashes") != expected_inputs
                or captured_invocation.get("output_schema")
                != {
                    "sha256": sha256_bytes(schema_bytes),
                    "value_persisted": False,
                }
                or captured_invocation.get("max_output_tokens") != max_output_tokens
                or captured_invocation.get("provider_tools") is not False
                or captured_invocation.get("scientific_evidence") is not False
                or captured_invocation.get("secret_values_persisted") is not False
                or capture.invocation.parent_artifacts != tuple(expected_inputs)
            ):
                return False

            request_id = request_projection.request_id
            request_intent = safe_json_loads(
                self.registry.get_bytes(capture.request_intent.sha256),
                max_bytes=64 * 1024,
            )
            expected_intent = {
                "schema_version": "1.0",
                "kind": "MODEL_PROVIDER_REQUEST_INTENT",
                "invocation_artifact_sha256": capture.invocation.sha256,
                "request_body_artifact_sha256": capture.request_body.sha256,
                "request_id": request_id,
                "provider_id": contract.provider_id,
                "method": "POST",
                "endpoint": contract.endpoint,
                "body_sha256": request_projection.body_sha256,
                "body_size": request_projection.body_size,
                "credential_value_persisted": False,
                "scientific_evidence": False,
            }
            if (
                request_intent != expected_intent
                or capture.request_intent.parent_artifacts
                != (capture.invocation.sha256, capture.request_body.sha256)
            ):
                return False

            external_request = safe_json_loads(
                self.registry.get_bytes(capture.external_request.sha256),
                max_bytes=64 * 1024,
            )
            if (
                not isinstance(external_request, Mapping)
                or capture.external_request.parent_artifacts
                != (capture.request_intent.sha256,)
            ):
                return False

            receipt = safe_json_loads(
                self.registry.get_bytes(capture.response_receipt.sha256),
                max_bytes=256 * 1024,
            )
            if not isinstance(receipt, Mapping) or set(receipt) != {
                "schema_version",
                "kind",
                "request_id",
                "policy_claim_sha256",
                "request_artifact_sha256",
                "raw_response_sha256",
                "raw_response_record_sha256",
                "status_code",
                "content_type",
                "body_size",
                "headers",
                "attempts",
                "captured_at",
                "network_used",
                "scientific_evidence",
                "external_validation",
                "transport_authority",
                "egress_budget",
            }:
                return False
            attempts = receipt.get("attempts")
            if not isinstance(attempts, list) or not 1 <= len(attempts) <= 8:
                return False
            policy_claim_sha256 = external_request.get("policy_claim_sha256")
            budget_policy = {
                "schema_version": EGRESS_BUDGET_SCHEMA,
                "maximum_total_bytes": 32 * 1024 * 1024,
                "byte_accounting": (
                    "REQUEST_BODY_PER_ATTEMPT_PLUS_EACH_RECEIVED_RESPONSE_BODY"
                ),
                "deadline_budget_seconds": 60.0,
                "deadline_scope": (
                    "MONOTONIC_EXECUTE_ENTRY_THROUGH_FINAL_RESPONSE_CAPTURE"
                ),
            }
            if (
                not isinstance(policy_claim_sha256, str)
                or len(policy_claim_sha256) != 64
                or any(character not in "0123456789abcdef" for character in policy_claim_sha256)
            ):
                return False
            expected_external_request = {
                "schema_version": EGRESS_REQUEST_SCHEMA,
                "kind": "REDACTED_EXTERNAL_REQUEST",
                "request_id": request_id,
                "policy_id": contract.provider_version,
                "policy_claim_sha256": policy_claim_sha256,
                "adapter_id": contract.provider_id,
                "method": "POST",
                "url": contract.endpoint,
                "headers": [
                    ["Accept", "application/json"],
                    ["User-Agent", "Scientist-One-vNext/1"],
                    ["Idempotency-Key", expected_invocation_id],
                ],
                "body_sha256": sha256_bytes(body_bytes),
                "body_size": len(body_bytes),
                "content_type": "application/json",
                "credential_env_name": contract.credential_env_name,
                "credential_present": contract.credential_present,
                "parent_artifacts": [capture.request_intent.sha256],
                "scientific_evidence": False,
                "egress_budget": budget_policy,
            }
            if dict(external_request) != expected_external_request:
                return False
            raw_by_hash = {record.sha256: record for record in capture.raw_responses}
            ordered_raw_hashes: list[str] = []
            request_bytes_used = 0
            response_bytes_used = 0
            prior_completed = 0.0
            for index, attempt in enumerate(attempts, start=1):
                if not isinstance(attempt, Mapping) or set(attempt) != {
                    "schema_version",
                    "attempt",
                    "status",
                    "status_code",
                    "body_sha256",
                    "body_size",
                    "raw_response_record_sha256",
                    "request_body_bytes",
                    "response_body_bytes",
                    "cumulative_bytes",
                    "started_offset_seconds",
                    "completed_offset_seconds",
                    "retry_delay_seconds",
                } or (
                    attempt.get("schema_version") != EGRESS_ATTEMPT_SCHEMA
                    or attempt.get("attempt") != index
                ):
                    return False
                started = attempt.get("started_offset_seconds")
                completed = attempt.get("completed_offset_seconds")
                if (
                    isinstance(started, bool)
                    or not isinstance(started, (int, float))
                    or isinstance(completed, bool)
                    or not isinstance(completed, (int, float))
                    or float(started) < prior_completed
                    or float(completed) < float(started)
                    or attempt.get("request_body_bytes") != len(body_bytes)
                ):
                    return False
                if attempt.get("status") == "TRANSPORT_FAILURE":
                    if any(
                        attempt.get(field) is not None
                        for field in (
                            "status_code",
                            "body_sha256",
                            "body_size",
                            "raw_response_record_sha256",
                        )
                    ) or attempt.get("response_body_bytes") != 0:
                        return False
                    request_bytes_used += len(body_bytes)
                    if (
                        attempt.get("cumulative_bytes")
                        != request_bytes_used + response_bytes_used
                    ):
                        return False
                    prior_completed = float(completed)
                    continue
                if attempt.get("status") != "RESPONSE":
                    return False
                raw_hash = attempt.get("raw_response_record_sha256")
                raw_record = raw_by_hash.get(raw_hash)
                if raw_record is None:
                    return False
                raw_bytes = self.registry.get_bytes(raw_record.sha256)
                if (
                    attempt.get("body_sha256") != sha256_bytes(raw_bytes)
                    or attempt.get("body_size") != len(raw_bytes)
                    or isinstance(attempt.get("status_code"), bool)
                    or not isinstance(attempt.get("status_code"), int)
                    or not 100 <= attempt["status_code"] <= 599
                    or (
                        index < len(attempts)
                        and attempt["status_code"]
                        not in {429, 500, 502, 503, 504}
                    )
                ):
                    return False
                request_bytes_used += len(body_bytes)
                response_bytes_used += len(raw_bytes)
                if (
                    attempt.get("response_body_bytes") != len(raw_bytes)
                    or attempt.get("cumulative_bytes")
                    != request_bytes_used + response_bytes_used
                ):
                    return False
                if index < len(attempts):
                    retry_delay = attempt.get("retry_delay_seconds")
                    if (
                        isinstance(retry_delay, bool)
                        or not isinstance(retry_delay, (int, float))
                        or float(retry_delay) < 0.0
                    ):
                        return False
                elif attempt.get("retry_delay_seconds") is not None:
                    return False
                prior_completed = float(completed)
                if raw_hash not in ordered_raw_hashes:
                    ordered_raw_hashes.append(raw_hash)
            final_attempt = attempts[-1]
            final_raw_hash = final_attempt.get("raw_response_record_sha256")
            final_raw = raw_by_hash.get(final_raw_hash)
            if (
                final_attempt.get("status") != "RESPONSE"
                or final_raw is None
                or set(raw_by_hash) != set(ordered_raw_hashes)
                or tuple(record.sha256 for record in capture.raw_responses)
                != tuple(ordered_raw_hashes)
            ):
                return False
            final_raw_bytes = self.registry.get_bytes(final_raw.sha256)
            status_code = final_attempt.get("status_code")
            captured_at = receipt.get("captured_at")
            network_used = receipt.get("network_used")
            external_validation = receipt.get("external_validation")
            transport_authority = receipt.get("transport_authority")
            transport_execution_authority_hash = (
                capture.transport_execution_authority.sha256
                if capture.transport_execution_authority is not None
                else None
            )
            response_headers = receipt.get("headers")
            try:
                contract.validate_response_headers(
                    response_headers,
                    body_size=len(final_raw_bytes),
                )
            except ProviderVerificationError:
                return False
            if (
                receipt.get("schema_version") != EGRESS_RESPONSE_RECEIPT_SCHEMA
                or receipt.get("kind") != "EXTERNAL_RESPONSE_RECEIPT"
                or receipt.get("request_id") != request_id
                or receipt.get("policy_claim_sha256") != policy_claim_sha256
                or receipt.get("request_artifact_sha256")
                != capture.external_request.sha256
                or receipt.get("raw_response_sha256") != sha256_bytes(final_raw_bytes)
                or receipt.get("raw_response_record_sha256") != final_raw.sha256
                or receipt.get("status_code") != status_code
                or not isinstance(status_code, int)
                or not 200 <= status_code <= 299
                or receipt.get("content_type") != "application/json"
                or receipt.get("body_size") != len(final_raw_bytes)
                or not isinstance(captured_at, str)
                or not 1 <= len(captured_at) <= 128
                or "\x00" in captured_at
                or not isinstance(network_used, bool)
                or not isinstance(external_validation, str)
                or not 1 <= len(external_validation) <= 128
                or "\x00" in external_validation
                or transport_authority
                not in {
                    AUDITED_LIVE_TRANSPORT_AUTHORITY,
                    UNVERIFIED_TRANSPORT_AUTHORITY,
                }
                or (
                    transport_authority == AUDITED_LIVE_TRANSPORT_AUTHORITY
                    and (
                        network_used is not True
                        or external_validation
                        != "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                        or transport_execution_authority_hash is None
                    )
                )
                or (
                    transport_authority == UNVERIFIED_TRANSPORT_AUTHORITY
                    and (
                        external_validation != "UNTESTED"
                        or transport_execution_authority_hash is not None
                    )
                )
                or receipt.get("scientific_evidence") is not False
                or not isinstance(receipt.get("egress_budget"), Mapping)
                or capture.response_receipt.parent_artifacts
                != (capture.external_request.sha256, *ordered_raw_hashes)
            ):
                return False
            if transport_authority == AUDITED_LIVE_TRANSPORT_AUTHORITY:
                if (
                    not contract.audited_live_allowed
                    or self._expected_run_id is None
                    or self._authority_ledger is None
                    or capture.transport_execution_authority is None
                    or not self._live_authority_context_is_canonical(
                        self.registry,
                        self._authority_ledger,
                        self._expected_run_id,
                    )
                ):
                    return False
                authenticated = require_audited_live_transport_execution(
                    self.registry,
                    self._authority_ledger,
                    run_id=self._expected_run_id,
                    authority_artifact_sha256=(
                        capture.transport_execution_authority.sha256
                    ),
                    response_receipt_artifact_sha256=(
                        capture.response_receipt.sha256
                    ),
                )
                if (
                    authenticated.run_id != self._expected_run_id
                    or authenticated.authority_artifact
                    != capture.transport_execution_authority
                    or authenticated.response_receipt_artifact
                    != capture.response_receipt
                    or authenticated.request_artifact != capture.external_request
                    or authenticated.raw_response_artifact != final_raw
                    or authenticated.request_id != request_id
                    or authenticated.policy_id != contract.provider_version
                    or authenticated.body_sha256
                    != sha256_bytes(final_raw_bytes)
                    or authenticated.body_size != len(final_raw_bytes)
                    or authenticated.status_code != status_code
                    or authenticated.content_type != "application/json"
                ):
                    return False
            elif (
                not contract.audited_live_allowed
                and (network_used is not False or external_validation != "UNTESTED")
            ):
                return False
            budget = receipt["egress_budget"]
            expected_budget_keys = {
                *budget_policy,
                "request_bytes_used",
                "response_bytes_used",
                "total_bytes_used",
                "deadline_elapsed_seconds",
                "deadline_remaining_seconds",
                "deadline_satisfied",
            }
            if (
                set(budget) != expected_budget_keys
                or any(budget.get(key) != value for key, value in budget_policy.items())
                or budget.get("request_bytes_used") != request_bytes_used
                or budget.get("response_bytes_used") != response_bytes_used
                or budget.get("total_bytes_used") != request_bytes_used + response_bytes_used
                or budget.get("deadline_satisfied") is not True
                or isinstance(budget.get("deadline_elapsed_seconds"), bool)
                or not isinstance(budget.get("deadline_elapsed_seconds"), (int, float))
                or float(budget["deadline_elapsed_seconds"]) < prior_completed
                or isinstance(budget.get("deadline_remaining_seconds"), bool)
                or not isinstance(budget.get("deadline_remaining_seconds"), (int, float))
                or float(budget["deadline_remaining_seconds"]) < 0.0
            ):
                return False

            envelope = safe_json_loads(
                final_raw_bytes,
                max_bytes=MAX_PROVIDER_RESPONSE_BYTES,
            )
            provider_response = safe_json_loads(
                self.registry.get_bytes(capture.provider_response.sha256),
                max_bytes=MAX_PROVIDER_RESPONSE_BYTES,
            )
            expected_provider_response: dict[str, Any] = {
                "schema_version": "1.0",
                "kind": "MODEL_PROVIDER_RESPONSE",
                "request_id": request_id,
                "raw_response_sha256": sha256_bytes(final_raw_bytes),
                "response": dict(envelope),
                "network_used": network_used,
                "external_validation": external_validation,
                "transport_authority": transport_authority,
                "scientific_evidence": False,
            }
            if transport_execution_authority_hash is not None:
                expected_provider_response[
                    "transport_execution_authority_artifact_sha256"
                ] = transport_execution_authority_hash
            expected_provider_response_parents = (
                final_raw.sha256,
                capture.response_receipt.sha256,
                *(
                    (transport_execution_authority_hash,)
                    if transport_execution_authority_hash is not None
                    else ()
                ),
            )
            if (
                not isinstance(envelope, Mapping)
                or provider_response != expected_provider_response
                or capture.provider_response.parent_artifacts
                != expected_provider_response_parents
            ):
                return False
            parsed_envelope = contract.parse_and_project_response(
                raw_bytes=final_raw_bytes,
                requested_model=expected_model,
                output_schema=expected_schema,
                maximum_output_bytes=MAX_PROVIDER_RESPONSE_BYTES,
                expected_request_id=request_id,
            )
            response_id = parsed_envelope.response_id
            usage = thaw_json(parsed_envelope.usage)
            parsed_output = thaw_json(parsed_envelope.output)
            if not self._provider_usage_valid(usage):
                return False

            captured_output = safe_json_loads(
                self.registry.get_bytes(capture.output.sha256),
                max_bytes=MAX_PROVIDER_RESPONSE_BYTES,
            )
            expected_output = {
                "schema_version": "1.0",
                "kind": "MODEL_OUTPUT",
                "invocation_id": expected_invocation_id,
                "provider_id": contract.provider_id,
                "provider_response_id": response_id,
                "model_requested": expected_model,
                "model_returned": expected_model,
                "capability": expected_capability,
                "output": dict(parsed_output),
                "usage": dict(usage) if usage is not None else None,
                "network_used": network_used,
                "external_validation": external_validation,
                "transport_authority": transport_authority,
                "scientific_evidence": False,
                "provider_tools": False,
            }
            if transport_execution_authority_hash is not None:
                expected_output[
                    "transport_execution_authority_artifact_sha256"
                ] = transport_execution_authority_hash
            if (
                captured_output != expected_output
                or capture.output.parent_artifacts
                != (
                    capture.invocation.sha256,
                    capture.request_body.sha256,
                    capture.provider_response.sha256,
                )
            ):
                return False
            if result is not None:
                if not (
                    result.provenance_status == "CAPTURED"
                    and result.status is ModelRunStatus.COMPLETED
                    and result.invocation_id == expected_invocation_id
                    and result.provider_id == contract.provider_id
                    and result.capability is invocation.capability
                    and result.model_requested == expected_model
                    and result.model_returned == expected_model
                    and result.provider_response_id == response_id
                    and result.request_id == request_id
                    and thaw_json(result.output) == parsed_output
                    and (
                        thaw_json(result.usage) if result.usage is not None else None
                    )
                    == (dict(usage) if usage is not None else None)
                    and result.network_used == network_used
                    and result.external_validation == external_validation
                    and result.transport_authority == transport_authority
                    and result.transport_execution_authority_artifact_sha256
                    == transport_execution_authority_hash
                    and result.scientific_evidence is False
                ):
                    return False
            else:
                assert proposal_payload is not None
                if not (
                    proposal_payload.get("provider_id") == contract.provider_id
                    and proposal_payload.get("output") == parsed_output
                    and proposal_payload.get("result_status")
                    == ModelRunStatus.COMPLETED.value
                    and proposal_payload.get("provider_tools") is False
                    and proposal_payload.get("scientific_evidence") is False
                ):
                    return False
            return contract.verify_execution(
                provider_version=external_request.get("policy_id"),
                endpoint=request_intent.get("endpoint"),
                credential_env_name=external_request.get("credential_env_name"),
                credential_present=external_request.get("credential_present"),
                invocation_id=expected_invocation_id,
                request_projection=request_projection,
                response_projection=parsed_envelope,
                request_body_bytes=body_bytes,
                raw_response_bytes=final_raw_bytes,
                retained_instructions=instructions,
                retained_input=input_text,
                retained_schema=expected_schema,
                maximum_output_bytes=MAX_PROVIDER_RESPONSE_BYTES,
                network_used=network_used,
                external_validation=external_validation,
                transport_authority=transport_authority,
                transport_execution_authority_artifact_sha256=(
                    transport_execution_authority_hash
                ),
                custody_artifact_hashes=tuple(
                    record.sha256 for record in capture.records
                ),
            )
        except (
            ArtifactError,
            EgressPolicyError,
            UnicodeDecodeError,
            ValidationError,
            ValueError,
            TypeError,
        ):
            return False

    def _provider_capture_valid(
        self,
        capture: _ProviderCapture,
        *,
        invocation: ModelInvocation | None = None,
        result: ModelResult | None = None,
        proposal_payload: Mapping[str, Any] | None = None,
    ) -> bool:
        projection = self._provider_capture_projection(
            capture,
            invocation=invocation,
            result=result,
            proposal_payload=proposal_payload,
        )
        return isinstance(projection, ProviderExecutionProjection)

    def _provider_provenance_valid(
        self,
        invocation: ModelInvocation,
        result: ModelResult,
    ) -> bool:
        """Resolve the complete captured provider/gateway graph before admission."""

        if (
            result.provenance_status != "CAPTURED"
            or not result.artifacts
            or result.model_requested != invocation.model
            or result.model_returned != invocation.model
        ):
            return False
        capture = self._provider_capture(result.artifacts)
        return bool(
            capture is not None
            and self._provider_capture_valid(
                capture,
                invocation=invocation,
                result=result,
            )
        )

    def _proposal_artifact(
        self,
        invocation: ModelInvocation,
        result: ModelResult,
    ) -> ArtifactRecord:
        output = thaw_json(result.output) if result.output is not None else None
        payload = {
            "schema_version": "AUTONOMOUS_IMPLEMENTATION_PROVIDER_ATTEMPT_V1",
            "invocation_id": invocation.invocation_id,
            "provider_id": result.provider_id,
            "model_requested": result.model_requested,
            "capability": result.capability.value,
            "result_status": result.status.value,
            "output": output,
            "declared_input_artifact_hashes": list(invocation.input_artifact_hashes),
            "trust_class": "UNTRUSTED_ADVISORY",
            "scientific_evidence": False,
            "provider_tools": False,
        }
        encoded = canonical_json_bytes(payload) + b"\n"
        if len(encoded) > MAX_PROPOSAL_BYTES:
            raise AutonomousImplementationError("provider proposal attempt exceeds byte bound")
        return self.registry.put_bytes(
            encoded,
            logical_type="autonomous_implementation.model_proposal",
            origin="untrusted advisory CODING provider output",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "capture-coding-proposal"),
            parent_artifacts=self._available_parents(invocation, result),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def _receipt(
        self,
        *,
        proposal_artifact: ArtifactRecord,
        status: AdmissionStatus,
        reason_code: str,
        declared_evidence: Sequence[str],
        checked_evidence: Sequence[str],
        additional_parents: Sequence[str] = (),
        template_id: str | None = None,
        code_sha256: str | None = None,
        configuration_sha256: str | None = None,
    ) -> ArtifactRecord:
        validate_identifier(reason_code, "implementation decision reason")
        payload = {
            "schema_version": VALIDATION_SCHEMA_VERSION,
            "status": status.value,
            "reason_code": reason_code,
            "proposal_artifact_sha256": proposal_artifact.sha256,
            "catalog_artifact_sha256": self.catalog.artifact.sha256,
            "template_id": template_id,
            "worker_code_sha256": code_sha256,
            "configuration_sha256": configuration_sha256,
            "declared_parent_evidence_sha256s": list(declared_evidence),
            "verified_parent_evidence_sha256s": list(checked_evidence),
            "checks": [
                "exact_provider_capability",
                "exact_provider_schema",
                "strict_proposal_shape",
                "reviewed_template_membership",
                "bounded_template_parameters",
                "complete_parent_evidence",
                "double_render_determinism",
                "reviewed_worker_code_hash",
                "fixed_no_shell_no_network_execution_contract",
            ],
            "provider_output_trust": "UNTRUSTED_ADVISORY",
            "scientific_evidence": False,
        }
        parents: list[str] = [proposal_artifact.sha256, self.catalog.artifact.sha256]
        for digest in (*checked_evidence, *additional_parents):
            if digest not in parents:
                parents.append(digest)
        return self.registry.put_json(
            payload,
            logical_type="autonomous_implementation.validation_receipt",
            origin="deterministic autonomous implementation admission",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "validate-coding-proposal"),
            parent_artifacts=tuple(parents),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def _reject(
        self,
        proposal_artifact: ArtifactRecord,
        reason_code: str,
        declared_evidence: Sequence[str],
        checked_evidence: Sequence[str],
    ) -> ImplementationAdmission:
        receipt = self._receipt(
            proposal_artifact=proposal_artifact,
            status=AdmissionStatus.REJECTED,
            reason_code=reason_code,
            declared_evidence=declared_evidence,
            checked_evidence=checked_evidence,
        )
        return ImplementationAdmission(
            status=AdmissionStatus.REJECTED,
            reason_code=reason_code,
            proposal_artifact=proposal_artifact,
            validation_receipt=receipt,
        )

    @staticmethod
    def _action_semantics(
        proposal: ImplementationProposal,
        context: ImplementationContext,
    ) -> dict[str, Any]:
        """Return provider-neutral executable semantics for one reviewed action."""

        return {
            "schema_version": ACTION_SEMANTICS_SCHEMA_VERSION,
            "experiment_id": context.experiment_id,
            "hypothesis_id": context.hypothesis_id,
            "phase": context.phase.value,
            "template_id": proposal.template_id.value,
            "template_version": "1.0",
            "parameters": dict(sorted(proposal.parameters.items())),
            "parent_evidence_sha256s": sorted(proposal.parent_evidence_sha256s),
            "data_sha256": context.data_artifact_sha256,
            "evaluator_sha256": context.evaluator_artifact_sha256,
            "seeds": list(context.seeds),
        }

    @classmethod
    def _normalize_actionable_proposal(
        cls,
        proposal: ImplementationProposal,
        context: ImplementationContext,
    ) -> tuple[ImplementationProposal, str]:
        semantics = cls._action_semantics(proposal, context)
        semantic_id = sha256_bytes(canonical_json_bytes(semantics))
        return (
            ImplementationProposal(
                proposal_id=f"action-{semantic_id}",
                implementation_id=f"implementation-{semantic_id}",
                template_id=proposal.template_id,
                parameters=proposal.parameters,
                parent_evidence_sha256s=tuple(
                    semantics["parent_evidence_sha256s"]
                ),
                rationale=(
                    "Source-owned deterministic normalization of an admitted "
                    "reviewed-template action."
                ),
            ),
            semantic_id,
        )

    @classmethod
    def _actionable_proposal_payload(
        cls,
        proposal: ImplementationProposal,
        context: ImplementationContext,
        *,
        semantic_id: str,
        catalog_artifact_sha256: str,
    ) -> dict[str, Any]:
        validate_sha256(semantic_id, "action semantic SHA-256")
        validate_sha256(
            catalog_artifact_sha256,
            "action catalog artifact SHA-256",
        )
        return {
            "schema_version": ACTIONABLE_PROPOSAL_SCHEMA_VERSION,
            "semantic_id": semantic_id,
            "semantics": cls._action_semantics(proposal, context),
            "proposal": proposal.to_dict(),
            "catalog_artifact_sha256": catalog_artifact_sha256,
            "provider_identity_included": False,
            "scientific_evidence": False,
        }

    @staticmethod
    def _configuration(
        proposal: ImplementationProposal,
        context: ImplementationContext,
        proposal_artifact_sha256: str,
    ) -> dict[str, Any]:
        validate_sha256(
            proposal_artifact_sha256,
            "implementation proposal artifact SHA-256",
        )
        return {
            "schema_version": WORKER_CONFIGURATION_SCHEMA_VERSION,
            "experiment_id": context.experiment_id,
            "hypothesis_id": context.hypothesis_id,
            "implementation_id": proposal.implementation_id,
            "phase": context.phase.value,
            "proposal_id": proposal.proposal_id,
            "proposal_artifact_sha256": proposal_artifact_sha256,
            "template_id": proposal.template_id.value,
            "template_version": "1.0",
            "parameters": dict(sorted(proposal.parameters.items())),
            "parent_evidence_sha256s": list(proposal.parent_evidence_sha256s),
            "data_sha256": context.data_artifact_sha256,
            "evaluator_sha256": context.evaluator_artifact_sha256,
            "seeds": list(context.seeds),
        }

    def _action_validation_payload(
        self,
        *,
        actionable_proposal_sha256: str,
        proposal: ImplementationProposal,
        semantic_id: str,
        declared_evidence: Sequence[str],
        code_artifact_sha256: str,
        configuration_artifact_sha256: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": ACTION_VALIDATION_SCHEMA_VERSION,
            "status": AdmissionStatus.ADMITTED.value,
            "reason_code": "REVIEWED_TEMPLATE_ACTION_ADMITTED",
            "semantic_id": semantic_id,
            "actionable_proposal_artifact_sha256": actionable_proposal_sha256,
            "catalog_artifact_sha256": self.catalog.artifact.sha256,
            "template_id": proposal.template_id.value,
            "worker_code_sha256": code_artifact_sha256,
            "configuration_sha256": configuration_artifact_sha256,
            "declared_parent_evidence_sha256s": list(declared_evidence),
            "verified_parent_evidence_sha256s": list(declared_evidence),
            "checks": [
                "strict_normalized_action_shape",
                "reviewed_template_membership",
                "bounded_template_parameters",
                "complete_parent_evidence",
                "double_render_determinism",
                "reviewed_worker_code_hash",
                "fixed_no_shell_no_network_execution_contract",
            ],
            "provider_provenance_custody": "SEPARATE_ADVISORY_LINK_REQUIRED",
            "provider_identity_included": False,
            "scientific_evidence": False,
        }

    def _action_validation_receipt(
        self,
        *,
        actionable_proposal: ArtifactRecord,
        proposal: ImplementationProposal,
        semantic_id: str,
        declared_evidence: Sequence[str],
        code_artifact: ArtifactRecord,
        configuration_artifact: ArtifactRecord,
    ) -> ArtifactRecord:
        payload = self._action_validation_payload(
            actionable_proposal_sha256=actionable_proposal.sha256,
            proposal=proposal,
            semantic_id=semantic_id,
            declared_evidence=declared_evidence,
            code_artifact_sha256=code_artifact.sha256,
            configuration_artifact_sha256=configuration_artifact.sha256,
        )
        return self.registry.put_json(
            payload,
            logical_type="autonomous_implementation.validation_receipt",
            origin="provider-neutral deterministic implementation admission",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "validate-actionable-proposal"),
            parent_artifacts=_unique_digests(
                (
                    actionable_proposal.sha256,
                    self.catalog.artifact.sha256,
                    code_artifact.sha256,
                    configuration_artifact.sha256,
                ),
                declared_evidence,
            ),
            schema_version="2.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    @staticmethod
    def _provider_admission_link_payload(
        *,
        provider_attempt_sha256: str,
        actionable_proposal_sha256: str,
        action_validation_receipt_sha256: str,
        projection: ProviderExecutionProjection,
        semantic_id: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": PROVIDER_ADMISSION_LINK_SCHEMA_VERSION,
            "status": AdmissionStatus.ADMITTED.value,
            "reason_code": "VERIFIED_ADVISORY_PROVIDER_ACTION_LINK",
            "provider_attempt_artifact_sha256": provider_attempt_sha256,
            "actionable_proposal_artifact_sha256": actionable_proposal_sha256,
            "action_validation_receipt_sha256": action_validation_receipt_sha256,
            "semantic_id": semantic_id,
            "provider": {
                "provider_id": projection.provider_id,
                "provenance_schema_version": (
                    projection.provenance_schema_version
                ),
                "provider_version": projection.provider_version,
                "invocation_id": projection.invocation_id,
                "request_id": projection.request_id,
                "model_requested": projection.model_requested,
                "model_returned": projection.model_returned,
                "provider_response_id": projection.provider_response_id,
                "network_used": projection.network_used,
                "external_validation": projection.external_validation,
                "transport_authority": projection.transport_authority,
                "transport_execution_authority_artifact_sha256": (
                    projection.transport_execution_authority_artifact_sha256
                ),
                "custody_artifact_hashes": list(
                    projection.custody_artifact_hashes
                ),
                "scientific_evidence": False,
            },
            "provider_output_trust": "UNTRUSTED_ADVISORY",
            "core_action_identity": "PROVIDER_NEUTRAL",
            "scientific_evidence": False,
        }

    def _provider_admission_link(
        self,
        *,
        provider_attempt: ArtifactRecord,
        actionable_proposal: ArtifactRecord,
        action_validation_receipt: ArtifactRecord,
        projection: ProviderExecutionProjection,
        semantic_id: str,
    ) -> ArtifactRecord:
        payload = self._provider_admission_link_payload(
            provider_attempt_sha256=provider_attempt.sha256,
            actionable_proposal_sha256=actionable_proposal.sha256,
            action_validation_receipt_sha256=action_validation_receipt.sha256,
            projection=projection,
            semantic_id=semantic_id,
        )
        return self.registry.put_json(
            payload,
            logical_type="autonomous_implementation.provider_admission_link",
            origin="advisory provider custody linked to a normalized action",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "link-provider-action"),
            parent_artifacts=_unique_digests(
                (
                    provider_attempt.sha256,
                    actionable_proposal.sha256,
                    action_validation_receipt.sha256,
                ),
                projection.custody_artifact_hashes,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def _fixture_inputs_validate(self, context: ImplementationContext) -> bool:
        """Validate the exact closed-catalog fixture input contracts."""

        try:
            data = safe_json_loads(
                self.registry.get_bytes(context.data_artifact_sha256),
                max_bytes=256 * 1024,
            )
            evaluator = safe_json_loads(
                self.registry.get_bytes(context.evaluator_artifact_sha256),
                max_bytes=64 * 1024,
            )
        except (ArtifactError, ValidationError):
            return False
        if not isinstance(data, Mapping) or set(data) != {"values"}:
            return False
        values = data["values"]
        if (
            not isinstance(values, list)
            or not 1 <= len(values) <= 256
            or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                for value in values
            )
        ):
            return False
        return evaluator == {
            "metric": "template_defined_scalar",
            "metric_id": "metric-autonomous-template-scalar",
            "direction": "HIGHER_IS_BETTER",
        }

    def admit_model_result(
        self,
        invocation: ModelInvocation,
        result: ModelResult,
        context: ImplementationContext,
    ) -> ImplementationAdmission:
        """Persist and deterministically admit or reject one coding proposal."""

        if not isinstance(invocation, ModelInvocation) or not isinstance(result, ModelResult):
            raise AutonomousImplementationError("typed provider invocation and result are required")
        if not isinstance(context, ImplementationContext):
            raise AutonomousImplementationError("typed implementation context is required")
        proposal_artifact = self._proposal_artifact(invocation, result)
        declared = tuple(invocation.input_artifact_hashes)
        checked = tuple(digest for digest in declared if self.registry.verify(digest))
        if invocation.capability is not ModelCapability.CODING:
            return self._reject(proposal_artifact, "WRONG_PROVIDER_CAPABILITY", declared, checked)
        if result.capability is not ModelCapability.CODING or result.invocation_id != invocation.invocation_id:
            return self._reject(proposal_artifact, "PROVIDER_RESULT_BINDING_MISMATCH", declared, checked)
        if result.status is not ModelRunStatus.COMPLETED or result.output is None:
            return self._reject(proposal_artifact, "PROVIDER_RESULT_NOT_COMPLETED", declared, checked)
        provider_capture = self._provider_capture(result.artifacts)
        provider_projection = (
            self._provider_capture_projection(
                provider_capture,
                invocation=invocation,
                result=result,
            )
            if provider_capture is not None
            else False
        )
        if not isinstance(provider_projection, ProviderExecutionProjection):
            return self._reject(
                proposal_artifact,
                "PROVIDER_PROVENANCE_INVALID",
                declared,
                checked,
            )
        expected_schema = canonical_json_bytes(self.catalog.proposal_schema())
        if canonical_json_bytes(thaw_json(invocation.output_schema)) != expected_schema:
            return self._reject(proposal_artifact, "PROVIDER_SCHEMA_CONFUSION", declared, checked)
        try:
            provider_proposal = ImplementationProposal.from_mapping(
                result.output,
                self.catalog,
            )
        except (AutonomousImplementationError, ModelResponseError, ValidationError, ValueError):
            return self._reject(proposal_artifact, "DECLARATIVE_PROPOSAL_INVALID", declared, checked)
        declared = provider_proposal.parent_evidence_sha256s
        checked = tuple(digest for digest in declared if self.registry.verify(digest))
        if set(declared) != set(invocation.input_artifact_hashes):
            return self._reject(proposal_artifact, "PARENT_EVIDENCE_BINDING_MISMATCH", declared, checked)
        required = {context.data_artifact_sha256, context.evaluator_artifact_sha256}
        if required != set(declared):
            return self._reject(proposal_artifact, "REQUIRED_EVIDENCE_NOT_DECLARED", declared, checked)
        if set(checked) != set(declared):
            return self._reject(proposal_artifact, "PARENT_EVIDENCE_MISSING", declared, checked)
        if not self._fixture_inputs_validate(context):
            return self._reject(proposal_artifact, "FIXTURE_INPUT_SCHEMA_INVALID", declared, checked)

        proposal, semantic_id = self._normalize_actionable_proposal(
            provider_proposal,
            context,
        )
        neutral_evidence = proposal.parent_evidence_sha256s
        template = self.catalog.template(proposal.template_id)
        first_render = _render_worker(proposal.template_id)
        second_render = _render_worker(proposal.template_id)
        if first_render != second_render:
            return self._reject(proposal_artifact, "WORKER_GENERATION_NONDETERMINISTIC", declared, checked)
        code_sha256 = sha256_bytes(first_render)
        if code_sha256 != template.worker_code_sha256:
            return self._reject(proposal_artifact, "WORKER_CODE_REVIEW_MISMATCH", declared, checked)
        try:
            actionable_proposal_artifact = self.registry.put_json(
                self._actionable_proposal_payload(
                    proposal,
                    context,
                    semantic_id=semantic_id,
                    catalog_artifact_sha256=self.catalog.artifact.sha256,
                ),
                logical_type="autonomous_implementation.actionable_proposal",
                origin="provider-neutral normalized reviewed-template action",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "normalize-coding-proposal"),
                parent_artifacts=_unique_digests(
                    (self.catalog.artifact.sha256,),
                    neutral_evidence,
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            configuration = self._configuration(
                proposal,
                context,
                actionable_proposal_artifact.sha256,
            )
            first_config = canonical_json_bytes(configuration) + b"\n"
            second_config = canonical_json_bytes(
                self._configuration(
                    proposal,
                    context,
                    actionable_proposal_artifact.sha256,
                )
            ) + b"\n"
            if first_config != second_config:
                return self._reject(
                    proposal_artifact,
                    "CONFIG_GENERATION_NONDETERMINISTIC",
                    declared,
                    checked,
                )
            code_artifact = self.registry.put_bytes(
                first_render,
                logical_type="autonomous_implementation.reviewed_worker_code",
                origin=f"closed reviewed worker template {proposal.template_id.value}",
                creator_role=Role.IMPLEMENTER,
                creation_command=(
                    "scientist-one",
                    "render-reviewed-worker",
                    proposal.template_id.value,
                ),
                parent_artifacts=(template.review_artifact_sha256,),
                schema_version="1.0",
                mime_type="text/x-python",
                validation_result="PASS",
                frozen=True,
            )
            configuration_artifact = self.registry.put_bytes(
                first_config,
                logical_type="autonomous_implementation.worker_configuration",
                origin="strict declarative proposal compiled to reviewed worker configuration",
                creator_role=Role.IMPLEMENTER,
                creation_command=("scientist-one", "compile-worker-configuration"),
                parent_artifacts=_unique_digests(
                    (
                        actionable_proposal_artifact.sha256,
                        self.catalog.artifact.sha256,
                    ),
                    neutral_evidence,
                ),
                schema_version="2.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            action_validation_receipt = self._action_validation_receipt(
                actionable_proposal=actionable_proposal_artifact,
                proposal=proposal,
                semantic_id=semantic_id,
                declared_evidence=neutral_evidence,
                code_artifact=code_artifact,
                configuration_artifact=configuration_artifact,
            )
            provider_admission_link = self._provider_admission_link(
                provider_attempt=proposal_artifact,
                actionable_proposal=actionable_proposal_artifact,
                action_validation_receipt=action_validation_receipt,
                projection=provider_projection,
                semantic_id=semantic_id,
            )
        except ArtifactError:
            return self._reject(
                proposal_artifact,
                "IMPLEMENTATION_ARTIFACT_PERSISTENCE_FAILED",
                declared,
                checked,
            )
        descriptor_payload = {
            "schema_version": DESCRIPTOR_SCHEMA_VERSION,
            "implementation_id": proposal.implementation_id,
            "experiment_id": context.experiment_id,
            "hypothesis_id": context.hypothesis_id,
            "phase": context.phase.value,
            "proposal_id": proposal.proposal_id,
            "template_id": proposal.template_id.value,
            "template_version": template.template_version,
            "catalog_artifact_sha256": self.catalog.artifact.sha256,
            "proposal_artifact_sha256": actionable_proposal_artifact.sha256,
            "worker_code_sha256": code_artifact.sha256,
            "configuration_sha256": configuration_artifact.sha256,
            "parent_evidence_sha256s": list(neutral_evidence),
            "validation_receipt_sha256": action_validation_receipt.sha256,
            "execution_boundary": "FROZEN_RUN_SPEC_LOCAL_MAC_ONLY",
            "shell_allowed": False,
            "network_allowed": False,
            "provider_provenance_custody": "SEPARATE_ADVISORY_LINK_REQUIRED",
            "provider_identity_included": False,
            "scientific_evidence": False,
        }
        descriptor = self.registry.put_json(
            descriptor_payload,
            logical_type="autonomous_implementation.admitted_descriptor",
            origin="admitted deterministic implementation descriptor",
            creator_role=Role.IMPLEMENTER,
            creation_command=("scientist-one", "admit-reviewed-worker"),
            parent_artifacts=_unique_digests(
                (
                    actionable_proposal_artifact.sha256,
                    code_artifact.sha256,
                    configuration_artifact.sha256,
                    action_validation_receipt.sha256,
                    self.catalog.artifact.sha256,
                ),
                neutral_evidence,
            ),
            schema_version="2.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        admitted = AdmittedImplementation(
            proposal=proposal,
            context=context,
            provider_attempt_artifact=proposal_artifact,
            provider_admission_link=provider_admission_link,
            proposal_artifact=actionable_proposal_artifact,
            worker_code_artifact=code_artifact,
            configuration_artifact=configuration_artifact,
            validation_receipt=action_validation_receipt,
            descriptor_artifact=descriptor,
            catalog_artifact_sha256=self.catalog.artifact.sha256,
        )
        return ImplementationAdmission(
            status=AdmissionStatus.ADMITTED,
            reason_code="REVIEWED_TEMPLATE_ADMITTED",
            proposal_artifact=proposal_artifact,
            validation_receipt=provider_admission_link,
            actionable_proposal_artifact=actionable_proposal_artifact,
            action_validation_receipt=action_validation_receipt,
            implementation=admitted,
        )

    def _validate_admitted(self, implementation: AdmittedImplementation) -> None:
        if not isinstance(implementation, AdmittedImplementation):
            raise AutonomousImplementationError("only typed admitted implementations may run")
        if not isinstance(implementation.proposal, ImplementationProposal) or not isinstance(
            implementation.context,
            ImplementationContext,
        ):
            raise AutonomousImplementationError(
                "admitted implementation has invalid typed action context"
            )
        self._validate_catalog()
        if implementation.catalog_artifact_sha256 != self.catalog.artifact.sha256:
            raise AutonomousImplementationError("implementation names another catalog")
        records = (
            implementation.provider_attempt_artifact,
            implementation.provider_admission_link,
            implementation.proposal_artifact,
            implementation.worker_code_artifact,
            implementation.configuration_artifact,
            implementation.validation_receipt,
            implementation.descriptor_artifact,
        )
        if any(
            not self.registry.verify(record.sha256)
            or self.registry.get_metadata(record.sha256) != record
            for record in records
        ):
            raise AutonomousImplementationError("admitted implementation artifact is corrupt")
        expected_metadata = (
            (
                implementation.provider_attempt_artifact,
                "autonomous_implementation.model_proposal",
                Role.ORCHESTRATOR,
                "1.0",
            ),
            (
                implementation.provider_admission_link,
                "autonomous_implementation.provider_admission_link",
                Role.ORCHESTRATOR,
                "1.0",
            ),
            (
                implementation.proposal_artifact,
                "autonomous_implementation.actionable_proposal",
                Role.ORCHESTRATOR,
                "1.0",
            ),
            (
                implementation.worker_code_artifact,
                "autonomous_implementation.reviewed_worker_code",
                Role.IMPLEMENTER,
                "1.0",
            ),
            (
                implementation.configuration_artifact,
                "autonomous_implementation.worker_configuration",
                Role.IMPLEMENTER,
                "2.0",
            ),
            (
                implementation.validation_receipt,
                "autonomous_implementation.validation_receipt",
                Role.ORCHESTRATOR,
                "2.0",
            ),
            (
                implementation.descriptor_artifact,
                "autonomous_implementation.admitted_descriptor",
                Role.IMPLEMENTER,
                "2.0",
            ),
        )
        if any(
            record.logical_type != logical_type
            or record.creator_role is not role
            or record.schema_version != schema_version
            or record.validation_result != "PASS"
            or not record.frozen
            for record, logical_type, role, schema_version in expected_metadata
        ):
            raise AutonomousImplementationError("implementation artifact metadata changed")
        template = self.catalog.template(implementation.proposal.template_id)
        _review_record(
            self.registry,
            template.template_id,
            template.review_artifact_sha256,
        )
        rendered_once = _render_worker(implementation.proposal.template_id)
        rendered_twice = _render_worker(implementation.proposal.template_id)
        if rendered_once != rendered_twice:
            raise AutonomousImplementationError("worker generation is no longer deterministic")
        if (
            sha256_bytes(rendered_once) != _pinned_worker_sha256(template.template_id)
            or template.worker_code_sha256
            != _pinned_worker_sha256(template.template_id)
            or self.registry.get_bytes(implementation.worker_code_artifact.sha256) != rendered_once
            or set(implementation.worker_code_artifact.parent_artifacts)
            != {template.review_artifact_sha256}
        ):
            raise AutonomousImplementationError("worker bytes no longer match reviewed catalog")
        evidence = implementation.proposal.parent_evidence_sha256s
        if (
            set(evidence)
            != set(
                (
                    implementation.context.data_artifact_sha256,
                    implementation.context.evaluator_artifact_sha256,
                )
            )
            or any(not self.registry.verify(digest) for digest in evidence)
            or not self._fixture_inputs_validate(implementation.context)
        ):
            raise AutonomousImplementationError("implementation evidence graph is invalid")
        try:
            provider_attempt_payload = safe_json_loads(
                self.registry.get_bytes(
                    implementation.provider_attempt_artifact.sha256
                ),
                max_bytes=MAX_PROPOSAL_BYTES,
            )
        except (ArtifactError, ValidationError) as exc:
            raise AutonomousImplementationError(
                "provider proposal attempt is malformed"
            ) from exc
        try:
            persisted_output = (
                provider_attempt_payload.get("output")
                if isinstance(provider_attempt_payload, Mapping)
                else None
            )
            if not isinstance(persisted_output, Mapping):
                raise AutonomousImplementationError(
                    "persisted provider proposal output is not an object"
                )
            persisted_proposal = ImplementationProposal.from_mapping(
                persisted_output,
                self.catalog,
            )
        except (
            AutonomousImplementationError,
            ModelResponseError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AutonomousImplementationError(
                "persisted provider proposal output is invalid"
            ) from exc

        evidence_set = set(evidence)
        if (
            not isinstance(provider_attempt_payload, Mapping)
            or set(provider_attempt_payload)
            != {
                "schema_version",
                "invocation_id",
                "provider_id",
                "model_requested",
                "capability",
                "result_status",
                "output",
                "declared_input_artifact_hashes",
                "trust_class",
                "scientific_evidence",
                "provider_tools",
            }
            or provider_attempt_payload.get("schema_version")
            != "AUTONOMOUS_IMPLEMENTATION_PROVIDER_ATTEMPT_V1"
            or not isinstance(provider_attempt_payload.get("invocation_id"), str)
            or not isinstance(provider_attempt_payload.get("provider_id"), str)
            or not isinstance(provider_attempt_payload.get("model_requested"), str)
            or provider_attempt_payload.get("capability")
            != ModelCapability.CODING.value
            or provider_attempt_payload.get("result_status")
            != ModelRunStatus.COMPLETED.value
            or not isinstance(
                provider_attempt_payload.get("declared_input_artifact_hashes"),
                list,
            )
            or set(provider_attempt_payload["declared_input_artifact_hashes"])
            != evidence_set
            or provider_attempt_payload.get("trust_class")
            != "UNTRUSTED_ADVISORY"
            or provider_attempt_payload.get("scientific_evidence") is not False
            or provider_attempt_payload.get("provider_tools") is not False
        ):
            raise AutonomousImplementationError(
                "provider proposal attempt binding is inconsistent"
            )
        normalized_proposal, semantic_id = self._normalize_actionable_proposal(
            persisted_proposal,
            implementation.context,
        )
        if normalized_proposal != implementation.proposal:
            raise AutonomousImplementationError(
                "provider proposal does not normalize to the admitted action"
            )
        provider_parents = tuple(
            self.registry.get_metadata(digest)
            for digest in implementation.provider_attempt_artifact.parent_artifacts
            if digest not in evidence_set
        )
        capture = self._provider_capture(provider_parents)
        if capture is None:
            raise AutonomousImplementationError(
                "proposal omits the complete captured provider provenance graph"
            )
        if set(implementation.provider_attempt_artifact.parent_artifacts) != {
            *evidence,
            *(record.sha256 for record in capture.records),
        }:
            raise AutonomousImplementationError(
                "proposal contains non-authoritative provider parents"
            )
        provider_projection = self._provider_capture_projection(
            capture,
            proposal_payload=provider_attempt_payload,
        )
        if not isinstance(provider_projection, ProviderExecutionProjection):
            raise AutonomousImplementationError(
                "captured provider provenance graph is corrupt or inconsistent"
            )

        try:
            actionable_payload = safe_json_loads(
                self.registry.get_bytes(implementation.proposal_artifact.sha256),
                max_bytes=MAX_PROPOSAL_BYTES,
            )
        except (ArtifactError, ValidationError) as exc:
            raise AutonomousImplementationError(
                "actionable proposal artifact is malformed"
            ) from exc
        expected_actionable_payload = self._actionable_proposal_payload(
            implementation.proposal,
            implementation.context,
            semantic_id=semantic_id,
            catalog_artifact_sha256=self.catalog.artifact.sha256,
        )
        expected_actionable_parents = _unique_digests(
            (self.catalog.artifact.sha256,),
            tuple(sorted(evidence)),
        )
        if (
            actionable_payload != expected_actionable_payload
            or implementation.proposal_artifact.parent_artifacts
            != expected_actionable_parents
        ):
            raise AutonomousImplementationError(
                "provider-neutral actionable proposal is inconsistent"
            )
        expected_config = canonical_json_bytes(
            self._configuration(
                implementation.proposal,
                implementation.context,
                implementation.proposal_artifact.sha256,
            )
        ) + b"\n"
        expected_configuration_parents = _unique_digests(
            (
                implementation.proposal_artifact.sha256,
                self.catalog.artifact.sha256,
            ),
            evidence,
        )
        if (
            self.registry.get_bytes(implementation.configuration_artifact.sha256)
            != expected_config
            or implementation.configuration_artifact.parent_artifacts
            != expected_configuration_parents
        ):
            raise AutonomousImplementationError("worker configuration changed after admission")
        receipt = safe_json_loads(
            self.registry.get_bytes(implementation.validation_receipt.sha256)
        )
        expected_receipt = self._action_validation_payload(
            actionable_proposal_sha256=implementation.proposal_artifact.sha256,
            proposal=implementation.proposal,
            semantic_id=semantic_id,
            declared_evidence=evidence,
            code_artifact_sha256=implementation.worker_code_artifact.sha256,
            configuration_artifact_sha256=(
                implementation.configuration_artifact.sha256
            ),
        )
        expected_receipt_parents = _unique_digests(
            (
                implementation.proposal_artifact.sha256,
                self.catalog.artifact.sha256,
                implementation.worker_code_artifact.sha256,
                implementation.configuration_artifact.sha256,
            ),
            evidence,
        )
        if (
            receipt != expected_receipt
            or implementation.validation_receipt.parent_artifacts
            != expected_receipt_parents
        ):
            raise AutonomousImplementationError("admission receipt is inconsistent")

        provider_link = safe_json_loads(
            self.registry.get_bytes(implementation.provider_admission_link.sha256)
        )
        expected_provider_link = self._provider_admission_link_payload(
            provider_attempt_sha256=implementation.provider_attempt_artifact.sha256,
            actionable_proposal_sha256=implementation.proposal_artifact.sha256,
            action_validation_receipt_sha256=implementation.validation_receipt.sha256,
            projection=provider_projection,
            semantic_id=semantic_id,
        )
        expected_provider_link_parents = _unique_digests(
            (
                implementation.provider_attempt_artifact.sha256,
                implementation.proposal_artifact.sha256,
                implementation.validation_receipt.sha256,
            ),
            provider_projection.custody_artifact_hashes,
        )
        if (
            provider_link != expected_provider_link
            or implementation.provider_admission_link.parent_artifacts
            != expected_provider_link_parents
        ):
            raise AutonomousImplementationError(
                "provider admission link is inconsistent"
            )
        descriptor = safe_json_loads(self.registry.get_bytes(implementation.descriptor_artifact.sha256))
        expected_descriptor = {
            "schema_version": DESCRIPTOR_SCHEMA_VERSION,
            "implementation_id": implementation.proposal.implementation_id,
            "experiment_id": implementation.context.experiment_id,
            "hypothesis_id": implementation.context.hypothesis_id,
            "phase": implementation.context.phase.value,
            "proposal_id": implementation.proposal.proposal_id,
            "template_id": implementation.proposal.template_id.value,
            "template_version": template.template_version,
            "catalog_artifact_sha256": self.catalog.artifact.sha256,
            "proposal_artifact_sha256": implementation.proposal_artifact.sha256,
            "worker_code_sha256": implementation.worker_code_artifact.sha256,
            "configuration_sha256": implementation.configuration_artifact.sha256,
            "parent_evidence_sha256s": list(evidence),
            "validation_receipt_sha256": implementation.validation_receipt.sha256,
            "execution_boundary": "FROZEN_RUN_SPEC_LOCAL_MAC_ONLY",
            "shell_allowed": False,
            "network_allowed": False,
            "provider_provenance_custody": "SEPARATE_ADVISORY_LINK_REQUIRED",
            "provider_identity_included": False,
            "scientific_evidence": False,
        }
        expected_descriptor_parents = _unique_digests(
            (
                implementation.proposal_artifact.sha256,
                implementation.worker_code_artifact.sha256,
                implementation.configuration_artifact.sha256,
                implementation.validation_receipt.sha256,
                self.catalog.artifact.sha256,
            ),
            evidence,
        )
        if (
            descriptor != expected_descriptor
            or implementation.descriptor_artifact.parent_artifacts
            != expected_descriptor_parents
        ):
            raise AutonomousImplementationError("implementation descriptor is inconsistent")

    @staticmethod
    def _worker_relative_path(implementation: AdmittedImplementation) -> Path:
        return Path(
            ".scientist-one-build",
            "autonomous-implementation",
            f"{implementation.worker_code_artifact.sha256}.py",
        )

    def _expected_run_spec(
        self,
        implementation: AdmittedImplementation,
        *,
        run_id: str,
        worker_relative: str,
    ) -> FrozenRunSpec:
        data_record = self.registry.get_metadata(
            implementation.context.data_artifact_sha256
        )
        evaluator_record = self.registry.get_metadata(
            implementation.context.evaluator_artifact_sha256
        )
        return FrozenRunSpec(
            run_id=run_id,
            experiment_id=implementation.context.experiment_id,
            hypothesis_id=implementation.context.hypothesis_id,
            phase=implementation.context.phase,
            argv=(
                PYTHON_EXECUTABLE,
                "-I",
                "-S",
                "-B",
                worker_relative,
                "--config",
                implementation.configuration_artifact.path,
                "--data",
                data_record.path,
            ),
            working_directory=".",
            code_sha256=implementation.worker_code_artifact.sha256,
            data_sha256=data_record.sha256,
            configuration_sha256=implementation.configuration_artifact.sha256,
            evaluator_sha256=evaluator_record.sha256,
            seeds=implementation.context.seeds,
            comparison_tolerance=0.0,
            timeout_seconds=30.0,
            maximum_stdout_bytes=64 * 1024,
            maximum_stderr_bytes=64 * 1024,
            network_allowed=False,
            shell_allowed=False,
            evidence_class=EvidenceClass.NON_EVIDENTIARY,
            scientific_purpose=(
                "exercise an admitted reviewed autonomous implementation as a "
                "non-evidentiary exploratory component fixture"
            ),
            expected_outputs=("output_manifest", "seed_result"),
            seed_policy="EXPLICIT_FIXED_SEEDS_NO_SELECTION",
            termination_conditions=("wall_clock_timeout", "all_planned_seeds_reported"),
            metadata={
                "autonomous_implementation_descriptor_sha256": (
                    implementation.descriptor_artifact.sha256
                ),
                "autonomous_implementation_validation_sha256": (
                    implementation.validation_receipt.sha256
                ),
                "catalog_artifact_sha256": self.catalog.artifact.sha256,
                "model_output_trust": "UNTRUSTED_ADVISORY",
                "model_output_scientific_evidence": False,
            },
        )

    def prepare_local_run(
        self,
        implementation: AdmittedImplementation,
        *,
        run_id: str,
    ) -> PreparedImplementationRun:
        """Freeze and persist the sole supported execution specification."""

        self._validate_admitted(implementation)
        validate_identifier(run_id, "autonomous implementation run ID")
        code = self.registry.get_bytes(implementation.worker_code_artifact.sha256)
        worker_relative = self._worker_relative_path(implementation)
        worker_path = atomic_write_bytes(
            self.registry.policy.root,
            worker_relative,
            code,
            immutable=True,
            create_parents=True,
            mode=0o600,
        )
        materialized = read_confined_bytes(
            self.registry.policy.root,
            worker_path,
            reject_hardlinks=True,
            max_bytes=len(code),
        )
        if materialized != code:
            raise AutonomousImplementationError("materialized worker differs from reviewed code")
        relative_worker = worker_path.relative_to(self.registry.policy.root).as_posix()
        spec = self._expected_run_spec(
            implementation,
            run_id=run_id,
            worker_relative=relative_worker,
        )
        spec_artifact = self.registry.put_json(
            spec.to_dict(),
            logical_type="autonomous_implementation.frozen_run_spec",
            origin="frozen admitted autonomous implementation run",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "freeze-autonomous-implementation-run"),
            parent_artifacts=(
                implementation.descriptor_artifact.sha256,
                implementation.validation_receipt.sha256,
                implementation.worker_code_artifact.sha256,
                implementation.configuration_artifact.sha256,
                implementation.context.data_artifact_sha256,
                implementation.context.evaluator_artifact_sha256,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        return PreparedImplementationRun(
            implementation=implementation,
            spec=spec,
            spec_artifact=spec_artifact,
            materialized_worker_path=relative_worker,
        )

    def execute_prepared_local_run(
        self,
        prepared: PreparedImplementationRun,
        backend: LocalMacBackend,
        *,
        idempotency_key: str,
    ) -> ExecutedImplementationRun:
        """Execute only a revalidated admitted worker through LocalMacBackend."""

        if not isinstance(prepared, PreparedImplementationRun):
            raise AutonomousImplementationError("only prepared admitted runs may execute")
        if type(backend) is not LocalMacBackend:
            raise AutonomousImplementationError("admitted workers require LocalMacBackend")
        if getattr(backend, "_root", None) != self.registry.policy.root:
            raise AutonomousImplementationError("backend and artifact registry roots differ")
        runner = getattr(backend, "_execution_runner", None)
        submit = getattr(backend, "submit", None)
        reconcile = getattr(backend, "reconcile", None)
        collect = getattr(backend, "collect", None)
        callable_shadow_names = {
            name
            for name, value in vars(backend).items()
            if callable(value) and name != "_execution_runner"
        }
        class_policy_changed = any(
            vars(LocalMacBackend).get(name) is not original
            for name, original in _BUILTIN_LOCAL_CALLABLES.items()
        )
        if (
            tuple(getattr(backend, "_allowed_executables", ()))
            != (PYTHON_EXECUTABLE,)
            or callable_shadow_names
            or class_policy_changed
            or getattr(runner, "__self__", None) is not backend
            or getattr(runner, "__func__", None) is not _BUILTIN_LOCAL_RUNNER
            or getattr(submit, "__self__", None) is not backend
            or getattr(submit, "__func__", None) is not _BUILTIN_LOCAL_SUBMIT
            or getattr(reconcile, "__self__", None) is not backend
            or getattr(reconcile, "__func__", None) is not _BUILTIN_LOCAL_RECONCILE
            or getattr(collect, "__self__", None) is not backend
            or getattr(collect, "__func__", None) is not _BUILTIN_LOCAL_COLLECT
        ):
            raise AutonomousImplementationError(
                "autonomous execution requires the exact built-in local runner policy"
            )
        self._validate_admitted(prepared.implementation)
        expected_relative = self._worker_relative_path(
            prepared.implementation
        ).as_posix()
        expected_spec = self._expected_run_spec(
            prepared.implementation,
            run_id=prepared.spec.run_id,
            worker_relative=expected_relative,
        )
        expected_spec_parents = {
            prepared.implementation.descriptor_artifact.sha256,
            prepared.implementation.validation_receipt.sha256,
            prepared.implementation.worker_code_artifact.sha256,
            prepared.implementation.configuration_artifact.sha256,
            prepared.implementation.context.data_artifact_sha256,
            prepared.implementation.context.evaluator_artifact_sha256,
        }
        if (
            prepared.materialized_worker_path != expected_relative
            or prepared.spec.to_dict() != expected_spec.to_dict()
            or not self.registry.verify(prepared.spec_artifact.sha256)
            or self.registry.get_metadata(prepared.spec_artifact.sha256)
            != prepared.spec_artifact
            or prepared.spec_artifact.logical_type
            != "autonomous_implementation.frozen_run_spec"
            or prepared.spec_artifact.creator_role is not Role.EXPERIMENT_RUNNER
            or prepared.spec_artifact.validation_result != "PASS"
            or not prepared.spec_artifact.frozen
            or set(prepared.spec_artifact.parent_artifacts)
            != expected_spec_parents
        ):
            raise AutonomousImplementationError("frozen run spec artifact is corrupt")
        expected_spec_bytes = canonical_json_bytes(prepared.spec.to_dict()) + b"\n"
        if self.registry.get_bytes(prepared.spec_artifact.sha256) != expected_spec_bytes:
            raise AutonomousImplementationError("frozen run spec artifact changed")
        code = read_confined_bytes(
            self.registry.policy.root,
            prepared.materialized_worker_path,
            reject_hardlinks=True,
            max_bytes=MAX_PROPOSAL_BYTES,
        )
        if code is None or sha256_bytes(code) != prepared.spec.code_sha256:
            raise AutonomousImplementationError("materialized worker is absent or changed")
        data_record = self.registry.get_metadata(
            prepared.implementation.context.data_artifact_sha256
        )
        evaluator_record = self.registry.get_metadata(
            prepared.implementation.context.evaluator_artifact_sha256
        )
        submission = backend.submit(
            prepared.spec,
            idempotency_key=idempotency_key,
            input_artifact_paths={
                "code": prepared.materialized_worker_path,
                "configuration": (
                    prepared.implementation.configuration_artifact.path
                ),
                "data": data_record.path,
                "evaluator": evaluator_record.path,
            },
        )
        collected = (
            backend.collect(submission.job_id)
            if submission.state is RunState.SUCCEEDED
            else None
        )
        payload = {
            "schema_version": RUN_RECEIPT_SCHEMA_VERSION,
            "implementation_descriptor_sha256": (
                prepared.implementation.descriptor_artifact.sha256
            ),
            "frozen_run_spec_sha256": prepared.spec.sha256,
            "frozen_run_spec_artifact_sha256": prepared.spec_artifact.sha256,
            "backend_id": submission.backend_id,
            "job_id": submission.job_id,
            "state": submission.state.value,
            "validation_status": submission.validation_status.value,
            "network_used": submission.network_used,
            "network_use_status": submission.network_use_status.value,
            "network_isolation_attested": submission.network_isolation_attested,
            "scientific_evidence": False,
            "manifest_sha256": collected.manifest_sha256 if collected else None,
            "execution_plan_sha256": submission.execution_plan_sha256,
            "execution_input_binding_sha256": (
                submission.execution_input_binding_sha256
            ),
        }
        receipt = self.registry.put_json(
            payload,
            logical_type="autonomous_implementation.execution_receipt",
            origin="LocalMacBackend execution of admitted reviewed worker",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "execute-admitted-local-worker"),
            parent_artifacts=(
                prepared.spec_artifact.sha256,
                prepared.implementation.descriptor_artifact.sha256,
                prepared.implementation.validation_receipt.sha256,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        return ExecutedImplementationRun(prepared, submission, collected, receipt)


__all__ = [
    "AdmissionStatus",
    "AdmittedImplementation",
    "AutonomousImplementationController",
    "AutonomousImplementationError",
    "ExecutedImplementationRun",
    "ImplementationAdmission",
    "ImplementationContext",
    "ImplementationProposal",
    "PreparedImplementationRun",
    "ReviewedImplementationCatalog",
    "ReviewedTemplate",
    "ReviewedWorkerTemplate",
    "create_reviewed_catalog",
    "implementation_proposal_schema",
    "template_review_payload",
]
