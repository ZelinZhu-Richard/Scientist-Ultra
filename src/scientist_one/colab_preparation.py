"""Offline Colab input preparation and returned-byte inspection.

No Colab CLI, filesystem, network, admission, spending or collection operation
is performed here. These helpers neither implement ScheduledGPUTransport nor
authenticate a caller-supplied commit. Existing controller authority, CU budget
integration and provider lifecycle support remain prerequisites for live use.
The deliberately narrow first profile is non-evidentiary exploratory work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re

from .experiments import (
    MAX_OUTPUT_ARTIFACT_BYTES,
    MAX_OUTPUT_MANIFEST_BYTES,
    MAX_RETURNED_ARTIFACT_TOTAL_BYTES,
    ComputeMode,
    EvidenceClass,
    ExperimentError,
    ExperimentIntegrityError,
    ExperimentPhase,
    OutputManifest,
    ScheduledGPUArtifactBundle,
    ScheduledGPURequest,
    SchedulerKind,
    StagedArtifact,
    _validate_manifest_bindings,
)
from .security import canonical_json_bytes, safe_json_loads


_INPUT_NAMES = ("worker.py", "configuration.bin", "data.bin")
_PREPARATION_SCHEMA = "SCIENTIST_ONE_COLAB_OFFLINE_INPUTS_V1"


def _require_preparation_profile(request: ScheduledGPURequest) -> None:
    if type(request) is not ScheduledGPURequest:
        raise ExperimentError("Colab preparation requires an existing typed GPU request")
    spec, plan = request.spec, request.submission_plan
    if (
        spec.compute_profile.mode is not ComputeMode.GPU_CLOUD
        or spec.compute_profile.scheduler is not SchedulerKind.DIRECT_REMOTE
        or plan.scheduler is not SchedulerKind.DIRECT_REMOTE
        or spec.compute_profile.accelerator_count != 1
        or plan.accelerator_count != 1
        or spec.compute_profile.queue_name is not None
        or plan.queue_name is not None
        or spec.phase is not ExperimentPhase.EXPLORATORY
        or spec.evidence_class is not EvidenceClass.NON_EVIDENTIARY
        or spec.attempt != 1
        or spec.retry_of_run_id is not None
    ):
        raise ExperimentError("Colab offline profile requires first exploratory non-evidentiary direct single-GPU work")
    if (
        plan.spec_sha256 != spec.sha256
        or plan.project_definition_sha256 != spec.project_definition_sha256
        or plan.compute_profile_sha256 != spec.compute_profile.sha256
        or plan.checkpoint_policy is not spec.checkpoint_policy
    ):
        raise ExperimentIntegrityError("Colab preparation plan differs from its frozen specification")


@dataclass(frozen=True)
class ColabInputPreparation:
    """Bound bytes, not a second plan, approval receipt or upload allowlist.

    The three fixed labels describe byte roles, not a runnable remote layout.
    A future authorized transport must resolve paths without rewriting the
    frozen argv. Caller responsibility for disclosure is not verified here.
    """

    request: ScheduledGPURequest
    source_commit: str
    worker_bytes: bytes = field(repr=False)
    configuration_bytes: bytes = field(repr=False)
    data_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_preparation_profile(self.request)
        if type(self.source_commit) is not str or re.fullmatch(
            r"[0-9a-f]{40}", self.source_commit
        ) is None:
            raise ExperimentError("source commit must be a complete lowercase Git SHA-1 identity")
        spec = self.request.spec
        for name, payload, digest in zip(
            _INPUT_NAMES,
            (self.worker_bytes, self.configuration_bytes, self.data_bytes),
            (spec.code_sha256, spec.configuration_sha256, spec.data_sha256),
        ):
            if type(payload) is not bytes or not 0 < len(payload) <= MAX_OUTPUT_ARTIFACT_BYTES:
                raise ExperimentError("Colab input must be nonempty bounded immutable bytes")
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ExperimentIntegrityError(f"Colab {name} differs from frozen input")

    def to_dict(self) -> dict:
        # No research payloads, local paths, CLI credentials or provider logs.
        return {
            "schema_version": _PREPARATION_SCHEMA,
            "classification": "OFFLINE_PREPARATION_NOT_EXECUTION_AUTHORITY",
            "source_commit": self.source_commit,
            "source_commit_verification": "CALLER_SUPPLIED_NOT_VERIFIED",
            "spec_sha256": self.request.spec.sha256,
            "submission_plan_sha256": self.request.submission_plan.sha256,
            "request_sha256": hashlib.sha256(
                canonical_json_bytes(self.request.to_dict())
            ).hexdigest(),
            "inputs": [
                {"role": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
                for name, payload in zip(
                    _INPUT_NAMES,
                    (self.worker_bytes, self.configuration_bytes, self.data_bytes),
                )
            ],
            "external_validation": "UNTESTED",
            "scientific_evidence": False,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()


def inspect_colab_output(
    request: ScheduledGPURequest,
    *,
    manifest_bytes: bytes,
    payloads: dict[str, bytes],
    provider_job_id: str,
) -> ScheduledGPUArtifactBundle:
    """Inspect already supplied bytes; never download or collect into a registry.

    This is the original worker OutputManifest contract, not a claim about a
    Colab CLI response schema. A caller-supplied job ID is not authenticated.
    The original backend must still verify durable submission/attempt identity
    and scientific authority before any returned artifact can be collected.
    """

    _require_preparation_profile(request)
    if type(manifest_bytes) is not bytes or len(manifest_bytes) > MAX_OUTPUT_MANIFEST_BYTES:
        raise ExperimentError("Colab manifest must be bounded immutable bytes")
    manifest = OutputManifest.from_mapping(
        safe_json_loads(manifest_bytes, max_bytes=MAX_OUTPUT_MANIFEST_BYTES)
    )
    _validate_manifest_bindings(request.spec, manifest)
    paths = tuple(item.path for item in manifest.artifacts)
    if type(payloads) is not dict or len(paths) != len(set(paths)) or set(payloads) != set(paths):
        raise ExperimentIntegrityError("Colab return must contain exactly the distinct manifest paths")
    if any(type(value) is not bytes for value in payloads.values()):
        raise ExperimentError("Colab returned payloads must be immutable bytes")
    if sum(len(value) for value in payloads.values()) > MAX_RETURNED_ARTIFACT_TOTAL_BYTES:
        raise ExperimentError("Colab returned payloads exceed the existing total byte bound")
    artifacts = tuple(
        StagedArtifact(item, payloads[item.path]) for item in manifest.artifacts
    )
    return ScheduledGPUArtifactBundle(
        manifest=manifest,
        artifacts=artifacts,
        manifest_bytes=manifest_bytes,
        provider_job_id=provider_job_id,
        spec_sha256=request.spec.sha256,
        submission_plan_sha256=request.submission_plan.sha256,
        attempt=request.spec.attempt,
        resumed_checkpoint_sha256=None,
        requeue_history=(),
    )
