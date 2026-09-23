"""Native descriptive projection into the existing canonical Ablation type.

Empty removed_component_ids is intentional: the observed feature-weight
intervention does not prove semantic removal of the named Method component.
Only this closed COMPLETE profile can use that shape; admission always replays
the fresh source owner and compares the entire rebuilt canonical object.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from .artifacts import ArtifactRecord
from .generic_ml_ablation import (
    GENERIC_ML_FEATURE_INTERVENTION_SCOPE,
    GenericMLFeatureIntervention,
)
from .models import Role, thaw_json, validate_identifier, validate_sha256
from .scientific_numeric_ablation import ScientificNumericAblationError


NUMERIC_ABLATION_CANONICAL_SCHEMA = "scientific-numeric-ablation-canonical/v1"


def is_numeric_ablation_metadata(value) -> bool:
    """Discriminator only, never scientific or canonical authority."""

    return isinstance(value, Mapping) and value.get("schema_version") == NUMERIC_ABLATION_CANONICAL_SCHEMA


def require_numeric_ablation_metadata_shape(metadata) -> dict:
    """Closed inert view validation after canonical nested-size validation.

    The ordinary canonical constructor owns nested bytes/items/depth bounds.
    This helper preflights the closed outer shape before making a mutable view;
    it is not a separate arbitrary-input bounded serialization API.
    """

    keys = {
        "schema_version", "authority_id", "intervention", "metric_id", "unit_count",
        "seed_order", "changed_coefficient_counts", "activity_sequence", "candidate_correct_total",
        "baseline_correct_total", "ablated_correct_total", "scope", "replay_status", "scientific_evidence_eligible",
    }
    if (not isinstance(metadata, Mapping) or len(metadata) != len(keys)
            or any(type(key) is not str for key in metadata) or set(metadata) != keys):
        raise ScientificNumericAblationError("numeric canonical metadata is not closed")
    value = thaw_json(metadata)
    if type(value) is not dict or set(value) != keys or any(type(key) is not str for key in value):
        raise ScientificNumericAblationError("numeric canonical metadata is not closed")
    if (not is_numeric_ablation_metadata(value) or value["scope"] != GENERIC_ML_FEATURE_INTERVENTION_SCOPE
            or value["replay_status"] != "DESCRIPTIVE_OUTPUT_VERIFIED"
            or value["scientific_evidence_eligible"] is not False):
        raise ScientificNumericAblationError("numeric canonical metadata exceeds descriptive scope")
    for key in ("authority_id", "metric_id"):
        if type(value[key]) is not str:
            raise ScientificNumericAblationError("numeric canonical identifiers require native text")
        validate_identifier(value[key], key)
    GenericMLFeatureIntervention.from_dict(value["intervention"])
    seeds, counts = value["seed_order"], value["changed_coefficient_counts"]
    if (type(seeds) is not list or not 1 <= len(seeds) <= 24
            or any(type(seed) is not int or not 0 <= seed <= 2**53 - 1 for seed in seeds)
            or len(set(seeds)) != len(seeds)
            or type(counts) is not list or len(counts) != len(seeds)
            or any(type(count) is not int or not 0 <= count <= 65_536 for count in counts)
            or not any(counts)
            or type(value["unit_count"]) is not int or not 1 <= value["unit_count"] <= 4096
            or type(value["activity_sequence"]) is not int or not 0 <= value["activity_sequence"] < 10_000):
        raise ScientificNumericAblationError("numeric canonical coordinates or counts are invalid")
    for name in ("candidate_correct_total", "baseline_correct_total", "ablated_correct_total"):
        if type(value[name]) is not int or not 0 <= value[name] <= value["unit_count"] * len(seeds):
            raise ScientificNumericAblationError("numeric canonical correctness total is outside the complete grid")
    return value


def _project_canonical(receipt, authority_record: ArtifactRecord, *, result, experiment, code_version: str, created_at: str):
    """Inert exact projection, not a shortcut around fresh authority replay."""

    from .research_state import Ablation, Experiment, ObjectReference, RecordStatus, Result
    from .scientific_numeric_ablation_authority import _time
    from .scientific_numeric_ablation_authority_value import ScientificNumericAblationAuthority

    if (type(receipt) is not ScientificNumericAblationAuthority or type(authority_record) is not ArtifactRecord
            or type(result) is not Result or type(experiment) is not Experiment):
        raise ScientificNumericAblationError("numeric canonical projection requires native values")
    # Reconstruct/detach even nominally frozen leaves before projecting.
    receipt = ScientificNumericAblationAuthority.from_dict(receipt.to_dict())
    if (authority_record.sha256 != hashlib.sha256(receipt.canonical_bytes()).hexdigest()
            or result.object_id != receipt.state_bindings[0].object_id
            or result.content_hash != receipt.state_bindings[0].content_hash
            or experiment.object_id != receipt.state_bindings[3].object_id
            or experiment.content_hash != receipt.state_bindings[3].content_hash
            or type(code_version) is not str or not code_version
            or result.code_version != code_version or experiment.code_version != code_version
            or any(_time(created_at) <= _time(prior) for prior in
                   (authority_record.created_at, result.created_at, experiment.created_at))):
        raise ScientificNumericAblationError("numeric canonical projection changed its source identity or chronology")
    return Ablation(
        object_id=receipt.canonical_object_id, producer=Role.STATISTICIAN, status=RecordStatus.COMPLETE,
        created_at=created_at, code_version=code_version,
        parents=(ObjectReference("Experiment", experiment.object_id, experiment.content_hash, "ablates", True),
                 ObjectReference("Result", result.object_id, result.content_hash, "evaluates", True)),
        authority_artifact_hashes=(authority_record.sha256,),
        hypothesis_id=receipt.intervention.hypothesis_id, experiment_ids=(experiment.object_id,),
        removed_component_ids=(), result_ids=(result.object_id,), metadata=receipt.canonical_metadata(),
    )


def require_numeric_ablation_canonical(repository, record, records, by_content):
    """Repository admission hook: exact native authority then entire object."""

    from .research_state import Ablation, Experiment, Result
    from .scientific_numeric_ablation_authority import require_scientific_numeric_ablation_authority

    if type(record) is not Ablation or not is_numeric_ablation_metadata(record.metadata):
        raise ScientificNumericAblationError("numeric canonical admission requires its exact profile")
    metadata = require_numeric_ablation_metadata_shape(record.metadata)
    if (len(records) != 1 or records[0].logical_type != "scientific_ablation_authority"
            or records[0].schema_version != "2.0"):
        raise ScientificNumericAblationError("numeric canonical admission requires one native source authority")
    result_refs = tuple(parent for parent in record.parents if parent.object_type == "Result")
    experiment_refs = tuple(parent for parent in record.parents if parent.object_type == "Experiment")
    if len(result_refs) != 1 or len(experiment_refs) != 1:
        raise ScientificNumericAblationError("numeric canonical admission lacks exact Result/Experiment parents")
    result_stored = by_content.get(result_refs[0].content_hash)
    experiment_stored = by_content.get(experiment_refs[0].content_hash)
    if result_stored is None or experiment_stored is None:
        raise ScientificNumericAblationError("numeric canonical parents are absent")
    result = result_stored.research_object
    experiment = experiment_stored.research_object
    if type(result) is not Result or type(experiment) is not Experiment or len(result.run_ids) != 1:
        raise ScientificNumericAblationError("numeric canonical parents lack exact Result/Experiment and one Run")
    receipt = require_scientific_numeric_ablation_authority(
        repository.registry, repository.ledger, expected_ledger_run_id=repository.run_id,
        expected_execution_run_id=result.run_ids[0], expected_ablation_id=metadata["intervention"]["ablation_id"],
        authority_artifact_sha256=records[0].sha256,
    )
    for binding in receipt.state_bindings:
        stored = by_content.get(binding.content_hash)
        if (stored is None or stored.artifact.sha256 != binding.artifact_sha256
                or stored.artifact.record_hash != binding.artifact_record_hash
                or stored.research_object.object_type != binding.object_type
                or stored.research_object.object_id != binding.object_id
                or stored.research_object.revision != binding.revision):
            raise ScientificNumericAblationError("numeric canonical state record differs from fresh authority")
    expected = _project_canonical(receipt, records[0], result=result, experiment=experiment,
                                  code_version=repository.code_version, created_at=record.created_at)
    if record != expected or record.canonical_bytes() != expected.canonical_bytes():
        raise ScientificNumericAblationError("numeric canonical Ablation differs from its exact source projection")
    return receipt


def materialize_scientific_numeric_ablation(repository, *, authority_artifact_sha256: str,
                                            created_at: str, reason: str | None = None):
    """Fresh source replay then the existing atomic canonical materializer.

    A caller retries with the same created_at to retain exact canonical bytes;
    registration of the authority alone is not canonical materialization.
    """

    from .research_state import ResearchStateRepository
    from .scientific_design import _load_scientific_ablation_state, _locked_checked_result_authority_snapshot
    from .scientific_numeric_ablation_authority import _read_native_record, _time, require_scientific_numeric_ablation_authority

    if type(repository) is not ResearchStateRepository:
        raise ScientificNumericAblationError("numeric canonical materialization requires the exact repository")
    if type(authority_artifact_sha256) is not str:
        raise ScientificNumericAblationError("numeric canonical authority selector requires native text")
    validate_sha256(authority_artifact_sha256, "numeric canonical authority selector")
    _time(created_at)
    before = _locked_checked_result_authority_snapshot(repository.registry, repository.ledger)
    authority_record = repository.registry.get_metadata(authority_artifact_sha256)
    selectors = _read_native_record(repository.registry, authority_record)
    receipt = require_scientific_numeric_ablation_authority(
        repository.registry, repository.ledger, expected_ledger_run_id=repository.run_id,
        expected_execution_run_id=selectors.execution_run_id, expected_ablation_id=selectors.intervention.ablation_id,
        authority_artifact_sha256=authority_record.sha256,
    )
    _, result = _load_scientific_ablation_state(repository.registry, receipt.state_bindings[0].artifact_sha256,
                                               expected_object_type="Result")
    _, experiment = _load_scientific_ablation_state(repository.registry, receipt.state_bindings[3].artifact_sha256,
                                                   expected_object_type="Experiment")
    candidate = _project_canonical(receipt, authority_record, result=result, experiment=experiment,
                                   code_version=repository.code_version, created_at=created_at)
    if _locked_checked_result_authority_snapshot(repository.registry, repository.ledger) != before:
        raise ScientificNumericAblationError("numeric canonical sources changed before materialization; retry")
    # materialize repeats semantic admission and performs its existing exact
    # registry/ledger CAS, publication event and idempotent recovery checks.
    return repository.materialize(candidate, reason=reason)
