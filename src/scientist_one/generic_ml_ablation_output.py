"""Pure compact executed-output byte relation for a declared intervention.

This codec does not attest execution, prospective selection, Dataset custody,
model/source identity, scientific adequacy or R5/E2 authority. The supplied
grid is revalidated for native shape and arithmetic consistency, not replayed
against scientific owners. An external owner must freshly derive that grid
from the complete verified sources and authenticate every supplied identity.

Only ablated predictions and their complete ordered seed/unit/source bindings
are serialized. Labels, model weights, candidate/baseline predictions, counts,
effects and decisions stay out of this compact output. In particular, never
serialize grid.to_dict(): its three prediction grids exceed the existing JSON
item budget at the supported maximum. There is no issuer, I/O or future-output
reference. Same-execution model record hashes are deliberately absent: their
metadata parents include the future output manifest, which names these bytes.
Embedding those record hashes would create an unissuable hash fixed point.
The full downstream owner joins model records via execution/projection/activity.
Byte verification rebuilds the exact canonical newline-terminated
output; it does not parse or interpret the observed, potentially hostile JSON.
"""

from __future__ import annotations

from .errors import ValidationError
from .generic_ml_ablation import (
    GENERIC_ML_FEATURE_INTERVENTION_SCOPE,
    GenericMLAblationError,
    GenericMLAblationGrid,
    GenericMLFeatureIntervention,
)
from .generic_ml_projection import MAX_GENERIC_ML_INTEGER_MAGNITUDE
from .models import validate_identifier, validate_sha256
from .security import DEFAULT_MAX_JSON_BYTES, canonical_json_bytes


GENERIC_ML_ABLATION_OUTPUT_SCHEMA = "generic-ml-ablation-output/v1"
# Includes the trailing LF, rather than allowing an extra byte past the
# existing JSON/artifact-read ceiling. The item/depth limits remain those of
# canonical_json_bytes; this module neither raises nor bypasses them.
MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES = DEFAULT_MAX_JSON_BYTES


class GenericMLAblationOutputError(GenericMLAblationError):
    """The compact output's supplied native shape or exact bytes differ."""


def _native_text(value: object, name: str, *, identifier: bool = False) -> str:
    if type(value) is not str:
        raise GenericMLAblationOutputError(f"{name} requires exact native text")
    try:
        return (validate_identifier if identifier else validate_sha256)(value, name)
    except ValidationError as exc:
        raise GenericMLAblationOutputError(str(exc)) from exc


def build_generic_ml_ablation_output(
    grid: GenericMLAblationGrid,
    *,
    execution_run_id: str,
    frozen_run_spec_artifact_sha256: str,
    frozen_run_spec_record_hash: str,
    frozen_run_spec_sha256: str,
    configuration_artifact_sha256: str,
    configuration_record_hash: str,
    evaluator_artifact_sha256: str,
    evaluator_record_hash: str,
    confirmatory_split_authority_artifact_sha256: str,
    confirmatory_split_authority_record_hash: str,
    method_definition_artifact_sha256: str,
    method_definition_record_hash: str,
    seed_model_bindings: tuple[tuple[int, str, str], ...],
) -> bytes:
    """Build bounded canonical bytes only; no supplied binding is authority.

    Each binding is (seed, candidate model artifact SHA, baseline model
    artifact SHA), all available before the manifest. It must match
    the entire grid's exact seed order. No caller metadata or policy mapping
    is accepted or silently folded into this closed output.
    """

    if type(grid) is not GenericMLAblationGrid:
        raise GenericMLAblationOutputError("grid requires the exact native GenericMLAblationGrid type")
    try:
        # Direct native constructor replay validates all leaves, including
        # fields deliberately absent from the compact wire. It does not call
        # a caller-selected method or the expansive grid serialization view.
        GenericMLAblationGrid.__post_init__(grid)
    except GenericMLAblationError as exc:
        raise GenericMLAblationOutputError(f"supplied grid is invalid: {exc}") from exc
    context = {
        "execution_run_id": execution_run_id,
        "frozen_run_spec_artifact_sha256": frozen_run_spec_artifact_sha256,
        "frozen_run_spec_record_hash": frozen_run_spec_record_hash,
        "frozen_run_spec_sha256": frozen_run_spec_sha256,
        "configuration_artifact_sha256": configuration_artifact_sha256,
        "configuration_record_hash": configuration_record_hash,
        "evaluator_artifact_sha256": evaluator_artifact_sha256,
        "evaluator_record_hash": evaluator_record_hash,
        "confirmatory_split_authority_artifact_sha256": confirmatory_split_authority_artifact_sha256,
        "confirmatory_split_authority_record_hash": confirmatory_split_authority_record_hash,
        "method_definition_artifact_sha256": method_definition_artifact_sha256,
        "method_definition_record_hash": method_definition_record_hash,
    }
    for name, value in context.items():
        _native_text(value, name, identifier=name == "execution_run_id")
    if type(seed_model_bindings) is not tuple or len(seed_model_bindings) != len(grid.seed_results):
        raise GenericMLAblationOutputError("seed_model_bindings must be the exact complete native seed tuple")
    model_fields = (
        "candidate_model_artifact_sha256", "baseline_model_artifact_sha256",
    )
    for binding in seed_model_bindings:
        if type(binding) is not tuple or len(binding) != 3:
            raise GenericMLAblationOutputError("each seed model binding requires an exact native three-tuple")
        seed = binding[0]
        if type(seed) is not int or not 0 <= seed <= MAX_GENERIC_ML_INTEGER_MAGNITUDE:
            raise GenericMLAblationOutputError("bound seed requires a bounded exact native integer")
        for name, value in zip(model_fields, binding[1:], strict=True):
            _native_text(value, name)
    if tuple(binding[0] for binding in seed_model_bindings) != grid.seed_order:
        raise GenericMLAblationOutputError("seed model bindings differ from the exact complete grid order")
    wire = {
        "schema_version": GENERIC_ML_ABLATION_OUTPUT_SCHEMA,
        "scope": GENERIC_ML_FEATURE_INTERVENTION_SCOPE,
        **context,
        "intervention": GenericMLFeatureIntervention.to_dict(grid.intervention),
        "unit_ids": list(grid.unit_ids),
        "unit_hashes": list(grid.unit_hashes),
        "seed_outputs": [
            {
                "seed": binding[0],
                **dict(zip(model_fields, binding[1:], strict=True)),
                "ablated_predictions": list(seed.ablated_predictions),
            }
            for seed, binding in zip(grid.seed_results, seed_model_bindings, strict=True)
        ],
    }
    encoded = canonical_json_bytes(wire)
    if len(encoded) + 1 > MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES:
        raise GenericMLAblationOutputError("compact output plus newline exceeds the existing byte capacity")
    return encoded + b"\n"


def require_generic_ml_ablation_output(
    raw: bytes,
    grid: GenericMLAblationGrid,
    *,
    execution_run_id: str,
    frozen_run_spec_artifact_sha256: str,
    frozen_run_spec_record_hash: str,
    frozen_run_spec_sha256: str,
    configuration_artifact_sha256: str,
    configuration_record_hash: str,
    evaluator_artifact_sha256: str,
    evaluator_record_hash: str,
    confirmatory_split_authority_artifact_sha256: str,
    confirmatory_split_authority_record_hash: str,
    method_definition_artifact_sha256: str,
    method_definition_record_hash: str,
    seed_model_bindings: tuple[tuple[int, str, str], ...],
) -> None:
    """Require the exact compact bytes, without parsing untrusted observed JSON."""

    # This guard is deliberately before ANY grid replay or output rebuilding.
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES:
        raise GenericMLAblationOutputError("raw output requires native bytes within the newline-inclusive capacity")
    expected = build_generic_ml_ablation_output(
        grid,
        execution_run_id=execution_run_id,
        frozen_run_spec_artifact_sha256=frozen_run_spec_artifact_sha256,
        frozen_run_spec_record_hash=frozen_run_spec_record_hash,
        frozen_run_spec_sha256=frozen_run_spec_sha256,
        configuration_artifact_sha256=configuration_artifact_sha256,
        configuration_record_hash=configuration_record_hash,
        evaluator_artifact_sha256=evaluator_artifact_sha256,
        evaluator_record_hash=evaluator_record_hash,
        confirmatory_split_authority_artifact_sha256=confirmatory_split_authority_artifact_sha256,
        confirmatory_split_authority_record_hash=confirmatory_split_authority_record_hash,
        method_definition_artifact_sha256=method_definition_artifact_sha256,
        method_definition_record_hash=method_definition_record_hash,
        seed_model_bindings=seed_model_bindings,
    )
    if raw != expected:
        raise GenericMLAblationOutputError("observed output differs from the exact rebuilt compact bytes")
