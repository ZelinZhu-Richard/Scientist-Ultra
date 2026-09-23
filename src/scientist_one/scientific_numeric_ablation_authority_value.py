"""Inert closed value for source-replayed descriptive numeric ablation.

Construction and codec roundtrips confer NO source, execution, custody,
prospective, mechanistic, robustness, or scientific authority. The full owner
must derive every identity, count, state binding and complete custody closure
afresh. DESCRIPTIVE_OUTPUT_VERIFIED names that owner's intended replay result;
it is not evidence merely because a caller constructed this value. Scientific
eligibility is deliberately and strictly False, including for positive effects.

The slot binds one Result/execution/contract/ablation obligation independently
of its values, timestamps or record hashes. It cannot create a second slot by
changing an outcome. Effects are signed exact descriptive count differences
over N*S, without statistical or positive-effect gates. No issuer, registry
write, ledger write, owner cache or separate metadata parser exists here.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace

from .artifacts import MAX_REGISTRY_RECORDS
from .errors import ValidationError
from .experiments import MAX_OUTPUT_ARTIFACTS
from .generic_ml_ablation import (
    GENERIC_ML_FEATURE_INTERVENTION_SCOPE,
    MAX_GENERIC_ML_ABLATION_UNITS,
    GenericMLFeatureIntervention,
)
from .generic_ml_projection import (
    MAX_GENERIC_ML_FROZEN_MODEL_PARAMETERS,
    MAX_GENERIC_ML_INTEGER_MAGNITUDE,
    MAX_GENERIC_ML_SEEDS,
)
from .ledger import MAX_LEDGER_EVENTS
from .models import validate_identifier, validate_sha256
from .scientific_design import (
    MAX_CHECKED_SUPERIORITY_BYTES,
    MAX_ITEMS,
    MAX_SOURCES,
    ScientificAblationStateBinding,
)
from .scientific_numeric_ablation import ScientificNumericAblationError
from .security import canonical_json_bytes, safe_json_loads, sha256_bytes


SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_SCHEMA = "scientific-ablation-authority/v2"
SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_LOGICAL_TYPE = "scientific_ablation_authority"
SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_ARTIFACT_SCHEMA_VERSION = "2.0"
SCIENTIFIC_NUMERIC_ABLATION_CANONICAL_SCHEMA = "scientific-numeric-ablation-canonical/v1"
SCIENTIFIC_NUMERIC_ABLATION_REPLAY_STATUS = "DESCRIPTIVE_OUTPUT_VERIFIED"

MAX_SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_BYTES = MAX_CHECKED_SUPERIORITY_BYTES
MAX_SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_JSON_ITEMS = 50_000
MAX_SCIENTIFIC_NUMERIC_ABLATION_CUSTODY_RECORDS = min(
    MAX_REGISTRY_RECORDS, MAX_SOURCES * 32 + MAX_ITEMS,
)
_STATE_TYPES = ("Result", "Run", "Method", "Experiment")
_STATE_FIELDS = tuple(item.name for item in fields(ScientificAblationStateBinding))
_SOURCE_PAIRS = (
    ("contract_artifact_sha256", "contract_record_hash"),
    ("promotion_artifact_sha256", "promotion_record_hash"),
    ("assessment_artifact_sha256", "assessment_record_hash"),
    ("execution_artifact_sha256", "execution_record_hash"),
    ("projection_artifact_sha256", "projection_record_hash"),
    ("ablation_output_artifact_sha256", "ablation_output_record_hash"),
)
_VECTOR_FIELDS = (
    "seed_order", "changed_coefficient_counts", "source_artifact_hashes",
    "source_artifact_record_hashes", "custody_artifact_hashes", "custody_artifact_record_hashes",
)


class ScientificNumericAblationValueError(ScientificNumericAblationError):
    """The inert value's native shape or exact internal relations differ."""


def _integer(value: object, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ScientificNumericAblationValueError(f"{name} requires an exact integer in {low}..{high}")
    return value


def _text(value: object, name: str, *, digest: bool = False) -> str:
    if type(value) is not str:
        raise ScientificNumericAblationValueError(f"{name} requires exact native text")
    try:
        return (validate_sha256 if digest else validate_identifier)(value, name)
    except ValidationError as exc:
        raise ScientificNumericAblationValueError(str(exc)) from exc


def _tuple(value: object, name: str, low: int, high: int) -> tuple:
    if type(value) is not tuple or not low <= len(value) <= high:
        raise ScientificNumericAblationValueError(f"{name} requires a native tuple of size {low}..{high}")
    return value


def _closed_dict(value: object, names: tuple[str, ...], name: str) -> dict:
    if (type(value) is not dict or len(value) != len(names)
            or any(type(key) is not str for key in value) or set(value) != set(names)):
        raise ScientificNumericAblationValueError(f"{name} requires exact closed native fields")
    return value


def _state_values(value: dict) -> dict:
    # The existing canonical revision bound is imported only when needed;
    # no canonical/source resolver is invoked by this value module.
    from .research_state import MAX_REVISION

    _closed_dict(value, _STATE_FIELDS, "state binding")
    if type(value["object_type"]) is not str or value["object_type"] not in _STATE_TYPES:
        raise ScientificNumericAblationValueError("state binding object_type is not native or supported")
    _text(value["object_id"], "state object_id")
    _text(value["materialization_event_id"], "state materialization event_id")
    _integer(value["revision"], "state revision", 1, MAX_REVISION)
    _integer(value["materialization_event_index"], "state materialization index", 0, MAX_LEDGER_EVENTS - 1)
    for name in ("content_hash", "artifact_sha256", "artifact_record_hash", "materialization_event_hash"):
        _text(value[name], name, digest=True)
    return value


def _detach_state(value: object) -> ScientificAblationStateBinding:
    if type(value) is not ScientificAblationStateBinding:
        raise ScientificNumericAblationValueError("state binding requires its exact existing native DTO type")
    native = _state_values({name: getattr(value, name) for name in _STATE_FIELDS})
    return ScientificAblationStateBinding(**native)


def _hashes(value: object, name: str, low: int, high: int) -> tuple[str, ...]:
    result = _tuple(value, name, low, high)
    for digest in result:
        _text(digest, name, digest=True)
    if len(set(result)) != len(result):
        raise ScientificNumericAblationValueError(f"{name} contains duplicates")
    return result


def _bounded_bytes(value: dict) -> bytes:
    # Reuse the existing serializer/parser's resource contract. Parsing our
    # own native encoded view here applies the smaller receipt item budget;
    # it is not an independent observed-source or canonical-metadata parser.
    raw = canonical_json_bytes(value) + b"\n"
    if len(raw) > MAX_SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_BYTES:
        raise ScientificNumericAblationValueError("numeric ablation value exceeds its newline-inclusive byte bound")
    safe_json_loads(raw, max_bytes=MAX_SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_BYTES,
                    max_items=MAX_SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_JSON_ITEMS)
    return raw


def numeric_ablation_slot_hash(
    *,
    ledger_run_id: str,
    execution_run_id: str,
    result_artifact_sha256: str,
    contract_artifact_sha256: str,
    ablation_id: str,
) -> str:
    """Pure outcome-independent slot identity, not reservation or authority."""

    for name, value in (("ledger_run_id", ledger_run_id), ("execution_run_id", execution_run_id),
                        ("ablation_id", ablation_id)):
        _text(value, name)
    _text(result_artifact_sha256, "result_artifact_sha256", digest=True)
    _text(contract_artifact_sha256, "contract_artifact_sha256", digest=True)
    return sha256_bytes(canonical_json_bytes({
        "schema_version": SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_SCHEMA,
        "ledger_run_id": ledger_run_id,
        "execution_run_id": execution_run_id,
        "result_artifact_sha256": result_artifact_sha256,
        "contract_artifact_sha256": contract_artifact_sha256,
        "ablation_id": ablation_id,
    }))


def _owned(value: object) -> ScientificNumericAblationAuthority:
    if type(value) is not ScientificNumericAblationAuthority:
        raise ScientificNumericAblationValueError("numeric ablation value requires its exact native DTO type")
    return replace(value)


@dataclass(frozen=True, slots=True)
class ScientificNumericAblationAuthority:
    """An inert value for full-owner replay, never authority by construction."""

    authority_id: str
    ledger_run_id: str
    execution_run_id: str
    intervention: GenericMLFeatureIntervention
    metric_id: str
    contract_artifact_sha256: str
    contract_record_hash: str
    promotion_artifact_sha256: str
    promotion_record_hash: str
    assessment_artifact_sha256: str
    assessment_record_hash: str
    execution_artifact_sha256: str
    execution_record_hash: str
    projection_artifact_sha256: str
    projection_record_hash: str
    ablation_output_artifact_sha256: str
    ablation_output_record_hash: str
    state_bindings: tuple[ScientificAblationStateBinding, ...]
    unit_count: int
    seed_order: tuple[int, ...]
    changed_coefficient_counts: tuple[int, ...]
    activity_sequence: int
    candidate_correct_total: int
    baseline_correct_total: int
    ablated_correct_total: int
    source_artifact_hashes: tuple[str, ...]
    source_artifact_record_hashes: tuple[str, ...]
    custody_artifact_hashes: tuple[str, ...]
    custody_artifact_record_hashes: tuple[str, ...]
    replay_status: str = SCIENTIFIC_NUMERIC_ABLATION_REPLAY_STATUS
    scope: str = GENERIC_ML_FEATURE_INTERVENTION_SCOPE
    scientific_evidence_eligible: bool = False
    schema_version: str = SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        if type(self) is not ScientificNumericAblationAuthority:
            raise ScientificNumericAblationValueError("numeric ablation value requires its exact native DTO type")
        for name in ("authority_id", "ledger_run_id", "execution_run_id", "metric_id"):
            _text(getattr(self, name), name)
        for artifact_name, record_name in _SOURCE_PAIRS:
            _text(getattr(self, artifact_name), artifact_name, digest=True)
            _text(getattr(self, record_name), record_name, digest=True)
        for name, expected in (("schema_version", SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_SCHEMA),
                               ("scope", GENERIC_ML_FEATURE_INTERVENTION_SCOPE),
                               ("replay_status", SCIENTIFIC_NUMERIC_ABLATION_REPLAY_STATUS)):
            value = getattr(self, name)
            if type(value) is not str or value != expected:
                raise ScientificNumericAblationValueError(f"unsupported exact numeric ablation {name}")
        if self.scientific_evidence_eligible is not False:
            raise ScientificNumericAblationValueError("descriptive numeric ablation eligibility must be strictly False")
        if type(self.intervention) is not GenericMLFeatureIntervention:
            raise ScientificNumericAblationValueError("intervention requires its exact native DTO type")
        GenericMLFeatureIntervention.__post_init__(self.intervention)
        object.__setattr__(self, "intervention", replace(self.intervention))
        bindings = _tuple(self.state_bindings, "state_bindings", 4, 4)
        owned = tuple(_detach_state(value) for value in bindings)
        if tuple(value.object_type for value in owned) != _STATE_TYPES:
            raise ScientificNumericAblationValueError("state bindings must be ordered Result/Run/Method/Experiment")
        result, run, method, experiment = owned
        if (run.object_id != self.execution_run_id or not (
                method.materialization_event_index < experiment.materialization_event_index
                < run.materialization_event_index < result.materialization_event_index)):
            raise ScientificNumericAblationValueError("state Run identity or materialization topology differs")
        object.__setattr__(self, "state_bindings", owned)
        _integer(self.unit_count, "unit_count", 1, MAX_GENERIC_ML_ABLATION_UNITS)
        seeds = _tuple(self.seed_order, "seed_order", 1, MAX_GENERIC_ML_SEEDS)
        for seed in seeds:
            _integer(seed, "seed", 0, MAX_GENERIC_ML_INTEGER_MAGNITUDE)
        if len(set(seeds)) != len(seeds):
            raise ScientificNumericAblationValueError("seed_order contains duplicates")
        changed = _tuple(self.changed_coefficient_counts, "changed_coefficient_counts", len(seeds), len(seeds))
        for count in changed:
            _integer(count, "changed coefficient count", 0, MAX_GENERIC_ML_FROZEN_MODEL_PARAMETERS)
        if not any(changed):
            raise ScientificNumericAblationValueError("whole seed grid cannot be a coefficient no-op")
        _integer(self.activity_sequence, "activity_sequence", 0, MAX_OUTPUT_ARTIFACTS - 1)
        for name in ("candidate_correct_total", "baseline_correct_total", "ablated_correct_total"):
            _integer(getattr(self, name), name, 0, self.unit_count * len(seeds))
        source_hashes = _hashes(self.source_artifact_hashes, "source_artifact_hashes", 10, 10)
        source_records = _hashes(self.source_artifact_record_hashes, "source_artifact_record_hashes", 10, 10)
        expected_hashes = tuple(getattr(self, pair[0]) for pair in _SOURCE_PAIRS) + tuple(
            binding.artifact_sha256 for binding in owned)
        expected_records = tuple(getattr(self, pair[1]) for pair in _SOURCE_PAIRS) + tuple(
            binding.artifact_record_hash for binding in owned)
        if source_hashes != expected_hashes or source_records != expected_records:
            raise ScientificNumericAblationValueError("direct sources differ from the exact six named and four state roots")
        custody_hashes = _hashes(self.custody_artifact_hashes, "custody_artifact_hashes", 10,
                                MAX_SCIENTIFIC_NUMERIC_ABLATION_CUSTODY_RECORDS)
        custody_records = _hashes(self.custody_artifact_record_hashes, "custody_artifact_record_hashes",
                                 len(custody_hashes), len(custody_hashes))
        if custody_hashes != tuple(sorted(custody_hashes)):
            raise ScientificNumericAblationValueError("custody artifact hashes must be sorted")
        custody = dict(zip(custody_hashes, custody_records, strict=True))
        if any(custody.get(digest) != record for digest, record in zip(source_hashes, source_records, strict=True)):
            raise ScientificNumericAblationValueError("custody omits or substitutes a direct source record mapping")
        expected_id = "numeric-ablation-authority:" + numeric_ablation_slot_hash(
            ledger_run_id=self.ledger_run_id, execution_run_id=self.execution_run_id,
            result_artifact_sha256=result.artifact_sha256,
            contract_artifact_sha256=self.contract_artifact_sha256,
            ablation_id=self.intervention.ablation_id,
        )
        if self.authority_id != expected_id:
            raise ScientificNumericAblationValueError("authority_id differs from the outcome-independent slot")
        _bounded_bytes(_authority_wire(self))

    @property
    def canonical_object_id(self) -> str:
        owned = _owned(self)
        return "numeric-ablation:" + numeric_ablation_slot_hash(
            ledger_run_id=owned.ledger_run_id, execution_run_id=owned.execution_run_id,
            result_artifact_sha256=owned.state_bindings[0].artifact_sha256,
            contract_artifact_sha256=owned.contract_artifact_sha256,
            ablation_id=owned.intervention.ablation_id,
        )

    @property
    def effect_denominator(self) -> int:
        owned = _owned(self)
        return owned.unit_count * len(owned.seed_order)

    @property
    def candidate_minus_ablated_numerator(self) -> int:
        owned = _owned(self)
        return owned.candidate_correct_total - owned.ablated_correct_total

    @property
    def ablated_minus_baseline_numerator(self) -> int:
        owned = _owned(self)
        return owned.ablated_correct_total - owned.baseline_correct_total

    @property
    def candidate_minus_baseline_numerator(self) -> int:
        owned = _owned(self)
        return owned.candidate_correct_total - owned.baseline_correct_total

    def to_dict(self) -> dict[str, object]:
        if type(self) is not ScientificNumericAblationAuthority:
            raise ScientificNumericAblationValueError("numeric ablation codec requires its exact native DTO")
        return _authority_wire(replace(self))

    @classmethod
    def from_dict(cls, value: object) -> ScientificNumericAblationAuthority:
        if cls is not ScientificNumericAblationAuthority:
            raise ScientificNumericAblationValueError("numeric ablation codec requires its exact native DTO")
        names = tuple(item.name for item in fields(cls))
        value = _closed_dict(value, names, "numeric ablation authority")
        arguments = dict(value)
        arguments["intervention"] = GenericMLFeatureIntervention.from_dict(value["intervention"])
        bindings = value["state_bindings"]
        if type(bindings) is not list or len(bindings) != 4:
            raise ScientificNumericAblationValueError("state_bindings requires an exact four-element native list")
        arguments["state_bindings"] = tuple(ScientificAblationStateBinding(**_state_values(item)) for item in bindings)
        for name in _VECTOR_FIELDS:
            vector = value[name]
            maximum = MAX_GENERIC_ML_SEEDS if name in {"seed_order", "changed_coefficient_counts"} else (
                10 if name.startswith("source_") else MAX_SCIENTIFIC_NUMERIC_ABLATION_CUSTODY_RECORDS)
            if type(vector) is not list or not 1 <= len(vector) <= maximum:
                raise ScientificNumericAblationValueError(f"{name} requires a bounded native JSON list")
            arguments[name] = tuple(vector)
        return cls(**arguments)

    def canonical_bytes(self) -> bytes:
        return _bounded_bytes(_authority_wire(_owned(self)))

    def canonical_metadata(self) -> dict[str, object]:
        """Closed descriptive view, not a source proof or separate parser."""

        if type(self) is not ScientificNumericAblationAuthority:
            raise ScientificNumericAblationValueError("numeric ablation metadata requires its exact native DTO")
        owned = replace(self)
        metadata = {
            "schema_version": SCIENTIFIC_NUMERIC_ABLATION_CANONICAL_SCHEMA,
            "authority_id": owned.authority_id,
            "intervention": GenericMLFeatureIntervention.to_dict(owned.intervention),
            "metric_id": owned.metric_id,
            "unit_count": owned.unit_count,
            "seed_order": list(owned.seed_order),
            "changed_coefficient_counts": list(owned.changed_coefficient_counts),
            "activity_sequence": owned.activity_sequence,
            "candidate_correct_total": owned.candidate_correct_total,
            "baseline_correct_total": owned.baseline_correct_total,
            "ablated_correct_total": owned.ablated_correct_total,
            "scope": owned.scope,
            "replay_status": owned.replay_status,
            "scientific_evidence_eligible": False,
        }
        _bounded_bytes(metadata)
        return metadata


def _authority_wire(value: ScientificNumericAblationAuthority) -> dict[str, object]:
    """Serialize an already native-validated local value without public hooks."""

    wire = {item.name: getattr(value, item.name) for item in fields(ScientificNumericAblationAuthority)}
    wire["intervention"] = GenericMLFeatureIntervention.to_dict(value.intervention)
    wire["state_bindings"] = [{name: getattr(binding, name) for name in _STATE_FIELDS}
                              for binding in value.state_bindings]
    for name in _VECTOR_FIELDS:
        wire[name] = list(getattr(value, name))
    return wire
