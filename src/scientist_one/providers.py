"""Provider-neutral model capabilities and an OpenAI Responses adapter.

Model providers are advisory computation only.  Their output is immutable,
captured, and schema-checked, but it is never scientific evidence or authority.
All external I/O is delegated to :mod:`scientist_one.external`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import math
import re
from typing import Any, Callable, Mapping, Protocol, Sequence

from .artifacts import ArtifactRecord
from .errors import ValidationError
from .external import (
    AUDITED_LIVE_TRANSPORT_AUTHORITY,
    EgressDeniedError,
    EgressGateway,
    EgressPolicy,
    EgressPolicyError,
    EgressRequest,
    ExternalParseError,
    ExternalUnavailableError,
    GatewayResult,
    TransportFailure,
    UNVERIFIED_TRANSPORT_AUTHORITY,
)
from .models import IDENTIFIER_RE, SHA256_RE, freeze_json, thaw_json
from .provider_verification import (
    MODEL_PROVIDER_CUSTODY_SCHEMA_V1,
    ProviderVerificationError,
    require_provider_verifier,
)
from .roles import Role
from .security import canonical_json_bytes, safe_json_loads, sha256_bytes


MAX_INSTRUCTIONS_BYTES = 64 * 1024
MAX_INPUT_BYTES = 1024 * 1024
MAX_OUTPUT_TOKENS = 100_000
MAX_SCHEMA_DEPTH = 32
MAX_SCHEMA_ITEMS = 50_000
MAX_SCHEMA_PROPERTIES = 256
MAX_SCHEMA_ARRAY_ITEMS = 10_000
MAX_SCHEMA_STRING_BYTES = 1024 * 1024
MAX_PROVIDER_ARTIFACTS = 32
MAX_TERMINAL_ATTEMPTS = 8
# Prospective OpenAI admission only; the neutral schema and retained-wire
# validators intentionally keep their existing contracts. Source checked
# 2026-09-19: https://developers.openai.com/api/docs/guides/structured-outputs
# This bounded profile is not exhaustive model/fine-tune API compatibility.
_OPENAI_SCHEMA_MAX_CONTAINER_DEPTH = 10
_OPENAI_SCHEMA_MAX_PROPERTIES = 5_000
_OPENAI_SCHEMA_MAX_STRING_CHARACTERS = 120_000
_OPENAI_SCHEMA_MAX_ENUM_ENTRIES = 1_000
_OPENAI_SCHEMA_LARGE_ENUM_THRESHOLD = 250
_OPENAI_SCHEMA_MAX_LARGE_ENUM_CHARACTERS = 15_000
OPENAI_RESPONSES_ENDPOINT = "https://api.openai.com/v1/responses"
_SCHEMA_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SUPPORTED_SCHEMA_TYPES = frozenset(
    {"object", "array", "string", "integer", "number", "boolean", "null"}
)
_COMMON_SCHEMA_KEYS = frozenset({"type", "description", "enum"})
_TYPE_SCHEMA_KEYS: dict[str, frozenset[str]] = {
    "object": frozenset({"properties", "required", "additionalProperties"}),
    "array": frozenset({"items", "minItems", "maxItems"}),
    "string": frozenset({"minLength", "maxLength"}),
    "integer": frozenset({"minimum", "maximum"}),
    "number": frozenset({"minimum", "maximum"}),
    "boolean": frozenset(),
    "null": frozenset(),
}


class ModelProviderError(RuntimeError):
    """Base class for a denied or invalid model-provider operation."""


class ModelSchemaError(ModelProviderError, ValueError):
    """A requested structured-output schema is unsafe or unsupported."""


class ModelResponseError(ModelProviderError):
    """Captured provider bytes do not satisfy the promised response contract."""


class ModelCapability(StrEnum):
    PLANNING = "planning"
    LITERATURE_ANALYSIS = "literature_analysis"
    RESEARCH_SYNTHESIS = "research_synthesis"
    CODING = "coding"
    CRITICISM = "criticism"
    SEMANTIC_EVIDENCE_ANALYSIS = "semantic_evidence_analysis"
    CLAIM_VERIFICATION = "claim_verification"
    SCIENTIFIC_REVIEW = "scientific_review"
    PAPER_COMPOSITION = "paper_composition"


class ModelRunStatus(StrEnum):
    COMPLETED = "COMPLETED"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"
    EXTERNAL_ERROR = "EXTERNAL_ERROR"
    INVALID_RESPONSE = "INVALID_RESPONSE"


def _bounded_text(
    value: object,
    label: str,
    *,
    maximum_bytes: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str) or (not value and not allow_empty) or "\x00" in value:
        raise ModelProviderError(f"{label} must be bounded UTF-8 text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ModelProviderError(f"{label} must be bounded UTF-8 text") from exc
    if len(encoded) > maximum_bytes:
        raise ModelProviderError(f"{label} exceeds its byte limit")
    return value


def _bounded_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelProviderError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ModelProviderError(f"{label} is outside its allowed range")
    return value


def _finite_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ModelSchemaError(f"{label} must be numeric")
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise ModelSchemaError(f"{label} must be finite") from exc
    if not math.isfinite(number):
        raise ModelSchemaError(f"{label} must be finite")
    return number


def _schema_enum_key(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise ModelSchemaError("schema enum values must be finite JSON") from exc


def _validate_schema_node(
    schema: Any,
    *,
    depth: int,
    budget: list[int],
) -> None:
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_SCHEMA_DEPTH:
        raise ModelSchemaError("structured-output schema exceeds its complexity bound")
    if not isinstance(schema, Mapping):
        raise ModelSchemaError("every structured-output schema node must be an object")
    if any(not isinstance(key, str) for key in schema):
        raise ModelSchemaError("structured-output schema keys must be strings")
    schema_type = schema.get("type")
    if not isinstance(schema_type, str) or schema_type not in _SUPPORTED_SCHEMA_TYPES:
        raise ModelSchemaError("structured-output schema requires one supported scalar type")
    allowed = _COMMON_SCHEMA_KEYS | _TYPE_SCHEMA_KEYS[schema_type]
    if set(schema) - allowed:
        raise ModelSchemaError("structured-output schema contains unsupported keywords")
    description = schema.get("description")
    if description is not None:
        _bounded_text(description, "schema description", maximum_bytes=4096)

    enum = schema.get("enum")
    if enum is not None:
        if not isinstance(enum, (list, tuple)) or not enum or len(enum) > 256:
            raise ModelSchemaError("schema enum must be a non-empty bounded sequence")
        if any(not _matches_type(value, schema_type) for value in enum):
            raise ModelSchemaError("schema enum value does not match its declared type")
        enum_keys = tuple(_schema_enum_key(value) for value in enum)
        if len(set(enum_keys)) != len(enum_keys):
            raise ModelSchemaError("schema enum values must be unique")
        if sum(len(value) for value in enum_keys) > MAX_SCHEMA_STRING_BYTES:
            raise ModelSchemaError("schema enum exceeds its byte bound")

    if schema_type == "object":
        properties = schema.get("properties")
        required = schema.get("required")
        if not isinstance(properties, Mapping) or len(properties) > MAX_SCHEMA_PROPERTIES:
            raise ModelSchemaError("object schema requires bounded properties")
        if any(
            not isinstance(key, str)
            or not key
            or len(key.encode("utf-8")) > 128
            for key in properties
        ):
            raise ModelSchemaError("object schema property names are invalid")
        if not isinstance(required, (list, tuple)):
            raise ModelSchemaError("object schema requires an explicit required list")
        if (
            any(not isinstance(value, str) for value in required)
            or len(set(required)) != len(required)
            or set(required) != set(properties)
        ):
            raise ModelSchemaError("strict object schemas must require every property exactly once")
        if schema.get("additionalProperties") is not False:
            raise ModelSchemaError("strict object schemas must forbid additional properties")
        for child in properties.values():
            _validate_schema_node(child, depth=depth + 1, budget=budget)
        return

    if schema_type == "array":
        if "items" not in schema:
            raise ModelSchemaError("array schema requires an item schema")
        maximum = _bounded_int(
            schema.get("maxItems"),
            "schema maxItems",
            0,
            MAX_SCHEMA_ARRAY_ITEMS,
        )
        minimum = _bounded_int(schema.get("minItems", 0), "schema minItems", 0, maximum)
        if minimum > maximum:
            raise ModelSchemaError("schema minItems exceeds maxItems")
        _validate_schema_node(schema["items"], depth=depth + 1, budget=budget)
        return

    if schema_type == "string":
        maximum = schema.get("maxLength")
        if maximum is None and enum is None:
            raise ModelSchemaError("string schemas require maxLength or an enum")
        if maximum is not None:
            maximum = _bounded_int(
                maximum,
                "schema maxLength",
                0,
                MAX_SCHEMA_STRING_BYTES,
            )
            minimum = _bounded_int(
                schema.get("minLength", 0),
                "schema minLength",
                0,
                maximum,
            )
            if minimum > maximum:
                raise ModelSchemaError("schema minLength exceeds maxLength")
        return

    if schema_type in {"integer", "number"}:
        if "minimum" not in schema or "maximum" not in schema:
            raise ModelSchemaError("numeric schemas require finite minimum and maximum")
        minimum = _finite_number(schema["minimum"], "schema minimum")
        maximum = _finite_number(schema["maximum"], "schema maximum")
        if minimum > maximum:
            raise ModelSchemaError("schema minimum exceeds maximum")


def validate_structured_output_schema(schema: Mapping[str, Any]) -> None:
    """Validate the deliberately small, bounded JSON-Schema subset we support."""

    _validate_schema_node(schema, depth=0, budget=[MAX_SCHEMA_ITEMS])
    if schema.get("type") != "object":
        raise ModelSchemaError("the provider output schema root must be an object")


def _validate_openai_schema_admission(schema: Mapping[str, Any]) -> None:
    """Apply the reference provider's limits to an already neutral-valid schema.

    Container depth is a conservative local profile: root object is level one,
    each nested object or array adds one, and scalar leaves add none. The guide
    does not specify array counting. Definitions/const are already unsupported
    by the neutral validator, so only property names and string enum values
    contribute to the documented aggregate character budget. Composite enum
    values are conservatively excluded by this local profile because the guide
    does not define their contribution to that budget; this is not a claim that
    the native API rejects every composite enum.
    """

    stack = [(schema, 0)]
    properties = 0
    enum_entries = 0
    string_characters = 0
    while stack:
        node, parent_depth = stack.pop()
        node_type = node["type"]
        depth = parent_depth + (node_type in {"object", "array"})
        if "enum" in node:
            enum = node["enum"]
            if not isinstance(enum, (list, tuple)):
                raise ModelSchemaError("OpenAI structured-output schema exceeds its admission profile")
        else:
            enum = ()
        if any(isinstance(value, (Mapping, list, tuple)) for value in enum):
            raise ModelSchemaError("OpenAI structured-output schema exceeds its admission profile")
        enum_entries += len(enum)
        enum_characters = sum(len(value) for value in enum if isinstance(value, str))
        string_characters += enum_characters
        if (
            node_type == "string"
            and len(enum) > _OPENAI_SCHEMA_LARGE_ENUM_THRESHOLD
            and enum_characters > _OPENAI_SCHEMA_MAX_LARGE_ENUM_CHARACTERS
        ):
            raise ModelSchemaError("OpenAI structured-output schema exceeds its admission profile")
        if node_type == "object":
            children = node["properties"]
            properties += len(children)
            string_characters += sum(len(name) for name in children)
            stack.extend((child, depth) for child in children.values())
        elif node_type == "array":
            stack.append((node["items"], depth))
        if (
            depth > _OPENAI_SCHEMA_MAX_CONTAINER_DEPTH
            or properties > _OPENAI_SCHEMA_MAX_PROPERTIES
            or enum_entries > _OPENAI_SCHEMA_MAX_ENUM_ENTRIES
            or string_characters > _OPENAI_SCHEMA_MAX_STRING_CHARACTERS
        ):
            raise ModelSchemaError("OpenAI structured-output schema exceeds its admission profile")


def _matches_type(value: Any, schema_type: str) -> bool:
    if schema_type == "object":
        return isinstance(value, Mapping)
    if schema_type == "array":
        return isinstance(value, (list, tuple))
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if schema_type == "boolean":
        return isinstance(value, bool)
    return value is None


def _validate_output_node(
    value: Any,
    schema: Mapping[str, Any],
    *,
    depth: int,
    budget: list[int],
) -> None:
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_SCHEMA_DEPTH:
        raise ModelResponseError("model output exceeds the structured-output complexity bound")
    schema_type = schema["type"]
    if not _matches_type(value, schema_type):
        raise ModelResponseError("model output does not match the requested scalar type")
    if "enum" in schema:
        candidate = _schema_enum_key(value)
        if candidate not in {_schema_enum_key(item) for item in schema["enum"]}:
            raise ModelResponseError("model output is outside the requested enum")

    if schema_type == "object":
        properties = schema["properties"]
        if set(value) != set(properties):
            raise ModelResponseError("model output object fields differ from the strict schema")
        for key, child_schema in properties.items():
            _validate_output_node(
                value[key], child_schema, depth=depth + 1, budget=budget
            )
    elif schema_type == "array":
        if len(value) < schema.get("minItems", 0) or len(value) > schema["maxItems"]:
            raise ModelResponseError("model output array length violates the schema")
        for child in value:
            _validate_output_node(
                child, schema["items"], depth=depth + 1, budget=budget
            )
    elif schema_type == "string":
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ModelResponseError("model output string is shorter than the schema")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ModelResponseError("model output string is longer than the schema")
        if len(value.encode("utf-8")) > MAX_SCHEMA_STRING_BYTES:
            raise ModelResponseError("model output string exceeds its absolute byte bound")
    elif schema_type in {"integer", "number"}:
        try:
            number = float(value)
        except (OverflowError, ValueError) as exc:
            raise ModelResponseError("model output numeric value is non-finite") from exc
        if not math.isfinite(number):
            raise ModelResponseError("model output numeric value is non-finite")
        if number < float(schema["minimum"]) or number > float(schema["maximum"]):
            raise ModelResponseError("model output numeric value is outside the schema")


def validate_structured_output(value: Any, schema: Mapping[str, Any]) -> None:
    validate_structured_output_schema(schema)
    _validate_output_node(value, schema, depth=0, budget=[MAX_SCHEMA_ITEMS])


@dataclass(frozen=True)
class ModelCapabilities:
    provider_id: str
    capabilities: tuple[ModelCapability, ...]
    structured_json: bool = True
    provider_tools: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.provider_id, str) or not IDENTIFIER_RE.fullmatch(self.provider_id):
            raise ModelProviderError("provider_id is invalid")
        if (
            not isinstance(self.capabilities, tuple)
            or not self.capabilities
            or len(self.capabilities) > len(ModelCapability)
            or any(not isinstance(value, ModelCapability) for value in self.capabilities)
            or len(set(self.capabilities)) != len(self.capabilities)
        ):
            raise ModelProviderError("provider capabilities are invalid")
        if self.structured_json is not True or self.provider_tools is not False:
            raise ModelProviderError("trusted providers require structured JSON without tools")


@dataclass(frozen=True)
class ProviderAvailability:
    provider_id: str
    status: str
    credential_status: str
    network_used: bool
    transport_authority: str = UNVERIFIED_TRANSPORT_AUTHORITY
    scientific_evidence: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.provider_id, str) or not IDENTIFIER_RE.fullmatch(self.provider_id):
            raise ModelProviderError("provider_id is invalid")
        if self.status not in {"AVAILABLE_UNVALIDATED", "UNTESTED", "BLOCKED_EXTERNAL"}:
            raise ModelProviderError("provider availability status is invalid")
        if self.credential_status not in {"NOT_REQUIRED", "PRESENT", "ABSENT", "UNAVAILABLE"}:
            raise ModelProviderError("provider credential status is invalid")
        if (
            not isinstance(self.network_used, bool)
            or self.transport_authority
            not in {
                AUDITED_LIVE_TRANSPORT_AUTHORITY,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            }
            or (
                self.status == "AVAILABLE_UNVALIDATED"
                and (
                    self.transport_authority
                    != AUDITED_LIVE_TRANSPORT_AUTHORITY
                    or self.network_used is not True
                )
            )
            or self.scientific_evidence is not False
        ):
            raise ModelProviderError("provider availability cannot assert scientific evidence")


@dataclass(frozen=True)
class ModelInvocation:
    invocation_id: str
    capability: ModelCapability
    model: str
    prompt_template_id: str
    prompt_template_version: str
    prompt_template_hash: str
    instructions: str
    input_text: str
    output_schema: Mapping[str, Any]
    input_artifact_hashes: tuple[str, ...] = ()
    max_output_tokens: int = 4096

    def __post_init__(self) -> None:
        for label, value in (
            ("invocation_id", self.invocation_id),
            ("prompt_template_id", self.prompt_template_id),
            ("prompt_template_version", self.prompt_template_version),
        ):
            if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
                raise ModelProviderError(f"{label} is invalid")
        if not isinstance(self.capability, ModelCapability):
            raise ModelProviderError("capability must be typed")
        _bounded_text(self.model, "model", maximum_bytes=256)
        if not isinstance(self.prompt_template_hash, str) or not SHA256_RE.fullmatch(
            self.prompt_template_hash
        ):
            raise ModelProviderError("prompt_template_hash must be lowercase SHA-256")
        _bounded_text(
            self.instructions,
            "instructions",
            maximum_bytes=MAX_INSTRUCTIONS_BYTES,
            allow_empty=True,
        )
        _bounded_text(self.input_text, "input_text", maximum_bytes=MAX_INPUT_BYTES)
        if (
            not isinstance(self.input_artifact_hashes, tuple)
            or len(self.input_artifact_hashes) > 256
            or len(set(self.input_artifact_hashes)) != len(self.input_artifact_hashes)
            or any(
                not isinstance(value, str) or not SHA256_RE.fullmatch(value)
                for value in self.input_artifact_hashes
            )
        ):
            raise ModelProviderError("input artifact hashes are invalid")
        _bounded_int(
            self.max_output_tokens,
            "max_output_tokens",
            1,
            MAX_OUTPUT_TOKENS,
        )
        if not isinstance(self.output_schema, Mapping):
            raise ModelSchemaError("output_schema must be a mapping")
        validate_structured_output_schema(self.output_schema)
        try:
            object.__setattr__(self, "output_schema", freeze_json(self.output_schema))
        except ValidationError as exc:
            raise ModelSchemaError("output_schema must be finite bounded JSON") from exc


@dataclass(frozen=True)
class OpenAIResponsesConfig:
    provider_id: str = "openai"
    endpoint: str = OPENAI_RESPONSES_ENDPOINT
    allowed_models: tuple[str, ...] = ("gpt-5",)
    supported_capabilities: tuple[ModelCapability, ...] = tuple(ModelCapability)
    schema_name: str = "scientist_one_output"
    maximum_output_tokens: int = MAX_OUTPUT_TOKENS

    def __post_init__(self) -> None:
        if self.provider_id != "openai":
            raise ModelProviderError("the reference Responses provider identity must be openai")
        _bounded_text(self.endpoint, "endpoint", maximum_bytes=8192)
        if self.endpoint != OPENAI_RESPONSES_ENDPOINT:
            raise ModelProviderError("the reference Responses provider endpoint is fixed")
        if (
            not isinstance(self.allowed_models, tuple)
            or not self.allowed_models
            or len(self.allowed_models) > 64
            or len(set(self.allowed_models)) != len(self.allowed_models)
        ):
            raise ModelProviderError("allowed model list is invalid")
        for model in self.allowed_models:
            _bounded_text(model, "allowed model", maximum_bytes=256)
        if (
            not isinstance(self.supported_capabilities, tuple)
            or not self.supported_capabilities
            or any(
                not isinstance(value, ModelCapability)
                for value in self.supported_capabilities
            )
            or len(set(self.supported_capabilities)) != len(self.supported_capabilities)
        ):
            raise ModelProviderError("supported capabilities are invalid")
        if not isinstance(self.schema_name, str) or not _SCHEMA_NAME_RE.fullmatch(self.schema_name):
            raise ModelProviderError("structured-output schema name is invalid")
        if self.schema_name != "scientist_one_output":
            raise ModelProviderError(
                "the reference provider schema name is source-owned"
            )
        _bounded_int(
            self.maximum_output_tokens,
            "maximum_output_tokens",
            1,
            MAX_OUTPUT_TOKENS,
        )


@dataclass(frozen=True)
class ModelResult:
    invocation_id: str
    provider_id: str
    capability: ModelCapability
    model_requested: str
    status: ModelRunStatus
    external_validation: str
    network_used: bool
    transport_authority: str = UNVERIFIED_TRANSPORT_AUTHORITY
    transport_execution_authority_artifact_sha256: str | None = None
    output: Mapping[str, Any] | None = None
    model_returned: str | None = None
    provider_response_id: str | None = None
    usage: Mapping[str, Any] | None = None
    request_id: str | None = None
    artifacts: tuple[ArtifactRecord, ...] = ()
    provenance_status: str = "NOT_CONFIGURED"
    terminal_receipt: ArtifactRecord | None = None
    error_code: str | None = None
    scientific_evidence: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.invocation_id, str) or not IDENTIFIER_RE.fullmatch(self.invocation_id):
            raise ModelProviderError("result invocation_id is invalid")
        if not isinstance(self.provider_id, str) or not IDENTIFIER_RE.fullmatch(self.provider_id):
            raise ModelProviderError("result provider_id is invalid")
        if not isinstance(self.capability, ModelCapability) or not isinstance(
            self.status, ModelRunStatus
        ):
            raise ModelProviderError("result status or capability is invalid")
        _bounded_text(self.model_requested, "model_requested", maximum_bytes=256)
        if not isinstance(self.external_validation, str) or not self.external_validation:
            raise ModelProviderError("external_validation is required")
        _bounded_text(
            self.external_validation,
            "external_validation",
            maximum_bytes=128,
        )
        if (
            not isinstance(self.network_used, bool)
            or self.transport_authority
            not in {
                AUDITED_LIVE_TRANSPORT_AUTHORITY,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            }
            or self.scientific_evidence is not False
        ):
            raise ModelProviderError("model results cannot assert scientific evidence")
        if self.transport_execution_authority_artifact_sha256 is not None and (
            not isinstance(
                self.transport_execution_authority_artifact_sha256,
                str,
            )
            or SHA256_RE.fullmatch(
                self.transport_execution_authority_artifact_sha256
            )
            is None
        ):
            raise ModelProviderError(
                "transport execution authority artifact SHA-256 is invalid"
            )
        if self.status is ModelRunStatus.COMPLETED and self.output is None:
            raise ModelProviderError("completed model result requires structured output")
        if self.output is not None:
            try:
                object.__setattr__(self, "output", freeze_json(self.output))
            except ValidationError as exc:
                raise ModelResponseError("model result output is not finite bounded JSON") from exc
        if self.usage is not None:
            try:
                object.__setattr__(self, "usage", freeze_json(self.usage))
            except ValidationError as exc:
                raise ModelResponseError("model usage is not finite bounded JSON") from exc
        if (
            not isinstance(self.artifacts, tuple)
            or len(self.artifacts) > MAX_PROVIDER_ARTIFACTS
            or any(not isinstance(value, ArtifactRecord) for value in self.artifacts)
            or len({value.sha256 for value in self.artifacts}) != len(self.artifacts)
        ):
            raise ModelProviderError("model provenance artifact set is invalid")
        if self.transport_execution_authority_artifact_sha256 is not None and (
            len(
                [
                    value
                    for value in self.artifacts
                    if value.sha256
                    == self.transport_execution_authority_artifact_sha256
                    and value.logical_type
                    == "audited_transport_execution_authority"
                ]
            )
            != 1
        ):
            raise ModelProviderError(
                "transport execution authority is absent from model provenance"
            )
        if self.provenance_status not in {
            "NOT_CONFIGURED",
            "CAPTURED",
            "TERMINAL_RECEIPT_CAPTURED",
        }:
            raise ModelProviderError("model provenance status is invalid")
        if self.terminal_receipt is not None:
            if (
                not isinstance(self.terminal_receipt, ArtifactRecord)
                or self.terminal_receipt.logical_type != "model_terminal_receipt"
                or self.terminal_receipt not in self.artifacts
            ):
                raise ModelProviderError("terminal receipt provenance is invalid")
        if self.provenance_status == "TERMINAL_RECEIPT_CAPTURED":
            if self.terminal_receipt is None or self.status is ModelRunStatus.COMPLETED:
                raise ModelProviderError("terminal provenance requires a failed model result")
        elif self.terminal_receipt is not None:
            raise ModelProviderError("terminal receipt and provenance status disagree")
        if self.provenance_status == "NOT_CONFIGURED" and self.artifacts:
            raise ModelProviderError("unconfigured provenance cannot contain artifacts")
        for label, value, maximum in (
            ("model_returned", self.model_returned, 256),
            ("provider_response_id", self.provider_response_id, 256),
            ("error_code", self.error_code, 128),
        ):
            if value is not None:
                _bounded_text(value, label, maximum_bytes=maximum)
        if self.request_id is not None and not SHA256_RE.fullmatch(self.request_id):
            raise ModelProviderError("request_id must be lowercase SHA-256")


class ModelProvider(Protocol):
    """Capability-oriented advisory model interface."""

    def capabilities(self) -> ModelCapabilities: ...

    def availability(self) -> ProviderAvailability: ...

    def invoke(self, invocation: ModelInvocation) -> ModelResult: ...


def openai_responses_policy(
    *,
    maximum_requests: int = 100,
    maximum_attempts: int = 3,
    timeout_seconds: float = 60.0,
    maximum_request_bytes: int = 2 * 1024 * 1024,
    maximum_response_bytes: int = 8 * 1024 * 1024,
    enabled: bool = True,
) -> EgressPolicy:
    """Return the exact, provider-specific policy for the Responses endpoint."""

    return EgressPolicy(
        policy_id="openai-responses-v1",
        adapter_id="openai",
        allowed_hosts=("api.openai.com",),
        allowed_path_prefixes=("/v1/responses",),
        allowed_methods=("POST",),
        allowed_query_keys=(),
        allowed_request_headers=(
            "accept",
            "content-type",
            "idempotency-key",
            "user-agent",
        ),
        allowed_request_content_types=("application/json",),
        allowed_response_content_types=("application/json",),
        maximum_request_bytes=maximum_request_bytes,
        maximum_response_bytes=maximum_response_bytes,
        timeout_seconds=timeout_seconds,
        minimum_interval_seconds=0.05,
        maximum_requests=maximum_requests,
        maximum_attempts=maximum_attempts,
        retry_statuses=(429, 500, 502, 503, 504),
        backoff_initial_seconds=0.5,
        backoff_maximum_seconds=8.0,
        maximum_json_depth=64,
        maximum_json_items=250_000,
        credential_env_name="OPENAI_API_KEY",
        credential_required=True,
        credential_header="Authorization",
        credential_prefix="Bearer ",
        enabled=enabled,
    )


def _records(*values: ArtifactRecord | None) -> tuple[ArtifactRecord, ...]:
    result: list[ArtifactRecord] = []
    seen: set[str] = set()
    for value in values:
        if value is not None and value.sha256 not in seen:
            seen.add(value.sha256)
            result.append(value)
    return tuple(result)


def _record_hashes(*values: ArtifactRecord | None) -> tuple[str, ...]:
    return tuple(value.sha256 for value in _records(*values))


def _text_descriptor(value: str) -> dict[str, object]:
    encoded = value.encode("utf-8")
    return {
        "sha256": sha256_bytes(encoded),
        "size": len(encoded),
        "value_persisted": False,
    }


def _bounded_attempt_metadata(
    values: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for index, value in enumerate(tuple(values)[:MAX_TERMINAL_ATTEMPTS], start=1):
        if not isinstance(value, Mapping):
            result.append({"attempt": index, "status": "INVALID_ATTEMPT_METADATA"})
            continue
        attempt = value.get("attempt")
        status = value.get("status")
        status_code = value.get("status_code")
        body_hash = value.get("body_sha256")
        raw_hash = value.get("raw_response_record_sha256")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or not 1 <= attempt <= 8:
            attempt = index
        if status not in {"TRANSPORT_FAILURE", "RESPONSE"}:
            status = "INVALID_ATTEMPT_METADATA"
        if (
            isinstance(status_code, bool)
            or status_code is not None
            and (not isinstance(status_code, int) or not 100 <= status_code <= 599)
        ):
            status_code = None
        if not isinstance(body_hash, str) or not SHA256_RE.fullmatch(body_hash):
            body_hash = None
        if not isinstance(raw_hash, str) or not SHA256_RE.fullmatch(raw_hash):
            raw_hash = None
        result.append(
            {
                "attempt": attempt,
                "status": status,
                "status_code": status_code,
                "body_sha256": body_hash,
                "raw_response_record_sha256": raw_hash,
            }
        )
    return result


def _usage_count(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10**12:
        raise ModelResponseError(f"provider usage {label} is invalid")
    return value


def _usage_details(
    value: object,
    *,
    label: str,
    allowed: tuple[str, ...],
    required: tuple[str, ...],
    parent_total: int,
) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise ModelResponseError(f"provider usage {label} must be an object")
    if set(value) - set(allowed) or not set(required).issubset(value):
        raise ModelResponseError(f"provider usage {label} contains invalid fields")
    details = {
        key: _usage_count(value[key], f"{label}.{key}")
        for key in allowed
        if key in value
    }
    if any(count > parent_total for count in details.values()):
        raise ModelResponseError(f"provider usage {label} exceeds its parent token count")
    return details


def _usage(value: Any) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ModelResponseError("provider usage must be an object")
    required = {"input_tokens", "output_tokens", "total_tokens"}
    allowed = required | {"input_tokens_details", "output_tokens_details"}
    if set(value) - allowed or not required.issubset(value):
        raise ModelResponseError("provider usage contains unknown fields")
    input_tokens = _usage_count(value["input_tokens"], "input_tokens")
    output_tokens = _usage_count(value["output_tokens"], "output_tokens")
    total_tokens = _usage_count(value["total_tokens"], "total_tokens")
    if total_tokens != input_tokens + output_tokens:
        raise ModelResponseError("provider usage total_tokens is inconsistent")
    result: dict[str, Any] = {"input_tokens": input_tokens}
    if "input_tokens_details" in value:
        result["input_tokens_details"] = _usage_details(
            value["input_tokens_details"],
            label="input_tokens_details",
            allowed=("cached_tokens", "cache_write_tokens"),
            required=("cached_tokens",),
            parent_total=input_tokens,
        )
    result["output_tokens"] = output_tokens
    if "output_tokens_details" in value:
        result["output_tokens_details"] = _usage_details(
            value["output_tokens_details"],
            label="output_tokens_details",
            allowed=("reasoning_tokens",),
            required=("reasoning_tokens",),
            parent_total=output_tokens,
        )
    result["total_tokens"] = total_tokens
    return result


def _output_text(envelope: Mapping[str, Any]) -> str:
    top_candidate: str | None = None
    top_level = envelope.get("output_text")
    if top_level is not None:
        if not isinstance(top_level, str):
            raise ModelResponseError("provider output_text must be text")
        top_candidate = top_level
    nested_candidates: list[str] = []
    output = envelope.get("output")
    if output is not None:
        if not isinstance(output, list) or len(output) > 1024:
            raise ModelResponseError("provider output list is malformed")
        for item in output:
            if not isinstance(item, Mapping):
                raise ModelResponseError("provider output item is malformed")
            item_type = item.get("type")
            if isinstance(item_type, str) and "call" in item_type:
                raise ModelResponseError("provider returned a forbidden tool-call item")
            content = item.get("content", [])
            if not isinstance(content, list) or len(content) > 1024:
                raise ModelResponseError("provider output content is malformed")
            for child in content:
                if not isinstance(child, Mapping):
                    raise ModelResponseError("provider output content item is malformed")
                content_type = child.get("type")
                if content_type == "output_text":
                    text = child.get("text")
                    if not isinstance(text, str):
                        raise ModelResponseError("provider output content text is malformed")
                    nested_candidates.append(text)
                elif content_type == "refusal":
                    raise ModelResponseError("provider refused the structured-output request")
                elif content_type is not None:
                    raise ModelResponseError("provider returned unsupported output content")
    nested_candidate = "".join(nested_candidates) if nested_candidates else None
    if top_candidate is not None and nested_candidate is not None:
        if top_candidate != nested_candidate:
            raise ModelResponseError("provider output_text fields disagree")
        return top_candidate
    candidate = top_candidate if top_candidate is not None else nested_candidate
    if candidate is None:
        raise ModelResponseError("provider response contains no structured output text")
    return candidate


@dataclass(frozen=True, slots=True)
class ParsedResponsesEnvelope:
    """Immutable, schema-checked projection of one Responses envelope."""

    response_id: str
    model_returned: str
    usage: Mapping[str, Any] | None
    output: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "usage",
            freeze_json(self.usage) if self.usage is not None else None,
        )
        object.__setattr__(self, "output", freeze_json(self.output))


def parse_responses_envelope(
    envelope: Mapping[str, Any],
    *,
    expected_model: str,
    output_schema: Mapping[str, Any],
    maximum_output_bytes: int,
) -> ParsedResponsesEnvelope:
    """Parse exactly one supported Responses envelope and validate its output."""

    if not isinstance(envelope, Mapping) or envelope.get("status") != "completed":
        raise ModelResponseError("provider response is not complete")
    response_id = envelope.get("id")
    _bounded_text(response_id, "provider response id", maximum_bytes=256)
    model_returned = envelope.get("model")
    _bounded_text(model_returned, "returned model", maximum_bytes=256)
    if model_returned != expected_model:
        raise ModelResponseError("provider returned a different model identity")
    if (
        isinstance(maximum_output_bytes, bool)
        or not isinstance(maximum_output_bytes, int)
        or maximum_output_bytes <= 0
    ):
        raise ModelResponseError("structured model output byte bound is invalid")
    usage = _usage(envelope.get("usage"))
    output_text = _output_text(envelope)
    output_bytes = output_text.encode("utf-8")
    if len(output_bytes) > maximum_output_bytes:
        raise ModelResponseError("structured model output exceeds its byte bound")
    output = safe_json_loads(
        output_bytes,
        max_bytes=maximum_output_bytes,
        max_depth=MAX_SCHEMA_DEPTH,
        max_items=MAX_SCHEMA_ITEMS,
    )
    if not isinstance(output, Mapping):
        raise ModelResponseError("structured model output root must be an object")
    validate_structured_output(output, output_schema)
    return ParsedResponsesEnvelope(
        response_id=response_id,
        model_returned=model_returned,
        usage=usage,
        output=output,
    )


def _build_provider_gateway_classifier() -> Callable[[object], bool]:
    """Pin the exact gateway implementation used by the provider runtime."""

    exact_gateway_type = EgressGateway
    exact_namespace = tuple(vars(exact_gateway_type).items())
    exact_state_fields = {
        "_policy",
        "transport",
        "_registry",
        "_secret_resolver",
        "_clock",
        "_sleeper",
        "_timestamp",
        "_request_count",
        "_last_request_at",
        "_next_request_at",
        "_last_clock_at",
        "_admission_lock",
        "_authority_run_id",
        "_authority_ledger",
    }
    exact_methods = {
        name: exact_gateway_type.__dict__[name]
        for name in (
            "availability",
            "credential_status",
            "validate_idempotency_key",
            "validate_custody_bytes",
            "capture_custody_bytes",
            "capture_json_artifact",
            "execute",
            "parse_json",
        )
    }

    def classify(value: object) -> bool:
        try:
            state = vars(value)
            namespace = vars(exact_gateway_type)
        except (AttributeError, TypeError):
            return False
        if (
            type(value) is not exact_gateway_type
            or set(state) != exact_state_fields
            or len(namespace) != len(exact_namespace)
            or any(
                namespace.get(name) is not member
                for name, member in exact_namespace
            )
        ):
            return False
        for name, method in exact_methods.items():
            bound = getattr(value, name, None)
            if (
                getattr(bound, "__self__", None) is not value
                or getattr(bound, "__func__", None) is not method
            ):
                return False
        return True

    return classify


_is_exact_provider_gateway = _build_provider_gateway_classifier()
del _build_provider_gateway_classifier


class OpenAIResponsesProvider:
    """Structured-output OpenAI Responses implementation over an injected gateway."""

    def __init__(
        self,
        gateway: EgressGateway,
        *,
        config: OpenAIResponsesConfig | None = None,
    ) -> None:
        if not _is_exact_provider_gateway(gateway):
            raise ModelProviderError(
                "OpenAI provider requires the exact audited egress gateway"
            )
        if gateway.registry is None:
            raise ModelProviderError(
                "supported OpenAI provider execution requires immutable registry custody"
            )
        self.gateway = gateway
        self.config = config or OpenAIResponsesConfig()
        if gateway.policy.adapter_id != self.config.provider_id:
            raise ModelProviderError("provider and gateway adapter identities differ")

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            provider_id=self.config.provider_id,
            capabilities=self.config.supported_capabilities,
            structured_json=True,
            provider_tools=False,
        )

    def availability(self) -> ProviderAvailability:
        if not _is_exact_provider_gateway(self.gateway):
            raise ModelProviderError("provider gateway implementation changed")
        return ProviderAvailability(
            provider_id=self.config.provider_id,
            status=self.gateway.availability(),
            credential_status=self.gateway.credential_status(),
            network_used=self.gateway.network_used,
            transport_authority=self.gateway.transport_authority,
            scientific_evidence=False,
        )

    def _custody_valid(
        self,
        expectations: Sequence[tuple[ArtifactRecord, bytes, str]],
    ) -> bool:
        registry = self.gateway.registry
        if registry is None:
            return False
        try:
            return all(
                record.logical_type == logical_type
                and registry.verify(record.sha256)
                and registry.get_metadata(record.sha256) == record
                and registry.get_bytes(record.sha256) == expected
                for record, expected, logical_type in expectations
            )
        except Exception:
            return False

    def _result(
        self,
        invocation: ModelInvocation,
        *,
        status: ModelRunStatus,
        external_validation: str,
        network_used: bool,
        artifacts: Sequence[ArtifactRecord] = (),
        gateway_result: GatewayResult | None = None,
        output: Mapping[str, Any] | None = None,
        model_returned: str | None = None,
        response_id: str | None = None,
        usage: Mapping[str, Any] | None = None,
        error_code: str | None = None,
        terminal_receipt: ArtifactRecord | None = None,
        transport_authority: str | None = None,
    ) -> ModelResult:
        if status is ModelRunStatus.COMPLETED and (
            self.gateway.registry is None or not artifacts
        ):
            raise ModelProviderError(
                "completed provider output requires captured immutable provenance"
            )
        effective_transport_authority = (
            gateway_result.transport_authority
            if gateway_result is not None
            else transport_authority or self.gateway.transport_authority
        )
        if status is ModelRunStatus.COMPLETED and (
            (
                effective_transport_authority
                == AUDITED_LIVE_TRANSPORT_AUTHORITY
                and (
                    network_used is not True
                    or external_validation
                    != "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                )
            )
            or (
                effective_transport_authority
                == UNVERIFIED_TRANSPORT_AUTHORITY
                and external_validation != "UNTESTED"
            )
        ):
            raise ModelProviderError(
                "completed provider output transport authority is inconsistent"
            )
        provenance_status = (
            "TERMINAL_RECEIPT_CAPTURED"
            if terminal_receipt is not None
            else "CAPTURED"
            if artifacts
            else "NOT_CONFIGURED"
        )
        return ModelResult(
            invocation_id=invocation.invocation_id,
            provider_id=self.config.provider_id,
            capability=invocation.capability,
            model_requested=invocation.model,
            status=status,
            external_validation=external_validation,
            network_used=network_used,
            transport_authority=effective_transport_authority,
            transport_execution_authority_artifact_sha256=(
                gateway_result.transport_execution_authority_artifact.sha256
                if gateway_result is not None
                and gateway_result.transport_execution_authority_artifact
                is not None
                else None
            ),
            output=output,
            model_returned=model_returned,
            provider_response_id=response_id,
            usage=usage,
            request_id=gateway_result.request_id if gateway_result is not None else None,
            artifacts=tuple(artifacts),
            provenance_status=provenance_status,
            terminal_receipt=terminal_receipt,
            error_code=error_code,
            scientific_evidence=False,
        )

    def _terminal_result(
        self,
        invocation: ModelInvocation,
        *,
        status: ModelRunStatus,
        terminal_state: str,
        error_code: str,
        failure_class: str,
        failure_stage: str,
        external_validation: str,
        network_used: bool,
        artifacts: Sequence[ArtifactRecord],
        gateway_result: GatewayResult | None = None,
        request_id: str | None = None,
        attempts: Sequence[Mapping[str, object]] = (),
        transport_authority: str | None = None,
    ) -> ModelResult:
        if terminal_state not in {"BLOCKED", "FAILED"}:
            raise ModelProviderError("terminal receipt state is invalid")
        base_records = _records(*artifacts)
        effective_request_id = (
            gateway_result.request_id if gateway_result is not None else request_id
        )
        effective_attempts = (
            gateway_result.attempts if gateway_result is not None else attempts
        )
        effective_transport_authority = (
            gateway_result.transport_authority
            if gateway_result is not None
            else transport_authority or self.gateway.transport_authority
        )
        receipt = self.gateway.capture_json_artifact(
            {
                "schema_version": "1.0",
                "kind": "MODEL_INVOCATION_TERMINAL_RECEIPT",
                "invocation_id": _text_descriptor(invocation.invocation_id),
                "provider_id": self.config.provider_id,
                "capability": invocation.capability.value,
                "model": _text_descriptor(invocation.model),
                "terminal_state": terminal_state,
                "model_run_status": status.value,
                "error_code": error_code,
                "failure_class": failure_class,
                "failure_stage": failure_stage,
                "request_id": effective_request_id,
                "attempts": _bounded_attempt_metadata(effective_attempts),
                "credential_status": self.gateway.credential_status(),
                "network_used": network_used,
                "external_validation": external_validation,
                "transport_authority": effective_transport_authority,
                "captured_parent_hashes": [value.sha256 for value in base_records],
                "scientific_evidence": False,
                "secret_values_persisted": False,
            },
            logical_type="model_terminal_receipt",
            origin="terminal model-provider invocation outcome",
            creator_role=Role.ORCHESTRATOR,
            parents=tuple(value.sha256 for value in base_records),
        )
        records = _records(*base_records, receipt)
        return self._result(
            invocation,
            status=status,
            external_validation=external_validation,
            network_used=network_used,
            gateway_result=gateway_result,
            artifacts=records,
            error_code=error_code,
            terminal_receipt=receipt,
            transport_authority=effective_transport_authority,
        )

    def invoke(self, invocation: ModelInvocation) -> ModelResult:
        if not _is_exact_provider_gateway(self.gateway):
            raise ModelProviderError("provider gateway implementation changed")
        if not isinstance(invocation, ModelInvocation):
            raise ModelProviderError("provider invocation must be typed")
        schema = thaw_json(invocation.output_schema)
        instructions_bytes = invocation.instructions.encode("utf-8")
        input_bytes = invocation.input_text.encode("utf-8")
        schema_bytes = canonical_json_bytes(schema)
        provider_contract = require_provider_verifier(
            self.config.provider_id,
            MODEL_PROVIDER_CUSTODY_SCHEMA_V1,
        )
        body = provider_contract.build_request_body(
            retained_instructions=invocation.instructions,
            retained_input=invocation.input_text,
            retained_schema=schema,
            model_requested=invocation.model,
            maximum_output_tokens=invocation.max_output_tokens,
        )
        try:
            self.gateway.validate_idempotency_key(invocation.invocation_id)
            for exact_value in (
                instructions_bytes,
                input_bytes,
                schema_bytes,
                body,
            ):
                self.gateway.validate_custody_bytes(exact_value)
            instructions_artifact = self.gateway.capture_custody_bytes(
                instructions_bytes,
                logical_type="model_judged_instructions",
                origin="exact secret-scanned model instructions",
                creator_role=Role.ORCHESTRATOR,
                mime_type="text/plain",
            )
            input_artifact = self.gateway.capture_custody_bytes(
                input_bytes,
                logical_type="model_judged_input",
                origin="exact secret-scanned model input",
                creator_role=Role.ORCHESTRATOR,
                mime_type="text/plain",
            )
            schema_artifact = self.gateway.capture_custody_bytes(
                schema_bytes,
                logical_type="model_output_schema",
                origin="exact bounded structured-output schema",
                creator_role=Role.ORCHESTRATOR,
                mime_type="application/json",
            )
        except (EgressDeniedError, EgressPolicyError, ExternalUnavailableError):
            availability = self.availability()
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.EXTERNAL_ERROR,
                terminal_state="FAILED",
                error_code="PROVIDER_INPUT_CUSTODY_DENIED",
                failure_class="PROVIDER_INPUT_POLICY_DENIAL",
                failure_stage="INPUT_CUSTODY",
                external_validation=(
                    "BLOCKED_EXTERNAL"
                    if availability.status == "BLOCKED_EXTERNAL"
                    else self.gateway.external_validation
                ),
                network_used=False,
                artifacts=(),
            )
        custody_expectations: list[tuple[ArtifactRecord, bytes, str]] = [
            (instructions_artifact, instructions_bytes, "model_judged_instructions"),
            (input_artifact, input_bytes, "model_judged_input"),
            (schema_artifact, schema_bytes, "model_output_schema"),
        ]
        invocation_payload: dict[str, Any] = {
            "schema_version": "1.0",
            "kind": "MODEL_INVOCATION",
            "invocation_id": _text_descriptor(invocation.invocation_id),
            "provider_id": self.config.provider_id,
            "capability": invocation.capability.value,
            "model": _text_descriptor(invocation.model),
            "prompt_template": {
                "id": _text_descriptor(invocation.prompt_template_id),
                "version": _text_descriptor(invocation.prompt_template_version),
                "sha256": invocation.prompt_template_hash,
            },
            "instructions": _text_descriptor(invocation.instructions),
            "input_text": _text_descriptor(invocation.input_text),
            "input_artifact_hashes": list(invocation.input_artifact_hashes),
            "output_schema": {
                "sha256": sha256_bytes(canonical_json_bytes(schema)),
                "value_persisted": False,
            },
            "max_output_tokens": invocation.max_output_tokens,
            "provider_tools": False,
            "scientific_evidence": False,
            "secret_values_persisted": False,
        }
        invocation_artifact = self.gateway.capture_json_artifact(
            invocation_payload,
            logical_type="model_invocation",
            origin="capability-oriented model invocation",
            creator_role=Role.ORCHESTRATOR,
            parents=invocation.input_artifact_hashes,
        )
        if invocation_artifact is None:
            raise ModelProviderError("provider invocation custody was not captured")
        preliminary_records = _records(
            instructions_artifact,
            input_artifact,
            schema_artifact,
            invocation_artifact,
        )
        try:
            request_body_artifact = self.gateway.capture_custody_bytes(
                body,
                logical_type="model_provider_request_body",
                origin="exact secret-scanned model-provider request body",
                creator_role=Role.ORCHESTRATOR,
                mime_type="application/json",
            )
        except (EgressDeniedError, EgressPolicyError, ExternalUnavailableError):
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.EXTERNAL_ERROR,
                terminal_state="FAILED",
                error_code="PROVIDER_REQUEST_CUSTODY_DENIED",
                failure_class="PROVIDER_INPUT_POLICY_DENIAL",
                failure_stage="REQUEST_CUSTODY",
                external_validation=self.gateway.external_validation,
                network_used=False,
                artifacts=preliminary_records,
            )
        custody_expectations.append(
            (request_body_artifact, body, "model_provider_request_body")
        )
        intent_records = _records(*preliminary_records, request_body_artifact)
        if not self._custody_valid(custody_expectations):
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.EXTERNAL_ERROR,
                terminal_state="FAILED",
                error_code="PROVIDER_INPUT_CUSTODY_INVALID",
                failure_class="PROVIDER_PROVENANCE_FAILURE",
                failure_stage="INPUT_CUSTODY_READBACK",
                external_validation=self.gateway.external_validation,
                network_used=False,
                artifacts=intent_records,
            )
        if invocation.capability not in self.config.supported_capabilities:
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.EXTERNAL_ERROR,
                terminal_state="FAILED",
                error_code="CAPABILITY_NOT_ALLOWED",
                failure_class="PROVIDER_POLICY_DENIAL",
                failure_stage="PRE_REQUEST_POLICY",
                external_validation="BLOCKED_EXTERNAL",
                network_used=False,
                artifacts=intent_records,
            )
        if invocation.model not in self.config.allowed_models:
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.EXTERNAL_ERROR,
                terminal_state="FAILED",
                error_code="MODEL_NOT_ALLOWED",
                failure_class="PROVIDER_POLICY_DENIAL",
                failure_stage="PRE_REQUEST_POLICY",
                external_validation="BLOCKED_EXTERNAL",
                network_used=False,
                artifacts=intent_records,
            )
        if invocation.max_output_tokens > self.config.maximum_output_tokens:
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.EXTERNAL_ERROR,
                terminal_state="FAILED",
                error_code="TOKEN_BUDGET_NOT_ALLOWED",
                failure_class="PROVIDER_POLICY_DENIAL",
                failure_stage="PRE_REQUEST_POLICY",
                external_validation="BLOCKED_EXTERNAL",
                network_used=False,
                artifacts=intent_records,
            )

        try:
            _validate_openai_schema_admission(schema)
        except ModelSchemaError:
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.EXTERNAL_ERROR,
                terminal_state="FAILED",
                error_code="SCHEMA_NOT_SUPPORTED",
                failure_class="PROVIDER_POLICY_DENIAL",
                failure_stage="PRE_REQUEST_POLICY",
                external_validation="BLOCKED_EXTERNAL",
                network_used=False,
                artifacts=intent_records,
            )

        availability = self.availability()
        if availability.status == "BLOCKED_EXTERNAL":
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.BLOCKED_EXTERNAL,
                terminal_state="BLOCKED",
                error_code="PROVIDER_UNAVAILABLE",
                failure_class="EXTERNAL_UNAVAILABLE",
                failure_stage="AVAILABILITY",
                external_validation="BLOCKED_EXTERNAL",
                network_used=False,
                artifacts=intent_records,
            )
        request_intent_artifact: ArtifactRecord | None = None
        try:
            request = EgressRequest(
                adapter_id=self.config.provider_id,
                method="POST",
                url=self.config.endpoint,
                headers=(
                    ("Accept", "application/json"),
                    ("User-Agent", "Scientist-One-vNext/1"),
                ),
                body=body,
                content_type="application/json",
                target_source="CONFIGURED",
                idempotency_key=invocation.invocation_id,
            )
            request_intent_artifact = self.gateway.capture_json_artifact(
                {
                    "schema_version": "1.0",
                    "kind": "MODEL_PROVIDER_REQUEST_INTENT",
                    "invocation_artifact_sha256": (
                        invocation_artifact.sha256
                        if invocation_artifact is not None
                        else None
                    ),
                    "request_body_artifact_sha256": request_body_artifact.sha256,
                    "request_id": request.request_id,
                    "provider_id": self.config.provider_id,
                    "method": "POST",
                    "endpoint": OPENAI_RESPONSES_ENDPOINT,
                    "body_sha256": sha256_bytes(body),
                    "body_size": len(body),
                    "credential_value_persisted": False,
                    "scientific_evidence": False,
                },
                logical_type="model_provider_request_intent",
                origin="redacted model-provider request intent",
                creator_role=Role.ORCHESTRATOR,
                parents=_record_hashes(invocation_artifact, request_body_artifact),
            )
            if not _is_exact_provider_gateway(self.gateway):
                raise ModelProviderError("provider gateway implementation changed")
            result = self.gateway.execute(
                request,
                parent_artifacts=_record_hashes(
                    request_intent_artifact or invocation_artifact
                ),
            )
        except ExternalUnavailableError:
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.BLOCKED_EXTERNAL,
                terminal_state="BLOCKED",
                error_code="PROVIDER_UNAVAILABLE",
                failure_class="EXTERNAL_UNAVAILABLE",
                failure_stage="EGRESS",
                external_validation="BLOCKED_EXTERNAL",
                network_used=False,
                artifacts=_records(*intent_records, request_intent_artifact),
            )
        except TransportFailure as exc:
            failure_records = _records(
                *intent_records,
                request_intent_artifact,
                *exc.artifacts,
            )
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.BLOCKED_EXTERNAL,
                terminal_state="BLOCKED",
                error_code="TRANSPORT_UNAVAILABLE",
                failure_class="TRANSPORT_RETRY_EXHAUSTED",
                failure_stage="TRANSPORT",
                external_validation="BLOCKED_EXTERNAL",
                network_used=(
                    exc.network_used
                    if isinstance(exc.network_used, bool)
                    else self.gateway.network_used
                ),
                artifacts=failure_records,
                request_id=exc.request_id,
                attempts=exc.attempts,
                transport_authority=exc.transport_authority,
            )
        except EgressDeniedError as exc:
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.EXTERNAL_ERROR,
                terminal_state="FAILED",
                error_code="EGRESS_POLICY_DENIED",
                failure_class="EGRESS_POLICY_DENIAL",
                failure_stage="EGRESS",
                external_validation="BLOCKED_EXTERNAL",
                network_used=(
                    exc.network_used
                    if isinstance(exc.network_used, bool)
                    else False
                ),
                artifacts=_records(
                    *intent_records,
                    request_intent_artifact,
                    *exc.artifacts,
                ),
                request_id=exc.request_id,
                attempts=exc.attempts,
                transport_authority=exc.transport_authority,
            )
        except EgressPolicyError:
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.EXTERNAL_ERROR,
                terminal_state="FAILED",
                error_code="EGRESS_POLICY_DENIED",
                failure_class="EGRESS_POLICY_DENIAL",
                failure_stage="REQUEST_CONSTRUCTION",
                external_validation="BLOCKED_EXTERNAL",
                network_used=False,
                artifacts=_records(*intent_records, request_intent_artifact),
            )

        base_records = _records(
            *intent_records,
            request_intent_artifact,
            result.request_artifact,
            *result.attempt_raw_response_artifacts,
            result.raw_response_artifact,
            result.response_receipt_artifact,
            result.transport_execution_authority_artifact,
        )
        if not self._custody_valid(custody_expectations):
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.EXTERNAL_ERROR,
                terminal_state="FAILED",
                error_code="PROVIDER_INPUT_CUSTODY_INVALID",
                failure_class="PROVIDER_PROVENANCE_FAILURE",
                failure_stage="PRE_RESPONSE_PARSE_CUSTODY_READBACK",
                external_validation=result.external_validation,
                network_used=result.network_used,
                gateway_result=result,
                artifacts=base_records,
            )
        if result.retrieval_status != "CAPTURED":
            status = (
                ModelRunStatus.BLOCKED_EXTERNAL
                if result.status_code in {401, 403}
                else ModelRunStatus.EXTERNAL_ERROR
            )
            return self._terminal_result(
                invocation,
                status=status,
                terminal_state=(
                    "BLOCKED"
                    if status is ModelRunStatus.BLOCKED_EXTERNAL
                    else "FAILED"
                ),
                error_code=(
                    "AUTHENTICATION_REJECTED"
                    if status is ModelRunStatus.BLOCKED_EXTERNAL
                    else "PROVIDER_HTTP_ERROR"
                ),
                failure_class="NON_SUCCESS_HTTP_RESPONSE",
                failure_stage="HTTP_RESPONSE",
                external_validation=(
                    "BLOCKED_EXTERNAL"
                    if status is ModelRunStatus.BLOCKED_EXTERNAL
                    else result.external_validation
                ),
                network_used=result.network_used,
                gateway_result=result,
                artifacts=base_records,
            )

        if not _is_exact_provider_gateway(self.gateway):
            raise ModelProviderError("provider gateway implementation changed")
        try:
            envelope = self.gateway.parse_json(result)
        except ExternalParseError:
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.INVALID_RESPONSE,
                terminal_state="FAILED",
                error_code="INVALID_PROVIDER_JSON",
                failure_class="MALFORMED_PROVIDER_RESPONSE",
                failure_stage="RESPONSE_PARSE",
                external_validation=result.external_validation,
                network_used=result.network_used,
                gateway_result=result,
                artifacts=base_records,
            )
        if not isinstance(envelope, Mapping):
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.INVALID_RESPONSE,
                terminal_state="FAILED",
                error_code="INVALID_PROVIDER_ENVELOPE",
                failure_class="MALFORMED_PROVIDER_RESPONSE",
                failure_stage="RESPONSE_ENVELOPE",
                external_validation=result.external_validation,
                network_used=result.network_used,
                gateway_result=result,
                artifacts=base_records,
            )

        provider_response_payload: dict[str, Any] = {
            "schema_version": "1.0",
            "kind": "MODEL_PROVIDER_RESPONSE",
            "request_id": result.request_id,
            "raw_response_sha256": result.body_sha256,
            "response": dict(envelope),
            "network_used": result.network_used,
            "external_validation": result.external_validation,
            "transport_authority": result.transport_authority,
            "scientific_evidence": False,
        }
        if result.transport_execution_authority_artifact is not None:
            provider_response_payload[
                "transport_execution_authority_artifact_sha256"
            ] = result.transport_execution_authority_artifact.sha256
        envelope_artifact = self.gateway.capture_json_artifact(
            provider_response_payload,
            logical_type="model_provider_response",
            origin="strictly parsed model-provider response envelope",
            creator_role=Role.ORCHESTRATOR,
            parents=_record_hashes(
                result.raw_response_artifact,
                result.response_receipt_artifact,
                result.transport_execution_authority_artifact,
            ),
        )
        records_with_envelope = _records(*base_records, envelope_artifact)
        try:
            parsed_envelope = provider_contract.parse_and_project_response(
                raw_bytes=result.body,
                requested_model=invocation.model,
                output_schema=invocation.output_schema,
                maximum_output_bytes=self.gateway.policy.maximum_response_bytes,
                expected_request_id=result.request_id,
            )
            response_id = parsed_envelope.response_id
            model_returned = parsed_envelope.model_returned
            usage = parsed_envelope.usage
            output = parsed_envelope.output
        except (
            ModelProviderError,
            ProviderVerificationError,
            ValidationError,
            ValueError,
        ):
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.INVALID_RESPONSE,
                terminal_state="FAILED",
                error_code="STRUCTURED_OUTPUT_INVALID",
                failure_class="MALFORMED_STRUCTURED_OUTPUT",
                failure_stage="STRUCTURED_OUTPUT_VALIDATION",
                external_validation=result.external_validation,
                network_used=result.network_used,
                gateway_result=result,
                artifacts=records_with_envelope,
            )

        if not self._custody_valid(custody_expectations):
            return self._terminal_result(
                invocation,
                status=ModelRunStatus.EXTERNAL_ERROR,
                terminal_state="FAILED",
                error_code="PROVIDER_INPUT_CUSTODY_INVALID",
                failure_class="PROVIDER_PROVENANCE_FAILURE",
                failure_stage="STRUCTURED_OUTPUT_CUSTODY_READBACK",
                external_validation=result.external_validation,
                network_used=result.network_used,
                gateway_result=result,
                artifacts=records_with_envelope,
            )

        output_payload: dict[str, Any] = {
            "schema_version": "1.0",
            "kind": "MODEL_OUTPUT",
            "invocation_id": invocation.invocation_id,
            "provider_id": self.config.provider_id,
            "provider_response_id": response_id,
            "model_requested": invocation.model,
            "model_returned": model_returned,
            "capability": invocation.capability.value,
            "output": dict(output),
            "usage": dict(usage) if usage is not None else None,
            "network_used": result.network_used,
            "external_validation": result.external_validation,
            "transport_authority": result.transport_authority,
            "scientific_evidence": False,
            "provider_tools": False,
        }
        if result.transport_execution_authority_artifact is not None:
            output_payload[
                "transport_execution_authority_artifact_sha256"
            ] = result.transport_execution_authority_artifact.sha256
        output_artifact = self.gateway.capture_json_artifact(
            output_payload,
            logical_type="model_output",
            origin="schema-validated advisory model output",
            creator_role=Role.ORCHESTRATOR,
            parents=_record_hashes(
                invocation_artifact,
                request_body_artifact,
                envelope_artifact,
            ),
        )
        if output_artifact is None:
            raise ModelProviderError("provider output custody was not captured")
        return self._result(
            invocation,
            status=ModelRunStatus.COMPLETED,
            external_validation=result.external_validation,
            network_used=result.network_used,
            gateway_result=result,
            output=dict(output),
            model_returned=model_returned,
            response_id=response_id,
            usage=usage,
            artifacts=_records(*records_with_envelope, output_artifact),
        )


__all__ = [
    "ModelCapabilities",
    "ModelCapability",
    "ModelInvocation",
    "ModelProvider",
    "ModelProviderError",
    "ModelResponseError",
    "ModelResult",
    "ModelRunStatus",
    "ModelSchemaError",
    "OpenAIResponsesConfig",
    "OpenAIResponsesProvider",
    "ParsedResponsesEnvelope",
    "ProviderAvailability",
    "openai_responses_policy",
    "parse_responses_envelope",
    "validate_structured_output",
    "validate_structured_output_schema",
]
