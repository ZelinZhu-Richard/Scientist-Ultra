"""Source-owned validation for the closed model-provider wire protocols.

This module has no dependency on :mod:`scientist_one.providers`.  The closed
provider-verifier dispatch captures these functions when it is constructed so
later mutation of module attributes cannot replace a contract's parser.
"""

from __future__ import annotations

import math
from types import MappingProxyType
from typing import Any, Mapping

from .errors import ValidationError
from .security import canonical_json_bytes, safe_json_loads


MAX_SCHEMA_DEPTH = 32
MAX_SCHEMA_ITEMS = 50_000
MAX_SCHEMA_PROPERTIES = 256
MAX_SCHEMA_ARRAY_ITEMS = 10_000
MAX_SCHEMA_STRING_BYTES = 1024 * 1024

_SUPPORTED_SCHEMA_TYPES = frozenset(
    {"object", "array", "string", "integer", "number", "boolean", "null"}
)
_COMMON_SCHEMA_KEYS = frozenset({"type", "description", "enum"})
_TYPE_SCHEMA_KEYS: Mapping[str, frozenset[str]] = MappingProxyType({
    "object": frozenset({"properties", "required", "additionalProperties"}),
    "array": frozenset({"items", "minItems", "maxItems"}),
    "string": frozenset({"minLength", "maxLength"}),
    "integer": frozenset({"minimum", "maximum"}),
    "number": frozenset({"minimum", "maximum"}),
    "boolean": frozenset(),
    "null": frozenset(),
})


class ProviderWireError(ValidationError):
    """Native provider bytes violate their source-owned wire contract."""


def _bounded_text(
    value: object,
    label: str,
    *,
    maximum_bytes: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str) or (not value and not allow_empty) or "\x00" in value:
        raise ProviderWireError(f"{label} must be bounded UTF-8 text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ProviderWireError(f"{label} must be bounded UTF-8 text") from exc
    if len(encoded) > maximum_bytes:
        raise ProviderWireError(f"{label} exceeds its byte limit")
    return value


def _bounded_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProviderWireError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ProviderWireError(f"{label} is outside its allowed range")
    return value


def _finite_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProviderWireError(f"{label} must be numeric")
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise ProviderWireError(f"{label} must be finite") from exc
    if not math.isfinite(number):
        raise ProviderWireError(f"{label} must be finite")
    return number


def _schema_enum_key(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise ProviderWireError("schema enum values must be finite JSON") from exc


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


def _validate_schema_node(
    schema: Any,
    *,
    depth: int,
    budget: list[int],
) -> None:
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_SCHEMA_DEPTH:
        raise ProviderWireError(
            "structured-output schema exceeds its complexity bound"
        )
    if not isinstance(schema, Mapping):
        raise ProviderWireError(
            "every structured-output schema node must be an object"
        )
    if any(not isinstance(key, str) for key in schema):
        raise ProviderWireError("structured-output schema keys must be strings")
    schema_type = schema.get("type")
    if not isinstance(schema_type, str) or schema_type not in _SUPPORTED_SCHEMA_TYPES:
        raise ProviderWireError(
            "structured-output schema requires one supported scalar type"
        )
    allowed = _COMMON_SCHEMA_KEYS | _TYPE_SCHEMA_KEYS[schema_type]
    if set(schema) - allowed:
        raise ProviderWireError(
            "structured-output schema contains unsupported keywords"
        )
    description = schema.get("description")
    if description is not None:
        _bounded_text(description, "schema description", maximum_bytes=4096)

    enum = schema.get("enum")
    if enum is not None:
        if not isinstance(enum, (list, tuple)) or not enum or len(enum) > 256:
            raise ProviderWireError(
                "schema enum must be a non-empty bounded sequence"
            )
        if any(not _matches_type(item, schema_type) for item in enum):
            raise ProviderWireError(
                "schema enum value does not match its declared type"
            )
        enum_keys = tuple(_schema_enum_key(item) for item in enum)
        if len(set(enum_keys)) != len(enum_keys):
            raise ProviderWireError("schema enum values must be unique")
        if sum(len(item) for item in enum_keys) > MAX_SCHEMA_STRING_BYTES:
            raise ProviderWireError("schema enum exceeds its byte bound")

    if schema_type == "object":
        properties = schema.get("properties")
        required = schema.get("required")
        if not isinstance(properties, Mapping) or len(properties) > MAX_SCHEMA_PROPERTIES:
            raise ProviderWireError("object schema requires bounded properties")
        if any(
            not isinstance(key, str)
            or not key
            or len(key.encode("utf-8")) > 128
            for key in properties
        ):
            raise ProviderWireError("object schema property names are invalid")
        if not isinstance(required, (list, tuple)):
            raise ProviderWireError("object schema requires an explicit required list")
        if (
            any(not isinstance(item, str) for item in required)
            or len(set(required)) != len(required)
            or set(required) != set(properties)
        ):
            raise ProviderWireError(
                "strict object schemas must require every property exactly once"
            )
        if schema.get("additionalProperties") is not False:
            raise ProviderWireError(
                "strict object schemas must forbid additional properties"
            )
        for child in properties.values():
            _validate_schema_node(child, depth=depth + 1, budget=budget)
        return

    if schema_type == "array":
        if "items" not in schema:
            raise ProviderWireError("array schema requires an item schema")
        maximum = _bounded_int(
            schema.get("maxItems"),
            "schema maxItems",
            0,
            MAX_SCHEMA_ARRAY_ITEMS,
        )
        minimum = _bounded_int(
            schema.get("minItems", 0), "schema minItems", 0, maximum
        )
        if minimum > maximum:
            raise ProviderWireError("schema minItems exceeds maxItems")
        _validate_schema_node(schema["items"], depth=depth + 1, budget=budget)
        return

    if schema_type == "string":
        maximum = schema.get("maxLength")
        if maximum is None and enum is None:
            raise ProviderWireError("string schemas require maxLength or an enum")
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
                raise ProviderWireError("schema minLength exceeds maxLength")
        return

    if schema_type in {"integer", "number"}:
        if "minimum" not in schema or "maximum" not in schema:
            raise ProviderWireError(
                "numeric schemas require finite minimum and maximum"
            )
        minimum = _finite_number(schema["minimum"], "schema minimum")
        maximum = _finite_number(schema["maximum"], "schema maximum")
        if minimum > maximum:
            raise ProviderWireError("schema minimum exceeds maximum")


def _validate_schema(schema: Mapping[str, Any]) -> None:
    _validate_schema_node(schema, depth=0, budget=[MAX_SCHEMA_ITEMS])
    if schema.get("type") != "object":
        raise ProviderWireError("the provider output schema root must be an object")


def _validate_output_node(
    value: Any,
    schema: Mapping[str, Any],
    *,
    depth: int,
    budget: list[int],
) -> None:
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_SCHEMA_DEPTH:
        raise ProviderWireError(
            "model output exceeds the structured-output complexity bound"
        )
    schema_type = schema["type"]
    if not _matches_type(value, schema_type):
        raise ProviderWireError(
            "model output does not match the requested scalar type"
        )
    if "enum" in schema:
        candidate = _schema_enum_key(value)
        if candidate not in {_schema_enum_key(item) for item in schema["enum"]}:
            raise ProviderWireError("model output is outside the requested enum")

    if schema_type == "object":
        properties = schema["properties"]
        if set(value) != set(properties):
            raise ProviderWireError(
                "model output object fields differ from the strict schema"
            )
        for key, child_schema in properties.items():
            _validate_output_node(
                value[key], child_schema, depth=depth + 1, budget=budget
            )
    elif schema_type == "array":
        if len(value) < schema.get("minItems", 0) or len(value) > schema["maxItems"]:
            raise ProviderWireError("model output array length violates the schema")
        for child in value:
            _validate_output_node(
                child, schema["items"], depth=depth + 1, budget=budget
            )
    elif schema_type == "string":
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ProviderWireError(
                "model output string is shorter than the schema"
            )
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ProviderWireError("model output string is longer than the schema")
        if len(value.encode("utf-8")) > MAX_SCHEMA_STRING_BYTES:
            raise ProviderWireError(
                "model output string exceeds its absolute byte bound"
            )
    elif schema_type in {"integer", "number"}:
        try:
            number = float(value)
        except (OverflowError, ValueError) as exc:
            raise ProviderWireError("model output numeric value is non-finite") from exc
        if not math.isfinite(number):
            raise ProviderWireError("model output numeric value is non-finite")
        if number < float(schema["minimum"]) or number > float(schema["maximum"]):
            raise ProviderWireError(
                "model output numeric value is outside the schema"
            )


def _validate_output(value: Any, schema: Mapping[str, Any]) -> None:
    _validate_schema(schema)
    _validate_output_node(value, schema, depth=0, budget=[MAX_SCHEMA_ITEMS])


def _usage_count(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10**12:
        raise ProviderWireError(f"provider usage {label} is invalid")
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
        raise ProviderWireError(f"provider usage {label} must be an object")
    if set(value) - set(allowed) or not set(required).issubset(value):
        raise ProviderWireError(f"provider usage {label} contains invalid fields")
    details = {
        key: _usage_count(value[key], f"{label}.{key}")
        for key in allowed
        if key in value
    }
    if any(count > parent_total for count in details.values()):
        raise ProviderWireError(
            f"provider usage {label} exceeds its parent token count"
        )
    return details


def _usage(value: Any) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ProviderWireError("provider usage must be an object")
    required = {"input_tokens", "output_tokens", "total_tokens"}
    allowed = required | {"input_tokens_details", "output_tokens_details"}
    if set(value) - allowed or not required.issubset(value):
        raise ProviderWireError("provider usage contains unknown fields")
    input_tokens = _usage_count(value["input_tokens"], "input_tokens")
    output_tokens = _usage_count(value["output_tokens"], "output_tokens")
    total_tokens = _usage_count(value["total_tokens"], "total_tokens")
    if total_tokens != input_tokens + output_tokens:
        raise ProviderWireError("provider usage total_tokens is inconsistent")
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


def _openai_output_text(envelope: Mapping[str, Any]) -> str:
    top_candidate: str | None = None
    top_level = envelope.get("output_text")
    if top_level is not None:
        if not isinstance(top_level, str):
            raise ProviderWireError("provider output_text must be text")
        top_candidate = top_level
    nested_candidates: list[str] = []
    output = envelope.get("output")
    if output is not None:
        if not isinstance(output, list) or len(output) > 1024:
            raise ProviderWireError("provider output list is malformed")
        for item in output:
            if not isinstance(item, Mapping):
                raise ProviderWireError("provider output item is malformed")
            item_type = item.get("type")
            if isinstance(item_type, str) and "call" in item_type:
                raise ProviderWireError("provider returned a forbidden tool-call item")
            content = item.get("content", [])
            if not isinstance(content, list) or len(content) > 1024:
                raise ProviderWireError("provider output content is malformed")
            for child in content:
                if not isinstance(child, Mapping):
                    raise ProviderWireError(
                        "provider output content item is malformed"
                    )
                content_type = child.get("type")
                if content_type == "output_text":
                    text = child.get("text")
                    if not isinstance(text, str):
                        raise ProviderWireError(
                            "provider output content text is malformed"
                        )
                    nested_candidates.append(text)
                elif content_type == "refusal":
                    raise ProviderWireError(
                        "provider refused the structured-output request"
                    )
                elif content_type is not None:
                    raise ProviderWireError(
                        "provider returned unsupported output content"
                    )
    nested_candidate = "".join(nested_candidates) if nested_candidates else None
    if top_candidate is not None and nested_candidate is not None:
        if top_candidate != nested_candidate:
            raise ProviderWireError("provider output_text fields disagree")
        return top_candidate
    candidate = top_candidate if top_candidate is not None else nested_candidate
    if candidate is None:
        raise ProviderWireError(
            "provider response contains no structured output text"
        )
    return candidate


def _parse_output_text(
    output_text: object,
    *,
    output_schema: Mapping[str, Any],
    maximum_output_bytes: int,
) -> Mapping[str, Any]:
    if not isinstance(output_text, str) or not output_text or "\x00" in output_text:
        raise ProviderWireError("provider structured output is invalid")
    output_bytes = output_text.encode("utf-8")
    if len(output_bytes) > maximum_output_bytes:
        raise ProviderWireError(
            "provider structured output exceeds its byte bound"
        )
    output = safe_json_loads(
        output_bytes,
        max_bytes=maximum_output_bytes,
        max_depth=MAX_SCHEMA_DEPTH,
        max_items=MAX_SCHEMA_ITEMS,
    )
    if not isinstance(output, Mapping):
        raise ProviderWireError("provider structured output root must be an object")
    _validate_output(output, output_schema)
    return output


def parse_openai_response_wire(
    raw_bytes: bytes,
    *,
    requested_model: str,
    output_schema: Mapping[str, Any],
    maximum_output_bytes: int,
    expected_request_id: str,
) -> tuple[str, str, Mapping[str, Any] | None, Mapping[str, Any]]:
    """Parse the supported OpenAI Responses v1 envelope."""

    del expected_request_id  # The OpenAI response body has no request-reference field.
    envelope = safe_json_loads(
        raw_bytes,
        max_bytes=maximum_output_bytes,
        max_depth=64,
        max_items=250_000,
    )
    if not isinstance(envelope, Mapping) or envelope.get("status") != "completed":
        raise ProviderWireError("OpenAI response is not complete")
    response_id = _bounded_text(
        envelope.get("id"), "provider response ID", maximum_bytes=256
    )
    model_returned = _bounded_text(
        envelope.get("model"), "provider returned model", maximum_bytes=256
    )
    if model_returned != requested_model:
        raise ProviderWireError("provider returned a different model identity")
    usage = _usage(envelope.get("usage"))
    output = _parse_output_text(
        _openai_output_text(envelope),
        output_schema=output_schema,
        maximum_output_bytes=maximum_output_bytes,
    )
    return response_id, model_returned, usage, output


def parse_deterministic_fixture_response_wire(
    raw_bytes: bytes,
    *,
    requested_model: str,
    output_schema: Mapping[str, Any],
    maximum_output_bytes: int,
    expected_request_id: str,
) -> tuple[str, str, Mapping[str, Any] | None, Mapping[str, Any]]:
    """Parse the deliberately distinct deterministic-fixture envelope."""

    envelope = safe_json_loads(
        raw_bytes,
        max_bytes=maximum_output_bytes,
        max_depth=64,
        max_items=250_000,
    )
    if not isinstance(envelope, Mapping) or set(envelope) != {
        "fixture_protocol",
        "request_ref",
        "engine",
        "response_ref",
        "state",
        "result_json",
        "metering",
    }:
        raise ProviderWireError(
            "deterministic response has missing or unknown fields"
        )
    if (
        envelope.get("fixture_protocol") != "deterministic-fixture-wire/v1"
        or envelope.get("request_ref") != expected_request_id
        or envelope.get("state") != "done"
    ):
        raise ProviderWireError("deterministic response context is invalid")
    response_id = _bounded_text(
        envelope.get("response_ref"), "provider response ID", maximum_bytes=256
    )
    model_returned = _bounded_text(
        envelope.get("engine"), "provider returned model", maximum_bytes=256
    )
    if model_returned != requested_model:
        raise ProviderWireError("provider returned a different model identity")
    metering = envelope.get("metering")
    if not isinstance(metering, Mapping) or set(metering) != {
        "prompt_units",
        "prompt_unit_details",
        "result_units",
        "result_unit_details",
        "total_units",
    }:
        raise ProviderWireError("deterministic response metering is invalid")
    usage_value: dict[str, Any] = {
        "input_tokens": metering.get("prompt_units"),
        "output_tokens": metering.get("result_units"),
        "total_tokens": metering.get("total_units"),
    }
    if metering.get("prompt_unit_details") is not None:
        usage_value["input_tokens_details"] = metering["prompt_unit_details"]
    if metering.get("result_unit_details") is not None:
        usage_value["output_tokens_details"] = metering["result_unit_details"]
    usage = _usage(usage_value)
    output = _parse_output_text(
        envelope.get("result_json"),
        output_schema=output_schema,
        maximum_output_bytes=maximum_output_bytes,
    )
    return response_id, model_returned, usage, output


def capture_response_wire_parsers():
    """Capture exact parsers plus their full source-owned helper namespace.

    The returned closures fail closed if any parser, transitive helper,
    imported primitive, or wire-validation constant is rebound or has its code
    replaced after capture.  The closed dispatch calls this factory exactly
    once during import and retains only the resulting closures.
    """

    namespace = globals()
    names = (
        "Mapping",
        "ProviderWireError",
        "canonical_json_bytes",
        "safe_json_loads",
        "math",
        "MAX_SCHEMA_DEPTH",
        "MAX_SCHEMA_ITEMS",
        "MAX_SCHEMA_PROPERTIES",
        "MAX_SCHEMA_ARRAY_ITEMS",
        "MAX_SCHEMA_STRING_BYTES",
        "_SUPPORTED_SCHEMA_TYPES",
        "_COMMON_SCHEMA_KEYS",
        "_TYPE_SCHEMA_KEYS",
        "_bounded_text",
        "_bounded_int",
        "_finite_number",
        "_schema_enum_key",
        "_matches_type",
        "_validate_schema_node",
        "_validate_schema",
        "_validate_output_node",
        "_validate_output",
        "_usage_count",
        "_usage_details",
        "_usage",
        "_openai_output_text",
        "_parse_output_text",
        "parse_openai_response_wire",
        "parse_deterministic_fixture_response_wire",
    )
    snapshot = tuple(
        (
            name,
            namespace[name],
            getattr(namespace[name], "__code__", None),
            getattr(namespace[name], "__defaults__", None),
            getattr(namespace[name], "__kwdefaults__", None),
        )
        for name in names
    )
    openai_parser = parse_openai_response_wire
    deterministic_parser = parse_deterministic_fixture_response_wire
    wire_error_type = ProviderWireError

    def assert_exact_namespace() -> None:
        for name, expected, code, defaults, keyword_defaults in snapshot:
            current = namespace.get(name)
            if (
                current is not expected
                or getattr(current, "__code__", None) is not code
                or getattr(current, "__defaults__", None) != defaults
                or getattr(current, "__kwdefaults__", None) != keyword_defaults
            ):
                raise wire_error_type(
                    "provider wire parser namespace changed after closed dispatch"
                )

    def checked_openai_parser(*args: Any, **kwargs: Any):
        assert_exact_namespace()
        result = openai_parser(*args, **kwargs)
        assert_exact_namespace()
        return result

    def checked_deterministic_parser(*args: Any, **kwargs: Any):
        assert_exact_namespace()
        result = deterministic_parser(*args, **kwargs)
        assert_exact_namespace()
        return result

    return checked_openai_parser, checked_deterministic_parser


__all__ = [
    "ProviderWireError",
    "capture_response_wire_parsers",
    "parse_deterministic_fixture_response_wire",
    "parse_openai_response_wire",
]
