"""Closed, provider-neutral dispatch contracts for captured model execution.

The dispatch is source-owned and intentionally exposes no registration API.
Provider-specific consumers replay their complete custody graphs against the
returned frozen metadata facade and then return a neutral
``ProviderExecutionProjection``.  Model output remains advisory and can never
assert scientific evidence through this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .errors import ValidationError
from .external import (
    AUDITED_LIVE_TRANSPORT_AUTHORITY,
    UNVERIFIED_TRANSPORT_AUTHORITY,
)
from .models import freeze_json, validate_identifier, validate_sha256
from .provider_wire import (
    ProviderWireError,
    capture_response_wire_parsers as _capture_response_wire_parsers,
)
from .security import canonical_json_bytes, sha256_bytes


MODEL_PROVIDER_CUSTODY_SCHEMA_V1 = "1.0"
OPENAI_PROVIDER_ID = "openai"
OPENAI_RESPONSES_POLICY_VERSION = "openai-responses-v1"
OPENAI_RESPONSES_ENDPOINT = "https://api.openai.com/v1/responses"
OPENAI_CREDENTIAL_ENV_NAME = "OPENAI_API_KEY"
DETERMINISTIC_FIXTURE_PROVIDER_ID = "deterministic-fixture"
DETERMINISTIC_FIXTURE_PROVIDER_VERSION = "deterministic-responses-fixture-v1"
DETERMINISTIC_FIXTURE_ENDPOINT = (
    "https://deterministic-fixture.invalid/v1/responses"
)
OPENAI_RESPONSES_WIRE_V1 = "openai-responses-wire/v1"
DETERMINISTIC_FIXTURE_WIRE_V1 = "deterministic-fixture-wire/v1"

(_openai_response_parser, _deterministic_response_parser) = (
    _capture_response_wire_parsers()
)
del _capture_response_wire_parsers


class ProviderVerificationError(ValidationError):
    """A provider graph has no exact source-owned verifier contract."""


@dataclass(frozen=True, slots=True)
class ProviderRequestProjection:
    """Provider-neutral facts derived from one exact native request body."""

    provider_id: str
    provenance_schema_version: str
    wire_protocol: str
    request_id: str
    body_sha256: str
    body_size: int
    model_requested: str
    maximum_output_tokens: int

    def __post_init__(self) -> None:
        validate_identifier(self.provider_id, "provider request projection provider")
        if self.provenance_schema_version != MODEL_PROVIDER_CUSTODY_SCHEMA_V1:
            raise ProviderVerificationError(
                "provider request projection schema is unsupported"
            )
        if self.wire_protocol not in {
            OPENAI_RESPONSES_WIRE_V1,
            DETERMINISTIC_FIXTURE_WIRE_V1,
        }:
            raise ProviderVerificationError(
                "provider request projection wire protocol is unsupported"
            )
        validate_sha256(self.request_id, "provider request projection ID")
        validate_sha256(self.body_sha256, "provider request projection body")
        if (
            not isinstance(self.body_size, int)
            or isinstance(self.body_size, bool)
            or self.body_size <= 0
            or not isinstance(self.maximum_output_tokens, int)
            or isinstance(self.maximum_output_tokens, bool)
            or not 1 <= self.maximum_output_tokens <= 100_000
            or not isinstance(self.model_requested, str)
            or not self.model_requested
            or "\x00" in self.model_requested
            or len(self.model_requested.encode("utf-8")) > 256
        ):
            raise ProviderVerificationError(
                "provider request projection bounds are invalid"
            )


@dataclass(frozen=True, slots=True)
class ProviderResponseProjection:
    """Provider-neutral facts parsed from one exact native response body."""

    provider_id: str
    provenance_schema_version: str
    wire_protocol: str
    request_id: str
    raw_sha256: str
    raw_size: int
    response_id: str
    model_returned: str
    usage: Mapping[str, Any] | None
    output: Mapping[str, Any]

    def __post_init__(self) -> None:
        validate_identifier(self.provider_id, "provider response projection provider")
        if self.provenance_schema_version != MODEL_PROVIDER_CUSTODY_SCHEMA_V1:
            raise ProviderVerificationError(
                "provider response projection schema is unsupported"
            )
        if self.wire_protocol not in {
            OPENAI_RESPONSES_WIRE_V1,
            DETERMINISTIC_FIXTURE_WIRE_V1,
        }:
            raise ProviderVerificationError(
                "provider response projection wire protocol is unsupported"
            )
        validate_sha256(self.request_id, "provider response projection request ID")
        validate_sha256(self.raw_sha256, "provider response projection raw body")
        if (
            not isinstance(self.raw_size, int)
            or isinstance(self.raw_size, bool)
            or self.raw_size <= 0
        ):
            raise ProviderVerificationError(
                "provider response projection raw byte size is invalid"
            )
        for label, value in (
            ("provider response projection ID", self.response_id),
            ("provider response projection model", self.model_returned),
        ):
            if (
                not isinstance(value, str)
                or not value
                or "\x00" in value
                or len(value.encode("utf-8")) > 256
            ):
                raise ProviderVerificationError(f"{label} is invalid")
        try:
            if not isinstance(self.output, Mapping) or (
                self.usage is not None and not isinstance(self.usage, Mapping)
            ):
                raise ProviderVerificationError(
                    "provider response projection payload is invalid"
                )
            object.__setattr__(
                self,
                "usage",
                freeze_json(self.usage) if self.usage is not None else None,
            )
            object.__setattr__(self, "output", freeze_json(self.output))
        except ValidationError as exc:
            raise ProviderVerificationError(
                "provider response projection is invalid"
            ) from exc


@dataclass(frozen=True, slots=True)
class _ProviderVerifierImplementation:
    """Hidden executable implementation retained only by the closed dispatch."""

    provider_id: str
    provenance_schema_version: str
    provider_version: str
    endpoint: str
    credential_env_name: str | None
    credential_present: bool
    audited_live_allowed: bool
    wire_protocol: str
    _response_parser: Callable[..., tuple[
        str,
        str,
        Mapping[str, Any] | None,
        Mapping[str, Any],
    ]] = field(repr=False, compare=False)
    _response_parser_code: Any = field(
        init=False,
        repr=False,
        compare=False,
    )
    _response_parser_defaults: Any = field(
        init=False,
        repr=False,
        compare=False,
    )
    _response_parser_keyword_defaults: Any = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        validate_identifier(self.provider_id, "provider verifier ID")
        if self.provenance_schema_version != MODEL_PROVIDER_CUSTODY_SCHEMA_V1:
            raise ProviderVerificationError(
                "provider verifier provenance schema is unsupported"
            )
        for label, value in (
            ("provider verifier version", self.provider_version),
            ("provider verifier endpoint", self.endpoint),
        ):
            if (
                not isinstance(value, str)
                or not value
                or "\x00" in value
                or len(value.encode("utf-8")) > 8192
            ):
                raise ProviderVerificationError(f"{label} is invalid")
        if self.credential_env_name is not None:
            validate_identifier(
                self.credential_env_name,
                "provider verifier credential environment name",
            )
        if not isinstance(self.credential_present, bool) or not isinstance(
            self.audited_live_allowed,
            bool,
        ):
            raise ProviderVerificationError(
                "provider verifier trust flags must be booleans"
            )
        if self.credential_present is not (self.credential_env_name is not None):
            raise ProviderVerificationError(
                "provider verifier credential projection is inconsistent"
            )
        if self.wire_protocol not in {
            OPENAI_RESPONSES_WIRE_V1,
            DETERMINISTIC_FIXTURE_WIRE_V1,
        }:
            raise ProviderVerificationError(
                "provider verifier wire protocol is unsupported"
            )
        parser_code = getattr(self._response_parser, "__code__", None)
        if not callable(self._response_parser) or parser_code is None:
            raise ProviderVerificationError(
                "provider verifier response parser is invalid"
            )
        object.__setattr__(self, "_response_parser_code", parser_code)
        object.__setattr__(
            self,
            "_response_parser_defaults",
            getattr(self._response_parser, "__defaults__", None),
        )
        keyword_defaults = getattr(self._response_parser, "__kwdefaults__", None)
        object.__setattr__(
            self,
            "_response_parser_keyword_defaults",
            dict(keyword_defaults) if keyword_defaults is not None else None,
        )

    def _response_parser_is_exact(self) -> bool:
        return (
            getattr(self._response_parser, "__code__", None)
            is self._response_parser_code
            and getattr(self._response_parser, "__defaults__", None)
            == self._response_parser_defaults
            and getattr(self._response_parser, "__kwdefaults__", None)
            == self._response_parser_keyword_defaults
        )

    @property
    def key(self) -> tuple[str, str]:
        return (self.provider_id, self.provenance_schema_version)

    def expected_request_id(self, body: bytes, invocation_id: str) -> str:
        """Derive the exact gateway request identity for this provider contract."""

        if not isinstance(body, bytes):
            raise ProviderVerificationError("provider request body must be bytes")
        return self.expected_request_id_from_projection(
            body_sha256=sha256_bytes(body),
            body_size=len(body),
            invocation_id=invocation_id,
        )

    def expected_request_id_from_projection(
        self,
        *,
        body_sha256: str,
        body_size: int,
        invocation_id: str,
    ) -> str:
        """Derive request identity from exact source-owned wire-byte facts."""

        validate_sha256(body_sha256, "provider request body SHA-256")
        if (
            not isinstance(body_size, int)
            or isinstance(body_size, bool)
            or body_size <= 0
        ):
            raise ProviderVerificationError("provider request body size is invalid")
        validate_identifier(invocation_id, "provider invocation ID")
        return sha256_bytes(
            canonical_json_bytes(
                {
                    "adapter_id": self.provider_id,
                    "method": "POST",
                    "url": self.endpoint,
                    "headers": [
                        ["Accept", "application/json"],
                        ["User-Agent", "Scientist-One-vNext/1"],
                    ],
                    "body_sha256": body_sha256,
                    "body_size": body_size,
                    "content_type": "application/json",
                    "target_source": "CONFIGURED",
                    "idempotency_key": invocation_id,
                }
            )
        )

    def build_request_body(
        self,
        *,
        retained_instructions: str,
        retained_input: str,
        retained_schema: Mapping[str, Any],
        model_requested: str,
        maximum_output_tokens: int,
    ) -> bytes:
        """Build the one native request grammar owned by this contract."""

        if (
            not isinstance(retained_instructions, str)
            or not isinstance(retained_input, str)
            or not isinstance(retained_schema, Mapping)
            or not isinstance(model_requested, str)
            or not model_requested
            or "\x00" in model_requested
            or len(model_requested.encode("utf-8")) > 256
            or isinstance(maximum_output_tokens, bool)
            or not isinstance(maximum_output_tokens, int)
            or not 1 <= maximum_output_tokens <= 100_000
        ):
            raise ProviderVerificationError(
                "provider request construction inputs are invalid"
            )
        if self.wire_protocol == OPENAI_RESPONSES_WIRE_V1:
            value = {
                "model": model_requested,
                "instructions": retained_instructions,
                "input": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "input_text", "text": retained_input}
                        ],
                    }
                ],
                "max_output_tokens": maximum_output_tokens,
                "store": False,
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "scientist_one_output",
                        "strict": True,
                        "schema": dict(retained_schema),
                    }
                },
                "tool_choice": "none",
                "tools": [],
                "truncation": "disabled",
            }
        else:
            value = {
                "fixture_protocol": DETERMINISTIC_FIXTURE_WIRE_V1,
                "engine": model_requested,
                "system": retained_instructions,
                "prompt": retained_input,
                "response_contract": {
                    "encoding": "canonical-json",
                    "strict": True,
                    "schema": dict(retained_schema),
                },
                "limit": maximum_output_tokens,
            }
        return canonical_json_bytes(value)

    def validate_and_project_request(
        self,
        *,
        body_bytes: bytes,
        retained_instructions: str,
        retained_input: str,
        retained_schema: Mapping[str, Any],
        invocation_id: str,
        model_requested: str,
        maximum_output_tokens: int,
    ) -> ProviderRequestProjection:
        """Validate native request bytes and return only neutral facts."""

        if not isinstance(body_bytes, bytes):
            raise ProviderVerificationError("provider request body must be bytes")
        expected = self.build_request_body(
            retained_instructions=retained_instructions,
            retained_input=retained_input,
            retained_schema=retained_schema,
            model_requested=model_requested,
            maximum_output_tokens=maximum_output_tokens,
        )
        if body_bytes != expected:
            raise ProviderVerificationError(
                "provider request body violates its native wire contract"
            )
        return ProviderRequestProjection(
            provider_id=self.provider_id,
            provenance_schema_version=self.provenance_schema_version,
            wire_protocol=self.wire_protocol,
            request_id=self.expected_request_id(body_bytes, invocation_id),
            body_sha256=sha256_bytes(body_bytes),
            body_size=len(body_bytes),
            model_requested=model_requested,
            maximum_output_tokens=maximum_output_tokens,
        )

    def parse_and_project_response(
        self,
        *,
        raw_bytes: bytes,
        requested_model: str,
        output_schema: Mapping[str, Any],
        maximum_output_bytes: int,
        expected_request_id: str,
    ) -> ProviderResponseProjection:
        """Parse the native response grammar and return only neutral facts."""

        if (
            not isinstance(raw_bytes, bytes)
            or isinstance(maximum_output_bytes, bool)
            or not isinstance(maximum_output_bytes, int)
            or maximum_output_bytes <= 0
        ):
            raise ProviderVerificationError(
                "provider response parsing inputs are invalid"
            )
        validate_sha256(expected_request_id, "provider response request ID")
        if not self._response_parser_is_exact():
            raise ProviderVerificationError(
                "provider response parser changed after closed dispatch"
            )
        try:
            response_id, model_returned, usage, output = self._response_parser(
                raw_bytes,
                requested_model=requested_model,
                output_schema=output_schema,
                maximum_output_bytes=maximum_output_bytes,
                expected_request_id=expected_request_id,
            )
        except (ProviderWireError, ValidationError, ValueError) as exc:
            raise ProviderVerificationError(
                "provider response violates its native wire contract"
            ) from exc
        if not self._response_parser_is_exact():
            raise ProviderVerificationError(
                "provider response parser changed during native parsing"
            )
        return ProviderResponseProjection(
            provider_id=self.provider_id,
            provenance_schema_version=self.provenance_schema_version,
            wire_protocol=self.wire_protocol,
            request_id=expected_request_id,
            raw_sha256=sha256_bytes(raw_bytes),
            raw_size=len(raw_bytes),
            response_id=response_id,
            model_returned=model_returned,
            usage=usage,
            output=output,
        )

    def validate_response_headers(
        self,
        headers: Mapping[str, Any],
        *,
        body_size: int,
    ) -> None:
        """Validate provider-specific retained response header names."""

        allowed = {
            "content-type",
            "content-length",
            "retry-after",
            "request-id",
            "x-request-id",
        }
        if self.wire_protocol == OPENAI_RESPONSES_WIRE_V1:
            allowed.add("openai-request-id")
        if (
            not isinstance(headers, Mapping)
            or set(headers) - allowed
            or any(
                not isinstance(name, str)
                or not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > 8192
                or any(character in value for character in "\x00\r\n")
                for name, value in headers.items()
            )
        ):
            raise ProviderVerificationError(
                "provider response headers violate the native contract"
            )
        content_type = headers.get("content-type")
        if (
            not isinstance(content_type, str)
            or content_type.split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            raise ProviderVerificationError(
                "provider response content type is invalid"
            )
        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError as exc:
                raise ProviderVerificationError(
                    "provider response content length is invalid"
                ) from exc
            if declared != body_size:
                raise ProviderVerificationError(
                    "provider response content length differs from custody"
                )

    def verify_execution(
        self,
        *,
        provider_version: str,
        endpoint: str,
        credential_env_name: str | None,
        credential_present: bool,
        invocation_id: str,
        request_projection: ProviderRequestProjection,
        response_projection: ProviderResponseProjection,
        request_body_bytes: bytes,
        raw_response_bytes: bytes,
        retained_instructions: str,
        retained_input: str,
        retained_schema: Mapping[str, Any],
        maximum_output_bytes: int,
        network_used: bool,
        external_validation: str,
        transport_authority: str,
        transport_execution_authority_artifact_sha256: str | None,
        custody_artifact_hashes: tuple[str, ...],
    ) -> "ProviderExecutionProjection":
        """Check this exact wire contract and return a neutral projection.

        Consumers remain responsible for reopening and replaying their complete
        artifact graphs before calling this method.  The returned projection is
        deliberately advisory: it can never be used as scientific evidence.
        """

        if (
            provider_version != self.provider_version
            or endpoint != self.endpoint
            or credential_env_name != self.credential_env_name
            or credential_present is not self.credential_present
        ):
            raise ProviderVerificationError(
                "provider execution differs from its source-owned wire contract"
            )
        if not isinstance(request_projection, ProviderRequestProjection) or not isinstance(
            response_projection,
            ProviderResponseProjection,
        ):
            raise ProviderVerificationError(
                "provider execution lacks native wire projections"
            )
        try:
            derived_request_projection = self.validate_and_project_request(
                body_bytes=request_body_bytes,
                retained_instructions=retained_instructions,
                retained_input=retained_input,
                retained_schema=retained_schema,
                invocation_id=invocation_id,
                model_requested=request_projection.model_requested,
                maximum_output_tokens=request_projection.maximum_output_tokens,
            )
            derived_response_projection = self.parse_and_project_response(
                raw_bytes=raw_response_bytes,
                requested_model=request_projection.model_requested,
                output_schema=retained_schema,
                maximum_output_bytes=maximum_output_bytes,
                expected_request_id=derived_request_projection.request_id,
            )
        except ProviderVerificationError as exc:
            raise ProviderVerificationError(
                "provider execution wire bytes cannot be reprojected"
            ) from exc
        if (
            request_projection != derived_request_projection
            or response_projection != derived_response_projection
        ):
            raise ProviderVerificationError(
                "provider execution projections differ from exact wire bytes"
            )
        expected_contract_identity = (
            self.provider_id,
            self.provenance_schema_version,
            self.wire_protocol,
        )
        if (
            (
                request_projection.provider_id,
                request_projection.provenance_schema_version,
                request_projection.wire_protocol,
            )
            != expected_contract_identity
            or (
                response_projection.provider_id,
                response_projection.provenance_schema_version,
                response_projection.wire_protocol,
            )
            != expected_contract_identity
            or response_projection.request_id != request_projection.request_id
            or request_projection.request_id
            != self.expected_request_id_from_projection(
                body_sha256=request_projection.body_sha256,
                body_size=request_projection.body_size,
                invocation_id=invocation_id,
            )
        ):
            raise ProviderVerificationError(
                "provider execution projections cross a wire-contract boundary"
            )
        if transport_authority == AUDITED_LIVE_TRANSPORT_AUTHORITY:
            if (
                not self.audited_live_allowed
                or network_used is not True
                or external_validation
                != "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                or transport_execution_authority_artifact_sha256 is None
            ):
                raise ProviderVerificationError(
                    "provider execution has invalid audited-live authority"
                )
        elif transport_authority == UNVERIFIED_TRANSPORT_AUTHORITY:
            if (
                network_used is not False
                or external_validation != "UNTESTED"
                or transport_execution_authority_artifact_sha256 is not None
            ):
                raise ProviderVerificationError(
                    "provider execution has invalid unverified authority"
                )
        else:
            raise ProviderVerificationError(
                "provider execution transport authority is unsupported"
            )
        return ProviderExecutionProjection(
            provider_id=self.provider_id,
            provenance_schema_version=self.provenance_schema_version,
            provider_version=self.provider_version,
            invocation_id=invocation_id,
            request_id=request_projection.request_id,
            model_requested=request_projection.model_requested,
            model_returned=response_projection.model_returned,
            provider_response_id=response_projection.response_id,
            structured_output=response_projection.output,
            network_used=network_used,
            external_validation=external_validation,
            transport_authority=transport_authority,
            transport_execution_authority_artifact_sha256=(
                transport_execution_authority_artifact_sha256
            ),
            custody_artifact_hashes=custody_artifact_hashes,
        )


@dataclass(frozen=True, slots=True)
class ProviderExecutionProjection:
    """Frozen provider-neutral result of exact custody-graph verification."""

    provider_id: str
    provenance_schema_version: str
    provider_version: str
    invocation_id: str
    request_id: str
    model_requested: str
    model_returned: str
    provider_response_id: str
    structured_output: Mapping[str, Any]
    network_used: bool
    external_validation: str
    transport_authority: str
    transport_execution_authority_artifact_sha256: str | None
    custody_artifact_hashes: tuple[str, ...]
    scientific_evidence: bool = False

    def __post_init__(self) -> None:
        validate_identifier(self.provider_id, "verified provider ID")
        validate_identifier(self.invocation_id, "verified provider invocation ID")
        for label, value in (
            ("verified provenance schema", self.provenance_schema_version),
            ("verified provider version", self.provider_version),
            ("verified provider model requested", self.model_requested),
            ("verified provider model returned", self.model_returned),
            ("verified provider response ID", self.provider_response_id),
            ("verified provider external validation", self.external_validation),
        ):
            if (
                not isinstance(value, str)
                or not value
                or "\x00" in value
                or len(value.encode("utf-8")) > 8192
            ):
                raise ProviderVerificationError(f"{label} is invalid")
        validate_sha256(self.request_id, "verified provider request ID")
        if (
            not isinstance(self.network_used, bool)
            or not isinstance(self.structured_output, Mapping)
            or self.transport_authority
            not in {
                AUDITED_LIVE_TRANSPORT_AUTHORITY,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            }
            or self.scientific_evidence is not False
        ):
            raise ProviderVerificationError(
                "verified provider trust projection is invalid"
            )
        if self.transport_execution_authority_artifact_sha256 is not None:
            validate_sha256(
                self.transport_execution_authority_artifact_sha256,
                "verified transport execution authority SHA-256",
            )
        if (
            not isinstance(self.custody_artifact_hashes, tuple)
            or not self.custody_artifact_hashes
            or len(set(self.custody_artifact_hashes))
            != len(self.custody_artifact_hashes)
        ):
            raise ProviderVerificationError(
                "verified provider custody identities are invalid"
            )
        for digest in self.custody_artifact_hashes:
            validate_sha256(digest, "verified provider custody SHA-256")
        if (
            self.transport_execution_authority_artifact_sha256 is not None
            and self.transport_execution_authority_artifact_sha256
            not in self.custody_artifact_hashes
        ):
            raise ProviderVerificationError(
                "verified transport authority is absent from provider custody"
            )
        try:
            object.__setattr__(
                self,
                "structured_output",
                freeze_json(self.structured_output),
            )
        except ValidationError as exc:
            raise ProviderVerificationError(
                "verified provider structured output is invalid"
            ) from exc


def _build_provider_verifier_dispatch(
    implementation_factory: Callable[..., Any] = _ProviderVerifierImplementation,
    openai_response_parser: Callable[..., Any] = _openai_response_parser,
    deterministic_response_parser: Callable[..., Any] = (
        _deterministic_response_parser
    ),
):
    implementations = (
        implementation_factory(
            provider_id=OPENAI_PROVIDER_ID,
            provenance_schema_version=MODEL_PROVIDER_CUSTODY_SCHEMA_V1,
            provider_version=OPENAI_RESPONSES_POLICY_VERSION,
            endpoint=OPENAI_RESPONSES_ENDPOINT,
            credential_env_name=OPENAI_CREDENTIAL_ENV_NAME,
            credential_present=True,
            audited_live_allowed=True,
            wire_protocol=OPENAI_RESPONSES_WIRE_V1,
            _response_parser=openai_response_parser,
        ),
        implementation_factory(
            provider_id=DETERMINISTIC_FIXTURE_PROVIDER_ID,
            provenance_schema_version=MODEL_PROVIDER_CUSTODY_SCHEMA_V1,
            provider_version=DETERMINISTIC_FIXTURE_PROVIDER_VERSION,
            endpoint=DETERMINISTIC_FIXTURE_ENDPOINT,
            credential_env_name=None,
            credential_present=False,
            audited_live_allowed=False,
            wire_protocol=DETERMINISTIC_FIXTURE_WIRE_V1,
            _response_parser=deterministic_response_parser,
        ),
    )
    implementation_type = type(implementations[0])
    implementation_method_names = (
        "expected_request_id",
        "expected_request_id_from_projection",
        "build_request_body",
        "validate_and_project_request",
        "parse_and_project_response",
        "_response_parser_is_exact",
        "validate_response_headers",
        "verify_execution",
    )
    implementation_namespace = tuple(
        (
            name,
            implementation_type.__dict__[name],
            getattr(implementation_type.__dict__[name], "__code__", None),
            getattr(implementation_type.__dict__[name], "__defaults__", None),
            (
                dict(implementation_type.__dict__[name].__kwdefaults__)
                if getattr(
                    implementation_type.__dict__[name],
                    "__kwdefaults__",
                    None,
                )
                is not None
                else None
            ),
        )
        for name in implementation_method_names
    )

    def assert_exact_implementation_namespace() -> None:
        for name, expected, code, defaults, keyword_defaults in (
            implementation_namespace
        ):
            current = implementation_type.__dict__.get(name)
            if (
                current is not expected
                or getattr(current, "__code__", None) is not code
                or getattr(current, "__defaults__", None) != defaults
                or getattr(current, "__kwdefaults__", None)
                != keyword_defaults
            ):
                raise ProviderVerificationError(
                    "provider verifier implementation changed after dispatch"
                )

    sealed_contract_types: set[int] = set()

    class _SealedContractType(type):
        def __setattr__(cls, name: str, value: Any) -> None:
            if id(cls) in sealed_contract_types:
                raise TypeError("provider verifier contract type is sealed")
            super().__setattr__(name, value)

        def __delattr__(cls, name: str) -> None:
            if id(cls) in sealed_contract_types:
                raise TypeError("provider verifier contract type is sealed")
            super().__delattr__(name)

    @dataclass(frozen=True, slots=True)
    class ProviderVerifierContract(metaclass=_SealedContractType):
        """Opaque metadata facade for one source-owned provider verifier.

        Executable parsers and their integrity sentinels are held only in this
        factory's closure.  Every operation resolves this exact facade identity
        and compares all visible metadata to the captured canonical snapshot
        before delegating; caller construction or ``object.__setattr__`` cannot
        substitute a parser, endpoint, policy, or wire identity.

        This is a fail-closed boundary for supported calls and ordinary
        namespace mutation, not a defence against arbitrary same-interpreter
        code rewriting by a process principal that already controls Python.
        """

        provider_id: str
        provenance_schema_version: str
        provider_version: str
        endpoint: str
        credential_env_name: str | None
        credential_present: bool
        audited_live_allowed: bool
        wire_protocol: str

        @property
        def key(self) -> tuple[str, str]:
            entry = resolve(self)
            return (entry[1][0], entry[1][1])

        def expected_request_id(self, body: bytes, invocation_id: str) -> str:
            return invoke(self, "expected_request_id", body, invocation_id)

        def expected_request_id_from_projection(
            self,
            *,
            body_sha256: str,
            body_size: int,
            invocation_id: str,
        ) -> str:
            return invoke(
                self,
                "expected_request_id_from_projection",
                body_sha256=body_sha256,
                body_size=body_size,
                invocation_id=invocation_id,
            )

        def build_request_body(self, **kwargs: Any) -> bytes:
            return invoke(self, "build_request_body", **kwargs)

        def validate_and_project_request(
            self,
            **kwargs: Any,
        ) -> ProviderRequestProjection:
            return invoke(self, "validate_and_project_request", **kwargs)

        def parse_and_project_response(
            self,
            **kwargs: Any,
        ) -> ProviderResponseProjection:
            return invoke(self, "parse_and_project_response", **kwargs)

        def validate_response_headers(
            self,
            headers: Mapping[str, Any],
            *,
            body_size: int,
        ) -> None:
            invoke(
                self,
                "validate_response_headers",
                headers,
                body_size=body_size,
            )

        def verify_execution(self, **kwargs: Any) -> ProviderExecutionProjection:
            return invoke(self, "verify_execution", **kwargs)

    sealed_contract_types.add(id(ProviderVerifierContract))

    owned: dict[
        int,
        tuple[
            ProviderVerifierContract,
            tuple[Any, ...],
            Mapping[str, Callable[..., Any]],
        ],
    ] = {}

    def metadata(implementation: Any) -> tuple[Any, ...]:
        return (
            implementation.provider_id,
            implementation.provenance_schema_version,
            implementation.provider_version,
            implementation.endpoint,
            implementation.credential_env_name,
            implementation.credential_present,
            implementation.audited_live_allowed,
            implementation.wire_protocol,
        )

    def visible(contract: ProviderVerifierContract) -> tuple[Any, ...]:
        return (
            contract.provider_id,
            contract.provenance_schema_version,
            contract.provider_version,
            contract.endpoint,
            contract.credential_env_name,
            contract.credential_present,
            contract.audited_live_allowed,
            contract.wire_protocol,
        )

    def resolve(
        contract: ProviderVerifierContract,
    ) -> tuple[
        ProviderVerifierContract,
        tuple[Any, ...],
        Mapping[str, Callable[..., Any]],
    ]:
        entry = owned.get(id(contract))
        if (
            entry is None
            or entry[0] is not contract
            or visible(contract) != entry[1]
        ):
            raise ProviderVerificationError(
                "provider verifier is not an exact source-owned contract"
            )
        return entry

    def invoke(
        contract: ProviderVerifierContract,
        operation: str,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        assert_exact_implementation_namespace()
        operations = resolve(contract)[2]
        selected = operations.get(operation)
        if selected is None:
            raise ProviderVerificationError(
                "provider verifier operation is not source-owned"
            )
        result = selected(*args, **kwargs)
        assert_exact_implementation_namespace()
        return result

    contracts: list[ProviderVerifierContract] = []
    for implementation in implementations:
        canonical_metadata = metadata(implementation)
        contract = ProviderVerifierContract(*canonical_metadata)
        operations = MappingProxyType(
            {
                name: getattr(implementation, name)
                for name in implementation_method_names
                if not name.startswith("_")
            }
        )
        owned[id(contract)] = (contract, canonical_metadata, operations)
        contracts.append(contract)
    dispatch = MappingProxyType({contract.key: contract for contract in contracts})

    def require(
        provider_id: str,
        provenance_schema_version: str,
    ) -> ProviderVerifierContract:
        if not isinstance(provider_id, str) or not isinstance(
            provenance_schema_version,
            str,
        ):
            raise ProviderVerificationError("provider verifier key must be exact text")
        contract = dispatch.get((provider_id, provenance_schema_version))
        if contract is None:
            raise ProviderVerificationError(
                "provider and provenance schema have no source-owned verifier"
            )
        return contract

    return ProviderVerifierContract, require


ProviderVerifierContract, require_provider_verifier = (
    _build_provider_verifier_dispatch()
)
del _build_provider_verifier_dispatch
del _ProviderVerifierImplementation
del _openai_response_parser
del _deterministic_response_parser


__all__ = [
    "DETERMINISTIC_FIXTURE_ENDPOINT",
    "DETERMINISTIC_FIXTURE_PROVIDER_ID",
    "DETERMINISTIC_FIXTURE_PROVIDER_VERSION",
    "DETERMINISTIC_FIXTURE_WIRE_V1",
    "MODEL_PROVIDER_CUSTODY_SCHEMA_V1",
    "OPENAI_CREDENTIAL_ENV_NAME",
    "OPENAI_PROVIDER_ID",
    "OPENAI_RESPONSES_ENDPOINT",
    "OPENAI_RESPONSES_POLICY_VERSION",
    "OPENAI_RESPONSES_WIRE_V1",
    "ProviderExecutionProjection",
    "ProviderRequestProjection",
    "ProviderResponseProjection",
    "ProviderVerificationError",
    "ProviderVerifierContract",
    "require_provider_verifier",
]
