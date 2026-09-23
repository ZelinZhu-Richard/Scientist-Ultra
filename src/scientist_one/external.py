"""Controlled, auditable HTTPS egress for external research services.

This module is the sole Scientist-One owner of network primitives.  Callers
submit immutable requests to :class:`EgressGateway`; adapters never open
sockets, inherit proxy settings, follow redirects, or handle credential values.
All external bytes remain untrusted data and carry no execution, evaluator, or
scientific authority.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import ipaddress
import math
import os
import re
import secrets
import ssl
import stat
import threading
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .artifacts import ArtifactRecord, ArtifactRegistry
from .errors import (
    ArtifactError,
    LedgerError,
    PathSecurityError,
    UnsafeSerializationError,
    ValidationError,
)
from .ledger import EventLedger, LedgerEvent
from .models import validate_identifier
from .roles import Role
from .security import (
    INVALID_UTF8_SECRET_SCAN_LABEL,
    atomic_write_bytes,
    canonical_json_bytes,
    detect_secret_patterns,
    detect_secret_patterns_in_bytes,
    open_confined_directory_fd,
    safe_json_loads,
)


from .bounded_http_decoder import decode_http_content as _bounded_decode_http_content


MAX_ABSOLUTE_REQUEST_BYTES = 8 * 1024 * 1024
MAX_ABSOLUTE_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_POLICY_HOSTS = 32
MAX_POLICY_PATHS = 64
MAX_HEADERS = 64
MAX_HEADER_BYTES = 64 * 1024
MAX_URL_BYTES = 8 * 1024
MAX_ATTEMPTS = 8
MAX_ABSOLUTE_TOTAL_BYTES = MAX_ATTEMPTS * (
    MAX_ABSOLUTE_REQUEST_BYTES + MAX_ABSOLUTE_RESPONSE_BYTES
)
MAX_REQUESTS_PER_GATEWAY = 10_000
MAX_TIMEOUT_SECONDS = 300.0
MAX_JSON_DEPTH = 64
MAX_JSON_ITEMS = 250_000
AUDITED_LIVE_TRANSPORT_AUTHORITY = "AUDITED_STDLIB_HTTPS_TRANSPORT_V1"
UNVERIFIED_TRANSPORT_AUTHORITY = "UNVERIFIED_REPLACEABLE_TRANSPORT"
EGRESS_REQUEST_SCHEMA = "controlled-egress-request/v2"
EGRESS_RESPONSE_RECEIPT_SCHEMA = "controlled-egress-response/v2"
EGRESS_PMC_RESPONSE_SCHEMA_V3 = "controlled-egress-response/v3"
PMC_CONTENT_ADAPTER_ID = "scholarly-pmc-oai-jats-v2"
PMC_CONTENT_PROFILE = "PMC_OAI_XML_BOUNDED_DECODING_V1"
PMC_DECODING_SCHEMA = "external-content-decoding/v1"
PMC_WIRE_ADAPTER_ID = "scholarly-pmc-oai-jats-v3"
PMC_REQUEST_WIRE_PROFILE = "PMC_OAI_GETRECORD_GZIP_DEFLATE_V1"
PMC_COORDINATION_PROFILE = "PMC_SAME_PRINCIPAL_SAME_BOOT_OFFPEAK_V1"
PMC_RULES_SCHEMA = "pmc-schedule-rules/v1"
PMC_WIRE_ATTEMPT_SCHEMA = "controlled-egress-attempt/v3"
PMC_WIRE_RESPONSE_SCHEMA = "controlled-egress-response/v4"
PMC_WIRE_AUTHORITY_SCHEMA = "audited-transport-authority/v3"
PMC_WIRE_DEADLINE_SCOPE = "MONOTONIC_EXECUTE_ENTRY_THROUGH_TRANSPORT_DECODE_AND_RULES_CUSTODY_ADMISSION"
EGRESS_ATTEMPT_SCHEMA = "controlled-egress-attempt/v2"
EGRESS_BUDGET_SCHEMA = "controlled-egress-budget/v2"
AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA = (
    "audited-transport-authority/v2"
)
AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE = (
    "audited_transport_execution_authority"
)
_AUDITED_TRANSPORT_AUTHORITY_KEY_BYTES = 32
_AUDITED_TRANSPORT_AUTHORITY_KEY_NAME = (
    ".gateway-execution-" + "authority.key"
)
_AUDITED_TRANSPORT_AUTHORITY_ORIGIN = (
    "gateway-signed audited HTTPS transport execution authority"
)
_AUDITED_TRANSPORT_AUTHORITY_COMMAND = (
    "scientist-one",
    "issue-audited-transport-execution-authority",
)
_AUDITED_TRANSPORT_AUTHORITY_EVENT_REASON = (
    "anchor gateway-signed audited HTTPS transport execution authority"
)
_LIVE_RESPONSE_VALIDATION = (
    "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
)
_EGRESS_BYTE_ACCOUNTING = (
    "REQUEST_BODY_PER_ATTEMPT_PLUS_EACH_RECEIVED_RESPONSE_BODY"
)
_EGRESS_DEADLINE_SCOPE = (
    "MONOTONIC_EXECUTE_ENTRY_THROUGH_FINAL_RESPONSE_CAPTURE"
)
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_HEADER_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$")
_MEDIA_TYPE_RE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
)
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_SENSITIVE_QUERY_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|authorization)"
)
_BOUNDARY_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)['\"]?(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|password)['\"]?\s*[:=]\s*['\"]?"
    r"[A-Za-z0-9_./+\-=]{16,}"
)
_FORBIDDEN_CALLER_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "proxy-connection",
        "connection",
        "host",
        "content-length",
        "transfer-encoding",
    }
)
_DEFAULT_RECORDED_RESPONSE_HEADERS = (
    "content-type",
    "content-length",
    "retry-after",
    "request-id",
    "x-request-id",
    "openai-request-id",
)


class ExternalBoundaryError(RuntimeError):
    """Base error for a denied or failed external operation."""


class EgressPolicyError(ExternalBoundaryError, ValueError):
    """The frozen egress policy or request is invalid."""


class EgressDeniedError(ExternalBoundaryError):
    """A sanitized policy denial with optional captured provenance."""

    def __init__(
        self,
        message: str,
        *,
        request_id: str | None = None,
        attempts: Sequence[Mapping[str, object]] = (),
        artifacts: Sequence[ArtifactRecord] = (),
        network_used: bool | None = None,
        external_validation: str | None = None,
        transport_authority: str | None = None,
    ) -> None:
        super().__init__(message)
        self.request_id = request_id
        self.attempts = tuple(MappingProxyType(dict(value)) for value in attempts)
        self.artifacts = tuple(artifacts)
        self.network_used = network_used
        self.external_validation = external_validation
        self.transport_authority = transport_authority


class ExternalUnavailableError(ExternalBoundaryError):
    """A required credential, network path, or external service is unavailable."""


class TransportFailure(ExternalBoundaryError):
    """A sanitized transport failure with optional captured provenance."""

    def __init__(
        self,
        message: str,
        *,
        request_id: str | None = None,
        attempts: Sequence[Mapping[str, object]] = (),
        artifacts: Sequence[ArtifactRecord] = (),
        network_used: bool | None = None,
        external_validation: str | None = None,
        transport_authority: str | None = None,
    ) -> None:
        super().__init__(message)
        self.request_id = request_id
        self.attempts = tuple(MappingProxyType(dict(value)) for value in attempts)
        self.artifacts = tuple(artifacts)
        self.network_used = network_used
        self.external_validation = external_validation
        self.transport_authority = transport_authority


class _PartialResponseTransportFailure(TransportFailure):
    """Internal transport failure retaining only known received-byte count."""

    def __init__(
        self,
        message: str,
        *,
        response_body_bytes: int,
        policy_denial: bool = False,
    ) -> None:
        if (
            isinstance(response_body_bytes, bool)
            or not isinstance(response_body_bytes, int)
            or response_body_bytes < 0
            or response_body_bytes > MAX_ABSOLUTE_RESPONSE_BYTES + 1
            or not isinstance(policy_denial, bool)
        ):
            raise EgressPolicyError(
                "partial transport byte accounting is invalid"
            )
        super().__init__(message)
        self.response_body_bytes = response_body_bytes
        self.policy_denial = policy_denial


class ExternalParseError(ExternalBoundaryError):
    """Captured external bytes do not satisfy the expected strict format."""


def _bounded_text(value: object, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise EgressPolicyError(f"{label} must be non-empty text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EgressPolicyError(f"{label} must be valid UTF-8") from exc
    if len(encoded) > maximum or "\r" in value or "\n" in value:
        raise EgressPolicyError(f"{label} exceeds its bounded text contract")
    return value


def _bounded_integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EgressPolicyError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise EgressPolicyError(f"{label} is outside its allowed range")
    return value


def _bounded_number(
    value: object,
    label: str,
    *,
    minimum: float,
    maximum: float,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EgressPolicyError(f"{label} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number < minimum or number > maximum:
        raise EgressPolicyError(f"{label} is outside its allowed range")
    return number


def _media_type(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if not _MEDIA_TYPE_RE.fullmatch(normalized):
        raise EgressPolicyError(f"invalid {label}")
    return normalized


def _response_media_type(value: str) -> str:
    return value.split(";", 1)[0].strip().lower()


def _headers(
    values: Sequence[tuple[str, str]],
    *,
    caller_supplied: bool,
) -> tuple[tuple[str, str], ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise EgressPolicyError("headers must be an ordered pair sequence")
    if len(values) > MAX_HEADERS:
        raise EgressPolicyError("header count exceeds the bounded contract")
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    total = 0
    for item in values:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise EgressPolicyError("header entries must be name/value pairs")
        name, value = item
        if not isinstance(name, str) or not _HEADER_RE.fullmatch(name):
            raise EgressPolicyError("invalid header name")
        value = _bounded_text(value, "header value", maximum=8192)
        lowered = name.lower()
        if lowered in seen:
            raise EgressPolicyError("duplicate headers are ambiguous")
        if caller_supplied and lowered in _FORBIDDEN_CALLER_HEADERS:
            raise EgressDeniedError("caller-controlled authorization or transport header is forbidden")
        seen.add(lowered)
        total += len(name.encode("ascii")) + len(value.encode("utf-8"))
        if total > MAX_HEADER_BYTES:
            raise EgressPolicyError("headers exceed the bounded byte contract")
        result.append((name, value))
    return tuple(result)


def _header_value(headers: Sequence[tuple[str, str]], name: str) -> str | None:
    lowered = name.lower()
    matches = [value for key, value in headers if key.lower() == lowered]
    if len(matches) > 1:
        raise EgressDeniedError("duplicate response control header is ambiguous")
    return matches[0] if matches else None


def _safe_hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class EgressPolicy:
    """Frozen allowlist and resource policy for one external adapter."""

    policy_id: str
    adapter_id: str
    allowed_hosts: tuple[str, ...]
    allowed_path_prefixes: tuple[str, ...]
    allowed_methods: tuple[str, ...] = ("GET", "POST")
    allowed_query_keys: tuple[str, ...] = ()
    allowed_request_headers: tuple[str, ...] = (
        "accept",
        "content-type",
        "idempotency-key",
        "user-agent",
    )
    allowed_request_content_types: tuple[str, ...] = ("application/json",)
    allowed_response_content_types: tuple[str, ...] = ("application/json",)
    recorded_response_headers: tuple[str, ...] = _DEFAULT_RECORDED_RESPONSE_HEADERS
    maximum_request_bytes: int = 1024 * 1024
    maximum_response_bytes: int = 8 * 1024 * 1024
    maximum_total_bytes: int = 32 * 1024 * 1024
    timeout_seconds: float = 30.0
    minimum_interval_seconds: float = 0.0
    maximum_requests: int = 100
    maximum_attempts: int = 3
    retry_statuses: tuple[int, ...] = (429, 500, 502, 503, 504)
    backoff_initial_seconds: float = 0.25
    backoff_maximum_seconds: float = 8.0
    maximum_json_depth: int = MAX_JSON_DEPTH
    maximum_json_items: int = MAX_JSON_ITEMS
    credential_env_name: str | None = None
    credential_required: bool = False
    credential_header: str = "Authorization"
    credential_prefix: str = "Bearer "
    enabled: bool = True

    def __post_init__(self) -> None:
        _bounded_text(self.policy_id, "policy_id", maximum=128)
        _bounded_text(self.adapter_id, "adapter_id", maximum=128)
        if not isinstance(self.enabled, bool):
            raise EgressPolicyError("enabled must be boolean")
        if (
            not isinstance(self.allowed_hosts, tuple)
            or not self.allowed_hosts
            or len(self.allowed_hosts) > MAX_POLICY_HOSTS
        ):
            raise EgressPolicyError("an explicit bounded host allowlist is required")
        hosts: list[str] = []
        for host in self.allowed_hosts:
            normalized = _bounded_text(host, "allowed host", maximum=253).lower()
            if normalized.endswith(".") or not _HOST_RE.fullmatch(normalized):
                raise EgressPolicyError("invalid allowed host")
            try:
                ipaddress.ip_address(normalized)
            except ValueError:
                pass
            else:
                raise EgressPolicyError("IP literals cannot be allowlisted")
            hosts.append(normalized)
        if len(set(hosts)) != len(hosts):
            raise EgressPolicyError("allowed hosts must be unique")
        object.__setattr__(self, "allowed_hosts", tuple(hosts))

        if (
            not isinstance(self.allowed_path_prefixes, tuple)
            or not self.allowed_path_prefixes
            or len(self.allowed_path_prefixes) > MAX_POLICY_PATHS
        ):
            raise EgressPolicyError("an explicit bounded path allowlist is required")
        paths: list[str] = []
        for path in self.allowed_path_prefixes:
            path = _bounded_text(path, "allowed path", maximum=2048)
            if not path.startswith("/") or "\\" in path or "?" in path or "#" in path:
                raise EgressPolicyError("invalid allowed path")
            if "%" in path or ".." in path.split("/"):
                raise EgressPolicyError("encoded or traversing allowed paths are forbidden")
            paths.append(path)
        if len(set(paths)) != len(paths):
            raise EgressPolicyError("allowed paths must be unique")
        object.__setattr__(self, "allowed_path_prefixes", tuple(paths))

        methods = tuple(str(value).upper() for value in self.allowed_methods)
        if not methods or len(methods) > 8 or any(value not in {"GET", "POST"} for value in methods):
            raise EgressPolicyError("only explicitly allowed GET/POST methods are supported")
        if len(set(methods)) != len(methods):
            raise EgressPolicyError("allowed methods must be unique")
        object.__setattr__(self, "allowed_methods", methods)

        query_keys = tuple(
            _bounded_text(value, "allowed query key", maximum=128)
            for value in self.allowed_query_keys
        )
        if len(query_keys) > 64 or len(set(query_keys)) != len(query_keys):
            raise EgressPolicyError("allowed query keys are invalid")
        if any(_SENSITIVE_QUERY_RE.search(value) for value in query_keys):
            raise EgressPolicyError("credential-like query parameters are forbidden")
        object.__setattr__(self, "allowed_query_keys", query_keys)

        request_headers = tuple(value.lower() for value in self.allowed_request_headers)
        recorded_headers = tuple(value.lower() for value in self.recorded_response_headers)
        for values, label in (
            (request_headers, "request header allowlist"),
            (recorded_headers, "recorded response header allowlist"),
        ):
            if len(values) > MAX_HEADERS or len(set(values)) != len(values):
                raise EgressPolicyError(f"{label} is invalid")
            if any(not _HEADER_RE.fullmatch(value) for value in values):
                raise EgressPolicyError(f"{label} contains an invalid name")
        if any(value in _FORBIDDEN_CALLER_HEADERS for value in request_headers):
            raise EgressPolicyError("request header allowlist contains a transport-owned header")
        object.__setattr__(self, "allowed_request_headers", request_headers)
        object.__setattr__(self, "recorded_response_headers", recorded_headers)

        request_types = tuple(
            _media_type(value, "request content type")
            for value in self.allowed_request_content_types
        )
        response_types = tuple(
            _media_type(value, "response content type")
            for value in self.allowed_response_content_types
        )
        if not request_types or not response_types:
            raise EgressPolicyError("explicit request and response content types are required")
        if len(set(request_types)) != len(request_types) or len(set(response_types)) != len(response_types):
            raise EgressPolicyError("content type allowlists must be unique")
        object.__setattr__(self, "allowed_request_content_types", request_types)
        object.__setattr__(self, "allowed_response_content_types", response_types)

        _bounded_integer(
            self.maximum_request_bytes,
            "maximum_request_bytes",
            minimum=0,
            maximum=MAX_ABSOLUTE_REQUEST_BYTES,
        )
        _bounded_integer(
            self.maximum_response_bytes,
            "maximum_response_bytes",
            minimum=1,
            maximum=MAX_ABSOLUTE_RESPONSE_BYTES,
        )
        _bounded_integer(
            self.maximum_total_bytes,
            "maximum_total_bytes",
            minimum=1,
            maximum=MAX_ABSOLUTE_TOTAL_BYTES,
        )
        _bounded_number(
            self.timeout_seconds,
            "timeout_seconds",
            minimum=0.01,
            maximum=MAX_TIMEOUT_SECONDS,
        )
        _bounded_number(
            self.minimum_interval_seconds,
            "minimum_interval_seconds",
            minimum=0.0,
            maximum=3600.0,
        )
        _bounded_integer(
            self.maximum_requests,
            "maximum_requests",
            minimum=1,
            maximum=MAX_REQUESTS_PER_GATEWAY,
        )
        _bounded_integer(
            self.maximum_attempts,
            "maximum_attempts",
            minimum=1,
            maximum=MAX_ATTEMPTS,
        )
        retries = tuple(self.retry_statuses)
        if len(retries) > 16 or len(set(retries)) != len(retries):
            raise EgressPolicyError("retry status policy is invalid")
        for status in retries:
            _bounded_integer(status, "retry status", minimum=400, maximum=599)
        object.__setattr__(self, "retry_statuses", retries)
        initial = _bounded_number(
            self.backoff_initial_seconds,
            "backoff_initial_seconds",
            minimum=0.0,
            maximum=3600.0,
        )
        maximum = _bounded_number(
            self.backoff_maximum_seconds,
            "backoff_maximum_seconds",
            minimum=0.0,
            maximum=3600.0,
        )
        if initial > maximum:
            raise EgressPolicyError("initial backoff exceeds maximum backoff")
        _bounded_integer(
            self.maximum_json_depth,
            "maximum_json_depth",
            minimum=1,
            maximum=MAX_JSON_DEPTH,
        )
        _bounded_integer(
            self.maximum_json_items,
            "maximum_json_items",
            minimum=1,
            maximum=MAX_JSON_ITEMS,
        )
        if not isinstance(self.credential_required, bool):
            raise EgressPolicyError("credential_required must be boolean")
        if self.credential_env_name is not None:
            if not isinstance(self.credential_env_name, str) or not _ENV_NAME_RE.fullmatch(
                self.credential_env_name
            ):
                raise EgressPolicyError("credential environment name is invalid")
        elif self.credential_required:
            raise EgressPolicyError("required credentials need an environment-variable name")
        if not _HEADER_RE.fullmatch(self.credential_header):
            raise EgressPolicyError("credential header is invalid")
        if self.credential_header.lower() in (
            _FORBIDDEN_CALLER_HEADERS - {"authorization"}
        ):
            raise EgressPolicyError("credential header cannot control HTTP routing or framing")
        if self.credential_header.lower() in {
            value.lower() for value in self.allowed_request_headers
        }:
            raise EgressPolicyError("credential header must remain gateway-owned")
        if (
            not isinstance(self.credential_prefix, str)
            or len(self.credential_prefix.encode("utf-8")) > 128
            or "\x00" in self.credential_prefix
            or "\r" in self.credential_prefix
            or "\n" in self.credential_prefix
        ):
            raise EgressPolicyError("credential prefix exceeds its bounded text contract")


@dataclass(frozen=True)
class EgressRequest:
    """Provider-supplied request with no credential value or transport authority."""

    adapter_id: str
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = field(default=b"", repr=False)
    content_type: str = "application/json"
    target_source: str = "CONFIGURED"
    idempotency_key: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _bounded_text(self.adapter_id, "adapter_id", maximum=128)
        method = _bounded_text(self.method, "method", maximum=8).upper()
        object.__setattr__(self, "method", method)
        _bounded_text(self.url, "url", maximum=MAX_URL_BYTES)
        object.__setattr__(self, "headers", _headers(self.headers, caller_supplied=True))
        if not isinstance(self.body, bytes) or len(self.body) > MAX_ABSOLUTE_REQUEST_BYTES:
            raise EgressPolicyError("request body exceeds the absolute byte contract")
        object.__setattr__(self, "content_type", _media_type(self.content_type, "request content type"))
        if self.target_source != "CONFIGURED":
            raise EgressDeniedError("arbitrary or response-discovered target URLs are forbidden")
        if self.idempotency_key is not None:
            _bounded_text(self.idempotency_key, "idempotency_key", maximum=256)

    @property
    def request_id(self) -> str:
        return _safe_hash(
            canonical_json_bytes(
                {
                    "adapter_id": self.adapter_id,
                    "method": self.method,
                    "url": self.url,
                    "headers": [list(item) for item in self.headers],
                    "body_sha256": _safe_hash(self.body),
                    "body_size": len(self.body),
                    "content_type": self.content_type,
                    "target_source": self.target_source,
                    "idempotency_key": self.idempotency_key,
                }
            )
        )


def _require_pmc_wire_activation() -> None:
    """Closed production gate; fixture reconstruction is never native authority."""
    raise EgressPolicyError("PMC versioned wire custody activation remains unavailable")


def _pmc_content_profile(policy: EgressPolicy, request: EgressRequest) -> bool:
    """Select one closed unsigned content profile before any caller callback."""
    if policy.adapter_id not in {PMC_CONTENT_ADAPTER_ID, PMC_WIRE_ADAPTER_ID}:
        return False
    if type(policy) is not EgressPolicy or type(request) is not EgressRequest:
        raise EgressPolicyError("egress source selection requires exact policy/request")
    expected = {
        "allowed_hosts": ("pmc.ncbi.nlm.nih.gov",),
        "allowed_path_prefixes": ("/api/oai/v1/mh/",),
        "allowed_methods": ("GET",),
        "allowed_query_keys": ("identifier", "metadataPrefix", "verb"),
        "allowed_request_headers": ("accept", "user-agent"),
        "allowed_request_content_types": ("application/xml",),
        "allowed_response_content_types": ("application/xml", "text/xml"),
        "recorded_response_headers": (*_DEFAULT_RECORDED_RESPONSE_HEADERS, "content-encoding"),
        "retry_statuses": (429, 500, 502, 503, 504),
    }
    if any(type(getattr(policy, name)) is not tuple
           or any(type(item) is not (int if name == "retry_statuses" else str)
                  for item in getattr(policy, name))
           or getattr(policy, name) != value for name, value in expected.items()):
        raise EgressPolicyError("PMC content policy differs from closed source profile")
    if (
        type(policy.maximum_request_bytes) is not int or policy.maximum_request_bytes != 0
        or type(policy.maximum_requests) is not int or policy.maximum_requests > 100
        or policy.minimum_interval_seconds < 1.0 / 3.0
        or policy.credential_env_name is not None or policy.credential_required is not False
        or policy.backoff_initial_seconds != 0.25 or policy.backoff_maximum_seconds != 8.0
        or type(request.adapter_id) is not str or request.adapter_id != policy.adapter_id
        or type(request.url) is not str
        or re.fullmatch(
            r"https://pmc\.ncbi\.nlm\.nih\.gov/api/oai/v1/mh/\?verb=GetRecord"
            r"&identifier=oai%3Apubmedcentral\.nih\.gov%3A[0-9]+&metadataPrefix=pmc",
            request.url,
        ) is None
        or type(request.method) is not str or request.method != "GET"
        or type(request.body) is not bytes or request.body != b""
        or request.content_type != "application/xml"
        or request.headers != (
            ("Accept", "application/xml, text/xml;q=0.9"),
            ("User-Agent", "Scientist-One-vNext-Scholarly/2"),
        )
    ):
        raise EgressPolicyError("PMC content request differs from closed source profile")
    return True


def _pmc_content_coding(headers: Sequence[tuple[str, str]]) -> str:
    value = _header_value(headers, "content-encoding")
    if value is None:
        return "identity"
    if type(value) is not str or value.strip().lower() not in {"identity", "gzip", "deflate"}:
        raise EgressDeniedError("PMC content coding is unsupported")
    return value.strip().lower()


def _build_pmc_content_decoder():
    """Bind the separately captured pure helper, never a caller decoder."""
    exact_decode = _bounded_decode_http_content
    exact_clock = time.monotonic

    def decode(raw, coding, maximum_input_bytes, check_deadline):
        return exact_decode(
            raw, coding, maximum_input_bytes=maximum_input_bytes,
            maximum_output_bytes=16 * 1024 * 1024,
            maximum_expansion_ratio=200, check_deadline=check_deadline,
        )

    def replay(raw, coding, maximum_input_bytes):
        deadline = exact_clock() + 30.0

        def check():
            now = exact_clock()
            if not math.isfinite(now) or now >= deadline:
                raise EgressDeniedError("PMC decoding replay deadline exceeded")
        return decode(raw, coding, maximum_input_bytes, check)

    return decode, replay


_decode_pmc_content, _replay_pmc_content = _build_pmc_content_decoder()
del _build_pmc_content_decoder


def _require_pmc_decoding_descriptor(
    registry: ArtifactRegistry,
    *,
    descriptor_sha256: str,
    request_hash: str,
    raw_hash: str,
    expected_record: ArtifactRecord | None = None,
    expected_bytes: bytes | None = None,
) -> tuple[ArtifactRecord, Mapping[str, object]]:
    """One descriptor readback owner shared by capture, cache and replay."""
    if type(registry) is not ArtifactRegistry:
        raise EgressPolicyError("PMC decoding custody owner is mismatched")
    fields = {
        "schema_version", "kind", "content_profile", "request_id",
        "request_artifact_sha256", "request_artifact_record_hash", "attempt",
        "wire_raw_artifact_sha256", "wire_raw_artifact_record_hash", "wire_body_size",
        "content_coding", "decode_limits", "decoded_xml_sha256", "decoded_xml_size",
        "decoding_started_offset_seconds", "decoding_completed_offset_seconds",
        "scientific_evidence",
    }
    registry.verify(descriptor_sha256, raise_on_error=True)
    record = registry.get_metadata(descriptor_sha256)
    value = safe_json_loads(registry.get_bytes(descriptor_sha256), max_bytes=16384,
                           max_depth=8, max_items=128)
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EgressPolicyError("PMC decoding descriptor fields are invalid")
    if (
        type(record) is not ArtifactRecord
        or record.sha256 != descriptor_sha256
        or (expected_record is not None
            and (type(expected_record) is not ArtifactRecord or record != expected_record))
        or record.logical_type != "external_response_decoding"
        or record.schema_version != PMC_DECODING_SCHEMA
        or record.origin != "bounded source-owned external content decoding"
        or record.creator_role is not Role.EVIDENCE_CURATOR
        or record.creation_command != ("scientist-one", "controlled-egress")
        or record.parent_artifacts != (request_hash, raw_hash)
        or record.mime_type != "application/json"
        or record.validation_result != "PASS" or record.frozen is not True
    ):
        raise EgressPolicyError("PMC decoding descriptor record binding differs")
    raw_descriptor = registry.get_bytes(descriptor_sha256)
    if (
        raw_descriptor != canonical_json_bytes(value) + b"\n"
        or (expected_bytes is not None and raw_descriptor != expected_bytes)
        or _safe_hash(raw_descriptor) != descriptor_sha256
        or record.size != len(raw_descriptor)
    ):
        raise EgressPolicyError("PMC decoding descriptor bytes differ")
    return record, value


def _require_pmc_content_decoding_binding(
    registry: ArtifactRegistry,
    *,
    descriptor_sha256: str,
    receipt: Mapping[str, object],
    policy: EgressPolicy,
) -> tuple[ArtifactRecord, bytes, Mapping[str, object], int]:
    """Validate unsigned descriptor joins without decompression or authority.

    The native capture owner separately verifies the complete request/raw/receipt
    history. This owner validates the descriptor and its precise transform joins.
    """
    if type(registry) is not ArtifactRegistry or policy.adapter_id not in {PMC_CONTENT_ADAPTER_ID, PMC_WIRE_ADAPTER_ID}:
        raise EgressPolicyError("PMC decoding custody owner is mismatched")
    request_hash = receipt.get("request_artifact_sha256")
    raw_hash = receipt.get("raw_response_record_sha256")
    record, value = _require_pmc_decoding_descriptor(
        registry, descriptor_sha256=descriptor_sha256,
        request_hash=request_hash, raw_hash=raw_hash,
    )
    registry.verify(request_hash, raise_on_error=True)
    registry.verify(raw_hash, raise_on_error=True)
    request_record = registry.get_metadata(request_hash)
    raw_record = registry.get_metadata(raw_hash)
    raw = registry.get_bytes(raw_hash)
    request_value = safe_json_loads(registry.get_bytes(request_hash),
                                   max_bytes=MAX_ABSOLUTE_REQUEST_BYTES,
                                   max_depth=16, max_items=256)
    attempt = receipt["attempts"][-1]
    maximum_input = min(
        policy.maximum_response_bytes,
        policy.maximum_total_bytes - (attempt["cumulative_bytes"] - attempt["response_body_bytes"]),
        MAX_ABSOLUTE_RESPONSE_BYTES,
    )
    limits = {"maximum_input_bytes": maximum_input,
              "maximum_output_bytes": 16 * 1024 * 1024,
              "maximum_expansion_ratio": 200}
    coding = _pmc_content_coding(tuple(receipt["headers"].items()))
    if (
        value["schema_version"] != PMC_DECODING_SCHEMA
        or value["kind"] != "EXTERNAL_CONTENT_DECODING"
        or value["content_profile"] != PMC_CONTENT_PROFILE
        or value["request_id"] != receipt.get("request_id")
        or value["request_id"] != request_value.get("request_id")
        or value["request_artifact_sha256"] != request_hash
        or value["request_artifact_record_hash"] != request_record.record_hash
        or value["wire_raw_artifact_sha256"] != raw_hash
        or value["wire_raw_artifact_record_hash"] != raw_record.record_hash
        or type(value["attempt"]) is not int or value["attempt"] != attempt["attempt"]
        or type(value["wire_body_size"]) is not int or value["wire_body_size"] != len(raw)
        or value["content_coding"] != coding or receipt.get("content_coding") != coding
        or type(value["decode_limits"]) is not dict
        or value["decode_limits"] != limits
        or any(type(item) is not int for item in value["decode_limits"].values())
        or type(value["decoded_xml_size"]) is not int
        or not 0 <= value["decoded_xml_size"] <= 16 * 1024 * 1024
        or type(value["decoded_xml_sha256"]) is not str
        or re.fullmatch(r"[0-9a-f]{64}", value["decoded_xml_sha256"]) is None
        or value["scientific_evidence"] is not False
        or receipt.get("decoding_artifact_sha256") != descriptor_sha256
        or receipt.get("decoding_artifact_record_hash") != record.record_hash
        or receipt.get("content_profile") != PMC_CONTENT_PROFILE
    ):
        raise EgressPolicyError("PMC decoding descriptor binding differs")
    offsets = (value["decoding_started_offset_seconds"],
               value["decoding_completed_offset_seconds"])
    if (
        any(type(offset) not in (int, float) or not math.isfinite(offset) for offset in offsets)
        or not 0 <= attempt["completed_offset_seconds"] <= offsets[0] <= offsets[1]
        <= receipt["egress_budget"]["deadline_elapsed_seconds"] < policy.timeout_seconds
    ):
        raise EgressPolicyError("PMC decoding descriptor timing differs")
    return record, raw, MappingProxyType(dict(value)), maximum_input

def require_pmc_content_decoding(
    registry: ArtifactRegistry,
    *,
    descriptor_sha256: str,
    receipt: Mapping[str, object],
    policy: EgressPolicy,
) -> tuple[ArtifactRecord, bytes, Mapping[str, object]]:
    """Re-derive unsigned descriptor custody after native history validation."""
    record, raw, value, maximum_input = _require_pmc_content_decoding_binding(
        registry, descriptor_sha256=descriptor_sha256, receipt=receipt, policy=policy,
    )
    decoded = _replay_pmc_content(raw, value["content_coding"], maximum_input)
    if len(decoded) != value["decoded_xml_size"] or _safe_hash(decoded) != value["decoded_xml_sha256"]:
        raise EgressPolicyError("PMC decoded XML differs from exact raw replay")
    return record, decoded, value


def require_pmc_content_cache(
    registry: ArtifactRegistry,
    *,
    result: GatewayResult,
    policy: EgressPolicy,
) -> tuple[bytes, Mapping[str, object]]:
    """Check transient cache against actual descriptor custody; never decode.

    This is a consistency check for the immediate source-owned consumer, not
    an independently complete raw-provenance verifier or scientific authority.
    Historical native replay still validates history and rederives actual bytes.
    """
    refused = False
    try:
        if (
            type(result) is not GatewayResult
            or type(result.content_decoding_artifact) is not ArtifactRecord
            or type(result.response_receipt_artifact) is not ArtifactRecord
            or type(result.request_artifact) is not ArtifactRecord
            or type(result.raw_response_artifact) is not ArtifactRecord
            or type(result.decoded_body) is not bytes
        ):
            raise EgressPolicyError("PMC decoded content cache is incomplete")
        receipt_record = result.response_receipt_artifact
        registry.verify(receipt_record.sha256, raise_on_error=True)
        if registry.get_metadata(receipt_record.sha256) != receipt_record:
            raise EgressPolicyError("PMC decoded content receipt record differs")
        receipt = safe_json_loads(registry.get_bytes(receipt_record.sha256),
                                 max_bytes=MAX_ABSOLUTE_REQUEST_BYTES,
                                 max_depth=16, max_items=2048)
        record, raw, value, _ = _require_pmc_content_decoding_binding(
            registry, descriptor_sha256=result.content_decoding_artifact.sha256,
            receipt=receipt, policy=policy,
        )
        if (
            record != result.content_decoding_artifact
            or receipt.get("schema_version") != (PMC_WIRE_RESPONSE_SCHEMA if policy.adapter_id == PMC_WIRE_ADAPTER_ID else EGRESS_PMC_RESPONSE_SCHEMA_V3)
            or receipt.get("request_id") != result.request_id
            or receipt.get("request_artifact_sha256") != result.request_artifact.sha256
            or receipt.get("raw_response_record_sha256") != result.raw_response_artifact.sha256
            or registry.get_metadata(result.request_artifact.sha256) != result.request_artifact
            or registry.get_metadata(result.raw_response_artifact.sha256) != result.raw_response_artifact
            or raw != result.body or _safe_hash(raw) != result.body_sha256
            or len(raw) != result.body_size
            or len(result.decoded_body) != value["decoded_xml_size"]
            or _safe_hash(result.decoded_body) != value["decoded_xml_sha256"]
        ):
            raise EgressPolicyError("PMC decoded content cache binding differs")
    except Exception:
        refused = True
    if refused:
        raise EgressPolicyError("PMC decoded content cache is inconsistent") from None
    return result.decoded_body, value



def _egress_budget_policy_claim(policy: EgressPolicy) -> dict[str, object]:
    """Return stable cumulative-byte and absolute-deadline semantics."""

    return {
        "schema_version": EGRESS_BUDGET_SCHEMA,
        "maximum_total_bytes": policy.maximum_total_bytes,
        "byte_accounting": _EGRESS_BYTE_ACCOUNTING,
        "deadline_budget_seconds": policy.timeout_seconds,
        "deadline_scope": (PMC_WIRE_DEADLINE_SCOPE if policy.adapter_id == PMC_WIRE_ADAPTER_ID
                           else _EGRESS_DEADLINE_SCOPE),
    }


def _retry_backoff_floor(policy: EgressPolicy, attempt: int) -> float:
    """Return the policy-derived retry delay excluding remote Retry-After."""

    return min(
        policy.backoff_maximum_seconds,
        policy.backoff_initial_seconds * (2 ** max(0, attempt - 1)),
    )


def _replay_retry_backoff(
    policy: EgressPolicy,
    attempts: Sequence[Mapping[str, object]],
) -> None:
    """Replay signed retry delays and their monotonic attempt gaps."""

    prior: Mapping[str, object] | None = None
    attempt_count = len(attempts)
    for expected_attempt, attempt in enumerate(attempts, start=1):
        if not isinstance(attempt, Mapping):
            raise EgressPolicyError("signed retry timing is malformed")
        started = attempt.get("started_offset_seconds")
        completed = attempt.get("completed_offset_seconds")
        retry_delay = attempt.get("retry_delay_seconds")
        is_final = expected_attempt == attempt_count
        minimum_delay = min(
            policy.backoff_maximum_seconds,
            policy.backoff_initial_seconds
            * (2 ** max(0, expected_attempt - 1)),
        )
        if (
            attempt.get("attempt") != expected_attempt
            or isinstance(started, bool)
            or not isinstance(started, (int, float))
            or not math.isfinite(float(started))
            or isinstance(completed, bool)
            or not isinstance(completed, (int, float))
            or not math.isfinite(float(completed))
            or float(completed) < float(started)
            or (
                is_final
                and retry_delay is not None
            )
            or (
                not is_final
                and (
                    isinstance(retry_delay, bool)
                    or not isinstance(retry_delay, (int, float))
                    or not math.isfinite(float(retry_delay))
                    or float(retry_delay) + 1e-9 < minimum_delay
                    or float(retry_delay)
                    > policy.backoff_maximum_seconds + 1e-9
                )
            )
        ):
            raise EgressPolicyError("signed retry timing is malformed")
        if prior is not None:
            prior_completed = prior.get("completed_offset_seconds")
            prior_status = prior.get("status")
            prior_status_code = prior.get("status_code")
            prior_retry_delay = prior.get("retry_delay_seconds")
            if (
                not isinstance(prior_completed, (int, float))
                or isinstance(prior_completed, bool)
                or not isinstance(prior_retry_delay, (int, float))
                or isinstance(prior_retry_delay, bool)
                or (
                    prior_status == "RESPONSE"
                    and prior_status_code not in policy.retry_statuses
                )
                or prior_status not in {"RESPONSE", "TRANSPORT_FAILURE"}
                or float(started) + 1e-9
                < float(prior_completed) + float(prior_retry_delay)
            ):
                raise EgressPolicyError(
                    "signed retry timing violates the egress policy"
                )
        prior = attempt


@dataclass(frozen=True)
class PreparedEgressRequest:
    """Validated transport input. Credential material is passed separately."""

    request_id: str
    method: str
    url: str
    host: str
    target: str
    headers: tuple[tuple[str, str], ...]
    body: bytes = field(repr=False)
    content_type: str = "application/json"
    timeout_seconds: float = 30.0
    maximum_response_bytes: int = 8 * 1024 * 1024
    attempt_number: int = 1
    cumulative_bytes_before_attempt: int = 0
    deadline_elapsed_seconds: float = 0.0
    credential_header: str | None = None
    credential_prefix: str = ""
    _deadline_monotonic: float | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    _capability: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )


def _prepared_request_claim(request: PreparedEgressRequest) -> dict[str, object]:
    return {
        "request_id": request.request_id,
        "method": request.method,
        "url": request.url,
        "host": request.host,
        "target": request.target,
        "headers": [list(value) for value in request.headers],
        "body_sha256": _safe_hash(request.body),
        "body_size": len(request.body),
        "content_type": request.content_type,
        "timeout_seconds": request.timeout_seconds,
        "maximum_response_bytes": request.maximum_response_bytes,
        "attempt_number": request.attempt_number,
        "cumulative_bytes_before_attempt": (
            request.cumulative_bytes_before_attempt
        ),
        "deadline_elapsed_seconds": request.deadline_elapsed_seconds,
        "credential_header": request.credential_header,
        "credential_prefix": request.credential_prefix,
    }


def _prepared_request_binding(request: PreparedEgressRequest) -> str:
    return _safe_hash(canonical_json_bytes(_prepared_request_claim(request)))


class _PmcProgressAccountingError(EgressDeniedError):
    """Terminal UNKNOWN progress; never manufacture an attempt or receipt."""


def _egress_policy_claim(policy: EgressPolicy) -> dict[str, object]:
    """Return the complete frozen policy without any credential value."""

    return {
        "policy_id": policy.policy_id,
        "adapter_id": policy.adapter_id,
        "allowed_hosts": list(policy.allowed_hosts),
        "allowed_path_prefixes": list(policy.allowed_path_prefixes),
        "allowed_methods": list(policy.allowed_methods),
        "allowed_query_keys": list(policy.allowed_query_keys),
        "allowed_request_headers": list(policy.allowed_request_headers),
        "allowed_request_content_types": list(
            policy.allowed_request_content_types
        ),
        "allowed_response_content_types": list(
            policy.allowed_response_content_types
        ),
        "recorded_response_headers": list(policy.recorded_response_headers),
        "maximum_request_bytes": policy.maximum_request_bytes,
        "maximum_response_bytes": policy.maximum_response_bytes,
        "maximum_total_bytes": policy.maximum_total_bytes,
        "timeout_seconds": policy.timeout_seconds,
        "budget_semantics": _egress_budget_policy_claim(policy),
        "minimum_interval_seconds": policy.minimum_interval_seconds,
        "maximum_requests": policy.maximum_requests,
        "maximum_attempts": policy.maximum_attempts,
        "retry_statuses": list(policy.retry_statuses),
        "backoff_initial_seconds": policy.backoff_initial_seconds,
        "backoff_maximum_seconds": policy.backoff_maximum_seconds,
        "maximum_json_depth": policy.maximum_json_depth,
        "maximum_json_items": policy.maximum_json_items,
        "credential_env_name": policy.credential_env_name,
        "credential_required": policy.credential_required,
        "credential_header": policy.credential_header,
        "credential_prefix": policy.credential_prefix,
        "enabled": policy.enabled,
    }


def _pmc_wire_response_facts(response):
    if type(response) is not TransportResponse:
        raise EgressDeniedError("PMC wire response must be exact")
    headers = _headers(response.headers, caller_supplied=False)
    controls = tuple((name.lower(), value) for name, value in headers if name.lower() in {
        "content-type", "content-encoding", "content-length", "transfer-encoding", "retry-after"})
    return (response.status_code, _safe_hash(response.body), len(response.body), response.effective_url,
            controls, _safe_hash(canonical_json_bytes([list(pair) for pair in headers])), len(headers))


def _capture_pmc_wire_rules(registry, rules, wall):
    from .pmc_coordination import project_pmc_schedule
    projection = project_pmc_schedule(rules, utc_unix_ns=wall)
    if projection.weekday_0500_2100_window:
        raise EgressDeniedError("PMC schedule rules refuse admission")
    record = registry.put_bytes(
        rules, logical_type="pmc_schedule_rules", origin="source-owned PMC schedule rule observation",
        creator_role=Role.EVIDENCE_CURATOR, creation_command=("scientist-one", "pmc-schedule-rules"),
        parent_artifacts=(), schema_version=PMC_RULES_SCHEMA, mime_type="application/octet-stream",
        validation_result="PASS", frozen=True,
    )
    _require_pmc_wire_rules(registry, record.sha256, record.record_hash, wall)
    return record


def _require_pmc_wire_rules(registry, sha256, record_hash, wall):
    from .pmc_coordination import project_pmc_schedule
    registry.verify(sha256, raise_on_error=True)
    record = registry.get_metadata(sha256)
    rules = registry.get_bytes(sha256)
    if (record.record_hash != record_hash or record.logical_type != "pmc_schedule_rules"
            or record.origin != "source-owned PMC schedule rule observation"
            or record.creator_role is not Role.EVIDENCE_CURATOR
            or record.creation_command != ("scientist-one", "pmc-schedule-rules") or record.parent_artifacts
            or record.schema_version != PMC_RULES_SCHEMA or record.mime_type != "application/octet-stream"
            or record.validation_result != "PASS" or record.frozen is not True
            or not 1 <= len(rules) <= 65536
            or project_pmc_schedule(rules, utc_unix_ns=wall).weekday_0500_2100_window):
        raise EgressPolicyError("PMC schedule rule custody differs")
    return record


def _build_prepared_request_authority() -> tuple[
    Callable[..., None],
    Callable[..., Any],
    Callable[[Callable[..., ArtifactRecord | None]], None],
    Callable[..., None],
    Callable[..., None],
    Callable[..., tuple],
]:
    """Create the sole request-capability state and authority-issuer binding.

    Inspecting arbitrary closure cells together, reading the private key as the
    same local user, or rewriting trusted source is a trusted-kernel compromise
    reported as ``BLOCKED_LOCAL``; it is not cryptographic process isolation.
    """

    exact_prepared_request_binding = _prepared_request_binding
    exact_pmc_profile = _pmc_content_profile
    exact_native_clock = time.monotonic
    exact_native_sleep = time.sleep
    exact_policy_claim = _egress_policy_claim
    exact_canonical, exact_hash = canonical_json_bytes, _safe_hash
    exact_prepared_claim = _prepared_request_claim
    require_wire_activation = _require_pmc_wire_activation
    response_facts, capture_rules = _pmc_wire_response_facts, _capture_pmc_wire_rules
    from .pmc_coordination import _pmc_floor_deadline_ns, _pmc_trace_ns, _pmc_trace_uuid
    floor_deadline, exact_ns, exact_uuid = _pmc_floor_deadline_ns, _pmc_trace_ns, _pmc_trace_uuid
    outcome_keys = frozenset({"kind", "coordinator_uuid", "boot_uuid", "sequence", "request_id",
                              "prepared_claim_sha256", "policy_claim_sha256", "attempt_number", "observed_ns"})
    issued: dict[
        int,
        tuple[
            object,
            object,
            object,
            PreparedEgressRequest,
            str,
            str,
            bool,
            bool,
            bool,
            str,
            object,
            int | None,
            object,
            object,
            str | None,
            tuple,
            tuple | None,
        ],
    ] = {}
    authority_signer: Callable[..., ArtifactRecord | None] | None = None
    progress_inspector = None
    progress_admissible = None
    progress_pre_request = None

    def unknown():
        raise _PmcProgressAccountingError("PMC_PROGRESS_UNKNOWN")

    def bind_progress_owner(lifecycle_type, parser_type):
        nonlocal progress_inspector, progress_admissible, progress_pre_request
        if progress_inspector is not None:
            unknown()
        # Exact member descriptors are captured once; no replaceable instance
        # property/getter/deadline callback is consulted by the bridge.
        lifecycle_slots = {name: lifecycle_type.__dict__[name].__get__ for name in
                           ("_prepared", "_used", "_network", "_ownership", "_framing", "_count", "_reader")}
        parser_slots = {name: parser_type.__dict__[name].__get__ for name in ("_prepared", "_used", "_count")}

        def admissible(owner, prepared):
            return (type(owner) is lifecycle_type
                    and lifecycle_slots["_prepared"](owner) is prepared
                    and lifecycle_slots["_used"](owner) is False
                    and lifecycle_slots["_reader"](owner) is None
                    and type(lifecycle_slots["_count"](owner)) is int
                    and lifecycle_slots["_count"](owner) == 0)

        def inspect(owner, prepared):
            if type(owner) is not lifecycle_type or lifecycle_slots["_prepared"](owner) is not prepared:
                unknown()
            values = {name: getter(owner) for name, getter in lifecycle_slots.items()}
            if any(type(values[name]) is not bool for name in ("_used", "_network", "_ownership", "_framing")):
                unknown()
            copied = values["_count"]
            if type(copied) is not int or copied < 0:
                unknown()
            parser = values["_reader"]
            if parser is None:
                if values["_network"] or values["_ownership"] or values["_framing"] or copied != 0:
                    unknown()
                return 0  # Known no-reader/body-count prefix, not native no-I/O or NOT_SENT proof.
            if (type(parser) is not parser_type or parser_slots["_prepared"](parser) is not prepared
                    or parser_slots["_used"](parser) is not True
                    or not values["_used"] or not values["_network"] or not values["_ownership"]):
                unknown()
            count = parser_slots["_count"](parser)
            if (type(count) is not int or not 0 <= count <= MAX_ABSOLUTE_RESPONSE_BYTES + 1
                    or copied not in (0, count) or (not values["_framing"] and copied != 0)):
                unknown()
            return count

        progress_admissible, progress_inspector = admissible, inspect
        def pre_request(owner, prepared):
            return (type(owner) is lifecycle_type and lifecycle_slots["_prepared"](owner) is prepared
                    and lifecycle_slots["_network"](owner) is False)
        progress_pre_request = pre_request

    def register_progress(prepared, transport, lifecycle):
        if type(prepared) is not PreparedEgressRequest:
            unknown()
        capability = prepared._capability
        row = issued.get(id(capability))
        if row is None or row[0] is not capability or row[3] is not prepared:
            unknown()
        # Once registration is attempted for this exact row, failure is required
        # UNKNOWN, never optional generic absence even if a caller catches it.
        issued[id(capability)] = (*row[:9], "UNKNOWN", None, None, *row[12:])
        if (progress_admissible is None or row[2] is not transport
                or getattr(row[1], "transport", None) is not transport
                or row[4] != prepared.request_id or row[5] != exact_prepared_request_binding(prepared)
                or row[6] is not True or row[7] is not False or row[8] is not True
                or row[9] != "OPTIONAL" or not progress_admissible(lifecycle, prepared)):
            unknown()
        issued[id(capability)] = (*row[:9], "REGISTERED", lifecycle, None, *row[12:])

    def attempt_admission(prepared, transport):
        if type(prepared) is not PreparedEgressRequest:
            unknown()
        capability = prepared._capability
        row = issued.get(id(capability))
        if row is None or row[0] is not capability or row[3] is not prepared:
            unknown()
        gateway = row[1]

        def refuse():
            raise EgressDeniedError("PMC_OUTCOME_UNAVAILABLE")

        def poison():
            current = issued.get(id(capability))
            if current is not None and current[0] is capability and not current[15][4]:
                issued[id(capability)] = (*current[:15], ("UNKNOWN", *current[15][1:]), *current[16:])

        def current_row():
            current = issued.get(id(capability))
            if (current is None or current[0] is not capability or current[1] is not gateway
                    or current[2] is not transport or gateway.transport is not transport
                    or current[3] is not prepared or prepared._capability is not capability
                    or current[4] != prepared.request_id
                    or current[5] != exact_prepared_request_binding(prepared)
                    or current[6] is not True or current[7] is not False or current[8] is not True
                    or current[15][4]):
                refuse()
            return current

        # Mandatory before any fallible admission check; failure is sticky and
        # cannot reset the independent progress/count state to OPTIONAL.
        original_outcome = row[15]
        if not original_outcome[4]:
            issued[id(capability)] = (*row[:15], ("REQUIRED", *original_outcome[1:]), *row[16:])
        try:
            row = current_row()
            if (original_outcome[0] != "OPTIONAL" or row[9] != "OPTIONAL"
                    or row[12] is None or row[13] is None or row[14] is None):
                refuse()
        except BaseException:
            poison()
            raise

        def record_projection(value, current, pending):
            if (type(value) is not dict or len(value) not in (9, 10)
                    or any(type(key) is not str or len(key) > 32 for key in value)):
                refuse()
            kind = value.get("kind")
            if type(kind) is not str or len(kind) > 32 or kind not in {
                    "PENDING", "NOT_SENT", "LOCAL_CLOSED_COMPLETE", "LOCAL_CLOSED_ABORTED"}:
                refuse()
            extra = {"deadline_seconds"} if kind == "PENDING" else set() if kind == "NOT_SENT" else {"cleanup_ns"}
            if set(value) != outcome_keys | extra:
                refuse()
            exact_uuid(value["coordinator_uuid"])
            exact_uuid(value["boot_uuid"])
            exact_ns(value["sequence"], positive=True)
            exact_ns(value["attempt_number"], positive=True)
            observed = exact_ns(value["observed_ns"])
            for name in ("request_id", "prepared_claim_sha256", "policy_claim_sha256"):
                item = value[name]
                if type(item) is not str or len(item) != 64 or re.fullmatch(r"[0-9a-f]{64}", item) is None:
                    refuse()
            if (value["request_id"] != current[4] or value["prepared_claim_sha256"] != current[5]
                    or value["policy_claim_sha256"] != current[14]
                    or value["attempt_number"] != prepared.attempt_number):
                refuse()
            if pending is None:
                if (kind != "PENDING" or type(value["deadline_seconds"]) is not float
                        or value["deadline_seconds"] != current[12][1]
                        or observed >= floor_deadline(value["deadline_seconds"])):
                    refuse()
            else:
                prior = dict(pending)
                if (kind == "PENDING" or observed < prior["observed_ns"]
                        or any(value[key] != prior[key] for key in outcome_keys - {"kind", "observed_ns"})):
                    refuse()
                if kind != "NOT_SENT":
                    cleanup = exact_ns(value["cleanup_ns"])
                    if not prior["observed_ns"] <= cleanup <= observed:
                        refuse()
            return tuple(sorted(value.items()))

        def event(kind, record=None):
            try:
                current = current_row()
                phase, pending, terminal, finalized, settled = current[15]
                if finalized or phase not in {"REQUIRED", "UNKNOWN"}:
                    refuse()
                if kind == "FINALIZED":
                    finalized = True  # Independent diagnostic, never repairs UNKNOWN.
                elif phase == "UNKNOWN":
                    refuse()
                elif kind == "PENDING":
                    if pending is not None or terminal is not None:
                        refuse()
                    pending = record_projection(record, current, None)
                else:
                    if pending is None or terminal is not None:
                        refuse()
                    terminal = record_projection(record, current, pending)
                issued[id(capability)] = (*current[:15], (phase, pending, terminal, finalized, settled), *current[16:])
            except BaseException as error:
                poison()
                if isinstance(error, Exception):
                    refuse()
                raise

        def pending_confirmed(record):
            event("PENDING", record)

        def terminal_confirmed(record):
            event("TERMINAL", record)

        def mark_finalized():
            event("FINALIZED")

        def schedule_observed(observation):
            try:
                current = current_row()
                if (current[16] is None or current[15][0] != "REQUIRED" or current[15][1] is None
                        or current[15][3] or not progress_pre_request(current[10], prepared)
                        or type(observation) is not tuple or len(observation) != 4):
                    refuse()
                rules, wall, start, end = observation
                if (type(rules) is not bytes or not 1 <= len(rules) <= 65536
                        or type(wall) is not int or not -(1 << 63) <= wall < (1 << 63)
                        or not dict(current[15][1])["observed_ns"] <= exact_ns(start) <= exact_ns(end)
                        < floor_deadline(current[12][1])):
                    refuse()
                issued[id(capability)] = (*current[:16], (observation, current[16][1], current[16][2]))
            except BaseException as error:
                poison()
                if isinstance(error, Exception):
                    refuse()
                raise

        def response_observed(response):
            try:
                current = current_row()
                phase, pending, terminal, finalized, _ = current[15]
                if (current[16] is None or current[16][0] is None or current[16][1] is not None
                        or phase != "REQUIRED" or pending is None or terminal is None or not finalized
                        or dict(terminal)["kind"] != "LOCAL_CLOSED_COMPLETE"
                        or type(response) is not TransportResponse):
                    refuse()
                schedule = current[16][0]
                if not schedule[3] <= dict(terminal)["cleanup_ns"] <= dict(terminal)["observed_ns"] < floor_deadline(current[12][1]):
                    refuse()
                facts = response_facts(response)
                if facts[3] != prepared.url:
                    refuse()
                issued[id(capability)] = (*current[:16], (schedule, facts, None))
            except BaseException as error:
                poison()
                if isinstance(error, Exception):
                    refuse()
                raise

        return row[12], row[13], row[14], row[5], (pending_confirmed, terminal_confirmed, mark_finalized,
                                                 schedule_observed, response_observed)

    def consume(request: PreparedEgressRequest, transport: object) -> None:
        if not isinstance(request, PreparedEgressRequest):
            raise EgressDeniedError("prepared HTTPS request must be typed")
        capability = request._capability
        admitted = issued.get(id(capability)) if capability is not None else None
        if (
            admitted is None
            or admitted[0] is not capability
            or admitted[2] is not transport
            or admitted[3] is not request
            or admitted[4] != request.request_id
            or admitted[5] != exact_prepared_request_binding(request)
            or admitted[6]
            or admitted[7]
        ):
            raise EgressDeniedError(
                "prepared egress authority is invalid or already used"
            )
        issued[id(capability)] = (*admitted[:6], True, False, *admitted[8:])

    def bind_authority_signer(
        signer: Callable[..., ArtifactRecord | None],
    ) -> None:
        nonlocal authority_signer
        if authority_signer is not None or not callable(signer):
            raise RuntimeError("gateway authority issuer binding is invalid")
        authority_signer = signer

    def authority_issuer(
        capability: object,
        *,
        gateway: object,
        **kwargs: object,
    ) -> ArtifactRecord | None:
        """Consume exact transport proof before invoking the hidden signer."""

        admitted = issued.get(id(capability))
        signer = authority_signer
        if (
            signer is None
            or admitted is None
            or admitted[0] is not capability
            or admitted[1] is not gateway
            or admitted[2] is not getattr(gateway, "transport", None)
            or admitted[3]._capability is not capability
            or admitted[4] != admitted[3].request_id
            or admitted[5] != exact_prepared_request_binding(admitted[3])
            or admitted[6] is not True
            or admitted[7] is not True
        ):
            return None
        # Consume before signing. A second call, cross-request token, or
        # recovered issuer callable without this exact token fails closed.
        del issued[id(capability)]
        return signer(
            gateway,
            prepared_request=admitted[3],
            prepared_request_binding=admitted[5],
            **kwargs,
        )

    def admit_execute(method: Callable[..., Any]) -> Callable[..., Any]:
        def admitted_execute(
            self: object,
            request: EgressRequest,
            *,
            parent_artifacts: Sequence[str] = (),
        ) -> GatewayResult:
            gateway = self
            native_timing = None
            admitted_policy = gateway.policy
            pmc_selected = exact_pmc_profile(admitted_policy, request)
            wire_selected = admitted_policy.adapter_id == PMC_WIRE_ADAPTER_ID
            if wire_selected:
                require_wire_activation()
            if pmc_selected:
                start = exact_native_clock()
                native_timing = (start, start + admitted_policy.timeout_seconds,
                                 exact_native_clock, exact_native_sleep)
            admitted_policy_hash = (exact_hash(exact_canonical(exact_policy_claim(admitted_policy)))
                                    if pmc_selected else None)
            owned_capabilities: set[int] = set()

            def issue(prepared: PreparedEgressRequest) -> object:
                if not isinstance(prepared, PreparedEgressRequest):
                    raise EgressDeniedError("prepared HTTPS request must be typed")
                capability = object()
                issued[id(capability)] = (
                    capability,
                    gateway,
                    gateway.transport,
                    prepared,
                    prepared.request_id,
                    exact_prepared_request_binding(prepared),
                    False,
                    False,
                    pmc_selected,
                    "OPTIONAL",
                    None,
                    None,
                    native_timing,
                    admitted_policy if pmc_selected else None,
                    admitted_policy_hash,
                    ("OPTIONAL", None, None, False, False),
                    (None, None, None) if wire_selected else None,
                )
                owned_capabilities.add(id(capability))
                object.__setattr__(prepared, "_capability", capability)
                return capability

            def consumed(capability: object) -> bool:
                admitted = issued.get(id(capability))
                return bool(
                    admitted is not None
                    and admitted[0] is capability
                    and admitted[1] is gateway
                    and admitted[6]
                    and not admitted[7]
                )

            def revoke(capability: object) -> None:
                admitted = issued.get(id(capability))
                if (
                    admitted is not None
                    and admitted[0] is capability
                    and admitted[1] is gateway
                ):
                    issued[id(capability)] = (*admitted[:7], True, *admitted[8:])

            def settle_progress(capability):
                row = issued.get(id(capability))
                if row is None or row[0] is not capability or row[1] is not gateway:
                    unknown()
                if row[9] == "OPTIONAL":
                    issued[id(capability)] = (*row[:9], "OPTIONAL_SETTLED", None, None, *row[12:])
                    return None
                if (row[9] != "REGISTERED" or row[6] is not True or row[7] is not False
                        or row[2] is not gateway.transport or row[3]._capability is not capability
                        or row[4] != row[3].request_id
                        or row[5] != exact_prepared_request_binding(row[3])):
                    unknown()
                issued[id(capability)] = (*row[:9], "UNKNOWN", None, None, *row[12:])
                try:
                    count = progress_inspector(row[10], row[3])
                except Exception:
                    unknown()
                issued[id(capability)] = (*row[:9], "SETTLED", None, count, *row[12:])
                return count

            def issue_execution_authority(
                capability: object,
                **kwargs: object,
            ) -> ArtifactRecord | None:
                if wire_selected:
                    rows = [issued.get(value) for value in owned_capabilities]
                    if (not rows or any(row is None or row[1] is not gateway or row[16] is None
                                        or row[16][2] is None or row[6] is not True or row[7] is not True
                                        or row[9] != "SETTLED" or row[15][0] != "REQUIRED"
                                        or row[15][3:] != (True, True) for row in rows)):
                        raise EgressDeniedError("PMC wire invocation custody is incomplete")
                    rows.sort(key=lambda row: row[3].attempt_number)
                    expected = tuple(safe_json_loads(row[16][2]) for row in rows)
                    if (len(rows) != len(kwargs["attempts"]) or rows[-1][0] is not capability
                            or response_facts(kwargs["response"]) != rows[-1][16][1]
                            or any(row[3].attempt_number != index for index, row in enumerate(rows, 1))):
                        raise EgressDeniedError("PMC wire invocation attempts differ")
                    for attempt, projection, row in zip(kwargs["attempts"], expected, rows):
                        if (any(attempt.get(key) != value for key, value in projection.items())
                                or attempt.get("status_code") != row[16][1][0]
                                or attempt.get("body_sha256") != row[16][1][1]
                                or attempt.get("body_size") != row[16][1][2]
                                or attempt.get("response_body_bytes") != row[11]):
                            raise EgressDeniedError("PMC wire invocation response differs")
                    kwargs["pmc_wire_rows"] = expected
                    for row in rows[:-1]:
                        del issued[id(row[0])]
                return authority_issuer(
                    capability,
                    gateway=gateway,
                    **kwargs,
                )

            def project_wire_attempt(capability, response, raw_record):
                if not wire_selected:
                    return None
                row = issued.get(id(capability))
                if (row is None or row[1] is not gateway or row[2] is not gateway.transport
                        or row[6] is not True or row[7] is not True or row[9] != "SETTLED"
                        or row[15][0] != "REQUIRED" or row[15][3:] != (True, True)
                        or row[16] is None or row[16][1] != response_facts(response)
                        or row[16][2] is not None or row[11] != len(response.body)
                        or type(raw_record) is not ArtifactRecord or gateway.registry is None):
                    raise EgressDeniedError("PMC wire source projection unavailable")
                rules, wall, start, end = row[16][0]
                registry = gateway.registry
                registry.verify(raw_record.sha256, raise_on_error=True)
                if (registry.get_metadata(raw_record.sha256) != raw_record
                        or raw_record.sha256 != exact_hash(response.body)):
                    raise EgressDeniedError("PMC wire raw custody differs")
                now = row[12][2]()
                if type(now) is not float or not row[12][0] <= now < row[12][1]:
                    raise EgressDeniedError("PMC wire rules deadline exhausted")
                rules_record = capture_rules(registry, rules, wall)
                now = row[12][2]()
                if type(now) is not float or not row[12][0] <= now < row[12][1]:
                    raise EgressDeniedError("PMC wire rules deadline exhausted")
                pending, terminal = dict(row[15][1]), dict(row[15][2])
                value = {
                    "prepared_request": exact_prepared_claim(row[3]), "prepared_request_binding": row[5],
                    "raw_response_record_hash": raw_record.record_hash,
                    "control_headers": [list(pair) for pair in row[16][1][4]],
                    "coordination": {
                        "profile": PMC_COORDINATION_PROFILE, "coordinator_uuid": pending["coordinator_uuid"].decode("ascii"),
                        "boot_uuid": pending["boot_uuid"].decode("ascii"), "sequence": pending["sequence"],
                        "pending_observed_ns": pending["observed_ns"], "deadline_seconds_hex": row[12][1].hex(),
                        "terminal_kind": terminal["kind"], "terminal_observed_ns": terminal["observed_ns"],
                        "cleanup_ns": terminal["cleanup_ns"], "finalized": True,
                        "schedule": {"utc_unix_ns": wall, "observation_start_ns": start, "observation_end_ns": end,
                                     "rules_artifact_sha256": rules_record.sha256,
                                     "rules_artifact_record_hash": rules_record.record_hash},
                    },
                }
                if exact_hash(exact_canonical(value["prepared_request"])) != row[5]:
                    raise EgressDeniedError("PMC wire prepared custody differs")
                issued[id(capability)] = (*row[:16], (*row[16][:2], exact_canonical(value)))
                return value

            def settle_outcome(capability):
                row = issued.get(id(capability))
                # Burn settlement before fallible binding revalidation. A later
                # repaired DTO cannot make a failed settlement eligible again.
                if row is not None and row[0] is capability and row[1] is gateway and not row[15][4]:
                    issued[id(capability)] = (*row[:15], ("UNKNOWN", *row[15][1:4], True), *row[16:])
                if (row is None or row[0] is not capability or row[1] is not gateway
                        or row[2] is not gateway.transport or row[3]._capability is not capability
                        or row[4] != row[3].request_id or row[5] != exact_prepared_request_binding(row[3])
                        or row[7] is not False or row[15][4]):
                    raise EgressDeniedError("PMC_OUTCOME_UNAVAILABLE")
                phase, pending, terminal, finalized, _ = row[15]
                issued[id(capability)] = (*row[:15], (phase, pending, terminal, finalized, True), *row[16:])
                if phase == "OPTIONAL":
                    return None
                return (phase == "REQUIRED" and row[6] is True and pending is not None
                        and terminal is not None and dict(terminal)["kind"] == "LOCAL_CLOSED_COMPLETE"
                        and finalized)

            primary = None
            try:
                return method(
                    gateway,
                    request,
                    parent_artifacts=parent_artifacts,
                    _issue_prepared=issue,
                    _capability_consumed=consumed,
                    _revoke_capability=revoke,
                    _issue_execution_authority=issue_execution_authority,
                    _native_timing=native_timing,
                    _settle_pmc_progress=settle_progress,
                    _settle_pmc_outcome=settle_outcome,
                    _project_pmc_wire_attempt=project_wire_attempt,
                )
            except BaseException as error:
                primary = error
                raise
            finally:
                for capability_id in owned_capabilities:
                    try:
                        issued.pop(capability_id, None)
                    except BaseException:
                        if primary is None:
                            raise

        admitted_execute.__name__ = method.__name__
        admitted_execute.__qualname__ = method.__qualname__
        admitted_execute.__doc__ = method.__doc__
        return admitted_execute

    def wire_selected(request, transport):
        row = issued.get(id(request._capability))
        return (row is not None and row[0] is request._capability and row[2] is transport
                and row[3] is request and row[6] is True and row[7] is False
                and row[8] is True and type(row[13]) is EgressPolicy
                and row[13].adapter_id == PMC_WIRE_ADAPTER_ID)

    return consume, admit_execute, bind_authority_signer, register_progress, bind_progress_owner, attempt_admission, wire_selected


(
    _consume_prepared_request,
    _admit_gateway_execute,
    _bind_transport_authority_issuer,
    _register_pmc_exchange_progress,
    _bind_pmc_progress_owner,
    _pmc_attempt_admission,
    _pmc_wire_prepared_selected,
) = _build_prepared_request_authority()
del _build_prepared_request_authority


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes = field(repr=False)
    effective_url: str = ""

    def __post_init__(self) -> None:
        _bounded_integer(self.status_code, "HTTP status", minimum=100, maximum=599)
        object.__setattr__(self, "headers", _headers(self.headers, caller_supplied=False))
        if not isinstance(self.body, bytes) or len(self.body) > MAX_ABSOLUTE_RESPONSE_BYTES:
            raise EgressDeniedError("response exceeds the absolute byte contract")
        _bounded_text(self.effective_url, "effective URL", maximum=MAX_URL_BYTES)


class EgressTransport(Protocol):
    """Transport contract; implementations never expose credential values."""

    network_used: bool
    inherits_proxy_environment: bool
    scientific_evidence: bool
    external_validation: str

    def send(
        self,
        request: PreparedEgressRequest,
        *,
        credential: str | None,
    ) -> TransportResponse: ...


class FixtureTransport:
    """Deterministic offline transport for schema and boundary tests only."""

    network_used = False
    inherits_proxy_environment = False
    scientific_evidence = False
    external_validation = "UNTESTED"

    def __init__(self, responses: Sequence[TransportResponse]) -> None:
        if isinstance(responses, (str, bytes)) or not isinstance(responses, Sequence):
            raise EgressPolicyError("fixture responses must be a bounded sequence")
        if not responses or len(responses) > MAX_ATTEMPTS:
            raise EgressPolicyError("fixture response count is invalid")
        if any(not isinstance(response, TransportResponse) for response in responses):
            raise EgressPolicyError("fixture responses must be typed")
        self._responses = tuple(responses)
        self._position = 0
        self.sent_request_ids: list[str] = []
        self.credential_present: list[bool] = []
        self.prepared_requests: list[PreparedEgressRequest] = []

    def send(
        self,
        request: PreparedEgressRequest,
        *,
        credential: str | None,
    ) -> TransportResponse:
        _consume_prepared_request(request, self)
        if self._position >= len(self._responses):
            raise TransportFailure("fixture transport has no remaining response")
        self.sent_request_ids.append(request.request_id)
        self.credential_present.append(credential is not None)
        self.prepared_requests.append(request)
        response = self._responses[self._position]
        self._position += 1
        return response


def _stdlib_tls_context_is_audited(value: object) -> bool:
    """Recognize the exact certificate-verifying client context we support."""

    return (
        type(value) is ssl.SSLContext
        and not vars(value)
        and value.protocol == ssl.PROTOCOL_TLS_CLIENT
        and value.check_hostname is True
        and value.verify_mode == ssl.CERT_REQUIRED
        and value.minimum_version >= ssl.TLSVersion.TLSv1_2
        and value.sslsocket_class is ssl.SSLSocket
        and value.sslobject_class is ssl.SSLObject
        and value.keylog_filename is None
    )


def _build_bounded_response_reader() -> Callable[..., bytes]:
    """Retain exact known body-byte counts when a bounded read fails."""

    exact_incomplete_read = http.client.IncompleteRead
    exact_partial_failure = _PartialResponseTransportFailure
    exact_egress_denied = EgressDeniedError
    exact_egress_policy_error = EgressPolicyError
    read_chunk_bytes = 64 * 1024

    def incomplete_read_byte_count(error: BaseException) -> int:
        count = 0
        seen: set[int] = set()
        current: BaseException | None = error
        while type(current) is exact_incomplete_read and id(current) not in seen:
            seen.add(id(current))
            partial = current.partial
            if type(partial) is not bytes:
                break
            count += len(partial)
            cause = current.__cause__
            current = cause if isinstance(cause, BaseException) else None
        return count

    def read_bounded_response_body(
        response: object,
        connection: object,
        request: PreparedEgressRequest,
        *,
        deadline_remaining: Callable[[PreparedEgressRequest], float],
    ) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                remaining = deadline_remaining(request)
                socket_value = connection.sock
                if socket_value is not None:
                    socket_value.settimeout(remaining)
                chunk = response.read(
                    min(
                        read_chunk_bytes,
                        request.maximum_response_bytes + 1 - total,
                    )
                )
            except (exact_egress_denied, exact_egress_policy_error):
                if total:
                    raise exact_partial_failure(
                        "external HTTPS response read was denied",
                        response_body_bytes=total,
                        policy_denial=True,
                    ) from None
                raise
            except exact_incomplete_read as exc:
                received = total + incomplete_read_byte_count(exc)
                raise exact_partial_failure(
                    "external HTTPS response body was incomplete",
                    response_body_bytes=received,
                    policy_denial=(
                        received > request.maximum_response_bytes
                    ),
                ) from None
            except Exception:
                # An arbitrary read exception may have consumed bytes into a
                # buffered layer without exposing them. Retain every byte we
                # can prove, but make the attempt terminal so unknown bytes
                # can never be reset by a retry or enter positive authority.
                raise exact_partial_failure(
                    "external HTTPS response read failed",
                    response_body_bytes=total,
                    policy_denial=True,
                ) from None
            if type(chunk) is not bytes:
                if total:
                    raise exact_partial_failure(
                        "external HTTPS response read was untyped",
                        response_body_bytes=total,
                        policy_denial=True,
                    )
                raise exact_egress_denied(
                    "external HTTPS response read was untyped"
                )
            if not chunk:
                break
            total += len(chunk)
            if total > request.maximum_response_bytes:
                raise exact_partial_failure(
                    "response exceeds the configured byte limit",
                    response_body_bytes=total,
                    policy_denial=True,
                )
            chunks.append(chunk)
        try:
            deadline_remaining(request)
            return b"".join(chunks)
        except (exact_egress_denied, exact_egress_policy_error):
            if total:
                raise exact_partial_failure(
                    "external HTTPS response deadline was exhausted",
                    response_body_bytes=total,
                    policy_denial=True,
                ) from None
            raise
        except Exception:
            if total:
                raise exact_partial_failure(
                    "external HTTPS response assembly failed",
                    response_body_bytes=total,
                ) from None
            raise

    return read_bounded_response_body


_read_bounded_response_body = _build_bounded_response_reader()
del _build_bounded_response_reader


# BEGIN PRIVATE PMC FRAMING CANDIDATE
def _build_pmc_framed_response_reader():
    """Capture a private supplied-stream parser, never native request authority."""
    exact_type, exact_bytes, exact_str, exact_int = type, bytes, str, int
    exact_float, exact_len, exact_min = float, len, min
    exact_exception, exact_base_exception = Exception, BaseException
    exact_prepared, exact_headers = PreparedEgressRequest, _headers
    exact_partial, exact_incomplete = _PartialResponseTransportFailure, http.client.IncompleteRead
    exact_finite, exact_join = math.isfinite, b"".join
    maximum_body, line_limit = MAX_ABSOLUTE_RESPONSE_BYTES, 8192
    head_limit, trailer_limit, syntax_limit = 65536, 65536, 1048576
    token = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    decimal, hexadecimal = frozenset(b"0123456789"), frozenset(b"0123456789abcdefABCDEF")
    trailer_controls = frozenset({
        "content-length", "transfer-encoding", "content-encoding", "content-type", "trailer",
        "host", "connection", "proxy-connection", "retry-after", "location",
    })

    def refuse():
        raise ValueError("PMC_FRAMING_INVALID")

    def visible(raw):
        return all(value == 9 or 32 <= value <= 126 or value >= 128 for value in raw)

    def number(raw, base, cap):
        alphabet = decimal if base == 10 else hexadecimal
        if not raw or any(value not in alphabet for value in raw):
            refuse()
        significant = raw.lstrip(b"0").lower() or b"0"
        bound = (str(cap) if base == 10 else format(cap, "x")).encode("ascii")
        if (exact_len(significant) > exact_len(bound)
                or (exact_len(significant) == exact_len(bound) and significant > bound)):
            refuse()
        return exact_int(significant, base)

    def field(raw):
        colon = raw.find(b":")
        if colon <= 0 or any(value not in token for value in raw[:colon]):
            refuse()
        value = raw[colon + 1:].strip(b" \t")
        if not visible(value):
            refuse()
        return raw[:colon].decode("ascii"), value.decode("iso-8859-1")

    def extensions(raw, cursor):
        length = exact_len(raw)

        def bws(index):
            while index < length and raw[index] in (32, 9):
                index += 1
            return index

        def take_token(index):
            start = index
            while index < length and raw[index] in token:
                index += 1
            if index == start:
                refuse()
            return index

        while cursor < length:
            cursor = bws(cursor)
            if cursor == length or raw[cursor] != 59:
                refuse()
            cursor = take_token(bws(cursor + 1))
            after_name = cursor
            probe = bws(cursor)
            if probe < length and raw[probe] == 61:
                cursor = bws(probe + 1)
                if cursor < length and raw[cursor] == 34:
                    cursor += 1
                    while True:
                        if cursor == length:
                            refuse()
                        value = raw[cursor]
                        cursor += 1
                        if value == 34:
                            break
                        if value == 92:
                            if cursor == length or not (raw[cursor] == 9 or 32 <= raw[cursor] <= 126):
                                refuse()
                            cursor += 1
                        elif not (value in (9, 32, 33) or 35 <= value <= 91 or 93 <= value <= 126):
                            refuse()
                else:
                    cursor = take_token(cursor)
            else:
                # BWS belongs to a following semicolon, never a trailing suffix.
                cursor = after_name

    class _PmcFramedResponseReader:
        """Single-use private framing evidence over supplied handles, no authority."""
        __slots__ = ("_stream", "_socket", "_prepared", "_remaining", "_used", "_failed",
                     "_count", "_head_bytes", "_syntax_bytes", "_trailer_bytes", "_cap")

        def __init__(self, *, stream, retained_socket, prepared, deadline_remaining):
            self._stream, self._socket = stream, retained_socket
            self._prepared, self._remaining = prepared, deadline_remaining
            self._used = self._failed = False
            self._count = self._head_bytes = self._syntax_bytes = self._trailer_bytes = 0
            self._cap = 0

        @property
        def response_body_bytes(self):
            return self._count

        def _deadline(self, *, refresh=False):
            if self._failed:
                refuse()
            remaining = self._remaining(self._prepared)
            if (exact_type(remaining) not in (exact_float, exact_int)
                    or not exact_finite(remaining) or remaining <= 0):
                refuse()
            if refresh:
                self._socket.settimeout(remaining)
            if self._failed:
                refuse()

        def _operation(self, amount, *, line=False, body=False):
            self._deadline(refresh=True)
            try:
                value = self._stream.readline(amount) if line else self._stream.read(amount)
            except exact_incomplete as error:
                if (exact_type(error) is exact_incomplete and body
                        and exact_type(error.partial) is exact_bytes and exact_len(error.partial) <= amount):
                    self._count += exact_len(error.partial)
                raise
            if exact_type(value) is not exact_bytes or exact_len(value) > amount:
                refuse()
            if body:
                self._count += exact_len(value)
            self._deadline()
            return value

        def _syntax(self, count, *, trailer=False):
            self._syntax_bytes += count
            if self._syntax_bytes > syntax_limit:
                refuse()
            if trailer:
                self._trailer_bytes += count
                if self._trailer_bytes > trailer_limit:
                    refuse()

        def _line(self, *, head=False, trailer=False):
            pieces, size = [], 0
            while size < line_limit:
                part = self._operation(line_limit - size, line=True)
                if not part:
                    refuse()
                size += exact_len(part)
                if head:
                    self._head_bytes += exact_len(part)
                    if self._head_bytes > head_limit:
                        refuse()
                else:
                    self._syntax(exact_len(part), trailer=trailer)
                pieces.append(part)
                if b"\n" in part:
                    raw = exact_join(pieces)
                    if not raw.endswith(b"\r\n") or b"\n" in raw[:-2] or b"\r" in raw[:-2]:
                        refuse()
                    return raw[:-2]
            refuse()

        def _head(self):
            raw = self._line(head=True)
            if (exact_len(raw) < 13 or raw[:9] not in (b"HTTP/1.0 ", b"HTTP/1.1 ")
                    or raw[12:13] != b" " or not visible(raw[13:])
                    or any(value not in decimal for value in raw[9:12])):
                refuse()
            status = exact_int(raw[9:12])
            if not 100 <= status <= 599 or status == 101:
                refuse()
            values = []
            while True:
                line = self._line(head=True)
                if not line:
                    break
                if exact_len(values) == 64:
                    refuse()
                values.append(field(line))
            headers = exact_headers(tuple(values), caller_supplied=False)
            by_name = {name.lower(): value for name, value in headers}
            if ("upgrade" in by_name or "upgrade" in {
                    item.strip(" \t").lower() for item in by_name.get("connection", "").split(",")
            }):
                refuse()
            return raw[:8], status, headers, by_name

        def _body_data(self, amount, pieces):
            while amount:
                part = self._operation(exact_min(65536, amount), body=True)
                if not part:
                    refuse()
                pieces.append(part)
                amount -= exact_len(part)

        def _delimiter(self):
            pieces, remaining = [], 2
            while remaining:
                part = self._operation(remaining)
                if not part:
                    refuse()
                self._syntax(exact_len(part))
                pieces.append(part)
                remaining -= exact_len(part)
            if exact_join(pieces) != b"\r\n":
                refuse()

        def _trailers(self, header_names):
            trailers, names = [], set()
            while True:
                raw = self._line(trailer=True)
                if not raw:
                    break
                if exact_len(trailers) == 64:
                    refuse()
                name, value = field(raw)
                lowered = name.lower()
                if lowered in names or lowered in header_names or lowered in trailer_controls:
                    refuse()
                names.add(lowered)
                trailers.append((name, value))
            exact_headers(tuple(trailers), caller_supplied=False)

        def _chunks(self, cap, header_names, pieces):
            while True:
                raw = self._line()
                cursor = 0
                while cursor < exact_len(raw) and raw[cursor] in hexadecimal:
                    cursor += 1
                size = number(raw[:cursor], 16, cap - self._count)
                extensions(raw, cursor)
                if size == 0:
                    self._trailers(header_names)
                    return
                self._body_data(size, pieces)
                self._delimiter()

        @staticmethod
        def _assemble(pieces):
            return exact_join(pieces)

        def read(self):
            if self._used:
                self._failed = True
                raise exact_partial("PMC framed response reader is single use",
                                    response_body_bytes=self._count, policy_denial=True)
            self._used = True  # Burn before any supplied/deadline operation.
            failed = False
            try:
                prepared = self._prepared
                if (exact_type(prepared) is not exact_prepared or exact_type(prepared.method) is not exact_str
                        or prepared.method != "GET" or exact_type(prepared.maximum_response_bytes) is not exact_int
                        or prepared.maximum_response_bytes < 0):
                    refuse()
                self._cap = exact_min(maximum_body, prepared.maximum_response_bytes)
                informational = 0
                while True:
                    version, status, headers, controls = self._head()
                    length, transfer = controls.get("content-length"), controls.get("transfer-encoding")
                    if length is not None and transfer is not None:
                        refuse()
                    if status >= 200:
                        break
                    informational += 1
                    if informational > 8 or length is not None or transfer is not None:
                        refuse()
                if transfer is not None and (transfer.lower() != "chunked" or version != b"HTTP/1.1"):
                    refuse()
                cap = (1 << 63) - 1 if status == 304 else 0 if status == 205 else self._cap
                declared = None if length is None else number(length.encode("ascii"), 10, cap)
                pieces = []
                if status == 204:
                    if length is not None or transfer is not None:
                        refuse()
                elif status == 304:
                    pass  # Metadata length/TE never causes body reads or charges.
                elif transfer is not None:
                    self._chunks(cap, set(controls), pieces)
                elif declared is not None:
                    self._body_data(declared, pieces)
                else:
                    refuse()
                body = self._assemble(pieces)
                self._deadline()
                return status, headers, body
            except exact_exception:
                self._failed = failed = True
            except exact_base_exception:
                self._failed = True
                raise
            if failed:
                # Outside the handler: no explicit underlying cause/context or
                # partial content attributes survive in the fixed failure.
                raise exact_partial("PMC response framing was refused",
                                    response_body_bytes=self._count, policy_denial=True) from None

    return _PmcFramedResponseReader


_PmcFramedResponseReader = _build_pmc_framed_response_reader()
del _build_pmc_framed_response_reader
# END PRIVATE PMC FRAMING CANDIDATE


# BEGIN PRIVATE PMC EXCHANGE CANDIDATE
def _build_pmc_exchange_lifecycle():
    import errno
    import io
    import socket

    socket_types = (socket.socket, ssl.SSLSocket)
    raw_type, buffer_type = socket.SocketIO, io.BufferedReader
    prepared_type, validate_headers = PreparedEgressRequest, _headers
    reader_type, failure_type = _PmcFramedResponseReader, _PartialResponseTransportFailure

    def refuse():
        raise ValueError("PMC_EXCHANGE_REFUSED")

    def positive(value):
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            refuse()
        return value

    def initial_socket(value):
        if (type(value) not in socket_types or value._closed is not False
                or type(value._io_refs) is not int or value._io_refs != 0):
            refuse()
        descriptor = value.fileno()
        if type(descriptor) is not int or descriptor < 0:
            refuse()
        return descriptor

    class _PmcExchangeLifecycle:
        """Private supplied-connection observations, never native authority."""

        __slots__ = ("_connection", "_prepared", "_headers", "_remaining", "_used", "_poisoned",
                     "_network", "_ownership", "_framing", "_cleanup", "_count", "_reader",
                     "_socket", "_descriptor", "_raw", "_buffer")

        def __init__(self, *, connection, prepared, headers, deadline_remaining):
            self._connection, self._prepared = connection, prepared
            self._headers, self._remaining = headers, deadline_remaining
            self._used = self._poisoned = False
            self._network = self._ownership = self._framing = self._cleanup = False
            self._count = 0
            self._reader = self._socket = self._descriptor = self._raw = self._buffer = None

        @property
        def network_started(self):
            return self._network

        @property
        def ownership_complete(self):
            return self._ownership

        @property
        def framing_complete(self):
            return self._framing

        @property
        def local_cleanup_complete(self):
            return self._cleanup

        @property
        def response_body_bytes(self):
            return self._count if self._reader is None else self._reader.response_body_bytes

        def _deadline(self):
            if self._poisoned:
                refuse()
            value = positive(self._remaining(self._prepared))
            if self._poisoned:
                refuse()
            return value

        def _bindings(self):
            if (self._connection.sock is not self._socket
                    or type(self._raw) is not raw_type or self._raw.closed
                    or self._raw.mode != "rb" or self._raw._sock is not self._socket
                    or type(self._socket._io_refs) is not int or self._socket._io_refs != 1
                    or self._socket._closed is not False
                    or self._socket.fileno() != self._descriptor):
                refuse()

        def _capture(self):
            # Capture before any post-request deadline hook. Partial captures
            # remain retained but cannot be upgraded by successful cleanup.
            attached = self._connection.sock
            if self._socket is not None and attached is not self._socket:
                refuse()
            self._socket = attached
            self._descriptor = initial_socket(attached)
            self._raw = attached.makefile("rb", buffering=0)
            self._bindings()
            self._buffer = io.BufferedReader(self._raw)
            if (type(self._buffer) is not buffer_type or self._buffer.raw is not self._raw
                    or self._buffer.closed):
                refuse()
            self._bindings()
            self._ownership = True

        def _close(self, primary):
            clean = True

            def remember(error):
                nonlocal primary, clean
                clean = False
                if primary is None:
                    primary = error
                else:
                    try:
                        BaseException.add_note(primary, "PMC_EXCHANGE_SECONDARY_CLEANUP_FAILURE")
                    except BaseException:
                        pass  # Optional diagnostics never replace the primary or skip cleanup.

            # Two alias groups, each attempted once. Never retry a raw/socket
            # close after the owning buffer/connection close was attempted.
            if self._buffer is not None:
                try:
                    if (type(self._buffer) is not buffer_type or self._buffer.raw is not self._raw
                            or type(self._raw) is not raw_type or self._raw._sock is not self._socket):
                        refuse()
                    self._buffer.close()
                except BaseException as error:
                    remember(error)
            elif self._raw is not None:
                try:
                    if type(self._raw) is not raw_type or self._raw._sock is not self._socket:
                        refuse()
                    self._raw.close()
                except BaseException as error:
                    remember(error)

            matched = self._socket is None
            if self._socket is not None:
                try:
                    matched = self._connection.sock is self._socket
                    if not matched:
                        refuse()
                except BaseException as error:
                    remember(error)
                    matched = False
            try:
                if matched:
                    self._connection.close()
                elif type(self._socket) in socket_types:
                    self._socket.close()
            except BaseException as error:
                remember(error)

            if self._ownership and clean:
                try:
                    if (self._buffer.raw is not self._raw or self._buffer.closed is not True
                            or self._raw.closed is not True or self._raw._sock is not None
                            or type(self._socket._io_refs) is not int or self._socket._io_refs != 0
                            or self._connection.sock is not None or self._socket.fileno() != -1):
                        refuse()
                    try:
                        os.fstat(self._descriptor)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise
                    else:
                        refuse()
                    self._cleanup = True
                except BaseException as error:
                    remember(error)
            return primary

        def run(self):
            if self._used:
                self._poisoned = True
                raise failure_type("PMC exchange is single use", response_body_bytes=self.response_body_bytes,
                                   policy_denial=True)
            self._used = True
            primary, result = None, None
            try:
                prepared = self._prepared
                if (type(prepared) is not prepared_type or type(prepared.method) is not str
                        or prepared.method != "GET" or type(prepared.body) is not bytes
                        or prepared.body != b"" or prepared.credential_header is not None
                        or type(prepared.maximum_response_bytes) is not int
                        or prepared.maximum_response_bytes < 0):
                    refuse()
                if (type(self._headers) is not tuple or any(
                        type(pair) is not tuple or len(pair) != 2
                        or any(type(value) is not str for value in pair) for pair in self._headers)):
                    refuse()
                headers = dict(validate_headers(self._headers, caller_supplied=True))
                timeout = min(positive(prepared.timeout_seconds), self._deadline())
                self._connection.timeout = timeout
                attached = self._connection.sock
                if attached is not None:
                    initial_socket(attached)
                    self._socket = attached
                    attached.settimeout(timeout)
                self._deadline()
                self._network = True
                self._connection.request(prepared.method, prepared.target, body=None, headers=headers)
                self._capture()
                self._deadline()
                self._reader = reader_type(stream=self._buffer, retained_socket=self._socket,
                                           prepared=prepared, deadline_remaining=lambda request: self._deadline())
                result = self._reader.read()
                self._framing = True
                self._count = self._reader.response_body_bytes
            except BaseException as error:
                primary = error
            primary = self._close(primary)
            if primary is None:
                try:
                    if not self._cleanup:
                        refuse()
                    self._deadline()
                except BaseException as error:
                    primary = error
            if primary is not None:
                if not isinstance(primary, Exception):
                    raise primary
                # Outside exception handlers: no underlying chain or text is
                # published. The count remains owned even through cancellation.
                raise failure_type("PMC exchange was refused", response_body_bytes=self.response_body_bytes,
                                   policy_denial=True) from None
            return result

    return _PmcExchangeLifecycle


_PmcExchangeLifecycle = _build_pmc_exchange_lifecycle()
del _build_pmc_exchange_lifecycle
_bind_pmc_progress_owner(_PmcExchangeLifecycle, _PmcFramedResponseReader)
del _bind_pmc_progress_owner
# END PRIVATE PMC EXCHANGE CANDIDATE


# BEGIN PRIVATE PMC COMPOSED ATTEMPT
def _build_pmc_attempt_driver():
    from .pmc_coordination import _PmcAttemptNativeOwner, _PmcStoreDeadlineExpired

    native_type, expiry_type = _PmcAttemptNativeOwner, _PmcStoreDeadlineExpired
    # Import-time factory runs before deliberate deletion of the temporary binding.
    admission, register = _pmc_attempt_admission, _register_pmc_exchange_progress  # noqa: F821
    classify_transport = _classify_transport_authority
    exact_transport_type = StdlibHttpsTransport
    lifecycle_type, response_type = _PmcExchangeLifecycle, TransportResponse
    connection_type = http.client.HTTPSConnection
    create_tls, audit_tls = ssl.create_default_context, _stdlib_tls_context_is_audited
    require_wire_activation = _require_pmc_wire_activation
    close_connection = connection_type.close
    getters = {name: lifecycle_type.__dict__[name].__get__ for name in
               ("_prepared", "_used", "_network", "_ownership", "_framing", "_cleanup", "_connection")}
    bind_connection = lifecycle_type.__dict__["_connection"].__set__
    run_exchange = lifecycle_type.run

    def refuse():
        raise EgressDeniedError("PMC_ATTEMPT_REFUSED")

    def execute(prepared, transport):
        if (type(transport) is not exact_transport_type
                or classify_transport(transport) != AUDITED_LIVE_TRANSPORT_AUTHORITY):
            refuse()
        timing, policy, policy_hash, prepared_hash, outcome_writers = admission(prepared, transport)
        pending_confirmed, terminal_confirmed, mark_finalized = outcome_writers[:3]
        if type(policy) is not EgressPolicy or policy.adapter_id not in {PMC_CONTENT_ADAPTER_ID, PMC_WIRE_ADAPTER_ID}:
            refuse()
        wire_selected = policy.adapter_id == PMC_WIRE_ADAPTER_ID
        if wire_selected:
            require_wire_activation()
        start, deadline, clock, _ = timing
        last = start
        lifecycle = native = connection = None
        request_entered = construction_entered = run_entered = False
        not_sent_allowed = False
        primary, result = None, None

        def remaining():
            nonlocal last
            now = clock()
            if (type(now) not in (int, float) or not math.isfinite(now)
                    or now < last or now >= deadline):
                refuse()
            last = now
            return deadline - now

        def exchange_remaining(request):
            nonlocal request_entered
            if (request is not prepared or type(lifecycle) is not lifecycle_type
                    or getters["_prepared"](lifecycle) is not prepared):
                refuse()
            entered = getters["_network"](lifecycle)
            if type(entered) is not bool or (request_entered and not entered):
                refuse()
            request_entered = request_entered or entered
            remaining()
            if not request_entered:
                observed_schedule = native.schedule()
                if wire_selected:
                    outcome_writers[3](observed_schedule)
            return remaining()

        # This allocation/registration precedes acquisition, locking and TLS or
        # connection construction. Its zero count is not a no-I/O certificate.
        headers = (*prepared.headers, ("Accept-Encoding", "gzip, deflate" if wire_selected else "identity"))
        lifecycle = lifecycle_type(connection=None, prepared=prepared, headers=headers,
                                   deadline_remaining=exchange_remaining)
        register(prepared, transport, lifecycle)
        try:
            remaining()
            native = native_type(deadline)
            native.open()
            remaining()
            try:
                pending = native.begin_pending({
                    "request_id": prepared.request_id, "prepared_claim_sha256": prepared_hash,
                    "policy_claim_sha256": policy_hash, "attempt_number": prepared.attempt_number,
                })
            except expiry_type:
                # The unchanged store guard, NOT this exception, establishes
                # whether an owned confirmed pending exists on the expiry path.
                not_sent_allowed = True
                raise
            native.confirm(pending)
            not_sent_allowed = True
            pending_confirmed(pending)
            remaining()
            native.schedule()
            remaining()
            construction_entered = True
            tls = create_tls()
            if not audit_tls(tls):
                refuse()
            owned = connection_type(prepared.host, 443,
                                    timeout=min(prepared.timeout_seconds, remaining()), context=tls)
            if type(owned) is not connection_type:
                refuse()
            connection = owned
            if (type(lifecycle) is not lifecycle_type or getters["_prepared"](lifecycle) is not prepared
                    or getters["_used"](lifecycle) is not False
                    or getters["_connection"](lifecycle) is not None):
                refuse()
            bind_connection(lifecycle, connection)
            run_entered = True
            result = run_exchange(lifecycle)
        except BaseException as error:
            primary = error

        # Independent cleanup/publication steps preserve the first actual
        # primary, never an ambient exception from the caller's handled block.
        try:
            if not_sent_allowed and not construction_entered:
                terminal = native.terminal("NOT_SENT")
                native.confirm(terminal)
                terminal_confirmed(terminal)
            elif run_entered:
                ownership, cleanup, framing = (getters[name](lifecycle)
                                                for name in ("_ownership", "_cleanup", "_framing"))
                if any(type(value) is not bool for value in (ownership, cleanup, framing)):
                    refuse()
                if ownership and cleanup:
                    terminal = native.terminal("LOCAL_CLOSED_COMPLETE" if framing else "LOCAL_CLOSED_ABORTED")
                    native.confirm(terminal)
                    terminal_confirmed(terminal)
                elif primary is None:
                    refuse()
        except BaseException as error:
            if primary is None:
                primary = error
        if connection is not None and not run_entered:
            try:
                close_connection(connection)
            except BaseException as error:
                if primary is None:
                    primary = error
        if native is not None:
            try:
                native.close()
                mark_finalized()
            except BaseException as error:
                if primary is None:
                    primary = error
        if primary is None:
            try:
                remaining()
                if result is None:
                    refuse()
                status, response_headers, body = result
                response = response_type(status, response_headers, body, prepared.url)
                if wire_selected:
                    outcome_writers[4](response)
                return response
            except BaseException as error:
                primary = error
        if not isinstance(primary, Exception):
            raise primary
        # Gateway settlement owns count inspection; don't dispatch the public
        # lifecycle property or manufacture a scalar if the registered state is lost.
        raise EgressDeniedError("PMC_ATTEMPT_REFUSED") from None

    return execute


# END PRIVATE PMC COMPOSED ATTEMPT


def _build_stdlib_https_send() -> Callable[..., TransportResponse]:
    """Bind the audited transport call chain before caller hooks can run.

    The gateway deliberately accepts replaceable clocks, sleepers, and secret
    resolvers.  Those callbacks run before transport dispatch and therefore
    must not be able to substitute a module global only for the interval
    between the gateway's pre- and post-send integrity observations.  The
    exact implementation objects below are captured once, checked again at
    the send boundary, and then used directly.
    """

    module_namespace = globals()
    exact_consume_prepared_request = _consume_prepared_request
    exact_wire_selected = _pmc_wire_prepared_selected  # noqa: F821 - deleted after one-time capture
    require_wire_activation = _require_pmc_wire_activation
    pmc_driver = None
    exact_create_default_context = ssl.create_default_context
    exact_tls_context_is_audited = _stdlib_tls_context_is_audited
    exact_headers = _headers
    exact_media_type = _media_type
    exact_header_value = _header_value
    exact_bounded_text = _bounded_text
    exact_bounded_integer = _bounded_integer
    exact_https_connection = http.client.HTTPSConnection
    exact_read_bounded_response_body = _read_bounded_response_body
    exact_partial_failure = _PartialResponseTransportFailure
    exact_response_type = TransportResponse
    exact_response_init = exact_response_type.__dict__["__init__"]
    exact_object_new = object.__new__
    exact_object_getattribute = object.__getattribute__
    exact_http_module = http
    exact_http_client_module = http.client
    exact_socket_module = exact_http_client_module.socket
    exact_create_connection = exact_socket_module.create_connection
    exact_ssl_module = ssl
    exact_time_module = time
    exact_monotonic = time.monotonic
    exact_isfinite = math.isfinite
    exact_egress_denied = EgressDeniedError
    exact_egress_policy_error = EgressPolicyError
    exact_transport_failure = TransportFailure
    exact_header_re = _HEADER_RE
    exact_media_type_re = _MEDIA_TYPE_RE
    exact_forbidden_headers = _FORBIDDEN_CALLER_HEADERS
    exact_sequence_type = Sequence
    exact_max_headers = MAX_HEADERS
    exact_max_header_bytes = MAX_HEADER_BYTES
    exact_max_response_bytes = MAX_ABSOLUTE_RESPONSE_BYTES
    exact_max_url_bytes = MAX_URL_BYTES
    def namespace_snapshot(value: object) -> tuple[tuple[str, object], ...]:
        return tuple(vars(value).items())

    def namespace_is_unchanged(
        value: object,
        expected: tuple[tuple[str, object], ...],
    ) -> bool:
        current = vars(value)
        return len(current) == len(expected) and all(
            current.get(name) is member for name, member in expected
        )

    exact_http_client_namespace = namespace_snapshot(
        exact_http_client_module
    )
    exact_socket_namespace = namespace_snapshot(exact_socket_module)
    exact_ssl_namespace = namespace_snapshot(exact_ssl_module)

    identity_bindings = (
        ("_consume_prepared_request", exact_consume_prepared_request),
        ("_stdlib_tls_context_is_audited", exact_tls_context_is_audited),
        ("_headers", exact_headers),
        ("_media_type", exact_media_type),
        ("_header_value", exact_header_value),
        ("_bounded_text", exact_bounded_text),
        ("_bounded_integer", exact_bounded_integer),
        ("_HEADER_RE", exact_header_re),
        ("_MEDIA_TYPE_RE", exact_media_type_re),
        ("_FORBIDDEN_CALLER_HEADERS", exact_forbidden_headers),
        ("Sequence", exact_sequence_type),
        ("TransportResponse", exact_response_type),
        ("EgressDeniedError", exact_egress_denied),
        ("EgressPolicyError", exact_egress_policy_error),
        ("TransportFailure", exact_transport_failure),
        ("_PartialResponseTransportFailure", exact_partial_failure),
        ("_read_bounded_response_body", exact_read_bounded_response_body),
    )
    value_bindings = (
        ("MAX_HEADERS", exact_max_headers),
        ("MAX_HEADER_BYTES", exact_max_header_bytes),
        ("MAX_ABSOLUTE_RESPONSE_BYTES", exact_max_response_bytes),
        ("MAX_URL_BYTES", exact_max_url_bytes),
    )

    def call_chain_is_admitted() -> bool:
        return (
            all(
                module_namespace.get(name) is expected
                for name, expected in identity_bindings
            )
            and all(
                type(module_namespace.get(name)) is type(expected)
                and module_namespace.get(name) == expected
                for name, expected in value_bindings
            )
            and module_namespace.get("http") is exact_http_module
            and exact_http_module.client is exact_http_client_module
            and exact_http_client_module.HTTPSConnection is exact_https_connection
            and exact_http_client_module.socket is exact_socket_module
            and exact_socket_module.create_connection
            is exact_create_connection
            and module_namespace.get("ssl") is exact_ssl_module
            and exact_ssl_module.create_default_context
            is exact_create_default_context
            and module_namespace.get("time") is exact_time_module
            and exact_time_module.monotonic is exact_monotonic
            and math.isfinite is exact_isfinite
            and namespace_is_unchanged(
                exact_http_client_module,
                exact_http_client_namespace,
            )
            and namespace_is_unchanged(
                exact_socket_module,
                exact_socket_namespace,
            )
            and namespace_is_unchanged(
                exact_ssl_module,
                exact_ssl_namespace,
            )
        )

    def exact_transport_response(
        *,
        status_code: int,
        headers: tuple[tuple[str, str], ...],
        body: bytes,
        effective_url: str,
    ) -> TransportResponse:
        candidate = exact_object_new(exact_response_type)
        exact_response_init(
            candidate,
            status_code=status_code,
            headers=headers,
            body=body,
            effective_url=effective_url,
        )
        if (
            type(candidate) is not exact_response_type
            or exact_object_getattribute(candidate, "status_code") != status_code
            or exact_object_getattribute(candidate, "headers") != headers
            or exact_object_getattribute(candidate, "body") != body
            or exact_object_getattribute(candidate, "effective_url")
            != effective_url
        ):
            raise exact_egress_denied(
                "standard-library transport response construction changed"
            )
        return candidate

    def deadline_remaining(request: PreparedEgressRequest) -> float:
        deadline = request._deadline_monotonic
        now = exact_monotonic()
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or not exact_isfinite(float(deadline))
            or not exact_isfinite(now)
        ):
            raise exact_egress_denied("egress deadline is invalid")
        remaining = float(deadline) - now
        if remaining <= 0:
            raise exact_egress_denied("egress deadline is exhausted")
        return remaining

    def send(
        self: object,
        request: PreparedEgressRequest,
        *,
        credential: str | None,
    ) -> TransportResponse:
        if not call_chain_is_admitted():
            raise exact_egress_denied(
                "standard-library HTTPS transport implementation changed"
            )
        exact_consume_prepared_request(request, self)
        if request.host == "pmc.ncbi.nlm.nih.gov":
            if exact_wire_selected(request, self):
                require_wire_activation()
                if pmc_driver is None or credential is not None:
                    raise exact_egress_denied("PMC sender binding is unavailable")
                return pmc_driver(request, self)
            raise exact_egress_denied("live PMC dispatch requires unavailable source coordination")
        tls_context = (
            exact_create_default_context()
            if self._tls_context is None
            else self._tls_context
        )
        if not exact_tls_context_is_audited(tls_context):
            raise exact_egress_denied(
                "standard-library HTTPS transport requires certificate verification"
            )
        prepared_headers = exact_headers(request.headers, caller_supplied=True)
        content_type = exact_media_type(request.content_type, "request content type")
        explicit_content_types = tuple(
            value
            for name, value in prepared_headers
            if name.lower() == "content-type"
        )
        if explicit_content_types and (
            len(explicit_content_types) != 1
            or explicit_content_types[0].strip().lower() != content_type
        ):
            raise exact_egress_denied("request Content-Type is ambiguous")
        headers = {name: value for name, value in prepared_headers}
        headers["Accept-Encoding"] = "identity"
        if request.body and not explicit_content_types:
            headers["Content-Type"] = content_type
        if credential is not None:
            if request.credential_header is None:
                raise exact_transport_failure(
                    "credential supplied without a configured header"
                )
            headers[request.credential_header] = (
                request.credential_prefix + credential
            )
        connection = exact_https_connection(
            request.host,
            443,
            timeout=min(request.timeout_seconds, deadline_remaining(request)),
            context=tls_context,
        )
        try:
            connection.request(
                request.method,
                request.target,
                body=request.body if request.body else None,
                headers=headers,
            )
            # HTTPSConnection.request may perform DNS, TCP connect, TLS, and
            # request writes. Its socket timeout is bounded by the remaining
            # absolute budget; the post-call observation also counts a DNS
            # resolver that does not itself honor socket timeouts.
            remaining = deadline_remaining(request)
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            response = connection.getresponse()
            deadline_remaining(request)
            response_headers = exact_headers(
                tuple(response.getheaders()),
                caller_supplied=False,
            )
            content_length = exact_header_value(
                response_headers,
                "content-length",
            )
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError:
                    raise exact_egress_denied(
                        "response Content-Length is malformed"
                    ) from None
                if declared < 0 or declared > request.maximum_response_bytes:
                    raise exact_egress_denied(
                        "response exceeds the configured byte limit"
                    )
            raw_body = exact_read_bounded_response_body(
                response,
                connection,
                request,
                deadline_remaining=deadline_remaining,
            )
            return exact_transport_response(
                status_code=int(response.status),
                headers=response_headers,
                body=raw_body,
                effective_url=request.url,
            )
        except (
            exact_egress_denied,
            exact_egress_policy_error,
            exact_partial_failure,
        ):
            raise
        except Exception:
            raise exact_transport_failure("external HTTPS request failed") from None
        finally:
            try:
                connection.close()
            except Exception:
                # Closing is best-effort after the response path has already
                # established its result or exact partial-byte failure. Never
                # let cleanup replace that accounting-bearing outcome.
                pass

    send.__name__ = "send"
    send.__qualname__ = "StdlibHttpsTransport.send"
    def bind_pmc_driver(driver):
        nonlocal pmc_driver
        if pmc_driver is not None or driver is not _execute_pmc_coordinated_attempt:
            raise RuntimeError("PMC sender binding is invalid")
        pmc_driver = driver

    return send, bind_pmc_driver


_stdlib_https_send, _bind_stdlib_pmc_driver = _build_stdlib_https_send()


class StdlibHttpsTransport:
    """Direct standard-library TLS transport with no proxy or redirect support."""

    network_used = True
    inherits_proxy_environment = False
    scientific_evidence = False
    external_validation = _LIVE_RESPONSE_VALIDATION

    def __init__(self, *, tls_context: ssl.SSLContext | None = None) -> None:
        # A caller-supplied context remains usable for non-authoritative custom
        # transport testing, but only the internally created default can mint
        # audited-live custody.
        self._tls_context = tls_context

    send = _stdlib_https_send


del _build_stdlib_https_send
del _stdlib_https_send
del _pmc_wire_prepared_selected


def _build_transport_authority_classifier() -> Callable[[object], str]:
    """Capture the approved implementation identity outside caller disclosures."""

    def class_snapshot(value: type[object]) -> tuple[tuple[str, object], ...]:
        return tuple(vars(value).items())

    def class_is_unchanged(
        value: type[object],
        expected: tuple[tuple[str, object], ...],
    ) -> bool:
        current = vars(value)
        return len(current) == len(expected) and all(
            current.get(name) is member for name, member in expected
        )

    exact_transport_type = StdlibHttpsTransport
    exact_send = exact_transport_type.__dict__["send"]
    exact_http_module = http
    exact_http_client_module = http.client
    exact_https_connection = http.client.HTTPSConnection
    exact_socket_module = exact_http_client_module.socket
    exact_create_connection = exact_socket_module.create_connection
    exact_ssl_module = ssl
    exact_create_default_context = ssl.create_default_context
    exact_tls_context_type = ssl.SSLContext
    exact_tls_auditor = _stdlib_tls_context_is_audited
    exact_consume_prepared_request = _consume_prepared_request
    exact_headers = _headers
    exact_media_type = _media_type
    exact_header_value = _header_value
    exact_bounded_text = _bounded_text
    exact_bounded_integer = _bounded_integer
    exact_header_re = _HEADER_RE
    exact_media_type_re = _MEDIA_TYPE_RE
    exact_forbidden_headers = _FORBIDDEN_CALLER_HEADERS
    exact_sequence_type = Sequence
    exact_egress_denied = EgressDeniedError
    exact_egress_policy_error = EgressPolicyError
    exact_transport_failure = TransportFailure
    exact_partial_failure = _PartialResponseTransportFailure
    exact_read_bounded_response_body = _read_bounded_response_body
    exact_max_headers = MAX_HEADERS
    exact_max_header_bytes = MAX_HEADER_BYTES
    exact_max_response_bytes = MAX_ABSOLUTE_RESPONSE_BYTES
    exact_max_url_bytes = MAX_URL_BYTES
    exact_response_type = TransportResponse
    exact_module_namespaces = tuple(
        (value, class_snapshot(value))
        for value in (
            exact_http_client_module,
            exact_socket_module,
            exact_ssl_module,
        )
    )
    exact_class_namespaces = tuple(
        (value, class_snapshot(value))
        for value in (
            TransportResponse,
            _PartialResponseTransportFailure,
            http.client.HTTPConnection,
            http.client.HTTPSConnection,
            http.client.HTTPResponse,
            ssl.SSLContext,
            ssl.SSLSocket,
            ssl.SSLObject,
        )
    )

    def classify(transport: object) -> str:
        try:
            state = vars(transport)
            bound_send = getattr(transport, "send")
            context = state.get("_tls_context")
        except (AttributeError, TypeError):
            return UNVERIFIED_TRANSPORT_AUTHORITY
        if (
            type(transport) is exact_transport_type
            and set(state) == {"_tls_context"}
            and exact_transport_type.__dict__.get("send") is exact_send
            and getattr(bound_send, "__self__", None) is transport
            and getattr(bound_send, "__func__", None) is exact_send
            and exact_transport_type.__dict__.get("network_used") is True
            and exact_transport_type.__dict__.get("inherits_proxy_environment")
            is False
            and exact_transport_type.__dict__.get("scientific_evidence") is False
            and exact_transport_type.__dict__.get("external_validation")
            == _LIVE_RESPONSE_VALIDATION
            and http is exact_http_module
            and http.client is exact_http_client_module
            and http.client.HTTPSConnection is exact_https_connection
            and exact_http_client_module.socket is exact_socket_module
            and exact_socket_module.create_connection
            is exact_create_connection
            and ssl is exact_ssl_module
            and ssl.create_default_context is exact_create_default_context
            and ssl.SSLContext is exact_tls_context_type
            and _stdlib_tls_context_is_audited is exact_tls_auditor
            and _consume_prepared_request is exact_consume_prepared_request
            and _headers is exact_headers
            and _media_type is exact_media_type
            and _header_value is exact_header_value
            and _bounded_text is exact_bounded_text
            and _bounded_integer is exact_bounded_integer
            and _HEADER_RE is exact_header_re
            and _MEDIA_TYPE_RE is exact_media_type_re
            and _FORBIDDEN_CALLER_HEADERS is exact_forbidden_headers
            and Sequence is exact_sequence_type
            and EgressDeniedError is exact_egress_denied
            and EgressPolicyError is exact_egress_policy_error
            and TransportFailure is exact_transport_failure
            and _PartialResponseTransportFailure is exact_partial_failure
            and _read_bounded_response_body
            is exact_read_bounded_response_body
            and type(MAX_HEADERS) is type(exact_max_headers)
            and MAX_HEADERS == exact_max_headers
            and type(MAX_HEADER_BYTES) is type(exact_max_header_bytes)
            and MAX_HEADER_BYTES == exact_max_header_bytes
            and type(MAX_ABSOLUTE_RESPONSE_BYTES)
            is type(exact_max_response_bytes)
            and MAX_ABSOLUTE_RESPONSE_BYTES == exact_max_response_bytes
            and type(MAX_URL_BYTES) is type(exact_max_url_bytes)
            and MAX_URL_BYTES == exact_max_url_bytes
            and TransportResponse is exact_response_type
            and all(
                class_is_unchanged(value, expected)
                for value, expected in exact_module_namespaces
            )
            and all(
                class_is_unchanged(value, expected)
                for value, expected in exact_class_namespaces
            )
            and context is None
        ):
            return AUDITED_LIVE_TRANSPORT_AUTHORITY
        return UNVERIFIED_TRANSPORT_AUTHORITY

    return classify


_classify_transport_authority = _build_transport_authority_classifier()
del _build_transport_authority_classifier

_execute_pmc_coordinated_attempt = _build_pmc_attempt_driver()
_bind_stdlib_pmc_driver(_execute_pmc_coordinated_attempt)
del _bind_stdlib_pmc_driver
del _build_pmc_attempt_driver
del _pmc_attempt_admission


@dataclass(frozen=True)
class AuditedTransportExecutionAuthority:
    """Freshly verified gateway issuance and exact run-ledger anchoring."""

    authority_artifact: ArtifactRecord
    response_receipt_artifact: ArtifactRecord
    request_artifact: ArtifactRecord
    raw_response_artifact: ArtifactRecord
    run_id: str
    request_id: str
    policy_id: str
    body_sha256: str
    body_size: int
    status_code: int
    content_type: str
    ledger_prefix_head_hash: str
    ledger_prefix_event_count: int
    ledger_event_id: str
    ledger_event_hash: str
    key_id: str


@dataclass(frozen=True)
class _AuditedTransportExecutionClaim:
    """Read-only inputs returned to the hidden signer after exact replay."""

    registry: ArtifactRegistry
    ledger: EventLedger
    run_id: str
    response_receipt_artifact: ArtifactRecord
    request_id: str
    captured_at: str
    prefix_head_hash: str
    prefix_event_count: int
    prior_event: LedgerEvent
    unsigned: Mapping[str, object]


@dataclass(frozen=True)
class GatewayResult:
    request_id: str
    retrieval_status: str
    status_code: int
    content_type: str
    body_sha256: str
    body_size: int
    attempts: tuple[Mapping[str, object], ...]
    network_used: bool
    scientific_evidence: bool
    external_validation: str
    transport_authority: str
    captured_at: str
    policy_id: str
    maximum_total_bytes: int
    total_bytes_used: int
    deadline_budget_seconds: float
    deadline_elapsed_seconds: float
    transport_execution_authority_artifact: ArtifactRecord | None = None
    request_artifact: ArtifactRecord | None = None
    raw_response_artifact: ArtifactRecord | None = None
    attempt_raw_response_artifacts: tuple[ArtifactRecord, ...] = ()
    response_receipt_artifact: ArtifactRecord | None = None
    body: bytes = field(default=b"", repr=False)
    content_decoding_artifact: ArtifactRecord | None = None
    decoded_body: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            (self.content_decoding_artifact is None) != (self.decoded_body is None)
            or (self.content_decoding_artifact is not None
                and type(self.content_decoding_artifact) is not ArtifactRecord)
            or (self.decoded_body is not None
                and (type(self.decoded_body) is not bytes or len(self.decoded_body) > 16 * 1024 * 1024))
        ):
            raise EgressPolicyError("decoded content cache is malformed")
        if (
            not isinstance(self.network_used, bool)
            or self.scientific_evidence is not False
            or self.transport_authority
            not in {
                AUDITED_LIVE_TRANSPORT_AUTHORITY,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            }
            or (
                self.transport_authority == AUDITED_LIVE_TRANSPORT_AUTHORITY
                and (
                    self.network_used is not True
                    or self.external_validation != _LIVE_RESPONSE_VALIDATION
                )
            )
            or (
                self.transport_authority == UNVERIFIED_TRANSPORT_AUTHORITY
                and (
                    self.external_validation != "UNTESTED"
                    or self.transport_execution_authority_artifact is not None
                )
            )
            or (
                self.transport_execution_authority_artifact is not None
                and not isinstance(
                    self.transport_execution_authority_artifact,
                    ArtifactRecord,
                )
            )
        ):
            raise EgressPolicyError("external transport bytes cannot be scientific authority")
        object.__setattr__(
            self,
            "attempts",
            tuple(MappingProxyType(dict(value)) for value in self.attempts),
        )
        if (
            not isinstance(self.attempt_raw_response_artifacts, tuple)
            or any(
                not isinstance(value, ArtifactRecord)
                for value in self.attempt_raw_response_artifacts
            )
            or len(
                {value.sha256 for value in self.attempt_raw_response_artifacts}
            )
            != len(self.attempt_raw_response_artifacts)
        ):
            raise EgressPolicyError("attempt raw-response provenance is invalid")


@dataclass(frozen=True)
class _NormalizedTarget:
    url: str
    host: str
    target: str


def _build_authority_registry_classifier() -> Callable[[object], bool]:
    """Pin the registry implementation that stores signed gateway authority."""

    exact_type = ArtifactRegistry
    exact_namespace = tuple(vars(exact_type).items())
    exact_state_fields = {
        "policy",
        "base_path",
        "objects_path",
        "metadata_path",
        "quarantine_path",
        "_root_identity",
        "_base_identity",
        "_metadata_verification_cache",
        "_content_verification_cache",
        "_object_relative_cache",
        "_metadata_relative_cache",
        "_directory_key_cache",
    }
    exact_methods = {
        name: exact_type.__dict__[name]
        for name in ("get_bytes", "get_metadata", "put_json", "verify")
    }

    def classify(value: object) -> bool:
        try:
            state = vars(value)
            namespace = vars(exact_type)
        except (AttributeError, TypeError):
            return False
        if (
            type(value) is not exact_type
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


_is_exact_authority_registry = _build_authority_registry_classifier()
del _build_authority_registry_classifier


def _build_authority_ledger_classifier() -> Callable[[object], bool]:
    """Pin the ledger implementation used to anchor gateway issuance."""

    exact_type = EventLedger
    exact_namespace = tuple(vars(exact_type).items())
    exact_state_fields = {
        "policy",
        "relative_path",
        "path",
        "lock_path",
        "_root_identity",
        "_parent_identity",
    }
    exact_methods = {
        name: exact_type.__dict__[name]
        for name in ("append", "validate")
    }

    def classify(value: object) -> bool:
        try:
            state = vars(value)
            namespace = vars(exact_type)
        except (AttributeError, TypeError):
            return False
        if (
            type(value) is not exact_type
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


_is_exact_authority_ledger = _build_authority_ledger_classifier()
del _build_authority_ledger_classifier


class EgressGateway:
    """The sole audited crossing from research state to external HTTPS."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("the audited egress gateway cannot be subclassed")

    def __setattr__(self, name: str, value: object) -> None:
        if name == "policy" or (
            name == "_policy" and "_policy" in vars(self)
        ):
            raise AttributeError("gateway policy is write-once")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if name in {"policy", "_policy"}:
            raise AttributeError("gateway policy is write-once")
        object.__delattr__(self, name)

    def __init__(
        self,
        policy: EgressPolicy,
        transport: EgressTransport,
        *,
        registry: ArtifactRegistry | None = None,
        secret_resolver: Callable[[str], str | None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        timestamp: Callable[[], str] | None = None,
        authority_run_id: str | None = None,
        authority_ledger: EventLedger | None = None,
    ) -> None:
        if not isinstance(policy, EgressPolicy):
            raise EgressPolicyError("gateway policy must be typed")
        for name, expected in (
            ("network_used", bool),
            ("inherits_proxy_environment", bool),
            ("scientific_evidence", bool),
            ("external_validation", str),
        ):
            if not isinstance(getattr(transport, name, None), expected):
                raise EgressPolicyError("transport disclosure contract is incomplete")
        if transport.inherits_proxy_environment is not False:
            raise EgressDeniedError("proxy-environment inheritance is forbidden")
        if transport.scientific_evidence is not False:
            raise EgressDeniedError("transport cannot declare scientific authority")
        _bounded_text(
            transport.external_validation,
            "transport external_validation",
            maximum=128,
        )
        if (authority_run_id is None) != (authority_ledger is None):
            raise EgressPolicyError(
                "gateway authority run and ledger must be configured together"
            )
        if authority_run_id is not None:
            try:
                validate_identifier(authority_run_id, "gateway authority run ID")
            except ValidationError as exc:
                raise EgressPolicyError("gateway authority run ID is invalid") from exc
            if (
                not _is_exact_authority_registry(registry)
                or not _is_exact_authority_ledger(authority_ledger)
                or authority_ledger.policy.root != registry.policy.root
            ):
                raise EgressPolicyError(
                    "gateway authority requires the exact co-rooted run ledger"
                )
        # Keep the authority snapshot in conventional private, write-once
        # instance state. The property below is the only supported exposure.
        vars(self)["_policy"] = policy
        self.transport = transport
        self._registry = registry
        self._secret_resolver = secret_resolver or os.environ.get
        self._clock = clock
        self._sleeper = sleeper
        self._timestamp = timestamp or (
            lambda: datetime.now(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
        self._request_count = 0
        self._last_request_at: float | None = None
        self._next_request_at: float | None = None
        self._last_clock_at: float | None = None
        self._admission_lock = threading.Lock()
        self._authority_run_id = authority_run_id
        self._authority_ledger = authority_ledger

    @property
    def registry(self) -> ArtifactRegistry | None:
        return self._registry

    @property
    def policy(self) -> EgressPolicy:
        """Expose the immutable policy snapshot without reassignment authority."""

        return vars(self)["_policy"]

    @property
    def transport_authority(self) -> str:
        """Return gateway-derived implementation authority, never transport claims."""

        return _classify_transport_authority(self.transport)

    @property
    def network_used(self) -> bool:
        """Return the transport's factual network-use disclosure."""

        return self.transport.network_used

    @property
    def external_validation(self) -> str:
        """Expose a live label only for the audited built-in implementation."""

        if (
            self.transport_authority == AUDITED_LIVE_TRANSPORT_AUTHORITY
            and self.network_used is True
        ):
            return _LIVE_RESPONSE_VALIDATION
        return "UNTESTED"

    def credential_status(self) -> str:
        policy = self.policy
        name = policy.credential_env_name
        if name is None:
            return "NOT_REQUIRED"
        try:
            value = self._secret_resolver(name)
        except Exception:
            return "UNAVAILABLE"
        return "PRESENT" if isinstance(value, str) and bool(value) else "ABSENT"

    def availability(self) -> str:
        policy = self.policy
        if not policy.enabled:
            return "BLOCKED_EXTERNAL"
        credential_status = self.credential_status()
        if policy.credential_required and credential_status != "PRESENT":
            return "BLOCKED_EXTERNAL"
        # A hostile remote service sees the transport credential and can return
        # an arbitrary reversible representation of it.  Pattern matching
        # therefore cannot prove that a credential-bearing response is safe for
        # ordinary immutable artifact custody.  Keep the real-network path
        # closed until a separately controlled sensitive-response store exists;
        # offline fixture transports remain available for contract testing.
        if credential_status == "PRESENT" and self.network_used is True:
            return "BLOCKED_EXTERNAL"
        if self.transport_authority != AUDITED_LIVE_TRANSPORT_AUTHORITY:
            return "UNTESTED"
        return "AVAILABLE_UNVALIDATED"

    def _credential(self, policy: EgressPolicy) -> str | None:
        name = policy.credential_env_name
        if name is None:
            return None
        try:
            value = self._secret_resolver(name)
        except Exception:
            value = None
        if value is None or value == "":
            if policy.credential_required:
                raise ExternalUnavailableError("required external credential is unavailable")
            return None
        try:
            encoded = value.encode("utf-8") if isinstance(value, str) else b""
        except UnicodeEncodeError:
            encoded = b""
        if (
            not isinstance(value, str)
            or not encoded
            or len(encoded) > 8192
            or "\x00" in value
            or "\r" in value
            or "\n" in value
        ):
            raise ExternalUnavailableError("required external credential is malformed")
        return value

    def _target(
        self,
        request: EgressRequest,
        policy: EgressPolicy,
    ) -> _NormalizedTarget:
        try:
            parsed = urlsplit(request.url)
            port = parsed.port
        except ValueError as exc:
            raise EgressDeniedError("external URL is malformed") from exc
        if parsed.scheme.lower() != "https":
            raise EgressDeniedError("only HTTPS egress is permitted")
        if parsed.username is not None or parsed.password is not None:
            raise EgressDeniedError("URL userinfo is forbidden")
        if parsed.fragment:
            raise EgressDeniedError("URL fragments are forbidden")
        if port not in (None, 443):
            raise EgressDeniedError("non-443 egress ports are forbidden")
        host = parsed.hostname.lower() if isinstance(parsed.hostname, str) else ""
        if not host or host.endswith(".") or not host.isascii() or not _HOST_RE.fullmatch(host):
            raise EgressDeniedError("external host is malformed")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise EgressDeniedError("IP-literal egress targets are forbidden")
        if host not in policy.allowed_hosts:
            raise EgressDeniedError("external host is not allowlisted")
        path = parsed.path or "/"
        if "%" in path:
            raise EgressDeniedError("encoded external paths are forbidden")
        if (
            not path.startswith("/")
            or "\\" in path
            or "//" in path
            or any(part == ".." for part in path.split("/"))
            or any(ord(character) < 32 for character in path)
        ):
            raise EgressDeniedError("external path is unsafe")
        permitted = any(
            path == prefix or (prefix.endswith("/") and path.startswith(prefix))
            for prefix in policy.allowed_path_prefixes
        )
        if not permitted:
            raise EgressDeniedError("external path is not allowlisted")
        query = parsed.query
        if query:
            try:
                pairs = parse_qsl(
                    query,
                    keep_blank_values=True,
                    strict_parsing=True,
                    max_num_fields=64,
                )
            except ValueError as exc:
                raise EgressDeniedError("external query is malformed") from exc
            allowed = set(policy.allowed_query_keys)
            seen_query_keys: set[str] = set()
            for key, value in pairs:
                if key not in allowed:
                    raise EgressDeniedError("external query key is not allowlisted")
                if key in seen_query_keys:
                    raise EgressDeniedError("duplicate external query keys are ambiguous")
                seen_query_keys.add(key)
                if _SENSITIVE_QUERY_RE.search(key):
                    raise EgressDeniedError("credential-like query parameters are forbidden")
                _bounded_text(key, "query key", maximum=128)
                if (
                    len(value.encode("utf-8")) > 4096
                    or "\x00" in value
                    or "\r" in value
                    or "\n" in value
                ):
                    raise EgressDeniedError("external query value exceeds its bound")
        normalized = urlunsplit(("https", host, path, query, ""))
        target = path + (f"?{query}" if query else "")
        return _NormalizedTarget(normalized, host, target)

    def _request_headers(
        self,
        request: EgressRequest,
        policy: EgressPolicy,
    ) -> tuple[tuple[str, str], ...]:
        allowed = set(policy.allowed_request_headers)
        result = _headers(request.headers, caller_supplied=True)
        for name, value in result:
            if name.lower() not in allowed:
                raise EgressDeniedError("request header is not allowlisted")
            if detect_secret_patterns(value):
                raise EgressDeniedError("request header contains secret-like material")
            if (
                name.lower() == "content-type"
                and value.strip().lower() != request.content_type
            ):
                raise EgressDeniedError("request Content-Type is ambiguous")
        if request.idempotency_key is not None:
            if "idempotency-key" not in allowed:
                raise EgressDeniedError("idempotency headers are not allowed by policy")
            if any(name.lower() == "idempotency-key" for name, _ in result):
                raise EgressDeniedError("idempotency key is ambiguously specified")
            self.validate_idempotency_key(
                request.idempotency_key,
                policy=policy,
            )
            result = (*result, ("Idempotency-Key", request.idempotency_key))
        return result

    @staticmethod
    def _secret_labels(payload: bytes) -> tuple[str, ...]:
        labels = list(
            label
            for label in detect_secret_patterns_in_bytes(payload)
            if label != INVALID_UTF8_SECRET_SCAN_LABEL
        )
        decoded = payload.decode("utf-8", errors="replace")
        if _BOUNDARY_SECRET_ASSIGNMENT_RE.search(decoded):
            labels.append("boundary_secret_assignment")
        return tuple(labels)

    def _credential_forms(
        self,
        credential: str | None,
        policy: EgressPolicy | None = None,
    ) -> tuple[bytes, ...]:
        """Return common reversible forms as defense in depth.

        This is deliberately not the authority for credentialed live response
        safety: a remote party can invent unlimited reversible transforms.  The
        pre-request network guard in ``availability``/``execute`` owns that
        guarantee.  These forms protect offline custody and accidental caller
        reflection at every ordinary persistence sink.
        """

        if credential is None:
            return ()
        try:
            raw = credential.encode("utf-8")
            effective_policy = policy if policy is not None else self.policy
            transmitted = (effective_policy.credential_prefix + credential).encode(
                "utf-8"
            )
        except UnicodeEncodeError as exc:
            raise ExternalUnavailableError(
                "configured external credential is malformed"
            ) from exc
        forms: set[bytes] = set()
        for source in (raw, transmitted):
            if not source:
                continue
            forms.add(source)
            hexadecimal = source.hex().encode("ascii")
            forms.add(hexadecimal)
            forms.add(hexadecimal.upper())
            for encoded in (
                base64.b64encode(source),
                base64.urlsafe_b64encode(source),
            ):
                forms.add(encoded)
                unpadded = encoded.rstrip(b"=")
                if unpadded:
                    forms.add(unpadded)
        return tuple(sorted(forms, key=lambda item: (len(item), item), reverse=True))

    def _assert_custody_secret_free(
        self,
        value: bytes,
        *,
        credential: str | None,
        location: str,
        policy: EgressPolicy | None = None,
    ) -> None:
        if any(
            form in value
            for form in self._credential_forms(credential, policy)
        ):
            raise EgressDeniedError(
                f"credential leakage was detected {location}"
            )
        if self._secret_labels(value):
            raise EgressDeniedError(
                f"secret-like material was detected {location}"
            )

    def _assert_no_secret_leakage(
        self,
        *,
        credential: str | None,
        request: EgressRequest | None = None,
        response: TransportResponse | None = None,
        policy: EgressPolicy | None = None,
    ) -> None:
        values: list[bytes] = []
        if request is not None:
            values.append(request.url.encode("utf-8"))
            values.append(request.body)
            values.extend(value.encode("utf-8") for _, value in request.headers)
            if request.idempotency_key is not None:
                values.append(request.idempotency_key.encode("utf-8"))
        if response is not None:
            values.append(response.body)
            values.extend(value.encode("utf-8") for _, value in response.headers)
        for value in values:
            self._assert_custody_secret_free(
                value,
                credential=credential,
                location="at the external boundary",
                policy=policy,
            )

    def validate_custody_bytes(
        self,
        value: bytes,
        *,
        policy: EgressPolicy | None = None,
    ) -> None:
        """Fail closed before exact provider-controlled bytes are persisted."""

        if not isinstance(value, bytes) or len(value) > MAX_ABSOLUTE_REQUEST_BYTES:
            raise EgressPolicyError("provider custody bytes exceed the absolute bound")
        credential: str | None = None
        effective_policy = policy if policy is not None else self.policy
        name = effective_policy.credential_env_name
        if name is not None:
            try:
                candidate = self._secret_resolver(name)
            except Exception:
                candidate = None
            if isinstance(candidate, str) and candidate:
                credential = candidate
        self._assert_custody_secret_free(
            value,
            credential=credential,
            location="in provider custody",
            policy=effective_policy,
        )

    def validate_idempotency_key(
        self,
        value: str,
        *,
        policy: EgressPolicy | None = None,
    ) -> None:
        """Apply the custody secret policy before a key can reach any capture."""

        _bounded_text(value, "idempotency_key", maximum=256)
        self.validate_custody_bytes(value.encode("utf-8"), policy=policy)

    def _register_json(
        self,
        value: Mapping[str, object],
        *,
        logical_type: str,
        origin: str,
        creator_role: Role,
        parents: Sequence[str] = (),
        schema_version: str = "1.0",
    ) -> ArtifactRecord | None:
        if self._registry is None:
            return None
        return self._registry.put_json(
            dict(value),
            logical_type=logical_type,
            origin=origin,
            creator_role=creator_role,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=tuple(parents),
            schema_version=schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def capture_json_artifact(
        self,
        value: Mapping[str, object],
        *,
        logical_type: str,
        origin: str,
        creator_role: Role,
        parents: Sequence[str] = (),
    ) -> ArtifactRecord | None:
        """Register a derived JSON view parented to captured external bytes."""

        if not isinstance(value, Mapping):
            raise EgressPolicyError("derived external artifact must be a mapping")
        if creator_role not in {Role.ORCHESTRATOR, Role.EVIDENCE_CURATOR}:
            raise EgressDeniedError("external artifacts cannot claim unrelated role authority")
        self.validate_custody_bytes(canonical_json_bytes(value))
        return self._register_json(
            value,
            logical_type=logical_type,
            origin=origin,
            creator_role=creator_role,
            parents=parents,
        )

    def capture_custody_bytes(
        self,
        value: bytes,
        *,
        logical_type: str,
        origin: str,
        creator_role: Role,
        mime_type: str,
        parents: Sequence[str] = (),
    ) -> ArtifactRecord:
        """Freeze exact provider input bytes only after boundary secret checks."""

        if self._registry is None:
            raise EgressPolicyError("provider custody requires an artifact registry")
        if creator_role not in {Role.ORCHESTRATOR, Role.EVIDENCE_CURATOR}:
            raise EgressDeniedError("provider custody cannot claim unrelated role authority")
        self.validate_custody_bytes(value)
        return self._registry.put_bytes(
            value,
            logical_type=logical_type,
            origin=origin,
            creator_role=creator_role,
            creation_command=("scientist-one", "provider-custody"),
            parent_artifacts=tuple(parents),
            schema_version="1.0",
            mime_type=mime_type,
            validation_result="PASS",
            frozen=True,
        )

    def _capture_raw(
        self,
        body: bytes,
        *,
        credential: str | None,
        policy: EgressPolicy | None = None,
    ) -> ArtifactRecord | None:
        if self._registry is None:
            return None
        self._assert_custody_secret_free(
            body,
            credential=credential,
            location="in raw external response custody",
            policy=policy,
        )
        return self._registry.put_bytes(
            body,
            logical_type="external_response_raw",
            origin="controlled external egress raw response",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(),
            schema_version="1.0",
            # The receipt records the asserted media type.  The raw object has
            # one stable semantic identity even when two servers label the same
            # bytes differently.
            mime_type="application/octet-stream",
            validation_result="PASS",
            frozen=True,
        )

    def _reserve_rate_limited_attempt(
        self,
        policy: EgressPolicy,
        *,
        deadline_monotonic: float,
        _native_timing: tuple | None = None,
    ) -> tuple[float, float]:
        """Atomically charge one attempt and reserve its monotonic send slot.

        The lock protects only gateway accounting and scheduling.  Callbacks and
        transport I/O run after reservation so cancellation or failure cannot
        release an already-admitted request back into the global quota.
        """

        with self._admission_lock:
            now = float((_native_timing[2] if _native_timing else self._clock)())
            if not math.isfinite(now):
                raise EgressDeniedError("egress rate clock is invalid")
            if self._last_clock_at is not None and now < self._last_clock_at:
                raise EgressDeniedError("egress rate clock moved backwards")
            self._last_clock_at = now
            if self._request_count >= policy.maximum_requests:
                raise EgressDeniedError("egress request budget is exhausted")
            scheduled = max(now, self._next_request_at or now)
            if not math.isfinite(scheduled) or scheduled >= deadline_monotonic:
                raise EgressDeniedError(
                    "egress deadline cannot admit rate-limit sleep"
                )
            self._request_count += 1
            self._last_request_at = scheduled
            self._next_request_at = scheduled + policy.minimum_interval_seconds
            if not math.isfinite(self._next_request_at):
                raise EgressDeniedError("egress rate slot is invalid")
            return scheduled, scheduled - now

    def _complete_rate_limited_reservation(
        self,
        *,
        scheduled_at: float,
        delay: float,
        deadline_monotonic: float,
        _native_timing: tuple | None = None,
    ) -> None:
        if delay > 0:
            (_native_timing[3] if _native_timing else self._sleeper)(delay)
        with self._admission_lock:
            now = float((_native_timing[2] if _native_timing else self._clock)())
            if not math.isfinite(now):
                raise EgressDeniedError("egress rate clock is invalid")
            if self._last_clock_at is not None and now < self._last_clock_at:
                raise EgressDeniedError("egress rate clock moved backwards")
            self._last_clock_at = now
            if now >= deadline_monotonic:
                raise EgressDeniedError("egress deadline is exhausted")
            if delay > 0:
                if now + 1e-9 < scheduled_at:
                    raise EgressDeniedError("egress rate limiter did not advance safely")

    def _response_controls(
        self,
        response: TransportResponse,
        policy: EgressPolicy,
    ) -> str:
        content_header = _header_value(response.headers, "content-type")
        if content_header is None:
            raise EgressDeniedError("response Content-Type is required")
        content_type = _response_media_type(content_header)
        if content_type not in policy.allowed_response_content_types:
            raise EgressDeniedError("response content type is not allowlisted")
        content_encoding = _header_value(response.headers, "content-encoding")
        if policy.adapter_id in {PMC_CONTENT_ADAPTER_ID, PMC_WIRE_ADAPTER_ID}:
            _pmc_content_coding(response.headers)
        elif content_encoding not in (None, "", "identity"):
            raise EgressDeniedError("compressed external responses are forbidden")
        content_length = _header_value(response.headers, "content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                raise EgressDeniedError("response Content-Length is malformed") from None
            if declared < 0 or declared > policy.maximum_response_bytes:
                raise EgressDeniedError("response exceeds the configured byte limit")
            if declared != len(response.body):
                raise EgressDeniedError("response Content-Length differs from captured bytes")
        return content_type

    def _retry_delay(
        self,
        response: TransportResponse | None,
        attempt: int,
        policy: EgressPolicy,
    ) -> float:
        exponential = _retry_backoff_floor(policy, attempt)
        if response is None:
            return exponential
        retry_after = _header_value(response.headers, "retry-after")
        if retry_after is None:
            return exponential
        try:
            value = float(retry_after)
        except ValueError:
            return exponential
        if not math.isfinite(value) or value < 0:
            return exponential
        return min(policy.backoff_maximum_seconds, max(exponential, value))

    @_admit_gateway_execute
    def execute(
        self,
        request: EgressRequest,
        *,
        parent_artifacts: Sequence[str] = (),
        _issue_prepared: Callable[[PreparedEgressRequest], object],
        _capability_consumed: Callable[[object], bool],
        _revoke_capability: Callable[[object], None],
        _issue_execution_authority: Callable[..., ArtifactRecord | None],
        _native_timing: tuple | None = None,
        _settle_pmc_progress: Callable[[object], int | None],
        _settle_pmc_outcome: Callable[[object], bool | None] | None = None,
        _project_pmc_wire_attempt: Callable[..., dict | None] | None = None,
    ) -> GatewayResult:
        # Capture one immutable authority object before any caller-controlled
        # callback can run. Public reassignment is disabled and every decision
        # in this execution receives this exact snapshot explicitly.
        policy = self.policy
        content_profile = _pmc_content_profile(policy, request)
        wire_selected = policy.adapter_id == PMC_WIRE_ADAPTER_ID
        if content_profile != (_native_timing is not None):
            raise EgressPolicyError("PMC native timing was not owned by execute admission")
        clock = _native_timing[2] if content_profile else self._clock
        sleeper = _native_timing[3] if content_profile else self._sleeper
        if not _is_exact_egress_gateway(self):
            raise EgressPolicyError(
                "audited egress execution requires the exact gateway implementation"
            )
        if not isinstance(request, EgressRequest):
            raise EgressPolicyError("gateway request must be typed")
        if not policy.enabled:
            raise ExternalUnavailableError("external access is disabled by policy")
        if request.adapter_id != policy.adapter_id:
            raise EgressDeniedError("request adapter does not match the frozen policy")
        if request.method not in policy.allowed_methods:
            raise EgressDeniedError("request method is not allowlisted")
        if request.content_type not in policy.allowed_request_content_types:
            raise EgressDeniedError("request content type is not allowlisted")
        if len(request.body) > policy.maximum_request_bytes:
            raise EgressDeniedError("request exceeds the configured byte limit")
        if request.method == "GET" and request.body:
            raise EgressDeniedError("GET requests cannot carry a body")
        transport_authority = _classify_transport_authority(self.transport)
        network_used = self.transport.network_used
        policy_claim = MappingProxyType(_egress_policy_claim(policy))
        policy_claim_sha256 = _safe_hash(canonical_json_bytes(policy_claim))
        budget_policy = MappingProxyType(_egress_budget_policy_claim(policy))
        try:
            execution_started = _native_timing[0] if content_profile else float(clock())
        except Exception as exc:
            raise EgressDeniedError("egress deadline clock is unavailable") from exc
        if not math.isfinite(execution_started):
            raise EgressDeniedError("egress deadline clock is invalid")
        deadline_monotonic = (_native_timing[1] if content_profile
                              else execution_started + policy.timeout_seconds)
        if not math.isfinite(deadline_monotonic):
            raise EgressDeniedError("egress deadline is invalid")
        last_observed = execution_started
        request_bytes_used = 0
        response_bytes_used = 0

        def observe_time(*, require_remaining: bool = False) -> float:
            nonlocal last_observed
            try:
                now = float(clock())
            except Exception as exc:
                raise EgressDeniedError(
                    "egress deadline clock is unavailable"
                ) from exc
            if not math.isfinite(now) or now < last_observed:
                raise EgressDeniedError("egress deadline clock is invalid")
            last_observed = now
            if require_remaining and now >= deadline_monotonic:
                raise EgressDeniedError("egress deadline is exhausted")
            return now

        def elapsed(now: float | None = None) -> float:
            observed = last_observed if now is None else now
            return observed - execution_started

        def budget_snapshot(now: float | None = None) -> dict[str, object]:
            observed = last_observed if now is None else now
            return {
                **dict(budget_policy),
                "request_bytes_used": request_bytes_used,
                "response_bytes_used": response_bytes_used,
                "total_bytes_used": request_bytes_used + response_bytes_used,
                "deadline_elapsed_seconds": elapsed(observed),
                "deadline_remaining_seconds": max(
                    0.0,
                    deadline_monotonic - observed,
                ),
                "deadline_satisfied": observed <= deadline_monotonic,
            }

        def observe_transport_authority() -> None:
            nonlocal transport_authority
            if (
                _classify_transport_authority(self.transport)
                != AUDITED_LIVE_TRANSPORT_AUTHORITY
            ):
                transport_authority = UNVERIFIED_TRANSPORT_AUTHORITY

        def effective_external_validation() -> str:
            if (
                transport_authority == AUDITED_LIVE_TRANSPORT_AUTHORITY
                and network_used is True
            ):
                return _LIVE_RESPONSE_VALIDATION
            return "UNTESTED"

        target = self._target(request, policy)
        if target.host == "pmc.ncbi.nlm.nih.gov" and network_used is True and not wire_selected:
            raise ExternalUnavailableError("live PMC dispatch requires unavailable source coordination")
        headers = self._request_headers(request, policy)
        credential = self._credential(policy)
        if credential is not None and network_used is True:
            raise ExternalUnavailableError(
                "credentialed live egress requires unavailable "
                "sensitive-response custody"
            )
        # Replaceable transports are useful for deterministic contract tests,
        # but their ``network_used`` disclosure is not a confidentiality
        # boundary.  Never hand resolved secret material to one: a dishonest
        # implementation could claim to be offline, transform the credential,
        # and return or exfiltrate it.  The only transport eligible to receive
        # a real credential is the exact audited implementation, whose
        # credentialed live path is deliberately blocked above until sensitive
        # response custody exists.
        transport_credential = (
            credential
            if transport_authority == AUDITED_LIVE_TRANSPORT_AUTHORITY
            else None
        )
        self._assert_no_secret_leakage(
            credential=credential,
            request=request,
            policy=policy,
        )

        parent_tuple = tuple(parent_artifacts)
        request_payload: dict[str, object] = {
            "schema_version": EGRESS_REQUEST_SCHEMA,
            "kind": "REDACTED_EXTERNAL_REQUEST",
            "request_id": request.request_id,
            "policy_id": policy.policy_id,
            "policy_claim_sha256": policy_claim_sha256,
            "adapter_id": request.adapter_id,
            "method": request.method,
            "url": target.url,
            "headers": [list(item) for item in headers],
            "body_sha256": _safe_hash(request.body),
            "body_size": len(request.body),
            "content_type": request.content_type,
            "credential_env_name": policy.credential_env_name,
            "credential_present": credential is not None,
            "parent_artifacts": list(parent_tuple),
            "scientific_evidence": False,
            "egress_budget": dict(budget_policy),
        }
        request_artifact = self._register_json(
            request_payload,
            logical_type="external_request",
            origin="controlled external egress request intent",
            creator_role=Role.ORCHESTRATOR,
            parents=parent_tuple,
            schema_version=EGRESS_REQUEST_SCHEMA,
        )

        def prepare_for_transport(
            *,
            attempt: int,
            attempt_started: float,
        ) -> PreparedEgressRequest:
            remaining_total_bytes = policy.maximum_total_bytes - (
                request_bytes_used + response_bytes_used
            )
            prepared = PreparedEgressRequest(
                request_id=request.request_id,
                method=request.method,
                url=target.url,
                host=target.host,
                target=target.target,
                headers=headers,
                body=request.body,
                content_type=request.content_type,
                timeout_seconds=deadline_monotonic - attempt_started,
                maximum_response_bytes=min(
                    policy.maximum_response_bytes,
                    remaining_total_bytes,
                ),
                attempt_number=attempt,
                cumulative_bytes_before_attempt=(
                    request_bytes_used + response_bytes_used - len(request.body)
                ),
                deadline_elapsed_seconds=elapsed(attempt_started),
                credential_header=(
                    policy.credential_header if credential is not None else None
                ),
                credential_prefix=policy.credential_prefix,
                _deadline_monotonic=deadline_monotonic,
            )
            _issue_prepared(prepared)
            return prepared
        attempts: list[dict[str, object]] = []
        attempt_raw_artifacts: list[ArtifactRecord] = []
        attempt_raw_hashes: set[str] = set()
        denial_receipts: list[ArtifactRecord] = []
        response: TransportResponse | None = None
        raw_artifact: ArtifactRecord | None = None
        content_type: str | None = None
        last_failure: TransportFailure | None = None
        final_capability: object | None = None

        def denied(message: str) -> EgressDeniedError:
            captured = tuple(
                value
                for value in (
                    request_artifact,
                    *attempt_raw_artifacts,
                    *denial_receipts,
                )
                if value is not None
            )
            return EgressDeniedError(
                message,
                request_id=request.request_id,
                attempts=attempts,
                artifacts=captured,
                network_used=network_used,
                external_validation=effective_external_validation(),
                transport_authority=transport_authority,
            )

        def record_received_attempt(
            candidate: TransportResponse,
            attempt: int,
            *,
            persist_raw: bool,
            attempt_started: float,
            attempt_completed: float,
            wire_eligible: bool = False,
        ) -> ArtifactRecord | None:
            captured_raw = (
                self._capture_raw(
                    candidate.body,
                    credential=credential,
                    policy=policy,
                )
                if persist_raw
                else None
            )
            if (
                captured_raw is not None
                and captured_raw.sha256 not in attempt_raw_hashes
            ):
                attempt_raw_hashes.add(captured_raw.sha256)
                attempt_raw_artifacts.append(captured_raw)
            attempts.append(
                {
                    "schema_version": EGRESS_ATTEMPT_SCHEMA,
                    "attempt": attempt,
                    "status": "RESPONSE",
                    "status_code": candidate.status_code,
                    "body_sha256": _safe_hash(candidate.body),
                    "body_size": len(candidate.body),
                    "raw_response_record_sha256": (
                        captured_raw.sha256 if captured_raw is not None else None
                    ),
                    "request_body_bytes": len(request.body),
                    "response_body_bytes": len(candidate.body),
                    "cumulative_bytes": (
                        request_bytes_used + response_bytes_used
                    ),
                    "started_offset_seconds": elapsed(attempt_started),
                    "completed_offset_seconds": elapsed(attempt_completed),
                    "retry_delay_seconds": None,
                }
            )
            if wire_selected:
                projection = (_project_pmc_wire_attempt(final_capability, candidate, captured_raw)
                              if wire_eligible and _project_pmc_wire_attempt is not None else None)
                if wire_eligible and projection is None:
                    raise EgressDeniedError("PMC wire attempt custody unavailable")
                attempts[-1].update(
                    schema_version=PMC_WIRE_ATTEMPT_SCHEMA,
                    prepared_request=_prepared_request_claim(prepared),
                    prepared_request_binding=_prepared_request_binding(prepared),
                    raw_response_record_hash=captured_raw.record_hash if captured_raw else None,
                    control_headers=[], coordination=None,
                )
                if projection is not None:
                    attempts[-1].update(projection)
            return captured_raw

        def denied_transport(
            message: str,
            *,
            reason_code: str,
            attempt: int,
            attempt_started: float,
            attempt_completed: float,
            response_body_bytes: int = 0,
        ) -> EgressDeniedError:
            record_transport_failure_attempt(
                attempt=attempt,
                attempt_started=attempt_started,
                attempt_completed=attempt_completed,
                response_body_bytes=response_body_bytes,
            )
            receipt = self._register_json(
                {
                    "schema_version": EGRESS_RESPONSE_RECEIPT_SCHEMA,
                    "kind": "EXTERNAL_TRANSPORT_DENIAL_RECEIPT",
                    "request_id": request.request_id,
                    "policy_claim_sha256": policy_claim_sha256,
                    "request_artifact_sha256": (
                        request_artifact.sha256 if request_artifact is not None else None
                    ),
                    "attempt": attempt,
                    "denial_reason": reason_code,
                    "response_metadata_captured": False,
                    "status_code": None,
                    "raw_response_sha256": None,
                    "raw_response_record_sha256": None,
                    "body_size": None,
                    "captured_at": self._timestamp(),
                    "network_used": network_used,
                    "scientific_evidence": False,
                    "external_validation": effective_external_validation(),
                    "transport_authority": transport_authority,
                    "egress_budget": budget_snapshot(attempt_completed),
                },
                logical_type="external_transport_denial_receipt",
                origin="sanitized controlled-egress transport denial",
                creator_role=Role.EVIDENCE_CURATOR,
                parents=(
                    (request_artifact.sha256,)
                    if request_artifact is not None
                    else ()
                ),
                schema_version=EGRESS_RESPONSE_RECEIPT_SCHEMA,
            )
            if receipt is not None:
                denial_receipts.append(receipt)
            return denied(message)

        def record_transport_failure_attempt(
            *,
            attempt: int,
            attempt_started: float,
            attempt_completed: float,
            response_body_bytes: int,
        ) -> None:
            attempts.append(
                {
                    "schema_version": EGRESS_ATTEMPT_SCHEMA,
                    "attempt": attempt,
                    "status": "TRANSPORT_FAILURE",
                    "status_code": None,
                    "body_sha256": None,
                    "body_size": None,
                    "raw_response_record_sha256": None,
                    "request_body_bytes": len(request.body),
                    "response_body_bytes": response_body_bytes,
                    "cumulative_bytes": (
                        request_bytes_used + response_bytes_used
                    ),
                    "started_offset_seconds": elapsed(attempt_started),
                    "completed_offset_seconds": elapsed(
                        attempt_completed
                    ),
                    "retry_delay_seconds": None,
                }
            )
            if wire_selected:
                attempts[-1].update(
                    schema_version=PMC_WIRE_ATTEMPT_SCHEMA,
                    prepared_request=_prepared_request_claim(prepared),
                    prepared_request_binding=_prepared_request_binding(prepared),
                    raw_response_record_hash=None, control_headers=[], coordination=None,
                )

        def denied_response(
            message: str,
            *,
            reason_code: str,
            candidate: TransportResponse,
            attempt: int,
            persist_raw: bool,
            attempt_started: float,
            attempt_completed: float,
        ) -> EgressDeniedError:
            captured_raw = record_received_attempt(
                candidate,
                attempt,
                persist_raw=persist_raw,
                attempt_started=attempt_started,
                attempt_completed=attempt_completed,
            )
            receipt_parents = tuple(
                value
                for value in (
                    request_artifact.sha256 if request_artifact is not None else None,
                    captured_raw.sha256 if captured_raw is not None else None,
                )
                if value is not None
            )
            receipt = self._register_json(
                {
                    "schema_version": EGRESS_RESPONSE_RECEIPT_SCHEMA,
                    "kind": "EXTERNAL_RESPONSE_DENIAL_RECEIPT",
                    "request_id": request.request_id,
                    "policy_claim_sha256": policy_claim_sha256,
                    "request_artifact_sha256": (
                        request_artifact.sha256 if request_artifact is not None else None
                    ),
                    "attempt": attempt,
                    "denial_reason": reason_code,
                    "status_code": candidate.status_code,
                    "raw_response_sha256": _safe_hash(candidate.body),
                    "raw_response_record_sha256": (
                        captured_raw.sha256 if captured_raw is not None else None
                    ),
                    "raw_response_persisted": captured_raw is not None,
                    "body_size": len(candidate.body),
                    "captured_at": self._timestamp(),
                    "network_used": network_used,
                    "scientific_evidence": False,
                    "external_validation": effective_external_validation(),
                    "transport_authority": transport_authority,
                    "egress_budget": budget_snapshot(attempt_completed),
                },
                logical_type="external_response_denial_receipt",
                origin="sanitized controlled-egress response denial",
                creator_role=Role.EVIDENCE_CURATOR,
                parents=receipt_parents,
                schema_version=EGRESS_RESPONSE_RECEIPT_SCHEMA,
            )
            if receipt is not None:
                denial_receipts.append(receipt)
            return denied(message)

        def denied_budget(
            message: str,
            *,
            reason_code: str,
        ) -> EgressDeniedError:
            receipt = self._register_json(
                {
                    "schema_version": EGRESS_RESPONSE_RECEIPT_SCHEMA,
                    "kind": "EXTERNAL_BUDGET_DENIAL_RECEIPT",
                    "request_id": request.request_id,
                    "policy_claim_sha256": policy_claim_sha256,
                    "request_artifact_sha256": (
                        request_artifact.sha256
                        if request_artifact is not None
                        else None
                    ),
                    "attempts": attempts,
                    "denial_reason": reason_code,
                    "captured_at": self._timestamp(),
                    "network_used": network_used,
                    "scientific_evidence": False,
                    "external_validation": effective_external_validation(),
                    "transport_authority": transport_authority,
                    "egress_budget": budget_snapshot(),
                },
                logical_type="external_budget_denial_receipt",
                origin="sanitized controlled-egress budget denial",
                creator_role=Role.EVIDENCE_CURATOR,
                parents=tuple(
                    dict.fromkeys(
                        value
                        for value in (
                            request_artifact.sha256
                            if request_artifact is not None
                            else None,
                            *(
                                record.sha256
                                for record in attempt_raw_artifacts
                            ),
                        )
                        if value is not None
                    )
                ),
                schema_version=EGRESS_RESPONSE_RECEIPT_SCHEMA,
            )
            if receipt is not None:
                denial_receipts.append(receipt)
            return denied(message)

        def wait_for_retry(
            *,
            delay: float,
            attempt_completed: float,
        ) -> None:
            if attempt_completed + delay >= deadline_monotonic:
                raise denied_budget(
                    "egress deadline cannot admit retry backoff",
                    reason_code="DEADLINE_LIMIT",
                )
            sleeper(delay)
            try:
                backoff_completed = observe_time(require_remaining=True)
            except EgressDeniedError:
                raise denied_budget(
                    "egress deadline was exhausted during retry backoff",
                    reason_code="DEADLINE_LIMIT",
                ) from None
            if backoff_completed + 1e-9 < attempt_completed + delay:
                raise denied_budget(
                    "egress retry backoff did not advance safely",
                    reason_code="BACKOFF_LIMIT",
                )

        for attempt in range(1, policy.maximum_attempts + 1):
            if (
                request_bytes_used
                + response_bytes_used
                + len(request.body)
                >= policy.maximum_total_bytes
            ):
                raise denied_budget(
                    "egress cumulative byte budget cannot admit a response",
                    reason_code="CUMULATIVE_BYTE_LIMIT",
                )
            try:
                observe_time(require_remaining=True)
                scheduled_at, delay = self._reserve_rate_limited_attempt(
                    policy, deadline_monotonic=deadline_monotonic, _native_timing=_native_timing
                )
                self._complete_rate_limited_reservation(
                    scheduled_at=scheduled_at,
                    delay=delay, deadline_monotonic=deadline_monotonic,
                    _native_timing=_native_timing,
                )
                attempt_started = observe_time(require_remaining=True)
            except EgressDeniedError:
                raise denied_budget(
                    "egress rate or deadline policy denied the request",
                    reason_code="RATE_OR_DEADLINE_LIMIT",
                ) from None
            request_bytes_used += len(request.body)
            prepared = prepare_for_transport(
                attempt=attempt,
                attempt_started=attempt_started,
            )
            capability = prepared._capability
            owned_progress_count = None
            outcome_primary = None
            try:
                try:
                    observe_transport_authority()
                    transport_primary = None
                    try:
                        candidate = self.transport.send(
                            prepared,
                            credential=transport_credential,
                        )
                    except BaseException as error:
                        transport_primary = error
                    try:
                        owned_progress_count = _settle_pmc_progress(capability)
                    except BaseException as settlement_error:
                        if transport_primary is not None and not isinstance(transport_primary, Exception):
                            raise transport_primary
                        if isinstance(settlement_error, Exception):
                            raise _PmcProgressAccountingError("PMC_PROGRESS_UNKNOWN") from None
                        raise
                    if owned_progress_count is not None:
                        response_bytes_used += owned_progress_count
                    confirmed_outcome = None
                    try:
                        if _settle_pmc_outcome is not None:
                            confirmed_outcome = _settle_pmc_outcome(capability)
                    except BaseException:
                        if transport_primary is None:
                            raise
                    if transport_primary is not None:
                        raise transport_primary
                    if confirmed_outcome is not None:
                        if owned_progress_count is None:
                            raise _PmcProgressAccountingError("PMC_PROGRESS_UNKNOWN")
                        if confirmed_outcome is not True:
                            raise EgressDeniedError("PMC_OUTCOME_UNAVAILABLE")
                    observe_transport_authority()
                    if capability is None or not _capability_consumed(capability):
                        raise EgressDeniedError(
                            "transport did not consume gateway request authority"
                        )
                    final_capability = capability
                    if not isinstance(candidate, TransportResponse):
                        raise TransportFailure("transport returned an untyped response")
                    if owned_progress_count is not None and owned_progress_count != len(candidate.body):
                        raise EgressDeniedError("PMC progress disagrees with the response")
                    response = candidate
                    last_failure = None
                except _PmcProgressAccountingError:
                    # UNKNOWN is terminal and has no fabricated current-attempt
                    # zero, completion timestamp, denial or retry-exhausted receipt.
                    raise
                except _PartialResponseTransportFailure as exc:
                    # Snapshot the only safe facts and sever reader frames before
                    # any injected callback or other fallible operation can run.
                    received_body_bytes = exc.response_body_bytes
                    partial_policy_denial = exc.policy_denial
                    partial_progress_mismatch = (
                        owned_progress_count is not None and received_body_bytes != owned_progress_count
                    )
                    if owned_progress_count is not None:
                        partial_policy_denial = True  # Registered progress never takes generic retry.
                        received_body_bytes = owned_progress_count
                    exc.__traceback__ = None
                    exc.__context__ = None
                    exc.__cause__ = None
                    # Charge the exact known count before any later callback can
                    # fail. A callback failure terminates execution, but it must
                    # not conceptually reset bytes already received.
                    if owned_progress_count is None:
                        response_bytes_used += received_body_bytes
                    observe_transport_authority()
                    attempt_completed = observe_time()
                    partial_policy_denial = (
                        partial_policy_denial
                        or received_body_bytes > prepared.maximum_response_bytes
                        or attempt_completed >= deadline_monotonic
                    )
                    last_failure = TransportFailure("external transport failed")
                    if (
                        request_bytes_used + response_bytes_used
                        > policy.maximum_total_bytes
                    ):
                        record_transport_failure_attempt(
                            attempt=attempt,
                            attempt_started=attempt_started,
                            attempt_completed=attempt_completed,
                            response_body_bytes=received_body_bytes,
                        )
                        raise denied_budget(
                            "egress cumulative byte budget is exhausted",
                            reason_code="CUMULATIVE_BYTE_LIMIT",
                        ) from None
                    if partial_policy_denial:
                        raise denied_transport(
                            "transport response violated the egress policy",
                            reason_code=("PMC_PROGRESS_MISMATCH" if partial_progress_mismatch
                                         else "TRANSPORT_POLICY_DENIAL"),
                            attempt=attempt,
                            attempt_started=attempt_started,
                            attempt_completed=attempt_completed,
                            response_body_bytes=received_body_bytes,
                        ) from None
                    record_transport_failure_attempt(
                        attempt=attempt,
                        attempt_started=attempt_started,
                        attempt_completed=attempt_completed,
                        response_body_bytes=received_body_bytes,
                    )
                    if attempt >= policy.maximum_attempts:
                        break
                    retry_delay = self._retry_delay(None, attempt, policy)
                    attempts[-1]["retry_delay_seconds"] = retry_delay
                    wait_for_retry(
                        delay=retry_delay,
                        attempt_completed=attempt_completed,
                    )
                    continue
                except (EgressDeniedError, EgressPolicyError):
                    observe_transport_authority()
                    attempt_completed = observe_time()
                    raise denied_transport(
                        "transport response violated the egress policy",
                        reason_code="TRANSPORT_POLICY_DENIAL",
                        attempt=attempt,
                        attempt_started=attempt_started,
                        attempt_completed=attempt_completed,
                        response_body_bytes=(0 if owned_progress_count is None else owned_progress_count),
                    ) from None
                except Exception:
                    observe_transport_authority()
                    attempt_completed = observe_time()
                    if owned_progress_count is not None:
                        raise denied_transport(
                            "registered PMC transport failed",
                            reason_code="TRANSPORT_POLICY_DENIAL",
                            attempt=attempt,
                            attempt_started=attempt_started,
                            attempt_completed=attempt_completed,
                            response_body_bytes=owned_progress_count,
                        ) from None
                    last_failure = TransportFailure("external transport failed")
                    record_transport_failure_attempt(
                        attempt=attempt,
                        attempt_started=attempt_started,
                        attempt_completed=attempt_completed,
                        response_body_bytes=0,
                    )
                    if attempt >= policy.maximum_attempts:
                        break
                    retry_delay = self._retry_delay(None, attempt, policy)
                    attempts[-1]["retry_delay_seconds"] = retry_delay
                    wait_for_retry(
                        delay=retry_delay,
                        attempt_completed=attempt_completed,
                    )
                    continue
            except BaseException as error:
                outcome_primary = error
                raise
            finally:
                if capability is not None:
                    try:
                        _revoke_capability(capability)
                    except BaseException:
                        if outcome_primary is None:
                            raise

            attempt_completed = observe_time()
            if owned_progress_count is None:
                response_bytes_used += len(response.body)
            if (
                request_bytes_used + response_bytes_used
                > policy.maximum_total_bytes
            ):
                raise denied_response(
                    "egress cumulative byte budget is exhausted",
                    reason_code="CUMULATIVE_BYTE_LIMIT",
                    candidate=response,
                    attempt=attempt,
                    persist_raw=False,
                    attempt_started=attempt_started,
                    attempt_completed=attempt_completed,
                )
            if attempt_completed >= deadline_monotonic:
                raise denied_response(
                    "egress deadline is exhausted",
                    reason_code="DEADLINE_LIMIT",
                    candidate=response,
                    attempt=attempt,
                    persist_raw=False,
                    attempt_started=attempt_started,
                    attempt_completed=attempt_completed,
                )

            try:
                self._assert_no_secret_leakage(
                    credential=credential,
                    response=response,
                    policy=policy,
                )
            except EgressDeniedError:
                raise denied_response(
                    "external response violated the egress secret policy",
                    reason_code="SECRET_LEAKAGE",
                    candidate=response,
                    attempt=attempt,
                    persist_raw=False,
                    attempt_started=attempt_started,
                    attempt_completed=attempt_completed,
                ) from None
            if len(response.body) > policy.maximum_response_bytes:
                raise denied_response(
                    "response exceeds the configured byte limit",
                    reason_code="RESPONSE_SIZE_LIMIT",
                    candidate=response,
                    attempt=attempt,
                    persist_raw=False,
                    attempt_started=attempt_started,
                    attempt_completed=attempt_completed,
                )
            if response.effective_url != target.url:
                raise denied_response(
                    "transport target changed or redirected",
                    reason_code="TARGET_CHANGED",
                    candidate=response,
                    attempt=attempt,
                    persist_raw=True,
                    attempt_started=attempt_started,
                    attempt_completed=attempt_completed,
                )
            if 300 <= response.status_code <= 399:
                raise denied_response(
                    "HTTP redirects are forbidden",
                    reason_code="REDIRECT_FORBIDDEN",
                    candidate=response,
                    attempt=attempt,
                    persist_raw=True,
                    attempt_started=attempt_started,
                    attempt_completed=attempt_completed,
                )
            try:
                content_type = self._response_controls(response, policy)
            except EgressDeniedError:
                raise denied_response(
                    "external response controls violated the egress policy",
                    reason_code="RESPONSE_CONTROLS_INVALID",
                    candidate=response,
                    attempt=attempt,
                    persist_raw=True,
                    attempt_started=attempt_started,
                    attempt_completed=attempt_completed,
                ) from None
            # Capture every admitted response attempt before retry logic can
            # discard it.  Provider parsing only receives the final record.
            raw_artifact = record_received_attempt(
                response,
                attempt,
                persist_raw=True,
                attempt_started=attempt_started,
                attempt_completed=attempt_completed,
                wire_eligible=wire_selected,
            )
            if (
                response.status_code in policy.retry_statuses
                and attempt < policy.maximum_attempts
            ):
                retry_delay = self._retry_delay(response, attempt, policy)
                attempts[-1]["retry_delay_seconds"] = retry_delay
                wait_for_retry(
                    delay=retry_delay,
                    attempt_completed=attempt_completed,
                )
                continue
            break
        transport_failure_receipt: ArtifactRecord | None = None
        if response is None or last_failure is not None:
            failure_parents = tuple(
                value
                for value in (
                    request_artifact.sha256 if request_artifact is not None else None,
                    *(record.sha256 for record in attempt_raw_artifacts),
                )
                if value is not None
            )
            transport_failure_receipt = self._register_json(
                {
                    "schema_version": EGRESS_RESPONSE_RECEIPT_SCHEMA,
                    "kind": "EXTERNAL_TRANSPORT_FAILURE_RECEIPT",
                    "request_id": request.request_id,
                    "policy_claim_sha256": policy_claim_sha256,
                    "request_artifact_sha256": (
                        request_artifact.sha256 if request_artifact is not None else None
                    ),
                    "attempts": attempts,
                    "terminal_reason": "TRANSPORT_RETRY_EXHAUSTED",
                    "captured_at": self._timestamp(),
                    "network_used": network_used,
                    "scientific_evidence": False,
                    "external_validation": effective_external_validation(),
                    "transport_authority": transport_authority,
                    "egress_budget": budget_snapshot(),
                },
                logical_type="external_transport_failure_receipt",
                origin="sanitized controlled-egress transport failure",
                creator_role=Role.EVIDENCE_CURATOR,
                parents=failure_parents,
                schema_version=EGRESS_RESPONSE_RECEIPT_SCHEMA,
            )
        failure_artifacts = tuple(
            value
            for value in (
                request_artifact,
                *attempt_raw_artifacts,
                transport_failure_receipt,
            )
            if value is not None
        )
        if response is None:
            raise TransportFailure(
                "external transport exhausted its retry policy",
                request_id=request.request_id,
                attempts=attempts,
                artifacts=failure_artifacts,
                network_used=network_used,
                external_validation=effective_external_validation(),
                transport_authority=transport_authority,
            ) from None
        if last_failure is not None:
            raise TransportFailure(
                "external transport failed",
                request_id=request.request_id,
                attempts=attempts,
                artifacts=failure_artifacts,
                network_used=network_used,
                external_validation=effective_external_validation(),
                transport_authority=transport_authority,
            ) from None
        if content_type is None:
            raise denied("response controls were not validated")
        decoding_artifact = None
        decoded_body = None
        if content_profile and 200 <= response.status_code <= 299:
            decoding_refused = False
            try:
                decode_start = observe_time(require_remaining=True)
                coding = _pmc_content_coding(response.headers)
                maximum_input = min(prepared.maximum_response_bytes, MAX_ABSOLUTE_RESPONSE_BYTES)
                decoded_body = _decode_pmc_content(
                    response.body, coding, maximum_input,
                    lambda: observe_time(require_remaining=True),
                )
                self._assert_custody_secret_free(
                    decoded_body, credential=None, location="in decoded PMC content", policy=policy,
                )
                decode_complete = observe_time(require_remaining=True)
                if request_artifact is None or raw_artifact is None:
                    raise EgressDeniedError("PMC decoding requires exact registry custody")
                value = {
                    "schema_version": PMC_DECODING_SCHEMA,
                    "kind": "EXTERNAL_CONTENT_DECODING",
                    "content_profile": PMC_CONTENT_PROFILE,
                    "request_id": request.request_id,
                    "request_artifact_sha256": request_artifact.sha256,
                    "request_artifact_record_hash": request_artifact.record_hash,
                    "attempt": attempt,
                    "wire_raw_artifact_sha256": raw_artifact.sha256,
                    "wire_raw_artifact_record_hash": raw_artifact.record_hash,
                    "wire_body_size": len(response.body),
                    "content_coding": coding,
                    "decode_limits": {"maximum_input_bytes": maximum_input,
                                      "maximum_output_bytes": 16 * 1024 * 1024,
                                      "maximum_expansion_ratio": 200},
                    "decoded_xml_sha256": _safe_hash(decoded_body),
                    "decoded_xml_size": len(decoded_body),
                    "decoding_started_offset_seconds": elapsed(decode_start),
                    "decoding_completed_offset_seconds": elapsed(decode_complete),
                    "scientific_evidence": False,
                }
                expected_descriptor_bytes = canonical_json_bytes(value) + b"\n"
                decoding_artifact = self._register_json(
                    value, logical_type="external_response_decoding",
                    origin="bounded source-owned external content decoding",
                    creator_role=Role.EVIDENCE_CURATOR,
                    parents=(request_artifact.sha256, raw_artifact.sha256),
                    schema_version=PMC_DECODING_SCHEMA,
                )
                if decoding_artifact is None or self._registry is None:
                    raise EgressDeniedError("PMC decoding descriptor unavailable")
                _require_pmc_decoding_descriptor(
                    self._registry, descriptor_sha256=_safe_hash(expected_descriptor_bytes),
                    request_hash=request_artifact.sha256, raw_hash=raw_artifact.sha256,
                    expected_record=decoding_artifact, expected_bytes=expected_descriptor_bytes,
                )
                observe_time(require_remaining=True)
            except Exception:
                # Raw attempt already exists. Never append it or charge it twice.
                # A raising callback may itself exhaust the original native deadline.
                # If fresh clock evidence is unavailable, do not publish a timed receipt.
                observation_available = False
                try:
                    observe_time()
                    observation_available = True
                except Exception:
                    pass
                if observation_available:
                    receipt = None
                    try:
                        receipt = self._register_json(
                            {"schema_version": EGRESS_PMC_RESPONSE_SCHEMA_V3,
                             "kind": "EXTERNAL_RESPONSE_DENIAL_RECEIPT",
                             "request_id": request.request_id,
                             "policy_claim_sha256": policy_claim_sha256,
                             "request_artifact_sha256": request_artifact.sha256 if request_artifact else None,
                             "attempt": attempt, "denial_reason": "CONTENT_DECODING_REFUSED",
                             "raw_response_record_sha256": raw_artifact.sha256 if raw_artifact else None,
                             "raw_response_sha256": _safe_hash(response.body),
                             "body_size": len(response.body),
                             "scientific_evidence": False, "network_used": network_used,
                             "external_validation": effective_external_validation(),
                             "transport_authority": transport_authority,
                             "egress_budget": budget_snapshot()},
                            logical_type="external_response_denial_receipt",
                            origin="sanitized controlled-egress response denial",
                            creator_role=Role.EVIDENCE_CURATOR,
                            parents=tuple(r.sha256 for r in (request_artifact, raw_artifact) if r is not None),
                            schema_version=EGRESS_PMC_RESPONSE_SCHEMA_V3,
                        )
                    except Exception:
                        # Secondary publication is best-effort; original raw
                        # custody and the static outer refusal remain available.
                        pass
                    if receipt is not None:
                        denial_receipts.append(receipt)
                decoding_refused = True
            if decoding_refused:
                raise denied("CONTENT_DECODING_REFUSED") from None
        final_observed = observe_time(require_remaining=True)
        captured_at = self._timestamp()
        final_observed = observe_time(require_remaining=True)
        observe_transport_authority()
        recorded_headers = {
            name.lower(): value
            for name, value in response.headers
            if name.lower() in policy.recorded_response_headers
        }
        receipt_payload: dict[str, object] = {
            "schema_version": EGRESS_RESPONSE_RECEIPT_SCHEMA,
            "kind": "EXTERNAL_RESPONSE_RECEIPT",
            "request_id": request.request_id,
            "policy_claim_sha256": policy_claim_sha256,
            "request_artifact_sha256": (
                request_artifact.sha256 if request_artifact is not None else None
            ),
            "raw_response_sha256": _safe_hash(response.body),
            "raw_response_record_sha256": (
                raw_artifact.sha256 if raw_artifact is not None else None
            ),
            "status_code": response.status_code,
            "content_type": content_type,
            "body_size": len(response.body),
            "headers": dict(sorted(recorded_headers.items())),
            "attempts": attempts,
            "captured_at": captured_at,
            "network_used": network_used,
            "scientific_evidence": False,
            "external_validation": effective_external_validation(),
            "transport_authority": transport_authority,
            "egress_budget": budget_snapshot(final_observed),
        }
        if content_profile:
            receipt_payload.update(
                schema_version=EGRESS_PMC_RESPONSE_SCHEMA_V3,
                content_profile=PMC_CONTENT_PROFILE,
                content_coding=_pmc_content_coding(response.headers),
                decoding_artifact_sha256=decoding_artifact.sha256 if decoding_artifact else None,
                decoding_artifact_record_hash=decoding_artifact.record_hash if decoding_artifact else None,
            )
        if wire_selected:
            receipt_payload.update(schema_version=PMC_WIRE_RESPONSE_SCHEMA,
                                   request_wire_profile=PMC_REQUEST_WIRE_PROFILE)
        receipt_parents = tuple(
            dict.fromkeys(
                value
                for value in (
                    request_artifact.sha256 if request_artifact is not None else None,
                    *(record.sha256 for record in attempt_raw_artifacts),
                    *(item["coordination"]["schedule"]["rules_artifact_sha256"]
                      for item in attempts if wire_selected and item.get("coordination") is not None),
                    decoding_artifact.sha256 if decoding_artifact else None,
                )
                if value is not None
            )
        )
        response_receipt = self._register_json(
            receipt_payload,
            logical_type="external_response_receipt",
            origin="controlled external egress response receipt",
            creator_role=Role.EVIDENCE_CURATOR,
            parents=receipt_parents,
            schema_version=(PMC_WIRE_RESPONSE_SCHEMA if wire_selected else
                            EGRESS_PMC_RESPONSE_SCHEMA_V3 if content_profile else EGRESS_RESPONSE_RECEIPT_SCHEMA),
        )
        observe_transport_authority()
        transport_execution_authority = (
            _issue_execution_authority(
                final_capability,
                request_artifact=request_artifact,
                response_receipt_artifact=response_receipt,
                raw_response_artifact=raw_artifact,
                attempts=attempts,
                response=response,
                content_type=content_type,
                captured_at=captured_at,
                policy_snapshot=policy,
                policy_claim=policy_claim,
                policy_claim_sha256=policy_claim_sha256,
                egress_budget=budget_snapshot(final_observed),
            )
            if (
                (not content_profile or wire_selected)
                and transport_authority == AUDITED_LIVE_TRANSPORT_AUTHORITY
                and final_capability is not None
            )
            else None
        )
        return GatewayResult(
            request_id=request.request_id,
            retrieval_status=(
                "CAPTURED" if 200 <= response.status_code <= 299 else "HTTP_ERROR"
            ),
            status_code=response.status_code,
            content_type=content_type,
            body_sha256=_safe_hash(response.body),
            body_size=len(response.body),
            attempts=tuple(attempts),
            network_used=network_used,
            scientific_evidence=False,
            external_validation=effective_external_validation(),
            transport_authority=transport_authority,
            captured_at=captured_at,
            policy_id=policy.policy_id,
            maximum_total_bytes=policy.maximum_total_bytes,
            total_bytes_used=request_bytes_used + response_bytes_used,
            deadline_budget_seconds=policy.timeout_seconds,
            deadline_elapsed_seconds=elapsed(final_observed),
            transport_execution_authority_artifact=(
                transport_execution_authority
            ),
            request_artifact=request_artifact,
            raw_response_artifact=raw_artifact,
            attempt_raw_response_artifacts=tuple(attempt_raw_artifacts),
            response_receipt_artifact=response_receipt,
            body=response.body,
            content_decoding_artifact=decoding_artifact,
            decoded_body=decoded_body,
        )

    def parse_json(self, result: GatewayResult) -> Any:
        """Strictly parse bytes only after their response receipt is frozen."""

        if not isinstance(result, GatewayResult):
            raise ExternalParseError("gateway result must be typed")
        if result.retrieval_status != "CAPTURED":
            raise ExternalParseError("HTTP error response is not provider output")
        if result.content_type != "application/json":
            raise ExternalParseError("captured response is not JSON")
        if _safe_hash(result.body) != result.body_sha256:
            raise ExternalParseError("captured response bytes changed before parsing")
        if self._registry is not None:
            if result.raw_response_artifact is None:
                raise ExternalParseError("captured response lacks registry provenance")
            try:
                stored = self._registry.get_bytes(result.raw_response_artifact.sha256)
            except Exception as exc:
                raise ExternalParseError("captured response provenance is unavailable") from exc
            if stored != result.body:
                raise ExternalParseError("registry response differs from captured bytes")
        try:
            return safe_json_loads(
                result.body,
                max_bytes=self.policy.maximum_response_bytes,
                max_depth=self.policy.maximum_json_depth,
                max_items=self.policy.maximum_json_items,
            )
        except UnsafeSerializationError as exc:
            raise ExternalParseError("captured response is not strict bounded JSON") from exc


def _build_exact_gateway_classifier() -> Callable[[object], bool]:
    """Capture the exact audited gateway implementation after class creation."""

    exact_gateway_type = EgressGateway
    exact_execute = exact_gateway_type.__dict__["execute"]
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

    def classify(value: object) -> bool:
        try:
            state = vars(value)
            namespace = vars(exact_gateway_type)
            bound_execute = getattr(value, "execute")
        except (AttributeError, TypeError):
            return False
        return (
            type(value) is exact_gateway_type
            and set(state) == exact_state_fields
            and len(namespace) == len(exact_namespace)
            and all(namespace.get(name) is member for name, member in exact_namespace)
            and getattr(bound_execute, "__self__", None) is value
            and getattr(bound_execute, "__func__", None) is exact_execute
        )

    return classify


_is_exact_egress_gateway = _build_exact_gateway_classifier()
del _build_exact_gateway_classifier


def _build_gateway_authority_key_access() -> tuple[
    Callable[[ArtifactRegistry], bytes | None],
    Callable[[ArtifactRegistry], bytes],
]:
    """Confine trust-root access to closures deleted from the module surface."""

    exact_os = os
    exact_stat = stat
    exact_open_directory = open_confined_directory_fd
    exact_atomic_write = atomic_write_bytes
    exact_token_bytes = secrets.token_bytes
    exact_registry = _is_exact_authority_registry
    key_name = _AUDITED_TRANSPORT_AUTHORITY_KEY_NAME
    key_bytes = _AUDITED_TRANSPORT_AUTHORITY_KEY_BYTES

    def key_relative_path(registry: ArtifactRegistry) -> Any:
        return registry.base_path / key_name

    def read_key(registry: ArtifactRegistry) -> bytes | None:
        if not exact_registry(registry):
            raise EgressPolicyError(
                "gateway authority registry implementation changed"
            )
        relative = key_relative_path(registry)
        directory_fd = exact_open_directory(
            registry.policy.root,
            relative.parent,
            create=False,
        )
        descriptor: int | None = None
        try:
            flags = (
                exact_os.O_RDONLY
                | getattr(exact_os, "O_NOFOLLOW", 0)
                | getattr(exact_os, "O_CLOEXEC", 0)
            )
            try:
                descriptor = exact_os.open(
                    relative.name,
                    flags,
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return None
            metadata = exact_os.fstat(descriptor)
            named = exact_os.stat(
                relative.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            identity = (metadata.st_dev, metadata.st_ino)
            if (
                not exact_stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or (metadata.st_mode & 0o777) != 0o600
                or metadata.st_size != key_bytes
                or identity != (named.st_dev, named.st_ino)
            ):
                raise EgressPolicyError("gateway authority trust root is unsafe")
            value = exact_os.read(descriptor, key_bytes + 1)
            final = exact_os.fstat(descriptor)
            final_named = exact_os.stat(
                relative.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                len(value) != key_bytes
                or (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_mode,
                    metadata.st_nlink,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                )
                != (
                    final.st_dev,
                    final.st_ino,
                    final.st_mode,
                    final.st_nlink,
                    final.st_size,
                    final.st_mtime_ns,
                    final.st_ctime_ns,
                )
                or identity != (final_named.st_dev, final_named.st_ino)
            ):
                raise EgressPolicyError(
                    "gateway authority trust root changed during read"
                )
            return value
        except OSError as exc:
            raise EgressPolicyError(
                "gateway authority trust root cannot be read"
            ) from exc
        finally:
            if descriptor is not None:
                exact_os.close(descriptor)
            exact_os.close(directory_fd)

    def load_or_create_key(registry: ArtifactRegistry) -> bytes:
        existing = read_key(registry)
        if existing is not None:
            return existing
        candidate = exact_token_bytes(key_bytes)
        relative = key_relative_path(registry)
        try:
            exact_atomic_write(
                registry.policy.root,
                relative,
                candidate,
                immutable=True,
                create_parents=False,
                mode=0o600,
            )
        except PathSecurityError:
            # A concurrent exact gateway may have won create-only publication.
            pass
        loaded = read_key(registry)
        if loaded is None:
            raise EgressPolicyError(
                "gateway authority trust root was not published"
            )
        return loaded

    return read_key, load_or_create_key


_PMC_WIRE_AUTHORITY_FIELDS = frozenset({
    "request_wire_profile", "content_profile", "content_coding",
    "decoding_artifact_sha256", "decoding_artifact_record_hash",
})
_PMC_WIRE_ATTEMPT_FIELDS = frozenset({
    "prepared_request", "prepared_request_binding", "raw_response_record_hash",
    "control_headers", "coordination",
})


def _pmc_wire_implementation_profile(base):
    return {**dict(base), "request_wire_profile": PMC_REQUEST_WIRE_PROFILE,
            "coordination_profile": PMC_COORDINATION_PROFILE,
            "deadline_scope": PMC_WIRE_DEADLINE_SCOPE}


def _pmc_wire_remaining_seconds_match(remaining, elapsed, timeout, deadline):
    """Bound the source float add/subtract roundoff, never restart a deadline.

    D=fl(start+timeout), elapsed=fl(now-start), remaining=fl(D-now).
    Reassociation to timeout-elapsed has four rounded operations. One ULP per
    operand/result is a conservative representation bound, not wall-time slack.
    The absolute original D is already authenticated and shared by all rows.
    """
    values = (remaining, elapsed, timeout, deadline)
    if any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
        return False
    expected = timeout - elapsed
    allowance = math.fsum(math.ulp(v) for v in (*values, expected))
    return remaining > 0 and abs(remaining - expected) <= allowance


def _replay_pmc_wire_attempts(registry, policy, request_payload, receipt):
    """Recompute bounded supplied custody joins; this never establishes native origin.

    The enclosing existing signer/key/ledger owner authenticates those observations.
    No current host timezone, native context, operational state or network is read.
    """
    from .pmc_coordination import _pmc_floor_deadline_ns

    def refuse():
        raise EgressPolicyError("PMC wire custody replay differs")

    def ns(value):
        if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
            refuse()
        return value

    def number(value):
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            refuse()
        return float(value)

    def digest(value):
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            refuse()
        return value

    if (type(registry) is not ArtifactRegistry or type(policy) is not EgressPolicy
            or policy.adapter_id != PMC_WIRE_ADAPTER_ID
            or type(request_payload) is not dict or type(receipt) is not dict
            or receipt.get("schema_version") != PMC_WIRE_RESPONSE_SCHEMA
            or receipt.get("request_wire_profile") != PMC_REQUEST_WIRE_PROFILE
            or receipt.get("content_profile") != PMC_CONTENT_PROFILE):
        refuse()
    request = EgressRequest(adapter_id=policy.adapter_id, method=request_payload.get("method"),
                            url=request_payload.get("url"), body=b"",
                            content_type=request_payload.get("content_type"),
                            headers=tuple(tuple(pair) for pair in request_payload.get("headers", ())))
    if not _pmc_content_profile(policy, request) or request.request_id != request_payload.get("request_id"):
        refuse()
    attempts = receipt.get("attempts")
    base_fields = {"schema_version", "attempt", "status", "status_code", "body_sha256", "body_size",
                   "raw_response_record_sha256", "request_body_bytes", "response_body_bytes",
                   "cumulative_bytes", "started_offset_seconds", "completed_offset_seconds", "retry_delay_seconds"}
    coordination_fields = {"profile", "coordinator_uuid", "boot_uuid", "sequence", "pending_observed_ns",
                           "deadline_seconds_hex", "terminal_kind", "terminal_observed_ns", "cleanup_ns",
                           "finalized", "schedule"}
    schedule_fields = {"utc_unix_ns", "observation_start_ns", "observation_end_ns",
                       "rules_artifact_sha256", "rules_artifact_record_hash"}
    prepared_fields = {"request_id", "method", "url", "host", "target", "headers", "body_sha256", "body_size",
                       "content_type", "timeout_seconds", "maximum_response_bytes", "attempt_number",
                       "cumulative_bytes_before_attempt", "deadline_elapsed_seconds", "credential_header", "credential_prefix"}
    if type(attempts) is not list or not 1 <= len(attempts) <= policy.maximum_attempts:
        refuse()
    previous = None
    cumulative = 0
    for ordinal, attempt in enumerate(attempts, 1):
        if (type(attempt) is not dict or set(attempt) != base_fields | _PMC_WIRE_ATTEMPT_FIELDS
                or attempt["schema_version"] != PMC_WIRE_ATTEMPT_SCHEMA
                or type(attempt["attempt"]) is not int or attempt["attempt"] != ordinal
                or attempt["status"] != "RESPONSE"):
            refuse()
        prepared, coord = attempt["prepared_request"], attempt["coordination"]
        if type(prepared) is not dict or set(prepared) != prepared_fields or type(coord) is not dict or set(coord) != coordination_fields:
            refuse()
        if digest(attempt["prepared_request_binding"]) != _safe_hash(canonical_json_bytes(prepared)):
            refuse()
        _replay_signed_request_against_policy(policy, request_payload, prepared)
        expected_cap = min(policy.maximum_response_bytes, policy.maximum_total_bytes - cumulative)
        if (prepared["request_id"] != request.request_id or prepared["body_sha256"] != _safe_hash(b"")
                or type(prepared["body_size"]) is not int or prepared["body_size"] != 0
                or type(prepared["attempt_number"]) is not int or prepared["attempt_number"] != ordinal
                or type(prepared["cumulative_bytes_before_attempt"]) is not int
                or prepared["cumulative_bytes_before_attempt"] != cumulative
                or type(prepared["maximum_response_bytes"]) is not int or prepared["maximum_response_bytes"] != expected_cap
                or number(prepared["timeout_seconds"]) <= 0
                or number(prepared["deadline_elapsed_seconds"]) < number(attempt["started_offset_seconds"])
                or number(prepared["deadline_elapsed_seconds"]) > number(attempt["completed_offset_seconds"])):
            refuse()
        for key in ("coordinator_uuid", "boot_uuid"):
            if (type(coord[key]) is not str or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", coord[key]) is None
                    or coord[key].replace("-", "") == "0" * 32):
                refuse()
        deadline_text = coord["deadline_seconds_hex"]
        if type(deadline_text) is not str or len(deadline_text) > 32:
            refuse()
        try:
            deadline = float.fromhex(deadline_text)
            deadline_ns = _pmc_floor_deadline_ns(deadline)
        except (ValueError, OverflowError):
            refuse()
        if deadline.hex() != deadline_text:
            refuse()
        if not _pmc_wire_remaining_seconds_match(prepared["timeout_seconds"], prepared["deadline_elapsed_seconds"],
                                                  policy.timeout_seconds, deadline):
            refuse()
        schedule = coord["schedule"]
        if (coord["profile"] != PMC_COORDINATION_PROFILE or coord["terminal_kind"] != "LOCAL_CLOSED_COMPLETE"
                or coord["finalized"] is not True or ns(coord["sequence"]) == 0
                or type(schedule) is not dict or set(schedule) != schedule_fields
                or type(schedule["utc_unix_ns"]) is not int or not -(1 << 63) <= schedule["utc_unix_ns"] < (1 << 63)
                or not ns(coord["pending_observed_ns"]) <= ns(schedule["observation_start_ns"])
                <= ns(schedule["observation_end_ns"]) <= ns(coord["cleanup_ns"])
                <= ns(coord["terminal_observed_ns"]) < deadline_ns):
            refuse()
        if previous is not None and (
                any(coord[key] != previous[key] for key in ("coordinator_uuid", "boot_uuid", "deadline_seconds_hex"))
                or coord["sequence"] <= previous["sequence"]
                or coord["pending_observed_ns"] < previous["cleanup_ns"] + 333333334):
            refuse()
        # Original deadline was one float addition; elapsed offsets were one
        # subtraction. Bound only that representational rounding plus ns floor.
        origin = deadline - policy.timeout_seconds
        started = number(attempt["started_offset_seconds"])
        completed = number(attempt["completed_offset_seconds"])
        rounding = (math.ulp(deadline) + math.ulp(origin) + math.ulp(started)
                    + math.ulp(completed) + math.ulp(origin + started)
                    + math.ulp(origin + completed) + 1e-9)
        if (coord["pending_observed_ns"] / 1e9 + rounding < origin + started
                or coord["terminal_observed_ns"] / 1e9 - rounding > origin + completed):
            refuse()
        _require_pmc_wire_rules(registry, digest(schedule["rules_artifact_sha256"]),
                                digest(schedule["rules_artifact_record_hash"]), schedule["utc_unix_ns"])
        raw_hash = digest(attempt["raw_response_record_sha256"])
        registry.verify(raw_hash, raise_on_error=True)
        raw_record, raw = registry.get_metadata(raw_hash), registry.get_bytes(raw_hash)
        if (raw_record.record_hash != digest(attempt["raw_response_record_hash"])
                or raw_record.logical_type != "external_response_raw" or raw_record.origin != "controlled external egress raw response"
                or raw_record.creator_role is not Role.EVIDENCE_CURATOR
                or raw_record.creation_command != ("scientist-one", "controlled-egress")
                or raw_record.parent_artifacts or raw_record.schema_version != "1.0"
                or raw_record.mime_type != "application/octet-stream" or raw_record.validation_result != "PASS" or raw_record.frozen is not True
                or digest(attempt["body_sha256"]) != _safe_hash(raw)
                or type(attempt["body_size"]) is not int or attempt["body_size"] != len(raw)
                or type(attempt["response_body_bytes"]) is not int or attempt["response_body_bytes"] != len(raw)
                or type(attempt["request_body_bytes"]) is not int or attempt["request_body_bytes"] != 0
                or len(raw) > expected_cap):
            refuse()
        controls = attempt["control_headers"]
        if (type(controls) is not list or len(controls) > 5
                or any(type(pair) is not list or len(pair) != 2 or any(type(v) is not str for v in pair)
                       or pair[0] not in {"content-type", "content-encoding", "content-length", "transfer-encoding", "retry-after"}
                       for pair in controls)):
            refuse()
        response = TransportResponse(attempt["status_code"], tuple(tuple(pair) for pair in controls), raw, prepared["url"])
        framing = dict(controls)
        length, transfer = framing.get("content-length"), framing.get("transfer-encoding")
        if (len(framing) != len(controls) or response.status_code < 200 or 300 <= response.status_code <= 399
                or (length is not None and (transfer is not None or re.fullmatch(r"[0-9]+", length) is None))
                or (transfer is not None and transfer.lower() != "chunked")
                or (response.status_code == 204 and (length is not None or transfer is not None or raw))
                or (response.status_code == 205 and raw)
                or (response.status_code != 204 and length is None and transfer is None)):
            refuse()
        EgressGateway._response_controls(None, response, policy)
        if ordinal < len(attempts):
            if response.status_code not in policy.retry_statuses or attempt["retry_delay_seconds"] != EgressGateway._retry_delay(None, response, ordinal, policy):
                refuse()
        cumulative += len(raw)
        if type(attempt["cumulative_bytes"]) is not int or attempt["cumulative_bytes"] != cumulative:
            refuse()
        previous = coord
    _replay_retry_backoff(policy, attempts)
    final = attempts[-1]
    final_controls = dict(final["control_headers"])
    recorded = receipt.get("headers")
    if (type(recorded) is not dict or any(type(k) is not str or type(v) is not str for k, v in recorded.items())
            or set(recorded) - set(policy.recorded_response_headers)
            or {k: v for k, v in recorded.items() if k in {"content-type", "content-encoding", "content-length", "transfer-encoding", "retry-after"}}
            != {k: v for k, v in final_controls.items() if k in policy.recorded_response_headers}
            or receipt.get("content_type") != _response_media_type(final_controls["content-type"])):
        refuse()
    if (receipt.get("request_id") != request.request_id or receipt.get("raw_response_record_sha256") != final["raw_response_record_sha256"]
            or receipt.get("raw_response_sha256") != final["body_sha256"] or receipt.get("body_size") != final["body_size"]
            or receipt.get("status_code") != final["status_code"]
            or receipt.get("content_coding") != _pmc_content_coding(tuple(tuple(p) for p in final["control_headers"]))):
        refuse()
    if 200 <= final["status_code"] <= 299:
        require_pmc_content_decoding(registry, descriptor_sha256=receipt.get("decoding_artifact_sha256"), receipt=receipt, policy=policy)
    elif receipt.get("decoding_artifact_sha256") is not None or receipt.get("decoding_artifact_record_hash") is not None:
        refuse()


def _authority_artifact_metadata_claim(
    *,
    response_receipt_artifact_sha256: str,
    created_at: str,
    schema_version: str = AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
) -> dict[str, object]:
    return {
        "logical_type": AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
        "origin": _AUDITED_TRANSPORT_AUTHORITY_ORIGIN,
        "creator_role": Role.EVIDENCE_CURATOR.value,
        "creation_command": list(_AUDITED_TRANSPORT_AUTHORITY_COMMAND),
        "parent_artifacts": [response_receipt_artifact_sha256],
        "schema_version": schema_version,
        "mime_type": "application/json",
        "validation_result": "PASS",
        "frozen": True,
        "created_at": created_at,
    }


def _audited_transport_implementation_profile() -> dict[str, object]:
    return {
        "transport_type": "scientist_one.external.StdlibHttpsTransport",
        "send_implementation": (
            "scientist_one.external.StdlibHttpsTransport.send"
        ),
        "https_connection_type": "http.client.HTTPSConnection",
        "tls_context_type": "ssl.SSLContext",
        "tls_protocol": "PROTOCOL_TLS_CLIENT",
        "minimum_tls_version": "TLSv1_2",
        "certificate_verification": "CERT_REQUIRED",
        "check_hostname": True,
        "proxy_environment_inherited": False,
    }


def _authority_event_metadata(
    *,
    authority_artifact: ArtifactRecord,
    response_receipt_artifact_sha256: str,
    request_id: str,
    prefix_head_hash: str,
) -> dict[str, object]:
    return {
        "schema_version": authority_artifact.schema_version,
        "authority_artifact_sha256": authority_artifact.sha256,
        "authority_record_hash": authority_artifact.record_hash,
        "response_receipt_artifact_sha256": response_receipt_artifact_sha256,
        "request_id": request_id,
        "ledger_prefix_head_hash": prefix_head_hash,
    }


def _prepare_audited_transport_execution_claim(
    gateway: EgressGateway,
    *,
    policy_snapshot: EgressPolicy,
    policy_claim_sha256: str,
    egress_budget: Mapping[str, object],
    prepared_request: PreparedEgressRequest,
    prepared_request_binding: str,
    prepared_request_claim: Mapping[str, object],
    policy_claim: Mapping[str, object],
    implementation_profile: Mapping[str, object],
    request_policy_replay: Callable[
        [EgressPolicy, Mapping[str, object], Mapping[str, object]],
        None,
    ],
    retry_backoff_replay: Callable[
        [EgressPolicy, Sequence[Mapping[str, object]]],
        None,
    ],
    request_artifact: ArtifactRecord | None,
    response_receipt_artifact: ArtifactRecord | None,
    raw_response_artifact: ArtifactRecord | None,
    attempts: Sequence[Mapping[str, object]],
    response: TransportResponse,
    content_type: str,
    captured_at: str,
    pmc_wire_rows: tuple | None = None,
) -> _AuditedTransportExecutionClaim | None:
    """Read and validate exact issuance inputs without signing or mutating state."""

    if policy_snapshot.adapter_id == PMC_CONTENT_ADAPTER_ID:
        return None  # No v3 live issuance before coordinated admission exists.
    wire_selected = policy_snapshot.adapter_id == PMC_WIRE_ADAPTER_ID
    if wire_selected:
        _require_pmc_wire_activation()
        if type(pmc_wire_rows) is not tuple or len(pmc_wire_rows) != len(attempts):
            return None
        for projection, attempt in zip(pmc_wire_rows, attempts):
            if type(projection) is not dict or any(attempt.get(k) != v for k, v in projection.items()):
                return None
    registry = gateway.registry
    ledger = gateway._authority_ledger
    run_id = gateway._authority_run_id
    if (
        not isinstance(prepared_request, PreparedEgressRequest)
        or not isinstance(policy_snapshot, EgressPolicy)
        or gateway.policy is not policy_snapshot
        or not isinstance(policy_claim_sha256, str)
        or policy_claim_sha256
        != _safe_hash(canonical_json_bytes(dict(policy_claim)))
        or not isinstance(prepared_request_binding, str)
        or _safe_hash(canonical_json_bytes(dict(prepared_request_claim)))
        != prepared_request_binding
        or not _is_exact_egress_gateway(gateway)
        or gateway._clock is not time.monotonic
        or gateway._sleeper is not time.sleep
        or _classify_transport_authority(gateway.transport)
        != AUDITED_LIVE_TRANSPORT_AUTHORITY
        or not _is_exact_authority_registry(registry)
        or not _is_exact_authority_ledger(ledger)
        or run_id is None
        or request_artifact is None
        or response_receipt_artifact is None
        or raw_response_artifact is None
        or ledger.policy.root != registry.policy.root
    ):
        return None
    try:
        validate_identifier(run_id, "gateway authority run ID")
        registry.verify(request_artifact.sha256, raise_on_error=True)
        registry.verify(response_receipt_artifact.sha256, raise_on_error=True)
        registry.verify(raw_response_artifact.sha256, raise_on_error=True)
        request_payload = safe_json_loads(
            registry.get_bytes(request_artifact.sha256),
            max_bytes=MAX_ABSOLUTE_REQUEST_BYTES,
            max_depth=MAX_JSON_DEPTH,
            max_items=MAX_JSON_ITEMS,
        )
        receipt_bytes = registry.get_bytes(response_receipt_artifact.sha256)
        receipt = safe_json_loads(
            receipt_bytes,
            max_bytes=MAX_ABSOLUTE_REQUEST_BYTES,
            max_depth=MAX_JSON_DEPTH,
            max_items=MAX_JSON_ITEMS,
        )
        if (
            not isinstance(receipt, Mapping)
            or receipt.get("kind") != "EXTERNAL_RESPONSE_RECEIPT"
        ):
            return None
        request_policy_replay(
            policy_snapshot,
            request_payload,
            prepared_request_claim,
        )
        retry_backoff_replay(policy_snapshot, attempts)
        if (
            not isinstance(request_payload, Mapping)
            or request_payload.get("kind") != "REDACTED_EXTERNAL_REQUEST"
            or request_payload.get("schema_version") != EGRESS_REQUEST_SCHEMA
            or request_payload.get("request_id") != prepared_request.request_id
            or request_payload.get("policy_id") != policy_snapshot.policy_id
            or request_payload.get("policy_claim_sha256")
            != policy_claim_sha256
            or request_payload.get("egress_budget")
            != _egress_budget_policy_claim(policy_snapshot)
            or request_payload.get("adapter_id") != policy_snapshot.adapter_id
            or request_payload.get("method") != prepared_request.method
            or request_payload.get("url") != prepared_request.url
            or request_payload.get("headers")
            != [list(value) for value in prepared_request.headers]
            or request_payload.get("body_sha256")
            != _safe_hash(prepared_request.body)
            or request_payload.get("body_size") != len(prepared_request.body)
            or request_payload.get("content_type")
            != prepared_request.content_type
            or prepared_request.timeout_seconds <= 0
            or (not wire_selected and prepared_request.timeout_seconds > policy_snapshot.timeout_seconds)
            or prepared_request.maximum_response_bytes < 0
            or prepared_request.maximum_response_bytes
            > policy_snapshot.maximum_response_bytes
            or prepared_request.credential_header
            != (
                policy_snapshot.credential_header
                if request_payload.get("credential_present") is True
                else None
            )
            or prepared_request.credential_prefix
            != policy_snapshot.credential_prefix
            or dict(policy_claim) != _egress_policy_claim(policy_snapshot)
            or receipt.get("request_id") != prepared_request.request_id
            or receipt.get("schema_version")
            != (PMC_WIRE_RESPONSE_SCHEMA if wire_selected else EGRESS_RESPONSE_RECEIPT_SCHEMA)
            or receipt.get("policy_claim_sha256") != policy_claim_sha256
            or receipt.get("egress_budget") != dict(egress_budget)
            or receipt.get("request_artifact_sha256") != request_artifact.sha256
            or receipt.get("raw_response_record_sha256")
            != raw_response_artifact.sha256
            or receipt.get("raw_response_sha256") != _safe_hash(response.body)
            or receipt.get("body_size") != len(response.body)
            or receipt.get("status_code") != response.status_code
            or (not wire_selected and not 200 <= response.status_code <= 299)
            or receipt.get("content_type") != content_type
            or (not wire_selected and content_type != "application/json")
            or receipt.get("attempts") != list(attempts)
            or receipt.get("network_used") is not True
            or receipt.get("external_validation") != _LIVE_RESPONSE_VALIDATION
            or receipt.get("transport_authority")
            != AUDITED_LIVE_TRANSPORT_AUTHORITY
        ):
            return None
        ledger_result = ledger.validate(raise_on_error=True)
        events = ledger_result.events
        if (
            not ledger_result.valid
            or not events
            or ledger_result.head_hash is None
            or any(event.run_id != run_id for event in events)
        ):
            return None
        prefix_head_hash = ledger_result.head_hash
        prefix_event_count = len(events)
        unsigned: dict[str, object] = {
            "schema_version": AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
            "kind": "AUDITED_TRANSPORT_EXECUTION_AUTHORITY",
            "run_id": run_id,
            "request_id": receipt["request_id"],
            "policy_id": policy_snapshot.policy_id,
            "adapter_id": policy_snapshot.adapter_id,
            "policy": dict(policy_claim),
            "policy_claim_sha256": policy_claim_sha256,
            "prepared_request": dict(prepared_request_claim),
            "prepared_request_binding": prepared_request_binding,
            "request_artifact_sha256": request_artifact.sha256,
            "request_artifact_record_hash": request_artifact.record_hash,
            "response_receipt_artifact_sha256": response_receipt_artifact.sha256,
            "response_receipt_record_hash": response_receipt_artifact.record_hash,
            "raw_response_artifact_sha256": raw_response_artifact.sha256,
            "raw_response_artifact_record_hash": raw_response_artifact.record_hash,
            "raw_response_sha256": _safe_hash(response.body),
            "body_size": len(response.body),
            "status_code": response.status_code,
            "content_type": content_type,
            "response_effective_url": response.effective_url,
            "response_headers_sha256": _safe_hash(
                canonical_json_bytes([list(value) for value in response.headers])
            ),
            "response_header_count": len(response.headers),
            "attempts": [dict(value) for value in attempts],
            "attempts_sha256": _safe_hash(canonical_json_bytes(list(attempts))),
            "egress_budget": dict(egress_budget),
            "network_used": True,
            "external_validation": _LIVE_RESPONSE_VALIDATION,
            "transport_authority": AUDITED_LIVE_TRANSPORT_AUTHORITY,
            "implementation_profile": dict(implementation_profile),
            "ledger_prefix_head_hash": prefix_head_hash,
            "ledger_prefix_event_count": prefix_event_count,
            "issued_at": captured_at,
        }
        if wire_selected:
            if receipt.get("headers") != dict(sorted((name.lower(), value) for name, value in response.headers
                                                     if name.lower() in policy_snapshot.recorded_response_headers)):
                return None
            _replay_pmc_wire_attempts(registry, policy_snapshot, request_payload, receipt)
            unsigned.update(schema_version=PMC_WIRE_AUTHORITY_SCHEMA,
                            implementation_profile=_pmc_wire_implementation_profile(implementation_profile))
            for key in _PMC_WIRE_AUTHORITY_FIELDS:
                unsigned[key] = receipt[key]
        return _AuditedTransportExecutionClaim(
            registry=registry,
            ledger=ledger,
            run_id=run_id,
            response_receipt_artifact=response_receipt_artifact,
            request_id=str(receipt["request_id"]),
            captured_at=captured_at,
            prefix_head_hash=prefix_head_hash,
            prefix_event_count=prefix_event_count,
            prior_event=events[-1],
            unsigned=MappingProxyType(unsigned),
        )
    except (
        ArtifactError,
        EgressPolicyError,
        LedgerError,
        OSError,
        PathSecurityError,
        TypeError,
        UnsafeSerializationError,
        ValidationError,
        ValueError,
    ):
        return None


def _replay_signed_request_against_policy(
    policy: EgressPolicy,
    request: Mapping[str, object],
    prepared: Mapping[str, object],
) -> None:
    """Independently replay target and request admission from signed values."""

    if not policy.enabled:
        raise EgressPolicyError("signed egress policy is disabled")
    credential_present = request.get("credential_present")
    body_size = request.get("body_size")
    if (
        request.get("schema_version") != EGRESS_REQUEST_SCHEMA
        or request.get("kind") != "REDACTED_EXTERNAL_REQUEST"
        or request.get("policy_id") != policy.policy_id
        or request.get("policy_claim_sha256")
        != _safe_hash(canonical_json_bytes(_egress_policy_claim(policy)))
        or request.get("egress_budget")
        != _egress_budget_policy_claim(policy)
        or request.get("adapter_id") != policy.adapter_id
        or prepared.get("method") != request.get("method")
        or request.get("method") not in policy.allowed_methods
        or prepared.get("content_type") != request.get("content_type")
        or request.get("content_type")
        not in policy.allowed_request_content_types
        or isinstance(body_size, bool)
        or not isinstance(body_size, int)
        or body_size < 0
        or body_size > policy.maximum_request_bytes
        or (
            request.get("method") == "GET"
            and body_size != 0
        )
        or not isinstance(credential_present, bool)
        or credential_present is not False
        or request.get("credential_env_name")
        != policy.credential_env_name
        or (policy.credential_required and credential_present is not True)
        or (credential_present is True and policy.credential_env_name is None)
        or prepared.get("credential_header")
        != (policy.credential_header if credential_present is True else None)
        or prepared.get("credential_prefix") != policy.credential_prefix
        or request.get("scientific_evidence") is not False
    ):
        raise EgressPolicyError("signed request is not admitted by its policy")
    try:
        parsed = urlsplit(request.get("url"))
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise EgressPolicyError("signed request URL is malformed") from exc
    host = parsed.hostname.lower() if isinstance(parsed.hostname, str) else ""
    if (
        parsed.scheme.lower() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.fragment)
        or port not in (None, 443)
        or not host
        or host.endswith(".")
        or not host.isascii()
        or not _HOST_RE.fullmatch(host)
        or host not in policy.allowed_hosts
    ):
        raise EgressPolicyError("signed request target is not admitted by its policy")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise EgressPolicyError("signed request target cannot be an IP literal")
    path = parsed.path or "/"
    if (
        "%" in path
        or not path.startswith("/")
        or "\\" in path
        or "//" in path
        or any(part == ".." for part in path.split("/"))
        or any(ord(character) < 32 for character in path)
        or not any(
            path == prefix
            or (prefix.endswith("/") and path.startswith(prefix))
            for prefix in policy.allowed_path_prefixes
        )
    ):
        raise EgressPolicyError("signed request path is not admitted by its policy")
    query = parsed.query
    if query:
        try:
            pairs = parse_qsl(
                query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=64,
            )
        except ValueError as exc:
            raise EgressPolicyError("signed request query is malformed") from exc
        allowed_query = set(policy.allowed_query_keys)
        seen_query: set[str] = set()
        for key, value in pairs:
            if (
                key not in allowed_query
                or key in seen_query
                or _SENSITIVE_QUERY_RE.search(key)
                or len(key.encode("utf-8")) > 128
                or len(value.encode("utf-8")) > 4096
                or any(character in value for character in ("\x00", "\r", "\n"))
            ):
                raise EgressPolicyError(
                    "signed request query is not admitted by its policy"
                )
            seen_query.add(key)
    normalized_url = urlunsplit(("https", host, path, query, ""))
    target = path + (f"?{query}" if query else "")
    if (
        request.get("url") != normalized_url
        or prepared.get("url") != normalized_url
        or prepared.get("host") != host
        or prepared.get("target") != target
    ):
        raise EgressPolicyError("signed prepared target differs from policy replay")
    header_value = request.get("headers")
    if not isinstance(header_value, list):
        raise EgressPolicyError("signed request headers are malformed")
    try:
        headers = _headers(
            tuple(tuple(value) for value in header_value),
            caller_supplied=True,
        )
    except (EgressDeniedError, EgressPolicyError, TypeError) as exc:
        raise EgressPolicyError("signed request headers are malformed") from exc
    allowed_headers = set(policy.allowed_request_headers)
    for name, value in headers:
        if (
            name.lower() not in allowed_headers
            or detect_secret_patterns(value)
            or (
                name.lower() == "content-type"
                and value.strip().lower() != request.get("content_type")
            )
        ):
            raise EgressPolicyError(
                "signed request headers are not admitted by their policy"
            )
    if prepared.get("headers") != [list(value) for value in headers]:
        raise EgressPolicyError("signed prepared headers differ from policy replay")


def _require_audited_live_transport_execution_with_key(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    authority_artifact_sha256: str,
    response_receipt_artifact_sha256: str,
    authority_key: bytes,
    implementation_profile: Mapping[str, object],
    request_policy_replay: Callable[
        [EgressPolicy, Mapping[str, object], Mapping[str, object]],
        None,
    ],
    retry_backoff_replay: Callable[
        [EgressPolicy, Sequence[Mapping[str, object]]],
        None,
    ],
) -> AuditedTransportExecutionAuthority:
    """Internal resolver captured by the public key-hiding verifier closure."""

    try:
        validate_identifier(run_id, "gateway authority run ID")
    except ValidationError as exc:
        raise EgressPolicyError("gateway authority run ID is invalid") from exc
    if (
        not _is_exact_authority_registry(registry)
        or not _is_exact_authority_ledger(ledger)
        or ledger.policy.root != registry.policy.root
        or not isinstance(authority_artifact_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", authority_artifact_sha256) is None
        or not isinstance(response_receipt_artifact_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", response_receipt_artifact_sha256)
        is None
        or not isinstance(authority_key, bytes)
        or len(authority_key) != _AUDITED_TRANSPORT_AUTHORITY_KEY_BYTES
    ):
        raise EgressPolicyError("audited transport execution binding is invalid")
    try:
        registry.verify(authority_artifact_sha256, raise_on_error=True)
        registry.verify(response_receipt_artifact_sha256, raise_on_error=True)
        authority_record = registry.get_metadata(authority_artifact_sha256)
        receipt_record = registry.get_metadata(response_receipt_artifact_sha256)
        authority = safe_json_loads(
            registry.get_bytes(authority_artifact_sha256),
            max_bytes=MAX_ABSOLUTE_REQUEST_BYTES,
            max_depth=MAX_JSON_DEPTH,
            max_items=MAX_JSON_ITEMS,
        )
        receipt = safe_json_loads(
            registry.get_bytes(response_receipt_artifact_sha256),
            max_bytes=MAX_ABSOLUTE_REQUEST_BYTES,
            max_depth=MAX_JSON_DEPTH,
            max_items=MAX_JSON_ITEMS,
        )
    except (ArtifactError, UnsafeSerializationError) as exc:
        raise EgressPolicyError(
            "audited transport execution artifacts are absent or corrupt"
        ) from exc
    required = {
        "schema_version",
        "kind",
        "run_id",
        "request_id",
        "policy_id",
        "adapter_id",
        "policy",
        "policy_claim_sha256",
        "prepared_request",
        "prepared_request_binding",
        "request_artifact_sha256",
        "request_artifact_record_hash",
        "response_receipt_artifact_sha256",
        "response_receipt_record_hash",
        "raw_response_artifact_sha256",
        "raw_response_artifact_record_hash",
        "raw_response_sha256",
        "body_size",
        "status_code",
        "content_type",
        "response_effective_url",
        "response_headers_sha256",
        "response_header_count",
        "attempts",
        "attempts_sha256",
        "egress_budget",
        "network_used",
        "external_validation",
        "transport_authority",
        "implementation_profile",
        "ledger_prefix_head_hash",
        "ledger_prefix_event_count",
        "issued_at",
        "nonce",
        "key_id",
        "claim_sha256",
        "authentication_tag",
    }
    wire_selected = isinstance(authority, Mapping) and authority.get("schema_version") == PMC_WIRE_AUTHORITY_SCHEMA
    if wire_selected:
        _require_pmc_wire_activation()
        required |= _PMC_WIRE_AUTHORITY_FIELDS
    authority_schema = PMC_WIRE_AUTHORITY_SCHEMA if wire_selected else AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA
    response_schema = PMC_WIRE_RESPONSE_SCHEMA if wire_selected else EGRESS_RESPONSE_RECEIPT_SCHEMA
    if not isinstance(authority, Mapping) or set(authority) != required:
        raise EgressPolicyError("audited transport execution schema is invalid")
    unsigned = {
        name: authority[name]
        for name in required - {"claim_sha256", "authentication_tag"}
    }
    metadata_claim = _authority_artifact_metadata_claim(
        response_receipt_artifact_sha256=response_receipt_artifact_sha256,
        created_at=str(authority.get("issued_at")),
        schema_version=authority_schema,
    )
    claim_bytes = canonical_json_bytes(
        {"authority": unsigned, "artifact_metadata": metadata_claim}
    )
    expected_tag = hmac.new(
        authority_key,
        claim_bytes,
        hashlib.sha256,
    ).hexdigest()
    if (
        authority.get("schema_version")
        != authority_schema
        or authority.get("kind") != "AUDITED_TRANSPORT_EXECUTION_AUTHORITY"
        or authority.get("run_id") != run_id
        or not isinstance(authority.get("request_id"), str)
        or re.fullmatch(r"[0-9a-f]{64}", authority["request_id"]) is None
        or authority.get("response_receipt_artifact_sha256")
        != response_receipt_artifact_sha256
        or not isinstance(authority.get("issued_at"), str)
        or not isinstance(authority.get("nonce"), str)
        or re.fullmatch(r"[0-9a-f]{32}", authority["nonce"]) is None
        or not isinstance(authority.get("key_id"), str)
        or re.fullmatch(r"[0-9a-f]{64}", authority["key_id"]) is None
        or not isinstance(authority.get("claim_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", authority["claim_sha256"])
        is None
        or authority.get("claim_sha256") != _safe_hash(claim_bytes)
        or authority.get("key_id") != _safe_hash(authority_key)
        or not isinstance(authority.get("authentication_tag"), str)
        or re.fullmatch(
            r"[0-9a-f]{64}",
            authority["authentication_tag"],
        )
        is None
        or not hmac.compare_digest(
            authority["authentication_tag"],
            expected_tag,
        )
        or authority.get("implementation_profile")
        != (_pmc_wire_implementation_profile(implementation_profile) if wire_selected else dict(implementation_profile))
        or authority.get("network_used") is not True
        or authority.get("external_validation") != _LIVE_RESPONSE_VALIDATION
        or authority.get("transport_authority")
        != AUDITED_LIVE_TRANSPORT_AUTHORITY
        or authority_record.logical_type
        != AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE
        or authority_record.origin != _AUDITED_TRANSPORT_AUTHORITY_ORIGIN
        or authority_record.creator_role is not Role.EVIDENCE_CURATOR
        or authority_record.creation_command
        != _AUDITED_TRANSPORT_AUTHORITY_COMMAND
        or authority_record.parent_artifacts
        != (response_receipt_artifact_sha256,)
        or authority_record.schema_version
        != authority_schema
        or authority_record.mime_type != "application/json"
        or authority_record.validation_result != "PASS"
        or authority_record.frozen is not True
        or authority_record.created_at != authority.get("issued_at")
        or authority.get("response_receipt_record_hash")
        != receipt_record.record_hash
    ):
        raise EgressPolicyError(
            "audited transport execution signature or metadata is invalid"
        )
    if not isinstance(receipt, Mapping):
        raise EgressPolicyError("external response receipt is malformed")
    try:
        request_hash = str(authority["request_artifact_sha256"])
        raw_hash = str(authority["raw_response_artifact_sha256"])
        registry.verify(request_hash, raise_on_error=True)
        registry.verify(raw_hash, raise_on_error=True)
        request_record = registry.get_metadata(request_hash)
        raw_record = registry.get_metadata(raw_hash)
        request = safe_json_loads(
            registry.get_bytes(request_hash),
            max_bytes=MAX_ABSOLUTE_REQUEST_BYTES,
            max_depth=MAX_JSON_DEPTH,
            max_items=MAX_JSON_ITEMS,
        )
        raw_bytes = registry.get_bytes(raw_hash)
    except (ArtifactError, UnsafeSerializationError) as exc:
        raise EgressPolicyError("audited transport execution ancestry is invalid") from exc
    attempts = receipt.get("attempts")
    policy_value = authority.get("policy")
    prepared = authority.get("prepared_request")
    policy_sequence_fields = (
        "allowed_hosts",
        "allowed_path_prefixes",
        "allowed_methods",
        "allowed_query_keys",
        "allowed_request_headers",
        "allowed_request_content_types",
        "allowed_response_content_types",
        "recorded_response_headers",
        "retry_statuses",
    )
    prepared_fields = {
        "request_id",
        "method",
        "url",
        "host",
        "target",
        "headers",
        "body_sha256",
        "body_size",
        "content_type",
        "timeout_seconds",
        "maximum_response_bytes",
        "attempt_number",
        "cumulative_bytes_before_attempt",
        "deadline_elapsed_seconds",
        "credential_header",
        "credential_prefix",
    }
    try:
        if (
            not isinstance(policy_value, Mapping)
            or any(
                not isinstance(policy_value.get(name), list)
                for name in policy_sequence_fields
            )
        ):
            raise EgressPolicyError("signed egress policy is malformed")
        reconstructed_policy = EgressPolicy(
            policy_id=policy_value.get("policy_id"),
            adapter_id=policy_value.get("adapter_id"),
            allowed_hosts=tuple(policy_value["allowed_hosts"]),
            allowed_path_prefixes=tuple(policy_value["allowed_path_prefixes"]),
            allowed_methods=tuple(policy_value["allowed_methods"]),
            allowed_query_keys=tuple(policy_value["allowed_query_keys"]),
            allowed_request_headers=tuple(
                policy_value["allowed_request_headers"]
            ),
            allowed_request_content_types=tuple(
                policy_value["allowed_request_content_types"]
            ),
            allowed_response_content_types=tuple(
                policy_value["allowed_response_content_types"]
            ),
            recorded_response_headers=tuple(
                policy_value["recorded_response_headers"]
            ),
            maximum_request_bytes=policy_value.get("maximum_request_bytes"),
            maximum_response_bytes=policy_value.get("maximum_response_bytes"),
            maximum_total_bytes=policy_value.get("maximum_total_bytes"),
            timeout_seconds=policy_value.get("timeout_seconds"),
            minimum_interval_seconds=policy_value.get(
                "minimum_interval_seconds"
            ),
            maximum_requests=policy_value.get("maximum_requests"),
            maximum_attempts=policy_value.get("maximum_attempts"),
            retry_statuses=tuple(policy_value["retry_statuses"]),
            backoff_initial_seconds=policy_value.get(
                "backoff_initial_seconds"
            ),
            backoff_maximum_seconds=policy_value.get(
                "backoff_maximum_seconds"
            ),
            maximum_json_depth=policy_value.get("maximum_json_depth"),
            maximum_json_items=policy_value.get("maximum_json_items"),
            credential_env_name=policy_value.get("credential_env_name"),
            credential_required=policy_value.get("credential_required"),
            credential_header=policy_value.get("credential_header"),
            credential_prefix=policy_value.get("credential_prefix"),
            enabled=policy_value.get("enabled"),
        )
    except (EgressPolicyError, TypeError, ValueError) as exc:
        raise EgressPolicyError("signed egress policy is malformed") from exc
    if (
        dict(policy_value) != _egress_policy_claim(reconstructed_policy)
        or authority.get("policy_claim_sha256")
        != _safe_hash(canonical_json_bytes(dict(policy_value)))
        or not isinstance(prepared, Mapping)
        or set(prepared) != prepared_fields
    ):
        raise EgressPolicyError("signed request or policy projection is invalid")
    if not isinstance(request, Mapping):
        raise EgressPolicyError("signed request projection is invalid")
    request_policy_replay(
        reconstructed_policy,
        request,
        prepared,
    )
    try:
        prepared_url = urlsplit(prepared.get("url"))
        prepared_target = (prepared_url.path or "/") + (
            f"?{prepared_url.query}" if prepared_url.query else ""
        )
    except (TypeError, ValueError) as exc:
        raise EgressPolicyError("signed prepared request URL is malformed") from exc
    prepared_headers = prepared.get("headers")
    prepared_body_size = prepared.get("body_size")
    response_header_count = authority.get("response_header_count")
    if (
        isinstance(prepared_body_size, bool)
        or not isinstance(prepared_body_size, int)
        or prepared_body_size < 0
        or prepared_body_size > reconstructed_policy.maximum_request_bytes
        or
        not isinstance(attempts, list)
        or not attempts
        or len(attempts) > reconstructed_policy.maximum_attempts
    ):
        raise EgressPolicyError("audited transport attempts are malformed")
    attempt_raw_hashes: list[str] = []
    calculated_request_bytes = 0
    calculated_response_bytes = 0
    prior_completed_offset = 0.0
    attempt_fields = {
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
    }
    if wire_selected:
        attempt_fields |= _PMC_WIRE_ATTEMPT_FIELDS
        _replay_pmc_wire_attempts(registry, reconstructed_policy, request, receipt)
        if (any(authority.get(key) != receipt.get(key) for key in _PMC_WIRE_AUTHORITY_FIELDS)
                or prepared != attempts[-1]["prepared_request"]
                or authority.get("prepared_request_binding") != attempts[-1]["prepared_request_binding"]):
            raise EgressPolicyError("PMC final wire authority projection differs")
    for expected_attempt, attempt_value in enumerate(attempts, start=1):
        if not isinstance(attempt_value, Mapping):
            raise EgressPolicyError("audited transport attempt ordering is invalid")
        started_offset = attempt_value.get("started_offset_seconds")
        completed_offset = attempt_value.get("completed_offset_seconds")
        if (
            set(attempt_value) != attempt_fields
            or attempt_value.get("schema_version") != (PMC_WIRE_ATTEMPT_SCHEMA if wire_selected else EGRESS_ATTEMPT_SCHEMA)
            or attempt_value.get("attempt") != expected_attempt
            or isinstance(started_offset, bool)
            or not isinstance(started_offset, (int, float))
            or not math.isfinite(float(started_offset))
            or isinstance(completed_offset, bool)
            or not isinstance(completed_offset, (int, float))
            or not math.isfinite(float(completed_offset))
            or float(started_offset) < prior_completed_offset
            or float(completed_offset) < float(started_offset)
            or float(completed_offset) >= reconstructed_policy.timeout_seconds
            or attempt_value.get("request_body_bytes") != prepared_body_size
        ):
            raise EgressPolicyError("audited transport attempt ordering is invalid")
        calculated_request_bytes += int(prepared_body_size)
        maximum_admitted_response = min(
            reconstructed_policy.maximum_response_bytes,
            reconstructed_policy.maximum_total_bytes
            - calculated_request_bytes
            - calculated_response_bytes,
        )
        if maximum_admitted_response <= 0:
            raise EgressPolicyError(
                "audited transport request leaves no cumulative response budget"
            )
        prior_completed_offset = float(completed_offset)
        if attempt_value.get("status") == "TRANSPORT_FAILURE":
            failed_response_bytes = attempt_value.get("response_body_bytes")
            if any(
                attempt_value.get(name) is not None
                for name in (
                    "status_code",
                    "body_sha256",
                    "body_size",
                    "raw_response_record_sha256",
                )
            ) or (
                isinstance(failed_response_bytes, bool)
                or not isinstance(failed_response_bytes, int)
                or failed_response_bytes < 0
                or failed_response_bytes > maximum_admitted_response
            ):
                raise EgressPolicyError(
                    "transport-failure attempt contains response metadata"
                )
            calculated_response_bytes += failed_response_bytes
            expected_cumulative = (
                calculated_request_bytes + calculated_response_bytes
            )
            if (
                attempt_value.get("cumulative_bytes") != expected_cumulative
                or expected_cumulative
                > reconstructed_policy.maximum_total_bytes
            ):
                raise EgressPolicyError(
                    "transport-failure byte accounting is invalid"
                )
            continue
        attempt_raw_hash = attempt_value.get("raw_response_record_sha256")
        attempt_status = attempt_value.get("status_code")
        attempt_body_size = attempt_value.get("body_size")
        attempt_body_sha256 = attempt_value.get("body_sha256")
        if (
            attempt_value.get("status") != "RESPONSE"
            or isinstance(attempt_status, bool)
            or not isinstance(attempt_status, int)
            or not 100 <= attempt_status <= 599
            or isinstance(attempt_body_size, bool)
            or not isinstance(attempt_body_size, int)
            or not 0 <= attempt_body_size <= MAX_ABSOLUTE_RESPONSE_BYTES
            or attempt_body_size > maximum_admitted_response
            or attempt_value.get("response_body_bytes") != attempt_body_size
            or not isinstance(attempt_body_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", attempt_body_sha256) is None
            or not isinstance(attempt_raw_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", attempt_raw_hash) is None
        ):
            raise EgressPolicyError("audited response attempt is malformed")
        calculated_response_bytes += attempt_body_size
        expected_cumulative = calculated_request_bytes + calculated_response_bytes
        if (
            attempt_value.get("cumulative_bytes") != expected_cumulative
            or expected_cumulative > reconstructed_policy.maximum_total_bytes
            or (
                expected_attempt < len(attempts)
                and attempt_status not in reconstructed_policy.retry_statuses
            )
        ):
            raise EgressPolicyError("audited response byte or retry policy is invalid")
        try:
            registry.verify(attempt_raw_hash, raise_on_error=True)
            attempt_raw_record = registry.get_metadata(attempt_raw_hash)
            attempt_raw_bytes = registry.get_bytes(attempt_raw_hash)
        except ArtifactError as exc:
            raise EgressPolicyError(
                "audited attempt raw response is absent or corrupt"
            ) from exc
        if (
            _safe_hash(attempt_raw_bytes) != attempt_body_sha256
            or len(attempt_raw_bytes) != attempt_body_size
            or attempt_raw_record.logical_type != "external_response_raw"
            or attempt_raw_record.origin
            != "controlled external egress raw response"
            or attempt_raw_record.creator_role is not Role.EVIDENCE_CURATOR
            or attempt_raw_record.creation_command
            != ("scientist-one", "controlled-egress")
            or attempt_raw_record.parent_artifacts
            or attempt_raw_record.schema_version != "1.0"
            or attempt_raw_record.mime_type != "application/octet-stream"
            or attempt_raw_record.validation_result != "PASS"
            or attempt_raw_record.frozen is not True
        ):
            raise EgressPolicyError(
                "audited attempt raw-response custody differs"
            )
        attempt_raw_hashes.append(attempt_raw_hash)
    retry_backoff_replay(reconstructed_policy, attempts)
    final_attempt = attempts[-1]
    budget = authority.get("egress_budget")
    budget_fields = {
        "schema_version",
        "maximum_total_bytes",
        "byte_accounting",
        "deadline_budget_seconds",
        "deadline_scope",
        "request_bytes_used",
        "response_bytes_used",
        "total_bytes_used",
        "deadline_elapsed_seconds",
        "deadline_remaining_seconds",
        "deadline_satisfied",
    }
    if not isinstance(budget, Mapping) or set(budget) != budget_fields:
        raise EgressPolicyError("audited egress budget is malformed")
    deadline_elapsed = budget.get("deadline_elapsed_seconds")
    deadline_remaining = budget.get("deadline_remaining_seconds")
    expected_budget_policy = _egress_budget_policy_claim(reconstructed_policy)
    wire_deadline = float.fromhex(final_attempt["coordination"]["deadline_seconds_hex"]) if wire_selected else None
    if (
        any(budget.get(name) != value for name, value in expected_budget_policy.items())
        or budget.get("request_bytes_used") != calculated_request_bytes
        or budget.get("response_bytes_used") != calculated_response_bytes
        or budget.get("total_bytes_used")
        != calculated_request_bytes + calculated_response_bytes
        or budget.get("total_bytes_used") > reconstructed_policy.maximum_total_bytes
        or isinstance(deadline_elapsed, bool)
        or not isinstance(deadline_elapsed, (int, float))
        or not math.isfinite(float(deadline_elapsed))
        or float(deadline_elapsed) < prior_completed_offset
        or float(deadline_elapsed) >= reconstructed_policy.timeout_seconds
        or isinstance(deadline_remaining, bool)
        or not isinstance(deadline_remaining, (int, float))
        or not math.isfinite(float(deadline_remaining))
        or not (_pmc_wire_remaining_seconds_match(deadline_remaining, deadline_elapsed, reconstructed_policy.timeout_seconds, wire_deadline)
                if wire_selected else math.isclose(
            float(deadline_remaining),
            reconstructed_policy.timeout_seconds - float(deadline_elapsed),
            rel_tol=0.0,
            abs_tol=1e-9,
        ))
        or budget.get("deadline_satisfied") is not True
        or receipt.get("egress_budget") != dict(budget)
    ):
        raise EgressPolicyError("audited egress budget replay differs")
    final_response_bytes = final_attempt.get("response_body_bytes")
    expected_cumulative_before_final = (
        calculated_request_bytes
        + calculated_response_bytes
        - prepared_body_size
        - (
            final_response_bytes
            if isinstance(final_response_bytes, int)
            and not isinstance(final_response_bytes, bool)
            else 0
        )
    )
    expected_prepared_response_limit = min(
        reconstructed_policy.maximum_response_bytes,
        reconstructed_policy.maximum_total_bytes
        - expected_cumulative_before_final
        - prepared_body_size,
    )
    final_started_offset = final_attempt.get("started_offset_seconds")
    prepared_timeout = prepared.get("timeout_seconds")
    if (
        prepared.get("attempt_number") != len(attempts)
        or prepared.get("cumulative_bytes_before_attempt")
        != expected_cumulative_before_final
        or prepared.get("deadline_elapsed_seconds") != final_started_offset
        or not isinstance(final_started_offset, (int, float))
        or isinstance(final_started_offset, bool)
        or not isinstance(prepared_timeout, (int, float))
        or isinstance(prepared_timeout, bool)
        or not (_pmc_wire_remaining_seconds_match(prepared_timeout, final_started_offset, reconstructed_policy.timeout_seconds, wire_deadline)
                if wire_selected else math.isclose(
            float(prepared_timeout),
            reconstructed_policy.timeout_seconds - float(final_started_offset),
            rel_tol=0.0,
            abs_tol=1e-9,
        ))
        or prepared.get("maximum_response_bytes")
        != expected_prepared_response_limit
    ):
        raise EgressPolicyError("signed prepared request budget replay differs")
    expected_receipt_parents = (
        request_hash,
        *tuple(dict.fromkeys(attempt_raw_hashes)),
    )
    if wire_selected:
        expected_receipt_parents = tuple(dict.fromkeys((*expected_receipt_parents,
            *(item["coordination"]["schedule"]["rules_artifact_sha256"] for item in attempts),
            *((receipt["decoding_artifact_sha256"],) if receipt.get("decoding_artifact_sha256") else ()))))
    if (
        not isinstance(request, Mapping)
        or set(request)
        != {
            "schema_version",
            "kind",
            "request_id",
            "policy_id",
            "policy_claim_sha256",
            "adapter_id",
            "method",
            "url",
            "headers",
            "body_sha256",
            "body_size",
            "content_type",
            "credential_env_name",
            "credential_present",
            "parent_artifacts",
            "scientific_evidence",
            "egress_budget",
        }
        or request.get("kind") != "REDACTED_EXTERNAL_REQUEST"
        or request.get("schema_version") != EGRESS_REQUEST_SCHEMA
        or not isinstance(request.get("credential_present"), bool)
        or request.get("scientific_evidence") is not False
        or not isinstance(request.get("parent_artifacts"), list)
        or request_record.parent_artifacts
        != tuple(request.get("parent_artifacts"))
        or request.get("request_id") != authority.get("request_id")
        or request.get("policy_id") != authority.get("policy_id")
        or request.get("policy_claim_sha256")
        != authority.get("policy_claim_sha256")
        or request.get("egress_budget")
        != _egress_budget_policy_claim(reconstructed_policy)
        or request.get("adapter_id") != authority.get("adapter_id")
        or authority.get("policy_id") != reconstructed_policy.policy_id
        or authority.get("adapter_id") != reconstructed_policy.adapter_id
        or prepared.get("request_id") != authority.get("request_id")
        or prepared.get("method") != request.get("method")
        or prepared.get("url") != request.get("url")
        or prepared_url.scheme != "https"
        or prepared_url.hostname != prepared.get("host")
        or prepared_target != prepared.get("target")
        or prepared_headers != request.get("headers")
        or not isinstance(prepared_headers, list)
        or prepared.get("body_sha256") != request.get("body_sha256")
        or not isinstance(prepared.get("body_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", prepared["body_sha256"]) is None
        or prepared_body_size != request.get("body_size")
        or isinstance(prepared_body_size, bool)
        or not isinstance(prepared_body_size, int)
        or prepared_body_size < 0
        or prepared_body_size > reconstructed_policy.maximum_request_bytes
        or prepared.get("content_type") != request.get("content_type")
        or prepared.get("credential_header")
        != (
            reconstructed_policy.credential_header
            if request.get("credential_present") is True
            else None
        )
        or prepared.get("credential_prefix")
        != reconstructed_policy.credential_prefix
        or request.get("credential_env_name")
        != reconstructed_policy.credential_env_name
        or authority.get("prepared_request_binding")
        != _safe_hash(canonical_json_bytes(dict(prepared)))
        or request_record.record_hash
        != authority.get("request_artifact_record_hash")
        or receipt.get("kind") != "EXTERNAL_RESPONSE_RECEIPT"
        or set(receipt)
        != ({
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
        } | (_PMC_WIRE_AUTHORITY_FIELDS if wire_selected else set()))
        or receipt.get("schema_version") != response_schema
        or receipt.get("scientific_evidence") is not False
        or receipt.get("captured_at") != authority.get("issued_at")
        or receipt.get("request_id") != authority.get("request_id")
        or receipt.get("policy_claim_sha256")
        != authority.get("policy_claim_sha256")
        or receipt.get("egress_budget") != authority.get("egress_budget")
        or receipt.get("request_artifact_sha256") != request_hash
        or receipt.get("raw_response_record_sha256") != raw_hash
        or receipt.get("raw_response_sha256") != _safe_hash(raw_bytes)
        or receipt.get("raw_response_sha256")
        != authority.get("raw_response_sha256")
        or receipt.get("body_size") != len(raw_bytes)
        or receipt.get("body_size") != authority.get("body_size")
        or receipt.get("status_code") != authority.get("status_code")
        or receipt.get("content_type") != authority.get("content_type")
        or (not wire_selected and authority.get("content_type") != "application/json")
        or authority.get("content_type")
        not in reconstructed_policy.allowed_response_content_types
        or authority.get("response_effective_url") != prepared.get("url")
        or not isinstance(authority.get("response_headers_sha256"), str)
        or re.fullmatch(
            r"[0-9a-f]{64}",
            authority["response_headers_sha256"],
        )
        is None
        or isinstance(response_header_count, bool)
        or not isinstance(response_header_count, int)
        or not 1 <= response_header_count <= MAX_HEADERS
        or not isinstance(receipt.get("headers"), Mapping)
        or set(receipt.get("headers"))
        - set(reconstructed_policy.recorded_response_headers)
        or receipt.get("network_used") is not True
        or receipt.get("external_validation") != _LIVE_RESPONSE_VALIDATION
        or receipt.get("transport_authority")
        != AUDITED_LIVE_TRANSPORT_AUTHORITY
        or authority.get("attempts") != attempts
        or authority.get("attempts_sha256")
        != _safe_hash(canonical_json_bytes(attempts))
        or raw_record.record_hash
        != authority.get("raw_response_artifact_record_hash")
        or request_record.logical_type != "external_request"
        or request_record.origin != "controlled external egress request intent"
        or request_record.creator_role is not Role.ORCHESTRATOR
        or request_record.creation_command
        != ("scientist-one", "controlled-egress")
        or request_record.validation_result != "PASS"
        or request_record.frozen is not True
        or request_record.schema_version != EGRESS_REQUEST_SCHEMA
        or request_record.mime_type != "application/json"
        or raw_record.logical_type != "external_response_raw"
        or raw_record.origin != "controlled external egress raw response"
        or raw_record.creator_role is not Role.EVIDENCE_CURATOR
        or raw_record.creation_command != ("scientist-one", "controlled-egress")
        or raw_record.parent_artifacts
        or raw_record.validation_result != "PASS"
        or raw_record.frozen is not True
        or raw_record.schema_version != "1.0"
        or raw_record.mime_type != "application/octet-stream"
        or receipt_record.logical_type != "external_response_receipt"
        or receipt_record.origin
        != "controlled external egress response receipt"
        or receipt_record.creator_role is not Role.EVIDENCE_CURATOR
        or receipt_record.creation_command
        != ("scientist-one", "controlled-egress")
        or receipt_record.validation_result != "PASS"
        or receipt_record.frozen is not True
        or receipt_record.schema_version != response_schema
        or receipt_record.mime_type != "application/json"
        or receipt_record.parent_artifacts != expected_receipt_parents
        or final_attempt.get("status") != "RESPONSE"
        or final_attempt.get("raw_response_record_sha256") != raw_hash
        or final_attempt.get("status_code") != authority.get("status_code")
    ):
        raise EgressPolicyError(
            "audited transport execution request or response binding differs"
        )
    prefix_count = authority.get("ledger_prefix_event_count")
    prefix_head = authority.get("ledger_prefix_head_hash")
    if (
        isinstance(prefix_count, bool)
        or not isinstance(prefix_count, int)
        or prefix_count <= 0
        or not isinstance(prefix_head, str)
        or re.fullmatch(r"[0-9a-f]{64}", prefix_head) is None
    ):
        raise EgressPolicyError("audited transport ledger prefix is invalid")
    try:
        ledger_result = ledger.validate(raise_on_error=True)
    except LedgerError as exc:
        raise EgressPolicyError("audited transport run ledger is invalid") from exc
    events = ledger_result.events
    if (
        not ledger_result.valid
        or len(events) <= prefix_count
        or any(event.run_id != run_id for event in events)
        or events[prefix_count - 1].event_hash != prefix_head
    ):
        raise EgressPolicyError("audited transport ledger prefix is absent or stale")
    event = events[prefix_count]
    previous = events[prefix_count - 1]
    expected_event_metadata = _authority_event_metadata(
        authority_artifact=authority_record,
        response_receipt_artifact_sha256=response_receipt_artifact_sha256,
        request_id=str(authority["request_id"]),
        prefix_head_hash=prefix_head,
    )
    bound_ids = {value.event_id for value in events[: prefix_count + 1]}
    if (
        event.event_id
        != f"egress-authority-{authority_artifact_sha256[:24]}"
        or event.timestamp != authority.get("issued_at")
        or event.prior_event_hash != prefix_head
        or event.actor_role is not Role.EVIDENCE_CURATOR
        or event.state_before != previous.requested_state_after
        or event.requested_state_after != previous.requested_state_after
        or event.artifact_hashes != (authority_artifact_sha256,)
        or event.code_version != previous.code_version
        or event.configuration_hash != previous.configuration_hash
        or event.dataset_identifiers != previous.dataset_identifiers
        or event.random_seeds != previous.random_seeds
        or event.evaluator_outputs
        or event.reason != _AUDITED_TRANSPORT_AUTHORITY_EVENT_REASON
        or event.event_type != "CHECKPOINT"
        or dict(event.metadata) != expected_event_metadata
        or any(
            later.event_type == "CORRECTION"
            and later.supersedes_event_id in bound_ids
            for later in events[prefix_count + 1 :]
        )
    ):
        raise EgressPolicyError(
            "audited transport authority lacks exact unsuperseded run anchoring"
        )
    if event.event_hash is None:
        raise EgressPolicyError("audited transport authority event hash is absent")
    return AuditedTransportExecutionAuthority(
        authority_artifact=authority_record,
        response_receipt_artifact=receipt_record,
        request_artifact=request_record,
        raw_response_artifact=raw_record,
        run_id=run_id,
        request_id=str(authority["request_id"]),
        policy_id=str(authority["policy_id"]),
        body_sha256=str(authority["raw_response_sha256"]),
        body_size=int(authority["body_size"]),
        status_code=int(authority["status_code"]),
        content_type=str(authority["content_type"]),
        ledger_prefix_head_hash=prefix_head,
        ledger_prefix_event_count=prefix_count,
        ledger_event_id=event.event_id,
        ledger_event_hash=event.event_hash,
        key_id=str(authority["key_id"]),
    )


def _build_audited_transport_execution_authority() -> tuple[
    Callable[..., ArtifactRecord | None],
    Callable[..., AuditedTransportExecutionAuthority],
]:
    """Hide key access/signing behind one-shot gateway issuance.

    This boundary rejects ordinary callers, replaceable transports, and direct
    registry/ledger fabrication. It does not claim resistance to a same-process
    actor that extracts the full closure state or reads the same-user key file;
    that unsupported local compromise is ``BLOCKED_LOCAL``.
    """

    read_key, load_or_create_key = _build_gateway_authority_key_access()
    prepare_claim = _prepare_audited_transport_execution_claim
    require_with_key = _require_audited_live_transport_execution_with_key
    exact_gateway = _is_exact_egress_gateway
    exact_transport_authority = _classify_transport_authority
    exact_prepared_claim = _prepared_request_claim
    exact_policy_claim = _egress_policy_claim
    exact_request_policy_replay = _replay_signed_request_against_policy
    exact_retry_backoff_replay = _replay_retry_backoff
    implementation_profile = MappingProxyType(
        _audited_transport_implementation_profile()
    )
    exact_token_hex = secrets.token_hex
    exact_hmac_new = hmac.new
    exact_sha256 = hashlib.sha256
    metadata_claim_for = _authority_artifact_metadata_claim
    event_metadata_for = _authority_event_metadata

    def issue(
        gateway: EgressGateway,
        *,
        policy_snapshot: EgressPolicy,
        policy_claim: Mapping[str, object],
        policy_claim_sha256: str,
        egress_budget: Mapping[str, object],
        prepared_request: PreparedEgressRequest,
        prepared_request_binding: str,
        request_artifact: ArtifactRecord | None,
        response_receipt_artifact: ArtifactRecord | None,
        raw_response_artifact: ArtifactRecord | None,
        attempts: Sequence[Mapping[str, object]],
        response: TransportResponse,
        content_type: str,
        captured_at: str,
        pmc_wire_rows: tuple | None = None,
    ) -> ArtifactRecord | None:
        if (
            not exact_gateway(gateway)
            or exact_transport_authority(gateway.transport)
            != AUDITED_LIVE_TRANSPORT_AUTHORITY
            or gateway.registry is None
        ):
            return None
        try:
            if (
                gateway.policy is not policy_snapshot
                or dict(policy_claim) != exact_policy_claim(policy_snapshot)
                or policy_claim_sha256
                != _safe_hash(canonical_json_bytes(dict(policy_claim)))
            ):
                return None
            prepared_claim = exact_prepared_claim(prepared_request)
            claim = prepare_claim(
                gateway,
                policy_snapshot=policy_snapshot,
                policy_claim_sha256=policy_claim_sha256,
                egress_budget=egress_budget,
                prepared_request=prepared_request,
                prepared_request_binding=prepared_request_binding,
                prepared_request_claim=prepared_claim,
                policy_claim=policy_claim,
                implementation_profile=implementation_profile,
                request_policy_replay=exact_request_policy_replay,
                retry_backoff_replay=exact_retry_backoff_replay,
                request_artifact=request_artifact,
                response_receipt_artifact=response_receipt_artifact,
                raw_response_artifact=raw_response_artifact,
                attempts=attempts,
                response=response,
                content_type=content_type,
                captured_at=captured_at,
                pmc_wire_rows=pmc_wire_rows,
            )
            if claim is None:
                return None
            key = load_or_create_key(claim.registry)
            unsigned = {
                **dict(claim.unsigned),
                "nonce": exact_token_hex(16),
                "key_id": _safe_hash(key),
            }
            metadata_claim = metadata_claim_for(
                response_receipt_artifact_sha256=(
                    claim.response_receipt_artifact.sha256
                ),
                created_at=claim.captured_at,
                schema_version=unsigned["schema_version"],
            )
            signed_claim_bytes = canonical_json_bytes(
                {
                    "authority": unsigned,
                    "artifact_metadata": metadata_claim,
                }
            )
            payload = {
                **unsigned,
                "claim_sha256": _safe_hash(signed_claim_bytes),
                "authentication_tag": exact_hmac_new(
                    key,
                    signed_claim_bytes,
                    exact_sha256,
                ).hexdigest(),
            }
            authority_artifact = claim.registry.put_json(
                payload,
                logical_type=(
                    AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE
                ),
                origin=_AUDITED_TRANSPORT_AUTHORITY_ORIGIN,
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=_AUDITED_TRANSPORT_AUTHORITY_COMMAND,
                parent_artifacts=(
                    claim.response_receipt_artifact.sha256,
                ),
                schema_version=unsigned["schema_version"],
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=claim.captured_at,
            )
            event = LedgerEvent.create(
                run_id=claim.run_id,
                event_id=(
                    f"egress-authority-{authority_artifact.sha256[:24]}"
                ),
                timestamp=claim.captured_at,
                actor_role=Role.EVIDENCE_CURATOR,
                state_before=claim.prior_event.requested_state_after,
                requested_state_after=claim.prior_event.requested_state_after,
                artifact_hashes=(authority_artifact.sha256,),
                code_version=claim.prior_event.code_version,
                configuration_hash=claim.prior_event.configuration_hash,
                dataset_identifiers=claim.prior_event.dataset_identifiers,
                random_seeds=claim.prior_event.random_seeds,
                evaluator_outputs=(),
                reason=_AUDITED_TRANSPORT_AUTHORITY_EVENT_REASON,
                prior_event_hash=claim.prefix_head_hash,
                event_type="CHECKPOINT",
                metadata=event_metadata_for(
                    authority_artifact=authority_artifact,
                    response_receipt_artifact_sha256=(
                        claim.response_receipt_artifact.sha256
                    ),
                    request_id=claim.request_id,
                    prefix_head_hash=claim.prefix_head_hash,
                ),
            )
            anchored = claim.ledger.append(event)
            final_ledger = claim.ledger.validate(raise_on_error=True)
            if (
                not final_ledger.valid
                or len(final_ledger.events) <= claim.prefix_event_count
                or final_ledger.events[claim.prefix_event_count] != anchored
            ):
                return None
            return authority_artifact
        except (
            ArtifactError,
            EgressPolicyError,
            LedgerError,
            OSError,
            PathSecurityError,
            TypeError,
            UnsafeSerializationError,
            ValidationError,
            ValueError,
        ):
            return None

    def require(
        registry: ArtifactRegistry,
        ledger: EventLedger,
        *,
        run_id: str,
        authority_artifact_sha256: str,
        response_receipt_artifact_sha256: str,
    ) -> AuditedTransportExecutionAuthority:
        try:
            key = read_key(registry)
        except (EgressPolicyError, OSError, PathSecurityError) as exc:
            raise EgressPolicyError(
                "gateway authority trust root is unavailable"
            ) from exc
        if key is None:
            raise EgressPolicyError("gateway authority trust root is unavailable")
        return require_with_key(
            registry,
            ledger,
            run_id=run_id,
            authority_artifact_sha256=authority_artifact_sha256,
            response_receipt_artifact_sha256=response_receipt_artifact_sha256,
            authority_key=key,
            implementation_profile=implementation_profile,
            request_policy_replay=exact_request_policy_replay,
            retry_backoff_replay=exact_retry_backoff_replay,
        )

    require.__name__ = "require_audited_live_transport_execution"
    require.__qualname__ = "require_audited_live_transport_execution"
    require.__doc__ = (
        "Freshly verify gateway-signed audited HTTPS execution and run anchoring."
    )
    return issue, require


(
    _transport_authority_issuer,
    require_audited_live_transport_execution,
) = _build_audited_transport_execution_authority()
_bind_transport_authority_issuer(_transport_authority_issuer)

del _transport_authority_issuer
del _bind_transport_authority_issuer
del _build_audited_transport_execution_authority
globals().pop("_build_gateway_authority_key_access", None)
for _hidden_gateway_authority_name in (
    "_prepare_audited_transport_execution_claim",
    "_require_audited_live_transport_execution_with_key",
):
    globals().pop(_hidden_gateway_authority_name, None)
del _hidden_gateway_authority_name
del _admit_gateway_execute


__all__ = [
    "AUDITED_LIVE_TRANSPORT_AUTHORITY",
    "AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE",
    "AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA",
    "AuditedTransportExecutionAuthority",
    "EGRESS_ATTEMPT_SCHEMA",
    "EGRESS_BUDGET_SCHEMA",
    "EGRESS_REQUEST_SCHEMA",
    "EGRESS_RESPONSE_RECEIPT_SCHEMA",
    "EgressDeniedError",
    "EgressGateway",
    "EgressPolicy",
    "EgressPolicyError",
    "EgressRequest",
    "EgressTransport",
    "ExternalBoundaryError",
    "ExternalParseError",
    "ExternalUnavailableError",
    "FixtureTransport",
    "GatewayResult",
    "TransportFailure",
    "TransportResponse",
    "UNVERIFIED_TRANSPORT_AUTHORITY",
    "require_audited_live_transport_execution",
]
