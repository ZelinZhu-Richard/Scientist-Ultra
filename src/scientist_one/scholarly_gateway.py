"""Source-owned native scholarly routes over the audited egress gateway.

This module is the closed wire boundary missing from the provider-neutral
normalizers in :mod:`scientist_one.literature`.  It owns fixed endpoint,
request-encoding, and response-projection contracts for two deliberately
bounded routes:

* OpenAlex works search, singleton metadata, references, and cited-by pages;
* PMC OAI-PMH ``GetRecord`` full-text JATS decoding for explicitly reusable
  articles.  Fixture replay is implemented, while live dispatch is blocked
  until the shared transport can enforce PMC's compression and serialization
  rules.

No response-provided URL is ever followed.  External bytes remain advisory,
untrusted, and non-scientific even when the built-in live transport captures
them.  A caller cannot register another route or inject an encoder/parser;
unsupported and credential-required paths return typed unavailable results.

The documentation URLs embedded in route-authority artifacts describe the
wire assumptions current when this schema was written.  A credentialless
encoding is not a claim that a remote endpoint will accept an anonymous call.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime
from enum import Enum
import hashlib
import math
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence
from urllib.parse import quote, urlencode
import unicodedata
import xml.etree.ElementTree as ElementTree

from .artifacts import ArtifactRecord, ArtifactRegistry
from .errors import ArtifactError, UnsafeSerializationError, ValidationError
from .external import (
    AUDITED_LIVE_TRANSPORT_AUTHORITY,
    EGRESS_ATTEMPT_SCHEMA,
    EGRESS_BUDGET_SCHEMA,
    EGRESS_REQUEST_SCHEMA,
    EGRESS_RESPONSE_RECEIPT_SCHEMA,
    EGRESS_PMC_RESPONSE_SCHEMA_V3,
    PMC_CONTENT_ADAPTER_ID,
    PMC_WIRE_ADAPTER_ID,
    PMC_WIRE_DEADLINE_SCOPE,
    PMC_WIRE_RESPONSE_SCHEMA,
    PMC_WIRE_AUTHORITY_SCHEMA,
    _require_pmc_wire_activation,
    require_audited_live_transport_execution,
    require_pmc_content_decoding,
    require_pmc_content_cache,
    EgressDeniedError,
    EgressGateway,
    EgressPolicy,
    EgressPolicyError,
    EgressRequest,
    ExternalBoundaryError,
    ExternalParseError,
    ExternalUnavailableError,
    GatewayResult,
    TransportFailure,
    UNVERIFIED_TRANSPORT_AUTHORITY,
)
from .literature import (
    CitationPageRequest,
    CitationTraversal,
    FullTextStatus,
    GatewayEnvelope,
    IdentifierKind,
    LiteratureError,
    RetrievalStatus,
    ScholarlyIdentifier,
    ScholarlyRequest,
    ScholarlySearchFilter,
    ScholarlySearchRequest,
    ScholarlySearchPageRequest,
    require_scholarly_search_cursor,
    ScholarlySource,
)
from .roles import Role
from .security import canonical_json_bytes, safe_json_loads


SCHOLARLY_EGRESS_ROUTE_AUTHORITY_SCHEMA_V2 = (
    "scholarly-egress-route-authority/v2"
)
SCHOLARLY_NATIVE_REQUEST_PROJECTION_SCHEMA_V2 = (
    "scholarly-native-request-projection/v2"
)
SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V2 = "scholarly-native-response/v2"
SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V3 = "scholarly-native-response/v3"
SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V4 = "scholarly-native-response/v4"
OPENALEX_CURSOR_WIRE_PROTOCOL_V2 = "openalex-cursor-search-json/v2"
_OPENALEX_CURSOR_ADAPTER_ID = "scholarly-openalex-cursor-search-v2"
PMC_OAI_JATS_WIRE_PROTOCOL_V2 = "pmc-oai-jats-xml/v2"
OPENALEX_WIRE_PROTOCOL_V1 = "openalex-rest-json/v1"
PMC_OAI_JATS_WIRE_PROTOCOL_V1 = "pmc-oai-jats-xml/v1"

OPENALEX_API_DOCUMENTATION_URLS = (
    "https://help.openalex.org/api/",
    "https://help.openalex.org/api/authentication/",
    "https://help.openalex.org/api/filtering/",
    "https://help.openalex.org/api/searching/",
    "https://help.openalex.org/api/paging/",
    "https://help.openalex.org/api/get-single-entities/",
    "https://help.openalex.org/how-to/api-recipes/",
    "https://help.openalex.org/access/oql-spec/",
    "https://help.openalex.org/data/work-types/",
)
PMC_OAI_JATS_DOCUMENTATION_URLS = (
    "https://pmc.ncbi.nlm.nih.gov/tools/oai/",
    "https://pmc.ncbi.nlm.nih.gov/about/copyright/",
    "https://jats.nlm.nih.gov/archiving/",
    "https://jats.nlm.nih.gov/archiving/tag-library/1.4/element/ali-license_ref.html",
    "https://creativecommons.org/cc-licenses/",
)

_OPENALEX_BASE_URL = "https://api.openalex.org"
_PMC_OAI_ENDPOINT_URL = "https://pmc.ncbi.nlm.nih.gov/api/oai/v1/mh/"
_OPENALEX_ADAPTER_ID = "scholarly-openalex-native-v1"
_PMC_ADAPTER_ID = "scholarly-pmc-oai-jats-v1"
_OPENALEX_MAX_RESULTS = 100
_OPENALEX_MAX_URL_BYTES = 4094
_MAX_CAPTURE_TEXT = 1_048_576
_MAX_PMC_XML_ELEMENTS = 100_000
_MAX_PMC_XML_DEPTH = 128
_MAX_PMC_PASSAGES = 10_000
_MAX_PMC_TOTAL_TEXT = 8 * 1024 * 1024
_MAX_PMC_CONTEXT_CHARS = 512
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_OPENALEX_ID_RE = re.compile(r"^W[0-9]+$")
_PMC_ID_RE = re.compile(r"^PMC([0-9]+)$")
_DATE_RE = re.compile(r"^([12][0-9]{3})-([01][0-9])-([0-3][0-9])$")
_YEAR_RE = re.compile(r"^[12][0-9]{3}(?:-[12][0-9]{3})?$")
_CURSOR_RE = re.compile(r"^[^\x00-\x20\x7f]{1,4096}$")
_XLINK_HREF = "{http://www.w3.org/1999/xlink}href"
_OAI_NAMESPACE = "http://www.openarchives.org/OAI/2.0/"
_ALI_NAMESPACE = "http://www.niso.org/schemas/ali/1.0/"
_ALI_LICENSE_REF = f"{{{_ALI_NAMESPACE}}}license_ref"
_XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"
_HTTP_URI_RE = re.compile(r"https?://[^\s<>\"']{1,4096}", re.IGNORECASE)
_PMC_XML_DECLARATION_V1 = b'<?xml version="1.0" encoding="UTF-8"?>'
_OAI_RESPONSE_DATE_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_PMC_TEXT_PROJECTION_SCHEMA_V1 = "pmc-jats-normalized-text-projection/v1"
_PMC_TEXT_PROJECTION_SCHEMA_V2 = "pmc-jats-normalized-text-projection/v2"
_PMC_TEXT_EXTRACTION_CODEC_V1 = "pmc-jats-paragraph-nfkc-collapse-whitespace/v1"


class _PmcProjectionProfile(Enum):
    RAW_XML_V1 = _PMC_TEXT_PROJECTION_SCHEMA_V1
    DECODED_XML_V2 = _PMC_TEXT_PROJECTION_SCHEMA_V2


def _pmc_projection_sources(
    profile: _PmcProjectionProfile,
    *,
    wire_raw_artifact_sha256: str,
    decoded_xml_sha256: str | None,
    decoding_descriptor_artifact_sha256: str | None,
) -> dict[str, object]:
    """Select closed projection vocabulary, without authenticating provenance."""
    if type(profile) is not _PmcProjectionProfile:
        raise ScholarlyGatewayError("PMC projection profile is unsupported")
    if profile is _PmcProjectionProfile.RAW_XML_V1:
        if decoded_xml_sha256 is not None or decoding_descriptor_artifact_sha256 is not None:
            raise ScholarlyGatewayError("PMC projection identities mix profiles")
        return {"source_raw_artifact_sha256": wire_raw_artifact_sha256}
    if any(
        type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in (
            wire_raw_artifact_sha256,
            decoded_xml_sha256,
            decoding_descriptor_artifact_sha256,
        )
    ):
        raise ScholarlyGatewayError("PMC decoded projection identities are malformed")
    return {
        "source_wire_raw_artifact_sha256": wire_raw_artifact_sha256,
        "source_decoded_xml_sha256": decoded_xml_sha256,
        "source_decoding_descriptor_artifact_sha256": decoding_descriptor_artifact_sha256,
    }
_EGRESS_BYTE_ACCOUNTING = "REQUEST_BODY_PER_ATTEMPT_PLUS_EACH_RECEIVED_RESPONSE_BODY"
_EGRESS_DEADLINE_SCOPE = "MONOTONIC_EXECUTE_ENTRY_THROUGH_FINAL_RESPONSE_CAPTURE"
_EXPECTED_RECORDED_RESPONSE_HEADERS = (
    "content-type",
    "content-length",
    "retry-after",
    "request-id",
    "x-request-id",
    "openai-request-id",
)
_EXPECTED_RETRY_STATUSES = (429, 500, 502, 503, 504)
_OPENALEX_WORK_TYPES = frozenset(
    {
        "article",
        "book",
        "book-chapter",
        "book-review",
        "conference-abstract",
        "conference-paper",
        "data-paper",
        "dataset",
        "dissertation",
        "editorial",
        "erratum",
        "letter",
        "libguides",
        "other",
        "paratext",
        "peer-review",
        "preprint",
        "reference-entry",
        "report",
        "retraction",
        "review",
        "software",
        "software-paper",
        "standard",
        "supplementary-materials",
    }
)


def _build_reusable_pmc_license_policy() -> Mapping[str, tuple[str, tuple[str, ...]]]:
    values: dict[str, tuple[str, tuple[str, ...]]] = {
        "https://creativecommons.org/publicdomain/zero/1.0/": (
            "CC0-1.0",
            ("retain-source-and-license-provenance",),
        )
    }
    for version in ("1.0", "2.0", "2.5", "3.0", "4.0"):
        values[f"https://creativecommons.org/licenses/by/{version}/"] = (
            f"CC-BY-{version}",
            (
                "give-appropriate-credit",
                "provide-license-link",
                "indicate-changes",
                "retain-source-and-license-provenance",
            ),
        )
        values[f"https://creativecommons.org/licenses/by-sa/{version}/"] = (
            f"CC-BY-SA-{version}",
            (
                "give-appropriate-credit",
                "provide-license-link",
                "indicate-changes",
                "share-adaptations-under-same-or-compatible-terms",
                "retain-source-and-license-provenance",
            ),
        )
    return MappingProxyType(values)


_REUSABLE_PMC_LICENSES = _build_reusable_pmc_license_policy()
del _build_reusable_pmc_license_policy


def _egress_budget_policy_claim(policy: EgressPolicy) -> dict[str, object]:
    return {
        "schema_version": EGRESS_BUDGET_SCHEMA,
        "maximum_total_bytes": policy.maximum_total_bytes,
        "byte_accounting": _EGRESS_BYTE_ACCOUNTING,
        "deadline_budget_seconds": policy.timeout_seconds,
        "deadline_scope": PMC_WIRE_DEADLINE_SCOPE if policy.adapter_id == PMC_WIRE_ADAPTER_ID else _EGRESS_DEADLINE_SCOPE,
    }


def _egress_policy_claim(policy: EgressPolicy) -> dict[str, object]:
    """Mirror the gateway's complete credential-free frozen policy claim."""

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


class ScholarlyGatewayError(RuntimeError):
    """Base error for misuse of the closed scholarly wire boundary."""


class ScholarlyRouteConfigurationError(ScholarlyGatewayError, ValueError):
    """A supplied audited gateway does not match a source-owned route."""


class ScholarlyGatewayFailureCode(str, Enum):
    """Machine-readable reason that a route did not produce usable data."""

    SOURCE_UNSUPPORTED = "SOURCE_UNSUPPORTED"
    ROUTE_UNCONFIGURED = "ROUTE_UNCONFIGURED"
    ROUTE_DISABLED = "ROUTE_DISABLED"
    OPERATION_UNSUPPORTED = "OPERATION_UNSUPPORTED"
    IDENTIFIER_KIND_UNSUPPORTED = "IDENTIFIER_KIND_UNSUPPORTED"
    FILTER_UNSUPPORTED = "FILTER_UNSUPPORTED"
    RESULT_LIMIT_UNSUPPORTED = "RESULT_LIMIT_UNSUPPORTED"
    REQUEST_INCONSISTENT = "REQUEST_INCONSISTENT"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    NOT_FOUND = "NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    HTTP_UNAVAILABLE = "HTTP_UNAVAILABLE"
    TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"
    TRANSPORT_POLICY_INCOMPATIBLE = "TRANSPORT_POLICY_INCOMPATIBLE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    LICENSE_RESTRICTED = "LICENSE_RESTRICTED"
    CAPTURE_UNAVAILABLE = "CAPTURE_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class ScholarlyRouteDescriptor:
    """Read-only metadata for one source-owned native wire contract.

    Descriptors are informational.  No public API accepts one as routing
    authority; the gateway resolves requests against its private closed map.
    """

    source: ScholarlySource
    operations: tuple[str, ...]
    adapter_id: str
    endpoint_url: str
    allowed_hosts: tuple[str, ...]
    allowed_path_prefixes: tuple[str, ...]
    allowed_query_keys: tuple[str, ...]
    request_encoding: str
    response_encoding: str
    wire_protocol: str
    documentation_urls: tuple[str, ...]
    allowed_request_content_types: tuple[str, ...]
    allowed_response_content_types: tuple[str, ...]
    license_policy_id: str
    live_network_dispatch_status: str
    retrieval_depth: str
    transport_content_encoding_policy: str
    concurrency_policy: str
    operational_caveats: tuple[str, ...]

    def authority_payload(
        self,
        *,
        policy: EgressPolicy,
        network_expected: bool,
    ) -> dict[str, object]:
        policy_claim = _egress_policy_claim(policy)
        resource_policy = {
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
            "minimum_interval_seconds": policy.minimum_interval_seconds,
            "maximum_requests": policy.maximum_requests,
            "maximum_attempts": policy.maximum_attempts,
            "retry_statuses": list(policy.retry_statuses),
            "backoff_initial_seconds": policy.backoff_initial_seconds,
            "backoff_maximum_seconds": policy.backoff_maximum_seconds,
            "maximum_json_depth": policy.maximum_json_depth,
            "maximum_json_items": policy.maximum_json_items,
        }
        return {
            "schema_version": SCHOLARLY_EGRESS_ROUTE_AUTHORITY_SCHEMA_V2,
            "adapter_id": self.adapter_id,
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_methods": ["GET"],
            "allowed_path_prefixes": list(self.allowed_path_prefixes),
            "allowed_query_keys": list(self.allowed_query_keys),
            "allowed_scholarly_sources": [self.source.value],
            "base_endpoint_url": self.endpoint_url,
            "credential_mode": "NONE",
            "documentation_urls": list(self.documentation_urls),
            "documentation_verified_on": ("2026-09-19" if self.adapter_id == PMC_WIRE_ADAPTER_ID else "2026-09-13" if self.adapter_id == _OPENALEX_CURSOR_ADAPTER_ID else "2026-09-04"),
            "enabled": policy.enabled,
            "egress_policy": policy_claim,
            "egress_policy_sha256": hashlib.sha256(
                canonical_json_bytes(policy_claim)
            ).hexdigest(),
            "endpoint_url": self.endpoint_url,
            "network_expected": network_expected,
            "operations": list(self.operations),
            "operational_caveats": list(self.operational_caveats),
            "policy_id": policy.policy_id,
            "license_policy_id": self.license_policy_id,
            "live_network_dispatch_status": self.live_network_dispatch_status,
            "request_encoding": self.request_encoding,
            "retrieval_depth": self.retrieval_depth,
            "resource_policy": resource_policy,
            "resource_policy_sha256": hashlib.sha256(
                canonical_json_bytes(resource_policy)
            ).hexdigest(),
            "response_encoding": self.response_encoding,
            "scientific_evidence": False,
            "source": self.source.value,
            "transport_content_encoding_policy": (
                self.transport_content_encoding_policy
            ),
            "concurrency_policy": self.concurrency_policy,
            "wire_protocol": self.wire_protocol,
        }


@dataclass(frozen=True, slots=True)
class ScholarlyNativeRequestProjection:
    """Provider-neutral binding to one exact native GET request."""

    source: ScholarlySource
    operation: str
    scholarly_request_id: str
    route_authority_artifact_sha256: str
    wire_protocol: str
    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body_sha256: str
    body_size: int
    egress_request_id: str
    schema_version: str = SCHOLARLY_NATIVE_REQUEST_PROJECTION_SCHEMA_V2

    def __post_init__(self) -> None:
        if self.schema_version != SCHOLARLY_NATIVE_REQUEST_PROJECTION_SCHEMA_V2:
            raise ScholarlyGatewayError("unsupported native request projection schema")
        if not isinstance(self.source, ScholarlySource):
            raise ScholarlyGatewayError("native request projection source is invalid")
        for value, label in (
            (self.scholarly_request_id, "scholarly request"),
            (self.route_authority_artifact_sha256, "route authority"),
            (self.body_sha256, "request body"),
            (self.egress_request_id, "egress request"),
        ):
            if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
                raise ScholarlyGatewayError(f"{label} binding is invalid")
        if self.method != "GET" or self.body_size != 0:
            raise ScholarlyGatewayError("native route projection must bind a bodyless GET")
        if self.body_sha256 != hashlib.sha256(b"").hexdigest():
            raise ScholarlyGatewayError("native route projection body hash is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "source": self.source.value,
            "operation": self.operation,
            "scholarly_request_id": self.scholarly_request_id,
            "route_authority_artifact_sha256": (
                self.route_authority_artifact_sha256
            ),
            "wire_protocol": self.wire_protocol,
            "method": self.method,
            "url": self.url,
            "headers": [list(value) for value in self.headers],
            "body_sha256": self.body_sha256,
            "body_size": self.body_size,
            "egress_request_id": self.egress_request_id,
        }


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _pmc_diagnostic_dto(descriptor):
    if descriptor is None or descriptor.adapter_id != PMC_WIRE_ADAPTER_ID:
        return {}
    return {"capture_authority": "UNVERIFIED_TERMINAL_DIAGNOSTIC",
            "transport_execution_authority_artifact_sha256": None}


def _pmc_diagnostic_fields(descriptor):
    fields = _pmc_diagnostic_dto(descriptor)
    return {**fields, "decoding_artifact_sha256": None} if fields else fields


@dataclass(frozen=True, slots=True)
class CapturedScholarlyResponse:
    """Typed native-route result satisfying ``CapturedGatewayResponse``.

    ``response_artifact_hash`` identifies this normalized non-scientific view;
    the exact external receipt and raw bytes remain separately bound in
    ``custody_artifact_hashes`` and in the normalized artifact payload.
    """

    source: ScholarlySource
    request_id: str
    status: RetrievalStatus
    payload: Mapping[str, Any] | None
    raw_artifact_hash: str | None
    response_artifact_hash: str | None
    failure_reason: str | None
    license: str | None
    full_text_status: FullTextStatus | None
    failure_code: ScholarlyGatewayFailureCode | None
    wire_protocol: str | None
    route_authority_artifact_hash: str | None
    egress_request_id: str | None
    network_used: bool
    external_validation: str
    transport_authority: str
    custody_artifact_hashes: tuple[str, ...] = ()
    scientific_evidence: bool = False
    schema_version: str = SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V2
    capture_authority: str | None = None
    transport_execution_authority_artifact_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version not in {SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V2, SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V3, SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V4, SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V5}:
            raise ScholarlyGatewayError("unsupported native response schema")
        if self.schema_version == SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V5:
            if self.source is not ScholarlySource.PMC or self.wire_protocol != PMC_OAI_JATS_WIRE_PROTOCOL_V3:
                raise ScholarlyGatewayError("PMC v5 capture profile is mismatched")
            if self.capture_authority == "SIGNED_HTTP_CAPTURE":
                if (type(self.transport_execution_authority_artifact_sha256) is not str
                        or _SHA256_RE.fullmatch(self.transport_execution_authority_artifact_sha256) is None
                        or self.network_used is not True or self.transport_authority != AUDITED_LIVE_TRANSPORT_AUTHORITY
                        or self.external_validation != "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"):
                    raise ScholarlyGatewayError("PMC signed capture binding is absent")
            elif self.capture_authority == "UNVERIFIED_TERMINAL_DIAGNOSTIC":
                if self.payload is not None or self.status is RetrievalStatus.AVAILABLE or self.transport_execution_authority_artifact_sha256 is not None:
                    raise ScholarlyGatewayError("PMC diagnostic cannot claim accepted content")
            else:
                raise ScholarlyGatewayError("PMC capture authority tag is invalid")
        elif self.capture_authority is not None or self.transport_execution_authority_artifact_sha256 is not None:
            raise ScholarlyGatewayError("legacy native capture cannot carry PMC v5 authority")
        if self.schema_version == SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V4 and (
            self.source is not ScholarlySource.OPENALEX
            or self.wire_protocol != OPENALEX_CURSOR_WIRE_PROTOCOL_V2
        ):
            raise ScholarlyGatewayError("OpenAlex cursor capture profile is mismatched")
        if self.schema_version == SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V3 and (
            self.source is not ScholarlySource.PMC
            or self.wire_protocol != PMC_OAI_JATS_WIRE_PROTOCOL_V2
            or self.network_used is not False
            or self.transport_authority != UNVERIFIED_TRANSPORT_AUTHORITY
            or self.external_validation != "UNTESTED"
        ):
            raise ScholarlyGatewayError("unsigned PMC v3 capture profile is mismatched")
        if not isinstance(self.source, ScholarlySource):
            raise ScholarlyGatewayError("native response source is invalid")
        if not isinstance(self.status, RetrievalStatus):
            raise ScholarlyGatewayError("native response status is invalid")
        if not isinstance(self.network_used, bool) or self.scientific_evidence is not False:
            raise ScholarlyGatewayError("scholarly capture cannot claim scientific authority")
        if not isinstance(self.external_validation, str) or not self.external_validation:
            raise ScholarlyGatewayError("native response validation status is invalid")
        if not isinstance(self.transport_authority, str) or not self.transport_authority:
            raise ScholarlyGatewayError("native response transport authority is invalid")
        for value, label, optional in (
            (self.request_id, "scholarly request", False),
            (self.raw_artifact_hash, "raw response", True),
            (self.response_artifact_hash, "normalized response", True),
            (self.route_authority_artifact_hash, "route authority", True),
            (self.egress_request_id, "egress request", True),
        ):
            if value is None and optional:
                continue
            if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
                raise ScholarlyGatewayError(f"{label} binding is invalid")
        custody = tuple(sorted(set(self.custody_artifact_hashes)))
        if len(custody) != len(self.custody_artifact_hashes) or any(
            _SHA256_RE.fullmatch(value) is None for value in custody
        ):
            raise ScholarlyGatewayError("scholarly custody bindings are invalid")
        object.__setattr__(self, "custody_artifact_hashes", custody)
        if self.status is RetrievalStatus.AVAILABLE:
            if (
                not isinstance(self.payload, Mapping)
                or self.raw_artifact_hash is None
                or self.response_artifact_hash is None
                or self.failure_code is not None
                or self.failure_reason is not None
                or self.wire_protocol is None
                or self.route_authority_artifact_hash is None
                or self.egress_request_id is None
            ):
                raise ScholarlyGatewayError("available scholarly response lacks exact custody")
        else:
            if self.payload is not None:
                raise ScholarlyGatewayError("unavailable scholarly response cannot expose payload")
            if self.failure_code is None or not self.failure_reason:
                raise ScholarlyGatewayError("unavailable scholarly response needs a typed reason")
        if self.full_text_status is FullTextStatus.AVAILABLE:
            if self.source is not ScholarlySource.PMC or not self.license:
                raise ScholarlyGatewayError("available full text needs a reusable PMC license")
        if (
            self.status is RetrievalStatus.LICENSE_RESTRICTED
            and self.full_text_status is not FullTextStatus.LICENSE_RESTRICTED
        ):
            raise ScholarlyGatewayError(
                "license-restricted response needs a matching full-text status"
            )
        if self.payload is not None:
            object.__setattr__(self, "payload", _freeze_json(self.payload))

    @property
    def payload_dict(self) -> dict[str, Any] | None:
        return None if self.payload is None else _thaw_json(self.payload)


@dataclass(frozen=True, slots=True)
class ReplayedScholarlyNativeCapture:
    """Exact v2 native capture projection returned only by source-owned replay.

    This value proves deterministic artifact/request/response replay.  It does
    not grant scientific authority; callers must independently require the
    audited-live transport/ledger authority appropriate to their run.
    """

    envelope: GatewayEnvelope
    artifact_hashes: tuple[str, ...]
    raw_artifact_hash: str
    response_artifact_hash: str
    response_receipt_artifact_hash: str
    request_artifact_hash: str
    route_artifact_hash: str
    request_body_sha256: str
    request_body_size: int
    response_body_sha256: str
    response_body_size: int
    network_used: bool
    external_validation: str
    transport_authority: str

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, GatewayEnvelope):
            raise ScholarlyGatewayError("replayed scholarly envelope is invalid")
        for value in (
            self.raw_artifact_hash,
            self.response_artifact_hash,
            self.response_receipt_artifact_hash,
            self.request_artifact_hash,
            self.route_artifact_hash,
            self.request_body_sha256,
            self.response_body_sha256,
            *self.artifact_hashes,
        ):
            if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
                raise ScholarlyGatewayError("replayed scholarly hash is invalid")
        if tuple(sorted(set(self.artifact_hashes))) != self.artifact_hashes:
            raise ScholarlyGatewayError("replayed scholarly custody is not canonical")
        if not isinstance(self.network_used, bool):
            raise ScholarlyGatewayError("replayed scholarly network label is invalid")


@dataclass(frozen=True, slots=True)
class _RouteBinding:
    descriptor: ScholarlyRouteDescriptor
    gateway: EgressGateway
    authority_artifact: ArtifactRecord


@dataclass(frozen=True, slots=True)
class _WireRequest:
    request: EgressRequest
    projection: ScholarlyNativeRequestProjection


@dataclass(frozen=True, slots=True)
class _ParsedNativeResponse:
    payload: Mapping[str, Any] | None
    status: RetrievalStatus
    failure_code: ScholarlyGatewayFailureCode | None
    failure_reason: str | None
    license: str | None
    full_text_status: FullTextStatus


def _build_closed_route_registry() -> tuple[
    tuple[ScholarlyRouteDescriptor, ...],
    Mapping[ScholarlySource, ScholarlyRouteDescriptor],
]:
    openalex = ScholarlyRouteDescriptor(
        source=ScholarlySource.OPENALEX,
        operations=(
            "expand_citations",
            "expand_references",
            "resolve_work",
            "search_works",
        ),
        adapter_id=_OPENALEX_ADAPTER_ID,
        endpoint_url=_OPENALEX_BASE_URL,
        allowed_hosts=("api.openalex.org",),
        allowed_path_prefixes=("/works", "/works/"),
        allowed_query_keys=("cursor", "filter", "page", "per_page", "search"),
        request_encoding="native-query-get/v1",
        response_encoding="openalex-list-or-work-json/v1",
        wire_protocol=OPENALEX_WIRE_PROTOCOL_V1,
        documentation_urls=OPENALEX_API_DOCUMENTATION_URLS,
        allowed_request_content_types=("application/json",),
        allowed_response_content_types=("application/json",),
        license_policy_id="openalex-cc0-metadata-only/v1",
        live_network_dispatch_status="UNTESTED_EXTERNAL",
        retrieval_depth="SINGLE_HTTP_EXCHANGE",
        transport_content_encoding_policy="IDENTITY_ONLY",
        concurrency_policy="SERIALIZED_PER_GATEWAY",
        operational_caveats=(
            "anonymous endpoint acceptance and available budget require live validation",
            "provider text is untrusted advisory data",
            "no response-provided content URL may be followed",
        ),
    )
    pmc = ScholarlyRouteDescriptor(
        source=ScholarlySource.PMC,
        operations=("resolve_work",),
        adapter_id=_PMC_ADAPTER_ID,
        endpoint_url=_PMC_OAI_ENDPOINT_URL,
        allowed_hosts=("pmc.ncbi.nlm.nih.gov",),
        allowed_path_prefixes=("/api/oai/v1/mh/",),
        allowed_query_keys=("identifier", "metadataPrefix", "verb"),
        request_encoding="oai-pmh-getrecord-query/v1",
        response_encoding="oai-pmh-2.0-jats-xml/v1",
        wire_protocol=PMC_OAI_JATS_WIRE_PROTOCOL_V1,
        documentation_urls=PMC_OAI_JATS_DOCUMENTATION_URLS,
        allowed_request_content_types=("application/xml",),
        allowed_response_content_types=("application/xml", "text/xml"),
        license_policy_id="pmc-explicit-reusable-cc-license/v1",
        live_network_dispatch_status="UNAVAILABLE_TRANSPORT_POLICY_INCOMPATIBLE",
        retrieval_depth="SINGLE_HTTP_EXCHANGE",
        transport_content_encoding_policy="IDENTITY_ONLY_FIXTURE_REPLAY_ONLY",
        concurrency_policy="LIVE_DISPATCH_DISABLED_NO_GLOBAL_SERIALIZATION",
        operational_caveats=(
            "credentialless endpoint acceptance requires live validation",
            "PMC says Accept-Encoding gzip, deflate must be set for efficient transfer; current audited egress accepts identity encoding only",
            "PMC prohibits concurrent requests; current route has no source-global in-flight serialization",
            "live PMC dispatch is unavailable until both transport-policy requirements are enforced",
            "unknown, conflicting, NC, and ND licenses are license-restricted",
            "no response-provided content URL may be followed",
        ),
    )
    ordered = (openalex, pmc)
    return ordered, MappingProxyType({value.source: value for value in ordered})


(_CLOSED_ROUTES, _CLOSED_ROUTES_BY_SOURCE) = _build_closed_route_registry()
del _build_closed_route_registry


_OPENALEX_CURSOR_ROUTE = replace(
    _CLOSED_ROUTES_BY_SOURCE[ScholarlySource.OPENALEX],
    operations=("search_works",),
    adapter_id=_OPENALEX_CURSOR_ADAPTER_ID,
    allowed_query_keys=("corpus", "cursor", "filter", "per_page", "search", "sort"),
    request_encoding="native-cursor-query-get/v2",
    response_encoding="openalex-cursor-search-json/v2",
    wire_protocol=OPENALEX_CURSOR_WIRE_PROTOCOL_V2,
    documentation_urls=(*OPENALEX_API_DOCUMENTATION_URLS,
                        "https://help.openalex.org/api/sorting/",
                        "https://help.openalex.org/data/works/corpus/"),
    operational_caveats=(
        "explicit relevance_score:desc sort and core corpus; no snapshot guarantee",
        "captured cursor progression is not source exhaustion or scientific authority",
        "default OpenAlex basic-page and citation routes remain separate",
    ),
)


SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V5 = "scholarly-native-response/v5"
PMC_OAI_JATS_WIRE_PROTOCOL_V3 = "pmc-oai-jats-xml/v3"


_PMC_CONTENT_ROUTE = replace(
    _CLOSED_ROUTES_BY_SOURCE[ScholarlySource.PMC],
    adapter_id=PMC_CONTENT_ADAPTER_ID,
    wire_protocol=PMC_OAI_JATS_WIRE_PROTOCOL_V2,
    response_encoding="oai-pmh-2.0-jats-bounded-content/v1",
    transport_content_encoding_policy="BOUNDED_IDENTITY_GZIP_ZLIB_DEFLATE",
    operational_caveats=(
        "unsigned bounded content custody only; live dispatch and signing remain closed",
        "source-global coordination and final signed native integration are unavailable",
        "unknown, conflicting, NC, and ND licenses are license-restricted",
        "no response-provided content URL may be followed",
    ),
)

_PMC_WIRE_ROUTE = replace(
    _PMC_CONTENT_ROUTE, adapter_id=PMC_WIRE_ADAPTER_ID,
    wire_protocol=PMC_OAI_JATS_WIRE_PROTOCOL_V3,
    operational_caveats=(
        "versioned wire custody is private; production activation remains closed",
        "transport proof is not scholarly availability or scientific authority",
        "conservative source-global off-peak-only coordination; historical rules remain private",
        "deadline covers transport, decoding and rules admission, not later immutable publication",
    ),
)


def _descriptor_for_policy(source, policy):
    if source is ScholarlySource.PMC and policy.adapter_id == PMC_WIRE_ADAPTER_ID:
        return _PMC_WIRE_ROUTE
    if source is ScholarlySource.OPENALEX and policy.adapter_id == _OPENALEX_CURSOR_ADAPTER_ID:
        return _OPENALEX_CURSOR_ROUTE
    if source is ScholarlySource.PMC and policy.adapter_id == PMC_CONTENT_ADAPTER_ID:
        return _PMC_CONTENT_ROUTE
    return _CLOSED_ROUTES_BY_SOURCE[source]


def _native_schema(descriptor):
    if descriptor.adapter_id == PMC_WIRE_ADAPTER_ID:
        return SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V5
    if descriptor.adapter_id == _OPENALEX_CURSOR_ADAPTER_ID:
        return SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V4
    return (SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V3 if descriptor.adapter_id == PMC_CONTENT_ADAPTER_ID
            else SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V2)


def pmc_content_scholarly_egress_policy(**kwargs) -> EgressPolicy:
    """Explicit unsigned v3 policy; historical PMC policy defaults are unchanged."""
    kwargs.setdefault("policy_id", "scholarly-pmc-oai-keyless-v2")
    return replace(pmc_scholarly_egress_policy(**kwargs),
                   adapter_id=PMC_CONTENT_ADAPTER_ID,
                   recorded_response_headers=(*_EXPECTED_RECORDED_RESPONSE_HEADERS, "content-encoding"))


def pmc_wire_scholarly_egress_policy(**kwargs) -> EgressPolicy:
    """Explicit closed-route PMC wire/custody version; never activation authority."""
    kwargs.setdefault("policy_id", "scholarly-pmc-oai-keyless-v3")
    return replace(pmc_content_scholarly_egress_policy(**kwargs), adapter_id=PMC_WIRE_ADAPTER_ID)


def supported_scholarly_routes() -> tuple[ScholarlyRouteDescriptor, ...]:
    """Return the fixed informational route descriptors in stable order."""

    return _CLOSED_ROUTES


def openalex_cursor_scholarly_egress_policy(**kwargs) -> EgressPolicy:
    """Explicit cursor-search profile; the historical default is unchanged."""
    kwargs.setdefault("policy_id", "scholarly-openalex-cursor-keyless-v2")
    return replace(
        openalex_scholarly_egress_policy(**kwargs),
        adapter_id=_OPENALEX_CURSOR_ADAPTER_ID,
        allowed_query_keys=_OPENALEX_CURSOR_ROUTE.allowed_query_keys,
    )


def openalex_scholarly_egress_policy(
    *,
    policy_id: str = "scholarly-openalex-keyless-v1",
    enabled: bool = True,
    maximum_request_bytes: int = 0,
    maximum_response_bytes: int = 8 * 1024 * 1024,
    maximum_total_bytes: int = 24 * 1024 * 1024,
    timeout_seconds: float = 30.0,
    minimum_interval_seconds: float = 0.1,
    maximum_requests: int = 100,
    maximum_attempts: int = 3,
) -> EgressPolicy:
    """Build the only accepted credentialless OpenAlex route policy."""

    descriptor = _CLOSED_ROUTES_BY_SOURCE[ScholarlySource.OPENALEX]
    return EgressPolicy(
        policy_id=policy_id,
        adapter_id=descriptor.adapter_id,
        allowed_hosts=descriptor.allowed_hosts,
        allowed_path_prefixes=descriptor.allowed_path_prefixes,
        allowed_methods=("GET",),
        allowed_query_keys=descriptor.allowed_query_keys,
        allowed_request_headers=("accept", "user-agent"),
        allowed_request_content_types=descriptor.allowed_request_content_types,
        allowed_response_content_types=descriptor.allowed_response_content_types,
        maximum_request_bytes=maximum_request_bytes,
        maximum_response_bytes=maximum_response_bytes,
        maximum_total_bytes=maximum_total_bytes,
        timeout_seconds=timeout_seconds,
        minimum_interval_seconds=minimum_interval_seconds,
        maximum_requests=maximum_requests,
        maximum_attempts=maximum_attempts,
        retry_statuses=(429, 500, 502, 503, 504),
        credential_env_name=None,
        credential_required=False,
        enabled=enabled,
    )


def pmc_scholarly_egress_policy(
    *,
    policy_id: str = "scholarly-pmc-oai-keyless-v1",
    enabled: bool = True,
    maximum_request_bytes: int = 0,
    maximum_response_bytes: int = 16 * 1024 * 1024,
    maximum_total_bytes: int = 32 * 1024 * 1024,
    timeout_seconds: float = 45.0,
    minimum_interval_seconds: float = 1.0 / 3.0,
    maximum_requests: int = 100,
    maximum_attempts: int = 3,
) -> EgressPolicy:
    """Build the PMC replay policy; current live dispatch remains unavailable."""

    descriptor = _CLOSED_ROUTES_BY_SOURCE[ScholarlySource.PMC]
    return EgressPolicy(
        policy_id=policy_id,
        adapter_id=descriptor.adapter_id,
        allowed_hosts=descriptor.allowed_hosts,
        allowed_path_prefixes=descriptor.allowed_path_prefixes,
        allowed_methods=("GET",),
        allowed_query_keys=descriptor.allowed_query_keys,
        allowed_request_headers=("accept", "user-agent"),
        allowed_request_content_types=descriptor.allowed_request_content_types,
        allowed_response_content_types=descriptor.allowed_response_content_types,
        maximum_request_bytes=maximum_request_bytes,
        maximum_response_bytes=maximum_response_bytes,
        maximum_total_bytes=maximum_total_bytes,
        timeout_seconds=timeout_seconds,
        minimum_interval_seconds=minimum_interval_seconds,
        maximum_requests=maximum_requests,
        maximum_attempts=maximum_attempts,
        retry_statuses=(429, 500, 502, 503, 504),
        credential_env_name=None,
        credential_required=False,
        enabled=enabled,
    )


def _validate_route_policy(
    descriptor: ScholarlyRouteDescriptor,
    policy: EgressPolicy,
    *,
    network_expected: bool,
) -> None:
    exact_pairs = (
        (policy.adapter_id, descriptor.adapter_id),
        (policy.allowed_hosts, descriptor.allowed_hosts),
        (policy.allowed_path_prefixes, descriptor.allowed_path_prefixes),
        (policy.allowed_methods, ("GET",)),
        (policy.allowed_query_keys, descriptor.allowed_query_keys),
        (policy.allowed_request_headers, ("accept", "user-agent")),
        (policy.allowed_request_content_types, descriptor.allowed_request_content_types),
        (policy.allowed_response_content_types, descriptor.allowed_response_content_types),
        (policy.recorded_response_headers, (*_EXPECTED_RECORDED_RESPONSE_HEADERS, "content-encoding")
         if descriptor.adapter_id in {PMC_CONTENT_ADAPTER_ID, PMC_WIRE_ADAPTER_ID} else _EXPECTED_RECORDED_RESPONSE_HEADERS),
        (policy.maximum_request_bytes, 0),
        (policy.retry_statuses, _EXPECTED_RETRY_STATUSES),
        (policy.backoff_initial_seconds, 0.25),
        (policy.backoff_maximum_seconds, 8.0),
        (policy.maximum_json_depth, 64),
        (policy.maximum_json_items, 250_000),
        (policy.credential_env_name, None),
        (policy.credential_required, False),
        (policy.credential_header, "Authorization"),
        (policy.credential_prefix, "Bearer "),
    )
    if any(actual != expected for actual, expected in exact_pairs):
        raise ScholarlyRouteConfigurationError(
            "egress policy does not match the source-owned scholarly route"
        )
    if descriptor.source is ScholarlySource.OPENALEX and policy.maximum_requests > 100:
        raise ScholarlyRouteConfigurationError(
            "OpenAlex anonymous route exceeds its bounded request budget"
        )
    if (
        descriptor.source is ScholarlySource.OPENALEX
        and network_expected is True
        and policy.minimum_interval_seconds + 1e-12 < 0.01
    ):
        raise ScholarlyRouteConfigurationError(
            "OpenAlex live route exceeds its documented request-rate ceiling"
        )
    if descriptor.source is ScholarlySource.PMC and (
        policy.maximum_requests > 100
        or policy.minimum_interval_seconds + 1e-12 < 1.0 / 3.0
    ):
        raise ScholarlyRouteConfigurationError(
            "PMC route violates its documented request-rate ceiling"
        )


def _validate_route_gateway(
    descriptor: ScholarlyRouteDescriptor,
    gateway: EgressGateway,
) -> None:
    if type(gateway) is not EgressGateway:
        raise ScholarlyRouteConfigurationError(
            "scholarly route requires the exact audited egress gateway"
        )
    if not isinstance(gateway.registry, ArtifactRegistry):
        raise ScholarlyRouteConfigurationError(
            "scholarly route requires immutable artifact custody"
        )
    _validate_route_policy(
        descriptor,
        gateway.policy,
        network_expected=gateway.network_used,
    )


def _policy_from_claim(value: object) -> EgressPolicy:
    fields = {
        "policy_id",
        "adapter_id",
        "allowed_hosts",
        "allowed_path_prefixes",
        "allowed_methods",
        "allowed_query_keys",
        "allowed_request_headers",
        "allowed_request_content_types",
        "allowed_response_content_types",
        "recorded_response_headers",
        "maximum_request_bytes",
        "maximum_response_bytes",
        "maximum_total_bytes",
        "timeout_seconds",
        "budget_semantics",
        "minimum_interval_seconds",
        "maximum_requests",
        "maximum_attempts",
        "retry_statuses",
        "backoff_initial_seconds",
        "backoff_maximum_seconds",
        "maximum_json_depth",
        "maximum_json_items",
        "credential_env_name",
        "credential_required",
        "credential_header",
        "credential_prefix",
        "enabled",
    }
    sequence_fields = (
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
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or any(not isinstance(value.get(name), list) for name in sequence_fields)
    ):
        raise ScholarlyGatewayError("scholarly egress policy claim is malformed")
    try:
        policy = EgressPolicy(
            policy_id=value.get("policy_id"),
            adapter_id=value.get("adapter_id"),
            allowed_hosts=tuple(value["allowed_hosts"]),
            allowed_path_prefixes=tuple(value["allowed_path_prefixes"]),
            allowed_methods=tuple(value["allowed_methods"]),
            allowed_query_keys=tuple(value["allowed_query_keys"]),
            allowed_request_headers=tuple(value["allowed_request_headers"]),
            allowed_request_content_types=tuple(
                value["allowed_request_content_types"]
            ),
            allowed_response_content_types=tuple(
                value["allowed_response_content_types"]
            ),
            recorded_response_headers=tuple(value["recorded_response_headers"]),
            maximum_request_bytes=value.get("maximum_request_bytes"),
            maximum_response_bytes=value.get("maximum_response_bytes"),
            maximum_total_bytes=value.get("maximum_total_bytes"),
            timeout_seconds=value.get("timeout_seconds"),
            minimum_interval_seconds=value.get("minimum_interval_seconds"),
            maximum_requests=value.get("maximum_requests"),
            maximum_attempts=value.get("maximum_attempts"),
            retry_statuses=tuple(value["retry_statuses"]),
            backoff_initial_seconds=value.get("backoff_initial_seconds"),
            backoff_maximum_seconds=value.get("backoff_maximum_seconds"),
            maximum_json_depth=value.get("maximum_json_depth"),
            maximum_json_items=value.get("maximum_json_items"),
            credential_env_name=value.get("credential_env_name"),
            credential_required=value.get("credential_required"),
            credential_header=value.get("credential_header"),
            credential_prefix=value.get("credential_prefix"),
            enabled=value.get("enabled"),
        )
    except (EgressPolicyError, TypeError, ValueError) as exc:
        raise ScholarlyGatewayError("scholarly egress policy claim is malformed") from exc
    if (
        _egress_policy_claim(policy) != dict(value)
        or value.get("budget_semantics") != _egress_budget_policy_claim(policy)
    ):
        raise ScholarlyGatewayError("scholarly egress policy claim is inconsistent")
    return policy


def _clean_wire_text(value: object, label: str, *, maximum: int = 8192) -> str:
    if not isinstance(value, str):
        raise ScholarlyGatewayError(f"{label} must be text")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if (
        not normalized
        or len(normalized.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise ScholarlyGatewayError(f"{label} exceeds its bounded text contract")
    return normalized


def _quote_openalex_search_term(value: str) -> str:
    normalized = _clean_wire_text(value, "OpenAlex search term", maximum=1024)
    return '"' + normalized.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _is_valid_openalex_year_filter(value: str) -> bool:
    if _YEAR_RE.fullmatch(value) is None:
        return False
    years = tuple(int(item) for item in value.split("-"))
    return len(years) == 1 or years[0] <= years[1]


def _is_valid_openalex_date_filter(value: str) -> bool:
    if _DATE_RE.fullmatch(value) is None:
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _encode_openalex_filters(
    filters: Sequence[ScholarlySearchFilter],
) -> str | None:
    mappings: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in filters:
        if not isinstance(item, ScholarlySearchFilter):
            raise ScholarlyGatewayError("OpenAlex search filter is malformed")
        name = item.name
        value = item.value.strip().lower()
        if name == "publication_year" and _is_valid_openalex_year_filter(value):
            provider_name = "publication_year"
        elif name in {
            "from_publication_date",
            "to_publication_date",
        } and _is_valid_openalex_date_filter(value):
            provider_name = name
        elif name == "type" and value in _OPENALEX_WORK_TYPES:
            provider_name = "type"
        elif name == "open_access" and value in {"true", "false"}:
            provider_name = "open_access.is_oa"
        elif name == "has_abstract" and value in {"true", "false"}:
            provider_name = "has_abstract"
        else:
            raise ScholarlyGatewayError("OpenAlex search filter is unsupported")
        if provider_name in seen:
            raise ScholarlyGatewayError("duplicate OpenAlex search filter is ambiguous")
        seen.add(provider_name)
        mappings.append((provider_name, value))
    mapped = dict(mappings)
    lower_date = mapped.get("from_publication_date")
    upper_date = mapped.get("to_publication_date")
    if lower_date is not None and upper_date is not None and lower_date > upper_date:
        raise ScholarlyGatewayError("OpenAlex publication date range is reversed")
    if not mappings:
        return None
    return ",".join(f"{name}:{value}" for name, value in sorted(mappings))


def _url(base: str, pairs: Sequence[tuple[str, str]]) -> str:
    query = urlencode(tuple(pairs), doseq=False, quote_via=quote, safe="")
    result = f"{base}?{query}" if query else base
    if len(result.encode("utf-8")) > _OPENALEX_MAX_URL_BYTES:
        raise ScholarlyGatewayError("native scholarly request URL is too large")
    return result


def _operation(request: object) -> str:
    if type(request) is ScholarlySearchPageRequest:
        return "search_works"
    if isinstance(request, ScholarlySearchRequest):
        return "search_works"
    if isinstance(request, (ScholarlyRequest, CitationPageRequest)):
        return request.operation
    raise ScholarlyGatewayError("scholarly request type is unsupported")


def _request_source(request: object) -> ScholarlySource:
    if type(request) is ScholarlySearchPageRequest:
        return request.source
    if isinstance(request, (ScholarlyRequest, ScholarlySearchRequest, CitationPageRequest)):
        return request.source
    raise ScholarlyGatewayError("scholarly request type is unsupported")


def _request_id(request: object) -> str:
    if type(request) is ScholarlySearchPageRequest:
        return request.request_id
    if isinstance(request, (ScholarlyRequest, ScholarlySearchRequest, CitationPageRequest)):
        return request.request_id
    raise ScholarlyGatewayError("scholarly request type is unsupported")


def _encode_openalex_request(request: object) -> EgressRequest:
    if type(request) is ScholarlySearchPageRequest:
        terms = (request.query, *request.synonyms)
        expression = " OR ".join(_quote_openalex_search_term(value) for value in terms)
        if len(terms) > 1:
            expression = f"({expression})"
        pairs = [("search", expression)]
        filter_value = _encode_openalex_filters(request.filters)
        if filter_value is not None:
            pairs.append(("filter", filter_value))
        pairs.extend((("sort", "relevance_score:desc"), ("corpus", "core"),
                      ("per_page", str(request.page_size)),
                      ("cursor", require_scholarly_search_cursor(request.cursor))))
        return EgressRequest(
            adapter_id=_OPENALEX_CURSOR_ADAPTER_ID, method="GET",
            url=_url(f"{_OPENALEX_BASE_URL}/works", pairs),
            headers=(("Accept", "application/json"), ("User-Agent", "Scientist-One-vNext-Scholarly/2")),
            body=b"", content_type="application/json", target_source="CONFIGURED",
        )
    if isinstance(request, ScholarlySearchRequest):
        if request.max_results > _OPENALEX_MAX_RESULTS:
            raise ScholarlyGatewayError("OpenAlex result limit exceeds 100")
        terms = (request.query, *request.synonyms)
        expression = " OR ".join(_quote_openalex_search_term(value) for value in terms)
        if len(terms) > 1:
            expression = f"({expression})"
        pairs: list[tuple[str, str]] = [("search", expression)]
        filter_value = _encode_openalex_filters(request.filters)
        if filter_value is not None:
            pairs.append(("filter", filter_value))
        pairs.extend((("per_page", str(request.max_results)), ("page", "1")))
        url = _url(f"{_OPENALEX_BASE_URL}/works", pairs)
    elif isinstance(request, ScholarlyRequest):
        if request.operation != "resolve_work":
            raise ScholarlyGatewayError("OpenAlex operation is unsupported")
        if request.identifier.kind is not IdentifierKind.OPENALEX:
            raise ScholarlyGatewayError("OpenAlex singleton requires an OpenAlex work ID")
        if _OPENALEX_ID_RE.fullmatch(request.identifier.value) is None:
            raise ScholarlyGatewayError("OpenAlex work ID is invalid")
        url = f"{_OPENALEX_BASE_URL}/works/{request.identifier.value}"
    elif isinstance(request, CitationPageRequest):
        if request.identifier.kind is not IdentifierKind.OPENALEX:
            raise ScholarlyGatewayError("OpenAlex graph expansion requires an OpenAlex work ID")
        if request.page_number == 1 and request.cursor is not None:
            raise ScholarlyGatewayError("first citation page cannot supply a cursor")
        if request.page_number > 1 and request.cursor is None:
            raise ScholarlyGatewayError("later citation page requires a cursor")
        cursor = request.cursor or "*"
        if cursor != "*" and _CURSOR_RE.fullmatch(cursor) is None:
            raise ScholarlyGatewayError("OpenAlex citation cursor is invalid")
        relation = (
            "cited_by"
            if request.traversal is CitationTraversal.REFERENCES
            else "cites"
        )
        url = _url(
            f"{_OPENALEX_BASE_URL}/works",
            (
                ("filter", f"{relation}:{request.identifier.value}"),
                ("per_page", str(_OPENALEX_MAX_RESULTS)),
                ("cursor", cursor),
            ),
        )
    else:
        raise ScholarlyGatewayError("OpenAlex request type is unsupported")
    return EgressRequest(
        adapter_id=_OPENALEX_ADAPTER_ID,
        method="GET",
        url=url,
        headers=(
            ("Accept", "application/json"),
            ("User-Agent", "Scientist-One-vNext-Scholarly/2"),
        ),
        body=b"",
        content_type="application/json",
        target_source="CONFIGURED",
    )


def _encode_pmc_request(request: object) -> EgressRequest:
    if not isinstance(request, ScholarlyRequest) or request.operation != "resolve_work":
        raise ScholarlyGatewayError("PMC route supports resolve_work only")
    if request.identifier.kind is not IdentifierKind.PMCID:
        raise ScholarlyGatewayError("PMC full text requires a PMCID")
    match = _PMC_ID_RE.fullmatch(request.identifier.value)
    if match is None:
        raise ScholarlyGatewayError("PMC identifier is invalid")
    url = _url(
        _PMC_OAI_ENDPOINT_URL,
        (
            ("verb", "GetRecord"),
            ("identifier", f"oai:pubmedcentral.nih.gov:{match.group(1)}"),
            ("metadataPrefix", "pmc"),
        ),
    )
    return EgressRequest(
        adapter_id=_PMC_ADAPTER_ID,
        method="GET",
        url=url,
        headers=(
            ("Accept", "application/xml, text/xml;q=0.9"),
            ("User-Agent", "Scientist-One-vNext-Scholarly/2"),
        ),
        body=b"",
        content_type="application/xml",
        target_source="CONFIGURED",
    )


def _projection(
    descriptor: ScholarlyRouteDescriptor,
    route_authority_hash: str,
    scholarly_request: object,
    egress_request: EgressRequest,
) -> ScholarlyNativeRequestProjection:
    return ScholarlyNativeRequestProjection(
        source=descriptor.source,
        operation=_operation(scholarly_request),
        scholarly_request_id=_request_id(scholarly_request),
        route_authority_artifact_sha256=route_authority_hash,
        wire_protocol=descriptor.wire_protocol,
        method=egress_request.method,
        url=egress_request.url,
        headers=egress_request.headers,
        body_sha256=hashlib.sha256(egress_request.body).hexdigest(),
        body_size=len(egress_request.body),
        egress_request_id=egress_request.request_id,
    )


def _content_text(
    value: object,
    label: str,
    *,
    optional: bool = False,
    maximum: int = _MAX_CAPTURE_TEXT,
) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise ScholarlyGatewayError(f"{label} must be text")
    normalized = " ".join(unicodedata.normalize("NFKC", value).split())
    if not normalized:
        if optional:
            return None
        raise ScholarlyGatewayError(f"{label} cannot be empty")
    if len(normalized) > maximum:
        raise ScholarlyGatewayError(f"{label} exceeds the text bound")
    return normalized


def _openalex_identifier(value: object, label: str = "OpenAlex work ID") -> str:
    if not isinstance(value, str):
        raise ScholarlyGatewayError(f"{label} must be text")
    try:
        return ScholarlyIdentifier(IdentifierKind.OPENALEX, value).value
    except LiteratureError as exc:
        raise ScholarlyGatewayError(f"{label} is malformed") from exc


def _optional_doi(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ScholarlyGatewayError("OpenAlex DOI is malformed")
    try:
        return ScholarlyIdentifier(IdentifierKind.DOI, value).value
    except LiteratureError as exc:
        raise ScholarlyGatewayError("OpenAlex DOI is malformed") from exc


def _openalex_abstract(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or len(value) > 100_000:
        raise ScholarlyGatewayError("OpenAlex abstract index is malformed")
    positioned: dict[int, str] = {}
    for word, positions in value.items():
        token = _content_text(word, "OpenAlex abstract token", maximum=4096)
        if not isinstance(positions, (list, tuple)) or len(positions) > 100_000:
            raise ScholarlyGatewayError("OpenAlex abstract positions are malformed")
        assert token is not None
        for position in positions:
            if (
                isinstance(position, bool)
                or not isinstance(position, int)
                or position < 0
                or position > 1_000_000
                or position in positioned
            ):
                raise ScholarlyGatewayError("OpenAlex abstract positions are ambiguous")
            positioned[position] = token
    if not positioned:
        return None
    if tuple(sorted(positioned)) != tuple(range(max(positioned) + 1)):
        raise ScholarlyGatewayError("OpenAlex abstract positions are discontinuous")
    abstract = " ".join(positioned[index] for index in range(len(positioned)))
    if len(abstract) > _MAX_CAPTURE_TEXT:
        raise ScholarlyGatewayError("OpenAlex abstract exceeds the text bound")
    return abstract


def _project_openalex_work(
    value: object,
    *,
    expected_identifier: str | None = None,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ScholarlyGatewayError("OpenAlex work must be an object")
    identifier = _openalex_identifier(value.get("id"))
    if expected_identifier is not None and identifier != expected_identifier:
        raise ScholarlyGatewayError("OpenAlex singleton ID differs from its request")
    title = _content_text(
        value.get("title") or value.get("display_name"),
        "OpenAlex work title",
    )
    authorships = value.get("authorships")
    if authorships is None:
        authorships = []
    if not isinstance(authorships, (list, tuple)) or len(authorships) > 10_000:
        raise ScholarlyGatewayError("OpenAlex authorships are malformed")
    projected_authorships: list[dict[str, object]] = []
    for item in authorships:
        if not isinstance(item, Mapping) or not isinstance(item.get("author"), Mapping):
            raise ScholarlyGatewayError("OpenAlex authorship is malformed")
        name = _content_text(
            item["author"].get("display_name"),
            "OpenAlex author name",
        )
        projected_authorships.append({"author": {"display_name": name}})
    publication_year = value.get("publication_year")
    if publication_year is not None and (
        isinstance(publication_year, bool)
        or not isinstance(publication_year, int)
        or not 1000 <= publication_year <= 3000
    ):
        raise ScholarlyGatewayError("OpenAlex publication year is malformed")
    venue: str | None = None
    primary_location = value.get("primary_location")
    if primary_location is not None:
        if not isinstance(primary_location, Mapping):
            raise ScholarlyGatewayError("OpenAlex primary location is malformed")
        source = primary_location.get("source")
        if source is not None:
            if not isinstance(source, Mapping):
                raise ScholarlyGatewayError("OpenAlex primary source is malformed")
            venue = _content_text(
                source.get("display_name"),
                "OpenAlex source display name",
                optional=True,
            )
    projected: dict[str, object] = {
        "id": identifier,
        "title": title,
        "authorships": projected_authorships,
        "publication_year": publication_year,
        "abstract": _openalex_abstract(value.get("abstract_inverted_index")),
    }
    doi = _optional_doi(value.get("doi"))
    if doi is not None:
        projected["doi"] = doi
    if venue is not None:
        projected["primary_location"] = {"source": {"display_name": venue}}
    return projected


def _openalex_list_envelope(
    value: object,
    *,
    maximum_results: int,
) -> tuple[Mapping[str, object], Sequence[object]]:
    if not isinstance(value, Mapping):
        raise ScholarlyGatewayError("OpenAlex list response root must be an object")
    meta = value.get("meta")
    results = value.get("results")
    group_by = value.get("group_by")
    if (
        not isinstance(meta, Mapping)
        or not isinstance(results, (list, tuple))
        or not isinstance(group_by, (list, tuple))
        or len(results) > maximum_results
    ):
        raise ScholarlyGatewayError("OpenAlex list response envelope is malformed")
    return meta, results


def _project_openalex_response(
    value: object,
    request: object,
) -> _ParsedNativeResponse:
    if type(request) is ScholarlySearchPageRequest:
        meta, results = _openalex_list_envelope(value, maximum_results=request.page_size)
        if (type(meta.get("count")) is not int or meta["count"] < 0
                or type(meta.get("per_page")) is not int
                or meta["per_page"] != request.page_size or "next_cursor" not in meta):
            raise ScholarlyGatewayError("OpenAlex cursor search metadata is malformed")
        cursor = meta["next_cursor"]
        if cursor is not None:
            require_scholarly_search_cursor(cursor)
        hits = []
        seen = set()
        for item in results:
            projected = _project_openalex_work(item)
            identifier = projected["id"]
            if identifier in seen:
                raise ScholarlyGatewayError("OpenAlex search contains duplicate work IDs")
            seen.add(identifier)
            hits.append({"identifier_kind": IdentifierKind.OPENALEX.value,
                         "identifier": identifier, "title": projected["title"]})
        return _ParsedNativeResponse(
            payload={"results": hits, "next_cursor": cursor,
                     "reported_count": meta["count"], "reported_page_size": meta["per_page"]},
            status=RetrievalStatus.AVAILABLE, failure_code=None, failure_reason=None,
            license="CC0-1.0 OpenAlex metadata", full_text_status=FullTextStatus.METADATA_ONLY,
        )
    if isinstance(request, ScholarlySearchRequest):
        meta, results = _openalex_list_envelope(
            value,
            maximum_results=request.max_results,
        )
        if meta.get("page") != 1 or meta.get("per_page") != request.max_results:
            raise ScholarlyGatewayError("OpenAlex search pagination is malformed")
        hits: list[dict[str, object]] = []
        seen: set[str] = set()
        for item in results:
            projected = _project_openalex_work(item)
            identifier = projected["id"]
            assert isinstance(identifier, str)
            if identifier in seen:
                raise ScholarlyGatewayError("OpenAlex search contains duplicate work IDs")
            seen.add(identifier)
            hits.append(
                {
                    "identifier_kind": IdentifierKind.OPENALEX.value,
                    "identifier": identifier,
                    "title": projected["title"],
                }
            )
        return _ParsedNativeResponse(
            payload={"results": hits, "next_cursor": None},
            status=RetrievalStatus.AVAILABLE,
            failure_code=None,
            failure_reason=None,
            license="CC0-1.0 OpenAlex metadata",
            full_text_status=FullTextStatus.METADATA_ONLY,
        )
    if isinstance(request, ScholarlyRequest):
        projected = _project_openalex_work(
            value,
            expected_identifier=request.identifier.value,
        )
        return _ParsedNativeResponse(
            payload=projected,
            status=RetrievalStatus.AVAILABLE,
            failure_code=None,
            failure_reason=None,
            license="CC0-1.0 OpenAlex metadata",
            full_text_status=FullTextStatus.METADATA_ONLY,
        )
    if isinstance(request, CitationPageRequest):
        meta, results = _openalex_list_envelope(
            value,
            maximum_results=_OPENALEX_MAX_RESULTS,
        )
        if meta.get("per_page") != _OPENALEX_MAX_RESULTS:
            raise ScholarlyGatewayError("OpenAlex citation pagination is malformed")
        if "next_cursor" not in meta:
            raise ScholarlyGatewayError("OpenAlex citation cursor state is missing")
        next_cursor = meta.get("next_cursor")
        if next_cursor is not None and (
            not isinstance(next_cursor, str)
            or _CURSOR_RE.fullmatch(next_cursor) is None
        ):
            raise ScholarlyGatewayError("OpenAlex next cursor is malformed")
        works = [_project_openalex_work(item) for item in results]
        identifiers = [item["id"] for item in works]
        if len(set(identifiers)) != len(identifiers):
            raise ScholarlyGatewayError("OpenAlex citation page has duplicate work IDs")
        return _ParsedNativeResponse(
            payload={"works": works, "next_cursor": next_cursor},
            status=RetrievalStatus.AVAILABLE,
            failure_code=None,
            failure_reason=None,
            license="CC0-1.0 OpenAlex metadata",
            full_text_status=FullTextStatus.METADATA_ONLY,
        )
    raise ScholarlyGatewayError("OpenAlex response request type is unsupported")


def _parse_openalex_response(
    gateway: EgressGateway,
    result: GatewayResult,
    request: object,
) -> _ParsedNativeResponse:
    return _project_openalex_response(gateway.parse_json(result), request)


def _local_name(tag: object) -> str:
    if not isinstance(tag, str):
        raise ScholarlyGatewayError("PMC XML tag is malformed")
    return tag.rsplit("}", 1)[-1]


def _xml_text(
    element: ElementTree.Element | None,
    label: str,
    *,
    optional: bool = False,
    maximum: int = _MAX_CAPTURE_TEXT,
) -> str | None:
    if element is None:
        if optional:
            return None
        raise ScholarlyGatewayError(f"PMC {label} is missing")
    return _content_text(
        "".join(element.itertext()),
        f"PMC {label}",
        optional=optional,
        maximum=maximum,
    )


def _descendants(
    element: ElementTree.Element,
    name: str,
) -> tuple[ElementTree.Element, ...]:
    """Return namespace-free JATS descendants only."""

    return tuple(item for item in element.iter() if item.tag == name)


def _children(
    element: ElementTree.Element,
    name: str,
) -> tuple[ElementTree.Element, ...]:
    """Return namespace-free direct JATS children only."""

    return tuple(item for item in list(element) if item.tag == name)


def _one_child(
    element: ElementTree.Element,
    name: str,
    label: str,
) -> ElementTree.Element:
    values = _children(element, name)
    if len(values) != 1:
        raise ScholarlyGatewayError(f"PMC {label} must occur exactly once")
    return values[0]


def _oai_tag(name: str) -> str:
    return f"{{{_OAI_NAMESPACE}}}{name}"


def _oai_children(
    element: ElementTree.Element,
    name: str,
) -> tuple[ElementTree.Element, ...]:
    tag = _oai_tag(name)
    return tuple(item for item in list(element) if item.tag == tag)


def _one_oai_child(
    element: ElementTree.Element,
    name: str,
    label: str,
) -> ElementTree.Element:
    values = _oai_children(element, name)
    if len(values) != 1:
        raise ScholarlyGatewayError(f"PMC {label} must occur exactly once")
    return values[0]


def _validate_xml_tree(root: ElementTree.Element) -> None:
    allowed_element_namespaces = {
        "",
        _OAI_NAMESPACE,
        "http://www.w3.org/1998/Math/MathML",
        _ALI_NAMESPACE,
    }
    allowed_attribute_namespaces = {
        "http://www.w3.org/1999/xlink",
        "http://www.w3.org/XML/1998/namespace",
        _XSI_NAMESPACE,
    }
    count = 0
    stack: list[tuple[ElementTree.Element, int]] = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        count += 1
        if count > _MAX_PMC_XML_ELEMENTS or depth > _MAX_PMC_XML_DEPTH:
            raise ScholarlyGatewayError("PMC XML exceeds structural bounds")
        tag = element.tag
        namespace = tag[1:].split("}", 1)[0] if tag.startswith("{") else ""
        if namespace not in allowed_element_namespaces:
            raise ScholarlyGatewayError("PMC XML contains an unsupported namespace")
        if len(element.attrib) > 64:
            raise ScholarlyGatewayError("PMC XML element has too many attributes")
        for attribute in element.attrib:
            if attribute.startswith("{"):
                attribute_namespace = attribute[1:].split("}", 1)[0]
                if attribute_namespace not in allowed_attribute_namespaces:
                    raise ScholarlyGatewayError(
                        "PMC XML contains an unsupported attribute namespace"
                    )
                if attribute_namespace == _XSI_NAMESPACE and element is not root:
                    raise ScholarlyGatewayError(
                        "PMC XML contains a misplaced schema-instance attribute"
                    )
        stack.extend((child, depth + 1) for child in list(element))


def _pmc_error(root: ElementTree.Element) -> _ParsedNativeResponse | None:
    errors = _oai_children(root, "error")
    if not errors:
        return None
    if len(errors) != 1:
        raise ScholarlyGatewayError("PMC OAI response contains ambiguous errors")
    code = errors[0].attrib.get("code")
    message = _xml_text(errors[0], "OAI error", optional=True, maximum=4096)
    if code == "idDoesNotExist":
        status = RetrievalStatus.NOT_FOUND
        failure_code = ScholarlyGatewayFailureCode.NOT_FOUND
    elif code == "cannotDisseminateFormat":
        status = RetrievalStatus.LICENSE_RESTRICTED
        failure_code = ScholarlyGatewayFailureCode.LICENSE_RESTRICTED
    elif code in {"badArgument", "badResumptionToken", "badVerb", "noRecordsMatch"}:
        status = RetrievalStatus.MALFORMED
        failure_code = ScholarlyGatewayFailureCode.MALFORMED_RESPONSE
    else:
        status = RetrievalStatus.MALFORMED
        failure_code = ScholarlyGatewayFailureCode.MALFORMED_RESPONSE
    return _ParsedNativeResponse(
        payload=None,
        status=status,
        failure_code=failure_code,
        failure_reason=f"PMC OAI {code or 'unknown'}: {message or 'request unavailable'}",
        license=None,
        full_text_status=(
            FullTextStatus.LICENSE_RESTRICTED
            if status is RetrievalStatus.LICENSE_RESTRICTED
            else FullTextStatus.UNAVAILABLE
        ),
    )


def _jats_identifiers(
    article_meta: ElementTree.Element,
    expected_pmcid: str,
) -> dict[str, str]:
    found: dict[str, str] = {}
    for item in _children(article_meta, "article-id"):
        kind = item.attrib.get("pub-id-type", "").strip().lower()
        if kind not in {"pmc", "pmcid", "pmid", "doi"}:
            continue
        text = _xml_text(item, "article identifier", maximum=4096)
        assert text is not None
        canonical_kind = "pmcid" if kind in {"pmc", "pmcid"} else kind
        if canonical_kind in found and found[canonical_kind] != text:
            raise ScholarlyGatewayError("PMC JATS has conflicting article identifiers")
        found[canonical_kind] = text
    if "pmcid" not in found:
        raise ScholarlyGatewayError("PMC JATS omits its PMCID")
    try:
        pmcid = ScholarlyIdentifier(IdentifierKind.PMCID, found["pmcid"]).value
    except LiteratureError as exc:
        raise ScholarlyGatewayError("PMC JATS PMCID is malformed") from exc
    if pmcid != expected_pmcid:
        raise ScholarlyGatewayError("PMC JATS PMCID differs from its request")
    output = {"pmcid": pmcid}
    for name, kind in (("pmid", IdentifierKind.PMID), ("doi", IdentifierKind.DOI)):
        value = found.get(name)
        if value is None:
            continue
        try:
            output[name] = ScholarlyIdentifier(kind, value).value
        except LiteratureError as exc:
            raise ScholarlyGatewayError(f"PMC JATS {name} is malformed") from exc
    return output


def _jats_license(
    article_meta: ElementTree.Element,
) -> tuple[str, Mapping[str, object]] | None:
    permissions_values = _children(article_meta, "permissions")
    if len(permissions_values) != 1:
        return None
    observed: set[str] = set()
    license_elements = _children(permissions_values[0], "license")
    if not license_elements:
        return None
    for license_element in license_elements:
        references = [
            child for child in list(license_element) if child.tag == _ALI_LICENSE_REF
        ]
        if any(
            _local_name(child.tag) == "license_ref"
            and child.tag != _ALI_LICENSE_REF
            for child in list(license_element)
        ):
            return None
        if len(references) > 1:
            return None
        candidates: list[str] = []
        for attribute in (_XLINK_HREF, "href"):
            href = license_element.attrib.get(attribute)
            if href is not None:
                if not isinstance(href, str):
                    return None
                candidates.append(href)
        if references:
            reference = references[0]
            if "start_date" in reference.attrib or "end_date" in reference.attrib:
                return None
            reference_text = _xml_text(
                reference,
                "JATS ALI license reference",
                maximum=4096,
            )
            assert reference_text is not None
            candidates.append(reference_text)
        for descendant in license_element.iter():
            if descendant.tag != "ext-link":
                continue
            for attribute in (_XLINK_HREF, "href"):
                link = descendant.attrib.get(attribute)
                if link is not None:
                    if not isinstance(link, str):
                        return None
                    candidates.append(link)
        license_text = " ".join(license_element.itertext())
        candidates.extend(match.group(0) for match in _HTTP_URI_RE.finditer(license_text))
        if not candidates:
            return None
        for candidate in candidates:
            normalized = candidate.strip().lower()
            if not normalized.endswith("/"):
                normalized += "/"
            observed.add(normalized)
    if len(observed) != 1:
        return None
    observed_uri = next(iter(observed))
    canonical_uri = (
        "https://" + observed_uri[len("http://") :]
        if observed_uri.startswith("http://")
        else observed_uri
    )
    policy = _REUSABLE_PMC_LICENSES.get(canonical_uri)
    if policy is None:
        return None
    label, obligations = policy
    return (
        canonical_uri,
        MappingProxyType(
            {
                "schema_version": "pmc-reuse-license-decision/v1",
                "policy_id": "pmc-explicit-reusable-cc-license/v1",
                "decision": "REUSABLE_WITH_RECORDED_OBLIGATIONS",
                "observed_license_uri": observed_uri,
                "canonical_license_uri": canonical_uri,
                "license_label": label,
                "obligations": list(obligations),
                "documentation_urls": list(PMC_OAI_JATS_DOCUMENTATION_URLS),
            }
        ),
    )


def _jats_authors(article_meta: ElementTree.Element) -> list[str]:
    authors: list[str] = []
    for group in _children(article_meta, "contrib-group"):
        for contrib in _children(group, "contrib"):
            if contrib.attrib.get("contrib-type", "author") != "author":
                continue
            collabs = _children(contrib, "collab")
            names = _children(contrib, "name")
            if len(collabs) == 1 and not names:
                name = _xml_text(
                    collabs[0],
                    "collaborative author",
                    optional=True,
                    maximum=4096,
                )
            elif len(names) == 1 and not collabs:
                surname_values = _children(names[0], "surname")
                given_values = _children(names[0], "given-names")
                if len(surname_values) > 1 or len(given_values) > 1:
                    raise ScholarlyGatewayError("PMC author name is ambiguous")
                surname_text = _xml_text(
                    surname_values[0] if surname_values else None,
                    "author surname",
                    optional=True,
                    maximum=2048,
                )
                given_text = _xml_text(
                    given_values[0] if given_values else None,
                    "author given names",
                    optional=True,
                    maximum=2048,
                )
                name = (
                    " ".join(value for value in (given_text, surname_text) if value)
                    or None
                )
            else:
                raise ScholarlyGatewayError("PMC author identity is ambiguous")
            if name is not None:
                authors.append(name)
    return authors


def _nearest_section(
    element: ElementTree.Element,
    parent: Mapping[ElementTree.Element, ElementTree.Element],
) -> ElementTree.Element | None:
    current = parent.get(element)
    while current is not None:
        if current.tag == "sec":
            return current
        current = parent.get(current)
    return None


def _jats_passages(
    article: ElementTree.Element,
    *,
    source_raw_artifact_sha256: str,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    return _jats_passages_core(
        article,
        projection_profile=_PmcProjectionProfile.RAW_XML_V1,
        wire_raw_artifact_sha256=source_raw_artifact_sha256,
        decoded_xml_sha256=None,
        decoding_descriptor_artifact_sha256=None,
    )


def _jats_passages_core(
    article: ElementTree.Element,
    *,
    projection_profile: _PmcProjectionProfile,
    wire_raw_artifact_sha256: str,
    decoded_xml_sha256: str | None,
    decoding_descriptor_artifact_sha256: str | None,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    sources = _pmc_projection_sources(
        projection_profile,
        wire_raw_artifact_sha256=wire_raw_artifact_sha256,
        decoded_xml_sha256=decoded_xml_sha256,
        decoding_descriptor_artifact_sha256=decoding_descriptor_artifact_sha256,
    )
    bodies = _children(article, "body")
    if len(bodies) != 1:
        raise ScholarlyGatewayError("PMC JATS must contain exactly one body")
    body = bodies[0]
    parent = {child: owner for owner in body.iter() for child in list(owner)}
    candidates: list[tuple[str, str]] = []
    for paragraph in _descendants(body, "p"):
        text = _xml_text(paragraph, "body paragraph", optional=True)
        if text is None:
            continue
        section = _nearest_section(paragraph, parent)
        section_id = "body"
        if section is not None:
            raw_id = section.attrib.get("id")
            if isinstance(raw_id, str) and raw_id.strip():
                section_id = _content_text(raw_id, "PMC section ID", maximum=4096) or "body"
            else:
                direct_title = next(
                    (child for child in list(section) if child.tag == "title"),
                    None,
                )
                section_id = _xml_text(
                    direct_title,
                    "section title",
                    optional=True,
                    maximum=4096,
                ) or "body"
        candidates.append((section_id, text))
        if len(candidates) > _MAX_PMC_PASSAGES:
            raise ScholarlyGatewayError("PMC JATS passage count exceeds the bound")
    if not candidates:
        raise ScholarlyGatewayError("PMC JATS contains no reusable body passages")
    total_text = sum(len(text) for _, text in candidates) + 2 * (len(candidates) - 1)
    if total_text > _MAX_PMC_TOTAL_TEXT:
        raise ScholarlyGatewayError("PMC JATS body exceeds the text bound")
    passages: list[dict[str, object]] = []
    offset = 0
    for index, (section_id, text) in enumerate(candidates):
        before = candidates[index - 1][1][-_MAX_PMC_CONTEXT_CHARS:] if index else ""
        after = (
            candidates[index + 1][1][:_MAX_PMC_CONTEXT_CHARS]
            if index + 1 < len(candidates)
            else ""
        )
        passages.append(
            {
                "coordinate_schema_version": projection_profile.value,
                "section_id": section_id,
                "passage_id": f"jats-p-{index + 1:05d}",
                "text": text,
                "start_char": offset,
                "end_char": offset + len(text),
                "context_before": before,
                "context_after": after,
            }
        )
        offset += len(text) + 2
    normalized_text = "\n\n".join(text for _, text in candidates)
    projection = {
        "schema_version": projection_profile.value,
        "extraction_codec": _PMC_TEXT_EXTRACTION_CODEC_V1,
        "coordinate_space": "normalized-jats-body-text",
        "offset_unit": "unicode-code-point-index",
        "paragraph_separator": "\n\n",
        "normalization": "NFKC followed by Unicode whitespace collapse",
        "offsets_reference_raw_xml": False,
        **sources,
        "normalized_text_sha256": hashlib.sha256(
            normalized_text.encode("utf-8")
        ).hexdigest(),
        "normalized_text_length": len(normalized_text),
        "passage_count": len(passages),
    }
    return passages, projection


def _project_pmc_response(
    raw_bytes: bytes,
    raw_artifact_sha256: str,
    request: ScholarlyRequest,
) -> _ParsedNativeResponse:
    """Historical raw-XML wrapper; original signature and v1 output are fixed."""
    return _project_pmc_response_core(
        raw_bytes,
        raw_artifact_sha256,
        request,
        projection_profile=_PmcProjectionProfile.RAW_XML_V1,
        wire_raw_artifact_sha256=raw_artifact_sha256,
        decoding_descriptor_artifact_sha256=None,
    )


def _project_decoded_pmc_response(
    decoded_xml_bytes: bytes,
    request: ScholarlyRequest,
    *,
    wire_raw_artifact_sha256: str,
    decoded_xml_sha256: str,
    decoding_descriptor_artifact_sha256: str,
) -> _ParsedNativeResponse:
    """Project XML using distinct identity roles, without verifying derivation.

    The upcoming gateway replay owner must verify wire-to-decoded derivation and
    descriptor artifact provenance BEFORE invoking this pure wrapper. It checks
    the XML digest, not existence/authenticity of either named artifact. Matching
    wire/XML digests are legitimate for identity encoding. No live or scientific
    authority follows from this result.
    """
    if type(decoded_xml_bytes) is not bytes:
        raise ScholarlyGatewayError("PMC decoded XML must use exact bytes")
    _pmc_projection_sources(
        _PmcProjectionProfile.DECODED_XML_V2,
        wire_raw_artifact_sha256=wire_raw_artifact_sha256,
        decoded_xml_sha256=decoded_xml_sha256,
        decoding_descriptor_artifact_sha256=decoding_descriptor_artifact_sha256,
    )
    return _project_pmc_response_core(
        decoded_xml_bytes,
        decoded_xml_sha256,
        request,
        projection_profile=_PmcProjectionProfile.DECODED_XML_V2,
        wire_raw_artifact_sha256=wire_raw_artifact_sha256,
        decoding_descriptor_artifact_sha256=decoding_descriptor_artifact_sha256,
    )


def _project_pmc_response_core(
    raw_bytes: bytes,
    xml_sha256: str,
    request: ScholarlyRequest,
    *,
    projection_profile: _PmcProjectionProfile,
    wire_raw_artifact_sha256: str,
    decoding_descriptor_artifact_sha256: str | None,
) -> _ParsedNativeResponse:
    if (
        projection_profile is _PmcProjectionProfile.RAW_XML_V1
        and wire_raw_artifact_sha256 != xml_sha256
    ):
        raise ScholarlyGatewayError("PMC raw XML projection identities differ")
    _pmc_projection_sources(
        projection_profile,
        wire_raw_artifact_sha256=wire_raw_artifact_sha256,
        decoded_xml_sha256=(
            xml_sha256 if projection_profile is _PmcProjectionProfile.DECODED_XML_V2 else None
        ),
        decoding_descriptor_artifact_sha256=decoding_descriptor_artifact_sha256,
    )
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise ScholarlyGatewayError("PMC XML byte-order marks are unsupported")
    if not raw_bytes.startswith(_PMC_XML_DECLARATION_V1):
        raise ScholarlyGatewayError(
            "PMC XML must begin with the pinned XML 1.0 UTF-8 declaration"
        )
    try:
        decoded = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScholarlyGatewayError("PMC XML must use the pinned UTF-8 wire encoding") from exc
    without_declaration = decoded[
        len(_PMC_XML_DECLARATION_V1) :
    ].casefold()
    if (
        "<!doctype" in without_declaration
        or "<!entity" in without_declaration
        or "<?" in without_declaration
    ):
        raise ScholarlyGatewayError("PMC XML contains a forbidden declaration")
    if hashlib.sha256(raw_bytes).hexdigest() != xml_sha256:
        raise ScholarlyGatewayError("PMC XML changed after gateway capture")
    try:
        root = ElementTree.fromstring(decoded)
    except ElementTree.ParseError as exc:
        raise ScholarlyGatewayError("PMC response is not well-formed XML") from exc
    _validate_xml_tree(root)
    schema_location_key = f"{{{_XSI_NAMESPACE}}}schemaLocation"
    schema_location = root.attrib.get(schema_location_key)
    if (
        root.tag != _oai_tag("OAI-PMH")
        or set(root.attrib) != {schema_location_key}
        or not isinstance(schema_location, str)
        or schema_location.split()
        != [
            _OAI_NAMESPACE,
            f"{_OAI_NAMESPACE}OAI-PMH.xsd",
        ]
    ):
        raise ScholarlyGatewayError("PMC response is not an OAI-PMH envelope")
    expected_identifier = f"oai:pubmedcentral.nih.gov:{request.identifier.value[3:]}"
    response_date = _one_oai_child(root, "responseDate", "OAI response date")
    response_date_text = response_date.text
    if (
        response_date.attrib
        or list(response_date)
        or not isinstance(response_date_text, str)
        or len(response_date_text) > 64
    ):
        raise ScholarlyGatewayError("PMC OAI response date is malformed")
    if _OAI_RESPONSE_DATE_RE.fullmatch(response_date_text) is None:
        raise ScholarlyGatewayError(
            "PMC OAI response date must use canonical UTC seconds"
        )
    try:
        datetime.strptime(response_date_text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ScholarlyGatewayError("PMC OAI response date is malformed") from exc
    request_echo = _one_oai_child(root, "request", "OAI request echo")
    if (
        set(request_echo.attrib) != {"verb", "identifier", "metadataPrefix"}
        or request_echo.attrib.get("verb") != "GetRecord"
        or request_echo.attrib.get("identifier") != expected_identifier
        or request_echo.attrib.get("metadataPrefix") != "pmc"
        or _xml_text(request_echo, "OAI request endpoint", maximum=4096)
        != _PMC_OAI_ENDPOINT_URL
    ):
        raise ScholarlyGatewayError("PMC OAI request echo differs from its request")
    parsed_error = _pmc_error(root)
    if parsed_error is not None:
        if [child.tag for child in list(root)] != [
            _oai_tag("responseDate"),
            _oai_tag("request"),
            _oai_tag("error"),
        ]:
            raise ScholarlyGatewayError("PMC OAI error envelope shape is malformed")
        return parsed_error
    if [child.tag for child in list(root)] != [
        _oai_tag("responseDate"),
        _oai_tag("request"),
        _oai_tag("GetRecord"),
    ]:
        raise ScholarlyGatewayError("PMC OAI success envelope shape is malformed")
    get_record = _one_oai_child(root, "GetRecord", "GetRecord result")
    if get_record.attrib or [child.tag for child in list(get_record)] != [
        _oai_tag("record")
    ]:
        raise ScholarlyGatewayError("PMC OAI GetRecord shape is malformed")
    record = _one_oai_child(get_record, "record", "OAI record")
    if record.attrib or [child.tag for child in list(record)] != [
        _oai_tag("header"),
        _oai_tag("metadata"),
    ]:
        raise ScholarlyGatewayError("PMC OAI record shape is malformed")
    header = _one_oai_child(record, "header", "OAI record header")
    header_children = list(header)
    if (
        header.attrib
        or len(header_children) < 2
        or header_children[0].tag != _oai_tag("identifier")
        or header_children[1].tag != _oai_tag("datestamp")
        or any(child.tag != _oai_tag("setSpec") for child in header_children[2:])
    ):
        raise ScholarlyGatewayError("PMC OAI record header shape is malformed")
    header_identifier = header_children[0]
    if _xml_text(header_identifier, "OAI identifier", maximum=4096) != expected_identifier:
        raise ScholarlyGatewayError("PMC OAI record is not bound to its request")
    metadata = _one_oai_child(record, "metadata", "OAI metadata")
    if metadata.attrib or len(list(metadata)) != 1:
        raise ScholarlyGatewayError("PMC OAI metadata shape is malformed")
    article = _one_child(metadata, "article", "top-level JATS article")
    front = _one_child(article, "front", "JATS front matter")
    article_meta = _one_child(front, "article-meta", "JATS article metadata")
    journal_meta = _one_child(front, "journal-meta", "JATS journal metadata")
    identifiers = _jats_identifiers(article_meta, request.identifier.value)
    license_result = _jats_license(article_meta)
    if license_result is None:
        return _ParsedNativeResponse(
            payload=None,
            status=RetrievalStatus.LICENSE_RESTRICTED,
            failure_code=ScholarlyGatewayFailureCode.LICENSE_RESTRICTED,
            failure_reason="PMC article lacks one unambiguous reusable Creative Commons license URI",
            license=None,
            full_text_status=FullTextStatus.LICENSE_RESTRICTED,
        )
    license_uri, license_decision = license_result
    title_groups = _children(article_meta, "title-group")
    titles = _children(title_groups[0], "article-title") if len(title_groups) == 1 else ()
    if len(titles) != 1:
        raise ScholarlyGatewayError("PMC JATS article title is ambiguous")
    title = _xml_text(titles[0], "article title")
    journal_title_groups = _children(journal_meta, "journal-title-group")
    journal_titles = (
        _children(journal_title_groups[0], "journal-title")
        if len(journal_title_groups) == 1
        else ()
    )
    if len(journal_titles) > 1:
        raise ScholarlyGatewayError("PMC JATS journal title is ambiguous")
    journal = _xml_text(
        journal_titles[0] if journal_titles else None,
        "journal title",
        optional=True,
    )
    years: set[int] = set()
    for pub_date in _children(article_meta, "pub-date"):
        year_values = _children(pub_date, "year")
        if len(year_values) > 1:
            raise ScholarlyGatewayError("PMC JATS publication year is ambiguous")
        text = _xml_text(
            year_values[0] if year_values else None,
            "publication year",
            optional=True,
            maximum=16,
        )
        if text is not None:
            if re.fullmatch(r"[12][0-9]{3}", text) is None:
                raise ScholarlyGatewayError("PMC JATS publication year is malformed")
            years.add(int(text))
    if len(years) > 1:
        raise ScholarlyGatewayError("PMC JATS publication years conflict")
    year = next(iter(years), None)
    abstracts = _children(article_meta, "abstract")
    if len(abstracts) > 1:
        raise ScholarlyGatewayError("PMC JATS abstract is ambiguous")
    abstract = (
        _xml_text(abstracts[0], "abstract", optional=True)
        if abstracts
        else None
    )
    passages, text_projection = _jats_passages_core(
        article,
        projection_profile=projection_profile,
        wire_raw_artifact_sha256=wire_raw_artifact_sha256,
        decoded_xml_sha256=(
            xml_sha256 if projection_profile is _PmcProjectionProfile.DECODED_XML_V2 else None
        ),
        decoding_descriptor_artifact_sha256=decoding_descriptor_artifact_sha256,
    )
    payload: dict[str, object] = {
        **identifiers,
        "title": title,
        "authors": _jats_authors(article_meta),
        "year": year,
        "journal": journal,
        "abstract": abstract,
        "license_decision": dict(license_decision),
        "full_text_projection": text_projection,
        "passages": passages,
    }
    return _ParsedNativeResponse(
        payload=payload,
        status=RetrievalStatus.AVAILABLE,
        failure_code=None,
        failure_reason=None,
        license=license_uri,
        full_text_status=FullTextStatus.AVAILABLE,
    )


def _parse_pmc_response(
    result: GatewayResult,
    request: ScholarlyRequest,
) -> _ParsedNativeResponse:
    if result.raw_response_artifact is None:
        raise ScholarlyGatewayError("PMC JATS lacks raw artifact custody")
    return _project_pmc_response(
        result.body,
        result.raw_response_artifact.sha256,
        request,
    )


def _logical_response_type(request: object) -> str:
    if type(request) is ScholarlySearchPageRequest:
        return "scholarly_search_response"
    if isinstance(request, ScholarlySearchRequest):
        return "scholarly_search_response"
    if isinstance(request, CitationPageRequest):
        return "citation_expansion_response"
    return "scholarly_response"


def _http_failure(status_code: int) -> _ParsedNativeResponse:
    if status_code in {401, 403}:
        status = RetrievalStatus.UNAVAILABLE
        code = ScholarlyGatewayFailureCode.AUTHENTICATION_REQUIRED
        reason = "scholarly endpoint requires unavailable authentication or access"
    elif status_code == 404:
        status = RetrievalStatus.NOT_FOUND
        code = ScholarlyGatewayFailureCode.NOT_FOUND
        reason = "scholarly endpoint did not find the requested object"
    elif status_code == 429:
        status = RetrievalStatus.RATE_LIMITED
        code = ScholarlyGatewayFailureCode.RATE_LIMITED
        reason = "scholarly endpoint rate limit was reached"
    else:
        status = RetrievalStatus.UNAVAILABLE
        code = ScholarlyGatewayFailureCode.HTTP_UNAVAILABLE
        reason = f"scholarly endpoint returned HTTP status {status_code}"
    return _ParsedNativeResponse(
        payload=None,
        status=status,
        failure_code=code,
        failure_reason=reason,
        license=None,
        full_text_status=FullTextStatus.UNAVAILABLE,
    )


def _preflight_failure(
    request: object,
    descriptor: ScholarlyRouteDescriptor,
) -> tuple[ScholarlyGatewayFailureCode, str] | None:
    if (descriptor.adapter_id == _OPENALEX_CURSOR_ADAPTER_ID) != (type(request) is ScholarlySearchPageRequest):
        return (ScholarlyGatewayFailureCode.OPERATION_UNSUPPORTED,
                "scholarly request and cursor route profiles differ")
    operation = _operation(request)
    if operation not in descriptor.operations:
        return (
            ScholarlyGatewayFailureCode.OPERATION_UNSUPPORTED,
            "source-owned route does not support this operation",
        )
    if descriptor.source is ScholarlySource.OPENALEX:
        if type(request) is ScholarlySearchPageRequest:
            try:
                _encode_openalex_request(request)
            except (ScholarlyGatewayError, LiteratureError):
                return (ScholarlyGatewayFailureCode.FILTER_UNSUPPORTED,
                        "OpenAlex cursor request is not encodable")
            return None
        if isinstance(request, ScholarlySearchRequest):
            if request.max_results > _OPENALEX_MAX_RESULTS:
                return (
                    ScholarlyGatewayFailureCode.RESULT_LIMIT_UNSUPPORTED,
                    "OpenAlex native route supports at most 100 results",
                )
            try:
                _encode_openalex_filters(request.filters)
            except ScholarlyGatewayError:
                return (
                    ScholarlyGatewayFailureCode.FILTER_UNSUPPORTED,
                    "OpenAlex search contains an unsupported or ambiguous filter",
                )
        elif isinstance(request, ScholarlyRequest):
            if request.identifier.kind is not IdentifierKind.OPENALEX:
                return (
                    ScholarlyGatewayFailureCode.IDENTIFIER_KIND_UNSUPPORTED,
                    "OpenAlex singleton route requires a source-native work ID",
                )
        elif isinstance(request, CitationPageRequest):
            if request.identifier.kind is not IdentifierKind.OPENALEX:
                return (
                    ScholarlyGatewayFailureCode.IDENTIFIER_KIND_UNSUPPORTED,
                    "OpenAlex graph route requires a source-native work ID",
                )
            if (request.page_number == 1) != (request.cursor is None):
                return (
                    ScholarlyGatewayFailureCode.REQUEST_INCONSISTENT,
                    "citation page number and cursor are inconsistent",
                )
            if request.cursor is not None and _CURSOR_RE.fullmatch(request.cursor) is None:
                return (
                    ScholarlyGatewayFailureCode.REQUEST_INCONSISTENT,
                    "citation cursor violates the closed grammar",
                )
        else:
            return (
                ScholarlyGatewayFailureCode.OPERATION_UNSUPPORTED,
                "OpenAlex request type is unsupported",
            )
    elif descriptor.source is ScholarlySource.PMC:
        if not isinstance(request, ScholarlyRequest):
            return (
                ScholarlyGatewayFailureCode.OPERATION_UNSUPPORTED,
                "PMC native route supports singleton full text only",
            )
        if request.identifier.kind is not IdentifierKind.PMCID:
            return (
                ScholarlyGatewayFailureCode.IDENTIFIER_KIND_UNSUPPORTED,
                "PMC native route requires a PMCID",
            )
    return None


def _encode_failure(exc: ScholarlyGatewayError) -> ScholarlyGatewayFailureCode:
    message = str(exc)
    if "URL is too large" in message:
        return ScholarlyGatewayFailureCode.REQUEST_TOO_LARGE
    if "filter" in message:
        return ScholarlyGatewayFailureCode.FILTER_UNSUPPORTED
    if "result limit" in message:
        return ScholarlyGatewayFailureCode.RESULT_LIMIT_UNSUPPORTED
    if "identifier" in message or "work ID" in message or "PMCID" in message:
        return ScholarlyGatewayFailureCode.IDENTIFIER_KIND_UNSUPPORTED
    if "operation" in message or "request type" in message:
        return ScholarlyGatewayFailureCode.OPERATION_UNSUPPORTED
    return ScholarlyGatewayFailureCode.REQUEST_INCONSISTENT


class SourceOwnedScholarlyGateway:
    """Closed OpenAlex/PMC adapter backed only by exact ``EgressGateway`` objects.

    The constructor accepts transport/configuration owners, not route data.
    Endpoint URLs, operation matrices, encoders, parsers, and documentation
    remain source-owned constants.  Omitting a source gateway creates an
    explicit typed-unavailable route rather than a hidden fallback.
    """

    def __init__(
        self,
        *,
        openalex_gateway: EgressGateway | None = None,
        pmc_gateway: EgressGateway | None = None,
    ) -> None:
        supplied = {
            ScholarlySource.OPENALEX: openalex_gateway,
            ScholarlySource.PMC: pmc_gateway,
        }
        configured = [gateway for gateway in supplied.values() if gateway is not None]
        if len(configured) > 1 and any(
            gateway.registry is not configured[0].registry for gateway in configured[1:]
        ):
            raise ScholarlyRouteConfigurationError(
                "configured scholarly routes must share one registry instance"
            )
        bindings: dict[ScholarlySource, _RouteBinding] = {}
        for source, gateway in supplied.items():
            if gateway is None:
                continue
            descriptor = _descriptor_for_policy(source, gateway.policy)
            _validate_route_gateway(descriptor, gateway)
            authority = gateway.capture_json_artifact(
                descriptor.authority_payload(
                    policy=gateway.policy,
                    network_expected=gateway.network_used,
                ),
                logical_type="scholarly_egress_route_authority",
                origin="source-owned native scholarly route authority",
                creator_role=Role.ORCHESTRATOR,
            )
            if authority is None:
                raise ScholarlyRouteConfigurationError(
                    "scholarly route authority could not be frozen"
                )
            bindings[source] = _RouteBinding(descriptor, gateway, authority)
        self._bindings = MappingProxyType(bindings)

    @property
    def configured_sources(self) -> tuple[ScholarlySource, ...]:
        return tuple(sorted(self._bindings, key=lambda value: value.value))

    def route_authority_artifact(
        self,
        source: ScholarlySource,
    ) -> ArtifactRecord | None:
        """Return the source-specific v2 route artifact, if configured."""

        normalized = source if isinstance(source, ScholarlySource) else ScholarlySource(source)
        binding = self._bindings.get(normalized)
        return None if binding is None else binding.authority_artifact

    def _wire_request(
        self,
        request: ScholarlyRequest | ScholarlySearchRequest | CitationPageRequest,
    ) -> _WireRequest:
        source = _request_source(request)
        binding = self._bindings.get(source)
        if binding is None:
            raise ScholarlyGatewayError("source-owned route is not configured")
        if source is ScholarlySource.OPENALEX:
            egress_request = _encode_openalex_request(request)
        elif source is ScholarlySource.PMC:
            egress_request = _encode_pmc_request(request)
            if binding.descriptor.adapter_id in {PMC_CONTENT_ADAPTER_ID, PMC_WIRE_ADAPTER_ID}:
                egress_request = replace(egress_request, adapter_id=binding.descriptor.adapter_id)
        else:  # pragma: no cover - the closed map has only two entries
            raise ScholarlyGatewayError("source-owned route is unsupported")
        return _WireRequest(
            egress_request,
            _projection(
                binding.descriptor,
                binding.authority_artifact.sha256,
                request,
                egress_request,
            ),
        )

    def project_request(
        self,
        request: ScholarlyRequest | ScholarlySearchRequest | CitationPageRequest,
        /,
    ) -> ScholarlyNativeRequestProjection:
        """Deterministically project one configured request without egress."""

        if type(request) not in {ScholarlyRequest, ScholarlySearchRequest, CitationPageRequest, ScholarlySearchPageRequest}:
            raise ScholarlyGatewayError("scholarly request must use an exact typed schema")
        source = _request_source(request)
        binding = self._bindings.get(source)
        if binding is None:
            raise ScholarlyGatewayError("source-owned route is not configured")
        failure = _preflight_failure(request, binding.descriptor)
        if failure is not None:
            raise ScholarlyGatewayError(failure[1])
        return self._wire_request(request).projection

    def _unavailable(
        self,
        request: ScholarlyRequest | ScholarlySearchRequest | CitationPageRequest,
        *,
        code: ScholarlyGatewayFailureCode,
        reason: str,
        status: RetrievalStatus = RetrievalStatus.UNAVAILABLE,
        binding: _RouteBinding | None = None,
    ) -> CapturedScholarlyResponse:
        route_hash = binding.authority_artifact.sha256 if binding is not None else None
        response_hash: str | None = None
        custody: tuple[str, ...] = (route_hash,) if route_hash is not None else ()
        if binding is not None:
            artifact = binding.gateway.capture_json_artifact(
                {
                    "schema_version": _native_schema(binding.descriptor),
                    "source": request.source.value,
                    "scholarly_request_id": request.request_id,
                    "retrieval_status": status.value,
                    "failure_code": code.value,
                    "failure_reason": reason,
                    "payload": None,
                    "raw_artifact_hash": None,
                    "response_receipt_artifact_hash": None,
                    "egress_request_id": None,
                    "route_authority_artifact_sha256": route_hash,
                    "wire_protocol": binding.descriptor.wire_protocol,
                    "full_text_status": FullTextStatus.UNAVAILABLE.value,
                    "license": None,
                    "network_used": False,
                    "external_validation": "UNTESTED",
                    "transport_authority": UNVERIFIED_TRANSPORT_AUTHORITY,
                    "scientific_evidence": False,
                    **(_pmc_diagnostic_fields(binding.descriptor)),
                },
                logical_type=_logical_response_type(request),
                origin="source-owned scholarly pre-egress terminal response",
                creator_role=Role.EVIDENCE_CURATOR,
                parents=(route_hash,),
            )
            if artifact is not None:
                response_hash = artifact.sha256
                custody = tuple(sorted({route_hash, response_hash}))
        return CapturedScholarlyResponse(
            source=request.source,
            request_id=request.request_id,
            status=status,
            payload=None,
            raw_artifact_hash=None,
            response_artifact_hash=response_hash,
            failure_reason=reason,
            license=None,
            full_text_status=FullTextStatus.UNAVAILABLE,
            failure_code=code,
            wire_protocol=binding.descriptor.wire_protocol if binding is not None else None,
            schema_version=_native_schema(binding.descriptor) if binding is not None else SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V2,
            route_authority_artifact_hash=route_hash,
            egress_request_id=None,
            network_used=False,
            external_validation="UNTESTED",
            transport_authority=UNVERIFIED_TRANSPORT_AUTHORITY,
            custody_artifact_hashes=custody,
            **_pmc_diagnostic_dto(binding.descriptor if binding else None),
        )

    def _capture_parsed(
        self,
        request: ScholarlyRequest | ScholarlySearchRequest | CitationPageRequest,
        binding: _RouteBinding,
        wire: _WireRequest,
        result: GatewayResult,
        parsed: _ParsedNativeResponse,
    ) -> CapturedScholarlyResponse:
        if result.request_id != wire.projection.egress_request_id:
            raise ScholarlyGatewayError("egress result is not bound to its request projection")
        if (
            result.request_artifact is None
            or result.raw_response_artifact is None
            or result.response_receipt_artifact is None
        ):
            raise ScholarlyGatewayError("native scholarly result lacks exact registry custody")
        raw_hash = result.raw_response_artifact.sha256
        receipt_hash = result.response_receipt_artifact.sha256
        payload = None if parsed.payload is None else dict(parsed.payload)
        normalized_value = {
            "schema_version": _native_schema(binding.descriptor),
            "source": request.source.value,
            "scholarly_request_id": request.request_id,
            "retrieval_status": parsed.status.value,
            "failure_code": (
                parsed.failure_code.value if parsed.failure_code is not None else None
            ),
            "failure_reason": parsed.failure_reason,
            "payload": payload,
            "raw_artifact_hash": raw_hash,
            "response_receipt_artifact_hash": receipt_hash,
            "egress_request_id": result.request_id,
            "request_projection": wire.projection.to_dict(),
            "route_authority_artifact_sha256": binding.authority_artifact.sha256,
            "wire_protocol": binding.descriptor.wire_protocol,
            "full_text_status": parsed.full_text_status.value,
            "license": parsed.license,
            "network_used": result.network_used,
            "external_validation": result.external_validation,
            "transport_authority": result.transport_authority,
            "scientific_evidence": False,
        }
        extra_parents = ()
        if binding.descriptor.adapter_id in {PMC_CONTENT_ADAPTER_ID, PMC_WIRE_ADAPTER_ID}:
            descriptor_artifact = result.content_decoding_artifact
            normalized_value["decoding_artifact_sha256"] = (
                descriptor_artifact.sha256 if descriptor_artifact else None
            )
            extra_parents = (descriptor_artifact.sha256,) if descriptor_artifact else ()
        authority_hash = None
        if binding.descriptor.adapter_id == PMC_WIRE_ADAPTER_ID:
            authority = result.transport_execution_authority_artifact
            if authority is None:
                raise ScholarlyGatewayError("PMC signed native capture authority absent")
            verified = require_audited_live_transport_execution(
                binding.gateway.registry, binding.gateway._authority_ledger,
                run_id=binding.gateway._authority_run_id,
                authority_artifact_sha256=authority.sha256,
                response_receipt_artifact_sha256=receipt_hash,
            )
            if (verified.authority_artifact.schema_version != PMC_WIRE_AUTHORITY_SCHEMA
                    or verified.raw_response_artifact.sha256 != raw_hash):
                raise ScholarlyGatewayError("PMC signed native capture authority differs")
            authority_hash = authority.sha256
            normalized_value.update(capture_authority="SIGNED_HTTP_CAPTURE",
                                    transport_execution_authority_artifact_sha256=authority_hash)
            extra_parents = (*extra_parents, authority_hash)
        normalized = binding.gateway.capture_json_artifact(
            normalized_value,
            logical_type=_logical_response_type(request),
            origin="strictly parsed source-owned native scholarly response",
            creator_role=Role.EVIDENCE_CURATOR,
            parents=(binding.authority_artifact.sha256, raw_hash, receipt_hash, *extra_parents),
        )
        if normalized is None:
            raise ScholarlyGatewayError("normalized scholarly response could not be frozen")
        custody_records = (
            binding.authority_artifact,
            result.request_artifact,
            *result.attempt_raw_response_artifacts,
            result.response_receipt_artifact,
            *((result.content_decoding_artifact,) if result.content_decoding_artifact else ()),
            *(
                (result.transport_execution_authority_artifact,)
                if result.transport_execution_authority_artifact is not None
                else ()
            ),
            normalized,
        )
        return CapturedScholarlyResponse(
            source=request.source,
            request_id=request.request_id,
            status=parsed.status,
            payload=payload,
            raw_artifact_hash=raw_hash,
            response_artifact_hash=normalized.sha256,
            failure_reason=parsed.failure_reason,
            license=parsed.license,
            full_text_status=parsed.full_text_status,
            failure_code=parsed.failure_code,
            wire_protocol=binding.descriptor.wire_protocol,
            schema_version=_native_schema(binding.descriptor),
            route_authority_artifact_hash=binding.authority_artifact.sha256,
            egress_request_id=result.request_id,
            network_used=result.network_used,
            external_validation=result.external_validation,
            transport_authority=result.transport_authority,
            custody_artifact_hashes=tuple(
                sorted({record.sha256 for record in custody_records})
            ),
            **({"capture_authority": "SIGNED_HTTP_CAPTURE",
                "transport_execution_authority_artifact_sha256": authority_hash} if authority_hash else {}),
        )

    def _capture_transport_failure(
        self,
        request: ScholarlyRequest | ScholarlySearchRequest | CitationPageRequest,
        binding: _RouteBinding,
        wire: _WireRequest,
        exc: ExternalBoundaryError,
    ) -> CapturedScholarlyResponse:
        records = tuple(
            value
            for value in getattr(exc, "artifacts", ())
            if isinstance(value, ArtifactRecord)
        )
        parents = tuple(
            dict.fromkeys((binding.authority_artifact.sha256, *(value.sha256 for value in records)))
        )
        raw_records = [value for value in records if value.logical_type == "external_response_raw"]
        raw_hash = raw_records[-1].sha256 if raw_records else None
        network_used = getattr(exc, "network_used", None)
        if not isinstance(network_used, bool):
            network_used = binding.gateway.network_used
        external_validation = getattr(exc, "external_validation", None)
        if not isinstance(external_validation, str) or not external_validation:
            external_validation = binding.gateway.external_validation
        transport_authority = getattr(exc, "transport_authority", None)
        if not isinstance(transport_authority, str) or not transport_authority:
            transport_authority = binding.gateway.transport_authority
        reason = f"controlled scholarly egress failed: {type(exc).__name__}"
        value = {
            "schema_version": _native_schema(binding.descriptor),
            "source": request.source.value,
            "scholarly_request_id": request.request_id,
            "retrieval_status": RetrievalStatus.FAILED.value,
            "failure_code": ScholarlyGatewayFailureCode.TRANSPORT_UNAVAILABLE.value,
            "failure_reason": reason,
            "payload": None,
            "raw_artifact_hash": raw_hash,
            "response_receipt_artifact_hash": None,
            "egress_request_id": wire.projection.egress_request_id,
            "request_projection": wire.projection.to_dict(),
            "route_authority_artifact_sha256": binding.authority_artifact.sha256,
            "wire_protocol": binding.descriptor.wire_protocol,
            "full_text_status": FullTextStatus.UNAVAILABLE.value,
            "license": None,
            "network_used": network_used,
            "external_validation": external_validation,
            "transport_authority": transport_authority,
            "scientific_evidence": False,
            **_pmc_diagnostic_fields(binding.descriptor),
        }
        normalized = binding.gateway.capture_json_artifact(
            value,
            logical_type=_logical_response_type(request),
            origin="source-owned scholarly transport terminal response",
            creator_role=Role.EVIDENCE_CURATOR,
            parents=parents,
        )
        response_hash = normalized.sha256 if normalized is not None else None
        custody = tuple(
            sorted(
                {
                    binding.authority_artifact.sha256,
                    *(value.sha256 for value in records),
                    *((response_hash,) if response_hash is not None else ()),
                }
            )
        )
        return CapturedScholarlyResponse(
            source=request.source,
            request_id=request.request_id,
            status=RetrievalStatus.FAILED,
            payload=None,
            raw_artifact_hash=raw_hash,
            response_artifact_hash=response_hash,
            failure_reason=reason,
            license=None,
            full_text_status=FullTextStatus.UNAVAILABLE,
            failure_code=ScholarlyGatewayFailureCode.TRANSPORT_UNAVAILABLE,
            wire_protocol=binding.descriptor.wire_protocol,
            schema_version=_native_schema(binding.descriptor),
            route_authority_artifact_hash=binding.authority_artifact.sha256,
            egress_request_id=wire.projection.egress_request_id,
            network_used=network_used,
            external_validation=external_validation,
            transport_authority=transport_authority,
            custody_artifact_hashes=custody,
            **_pmc_diagnostic_dto(binding.descriptor),
        )

    def fetch(
        self,
        request: ScholarlyRequest | ScholarlySearchRequest | CitationPageRequest,
        /,
    ) -> CapturedScholarlyResponse:
        """Execute one exact native route or return a typed unavailable capture."""

        if type(request) not in {ScholarlyRequest, ScholarlySearchRequest, CitationPageRequest, ScholarlySearchPageRequest}:
            raise ScholarlyGatewayError("scholarly request must use an exact typed schema")
        source = _request_source(request)
        descriptor = _CLOSED_ROUTES_BY_SOURCE.get(source)
        if descriptor is None:
            return self._unavailable(
                request,
                code=ScholarlyGatewayFailureCode.SOURCE_UNSUPPORTED,
                reason="source has no source-owned native route",
            )
        binding = self._bindings.get(source)
        if binding is None:
            return self._unavailable(
                request,
                code=ScholarlyGatewayFailureCode.ROUTE_UNCONFIGURED,
                reason="source-owned native route is not configured",
            )
        if not binding.gateway.policy.enabled:
            return self._unavailable(
                request,
                code=ScholarlyGatewayFailureCode.ROUTE_DISABLED,
                reason="source-owned native route is disabled",
                binding=binding,
            )
        descriptor = binding.descriptor
        failure = _preflight_failure(request, descriptor)
        if failure is not None:
            return self._unavailable(
                request,
                code=failure[0],
                reason=failure[1],
                binding=binding,
            )
        if (source is ScholarlySource.PMC and binding.gateway.network_used is True
                and binding.descriptor.adapter_id == PMC_WIRE_ADAPTER_ID):
            try:
                _require_pmc_wire_activation()
            except EgressPolicyError:
                return self._unavailable(request, code=ScholarlyGatewayFailureCode.TRANSPORT_POLICY_INCOMPATIBLE,
                                         reason="PMC versioned wire custody activation remains unavailable", binding=binding)
        if (source is ScholarlySource.PMC and binding.gateway.network_used is True
                and binding.descriptor.adapter_id != PMC_WIRE_ADAPTER_ID):
            return self._unavailable(
                request,
                code=(
                    ScholarlyGatewayFailureCode.TRANSPORT_POLICY_INCOMPATIBLE
                ),
                reason=(
                    "live PMC OAI dispatch is unavailable because the current "
                    "audited gateway cannot enforce both the Accept-Encoding "
                    "gzip/deflate header and source-global non-concurrent dispatch"
                ),
                binding=binding,
            )
        try:
            wire = self._wire_request(request)
        except ScholarlyGatewayError as exc:
            return self._unavailable(
                request,
                code=_encode_failure(exc),
                reason=str(exc),
                binding=binding,
            )
        request_parents = (binding.authority_artifact.sha256,)
        if type(request) is ScholarlySearchPageRequest:
            from .scientific_design import _require_registered_scholarly_search_page_request
            request_parents = _require_registered_scholarly_search_page_request(
                binding.gateway.registry, request=request,
                route_artifact_sha256=binding.authority_artifact.sha256,
            )
        try:
            result = binding.gateway.execute(
                wire.request,
                parent_artifacts=request_parents,
            )
        except (EgressDeniedError, EgressPolicyError, ExternalUnavailableError, TransportFailure) as exc:
            return self._capture_transport_failure(request, binding, wire, exc)
        parsed: _ParsedNativeResponse
        if result.retrieval_status != "CAPTURED":
            parsed = _http_failure(result.status_code)
        else:
            try:
                if source is ScholarlySource.OPENALEX:
                    parsed = _parse_openalex_response(binding.gateway, result, request)
                else:
                    assert isinstance(request, ScholarlyRequest)
                    if binding.descriptor.adapter_id in {PMC_CONTENT_ADAPTER_ID, PMC_WIRE_ADAPTER_ID}:
                        decoded_xml, decoding_value = require_pmc_content_cache(
                            binding.gateway.registry, result=result, policy=binding.gateway.policy,
                        )
                        parsed = _project_decoded_pmc_response(
                            decoded_xml, request,
                            wire_raw_artifact_sha256=result.raw_response_artifact.sha256,
                            decoded_xml_sha256=decoding_value["decoded_xml_sha256"],
                            decoding_descriptor_artifact_sha256=result.content_decoding_artifact.sha256,
                        )
                    else:
                        parsed = _parse_pmc_response(result, request)
            except (ExternalParseError, ScholarlyGatewayError, LiteratureError, TypeError, ValueError):
                parsed = _ParsedNativeResponse(
                    payload=None,
                    status=RetrievalStatus.MALFORMED,
                    failure_code=ScholarlyGatewayFailureCode.MALFORMED_RESPONSE,
                    failure_reason="captured scholarly response violates its native schema",
                    license=None,
                    full_text_status=FullTextStatus.UNAVAILABLE,
                )
        try:
            return self._capture_parsed(request, binding, wire, result, parsed)
        except (ScholarlyGatewayError, ExternalBoundaryError):
            return CapturedScholarlyResponse(
                source=request.source,
                request_id=request.request_id,
                status=RetrievalStatus.FAILED,
                payload=None,
                raw_artifact_hash=(
                    result.raw_response_artifact.sha256
                    if result.raw_response_artifact is not None
                    else None
                ),
                response_artifact_hash=None,
                failure_reason="captured scholarly response could not be frozen",
                license=None,
                full_text_status=FullTextStatus.UNAVAILABLE,
                failure_code=ScholarlyGatewayFailureCode.CAPTURE_UNAVAILABLE,
                wire_protocol=descriptor.wire_protocol,
                schema_version=_native_schema(binding.descriptor),
                route_authority_artifact_hash=binding.authority_artifact.sha256,
                egress_request_id=result.request_id,
                network_used=result.network_used,
                external_validation=result.external_validation,
                transport_authority=result.transport_authority,
                custody_artifact_hashes=tuple(
                    sorted(
                        {
                            record.sha256
                            for record in (
                                binding.authority_artifact,
                                result.request_artifact,
                                *result.attempt_raw_response_artifacts,
                                result.raw_response_artifact,
                                result.response_receipt_artifact,
                                result.transport_execution_authority_artifact,
                            )
                            if record is not None
                        }
                    )
                ),
                **_pmc_diagnostic_dto(binding.descriptor),
            )


def _require_replay_artifact(
    registry: ArtifactRegistry,
    digest: str,
    *,
    label: str,
    logical_type: str,
    creator_role: Role,
    schema_version: str,
    mime_type: str,
    origin: str,
) -> ArtifactRecord:
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise ScholarlyGatewayError(f"{label} hash is invalid")
    try:
        registry.verify(digest, raise_on_error=True)
        record = registry.get_metadata(digest)
    except (ArtifactError, ValidationError) as exc:
        raise ScholarlyGatewayError(f"{label} is absent or corrupt") from exc
    if (
        record.sha256 != digest
        or record.logical_type != logical_type
        or record.creator_role is not creator_role
        or record.schema_version != schema_version
        or record.mime_type != mime_type
        or record.origin != origin
        or record.creation_command != ("scientist-one", "controlled-egress")
        or record.validation_result != "PASS"
        or record.frozen is not True
        or record.record_hash is None
    ):
        raise ScholarlyGatewayError(f"{label} metadata is not exact frozen custody")
    return record


def _load_replay_json(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
    *,
    label: str,
    maximum_bytes: int = 64 * 1024 * 1024,
) -> Mapping[str, Any]:
    try:
        content = registry.get_bytes(record.sha256)
        value = safe_json_loads(
            content,
            max_bytes=maximum_bytes,
            max_depth=64,
            max_items=250_000,
        )
    except (ArtifactError, UnsafeSerializationError) as exc:
        raise ScholarlyGatewayError(f"{label} is not bounded JSON") from exc
    if (
        not isinstance(value, Mapping)
        or content != canonical_json_bytes(value) + b"\n"
    ):
        raise ScholarlyGatewayError(f"{label} is not exact canonical JSON")
    return value


def _replay_numeric(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise ScholarlyGatewayError(f"{label} is not a finite number")
    return float(value)


def _require_native_route_authority(
    registry: ArtifactRegistry,
    *,
    route_artifact_sha256: str,
    expected_source: ScholarlySource,
) -> tuple[ArtifactRecord, ScholarlyRouteDescriptor, EgressPolicy, bool]:
    route_record = _require_replay_artifact(
        registry,
        route_artifact_sha256,
        label="scholarly v2 route authority",
        logical_type="scholarly_egress_route_authority",
        creator_role=Role.ORCHESTRATOR,
        schema_version="1.0",
        mime_type="application/json",
        origin="source-owned native scholarly route authority",
    )
    if route_record.parent_artifacts:
        raise ScholarlyGatewayError("scholarly v2 route authority must be parentless")
    route = _load_replay_json(
        registry,
        route_record,
        label="scholarly v2 route authority",
    )
    descriptor = _CLOSED_ROUTES_BY_SOURCE.get(expected_source)
    network_expected = route.get("network_expected")
    policy_claim = route.get("egress_policy")
    policy_hash = route.get("egress_policy_sha256")
    if (
        descriptor is None
        or route.get("schema_version")
        != SCHOLARLY_EGRESS_ROUTE_AUTHORITY_SCHEMA_V2
        or route.get("source") != expected_source.value
        or not isinstance(network_expected, bool)
        or not isinstance(policy_hash, str)
        or _SHA256_RE.fullmatch(policy_hash) is None
        or not isinstance(policy_claim, Mapping)
        or hashlib.sha256(canonical_json_bytes(policy_claim)).hexdigest()
        != policy_hash
    ):
        raise ScholarlyGatewayError("scholarly v2 route authority is malformed")
    policy = _policy_from_claim(policy_claim)
    descriptor = _descriptor_for_policy(expected_source, policy)
    try:
        _validate_route_policy(
            descriptor,
            policy,
            network_expected=network_expected,
        )
    except ScholarlyRouteConfigurationError as exc:
        raise ScholarlyGatewayError(
            "scholarly v2 route policy is not source-owned"
        ) from exc
    if (
        route != descriptor.authority_payload(
            policy=policy,
            network_expected=network_expected,
        )
        or (
            expected_source is ScholarlySource.PMC
            and network_expected is True
            and descriptor.adapter_id != PMC_WIRE_ADAPTER_ID
        )
    ):
        raise ScholarlyGatewayError(
            "scholarly v2 route authority differs from its closed contract"
        )
    if descriptor.adapter_id == PMC_WIRE_ADAPTER_ID and network_expected:
        _require_pmc_wire_activation()
    return route_record, descriptor, policy, network_expected


def _require_native_request_artifact(
    registry: ArtifactRegistry,
    *,
    request_artifact_sha256: str,
    route_artifact_sha256: str,
    expected_request: EgressRequest,
    expected_policy: EgressPolicy,
) -> ArtifactRecord:
    return _require_native_request_artifact_parents(
        registry, request_artifact_sha256=request_artifact_sha256,
        expected_request=expected_request, expected_policy=expected_policy,
        expected_parents=(route_artifact_sha256,),
    )


def _require_native_request_artifact_parents(
    registry: ArtifactRegistry, *, request_artifact_sha256: str,
    expected_request: EgressRequest, expected_policy: EgressPolicy,
    expected_parents: tuple[str, ...],
) -> ArtifactRecord:
    request_record = _require_replay_artifact(
        registry,
        request_artifact_sha256,
        label="scholarly v2 external request",
        logical_type="external_request",
        creator_role=Role.ORCHESTRATOR,
        schema_version=EGRESS_REQUEST_SCHEMA,
        mime_type="application/json",
        origin="controlled external egress request intent",
    )
    request_value = _load_replay_json(
        registry,
        request_record,
        label="scholarly v2 external request",
    )
    fields = {
        "adapter_id",
        "body_sha256",
        "body_size",
        "content_type",
        "credential_env_name",
        "credential_present",
        "egress_budget",
        "headers",
        "kind",
        "method",
        "parent_artifacts",
        "policy_claim_sha256",
        "policy_id",
        "request_id",
        "schema_version",
        "scientific_evidence",
        "url",
    }
    policy_hash = hashlib.sha256(
        canonical_json_bytes(_egress_policy_claim(expected_policy))
    ).hexdigest()
    expected_headers = [list(value) for value in expected_request.headers]
    expected_body_hash = hashlib.sha256(expected_request.body).hexdigest()
    if (
        set(request_value) != fields
        or request_value.get("schema_version") != EGRESS_REQUEST_SCHEMA
        or request_value.get("kind") != "REDACTED_EXTERNAL_REQUEST"
        or request_value.get("request_id") != expected_request.request_id
        or request_value.get("policy_id") != expected_policy.policy_id
        or request_value.get("policy_claim_sha256") != policy_hash
        or request_value.get("adapter_id") != expected_request.adapter_id
        or request_value.get("method") != expected_request.method
        or request_value.get("url") != expected_request.url
        or request_value.get("headers") != expected_headers
        or request_value.get("body_sha256") != expected_body_hash
        or request_value.get("body_size") != len(expected_request.body)
        or request_value.get("content_type") != expected_request.content_type
        or request_value.get("credential_env_name") is not None
        or request_value.get("credential_present") is not False
        or request_value.get("parent_artifacts") != list(expected_parents)
        or request_value.get("scientific_evidence") is not False
        or request_value.get("egress_budget")
        != _egress_budget_policy_claim(expected_policy)
        or request_record.parent_artifacts != expected_parents
    ):
        raise ScholarlyGatewayError(
            "scholarly v2 external request differs from its native projection"
        )
    return request_record


def _require_native_attempts(
    registry: ArtifactRegistry,
    *,
    attempts: object,
    policy: EgressPolicy,
    request_body_size: int,
) -> tuple[tuple[ArtifactRecord, ...], int, int, float]:
    fields = {
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
    if (
        not isinstance(attempts, list)
        or not attempts
        or len(attempts) > policy.maximum_attempts
    ):
        raise ScholarlyGatewayError("scholarly v2 response attempts are malformed")
    raw_records: list[ArtifactRecord] = []
    seen_raw: set[str] = set()
    request_bytes = 0
    response_bytes = 0
    prior_completed = 0.0
    prior_delay = 0.0
    for index, attempt in enumerate(attempts, start=1):
        if not isinstance(attempt, Mapping) or set(attempt) != fields:
            raise ScholarlyGatewayError("scholarly v2 response attempt is malformed")
        started = _replay_numeric(
            attempt.get("started_offset_seconds"),
            "scholarly attempt start",
        )
        completed = _replay_numeric(
            attempt.get("completed_offset_seconds"),
            "scholarly attempt completion",
        )
        if (
            attempt.get("schema_version") != EGRESS_ATTEMPT_SCHEMA
            or attempt.get("attempt") != index
            or started + 1e-9 < prior_completed + prior_delay
            or completed < started
            or completed >= policy.timeout_seconds
            or attempt.get("request_body_bytes") != request_body_size
        ):
            raise ScholarlyGatewayError("scholarly v2 attempt ordering is invalid")
        if request_bytes + response_bytes + request_body_size >= policy.maximum_total_bytes:
            raise ScholarlyGatewayError(
                "scholarly v2 attempt cannot fit another response"
            )
        request_bytes += request_body_size
        status = attempt.get("status")
        response_body_bytes = attempt.get("response_body_bytes")
        if (
            isinstance(response_body_bytes, bool)
            or not isinstance(response_body_bytes, int)
            or response_body_bytes < 0
            or response_body_bytes
            > min(
                policy.maximum_response_bytes,
                policy.maximum_total_bytes - request_bytes - response_bytes,
            )
        ):
            raise ScholarlyGatewayError("scholarly v2 attempt byte count is invalid")
        response_bytes += response_body_bytes
        raw_hash = attempt.get("raw_response_record_sha256")
        if status == "RESPONSE":
            body_size = attempt.get("body_size")
            body_hash = attempt.get("body_sha256")
            status_code = attempt.get("status_code")
            if (
                isinstance(status_code, bool)
                or not isinstance(status_code, int)
                or not 100 <= status_code <= 599
                or isinstance(body_size, bool)
                or not isinstance(body_size, int)
                or body_size != response_body_bytes
                or not isinstance(body_hash, str)
                or _SHA256_RE.fullmatch(body_hash) is None
                or not isinstance(raw_hash, str)
                or _SHA256_RE.fullmatch(raw_hash) is None
            ):
                raise ScholarlyGatewayError("scholarly v2 response attempt is malformed")
            raw_record = _require_replay_artifact(
                registry,
                raw_hash,
                label="scholarly v2 attempt raw response",
                logical_type="external_response_raw",
                creator_role=Role.EVIDENCE_CURATOR,
                schema_version="1.0",
                mime_type="application/octet-stream",
                origin="controlled external egress raw response",
            )
            raw_bytes = registry.get_bytes(raw_hash)
            if (
                raw_record.parent_artifacts
                or len(raw_bytes) != body_size
                or hashlib.sha256(raw_bytes).hexdigest() != body_hash
                or raw_hash != body_hash
            ):
                raise ScholarlyGatewayError(
                    "scholarly v2 attempt raw response is inconsistent"
                )
            if raw_hash not in seen_raw:
                seen_raw.add(raw_hash)
                raw_records.append(raw_record)
        elif status == "TRANSPORT_FAILURE":
            if any(
                attempt.get(name) is not None
                for name in (
                    "status_code",
                    "body_sha256",
                    "body_size",
                    "raw_response_record_sha256",
                )
            ):
                raise ScholarlyGatewayError(
                    "scholarly v2 transport-failure attempt is malformed"
                )
        else:
            raise ScholarlyGatewayError("scholarly v2 attempt status is invalid")
        if attempt.get("cumulative_bytes") != request_bytes + response_bytes:
            raise ScholarlyGatewayError("scholarly v2 attempt accounting is invalid")
        is_final = index == len(attempts)
        delay = attempt.get("retry_delay_seconds")
        if is_final:
            if delay is not None:
                raise ScholarlyGatewayError("terminal scholarly attempt cannot retry")
            prior_delay = 0.0
        else:
            retry_delay = _replay_numeric(delay, "scholarly retry delay")
            floor = min(
                policy.backoff_maximum_seconds,
                policy.backoff_initial_seconds * (2 ** max(0, index - 1)),
            )
            if (
                retry_delay + 1e-9 < floor
                or retry_delay > policy.backoff_maximum_seconds + 1e-9
                or (
                    status == "RESPONSE"
                    and attempt.get("status_code") not in policy.retry_statuses
                )
            ):
                raise ScholarlyGatewayError("scholarly v2 retry policy is invalid")
            prior_delay = retry_delay
        prior_completed = completed
    return tuple(raw_records), request_bytes, response_bytes, prior_completed


class _NativeCaptureReplayProfile(Enum):
    AVAILABLE_ONLY = "available-only"
    CAPTURED_OPENALEX_SEARCH = "captured-openalex-search"
    CAPTURED_OPENALEX_CURSOR_SEARCH = "captured-openalex-cursor-search"


def require_captured_pmc_wire_response(
    registry, ledger, *, run_id, request, raw_artifact_sha256, response_artifact_sha256,
):
    """Replay signed PMC v5 HTTP outcomes, including unusable captured responses.

    The existing authority owner checks the key and exact run-ledger ancestry.
    This is not a diagnostic promotion or a scientific/full-text authority.
    """
    _require_pmc_wire_activation()
    if type(request) is not ScholarlyRequest or request.source is not ScholarlySource.PMC:
        raise ScholarlyGatewayError("PMC wire replay requires exact scholarly request")
    record = _require_replay_artifact(
        registry, response_artifact_sha256, label="PMC signed native response",
        logical_type=_logical_response_type(request), creator_role=Role.EVIDENCE_CURATOR,
        schema_version="1.0", mime_type="application/json",
        origin="strictly parsed source-owned native scholarly response",
    )
    value = _load_replay_json(registry, record, label="PMC signed native response")
    fields = {"schema_version", "source", "scholarly_request_id", "retrieval_status", "failure_code",
              "failure_reason", "payload", "raw_artifact_hash", "response_receipt_artifact_hash",
              "egress_request_id", "request_projection", "route_authority_artifact_sha256", "wire_protocol",
              "full_text_status", "license", "network_used", "external_validation", "transport_authority",
              "scientific_evidence", "decoding_artifact_sha256", "capture_authority",
              "transport_execution_authority_artifact_sha256"}
    if (set(value) != fields or value.get("schema_version") != SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V5
            or value.get("capture_authority") != "SIGNED_HTTP_CAPTURE"
            or value.get("source") != ScholarlySource.PMC.value or value.get("scholarly_request_id") != request.request_id
            or value.get("wire_protocol") != PMC_OAI_JATS_WIRE_PROTOCOL_V3 or value.get("scientific_evidence") is not False
            or value.get("raw_artifact_hash") != raw_artifact_sha256):
        raise ScholarlyGatewayError("PMC signed native response grammar differs")
    route, descriptor, policy, network = _require_native_route_authority(
        registry, route_artifact_sha256=value["route_authority_artifact_sha256"], expected_source=ScholarlySource.PMC,
    )
    if descriptor != _PMC_WIRE_ROUTE or network is not True or _preflight_failure(request, descriptor) is not None:
        raise ScholarlyGatewayError("PMC signed native route differs")
    authority = require_audited_live_transport_execution(
        registry, ledger, run_id=run_id,
        authority_artifact_sha256=value["transport_execution_authority_artifact_sha256"],
        response_receipt_artifact_sha256=value["response_receipt_artifact_hash"],
    )
    receipt = _load_replay_json(registry, authority.response_receipt_artifact, label="PMC signed receipt")
    expected_request = replace(_encode_pmc_request(request), adapter_id=PMC_WIRE_ADAPTER_ID)
    request_record = _require_native_request_artifact(
        registry, request_artifact_sha256=authority.request_artifact.sha256,
        route_artifact_sha256=route.sha256, expected_request=expected_request, expected_policy=policy,
    )
    projection = _projection(descriptor, route.sha256, request, expected_request)
    decoding_hash = receipt.get("decoding_artifact_sha256")
    if (authority.authority_artifact.schema_version != PMC_WIRE_AUTHORITY_SCHEMA
            or authority.raw_response_artifact.sha256 != raw_artifact_sha256
            or receipt.get("schema_version") != PMC_WIRE_RESPONSE_SCHEMA
            or receipt.get("policy_claim_sha256") != hashlib.sha256(canonical_json_bytes(_egress_policy_claim(policy))).hexdigest()
            or value["request_projection"] != projection.to_dict()
            or value["egress_request_id"] != expected_request.request_id
            or value["decoding_artifact_sha256"] != decoding_hash
            or any(value[key] != receipt[key] for key in ("network_used", "external_validation", "transport_authority"))
            or record.parent_artifacts != (route.sha256, raw_artifact_sha256, authority.response_receipt_artifact.sha256,
                                            *((decoding_hash,) if decoding_hash else ()), authority.authority_artifact.sha256)):
        raise ScholarlyGatewayError("PMC signed native custody differs")
    if not 200 <= receipt["status_code"] <= 299:
        parsed = _http_failure(receipt["status_code"])
    else:
        decoding_record, decoded_xml, decoding_value = require_pmc_content_decoding(
            registry, descriptor_sha256=decoding_hash, receipt=receipt, policy=policy,
        )
        try:
            parsed = _project_decoded_pmc_response(
                decoded_xml, request, wire_raw_artifact_sha256=raw_artifact_sha256,
                decoded_xml_sha256=decoding_value["decoded_xml_sha256"],
                decoding_descriptor_artifact_sha256=decoding_record.sha256,
            )
        except (ExternalParseError, ScholarlyGatewayError, LiteratureError, TypeError, ValueError):
            parsed = _ParsedNativeResponse(payload=None, status=RetrievalStatus.MALFORMED,
                failure_code=ScholarlyGatewayFailureCode.MALFORMED_RESPONSE,
                failure_reason="captured scholarly response violates its native schema",
                license=None, full_text_status=FullTextStatus.UNAVAILABLE)
    if (value["retrieval_status"] != parsed.status.value
            or value["failure_code"] != (parsed.failure_code.value if parsed.failure_code else None)
            or value["failure_reason"] != parsed.failure_reason
            or value["payload"] != (dict(parsed.payload) if parsed.payload is not None else None)
            or value["license"] != parsed.license or value["full_text_status"] != parsed.full_text_status.value):
        raise ScholarlyGatewayError("PMC signed native outcome differs from parser replay")
    envelope = GatewayEnvelope(source=ScholarlySource.PMC, request_id=request.request_id,
        status=parsed.status, payload=value["payload"], raw_artifact_hash=raw_artifact_sha256,
        response_artifact_hash=response_artifact_sha256, failure_reason=parsed.failure_reason,
        license=parsed.license, full_text_status=parsed.full_text_status)
    ancestors = {record.sha256, route.sha256, request_record.sha256, authority.authority_artifact.sha256,
                 authority.response_receipt_artifact.sha256, *authority.response_receipt_artifact.parent_artifacts}
    raw = registry.get_bytes(raw_artifact_sha256)
    return ReplayedScholarlyNativeCapture(
        envelope=envelope, artifact_hashes=tuple(sorted(ancestors)), raw_artifact_hash=raw_artifact_sha256,
        response_artifact_hash=response_artifact_sha256,
        response_receipt_artifact_hash=authority.response_receipt_artifact.sha256,
        request_artifact_hash=request_record.sha256, route_artifact_hash=route.sha256,
        request_body_sha256=hashlib.sha256(expected_request.body).hexdigest(), request_body_size=len(expected_request.body),
        response_body_sha256=hashlib.sha256(raw).hexdigest(), response_body_size=len(raw),
        network_used=True, external_validation=value["external_validation"], transport_authority=value["transport_authority"],
    )


def require_available_scholarly_native_capture(
    registry: ArtifactRegistry,
    *,
    request: ScholarlyRequest | ScholarlySearchRequest | CitationPageRequest,
    raw_artifact_sha256: str,
    response_artifact_sha256: str,
    ledger=None,
    run_id=None,
) -> ReplayedScholarlyNativeCapture:
    """Replay available native-v2 or unsigned PMC-v3 custody without science."""

    if ledger is not None or run_id is not None:
        replayed = require_captured_pmc_wire_response(
            registry, ledger, run_id=run_id, request=request, raw_artifact_sha256=raw_artifact_sha256,
            response_artifact_sha256=response_artifact_sha256,
        )
        if replayed.envelope.status is not RetrievalStatus.AVAILABLE:
            raise ScholarlyGatewayError("PMC signed capture is not available full text")
        return replayed
    return _require_scholarly_native_capture(
        registry,
        request=request,
        raw_artifact_sha256=raw_artifact_sha256,
        response_artifact_sha256=response_artifact_sha256,
        profile=_NativeCaptureReplayProfile.AVAILABLE_ONLY,
    )


def require_captured_scholarly_search_response(
    registry: ArtifactRegistry,
    *,
    request: ScholarlySearchRequest,
    raw_artifact_sha256: str,
    response_artifact_sha256: str,
) -> ReplayedScholarlyNativeCapture:
    """Replay one complete captured OpenAlex search HTTP response.

    HTTP refusals and parser failures remain their captured outcomes.  Missing
    custody, terminal transport failures, and pre-egress refusals are outside
    this owner.  A bounded page, including zero hits, proves no exhaustion,
    scholarly insufficiency, fallback permission, or scientific authority.
    """

    return _require_scholarly_native_capture(
        registry,
        request=request,
        raw_artifact_sha256=raw_artifact_sha256,
        response_artifact_sha256=response_artifact_sha256,
        profile=_NativeCaptureReplayProfile.CAPTURED_OPENALEX_SEARCH,
    )


def require_captured_scholarly_search_page_response(
    registry: ArtifactRegistry, *, request: ScholarlySearchPageRequest,
    raw_artifact_sha256: str, response_artifact_sha256: str,
) -> ReplayedScholarlyNativeCapture:
    """Replay complete native-v4 cursor HTTP custody, not prefix completion."""
    return _require_scholarly_native_capture(
        registry, request=request, raw_artifact_sha256=raw_artifact_sha256,
        response_artifact_sha256=response_artifact_sha256,
        profile=_NativeCaptureReplayProfile.CAPTURED_OPENALEX_CURSOR_SEARCH,
    )


def _replay_captured_openalex_search_outcome(
    raw_bytes: bytes,
    request: ScholarlySearchRequest,
    policy: EgressPolicy,
    status_code: int,
) -> _ParsedNativeResponse:
    if not 200 <= status_code <= 299:
        return _http_failure(status_code)
    try:
        payload = safe_json_loads(
            raw_bytes,
            max_bytes=policy.maximum_response_bytes,
            max_depth=policy.maximum_json_depth,
            max_items=policy.maximum_json_items,
        )
        return _project_openalex_response(payload, request)
    except (UnsafeSerializationError, ScholarlyGatewayError, LiteratureError, TypeError, ValueError):
        # Match fetch's strict-JSON/native-parser outcome, never stored labels.
        return _ParsedNativeResponse(
            payload=None,
            status=RetrievalStatus.MALFORMED,
            failure_code=ScholarlyGatewayFailureCode.MALFORMED_RESPONSE,
            failure_reason="captured scholarly response violates its native schema",
            license=None,
            full_text_status=FullTextStatus.UNAVAILABLE,
        )


def _require_scholarly_native_capture(
    registry: ArtifactRegistry,
    *,
    request: ScholarlyRequest | ScholarlySearchRequest | CitationPageRequest,
    raw_artifact_sha256: str,
    response_artifact_sha256: str,
    profile: _NativeCaptureReplayProfile,
) -> ReplayedScholarlyNativeCapture:
    """Replay native-v2 or explicit unsigned PMC-v3 custody without granting science.

    Legacy fixture schemas are deliberately outside this owner.  Callers must
    dispatch those to the historical v1 replay path and may not reinterpret a
    v1 capture as a v2 native route.
    """

    if type(profile) is not _NativeCaptureReplayProfile:
        raise ScholarlyGatewayError("native scholarly replay profile is invalid")
    cursor_profile = profile is _NativeCaptureReplayProfile.CAPTURED_OPENALEX_CURSOR_SEARCH
    if cursor_profile != (type(request) is ScholarlySearchPageRequest):
        raise ScholarlyGatewayError("native replay request and cursor profiles differ")
    if cursor_profile and request.source is not ScholarlySource.OPENALEX:
        raise ScholarlyGatewayError("cursor capture replay requires OpenAlex search")
    if profile is _NativeCaptureReplayProfile.CAPTURED_OPENALEX_SEARCH and (
        type(request) is not ScholarlySearchRequest
        or request.source is not ScholarlySource.OPENALEX
    ):
        raise ScholarlyGatewayError("captured search replay requires exact OpenAlex search")
    if not isinstance(registry, ArtifactRegistry):
        raise ScholarlyGatewayError("native scholarly replay requires ArtifactRegistry")
    if type(request) not in {
        ScholarlyRequest,
        ScholarlySearchRequest,
        CitationPageRequest,
        ScholarlySearchPageRequest,
    }:
        raise ScholarlyGatewayError("native scholarly replay requires an exact request")
    source = _request_source(request)
    descriptor = _OPENALEX_CURSOR_ROUTE if cursor_profile else _CLOSED_ROUTES_BY_SOURCE.get(source)
    if descriptor is None or _preflight_failure(request, descriptor) is not None:
        raise ScholarlyGatewayError("native scholarly replay request is unsupported")
    response_record = _require_replay_artifact(
        registry,
        response_artifact_sha256,
        label="scholarly native normalized response",
        logical_type=_logical_response_type(request),
        creator_role=Role.EVIDENCE_CURATOR,
        schema_version="1.0",
        mime_type="application/json",
        origin="strictly parsed source-owned native scholarly response",
    )
    response = _load_replay_json(
        registry,
        response_record,
        label="scholarly native normalized response",
    )
    response_fields = {
        "schema_version",
        "source",
        "scholarly_request_id",
        "retrieval_status",
        "failure_code",
        "failure_reason",
        "payload",
        "raw_artifact_hash",
        "response_receipt_artifact_hash",
        "egress_request_id",
        "request_projection",
        "route_authority_artifact_sha256",
        "wire_protocol",
        "full_text_status",
        "license",
        "network_used",
        "external_validation",
        "transport_authority",
        "scientific_evidence",
    }
    content_profile = response.get("schema_version") == SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V3
    if cursor_profile != (response.get("schema_version") == SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V4):
        raise ScholarlyGatewayError("native response and cursor profiles differ")
    if profile is _NativeCaptureReplayProfile.CAPTURED_OPENALEX_SEARCH and (
        response.get("schema_version") != SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V2
    ):
        raise ScholarlyGatewayError("captured search replay requires native-v2 response")
    response_schema = (SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V4 if cursor_profile else
                       SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V3 if content_profile else SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V2)
    receipt_schema = EGRESS_PMC_RESPONSE_SCHEMA_V3 if content_profile else EGRESS_RESPONSE_RECEIPT_SCHEMA
    decoding_hash = response.get("decoding_artifact_sha256")
    if content_profile:
        response_fields.add("decoding_artifact_sha256")
        if source is not ScholarlySource.PMC or type(decoding_hash) is not str or _SHA256_RE.fullmatch(decoding_hash) is None:
            raise ScholarlyGatewayError("PMC v3 descriptor identity is malformed")
    route_hash = response.get("route_authority_artifact_sha256")
    receipt_hash = response.get("response_receipt_artifact_hash")
    if (
        set(response) != response_fields
        or response.get("schema_version") != response_schema
        or response.get("source") != source.value
        or response.get("scholarly_request_id") != _request_id(request)
        or (
            profile is _NativeCaptureReplayProfile.AVAILABLE_ONLY
            and (
                response.get("retrieval_status") != RetrievalStatus.AVAILABLE.value
                or response.get("failure_code") is not None
                or response.get("failure_reason") is not None
                or not isinstance(response.get("payload"), Mapping)
            )
        )
        or response.get("raw_artifact_hash") != raw_artifact_sha256
        or not isinstance(route_hash, str)
        or _SHA256_RE.fullmatch(route_hash) is None
        or not isinstance(receipt_hash, str)
        or _SHA256_RE.fullmatch(receipt_hash) is None
        or response.get("scientific_evidence") is not False
        or not isinstance(response.get("network_used"), bool)
    ):
        raise ScholarlyGatewayError("scholarly native normalized response is malformed")
    route_record, descriptor, policy, network_expected = (
        _require_native_route_authority(
            registry,
            route_artifact_sha256=route_hash,
            expected_source=source,
        )
    )
    if content_profile != (descriptor.adapter_id == PMC_CONTENT_ADAPTER_ID):
        raise ScholarlyGatewayError("native capture mixes source profiles")
    if cursor_profile != (descriptor.adapter_id == _OPENALEX_CURSOR_ADAPTER_ID):
        raise ScholarlyGatewayError("native capture mixes cursor profiles")
    if response_record.parent_artifacts != (
        route_hash,
        raw_artifact_sha256,
        receipt_hash,
        *((decoding_hash,) if content_profile else ()),
    ):
        raise ScholarlyGatewayError(
            "scholarly native response has incorrect route/raw/receipt parents"
        )
    raw_record = _require_replay_artifact(
        registry,
        raw_artifact_sha256,
        label="scholarly native raw response",
        logical_type="external_response_raw",
        creator_role=Role.EVIDENCE_CURATOR,
        schema_version="1.0",
        mime_type="application/octet-stream",
        origin="controlled external egress raw response",
    )
    if raw_record.parent_artifacts:
        raise ScholarlyGatewayError("scholarly native raw response must be parentless")
    raw_bytes = registry.get_bytes(raw_artifact_sha256)
    if hashlib.sha256(raw_bytes).hexdigest() != raw_artifact_sha256:
        raise ScholarlyGatewayError("scholarly native raw bytes changed")
    receipt_record = _require_replay_artifact(
        registry,
        receipt_hash,
        label="scholarly native response receipt",
        logical_type="external_response_receipt",
        creator_role=Role.EVIDENCE_CURATOR,
        schema_version=receipt_schema,
        mime_type="application/json",
        origin="controlled external egress response receipt",
    )
    receipt = _load_replay_json(
        registry,
        receipt_record,
        label="scholarly native response receipt",
    )
    receipt_fields = {
        "attempts",
        "body_size",
        "captured_at",
        "content_type",
        "egress_budget",
        "external_validation",
        "headers",
        "kind",
        "network_used",
        "policy_claim_sha256",
        "raw_response_record_sha256",
        "raw_response_sha256",
        "request_artifact_sha256",
        "request_id",
        "schema_version",
        "scientific_evidence",
        "status_code",
        "transport_authority",
    }
    if content_profile:
        receipt_fields.update({"content_profile", "content_coding", "decoding_artifact_sha256", "decoding_artifact_record_hash"})
    request_hash = receipt.get("request_artifact_sha256")
    transport_authority = receipt.get("transport_authority")
    external_validation = receipt.get("external_validation")
    status_code = receipt.get("status_code")
    if (
        set(receipt) != receipt_fields
        or receipt.get("schema_version") != receipt_schema
        or receipt.get("kind") != "EXTERNAL_RESPONSE_RECEIPT"
        or not isinstance(request_hash, str)
        or _SHA256_RE.fullmatch(request_hash) is None
        or receipt.get("request_id") != response.get("egress_request_id")
        or receipt.get("raw_response_record_sha256") != raw_artifact_sha256
        or receipt.get("raw_response_sha256") != raw_artifact_sha256
        or receipt.get("body_size") != len(raw_bytes)
        or isinstance(status_code, bool)
        or not isinstance(status_code, int)
        or not 100 <= status_code <= 599
        or (
            profile in {_NativeCaptureReplayProfile.CAPTURED_OPENALEX_SEARCH,
                        _NativeCaptureReplayProfile.CAPTURED_OPENALEX_CURSOR_SEARCH}
            and 300 <= status_code <= 399
        )
        or (
            profile is _NativeCaptureReplayProfile.AVAILABLE_ONLY
            and not 200 <= status_code <= 299
        )
        or receipt.get("content_type")
        not in descriptor.allowed_response_content_types
        or not isinstance(receipt.get("headers"), Mapping)
        or any(
            key not in policy.recorded_response_headers
            or not isinstance(value, str)
            for key, value in receipt["headers"].items()
        )
        or receipt.get("network_used") != response.get("network_used")
        or receipt.get("network_used") != network_expected
        or receipt.get("external_validation") != response.get("external_validation")
        or receipt.get("transport_authority") != response.get("transport_authority")
        or receipt.get("scientific_evidence") is not False
        or not isinstance(receipt.get("captured_at"), str)
        or not receipt["captured_at"]
        or transport_authority
        not in {
            AUDITED_LIVE_TRANSPORT_AUTHORITY,
            UNVERIFIED_TRANSPORT_AUTHORITY,
        }
        or (
            transport_authority == AUDITED_LIVE_TRANSPORT_AUTHORITY
            and (
                network_expected is not True
                or external_validation
                != "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
            )
        )
        or (
            transport_authority == UNVERIFIED_TRANSPORT_AUTHORITY
            and external_validation != "UNTESTED"
        )
    ):
        raise ScholarlyGatewayError("scholarly native response receipt is malformed")
    expected_request = (
        _encode_openalex_request(request)
        if source is ScholarlySource.OPENALEX
        else _encode_pmc_request(request)
    )
    if content_profile:
        expected_request = replace(expected_request, adapter_id=PMC_CONTENT_ADAPTER_ID)
    inspected_cursor_artifacts = ()
    if cursor_profile:
        from .scientific_design import _require_scholarly_search_page_plan_binding
        _, _, inspected_cursor_artifacts = _require_scholarly_search_page_plan_binding(
            registry, request=request, route_artifact_sha256=route_hash,
        )
        request_record = _require_native_request_artifact_parents(
            registry, request_artifact_sha256=request_hash,
            expected_request=expected_request, expected_policy=policy,
            expected_parents=(route_hash, request.plan_artifact_hash,
                              *((request.previous_result_artifact_hash,)
                                if request.previous_result_artifact_hash else ())),
        )
    else:
        request_record = _require_native_request_artifact(
            registry,
            request_artifact_sha256=request_hash,
            route_artifact_sha256=route_hash,
            expected_request=expected_request,
            expected_policy=policy,
        )
    expected_policy_hash = hashlib.sha256(
        canonical_json_bytes(_egress_policy_claim(policy))
    ).hexdigest()
    if receipt.get("policy_claim_sha256") != expected_policy_hash:
        raise ScholarlyGatewayError("scholarly native receipt policy binding is invalid")
    attempt_records, request_bytes, response_bytes, final_completed = (
        _require_native_attempts(
            registry,
            attempts=receipt.get("attempts"),
            policy=policy,
            request_body_size=len(expected_request.body),
        )
    )
    attempts = receipt["attempts"]
    final_attempt = attempts[-1]
    if (
        final_attempt.get("status") != "RESPONSE"
        or final_attempt.get("status_code") != status_code
        or final_attempt.get("body_sha256") != raw_artifact_sha256
        or final_attempt.get("body_size") != len(raw_bytes)
        or final_attempt.get("raw_response_record_sha256")
        != raw_artifact_sha256
    ):
        raise ScholarlyGatewayError(
            "scholarly native receipt does not bind the terminal raw response"
        )
    expected_receipt_parents = (
        request_hash,
        *(record.sha256 for record in attempt_records),
        *((decoding_hash,) if content_profile else ()),
    )
    if receipt_record.parent_artifacts != expected_receipt_parents:
        raise ScholarlyGatewayError(
            "scholarly native receipt has incorrect request/raw parents"
        )
    receipt_budget = receipt.get("egress_budget")
    policy_budget = _egress_budget_policy_claim(policy)
    budget_fields = {
        *policy_budget,
        "request_bytes_used",
        "response_bytes_used",
        "total_bytes_used",
        "deadline_elapsed_seconds",
        "deadline_remaining_seconds",
        "deadline_satisfied",
    }
    if not isinstance(receipt_budget, Mapping):
        raise ScholarlyGatewayError("scholarly native receipt budget is malformed")
    elapsed = _replay_numeric(
        receipt_budget.get("deadline_elapsed_seconds"),
        "scholarly receipt elapsed deadline",
    )
    remaining = _replay_numeric(
        receipt_budget.get("deadline_remaining_seconds"),
        "scholarly receipt remaining deadline",
    )
    if (
        set(receipt_budget) != budget_fields
        or any(receipt_budget.get(key) != value for key, value in policy_budget.items())
        or receipt_budget.get("request_bytes_used") != request_bytes
        or receipt_budget.get("response_bytes_used") != response_bytes
        or receipt_budget.get("total_bytes_used") != request_bytes + response_bytes
        or receipt_budget.get("deadline_satisfied") is not True
        or elapsed + 1e-9 < final_completed
        or elapsed >= policy.timeout_seconds
        or remaining < 0.0
        or abs((elapsed + remaining) - policy.timeout_seconds) > 1e-6
        or request_bytes + response_bytes > policy.maximum_total_bytes
    ):
        raise ScholarlyGatewayError("scholarly native receipt budget is inconsistent")
    projection = _projection(
        descriptor,
        route_hash,
        request,
        expected_request,
    )
    if (
        response.get("request_projection") != projection.to_dict()
        or response.get("egress_request_id") != projection.egress_request_id
        or response.get("wire_protocol") != descriptor.wire_protocol
    ):
        raise ScholarlyGatewayError(
            "scholarly native request projection differs from its exact GET"
        )
    try:
        if profile in {_NativeCaptureReplayProfile.CAPTURED_OPENALEX_SEARCH,
                       _NativeCaptureReplayProfile.CAPTURED_OPENALEX_CURSOR_SEARCH}:
            parsed = _replay_captured_openalex_search_outcome(
                raw_bytes, request, policy, status_code,
            )
        elif content_profile:
            decoding_record, decoded_xml, decoding_value = require_pmc_content_decoding(
                registry, descriptor_sha256=decoding_hash, receipt=receipt, policy=policy,
            )
            parsed = _project_decoded_pmc_response(
                decoded_xml, request,
                wire_raw_artifact_sha256=raw_artifact_sha256,
                decoded_xml_sha256=decoding_value["decoded_xml_sha256"],
                decoding_descriptor_artifact_sha256=decoding_record.sha256,
            )
        elif source is ScholarlySource.OPENALEX:
            raw_payload = safe_json_loads(
                raw_bytes,
                max_bytes=policy.maximum_response_bytes,
                max_depth=policy.maximum_json_depth,
                max_items=policy.maximum_json_items,
            )
            parsed = _project_openalex_response(raw_payload, request)
        else:
            assert isinstance(request, ScholarlyRequest)
            parsed = _project_pmc_response(
                raw_bytes,
                raw_artifact_sha256,
                request,
            )
    except (UnsafeSerializationError, LiteratureError, TypeError, ValueError) as exc:
        raise ScholarlyGatewayError(
            "scholarly native raw response cannot be replayed"
        ) from exc
    if (
        (
            profile is _NativeCaptureReplayProfile.AVAILABLE_ONLY
            and (
                parsed.status is not RetrievalStatus.AVAILABLE
                or parsed.failure_code is not None
                or parsed.failure_reason is not None
                or parsed.payload is None
                or dict(parsed.payload) != dict(response["payload"])
            )
        )
        or parsed.status.value != response.get("retrieval_status")
        or (parsed.failure_code.value if parsed.failure_code is not None else None)
        != response.get("failure_code")
        or parsed.failure_reason != response.get("failure_reason")
        or (dict(parsed.payload) if parsed.payload is not None else None)
        != response.get("payload")
        or parsed.license != response.get("license")
        or parsed.full_text_status.value != response.get("full_text_status")
    ):
        raise ScholarlyGatewayError(
            "scholarly native normalized response differs from parser replay"
        )
    try:
        envelope = GatewayEnvelope(
            source=source,
            request_id=_request_id(request),
            status=parsed.status,
            payload=response["payload"],
            raw_artifact_hash=raw_artifact_sha256,
            response_artifact_hash=response_artifact_sha256,
            failure_reason=parsed.failure_reason,
            license=parsed.license,
            full_text_status=parsed.full_text_status,
        )
    except (LiteratureError, TypeError, ValueError) as exc:
        raise ScholarlyGatewayError(
            "scholarly native replay cannot form a gateway envelope"
        ) from exc
    artifacts = tuple(
        sorted(
            {
                route_record.sha256,
                request_record.sha256,
                *(record.sha256 for record in attempt_records),
                receipt_record.sha256,
                response_record.sha256,
                *((decoding_hash,) if content_profile else ()),
                *inspected_cursor_artifacts,
            }
        )
    )
    return ReplayedScholarlyNativeCapture(
        envelope=envelope,
        artifact_hashes=artifacts,
        raw_artifact_hash=raw_artifact_sha256,
        response_artifact_hash=response_artifact_sha256,
        response_receipt_artifact_hash=receipt_hash,
        request_artifact_hash=request_hash,
        route_artifact_hash=route_hash,
        request_body_sha256=hashlib.sha256(expected_request.body).hexdigest(),
        request_body_size=len(expected_request.body),
        response_body_sha256=raw_artifact_sha256,
        response_body_size=len(raw_bytes),
        network_used=network_expected,
        external_validation=str(external_validation),
        transport_authority=str(transport_authority),
    )


__all__ = [
    "OPENALEX_CURSOR_WIRE_PROTOCOL_V2",
    "SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V4",
    "openalex_cursor_scholarly_egress_policy",
    "require_captured_scholarly_search_page_response",
    "CapturedScholarlyResponse",
    "OPENALEX_API_DOCUMENTATION_URLS",
    "OPENALEX_WIRE_PROTOCOL_V1",
    "PMC_OAI_JATS_DOCUMENTATION_URLS",
    "PMC_OAI_JATS_WIRE_PROTOCOL_V1",
    "PMC_OAI_JATS_WIRE_PROTOCOL_V2",
    "SCHOLARLY_EGRESS_ROUTE_AUTHORITY_SCHEMA_V2",
    "SCHOLARLY_NATIVE_REQUEST_PROJECTION_SCHEMA_V2",
    "SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V2",
    "SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V3",
    "ReplayedScholarlyNativeCapture",
    "ScholarlyGatewayError",
    "ScholarlyGatewayFailureCode",
    "ScholarlyNativeRequestProjection",
    "ScholarlyRouteConfigurationError",
    "ScholarlyRouteDescriptor",
    "SourceOwnedScholarlyGateway",
    "openalex_scholarly_egress_policy",
    "pmc_scholarly_egress_policy",
    "pmc_content_scholarly_egress_policy",
    "require_available_scholarly_native_capture",
    "require_captured_scholarly_search_response",
    "supported_scholarly_routes",
]
