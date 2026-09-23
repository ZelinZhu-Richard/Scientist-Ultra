from __future__ import annotations

import ast
import base64
from dataclasses import FrozenInstanceError
import hashlib
import hmac
import http.client
import inspect
import os
from pathlib import Path
import ssl
import tempfile
import threading
import time
from types import MethodType
import unittest
from unittest import mock
import weakref

import scientist_one.external as external_module
import scientist_one.providers as providers_module
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.external import (
    AUDITED_LIVE_TRANSPORT_AUTHORITY,
    AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
    AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
    EgressDeniedError,
    EgressGateway,
    EgressPolicy,
    EgressPolicyError,
    EgressRequest,
    ExternalParseError,
    ExternalUnavailableError,
    FixtureTransport,
    PreparedEgressRequest,
    StdlibHttpsTransport,
    TransportFailure,
    TransportResponse,
    UNVERIFIED_TRANSPORT_AUTHORITY,
    require_audited_live_transport_execution,
)
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.providers import (
    ModelCapability,
    ModelInvocation,
    ModelProviderError,
    ModelRunStatus,
    ModelSchemaError,
    OpenAIResponsesConfig,
    OpenAIResponsesProvider,
    openai_responses_policy,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads
from scientist_one.roles import Role


BASIC_URL = "https://example.org/api/item"
OPENAI_URL = "https://api.openai.com/v1/responses"
PRIVATE_AUTHORITY_KEY_NAME = ".gateway-execution-" + "authority.key"


class FakeMonotonicClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.advance(seconds)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def basic_policy(**overrides) -> EgressPolicy:
    values = {
        "policy_id": "fixture-policy-v1",
        "adapter_id": "fixture",
        "allowed_hosts": ("example.org",),
        "allowed_path_prefixes": ("/api/item",),
        "allowed_methods": ("POST",),
        "allowed_query_keys": (),
        "maximum_request_bytes": 4096,
        "maximum_response_bytes": 4096,
        "timeout_seconds": 7.5,
        "minimum_interval_seconds": 0.0,
        "maximum_requests": 4,
        "maximum_attempts": 1,
        "retry_statuses": (429, 503),
        "backoff_initial_seconds": 0.1,
        "backoff_maximum_seconds": 0.5,
    }
    values.update(overrides)
    return EgressPolicy(**values)


def fixture_response(
    body: bytes = b'{"ok":true}',
    *,
    status: int = 200,
    url: str = BASIC_URL,
    content_type: str = "application/json",
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> TransportResponse:
    return TransportResponse(
        status_code=status,
        headers=(("Content-Type", content_type), *extra_headers),
        body=body,
        effective_url=url,
    )


def basic_gateway(
    response: TransportResponse,
    *,
    policy: EgressPolicy | None = None,
    registry: ArtifactRegistry | None = None,
    credential: str | None = None,
) -> tuple[EgressGateway, FixtureTransport]:
    transport = FixtureTransport((response,))
    gateway = EgressGateway(
        policy or basic_policy(),
        transport,
        registry=registry,
        secret_resolver=lambda _name: credential,
        sleeper=lambda _delay: None,
        timestamp=lambda: "2026-08-29T12:00:00.000000Z",
    )
    return gateway, transport


def basic_request(**overrides) -> EgressRequest:
    values = {
        "adapter_id": "fixture",
        "method": "POST",
        "url": BASIC_URL,
        "headers": (("Accept", "application/json"),),
        "body": b'{"request":true}',
        "content_type": "application/json",
        "target_source": "CONFIGURED",
    }
    values.update(overrides)
    return EgressRequest(**values)


def output_schema() -> dict[str, object]:
    return {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "minLength": 1,
                "maxLength": 200,
            },
            "score": {"type": "number", "minimum": 0, "maximum": 1},
        },
        "required": ["summary", "score"],
        "additionalProperties": False,
    }


def invocation(**overrides) -> ModelInvocation:
    values = {
        "invocation_id": "invocation-1",
        "capability": ModelCapability.RESEARCH_SYNTHESIS,
        "model": "gpt-5",
        "prompt_template_id": "research-summary",
        "prompt_template_version": "1.0",
        "prompt_template_hash": digest("research-summary-v1"),
        "instructions": "Return only the requested structured JSON.",
        "input_text": "Analyze the captured fixture evidence.",
        "output_schema": output_schema(),
        "max_output_tokens": 512,
    }
    values.update(overrides)
    return ModelInvocation(**values)


def openai_envelope(
    output: bytes | None = None,
    *,
    model: str = "gpt-5",
    status: str = "completed",
) -> bytes:
    output = output or canonical_json_bytes({"summary": "bounded result", "score": 0.75})
    return canonical_json_bytes(
        {
            "id": "resp_fixture_1",
            "model": model,
            "status": status,
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {"type": "output_text", "text": output.decode("utf-8")}
                    ],
                }
            ],
            "usage": {
                "input_tokens": 11,
                "input_tokens_details": {
                    "cached_tokens": 3,
                    "cache_write_tokens": 2,
                },
                "output_tokens": 7,
                "output_tokens_details": {"reasoning_tokens": 4},
                "total_tokens": 18,
            },
        }
    )


def openai_provider(
    body: bytes,
    *,
    status: int = 200,
    credential: str | None = "fixture-credential-material",
    registry: ArtifactRegistry | None = None,
) -> tuple[OpenAIResponsesProvider, FixtureTransport]:
    temporary_registry: tempfile.TemporaryDirectory[str] | None = None
    if registry is None:
        temporary_registry = tempfile.TemporaryDirectory()
        registry = ArtifactRegistry(temporary_registry.name)
    transport = FixtureTransport(
        (
            fixture_response(
                body,
                status=status,
                url=OPENAI_URL,
            ),
        )
    )
    gateway = EgressGateway(
        openai_responses_policy(maximum_attempts=1, maximum_requests=2),
        transport,
        registry=registry,
        secret_resolver=lambda _name: credential,
        sleeper=lambda _delay: None,
        timestamp=lambda: "2026-08-29T12:00:00.000000Z",
    )
    provider = OpenAIResponsesProvider(gateway)
    if temporary_registry is not None:
        provider._test_registry_directory = temporary_registry
        provider._test_registry_cleanup = weakref.finalize(
            provider,
            temporary_registry.cleanup,
        )
    return provider, transport


class ExternalPolicyTests(unittest.TestCase):
    def test_policy_and_request_are_frozen_and_bounded(self) -> None:
        policy = basic_policy()
        request = basic_request()
        with self.assertRaises(FrozenInstanceError):
            policy.timeout_seconds = 9.0  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            request.url = "https://example.org/api/other"  # type: ignore[misc]
        with self.assertRaises(EgressPolicyError):
            basic_policy(allowed_hosts=("127.0.0.1",))
        with self.assertRaises(EgressPolicyError):
            basic_policy(maximum_attempts=99)
        with self.assertRaises(EgressPolicyError):
            basic_policy(timeout_seconds=float("inf"))

    def test_hostile_targets_are_rejected_exactly(self) -> None:
        hostile = (
            "http://example.org/api/item",
            "https://example.org.evil.invalid/api/item",
            "https://127.0.0.1/api/item",
            "https://user:pass@example.org/api/item",
            "https://example.org:444/api/item",
            "https://example.org/api/item#fragment",
            "https://example.org/api/other",
            "https://example.org/api/%2e%2e/item",
            "https://example.org/api/item?api_key=value",
        )
        for url in hostile:
            with self.subTest(url=url):
                gateway, _ = basic_gateway(fixture_response())
                with self.assertRaises(EgressDeniedError):
                    gateway.execute(basic_request(url=url))

    def test_returned_target_changes_and_redirects_are_rejected(self) -> None:
        gateway, _ = basic_gateway(
            fixture_response(url="https://example.org/api/other")
        )
        with self.assertRaises(EgressDeniedError):
            gateway.execute(basic_request())
        gateway, _ = basic_gateway(fixture_response(status=302))
        with self.assertRaises(EgressDeniedError):
            gateway.execute(basic_request())

    def test_arbitrary_target_source_and_transport_headers_are_rejected(self) -> None:
        with self.assertRaises(EgressDeniedError):
            basic_request(target_source="DISCOVERED_FROM_RESPONSE")
        with self.assertRaises(EgressDeniedError):
            basic_request(headers=(("Authorization", "Bearer caller-controlled"),))
        with self.assertRaises(EgressDeniedError):
            basic_request(headers=(("Host", "evil.invalid"),))

    def test_content_type_header_is_single_and_matches_the_typed_value(self) -> None:
        with self.assertRaises(EgressPolicyError):
            basic_request(
                headers=(
                    ("Content-Type", "application/json"),
                    ("content-type", "application/json"),
                )
            )
        gateway, transport = basic_gateway(fixture_response())
        with self.assertRaises(EgressDeniedError):
            gateway.execute(
                basic_request(headers=(("content-type", "text/plain"),))
            )
        self.assertEqual(transport.sent_request_ids, [])

        gateway, transport = basic_gateway(fixture_response())
        gateway.execute(
            basic_request(headers=(("content-type", "application/json"),))
        )
        prepared = transport.prepared_requests[0]
        self.assertEqual(
            [
                value
                for name, value in prepared.headers
                if name.lower() == "content-type"
            ],
            ["application/json"],
        )

    def test_duplicate_response_content_type_fails_closed_with_receipt(self) -> None:
        response = object.__new__(TransportResponse)
        object.__setattr__(response, "status_code", 200)
        object.__setattr__(
            response,
            "headers",
            (
                ("Content-Type", "application/json"),
                ("content-type", "text/plain"),
            ),
        )
        object.__setattr__(response, "body", b'{"ok":true}')
        object.__setattr__(response, "effective_url", BASIC_URL)
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            gateway, _ = basic_gateway(response, registry=registry)
            with self.assertRaises(EgressDeniedError) as caught:
                gateway.execute(basic_request())
            self.assertEqual(len(caught.exception.attempts), 1)
            receipt = next(
                record
                for record in caught.exception.artifacts
                if record.logical_type == "external_response_denial_receipt"
            )
            payload = safe_json_loads(registry.get_bytes(receipt.sha256))
            self.assertEqual(payload["denial_reason"], "RESPONSE_CONTROLS_INVALID")
            self.assertEqual(payload["body_size"], len(b'{"ok":true}'))

    def test_content_type_and_size_are_enforced(self) -> None:
        gateway, _ = basic_gateway(fixture_response(content_type="text/html"))
        with self.assertRaises(EgressDeniedError):
            gateway.execute(basic_request())
        gateway, _ = basic_gateway(
            fixture_response(b"x" * 33),
            policy=basic_policy(maximum_response_bytes=32),
        )
        with self.assertRaises(EgressDeniedError):
            gateway.execute(basic_request())
        gateway, _ = basic_gateway(fixture_response())
        with self.assertRaises(EgressDeniedError):
            gateway.execute(basic_request(content_type="text/plain"))

    def test_request_and_response_secret_leakage_fail_closed(self) -> None:
        gateway, _ = basic_gateway(fixture_response())
        with self.assertRaises(EgressDeniedError):
            gateway.execute(
                basic_request(body=b'{"api_key":"abcdefghijklmnop"}')
            )
        credential_policy = basic_policy(
            credential_env_name="FIXTURE_API_KEY",
            credential_required=True,
        )
        secret = "fixture-credential-material"
        gateway, _ = basic_gateway(
            fixture_response(canonical_json_bytes({"echo": secret})),
            policy=credential_policy,
            credential=secret,
        )
        with self.assertRaises(EgressDeniedError):
            gateway.execute(basic_request())

    def test_reversible_credential_forms_never_enter_offline_custody(self) -> None:
        credential_policy = basic_policy(
            credential_env_name="FIXTURE_API_KEY",
            credential_required=True,
        )
        secret = "fixture-credential-material"
        raw = secret.encode("utf-8")
        transmitted = f"Bearer {secret}".encode("utf-8")
        forms = {
            raw,
            transmitted,
            raw.hex().encode("ascii"),
            raw.hex().upper().encode("ascii"),
            transmitted.hex().encode("ascii"),
            transmitted.hex().upper().encode("ascii"),
        }
        for source in (raw, transmitted):
            for encoded in (
                base64.b64encode(source),
                base64.urlsafe_b64encode(source),
            ):
                forms.add(encoded)
                forms.add(encoded.rstrip(b"="))

        for index, form in enumerate(sorted(forms), 1):
            with self.subTest(index=index, form_size=len(form)):
                body = canonical_json_bytes(
                    {"ordinary_response_field": form.decode("ascii")}
                )
                with tempfile.TemporaryDirectory() as directory:
                    registry = ArtifactRegistry(directory)
                    gateway, _ = basic_gateway(
                        fixture_response(body),
                        policy=credential_policy,
                        registry=registry,
                        credential=secret,
                    )
                    with self.assertRaises(EgressDeniedError) as caught:
                        gateway.execute(basic_request())
                    self.assertIsNone(
                        caught.exception.attempts[0][
                            "raw_response_record_sha256"
                        ]
                    )
                    self.assertNotIn(
                        "external_response_raw",
                        {
                            record.logical_type
                            for record in registry.list_records()
                        },
                    )

                with tempfile.TemporaryDirectory() as directory:
                    registry = ArtifactRegistry(directory)
                    gateway, _ = basic_gateway(
                        fixture_response(),
                        policy=credential_policy,
                        registry=registry,
                        credential=secret,
                    )
                    with self.assertRaises(EgressDeniedError):
                        gateway.capture_custody_bytes(
                            form,
                            logical_type="model_judged_input",
                            origin="transformed credential rejection test",
                            creator_role=Role.ORCHESTRATOR,
                            mime_type="text/plain",
                        )
                    with self.assertRaises(EgressDeniedError):
                        gateway.capture_json_artifact(
                            {"ordinary_response_field": form.decode("ascii")},
                            logical_type="model_provider_response",
                            origin="transformed credential rejection test",
                            creator_role=Role.ORCHESTRATOR,
                        )
                    self.assertEqual(registry.list_records(), ())

    def test_credentialed_network_transport_is_blocked_before_dispatch(self) -> None:
        class NetworkProbeTransport:
            network_used = True
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = "UNTESTED"

            def __init__(self) -> None:
                self.send_count = 0

            def send(self, request, *, credential):  # pragma: no cover
                del request, credential
                self.send_count += 1
                raise AssertionError("credentialed network dispatch must not run")

        for required in (False, True):
            with self.subTest(credential_required=required):
                with tempfile.TemporaryDirectory() as directory:
                    registry = ArtifactRegistry(directory)
                    transport = NetworkProbeTransport()
                    gateway = EgressGateway(
                        basic_policy(
                            credential_env_name="FIXTURE_API_KEY",
                            credential_required=required,
                        ),
                        transport,
                        registry=registry,
                        secret_resolver=lambda _name: (
                            "fixture-credential-material"
                        ),
                    )
                    self.assertEqual(gateway.availability(), "BLOCKED_EXTERNAL")
                    with self.assertRaises(ExternalUnavailableError):
                        gateway.execute(basic_request())
                    self.assertEqual(transport.send_count, 0)
                    self.assertEqual(gateway._request_count, 0)
                    self.assertEqual(registry.list_records(), ())

    def test_unverified_offline_transport_never_receives_resolved_credential(
        self,
    ) -> None:
        secret = "fixture-credential-material"

        class DeceptiveOfflineTransport:
            network_used = False
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = "UNTESTED"

            def __init__(self) -> None:
                self.received: list[str | None] = []

            def send(self, request, *, credential):
                external_module._consume_prepared_request(request, self)
                self.received.append(credential)
                reflected = credential[::-1] if credential is not None else "redacted"
                return fixture_response(
                    canonical_json_bytes({"ordinary_response_field": reflected})
                )

        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            transport = DeceptiveOfflineTransport()
            gateway = EgressGateway(
                basic_policy(
                    credential_env_name="FIXTURE_API_KEY",
                    credential_required=True,
                ),
                transport,
                registry=registry,
                secret_resolver=lambda _name: secret,
            )
            result = gateway.execute(basic_request())
            self.assertEqual(transport.received, [None])
            self.assertEqual(result.transport_authority, UNVERIFIED_TRANSPORT_AUTHORITY)
            self.assertFalse(result.network_used)
            reversed_secret = secret[::-1].encode("utf-8")
            self.assertFalse(
                any(
                    reversed_secret in registry.get_bytes(record.sha256)
                    for record in registry.list_records()
                )
            )

    def test_idempotency_keys_cannot_expose_credentials_or_secret_patterns(self) -> None:
        credential_policy = basic_policy(
            credential_env_name="FIXTURE_API_KEY",
            credential_required=True,
        )
        secret = "fixture-credential-material"
        for key in (secret, f"prefix-{secret}-suffix"):
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as directory:
                    registry = ArtifactRegistry(directory)
                    gateway, transport = basic_gateway(
                        fixture_response(),
                        policy=credential_policy,
                        registry=registry,
                        credential=secret,
                    )
                    with self.assertRaises(EgressDeniedError):
                        gateway.execute(basic_request(idempotency_key=key))
                    self.assertEqual(transport.sent_request_ids, [])
                    self.assertEqual(registry.list_records(), ())

        secret_pattern = "api_key=abcdefghijklmnop"
        gateway, transport = basic_gateway(
            fixture_response(),
            policy=credential_policy,
            credential=secret,
        )
        with self.assertRaises(EgressDeniedError):
            gateway.execute(basic_request(idempotency_key=secret_pattern))
        self.assertEqual(transport.sent_request_ids, [])

    def test_benign_idempotency_key_is_preserved_without_credential_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            credential_policy = basic_policy(
                credential_env_name="FIXTURE_API_KEY",
                credential_required=True,
            )
            gateway, transport = basic_gateway(
                fixture_response(),
                policy=credential_policy,
                registry=registry,
                credential="fixture-credential-material",
            )
            result = gateway.execute(
                basic_request(idempotency_key="benign-request-1")
            )
            self.assertIn(
                ("Idempotency-Key", "benign-request-1"),
                transport.prepared_requests[0].headers,
            )
            request_bytes = registry.get_bytes(
                result.request_artifact.sha256  # type: ignore[union-attr]
            )
            self.assertIn(b"benign-request-1", request_bytes)
            self.assertNotIn(b"fixture-credential-material", request_bytes)

    def test_fixture_disclosures_and_retry_policy_are_explicit(self) -> None:
        retry_policy = basic_policy(
            maximum_attempts=2,
            maximum_requests=2,
            backoff_initial_seconds=0.2,
        )
        transport = FixtureTransport(
            (
                fixture_response(status=429, extra_headers=(("Retry-After", "0"),)),
                fixture_response(),
            )
        )
        delays: list[float] = []
        clock = FakeMonotonicClock()

        def sleep(delay: float) -> None:
            delays.append(delay)
            clock.sleep(delay)

        gateway = EgressGateway(
            retry_policy,
            transport,
            clock=clock,
            sleeper=sleep,
            timestamp=lambda: "2026-08-29T12:00:00.000000Z",
        )
        result = gateway.execute(basic_request())
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(result.attempts), 2)
        self.assertEqual(delays, [0.2])
        self.assertFalse(result.network_used)
        self.assertFalse(result.scientific_evidence)
        self.assertEqual(result.external_validation, "UNTESTED")
        self.assertEqual(len(transport.prepared_requests), 2)
        self.assertGreater(transport.prepared_requests[0].timeout_seconds, 0.0)
        self.assertLessEqual(transport.prepared_requests[0].timeout_seconds, 7.5)

    def test_gateway_policy_is_write_once_during_transport_execution(self) -> None:
        original = basic_policy(maximum_response_bytes=16)
        permissive = basic_policy(maximum_response_bytes=4096)

        class MutatingTransport:
            network_used = False
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = "UNTESTED"

            def __init__(self) -> None:
                self.gateway: EgressGateway | None = None
                self.mutation_denied = False

            def send(self, request, *, credential):
                del credential
                external_module._consume_prepared_request(request, self)
                try:
                    self.gateway.policy = permissive  # type: ignore[union-attr,misc]
                except AttributeError:
                    self.mutation_denied = True
                # Same-process state introspection is outside the public API,
                # but forcing it here proves this in-flight execution never
                # re-reads policy after its entry snapshot.
                vars(self.gateway)["_policy"] = permissive  # type: ignore[arg-type]
                return fixture_response(b"x" * 32)

        transport = MutatingTransport()
        gateway = EgressGateway(original, transport)
        transport.gateway = gateway
        self.assertNotIn("policy", vars(gateway))
        self.assertIs(vars(gateway)["_policy"], original)
        with self.assertRaises(AttributeError):
            gateway.policy = permissive  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            gateway._policy = permissive  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            del gateway.policy
        with self.assertRaises(AttributeError):
            del gateway._policy
        self.assertIs(gateway.policy, original)
        with self.assertRaises(EgressDeniedError):
            gateway.execute(basic_request())
        self.assertTrue(transport.mutation_denied)
        self.assertIs(gateway.policy, permissive)

    def test_secret_resolver_cannot_change_the_active_policy_snapshot(self) -> None:
        original = basic_policy(
            maximum_response_bytes=16,
            credential_env_name="FIXTURE_API_KEY",
        )
        permissive = basic_policy(
            maximum_response_bytes=4096,
            credential_env_name="FIXTURE_API_KEY",
        )

        class MutatingResolver:
            gateway: EgressGateway | None = None

            def __call__(self, _name: str) -> None:
                assert self.gateway is not None
                vars(self.gateway)["_policy"] = permissive
                return None

        resolver = MutatingResolver()
        transport = FixtureTransport((fixture_response(b"x" * 32),))
        gateway = EgressGateway(
            original,
            transport,
            secret_resolver=resolver,
        )
        resolver.gateway = gateway
        with self.assertRaises(EgressDeniedError):
            gateway.execute(basic_request())
        self.assertEqual(len(transport.prepared_requests), 1)
        self.assertIs(gateway.policy, permissive)

    def test_bounded_reader_counts_incomplete_body_without_retaining_it(self) -> None:
        class FakeSocket:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def settimeout(self, value: float) -> None:
                self.timeouts.append(value)

        class FakeConnection:
            def __init__(self) -> None:
                self.sock = FakeSocket()

        inner = http.client.IncompleteRead(b"fg", 1)
        outer = http.client.IncompleteRead(b"de", 1)
        outer.__cause__ = inner

        class FailingResponse:
            def __init__(self) -> None:
                self.calls = 0

            def read(self, _amount: int) -> bytes:
                self.calls += 1
                if self.calls == 1:
                    return b"abc"
                raise outer

        prepared = PreparedEgressRequest(
            request_id=digest("partial-reader"),
            method="POST",
            url=BASIC_URL,
            host="example.org",
            target="/api/item",
            headers=(("Accept", "application/json"),),
            body=b"{}",
            maximum_response_bytes=16,
        )
        connection = FakeConnection()
        with self.assertRaises(
            external_module._PartialResponseTransportFailure
        ) as caught:
            external_module._read_bounded_response_body(
                FailingResponse(),
                connection,
                prepared,
                deadline_remaining=lambda _request: 1.0,
            )
        failure = caught.exception
        self.assertEqual(failure.response_body_bytes, 7)
        self.assertFalse(failure.policy_denial)
        self.assertFalse(hasattr(failure, "partial"))
        self.assertNotIn("abcdefg", repr(failure))
        self.assertEqual(connection.sock.timeouts, [1.0, 1.0])

    def test_partial_reader_chain_is_cleared_before_a_failing_clock(self) -> None:
        secret_partial = b"secret-body-that-must-not-escape"

        class FailingResponse:
            def read(self, _amount: int) -> bytes:
                raise http.client.IncompleteRead(secret_partial, 1)

        class PartialReaderTransport:
            network_used = False
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = "UNTESTED"

            def send(self, request, *, credential):
                del credential
                external_module._consume_prepared_request(request, self)
                return external_module._read_bounded_response_body(
                    FailingResponse(),
                    type("Connection", (), {"sock": None})(),
                    request,
                    deadline_remaining=lambda _request: 1.0,
                )

        class FailingClock:
            def __init__(self) -> None:
                self.calls = 0

            def __call__(self) -> float:
                self.calls += 1
                if self.calls >= 6:
                    raise RuntimeError("clock unavailable")
                return 0.0

        gateway = EgressGateway(
            basic_policy(),
            PartialReaderTransport(),
            clock=FailingClock(),
        )
        with self.assertRaises(EgressDeniedError) as caught:
            gateway.execute(basic_request())
        pending = [caught.exception]
        seen: set[int] = set()
        partial_failure = None
        while pending:
            error = pending.pop()
            if id(error) in seen:
                continue
            seen.add(id(error))
            if isinstance(
                error,
                external_module._PartialResponseTransportFailure,
            ):
                partial_failure = error
            for chained in (error.__cause__, error.__context__):
                if chained is not None:
                    pending.append(chained)
        self.assertIsNotNone(partial_failure)
        assert partial_failure is not None
        self.assertIsNone(partial_failure.__traceback__)
        self.assertIsNone(partial_failure.__cause__)
        self.assertIsNone(partial_failure.__context__)
        self.assertNotIn(secret_partial.decode("ascii"), repr(vars(partial_failure)))

    def test_partial_read_bytes_carry_forward_and_exhaust_total_budget(self) -> None:
        class PartialThenSuccessTransport:
            network_used = False
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = "UNTESTED"

            def __init__(self, partial_bytes: int) -> None:
                self.partial_bytes = partial_bytes
                self.send_count = 0
                self.response_limits: list[int] = []

            def send(self, request, *, credential):
                del credential
                external_module._consume_prepared_request(request, self)
                self.send_count += 1
                self.response_limits.append(request.maximum_response_bytes)
                if self.send_count == 1:
                    raise external_module._PartialResponseTransportFailure(
                        "fixture partial read",
                        response_body_bytes=self.partial_bytes,
                    )
                return fixture_response(b"{}")

        request = basic_request(body=b"{}")
        policy_values = {
            "maximum_attempts": 2,
            "maximum_requests": 2,
            "maximum_response_bytes": 64,
            "backoff_initial_seconds": 0.0,
            "backoff_maximum_seconds": 0.0,
        }
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            transport = PartialThenSuccessTransport(7)
            clock = FakeMonotonicClock()
            gateway = EgressGateway(
                basic_policy(maximum_total_bytes=13, **policy_values),
                transport,
                registry=registry,
                clock=clock,
                sleeper=clock.sleep,
            )
            result = gateway.execute(request)
            self.assertEqual(transport.response_limits, [11, 2])
            self.assertEqual(
                [attempt["response_body_bytes"] for attempt in result.attempts],
                [7, 2],
            )
            self.assertEqual(
                [attempt["cumulative_bytes"] for attempt in result.attempts],
                [9, 13],
            )
            self.assertEqual(result.total_bytes_used, 13)
            self.assertIsNone(
                result.attempts[0]["raw_response_record_sha256"]
            )
            receipt = safe_json_loads(
                registry.get_bytes(result.response_receipt_artifact.sha256)  # type: ignore[union-attr]
            )
            self.assertEqual(receipt["egress_budget"]["response_bytes_used"], 9)

        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            transport = PartialThenSuccessTransport(7)
            clock = FakeMonotonicClock()
            gateway = EgressGateway(
                basic_policy(maximum_total_bytes=9, **policy_values),
                transport,
                registry=registry,
                clock=clock,
                sleeper=clock.sleep,
            )
            with self.assertRaises(EgressDeniedError) as caught:
                gateway.execute(request)
            self.assertEqual(transport.send_count, 1)
            self.assertEqual(caught.exception.attempts[0]["response_body_bytes"], 7)
            denial = next(
                record
                for record in caught.exception.artifacts
                if record.logical_type == "external_budget_denial_receipt"
            )
            denial_value = safe_json_loads(registry.get_bytes(denial.sha256))
            self.assertEqual(denial_value["egress_budget"]["total_bytes_used"], 9)

        # Even a zero-byte retry request cannot dispatch once the first
        # partial body has consumed the entire cumulative body-byte budget.
        transport = PartialThenSuccessTransport(9)
        clock = FakeMonotonicClock()
        gateway = EgressGateway(
            basic_policy(maximum_total_bytes=9, **policy_values),
            transport,
            clock=clock,
            sleeper=clock.sleep,
        )
        with self.assertRaises(EgressDeniedError) as caught:
            gateway.execute(basic_request(body=b""))
        self.assertEqual(transport.send_count, 1)
        self.assertEqual(caught.exception.attempts[0]["response_body_bytes"], 9)

        # A replaceable transport cannot lie about the helper's denial bit to
        # retry after reporting more bytes than its issued response allowance.
        transport = PartialThenSuccessTransport(5)
        clock = FakeMonotonicClock()
        gateway = EgressGateway(
            basic_policy(
                maximum_total_bytes=64,
                maximum_response_bytes=4,
                **{
                    name: value
                    for name, value in policy_values.items()
                    if name != "maximum_response_bytes"
                },
            ),
            transport,
            clock=clock,
            sleeper=clock.sleep,
        )
        with self.assertRaises(EgressDeniedError) as caught:
            gateway.execute(basic_request(body=b""))
        self.assertEqual(transport.send_count, 1)
        self.assertEqual(caught.exception.attempts[0]["response_body_bytes"], 5)

        class LatePartialTransport(PartialThenSuccessTransport):
            def __init__(self, partial_bytes: int, clock: FakeMonotonicClock) -> None:
                super().__init__(partial_bytes)
                self.clock = clock

            def send(self, request, *, credential):
                if self.send_count == 0:
                    self.clock.advance(1.0)
                return super().send(request, credential=credential)

        clock = FakeMonotonicClock()
        late_transport = LatePartialTransport(1, clock)
        gateway = EgressGateway(
            basic_policy(
                timeout_seconds=1.0,
                maximum_total_bytes=64,
                **policy_values,
            ),
            late_transport,
            clock=clock,
            sleeper=clock.sleep,
        )
        with self.assertRaises(EgressDeniedError):
            gateway.execute(basic_request(body=b""))
        self.assertEqual(late_transport.send_count, 1)

    def test_cumulative_bytes_cover_request_response_and_retries(self) -> None:
        request = basic_request(body=b"{}")
        first = fixture_response(b'{"r":1}', status=503)
        second = fixture_response(b'{"r":2}')
        total_if_second_is_received = (
            2 * len(request.body) + len(first.body) + len(second.body)
        )
        policy = basic_policy(
            maximum_attempts=2,
            maximum_requests=2,
            maximum_response_bytes=64,
            maximum_total_bytes=total_if_second_is_received - 1,
            backoff_initial_seconds=0.0,
            backoff_maximum_seconds=0.0,
        )
        clock = FakeMonotonicClock()
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            transport = FixtureTransport((first, second))
            gateway = EgressGateway(
                policy,
                transport,
                registry=registry,
                clock=clock,
                sleeper=clock.sleep,
                timestamp=lambda: "2026-08-29T12:00:00.000000Z",
            )
            with self.assertRaises(EgressDeniedError) as caught:
                gateway.execute(request)
            self.assertEqual(len(transport.prepared_requests), 2)
            self.assertEqual(len(caught.exception.attempts), 2)
            self.assertEqual(
                caught.exception.attempts[-1]["cumulative_bytes"],
                total_if_second_is_received,
            )
            self.assertIsNone(
                caught.exception.attempts[-1]["raw_response_record_sha256"]
            )
            denial = next(
                record
                for record in caught.exception.artifacts
                if record.logical_type == "external_response_denial_receipt"
            )
            denial_value = safe_json_loads(registry.get_bytes(denial.sha256))
            self.assertEqual(denial_value["denial_reason"], "CUMULATIVE_BYTE_LIMIT")
            self.assertEqual(
                denial_value["egress_budget"]["total_bytes_used"],
                total_if_second_is_received,
            )
            self.assertEqual(
                denial_value["egress_budget"]["maximum_total_bytes"],
                total_if_second_is_received - 1,
            )

    def test_monotonic_deadline_covers_transport_and_retry_backoff(self) -> None:
        class AdvancingTransport:
            network_used = False
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = "UNTESTED"

            def __init__(self, clock: FakeMonotonicClock) -> None:
                self.clock = clock
                self.send_count = 0

            def send(self, request, *, credential):
                del credential
                external_module._consume_prepared_request(request, self)
                self.send_count += 1
                self.clock.advance(0.6)
                return fixture_response(b'{"retry":true}', status=503)

        clock = FakeMonotonicClock()
        transport = AdvancingTransport(clock)
        gateway = EgressGateway(
            basic_policy(
                timeout_seconds=1.0,
                maximum_attempts=2,
                maximum_requests=2,
                backoff_initial_seconds=0.5,
                backoff_maximum_seconds=0.5,
            ),
            transport,
            clock=clock,
            sleeper=clock.sleep,
        )
        with self.assertRaises(EgressDeniedError) as caught:
            gateway.execute(basic_request())
        self.assertEqual(transport.send_count, 1)
        self.assertEqual(clock.sleeps, [])
        self.assertIn("deadline", str(caught.exception))

        clock = FakeMonotonicClock()
        transport = AdvancingTransport(clock)

        def oversleep(delay: float) -> None:
            clock.sleeps.append(delay)
            clock.advance(delay + 1.0)

        gateway = EgressGateway(
            basic_policy(
                timeout_seconds=1.0,
                maximum_attempts=2,
                maximum_requests=2,
                backoff_initial_seconds=0.2,
                backoff_maximum_seconds=0.2,
            ),
            transport,
            clock=clock,
            sleeper=oversleep,
        )
        with self.assertRaises(EgressDeniedError) as caught:
            gateway.execute(basic_request())
        self.assertEqual(transport.send_count, 1)
        self.assertEqual(clock.sleeps, [0.2])
        self.assertIn("deadline", str(caught.exception))

        class OverDeadlineTransport(AdvancingTransport):
            def send(self, request, *, credential):
                del credential
                external_module._consume_prepared_request(request, self)
                self.send_count += 1
                self.clock.advance(1.1)
                return fixture_response()

        clock = FakeMonotonicClock()
        transport = OverDeadlineTransport(clock)
        gateway = EgressGateway(
            basic_policy(timeout_seconds=1.0),
            transport,
            clock=clock,
            sleeper=clock.sleep,
        )
        with self.assertRaises(EgressDeniedError) as caught:
            gateway.execute(basic_request())
        self.assertEqual(transport.send_count, 1)
        self.assertEqual(caught.exception.attempts[0]["completed_offset_seconds"], 1.1)

    def test_signed_policy_replay_rejects_request_or_target_mismatch(self) -> None:
        policy = basic_policy()
        request = {
            "schema_version": external_module.EGRESS_REQUEST_SCHEMA,
            "kind": "REDACTED_EXTERNAL_REQUEST",
            "policy_id": policy.policy_id,
            "policy_claim_sha256": hashlib.sha256(
                canonical_json_bytes(external_module._egress_policy_claim(policy))
            ).hexdigest(),
            "egress_budget": external_module._egress_budget_policy_claim(policy),
            "adapter_id": "fixture",
            "method": "POST",
            "url": BASIC_URL,
            "headers": [["Accept", "application/json"]],
            "body_size": 2,
            "content_type": "application/json",
            "credential_env_name": None,
            "credential_present": False,
            "scientific_evidence": False,
        }
        prepared = {
            "method": "POST",
            "url": BASIC_URL,
            "host": "example.org",
            "target": "/api/item",
            "headers": [["Accept", "application/json"]],
            "content_type": "application/json",
            "credential_header": None,
            "credential_prefix": policy.credential_prefix,
        }
        external_module._replay_signed_request_against_policy(
            policy,
            request,
            prepared,
        )
        with self.assertRaises(EgressPolicyError):
            external_module._replay_signed_request_against_policy(
                basic_policy(allowed_methods=("GET",)),
                request,
                prepared,
            )
        mismatched = dict(prepared)
        mismatched["host"] = "attacker.invalid"
        with self.assertRaises(EgressPolicyError):
            external_module._replay_signed_request_against_policy(
                policy,
                request,
                mismatched,
            )

    def test_v2_request_replay_rejects_v1_and_credential_tampering(self) -> None:
        policy = basic_policy(
            credential_env_name="FIXTURE_API_KEY",
            credential_required=False,
        )
        request = {
            "schema_version": external_module.EGRESS_REQUEST_SCHEMA,
            "kind": "REDACTED_EXTERNAL_REQUEST",
            "policy_id": policy.policy_id,
            "policy_claim_sha256": hashlib.sha256(
                canonical_json_bytes(external_module._egress_policy_claim(policy))
            ).hexdigest(),
            "egress_budget": external_module._egress_budget_policy_claim(policy),
            "adapter_id": policy.adapter_id,
            "method": "POST",
            "url": BASIC_URL,
            "headers": [["Accept", "application/json"]],
            "body_size": 2,
            "content_type": "application/json",
            "credential_env_name": "FIXTURE_API_KEY",
            "credential_present": False,
            "scientific_evidence": False,
        }
        prepared = {
            "method": "POST",
            "url": BASIC_URL,
            "host": "example.org",
            "target": "/api/item",
            "headers": [["Accept", "application/json"]],
            "content_type": "application/json",
            "credential_header": None,
            "credential_prefix": policy.credential_prefix,
        }
        external_module._replay_signed_request_against_policy(
            policy,
            request,
            prepared,
        )
        mutations = (
            ("legacy-request", {"schema_version": "1.0"}, {}),
            (
                "legacy-budget",
                {
                    "egress_budget": {
                        **request["egress_budget"],
                        "schema_version": "controlled-egress-budget/v1",
                    }
                },
                {},
            ),
            ("policy-id", {"policy_id": "substituted-policy"}, {}),
            ("policy-hash", {"policy_claim_sha256": "0" * 64}, {}),
            (
                "credential-present-live",
                {"credential_present": True},
                {"credential_header": policy.credential_header},
            ),
            (
                "credential-env",
                {"credential_env_name": "OTHER_API_KEY"},
                {},
            ),
            (
                "credential-header",
                {},
                {"credential_header": "X-Substituted"},
            ),
        )
        for label, request_change, prepared_change in mutations:
            with self.subTest(label=label), self.assertRaises(EgressPolicyError):
                external_module._replay_signed_request_against_policy(
                    policy,
                    {**request, **request_change},
                    {**prepared, **prepared_change},
                )

        required_policy = basic_policy(
            credential_env_name="FIXTURE_API_KEY",
            credential_required=True,
        )
        required_request = {
            **request,
            "policy_claim_sha256": hashlib.sha256(
                canonical_json_bytes(
                    external_module._egress_policy_claim(required_policy)
                )
            ).hexdigest(),
            "egress_budget": external_module._egress_budget_policy_claim(
                required_policy
            ),
        }
        # Required-and-absent violates the credential policy; required-and-
        # present violates the credentialless audited-live authority invariant.
        for credential_present, credential_header in (
            (False, None),
            (True, required_policy.credential_header),
        ):
            with self.assertRaises(EgressPolicyError):
                external_module._replay_signed_request_against_policy(
                    required_policy,
                    {
                        **required_request,
                        "credential_present": credential_present,
                    },
                    {
                        **prepared,
                        "credential_header": credential_header,
                    },
                )

    def test_retry_backoff_requires_clock_advance_and_signed_replay(self) -> None:
        policy = basic_policy(
            timeout_seconds=2.0,
            maximum_attempts=2,
            maximum_requests=2,
            backoff_initial_seconds=0.5,
            backoff_maximum_seconds=0.5,
        )
        clock = FakeMonotonicClock()
        transport = FixtureTransport(
            (fixture_response(status=503), fixture_response())
        )
        gateway = EgressGateway(
            policy,
            transport,
            clock=clock,
            sleeper=lambda _delay: None,
        )
        with self.assertRaises(EgressDeniedError) as caught:
            gateway.execute(basic_request())
        self.assertEqual(len(transport.prepared_requests), 1)
        self.assertEqual(len(caught.exception.attempts), 1)
        self.assertIn("backoff", str(caught.exception))
        self.assertEqual(
            caught.exception.attempts[0]["retry_delay_seconds"],
            0.5,
        )

        clock = FakeMonotonicClock()
        transport = FixtureTransport(
            (
                fixture_response(
                    status=503,
                    extra_headers=(("Retry-After", "0.75"),),
                ),
                fixture_response(),
            )
        )
        replay_policy = basic_policy(
            timeout_seconds=2.0,
            maximum_attempts=2,
            maximum_requests=2,
            backoff_initial_seconds=0.5,
            backoff_maximum_seconds=1.0,
        )
        gateway = EgressGateway(
            replay_policy,
            transport,
            clock=clock,
            sleeper=clock.sleep,
        )
        result = gateway.execute(basic_request())
        attempts = [dict(value) for value in result.attempts]
        self.assertEqual(attempts[0]["retry_delay_seconds"], 0.75)
        self.assertIsNone(attempts[1]["retry_delay_seconds"])
        self.assertEqual(clock.sleeps, [0.75])
        external_module._replay_retry_backoff(replay_policy, attempts)
        inconsistent = [dict(value) for value in attempts]
        inconsistent[1]["started_offset_seconds"] = 0.74
        with self.assertRaises(EgressPolicyError):
            external_module._replay_retry_backoff(
                replay_policy,
                inconsistent,
            )
        understated = [dict(value) for value in attempts]
        understated[0]["retry_delay_seconds"] = 0.49
        with self.assertRaises(EgressPolicyError):
            external_module._replay_retry_backoff(
                replay_policy,
                understated,
            )
        non_retryable = [dict(value) for value in attempts]
        non_retryable[0]["status"] = "RESPONSE"
        non_retryable[0]["status_code"] = 200
        with self.assertRaises(EgressPolicyError):
            external_module._replay_retry_backoff(
                replay_policy,
                non_retryable,
            )

    def test_proxy_inheriting_transport_is_rejected(self) -> None:
        class ProxyTransport:
            network_used = True
            inherits_proxy_environment = True
            scientific_evidence = False
            external_validation = "UNTESTED"

            def send(self, request, *, credential):  # pragma: no cover
                raise AssertionError((request.request_id, credential is not None))

        with self.assertRaises(EgressDeniedError):
            EgressGateway(basic_policy(), ProxyTransport())


    def test_concurrent_gateway_admission_reserves_quota_and_rate_slots(self) -> None:
        class RecordingTransport:
            network_used = False
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = "UNTESTED"

            def __init__(self) -> None:
                self.sent_at: list[float] = []
                self.lock = threading.Lock()

            def send(self, request, *, credential):
                del credential
                external_module._consume_prepared_request(request, self)
                with self.lock:
                    self.sent_at.append(time.monotonic())
                return fixture_response()

        def run_concurrently(gateway: EgressGateway, count: int) -> list[Exception]:
            barrier = threading.Barrier(count + 1)
            failures: list[Exception] = []
            failures_lock = threading.Lock()

            def invoke(index: int) -> None:
                barrier.wait()
                try:
                    gateway.execute(basic_request())
                except Exception as exc:  # Expected policy denials are asserted below.
                    with failures_lock:
                        failures.append(exc)

            workers = [threading.Thread(target=invoke, args=(index,)) for index in range(count)]
            for worker in workers:
                worker.start()
            barrier.wait()
            for worker in workers:
                worker.join(timeout=2)
                self.assertFalse(worker.is_alive())
            return failures

        quota_transport = RecordingTransport()
        quota_gateway = EgressGateway(
            basic_policy(maximum_requests=1), quota_transport
        )
        quota_failures = run_concurrently(quota_gateway, 2)
        self.assertEqual(len(quota_transport.sent_at), 1, repr(quota_failures))
        self.assertEqual(len(quota_failures), 1)
        self.assertIsInstance(quota_failures[0], EgressDeniedError)
        self.assertEqual(quota_gateway._request_count, 1)

        rate_transport = RecordingTransport()
        rate_gateway = EgressGateway(
            basic_policy(maximum_requests=3, minimum_interval_seconds=0.03),
            rate_transport,
        )
        self.assertEqual(run_concurrently(rate_gateway, 3), [])
        self.assertEqual(len(rate_transport.sent_at), 3)
        ordered = sorted(rate_transport.sent_at)
        self.assertTrue(
            all(
                later - earlier >= 0.02
                for earlier, later in zip(ordered, ordered[1:])
            )
        )


class CaptureAndParsingTests(unittest.TestCase):
    def test_raw_response_is_registered_before_strict_parsing(self) -> None:
        raw = b'{"captured":true}'
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            gateway, _ = basic_gateway(
                fixture_response(raw),
                registry=registry,
            )
            result = gateway.execute(basic_request())
            self.assertIsNotNone(result.request_artifact)
            self.assertIsNotNone(result.raw_response_artifact)
            self.assertIsNotNone(result.response_receipt_artifact)
            self.assertEqual(
                registry.get_bytes(result.raw_response_artifact.sha256),  # type: ignore[union-attr]
                raw,
            )
            self.assertIn(
                result.raw_response_artifact.sha256,  # type: ignore[union-attr]
                result.response_receipt_artifact.parent_artifacts,  # type: ignore[union-attr]
            )
            self.assertEqual(gateway.parse_json(result), {"captured": True})

    def test_strict_json_rejects_duplicates_nonfinite_and_depth(self) -> None:
        hostile_payloads = (
            b'{"a":1,"a":2}',
            b'{"value":NaN}',
            (b"[" * 70) + b"0" + (b"]" * 70),
        )
        for body in hostile_payloads:
            with self.subTest(body=body[:24]):
                gateway, _ = basic_gateway(fixture_response(body))
                result = gateway.execute(basic_request())
                with self.assertRaises(ExternalParseError):
                    gateway.parse_json(result)

    def test_response_control_denial_captures_raw_attempt_and_sanitized_receipt(self) -> None:
        body = b"not-admitted-as-json"
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            gateway, _ = basic_gateway(
                fixture_response(body, content_type="text/html"),
                registry=registry,
            )
            with self.assertRaises(EgressDeniedError) as caught:
                gateway.execute(basic_request())
            error = caught.exception
            self.assertEqual(len(error.attempts), 1)
            self.assertEqual(error.attempts[0]["status"], "RESPONSE")
            self.assertEqual(
                error.attempts[0]["body_sha256"], hashlib.sha256(body).hexdigest()
            )
            logical_types = {record.logical_type for record in error.artifacts}
            self.assertEqual(
                logical_types,
                {
                    "external_request",
                    "external_response_raw",
                    "external_response_denial_receipt",
                },
            )
            receipt_record = next(
                record
                for record in error.artifacts
                if record.logical_type == "external_response_denial_receipt"
            )
            receipt = safe_json_loads(registry.get_bytes(receipt_record.sha256))
            self.assertEqual(receipt["denial_reason"], "RESPONSE_CONTROLS_INVALID")
            self.assertEqual(receipt["raw_response_sha256"], hashlib.sha256(body).hexdigest())
            self.assertTrue(receipt["raw_response_persisted"])
            self.assertIsNotNone(receipt["raw_response_record_sha256"])
            self.assertNotIn(body, registry.get_bytes(receipt_record.sha256))

    def test_secret_response_denial_records_hash_but_never_raw_secret(self) -> None:
        secret = "fixture-credential-material"
        body = canonical_json_bytes({"echo": secret})
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            credential_policy = basic_policy(
                credential_env_name="FIXTURE_API_KEY",
                credential_required=True,
            )
            gateway, _ = basic_gateway(
                fixture_response(body),
                policy=credential_policy,
                registry=registry,
                credential=secret,
            )
            with self.assertRaises(EgressDeniedError) as caught:
                gateway.execute(basic_request())
            error = caught.exception
            self.assertEqual(len(error.attempts), 1)
            self.assertIsNone(error.attempts[0]["raw_response_record_sha256"])
            logical_types = {record.logical_type for record in error.artifacts}
            self.assertEqual(
                logical_types,
                {"external_request", "external_response_denial_receipt"},
            )
            receipt_record = next(
                record
                for record in error.artifacts
                if record.logical_type == "external_response_denial_receipt"
            )
            receipt = safe_json_loads(registry.get_bytes(receipt_record.sha256))
            self.assertEqual(receipt["denial_reason"], "SECRET_LEAKAGE")
            self.assertEqual(receipt["raw_response_sha256"], hashlib.sha256(body).hexdigest())
            self.assertFalse(receipt["raw_response_persisted"])
            self.assertIsNone(receipt["raw_response_record_sha256"])
            for record in registry.list_records():
                self.assertNotIn(secret.encode("utf-8"), registry.get_bytes(record.sha256))

    def test_transport_failure_after_a_retry_has_a_bounded_terminal_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            transport = FixtureTransport((fixture_response(status=503),))
            clock = FakeMonotonicClock()
            gateway = EgressGateway(
                basic_policy(maximum_attempts=2, maximum_requests=2),
                transport,
                registry=registry,
                clock=clock,
                sleeper=clock.sleep,
                timestamp=lambda: "2026-08-29T12:00:00.000000Z",
            )
            with self.assertRaises(TransportFailure) as caught:
                gateway.execute(basic_request())
            error = caught.exception
            self.assertEqual(len(error.attempts), 2)
            self.assertEqual(
                [attempt["status"] for attempt in error.attempts],
                ["RESPONSE", "TRANSPORT_FAILURE"],
            )
            logical_types = {record.logical_type for record in error.artifacts}
            self.assertEqual(
                logical_types,
                {
                    "external_request",
                    "external_response_raw",
                    "external_transport_failure_receipt",
                },
            )
            receipt_record = next(
                record
                for record in error.artifacts
                if record.logical_type == "external_transport_failure_receipt"
            )
            receipt = safe_json_loads(registry.get_bytes(receipt_record.sha256))
            self.assertEqual(receipt["terminal_reason"], "TRANSPORT_RETRY_EXHAUSTED")
            self.assertEqual(len(receipt["attempts"]), 2)

    def test_stdlib_transport_is_direct_and_ignores_proxy_environment(self) -> None:
        created: list[object] = []

        class FakeHTTPSConnection:
            def __init__(self, host, port, *, timeout, context):
                self.host = host
                self.port = port
                self.timeout = timeout
                self.context = context
                self.request_call = None
                self.closed = False
                created.append(self)

        transport = StdlibHttpsTransport()
        gateway = EgressGateway(
            basic_policy(
                timeout_seconds=4.0,
                maximum_response_bytes=1024,
            ),
            transport,
        )
        with mock.patch(
            "scientist_one.external.http.client.HTTPSConnection",
            FakeHTTPSConnection,
        ), mock.patch.dict(
            os.environ,
            {"HTTPS_PROXY": "http://proxy.invalid:3128"},
            clear=False,
        ), self.assertRaises(EgressDeniedError) as caught:
            gateway.execute(
                basic_request(
                    headers=(
                        ("Accept", "application/json"),
                        ("content-type", "application/json"),
                    ),
                    body=b"{}",
                )
            )
        self.assertEqual(
            caught.exception.transport_authority,
            UNVERIFIED_TRANSPORT_AUTHORITY,
        )
        self.assertEqual(caught.exception.external_validation, "UNTESTED")
        self.assertFalse(transport.inherits_proxy_environment)
        self.assertEqual(created, [])

    def test_self_reporting_transport_cannot_mint_live_authority(self) -> None:
        class SelfReportingTransport:
            network_used = True
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = (
                "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
            )

            def send(self, request, *, credential):
                external_module._consume_prepared_request(request, self)
                return fixture_response()

        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            ledger = EventLedger(directory)
            run_id = "run-self-reporting-transport"
            ledger.record(
                run_id=run_id,
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.GROUND,
                requested_state_after=MacroState.GROUND,
                artifact_hashes=(),
                code_version="fixture-code",
                configuration_hash=digest("configuration"),
                reason="establish self-reporting transport test prefix",
                event_type="CHECKPOINT",
            )
            gateway = EgressGateway(
                basic_policy(),
                SelfReportingTransport(),
                registry=registry,
                authority_run_id=run_id,
                authority_ledger=ledger,
            )
            self.assertEqual(gateway.availability(), "UNTESTED")
            result = gateway.execute(basic_request())
            self.assertTrue(result.network_used)
            self.assertEqual(result.external_validation, "UNTESTED")
            self.assertEqual(
                result.transport_authority,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            )
            receipt = safe_json_loads(
                registry.get_bytes(result.response_receipt_artifact.sha256)  # type: ignore[union-attr]
            )
            self.assertEqual(
                receipt["transport_authority"],
                UNVERIFIED_TRANSPORT_AUTHORITY,
            )
            self.assertEqual(receipt["external_validation"], "UNTESTED")
            self.assertIsNone(result.transport_execution_authority_artifact)
            self.assertFalse(
                (
                    registry.policy.root
                    / registry.base_path
                    / PRIVATE_AUTHORITY_KEY_NAME
                ).exists()
            )

    def test_gateway_subclass_and_mutable_transport_symbol_cannot_mint_authority(
        self,
    ) -> None:
        with self.assertRaises(TypeError):

            class BlockedGateway(EgressGateway):
                pass

        with mock.patch.object(
            EgressGateway,
            "__init_subclass__",
            classmethod(lambda cls, **kwargs: None),
        ):

            class DerivedGateway(EgressGateway):
                @property
                def transport_authority(self) -> str:
                    return AUDITED_LIVE_TRANSPORT_AUTHORITY

        transport = FixtureTransport((fixture_response(),))
        derived = DerivedGateway(basic_policy(), transport)
        with self.assertRaises(EgressPolicyError):
            derived.execute(basic_request())
        self.assertEqual(transport.sent_request_ids, [])
        with self.assertRaises(ModelProviderError):
            OpenAIResponsesProvider(derived)

        replacement_type = type(
            "StdlibHttpsTransport",
            (),
            {
                "network_used": True,
                "inherits_proxy_environment": False,
                "scientific_evidence": False,
                "external_validation": (
                    "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                ),
                "__init__": lambda self: setattr(self, "_tls_context", None),
                "send": StdlibHttpsTransport.__dict__["send"],
            },
        )
        with mock.patch.object(
            external_module,
            "StdlibHttpsTransport",
            replacement_type,
        ):
            replacement_gateway = EgressGateway(
                basic_policy(),
                replacement_type(),
            )
            self.assertEqual(
                replacement_gateway.transport_authority,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            )
            self.assertEqual(replacement_gateway.availability(), "UNTESTED")

        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            exact_gateway = EgressGateway(
                openai_responses_policy(maximum_attempts=1),
                FixtureTransport((fixture_response(url=OPENAI_URL),)),
                registry=registry,
                secret_resolver=lambda _name: "fixture-credential",
            )
            provider = OpenAIResponsesProvider(exact_gateway)
            exact_gateway.execute = lambda *args, **kwargs: None  # type: ignore[method-assign]
            with self.assertRaises(ModelProviderError):
                provider.availability()

            class ReplacementGateway:
                pass

            replacement = ReplacementGateway()
            with mock.patch.object(
                providers_module,
                "EgressGateway",
                ReplacementGateway,
            ), self.assertRaises(ModelProviderError):
                OpenAIResponsesProvider(replacement)  # type: ignore[arg-type]

    def test_class_level_https_and_tls_shadowing_is_unverified(self) -> None:
        class FakeHTTPResponse:
            status = 200

            def __init__(self) -> None:
                self.remaining = b'{"local":true}'

            def getheaders(self):
                return (
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(self.remaining))),
                )

            def read(self, _maximum):
                value, self.remaining = self.remaining, b""
                return value

        transport = StdlibHttpsTransport()
        gateway = EgressGateway(basic_policy(), transport)
        self.assertEqual(
            gateway.transport_authority,
            AUDITED_LIVE_TRANSPORT_AUTHORITY,
        )
        with mock.patch.object(
            external_module.http.client.HTTPSConnection,
            "request",
            lambda self, method, target, *, body, headers: None,
        ), mock.patch.object(
            external_module.http.client.HTTPSConnection,
            "getresponse",
            lambda self: FakeHTTPResponse(),
        ):
            self.assertEqual(gateway.availability(), "UNTESTED")
            result = gateway.execute(basic_request())
        self.assertEqual(
            result.transport_authority,
            UNVERIFIED_TRANSPORT_AUTHORITY,
        )
        self.assertEqual(result.external_validation, "UNTESTED")

        with mock.patch.object(
            ssl.SSLContext,
            "wrap_socket",
            lambda self, *args, **kwargs: None,
        ):
            self.assertEqual(
                gateway.transport_authority,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            )
            self.assertEqual(gateway.availability(), "UNTESTED")

    def test_transport_response_constructor_and_symbol_shadow_are_unverified(
        self,
    ) -> None:
        gateway = EgressGateway(basic_policy(), StdlibHttpsTransport())
        self.assertEqual(
            gateway.transport_authority,
            AUDITED_LIVE_TRANSPORT_AUTHORITY,
        )

        def forged_init(
            response,
            *,
            status_code,
            headers,
            body,
            effective_url,
        ) -> None:
            del status_code, headers, body
            object.__setattr__(response, "status_code", 299)
            object.__setattr__(
                response,
                "headers",
                (("Content-Type", "application/json"),),
            )
            object.__setattr__(response, "body", b'{"forged":true}')
            object.__setattr__(response, "effective_url", effective_url)

        with mock.patch.object(TransportResponse, "__init__", forged_init):
            forged = TransportResponse(
                status_code=200,
                headers=(("Content-Type", "application/json"),),
                body=b'{"original":true}',
                effective_url=BASIC_URL,
            )
            self.assertEqual(forged.status_code, 299)
            self.assertEqual(forged.body, b'{"forged":true}')
            self.assertEqual(
                gateway.transport_authority,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            )
            self.assertEqual(gateway.availability(), "UNTESTED")

        replacement_response_type = type(
            "TransportResponse",
            (),
            {},
        )
        with mock.patch.object(
            external_module,
            "TransportResponse",
            replacement_response_type,
        ):
            self.assertEqual(
                gateway.transport_authority,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            )
            self.assertEqual(gateway.availability(), "UNTESTED")

        self.assertEqual(
            gateway.transport_authority,
            AUDITED_LIVE_TRANSPORT_AUTHORITY,
        )

    def test_socket_connection_factory_shadow_is_unverified(self) -> None:
        gateway = EgressGateway(basic_policy(), StdlibHttpsTransport())
        self.assertEqual(
            gateway.transport_authority,
            AUDITED_LIVE_TRANSPORT_AUTHORITY,
        )

        def replacement_create_connection(*_args, **_kwargs):
            raise AssertionError("replacement connection factory must not run")

        with mock.patch.object(
            external_module.http.client.socket,
            "create_connection",
            replacement_create_connection,
        ):
            self.assertEqual(
                gateway.transport_authority,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            )
            self.assertEqual(gateway.availability(), "UNTESTED")

        self.assertEqual(
            gateway.transport_authority,
            AUDITED_LIVE_TRANSPORT_AUTHORITY,
        )

    def test_transient_consumer_swap_cannot_bypass_send_call_chain(self) -> None:
        original_consume = external_module._consume_prepared_request
        original_connection = external_module.http.client.HTTPSConnection
        fake_connections: list[object] = []

        class FakeHTTPResponse:
            status = 200

            def __init__(self) -> None:
                self.remaining = b'{"forged":true}'

            def getheaders(self):
                return (("Content-Type", "application/json"),)

            def read(self, _maximum):
                value, self.remaining = self.remaining, b""
                return value

        class FakeHTTPSConnection:
            def __init__(self, *_args, **_kwargs) -> None:
                fake_connections.append(self)
                external_module.http.client.HTTPSConnection = original_connection

            def request(self, *_args, **_kwargs) -> None:
                return None

            def getresponse(self):
                return FakeHTTPResponse()

            def close(self) -> None:
                return None

        def transient_consume(request, transport) -> None:
            external_module._consume_prepared_request = original_consume
            original_consume(request, transport)
            external_module.http.client.HTTPSConnection = FakeHTTPSConnection

        def clock() -> float:
            external_module._consume_prepared_request = transient_consume
            return 1.0

        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            ledger = EventLedger(directory)
            run_id = "run-transient-consumer-swap"
            ledger.record(
                run_id=run_id,
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.GROUND,
                requested_state_after=MacroState.GROUND,
                artifact_hashes=(),
                code_version="fixture-code",
                configuration_hash=digest("configuration"),
                reason="establish transient consumer swap test prefix",
                event_type="CHECKPOINT",
            )
            gateway = EgressGateway(
                basic_policy(),
                StdlibHttpsTransport(),
                registry=registry,
                clock=clock,
                authority_run_id=run_id,
                authority_ledger=ledger,
            )
            try:
                with self.assertRaises(EgressDeniedError) as caught:
                    gateway.execute(basic_request())
            finally:
                external_module._consume_prepared_request = original_consume
                external_module.http.client.HTTPSConnection = original_connection

            self.assertEqual(
                caught.exception.transport_authority,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            )
            self.assertEqual(caught.exception.external_validation, "UNTESTED")
            self.assertEqual(fake_connections, [])
            self.assertNotIn(
                AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
                {record.logical_type for record in registry.list_records()},
            )
            self.assertFalse(
                (
                    registry.policy.root
                    / registry.base_path
                    / PRIVATE_AUTHORITY_KEY_NAME
                ).exists()
            )

    def test_registry_and_ledger_strings_cannot_forge_gateway_issuance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            ledger = EventLedger(directory)
            run_id = "run-forged-live-authority"
            ledger.record(
                run_id=run_id,
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.GROUND,
                requested_state_after=MacroState.GROUND,
                artifact_hashes=(),
                code_version="fixture-code",
                configuration_hash=digest("configuration"),
                reason="establish exact forged-authority test prefix",
                event_type="CHECKPOINT",
            )
            gateway = EgressGateway(
                basic_policy(),
                StdlibHttpsTransport(),
                registry=registry,
                authority_run_id=run_id,
                authority_ledger=ledger,
            )
            self.assertEqual(
                gateway.transport_authority,
                AUDITED_LIVE_TRANSPORT_AUTHORITY,
            )
            key_path = (
                registry.policy.root
                / registry.base_path
                / PRIVATE_AUTHORITY_KEY_NAME
            )
            for forbidden in (
                "_issue_audited_transport_execution_authority",
                "_issue_audited_transport_execution_authority_with_key",
                "_prepare_audited_transport_execution_claim",
                "_read_gateway_authority_key",
                "_load_or_create_gateway_authority_key",
                "_build_gateway_authority_key_access",
                "_require_audited_live_transport_execution_with_key",
            ):
                self.assertNotIn(forbidden, vars(external_module))
                with self.assertRaises(AttributeError):
                    getattr(external_module, forbidden)
            self.assertFalse(key_path.exists())
            self.assertEqual(registry.list_records(), ())

            request_payload = {
                "schema_version": "1.0",
                "kind": "REDACTED_EXTERNAL_REQUEST",
                "request_id": digest("forged-request"),
                "policy_id": "fixture-policy-v1",
                "adapter_id": "fixture",
                "method": "POST",
                "url": BASIC_URL,
                "headers": [["Accept", "application/json"]],
                "body_sha256": digest("request-body"),
                "body_size": 2,
                "content_type": "application/json",
                "credential_env_name": None,
                "credential_present": False,
                "parent_artifacts": [],
                "scientific_evidence": False,
            }
            request_record = registry.put_json(
                request_payload,
                logical_type="external_request",
                origin="controlled external egress request intent",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "controlled-egress"),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            raw_body = b'{"forged":true}'
            raw_record = registry.put_bytes(
                raw_body,
                logical_type="external_response_raw",
                origin="controlled external egress raw response",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "controlled-egress"),
                schema_version="1.0",
                mime_type="application/octet-stream",
                validation_result="PASS",
                frozen=True,
            )
            attempts = [
                {
                    "attempt": 1,
                    "status": "RESPONSE",
                    "status_code": 200,
                    "body_sha256": hashlib.sha256(raw_body).hexdigest(),
                    "body_size": len(raw_body),
                    "raw_response_record_sha256": raw_record.sha256,
                }
            ]
            receipt_record = registry.put_json(
                {
                    "schema_version": "1.0",
                    "kind": "EXTERNAL_RESPONSE_RECEIPT",
                    "request_id": request_payload["request_id"],
                    "request_artifact_sha256": request_record.sha256,
                    "raw_response_sha256": hashlib.sha256(raw_body).hexdigest(),
                    "raw_response_record_sha256": raw_record.sha256,
                    "status_code": 200,
                    "content_type": "application/json",
                    "body_size": len(raw_body),
                    "headers": {"content-type": "application/json"},
                    "attempts": attempts,
                    "captured_at": "2026-08-29T12:00:00.000000Z",
                    "network_used": True,
                    "scientific_evidence": False,
                    "external_validation": (
                        "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                    ),
                    "transport_authority": AUDITED_LIVE_TRANSPORT_AUTHORITY,
                },
                logical_type="external_response_receipt",
                origin="controlled external egress response receipt",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "controlled-egress"),
                parent_artifacts=(request_record.sha256, raw_record.sha256),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            prefix = ledger.validate(raise_on_error=True)
            issued_at = "2026-08-29T12:00:01.000000Z"
            authority_record = registry.put_json(
                {
                    "schema_version": AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
                    "kind": "AUDITED_TRANSPORT_EXECUTION_AUTHORITY",
                    "run_id": run_id,
                    "request_id": request_payload["request_id"],
                    "policy_id": "fixture-policy-v1",
                    "adapter_id": "fixture",
                    "request_artifact_sha256": request_record.sha256,
                    "request_artifact_record_hash": request_record.record_hash,
                    "response_receipt_artifact_sha256": receipt_record.sha256,
                    "response_receipt_record_hash": receipt_record.record_hash,
                    "raw_response_artifact_sha256": raw_record.sha256,
                    "raw_response_artifact_record_hash": raw_record.record_hash,
                    "raw_response_sha256": hashlib.sha256(raw_body).hexdigest(),
                    "body_size": len(raw_body),
                    "status_code": 200,
                    "content_type": "application/json",
                    "attempts_sha256": hashlib.sha256(
                        canonical_json_bytes(attempts)
                    ).hexdigest(),
                    "network_used": True,
                    "external_validation": (
                        "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                    ),
                    "transport_authority": AUDITED_LIVE_TRANSPORT_AUTHORITY,
                    "implementation_profile": (
                        external_module._audited_transport_implementation_profile()
                    ),
                    "ledger_prefix_head_hash": prefix.head_hash,
                    "ledger_prefix_event_count": len(prefix.events),
                    "issued_at": issued_at,
                    "nonce": "0" * 32,
                    "key_id": "0" * 64,
                    "claim_sha256": "0" * 64,
                    "authentication_tag": "0" * 64,
                },
                logical_type=AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
                origin=(
                    "gateway-signed audited HTTPS transport execution authority"
                ),
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=(
                    "scientist-one",
                    "issue-audited-transport-execution-authority",
                ),
                parent_artifacts=(receipt_record.sha256,),
                schema_version=AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=issued_at,
            )
            ledger.record(
                run_id=run_id,
                actor_role=Role.EVIDENCE_CURATOR,
                state_before=MacroState.GROUND,
                requested_state_after=MacroState.GROUND,
                artifact_hashes=(authority_record.sha256,),
                code_version="fixture-code",
                configuration_hash=digest("configuration"),
                reason=(
                    "anchor gateway-signed audited HTTPS transport execution authority"
                ),
                event_type="CHECKPOINT",
            )
            with self.assertRaises(EgressPolicyError):
                require_audited_live_transport_execution(
                    registry,
                    ledger,
                    run_id=run_id,
                    authority_artifact_sha256=authority_record.sha256,
                    response_receipt_artifact_sha256=receipt_record.sha256,
                )
            self.assertFalse(key_path.exists())

    def test_authority_verifier_rejects_unsafe_private_key_entries(self) -> None:
        for variant in ("symlink", "hardlink", "mode", "size"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                registry = ArtifactRegistry(directory)
                ledger = EventLedger(directory)
                key_path = (
                    registry.policy.root
                    / registry.base_path
                    / PRIVATE_AUTHORITY_KEY_NAME
                )
                target = Path(directory) / "caller-key-material"
                target.write_bytes(b"k" * 32)
                os.chmod(target, 0o600)
                if variant == "symlink":
                    key_path.symlink_to(target)
                elif variant == "hardlink":
                    os.link(target, key_path)
                else:
                    key_path.write_bytes(
                        b"k" * (31 if variant == "size" else 32)
                    )
                    os.chmod(key_path, 0o600 if variant == "size" else 0o644)
                with self.assertRaises(EgressPolicyError):
                    require_audited_live_transport_execution(
                        registry,
                        ledger,
                        run_id="run-unsafe-authority-key",
                        authority_artifact_sha256=digest("authority"),
                        response_receipt_artifact_sha256=digest("receipt"),
                    )

    def test_authenticated_v1_authority_schema_matrix_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            ledger = EventLedger(directory)
            run_id = "run-authenticated-v1-rejection"
            receipt = registry.put_json(
                {"schema_version": external_module.EGRESS_RESPONSE_RECEIPT_SCHEMA},
                logical_type="external_response_receipt",
                origin="controlled external egress response receipt",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "controlled-egress"),
                schema_version=external_module.EGRESS_RESPONSE_RECEIPT_SCHEMA,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            closure = inspect.getclosurevars(
                require_audited_live_transport_execution
            ).nonlocals
            require_with_key = closure["require_with_key"]
            implementation_profile = closure["implementation_profile"]
            request_policy_replay = closure["exact_request_policy_replay"]
            retry_backoff_replay = closure["exact_retry_backoff_replay"]
            key = b"k" * 32
            issued_at = "2026-08-29T12:00:01.000000Z"
            for index, (payload_schema, record_schema) in enumerate((
                ("audited-transport-authority/v1", external_module.AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA),
                (external_module.AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA, "audited-transport-authority/v1"),
                ("audited-transport-authority/v1", "audited-transport-authority/v1"),
            ), start=1):
                with self.subTest(
                    payload_schema=payload_schema,
                    record_schema=record_schema,
                ):
                    unsigned = {
                        "schema_version": payload_schema,
                        "kind": "AUDITED_TRANSPORT_EXECUTION_AUTHORITY",
                        "run_id": run_id,
                        "request_id": digest("authenticated-v1-request"),
                        "policy_id": "fixture-policy-v1",
                        "adapter_id": "fixture",
                        "policy": {},
                        "policy_claim_sha256": digest("policy"),
                        "prepared_request": {},
                        "prepared_request_binding": digest("prepared"),
                        "request_artifact_sha256": digest("request"),
                        "request_artifact_record_hash": digest("request-record"),
                        "response_receipt_artifact_sha256": receipt.sha256,
                        "response_receipt_record_hash": receipt.record_hash,
                        "raw_response_artifact_sha256": digest("raw"),
                        "raw_response_artifact_record_hash": digest("raw-record"),
                        "raw_response_sha256": digest("raw-body"),
                        "body_size": 0,
                        "status_code": 200,
                        "content_type": "application/json",
                        "response_effective_url": BASIC_URL,
                        "response_headers_sha256": digest("headers"),
                        "response_header_count": 1,
                        "attempts": [],
                        "attempts_sha256": digest("attempts"),
                        "egress_budget": {},
                        "network_used": True,
                        "external_validation": (
                            "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                        ),
                        "transport_authority": AUDITED_LIVE_TRANSPORT_AUTHORITY,
                        "implementation_profile": dict(implementation_profile),
                        "ledger_prefix_head_hash": digest("prefix"),
                        "ledger_prefix_event_count": 1,
                        "issued_at": issued_at,
                        "nonce": f"{index:032x}",
                        "key_id": hashlib.sha256(key).hexdigest(),
                    }
                    metadata_claim = (
                        external_module._authority_artifact_metadata_claim(
                            response_receipt_artifact_sha256=receipt.sha256,
                            created_at=issued_at,
                        )
                    )
                    claim_bytes = canonical_json_bytes(
                        {
                            "authority": unsigned,
                            "artifact_metadata": metadata_claim,
                        }
                    )
                    payload = {
                        **unsigned,
                        "claim_sha256": hashlib.sha256(claim_bytes).hexdigest(),
                        "authentication_tag": hmac.new(
                            key,
                            claim_bytes,
                            hashlib.sha256,
                        ).hexdigest(),
                    }
                    authority = registry.put_json(
                        payload,
                        logical_type=(
                            AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE
                        ),
                        origin=(
                            "gateway-signed audited HTTPS transport execution authority"
                        ),
                        creator_role=Role.EVIDENCE_CURATOR,
                        creation_command=(
                            "scientist-one",
                            "issue-audited-transport-execution-authority",
                        ),
                        parent_artifacts=(receipt.sha256,),
                        schema_version=record_schema,
                        mime_type="application/json",
                        validation_result="PASS",
                        frozen=True,
                        created_at=issued_at,
                    )
                    with self.assertRaises(EgressPolicyError):
                        require_with_key(
                            registry,
                            ledger,
                            run_id=run_id,
                            authority_artifact_sha256=authority.sha256,
                            response_receipt_artifact_sha256=receipt.sha256,
                            authority_key=key,
                            implementation_profile=implementation_profile,
                            request_policy_replay=request_policy_replay,
                            retry_backoff_replay=retry_backoff_replay,
                        )

    def test_inspect_recovered_issuer_rejects_missing_one_shot_capability(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            ledger = EventLedger(directory)
            run_id = "run-recovered-issuer-without-capability"
            ledger.record(
                run_id=run_id,
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.GROUND,
                requested_state_after=MacroState.GROUND,
                artifact_hashes=(),
                code_version="fixture-code",
                configuration_hash=digest("configuration"),
                reason="establish recovered-issuer test prefix",
                event_type="CHECKPOINT",
            )
            gateway = EgressGateway(
                basic_policy(),
                StdlibHttpsTransport(),
                registry=registry,
                authority_run_id=run_id,
                authority_ledger=ledger,
            )
            closure_state = inspect.getclosurevars(EgressGateway.execute).nonlocals
            recovered_issuer = closure_state["authority_issuer"]
            self.assertIsNone(recovered_issuer(object(), gateway=gateway))
            self.assertIsNone(recovered_issuer(True, gateway=gateway))
            fixture_transport = FixtureTransport((fixture_response(),))
            fixture_gateway = EgressGateway(
                basic_policy(),
                fixture_transport,
                registry=registry,
            )
            fixture_gateway.execute(basic_request())
            stale_capability = fixture_transport.prepared_requests[0]._capability
            self.assertIsNotNone(stale_capability)
            self.assertIsNone(
                recovered_issuer(
                    stale_capability,
                    gateway=fixture_gateway,
                )
            )
            self.assertIsNone(
                recovered_issuer(stale_capability, gateway=gateway)
            )
            self.assertNotIn(
                AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
                {record.logical_type for record in registry.list_records()},
            )
            self.assertFalse(
                (
                    registry.policy.root
                    / registry.base_path
                    / PRIVATE_AUTHORITY_KEY_NAME
                ).exists()
            )

    def test_insecure_or_shadowed_stdlib_transport_is_not_audited(self) -> None:
        caller_context_gateway = EgressGateway(
            basic_policy(),
            StdlibHttpsTransport(tls_context=ssl.create_default_context()),
        )
        self.assertEqual(
            caller_context_gateway.transport_authority,
            UNVERIFIED_TRANSPORT_AUTHORITY,
        )
        self.assertEqual(caller_context_gateway.availability(), "UNTESTED")

        insecure_context = ssl.create_default_context()
        insecure_context.check_hostname = False
        insecure_context.verify_mode = ssl.CERT_NONE
        insecure = StdlibHttpsTransport(tls_context=insecure_context)
        insecure_gateway = EgressGateway(basic_policy(), insecure)
        self.assertEqual(
            insecure_gateway.transport_authority,
            UNVERIFIED_TRANSPORT_AUTHORITY,
        )
        self.assertEqual(insecure_gateway.availability(), "UNTESTED")
        with mock.patch(
            "scientist_one.external.http.client.HTTPSConnection"
        ) as connection, self.assertRaises(EgressDeniedError):
            insecure_gateway.execute(basic_request())
        connection.assert_not_called()

        weak_protocol_context = ssl.create_default_context()
        weak_protocol_context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        weak_protocol_gateway = EgressGateway(
            basic_policy(),
            StdlibHttpsTransport(tls_context=weak_protocol_context),
        )
        self.assertEqual(
            weak_protocol_gateway.transport_authority,
            UNVERIFIED_TRANSPORT_AUTHORITY,
        )
        with mock.patch(
            "scientist_one.external.http.client.HTTPSConnection"
        ) as weak_connection, self.assertRaises(EgressDeniedError):
            weak_protocol_gateway.execute(basic_request())
        weak_connection.assert_not_called()

        shadowed_context = ssl.create_default_context()
        shadowed_context.wrap_socket = lambda *args, **kwargs: None  # type: ignore[method-assign]
        shadowed_context_gateway = EgressGateway(
            basic_policy(),
            StdlibHttpsTransport(tls_context=shadowed_context),
        )
        self.assertEqual(
            shadowed_context_gateway.transport_authority,
            UNVERIFIED_TRANSPORT_AUTHORITY,
        )
        with mock.patch(
            "scientist_one.external.http.client.HTTPSConnection"
        ) as shadowed_connection, self.assertRaises(EgressDeniedError):
            shadowed_context_gateway.execute(basic_request())
        shadowed_connection.assert_not_called()

        shadowed = StdlibHttpsTransport()

        def local_response(self, request, *, credential):
            external_module._consume_prepared_request(request, self)
            del self.send
            return fixture_response()

        shadowed.send = MethodType(local_response, shadowed)  # type: ignore[method-assign]
        shadowed_gateway = EgressGateway(basic_policy(), shadowed)
        shadowed_result = shadowed_gateway.execute(basic_request())
        self.assertEqual(
            shadowed_gateway.transport_authority,
            AUDITED_LIVE_TRANSPORT_AUTHORITY,
        )
        self.assertEqual(
            shadowed_result.transport_authority,
            UNVERIFIED_TRANSPORT_AUTHORITY,
        )
        self.assertEqual(shadowed_result.external_validation, "UNTESTED")

    def test_raw_transport_rejects_direct_fake_and_replayed_authority(self) -> None:
        prepared = PreparedEgressRequest(
            request_id=digest("request"),
            method="POST",
            url=BASIC_URL,
            host="example.org",
            target="/api/item",
            headers=(("Accept", "application/json"),),
            body=b"{}",
        )
        transport = StdlibHttpsTransport()
        with mock.patch(
            "scientist_one.external.http.client.HTTPSConnection"
        ) as connection:
            with self.assertRaises(EgressDeniedError):
                transport.send(prepared, credential=None)
            connection.assert_not_called()

            gateway = EgressGateway(basic_policy(), transport)
            object.__setattr__(prepared, "_capability", object())
            with self.assertRaises(EgressDeniedError):
                transport.send(prepared, credential=None)
            connection.assert_not_called()
            with self.assertRaises(AttributeError):
                gateway._mint_transport_capability(  # type: ignore[attr-defined]
                    transport=transport,
                    request_id=prepared.request_id,
                    binding=external_module._prepared_request_binding(prepared),
                )

        fixture = FixtureTransport((fixture_response(),))
        gateway = EgressGateway(basic_policy(), fixture)
        gateway.execute(basic_request())
        admitted = fixture.prepared_requests[0]
        with self.assertRaises(EgressDeniedError):
            fixture.send(admitted, credential=None)
        self.assertNotIn("PreparedEgressRequest", external_module.__all__)
        self.assertNotIn("StdlibHttpsTransport", external_module.__all__)
        self.assertFalse(hasattr(external_module, "_PreparedEgressCapability"))
        self.assertFalse(hasattr(external_module, "_admit_gateway_execute"))

    def test_admitted_authority_is_exact_request_gateway_and_transport_bound(self) -> None:
        class AuthorityProbeTransport:
            network_used = False
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = "UNTESTED"

            def __init__(self) -> None:
                self.denied: list[str] = []
                self.admitted: PreparedEgressRequest | None = None

            @staticmethod
            def clone(request: PreparedEgressRequest) -> PreparedEgressRequest:
                return PreparedEgressRequest(
                    request_id=request.request_id,
                    method=request.method,
                    url=request.url,
                    host=request.host,
                    target=request.target,
                    headers=request.headers,
                    body=request.body,
                    content_type=request.content_type,
                    timeout_seconds=request.timeout_seconds,
                    maximum_response_bytes=request.maximum_response_bytes,
                    credential_header=request.credential_header,
                    credential_prefix=request.credential_prefix,
                )

            def must_deny(self, label: str, callback) -> None:
                try:
                    callback()
                except EgressDeniedError:
                    self.denied.append(label)
                    return
                raise AssertionError(f"{label} authority unexpectedly succeeded")

            def send(self, request, *, credential):
                token = request._capability
                clone = self.clone(request)
                object.__setattr__(clone, "_capability", token)
                self.must_deny(
                    "cross-request",
                    lambda: external_module._consume_prepared_request(clone, self),
                )

                other_transport = FixtureTransport((fixture_response(),))
                other_gateway = EgressGateway(basic_policy(), other_transport)
                self.assert_no_issuer(other_gateway)
                self.must_deny(
                    "cross-gateway-transport",
                    lambda: other_transport.send(clone, credential=None),
                )

                external_module._consume_prepared_request(request, self)
                self.admitted = request
                return fixture_response()

            @staticmethod
            def assert_no_issuer(gateway: EgressGateway) -> None:
                if hasattr(gateway, "_mint_transport_capability"):
                    raise AssertionError("cross-gateway issuer remained exposed")

        transport = AuthorityProbeTransport()
        gateway = EgressGateway(basic_policy(), transport)
        result = gateway.execute(basic_request())
        self.assertEqual(result.status_code, 200)
        self.assertEqual(
            transport.denied,
            ["cross-request", "cross-gateway-transport"],
        )
        self.assertIsNotNone(transport.admitted)
        with self.assertRaises(EgressDeniedError):
            transport.send(transport.admitted, credential=None)


class OpenAIProviderTests(unittest.TestCase):
    def test_offline_structured_success_has_full_non_evidence_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            provider, transport = openai_provider(
                openai_envelope(),
                registry=registry,
            )
            availability = provider.availability()
            self.assertEqual(availability.status, "UNTESTED")
            self.assertEqual(availability.credential_status, "PRESENT")
            self.assertFalse(availability.network_used)
            self.assertEqual(
                availability.transport_authority,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            )
            result = provider.invoke(invocation())
            self.assertEqual(result.status, ModelRunStatus.COMPLETED)
            self.assertEqual(result.external_validation, "UNTESTED")
            self.assertFalse(result.network_used)
            self.assertEqual(
                result.transport_authority,
                UNVERIFIED_TRANSPORT_AUTHORITY,
            )
            self.assertFalse(result.scientific_evidence)
            self.assertEqual(result.provenance_status, "CAPTURED")
            self.assertIsNone(
                result.transport_execution_authority_artifact_sha256
            )
            self.assertIsNone(result.terminal_receipt)
            self.assertEqual(dict(result.output), {"summary": "bounded result", "score": 0.75})
            self.assertEqual(
                safe_json_loads(canonical_json_bytes(result.usage)),
                {
                    "input_tokens": 11,
                    "input_tokens_details": {
                        "cached_tokens": 3,
                        "cache_write_tokens": 2,
                    },
                    "output_tokens": 7,
                    "output_tokens_details": {"reasoning_tokens": 4},
                    "total_tokens": 18,
                },
            )
            self.assertEqual(
                [record.logical_type for record in result.artifacts],
                [
                    "model_judged_instructions",
                    "model_judged_input",
                    "model_output_schema",
                    "model_invocation",
                    "model_provider_request_body",
                    "model_provider_request_intent",
                    "external_request",
                    "external_response_raw",
                    "external_response_receipt",
                    "model_provider_response",
                    "model_output",
                ],
            )
            logical_types = {record.logical_type for record in result.artifacts}
            self.assertEqual(
                {
                    "model_judged_instructions",
                    "model_judged_input",
                    "model_output_schema",
                    "model_invocation",
                    "model_provider_request_body",
                    "model_provider_request_intent",
                    "external_request",
                    "external_response_raw",
                    "external_response_receipt",
                    "model_provider_response",
                    "model_output",
                },
                logical_types,
            )
            for record in result.artifacts:
                self.assertEqual(registry.get_metadata(record.sha256).sha256, record.sha256)

            self.assertEqual(transport.credential_present, [False])
            prepared_body = transport.prepared_requests[0].body
            sent = safe_json_loads(prepared_body)
            self.assertEqual(sent["tools"], [])
            self.assertEqual(sent["tool_choice"], "none")
            self.assertIs(sent["store"], False)
            self.assertEqual(sent["truncation"], "disabled")
            self.assertEqual(sent["text"]["format"]["type"], "json_schema")
            self.assertIs(sent["text"]["format"]["strict"], True)

            by_type = {record.logical_type: record for record in result.artifacts}
            for logical_type in (
                "external_response_receipt",
                "model_provider_response",
                "model_output",
            ):
                value = safe_json_loads(registry.get_bytes(by_type[logical_type].sha256))
                self.assertEqual(
                    value["transport_authority"],
                    UNVERIFIED_TRANSPORT_AUTHORITY,
                )
                self.assertNotIn(
                    "transport_execution_authority_artifact_sha256",
                    value,
                )
            self.assertEqual(
                registry.get_bytes(by_type["model_judged_instructions"].sha256),
                invocation().instructions.encode("utf-8"),
            )
            self.assertEqual(
                registry.get_bytes(by_type["model_judged_input"].sha256),
                invocation().input_text.encode("utf-8"),
            )
            self.assertEqual(
                registry.get_bytes(by_type["model_output_schema"].sha256),
                canonical_json_bytes(output_schema()),
            )
            self.assertEqual(
                registry.get_bytes(by_type["model_provider_request_body"].sha256),
                prepared_body,
            )
            self.assertEqual(
                by_type["model_provider_request_body"].parent_artifacts,
                (),
            )
            self.assertEqual(
                set(by_type["model_provider_request_intent"].parent_artifacts),
                {
                    by_type["model_invocation"].sha256,
                    by_type["model_provider_request_body"].sha256,
                },
            )
            self.assertEqual(
                by_type["model_provider_response"].parent_artifacts,
                (
                    by_type["external_response_raw"].sha256,
                    by_type["external_response_receipt"].sha256,
                ),
            )
            self.assertEqual(
                by_type["model_output"].parent_artifacts,
                (
                    by_type["model_invocation"].sha256,
                    by_type["model_provider_request_body"].sha256,
                    by_type["model_provider_response"].sha256,
                ),
            )

    def test_provider_never_exposes_credential_to_unverified_transport(self) -> None:
        secret = "fixture-credential-material"

        class DeceptiveOfflineTransport:
            network_used = False
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = "UNTESTED"

            def __init__(self) -> None:
                self.received: list[str | None] = []

            def send(self, request, *, credential):
                external_module._consume_prepared_request(request, self)
                self.received.append(credential)
                reflected = credential[::-1] if credential is not None else "redacted"
                return fixture_response(
                    openai_envelope(
                        canonical_json_bytes(
                            {"summary": reflected, "score": 0.75}
                        )
                    ),
                    url=OPENAI_URL,
                )

        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            transport = DeceptiveOfflineTransport()
            provider = OpenAIResponsesProvider(
                EgressGateway(
                    openai_responses_policy(
                        maximum_attempts=1,
                        maximum_requests=2,
                    ),
                    transport,
                    registry=registry,
                    secret_resolver=lambda _name: secret,
                    sleeper=lambda _delay: None,
                )
            )
            result = provider.invoke(invocation())
            self.assertIs(result.status, ModelRunStatus.COMPLETED)
            self.assertEqual(
                dict(result.output),
                {"summary": "redacted", "score": 0.75},
            )
            self.assertEqual(transport.received, [None])
            reversed_secret = secret[::-1].encode("utf-8")
            self.assertFalse(
                any(
                    reversed_secret in registry.get_bytes(record.sha256)
                    for record in registry.list_records()
                )
            )

    def test_custody_readback_failure_prevents_provider_output_acceptance(self) -> None:
        provider, transport = openai_provider(openai_envelope())
        with mock.patch.object(
            provider,
            "_custody_valid",
            side_effect=(True, False),
        ):
            result = provider.invoke(invocation())
        self.assertEqual(result.status, ModelRunStatus.EXTERNAL_ERROR)
        self.assertEqual(result.error_code, "PROVIDER_INPUT_CUSTODY_INVALID")
        self.assertIsNone(result.output)
        self.assertEqual(result.provenance_status, "TERMINAL_RECEIPT_CAPTURED")
        self.assertEqual(len(transport.sent_request_ids), 1)

    def test_identical_request_bytes_are_reusable_across_invocations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            transport = FixtureTransport(
                (
                    fixture_response(openai_envelope(), url=OPENAI_URL),
                    fixture_response(openai_envelope(), url=OPENAI_URL),
                )
            )
            clock = FakeMonotonicClock()
            gateway = EgressGateway(
                openai_responses_policy(maximum_attempts=1, maximum_requests=2),
                transport,
                registry=registry,
                secret_resolver=lambda _name: "fixture-credential-material",
                clock=clock,
                sleeper=clock.sleep,
            )
            provider = OpenAIResponsesProvider(gateway)
            first = provider.invoke(invocation(invocation_id="invocation-1"))
            clock.advance(0.05)
            second = provider.invoke(invocation(invocation_id="invocation-2"))
            self.assertEqual(first.status, ModelRunStatus.COMPLETED)
            self.assertEqual(second.status, ModelRunStatus.COMPLETED)
            first_body = next(
                record
                for record in first.artifacts
                if record.logical_type == "model_provider_request_body"
            )
            second_body = next(
                record
                for record in second.artifacts
                if record.logical_type == "model_provider_request_body"
            )
            self.assertEqual(first_body, second_body)
            self.assertEqual(first_body.parent_artifacts, ())

    def test_missing_credential_returns_blocked_without_transport(self) -> None:
        provider, transport = openai_provider(
            openai_envelope(),
            credential=None,
        )
        self.assertEqual(provider.availability().status, "BLOCKED_EXTERNAL")
        result = provider.invoke(invocation())
        self.assertEqual(result.status, ModelRunStatus.BLOCKED_EXTERNAL)
        self.assertEqual(result.external_validation, "BLOCKED_EXTERNAL")
        self.assertFalse(result.scientific_evidence)
        self.assertEqual(result.provenance_status, "TERMINAL_RECEIPT_CAPTURED")
        self.assertIsNotNone(result.terminal_receipt)
        self.assertIn(
            "model_provider_request_body",
            {record.logical_type for record in result.artifacts},
        )
        self.assertEqual(transport.sent_request_ids, [])

    def test_live_credentialed_openai_is_blocked_before_external_custody(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            gateway = EgressGateway(
                openai_responses_policy(
                    maximum_attempts=1,
                    maximum_requests=1,
                ),
                StdlibHttpsTransport(),
                registry=registry,
                secret_resolver=lambda _name: (
                    "fixture-credential-material"
                ),
            )
            provider = OpenAIResponsesProvider(gateway)
            availability = provider.availability()
            self.assertEqual(availability.status, "BLOCKED_EXTERNAL")
            self.assertEqual(availability.credential_status, "PRESENT")
            self.assertTrue(availability.network_used)
            self.assertEqual(
                availability.transport_authority,
                AUDITED_LIVE_TRANSPORT_AUTHORITY,
            )

            result = provider.invoke(invocation())
            self.assertEqual(result.status, ModelRunStatus.BLOCKED_EXTERNAL)
            self.assertEqual(result.error_code, "PROVIDER_UNAVAILABLE")
            self.assertEqual(result.external_validation, "BLOCKED_EXTERNAL")
            self.assertFalse(result.network_used)
            assert result.terminal_receipt is not None
            terminal = safe_json_loads(
                registry.get_bytes(result.terminal_receipt.sha256)
            )
            self.assertEqual(terminal["terminal_state"], "BLOCKED")
            self.assertEqual(terminal["failure_stage"], "AVAILABILITY")
            forbidden = {
                "model_provider_request_intent",
                "external_request",
                "external_response_raw",
                "external_response_receipt",
                AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
                "model_provider_response",
                "model_output",
            }
            self.assertTrue(
                forbidden.isdisjoint(
                    {record.logical_type for record in registry.list_records()}
                )
            )
    def test_secret_like_input_is_rejected_before_exact_custody(self) -> None:
        secret_text = "_".join(("api", "key")) + '=\"' + "abcdefghijklmnop" + '\"'
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            provider, transport = openai_provider(
                openai_envelope(),
                credential=None,
                registry=registry,
            )
            result = provider.invoke(invocation(input_text=secret_text))
            self.assertEqual(result.status, ModelRunStatus.EXTERNAL_ERROR)
            self.assertEqual(result.error_code, "PROVIDER_INPUT_CUSTODY_DENIED")
            self.assertEqual(result.provenance_status, "TERMINAL_RECEIPT_CAPTURED")
            self.assertIsNotNone(result.terminal_receipt)
            self.assertEqual(transport.sent_request_ids, [])
            self.assertEqual(
                {record.logical_type for record in result.artifacts},
                {"model_terminal_receipt"},
            )
            for record in result.artifacts:
                self.assertNotIn(secret_text.encode("utf-8"), registry.get_bytes(record.sha256))
            receipt = safe_json_loads(
                registry.get_bytes(result.terminal_receipt.sha256)  # type: ignore[union-attr]
            )
            self.assertEqual(receipt["terminal_state"], "FAILED")
            self.assertEqual(receipt["failure_class"], "PROVIDER_INPUT_POLICY_DENIAL")
            self.assertEqual(receipt["attempts"], [])
            self.assertIs(receipt["secret_values_persisted"], False)

    def test_supported_provider_requires_registry_custody(self) -> None:
        transport = FixtureTransport((fixture_response(openai_envelope(), url=OPENAI_URL),))
        gateway = EgressGateway(
            openai_responses_policy(maximum_attempts=1, maximum_requests=1),
            transport,
            secret_resolver=lambda _name: "fixture-credential-material",
        )
        with self.assertRaises(ModelProviderError):
            OpenAIResponsesProvider(gateway)

    def test_authentication_rejection_is_captured_but_blocked(self) -> None:
        provider, _ = openai_provider(
            canonical_json_bytes({"error": {"code": "unauthorized"}}),
            status=401,
        )
        result = provider.invoke(invocation())
        self.assertEqual(result.status, ModelRunStatus.BLOCKED_EXTERNAL)
        self.assertEqual(result.error_code, "AUTHENTICATION_REJECTED")
        self.assertFalse(result.scientific_evidence)

    def test_duplicate_provider_json_is_invalid_not_evidence(self) -> None:
        provider, _ = openai_provider(b'{"status":"completed","status":"completed"}')
        result = provider.invoke(invocation())
        self.assertEqual(result.status, ModelRunStatus.INVALID_RESPONSE)
        self.assertEqual(result.error_code, "INVALID_PROVIDER_JSON")
        self.assertFalse(result.scientific_evidence)

    def test_malformed_output_has_parent_linked_terminal_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            provider, _ = openai_provider(
                b'{"status":"completed","status":"completed"}',
                registry=registry,
            )
            result = provider.invoke(invocation())
            self.assertEqual(result.status, ModelRunStatus.INVALID_RESPONSE)
            self.assertEqual(result.provenance_status, "TERMINAL_RECEIPT_CAPTURED")
            receipt = result.terminal_receipt
            self.assertIsNotNone(receipt)
            self.assertEqual(
                set(receipt.parent_artifacts),  # type: ignore[union-attr]
                {record.sha256 for record in result.artifacts if record is not receipt},
            )
            value = safe_json_loads(registry.get_bytes(receipt.sha256))  # type: ignore[union-attr]
            self.assertEqual(value["terminal_state"], "FAILED")
            self.assertEqual(value["error_code"], "INVALID_PROVIDER_JSON")
            self.assertEqual(len(value["attempts"]), 1)

    def test_retry_exhaustion_receipt_bounds_attempts_and_captures_raw_parents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            transport = FixtureTransport(
                (
                    fixture_response(
                        canonical_json_bytes({"error": "retry-one"}),
                        status=503,
                        url=OPENAI_URL,
                    ),
                    fixture_response(
                        canonical_json_bytes({"error": "retry-two"}),
                        status=503,
                        url=OPENAI_URL,
                    ),
                )
            )
            clock = FakeMonotonicClock()
            gateway = EgressGateway(
                openai_responses_policy(maximum_attempts=2, maximum_requests=2),
                transport,
                registry=registry,
                secret_resolver=lambda _name: "fixture-credential-material",
                clock=clock,
                sleeper=clock.sleep,
                timestamp=lambda: "2026-08-29T12:00:00.000000Z",
            )
            result = OpenAIResponsesProvider(gateway).invoke(invocation())
            self.assertEqual(result.status, ModelRunStatus.EXTERNAL_ERROR)
            self.assertEqual(result.provenance_status, "TERMINAL_RECEIPT_CAPTURED")
            raw_records = [
                record
                for record in result.artifacts
                if record.logical_type == "external_response_raw"
            ]
            self.assertEqual(len(raw_records), 2)
            receipt = safe_json_loads(
                registry.get_bytes(result.terminal_receipt.sha256)  # type: ignore[union-attr]
            )
            self.assertEqual(len(receipt["attempts"]), 2)
            self.assertEqual(receipt["failure_class"], "NON_SUCCESS_HTTP_RESPONSE")
            self.assertTrue(
                {record.sha256 for record in raw_records}.issubset(
                    set(result.terminal_receipt.parent_artifacts)  # type: ignore[union-attr]
                )
            )

    def test_duplicate_or_schema_violating_output_is_invalid(self) -> None:
        hostile_outputs = (
            b'{"summary":"first","summary":"second","score":0.5}',
            canonical_json_bytes({"summary": "bounded result", "score": 9}),
            canonical_json_bytes(
                {"summary": "bounded result", "score": 0.5, "extra": True}
            ),
        )
        for output in hostile_outputs:
            with self.subTest(output=output):
                provider, _ = openai_provider(openai_envelope(output))
                result = provider.invoke(invocation())
                self.assertEqual(result.status, ModelRunStatus.INVALID_RESPONSE)
                self.assertEqual(result.error_code, "STRUCTURED_OUTPUT_INVALID")
                self.assertFalse(result.scientific_evidence)

    def test_usage_detail_objects_are_optional_but_strictly_validated(self) -> None:
        envelope = safe_json_loads(openai_envelope())
        envelope["usage"] = {
            "input_tokens": 11,
            "output_tokens": 7,
            "total_tokens": 18,
        }
        provider, _ = openai_provider(canonical_json_bytes(envelope))
        self.assertEqual(provider.invoke(invocation()).status, ModelRunStatus.COMPLETED)

        invalid_usage_values = (
            {
                "input_tokens": 11,
                "input_tokens_details": {"cached_tokens": 3, "unknown": 1},
                "output_tokens": 7,
                "total_tokens": 18,
            },
            {
                "input_tokens": 11,
                "input_tokens_details": {"cache_write_tokens": 2},
                "output_tokens": 7,
                "total_tokens": 18,
            },
            {
                "input_tokens": 11,
                "input_tokens_details": {"cached_tokens": True},
                "output_tokens": 7,
                "total_tokens": 18,
            },
            {
                "input_tokens": 11,
                "input_tokens_details": {"cached_tokens": 12},
                "output_tokens": 7,
                "total_tokens": 18,
            },
            {
                "input_tokens": 11,
                "output_tokens": 7,
                "output_tokens_details": {"reasoning_tokens": 8},
                "total_tokens": 18,
            },
            {
                "input_tokens": 11,
                "output_tokens": 7,
                "total_tokens": 17,
            },
            {
                "input_tokens": 11,
                "output_tokens": 7,
                "total_tokens": 18,
                "unknown": 0,
            },
        )
        for usage in invalid_usage_values:
            with self.subTest(usage=usage):
                envelope = safe_json_loads(openai_envelope())
                envelope["usage"] = usage
                provider, _ = openai_provider(canonical_json_bytes(envelope))
                result = provider.invoke(invocation())
                self.assertEqual(result.status, ModelRunStatus.INVALID_RESPONSE)
                self.assertEqual(result.error_code, "STRUCTURED_OUTPUT_INVALID")

    def test_model_identity_switch_and_refusal_are_invalid(self) -> None:
        provider, _ = openai_provider(openai_envelope(model="gpt-5-other"))
        self.assertEqual(provider.invoke(invocation()).status, ModelRunStatus.INVALID_RESPONSE)
        refusal = canonical_json_bytes(
            {
                "id": "resp_refusal",
                "model": "gpt-5",
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "refusal", "refusal": "cannot comply"}],
                    }
                ],
            }
        )
        provider, _ = openai_provider(refusal)
        self.assertEqual(provider.invoke(invocation()).status, ModelRunStatus.INVALID_RESPONSE)

    def test_schema_and_model_allowlists_fail_closed(self) -> None:
        bad_schema = output_schema()
        bad_schema["properties"]["summary"] = {"type": "string"}  # type: ignore[index]
        with self.assertRaises(ModelSchemaError):
            invocation(output_schema=bad_schema)
        provider, transport = openai_provider(openai_envelope())
        denied = provider.invoke(invocation(model="unreviewed-model"))
        self.assertEqual(denied.status, ModelRunStatus.EXTERNAL_ERROR)
        self.assertEqual(denied.error_code, "MODEL_NOT_ALLOWED")
        unsupported = invocation(capability=ModelCapability.PLANNING)
        config = OpenAIResponsesConfig(
            supported_capabilities=(ModelCapability.RESEARCH_SYNTHESIS,)
        )
        restricted = OpenAIResponsesProvider(provider.gateway, config=config)
        denied = restricted.invoke(unsupported)
        self.assertEqual(denied.status, ModelRunStatus.EXTERNAL_ERROR)
        self.assertEqual(denied.error_code, "CAPABILITY_NOT_ALLOWED")
        self.assertEqual(transport.sent_request_ids, [])

    def test_policy_denial_with_registry_has_failed_terminal_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            provider, transport = openai_provider(
                openai_envelope(),
                registry=registry,
            )
            result = provider.invoke(invocation(model="unreviewed-model"))
            self.assertEqual(result.status, ModelRunStatus.EXTERNAL_ERROR)
            self.assertEqual(result.error_code, "MODEL_NOT_ALLOWED")
            self.assertEqual(result.provenance_status, "TERMINAL_RECEIPT_CAPTURED")
            self.assertEqual(transport.sent_request_ids, [])
            receipt = safe_json_loads(
                registry.get_bytes(result.terminal_receipt.sha256)  # type: ignore[union-attr]
            )
            self.assertEqual(receipt["terminal_state"], "FAILED")
            self.assertEqual(receipt["failure_class"], "PROVIDER_POLICY_DENIAL")
            self.assertEqual(
                receipt["captured_parent_hashes"],
                [
                    record.sha256
                    for record in result.artifacts
                    if record is not result.terminal_receipt
                ],
            )

    def test_token_budget_denial_has_terminal_provenance_without_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            provider, transport = openai_provider(
                openai_envelope(), registry=registry, credential=None,
            )
            restricted = OpenAIResponsesProvider(
                provider.gateway,
                config=OpenAIResponsesConfig(maximum_output_tokens=511),
            )
            request = invocation(max_output_tokens=512)
            result = restricted.invoke(request)
            self.assertEqual(result.status, ModelRunStatus.EXTERNAL_ERROR)
            self.assertEqual(result.error_code, "TOKEN_BUDGET_NOT_ALLOWED")
            self.assertFalse(result.network_used)
            self.assertFalse(result.scientific_evidence)
            self.assertIsNone(result.request_id)
            self.assertEqual(transport.sent_request_ids, [])
            self.assertEqual(transport.prepared_requests, [])
            self.assertEqual(result.provenance_status, "TERMINAL_RECEIPT_CAPTURED")
            self.assertIsNotNone(result.terminal_receipt)
            receipt = safe_json_loads(
                registry.get_bytes(result.terminal_receipt.sha256)
            )
            self.assertEqual(receipt["terminal_state"], "FAILED")
            self.assertEqual(receipt["failure_class"], "PROVIDER_POLICY_DENIAL")
            self.assertEqual(receipt["failure_stage"], "PRE_REQUEST_POLICY")
            self.assertEqual(receipt["attempts"], [])
            self.assertIsNone(receipt["request_id"])
            self.assertFalse(receipt["network_used"])
            self.assertFalse(receipt["scientific_evidence"])
            self.assertEqual(
                receipt["captured_parent_hashes"],
                [record.sha256 for record in result.artifacts
                 if record is not result.terminal_receipt],
            )
            self.assertEqual(
                result.terminal_receipt.parent_artifacts,
                tuple(receipt["captured_parent_hashes"]),
            )
            by_type = {record.logical_type: record for record in result.artifacts}
            self.assertEqual(
                set(by_type),
                {"model_judged_instructions", "model_judged_input",
                 "model_output_schema", "model_invocation",
                 "model_provider_request_body", "model_terminal_receipt"},
            )
            self.assertEqual(
                registry.get_bytes(by_type["model_judged_input"].sha256),
                request.input_text.encode("utf-8"),
            )
            body = safe_json_loads(
                registry.get_bytes(by_type["model_provider_request_body"].sha256)
            )
            self.assertEqual(body["max_output_tokens"], 512)
            for record in result.artifacts:
                self.assertEqual(registry.get_metadata(record.sha256), record)

    def test_exact_token_budget_is_allowed_by_offline_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            provider, transport = openai_provider(
                openai_envelope(), registry=ArtifactRegistry(directory),
            )
            restricted = OpenAIResponsesProvider(
                provider.gateway,
                config=OpenAIResponsesConfig(maximum_output_tokens=512),
            )
            result = restricted.invoke(invocation(max_output_tokens=512))
            self.assertEqual(result.status, ModelRunStatus.COMPLETED)
            self.assertIsNone(result.error_code)
            self.assertIsNone(result.terminal_receipt)
            self.assertEqual(len(transport.prepared_requests), 1)
            sent = safe_json_loads(transport.prepared_requests[0].body)
            self.assertEqual(sent["max_output_tokens"], 512)
            self.assertFalse(result.network_used)
            self.assertFalse(result.scientific_evidence)
            self.assertEqual(result.external_validation, "UNTESTED")

    def test_invocation_schema_and_result_are_immutable(self) -> None:
        request = invocation()
        with self.assertRaises(TypeError):
            request.output_schema["type"] = "array"  # type: ignore[index]
        provider, _ = openai_provider(openai_envelope())
        result = provider.invoke(request)
        with self.assertRaises(TypeError):
            result.output["score"] = 0.0  # type: ignore[index,union-attr]

    def test_provider_module_imports_no_network_primitives(self) -> None:
        import scientist_one.providers as providers_module

        source = Path(providers_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        forbidden = {"http", "http.client", "urllib", "urllib.request", "socket", "requests", "httpx", "aiohttp"}
        self.assertTrue(imported.isdisjoint(forbidden))


if __name__ == "__main__":
    unittest.main()
