"""Deterministic, non-scientific provider provenance fixtures for tests."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.external import UNVERIFIED_TRANSPORT_AUTHORITY
from scientist_one.models import thaw_json
from scientist_one.provider_verification import (
    DETERMINISTIC_FIXTURE_PROVIDER_ID,
    require_provider_verifier,
)
from scientist_one.providers import ModelResult, ModelRunStatus
from scientist_one.security import canonical_json_bytes, safe_json_loads, sha256_bytes


def _one(result: ModelResult, logical_type: str) -> ArtifactRecord:
    matches = tuple(
        record for record in result.artifacts if record.logical_type == logical_type
    )
    if len(matches) != 1:
        raise AssertionError(
            f"deterministic provider fixture requires one {logical_type} artifact"
        )
    return matches[0]


def _put_json_like(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
    value: Mapping[str, Any],
    *,
    parents: tuple[str, ...],
) -> ArtifactRecord:
    return registry.put_json(
        value,
        logical_type=record.logical_type,
        origin=record.origin,
        creator_role=record.creator_role,
        creation_command=record.creation_command,
        parent_artifacts=parents,
        schema_version=record.schema_version,
        mime_type=record.mime_type,
        validation_result=record.validation_result,
        frozen=record.frozen,
        created_at=record.created_at,
    )


def _put_bytes_like(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
    value: bytes,
    *,
    parents: tuple[str, ...],
) -> ArtifactRecord:
    return registry.put_bytes(
        value,
        logical_type=record.logical_type,
        origin=record.origin,
        creator_role=record.creator_role,
        creation_command=record.creation_command,
        parent_artifacts=parents,
        schema_version=record.schema_version,
        mime_type=record.mime_type,
        validation_result=record.validation_result,
        frozen=record.frozen,
        created_at=record.created_at,
    )


def deterministic_provider_result(
    registry: ArtifactRegistry,
    result: ModelResult,
) -> ModelResult:
    """Reissue one offline result through a distinct credentialless fixture graph.

    This helper is deliberately test-only.  It never performs network access,
    never mints audited-live authority, and preserves the normalized structured
    output while rebuilding every provider-dependent artifact and edge.
    """

    if (
        result.status is not ModelRunStatus.COMPLETED
        or result.provenance_status != "CAPTURED"
        or result.network_used is not False
        or result.external_validation != "UNTESTED"
        or result.transport_authority != UNVERIFIED_TRANSPORT_AUTHORITY
        or result.transport_execution_authority_artifact_sha256 is not None
    ):
        raise AssertionError(
            "deterministic provider fixture requires an offline unverified capture"
        )

    invocation = _one(result, "model_invocation")
    instructions = _one(result, "model_judged_instructions")
    judged_input = _one(result, "model_judged_input")
    output_schema = _one(result, "model_output_schema")
    request_body = _one(result, "model_provider_request_body")
    request_intent = _one(result, "model_provider_request_intent")
    external_request = _one(result, "external_request")
    raw_response = _one(result, "external_response_raw")
    response_receipt = _one(result, "external_response_receipt")
    provider_response = _one(result, "model_provider_response")
    model_output = _one(result, "model_output")
    contract = require_provider_verifier(
        DETERMINISTIC_FIXTURE_PROVIDER_ID,
        invocation.schema_version,
    )

    invocation_value = safe_json_loads(registry.get_bytes(invocation.sha256))
    if not isinstance(invocation_value, Mapping):
        raise AssertionError("model invocation fixture is malformed")
    invocation_value = dict(invocation_value)
    invocation_value["provider_id"] = contract.provider_id
    fixture_invocation = _put_json_like(
        registry,
        invocation,
        invocation_value,
        parents=invocation.parent_artifacts,
    )

    try:
        instructions_text = registry.get_bytes(instructions.sha256).decode("utf-8")
        judged_input_text = registry.get_bytes(judged_input.sha256).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AssertionError("deterministic provider prompt fixture is malformed") from exc
    output_schema_value = safe_json_loads(
        registry.get_bytes(output_schema.sha256)
    )
    if not isinstance(output_schema_value, Mapping):
        raise AssertionError("deterministic provider schema fixture is malformed")
    maximum_output_tokens = invocation_value.get("max_output_tokens")
    model_descriptor = invocation_value.get("model")
    if (
        not isinstance(maximum_output_tokens, int)
        or isinstance(maximum_output_tokens, bool)
        or not isinstance(model_descriptor, Mapping)
        or result.model_requested is None
    ):
        raise AssertionError("deterministic provider invocation fixture is malformed")
    request_body_bytes = contract.build_request_body(
        retained_instructions=instructions_text,
        retained_input=judged_input_text,
        retained_schema=output_schema_value,
        model_requested=result.model_requested,
        maximum_output_tokens=maximum_output_tokens,
    )
    fixture_request_body = _put_bytes_like(
        registry,
        request_body,
        request_body_bytes,
        parents=(),
    )
    request_projection = contract.validate_and_project_request(
        body_bytes=request_body_bytes,
        retained_instructions=instructions_text,
        retained_input=judged_input_text,
        retained_schema=output_schema_value,
        invocation_id=result.invocation_id,
        model_requested=result.model_requested,
        maximum_output_tokens=maximum_output_tokens,
    )
    request_id = request_projection.request_id
    request_intent_value = safe_json_loads(
        registry.get_bytes(request_intent.sha256)
    )
    if not isinstance(request_intent_value, Mapping):
        raise AssertionError("model request-intent fixture is malformed")
    request_intent_value = dict(request_intent_value)
    request_intent_value.update(
        {
            "invocation_artifact_sha256": fixture_invocation.sha256,
            "request_body_artifact_sha256": fixture_request_body.sha256,
            "request_id": request_id,
            "provider_id": contract.provider_id,
            "endpoint": contract.endpoint,
            "body_sha256": request_projection.body_sha256,
            "body_size": request_projection.body_size,
        }
    )
    fixture_intent = _put_json_like(
        registry,
        request_intent,
        request_intent_value,
        parents=(fixture_invocation.sha256, fixture_request_body.sha256),
    )

    policy_claim_sha256 = sha256_bytes(
        canonical_json_bytes(
            {
                "schema_version": "deterministic-provider-fixture-policy/v1",
                "provider_id": contract.provider_id,
                "provider_version": contract.provider_version,
                "endpoint": contract.endpoint,
                "network_used": False,
                "scientific_evidence": False,
            }
        )
    )
    external_request_value = safe_json_loads(
        registry.get_bytes(external_request.sha256)
    )
    if not isinstance(external_request_value, Mapping):
        raise AssertionError("external request fixture is malformed")
    external_request_value = dict(external_request_value)
    external_request_value.update(
        {
            "request_id": request_id,
            "policy_id": contract.provider_version,
            "policy_claim_sha256": policy_claim_sha256,
            "adapter_id": contract.provider_id,
            "url": contract.endpoint,
            "credential_env_name": contract.credential_env_name,
            "credential_present": contract.credential_present,
            "parent_artifacts": [fixture_intent.sha256],
            "body_sha256": request_projection.body_sha256,
            "body_size": request_projection.body_size,
        }
    )
    fixture_external_request = _put_json_like(
        registry,
        external_request,
        external_request_value,
        parents=(fixture_intent.sha256,),
    )

    model_output_value = safe_json_loads(registry.get_bytes(model_output.sha256))
    if not isinstance(model_output_value, Mapping):
        raise AssertionError("model output fixture is malformed")
    model_output_value = dict(model_output_value)
    normalized_output = model_output_value.get("output")
    normalized_usage = model_output_value.get("usage")
    source_response_id = model_output_value.get("provider_response_id")
    if (
        not isinstance(normalized_output, Mapping)
        or not isinstance(normalized_usage, Mapping)
        or not isinstance(source_response_id, str)
    ):
        raise AssertionError("model output fixture projection is malformed")
    response_id = f"deterministic-{source_response_id}"
    raw_response_value = {
        "fixture_protocol": contract.wire_protocol,
        "request_ref": request_id,
        "engine": result.model_requested,
        "response_ref": response_id,
        "state": "done",
        "result_json": canonical_json_bytes(normalized_output).decode("utf-8"),
        "metering": {
            "prompt_units": normalized_usage.get("input_tokens"),
            "prompt_unit_details": normalized_usage.get("input_tokens_details"),
            "result_units": normalized_usage.get("output_tokens"),
            "result_unit_details": normalized_usage.get("output_tokens_details"),
            "total_units": normalized_usage.get("total_tokens"),
        },
    }
    raw_response_bytes = canonical_json_bytes(raw_response_value)
    response_projection = contract.parse_and_project_response(
        raw_bytes=raw_response_bytes,
        requested_model=result.model_requested,
        output_schema=output_schema_value,
        maximum_output_bytes=32 * 1024 * 1024,
        expected_request_id=request_id,
    )
    if (
        response_projection.response_id != response_id
        or response_projection.model_returned != result.model_requested
        or thaw_json(response_projection.output) != dict(normalized_output)
        or thaw_json(response_projection.usage) != dict(normalized_usage)
    ):
        raise AssertionError(
            "deterministic provider native response projection changed"
        )
    fixture_raw_response = _put_bytes_like(
        registry,
        raw_response,
        raw_response_bytes,
        parents=(),
    )

    response_receipt_value = safe_json_loads(
        registry.get_bytes(response_receipt.sha256)
    )
    if not isinstance(response_receipt_value, Mapping):
        raise AssertionError("external response receipt fixture is malformed")
    response_receipt_value = dict(response_receipt_value)
    attempts = response_receipt_value.get("attempts")
    if not isinstance(attempts, list) or len(attempts) != 1:
        raise AssertionError(
            "deterministic provider fixture supports one captured response attempt"
        )
    attempt = dict(attempts[0])
    attempt.update(
        {
            "body_sha256": sha256_bytes(raw_response_bytes),
            "body_size": len(raw_response_bytes),
            "raw_response_record_sha256": fixture_raw_response.sha256,
            "request_body_bytes": len(request_body_bytes),
            "response_body_bytes": len(raw_response_bytes),
            "cumulative_bytes": len(request_body_bytes) + len(raw_response_bytes),
        }
    )
    budget = response_receipt_value.get("egress_budget")
    if not isinstance(budget, Mapping):
        raise AssertionError("external response budget fixture is malformed")
    budget = dict(budget)
    budget.update(
        {
            "response_bytes_used": len(raw_response_bytes),
            "request_bytes_used": len(request_body_bytes),
            "total_bytes_used": len(request_body_bytes) + len(raw_response_bytes),
        }
    )
    response_receipt_value.update(
        {
            "request_id": request_id,
            "policy_claim_sha256": policy_claim_sha256,
            "request_artifact_sha256": fixture_external_request.sha256,
            "raw_response_sha256": sha256_bytes(raw_response_bytes),
            "raw_response_record_sha256": fixture_raw_response.sha256,
            "body_size": len(raw_response_bytes),
            "attempts": [attempt],
            "network_used": False,
            "external_validation": "UNTESTED",
            "transport_authority": UNVERIFIED_TRANSPORT_AUTHORITY,
            "egress_budget": budget,
        }
    )
    fixture_response_receipt = _put_json_like(
        registry,
        response_receipt,
        response_receipt_value,
        parents=(fixture_external_request.sha256, fixture_raw_response.sha256),
    )

    provider_response_value = safe_json_loads(
        registry.get_bytes(provider_response.sha256)
    )
    if not isinstance(provider_response_value, Mapping):
        raise AssertionError("model provider response fixture is malformed")
    provider_response_value = dict(provider_response_value)
    provider_response_value.update(
        {
            "request_id": request_id,
            "raw_response_sha256": sha256_bytes(raw_response_bytes),
            "response": raw_response_value,
            "network_used": False,
            "external_validation": "UNTESTED",
            "transport_authority": UNVERIFIED_TRANSPORT_AUTHORITY,
        }
    )
    provider_response_value.pop(
        "transport_execution_authority_artifact_sha256",
        None,
    )
    fixture_provider_response = _put_json_like(
        registry,
        provider_response,
        provider_response_value,
        parents=(fixture_raw_response.sha256, fixture_response_receipt.sha256),
    )

    model_output_value.update(
        {
            "provider_id": contract.provider_id,
            "provider_response_id": response_id,
            "network_used": False,
            "external_validation": "UNTESTED",
            "transport_authority": UNVERIFIED_TRANSPORT_AUTHORITY,
        }
    )
    model_output_value.pop(
        "transport_execution_authority_artifact_sha256",
        None,
    )
    fixture_model_output = _put_json_like(
        registry,
        model_output,
        model_output_value,
        parents=(
            fixture_invocation.sha256,
            fixture_request_body.sha256,
            fixture_provider_response.sha256,
        ),
    )

    replacements = {
        invocation.sha256: fixture_invocation,
        request_body.sha256: fixture_request_body,
        request_intent.sha256: fixture_intent,
        external_request.sha256: fixture_external_request,
        raw_response.sha256: fixture_raw_response,
        response_receipt.sha256: fixture_response_receipt,
        provider_response.sha256: fixture_provider_response,
        model_output.sha256: fixture_model_output,
    }
    return replace(
        result,
        provider_id=contract.provider_id,
        provider_response_id=response_id,
        request_id=request_id,
        network_used=False,
        external_validation="UNTESTED",
        transport_authority=UNVERIFIED_TRANSPORT_AUTHORITY,
        transport_execution_authority_artifact_sha256=None,
        artifacts=tuple(
            replacements.get(record.sha256, record) for record in result.artifacts
        ),
    )


__all__ = ["deterministic_provider_result"]
