from __future__ import annotations

import hashlib
import tempfile
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.external import EgressGateway, FixtureTransport, TransportResponse
from scientist_one.provider_verification import (
    MODEL_PROVIDER_CUSTODY_SCHEMA_V1,
    require_provider_verifier,
)
from scientist_one.providers import (
    ModelCapability,
    ModelInvocation,
    ModelRunStatus,
    OpenAIResponsesProvider,
    openai_responses_policy,
    validate_structured_output_schema,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads


def object_schema(properties):
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def nested_schema(containers, *, mixed=False):
    schema = {"type": "boolean"}
    output = True
    for index in range(containers - 1):
        if mixed and index % 2 == 0:
            schema = {"type": "array", "items": schema, "maxItems": 1}
            output = [output]
        else:
            schema = object_schema({"v": schema})
            output = {"v": output}
    return object_schema({"v": schema}), {"v": output}


def property_schema(total):
    # Root contributes 20; no individual object exceeds the neutral 256 cap.
    quotient, remainder = divmod(total - 20, 20)
    return object_schema({
        f"p{index:02}": object_schema({
            f"v{child:03}": {"type": "boolean"}
            for child in range(quotient + (index < remainder))
        })
        for index in range(20)
    })


def enum_strings(count, characters, *, fill="x"):
    width, remainder = divmod(characters, count)
    assert width >= 4
    return [
        f"{index:04}" + fill * (width + (index < remainder) - 4)
        for index in range(count)
    ]


def string_enum_schema(count, characters, *, fill="x", name="v"):
    return object_schema({
        name: {"type": "string", "enum": enum_strings(count, characters, fill=fill)},
    })


def model_invocation(schema):
    return ModelInvocation(
        invocation_id="schema-admission-1",
        capability=ModelCapability.RESEARCH_SYNTHESIS,
        model="gpt-5",
        prompt_template_id="schema-admission",
        prompt_template_version="1.0",
        prompt_template_hash=hashlib.sha256(b"schema-admission-v1").hexdigest(),
        instructions="Return the requested structured JSON.",
        input_text="Analyze the synthetic schema fixture.",
        output_schema=schema,
        max_output_tokens=512,
    )


class OpenAISchemaAdmissionTests(unittest.TestCase):
    def make_provider(self, *, credential=None, output=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        registry = ArtifactRegistry(directory.name)
        body = canonical_json_bytes({
            "id": "resp_schema_fixture",
            "model": "gpt-5",
            "status": "completed",
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{
                    "type": "output_text",
                    "text": canonical_json_bytes(output or {"v": True}).decode("utf-8"),
                }],
            }],
        })
        transport = FixtureTransport((TransportResponse(
            status_code=200,
            headers=(("Content-Type", "application/json"),),
            body=body,
            effective_url="https://api.openai.com/v1/responses",
        ),))
        gateway = EgressGateway(
            openai_responses_policy(maximum_attempts=1, maximum_requests=1),
            transport,
            registry=registry,
            secret_resolver=lambda _name: credential,
            timestamp=lambda: "2026-09-19T12:00:00.000000Z",
        )
        return OpenAIResponsesProvider(gateway), transport, registry

    def assert_admission(self, schema, *, denied):
        # Both boundary sides must remain valid neutral invocations. The absent
        # credential distinguishes admission success from a real provider call.
        validate_structured_output_schema(schema)
        request = model_invocation(schema)
        provider, transport, registry = self.make_provider()
        result = provider.invoke(request)
        self.assertEqual(
            result.error_code,
            "SCHEMA_NOT_SUPPORTED" if denied else "PROVIDER_UNAVAILABLE",
        )
        self.assertEqual(
            result.status,
            ModelRunStatus.EXTERNAL_ERROR if denied else ModelRunStatus.BLOCKED_EXTERNAL,
        )
        self.assertEqual(transport.sent_request_ids, [])
        self.assertEqual(transport.prepared_requests, [])
        self.assertFalse(result.network_used)
        self.assertFalse(result.scientific_evidence)
        self.assertIsNone(result.request_id)
        self.assertIsNone(result.output)
        self.assertIsNone(result.transport_execution_authority_artifact_sha256)
        self.assertEqual(result.provenance_status, "TERMINAL_RECEIPT_CAPTURED")
        self.assertIsNotNone(result.terminal_receipt)
        receipt = safe_json_loads(registry.get_bytes(result.terminal_receipt.sha256))
        self.assertEqual(receipt["attempts"], [])
        self.assertIsNone(receipt["request_id"])
        self.assertFalse(receipt["network_used"])
        self.assertFalse(receipt["scientific_evidence"])
        self.assertEqual(receipt["terminal_state"], "FAILED" if denied else "BLOCKED")
        self.assertEqual(
            receipt["failure_stage"], "PRE_REQUEST_POLICY" if denied else "AVAILABILITY",
        )
        self.assertEqual(
            receipt["failure_class"],
            "PROVIDER_POLICY_DENIAL" if denied else "EXTERNAL_UNAVAILABLE",
        )
        parents = tuple(
            record.sha256 for record in result.artifacts
            if record is not result.terminal_receipt
        )
        self.assertEqual(receipt["captured_parent_hashes"], list(parents))
        self.assertEqual(result.terminal_receipt.parent_artifacts, parents)
        by_type = {record.logical_type: record for record in result.artifacts}
        self.assertEqual(set(by_type), {
            "model_judged_instructions", "model_judged_input", "model_output_schema",
            "model_invocation", "model_provider_request_body", "model_terminal_receipt",
        })
        self.assertEqual(len(registry.list_records()), len(by_type))
        self.assertEqual(
            registry.get_bytes(by_type["model_output_schema"].sha256),
            canonical_json_bytes(schema),
        )
        self.assertEqual(
            registry.get_bytes(by_type["model_judged_input"].sha256),
            request.input_text.encode("utf-8"),
        )
        body = safe_json_loads(registry.get_bytes(by_type["model_provider_request_body"].sha256))
        self.assertEqual(body["text"]["format"]["schema"], schema)
        for record in result.artifacts:
            self.assertEqual(registry.get_metadata(record.sha256), record)
            self.assertTrue(registry.verify(record.sha256))

    def test_object_container_depth_boundary(self):
        for depth in (10, 11):
            with self.subTest(depth=depth):
                schema, _ = nested_schema(depth)
                self.assert_admission(schema, denied=depth == 11)

    def test_mixed_array_object_container_depth_boundary(self):
        for depth in (10, 11):
            with self.subTest(depth=depth):
                schema, _ = nested_schema(depth, mixed=True)
                self.assert_admission(schema, denied=depth == 11)

    def test_total_property_boundary(self):
        for count in (5_000, 5_001):
            with self.subTest(count=count):
                self.assert_admission(property_schema(count), denied=count > 5_000)

    def test_aggregate_enum_entry_boundary_for_strings_and_numbers(self):
        for numeric in (False, True):
            for count in (1_000, 1_001):
                with self.subTest(numeric=numeric, count=count):
                    properties = {}
                    remaining = count
                    while remaining:
                        size = min(250, remaining)
                        properties[f"p{len(properties)}"] = (
                            {"type": "integer", "minimum": 0, "maximum": 249,
                             "enum": list(range(size))}
                            if numeric else
                            {"type": "string", "enum": enum_strings(size, size * 4)}
                        )
                        remaining -= size
                    self.assert_admission(object_schema(properties), denied=count > 1_000)

    def test_total_schema_string_character_boundary(self):
        for characters in (120_000, 120_001):
            with self.subTest(characters=characters):
                # The property name contributes one character independently.
                schema = string_enum_schema(250, characters - 1)
                self.assert_admission(schema, denied=characters > 120_000)

    def test_multibyte_strings_use_characters_not_utf8_bytes(self):
        schema = string_enum_schema(250, 119_999, fill="é", name="é")
        self.assertGreater(len(canonical_json_bytes(schema)), 120_000)
        self.assert_admission(schema, denied=False)

    def test_descriptions_and_required_names_do_not_double_count(self):
        schema = string_enum_schema(250, 119_999)
        schema["description"] = "d" * 4_096
        schema["properties"]["v"]["description"] = "e" * 4_096
        self.assert_admission(schema, denied=False)

    def test_large_single_enum_character_boundary(self):
        for characters in (15_000, 15_001):
            with self.subTest(characters=characters):
                self.assert_admission(
                    string_enum_schema(251, characters), denied=characters > 15_000,
                )

    def test_exactly_250_enum_entries_do_not_activate_large_enum_limit(self):
        self.assert_admission(string_enum_schema(250, 15_001), denied=False)

    def test_neutral_null_enum_is_denied_without_rewriting_native_schema(self):
        # Neutral validation treats enum:null as absent, but the native wire
        # retains it. Prospective OpenAI admission requires an enum array.
        self.assert_admission(
            object_schema({"v": {"type": "boolean", "enum": None}}), denied=True,
        )

    def test_object_enum_with_nested_long_string_is_denied_and_retained_exactly(self):
        schema = object_schema({"v": {"type": "string", "maxLength": 120_001}})
        schema["enum"] = [{"v": "x" * 120_001}]
        # This is a conservative local provider-profile exclusion, not a
        # demonstrated claim about native API enumeration serialization.
        self.assert_admission(schema, denied=True)

    def test_array_enum_with_nested_long_string_is_denied_and_retained_exactly(self):
        schema = object_schema({"v": {
            "type": "array",
            "items": {"type": "string", "maxLength": 120_001},
            "maxItems": 1,
            "enum": [["x" * 120_001]],
        }})
        self.assert_admission(schema, denied=True)

    def test_small_composite_enums_are_excluded_by_local_provider_profile(self):
        object_enum = object_schema({"v": {"type": "boolean"}})
        object_enum["enum"] = [{"v": True}]
        array_enum = object_schema({"v": {
            "type": "array", "items": {"type": "boolean"},
            "maxItems": 1, "enum": [[True]],
        }})
        for kind, schema in (("object", object_enum), ("array", array_enum)):
            with self.subTest(kind=kind):
                self.assert_admission(schema, denied=True)

    def test_depth_boundary_completes_offline_without_schema_rewriting(self):
        schema, output = nested_schema(10, mixed=True)
        request = model_invocation(schema)
        provider, transport, registry = self.make_provider(
            credential="fixture-credential-material", output=output,
        )
        result = provider.invoke(request)
        self.assertEqual(result.status, ModelRunStatus.COMPLETED)
        self.assertEqual(result.external_validation, "UNTESTED")
        self.assertFalse(result.network_used)
        self.assertFalse(result.scientific_evidence)
        self.assertEqual(canonical_json_bytes(result.output), canonical_json_bytes(output))
        self.assertEqual(transport.credential_present, [False])
        self.assertEqual(len(transport.prepared_requests), 1)
        by_type = {record.logical_type: record for record in result.artifacts}
        sent = transport.prepared_requests[0].body
        self.assertEqual(
            registry.get_bytes(by_type["model_provider_request_body"].sha256), sent,
        )
        self.assertEqual(safe_json_loads(sent)["text"]["format"]["schema"], schema)
        self.assertEqual(
            registry.get_bytes(by_type["model_output_schema"].sha256),
            canonical_json_bytes(schema),
        )

    def test_historical_wire_construction_and_replay_remain_exact_above_new_limit(self):
        schema = property_schema(5_001)
        request = model_invocation(schema)
        contract = require_provider_verifier("openai", MODEL_PROVIDER_CUSTODY_SCHEMA_V1)
        kwargs = dict(
            retained_instructions=request.instructions,
            retained_input=request.input_text,
            retained_schema=schema,
            model_requested=request.model,
            maximum_output_tokens=request.max_output_tokens,
        )
        body = contract.build_request_body(**kwargs)
        expected = canonical_json_bytes({
            "model": "gpt-5",
            "instructions": request.instructions,
            "input": [{"role": "user", "content": [
                {"type": "input_text", "text": request.input_text},
            ]}],
            "max_output_tokens": 512,
            "store": False,
            "text": {"format": {
                "type": "json_schema", "name": "scientist_one_output",
                "strict": True, "schema": schema,
            }},
            "tool_choice": "none", "tools": [], "truncation": "disabled",
        })
        self.assertEqual(body, expected)
        projection = contract.validate_and_project_request(
            body_bytes=body, invocation_id=request.invocation_id, **kwargs,
        )
        self.assertEqual(projection.body_sha256, hashlib.sha256(expected).hexdigest())
        self.assertEqual(projection.body_size, len(expected))
        self.assert_admission(schema, denied=True)


if __name__ == "__main__":
    unittest.main()
