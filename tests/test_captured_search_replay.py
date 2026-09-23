"""Captured native OpenAlex fixtures; no network or scientific authority."""
from __future__ import annotations

from dataclasses import replace
import json
import unittest

from scientist_one.external import (
    EgressGateway, FixtureTransport, TransportResponse, UNVERIFIED_TRANSPORT_AUTHORITY,
)
from scientist_one.literature import (
    FullTextStatus, GatewayEnvelope, IdentifierKind, RetrievalStatus,
    ScholarlyIdentifier, ScholarlyRequest, ScholarlySearchRequest, ScholarlySource,
    normalize_scholarly_search_result,
)
from scientist_one.roles import Role
from scientist_one.scholarly_gateway import (
    ScholarlyGatewayError, SourceOwnedScholarlyGateway,
    openalex_scholarly_egress_policy,
    require_available_scholarly_native_capture,
    require_captured_scholarly_search_response,
)
from scientist_one.security import canonical_json_bytes
from tests import test_scholarly_gateway as fixtures


class CapturedSearchReplayTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ScholarlyGatewayTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.registry = self.fixture.registry
        self.request = ScholarlySearchRequest.from_plan(
            self.fixture._search_plan(), ScholarlySource.OPENALEX,
        )

    def capture(self, responses, *, maximum_attempts=1, policy=None, request=None):
        transport = FixtureTransport(tuple(
            TransportResponse(status, (("Content-Type", "application/json"),), body,
                              fixtures.OPENALEX_SEARCH_URL)
            for status, body in responses
        ))
        egress = EgressGateway(
            policy or openalex_scholarly_egress_policy(
                minimum_interval_seconds=0.0, maximum_attempts=maximum_attempts,
            ), transport, registry=self.registry,
            timestamp=lambda: "2026-09-13T18:00:00.000000Z",
        )
        gateway = SourceOwnedScholarlyGateway(openalex_gateway=egress)
        return gateway.fetch(request or self.request), transport

    def replay(self, captured, *, response_hash=None, raw_hash=None, request=None, reader=None):
        before = self.registry.list_records()
        answer = (reader or require_captured_scholarly_search_response)(
            self.registry, request=request or self.request,
            raw_artifact_sha256=raw_hash or captured.raw_artifact_hash,
            response_artifact_sha256=response_hash or captured.response_artifact_hash,
        )
        self.assertEqual(self.registry.list_records(), before)
        return answer

    def exact_outcome(self, captured, **kwargs):
        answer = self.replay(captured, **kwargs)
        self.assertEqual(answer.envelope, GatewayEnvelope(
            source=captured.source, request_id=captured.request_id,
            status=captured.status, payload=captured.payload,
            raw_artifact_hash=captured.raw_artifact_hash,
            response_artifact_hash=captured.response_artifact_hash,
            failure_reason=captured.failure_reason, license=captured.license,
            full_text_status=captured.full_text_status,
        ))
        self.assertFalse(answer.network_used)
        self.assertEqual(answer.external_validation, "UNTESTED")
        self.assertEqual(answer.transport_authority, UNVERIFIED_TRANSPORT_AUTHORITY)
        return answer

    def put_like(self, original_hash, value, **overrides):
        metadata = self.registry.get_metadata(original_hash)
        fields = dict(
            logical_type=metadata.logical_type, origin=metadata.origin,
            creator_role=metadata.creator_role, creation_command=metadata.creation_command,
            parent_artifacts=metadata.parent_artifacts, schema_version=metadata.schema_version,
            mime_type=metadata.mime_type, validation_result=metadata.validation_result,
            frozen=metadata.frozen,
        )
        fields.update(overrides)
        return self.registry.put_json(value, **fields)

    def response_value(self, captured):
        return json.loads(self.registry.get_bytes(captured.response_artifact_hash))

    def tampered_response(self, captured, **changes):
        value = self.response_value(captured)
        value.update(changes)
        return self.put_like(captured.response_artifact_hash, value)

    def replace_receipt(self, captured, mutate, *, parent_transform=None):
        response = self.response_value(captured)
        receipt_hash = response["response_receipt_artifact_hash"]
        receipt = json.loads(self.registry.get_bytes(receipt_hash))
        mutate(receipt)
        overrides = {}
        if parent_transform:
            overrides["parent_artifacts"] = parent_transform(
                self.registry.get_metadata(receipt_hash).parent_artifacts,
            )
        new_receipt = self.put_like(receipt_hash, receipt, **overrides)
        response["response_receipt_artifact_hash"] = new_receipt.sha256
        parents = tuple(
            new_receipt.sha256 if item == receipt_hash else item
            for item in self.registry.get_metadata(captured.response_artifact_hash).parent_artifacts
        )
        return self.put_like(captured.response_artifact_hash, response, parent_artifacts=parents)

    def test_success_matches_strict_old_reader_exactly(self):
        captured, transport = self.capture([(200, fixtures.openalex_list(
            [fixtures.openalex_work()], per_page=2, page=1,
        ))])
        answer = self.exact_outcome(captured)
        old = self.replay(captured, reader=require_available_scholarly_native_capture)
        self.assertEqual(answer, old)
        self.assertEqual(len(transport.prepared_requests), 1)

    def test_zero_hits_remains_available_bounded_page(self):
        value = json.loads(fixtures.openalex_list([], per_page=2, page=1))
        value["meta"]["count"] = 9999
        value["meta"]["next_cursor"] = "unconsumed-provider-value"
        captured, _ = self.capture([(200, canonical_json_bytes(value))])
        answer = self.exact_outcome(captured)
        result = normalize_scholarly_search_result(
            self.request, answer.envelope, plan_artifact_hash=fixtures.digest("plan"),
        )
        self.assertIs(result.status, RetrievalStatus.AVAILABLE)
        self.assertEqual(result.hits, ())
        self.assertFalse(result.scientific_evidence)
        self.assertFalse(hasattr(answer, "scholarly_sources_exhausted"))
        self.assertFalse(hasattr(answer, "may_use_general_web"))

    def test_http_refusals_are_rederived_and_old_reader_rejects(self):
        for status, expected in (
            (401, RetrievalStatus.UNAVAILABLE), (403, RetrievalStatus.UNAVAILABLE),
            (404, RetrievalStatus.NOT_FOUND), (429, RetrievalStatus.RATE_LIMITED),
            (500, RetrievalStatus.UNAVAILABLE), (502, RetrievalStatus.UNAVAILABLE),
            (503, RetrievalStatus.UNAVAILABLE), (504, RetrievalStatus.UNAVAILABLE),
        ):
            with self.subTest(status=status):
                captured, _ = self.capture([(status, f"HTTP {status}; not JSON".encode())])
                self.assertIs(captured.status, expected)
                answer = self.exact_outcome(captured)
                self.assertIs(answer.envelope.status, expected)
                self.assertIsNone(answer.envelope.payload)
                self.assertIs(answer.envelope.full_text_status, FullTextStatus.UNAVAILABLE)
                with self.assertRaises(ScholarlyGatewayError):
                    self.replay(captured, reader=require_available_scholarly_native_capture)

    def test_redirect_denials_and_relabelled_terminal_receipts_refuse(self):
        for status in (300, 301, 302, 304, 307, 308, 350, 399):
            with self.subTest(status=status):
                raw = f"bounded synthetic redirect body {status}".encode()
                denied, _ = self.capture([(status, raw)])
                self.assertIs(denied.status, RetrievalStatus.FAILED)
                before = self.registry.list_records()
                with self.assertRaises(ScholarlyGatewayError):
                    self.replay(denied)
                self.assertEqual(self.registry.list_records(), before)

                captured, _ = self.capture([(404, raw)])
                response = self.response_value(captured)
                old_receipt = response["response_receipt_artifact_hash"]
                receipt = json.loads(self.registry.get_bytes(old_receipt))
                receipt["status_code"] = status
                receipt["attempts"][-1]["status_code"] = status
                new_receipt = self.put_like(old_receipt, receipt)
                response.update(
                    response_receipt_artifact_hash=new_receipt.sha256,
                    retrieval_status="UNAVAILABLE", failure_code="HTTP_UNAVAILABLE",
                    failure_reason=f"scholarly endpoint returned HTTP status {status}",
                )
                parents = tuple(
                    new_receipt.sha256 if item == old_receipt else item
                    for item in self.registry.get_metadata(captured.response_artifact_hash).parent_artifacts
                )
                forged = self.put_like(captured.response_artifact_hash, response, parent_artifacts=parents)
                before = self.registry.list_records()
                for reader in (require_captured_scholarly_search_response,
                               require_available_scholarly_native_capture):
                    with self.assertRaises(ScholarlyGatewayError):
                        self.replay(captured, response_hash=forged.sha256, reader=reader)
                self.assertEqual(self.registry.list_records(), before)

    def test_redirect_cannot_be_relabelled_as_an_earlier_retry(self):
        captured, _ = self.capture([(429, b"busy"), (404, b"not found")], maximum_attempts=2)
        for status in (300, 302, 399):
            with self.subTest(status=status):
                forged = self.replace_receipt(
                    captured, lambda r: r["attempts"][0].update(status_code=status),
                )
                before = self.registry.list_records()
                with self.assertRaisesRegex(ScholarlyGatewayError, "retry policy"):
                    self.replay(captured, response_hash=forged.sha256)
                self.assertEqual(self.registry.list_records(), before)

    def test_other_status_classes_preserve_producer_outcomes(self):
        valid = fixtures.openalex_list([], per_page=2, page=1)
        # Existing replaceable-transport DTO behavior, not native HTTP framing.
        cases = (
            (100, b"interim fixture"), (101, b"switch fixture"), (199, b"fixture"),
            (201, valid), (202, valid), (204, b""), (206, valid), (299, b"bad JSON"),
            (400, b"error"), (405, b"error"), (408, b"error"), (410, b"error"),
            (418, b"error"), (422, b"error"), (451, b"error"), (501, b"error"),
            (505, b"error"), (599, b"error"),
        )
        for status, raw in cases:
            with self.subTest(status=status):
                captured, _ = self.capture([(status, raw)])
                replayed = self.exact_outcome(captured)
                if captured.status is RetrievalStatus.AVAILABLE:
                    self.assertEqual(replayed, self.replay(
                        captured, reader=require_available_scholarly_native_capture,
                    ))
                else:
                    with self.assertRaises(ScholarlyGatewayError):
                        self.replay(captured, reader=require_available_scholarly_native_capture)

    def test_terminal_status_type_is_exact(self):
        captured, _ = self.capture([(404, b"not found")])
        for status in (301.0, 404.0, True, "302"):
            with self.subTest(status=status):
                def mutate(receipt):
                    receipt["status_code"] = status
                    receipt["attempts"][-1]["status_code"] = status
                forged = self.replace_receipt(captured, mutate)
                before = self.registry.list_records()
                with self.assertRaisesRegex(ScholarlyGatewayError, "response receipt is malformed"):
                    self.replay(captured, response_hash=forged.sha256)
                self.assertEqual(self.registry.list_records(), before)

    def test_successful_http_malformed_raw_is_rederived(self):
        for body in (
            b"not JSON", b'{"duplicate": 1, "duplicate": 2}', b"[]", b"{}",
            fixtures.openalex_list([], per_page=2, page=2),
            fixtures.openalex_list([fixtures.openalex_work(), fixtures.openalex_work()], per_page=2, page=1),
        ):
            with self.subTest(body=body[:60]):
                captured, _ = self.capture([(200, body)])
                self.assertIs(captured.status, RetrievalStatus.MALFORMED)
                self.exact_outcome(captured)
                with self.assertRaises(ScholarlyGatewayError):
                    self.replay(captured, reader=require_available_scholarly_native_capture)

    def test_parser_depth_and_item_limits_match_captured_policy(self):
        policy = openalex_scholarly_egress_policy(
            minimum_interval_seconds=0.0, maximum_attempts=1,
        )
        depth = policy.maximum_json_depth + 1
        for limit, body in (
            ("maximum_json_depth", b'{"a":' * depth + b"0" + b"}" * depth),
            ("maximum_json_items", b"[" + b"0," * policy.maximum_json_items + b"0]"),
        ):
            with self.subTest(limit=limit):
                captured, _ = self.capture([(200, body)], policy=policy)
                self.assertIs(captured.status, RetrievalStatus.MALFORMED)
                self.exact_outcome(captured)

    def test_two_response_retry_chain_keeps_both_raw_attempts(self):
        for terminal, body in (
            (200, fixtures.openalex_list([], per_page=2, page=1)),
            (503, b"terminal unavailable"),
        ):
            with self.subTest(terminal=terminal):
                captured, transport = self.capture([(429, b"busy"), (terminal, body)], maximum_attempts=2)
                answer = self.exact_outcome(captured)
                self.assertEqual(len(transport.prepared_requests), 2)
                receipt = json.loads(self.registry.get_bytes(answer.response_receipt_artifact_hash))
                self.assertEqual(len(receipt["attempts"]), 2)
                self.assertTrue(all(
                    attempt["raw_response_record_sha256"] in answer.artifact_hashes
                    for attempt in receipt["attempts"]
                ))

    def test_terminal_transport_failure_and_preegress_are_unsupported(self):
        transport_failure, _ = self.capture([(503, b"busy")], maximum_attempts=2)
        self.assertIs(transport_failure.status, RetrievalStatus.FAILED)
        with self.assertRaises(ScholarlyGatewayError):
            self.replay(transport_failure)
        oversized = replace(self.request, max_results=101)
        refusal, transport = self.capture([(200, b"unused")], request=oversized)
        self.assertIs(refusal.status, RetrievalStatus.UNAVAILABLE)
        self.assertEqual(transport.prepared_requests, [])
        with self.assertRaises(ScholarlyGatewayError):
            self.replay(refusal, request=oversized)

    def test_exact_search_type_and_source_are_mandatory(self):
        captured, _ = self.capture([(404, b"not found")])
        class SearchSubclass(ScholarlySearchRequest):
            pass
        for request in (
            object(), replace(self.request, source=ScholarlySource.PMC),
            ScholarlyRequest(ScholarlySource.OPENALEX, "resolve_work",
                            ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789")),
            SearchSubclass(**{name: getattr(self.request, name) for name in (
                "plan_sha256", "purpose", "goal_sha256", "target_sha256", "source",
                "query", "synonyms", "filters", "max_results",
            )}),
        ):
            with self.subTest(request_type=type(request).__name__):
                with self.assertRaisesRegex(ScholarlyGatewayError, "exact OpenAlex search"):
                    self.replay(captured, request=request)

    def test_wrong_query_plan_goal_target_and_limit_refuse(self):
        captured, _ = self.capture([(404, b"not found")])
        for changes in (
            {"query": "another query"}, {"plan_sha256": fixtures.digest("other-plan")},
            {"goal_sha256": fixtures.digest("other-goal")},
            {"target_sha256": fixtures.digest("other-target")},
            {"max_results": 1}, {"synonyms": ()}, {"filters": ()},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ScholarlyGatewayError):
                    self.replay(captured, request=replace(self.request, **changes))

    def test_rehashed_http_labels_and_payload_cannot_change_outcome(self):
        captured, _ = self.capture([(404, b"not found")])
        for changes in (
            {"retrieval_status": "AVAILABLE"}, {"retrieval_status": "UNAVAILABLE"},
            {"failure_code": "HTTP_UNAVAILABLE"}, {"failure_reason": "different reason"},
            {"payload": {}}, {"license": "invented"}, {"full_text_status": "METADATA_ONLY"},
            {"scientific_evidence": True}, {"network_used": True},
            {"external_validation": "VALIDATED"}, {"transport_authority": "AUDITED_LIVE_TRANSPORT"},
        ):
            with self.subTest(changes=changes):
                forged = self.tampered_response(captured, **changes)
                with self.assertRaises(ScholarlyGatewayError):
                    self.replay(captured, response_hash=forged.sha256)

    def test_rehashed_valid_payload_cannot_be_called_malformed(self):
        captured, _ = self.capture([(200, fixtures.openalex_list([], per_page=2, page=1))])
        forged = self.tampered_response(
            captured, retrieval_status="MALFORMED", payload=None, license=None,
            full_text_status="UNAVAILABLE", failure_code="MALFORMED_RESPONSE",
            failure_reason="captured scholarly response violates its native schema",
        )
        with self.assertRaisesRegex(ScholarlyGatewayError, "parser replay"):
            self.replay(captured, response_hash=forged.sha256)

    def test_rehashed_malformed_capture_cannot_be_called_not_found(self):
        captured, _ = self.capture([(200, b"not JSON")])
        forged = self.tampered_response(
            captured, retrieval_status="NOT_FOUND", failure_code="NOT_FOUND",
            failure_reason="scholarly endpoint did not find the requested object",
        )
        with self.assertRaisesRegex(ScholarlyGatewayError, "parser replay"):
            self.replay(captured, response_hash=forged.sha256)

    def test_raw_splice_is_rejected(self):
        first, _ = self.capture([(404, b"first raw")])
        second, _ = self.capture([(404, b"second raw")])
        with self.assertRaises(ScholarlyGatewayError):
            self.replay(first, raw_hash=second.raw_artifact_hash)
        response = self.response_value(first)
        response["raw_artifact_hash"] = second.raw_artifact_hash
        parents = tuple(second.raw_artifact_hash if p == first.raw_artifact_hash else p
                        for p in self.registry.get_metadata(first.response_artifact_hash).parent_artifacts)
        forged = self.put_like(first.response_artifact_hash, response, parent_artifacts=parents)
        with self.assertRaises(ScholarlyGatewayError):
            self.replay(first, raw_hash=second.raw_artifact_hash, response_hash=forged.sha256)

    def test_wrong_normalized_metadata_and_parent_order_refuse(self):
        captured, _ = self.capture([(404, b"not found")])
        for changes in (
            {"creator_role": Role.ORCHESTRATOR}, {"logical_type": "scholarly_response"},
            {"origin": "invented"}, {"schema_version": "2.0"},
            {"creation_command": ("invented",)}, {"frozen": False},
        ):
            with self.subTest(changes=changes):
                value = self.response_value(captured)
                value["metadata_case"] = str(changes)
                forged = self.put_like(captured.response_artifact_hash, value, **changes)
                with self.assertRaisesRegex(ScholarlyGatewayError, "metadata"):
                    self.replay(captured, response_hash=forged.sha256)
        extra, _ = self.capture([(404, b"other raw parent")])
        parents = self.registry.get_metadata(captured.response_artifact_hash).parent_artifacts
        for index, transformed in enumerate((parents[::-1], parents[:-1], parents + (extra.raw_artifact_hash,))):
            with self.subTest(parents=transformed):
                value = self.response_value(captured)
                value["failure_reason"] += " " * (index + 1)
                forged = self.put_like(captured.response_artifact_hash, value, parent_artifacts=transformed)
                with self.assertRaisesRegex(ScholarlyGatewayError, "parents"):
                    self.replay(captured, response_hash=forged.sha256)

    def test_missing_custody_cannot_be_replaced_by_a_failure_dto(self):
        captured, _ = self.capture([(404, b"not found")])
        for raw_hash, response_hash in (
            (None, captured.response_artifact_hash),
            (captured.raw_artifact_hash, None),
            (fixtures.digest("missing raw"), captured.response_artifact_hash),
            (captured.raw_artifact_hash, fixtures.digest("missing response")),
        ):
            with self.subTest(raw_hash=raw_hash, response_hash=response_hash):
                with self.assertRaises(ScholarlyGatewayError):
                    require_captured_scholarly_search_response(
                        self.registry, request=self.request,
                        raw_artifact_sha256=raw_hash,
                        response_artifact_sha256=response_hash,
                    )

    def test_terminal_receipt_and_attempt_status_must_match(self):
        captured, _ = self.capture([(404, b"not found")])
        for field, value in (("status_code", 503), ("body_size", 99), ("content_type", "text/html")):
            with self.subTest(field=field):
                forged = self.replace_receipt(captured, lambda receipt: receipt.update({field: value}))
                with self.assertRaises(ScholarlyGatewayError):
                    self.replay(captured, response_hash=forged.sha256)
        forged = self.replace_receipt(captured, lambda receipt: receipt["attempts"][-1].update(status_code=200))
        with self.assertRaises(ScholarlyGatewayError):
            self.replay(captured, response_hash=forged.sha256)

    def test_replayed_retry_and_budget_tampering_refuse(self):
        captured, _ = self.capture([(429, b"busy"), (503, b"still busy")], maximum_attempts=2)
        changes = (
            lambda r: r["attempts"][0].update(retry_delay_seconds=0.0),
            lambda r: r["attempts"][0].update(response_body_bytes=999999999),
            lambda r: r["attempts"][1].update(attempt=1),
            lambda r: r["attempts"][-1].update(retry_delay_seconds=1.0),
            lambda r: r["egress_budget"].update(deadline_satisfied=False),
            lambda r: r["egress_budget"].update(deadline_elapsed_seconds=30.0),
            lambda r: r["egress_budget"].update(total_bytes_used=0),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                forged = self.replace_receipt(captured, change)
                with self.assertRaises(ScholarlyGatewayError):
                    self.replay(captured, response_hash=forged.sha256)

    def test_legacy_and_v3_normalized_schemas_refuse(self):
        captured, _ = self.capture([(404, b"not found")])
        for schema in ("scholarly-response/v1", "scholarly-native-response/v3"):
            with self.subTest(schema=schema):
                forged = self.tampered_response(captured, schema_version=schema)
                with self.assertRaisesRegex(ScholarlyGatewayError, "native-v2"):
                    self.replay(captured, response_hash=forged.sha256)
