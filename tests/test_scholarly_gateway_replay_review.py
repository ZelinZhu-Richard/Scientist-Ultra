from __future__ import annotations

import hashlib
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.external import UNVERIFIED_TRANSPORT_AUTHORITY
from scientist_one.ledger import EventLedger
from scientist_one.literature import (
    CitationPageRequest,
    CitationTraversal,
    GatewayEnvelope,
    IdentifierKind,
    OpenAlexAdapter,
    PMCAdapter,
    ScholarlyIdentifier,
    ScholarlySearchRequest,
    ScholarlySource,
    normalize_citation_expansion_page,
)
from scientist_one.models import MacroState
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    ScientificPromotionError,
    _resolve_captured_gateway_envelope,
    _resolve_registry_scholarly_record,
    _scholarly_search_request_payload,
    require_audited_live_controlled_literature_authority,
)
from scientist_one.security import canonical_json_bytes
from tests import test_scholarly_gateway as native_fixtures


class ScholarlyGatewayReplayReviewTests(unittest.TestCase):
    """Exercise the real v2 owner through the historical literature consumer."""

    def setUp(self) -> None:
        self.fixture = native_fixtures.ScholarlyGatewayTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.run_id = "native-replay-review"
        self.registry = ArtifactRegistry(
            self.fixture.root, f"runs/{self.run_id}/registry"
        )
        self.fixture.registry = self.registry
        self.ledger = EventLedger(
            self.fixture.root, f"runs/{self.run_id}/events.jsonl"
        )

    @staticmethod
    def _envelope(captured):
        return GatewayEnvelope(
            captured.source,
            captured.request_id,
            captured.status,
            captured.payload,
            captured.raw_artifact_hash,
            captured.response_artifact_hash,
            captured.failure_reason,
            captured.license,
            captured.full_text_status,
        )

    def _check_record_replay(self, gateway, adapter, identifier, raw_body):
        request = adapter.build_request(identifier)
        captured = gateway.fetch(request)
        record = adapter.normalize(self._envelope(captured))
        registered = self.registry.put_json(
            record.to_dict(),
            logical_type="normalized_scholarly_record",
            origin="native replay integration fixture; not live evidence",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("test", "native-replay-review"),
            parent_artifacts=record.parent_artifact_hashes,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        before = self.registry.list_records()
        resolved = _resolve_registry_scholarly_record(
            self.registry, registered.sha256
        )
        self.assertEqual(resolved.scholarly_record, record)
        self.assertEqual(resolved.request, request)
        self.assertEqual(resolved.captured.request_body_size, 0)
        self.assertEqual(
            resolved.captured.request_body_sha256,
            hashlib.sha256(b"").hexdigest(),
        )
        self.assertEqual(
            resolved.captured.response_body_sha256,
            hashlib.sha256(raw_body).hexdigest(),
        )
        self.assertFalse(resolved.captured.network_used)
        self.assertEqual(resolved.captured.external_validation, "UNTESTED")
        self.assertEqual(
            resolved.captured.transport_authority,
            UNVERIFIED_TRANSPORT_AUTHORITY,
        )
        self.assertEqual(self.registry.list_records(), before)
        self.ledger.record(
            run_id=self.run_id,
            actor_role=Role.EVIDENCE_CURATOR,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=resolved.artifact_hashes,
            code_version=f"sha256:{'a' * 64}",
            configuration_hash="b" * 64,
            dataset_identifiers=("native-replay-fixture",),
            random_seeds=(),
            evaluator_outputs=(),
            reason="native fixture registered before checked literature consumption",
            event_type="CHECKPOINT",
            metadata={
                "phase": "CONTROLLED_LITERATURE",
                "research_os_materialization": "REGISTERED_BEFORE_CONSUMPTION",
                "scientific_evidence": False,
            },
        )
        events_before = self.ledger.assert_valid().events
        # Reaching this error means native parser/request replay and same-run
        # ledger custody passed, without granting fixture data live authority.
        with self.assertRaisesRegex(
            ScientificPromotionError,
            "lacks audited live transport authority",
        ):
            require_audited_live_controlled_literature_authority(
                self.registry,
                self.ledger,
                scholarly_record_artifact_sha256=registered.sha256,
                expected_run_id=self.run_id,
                expected_request=request,
            )
        self.assertEqual(self.registry.list_records(), before)
        self.assertEqual(self.ledger.assert_valid().events, events_before)

    def test_native_openalex_record_replays_without_live_promotion(self) -> None:
        body = canonical_json_bytes(native_fixtures.openalex_work())
        gateway, _ = self.fixture._openalex_gateway(
            body, native_fixtures.OPENALEX_WORK_URL
        )
        self._check_record_replay(
            gateway,
            OpenAlexAdapter(),
            ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789"),
            body,
        )

    def test_native_pmc_record_replays_without_live_promotion(self) -> None:
        body = native_fixtures.pmc_xml()
        gateway, _ = self.fixture._pmc_gateway(body)
        self._check_record_replay(
            gateway,
            PMCAdapter(),
            ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            body,
        )

    def test_native_search_capture_uses_typed_search_owner(self) -> None:
        plan = self.fixture._search_plan()
        request = ScholarlySearchRequest.from_plan(plan, ScholarlySource.OPENALEX)
        body = native_fixtures.openalex_list(
            [native_fixtures.openalex_work()], per_page=2, page=1
        )
        gateway, _ = self.fixture._openalex_gateway(
            body, native_fixtures.OPENALEX_SEARCH_URL
        )
        captured = gateway.fetch(request)
        resolved = _resolve_captured_gateway_envelope(
            self.registry,
            raw_artifact_hash=captured.raw_artifact_hash,
            response_artifact_hash=captured.response_artifact_hash,
            expected_request=request,
            expected_source=request.source,
            expected_request_id=request.request_id,
            expected_request_payload=_scholarly_search_request_payload(request),
            response_logical_type="scholarly_search_response",
        )
        self.assertEqual(resolved.envelope, self._envelope(captured))
        self.assertEqual(resolved.request_body_size, 0)
        self.assertEqual(resolved.external_validation, "UNTESTED")

    def test_native_graph_capture_preserves_both_traversal_directions(self) -> None:
        for traversal, operation, relation in (
            (CitationTraversal.REFERENCES, "expand_references", "cited_by"),
            (CitationTraversal.CITED_BY, "expand_citations", "cites"),
        ):
            with self.subTest(traversal=traversal.value):
                request = CitationPageRequest(
                    plan_sha256=native_fixtures.digest(f"plan:{traversal.value}"),
                    task_id=native_fixtures.digest(f"task:{traversal.value}"),
                    source=ScholarlySource.OPENALEX,
                    operation=operation,
                    identifier=ScholarlyIdentifier(
                        IdentifierKind.OPENALEX, "W123456789"
                    ),
                    traversal=traversal,
                    origin_node_id=f"citation-node:{native_fixtures.digest('origin')}",
                    depth=1,
                    page_number=1,
                    cursor=None,
                )
                body = native_fixtures.openalex_list(
                    [native_fixtures.openalex_work("W333333333")],
                    per_page=100,
                    next_cursor="cursor-next",
                )
                gateway, _ = self.fixture._openalex_gateway(
                    body,
                    "https://api.openalex.org/works?filter="
                    f"{relation}%3AW123456789&per_page=100&cursor=%2A",
                )
                captured = gateway.fetch(request)
                resolved = _resolve_captured_gateway_envelope(
                    self.registry,
                    raw_artifact_hash=captured.raw_artifact_hash,
                    response_artifact_hash=captured.response_artifact_hash,
                    expected_request=request,
                    expected_source=request.source,
                    expected_request_id=request.request_id,
                    expected_request_payload={
                        "citation_page": request.page_number,
                        "cursor": request.cursor,
                        "identifier": request.identifier.value,
                        "identifier_kind": request.identifier.kind.value,
                        "operation": request.operation,
                        "origin_node_id": request.origin_node_id,
                        "plan_sha256": request.plan_sha256,
                        "scholarly_request_id": request.request_id,
                        "source": request.source.value,
                        "task_id": request.task_id,
                        "traversal": request.traversal.value,
                    },
                    response_logical_type="citation_expansion_response",
                )
                expected = normalize_citation_expansion_page(
                    request, self._envelope(captured)
                )
                self.assertEqual(
                    normalize_citation_expansion_page(request, resolved.envelope),
                    expected,
                )
                self.assertFalse(resolved.network_used)

    def test_native_dispatch_rejects_inconsistent_typed_request(self) -> None:
        body = canonical_json_bytes(native_fixtures.openalex_work())
        gateway, _ = self.fixture._openalex_gateway(
            body, native_fixtures.OPENALEX_WORK_URL
        )
        adapter = OpenAlexAdapter()
        request = adapter.build_request(
            ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789")
        )
        other = adapter.build_request(
            ScholarlyIdentifier(IdentifierKind.OPENALEX, "W987654321")
        )
        captured = gateway.fetch(request)
        before = self.registry.list_records()
        with self.assertRaisesRegex(
            ScientificPromotionError, "differs from its exact typed request"
        ):
            _resolve_captured_gateway_envelope(
                self.registry,
                raw_artifact_hash=captured.raw_artifact_hash,
                response_artifact_hash=captured.response_artifact_hash,
                expected_request=other,
                expected_source=request.source,
                expected_request_id=request.request_id,
                expected_request_payload={},
                response_logical_type="scholarly_response",
            )
        self.assertEqual(self.registry.list_records(), before)


if __name__ == "__main__":
    unittest.main()
