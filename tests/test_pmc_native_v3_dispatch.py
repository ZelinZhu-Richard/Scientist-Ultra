"""Actual unsigned native custody through the scientific literature consumer.

Synthetic source data does not acquire audited live or scientific authority.
"""

import json
import unittest
import zlib

from scientist_one import scientific_design as subject
from scientist_one.external import EgressGateway, FixtureTransport, TransportResponse
from scientist_one.literature import IdentifierKind, PMCAdapter, ScholarlyIdentifier
from scientist_one.scholarly_gateway import (
    SourceOwnedScholarlyGateway, pmc_content_scholarly_egress_policy,
)
from tests import test_scholarly_gateway as fixtures
from tests import test_scholarly_gateway_replay_review as replay_controls


class PmcNativeV3DispatchTests(unittest.TestCase):
    def setUp(self):
        self.case = replay_controls.ScholarlyGatewayReplayReviewTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.registry = self.case.registry
        self.adapter = PMCAdapter()
        self.identifier = ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567")
        self.request = self.adapter.build_request(self.identifier)

    def gateway(self):
        compressor = zlib.compressobj(wbits=31)
        wire = compressor.compress(fixtures.pmc_xml()) + compressor.flush()
        transport = FixtureTransport((TransportResponse(
            200, (("Content-Type", "application/xml"), ("Content-Encoding", "gzip")),
            wire, fixtures.PMC_URL,
        ),))
        egress = EgressGateway(pmc_content_scholarly_egress_policy(maximum_attempts=1),
                               transport, registry=self.registry)
        return SourceOwnedScholarlyGateway(pmc_gateway=egress), wire

    def resolve(self, captured, *, request=None, response_hash=None):
        request = self.request if request is None else request
        return subject._resolve_captured_gateway_envelope(
            self.registry,
            raw_artifact_hash=captured.raw_artifact_hash,
            response_artifact_hash=(captured.response_artifact_hash
                                    if response_hash is None else response_hash),
            expected_request=request,
            expected_source=self.request.source,
            expected_request_id=self.request.request_id,
            expected_request_payload={},
            response_logical_type="scholarly_response",
        )

    def test_real_record_replay_and_same_run_ledger_do_not_grant_live_authority(self):
        gateway, wire = self.gateway()
        # This existing helper executes actual capture/normalization/registration,
        # source replay and ledger closure before requiring the live refusal.
        self.case._check_record_replay(gateway, self.adapter, self.identifier, wire)

    def test_custody_projection_retains_descriptor_and_encoded_body_identities(self):
        gateway, wire = self.gateway()
        captured = gateway.fetch(self.request)
        before = self.registry.list_records()
        resolved = self.resolve(captured)
        normalized = json.loads(self.registry.get_bytes(captured.response_artifact_hash))
        descriptor = normalized["decoding_artifact_sha256"]
        self.assertIn(descriptor, resolved.artifact_hashes)
        self.assertEqual(resolved.response_body_size, len(wire))
        self.assertEqual(resolved.envelope.payload, captured.payload)
        self.assertFalse(resolved.network_used)
        self.assertEqual(resolved.external_validation, "UNTESTED")
        self.assertEqual(self.registry.list_records(), before)

    def test_wrong_typed_request_and_unknown_native_schema_refuse_without_writes(self):
        gateway, _wire = self.gateway()
        captured = gateway.fetch(self.request)
        record = self.registry.get_metadata(captured.response_artifact_hash)
        payload = json.loads(self.registry.get_bytes(record.sha256))
        unknown_hashes = []
        for schema in ("scholarly-native-response/v999", {}, [], True, None, 999):
            unknown = self.registry.put_json(
                dict(payload, schema_version=schema), logical_type=record.logical_type,
                origin=record.origin, creator_role=record.creator_role,
                creation_command=record.creation_command,
                parent_artifacts=record.parent_artifacts, schema_version=record.schema_version,
                mime_type=record.mime_type, validation_result=record.validation_result,
                frozen=record.frozen,
            )
            unknown_hashes.append(unknown.sha256)
        other_request = self.adapter.build_request(
            ScholarlyIdentifier(IdentifierKind.PMCID, "PMC7654321"))
        cases = [{"request": other_request},
                 *({"response_hash": digest} for digest in unknown_hashes)]
        for overrides in cases:
            with self.subTest(fields=tuple(overrides)):
                before = self.registry.list_records()
                events = self.case.ledger.assert_valid().events
                with self.assertRaises(subject.ScientificPromotionError):
                    self.resolve(captured, **overrides)
                self.assertEqual(self.registry.list_records(), before)
                self.assertEqual(self.case.ledger.assert_valid().events, events)
