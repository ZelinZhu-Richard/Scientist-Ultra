"""Synthetic unsigned content custody tests, not live or signed authority."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import zlib

import scientist_one.external as external_module
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.external import (
    EgressGateway, FixtureTransport, TransportResponse, EgressDeniedError,
    ExternalUnavailableError, EgressPolicyError, EgressRequest,
    require_pmc_content_decoding, StdlibHttpsTransport,
)
from scientist_one.literature import PMCAdapter, ScholarlyIdentifier, IdentifierKind, RetrievalStatus
from scientist_one.roles import Role
from scientist_one.scholarly_gateway import (
    SourceOwnedScholarlyGateway, pmc_content_scholarly_egress_policy,
    require_available_scholarly_native_capture, _encode_pmc_request, ScholarlyGatewayError,
)
from tests.test_scholarly_gateway import PMC_URL, pmc_xml


def encoded(raw, coding):
    if coding == "identity":
        return raw
    compressor = zlib.compressobj(wbits=31 if coding == "gzip" else 15)
    return compressor.compress(raw) + compressor.flush()


class PmcContentGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.registry = ArtifactRegistry(Path(self.temporary.name))
        self.request = PMCAdapter().build_request(ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"))

    def gateway(self, bodies, coding="gzip", **options):
        transport = FixtureTransport(tuple(
            TransportResponse(status, (("Content-Type", "application/xml"),
                                       ("Content-Encoding", coding)), body, PMC_URL)
            for status, body in bodies))
        policy = pmc_content_scholarly_egress_policy(maximum_attempts=len(bodies), **options)
        def forbidden(*args):
            raise AssertionError("caller clock/sleeper must not own v3 time")
        egress = EgressGateway(policy, transport, registry=self.registry,
                               clock=forbidden, sleeper=forbidden,
                               timestamp=lambda: "2026-09-13T12:00:00.000000Z")
        return SourceOwnedScholarlyGateway(pmc_gateway=egress), transport

    def test_three_codings_capture_raw_and_replay_distinct_identity_roles(self):
        for coding in ("identity", "gzip", "deflate"):
            with self.subTest(coding=coding):
                # Registry per response prevents unrelated historical raw parent collisions.
                root = Path(self.temporary.name) / coding
                root.mkdir()
                self.registry = ArtifactRegistry(root)
                xml = pmc_xml()
                wire = encoded(xml, coding)
                gateway, transport = self.gateway([(200, wire)], coding)
                captured = gateway.fetch(self.request)
                self.assertEqual(captured.status, RetrievalStatus.AVAILABLE, captured.failure_reason)
                self.assertEqual(captured.schema_version, "scholarly-native-response/v3")
                self.assertEqual(self.registry.get_bytes(captured.raw_artifact_hash), wire)
                normalized = json.loads(self.registry.get_bytes(captured.response_artifact_hash))
                descriptor_hash = normalized["decoding_artifact_sha256"]
                descriptor = json.loads(self.registry.get_bytes(descriptor_hash))
                self.assertLess(len(self.registry.get_bytes(descriptor_hash)), 4096)
                self.assertEqual(descriptor["decoded_xml_sha256"], hashlib.sha256(xml).hexdigest())
                self.assertEqual(descriptor["wire_raw_artifact_sha256"], hashlib.sha256(wire).hexdigest())
                self.assertFalse(descriptor["scientific_evidence"])
                replay = require_available_scholarly_native_capture(
                    self.registry, request=self.request, raw_artifact_sha256=captured.raw_artifact_hash,
                    response_artifact_sha256=captured.response_artifact_hash)
                projection = replay.envelope.payload["full_text_projection"]
                self.assertEqual(projection["source_wire_raw_artifact_sha256"], captured.raw_artifact_hash)
                self.assertEqual(projection["source_decoded_xml_sha256"], hashlib.sha256(xml).hexdigest())
                self.assertEqual(projection["source_decoding_descriptor_artifact_sha256"], descriptor_hash)
                self.assertFalse(replay.network_used)
                self.assertEqual(replay.external_validation, "UNTESTED")
                self.assertEqual(len(transport.prepared_requests), 1)

    def test_malformed_success_retains_one_attempt_without_retry(self):
        gateway, transport = self.gateway([(200, b"not compressed"), (200, encoded(pmc_xml(), "gzip"))])
        captured = gateway.fetch(self.request)
        self.assertNotEqual(captured.status, RetrievalStatus.AVAILABLE)
        self.assertEqual(len(transport.prepared_requests), 1)

    def test_retry_retains_encoded_attempt_accounting(self):
        wire = encoded(pmc_xml(), "gzip")
        gateway, transport = self.gateway([(500, b"failure"), (200, wire)])
        captured = gateway.fetch(self.request)
        self.assertEqual(captured.status, RetrievalStatus.AVAILABLE, captured.failure_reason)
        self.assertEqual(len(transport.prepared_requests), 2)
        require_available_scholarly_native_capture(
            self.registry, request=self.request, raw_artifact_sha256=captured.raw_artifact_hash,
            response_artifact_sha256=captured.response_artifact_hash)

    def test_profile_cannot_relax_pmc_rate(self):
        with self.assertRaises(Exception):
            policy = replace(pmc_content_scholarly_egress_policy(), minimum_interval_seconds=0.0)
            SourceOwnedScholarlyGateway(pmc_gateway=EgressGateway(policy, FixtureTransport(()), registry=self.registry))

    def direct(self, gateway):
        binding = next(iter(gateway._bindings.values()))
        request = replace(_encode_pmc_request(self.request), adapter_id=binding.gateway.policy.adapter_id)
        return binding.gateway, request

    def clone(self, record, value, *, parents=None):
        return self.registry.put_json(
            value, logical_type=record.logical_type, origin=record.origin,
            creator_role=record.creator_role, creation_command=record.creation_command,
            parent_artifacts=record.parent_artifacts if parents is None else parents,
            schema_version=record.schema_version, mime_type=record.mime_type,
            validation_result=record.validation_result, frozen=record.frozen)

    def test_decoding_refusal_is_static_and_retains_exact_raw_once(self):
        for wire in (b"RAW_PRIVATE_MARKER", encoded(pmc_xml(), "gzip")[:-1],
                     encoded(pmc_xml(), "gzip") + b"extra",
                     encoded(b"A" * 100000, "gzip")):
            with self.subTest(size=len(wire)):
                gateway, transport = self.gateway([(200, wire), (200, wire)])
                egress, request = self.direct(gateway)
                with self.assertRaises(EgressDeniedError) as caught:
                    egress.execute(request)
                error = caught.exception
                self.assertEqual(str(error), "CONTENT_DECODING_REFUSED")
                self.assertIsNone(error.__context__)
                self.assertEqual(len(error.attempts), 1)
                self.assertEqual(error.attempts[0]["response_body_bytes"], len(wire))
                records = [record for record in error.artifacts if record.logical_type == "external_response_raw"]
                self.assertEqual(len(records), 1)
                self.assertEqual(self.registry.get_bytes(records[0].sha256), wire)
                self.assertEqual(len(transport.prepared_requests), 1)

    def test_descriptor_tampering_and_metadata_parent_splices_refuse(self):
        gateway, _ = self.gateway([(200, encoded(pmc_xml(), "gzip"))])
        egress, request = self.direct(gateway)
        result = egress.execute(request)
        original = result.content_decoding_artifact
        value = json.loads(self.registry.get_bytes(original.sha256))
        receipt = json.loads(self.registry.get_bytes(result.response_receipt_artifact.sha256))
        variants = [dict(value, unexpected=True), dict(value, scientific_evidence=True),
                    dict(value, decoded_xml_sha256="0" * 64), dict(value, decoded_xml_size=True),
                    dict(value, wire_body_size=value["wire_body_size"] + 1),
                    dict(value, content_coding="identity"), dict(value, content_profile="unknown"),
                    dict(value, decoding_started_offset_seconds=-1),
                    dict(value, request_artifact_record_hash="0" * 64),
                    dict(value, decode_limits=dict(value["decode_limits"], maximum_expansion_ratio=True))]
        for changed in variants:
            with self.subTest(changed=changed):
                record = self.clone(original, changed)
                rebound = dict(receipt, decoding_artifact_sha256=record.sha256,
                               decoding_artifact_record_hash=record.record_hash)
                with self.assertRaises(EgressPolicyError):
                    require_pmc_content_decoding(self.registry, descriptor_sha256=record.sha256,
                                                receipt=rebound, policy=egress.policy)
        # Change content as well to give a new content-addressed descriptor identity.
        changed = dict(value, decoded_xml_sha256="1" * 64)
        record = self.clone(original, changed, parents=tuple(reversed(original.parent_artifacts)))
        rebound = dict(receipt, decoding_artifact_sha256=record.sha256,
                       decoding_artifact_record_hash=record.record_hash)
        with self.assertRaises(EgressPolicyError):
            require_pmc_content_decoding(self.registry, descriptor_sha256=record.sha256,
                                        receipt=rebound, policy=egress.policy)

    def test_native_replay_rejects_version_mix_and_projection_splice(self):
        gateway, _ = self.gateway([(200, encoded(pmc_xml(), "gzip"))])
        captured = gateway.fetch(self.request)
        record = self.registry.get_metadata(captured.response_artifact_hash)
        original = json.loads(self.registry.get_bytes(record.sha256))
        for field, change in (("schema_version", "scholarly-native-response/v2"),
                              ("decoding_artifact_sha256", "0" * 64),
                              ("wire_protocol", "pmc-oai-jats-xml/v1"),
                              ("network_used", True), ("scientific_evidence", True)):
            with self.subTest(field=field):
                forged = self.clone(record, dict(original, **{field: change}))
                with self.assertRaises(ScholarlyGatewayError):
                    require_available_scholarly_native_capture(
                        self.registry, request=self.request, raw_artifact_sha256=captured.raw_artifact_hash,
                        response_artifact_sha256=forged.sha256)

    def test_generic_policy_alias_hosts_remain_closed_before_transport(self):
        for host in ("pmc.ncbi.nlm.nih.gov", "PMC.NCBI.NLM.NIH.GOV", "pmc.ncbi.nlm.nih.gov:443"):
            for path in ("/api/oai/v1/mh/", "/api/oai/v1/mh/./other"):
                with self.subTest(host=host, path=path):
                    policy = replace(pmc_content_scholarly_egress_policy(), adapter_id="generic-fixture", allowed_query_keys=())
                    egress = EgressGateway(policy, StdlibHttpsTransport(), registry=self.registry)
                    request = EgressRequest(adapter_id=policy.adapter_id, method="GET", url=f"https://{host}{path}",
                                            content_type="application/xml")
                    with self.assertRaisesRegex(ExternalUnavailableError, "source coordination"):
                        egress.execute(request)

    def test_decode_and_descriptor_capture_remain_inside_native_deadline(self):
        gateway, _ = self.gateway([(200, encoded(pmc_xml(), "gzip"))], timeout_seconds=0.10)
        egress, request = self.direct(gateway)
        original = self.registry.put_json
        def delayed_descriptor(value, **metadata):
            if metadata["logical_type"] == "external_response_decoding":
                time.sleep(0.13)
            return original(value, **metadata)
        with patch.object(self.registry, "put_json", side_effect=delayed_descriptor):
            with self.assertRaisesRegex(EgressDeniedError, "CONTENT_DECODING_REFUSED") as caught:
                egress.execute(request)
        self.assertEqual(len(caught.exception.attempts), 1)
        self.assertIsNone(caught.exception.__context__)

    def test_cancellation_is_not_minted_as_denial_or_authority(self):
        gateway, _ = self.gateway([(200, encoded(pmc_xml(), "gzip"))])
        egress, request = self.direct(gateway)
        original = self.registry.put_json
        def cancel_descriptor(value, **metadata):
            if metadata["logical_type"] == "external_response_decoding":
                raise KeyboardInterrupt("cancel fixture")
            return original(value, **metadata)
        with patch.object(self.registry, "put_json", side_effect=cancel_descriptor):
            with self.assertRaises(KeyboardInterrupt):
                egress.execute(request)
        self.assertFalse(list(Path(self.temporary.name).rglob("*.key")))

    def test_unknown_stacked_and_duplicate_codings_refuse_with_raw_custody(self):
        for coding in ("br", "gzip, deflate", "gzip;bad=1"):
            with self.subTest(coding=coding):
                gateway, transport = self.gateway([(200, encoded(pmc_xml(), "gzip"))], coding)
                egress, request = self.direct(gateway)
                with self.assertRaises(EgressDeniedError) as caught:
                    egress.execute(request)
                self.assertEqual(len(caught.exception.attempts), 1)
                self.assertEqual(len(transport.prepared_requests), 1)
        for headers in ((("Content-Encoding", ""),),
                        (("Content-Encoding", "gzip"), ("content-encoding", "gzip"))):
            with self.subTest(headers=headers):
                with self.assertRaises(EgressPolicyError):
                    TransportResponse(200, headers, b"fixture", PMC_URL)

    def test_wire_limit_uses_encoded_bytes_and_clamps_final_attempt_budget(self):
        wire = encoded(pmc_xml(), "gzip")
        gateway, _ = self.gateway([(500, b"fail"), (200, wire)], maximum_total_bytes=len(wire) + 4)
        egress, request = self.direct(gateway)
        result = egress.execute(request)
        value = json.loads(self.registry.get_bytes(result.content_decoding_artifact.sha256))
        self.assertEqual(value["decode_limits"]["maximum_input_bytes"], len(wire))
        self.assertEqual(result.body, wire)
        self.assertEqual(result.decoded_body, pmc_xml())
        self.assertIsNone(result.transport_execution_authority_artifact)

    def test_capture_failure_keeps_explicit_v3_protocol_and_raw_custody(self):
        gateway, _ = self.gateway([(200, encoded(pmc_xml(), "gzip"))])
        with patch.object(gateway, "_capture_parsed", side_effect=ScholarlyGatewayError("fixture custody refusal")):
            captured = gateway.fetch(self.request)
        self.assertEqual(captured.schema_version, "scholarly-native-response/v3")
        self.assertEqual(captured.wire_protocol, "pmc-oai-jats-xml/v2")
        self.assertEqual(captured.status, RetrievalStatus.FAILED)
        self.assertIsNotNone(captured.raw_artifact_hash)
        self.assertIsNone(captured.response_artifact_hash)

    def test_decoded_rights_and_adverse_xml_do_not_gain_passages(self):
        cases = [(pmc_xml(license_uri=None), RetrievalStatus.LICENSE_RESTRICTED),
                 (pmc_xml(license_uri="https://creativecommons.org/licenses/by-nc/4.0/"), RetrievalStatus.LICENSE_RESTRICTED),
                 (b"<OAI-PMH>", RetrievalStatus.MALFORMED),
                 (b'<!DOCTYPE x [<!ENTITY y SYSTEM "file:///not-read">]><OAI-PMH>&y;</OAI-PMH>', RetrievalStatus.MALFORMED)]
        for xml, expected in cases:
            with self.subTest(expected=expected):
                gateway, _ = self.gateway([(200, encoded(xml, "gzip"))])
                captured = gateway.fetch(self.request)
                self.assertEqual(captured.status, expected)
                self.assertIsNone(captured.payload)
                normalized = json.loads(self.registry.get_bytes(captured.response_artifact_hash))
                self.assertIsNotNone(normalized["decoding_artifact_sha256"])

    def test_coding_header_case_and_absence_are_canonicalized(self):
        for coding, wire in (("GZip", encoded(pmc_xml(), "gzip")), (None, pmc_xml())):
            with self.subTest(coding=coding):
                headers = (("Content-Type", "application/xml"),)
                if coding is not None:
                    headers += (("Content-Encoding", coding),)
                egress = EgressGateway(pmc_content_scholarly_egress_policy(maximum_attempts=1),
                                       FixtureTransport((TransportResponse(200, headers, wire, PMC_URL),)),
                                       registry=self.registry)
                gateway = SourceOwnedScholarlyGateway(pmc_gateway=egress)
                captured = gateway.fetch(self.request)
                self.assertEqual(captured.status, RetrievalStatus.AVAILABLE)
                require_available_scholarly_native_capture(
                    self.registry, request=self.request, raw_artifact_sha256=captured.raw_artifact_hash,
                    response_artifact_sha256=captured.response_artifact_hash)

    def test_native_epoch_includes_request_capture_callback_time(self):
        gateway, transport = self.gateway([(200, encoded(pmc_xml(), "gzip"))], timeout_seconds=0.10)
        egress, request = self.direct(gateway)
        original = self.registry.put_json
        def delayed_request(value, **metadata):
            if metadata["logical_type"] == "external_request":
                time.sleep(0.13)
            return original(value, **metadata)
        with patch.object(self.registry, "put_json", side_effect=delayed_request):
            with self.assertRaises(EgressDeniedError):
                egress.execute(request)
        self.assertEqual(len(transport.prepared_requests), 0)
        with self.assertRaises(TypeError):
            egress.execute(request, _native_timing=(0, 999999999, lambda: 0, lambda _: None))

    def test_delayed_raising_descriptor_records_fresh_native_denial_budget(self):
        gateway, transport = self.gateway([(200, encoded(pmc_xml(), "gzip"))], timeout_seconds=0.10)
        egress, request = self.direct(gateway)
        original = self.registry.put_json
        def delayed_raising(value, **metadata):
            if metadata["logical_type"] == "external_response_decoding":
                time.sleep(0.15)
                raise RuntimeError("PRIVATE_CALLBACK_MARKER")
            return original(value, **metadata)
        started = time.monotonic()
        with patch.object(self.registry, "put_json", side_effect=delayed_raising):
            with self.assertRaises(EgressDeniedError) as caught:
                egress.execute(request)
        actual_elapsed = time.monotonic() - started
        error = caught.exception
        denial_records = [record for record in error.artifacts
                          if record.logical_type == "external_response_denial_receipt"]
        denial = json.loads(self.registry.get_bytes(denial_records[-1].sha256))
        budget = denial["egress_budget"]
        self.assertEqual(str(error), "CONTENT_DECODING_REFUSED")
        self.assertIsNone(error.__context__)
        self.assertGreaterEqual(budget["deadline_elapsed_seconds"], 0.10)
        self.assertLessEqual(budget["deadline_elapsed_seconds"], actual_elapsed)
        self.assertEqual(budget["deadline_remaining_seconds"], 0.0)
        self.assertFalse(budget["deadline_satisfied"])
        self.assertEqual(len(error.attempts), 1)
        self.assertLess(error.attempts[0]["completed_offset_seconds"], 0.10)
        self.assertEqual(len(transport.prepared_requests), 1)
        self.assertEqual(len([r for r in error.artifacts if r.logical_type == "external_response_raw"]), 1)
        self.assertNotIn("PRIVATE_CALLBACK_MARKER", json.dumps(denial))

    def test_real_descriptor_metadata_splices_refuse_before_available(self):
        changes = (
            {"logical_type": "fixture_wrong_type"}, {"schema_version": "1.0"},
            {"origin": "fixture wrong origin"}, {"creator_role": Role.ORCHESTRATOR},
            {"creation_command": ("fixture", "wrong")}, {"parent_artifacts": ()},
            {"mime_type": "application/octet-stream"}, {"frozen": False},
            {"validation_result": "FAIL", "frozen": False},
        )
        for index, change in enumerate(changes):
            with self.subTest(change=change):
                root = Path(self.temporary.name) / f"metadata-{index}"
                root.mkdir()
                self.registry = ArtifactRegistry(root)
                gateway, transport = self.gateway([(200, encoded(pmc_xml(), "gzip"))])
                original = self.registry.put_json
                registered = []
                def altered(value, **metadata):
                    if metadata["logical_type"] == "external_response_decoding":
                        record = original(value, **dict(metadata, **change))
                        registered.append(record)
                        return record
                    return original(value, **metadata)
                with patch.object(self.registry, "put_json", side_effect=altered):
                    captured = gateway.fetch(self.request)
                self.assertEqual(len(registered), 1)
                actual = self.registry.get_metadata(registered[0].sha256)
                for field, expected in change.items():
                    self.assertEqual(getattr(actual, field), expected)
                self.assertEqual(captured.status, RetrievalStatus.FAILED)
                self.assertIsNone(captured.payload)
                self.assertIsNotNone(captured.raw_artifact_hash)
                self.assertEqual(len(transport.prepared_requests), 1)

    def test_returned_descriptor_record_splices_refuse_even_with_correct_real_metadata(self):
        changes = (
            {"sha256": "0" * 64}, {"path": "fixture/wrong", "relative_path": "fixture/wrong"},
            {"metadata_path": "fixture/wrong.json"}, {"logical_type": "fixture_wrong"},
            {"schema_version": "wrong/v1"}, {"mime_type": "application/octet-stream"},
            {"size": 1}, {"origin": "fixture wrong origin"},
            {"creator_role": Role.ORCHESTRATOR}, {"creation_command": ("fixture",)},
            {"parent_artifacts": ()}, {"frozen": False},
            {"validation_result": "FAIL", "frozen": False},
            {"created_at": "2001-01-01T00:00:00Z"},
        )
        for change in changes:
            with self.subTest(change=change):
                gateway, transport = self.gateway([(200, encoded(pmc_xml(), "gzip"))])
                egress, request = self.direct(gateway)
                original = self.registry.put_json
                def altered(value, **metadata):
                    record = original(value, **metadata)
                    if metadata["logical_type"] == "external_response_decoding":
                        return replace(record, **dict(change, record_hash=None))
                    return record
                with patch.object(self.registry, "put_json", side_effect=altered):
                    with self.assertRaisesRegex(EgressDeniedError, "CONTENT_DECODING_REFUSED") as caught:
                        egress.execute(request)
                self.assertIsNone(caught.exception.__context__)
                self.assertEqual(len(caught.exception.attempts), 1)
                self.assertEqual(len(transport.prepared_requests), 1)

    def test_descriptor_data_callback_cannot_change_prepublication_snapshot(self):
        gateway, _ = self.gateway([(200, encoded(pmc_xml(), "gzip"))])
        egress, request = self.direct(gateway)
        original = self.registry.put_json
        def alter_nested_limits(value, **metadata):
            if metadata["logical_type"] == "external_response_decoding":
                value["decode_limits"]["maximum_expansion_ratio"] = 199
            return original(value, **metadata)
        with patch.object(self.registry, "put_json", side_effect=alter_nested_limits):
            with self.assertRaisesRegex(EgressDeniedError, "CONTENT_DECODING_REFUSED"):
                egress.execute(request)

    def test_consumer_rejects_changed_cache_without_postdeadline_decompression(self):
        for changed in ("decoded_body", "content_decoding_artifact", "raw_response_artifact", "request_artifact"):
            with self.subTest(changed=changed):
                root = Path(self.temporary.name) / changed
                root.mkdir()
                self.registry = ArtifactRegistry(root)
                gateway, transport = self.gateway([(200, encoded(pmc_xml(), "gzip"))])
                egress, request = self.direct(gateway)
                binding = next(iter(gateway._bindings.values()))
                result = egress.execute(request, parent_artifacts=(binding.authority_artifact.sha256,))
                replacement = (pmc_xml().replace(b"Fixture Journal", b"Changed Journal")
                               if changed == "decoded_body"
                               else replace(getattr(result, changed), origin="fixture returned splice", record_hash=None))
                # The actual unsigned acquisition has finished. Inject only its
                # consumer value; do not bypass exact execution admission.
                altered_result = replace(result, **{changed: replacement})
                with patch.object(egress, "execute", return_value=altered_result), patch.object(
                    external_module, "_replay_pmc_content", side_effect=AssertionError("consumer must not decompress"),
                ) as replay:
                    captured = gateway.fetch(self.request)
                self.assertEqual(captured.status, RetrievalStatus.MALFORMED)
                self.assertIsNone(captured.payload)
                self.assertEqual(len(transport.prepared_requests), 1)
                replay.assert_not_called()

    def test_double_publication_failure_retains_static_error_and_original_attempt(self):
        wire = encoded(pmc_xml(), "gzip")
        gateway, transport = self.gateway([(200, wire), (200, wire)])
        egress, request = self.direct(gateway)
        original = self.registry.put_json
        failures = []
        def fail_publications(value, **metadata):
            if metadata["logical_type"] == "external_response_decoding":
                failures.append("descriptor")
                raise RuntimeError("PRIVATE_DESCRIPTOR_MARKER")
            if metadata["logical_type"] == "external_response_denial_receipt":
                failures.append("denial")
                raise RuntimeError("PRIVATE_DENIAL_MARKER")
            return original(value, **metadata)
        with patch.object(self.registry, "put_json", side_effect=fail_publications):
            with self.assertRaises(EgressDeniedError) as caught:
                egress.execute(request)
        error = caught.exception
        self.assertEqual(str(error), "CONTENT_DECODING_REFUSED")
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertEqual(failures, ["descriptor", "denial"])
        self.assertEqual(len(transport.prepared_requests), 1)
        self.assertEqual(len(error.attempts), 1)
        self.assertEqual(error.attempts[0]["response_body_bytes"], len(wire))
        self.assertEqual(error.attempts[0]["cumulative_bytes"], len(wire))
        raw = [r for r in error.artifacts if r.logical_type == "external_response_raw"]
        self.assertEqual(len(raw), 1)
        self.assertEqual(self.registry.get_bytes(raw[0].sha256), wire)
        self.assertEqual({r.logical_type for r in error.artifacts}, {"external_request", "external_response_raw"})
        self.assertFalse(any(r.logical_type == "external_response_denial_receipt"
                             for r in self.registry.list_records()))

    def test_double_publication_failure_returns_failed_scholarly_capture(self):
        wire = encoded(pmc_xml(), "gzip")
        gateway, transport = self.gateway([(200, wire)])
        original = self.registry.put_json
        def fail_publications(value, **metadata):
            if metadata["logical_type"] == "external_response_decoding":
                raise RuntimeError("PRIVATE_DESCRIPTOR_MARKER")
            if metadata["logical_type"] == "external_response_denial_receipt":
                raise OSError("PRIVATE_DENIAL_MARKER")
            return original(value, **metadata)
        with patch.object(self.registry, "put_json", side_effect=fail_publications):
            captured = gateway.fetch(self.request)
        self.assertEqual(captured.status, RetrievalStatus.FAILED)
        self.assertIsNone(captured.payload)
        self.assertEqual(len(transport.prepared_requests), 1)
        self.assertEqual(self.registry.get_bytes(captured.raw_artifact_hash), wire)
        normalized = json.loads(self.registry.get_bytes(captured.response_artifact_hash))
        self.assertIsNone(normalized["response_receipt_artifact_hash"])
        self.assertEqual(normalized["failure_reason"], "controlled scholarly egress failed: EgressDeniedError")
        self.assertNotIn("PRIVATE_", json.dumps(normalized))
        self.assertFalse(any(r.logical_type == "external_response_denial_receipt"
                             for r in self.registry.list_records()))

    def test_secondary_publication_cancellation_propagates_without_minted_denial(self):
        wire = encoded(pmc_xml(), "gzip")
        gateway, transport = self.gateway([(200, wire)])
        original = self.registry.put_json
        cancellation = KeyboardInterrupt("fixture cancellation")
        def cancel_secondary(value, **metadata):
            if metadata["logical_type"] == "external_response_decoding":
                raise RuntimeError("PRIVATE_DESCRIPTOR_MARKER")
            if metadata["logical_type"] == "external_response_denial_receipt":
                raise cancellation
            return original(value, **metadata)
        with patch.object(self.registry, "put_json", side_effect=cancel_secondary):
            with self.assertRaises(KeyboardInterrupt) as caught:
                gateway.fetch(self.request)
        self.assertIs(caught.exception, cancellation)
        self.assertEqual(len(transport.prepared_requests), 1)
        records = self.registry.list_records()
        raw = [r for r in records if r.logical_type == "external_response_raw"]
        self.assertEqual(len(raw), 1)
        self.assertEqual(self.registry.get_bytes(raw[0].sha256), wire)
        self.assertFalse(any(r.logical_type == "external_response_denial_receipt" for r in records))
