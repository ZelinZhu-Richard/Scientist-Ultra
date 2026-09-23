"""Pure synthetic decoded projections, not wire or descriptor authentication."""

import hashlib
import unittest

from scientist_one import scholarly_gateway as subject
from scientist_one.literature import (
    FullTextStatus, IdentifierKind, RetrievalStatus, ScholarlyIdentifier,
    ScholarlyRequest, ScholarlySource,
)
from scientist_one.security import canonical_json_bytes
from tests.test_scholarly_gateway import pmc_xml


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def request():
    return ScholarlyRequest(ScholarlySource.PMC, "resolve_work",
                            ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"))


def project(raw, **overrides):
    options = dict(wire_raw_artifact_sha256=digest(b"synthetic wire bytes"),
                   decoded_xml_sha256=digest(raw),
                   decoding_descriptor_artifact_sha256=digest(b"unverified descriptor label"))
    options.update(overrides)
    return subject._project_decoded_pmc_response(raw, request(), **options)


class PmcDecodedProjectionTests(unittest.TestCase):
    def test_roles_coordinates_and_old_wrapper_relationship(self):
        raw = pmc_xml()
        parsed = project(raw)
        self.assertEqual(parsed.status, RetrievalStatus.AVAILABLE)
        projection = parsed.payload["full_text_projection"]
        self.assertEqual(projection["schema_version"], "pmc-jats-normalized-text-projection/v2")
        self.assertEqual(projection["source_wire_raw_artifact_sha256"], digest(b"synthetic wire bytes"))
        self.assertEqual(projection["source_decoded_xml_sha256"], digest(raw))
        self.assertEqual(projection["source_decoding_descriptor_artifact_sha256"],
                         digest(b"unverified descriptor label"))
        self.assertNotIn("source_raw_artifact_sha256", projection)
        self.assertFalse(projection["offsets_reference_raw_xml"])
        passages = parsed.payload["passages"]
        self.assertEqual([entry["text"] for entry in passages[:2]],
                         ["Repeated text A.", "Repeated text A."])
        self.assertEqual([entry["start_char"] for entry in passages[:2]], [0, 18])
        self.assertTrue(all(entry["coordinate_schema_version"] == projection["schema_version"]
                            for entry in passages))
        self.assertEqual(projection["normalized_text_sha256"],
                         digest("\n\n".join(entry["text"] for entry in passages).encode()))
        # Existing v1 fixture tests independently verify its parser semantics.
        # This comparison asserts only the explicit new projection relationship.
        old = subject._project_pmc_response(raw, digest(raw), request())
        expected = dict(old.payload)
        expected["full_text_projection"] = dict(old.payload["full_text_projection"])
        expected["full_text_projection"].pop("source_raw_artifact_sha256")
        expected["full_text_projection"].update({key: projection[key] for key in (
            "schema_version", "source_wire_raw_artifact_sha256", "source_decoded_xml_sha256",
            "source_decoding_descriptor_artifact_sha256")})
        expected["passages"] = [dict(entry, coordinate_schema_version=projection["schema_version"])
                                for entry in old.payload["passages"]]
        self.assertEqual(canonical_json_bytes(expected), canonical_json_bytes(parsed.payload))

    def test_identity_encoding_may_share_wire_and_xml_digest(self):
        raw = pmc_xml()
        value = project(raw, wire_raw_artifact_sha256=digest(raw)).payload["full_text_projection"]
        self.assertEqual(value["source_wire_raw_artifact_sha256"], value["source_decoded_xml_sha256"])

    def test_actual_xml_digest_must_match(self):
        with self.assertRaises(subject.ScholarlyGatewayError):
            project(pmc_xml(), decoded_xml_sha256=digest(b"different XML"))

    def test_identity_fields_have_exact_types_and_canonical_values(self):
        class TextSubclass(str):
            pass
        for field in ("wire_raw_artifact_sha256", "decoded_xml_sha256",
                      "decoding_descriptor_artifact_sha256"):
            for value in (None, True, 7, b"a" * 64, "a" * 63, "a" * 65, "G" * 64,
                          "A" * 64, TextSubclass("a" * 64), " a" * 32):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(subject.ScholarlyGatewayError):
                        project(pmc_xml(), **{field: value})

    def test_exact_decoded_bytes_required(self):
        class BytesSubclass(bytes):
            pass
        for value in (bytearray(pmc_xml()), memoryview(pmc_xml()), BytesSubclass(pmc_xml())):
            with self.assertRaises(subject.ScholarlyGatewayError):
                project(value)

    def test_reuse_rights_remain_fail_closed(self):
        cases = [pmc_xml(license_uri=None),
                 pmc_xml(license_uri="https://creativecommons.org/licenses/by-nc/4.0/"),
                 pmc_xml(license_uri="https://creativecommons.org/licenses/by-nd/4.0/"),
                 pmc_xml(extra_license_uri="https://publisher.invalid/terms")]
        for raw in cases:
            with self.subTest(digest=digest(raw)):
                parsed = project(raw)
                self.assertEqual(parsed.status, RetrievalStatus.LICENSE_RESTRICTED)
                self.assertEqual(parsed.full_text_status, FullTextStatus.LICENSE_RESTRICTED)
                self.assertIsNone(parsed.payload)
        cc0 = project(pmc_xml(license_uri="https://creativecommons.org/publicdomain/zero/1.0/"))
        self.assertEqual(cc0.status, RetrievalStatus.AVAILABLE)

    def test_malformed_or_mismatched_XML_refused(self):
        raw = pmc_xml()
        cases = (b"", b"\xef\xbb\xbf" + raw, raw[:-10],
                 raw.replace(b"<OAI-PMH", b"<!DOCTYPE fixture><OAI-PMH", 1),
                 raw.replace(b"<body>", b"<body><?unsafe x?>", 1),
                 raw.replace(b'identifier="oai:pubmedcentral.nih.gov:1234567"',
                             b'identifier="oai:pubmedcentral.nih.gov:7654321"', 1),
                 raw.replace(b"</body>", b"</body><body><p>extra</p></body>", 1))
        for value in cases:
            with self.subTest(digest=digest(value)):
                with self.assertRaises(subject.ScholarlyGatewayError):
                    project(value)

    def test_profiles_are_closed_and_cannot_mix_identity_roles(self):
        values = dict(wire_raw_artifact_sha256=digest(pmc_xml()),
                      decoded_xml_sha256=None, decoding_descriptor_artifact_sha256=None)
        for profile in ("pmc-jats-normalized-text-projection/v1", "v3", {}, None, True):
            with self.assertRaises(subject.ScholarlyGatewayError):
                subject._pmc_projection_sources(profile, **values)
        with self.assertRaises(subject.ScholarlyGatewayError):
            subject._pmc_projection_sources(subject._PmcProjectionProfile.RAW_XML_V1,
                                            **dict(values, decoded_xml_sha256=digest(pmc_xml())))
        with self.assertRaises(subject.ScholarlyGatewayError):
            subject._pmc_projection_sources(subject._PmcProjectionProfile.DECODED_XML_V2, **values)

    def test_descriptor_label_does_not_authenticate_an_artifact(self):
        first = project(pmc_xml(), decoding_descriptor_artifact_sha256=digest(b"absent one"))
        second = project(pmc_xml(), decoding_descriptor_artifact_sha256=digest(b"absent two"))
        self.assertNotEqual(first.payload["full_text_projection"], second.payload["full_text_projection"])
        self.assertEqual(first.payload["passages"], second.payload["passages"])
