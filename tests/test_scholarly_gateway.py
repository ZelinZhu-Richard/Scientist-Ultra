from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import scientist_one.scholarly_gateway as scholarly_gateway_module
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.external import (
    EgressGateway,
    FixtureTransport,
    TransportResponse,
    UNVERIFIED_TRANSPORT_AUTHORITY,
)
from scientist_one.literature import (
    CitationPageRequest,
    CitationTraversal,
    FullTextStatus,
    GatewayEnvelope,
    IdentifierKind,
    OpenAlexAdapter,
    PMCAdapter,
    RetrievalStatus,
    ScholarlyIdentifier,
    ScholarlyRequest,
    ScholarlySearchFilter,
    ScholarlySearchPlan,
    ScholarlySearchPurpose,
    ScholarlySearchRequest,
    ScholarlySource,
    execute_scholarly_search,
    normalize_citation_expansion_page,
)
from scientist_one.scholarly_gateway import (
    OPENALEX_API_DOCUMENTATION_URLS,
    PMC_OAI_JATS_DOCUMENTATION_URLS,
    SCHOLARLY_EGRESS_ROUTE_AUTHORITY_SCHEMA_V2,
    SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V2,
    ReplayedScholarlyNativeCapture,
    ScholarlyGatewayError,
    ScholarlyGatewayFailureCode,
    ScholarlyRouteConfigurationError,
    SourceOwnedScholarlyGateway,
    openalex_scholarly_egress_policy,
    pmc_scholarly_egress_policy,
    require_available_scholarly_native_capture,
    supported_scholarly_routes,
)
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes


OPENALEX_SEARCH_URL = (
    "https://api.openalex.org/works?"
    "search=%28%22quantum%20gravity%22%20OR%20%22loop%20gravity%22%29"
    "&filter=open_access.is_oa%3Atrue%2Cpublication_year%3A2020-2024"
    "&per_page=2&page=1"
)
OPENALEX_WORK_URL = "https://api.openalex.org/works/W123456789"
PMC_URL = (
    "https://pmc.ncbi.nlm.nih.gov/api/oai/v1/mh/?verb=GetRecord"
    "&identifier=oai%3Apubmedcentral.nih.gov%3A1234567&metadataPrefix=pmc"
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def openalex_work(
    identifier: str = "W123456789",
    *,
    title: str = "A bounded work",
) -> dict[str, object]:
    return {
        "id": f"https://openalex.org/{identifier}",
        "doi": "https://doi.org/10.5555/bounded.1",
        "title": title,
        "authorships": [
            {"author": {"display_name": "Ada Researcher"}},
        ],
        "publication_year": 2025,
        "primary_location": {
            "source": {"display_name": "Bounded Journal"},
            "landing_page_url": "https://publisher.invalid/untrusted",
        },
        "abstract_inverted_index": {"Bounded": [0], "abstract": [1]},
        "cited_by_api_url": "https://attacker.invalid/follow-me",
    }


def openalex_list(
    results: list[dict[str, object]],
    *,
    per_page: int,
    page: int | None = None,
    next_cursor: str | None = None,
) -> bytes:
    meta: dict[str, object] = {
        "count": len(results),
        "per_page": per_page,
        "cost_usd": 0.0,
    }
    if page is not None:
        meta["page"] = page
    if next_cursor is not None:
        meta["next_cursor"] = next_cursor
    else:
        meta["next_cursor"] = None
    return canonical_json_bytes({"meta": meta, "results": results, "group_by": []})


def pmc_xml(
    *,
    pmcid: str = "PMC1234567",
    license_uri: str | None = "https://creativecommons.org/licenses/by/4.0/",
    extra_license_uri: str | None = None,
) -> bytes:
    licenses = ""
    if license_uri is not None:
        licenses += (
            '<license license-type="open-access" '
            f'xlink:href="{license_uri}"><license-p>License text.</license-p></license>'
        )
    if extra_license_uri is not None:
        licenses += (
            '<license license-type="open-access" '
            f'xlink:href="{extra_license_uri}"><license-p>Other terms.</license-p></license>'
        )
    numeric = pmcid[3:]
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xsi:schemaLocation="http://www.openarchives.org/OAI/2.0/ '
        'http://www.openarchives.org/OAI/2.0/OAI-PMH.xsd">'
        "<responseDate>2026-09-04T00:00:00Z</responseDate>"
        '<request verb="GetRecord" '
        f'identifier="oai:pubmedcentral.nih.gov:{numeric}" '
        'metadataPrefix="pmc">https://pmc.ncbi.nlm.nih.gov/api/oai/v1/mh/</request>'
        "<GetRecord><record><header>"
        f"<identifier>oai:pubmedcentral.nih.gov:{numeric}</identifier>"
        "<datestamp>2026-09-01</datestamp></header><metadata>"
        '<article xmlns="" xmlns:xlink="http://www.w3.org/1999/xlink">'
        "<front><journal-meta><journal-title-group>"
        "<journal-title>Fixture Journal</journal-title>"
        "</journal-title-group></journal-meta><article-meta>"
        f'<article-id pub-id-type="pmc">{pmcid}</article-id>'
        '<article-id pub-id-type="pmid">7654321</article-id>'
        '<article-id pub-id-type="doi">10.5555/pmc.1</article-id>'
        "<title-group><article-title>Reusable fixture article</article-title></title-group>"
        '<contrib-group><contrib contrib-type="author"><name>'
        "<surname>Curie</surname><given-names>Marie</given-names>"
        "</name></contrib></contrib-group>"
        "<pub-date><year>2024</year></pub-date>"
        "<abstract><p>Abstract   with spacing.</p></abstract>"
        f"<permissions>{licenses}</permissions>"
        "</article-meta></front><body>"
        '<sec id="results"><title>Results</title>'
        "<p>Repeated   text Ａ.</p><p>Repeated text A.</p>"
        "</sec></body></article>"
        "</metadata></record></GetRecord></OAI-PMH>"
    ).encode("utf-8")


class NetworkProbeTransport:
    """Live-disclosure probe that must never receive a blocked PMC request."""

    network_used = True
    inherits_proxy_environment = False
    scientific_evidence = False
    external_validation = "UNTESTED"

    def __init__(self) -> None:
        self.calls = 0

    def send(
        self,
        request: object,
        *,
        credential: str | None,
    ) -> TransportResponse:
        del request, credential
        self.calls += 1
        raise AssertionError("blocked PMC route reached transport")


class ScholarlyGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.registry = ArtifactRegistry(self.root)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _openalex_gateway(
        self,
        body: bytes,
        url: str,
        *,
        status: int = 200,
        content_type: str = "application/json",
        policy=None,
    ) -> tuple[SourceOwnedScholarlyGateway, FixtureTransport]:
        transport = FixtureTransport(
            (
                TransportResponse(
                    status,
                    (("Content-Type", content_type),),
                    body,
                    url,
                ),
            )
        )
        egress = EgressGateway(
            policy
            or openalex_scholarly_egress_policy(
                maximum_attempts=1,
                minimum_interval_seconds=0.0,
            ),
            transport,
            registry=self.registry,
            sleeper=lambda _delay: None,
            timestamp=lambda: "2026-09-04T12:00:00.000000Z",
        )
        return SourceOwnedScholarlyGateway(openalex_gateway=egress), transport

    def _pmc_gateway(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/xml",
    ) -> tuple[SourceOwnedScholarlyGateway, FixtureTransport]:
        transport = FixtureTransport(
            (
                TransportResponse(
                    status,
                    (("Content-Type", content_type),),
                    body,
                    PMC_URL,
                ),
            )
        )
        egress = EgressGateway(
            pmc_scholarly_egress_policy(maximum_attempts=1),
            transport,
            registry=self.registry,
            sleeper=lambda _delay: None,
            timestamp=lambda: "2026-09-04T12:00:00.000000Z",
        )
        return SourceOwnedScholarlyGateway(pmc_gateway=egress), transport

    def _search_plan(
        self,
        *,
        max_results: int = 2,
        filters: tuple[ScholarlySearchFilter, ...] | None = None,
    ) -> ScholarlySearchPlan:
        return ScholarlySearchPlan(
            purpose=ScholarlySearchPurpose.SEED,
            goal_id="scholarly-gateway-test",
            goal_sha256=digest("goal"),
            target_sha256=digest("target"),
            query="quantum gravity",
            synonyms=("loop gravity",),
            filters=(
                filters
                if filters is not None
                else (
                    ScholarlySearchFilter("publication_year", "2020-2024"),
                    ScholarlySearchFilter("open_access", "true"),
                )
            ),
            allowed_sources=(ScholarlySource.OPENALEX,),
            max_results=max_results,
            parent_artifact_hashes=(digest("search-parent"),),
        )

    def test_closed_descriptors_and_route_authority_retain_official_contract(self) -> None:
        routes = supported_scholarly_routes()
        self.assertEqual([value.source for value in routes], [ScholarlySource.OPENALEX, ScholarlySource.PMC])
        gateway, _ = self._openalex_gateway(
            openalex_list([], per_page=2, page=1),
            OPENALEX_SEARCH_URL,
        )
        authority = gateway.route_authority_artifact(ScholarlySource.OPENALEX)
        self.assertIsNotNone(authority)
        assert authority is not None
        value = json.loads(self.registry.get_bytes(authority.sha256))
        self.assertEqual(value["schema_version"], SCHOLARLY_EGRESS_ROUTE_AUTHORITY_SCHEMA_V2)
        self.assertEqual(value["source"], "openalex")
        self.assertEqual(value["credential_mode"], "NONE")
        self.assertFalse(value["scientific_evidence"])
        self.assertEqual(value["documentation_urls"], list(OPENALEX_API_DOCUMENTATION_URLS))
        self.assertEqual(value["documentation_verified_on"], "2026-09-04")
        self.assertIn("resource_policy_sha256", value)

    def test_openalex_search_uses_exact_native_get_and_existing_normalizer(self) -> None:
        body = openalex_list(
            [openalex_work("W222222222", title="Search hit")],
            per_page=2,
            page=1,
        )
        gateway, transport = self._openalex_gateway(body, OPENALEX_SEARCH_URL)
        plan = self._search_plan()
        result = execute_scholarly_search(
            plan,
            gateway,
            source=ScholarlySource.OPENALEX,
            plan_artifact_hash=digest("plan-artifact"),
        )
        self.assertEqual(result.status, RetrievalStatus.AVAILABLE)
        self.assertEqual(result.hits[0].identifier.value, "W222222222")
        prepared = transport.prepared_requests[0]
        self.assertEqual(prepared.method, "GET")
        self.assertEqual(prepared.url, OPENALEX_SEARCH_URL)
        self.assertEqual(prepared.body, b"")
        self.assertFalse(transport.credential_present[0])

    def test_openalex_singleton_projects_metadata_and_never_follows_response_urls(self) -> None:
        body = canonical_json_bytes(openalex_work())
        gateway, transport = self._openalex_gateway(body, OPENALEX_WORK_URL)
        identifier = ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789")
        request = OpenAlexAdapter().build_request(identifier)
        captured = gateway.fetch(request)
        envelope = GatewayEnvelope(
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
        record = OpenAlexAdapter().normalize(envelope)
        self.assertEqual(record.source_record_id, "W123456789")
        self.assertEqual(record.abstract, "Bounded abstract")
        self.assertEqual(record.venue, "Bounded Journal")
        self.assertEqual(len(transport.prepared_requests), 1)
        self.assertEqual(transport.prepared_requests[0].url, OPENALEX_WORK_URL)
        self.assertNotIn("attacker.invalid", json.dumps(captured.payload_dict))

    def test_openalex_graph_directions_are_source_owned_and_page_normalizes(self) -> None:
        for traversal, operation, relation in (
            (CitationTraversal.REFERENCES, "expand_references", "cited_by"),
            (CitationTraversal.CITED_BY, "expand_citations", "cites"),
        ):
            with self.subTest(traversal=traversal.value):
                request = CitationPageRequest(
                    plan_sha256=digest(f"plan:{traversal.value}"),
                    task_id=digest(f"task:{traversal.value}"),
                    source=ScholarlySource.OPENALEX,
                    operation=operation,
                    identifier=ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789"),
                    traversal=traversal,
                    origin_node_id=f"citation-node:{digest('origin')}",
                    depth=1,
                    page_number=1,
                    cursor=None,
                )
                expected_url = (
                    "https://api.openalex.org/works?filter="
                    f"{relation}%3AW123456789&per_page=100&cursor=%2A"
                )
                gateway, transport = self._openalex_gateway(
                    openalex_list(
                        [openalex_work("W333333333", title="Graph neighbor")],
                        per_page=100,
                        next_cursor="cursor-next",
                    ),
                    expected_url,
                )
                captured = gateway.fetch(request)
                envelope = GatewayEnvelope(
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
                page = normalize_citation_expansion_page(request, envelope)
                self.assertEqual(page.status, RetrievalStatus.AVAILABLE)
                self.assertEqual(page.next_cursor, "cursor-next")
                self.assertEqual(len(page.nodes), 1)
                self.assertEqual(transport.prepared_requests[0].url, expected_url)

    def test_openalex_graph_requires_explicit_cursor_state(self) -> None:
        request = CitationPageRequest(
            plan_sha256=digest("plan:missing-cursor"),
            task_id=digest("task:missing-cursor"),
            source=ScholarlySource.OPENALEX,
            operation="expand_references",
            identifier=ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789"),
            traversal=CitationTraversal.REFERENCES,
            origin_node_id=f"citation-node:{digest('origin')}",
            depth=1,
            page_number=1,
            cursor=None,
        )
        expected_url = (
            "https://api.openalex.org/works?filter="
            "cited_by%3AW123456789&per_page=100&cursor=%2A"
        )
        body = canonical_json_bytes(
            {
                "meta": {"count": 0, "per_page": 100, "cost_usd": 0.0},
                "results": [],
                "group_by": [],
            }
        )
        gateway, transport = self._openalex_gateway(body, expected_url)
        captured = gateway.fetch(request)
        self.assertEqual(captured.status, RetrievalStatus.MALFORMED)
        self.assertEqual(
            captured.failure_code,
            ScholarlyGatewayFailureCode.MALFORMED_RESPONSE,
        )
        self.assertEqual(len(transport.prepared_requests), 1)

    def test_pmc_oai_jats_full_text_binds_license_and_normalized_coordinates(self) -> None:
        gateway, transport = self._pmc_gateway(pmc_xml())
        identifier = ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567")
        request = PMCAdapter().build_request(identifier)
        captured = gateway.fetch(request)
        self.assertEqual(captured.status, RetrievalStatus.AVAILABLE)
        self.assertEqual(captured.full_text_status, FullTextStatus.AVAILABLE)
        self.assertEqual(captured.license, "https://creativecommons.org/licenses/by/4.0/")
        payload = captured.payload_dict
        assert payload is not None
        projection = payload["full_text_projection"]
        passages = payload["passages"]
        self.assertFalse(projection["offsets_reference_raw_xml"])
        self.assertEqual(projection["source_raw_artifact_sha256"], captured.raw_artifact_hash)
        self.assertEqual(passages[0]["text"], "Repeated text A.")
        self.assertEqual(passages[1]["text"], "Repeated text A.")
        self.assertEqual(passages[0]["start_char"], 0)
        self.assertEqual(passages[1]["start_char"], len("Repeated text A.") + 2)
        reconstructed = "\n\n".join(value["text"] for value in passages)
        self.assertEqual(
            projection["normalized_text_sha256"],
            hashlib.sha256(reconstructed.encode("utf-8")).hexdigest(),
        )
        self.assertIn("give-appropriate-credit", payload["license_decision"]["obligations"])
        envelope = GatewayEnvelope(
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
        record = PMCAdapter().normalize(envelope)
        self.assertEqual(record.source_record_id, "PMC1234567")
        self.assertEqual(record.authors, ("Marie Curie",))
        self.assertEqual(record.passages[0].source_artifact_hash, captured.raw_artifact_hash)
        self.assertEqual(transport.prepared_requests[0].url, PMC_URL)
        self.assertFalse(transport.credential_present[0])

    def test_pmc_accepts_one_undated_direct_ali_license_reference(self) -> None:
        ali_xml = pmc_xml().replace(
            (
                b'<license license-type="open-access" '
                b'xlink:href="https://creativecommons.org/licenses/by/4.0/">'
            ),
            (
                b'<license license-type="open-access">'
                b'<ali:license_ref '
                b'xmlns:ali="http://www.niso.org/schemas/ali/1.0/">'
                b"https://creativecommons.org/licenses/by/4.0/"
                b"</ali:license_ref>"
            ),
            1,
        )
        gateway, _ = self._pmc_gateway(ali_xml)
        captured = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.PMC,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            )
        )
        self.assertEqual(captured.status, RetrievalStatus.AVAILABLE)
        self.assertEqual(
            captured.license,
            "https://creativecommons.org/licenses/by/4.0/",
        )

        dated_xml = ali_xml.replace(
            b'xmlns:ali="http://www.niso.org/schemas/ali/1.0/">',
            (
                b'xmlns:ali="http://www.niso.org/schemas/ali/1.0/" '
                b'start_date="2026-01-01">'
            ),
            1,
        )
        gateway, _ = self._pmc_gateway(dated_xml)
        restricted = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.PMC,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            )
        )
        self.assertEqual(restricted.status, RetrievalStatus.LICENSE_RESTRICTED)

    def test_pmc_unknown_nc_and_conflicting_licenses_fail_closed(self) -> None:
        fixtures = (
            (None, None),
            ("https://creativecommons.org/licenses/by-nc/4.0/", None),
            (
                "https://creativecommons.org/licenses/by/4.0/",
                "https://publisher.invalid/custom-terms",
            ),
        )
        for license_uri, extra in fixtures:
            with self.subTest(license_uri=license_uri, extra=extra):
                gateway, transport = self._pmc_gateway(
                    pmc_xml(license_uri=license_uri, extra_license_uri=extra)
                )
                captured = gateway.fetch(
                    ScholarlyRequest(
                        ScholarlySource.PMC,
                        "resolve_work",
                        ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
                    )
                )
                self.assertEqual(captured.status, RetrievalStatus.LICENSE_RESTRICTED)
                self.assertEqual(
                    captured.failure_code,
                    ScholarlyGatewayFailureCode.LICENSE_RESTRICTED,
                )
                self.assertEqual(captured.full_text_status, FullTextStatus.LICENSE_RESTRICTED)
                self.assertIsNone(captured.payload)
                self.assertEqual(len(transport.prepared_requests), 1)

    def test_pmc_collects_all_direct_machine_license_markers(self) -> None:
        for restriction in ("by-nc", "by-nd"):
            with self.subTest(restriction=restriction):
                conflicting = pmc_xml().replace(
                    b"<license-p>License text.</license-p>",
                    (
                        b"<license-p><ext-link xlink:href=\"https://"
                        b"creativecommons.org/licenses/"
                        + restriction.encode("ascii")
                        + b"/4.0/\">conflicting machine marker"
                        b"</ext-link></license-p>"
                    ),
                    1,
                )
                gateway, _ = self._pmc_gateway(conflicting)
                restricted = gateway.fetch(
                    ScholarlyRequest(
                        ScholarlySource.PMC,
                        "resolve_work",
                        ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
                    )
                )
                self.assertEqual(
                    restricted.status,
                    RetrievalStatus.LICENSE_RESTRICTED,
                )

        ext_link_only = pmc_xml(license_uri=None).replace(
            b"<permissions></permissions>",
            (
                b"<permissions><license><license-p><ext-link "
                b'xlink:href="https://creativecommons.org/licenses/by/4.0/">'
                b"CC BY</ext-link></license-p></license></permissions>"
            ),
            1,
        )
        gateway, _ = self._pmc_gateway(ext_link_only)
        available = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.PMC,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            )
        )
        self.assertEqual(available.status, RetrievalStatus.AVAILABLE)
        self.assertEqual(
            available.license,
            "https://creativecommons.org/licenses/by/4.0/",
        )

    def test_pmc_dual_href_license_markers_must_agree(self) -> None:
        direct_conflict = pmc_xml().replace(
            b'xlink:href="https://creativecommons.org/licenses/by/4.0/"',
            (
                b'xlink:href="https://creativecommons.org/licenses/by/4.0/" '
                b'href="https://creativecommons.org/licenses/by-nc/4.0/"'
            ),
            1,
        )
        ext_link_conflict = pmc_xml().replace(
            b"<license-p>License text.</license-p>",
            (
                b"<license-p><ext-link "
                b'xlink:href="https://creativecommons.org/licenses/by/4.0/" '
                b'href="https://creativecommons.org/licenses/by-nd/4.0/">'
                b"conflicting marker</ext-link></license-p>"
            ),
            1,
        )
        for body in (direct_conflict, ext_link_conflict):
            with self.subTest(body_sha256=hashlib.sha256(body).hexdigest()):
                gateway, _ = self._pmc_gateway(body)
                captured = gateway.fetch(
                    ScholarlyRequest(
                        ScholarlySource.PMC,
                        "resolve_work",
                        ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
                    )
                )
                self.assertEqual(
                    captured.status,
                    RetrievalStatus.LICENSE_RESTRICTED,
                )

        identical = pmc_xml().replace(
            b'xlink:href="https://creativecommons.org/licenses/by/4.0/"',
            (
                b'xlink:href="https://creativecommons.org/licenses/by/4.0/" '
                b'href="https://creativecommons.org/licenses/by/4.0/"'
            ),
            1,
        )
        gateway, _ = self._pmc_gateway(identical)
        captured = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.PMC,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            )
        )
        self.assertEqual(captured.status, RetrievalStatus.AVAILABLE)

    def test_pmc_oai_namespace_echo_and_error_scope_are_exact(self) -> None:
        fixtures = (
            pmc_xml().replace(
                b'xmlns="http://www.openarchives.org/OAI/2.0/" ',
                b"",
                1,
            ),
            pmc_xml().replace(b'<request verb="GetRecord"', b'<request verb="ListRecords"', 1),
            pmc_xml().replace(
                b'<article xmlns=""',
                b'<article xmlns="http://www.openarchives.org/OAI/2.0/"',
                1,
            ),
        )
        for body in fixtures:
            with self.subTest(body_sha256=hashlib.sha256(body).hexdigest()):
                gateway, _ = self._pmc_gateway(body)
                captured = gateway.fetch(
                    ScholarlyRequest(
                        ScholarlySource.PMC,
                        "resolve_work",
                        ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
                    )
                )
                self.assertEqual(captured.status, RetrievalStatus.MALFORMED)

        nested_error = pmc_xml().replace(
            b"<body>",
            b'<body><error code="idDoesNotExist">nested prose</error>',
            1,
        )
        gateway, _ = self._pmc_gateway(nested_error)
        captured = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.PMC,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            )
        )
        self.assertEqual(captured.status, RetrievalStatus.AVAILABLE)

    def test_pmc_xml_declaration_and_oai_response_date_are_canonical(self) -> None:
        invalid = (
            pmc_xml().replace(
                b'<?xml version="1.0" encoding="UTF-8"?>',
                b"",
                1,
            ),
            pmc_xml().replace(b'encoding="UTF-8"', b'encoding="ISO-8859-1"', 1),
            pmc_xml().replace(b'version="1.0"', b'version="1.1"', 1),
            pmc_xml().replace(
                b'encoding="UTF-8"?>',
                b'encoding="UTF-8" standalone="yes"?>',
                1,
            ),
            pmc_xml().replace(
                b"2026-09-04T00:00:00Z",
                b"2026-09-04 00:00:00Z",
                1,
            ),
            pmc_xml().replace(
                b"2026-09-04T00:00:00Z",
                b"2026-09-04T00:00:00+00:00",
                1,
            ),
            pmc_xml().replace(
                b"2026-09-04T00:00:00Z",
                b"2026-09-04T00:00:00z",
                1,
            ),
            pmc_xml().replace(
                b"2026-09-04T00:00:00Z",
                b"2026-09-04",
                1,
            ),
            pmc_xml().replace(
                b"2026-09-04T00:00:00Z",
                b"2026-09-04T00:00:00.1Z",
                1,
            ),
            pmc_xml().replace(
                b"2026-09-04T00:00:00Z",
                b" 2026-09-04T00:00:00Z ",
                1,
            ),
            pmc_xml().replace(
                b"2026-09-04T00:00:00Z",
                b"2026-02-29T00:00:00Z",
                1,
            ),
        )
        for body in invalid:
            with self.subTest(body_sha256=hashlib.sha256(body).hexdigest()):
                gateway, _ = self._pmc_gateway(body)
                captured = gateway.fetch(
                    ScholarlyRequest(
                        ScholarlySource.PMC,
                        "resolve_work",
                        ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
                    )
                )
                self.assertEqual(captured.status, RetrievalStatus.MALFORMED)

        leap_date = pmc_xml().replace(
            b"2026-09-04T00:00:00Z",
            b"2024-02-29T23:59:59Z",
            1,
        )
        gateway, _ = self._pmc_gateway(leap_date)
        captured = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.PMC,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            )
        )
        self.assertEqual(captured.status, RetrievalStatus.AVAILABLE)

    def test_pmc_nested_component_cannot_supply_primary_license_or_metadata(self) -> None:
        nested_license = pmc_xml(license_uri=None).replace(
            b"<body>",
            (
                b"<sub-article><front><article-meta><permissions>"
                b'<license xmlns:xlink="http://www.w3.org/1999/xlink" '
                b'xlink:href="https://creativecommons.org/licenses/by/4.0/">'
                b"<license-p>Nested only.</license-p></license>"
                b"</permissions></article-meta></front></sub-article><body>"
            ),
            1,
        )
        gateway, _ = self._pmc_gateway(nested_license)
        restricted = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.PMC,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            )
        )
        self.assertEqual(restricted.status, RetrievalStatus.LICENSE_RESTRICTED)
        self.assertEqual(
            restricted.failure_code,
            ScholarlyGatewayFailureCode.LICENSE_RESTRICTED,
        )

        missing_primary = pmc_xml().replace(
            b'<article-id pub-id-type="pmc">PMC1234567</article-id>',
            b"",
            1,
        ).replace(
            b"<title-group><article-title>Reusable fixture article</article-title></title-group>",
            b"",
            1,
        ).replace(
            b"<body>",
            (
                b"<sub-article><front><article-meta>"
                b'<article-id pub-id-type="pmc">PMC1234567</article-id>'
                b"<title-group><article-title>Nested misleading title</article-title>"
                b"</title-group></article-meta></front></sub-article>"
                b"<ref-list><ref><element-citation>"
                b"<article-title>Reference misleading title</article-title>"
                b"</element-citation></ref></ref-list><body>"
            ),
            1,
        )
        gateway, _ = self._pmc_gateway(missing_primary)
        malformed = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.PMC,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            )
        )
        self.assertEqual(malformed.status, RetrievalStatus.MALFORMED)
        self.assertEqual(
            malformed.failure_code,
            ScholarlyGatewayFailureCode.MALFORMED_RESPONSE,
        )

    def test_unsupported_routes_filters_limits_and_identifiers_do_not_egress(self) -> None:
        gateway, transport = self._openalex_gateway(
            openalex_list([], per_page=2, page=1),
            OPENALEX_SEARCH_URL,
        )
        unsupported_source = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.SEMANTIC_SCHOLAR,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.SEMANTIC_SCHOLAR, "paper-123"),
            )
        )
        wrong_identifier = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.OPENALEX,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.DOI, "10.5555/not-a-path"),
            )
        )
        unsupported_filter = gateway.fetch(
            ScholarlySearchRequest.from_plan(
                self._search_plan(
                    filters=(ScholarlySearchFilter("fixture_mode", "system_fixture"),)
                ),
                ScholarlySource.OPENALEX,
            )
        )
        unknown_work_type = gateway.fetch(
            ScholarlySearchRequest.from_plan(
                self._search_plan(
                    filters=(ScholarlySearchFilter("type", "invented-type"),)
                ),
                ScholarlySource.OPENALEX,
            )
        )
        invalid_date = gateway.fetch(
            ScholarlySearchRequest.from_plan(
                self._search_plan(
                    filters=(
                        ScholarlySearchFilter(
                            "from_publication_date",
                            "2025-02-30",
                        ),
                    )
                ),
                ScholarlySource.OPENALEX,
            )
        )
        reversed_years = gateway.fetch(
            ScholarlySearchRequest.from_plan(
                self._search_plan(
                    filters=(ScholarlySearchFilter("publication_year", "2025-2020"),)
                ),
                ScholarlySource.OPENALEX,
            )
        )
        oversized = gateway.fetch(
            ScholarlySearchRequest.from_plan(
                self._search_plan(max_results=101),
                ScholarlySource.OPENALEX,
            )
        )
        self.assertEqual(
            unsupported_source.failure_code,
            ScholarlyGatewayFailureCode.SOURCE_UNSUPPORTED,
        )
        self.assertEqual(
            wrong_identifier.failure_code,
            ScholarlyGatewayFailureCode.IDENTIFIER_KIND_UNSUPPORTED,
        )
        self.assertEqual(
            unsupported_filter.failure_code,
            ScholarlyGatewayFailureCode.FILTER_UNSUPPORTED,
        )
        self.assertEqual(
            unknown_work_type.failure_code,
            ScholarlyGatewayFailureCode.FILTER_UNSUPPORTED,
        )
        self.assertEqual(
            invalid_date.failure_code,
            ScholarlyGatewayFailureCode.FILTER_UNSUPPORTED,
        )
        self.assertEqual(
            reversed_years.failure_code,
            ScholarlyGatewayFailureCode.FILTER_UNSUPPORTED,
        )
        self.assertEqual(
            oversized.failure_code,
            ScholarlyGatewayFailureCode.RESULT_LIMIT_UNSUPPORTED,
        )
        self.assertEqual(transport.prepared_requests, [])

    def test_http_unavailability_is_typed_and_captured(self) -> None:
        for status, retrieval, code in (
            (401, RetrievalStatus.UNAVAILABLE, ScholarlyGatewayFailureCode.AUTHENTICATION_REQUIRED),
            (403, RetrievalStatus.UNAVAILABLE, ScholarlyGatewayFailureCode.AUTHENTICATION_REQUIRED),
            (404, RetrievalStatus.NOT_FOUND, ScholarlyGatewayFailureCode.NOT_FOUND),
            (429, RetrievalStatus.RATE_LIMITED, ScholarlyGatewayFailureCode.RATE_LIMITED),
            (503, RetrievalStatus.UNAVAILABLE, ScholarlyGatewayFailureCode.HTTP_UNAVAILABLE),
        ):
            with self.subTest(status=status):
                gateway, _ = self._openalex_gateway(
                    b"{}",
                    OPENALEX_WORK_URL,
                    status=status,
                )
                captured = gateway.fetch(
                    ScholarlyRequest(
                        ScholarlySource.OPENALEX,
                        "resolve_work",
                        ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789"),
                    )
                )
                self.assertEqual(captured.status, retrieval)
                self.assertEqual(captured.failure_code, code)
                self.assertIsNotNone(captured.raw_artifact_hash)
                self.assertIsNotNone(captured.response_artifact_hash)
                self.assertFalse(captured.scientific_evidence)

    def test_malformed_cross_bound_json_and_hostile_xml_are_captured_not_promoted(self) -> None:
        wrong_body = canonical_json_bytes(openalex_work("W999999999"))
        gateway, _ = self._openalex_gateway(wrong_body, OPENALEX_WORK_URL)
        wrong = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.OPENALEX,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789"),
            )
        )
        self.assertEqual(wrong.status, RetrievalStatus.MALFORMED)
        self.assertEqual(wrong.failure_code, ScholarlyGatewayFailureCode.MALFORMED_RESPONSE)

        hostile = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><OAI-PMH>&y;</OAI-PMH>'
        pmc_gateway, _ = self._pmc_gateway(hostile)
        malformed = pmc_gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.PMC,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            )
        )
        self.assertEqual(malformed.status, RetrievalStatus.MALFORMED)
        self.assertEqual(
            malformed.failure_code,
            ScholarlyGatewayFailureCode.MALFORMED_RESPONSE,
        )

        utf16 = pmc_xml().decode("utf-8").replace(
            'encoding="UTF-8"',
            'encoding="UTF-16"',
            1,
        ).encode("utf-16")
        pmc_gateway, _ = self._pmc_gateway(utf16)
        malformed = pmc_gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.PMC,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            )
        )
        self.assertEqual(malformed.status, RetrievalStatus.MALFORMED)
        self.assertEqual(
            malformed.failure_code,
            ScholarlyGatewayFailureCode.MALFORMED_RESPONSE,
        )

    def test_normalized_response_has_exact_raw_receipt_route_ancestry(self) -> None:
        gateway, _ = self._openalex_gateway(
            canonical_json_bytes(openalex_work()),
            OPENALEX_WORK_URL,
        )
        captured = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.OPENALEX,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789"),
            )
        )
        self.assertEqual(captured.status, RetrievalStatus.AVAILABLE)
        assert captured.response_artifact_hash is not None
        metadata = self.registry.get_metadata(captured.response_artifact_hash)
        self.assertEqual(metadata.logical_type, "scholarly_response")
        self.assertEqual(
            set(metadata.parent_artifacts),
            {
                captured.route_authority_artifact_hash,
                captured.raw_artifact_hash,
                json.loads(self.registry.get_bytes(captured.response_artifact_hash))[
                    "response_receipt_artifact_hash"
                ],
            },
        )
        value = json.loads(self.registry.get_bytes(captured.response_artifact_hash))
        self.assertEqual(value["schema_version"], SCHOLARLY_NATIVE_RESPONSE_SCHEMA_V2)
        self.assertFalse(value["scientific_evidence"])
        self.assertFalse(value["network_used"])
        self.assertEqual(value["external_validation"], "UNTESTED")
        self.assertEqual(value["transport_authority"], UNVERIFIED_TRANSPORT_AUTHORITY)

    def test_native_v2_owner_replays_openalex_exact_get_receipt_and_parser(self) -> None:
        gateway, _ = self._openalex_gateway(
            canonical_json_bytes(openalex_work()),
            OPENALEX_WORK_URL,
        )
        request = ScholarlyRequest(
            ScholarlySource.OPENALEX,
            "resolve_work",
            ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789"),
        )
        captured = gateway.fetch(request)
        assert captured.raw_artifact_hash is not None
        assert captured.response_artifact_hash is not None

        replayed = require_available_scholarly_native_capture(
            self.registry,
            request=request,
            raw_artifact_sha256=captured.raw_artifact_hash,
            response_artifact_sha256=captured.response_artifact_hash,
        )

        self.assertIsInstance(replayed, ReplayedScholarlyNativeCapture)
        self.assertEqual(replayed.envelope.request_id, request.request_id)
        self.assertEqual(replayed.envelope.status, RetrievalStatus.AVAILABLE)
        self.assertEqual(replayed.envelope.payload["id"], "W123456789")
        self.assertEqual(replayed.raw_artifact_hash, captured.raw_artifact_hash)
        self.assertEqual(
            replayed.response_artifact_hash,
            captured.response_artifact_hash,
        )
        self.assertEqual(replayed.request_body_sha256, hashlib.sha256(b"").hexdigest())
        self.assertEqual(replayed.request_body_size, 0)
        self.assertEqual(replayed.response_body_sha256, captured.raw_artifact_hash)
        self.assertFalse(replayed.network_used)
        self.assertEqual(replayed.external_validation, "UNTESTED")
        self.assertEqual(
            replayed.transport_authority,
            UNVERIFIED_TRANSPORT_AUTHORITY,
        )
        self.assertEqual(len(replayed.artifact_hashes), 5)
        for artifact_hash in replayed.artifact_hashes:
            self.registry.verify(artifact_hash, raise_on_error=True)

    def test_native_v2_owner_replays_pmc_projection_and_license(self) -> None:
        gateway, _ = self._pmc_gateway(pmc_xml())
        request = ScholarlyRequest(
            ScholarlySource.PMC,
            "resolve_work",
            ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
        )
        captured = gateway.fetch(request)
        assert captured.raw_artifact_hash is not None
        assert captured.response_artifact_hash is not None

        replayed = require_available_scholarly_native_capture(
            self.registry,
            request=request,
            raw_artifact_sha256=captured.raw_artifact_hash,
            response_artifact_sha256=captured.response_artifact_hash,
        )

        self.assertEqual(replayed.envelope.full_text_status, FullTextStatus.AVAILABLE)
        self.assertEqual(
            replayed.envelope.license,
            "https://creativecommons.org/licenses/by/4.0/",
        )
        projection = replayed.envelope.payload["full_text_projection"]
        self.assertEqual(
            projection["source_raw_artifact_sha256"],
            captured.raw_artifact_hash,
        )
        self.assertFalse(projection["offsets_reference_raw_xml"])

    def test_native_v2_owner_rejects_splices_and_normalized_payload_forgery(self) -> None:
        gateway, _ = self._openalex_gateway(
            canonical_json_bytes(openalex_work()),
            OPENALEX_WORK_URL,
        )
        request = ScholarlyRequest(
            ScholarlySource.OPENALEX,
            "resolve_work",
            ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789"),
        )
        captured = gateway.fetch(request)
        assert captured.raw_artifact_hash is not None
        assert captured.response_artifact_hash is not None

        wrong_request = ScholarlyRequest(
            ScholarlySource.OPENALEX,
            "resolve_work",
            ScholarlyIdentifier(IdentifierKind.OPENALEX, "W999999999"),
        )
        with self.assertRaises(ScholarlyGatewayError):
            require_available_scholarly_native_capture(
                self.registry,
                request=wrong_request,
                raw_artifact_sha256=captured.raw_artifact_hash,
                response_artifact_sha256=captured.response_artifact_hash,
            )

        normalized = json.loads(
            self.registry.get_bytes(captured.response_artifact_hash)
        )
        normalized["payload"]["title"] = "forged normalized title"
        original_metadata = self.registry.get_metadata(
            captured.response_artifact_hash
        )
        forged = self.registry.put_json(
            normalized,
            logical_type=original_metadata.logical_type,
            origin=original_metadata.origin,
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=original_metadata.parent_artifacts,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(
            ScholarlyGatewayError,
            "differs from parser replay",
        ):
            require_available_scholarly_native_capture(
                self.registry,
                request=request,
                raw_artifact_sha256=captured.raw_artifact_hash,
                response_artifact_sha256=forged.sha256,
            )

    def test_native_v2_owner_never_upgrades_adjacent_legacy_v1_response(self) -> None:
        gateway, _ = self._openalex_gateway(
            canonical_json_bytes(openalex_work()),
            OPENALEX_WORK_URL,
        )
        request = ScholarlyRequest(
            ScholarlySource.OPENALEX,
            "resolve_work",
            ScholarlyIdentifier(IdentifierKind.OPENALEX, "W123456789"),
        )
        captured = gateway.fetch(request)
        assert captured.raw_artifact_hash is not None
        assert captured.response_artifact_hash is not None
        native = json.loads(self.registry.get_bytes(captured.response_artifact_hash))
        receipt_hash = native["response_receipt_artifact_hash"]
        legacy = {
            "external_validation": native["external_validation"],
            "full_text_status": FullTextStatus.METADATA_ONLY.value,
            "license": None,
            "network_used": native["network_used"],
            "payload": native["payload"],
            "raw_artifact_hash": captured.raw_artifact_hash,
            "response_receipt_artifact_hash": receipt_hash,
            "retrieval_status": RetrievalStatus.AVAILABLE.value,
            "schema_version": "scholarly-response/v2",
            "scholarly_request_id": request.request_id,
            "scientific_evidence": False,
            "source": ScholarlySource.OPENALEX.value,
        }
        legacy_artifact = self.registry.put_json(
            legacy,
            logical_type="scholarly_response",
            origin="strictly parsed synthetic scholarly response",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(captured.raw_artifact_hash, receipt_hash),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

        with self.assertRaises(ScholarlyGatewayError):
            require_available_scholarly_native_capture(
                self.registry,
                request=request,
                raw_artifact_sha256=captured.raw_artifact_hash,
                response_artifact_sha256=legacy_artifact.sha256,
            )

        replayed = require_available_scholarly_native_capture(
            self.registry,
            request=request,
            raw_artifact_sha256=captured.raw_artifact_hash,
            response_artifact_sha256=captured.response_artifact_hash,
        )
        self.assertEqual(replayed.response_artifact_hash, captured.response_artifact_hash)

    def test_native_v2_attempt_replay_enforces_each_response_byte_limit(self) -> None:
        body = pmc_xml()
        gateway, _ = self._pmc_gateway(body)
        request = ScholarlyRequest(
            ScholarlySource.PMC,
            "resolve_work",
            ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
        )
        captured = gateway.fetch(request)
        assert captured.response_artifact_hash is not None
        response = json.loads(self.registry.get_bytes(captured.response_artifact_hash))
        receipt = json.loads(
            self.registry.get_bytes(response["response_receipt_artifact_hash"])
        )
        at_limit = pmc_scholarly_egress_policy(
            maximum_attempts=1,
            maximum_response_bytes=len(body),
            maximum_total_bytes=len(body),
        )
        replayed, _, response_bytes, _ = (
            scholarly_gateway_module._require_native_attempts(
                self.registry,
                attempts=receipt["attempts"],
                policy=at_limit,
                request_body_size=0,
            )
        )
        self.assertEqual(len(replayed), 1)
        self.assertEqual(response_bytes, len(body))

        below_limit = replace(at_limit, maximum_response_bytes=len(body) - 1)
        with self.assertRaisesRegex(ScholarlyGatewayError, "byte count"):
            scholarly_gateway_module._require_native_attempts(
                self.registry,
                attempts=receipt["attempts"],
                policy=below_limit,
                request_body_size=0,
            )

        def raw_artifact(value: bytes):
            return self.registry.put_bytes(
                value,
                logical_type="external_response_raw",
                origin="controlled external egress raw response",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "controlled-egress"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/octet-stream",
                validation_result="PASS",
                frozen=True,
            )

        first = raw_artifact(b"busy")
        second = raw_artifact(b"ok")
        retry_attempts = [
            {
                "schema_version": "controlled-egress-attempt/v2",
                "attempt": 1,
                "status": "RESPONSE",
                "status_code": 503,
                "body_sha256": first.sha256,
                "body_size": 4,
                "raw_response_record_sha256": first.sha256,
                "request_body_bytes": 0,
                "response_body_bytes": 4,
                "cumulative_bytes": 4,
                "started_offset_seconds": 0.0,
                "completed_offset_seconds": 0.01,
                "retry_delay_seconds": 0.25,
            },
            {
                "schema_version": "controlled-egress-attempt/v2",
                "attempt": 2,
                "status": "RESPONSE",
                "status_code": 200,
                "body_sha256": second.sha256,
                "body_size": 2,
                "raw_response_record_sha256": second.sha256,
                "request_body_bytes": 0,
                "response_body_bytes": 2,
                "cumulative_bytes": 6,
                "started_offset_seconds": 0.26,
                "completed_offset_seconds": 0.27,
                "retry_delay_seconds": None,
            },
        ]
        retry_policy = openalex_scholarly_egress_policy(
            maximum_attempts=2,
            maximum_response_bytes=4,
            maximum_total_bytes=8,
        )
        scholarly_gateway_module._require_native_attempts(
            self.registry,
            attempts=retry_attempts,
            policy=retry_policy,
            request_body_size=0,
        )
        retry_attempts[0]["response_body_bytes"] = 5
        retry_attempts[0]["cumulative_bytes"] = 5
        retry_attempts[1]["cumulative_bytes"] = 7
        with self.assertRaisesRegex(ScholarlyGatewayError, "byte count"):
            scholarly_gateway_module._require_native_attempts(
                self.registry,
                attempts=retry_attempts,
                policy=retry_policy,
                request_body_size=0,
            )

        partial_failure_attempts = [
            {
                **retry_attempts[0],
                "status": "TRANSPORT_FAILURE",
                "status_code": None,
                "body_sha256": None,
                "body_size": None,
                "raw_response_record_sha256": None,
            },
            dict(retry_attempts[1]),
        ]
        with self.assertRaisesRegex(ScholarlyGatewayError, "byte count"):
            scholarly_gateway_module._require_native_attempts(
                self.registry,
                attempts=partial_failure_attempts,
                policy=retry_policy,
                request_body_size=0,
            )

    def test_policy_substitution_and_pmc_rate_violation_are_rejected(self) -> None:
        response = TransportResponse(
            200,
            (("Content-Type", "application/json"),),
            b"{}",
            OPENALEX_WORK_URL,
        )
        bad_policy = replace(
            openalex_scholarly_egress_policy(maximum_attempts=1),
            allowed_query_keys=("search",),
        )
        egress = EgressGateway(
            bad_policy,
            FixtureTransport((response,)),
            registry=self.registry,
        )
        with self.assertRaises(ScholarlyRouteConfigurationError):
            SourceOwnedScholarlyGateway(openalex_gateway=egress)

        for changed_policy in (
            replace(
                openalex_scholarly_egress_policy(maximum_attempts=1),
                recorded_response_headers=(),
            ),
            replace(
                openalex_scholarly_egress_policy(maximum_attempts=1),
                retry_statuses=(404,),
            ),
            replace(
                openalex_scholarly_egress_policy(maximum_attempts=1),
                maximum_json_depth=1,
            ),
        ):
            egress = EgressGateway(
                changed_policy,
                FixtureTransport((response,)),
                registry=self.registry,
            )
            with self.assertRaises(ScholarlyRouteConfigurationError):
                SourceOwnedScholarlyGateway(openalex_gateway=egress)

        pmc_response = TransportResponse(
            200,
            (("Content-Type", "application/xml"),),
            pmc_xml(),
            PMC_URL,
        )
        fast_pmc = EgressGateway(
            pmc_scholarly_egress_policy(
                minimum_interval_seconds=0.0,
                maximum_attempts=1,
            ),
            FixtureTransport((pmc_response,)),
            registry=self.registry,
        )
        with self.assertRaises(ScholarlyRouteConfigurationError):
            SourceOwnedScholarlyGateway(pmc_gateway=fast_pmc)

    def test_pmc_authority_records_official_license_and_compression_caveat(self) -> None:
        gateway, _ = self._pmc_gateway(pmc_xml())
        authority = gateway.route_authority_artifact(ScholarlySource.PMC)
        assert authority is not None
        value = json.loads(self.registry.get_bytes(authority.sha256))
        self.assertEqual(value["documentation_urls"], list(PMC_OAI_JATS_DOCUMENTATION_URLS))
        self.assertEqual(value["license_policy_id"], "pmc-explicit-reusable-cc-license/v1")
        self.assertEqual(
            value["live_network_dispatch_status"],
            "UNAVAILABLE_TRANSPORT_POLICY_INCOMPATIBLE",
        )
        self.assertEqual(
            value["concurrency_policy"],
            "LIVE_DISPATCH_DISABLED_NO_GLOBAL_SERIALIZATION",
        )
        self.assertTrue(
            any("must be set" in item for item in value["operational_caveats"])
        )
        self.assertTrue(
            any("concurrent requests" in item for item in value["operational_caveats"])
        )
        self.assertGreaterEqual(value["resource_policy"]["minimum_interval_seconds"], 1 / 3)
        self.assertIn("maximum_json_depth", value["resource_policy"])
        self.assertIn("backoff_maximum_seconds", value["resource_policy"])

    def test_live_pmc_route_is_typed_unavailable_before_transport(self) -> None:
        transport = NetworkProbeTransport()
        egress = EgressGateway(
            pmc_scholarly_egress_policy(maximum_attempts=1),
            transport,
            registry=self.registry,
        )
        gateway = SourceOwnedScholarlyGateway(pmc_gateway=egress)
        captured = gateway.fetch(
            ScholarlyRequest(
                ScholarlySource.PMC,
                "resolve_work",
                ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"),
            )
        )
        self.assertEqual(captured.status, RetrievalStatus.UNAVAILABLE)
        self.assertEqual(
            captured.failure_code,
            ScholarlyGatewayFailureCode.TRANSPORT_POLICY_INCOMPATIBLE,
        )
        self.assertEqual(transport.calls, 0)
        self.assertFalse(captured.network_used)
        self.assertIsNotNone(captured.response_artifact_hash)


if __name__ == "__main__":
    unittest.main()
