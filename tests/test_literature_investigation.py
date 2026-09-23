from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import tempfile
import unittest

from scientist_one.artifacts import ArtifactRegistry, MAX_ARTIFACT_PARENTS
from scientist_one.literature import (
    AcquisitionResult,
    CitationEdgeObservation,
    CitationExecutionStatus,
    CitationExpansionExecution,
    CitationExpansionPageReceipt,
    CitationExpansionPlan,
    CitationExpansionPolicy,
    CitationGraph,
    CitationGraphEdge,
    CitationGraphNode,
    CitationPageCursor,
    CitationPageRequest,
    CitationTraversal,
    CitationTruncationReason,
    EvidenceRankingCandidate,
    EvidenceSupportTier,
    FullTextPassage,
    FullTextStatus,
    GeneralWebFallbackPolicy,
    GeneralWebFallbackStatus,
    GeneralWebPurpose,
    GatewayEnvelope,
    IdentifierKind,
    LiteratureError,
    ReferenceVerification,
    RetrievalStatus,
    ScholarlyAttemptReceipt,
    ScholarlyIdentifier,
    ScholarlyRecord,
    ScholarlyRequest,
    ScholarlyRole,
    ScholarlySearchFilter,
    ScholarlySearchHit,
    ScholarlySearchHitResolutionBinding,
    ScholarlySearchPlan,
    ScholarlySearchPurpose,
    ScholarlySearchRequest,
    ScholarlySearchResult,
    ScholarlySearchSelection,
    ScholarlySearchSelectionPolicy,
    ScholarlySearchSummary,
    ScholarlySource,
    VerificationLevel,
    decide_general_web_fallback,
    execute_citation_expansion,
    execute_scholarly_search,
    normalize_citation_expansion_page,
    normalize_scholarly_search_result,
    plan_citation_expansion,
    rank_scholarly_evidence,
    verify_citation_expansion_execution,
)
from scientist_one.scientific_design import (
    InvestigationRound,
    InvestigationRoundKind,
    InvestigationSourceBinding,
    LiteratureRecord,
    ProblemInvestigationState,
    ProblemInvestigationStatus,
    ProblemInvestigator,
    ResearchBrief,
    ResearchDirection,
    ResearchGateOutcome,
    ResearchGoal,
    ResearchQuestionAssessment,
    ResearchQuestionCriteria,
    ScientificDesignError,
    ScientificPromotionError,
    require_research_gate,
)
from scientist_one.roles import Role


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def scholarly_record(index: int, *, full_text: bool = False) -> ScholarlyRecord:
    source = ScholarlySource.OPENALEX
    identifier = ScholarlyIdentifier(IdentifierKind.DOI, f"10.5555/work.{index}")
    request = ScholarlyRequest(source, "resolve_work", identifier)
    raw_hash = digest(f"raw:{index}")
    response_hash = digest(f"response:{index}")
    passages = ()
    roles = (ScholarlyRole.METADATA, ScholarlyRole.CITATION_GRAPH)
    parents = (raw_hash, response_hash)
    status = FullTextStatus.METADATA_ONLY
    if full_text:
        text = f"Full-text passage for work {index}."
        passages = (
            FullTextPassage(
                section_id="results",
                passage_id=f"passage-{index}",
                text=text,
                start_char=0,
                end_char=len(text),
                source_artifact_hash=raw_hash,
                context_before="Before.",
                context_after="After.",
            ),
        )
        roles = roles + (ScholarlyRole.FULL_TEXT,)
        status = FullTextStatus.AVAILABLE
    return ScholarlyRecord(
        source=source,
        source_record_id=f"W{index + 1000}",
        identifiers=(identifier,),
        title=f"Controlled work {index}",
        authors=("Ada Researcher",),
        publication_year=2025,
        venue="Controlled Venue",
        abstract=f"Abstract {index}.",
        roles=roles,
        full_text_status=status,
        passages=passages,
        request_id=request.request_id,
        raw_artifact_hash=raw_hash,
        response_artifact_hash=response_hash,
        parent_artifact_hashes=parents,
        license="fixture-license" if full_text else None,
    )


def acquisition(record: ScholarlyRecord) -> AcquisitionResult:
    request = ScholarlyRequest(
        record.source,
        "resolve_work",
        record.identifiers[0],
    )
    return AcquisitionResult(
        source=record.source,
        status=RetrievalStatus.AVAILABLE,
        request=request,
        record=record,
        failure_reason=None,
        raw_artifact_hash=record.raw_artifact_hash,
        response_artifact_hash=record.response_artifact_hash,
        license=record.license,
    )


def edge(citing: CitationGraphNode, cited: CitationGraphNode, label: str) -> CitationGraphEdge:
    return CitationGraphEdge(
        citing_node_id=citing.node_id,
        cited_node_id=cited.node_id,
        observations=(
            CitationEdgeObservation(
                source=ScholarlySource.OPENALEX,
                request_id=digest(f"request:{label}"),
                evidence_artifact_hash=digest(f"edge-evidence:{label}"),
            ),
        ),
    )


class PaginatedCitationGateway:
    def __init__(self) -> None:
        self.calls: list[object] = []

    def fetch(self, request):
        self.calls.append(request)
        index = request.page_number
        next_cursor = "cursor-page-2" if index == 1 else None
        payload = {
            "works": [
                {
                    "id": f"https://openalex.org/W{2000 + index}",
                    "doi": f"https://doi.org/10.5555/expanded.{index}",
                    "title": f"Expanded work {index}",
                    "authorships": [
                        {"author": {"display_name": "Grace Researcher"}}
                    ],
                    "publication_year": 2024,
                    "abstract": f"Expanded abstract {index}.",
                }
            ],
            "next_cursor": next_cursor,
        }
        return GatewayEnvelope(
            source=request.source,
            request_id=request.request_id,
            status=RetrievalStatus.AVAILABLE,
            payload=payload,
            raw_artifact_hash=digest(f"page-raw:{index}"),
            response_artifact_hash=digest(f"page-response:{index}"),
            license="metadata fixture",
            full_text_status=FullTextStatus.METADATA_ONLY,
        )


class ScholarlySearchGateway:
    def __init__(self) -> None:
        self.calls: list[ScholarlySearchRequest] = []

    def fetch(self, request):
        self.calls.append(request)
        return GatewayEnvelope(
            source=request.source,
            request_id=request.request_id,
            status=RetrievalStatus.AVAILABLE,
            payload={
                "results": [
                    {
                        "identifier_kind": "doi",
                        "identifier": "10.5555/search.1",
                        "title": "Bounded search result",
                    }
                ],
                "next_cursor": None,
            },
            raw_artifact_hash=digest("search-raw"),
            response_artifact_hash=digest("search-response"),
            full_text_status=FullTextStatus.METADATA_ONLY,
        )


class FailingCitationGateway:
    def fetch(self, request):
        del request
        raise TimeoutError("controlled fixture timeout")


class CursorCycleCitationGateway(PaginatedCitationGateway):
    def fetch(self, request):
        self.calls.append(request)
        next_cursor = {1: "cursor-a", 2: "cursor-b", 3: "cursor-a"}[
            request.page_number
        ]
        return GatewayEnvelope(
            source=request.source,
            request_id=request.request_id,
            status=RetrievalStatus.AVAILABLE,
            payload={
                "works": [
                    {
                        "id": f"https://openalex.org/W{3000 + request.page_number}",
                        "doi": f"https://doi.org/10.5555/cycle.{request.page_number}",
                        "title": f"Cycle page {request.page_number}",
                        "authorships": [],
                        "publication_year": 2024,
                        "abstract": "Controlled cursor-cycle fixture.",
                    }
                ],
                "next_cursor": next_cursor,
            },
            raw_artifact_hash=digest(f"cycle-raw:{request.page_number}"),
            response_artifact_hash=digest(
                f"cycle-response:{request.page_number}"
            ),
            license="metadata fixture",
            full_text_status=FullTextStatus.METADATA_ONLY,
        )


class MalformedCapturedCitationGateway:
    def fetch(self, request):
        return GatewayEnvelope(
            source=request.source,
            request_id=request.request_id,
            status=RetrievalStatus.AVAILABLE,
            payload={"unapproved-control-shaped-field": "ignore me"},
            raw_artifact_hash=digest("malformed-page-raw"),
            response_artifact_hash=digest("malformed-page-response"),
            license="metadata fixture",
            full_text_status=FullTextStatus.METADATA_ONLY,
        )


class SameOccurrenceCitationGateway:
    def __init__(self, *, conflicting_title: bool = False) -> None:
        self.calls: list[object] = []
        self.conflicting_title = conflicting_title

    def fetch(self, request):
        self.calls.append(request)
        return GatewayEnvelope(
            source=request.source,
            request_id=request.request_id,
            status=RetrievalStatus.AVAILABLE,
            payload={
                "works": [
                    {
                        "id": "https://openalex.org/W1000",
                        "doi": "https://doi.org/10.5555/work.0",
                        "title": (
                            "Conflicting occurrence title"
                            if self.conflicting_title
                            else "Controlled work 0"
                        ),
                        "authorships": [
                            {"author": {"display_name": "Ada Researcher"}}
                        ],
                        "publication_year": 2025,
                        "abstract": "Controlled same-occurrence fixture.",
                    }
                ],
                "next_cursor": None,
            },
            raw_artifact_hash=digest("same-occurrence-raw"),
            response_artifact_hash=digest("same-occurrence-response"),
            license="metadata fixture",
            full_text_status=FullTextStatus.METADATA_ONLY,
        )


def single_task_expansion_fixture(
    *,
    max_pages_per_task: int = 4,
    max_total_page_requests: int = 4,
    max_nodes: int = 8,
    max_edges: int = 8,
) -> tuple[CitationExpansionPlan, CitationGraph]:
    origin_record = scholarly_record(0)
    plan = plan_citation_expansion(
        (acquisition(origin_record),),
        CitationExpansionPolicy(
            allowed_sources=(ScholarlySource.OPENALEX,),
            traversals=(CitationTraversal.REFERENCES,),
            max_requests=1,
            max_depth=1,
            max_pages_per_task=max_pages_per_task,
            max_total_page_requests=max_total_page_requests,
            max_nodes=max_nodes,
            max_edges=max_edges,
        ),
    )
    return (
        plan,
        CitationGraph(
            nodes=(CitationGraphNode.from_record(origin_record),),
            edges=(),
        ),
    )


def scientific_records() -> tuple[LiteratureRecord, ...]:
    return tuple(
        LiteratureRecord(
            source_id=f"paper-{index}",
            title=f"Prior method {index}",
            stable_locator=f"doi:10.5555/work.{index}",
            full_text_sha256=digest(f"full-text:{index}"),
            methodology_relevance=4,
            problem_alignment=4,
            structured_notes=("Structured methods and evaluation notes.",),
            full_text_reviewed=True,
        )
        for index in range(5)
    )


def investigation_state(
    records: tuple[LiteratureRecord, ...],
    *,
    disconfirming_ids: tuple[str, ...] = ("paper-2",),
    duplicate_last_work: bool = False,
    goal: ResearchGoal | None = None,
) -> ProblemInvestigationState:
    goal = goal or ResearchGoal(
        goal_id="goal-1",
        question="Controlled fixture question?",
        scope="Controlled fixture scope.",
        constraints=("offline",),
        seed_source_ids=("paper-0",),
    )
    bindings = tuple(
        InvestigationSourceBinding(
            source_id=record.source_id,
            literature_record_sha256=record.sha256,
            record_artifact_hash=digest(f"record-artifact:{record.source_id}"),
            citation_node_id="citation-node:" + digest(record.source_id),
            canonical_work_key="citation-work:"
            + digest(
                records[0].stable_locator
                if duplicate_last_work and record is records[-1]
                else record.stable_locator
            ),
        )
        for record in records
    )
    by_id = {value.source_id: value for value in bindings}
    seed = InvestigationRound(
        round_id="round-seed",
        round_number=1,
        kind=InvestigationRoundKind.SEED_SEARCH,
        query="Seed query and controlled synonyms.",
        source_bindings=bindings,
        retained_source_ids=tuple(value.source_id for value in bindings),
        evidence_artifact_hashes=tuple(value.record_artifact_hash for value in bindings)
        + (digest("seed-receipt"),),
        findings=("Seed search completed through scholarly adapters.",),
        previous_round_sha256=None,
    )
    expansion = InvestigationRound(
        round_id="round-citation-expansion",
        round_number=2,
        kind=InvestigationRoundKind.CITATION_EXPANSION,
        query="Execute the bounded citation-expansion plan.",
        source_bindings=bindings,
        retained_source_ids=tuple(value.source_id for value in bindings),
        evidence_artifact_hashes=tuple(value.record_artifact_hash for value in bindings)
        + (digest("expansion-receipt"),),
        findings=("Citation expansion completed through the audited gateway.",),
        previous_round_sha256=seed.sha256,
    )
    filtering = InvestigationRound(
        round_id="round-relevance-filtering",
        round_number=3,
        kind=InvestigationRoundKind.RELEVANCE_FILTERING,
        query="Apply the frozen relevance and source-ranking rubric.",
        source_bindings=bindings,
        retained_source_ids=tuple(value.source_id for value in bindings),
        evidence_artifact_hashes=tuple(value.record_artifact_hash for value in bindings)
        + (digest("filtering-receipt"),),
        findings=("Relevant records were retained with typed ranking evidence.",),
        previous_round_sha256=expansion.sha256,
    )
    review = InvestigationRound(
        round_id="round-full-text",
        round_number=4,
        kind=InvestigationRoundKind.FULL_TEXT_REVIEW,
        query="Read retained works with the frozen relevance rubric.",
        source_bindings=bindings,
        retained_source_ids=tuple(value.source_id for value in bindings),
        evidence_artifact_hashes=tuple(value.record_artifact_hash for value in bindings)
        + (digest("review-receipt"),),
        findings=("Every elite work received structured full-text review.",),
        previous_round_sha256=filtering.sha256,
    )
    disconfirming_bindings = tuple(by_id[value] for value in disconfirming_ids)
    disconfirm = InvestigationRound(
        round_id="round-disconfirm",
        round_number=5,
        kind=InvestigationRoundKind.DISCONFIRMING_SEARCH,
        query="Search explicitly for work that destroys the proposed gap.",
        source_bindings=disconfirming_bindings,
        retained_source_ids=disconfirming_ids,
        evidence_artifact_hashes=tuple(
            value.record_artifact_hash for value in disconfirming_bindings
        )
        + (digest("disconfirming-receipt"),),
        findings=("The disconfirming query completed, including zero-result cases.",),
        previous_round_sha256=review.sha256,
    )
    return ProblemInvestigationState(
        goal_id=goal.goal_id,
        goal_sha256=goal.sha256,
        goal_artifact_hash=digest("research-goal-artifact"),
        status=ProblemInvestigationStatus.READY_FOR_BRIEF,
        rounds=(seed, expansion, filtering, review, disconfirm),
        citation_graph_sha256=digest("citation-graph"),
        citation_graph_artifact_hash=digest("citation-graph-artifact"),
        citation_expansion_plan_sha256=digest("citation-plan"),
        citation_expansion_plan_artifact_hash=digest("citation-plan-artifact"),
        citation_expansion_execution_sha256=digest("citation-execution"),
        citation_expansion_execution_artifact_hash=digest(
            "citation-execution-artifact"
        ),
        evidence_ranking_sha256=digest("evidence-ranking"),
        evidence_ranking_artifact_hash=digest("evidence-ranking-artifact"),
    )


class ScholarlySearchAuthorityTests(unittest.TestCase):
    def search_plan(self, **changes) -> ScholarlySearchPlan:
        values = {
            "purpose": ScholarlySearchPurpose.SEED,
            "goal_id": "goal-search",
            "goal_sha256": digest("goal-search"),
            "target_sha256": digest("target-search"),
            "query": "bounded target-bound seed query",
            "synonyms": ("controlled synonym",),
            "filters": (
                ScholarlySearchFilter("publication_type", "research article"),
            ),
            "allowed_sources": (ScholarlySource.OPENALEX,),
            "max_results": 5,
            "parent_artifact_hashes": (digest("search-goal-artifact"),),
        }
        values.update(changes)
        return ScholarlySearchPlan(**values)

    def test_search_plan_request_and_result_are_exact_round_trip_authorities(self) -> None:
        plan = self.search_plan()
        self.assertEqual(ScholarlySearchPlan.from_dict(plan.to_dict()).sha256, plan.sha256)
        request = ScholarlySearchRequest.from_plan(plan, ScholarlySource.OPENALEX)
        self.assertEqual(
            ScholarlySearchRequest.from_dict(request.to_dict()).request_id,
            request.request_id,
        )
        gateway = ScholarlySearchGateway()
        result = execute_scholarly_search(
            plan,
            gateway,
            source=ScholarlySource.OPENALEX,
            plan_artifact_hash=digest("search-plan-artifact"),
        )
        self.assertIs(result.status, RetrievalStatus.AVAILABLE)
        self.assertFalse(result.scientific_evidence)
        self.assertEqual(result.hits[0].rank, 1)
        self.assertEqual(result.hits[0].identifier.value, "10.5555/search.1")
        self.assertEqual(
            ScholarlySearchResult.from_dict(result.to_dict()).sha256,
            result.sha256,
        )
        self.assertEqual(len(gateway.calls), 1)

    def test_search_types_reject_bool_coercion_and_tampered_payload(self) -> None:
        with self.assertRaisesRegex(LiteratureError, "max_results"):
            self.search_plan(max_results=True)
        plan = self.search_plan()
        request = ScholarlySearchRequest.from_plan(plan, ScholarlySource.OPENALEX)
        envelope = ScholarlySearchGateway().fetch(request)
        malformed = GatewayEnvelope(
            source=envelope.source,
            request_id=envelope.request_id,
            status=envelope.status,
            payload={
                "results": [
                    {
                        "identifier_kind": "doi",
                        "identifier": "10.5555/search.1",
                        "title": "Bounded search result",
                        "retained": True,
                    }
                ],
                "next_cursor": None,
            },
            raw_artifact_hash=envelope.raw_artifact_hash,
            response_artifact_hash=envelope.response_artifact_hash,
        )
        with self.assertRaisesRegex(LiteratureError, "fields are invalid"):
            normalize_scholarly_search_result(
                request,
                malformed,
                plan_artifact_hash=digest("search-plan-artifact"),
            )
        result = execute_scholarly_search(
            plan,
            ScholarlySearchGateway(),
            source=ScholarlySource.OPENALEX,
            plan_artifact_hash=digest("search-plan-artifact"),
        )
        with self.assertRaisesRegex(LiteratureError, "not scientific evidence"):
            replace(result, scientific_evidence=0)
        forged = result.to_dict()
        forged["hits"][0]["title"] = "tampered title"
        with self.assertRaisesRegex(LiteratureError, "identity was tampered"):
            ScholarlySearchResult.from_dict(forged)

    def test_search_plan_parent_fan_in_matches_registry_boundary(self) -> None:
        parents = tuple(
            digest(f"search-parent:{index}") for index in range(MAX_ARTIFACT_PARENTS)
        )
        bounded = self.search_plan(parent_artifact_hashes=parents)
        self.assertEqual(len(bounded.parent_artifact_hashes), MAX_ARTIFACT_PARENTS)
        with self.assertRaisesRegex(LiteratureError, "registry parent bound"):
            self.search_plan(
                parent_artifact_hashes=parents + (digest("search-parent:overflow"),)
            )

    def test_search_selection_accounts_for_hits_and_persists_at_parent_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            parent_records = tuple(
                registry.put_bytes(
                    f"selection parent {index}".encode("utf-8"),
                    logical_type="search_selection_parent_fixture",
                    origin="selection parent boundary fixture",
                    creator_role=Role.PROBLEM_INVESTIGATOR,
                    creation_command=("scientist-one", "test"),
                    parent_artifacts=(),
                    schema_version="1.0",
                    mime_type="application/octet-stream",
                    validation_result="PASS",
                    frozen=True,
                )
                for index in range(MAX_ARTIFACT_PARENTS + 1)
            )
            plan = self.search_plan(max_results=512)
            request = ScholarlySearchRequest.from_plan(plan, ScholarlySource.OPENALEX)

            def selection(hit_count: int) -> ScholarlySearchSelection:
                hits = tuple(
                    ScholarlySearchHit(
                        source=ScholarlySource.OPENALEX,
                        identifier=ScholarlyIdentifier(
                            IdentifierKind.DOI,
                            f"10.5555/selection.{index}",
                        ),
                        title=f"Selection work {index}",
                        rank=index + 1,
                    )
                    for index in range(hit_count)
                )
                result = ScholarlySearchResult(
                    plan_sha256=plan.sha256,
                    plan_artifact_hash=parent_records[0].sha256,
                    request=request,
                    status=RetrievalStatus.AVAILABLE,
                    hits=hits,
                    raw_artifact_hash=digest("selection-raw"),
                    response_artifact_hash=digest("selection-response"),
                )
                return ScholarlySearchSelection(
                    plan_sha256=plan.sha256,
                    plan_artifact_hash=parent_records[0].sha256,
                    result=result,
                    result_artifact_hash=parent_records[1].sha256,
                    policy=ScholarlySearchSelectionPolicy.ALL_CAPTURED_HITS,
                    bindings=tuple(
                        ScholarlySearchHitResolutionBinding(
                            hit_id=hit.hit_id,
                            resolution_request_id=digest(
                                f"selection-resolution:{index}"
                            ),
                            scholarly_record_artifact_hash=parent_records[index + 2].sha256,
                            source_id=f"source-{index}",
                        )
                        for index, hit in enumerate(hits)
                    ),
                    unselected_hit_ids=(),
                )

            bounded = selection(MAX_ARTIFACT_PARENTS - 2)
            self.assertEqual(
                len(bounded.parent_artifact_hashes),
                MAX_ARTIFACT_PARENTS,
            )
            persisted = registry.put_json(
                bounded.to_dict(),
                logical_type="scholarly_search_selection",
                origin="selection parent boundary fixture",
                creator_role=Role.PROBLEM_INVESTIGATOR,
                creation_command=("scientist-one", "test"),
                parent_artifacts=bounded.parent_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertTrue(registry.verify(persisted.sha256))
            with self.assertRaisesRegex(LiteratureError, "registry parent bound"):
                selection(MAX_ARTIFACT_PARENTS - 1)

    def test_search_selection_rejects_omitted_and_unknown_hits(self) -> None:
        plan = self.search_plan()
        result = execute_scholarly_search(
            plan,
            ScholarlySearchGateway(),
            source=ScholarlySource.OPENALEX,
            plan_artifact_hash=digest("search-plan-artifact"),
        )
        binding = ScholarlySearchHitResolutionBinding(
            hit_id=result.hits[0].hit_id,
            resolution_request_id=digest("selection-resolution"),
            scholarly_record_artifact_hash=digest("selection-record"),
            source_id="source-1",
        )
        selection = ScholarlySearchSelection(
            plan_sha256=plan.sha256,
            plan_artifact_hash=digest("search-plan-artifact"),
            result=result,
            result_artifact_hash=digest("search-result-artifact"),
            policy=ScholarlySearchSelectionPolicy.ALL_CAPTURED_HITS,
            bindings=(binding,),
            unselected_hit_ids=(),
        )
        self.assertEqual(
            ScholarlySearchSelection.from_dict(selection.to_dict()).sha256,
            selection.sha256,
        )
        with self.assertRaisesRegex(LiteratureError, "account for every hit"):
            replace(selection, bindings=(), unselected_hit_ids=())
        with self.assertRaisesRegex(LiteratureError, "unknown hit"):
            replace(selection, bindings=(replace(binding, hit_id=digest("unknown-hit")),))


class CitationGraphAndPlanningTests(unittest.TestCase):
    def test_graph_is_immutable_and_flags_cycles_while_rejecting_bad_references(self) -> None:
        nodes = tuple(CitationGraphNode.from_record(scholarly_record(i)) for i in range(3))
        first, second, third = nodes
        graph = CitationGraph(
            nodes=(third, first, second),
            edges=(edge(second, third, "b-c"), edge(first, second, "a-b")),
        )
        restored = CitationGraph.from_dict(graph.to_dict())
        self.assertEqual(restored.canonical_bytes, graph.canonical_bytes)
        self.assertEqual(restored.sha256, graph.sha256)
        self.assertTrue(graph.parent_artifact_hashes)
        with self.assertRaises(FrozenInstanceError):
            graph.nodes = ()  # type: ignore[misc]
        with self.assertRaisesRegex(LiteratureError, "duplicate nodes"):
            CitationGraph(nodes=(first, first), edges=())
        with self.assertRaisesRegex(LiteratureError, "duplicate relationships"):
            CitationGraph(
                nodes=nodes,
                edges=(edge(first, second, "one"), edge(first, second, "two")),
            )
        unknown = CitationGraphNode.from_record(scholarly_record(9))
        with self.assertRaisesRegex(LiteratureError, "unknown node"):
            CitationGraph(nodes=nodes, edges=(edge(first, unknown, "unknown"),))
        cyclic = CitationGraph(
            nodes=nodes,
            edges=(
                edge(first, second, "cycle-a"),
                edge(second, third, "cycle-b"),
                edge(third, first, "cycle-c"),
            ),
        )
        self.assertTrue(cyclic.has_cycles)
        self.assertEqual(set(cyclic.cycle_node_ids), {value.node_id for value in nodes})
        self.assertEqual(CitationGraph.from_dict(cyclic.to_dict()).sha256, cyclic.sha256)

    def test_persisted_graph_provenance_respects_registry_parent_bound(self) -> None:
        paired_records = tuple(
            scholarly_record(index)
            for index in range((MAX_ARTIFACT_PARENTS - 2) // 2)
        )
        singleton_record = scholarly_record(len(paired_records))
        singleton_record = replace(
            singleton_record,
            response_artifact_hash=singleton_record.raw_artifact_hash,
            parent_artifact_hashes=(singleton_record.raw_artifact_hash,),
        )
        allowed = CitationGraph(
            nodes=tuple(
                CitationGraphNode.from_record(value)
                for value in (*paired_records, singleton_record)
            ),
            edges=(),
        )
        self.assertEqual(
            len(allowed.parent_artifact_hashes),
            MAX_ARTIFACT_PARENTS - 1,
        )

        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            for label in (
                *(f"raw:{index}" for index in range(len(paired_records))),
                *(f"response:{index}" for index in range(len(paired_records))),
                f"raw:{len(paired_records)}",
                "execution-authority",
            ):
                parent = registry.put_bytes(
                    label.encode("utf-8"),
                    logical_type="boundary_parent",
                    origin="citation graph registry-boundary fixture",
                    creator_role=Role.EVIDENCE_CURATOR,
                    creation_command=("scientist-one", "boundary-test"),
                    schema_version="1.0",
                    mime_type="application/octet-stream",
                    validation_result="PASS",
                    frozen=True,
                )
                self.assertEqual(parent.sha256, digest(label))
            persisted = registry.put_json(
                allowed.to_dict(),
                logical_type="citation_graph",
                origin="citation graph registry-boundary fixture",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "boundary-test"),
                parent_artifacts=(
                    digest("execution-authority"),
                    *allowed.parent_artifact_hashes,
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertEqual(
                len(persisted.parent_artifacts),
                MAX_ARTIFACT_PARENTS,
            )

        overflow = scholarly_record(len(paired_records) + 1)
        overflow = replace(
            overflow,
            response_artifact_hash=overflow.raw_artifact_hash,
            parent_artifact_hashes=(overflow.raw_artifact_hash,),
        )
        with self.assertRaisesRegex(LiteratureError, "registry parent bound"):
            CitationGraph(
                nodes=allowed.nodes + (CitationGraphNode.from_record(overflow),),
                edges=(),
            )

    def test_plan_execution_and_ranking_persist_at_registry_parent_bound(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            parent_records = tuple(
                registry.put_bytes(
                    f"shared-boundary-parent:{index}".encode("utf-8"),
                    logical_type="boundary_parent",
                    origin="literature aggregate registry-boundary fixture",
                    creator_role=Role.EVIDENCE_CURATOR,
                    creation_command=("scientist-one", "boundary-test"),
                    schema_version="1.0",
                    mime_type="application/octet-stream",
                    validation_result="PASS",
                    frozen=True,
                )
                for index in range(MAX_ARTIFACT_PARENTS)
            )
            parent_hashes = tuple(value.sha256 for value in parent_records)

            seed = acquisition(scholarly_record(700))
            base_plan = plan_citation_expansion(
                (seed,),
                CitationExpansionPolicy(
                    allowed_sources=(ScholarlySource.OPENALEX,),
                    traversals=(CitationTraversal.REFERENCES,),
                    max_requests=1,
                    max_depth=1,
                    max_pages_per_task=1,
                    max_total_page_requests=1,
                    max_nodes=512,
                    max_edges=512,
                ),
                depth=1,
            )
            bounded_task = replace(
                base_plan.tasks[0],
                parent_artifact_hashes=parent_hashes,
            )
            bounded_plan = replace(base_plan, tasks=(bounded_task,))
            plan_artifact = registry.put_json(
                bounded_plan.to_dict(),
                logical_type="citation_expansion_plan",
                origin="citation plan registry-boundary fixture",
                creator_role=Role.PROBLEM_INVESTIGATOR,
                creation_command=("scientist-one", "boundary-test"),
                parent_artifacts=bounded_plan.parent_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertEqual(
                len(plan_artifact.parent_artifacts),
                MAX_ARTIFACT_PARENTS,
            )
            with self.assertRaisesRegex(LiteratureError, "registry parent bound"):
                replace(
                    bounded_plan,
                    tasks=(
                        replace(
                            bounded_task,
                            parent_artifact_hashes=(
                                *parent_hashes,
                                digest("plan-parent-overflow"),
                            ),
                        ),
                    ),
                )

            graph_records = []
            for index in range((MAX_ARTIFACT_PARENTS - 2) // 2):
                record = scholarly_record(800 + index)
                graph_records.append(
                    replace(
                        record,
                        raw_artifact_hash=parent_hashes[index * 2],
                        response_artifact_hash=parent_hashes[index * 2 + 1],
                        parent_artifact_hashes=(
                            parent_hashes[index * 2],
                            parent_hashes[index * 2 + 1],
                        ),
                    )
                )
            graph = CitationGraph(
                nodes=tuple(
                    CitationGraphNode.from_record(value)
                    for value in graph_records
                ),
                edges=(),
            )
            base_graph_artifact = registry.put_json(
                graph.to_dict(),
                logical_type="citation_graph_base",
                origin="citation execution registry-boundary fixture",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "boundary-test"),
                parent_artifacts=graph.parent_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            execution = CitationExpansionExecution(
                plan_sha256=bounded_plan.sha256,
                plan_artifact_hash=plan_artifact.sha256,
                base_graph_sha256=graph.sha256,
                base_graph_artifact_hash=base_graph_artifact.sha256,
                graph=graph,
                pages=(),
                applied_page_request_ids=(),
                pending=(),
                active_task_ids=(bounded_task.task_id,),
                deferred_task_ids=(),
                completed_task_ids=(bounded_task.task_id,),
                failed_task_ids=(),
                truncations=(),
                status=CitationExecutionStatus.COMPLETE,
            )
            execution_artifact = registry.put_json(
                execution.to_dict(),
                logical_type="citation_expansion_execution",
                origin="citation execution registry-boundary fixture",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "boundary-test"),
                parent_artifacts=execution.parent_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertEqual(
                len(execution_artifact.parent_artifacts),
                2,
            )
            resumed_execution = replace(
                execution,
                previous_execution_sha256=digest("previous-execution"),
                previous_execution_artifact_hash=parent_hashes[-1],
            )
            self.assertEqual(
                len(resumed_execution.parent_artifact_hashes),
                3,
            )

            ranking = rank_scholarly_evidence(
                (
                    EvidenceRankingCandidate(
                        record=graph.nodes[0],
                        target_sha256=digest("boundary-ranking-target"),
                        methodology_relevance=3,
                        problem_alignment=3,
                        disconfirming_evidence=False,
                        relevance_assessment_artifact_hash=parent_hashes[-1],
                        verification=None,
                        verification_target_sha256=None,
                        verification_artifact_hash=None,
                    ),
                ),
                goal_id="boundary-ranking-goal",
                target_sha256=digest("boundary-ranking-target"),
            )
            bounded_ranked = replace(
                ranking.ranked[0],
                parent_artifact_hashes=parent_hashes,
            )
            bounded_ranking = replace(ranking, ranked=(bounded_ranked,))
            ranking_artifact = registry.put_json(
                bounded_ranking.to_dict(),
                logical_type="scholarly_evidence_ranking",
                origin="scholarly ranking registry-boundary fixture",
                creator_role=Role.PROBLEM_INVESTIGATOR,
                creation_command=("scientist-one", "boundary-test"),
                parent_artifacts=bounded_ranking.parent_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertEqual(
                len(ranking_artifact.parent_artifacts),
                MAX_ARTIFACT_PARENTS,
            )
            with self.assertRaisesRegex(LiteratureError, "registry parent bound"):
                replace(
                    bounded_ranking,
                    ranked=(
                        replace(
                            bounded_ranked,
                            parent_artifact_hashes=(
                                *parent_hashes,
                                plan_artifact.sha256,
                            ),
                        ),
                    ),
                )

            bounded_verification = ReferenceVerification(
                level=VerificationLevel.LEVEL_0,
                reference_identifier=None,
                matched_source_record_id=None,
                metadata_mismatches=(),
                failure_reasons=("boundary fixture has no resolved reference",),
                locator=None,
                parent_artifact_hashes=parent_hashes,
            )
            verification_artifact = registry.put_json(
                bounded_verification.to_dict(),
                logical_type="reference_verification",
                origin="reference verification registry-boundary fixture",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "boundary-test"),
                parent_artifacts=bounded_verification.parent_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertEqual(
                len(verification_artifact.parent_artifacts),
                MAX_ARTIFACT_PARENTS,
            )
            with self.assertRaisesRegex(LiteratureError, "registry parent bound"):
                replace(
                    bounded_verification,
                    parent_artifact_hashes=(
                        *parent_hashes,
                        digest("verification-parent-overflow"),
                    ),
                )

    def test_expansion_preflights_persistable_parent_budget_before_gateway_io(
        self,
    ) -> None:
        records = tuple(scholarly_record(index) for index in range(127))
        base_graph = CitationGraph(
            nodes=tuple(CitationGraphNode.from_record(value) for value in records),
            edges=(),
        )
        self.assertEqual(len(base_graph.parent_artifact_hashes), 254)
        plan = plan_citation_expansion(
            (acquisition(records[0]),),
            CitationExpansionPolicy(
                allowed_sources=(ScholarlySource.OPENALEX,),
                traversals=(CitationTraversal.REFERENCES,),
                max_requests=1,
                max_depth=1,
                max_pages_per_task=1,
                max_total_page_requests=1,
                max_nodes=512,
                max_edges=512,
            ),
            depth=1,
        )
        gateway = PaginatedCitationGateway()
        execution = execute_citation_expansion(
            plan,
            gateway,
            base_graph,
            plan_artifact_hash=digest("near-bound-plan-artifact"),
            base_graph_artifact_hash=digest("near-bound-base-graph-artifact"),
        )

        self.assertEqual(gateway.calls, [])
        self.assertEqual(
            execution.status,
            CitationExecutionStatus.PARTIAL_PERSISTENCE_BUDGET,
        )
        self.assertEqual(execution.pages, ())
        self.assertEqual(len(execution.truncations), 1)
        truncation = execution.truncations[0]
        self.assertEqual(
            truncation.reason,
            CitationTruncationReason.PERSISTENCE_PARENT_BUDGET,
        )
        expected_request = CitationPageRequest.for_task(
            plan,
            plan.tasks[0],
            page_number=1,
            cursor=None,
        )
        self.assertEqual(
            truncation.terminal_page_request_id,
            expected_request.request_id,
        )
        self.assertLessEqual(
            len(execution.parent_artifact_hashes),
            MAX_ARTIFACT_PARENTS,
        )
        verify_citation_expansion_execution(
            plan,
            base_graph,
            execution,
            plan_artifact_hash=digest("near-bound-plan-artifact"),
            base_graph_artifact_hash=digest("near-bound-base-graph-artifact"),
        )
        with self.assertRaisesRegex(
            LiteratureError,
            "available registry capacity",
        ):
            origin_node = next(
                value
                for value in base_graph.nodes
                if value.node_id == plan.tasks[0].origin_node_id
            )
            smaller_graph = CitationGraph(nodes=(origin_node,), edges=())
            verify_citation_expansion_execution(
                plan,
                smaller_graph,
                replace(
                    execution,
                    base_graph_sha256=smaller_graph.sha256,
                    graph=smaller_graph,
                ),
                plan_artifact_hash=digest("near-bound-plan-artifact"),
                base_graph_artifact_hash=digest(
                    "near-bound-base-graph-artifact"
                ),
            )

    def test_parent_budget_boundary_is_checkpoint_invariant_and_resumable(
        self,
    ) -> None:
        seed = scholarly_record(0)
        seed = replace(
            seed,
            response_artifact_hash=seed.raw_artifact_hash,
            parent_artifact_hashes=(seed.raw_artifact_hash,),
        )
        plan = plan_citation_expansion(
            (acquisition(seed),),
            CitationExpansionPolicy(
                allowed_sources=(ScholarlySource.OPENALEX,),
                traversals=(CitationTraversal.REFERENCES,),
                max_requests=1,
                max_depth=1,
                max_pages_per_task=128,
                max_total_page_requests=128,
                max_nodes=1000,
                max_edges=1000,
            ),
        )
        base_graph = CitationGraph(
            nodes=(CitationGraphNode.from_record(seed),),
            edges=(),
        )

        class LongPaginationGateway:
            def __init__(self) -> None:
                self.calls: list[CitationPageRequest] = []

            def fetch(self, request: CitationPageRequest) -> GatewayEnvelope:
                self.calls.append(request)
                page_number = request.page_number
                return GatewayEnvelope(
                    source=request.source,
                    request_id=request.request_id,
                    status=RetrievalStatus.AVAILABLE,
                    payload={
                        "works": [
                            {
                                "id": (
                                    "https://openalex.org/"
                                    f"W{8000 + page_number}"
                                ),
                                "doi": (
                                    "https://doi.org/10.5555/"
                                    f"lineage.{page_number}"
                                ),
                                "title": f"Lineage work {page_number}",
                                "authorships": [],
                                "publication_year": 2025,
                                "abstract": "Controlled lineage-bound fixture.",
                            }
                        ],
                        "next_cursor": (
                            None
                            if page_number == 128
                            else f"cursor-{page_number + 1}"
                        ),
                    },
                    raw_artifact_hash=digest(
                        f"lineage-raw:{page_number}"
                    ),
                    response_artifact_hash=digest(
                        f"lineage-response:{page_number}"
                    ),
                    license="metadata fixture",
                    full_text_status=FullTextStatus.METADATA_ONLY,
                )

        plan_hash = digest("lineage-plan-artifact")
        base_hash = digest("lineage-base-artifact")
        one_shot_gateway = LongPaginationGateway()
        one_shot = execute_citation_expansion(
            plan,
            one_shot_gateway,
            base_graph,
            plan_artifact_hash=plan_hash,
            base_graph_artifact_hash=base_hash,
        )
        first_gateway = LongPaginationGateway()
        checkpoint = execute_citation_expansion(
            plan,
            first_gateway,
            base_graph,
            plan_artifact_hash=plan_hash,
            base_graph_artifact_hash=base_hash,
            page_request_allowance=125,
        )
        resumed_gateway = LongPaginationGateway()
        resumed = execute_citation_expansion(
            plan,
            resumed_gateway,
            base_graph,
            plan_artifact_hash=plan_hash,
            base_graph_artifact_hash=base_hash,
            previous=checkpoint,
            previous_execution_artifact_hash=digest(
                "lineage-checkpoint-artifact"
            ),
        )

        self.assertEqual(len(one_shot_gateway.calls), 126)
        self.assertEqual(
            len(first_gateway.calls) + len(resumed_gateway.calls),
            126,
        )
        self.assertEqual(one_shot.status, resumed.status)
        self.assertIs(
            one_shot.status,
            CitationExecutionStatus.PARTIAL_PERSISTENCE_BUDGET,
        )
        self.assertEqual(
            tuple(value.to_dict() for value in one_shot.pages),
            tuple(value.to_dict() for value in resumed.pages),
        )
        self.assertEqual(
            one_shot.graph.canonical_bytes,
            resumed.graph.canonical_bytes,
        )
        self.assertEqual(
            tuple(value.to_dict() for value in one_shot.truncations),
            tuple(value.to_dict() for value in resumed.truncations),
        )
        self.assertLessEqual(
            len(resumed.parent_artifact_hashes),
            MAX_ARTIFACT_PARENTS,
        )
        verify_citation_expansion_execution(
            plan,
            base_graph,
            resumed,
            plan_artifact_hash=plan_hash,
            base_graph_artifact_hash=base_hash,
        )

        request = CitationPageRequest.for_task(
            plan,
            plan.tasks[0],
            page_number=127,
            cursor="cursor-127",
        )
        page = normalize_citation_expansion_page(
            request,
            LongPaginationGateway().fetch(request),
        )
        saturated_graph = CitationGraph(
            nodes=one_shot.graph.nodes + page.nodes,
            edges=one_shot.graph.edges + page.edges,
        )
        self.assertEqual(
            len(saturated_graph.parent_artifact_hashes),
            MAX_ARTIFACT_PARENTS - 1,
        )
        with self.assertRaisesRegex(LiteratureError, "resume custody"):
            replace(
                one_shot,
                graph=saturated_graph,
                pages=one_shot.pages + (page,),
                applied_page_request_ids=(
                    *one_shot.applied_page_request_ids,
                    page.request.request_id,
                ),
                pending=(
                    CitationPageCursor(
                        plan.tasks[0].task_id,
                        page.request.page_number + 1,
                        page.next_cursor,
                    ),
                ),
                truncations=(),
                status=CitationExecutionStatus.PARTIAL_PAGE_BUDGET,
            )

    def test_edge_provenance_is_atomic_and_missing_provenance_fails(self) -> None:
        first = CitationGraphNode.from_record(scholarly_record(0))
        second = CitationGraphNode.from_record(scholarly_record(1))
        with self.assertRaisesRegex(LiteratureError, "requires evidence provenance"):
            CitationGraphEdge(first.node_id, second.node_id, ())
        with self.assertRaisesRegex(LiteratureError, "SHA-256"):
            CitationEdgeObservation(
                ScholarlySource.OPENALEX,
                digest("valid-request"),
                "not-provenance",
            )

    def test_node_occurrence_identity_survives_identifier_enrichment(self) -> None:
        base = scholarly_record(0)
        openalex_identifier = ScholarlyIdentifier(IdentifierKind.OPENALEX, "W1000")
        initial = replace(base, identifiers=(openalex_identifier,))
        enriched = replace(
            initial,
            identifiers=(openalex_identifier, base.identifiers[0]),
        )
        initial_node = CitationGraphNode.from_record(initial)
        enriched_node = CitationGraphNode.from_record(enriched)
        self.assertEqual(initial_node.node_id, enriched_node.node_id)
        self.assertNotEqual(
            initial_node.canonical_work_key,
            enriched_node.canonical_work_key,
        )
        second_source = replace(
            base,
            source=ScholarlySource.SEMANTIC_SCHOLAR,
            source_record_id="semantic-work-1000",
            request_id=digest("semantic-request"),
            raw_artifact_hash=digest("semantic-raw"),
            response_artifact_hash=digest("semantic-response"),
            parent_artifact_hashes=(digest("semantic-raw"), digest("semantic-response")),
        )
        second_node = CitationGraphNode.from_record(second_source)
        self.assertNotEqual(enriched_node.node_id, second_node.node_id)
        self.assertEqual(enriched_node.canonical_work_key, second_node.canonical_work_key)
        CitationGraph(nodes=(enriched_node, second_node), edges=())

    def test_expansion_plan_is_deterministic_bounded_and_does_no_io(self) -> None:
        records = (scholarly_record(0), scholarly_record(1))
        acquisitions = tuple(acquisition(value) for value in records)
        policy = CitationExpansionPolicy(max_requests=3, max_depth=2)
        first = plan_citation_expansion(acquisitions, policy)
        second = plan_citation_expansion(tuple(reversed(acquisitions)), policy)
        self.assertEqual(first.canonical_bytes, second.canonical_bytes)
        self.assertEqual(
            CitationExpansionPlan.from_dict(first.to_dict()).sha256,
            first.sha256,
        )
        self.assertEqual(len(first.tasks), 3)
        self.assertEqual(len(first.deferred_task_ids), 5)
        self.assertEqual(
            set(first.parent_artifact_hashes),
            {
                artifact_hash
                for record in records
                for artifact_hash in record.parent_artifact_hashes
            },
        )
        self.assertEqual(
            {
                value.request.operation
                for value in first.tasks + first.deferred_tasks
            },
            {"expand_references", "expand_citations"},
        )
        with self.assertRaisesRegex(LiteratureError, "provenance is inconsistent"):
            plan_citation_expansion((replace(acquisitions[0], raw_artifact_hash=None),))
        with self.assertRaisesRegex(LiteratureError, "exceeds policy"):
            plan_citation_expansion(acquisitions, policy, depth=3)

    def test_paginated_expansion_executes_and_resumes_under_one_cumulative_budget(self) -> None:
        origin_record = scholarly_record(0)
        plan = plan_citation_expansion(
            (acquisition(origin_record),),
            CitationExpansionPolicy(
                allowed_sources=(ScholarlySource.OPENALEX,),
                traversals=(CitationTraversal.REFERENCES,),
                max_requests=1,
                max_depth=1,
                max_pages_per_task=2,
                max_total_page_requests=2,
                max_nodes=8,
                max_edges=8,
            ),
        )
        base = CitationGraph(
            nodes=(CitationGraphNode.from_record(origin_record),),
            edges=(),
        )
        gateway = PaginatedCitationGateway()
        first = execute_citation_expansion(
            plan,
            gateway,
            base,
            plan_artifact_hash=digest("plan-artifact"),
            base_graph_artifact_hash=digest("base-graph-artifact"),
            page_request_allowance=1,
        )
        self.assertIs(first.status, CitationExecutionStatus.PARTIAL_PAGE_BUDGET)
        self.assertEqual(len(first.pages), 1)
        self.assertEqual(len(first.pending), 1)
        resumed = execute_citation_expansion(
            plan,
            gateway,
            base,
            plan_artifact_hash=digest("plan-artifact"),
            base_graph_artifact_hash=digest("base-graph-artifact"),
            previous=first,
            previous_execution_artifact_hash=digest("first-execution-artifact"),
            page_request_allowance=1,
        )
        self.assertIs(resumed.status, CitationExecutionStatus.COMPLETE)
        self.assertEqual(len(resumed.pages), 2)
        self.assertEqual(len(resumed.graph.nodes), 3)
        self.assertEqual(len(resumed.graph.edges), 2)
        self.assertEqual(resumed.previous_execution_sha256, first.sha256)
        self.assertEqual(
            CitationExpansionExecution.from_dict(resumed.to_dict()).sha256,
            resumed.sha256,
        )
        self.assertEqual(len(gateway.calls), 2)
        replay = execute_citation_expansion(
            plan,
            gateway,
            base,
            plan_artifact_hash=digest("plan-artifact"),
            base_graph_artifact_hash=digest("base-graph-artifact"),
            previous=resumed,
            previous_execution_artifact_hash=digest("resumed-execution-artifact"),
            page_request_allowance=1,
        )
        self.assertEqual(len(replay.pages), 2)
        self.assertEqual(len(gateway.calls), 2)
        self.assertEqual(replay.sha256, resumed.sha256)

    def test_expansion_failure_is_a_typed_terminal_receipt(self) -> None:
        origin_record = scholarly_record(0)
        plan = plan_citation_expansion(
            (acquisition(origin_record),),
            CitationExpansionPolicy(
                allowed_sources=(ScholarlySource.OPENALEX,),
                traversals=(CitationTraversal.REFERENCES,),
                max_requests=1,
                max_depth=1,
                max_pages_per_task=1,
                max_total_page_requests=1,
            ),
        )
        execution = execute_citation_expansion(
            plan,
            FailingCitationGateway(),
            CitationGraph(
                nodes=(CitationGraphNode.from_record(origin_record),),
                edges=(),
            ),
            plan_artifact_hash=digest("failure-plan-artifact"),
            base_graph_artifact_hash=digest("failure-base-graph-artifact"),
        )
        self.assertIs(
            execution.status,
            CitationExecutionStatus.COMPLETED_WITH_FAILURES,
        )
        self.assertIs(execution.pages[0].status, RetrievalStatus.FAILED)
        self.assertTrue(execution.pages[0].failure_reason)
        self.assertEqual(execution.failed_task_ids, (plan.tasks[0].task_id,))

    def test_graph_budget_truncation_is_terminal_and_cannot_be_relabelled(self) -> None:
        plan, base = single_task_expansion_fixture(
            max_nodes=1,
            max_edges=1,
        )
        gateway = PaginatedCitationGateway()
        execution = execute_citation_expansion(
            plan,
            gateway,
            base,
            plan_artifact_hash=digest("graph-budget-plan-artifact"),
            base_graph_artifact_hash=digest("graph-budget-base-artifact"),
        )
        self.assertIs(
            execution.status,
            CitationExecutionStatus.PARTIAL_GRAPH_BUDGET,
        )
        self.assertEqual(execution.graph.sha256, base.sha256)
        self.assertEqual(execution.applied_page_request_ids, ())
        self.assertEqual(execution.pending, ())
        self.assertIs(
            execution.truncations[0].reason,
            CitationTruncationReason.GRAPH_BUDGET,
        )
        call_count = len(gateway.calls)
        replay = execute_citation_expansion(
            plan,
            gateway,
            base,
            plan_artifact_hash=digest("graph-budget-plan-artifact"),
            base_graph_artifact_hash=digest("graph-budget-base-artifact"),
            previous=execution,
            previous_execution_artifact_hash=digest(
                "graph-budget-execution-artifact"
            ),
        )
        self.assertEqual(replay.sha256, execution.sha256)
        self.assertEqual(len(gateway.calls), call_count)

        forged = replace(
            execution,
            truncations=(
                replace(
                    execution.truncations[0],
                    reason=CitationTruncationReason.GRAPH_CONFLICT,
                ),
            ),
            status=CitationExecutionStatus.PARTIAL_EVIDENCE_ANOMALY,
        )
        with self.assertRaisesRegex(LiteratureError, "budget breach"):
            verify_citation_expansion_execution(
                plan,
                base,
                forged,
                plan_artifact_hash=digest("graph-budget-plan-artifact"),
                base_graph_artifact_hash=digest("graph-budget-base-artifact"),
            )

    def test_external_verifier_rejects_empty_complete_execution_for_an_active_plan(self) -> None:
        plan, base = single_task_expansion_fixture()
        with self.assertRaisesRegex(LiteratureError, "completely partitioned"):
            CitationExpansionExecution(
                plan_sha256=plan.sha256,
                plan_artifact_hash=digest("forged-plan-artifact"),
                base_graph_sha256=base.sha256,
                base_graph_artifact_hash=digest("forged-base-artifact"),
                graph=base,
                pages=(),
                applied_page_request_ids=(),
                pending=(),
                active_task_ids=(plan.tasks[0].task_id,),
                deferred_task_ids=(),
                completed_task_ids=(),
                failed_task_ids=(),
                truncations=(),
                status=CitationExecutionStatus.COMPLETE,
            )
        internally_consistent_forgery = CitationExpansionExecution(
            plan_sha256=plan.sha256,
            plan_artifact_hash=digest("forged-plan-artifact"),
            base_graph_sha256=base.sha256,
            base_graph_artifact_hash=digest("forged-base-artifact"),
            graph=base,
            pages=(),
            applied_page_request_ids=(),
            pending=(),
            active_task_ids=(),
            deferred_task_ids=(),
            completed_task_ids=(),
            failed_task_ids=(),
            truncations=(),
            status=CitationExecutionStatus.COMPLETE,
        )
        with self.assertRaisesRegex(LiteratureError, "task inventory"):
            verify_citation_expansion_execution(
                plan,
                base,
                internally_consistent_forgery,
                plan_artifact_hash=digest("forged-plan-artifact"),
                base_graph_artifact_hash=digest("forged-base-artifact"),
            )
        wrong_base = CitationGraph(
            nodes=(CitationGraphNode.from_record(scholarly_record(9)),),
            edges=(),
        )
        gateway = PaginatedCitationGateway()
        with self.assertRaisesRegex(LiteratureError, "omits a planned origin"):
            execute_citation_expansion(
                plan,
                gateway,
                wrong_base,
                plan_artifact_hash=digest("forged-plan-artifact"),
                base_graph_artifact_hash=digest("wrong-base-artifact"),
            )
        self.assertEqual(gateway.calls, [])

    def test_page_receipt_rejects_spliced_node_and_edge_provenance(self) -> None:
        plan, base = single_task_expansion_fixture(
            max_pages_per_task=1,
            max_total_page_requests=1,
        )
        execution = execute_citation_expansion(
            plan,
            PaginatedCitationGateway(),
            base,
            plan_artifact_hash=digest("splice-plan-artifact"),
            base_graph_artifact_hash=digest("splice-base-artifact"),
        )
        page = execution.pages[0]
        node = page.nodes[0]
        with self.assertRaisesRegex(LiteratureError, "node is not bound"):
            replace(
                page,
                nodes=(replace(node, request_id=digest("spliced-request")),),
            )
        with self.assertRaisesRegex(LiteratureError, "node is not bound"):
            replace(
                page,
                nodes=(
                    replace(
                        node,
                        parent_artifact_hashes=(page.raw_artifact_hash,),
                    ),
                ),
            )
        edge_value = page.edges[0]
        spliced_observation = replace(
            edge_value.observations[0],
            evidence_artifact_hash=digest("spliced-evidence"),
        )
        with self.assertRaisesRegex(LiteratureError, "edge observation"):
            replace(
                page,
                edges=(replace(edge_value, observations=(spliced_observation,)),),
            )

    def test_cursor_cycle_and_page_limit_are_typed_terminal_receipts(self) -> None:
        cycle_plan, cycle_base = single_task_expansion_fixture(
            max_pages_per_task=4,
            max_total_page_requests=4,
        )
        cycle_gateway = CursorCycleCitationGateway()
        cycle_execution = execute_citation_expansion(
            cycle_plan,
            cycle_gateway,
            cycle_base,
            plan_artifact_hash=digest("cycle-plan-artifact"),
            base_graph_artifact_hash=digest("cycle-base-artifact"),
        )
        self.assertIs(
            cycle_execution.status,
            CitationExecutionStatus.PARTIAL_EVIDENCE_ANOMALY,
        )
        self.assertIs(
            cycle_execution.truncations[0].reason,
            CitationTruncationReason.CURSOR_CYCLE,
        )
        self.assertEqual(len(cycle_execution.pages), 3)
        self.assertEqual(cycle_execution.pending, ())

        page_plan, page_base = single_task_expansion_fixture(
            max_pages_per_task=1,
            max_total_page_requests=4,
        )
        page_gateway = PaginatedCitationGateway()
        page_execution = execute_citation_expansion(
            page_plan,
            page_gateway,
            page_base,
            plan_artifact_hash=digest("page-limit-plan-artifact"),
            base_graph_artifact_hash=digest("page-limit-base-artifact"),
        )
        self.assertIs(
            page_execution.status,
            CitationExecutionStatus.PARTIAL_PAGE_BUDGET,
        )
        self.assertIs(
            page_execution.truncations[0].reason,
            CitationTruncationReason.PAGE_LIMIT,
        )
        self.assertEqual(page_execution.pending, ())
        call_count = len(page_gateway.calls)
        replay = execute_citation_expansion(
            page_plan,
            page_gateway,
            page_base,
            plan_artifact_hash=digest("page-limit-plan-artifact"),
            base_graph_artifact_hash=digest("page-limit-base-artifact"),
            previous=page_execution,
            previous_execution_artifact_hash=digest(
                "page-limit-execution-artifact"
            ),
        )
        self.assertEqual(replay.sha256, page_execution.sha256)
        self.assertEqual(len(page_gateway.calls), call_count)

    def test_captured_malformed_page_preserves_salvageable_custody(self) -> None:
        plan, base = single_task_expansion_fixture(
            max_pages_per_task=1,
            max_total_page_requests=1,
        )
        execution = execute_citation_expansion(
            plan,
            MalformedCapturedCitationGateway(),
            base,
            plan_artifact_hash=digest("malformed-plan-artifact"),
            base_graph_artifact_hash=digest("malformed-base-artifact"),
        )
        page = execution.pages[0]
        self.assertIs(page.status, RetrievalStatus.MALFORMED)
        self.assertEqual(page.raw_artifact_hash, digest("malformed-page-raw"))
        self.assertEqual(
            page.response_artifact_hash,
            digest("malformed-page-response"),
        )
        self.assertIs(
            execution.status,
            CitationExecutionStatus.COMPLETED_WITH_FAILURES,
        )

    def test_identity_enrichment_preserves_self_cycle_and_conflicts_checkpoint(self) -> None:
        plan, base = single_task_expansion_fixture(
            max_pages_per_task=1,
            max_total_page_requests=1,
        )
        execution = execute_citation_expansion(
            plan,
            SameOccurrenceCitationGateway(),
            base,
            plan_artifact_hash=digest("same-plan-artifact"),
            base_graph_artifact_hash=digest("same-base-artifact"),
        )
        self.assertIs(execution.status, CitationExecutionStatus.COMPLETE)
        self.assertEqual(len(execution.graph.nodes), 1)
        self.assertEqual(execution.graph.nodes[0].node_id, base.nodes[0].node_id)
        self.assertGreater(
            len(execution.graph.nodes[0].identifiers),
            len(base.nodes[0].identifiers),
        )
        self.assertTrue(execution.graph.has_cycles)
        self.assertEqual(
            execution.graph.cycle_node_ids,
            (base.nodes[0].node_id,),
        )

        conflict_execution = execute_citation_expansion(
            plan,
            SameOccurrenceCitationGateway(conflicting_title=True),
            base,
            plan_artifact_hash=digest("conflict-plan-artifact"),
            base_graph_artifact_hash=digest("conflict-base-artifact"),
        )
        self.assertIs(
            conflict_execution.status,
            CitationExecutionStatus.PARTIAL_EVIDENCE_ANOMALY,
        )
        self.assertIs(
            conflict_execution.truncations[0].reason,
            CitationTruncationReason.GRAPH_CONFLICT,
        )
        self.assertEqual(conflict_execution.graph.sha256, base.sha256)
        self.assertEqual(conflict_execution.applied_page_request_ids, ())
        self.assertIs(conflict_execution.pages[0].status, RetrievalStatus.AVAILABLE)


class RankingAndFallbackTests(unittest.TestCase):
    def verification(self, record: ScholarlyRecord, level: VerificationLevel) -> ReferenceVerification:
        return ReferenceVerification(
            level=level,
            reference_identifier=record.identifiers[0],
            matched_source_record_id=record.source_record_id,
            metadata_mismatches=(),
            failure_reasons=(),
            locator=None,
            parent_artifact_hashes=record.parent_artifact_hashes,
        )

    def candidate(
        self,
        record: ScholarlyRecord,
        level: VerificationLevel,
        *,
        target: str,
    ) -> EvidenceRankingCandidate:
        return EvidenceRankingCandidate(
            record=record,
            target_sha256=target,
            methodology_relevance=4,
            problem_alignment=5,
            disconfirming_evidence=False,
            relevance_assessment_artifact_hash=digest(
                f"relevance:{record.source_record_id}"
            ),
            verification=self.verification(record, level),
            verification_target_sha256=target,
            verification_artifact_hash=digest(
                f"verification:{record.source_record_id}:{int(level)}"
            ),
        )

    def test_ranking_separates_support_depth_and_is_target_bound(self) -> None:
        target = digest("research-target")
        metadata = self.candidate(scholarly_record(0), VerificationLevel.LEVEL_2, target=target)
        supported = self.candidate(
            scholarly_record(1, full_text=True),
            VerificationLevel.LEVEL_5,
            target=target,
        )
        ranking = rank_scholarly_evidence(
            (metadata, supported),
            goal_id="goal-1",
            target_sha256=target,
        )
        reversed_ranking = rank_scholarly_evidence(
            (supported, metadata),
            goal_id="goal-1",
            target_sha256=target,
        )
        self.assertEqual(ranking.canonical_bytes, reversed_ranking.canonical_bytes)
        self.assertIs(
            ranking.ranked[0].evidence_support,
            EvidenceSupportTier.CONTEXT_CHECKED_SUPPORT,
        )
        self.assertIs(
            ranking.ranked[1].evidence_support,
            EvidenceSupportTier.METADATA_MATCHED,
        )
        self.assertIn("does not establish semantic", ranking.ranked[1].reasons[-1])
        with self.assertRaisesRegex(LiteratureError, "different ranking target"):
            rank_scholarly_evidence(
                (metadata,),
                goal_id="goal-1",
                target_sha256=digest("other-target"),
            )
        with self.assertRaisesRegex(LiteratureError, "different ranking target"):
            replace(metadata, verification_target_sha256=digest("wrong-claim"))
        duplicate_work = replace(
            scholarly_record(0),
            source=ScholarlySource.SEMANTIC_SCHOLAR,
            source_record_id="semantic-duplicate-work",
            request_id=digest("semantic-duplicate-request"),
            raw_artifact_hash=digest("semantic-duplicate-raw"),
            response_artifact_hash=digest("semantic-duplicate-response"),
            parent_artifact_hashes=(
                digest("semantic-duplicate-raw"),
                digest("semantic-duplicate-response"),
            ),
        )
        with self.assertRaisesRegex(LiteratureError, "duplicate scholarly works"):
            rank_scholarly_evidence(
                (
                    metadata,
                    self.candidate(
                        duplicate_work,
                        VerificationLevel.LEVEL_2,
                        target=target,
                    ),
                ),
                goal_id="goal-1",
                target_sha256=target,
            )

    def test_expanded_graph_node_is_ranked_as_explicit_metadata_evidence(self) -> None:
        target = digest("expanded-ranking-target")
        node = CitationGraphNode.from_record(scholarly_record(77))
        candidate = EvidenceRankingCandidate(
            record=node,
            target_sha256=target,
            methodology_relevance=1,
            problem_alignment=1,
            disconfirming_evidence=False,
            relevance_assessment_artifact_hash=digest("expanded-relevance"),
            verification=None,
            verification_target_sha256=None,
            verification_artifact_hash=None,
        )
        ranking = rank_scholarly_evidence(
            (candidate,),
            goal_id="goal-expanded",
            target_sha256=target,
        )
        restored = type(ranking).from_dict(ranking.to_dict())
        self.assertEqual(restored.sha256, ranking.sha256)
        self.assertEqual(restored.ranked[0].node_id, node.node_id)
        self.assertIs(
            restored.ranked[0].evidence_support,
            EvidenceSupportTier.CAPTURED_RECORD_ONLY,
        )
        with self.assertRaisesRegex(LiteratureError, "support tier"):
            replace(
                restored.ranked[0],
                evidence_support=EvidenceSupportTier.PASSAGE_SUPPORT,
            )
        with self.assertRaisesRegex(LiteratureError, "omits its verification"):
            replace(
                restored.ranked[0],
                evidence_support=EvidenceSupportTier.CONTEXT_CHECKED_SUPPORT,
                verification_level=VerificationLevel.LEVEL_5,
                verification_artifact_hash=digest(
                    "nonexistent-expanded-verification"
                ),
            )
        with self.assertRaisesRegex(LiteratureError, "graph-only evidence"):
            replace(
                candidate,
                verification=self.verification(
                    scholarly_record(77),
                    VerificationLevel.LEVEL_2,
                ),
                verification_target_sha256=target,
                verification_artifact_hash=digest(
                    "forged-expanded-verification"
                ),
            )

    def attempts(self, status: RetrievalStatus = RetrievalStatus.NOT_FOUND):
        return (
            ScholarlyAttemptReceipt(
                ScholarlySource.OPENALEX,
                digest("openalex-attempt"),
                status,
                digest("openalex-attempt-receipt"),
            ),
            ScholarlyAttemptReceipt(
                ScholarlySource.SEMANTIC_SCHOLAR,
                digest("s2-attempt"),
                RetrievalStatus.NOT_FOUND,
                digest("s2-attempt-receipt"),
            ),
        )

    def summary(self, **changes: object) -> ScholarlySearchSummary:
        values: dict[str, object] = {
            "goal_id": "goal-1",
            "citation_expansion_plan_sha256": digest("citation-plan"),
            "investigation_history_sha256": digest("investigation-history"),
            "sufficiency_assessment_artifact_hash": digest(
                "sufficiency-assessment"
            ),
            "scholarly_rounds_completed": 2,
            "attempts": self.attempts(),
            "records_acquired": 5,
            "full_text_records_reviewed": 5,
            "scholarly_evidence_sufficient": False,
            "scholarly_sources_exhausted": True,
            "insufficiency_reasons": ("No scholarly work covers the required artifact.",),
            "evidence_artifact_hashes": (digest("search-analysis"),),
        }
        values.update(changes)
        return ScholarlySearchSummary(**values)  # type: ignore[arg-type]

    def test_general_web_fallback_is_only_a_post_insufficiency_decision(self) -> None:
        policy = GeneralWebFallbackPolicy(
            allow_general_web=True,
            allowed_purposes=(GeneralWebPurpose.SOFTWARE_ARTIFACT,),
        )
        premature = decide_general_web_fallback(
            policy,
            self.summary(
                scholarly_rounds_completed=1,
                scholarly_sources_exhausted=False,
                insufficiency_reasons=(),
            ),
            GeneralWebPurpose.SOFTWARE_ARTIFACT,
        )
        self.assertIs(
            premature.status,
            GeneralWebFallbackStatus.MORE_SCHOLARLY_SEARCH_REQUIRED,
        )
        self.assertFalse(premature.may_use_general_web)
        allowed = decide_general_web_fallback(
            policy,
            self.summary(),
            GeneralWebPurpose.SOFTWARE_ARTIFACT,
        )
        self.assertTrue(allowed.may_use_general_web)
        self.assertEqual(allowed.goal_id, "goal-1")
        blocked_purpose = decide_general_web_fallback(
            policy,
            self.summary(),
            GeneralWebPurpose.GREY_LITERATURE,
        )
        self.assertIs(blocked_purpose.status, GeneralWebFallbackStatus.BLOCKED_BY_POLICY)
        with self.assertRaisesRegex(LiteratureError, "not exhaustion"):
            self.summary(attempts=self.attempts(RetrievalStatus.RATE_LIMITED))
        with self.assertRaisesRegex(LiteratureError, "requires captured provenance"):
            self.summary(evidence_artifact_hashes=())


class InvestigationHistoryAndGateTests(unittest.TestCase):
    def test_round_history_roundtrips_and_detects_tampering_or_missing_provenance(self) -> None:
        state = investigation_state(scientific_records())
        restored = ProblemInvestigationState.from_dict(state.to_dict())
        self.assertEqual(restored.sha256, state.sha256)
        self.assertEqual(restored.parent_artifact_hashes, state.parent_artifact_hashes)
        payload = state.to_dict()
        payload["rounds"][0]["query"] = "Tampered seed query."
        with self.assertRaisesRegex(ScientificDesignError, "hash chain"):
            ProblemInvestigationState.from_dict(payload)
        seed = state.rounds[0]
        with self.assertRaisesRegex(ScientificDesignError, "omits"):
            replace(seed, evidence_artifact_hashes=(digest("only-round-receipt"),))
        with self.assertRaisesRegex(ScientificDesignError, "multi-round|disconfirming"):
            replace(state, rounds=state.rounds[:-1])
        with self.assertRaisesRegex(ScientificDesignError, "content/artifact"):
            replace(
                state,
                general_web_fallback_decision_sha256=digest(
                    "forged-web-decision"
                ),
            )
        with self.assertRaisesRegex(ScientificDesignError, "brief-ready"):
            replace(
                state,
                general_web_fallback_decision_sha256=digest("web-decision"),
                general_web_fallback_decision_artifact_hash=digest(
                    "web-decision-artifact"
                ),
            )

    def test_persisted_investigation_state_respects_registry_parent_bound(self) -> None:
        state = investigation_state(scientific_records())
        additional_count = MAX_ARTIFACT_PARENTS - len(
            state.parent_artifact_hashes
        )
        extra = tuple(
            digest(f"state-parent:{index}") for index in range(additional_count)
        )
        final_round = replace(
            state.rounds[-1],
            evidence_artifact_hashes=(
                state.rounds[-1].evidence_artifact_hashes + extra
            ),
        )
        allowed = replace(state, rounds=state.rounds[:-1] + (final_round,))
        self.assertEqual(
            len(allowed.parent_artifact_hashes),
            MAX_ARTIFACT_PARENTS,
        )
        with self.assertRaisesRegex(ScientificDesignError, "registry parent bound"):
            replace(
                allowed,
                rounds=allowed.rounds[:-1]
                + (
                    replace(
                        allowed.rounds[-1],
                        evidence_artifact_hashes=(
                            allowed.rounds[-1].evidence_artifact_hashes
                            + (digest("state-parent-overflow"),)
                        ),
                    ),
                ),
            )

    def test_zero_result_disconfirming_search_is_valid_but_absent_search_is_not(self) -> None:
        records = scientific_records()
        goal = ResearchGoal(
            goal_id="goal-1",
            question="Does the candidate improve the frozen metric?",
            scope="Controlled fixture scope.",
            constraints=("offline",),
            seed_source_ids=("paper-0",),
        )
        state = investigation_state(records, disconfirming_ids=(), goal=goal)
        self.assertEqual(state.disconfirming_source_ids, frozenset())
        direction = ResearchDirection(
            direction_id="direction-1",
            question="Can the candidate improve the metric?",
            unresolved_weakness="Prior approaches fail a frozen control.",
            candidate_gap="No reviewed work resolves the control failure.",
            source_ids=("paper-0", "paper-1"),
            disconfirming_source_ids=(),
            experimentally_distinguishable=True,
            feasible_with_resources=True,
        )
        brief = ProblemInvestigator().build_checked_brief(
            brief_id="brief-1",
            goal=goal,
            literature_records=records,
            directions=(direction,),
            selected_direction_id=direction.direction_id,
            existing_approaches=("Controlled strong baseline",),
            evaluation_conventions=("Frozen held-out metric",),
            criteria=ResearchQuestionCriteria(True, True, True, True, True, True),
            investigation_state=state,
            investigation_state_artifact_hash=digest("investigation-state-artifact"),
        )
        require_research_gate(
            brief,
            state,
            investigation_state_artifact_hash=digest("investigation-state-artifact"),
        )
        duplicate_state = investigation_state(
            records,
            disconfirming_ids=(),
            duplicate_last_work=True,
            goal=goal,
        )
        with self.assertRaisesRegex(ScientificDesignError, "duplicate scholarly works"):
            ProblemInvestigator().build_checked_brief(
                brief_id="brief-duplicate-work",
                goal=goal,
                literature_records=records,
                directions=(direction,),
                selected_direction_id=direction.direction_id,
                existing_approaches=("Controlled strong baseline",),
                evaluation_conventions=("Frozen held-out metric",),
                criteria=ResearchQuestionCriteria(True, True, True, True, True, True),
                investigation_state=duplicate_state,
                investigation_state_artifact_hash=digest(
                    "investigation-state-artifact"
                ),
            )

    def test_forged_proceed_brief_cannot_reuse_unrelated_or_changed_state(self) -> None:
        records = scientific_records()
        goal = ResearchGoal(
            "goal-1",
            "A question?",
            "A scope.",
            ("offline",),
            ("paper-0",),
        )
        state = investigation_state(records, goal=goal)
        with self.assertRaisesRegex(ScientificDesignError, "persisted"):
            ResearchBrief(
                brief_id="forged-brief",
                goal=goal,
                elite_pool=ProblemInvestigator().build_checked_brief(
                    brief_id="temporary",
                    goal=goal,
                    literature_records=records,
                    directions=(
                        ResearchDirection(
                            "direction-temp",
                            "A question?",
                            "A weakness.",
                            "A gap.",
                            ("paper-0",),
                            ("paper-2",),
                            True,
                            True,
                        ),
                    ),
                    selected_direction_id="direction-temp",
                    existing_approaches=("A baseline.",),
                    evaluation_conventions=("A metric.",),
                    criteria=ResearchQuestionCriteria(True, True, True, True, True, True),
                    investigation_state=state,
                    investigation_state_artifact_hash=digest("investigation-state-artifact"),
                ).elite_pool,
                directions=(
                    ResearchDirection(
                        "direction-forged",
                        "A question?",
                        "A weakness.",
                        "A gap.",
                        ("paper-0",),
                        ("paper-2",),
                        True,
                        True,
                    ),
                ),
                selected_direction_id="direction-forged",
                existing_approaches=("A baseline.",),
                evaluation_conventions=("A metric.",),
                assessment=ResearchQuestionAssessment(
                    True, True, True, True, True, True, True, True
                ),
            )
        legitimate = ProblemInvestigator().build_checked_brief(
            brief_id="legitimate",
            goal=goal,
            literature_records=records,
            directions=(
                ResearchDirection(
                    "direction-legitimate",
                    "A question?",
                    "A weakness.",
                    "A gap.",
                    ("paper-0",),
                    ("paper-2",),
                    True,
                    True,
                ),
            ),
            selected_direction_id="direction-legitimate",
            existing_approaches=("A baseline.",),
            evaluation_conventions=("A metric.",),
            criteria=ResearchQuestionCriteria(True, True, True, True, True, True),
            investigation_state=state,
            investigation_state_artifact_hash=digest("investigation-state-artifact"),
        )
        changed_goal = replace(goal, question="A materially changed question?")
        with self.assertRaisesRegex(ScientificDesignError, "different research goal"):
            ProblemInvestigator().build_checked_brief(
                brief_id="changed-goal",
                goal=changed_goal,
                literature_records=records,
                directions=legitimate.directions,
                selected_direction_id=legitimate.selected_direction_id,
                existing_approaches=legitimate.existing_approaches,
                evaluation_conventions=legitimate.evaluation_conventions,
                criteria=ResearchQuestionCriteria(True, True, True, True, True, True),
                investigation_state=state,
                investigation_state_artifact_hash=digest(
                    "investigation-state-artifact"
                ),
            )
        changed_goal_forgery = replace(legitimate, goal=changed_goal)
        with self.assertRaisesRegex(ScientificPromotionError, "not bound"):
            require_research_gate(
                changed_goal_forgery,
                state,
                investigation_state_artifact_hash=digest(
                    "investigation-state-artifact"
                ),
            )
        changed_records = (replace(records[0], title="Changed after investigation"),) + records[1:]
        changed_state = investigation_state(changed_records, goal=goal)
        with self.assertRaisesRegex(ScientificPromotionError, "not bound"):
            require_research_gate(
                legitimate,
                changed_state,
                investigation_state_artifact_hash=digest("investigation-state-artifact"),
            )
        self.assertIs(legitimate.gate_outcome, ResearchGateOutcome.PROCEED)


if __name__ == "__main__":
    unittest.main()
