"""Offline registered-query joins; no selections, live calls, or new authority."""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, asdict, dataclass, replace
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import quote

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.external import EgressGateway, FixtureTransport, TransportResponse
from scientist_one.literature import (
    RetrievalStatus, ScholarlySearchFilter, ScholarlySearchPlan, ScholarlySearchPurpose,
    ScholarlySearchRequest, ScholarlySource, normalize_scholarly_search_result,
)
from scientist_one.roles import Role
import scientist_one.scientific_design as design
from scientist_one.scholarly_gateway import (
    SourceOwnedScholarlyGateway, openalex_scholarly_egress_policy,
)
from scientist_one.security import canonical_json_bytes
from tests.test_scholarly_gateway import digest, openalex_list, openalex_work


@dataclass
class SearchFixture:
    goal: object
    goal_record: object
    target_record: object
    plan: object
    plan_record: object
    result: object
    result_record: object
    captured: object
    gateway: object
    transport: object


class RegisteredSearchReplayTests(unittest.TestCase):
    def put(self, value, default_logical_type, role, parents=(), **overrides):
        metadata = dict(
            logical_type=default_logical_type, creator_role=role,
            origin="offline registered-query test", parent_artifacts=parents,
            creation_command=("scientist-one", "registered-query-test"),
            schema_version="1.0", mime_type="application/json",
            validation_result="PASS", frozen=True,
        )
        metadata.update(overrides)
        if callable(metadata["parent_artifacts"]):
            metadata["parent_artifacts"] = metadata["parent_artifacts"](parents)
        return self.registry.put_json(value, **metadata)

    def make(self, *, responses=None, question="What does this query capture?",
             query="quantum gravity", fixture_goal=False, allowed_sources=None,
             source=ScholarlySource.OPENALEX, maximum_attempts=1,
             goal_mutation=None, target_mutation=None, plan_mutation=None,
             plan_replacement=None, metadata=None, result_mutation=None, filters=()):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.registry = ArtifactRegistry(self.root)
        self.extra_record = self.put({"unrelated": True}, "registered_query_test_context", Role.ORCHESTRATOR)
        metadata = copy.deepcopy(metadata or {})
        for overrides in metadata.values():
            if "parent_artifacts" in overrides and not callable(overrides["parent_artifacts"]):
                overrides["parent_artifacts"] = tuple(
                    self.extra_record.sha256 if value == digest("extra-parent") else value
                    for value in overrides["parent_artifacts"]
                )
        goal = design.ResearchGoal(
            goal_id="registered-search", question=question,
            scope="Descriptive captured-query observation only",
            constraints=("No scientific or fallback authority",),
            seed_source_ids=("seed-one",),
        )
        wrapper = ({"fixture_notice": "Offline only", "scientific_evidence": False,
                    "research_goal": asdict(goal)} if fixture_goal else
                   {"schema_version": "research-goal/v1", "research_goal": asdict(goal)})
        if goal_mutation:
            goal_mutation(wrapper)
        goal_record = self.put(wrapper, "research_goal", Role.PROBLEM_INVESTIGATOR,
                               **metadata.get("goal", {}))
        target = dict(
            schema_version="scholarly-search-target/v2", purpose="SEED",
            goal_id=goal.goal_id, goal_sha256=goal.sha256,
            scientific_evidence=False, target_id="registered-seed-target",
            target_statement=goal.question, contribution_id=None,
            contribution_statement=None, reviewed_retained_set_artifact_hash=None,
        )
        if target_mutation:
            target_mutation(target)
        target_record = self.put(
            target, "scholarly_search_target", Role.PROBLEM_INVESTIGATOR,
            (goal_record.sha256,), **metadata.get("target", {}),
        )
        url = "https://api.openalex.org/works?search=" + quote('"' + query + '"', safe="")
        if filters:
            wire = sorted(("open_access.is_oa" if f.name == "open_access" else f.name,
                           f.value) for f in filters)
            url += "&filter=" + quote(",".join(name + ":" + value for name, value in wire), safe="")
        url += "&per_page=2&page=1"
        if responses is None:
            responses = [(200, openalex_list([openalex_work()], per_page=2, page=1))]
        transport = FixtureTransport(tuple(
            TransportResponse(status, (("Content-Type", "application/json"),), body, url)
            for status, body in responses
        ))
        gateway = SourceOwnedScholarlyGateway(openalex_gateway=EgressGateway(
            openalex_scholarly_egress_policy(
                minimum_interval_seconds=0.0, maximum_attempts=maximum_attempts,
            ), transport, registry=self.registry,
            timestamp=lambda: "2026-09-13T18:00:00.000000Z",
        ))
        route = gateway.route_authority_artifact(ScholarlySource.OPENALEX)
        plan = ScholarlySearchPlan(
            purpose=ScholarlySearchPurpose.SEED, goal_id=goal.goal_id,
            goal_sha256=goal.sha256, target_sha256=target_record.sha256,
            query=query, synonyms=(), filters=filters,
            allowed_sources=allowed_sources or (ScholarlySource.OPENALEX,),
            max_results=2,
            parent_artifact_hashes=(goal_record.sha256, target_record.sha256, route.sha256),
        )
        if plan_replacement:
            plan = plan_replacement(plan)
        plan_value = plan.to_dict()
        if plan_mutation:
            plan_mutation(plan_value)
        plan_record = self.put(
            plan_value, "scholarly_search_plan", Role.PROBLEM_INVESTIGATOR,
            plan.parent_artifact_hashes, **metadata.get("plan", {}),
        )
        request = ScholarlySearchRequest.from_plan(plan, source)
        captured = gateway.fetch(request)
        result = normalize_scholarly_search_result(
            request, design.GatewayEnvelope(
                source=captured.source, request_id=captured.request_id,
                status=captured.status, payload=captured.payload,
                raw_artifact_hash=captured.raw_artifact_hash,
                response_artifact_hash=captured.response_artifact_hash,
                failure_reason=captured.failure_reason, license=captured.license,
                full_text_status=captured.full_text_status,
            ), plan_artifact_hash=plan_record.sha256,
        )
        value = result.to_dict()
        if result_mutation:
            result_mutation(value)
        result_record = self.put(
            value, "scholarly_search_result", Role.EVIDENCE_CURATOR,
            result.parent_artifact_hashes, **metadata.get("result", {}),
        )
        return SearchFixture(goal, goal_record, target_record, plan, plan_record,
                             result, result_record, captured, gateway, transport)

    def snapshot(self):
        return {str(path.relative_to(self.root)): path.read_bytes()
                for path in self.root.rglob("*") if path.is_file()}

    def replay(self, fixture, **overrides):
        arguments = dict(goal_artifact_sha256=fixture.goal_record.sha256,
                         plan_artifact_sha256=fixture.plan_record.sha256,
                         result_artifact_sha256=fixture.result_record.sha256)
        arguments.update(overrides)
        before = self.snapshot()
        try:
            return design.require_captured_scholarly_search_result(self.registry, **arguments)
        finally:
            self.assertEqual(self.snapshot(), before, "reader mutated registry/ledger/storage")

    def refuse(self, fixture, **overrides):
        with self.assertRaises(design.ScientificPromotionError):
            self.replay(fixture, **overrides)

    def put_like(self, original_hash, value, **overrides):
        record = self.registry.get_metadata(original_hash)
        metadata = dict(logical_type=record.logical_type, origin=record.origin,
                        creator_role=record.creator_role, creation_command=record.creation_command,
                        parent_artifacts=record.parent_artifacts, schema_version=record.schema_version,
                        mime_type=record.mime_type, validation_result=record.validation_result,
                        frozen=record.frozen)
        metadata.update(overrides)
        return (self.registry.put_bytes(value, **metadata) if isinstance(value, bytes)
                else self.registry.put_json(value, **metadata))

    def result_with_capture(self, fixture, *, response_hash=None, raw_hash=None):
        result = replace(fixture.result,
                         response_artifact_hash=response_hash or fixture.result.response_artifact_hash,
                         raw_artifact_hash=raw_hash or fixture.result.raw_artifact_hash)
        return self.put_like(fixture.result_record.sha256, result.to_dict(),
                             parent_artifacts=result.parent_artifact_hashes)

    def test_registered_success_no_selection_and_complete_inspected_set(self):
        self.assertIn("ReplayedScholarlySearchResult", design.__all__)
        self.assertIn("require_captured_scholarly_search_result", design.__all__)
        fixture = self.make()
        replayed = self.replay(fixture)
        self.assertEqual(replayed.plan, fixture.plan)
        self.assertEqual(replayed.result, fixture.result)
        self.assertEqual(replayed.artifact_hashes, tuple(sorted({
            fixture.goal_record.sha256, fixture.target_record.sha256,
            fixture.plan_record.sha256, fixture.result_record.sha256,
            *replayed.capture.artifact_hashes,
        })))
        self.assertFalse(any(r.logical_type == "scholarly_search_selection"
                             for r in self.registry.list_records()))
        self.assertEqual(len(fixture.transport.prepared_requests), 1)
        self.assertFalse(replayed.capture.network_used)
        self.assertEqual(replayed.capture.external_validation, "UNTESTED")
        for name in ("scholarly_sources_exhausted", "may_use_general_web", "rounds_completed"):
            self.assertFalse(hasattr(replayed, name))
        with self.assertRaises(FrozenInstanceError):
            replayed.plan = fixture.plan

    def test_zero_hits_is_only_a_bounded_page(self):
        body = json.loads(openalex_list([], per_page=2, page=1))
        body["meta"].update(count=99999, next_cursor="not-consumed")
        fixture = self.make(responses=[(200, canonical_json_bytes(body))])
        result = self.replay(fixture).result
        self.assertIs(result.status, RetrievalStatus.AVAILABLE)
        self.assertEqual(result.hits, ())
        self.assertFalse(result.scientific_evidence)

    def test_http_and_parser_failures_are_replayed_without_selection(self):
        for status, body in [(s, f"HTTP {s}".encode()) for s in (401, 403, 404, 429, 500, 503)] + [
            (200, b"not JSON"), (200, b"{}"), (200, b'{"a":1,"a":2}'),
            (200, openalex_list([], per_page=2, page=2)),
        ]:
            with self.subTest(status=status, body=body):
                fixture = self.make(responses=[(status, body)])
                replayed = self.replay(fixture)
                self.assertNotEqual(replayed.result.status, RetrievalStatus.AVAILABLE)
                self.assertEqual(replayed.result, fixture.result)
                self.assertEqual(replayed.capture.envelope.failure_reason, fixture.result.failure_reason)

    def test_unicode_round_trips_use_registry_serializer_not_semantic_bytes(self):
        for fixture_goal in (False, True):
            with self.subTest(fixture_goal=fixture_goal):
                fixture = self.make(
                    question="What does café 東京 capture?", query="café 東京",
                    fixture_goal=fixture_goal,
                    responses=[(200, openalex_list([openalex_work(title="Étude 東京")],
                                                  per_page=2, page=1))],
                )
                replayed = self.replay(fixture)
                self.assertEqual(replayed.result.hits[0].title, "Étude 東京")
                self.assertNotEqual(self.registry.get_bytes(fixture.plan_record.sha256),
                                    fixture.plan.canonical_bytes + b"\n")
                self.assertNotEqual(self.registry.get_bytes(fixture.result_record.sha256),
                                    fixture.result.canonical_bytes + b"\n")

    def test_all_declared_sources_survive_without_claiming_coverage(self):
        sources = (ScholarlySource.OPENALEX, ScholarlySource.SEMANTIC_SCHOLAR)
        fixture = self.make(allowed_sources=sources)
        self.assertEqual(self.replay(fixture).plan.allowed_sources, sources)
        self.assertEqual(fixture.gateway.configured_sources, (ScholarlySource.OPENALEX,))
        self.assertEqual(len(fixture.transport.prepared_requests), 1)

    def test_retry_custody_is_retained_for_terminal_success_and_refusal(self):
        for terminal in (200, 404):
            with self.subTest(terminal=terminal):
                last = (openalex_list([], per_page=2, page=1) if terminal == 200 else b"not found")
                fixture = self.make(responses=[(429, b"busy"), (terminal, last)], maximum_attempts=2)
                replayed = self.replay(fixture)
                receipt = json.loads(self.registry.get_bytes(replayed.capture.response_receipt_artifact_hash))
                self.assertEqual(len(receipt["attempts"]), 2)
                for attempt in receipt["attempts"]:
                    self.assertIn(attempt["raw_response_record_sha256"], replayed.artifact_hashes)

    def test_existing_scientific_capture_dispatch_remains_strict(self):
        for status, body in ((404, b"not found"), (200, b"malformed")):
            with self.subTest(status=status):
                fixture = self.make(responses=[(status, body)])
                self.replay(fixture)
                before = self.snapshot()
                with self.assertRaisesRegex(design.ScientificPromotionError, "source-owned replay"):
                    design._resolve_captured_gateway_envelope(
                        self.registry, raw_artifact_hash=fixture.result.raw_artifact_hash,
                        response_artifact_hash=fixture.result.response_artifact_hash,
                        expected_request=fixture.result.request,
                        expected_source=ScholarlySource.OPENALEX,
                        expected_request_id=fixture.result.request.request_id,
                        expected_request_payload=design._scholarly_search_request_payload(fixture.result.request),
                        response_logical_type="scholarly_search_response",
                    )
                self.assertEqual(self.snapshot(), before)

    def test_registered_plan_normalization_cannot_hide_changed_stored_bytes(self):
        mutations = (
            lambda v: v.update(query="  quantum gravity  "),
            lambda v: v.update(query="ｑuantum gravity"),
            lambda v: v["parent_artifact_hashes"].reverse(),
            lambda v: v["allowed_sources"].reverse(),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                fixture = self.make(plan_mutation=mutation,
                                    allowed_sources=(ScholarlySource.OPENALEX, ScholarlySource.SEMANTIC_SCHOLAR))
                self.refuse(fixture)

    def test_registered_result_normalization_cannot_hide_changed_stored_bytes(self):
        for mutation in (
            lambda v: v["request"].update(query=" quantum gravity "),
            lambda v: v["hits"][0].update(title=" A bounded work "),
            lambda v: v["hits"][0].update(title="Ａ bounded work"),
        ):
            with self.subTest(mutation=mutation):
                self.refuse(self.make(result_mutation=mutation))
        self.refuse(self.make(responses=[(404, b"missing")],
                              result_mutation=lambda v: v.update(failure_reason=" " + v["failure_reason"])))

    def test_goal_wrapper_and_parsed_goal_mutations_refuse(self):
        for mutation in (
            lambda v: v.update(schema_version="research-goal/unknown"),
            lambda v: v.update(extra="caller claim"),
            lambda v: v["research_goal"].update(question=" altered question "),
            lambda v: v["research_goal"].update(goal_id="another-goal"),
            lambda v: v["research_goal"].update(scope="wrong scope"),
        ):
            with self.subTest(mutation=mutation):
                self.refuse(self.make(goal_mutation=mutation))
        self.refuse(self.make(fixture_goal=True, goal_mutation=lambda v: v.update(scientific_evidence=True)))

    def test_exact_seed_target_fields_and_question_are_required(self):
        for changes in (
            {"target_statement": "unrelated question"}, {"goal_id": "another"},
            {"goal_sha256": digest("other-goal")}, {"purpose": "DISCONFIRMING"},
            {"schema_version": "scholarly-search-target/v1"}, {"extra": "claim"},
            {"contribution_id": "unearned"}, {"contribution_statement": "unearned"},
            {"reviewed_retained_set_artifact_hash": digest("retained")},
            {"scientific_evidence": True}, {"target_id": ""},
        ):
            with self.subTest(changes=changes):
                self.refuse(self.make(target_mutation=lambda v: v.update(changes)))

    def test_roles_schema_frozen_and_exact_parent_metadata_are_checked(self):
        for component in ("goal", "target", "plan", "result"):
            for overrides in (
                {"creator_role": Role.ORCHESTRATOR}, {"logical_type": "wrong_type"},
                {"frozen": False}, {"validation_result": "FAIL", "frozen": False},
                {"schema_version": "2.0"}, {"mime_type": "text/plain"},
                {"parent_artifacts": (digest("extra-parent"),)},
            ):
                with self.subTest(component=component, overrides=overrides):
                    self.refuse(self.make(metadata={component: overrides}))
        for component in ("target", "plan", "result"):
            with self.subTest(component=component, parents="missing"):
                self.refuse(self.make(metadata={component: {"parent_artifacts": ()}}))

    def test_plan_parent_set_does_not_admit_extra_context(self):
        fixture = self.make(plan_replacement=lambda p: replace(
            p, parent_artifact_hashes=(*p.parent_artifact_hashes, self.extra_record.sha256),
        ))
        self.refuse(fixture)

    def test_semantic_and_artifact_hashes_are_not_interchangeable(self):
        fixture = self.make()
        for changes in (
            {"goal_artifact_sha256": fixture.goal.sha256},
            {"plan_artifact_sha256": fixture.plan.sha256},
            {"result_artifact_sha256": digest("missing-result")},
            {"goal_artifact_sha256": fixture.target_record.sha256},
        ):
            with self.subTest(changes=changes):
                self.refuse(fixture, **changes)
        for key in ("goal_sha256", "plan_sha256", "target_sha256"):
            with self.subTest(key=key):
                value = fixture.result.to_dict()
                value["request"][key] = fixture.goal_record.sha256
                forged = self.put_like(fixture.result_record.sha256, value)
                self.refuse(fixture, result_artifact_sha256=forged.sha256)

    def test_rehashed_result_status_reason_and_hits_cannot_replace_capture(self):
        fixture = self.make()
        for mutation in (
            lambda v: v["hits"][0].update(title="different captured title"),
            lambda v: v["hits"].clear(),
            lambda v: v.update(status="NOT_FOUND", hits=[], failure_reason="invented"),
            lambda v: v.update(scientific_evidence=True),
        ):
            with self.subTest(mutation=mutation):
                value = fixture.result.to_dict()
                mutation(value)
                forged = self.put_like(fixture.result_record.sha256, value)
                self.refuse(fixture, result_artifact_sha256=forged.sha256)
        fixture = self.make(responses=[(404, b"missing")])
        value = fixture.result.to_dict()
        value.update(status="AVAILABLE", failure_reason=None)
        forged = self.put_like(fixture.result_record.sha256, value)
        self.refuse(fixture, result_artifact_sha256=forged.sha256)

    def test_response_payload_and_raw_substitutions_reach_source_refusal(self):
        fixture = self.make()
        response = json.loads(self.registry.get_bytes(fixture.result.response_artifact_hash))
        response["payload"]["results"][0]["title"] = "invented response"
        forged = self.put_like(fixture.result.response_artifact_hash, response)
        result = self.result_with_capture(fixture, response_hash=forged.sha256)
        self.refuse(fixture, result_artifact_sha256=result.sha256)
        raw = self.put_like(fixture.result.raw_artifact_hash, b"different raw response")
        result = self.result_with_capture(fixture, raw_hash=raw.sha256)
        self.refuse(fixture, result_artifact_sha256=result.sha256)

    def test_rehashed_request_artifact_is_reopened_through_receipt(self):
        fixture = self.make()
        replayed = self.replay(fixture)
        capture = replayed.capture
        request = json.loads(self.registry.get_bytes(capture.request_artifact_hash))
        request["url"] += "&page=2"
        new_request = self.put_like(capture.request_artifact_hash, request)
        receipt = json.loads(self.registry.get_bytes(capture.response_receipt_artifact_hash))
        receipt["request_artifact_sha256"] = new_request.sha256
        parents = self.registry.get_metadata(capture.response_receipt_artifact_hash).parent_artifacts
        receipt_record = self.put_like(capture.response_receipt_artifact_hash, receipt,
            parent_artifacts=tuple(new_request.sha256 if p == capture.request_artifact_hash else p for p in parents))
        response = json.loads(self.registry.get_bytes(capture.response_artifact_hash))
        response["response_receipt_artifact_hash"] = receipt_record.sha256
        parents = self.registry.get_metadata(capture.response_artifact_hash).parent_artifacts
        response_record = self.put_like(capture.response_artifact_hash, response,
            parent_artifacts=tuple(receipt_record.sha256 if p == capture.response_receipt_artifact_hash else p for p in parents))
        result = self.result_with_capture(fixture, response_hash=response_record.sha256)
        self.refuse(fixture, result_artifact_sha256=result.sha256)

    def test_disconfirming_other_sources_and_incomplete_responses_stay_unsupported(self):
        self.refuse(self.make(plan_replacement=lambda p: replace(p, purpose=ScholarlySearchPurpose.DISCONFIRMING)))
        self.refuse(self.make(allowed_sources=(ScholarlySource.SEMANTIC_SCHOLAR,), source=ScholarlySource.SEMANTIC_SCHOLAR))
        self.refuse(self.make(responses=[(302, b"redirect denied")]))
        fixture = self.make(plan_replacement=lambda p: replace(p, max_results=101))
        self.assertIs(fixture.result.status, RetrievalStatus.UNAVAILABLE)
        self.refuse(fixture)
        fixture = self.make()
        value = fixture.result.to_dict()
        value.update(status="FAILED", hits=[], raw_artifact_hash=None,
                     response_artifact_hash=None, failure_reason="no custody")
        record = self.put_like(fixture.result_record.sha256, value,
                              parent_artifacts=(fixture.plan_record.sha256,))
        self.refuse(fixture, result_artifact_sha256=record.sha256)

    def test_old_search_serialization_is_not_upgraded_in_place(self):
        fixture = self.make(query="café 東京", responses=[(200, openalex_list([], per_page=2, page=1))])
        escaped = self.put_like(fixture.plan_record.sha256, fixture.plan.canonical_bytes + b"\n")
        self.refuse(fixture, plan_artifact_sha256=escaped.sha256)

    def test_actual_exhausted_transport_is_not_a_complete_captured_response(self):
        fixture = self.make(responses=[(429, b"busy before fixture transport exhausts")],
                            maximum_attempts=2)
        self.assertIs(fixture.result.status, RetrievalStatus.FAILED)
        self.assertEqual(len(fixture.transport.prepared_requests), 1)
        response = json.loads(self.registry.get_bytes(fixture.result.response_artifact_hash))
        self.assertIsNone(response["response_receipt_artifact_hash"])
        self.refuse(fixture)

    def test_filter_hit_order_and_coherent_request_changes_do_not_rebind(self):
        filters = (ScholarlySearchFilter("open_access", "true"),
                   ScholarlySearchFilter("publication_year", "2020-2024"))
        fixture = self.make(filters=filters)
        self.assertIs(self.replay(fixture).result.status, RetrievalStatus.AVAILABLE)
        for mutation in (
            lambda v: v["filters"].reverse(),
            lambda v: v["filters"][0].update(value="false"),
            lambda v: v.update(query="different query"),
            lambda v: v.update(max_results=1),
        ):
            with self.subTest(mutation=mutation):
                self.refuse(self.make(filters=filters, plan_mutation=mutation))
        self.refuse(self.make(filters=filters,
                              result_mutation=lambda v: v["request"]["filters"].reverse()))
        fixture = self.make(
            responses=[(200, openalex_list([openalex_work(), openalex_work("W987654321")],
                                           per_page=2, page=1))],
            result_mutation=lambda v: v["hits"].reverse(),
        )
        self.refuse(fixture)

    def test_metadata_parent_reordering_keeps_existing_set_semantics(self):
        fixture = self.make(metadata={
            "plan": {"parent_artifacts": lambda parents: tuple(reversed(parents))},
            "result": {"parent_artifacts": lambda parents: tuple(reversed(parents))},
        })
        replayed = self.replay(fixture)
        self.assertEqual(replayed.plan, fixture.plan)
        self.assertEqual(replayed.result, fixture.result)
