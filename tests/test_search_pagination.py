"""Actual offline cursor producer/registry/replay controls; no live evidence."""
from __future__ import annotations

import copy
from dataclasses import asdict, replace
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import quote, parse_qs, urlsplit
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.external import EgressGateway, FixtureTransport, TransportResponse
from scientist_one.literature import (
    LiteratureError, RetrievalStatus, ScholarlySearchPlan, ScholarlySearchPlanV2,
    ScholarlySearchRequest, GatewayEnvelope, normalize_scholarly_search_page,
    ScholarlySearchPurpose, ScholarlySearchStopReason, ScholarlySource,
    derive_scholarly_search_progress, require_scholarly_search_cursor,
)
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
import scientist_one.scientific_design as design
import scientist_one.scholarly_gateway as native
from tests.test_scholarly_gateway import openalex_work


def page(ids=(), cursor=None, count=2, size=2, title="A bounded work"):
    return canonical_json_bytes({"meta": {"count": count, "per_page": size,
                                          "next_cursor": cursor},
        "results": [openalex_work(identifier, title=title) for identifier in ids], "group_by": []})


def url(query, cursor, size=2):
    return ("https://api.openalex.org/works?search=" + quote('"' + query + '"', safe="")
        + "&sort=relevance_score%3Adesc&corpus=core&per_page=" + str(size)
        + "&cursor=" + quote(cursor, safe=""))


class ObservingTransport(FixtureTransport):
    def __init__(self, responses, before_send):
        super().__init__(responses)
        self.before_send = before_send

    def send(self, request, *, credential):
        self.before_send(request)
        return super().send(request, credential=credential)


class OfflineClock:
    def __init__(self):
        self.now = 0.0
    def __call__(self):
        return self.now
    def sleep(self, duration):
        self.now += duration


class CursorSearchTests(unittest.TestCase):
    def put(self, value, logical_type, role, parents=(), **overrides):
        args = dict(logical_type=logical_type, creator_role=role, parent_artifacts=parents,
                    origin="offline cursor test", frozen=True, validation_result="PASS",
                    schema_version="1.0", mime_type="application/json")
        args.update(overrides)
        return self.registry.put_json(value, **args)

    def make(self, responses=None, *, query="quantum gravity", question="What is captured?",
             size=2, maximum=4, attempts=1, fixture=False, old_profile=False,
             goal_role=Role.PROBLEM_INVESTIGATOR, target_mutation=None, plan_mutation=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.registry = ArtifactRegistry(self.root)
        self.goal = design.ResearchGoal("cursor-search", question, "Captured pages only",
            ("No scientific authority",), ("seed-one",))
        wrapper = ({"research_goal": asdict(self.goal), "fixture_notice": "Offline only",
                    "scientific_evidence": False} if fixture else
                   {"schema_version": "research-goal/v1", "research_goal": asdict(self.goal)})
        self.goal_record = self.put(wrapper, "research_goal", goal_role)
        target = dict(schema_version="scholarly-search-target/v2", purpose="SEED",
            goal_id=self.goal.goal_id, goal_sha256=self.goal.sha256, scientific_evidence=False,
            target_id="seed-target", target_statement=self.goal.question, contribution_id=None,
            contribution_statement=None, reviewed_retained_set_artifact_hash=None)
        if target_mutation:
            target_mutation(target)
        self.target_record = self.put(target, "scholarly_search_target", Role.PROBLEM_INVESTIGATOR,
                                       (self.goal_record.sha256,))
        responses = responses or [(200, page(("W1",), "next"), "*")]
        self.visible_before_send = []
        self.transport = ObservingTransport(tuple(TransportResponse(
            status, (("Content-Type", "application/json"),), body, url(query, cursor, size))
            for status, body, cursor in responses), self.before_send)
        policy_factory = (native.openalex_scholarly_egress_policy if old_profile
                          else native.openalex_cursor_scholarly_egress_policy)
        self.clock = OfflineClock()
        self.gateway = native.SourceOwnedScholarlyGateway(openalex_gateway=EgressGateway(
            policy_factory(minimum_interval_seconds=0, maximum_attempts=attempts),
            self.transport, registry=self.registry,
            clock=self.clock, sleeper=self.clock.sleep,
            timestamp=lambda: "2026-09-13T20:00:00.000000Z"))
        self.route = self.gateway.route_authority_artifact(ScholarlySource.OPENALEX)
        self.plan = ScholarlySearchPlanV2(ScholarlySearchPurpose.SEED, self.goal.goal_id,
            self.goal.sha256, self.target_record.sha256, query, (), (),
            (ScholarlySource.OPENALEX, ScholarlySource.SEMANTIC_SCHOLAR), size, maximum,
            (self.goal_record.sha256, self.target_record.sha256, self.route.sha256))
        value = self.plan.to_dict()
        if plan_mutation:
            plan_mutation(value)
        self.plan_record = self.put(value, "scholarly_search_plan", Role.PROBLEM_INVESTIGATOR,
                                    self.plan.parent_artifact_hashes)
        return self

    def before_send(self, request):
        records = self.registry.list_records()
        matches = [record for record in records if record.logical_type == "external_request"
                   and json.loads(self.registry.get_bytes(record.sha256))["request_id"] == request.request_id]
        self.assertEqual(len(matches), 1)
        intent = matches[0]
        self.assertEqual(intent.parent_artifacts[:2], (self.route.sha256, self.plan_record.sha256))
        if len(intent.parent_artifacts) == 3:
            previous = intent.parent_artifacts[2]
            replay = self.replay(previous)
            self.assertIsNotNone(replay.progress.next_request)
            self.assertEqual(replay.progress.next_request.cursor,
                             parse_qs(urlsplit(request.url).query)["cursor"][0])
        self.visible_before_send.append(intent.parent_artifacts)

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes()
                for p in self.root.rglob("*") if p.is_file()}

    def replay(self, digest, **overrides):
        args = dict(goal_artifact_sha256=self.goal_record.sha256,
                    plan_artifact_sha256=self.plan_record.sha256, result_artifact_sha256=digest)
        args.update(overrides)
        before = self.snapshot()
        try:
            return design.require_captured_scholarly_search_result_v2(self.registry, **args)
        finally:
            self.assertEqual(self.snapshot(), before)

    def acquire(self, previous=None):
        return design.acquire_next_scholarly_search_page(self.registry, self.gateway,
            goal_artifact_sha256=self.goal_record.sha256, plan_artifact_sha256=self.plan_record.sha256,
            previous_result_artifact_sha256=previous)

    def clone(self, digest, mutate, *, parents=None, **overrides):
        metadata = self.registry.get_metadata(digest)
        value = json.loads(self.registry.get_bytes(digest))
        mutate(value)
        args = dict(logical_type=metadata.logical_type, origin=metadata.origin,
                    creator_role=metadata.creator_role, creation_command=metadata.creation_command,
                    schema_version=metadata.schema_version, mime_type=metadata.mime_type,
                    frozen=metadata.frozen, validation_result=metadata.validation_result,
                    parent_artifacts=metadata.parent_artifacts if parents is None else parents)
        args.update(overrides)
        return self.registry.put_json(value, **args)

    def test_two_page_terminal_and_exact_predecessor_visibility(self):
        self.make([(200, page(("W1",), "next"), "*"), (200, page(), "next")])
        first = self.acquire()
        second = self.acquire(first.progress.result_artifact_hashes[-1])
        self.assertEqual(second.progress.stop_reason, ScholarlySearchStopReason.PROVIDER_TERMINAL_OBSERVED)
        self.assertEqual(second.progress.captured_hit_count, 1)
        self.assertEqual(second.observed_http_attempts, 2)
        self.assertEqual(len(self.visible_before_send), 2)
        self.assertEqual(len(self.visible_before_send[1]), 3)
        self.assertIsNone(second.progress.next_request)
        self.assertEqual(second.plan.allowed_sources,
                         (ScholarlySource.OPENALEX, ScholarlySource.SEMANTIC_SCHOLAR))

    def test_empty_nonnull_continues_and_final_empty_consumes_slot(self):
        self.make([(200, page(cursor="next"), "*"), (200, page(), "next")], maximum=2)
        first = self.acquire()
        final = self.acquire(first.progress.result_artifact_hashes[-1])
        self.assertEqual(len(final.progress.pages), 2)
        self.assertEqual(final.progress.stop_reason, ScholarlySearchStopReason.PROVIDER_TERMINAL_OBSERVED)
        with self.assertRaises(design.ScientificPromotionError):
            self.acquire(final.progress.result_artifact_hashes[-1])
        self.assertEqual(len(self.transport.sent_request_ids), 2)

    def test_nonterminal_budget_is_truncation(self):
        self.make(maximum=1)
        replay = self.acquire()
        self.assertEqual(replay.progress.stop_reason, ScholarlySearchStopReason.PAGE_BUDGET_TRUNCATED)
        self.assertIsNone(replay.progress.next_request)

    def test_http_negative_statuses_are_captured_not_terminal(self):
        for status in (100, 199, 401, 403, 404, 429, 500, 502, 503, 504, 599):
            with self.subTest(status=status):
                self.make([(status, b'{"error":"bounded"}', "*")], maximum=1)
                result = self.acquire()
                observed = result.progress.pages[0]
                self.assertNotEqual(observed.status, RetrievalStatus.AVAILABLE)
                self.assertIsNone(observed.reported_count)
                self.assertIsNone(observed.reported_page_size)
                self.assertEqual(result.progress.stop_reason, ScholarlySearchStopReason.CAPTURED_FAILURE)

    def test_malformed_parser_outcomes_preserve_custody(self):
        good = json.loads(page())
        bodies = [b"not JSON", page(("W1", "W1"), "next"), page(count=True), page(size=1),
                  page(cursor=""), page(cursor="bad\n"), page(cursor="x" * 1025)]
        for field in ("count", "per_page", "next_cursor"):
            changed = copy.deepcopy(good)
            del changed["meta"][field]
            bodies.append(canonical_json_bytes(changed))
        for body in bodies:
            with self.subTest(body=body[:60]):
                self.make([(200, body, "*")])
                replay = self.acquire()
                self.assertEqual(replay.progress.pages[0].status, RetrievalStatus.MALFORMED)
                self.assertIsNotNone(replay.progress.pages[0].raw_artifact_hash)
                self.assertIsNone(replay.progress.pages[0].reported_count)

    def test_cross_page_anomalies_retain_hits_and_stop(self):
        cases = [(page(("W1",), "later"), "CROSS_PAGE_WORK_OVERLAP"),
                 (page(("W2",), "later", count=3), "REPORTED_COUNT_DRIFT"),
                 (page(("W2",), "next"), "CURSOR_CYCLE"),
                 (page(("W2",), None), "NONEMPTY_NULL_CURSOR")]
        for body, anomaly in cases:
            with self.subTest(anomaly=anomaly):
                self.make([(200, page(("W1",), "next"), "*"), (200, body, "next")])
                first = self.acquire()
                final = self.acquire(first.progress.result_artifact_hashes[-1])
                self.assertIn(anomaly, final.progress.anomalies)
                self.assertEqual(final.progress.captured_hit_count, 2)
                self.assertIsNone(final.progress.next_request)
                with self.assertRaises(design.ScientificPromotionError):
                    self.acquire(final.progress.result_artifact_hashes[-1])
                self.assertEqual(len(self.transport.sent_request_ids), 2)

    def test_initial_cursor_cycle_and_nonempty_null_are_anomalies(self):
        for body, anomaly in ((page(cursor="*"), "CURSOR_CYCLE"),
                              (page(("W1",)), "NONEMPTY_NULL_CURSOR")):
            self.make([(200, body, "*")])
            self.assertIn(anomaly, self.acquire().progress.anomalies)

    def test_unicode_goal_query_title_and_opaque_cursor(self):
        token = "  e\u0301 Ａ＋/漢字==  "
        self.make([(200, page(("W1",), token, title="Café 漢字"), "*"),
                   (200, page(), token)], query="évidence 漢字", question="Quelle évidence — 漢字?", fixture=True)
        first = self.acquire()
        self.assertEqual(first.progress.next_request.cursor, token)
        self.assertEqual(first.progress.pages[0].hits[0].title, "Café 漢字")
        final = self.acquire(first.progress.result_artifact_hashes[-1])
        self.assertEqual(final.progress.pages[1].request.cursor, token)
        self.assertNotEqual(self.plan.canonical_bytes + b"\n", self.registry.get_bytes(self.plan_record.sha256))

    def test_cursor_byte_control_and_url_bounds(self):
        self.assertEqual(require_scholarly_search_cursor("é" * 512), "é" * 512)
        for token in ("", "é" * 513, "x\x7f", "\x00", "\ud800"):
            with self.assertRaises(LiteratureError):
                require_scholarly_search_cursor(token)
        self.make(query="x" * 4000)
        with self.assertRaises(design.ScientificPromotionError):
            self.acquire()
        self.assertFalse(self.transport.sent_request_ids)

    def test_plan_bounds_and_independent_schema_types(self):
        self.make()
        self.assertFalse(isinstance(self.plan, ScholarlySearchPlan))
        self.assertNotIn("cursor", asdict(self.plan))
        for size, maximum in ((0, 1), (101, 1), (1, 0), (1, 17), (100, 6), (True, 1)):
            with self.assertRaises(LiteratureError):
                replace(self.plan, page_size=size, max_page_requests=maximum)
        self.assertEqual(replace(self.plan, page_size=32, max_page_requests=16).page_size, 32)
        with self.assertRaises(LiteratureError):
            ScholarlySearchPlan.from_dict(self.plan.to_dict())

    def test_both_profile_mismatches_refuse_before_send(self):
        self.make(old_profile=True)
        req = derive_scholarly_search_progress(self.plan, plan_artifact_hash=self.plan_record.sha256,
            source=ScholarlySource.OPENALEX, checkpoints=()).next_request
        self.assertNotEqual(self.gateway.fetch(req).status, RetrievalStatus.AVAILABLE)
        self.assertFalse(self.transport.sent_request_ids)
        self.make()
        old = ScholarlySearchRequest(self.plan.sha256, self.plan.purpose, self.plan.goal_sha256,
            self.plan.target_sha256, ScholarlySource.OPENALEX, self.plan.query, (), (), 2)
        self.assertNotEqual(self.gateway.fetch(old).status, RetrievalStatus.AVAILABLE)
        self.assertFalse(self.transport.sent_request_ids)

    def test_old_capture_readers_refuse_native_v4(self):
        self.make()
        result = self.acquire().progress.pages[0]
        for reader in (native.require_available_scholarly_native_capture,
                       native.require_captured_scholarly_search_response):
            with self.assertRaises(native.ScholarlyGatewayError):
                reader(self.registry, request=result.request, raw_artifact_sha256=result.raw_artifact_hash,
                       response_artifact_sha256=result.response_artifact_hash)

    def test_checkpoint_publication_failure_cannot_send_next(self):
        self.make([(200, page(("W1",), "next"), "*"), (200, page(), "next")])
        put = self.registry.put_json
        def fail_checkpoint(value, **metadata):
            if metadata["logical_type"] == "scholarly_search_result":
                raise RuntimeError("checkpoint publication failed")
            return put(value, **metadata)
        with patch.object(self.registry, "put_json", side_effect=fail_checkpoint):
            with self.assertRaisesRegex(RuntimeError, "publication"):
                self.acquire()
        self.assertEqual(len(self.transport.sent_request_ids), 1)
        self.assertTrue(any(r.logical_type == "scholarly_search_response" for r in self.registry.list_records()))
        self.assertFalse(any(r.logical_type == "scholarly_search_result" for r in self.registry.list_records()))

    def test_restart_and_partition_equivalence(self):
        self.make([(200, page(("W1",), "next"), "*"), (200, page(), "next")])
        first = self.acquire()
        first_hash = first.progress.result_artifact_hashes[-1]
        self.assertEqual(self.replay(first_hash), first)
        # Reopen registry and gateway with identical route policy after restart.
        self.registry = ArtifactRegistry(self.root)
        self.transport = ObservingTransport((TransportResponse(200, (("Content-Type", "application/json"),),
            page(), url(self.plan.query, "next")),), self.before_send)
        self.gateway = native.SourceOwnedScholarlyGateway(openalex_gateway=EgressGateway(
            native.openalex_cursor_scholarly_egress_policy(minimum_interval_seconds=0, maximum_attempts=1),
            self.transport, registry=self.registry, clock=self.clock, sleeper=self.clock.sleep,
            timestamp=lambda: "2026-09-13T20:00:00.000000Z"))
        final = self.acquire(first_hash)
        self.assertEqual(self.replay(final.progress.result_artifact_hashes[-1]), final)
        self.assertEqual(final.progress.pages[0], first.progress.pages[0])
        self.assertEqual(final.observed_http_attempts, 2)

    def test_attempt_and_byte_multiplicity_for_identical_raw_bodies(self):
        body = page(cursor="next")
        self.make([(503, body, "*"), (200, body, "*")], attempts=2)
        result = self.acquire()
        self.assertEqual(result.observed_http_attempts, 2)
        self.assertEqual(result.observed_response_bytes, 2 * len(body))
        self.assertEqual(result.observed_request_bytes, 0)
        raw_records = [r for r in self.registry.list_records() if r.logical_type == "external_response_raw"]
        self.assertEqual(len(raw_records), 1)

    def test_registered_goal_target_and_normalized_plan_fail_before_send(self):
        cases = [dict(goal_role=Role.ORCHESTRATOR),
                 dict(target_mutation=lambda v: v.update(target_statement="Different question")),
                 dict(target_mutation=lambda v: v.update(purpose="DISCONFIRMING")),
                 dict(target_mutation=lambda v: v.update(contribution_id="claim")),
                 dict(plan_mutation=lambda v: v.update(query=" quantum gravity ")),
                 dict(plan_mutation=lambda v: v.update(goal_sha256="1" * 64))]
        for changes in cases:
            with self.subTest(changes=changes):
                self.make(**changes)
                before = self.snapshot()
                with self.assertRaises(design.ScientificPromotionError):
                    self.acquire()
                self.assertFalse(self.transport.sent_request_ids)
                self.assertEqual(self.snapshot(), before)

    def test_rehashed_result_mutations_refuse_without_writes(self):
        mutations = [lambda v: v.update(reported_count=91), lambda v: v.update(next_cursor="stolen"),
            lambda v: v.update(scientific_evidence=True), lambda v: v["hits"][0].update(title="Changed"),
            lambda v: v["hits"][0].update(title=" A bounded work "),
            lambda v: v["request"].update(plan_sha256=self.plan_record.sha256),
            lambda v: v["request"].update(plan_artifact_hash=self.plan.sha256),
            lambda v: v["request"].update(cursor="other"),
            lambda v: v.update(status="NOT_FOUND", hits=[], failure_reason="forged")]
        self.make()
        result = self.acquire()
        digest = result.progress.result_artifact_hashes[-1]
        for mutation in mutations:
            changed = self.clone(digest, mutation)
            with self.assertRaises((design.ScientificPromotionError, LiteratureError)):
                self.replay(changed.sha256)

    def test_extra_missing_result_parents_and_wrong_roles_refuse(self):
        self.make()
        result = self.acquire()
        digest = result.progress.result_artifact_hashes[-1]
        parents = self.registry.get_metadata(digest).parent_artifacts
        for index, proposed in enumerate((parents[:-1], (*parents, self.goal_record.sha256))):
            changed = self.clone(digest, lambda v: v.update(reported_count=19 + index), parents=proposed)
            with self.assertRaises(design.ScientificPromotionError):
                self.replay(changed.sha256)
        changed = self.clone(digest, lambda v: v.update(reported_count=21), creator_role=Role.ORCHESTRATOR)
        with self.assertRaises(design.ScientificPromotionError):
            self.replay(changed.sha256)

    def test_coherent_query_request_substitution_cannot_bypass_plan(self):
        self.make()
        result = self.acquire()
        original = result.progress.pages[0]
        request = replace(original.request, query="different query")
        changed = self.clone(result.progress.result_artifact_hashes[-1],
                             lambda v: v.update(request=request.to_dict()))
        with self.assertRaises(design.ScientificPromotionError):
            self.replay(changed.sha256)
        with self.assertRaises(design.ScientificPromotionError):
            self.gateway.fetch(request)
        self.assertEqual(len(self.transport.sent_request_ids), 1)

    def test_wrong_predecessor_cursor_and_page_order_cannot_send(self):
        self.make()
        first = self.acquire()
        request = first.progress.next_request
        for changed in (replace(request, cursor="unrelated"), replace(request, page_number=3)):
            with self.assertRaises(design.ScientificPromotionError):
                self.gateway.fetch(changed)
        self.assertEqual(len(self.transport.sent_request_ids), 1)

    def test_inspected_closure_contains_every_registered_page_custody(self):
        self.make([(200, page(("W1",), "next"), "*"), (200, page(), "next")])
        first = self.acquire()
        final = self.acquire(first.progress.result_artifact_hashes[-1])
        expected = {r.sha256 for r in self.registry.list_records()}
        self.assertEqual(set(final.artifact_hashes), expected)
        self.assertEqual(len(final.artifact_hashes), len(set(final.artifact_hashes)))

    def test_redirect_and_missing_transport_custody_never_checkpoint(self):
        self.make([(302, b"redirect", "*")])
        with self.assertRaises(design.ScientificPromotionError):
            self.acquire()
        self.assertFalse(any(r.logical_type == "scholarly_search_result" for r in self.registry.list_records()))
        self.make()
        self.transport._position = 1
        with self.assertRaises(design.ScientificPromotionError):
            self.acquire()
        self.assertFalse(any(r.logical_type == "scholarly_search_result" for r in self.registry.list_records()))

    def rewrite_capture(self, replay, *, response_mutation=None, receipt_mutation=None,
                        request_mutation=None, request_parents=None, raw_mutation=None):
        """Rehash the affected registered DAG, preserving unrelated metadata."""
        result = replay.progress.pages[-1]
        capture = replay.captures[-1]
        raw_hash = capture.raw_artifact_hash
        if raw_mutation:
            raw = raw_mutation(self.registry.get_bytes(raw_hash))
            metadata = self.registry.get_metadata(raw_hash)
            raw_hash = self.registry.put_bytes(raw, logical_type=metadata.logical_type,
                origin=metadata.origin, creator_role=metadata.creator_role,
                creation_command=metadata.creation_command).sha256
        request_hash = capture.request_artifact_hash
        if request_mutation:
            request_hash = self.clone(request_hash, request_mutation, parents=request_parents).sha256
        replacements = {capture.raw_artifact_hash: raw_hash, capture.request_artifact_hash: request_hash}
        def substitute(value):
            if isinstance(value, dict):
                return {key: substitute(item) for key, item in value.items()}
            if isinstance(value, list):
                return [substitute(item) for item in value]
            return replacements.get(value, value) if isinstance(value, str) else value
        receipt_hash = capture.response_receipt_artifact_hash
        if raw_mutation or request_mutation or receipt_mutation:
            metadata = self.registry.get_metadata(receipt_hash)
            def change_receipt(value):
                rewritten = substitute(value)
                value.clear()
                value.update(rewritten)
                if receipt_mutation:
                    receipt_mutation(value)
            receipt_hash = self.clone(receipt_hash, change_receipt,
                parents=tuple(replacements.get(p, p) for p in metadata.parent_artifacts)).sha256
        replacements[capture.response_receipt_artifact_hash] = receipt_hash
        def change_response(value):
            rewritten = substitute(value)
            value.clear()
            value.update(rewritten)
            if response_mutation:
                response_mutation(value)
        metadata = self.registry.get_metadata(capture.response_artifact_hash)
        response = self.clone(capture.response_artifact_hash, change_response,
            parents=tuple(replacements.get(p, p) for p in metadata.parent_artifacts))
        rewritten_result = replace(result, raw_artifact_hash=raw_hash, response_artifact_hash=response.sha256)
        record = self.put(rewritten_result.to_dict(), "scholarly_search_result", Role.EVIDENCE_CURATOR,
                          rewritten_result.parent_artifact_hashes)
        return record.sha256

    def test_coherently_rehashed_raw_normalized_and_receipt_mismatches(self):
        changes = [dict(raw_mutation=lambda b: b.replace(b'"count":2', b'"count":9')),
            dict(response_mutation=lambda v: v["payload"].update(reported_count=9)),
            dict(response_mutation=lambda v: v.update(schema_version="scholarly-native-response/v2")),
            dict(response_mutation=lambda v: v.update(network_used=True)),
            dict(response_mutation=lambda v: v.update(failure_reason="invented")),
            dict(receipt_mutation=lambda v: v.update(status_code=404)),
            dict(receipt_mutation=lambda v: v["egress_budget"].update(response_bytes_used=0)),
            dict(request_mutation=lambda v: v.update(url=v["url"].replace("corpus=core", "corpus=all")))]
        for change in changes:
            with self.subTest(change=change):
                self.make()
                replay = self.acquire()
                changed = self.rewrite_capture(replay, **change)
                with self.assertRaises(design.ScientificPromotionError):
                    self.replay(changed)

    def test_coherent_route_only_request_downgrade_refuses(self):
        self.make()
        replay = self.acquire()
        changed = self.rewrite_capture(replay,
            request_mutation=lambda v: v.update(parent_artifacts=[self.route.sha256]),
            request_parents=(self.route.sha256,))
        with self.assertRaises(design.ScientificPromotionError):
            self.replay(changed)

    def test_negative_status_failure_code_and_reason_are_source_derived(self):
        for field, replacement in (("retrieval_status", "AVAILABLE"),
                                   ("failure_code", "MALFORMED_RESPONSE"),
                                   ("failure_reason", "invented refusal")):
            self.make([(404, b"not found", "*")])
            replay = self.acquire()
            changed = self.rewrite_capture(replay,
                response_mutation=lambda v: v.update({field: replacement}))
            with self.assertRaises(design.ScientificPromotionError):
                self.replay(changed)

    def test_stale_page_and_unregistered_semantic_predecessor_refuse(self):
        self.make([(200, page(("W1",), "next"), "*"), (200, page(), "next")])
        first = self.acquire()
        second = self.acquire(first.progress.result_artifact_hashes[-1])
        changed = self.clone(second.progress.result_artifact_hashes[-1],
            lambda v: v.update(request=first.progress.pages[0].request.to_dict()))
        with self.assertRaises(design.ScientificPromotionError):
            self.replay(changed.sha256)
        request = replace(first.progress.next_request,
            previous_result_artifact_hash=first.progress.pages[0].sha256)
        with self.assertRaises(design.ScientificPromotionError):
            self.gateway.fetch(request)
        self.assertEqual(len(self.transport.sent_request_ids), 2)

    def test_hit_order_and_nfkc_cannot_change_registered_bytes(self):
        for mutation in (lambda v: v["hits"].reverse(),
                         lambda v: v["hits"][0].update(title="Ａ bounded work")):
            self.make([(200, page(("W1", "W2"), "next"), "*")])
            replay = self.acquire()
            changed = self.clone(replay.progress.result_artifact_hashes[-1], mutation)
            with self.assertRaises(design.ScientificPromotionError):
                self.replay(changed.sha256)

    def test_complete_chain_partition_has_exact_artifact_equivalence(self):
        responses = [(200, page(("W1",), "next"), "*"), (200, page(), "next")]
        self.make(responses)
        first = self.acquire()
        uninterrupted = self.acquire(first.progress.result_artifact_hashes[-1])
        self.make(responses)
        first = self.acquire()
        # Explicit interruption/reopen changes no selected prefix or byte identity.
        self.registry = ArtifactRegistry(self.root)
        self.gateway = native.SourceOwnedScholarlyGateway(openalex_gateway=EgressGateway(
            native.openalex_cursor_scholarly_egress_policy(minimum_interval_seconds=0, maximum_attempts=1),
            self.transport, registry=self.registry, clock=self.clock, sleeper=self.clock.sleep,
            timestamp=lambda: "2026-09-13T20:00:00.000000Z"))
        resumed = self.acquire(first.progress.result_artifact_hashes[-1])
        self.assertEqual(resumed, uninterrupted)
        self.assertEqual(resumed.artifact_hashes, uninterrupted.artifact_hashes)

    def test_literal_sixteen_page_ceiling_and_iterative_prefix(self):
        responses = [(200, page(cursor="p" + str(i + 1), count=0, size=1),
                      "*" if i == 1 else "p" + str(i)) for i in range(1, 9)]
        self.make(responses, maximum=16, size=1)
        previous = None
        for ordinal in range(1, 17):
            if ordinal == 9:
                self.transport = ObservingTransport(tuple(TransportResponse(200,
                    (("Content-Type", "application/json"),),
                    page(cursor="p" + str(i + 1) if i < 16 else None, count=0, size=1),
                    url(self.plan.query, "p" + str(i), 1)) for i in range(9, 17)), self.before_send)
                self.gateway = native.SourceOwnedScholarlyGateway(openalex_gateway=EgressGateway(
                    native.openalex_cursor_scholarly_egress_policy(minimum_interval_seconds=0, maximum_attempts=1),
                    self.transport, registry=self.registry, clock=self.clock, sleeper=self.clock.sleep,
                    timestamp=lambda: "2026-09-13T20:00:00.000000Z"))
            replay = self.acquire(previous)
            previous = replay.progress.result_artifact_hashes[-1]
            self.assertEqual(len(replay.progress.pages), ordinal)
        self.assertEqual(replay.observed_http_attempts, 16)
        self.assertEqual(replay.progress.stop_reason, ScholarlySearchStopReason.PROVIDER_TERMINAL_OBSERVED)
        self.assertEqual(self.replay(previous), replay)
        self.assertEqual(len(self.visible_before_send), 16)
        with self.assertRaises(design.ScientificPromotionError):
            self.acquire(previous)
        self.assertEqual(len(self.visible_before_send), 16)

    def sized_page_body(self, request, wanted_bytes, *, character="X"):
        """Construct raw test data whose derived registry checkpoint has exact size.

        Placeholder custody digests have the same fixed width as real captured
        hashes. This sizing preview is not used as replay or publication evidence.
        Every assertion below runs the actual gateway and registered reader.
        """
        titles = ["X"] * 5
        def predicted_result():
            payload = {"results": [{"identifier_kind": "openalex", "identifier": "W" + str(i + 1),
                                    "title": title} for i, title in enumerate(titles)],
                       "next_cursor": "later", "reported_count": 5, "reported_page_size": 5}
            return normalize_scholarly_search_page(request, GatewayEnvelope(
                ScholarlySource.OPENALEX, request.request_id, RetrievalStatus.AVAILABLE,
                payload, "a" * 64, "b" * 64))
        initial = len(canonical_json_bytes(predicted_result().to_dict()) + b"\n")
        extra = wanted_bytes - initial
        self.assertGreater(extra, 0)
        width = len(character.encode("utf-8"))
        for index in range(5):
            allocated = extra // 5 + (index < extra % 5)
            titles[index] += character * (allocated // width) + "X" * (allocated % width)
        self.assertEqual(len(canonical_json_bytes(predicted_result().to_dict()) + b"\n"), wanted_bytes)
        return canonical_json_bytes({
            "meta": {"count": 5, "per_page": 5, "next_cursor": "later"},
            "results": [openalex_work("W" + str(i + 1), title=title)
                        for i, title in enumerate(titles)], "group_by": [],
        })

    def first_request(self):
        return derive_scholarly_search_progress(self.plan,
            plan_artifact_hash=self.plan_record.sha256, source=ScholarlySource.OPENALEX,
            checkpoints=()).next_request

    def set_next_response(self, body, cursor="*", *, status=200):
        self.transport._responses = (TransportResponse(status,
            (("Content-Type", "application/json"),), body,
            url(self.plan.query, cursor, self.plan.page_size)),)
        self.transport._position = 0

    def replay_unpublished_page(self, request):
        matches = [record for record in self.registry.list_records()
                   if record.logical_type == "scholarly_search_response"
                   and json.loads(self.registry.get_bytes(record.sha256))["scholarly_request_id"] == request.request_id]
        self.assertEqual(len(matches), 1)
        response = matches[0]
        value = json.loads(self.registry.get_bytes(response.sha256))
        local = native.require_captured_scholarly_search_page_response(self.registry,
            request=request, raw_artifact_sha256=value["raw_artifact_hash"],
            response_artifact_sha256=response.sha256)
        self.assertEqual(local.envelope.status, RetrievalStatus.AVAILABLE)
        return normalize_scholarly_search_page(request, local.envelope)

    def assert_exact_publication_boundary(self, size, *, character="X", accepted=True):
        self.make(size=5)
        request = self.first_request()
        raw = self.sized_page_body(request, size, character=character)
        self.assertLess(len(raw), 8 * 1024 * 1024)
        self.set_next_response(raw)
        original_put = self.registry.put_json
        publications = []
        def observe_publication(value, **metadata):
            if metadata["logical_type"] == "scholarly_search_result":
                publications.append(len(canonical_json_bytes(value) + b"\n"))
            return original_put(value, **metadata)
        with patch.object(self.registry, "put_json", side_effect=observe_publication):
            if accepted:
                replay = self.acquire()
            else:
                with self.assertRaisesRegex(design.ScientificPromotionError,
                        "^cursor checkpoint exceeds the registered reader byte limit$"):
                    self.acquire()
        self.assertEqual(len(self.transport.sent_request_ids), 1)
        records = [record for record in self.registry.list_records()
                   if record.logical_type == "scholarly_search_result"]
        if accepted:
            self.assertEqual(publications, [size])
            self.assertEqual(len(records), 1)
            self.assertEqual(len(self.registry.get_bytes(records[0].sha256)), size)
            self.assertEqual(self.replay(records[0].sha256), replay)
            return replay.progress.pages[0]
        self.assertEqual(publications, [])
        self.assertEqual(records, [])
        result = self.replay_unpublished_page(request)
        self.assertEqual(len(canonical_json_bytes(result.to_dict()) + b"\n"), size)
        return result

    def test_checkpoint_reader_cap_minus_one_publishes_and_replays(self):
        self.assert_exact_publication_boundary(4 * 1024 * 1024 - 1)

    def test_checkpoint_reader_exact_cap_including_newline_publishes_and_replays(self):
        self.assert_exact_publication_boundary(4 * 1024 * 1024)

    def test_checkpoint_reader_cap_plus_one_refuses_before_publication(self):
        self.assert_exact_publication_boundary(4 * 1024 * 1024 + 1, accepted=False)

    def test_checkpoint_limit_uses_utf8_registry_not_ascii_semantic_bytes(self):
        result = self.assert_exact_publication_boundary(4 * 1024 * 1024, character="é")
        self.assertGreater(len(result.canonical_bytes + b"\n"), 4 * 1024 * 1024)
        self.assertEqual(len(canonical_json_bytes(result.to_dict()) + b"\n"), 4 * 1024 * 1024)

    def test_large_raw_http_error_keeps_small_true_failure_checkpoint(self):
        raw = canonical_json_bytes({"error": "E" * (4 * 1024 * 1024)})
        self.make([(404, raw, "*")])
        replay = self.acquire()
        result = replay.progress.pages[0]
        self.assertEqual(result.status, RetrievalStatus.NOT_FOUND)
        self.assertIsNone(result.reported_count)
        self.assertEqual(replay.progress.stop_reason, ScholarlySearchStopReason.CAPTURED_FAILURE)
        self.assertGreater(len(self.registry.get_bytes(result.raw_artifact_hash)), 4 * 1024 * 1024)
        self.assertLess(len(self.registry.get_bytes(replay.progress.result_artifact_hashes[0])), 4096)
        self.assertEqual(self.replay(replay.progress.result_artifact_hashes[0]), replay)

    def test_large_raw_ignored_field_keeps_small_available_checkpoint(self):
        value = json.loads(page())
        value["ignored_provider_extension"] = "I" * (4 * 1024 * 1024)
        self.make([(200, canonical_json_bytes(value), "*")])
        replay = self.acquire()
        result = replay.progress.pages[0]
        self.assertEqual(result.status, RetrievalStatus.AVAILABLE)
        self.assertEqual(replay.progress.stop_reason, ScholarlySearchStopReason.PROVIDER_TERMINAL_OBSERVED)
        self.assertGreater(len(self.registry.get_bytes(result.raw_artifact_hash)), 4 * 1024 * 1024)
        self.assertLess(len(self.registry.get_bytes(replay.progress.result_artifact_hashes[0])), 4096)
        self.assertEqual(self.replay(replay.progress.result_artifact_hashes[0]), replay)

    def test_oversize_later_page_preserves_prior_and_complete_new_capture(self):
        self.make([(200, page(("W999",), "next", count=5, size=5), "*")], size=5)
        first = self.acquire()
        first_hash = first.progress.result_artifact_hashes[0]
        prior = self.snapshot()
        request = first.progress.next_request
        raw = self.sized_page_body(request, 4 * 1024 * 1024 + 1)
        self.set_next_response(raw, request.cursor)
        original_put = self.registry.put_json
        publications = []
        def observe_publication(value, **metadata):
            if metadata["logical_type"] == "scholarly_search_result":
                publications.append(value)
            return original_put(value, **metadata)
        with patch.object(self.registry, "put_json", side_effect=observe_publication):
            with self.assertRaisesRegex(design.ScientificPromotionError,
                    "^cursor checkpoint exceeds the registered reader byte limit$"):
                self.acquire(first_hash)
        self.assertEqual(publications, [])
        self.assertEqual(len(self.visible_before_send), 2)
        after = self.snapshot()
        self.assertTrue(all(after.get(path) == content for path, content in prior.items()))
        records = self.registry.list_records()
        self.assertEqual([record.sha256 for record in records
                          if record.logical_type == "scholarly_search_result"], [first_hash])
        self.assertEqual(len([record for record in records
                              if record.logical_type == "scholarly_search_response"]), 2)
        unpublished = self.replay_unpublished_page(request)
        self.assertEqual(len(unpublished.hits), 5)
        self.assertEqual(len(canonical_json_bytes(unpublished.to_dict()) + b"\n"), 4 * 1024 * 1024 + 1)
        self.assertEqual(self.replay(first_hash), first)
        self.assertEqual(first.observed_http_attempts, 1)  # No invented global charge.


if __name__ == "__main__":
    unittest.main()
