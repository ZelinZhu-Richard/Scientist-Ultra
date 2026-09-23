"""Offline recovery publication: real captures, no subsequent acquisition I/O."""
from __future__ import annotations

from dataclasses import replace
import json
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.literature import RetrievalStatus, ScholarlySearchStopReason
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
import scientist_one.scientific_design as design
import scientist_one.scholarly_gateway as native
from tests import test_search_pagination as fixtures


class CapturedPagePublicationTests(unittest.TestCase):
    # Reuse the installed fixture construction/custody helpers, not its 36 tests.
    put = fixtures.CursorSearchTests.put
    make = fixtures.CursorSearchTests.make
    before_send = fixtures.CursorSearchTests.before_send
    snapshot = fixtures.CursorSearchTests.snapshot
    replay = fixtures.CursorSearchTests.replay
    acquire = fixtures.CursorSearchTests.acquire
    clone = fixtures.CursorSearchTests.clone
    rewrite_capture = fixtures.CursorSearchTests.rewrite_capture
    first_request = fixtures.CursorSearchTests.first_request
    sized_page_body = fixtures.CursorSearchTests.sized_page_body
    set_next_response = fixtures.CursorSearchTests.set_next_response

    def capture(self, previous=None):
        request = (self.first_request() if previous is None
                   else self.replay(previous).progress.next_request)
        self.assertIsNotNone(request)
        captured = self.gateway.fetch(request)
        self.assertIsNotNone(captured.raw_artifact_hash)
        self.assertIsNotNone(captured.response_artifact_hash)
        return captured

    def publish(self, captured, previous=None, **overrides):
        arguments = dict(goal_artifact_sha256=self.goal_record.sha256,
            plan_artifact_sha256=self.plan_record.sha256,
            raw_artifact_sha256=captured.raw_artifact_hash,
            response_artifact_sha256=captured.response_artifact_hash,
            previous_result_artifact_sha256=previous)
        arguments.update(overrides)
        sent = tuple(self.transport.sent_request_ids)
        with patch.object(native.SourceOwnedScholarlyGateway, "fetch",
                          side_effect=AssertionError("publication attempted acquisition")):
            try:
                return design.publish_captured_scholarly_search_page(self.registry, **arguments)
            finally:
                self.assertEqual(tuple(self.transport.sent_request_ids), sent)

    def assert_refused_without_writes(self, captured, previous=None, **overrides):
        before = self.snapshot()
        with self.assertRaises(design.ScientificPromotionError):
            self.publish(captured, previous, **overrides)
        self.assertEqual(self.snapshot(), before)

    def find_capture(self, request):
        matches = [(record, json.loads(self.registry.get_bytes(record.sha256)))
                   for record in self.registry.list_records()
                   if record.logical_type == "scholarly_search_response"]
        matches = [(record, value) for record, value in matches
                   if value["scholarly_request_id"] == request.request_id]
        self.assertEqual(len(matches), 1)
        record, value = matches[0]
        return native.require_captured_scholarly_search_page_response(self.registry,
            request=request, raw_artifact_sha256=value["raw_artifact_hash"],
            response_artifact_sha256=record.sha256).envelope

    def test_nonempty_and_empty_capture_publication_never_fetches(self):
        for body in (fixtures.page(("W1",), "next"), fixtures.page()):
            with self.subTest(body=body[:40]):
                self.make([(200, body, "*")])
                captured = self.capture()
                self.assertFalse(any(r.logical_type == "scholarly_search_result"
                                     for r in self.registry.list_records()))
                result = self.publish(captured)
                self.assertEqual(result.progress.pages[0].status, RetrievalStatus.AVAILABLE)
                self.assertEqual(len(self.transport.sent_request_ids), 1)
                self.assertEqual(set(result.artifact_hashes),
                                 {r.sha256 for r in self.registry.list_records()})
                self.assertEqual(self.replay(result.progress.result_artifact_hashes[-1]), result)

    def test_negative_and_malformed_capture_outcomes_are_preserved(self):
        for status, body in ((401, b"denied"), (403, b"denied"), (404, b"absent"),
                             (429, b"limited"), (503, b"failed"), (200, b"bad JSON"),
                             (200, fixtures.page(("W1", "W1"), "next"))):
            with self.subTest(status=status, body=body[:20]):
                self.make([(status, body, "*")])
                captured = self.capture()
                result = self.publish(captured)
                observed = result.progress.pages[0]
                self.assertEqual(observed.status, captured.status)
                self.assertIsNone(observed.reported_count)
                self.assertEqual(result.progress.stop_reason, ScholarlySearchStopReason.CAPTURED_FAILURE)
                self.assertEqual(result.observed_http_attempts, 1)

    def test_retry_custody_and_byte_multiplicity_survive_publication(self):
        body = fixtures.page(cursor="next")
        self.make([(503, body, "*"), (200, body, "*")], attempts=2)
        result = self.publish(self.capture())
        self.assertEqual(result.observed_http_attempts, 2)
        self.assertEqual(result.observed_response_bytes, 2 * len(body))
        self.assertEqual(len([r for r in self.registry.list_records()
                              if r.logical_type == "external_response_raw"]), 1)

    def test_fresh_registry_republication_is_byte_and_metadata_idempotent(self):
        self.make()
        captured = self.capture()
        first = self.publish(captured)
        self.registry = ArtifactRegistry(self.root)
        before = self.snapshot()
        second = self.publish(captured)
        self.assertEqual(first, second)
        self.assertEqual(self.snapshot(), before)

    def test_later_unicode_page_preserves_full_selected_prefix(self):
        token = "  e\u0301 Ａ＋/漢字==  "
        self.make([(200, fixtures.page(("W1",), token, title="Café 漢字"), "*"),
                   (200, fixtures.page(), token)], query="évidence 漢字", question="Quelle évidence?")
        first = self.publish(self.capture())
        previous = first.progress.result_artifact_hashes[-1]
        captured = self.capture(previous)
        self.registry = ArtifactRegistry(self.root)
        result = self.publish(captured, previous)
        self.assertEqual(result.progress.pages[1].request.cursor, token)
        self.assertEqual(result.progress.pages[0], first.progress.pages[0])
        self.assertEqual(result.observed_http_attempts, 2)
        self.assertEqual(set(result.artifact_hashes), {r.sha256 for r in self.registry.list_records()})
        self.assertEqual(result.progress.stop_reason, ScholarlySearchStopReason.PROVIDER_TERMINAL_OBSERVED)

    def test_failed_acquisition_publication_recovers_without_another_send(self):
        self.make()
        put = self.registry.put_json
        def fail(value, **metadata):
            if metadata["logical_type"] == "scholarly_search_result":
                raise RuntimeError("injected checkpoint publication failure")
            return put(value, **metadata)
        with patch.object(self.registry, "put_json", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "injected checkpoint"):
                self.acquire()
        self.assertEqual(len(self.transport.sent_request_ids), 1)
        captured = self.find_capture(self.first_request())
        prior = self.snapshot()
        self.registry = ArtifactRegistry(self.root)
        result = self.publish(captured)
        self.assertEqual(result.observed_http_attempts, 1)
        self.assertTrue(all(self.snapshot().get(path) == value for path, value in prior.items()))

    def test_publication_failure_and_readback_failure_allow_no_io_recovery(self):
        for stage in ("put", "readback"):
            with self.subTest(stage=stage):
                self.make()
                captured = self.capture()
                if stage == "put":
                    target, attribute = self.registry, "put_json"
                else:
                    target, attribute = design, "require_captured_scholarly_search_result_v2"
                with patch.object(target, attribute, side_effect=RuntimeError("injected " + stage)):
                    with self.assertRaisesRegex(RuntimeError, "injected " + stage):
                        self.publish(captured)
                records = [r for r in self.registry.list_records()
                           if r.logical_type == "scholarly_search_result"]
                self.assertEqual(len(records), int(stage == "readback"))
                before = self.snapshot()
                self.registry = ArtifactRegistry(self.root)
                recovered = self.publish(captured)
                self.assertEqual(recovered.progress.pages[0].status, captured.status)
                if stage == "readback":
                    self.assertEqual(self.snapshot(), before)

    def test_wrong_goal_plan_and_semantic_hash_inputs_refuse_before_writes(self):
        self.make()
        captured = self.capture()
        changed = self.clone(self.plan_record.sha256, lambda v: v.update(query="other query"))
        for overrides in (dict(goal_artifact_sha256=self.goal.sha256),
                          dict(goal_artifact_sha256=self.target_record.sha256),
                          dict(plan_artifact_sha256=self.plan.sha256),
                          dict(plan_artifact_sha256=changed.sha256),
                          dict(raw_artifact_sha256=self.plan_record.sha256),
                          dict(response_artifact_sha256=self.route.sha256),
                          dict(raw_artifact_sha256="0" * 64)):
            with self.subTest(overrides=overrides):
                self.assert_refused_without_writes(captured, **overrides)

    def test_changed_plan_parent_role_and_target_refuse_before_writes(self):
        for mutation, metadata in (
            (lambda v: v.update(query=" quantum gravity "), {}),
            (lambda v: v.update(query="different"), {"creator_role": Role.ORCHESTRATOR}),
            (lambda v: v.update(query="third"), {"parents": ()}),
        ):
            self.make()
            captured = self.capture()
            changed = self.clone(self.plan_record.sha256, mutation, **metadata)
            self.assert_refused_without_writes(captured, plan_artifact_sha256=changed.sha256)
        self.make()
        captured = self.capture()
        target = self.clone(self.target_record.sha256,
                            lambda v: v.update(target_statement="different question"))
        changed_plan = replace(self.plan, target_sha256=target.sha256,
            parent_artifact_hashes=(self.goal_record.sha256, target.sha256, self.route.sha256))
        plan_record = self.put(changed_plan.to_dict(), "scholarly_search_plan",
                              Role.PROBLEM_INVESTIGATOR, changed_plan.parent_artifact_hashes)
        self.assert_refused_without_writes(captured, plan_artifact_sha256=plan_record.sha256)

    def test_wrong_stale_and_terminal_predecessors_refuse_before_writes(self):
        self.make([(200, fixtures.page(("W1",), "next"), "*"),
                   (200, fixtures.page(), "next")])
        first_capture = self.capture()
        first = self.publish(first_capture)
        previous = first.progress.result_artifact_hashes[-1]
        second_capture = self.capture(previous)
        self.assert_refused_without_writes(second_capture)
        self.assert_refused_without_writes(first_capture, previous)
        self.assert_refused_without_writes(second_capture, first.progress.pages[0].sha256)
        altered = self.clone(previous, lambda v: v.update(next_cursor="stolen"))
        self.assert_refused_without_writes(second_capture, altered.sha256)
        second = self.publish(second_capture, previous)
        self.assert_refused_without_writes(second_capture, second.progress.result_artifact_hashes[-1])

    def test_coherently_rehashed_capture_and_route_substitutions_refuse(self):
        changes = [dict(raw_mutation=lambda b: b.replace(b'"count":2', b'"count":9')),
            dict(response_mutation=lambda v: v["payload"].update(reported_count=9)),
            dict(response_mutation=lambda v: v.update(schema_version="scholarly-native-response/v2")),
            dict(response_mutation=lambda v: v.update(network_used=True)),
            dict(receipt_mutation=lambda v: v.update(status_code=404)),
            dict(receipt_mutation=lambda v: v["egress_budget"].update(response_bytes_used=0)),
            dict(request_mutation=lambda v: v.update(url=v["url"].replace("corpus=core", "corpus=all")))]
        for change in changes:
            with self.subTest(change=change):
                self.make()
                original = self.acquire()
                changed = self.rewrite_capture(original, **change)
                value = json.loads(self.registry.get_bytes(changed))
                self.assert_refused_without_writes(original.captures[0].envelope,
                    raw_artifact_sha256=value["raw_artifact_hash"],
                    response_artifact_sha256=value["response_artifact_hash"])
        self.make()
        original = self.acquire()
        changed = self.rewrite_capture(original,
            request_mutation=lambda v: v.update(parent_artifacts=[self.route.sha256]),
            request_parents=(self.route.sha256,))
        value = json.loads(self.registry.get_bytes(changed))
        self.assert_refused_without_writes(original.captures[0].envelope,
            response_artifact_sha256=value["response_artifact_hash"])

    def test_negative_status_and_reason_substitutions_refuse(self):
        for field, value in (("retrieval_status", "AVAILABLE"),
                             ("failure_code", "MALFORMED_RESPONSE"),
                             ("failure_reason", "invented")):
            self.make([(404, b"absent", "*")])
            original = self.acquire()
            changed = self.rewrite_capture(original,
                response_mutation=lambda v: v.update({field: value}))
            body = json.loads(self.registry.get_bytes(changed))
            self.assert_refused_without_writes(original.captures[0].envelope,
                response_artifact_sha256=body["response_artifact_hash"])

    def test_exact_utf8_publication_cap_and_oversize_refusal_preserve_capture(self):
        for size in (4 * 1024 * 1024 - 1, 4 * 1024 * 1024, 4 * 1024 * 1024 + 1):
            with self.subTest(size=size):
                self.make(size=5)
                raw = self.sized_page_body(self.first_request(), size, character="é")
                self.set_next_response(raw)
                captured = self.capture()
                if size > 4 * 1024 * 1024:
                    self.assert_refused_without_writes(captured)
                    self.assertFalse(any(r.logical_type == "scholarly_search_result"
                                         for r in self.registry.list_records()))
                else:
                    result = self.publish(captured)
                    observed = result.progress.pages[0]
                    self.assertEqual(len(canonical_json_bytes(observed.to_dict()) + b"\n"), size)
                    self.assertGreater(len(observed.canonical_bytes + b"\n"), 4 * 1024 * 1024)
                self.assertEqual(self.registry.get_bytes(captured.raw_artifact_hash), raw)

    def test_large_error_and_ignored_payload_publish_small_true_outcomes(self):
        value = json.loads(fixtures.page())
        value["ignored"] = "I" * (4 * 1024 * 1024)
        for status, body in ((404, canonical_json_bytes({"error": value["ignored"]})),
                             (200, canonical_json_bytes(value))):
            self.make([(status, body, "*")])
            result = self.publish(self.capture())
            observed = result.progress.pages[0]
            self.assertEqual(observed.status,
                             RetrievalStatus.NOT_FOUND if status == 404 else RetrievalStatus.AVAILABLE)
            self.assertLess(len(self.registry.get_bytes(result.progress.result_artifact_hashes[-1])), 4096)
            self.assertGreater(len(self.registry.get_bytes(observed.raw_artifact_hash)), 4 * 1024 * 1024)

    def test_oversize_later_capture_keeps_prior_checkpoint_without_further_send(self):
        self.make([(200, fixtures.page(("W999",), "next", count=5, size=5), "*")], size=5)
        first = self.publish(self.capture())
        previous = first.progress.result_artifact_hashes[-1]
        prior = self.snapshot()
        request = first.progress.next_request
        self.set_next_response(self.sized_page_body(request, 4 * 1024 * 1024 + 1), request.cursor)
        captured = self.capture(previous)
        self.assert_refused_without_writes(captured, previous)
        self.assertEqual(self.replay(previous), first)
        self.assertTrue(all(self.snapshot().get(path) == content for path, content in prior.items()))
        self.assertEqual(len(self.transport.sent_request_ids), 2)

    def test_unavailable_transport_or_redirect_is_not_complete_page_authority(self):
        for redirect in (False, True):
            self.make([(302, b"redirect", "*")] if redirect else None)
            if not redirect:
                self.transport._position = len(self.transport._responses)
            captured = self.gateway.fetch(self.first_request())
            self.assert_refused_without_writes(captured)


if __name__ == "__main__":
    unittest.main()
