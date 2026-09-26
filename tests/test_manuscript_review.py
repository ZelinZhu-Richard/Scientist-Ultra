"""Inert checkpoint/control tests, never evidence of a live scientific review.

Composition owners are narrowly substituted in the persistence fixture because
no admitted scientific manuscript is fabricated here. Real registry/ledger
publication, readback, collisions, missing-authority refusal and policy execute.
The semantic stand-in always refuses live authority; no test mints scientific
INTERNAL_REVIEW_PASSED using a mocked gate.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.paper_composition import PaperManuscriptRevision, CompositionSourceMapEntry
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes, sha256_bytes, safe_json_loads
from scientist_one import manuscript_review as review


def digest(value: str) -> str:
    return sha256_bytes(value.encode())


def details(score: int = 4, *, material: bool = False) -> dict:
    return {"score": score, "confidence": "MEDIUM",
        "citations": [{"artifact_hash": digest("paper"), "passage": "inert manuscript"}],
        "strengths": "Explicit limitations", "weaknesses": "Clarity",
        "missing_evidence": "none", "proposed_resolutions": "Clarify wording",
        "concerns": [{"category": "PRESENTATION", "severity": "MATERIAL" if material else "MINOR", "description": "Clarify wording"}]}


class ManuscriptReviewPolicyTests(unittest.TestCase):
    def test_fixed_version_labels_and_two_revision_limit(self):
        rubric = review.internal_review_rubric()
        self.assertEqual(rubric["version"], "INTERNAL_PAPER_REVIEW_V1")
        self.assertEqual(rubric["ratings"], [
            {"score": 1, "label": "Reject"}, {"score": 2, "label": "Weak reject"},
            {"score": 3, "label": "Borderline"}, {"score": 4, "label": "Weak accept"},
            {"score": 5, "label": "Strong accept"}])
        self.assertEqual(rubric["maximum_autonomous_revisions"], 2)
        rubric["ratings"][0]["label"] = "accept"
        self.assertEqual(review.internal_review_rubric()["ratings"][0]["label"], "Reject")

    def test_scores_reject_boolean_fraction_and_out_of_range(self):
        for score in (True, False, 0, 6, 4.0, 4.5, "4"):
            with self.subTest(score=score), self.assertRaises(ValidationError):
                review._details(details(score))

    def test_review_details_require_evidence_and_all_fields(self):
        value = details()
        for mutate in (lambda d: d.pop("confidence"), lambda d: d.update(citations=[]),
                       lambda d: d.update(unknown=True), lambda d: d.update(confidence="CERTAIN")):
            changed = safe_json_loads(canonical_json_bytes(value))
            mutate(changed)
            with self.assertRaises(ValidationError):
                review._details(changed)

    def test_no_average_or_blocker_can_construct_passing_projection(self):
        base = {"round_hash": digest("round"), "result_hashes": [], "blockers": [],
            "status": "INTERNAL_REVIEW_PASSED", "scores": [4, 4, 4],
            "scientific_status": "PASS", "context_assurance": "AUDITED_STATELESS_REQUESTS",
            "activity": {slot: {} for slot in review.SLOTS}}
        # Pure shape validation, not issuance or scientific authority.
        review._validate_body("decision", base)
        for change in ({"scores": [5, 5, 3]}, {"scores": [4, None, 5]},
                       {"blockers": ["MATERIAL"]}, {"scientific_status": "BLOCKED"},
                       {"context_assurance": "UNVERIFIED"}, {"status": "RELEASED"}):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                review._validate_body("decision", {**base, **change})

    def test_nonauthor_three_contexts_are_mandatory(self):
        base = {"root_revision_hash": digest("r1"), "candidate_id": "candidate", "manuscript_id": "paper",
            "author_context_id": "author", "reviewer_contexts": ["a", "b", "c"], "rubric": review.internal_review_rubric()}
        for contexts in (["a", "b"], ["a", "a", "c"], ["author", "b", "c"]):
            with self.subTest(contexts=contexts), self.assertRaises(ValidationError):
                review._validate_body("campaign", {**base, "reviewer_contexts": contexts})
        for replacement in (True, 1.0):
            rubric = review.internal_review_rubric()
            rubric["ratings"][0]["score"] = replacement
            with self.assertRaises(ValidationError):
                review._validate_body("campaign", {**base, "rubric": rubric})


class InertManuscriptReviewCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.registry = ArtifactRegistry(self.root)
        self.ledger = EventLedger(self.root)
        self.run_id = "inert-review-run"
        self.ledger.record(run_id=self.run_id, actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.WRITE, requested_state_after=MacroState.WRITE,
            artifact_hashes=(), code_version="inert-control-only", configuration_hash=digest("config"),
            reason="inert review checkpoint fixture, no scientific authority", event_type="CHECKPOINT")
        self.revisions = {}
        self.source = self.put(b"inert evidence", "inert_review_evidence")
        self.candidate = self.put(b"inert candidate", "paper_candidate")
        self.bundle = self.put(b"inert bundle", "authoritative_research_bundle")
        self.verification = self.put(b"inert verification", "paper_verification")
        self.readiness = self.put(b"absent real readiness authority", "inert_readiness_bundle")
        self.first = self.add_revision(1)
        self.current_owner = patch.object(review, "require_paper_manuscript_revision", side_effect=self.resolve_revision)
        self.historical_owner = patch.object(review, "_replay_immutable_revision", side_effect=self.resolve_revision)
        self.current_owner.start()
        self.historical_owner.start()
        self.addCleanup(self.current_owner.stop)
        self.addCleanup(self.historical_owner.stop)
        self.campaign = review.freeze_manuscript_review(self.registry, self.ledger,
            revision_artifact_hash=self.first.revision_record.sha256,
            author_context_id="author", reviewer_contexts=("reviewer-a", "reviewer-b", "reviewer-c"))
        self.round = self.open_round(self.first)
        self.semantic_values = {}

    def put(self, data: bytes, logical_type: str, *, parents=(), frozen=True):
        return self.registry.put_bytes(data, logical_type=logical_type, origin="explicitly inert test fixture",
            creator_role=Role.PAPER_WRITER, mime_type="text/plain", frozen=frozen, parent_artifacts=parents)

    def invocation(self, slot="A", marker="first"):
        subject = f"imr-{self.round.sha256[:40]}-{slot}"
        return self.put(canonical_json_bytes({"schema_version": "1.0", "kind": "MODEL_INVOCATION",
            "invocation_id": {"sha256": digest(subject), "size": len(subject), "value_persisted": False},
            "provider_id": "inert-provider", "inert_marker": marker}), "model_invocation")

    def output(self, invocation, slot="A", *, rows=None, marker="first"):
        rows = rows if rows is not None else [{"attempt": 1, "status": "RESPONSE", "status_code": 200,
            "body_sha256": digest("inert-response"), "raw_response_record_sha256": digest("inert-raw")}]
        gateway = self.put(canonical_json_bytes({"request_id": f"inert-{slot}-{marker}", "network_used": False,
            "attempts": rows}), "external_response_receipt")
        envelope = self.put(canonical_json_bytes({"inert_marker": f"{slot}-{marker}"}),
            "model_provider_response", parents=(gateway.sha256,))
        return self.put(canonical_json_bytes({"invocation_id": f"imr-{self.round.sha256[:40]}-{slot}",
            "provider_id": "inert-provider", "inert_marker": marker}), "model_output",
            parents=(invocation.sha256, envelope.sha256))

    def terminal(self, slot="A", *, invocation=None, rows=None, marker="first", network_used=False,
                 state="FAILED", stage=None, extra_parents=()):
        subject = f"imr-{self.round.sha256[:40]}-{slot}"
        parents = ((invocation.sha256,) if invocation else ()) + extra_parents
        return self.put(canonical_json_bytes({"schema_version": "1.0", "kind": "MODEL_INVOCATION_TERMINAL_RECEIPT",
            "invocation_id": {"sha256": digest(subject), "size": len(subject), "value_persisted": False},
            "provider_id": "inert-provider", "terminal_state": state,
            "failure_stage": stage or ("TRANSPORT" if invocation else "INPUT_CUSTODY"),
            "request_id": f"inert-{slot}-{marker}", "attempts": rows or [], "network_used": network_used,
            "captured_parent_hashes": list(parents)}), "model_terminal_receipt", parents=parents)

    def add_revision(self, number: int, predecessor=None, *, assets=None):
        composition = self.put(canonical_json_bytes({"candidate_id": "inert-candidate", "assets": assets or []}), "paper_composition_input")
        content = self.put(f"inert manuscript revision {number}\n".encode(), "paper_manuscript_content")
        checked = self.put(f"inert composition check {number}".encode(), "paper_composition_verification")
        value = PaperManuscriptRevision(self.run_id, "inert-manuscript", number,
            predecessor.revision_record.sha256 if predecessor else None, composition.sha256, content.sha256,
            checked.sha256, self.candidate.sha256, self.bundle.sha256, self.verification.sha256, (), ())
        record = self.put(canonical_json_bytes(value.to_dict()), "paper_manuscript_revision")
        index = self.ledger.validate(raise_on_error=True).event_count
        event = self.ledger.record(run_id=self.run_id, actor_role=Role.PAPER_WRITER,
            state_before=MacroState.WRITE, requested_state_after=MacroState.WRITE,
            artifact_hashes=(record.sha256,), code_version="inert-control-only", configuration_hash=digest("config"),
            reason="inert manuscript identity; owner substituted only in this fixture", event_type="CHECKPOINT")
        result = SimpleNamespace(revision_record=record, revision=value,
            composition_input_record=composition, content_record=content,
            composition_verification_record=checked, content_bytes=self.registry.get_bytes(content.sha256),
            source_map=(CompositionSourceMapEntry("body", 0, content.size, content.sha256, (self.source.sha256,), ("body",)),),
            issuance_event=event, issuance_event_index=index, composition=SimpleNamespace(candidate_id="inert-candidate"))
        self.revisions[record.sha256] = result
        return result

    def resolve_revision(self, *args, revision_artifact_hash, **kwargs):
        if revision_artifact_hash not in self.revisions:
            raise ValidationError("unavailable inert revision")
        return self.revisions[revision_artifact_hash]

    def open_round(self, revision, plan=None):
        return review.open_manuscript_review_round(self.registry, self.ledger,
            campaign_hash=self.campaign.sha256, revision_artifact_hash=revision.revision_record.sha256,
            readiness_bundle_hash=self.readiness.sha256, revision_plan_hash=plan.sha256 if plan else None)

    def read(self, record):
        return review.read_manuscript_review_record(self.registry, self.ledger, artifact_hash=record.sha256)

    def inert_semantic(self, registry, ledger, round_hash, slot, receipt_hash, *, live):
        if live:
            raise ValidationError("inert fixture never has audited-live scientific authority")
        return self.semantic_values[receipt_hash]

    def retain_inert_review(self, slot, score=4, *, material=False, marker="first"):
        invocation = self.invocation(slot, marker)
        output = self.output(invocation, slot, marker=marker)
        raw = {"subject_kind": "MANUSCRIPT_REVIEW", "subject_id": f"imr-{self.round.sha256[:40]}-{slot}",
            "outcome": str(score), "inert_marker": marker,
            "invocation_artifact_hash": invocation.sha256, "model_output_artifact_hash": output.sha256}
        receipt = self.put(canonical_json_bytes(raw), review.SEMANTIC_JUDGMENT_RECEIPT_LOGICAL_TYPE)
        provenance = {"provider_id": "inert", "provider_version": "inert-v1", "model": "inert",
            "model_version": "UNVERIFIED", "invocation_hash": digest(slot), "prompt_template_hash": digest("prompt"),
            "reasoning_effort": "UNVERIFIED", "independence": "INERT_TEST_NOT_SCIENTIFIC"}
        self.semantic_values[receipt.sha256] = details(score, material=material), provenance
        with patch.object(review, "_receipt_details", side_effect=self.inert_semantic):
            return review.record_manuscript_review(self.registry, self.ledger, round_hash=self.round.sha256,
                slot=slot, semantic_receipt_hash=receipt.sha256)

    def decide_inert(self):
        with patch.object(review, "_receipt_details", side_effect=self.inert_semantic):
            return review.decide_manuscript_review(self.registry, self.ledger, round_hash=self.round.sha256)

    def rejected_plan(self):
        decision = self.decide_inert()
        concerns = []
        for result_hash in self.read(decision)["body"]["result_hashes"]:
            _, result = review._read(self.registry, self.ledger, result_hash, "result")
            for concern in result["body"]["details"]["concerns"]:
                concerns.append({"result_hash": result_hash, "category": concern["category"],
                    "description": concern["description"], "disposition": "MANUSCRIPT_EDIT"})
        with patch.object(review, "_receipt_details", side_effect=self.inert_semantic):
            return review.register_manuscript_revision_plan(self.registry, self.ledger,
                decision_hash=decision.sha256, concerns=concerns)

    def direct_receipt_fixture(self, *, rows=None):
        """Inert resolver projection; real parser, stored bytes and output census.

        This deliberately does not build or claim valid provider custody. Only
        the ordinary receipt resolver is substituted; its live counterpart is
        explicitly unavailable. The production _receipt_details is untouched.
        """
        request = review._request(self.registry, self.ledger, self.round.sha256, "A")
        expected = details(4)
        expected["citations"] = [
            {"artifact_hash": self.first.content_record.sha256,
             "passage": "inert manuscript revision 1"},
            {"artifact_hash": self.source.sha256, "passage": "inert evidence"},
        ]
        rationale = canonical_json_bytes(expected).decode("utf-8")
        instructions = self.put(request.instructions.encode("utf-8"), "inert_review_instructions")
        judged_input = self.put(request.input_text.encode("utf-8"), "inert_review_input")
        schema = self.put(canonical_json_bytes(request.output_schema), "inert_review_schema")
        invocation = self.invocation()
        output = self.output(invocation, rows=rows)
        receipt_record = self.put(canonical_json_bytes({"subject_kind": "MANUSCRIPT_REVIEW",
            "subject_id": request.subject_id, "outcome": "4", "rationale": rationale,
            "invocation_artifact_hash": invocation.sha256, "model_output_artifact_hash": output.sha256}),
            review.SEMANTIC_JUDGMENT_RECEIPT_LOGICAL_TYPE)
        receipt = SimpleNamespace(
            reviewer_id=request.reviewer_id, invocation_id=request.invocation_id,
            prompt_template_id=request.prompt_template_id,
            prompt_template_version=request.prompt_template_version,
            prompt_template_hash=request.prompt_template_hash,
            instructions_artifact_hash=instructions.sha256,
            input_artifact_hash=judged_input.sha256, output_schema_artifact_hash=schema.sha256,
            model_output_artifact_hash=output.sha256, invocation_artifact_hash=invocation.sha256,
            rationale=rationale, provider_id="inert-provider", provider_version="inert-v1",
            model="inert-model-requested", model_version="inert-model-observed",
        )
        ordinary_patch = patch.object(review, "require_semantic_judgment_receipt", return_value=receipt)
        live_patch = patch.object(review, "require_scientific_semantic_judgment_receipt",
            side_effect=ValidationError("live custody unavailable in direct-parser fixture"))
        ordinary, live = ordinary_patch.start(), live_patch.start()
        self.addCleanup(ordinary_patch.stop)
        self.addCleanup(live_patch.stop)
        return SimpleNamespace(request=request, expected=expected, receipt=receipt,
            record=receipt_record, ordinary=ordinary, live=live)

    def parse_direct_receipt(self, fixture, *, live=False):
        return review._receipt_details(self.registry, self.ledger, self.round.sha256,
            "A", fixture.record.sha256, live=live)

    def test_direct_receipt_parser_joins_exact_advisory_inputs_and_provenance(self):
        fixture = self.direct_receipt_fixture()
        before = review._snapshot(self.registry, self.ledger)
        parsed, provenance = self.parse_direct_receipt(fixture)
        self.assertEqual(parsed, fixture.expected)
        self.assertEqual(provenance, {
            "provider_id": "inert-provider", "provider_version": "inert-v1",
            "model": "inert-model-requested", "model_version": "inert-model-observed",
            "invocation_hash": fixture.receipt.invocation_artifact_hash,
            "prompt_template_hash": fixture.request.prompt_template_hash,
            "reasoning_effort": "UNVERIFIED",
            "independence": "REQUEST_CONTEXT_ONLY_NOT_INDEPENDENT_CERTIFICATION",
        })
        expected_kwargs = dict(receipt_artifact_hash=fixture.record.sha256,
            subject_kind=review.JudgmentSubjectKind.MANUSCRIPT_REVIEW,
            subject_id=fixture.request.subject_id, outcome="4",
            evidence_hashes=fixture.request.evidence_hashes,
            context_hashes=fixture.request.context_hashes)
        fixture.ordinary.assert_called_once_with(self.registry, **expected_kwargs)
        with self.assertRaisesRegex(ValidationError, "live custody unavailable"):
            self.parse_direct_receipt(fixture, live=True)
        fixture.live.assert_called_once_with(self.registry, self.ledger,
            run_id=self.run_id, **expected_kwargs)
        self.assertEqual(review._snapshot(self.registry, self.ledger), before)

    def test_direct_receipt_parser_rejects_reviewer_invocation_and_prompt_rebinding(self):
        fixture = self.direct_receipt_fixture()
        replacements = {
            "reviewer_id": "author", "invocation_id": "different-invocation",
            "prompt_template_id": "different-template", "prompt_template_version": "different-version",
            "prompt_template_hash": digest("different-prompt"),
        }
        for field, changed in replacements.items():
            original = getattr(fixture.receipt, field)
            with self.subTest(field=field):
                setattr(fixture.receipt, field, changed)
                try:
                    with self.assertRaisesRegex(ValidationError, "reviewer, invocation or prompt"):
                        self.parse_direct_receipt(fixture)
                finally:
                    setattr(fixture.receipt, field, original)
        fixture.live.assert_not_called()

    def test_direct_receipt_parser_rejects_changed_retained_request_bytes(self):
        fixture = self.direct_receipt_fixture()
        peer_input = safe_json_loads(fixture.request.input_text)
        peer_input["peer_scores"] = [5, 5]
        changed_schema = safe_json_loads(canonical_json_bytes(fixture.request.output_schema))
        changed_schema["additionalProperties"] = True
        replacements = {
            "instructions_artifact_hash": (fixture.request.instructions + " Target score five.").encode(),
            "input_artifact_hash": canonical_json_bytes(peer_input),
            "output_schema_artifact_hash": canonical_json_bytes(changed_schema),
        }
        for field, data in replacements.items():
            changed = self.put(data, "inert_changed_review_input")
            original = getattr(fixture.receipt, field)
            with self.subTest(field=field):
                setattr(fixture.receipt, field, changed.sha256)
                try:
                    with self.assertRaisesRegex(ValidationError, "exact blind frozen request"):
                        self.parse_direct_receipt(fixture)
                finally:
                    setattr(fixture.receipt, field, original)
        fixture.live.assert_not_called()

    def test_direct_receipt_parser_rejects_off_packet_and_inexact_citations(self):
        fixture = self.direct_receipt_fixture()
        for citation in (
            {"artifact_hash": digest("outside-packet"), "passage": "inert manuscript revision 1"},
            {"artifact_hash": self.first.content_record.sha256, "passage": "unwritten result claim"},
        ):
            changed = safe_json_loads(canonical_json_bytes(fixture.expected))
            changed["citations"] = [citation]
            with self.subTest(citation=citation):
                fixture.receipt.rationale = canonical_json_bytes(changed).decode("utf-8")
                with self.assertRaisesRegex(ValidationError, "outside frozen evidence or not an exact passage"):
                    self.parse_direct_receipt(fixture)
        fixture.live.assert_not_called()

    def test_direct_receipt_parser_rejects_additional_model_output_attempt(self):
        fixture = self.direct_receipt_fixture()
        additional = self.put(canonical_json_bytes({"invocation_id": fixture.request.invocation_id,
            "output": {"outcome": "1", "rationale": "inert second output"}}), "model_output")
        before = review._snapshot(self.registry, self.ledger)
        with self.assertRaisesRegex(ValidationError, "additional retained model-output attempts"):
            self.parse_direct_receipt(fixture)
        self.assertEqual(review._snapshot(self.registry, self.ledger), before)
        self.assertTrue(self.registry.verify(additional.sha256))
        fixture.live.assert_not_called()

    def test_direct_receipt_parser_rejects_noncanonical_or_mismatched_rationale(self):
        fixture = self.direct_receipt_fixture()
        mismatched = safe_json_loads(canonical_json_bytes(fixture.expected))
        mismatched["score"] = 3
        unknown = safe_json_loads(canonical_json_bytes(fixture.expected))
        unknown["unsupported_field"] = True
        for rationale in (fixture.receipt.rationale + "\n",
                          canonical_json_bytes(mismatched).decode("utf-8"),
                          canonical_json_bytes(unknown).decode("utf-8")):
            with self.subTest(rationale=rationale):
                fixture.receipt.rationale = rationale
                with self.assertRaises(ValidationError):
                    self.parse_direct_receipt(fixture)
        fixture.live.assert_not_called()

    def test_registry_and_ledger_checkpoint_round_trip_is_idempotent(self):
        self.assertEqual(self.read(self.campaign)["body"]["rubric"]["version"], review.RUBRIC_VERSION)
        before = review._snapshot(self.registry, self.ledger)
        self.assertEqual(self.open_round(self.first), self.round)
        self.assertEqual(review._snapshot(self.registry, self.ledger), before)
        self.assertTrue(self.registry.verify_all(raise_on_error=True).valid)

    def test_campaign_rename_cannot_replace_reviewers_or_reset_budget(self):
        before = review._snapshot(self.registry, self.ledger)
        with self.assertRaises(ValidationError):
            review.freeze_manuscript_review(self.registry, self.ledger,
                revision_artifact_hash=self.first.revision_record.sha256,
                author_context_id="new-author", reviewer_contexts=("new-a", "new-b", "new-c"))
        self.assertEqual(self.ledger.validate().event_count, before[1].event_count + 2)
        self.assertEqual(len([r for r in self.registry.list_records() if r.logical_type == "manuscript_review_campaign"]), 1)

    def test_blind_requests_share_complete_packet_and_have_distinct_subjects(self):
        requests = [review.manuscript_review_request(self.registry, self.ledger,
            round_hash=self.round.sha256, slot=slot) for slot in review.SLOTS]
        packets = [safe_json_loads(request.input_text) for request in requests]
        self.assertEqual(len({request.subject_id for request in requests}), 3)
        self.assertEqual(packets[0]["frozen_data"], packets[1]["frozen_data"])
        self.assertEqual(packets[1]["frozen_data"], packets[2]["frozen_data"])
        self.assertEqual(requests[0].evidence_hashes, requests[2].evidence_hashes)
        self.assertFalse(any("peer_scores" in packet for packet in packets))
        self.assertIn("untrusted data", requests[0].instructions)
        self.assertIn("inert manuscript", packets[0]["frozen_data"]["manuscript"])

    def test_missing_reviews_are_preserved_as_not_ready_not_error(self):
        decision = review.decide_manuscript_review(self.registry, self.ledger, round_hash=self.round.sha256)
        value = self.read(decision)["body"]
        self.assertEqual(value["status"], "NOT_READY")
        self.assertEqual(tuple(value["scores"]), (None, None, None))
        self.assertIn("A_MISSING_OR_MULTIPLE_REVIEWS", value["blockers"])
        self.assertIn("SCIENTIFIC_OR_CURRENTNESS_GATE_BLOCKED", value["blockers"])
        before = review._snapshot(self.registry, self.ledger)
        status = review.manuscript_review_status(self.registry, self.ledger,
            decision_artifact_hash=decision.sha256, revision_artifact_hash=self.first.revision_record.sha256)
        self.assertEqual((status["status"], status["review_status"], status["release_authority"]), ("BLOCKED", "NOT_READY", "NONE"))
        self.assertEqual(review._snapshot(self.registry, self.ledger), before)

    def test_perfect_inert_scores_never_pass_science_or_live_custody(self):
        for slot in review.SLOTS:
            self.retain_inert_review(slot, 5)
        decision = self.decide_inert()
        value = self.read(decision)["body"]
        self.assertEqual(tuple(value["scores"]), (5, 5, 5))
        self.assertEqual(value["status"], "NOT_READY")
        self.assertEqual(value["context_assurance"], "UNVERIFIED")
        with patch.object(review, "_receipt_details", side_effect=self.inert_semantic), self.assertRaises(ValidationError):
            review.require_internal_review_pass(self.registry, self.ledger, decision_hash=decision.sha256,
                revision_artifact_hash=self.first.revision_record.sha256)

    def test_one_borderline_cannot_be_averaged_away(self):
        for slot, score in zip(review.SLOTS, (5, 5, 3), strict=True):
            self.retain_inert_review(slot, score)
        value = self.read(self.decide_inert())["body"]
        self.assertIn("C_BELOW_THRESHOLD", value["blockers"])
        self.assertEqual(value["status"], "NOT_READY")

    def test_high_scores_do_not_override_material_concern(self):
        for slot in review.SLOTS:
            self.retain_inert_review(slot, 5, material=slot == "B")
        self.assertIn("B_UNRESOLVED_MATERIAL_BLOCKER", self.read(self.decide_inert())["body"]["blockers"])

    def test_invalid_and_extra_attempts_are_retained_and_block(self):
        missing = review.record_manuscript_review(self.registry, self.ledger, round_hash=self.round.sha256,
            slot="A", semantic_receipt_hash=digest("missing-receipt"))
        self.assertEqual(self.read(missing)["body"]["status"], "INVALID")
        extra = self.retain_inert_review("A", 5)
        self.assertEqual(self.read(extra)["body"]["status"], "EXTRA_ATTEMPT")
        self.assertIn("A_MISSING_OR_MULTIPLE_REVIEWS", self.read(self.decide_inert())["body"]["blockers"])
        with self.assertRaises(ValidationError):
            review.manuscript_review_request(self.registry, self.ledger, round_hash=self.round.sha256, slot="A")

    def test_unsubmitted_skeptical_receipt_cannot_be_omitted(self):
        for slot in review.SLOTS:
            self.retain_inert_review(slot)
        self.put(canonical_json_bytes({"subject_kind": "MANUSCRIPT_REVIEW",
            "subject_id": f"imr-{self.round.sha256[:40]}-A", "outcome": "1"}), review.SEMANTIC_JUDGMENT_RECEIPT_LOGICAL_TYPE)
        self.assertIn("A_UNACCOUNTED_REVIEW_ATTEMPTS", self.read(self.decide_inert())["body"]["blockers"])

    def test_captured_unsubmitted_output_prevents_new_request(self):
        self.put(canonical_json_bytes({"invocation_id": f"imr-{self.round.sha256[:40]}-B"}), "model_output")
        with self.assertRaisesRegex(ValidationError, "resampling"):
            review.manuscript_review_request(self.registry, self.ledger, round_hash=self.round.sha256, slot="B")

    def test_identical_review_submission_is_idempotent(self):
        result = self.retain_inert_review("A", 3)
        receipt = self.read(result)["body"]["semantic_receipt_hash"]
        before = review._snapshot(self.registry, self.ledger)
        repeated = review.record_manuscript_review(self.registry, self.ledger, round_hash=self.round.sha256,
            slot="A", semantic_receipt_hash=receipt)
        self.assertEqual(repeated, result)
        self.assertEqual(review._snapshot(self.registry, self.ledger), before)

    def test_malformed_submitted_artifact_is_retained_as_invalid(self):
        artifact = self.put(b"[]", "inert_malformed_receipt")
        result = review.record_manuscript_review(self.registry, self.ledger,
            round_hash=self.round.sha256, slot="A", semantic_receipt_hash=artifact.sha256)
        self.assertEqual(self.read(result)["body"]["status"], "INVALID")

    def test_revision_plan_preserves_all_concerns_and_cannot_waive_protocol(self):
        for slot, score in zip(review.SLOTS, (4, 3, 4), strict=True):
            self.retain_inert_review(slot, score)
        plan = self.rejected_plan()
        self.assertEqual(len(self.read(plan)["body"]["concerns"]), 3)
        self.assertEqual(self.read(plan)["body"]["permission"], "MANUSCRIPT_ONLY_NO_EXPERIMENT_OR_CONFIRMATION_AUTHORITY")
        _, decision = review._read(self.registry, self.ledger, self.read(plan)["body"]["decision_hash"], "decision")
        with patch.object(review, "_receipt_details", side_effect=self.inert_semantic), self.assertRaises(ValidationError):
            review._plan_concerns(self.registry, self.ledger, decision, [])

    def test_two_writer_rounds_then_budget_exhaustion_preserve_history(self):
        previous = self.first
        for number in (1, 2, 3):
            for slot in review.SLOTS:
                self.retain_inert_review(slot, 3)
            if number == 3:
                before = review._snapshot(self.registry, self.ledger)
                with self.assertRaisesRegex(ValidationError, "budget"):
                    self.rejected_plan()
                # A rejection decision may be appended, but all three rounds remain.
                self.assertGreaterEqual(self.ledger.validate().event_count, before[1].event_count)
                break
            plan = self.rejected_plan()
            current = self.add_revision(number + 1, previous)
            with patch.object(review, "_receipt_details", side_effect=self.inert_semantic):
                self.round = self.open_round(current, plan)
            previous = current
        rounds = [record for record in self.registry.list_records() if record.logical_type == "manuscript_review_round"]
        self.assertEqual(len(rounds), 3)

    def test_unchanged_manuscript_cannot_resample_review(self):
        for slot in review.SLOTS:
            self.retain_inert_review(slot, 3)
        plan = self.rejected_plan()
        current = self.add_revision(2, self.first)
        current.revision = replace(current.revision, content_artifact_hash=self.first.revision.content_artifact_hash)
        before = review._snapshot(self.registry, self.ledger)
        with patch.object(review, "_receipt_details", side_effect=self.inert_semantic), self.assertRaisesRegex(ValidationError, "resampling"):
            self.open_round(current, plan)
        self.assertEqual(self.ledger.validate().event_count, before[1].event_count + 2)

    def test_unplanned_later_manuscript_invalidates_old_round(self):
        decision = review.decide_manuscript_review(self.registry, self.ledger, round_hash=self.round.sha256)
        self.add_revision(2, self.first)
        status = review.manuscript_review_status(self.registry, self.ledger,
            decision_artifact_hash=decision.sha256, revision_artifact_hash=self.first.revision_record.sha256)
        self.assertEqual(status["status"], "BLOCKED")
        self.assertIn("SCIENTIFIC_OR_CURRENTNESS_GATE_BLOCKED", status["blockers"])
        with self.assertRaises(ValidationError):
            self.open_round(self.revisions[next(reversed(self.revisions))])

    def test_wrong_status_revision_binding_is_an_error(self):
        decision = review.decide_manuscript_review(self.registry, self.ledger, round_hash=self.round.sha256)
        with self.assertRaises(ValidationError):
            review.manuscript_review_status(self.registry, self.ledger,
                decision_artifact_hash=decision.sha256, revision_artifact_hash=digest("wrong"))

    def test_late_review_marks_previous_decision_stale(self):
        decision = review.decide_manuscript_review(self.registry, self.ledger, round_hash=self.round.sha256)
        self.retain_inert_review("A", 3)
        with patch.object(review, "_receipt_details", side_effect=self.inert_semantic):
            status = review.manuscript_review_status(self.registry, self.ledger,
                decision_artifact_hash=decision.sha256, revision_artifact_hash=self.first.revision_record.sha256)
        self.assertIn("STALE_DECISION_REQUIRES_NEW_CHECKPOINT", status["blockers"])
        self.assertEqual(self.read(decision)["body"]["result_hashes"], ())

    def test_required_figures_are_explicitly_blocked_on_text_only_provider(self):
        changed = self.add_revision(2, self.first, assets=[{"kind": "FIGURE"}])
        with self.assertRaisesRegex(ValidationError, "visual review is BLOCKED_EXTERNAL"):
            review._packet(self.registry, changed)

    def test_complete_evidence_is_never_truncated(self):
        with patch.object(review, "MAX_INPUT_BYTES", 4), self.assertRaisesRegex(ValidationError, "oversized"):
            review._packet(self.registry, self.first)

    def test_orphan_review_artifact_cannot_be_admitted_by_retry(self):
        data = safe_json_loads(self.registry.get_bytes(self.round.sha256))
        data["body"]["readiness_bundle_hash"] = self.bundle.sha256
        data["key"] = review._key("round", self.run_id, data["body"])
        self.registry.put_bytes(canonical_json_bytes(data) + b"\n", logical_type="manuscript_review_round",
            origin="inert orphan", creator_role=Role.ORCHESTRATOR, frozen=True)
        with self.assertRaises(ValidationError):
            self.open_round(self.first)

    def test_corrected_checkpoint_never_replays_as_current(self):
        value = self.read(self.round)
        target = self.ledger.validate().events[value["prefix_count"]]
        self.ledger.record(run_id=self.run_id, actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.WRITE, requested_state_after=MacroState.WRITE,
            artifact_hashes=(), code_version="inert-control-only", configuration_hash=digest("config"),
            reason="inert correction control", event_type="CORRECTION", supersedes_event_id=target.event_id)
        with self.assertRaisesRegex(ValidationError, "corrected"):
            self.read(self.round)

    def test_backdated_checkpoint_refuses_before_any_write(self):
        before = review._snapshot(self.registry, self.ledger)
        with patch.object(review, "utc_now", return_value="2000-01-01T00:00:00Z"), self.assertRaisesRegex(ValidationError, "predate"):
            review.decide_manuscript_review(self.registry, self.ledger, round_hash=self.round.sha256)
        self.assertEqual(review._snapshot(self.registry, self.ledger), before)

    def test_concurrent_append_aborts_before_registry_publication(self):
        records_before = self.registry.verify_all(raise_on_error=True)
        plan_record = review._record_for_bytes
        def append_during_preflight(*args, **kwargs):
            record = plan_record(*args, **kwargs)
            self.ledger.record(run_id=self.run_id, actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.WRITE, requested_state_after=MacroState.WRITE,
                artifact_hashes=(), code_version="inert-control-only", configuration_hash=digest("config"),
                reason="inert concurrent append control", event_type="CHECKPOINT")
            return record
        with patch.object(review, "_record_for_bytes", side_effect=append_during_preflight), self.assertRaisesRegex(ValidationError, "changed"):
            review.decide_manuscript_review(self.registry, self.ledger, round_hash=self.round.sha256)
        self.assertEqual(self.registry.verify_all(raise_on_error=True), records_before)

    def test_real_composition_owner_refusal_has_only_operational_attempt_and_outcome(self):
        before = review._snapshot(self.registry, self.ledger)
        self.current_owner.stop()
        with self.assertRaises((ValidationError, ValueError)):
            review.freeze_manuscript_review(self.registry, self.ledger,
                revision_artifact_hash=self.first.revision_record.sha256,
                author_context_id="other-author", reviewer_contexts=("x", "y", "z"))
        after = review._snapshot(self.registry, self.ledger)
        self.assertEqual(after[1].event_count, before[1].event_count + 2)
        values = review._inventory(self.registry, self.ledger)
        refusals = [value["body"] for _, value in values if value["kind"] == "outcome" and value["body"]["status"] == "REFUSED"]
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0]["reason_code"], "VALIDATION_REFUSED")
        self.assertIsNone(refusals[0]["result_hash"])

    def test_unfrozen_receipt_is_invalid_without_mutable_parent_and_cannot_retry(self):
        artifact = self.put(b'{"untrusted":"mutable submission"}', "inert_unfrozen_receipt", frozen=False)
        result = review.record_manuscript_review(self.registry, self.ledger,
            round_hash=self.round.sha256, slot="A", semantic_receipt_hash=artifact.sha256)
        body = self.read(result)["body"]
        self.assertEqual(body["status"], "INVALID")
        self.assertIsNone(body["receipt_parent_hash"])
        self.assertNotIn(artifact.sha256, result.parent_artifacts)
        self.assertFalse(self.registry.get_metadata(artifact.sha256).frozen)
        before = review._snapshot(self.registry, self.ledger)
        self.assertEqual(review.record_manuscript_review(self.registry, self.ledger,
            round_hash=self.round.sha256, slot="A", semantic_receipt_hash=artifact.sha256), result)
        self.assertEqual(review._snapshot(self.registry, self.ledger), before)
        with self.assertRaises(ValidationError):
            review.manuscript_review_request(self.registry, self.ledger, round_hash=self.round.sha256, slot="A")
        self.assertIn("A_FAILED_REVIEW", self.read(self.decide_inert())["body"]["blockers"])

    def test_malformed_hash_submission_retains_only_bounded_descriptor_and_refusal(self):
        raw = "invalid hash and untrusted secret-like caller text"
        before = review._snapshot(self.registry, self.ledger)
        with self.assertRaises(ValidationError):
            review.record_manuscript_review(self.registry, self.ledger,
                round_hash=self.round.sha256, slot="A", semantic_receipt_hash=raw)
        values = review._inventory(self.registry, self.ledger)
        attempt = [item for _, item in values if item["kind"] == "attempt" and item["body"]["operation"] == "record_manuscript_review"][0]
        self.assertEqual(attempt["body"]["requested_round_hash"], self.round.sha256)
        self.assertNotIn(raw, canonical_json_bytes([value for _, value in values]).decode())
        self.assertEqual(self.ledger.validate().event_count, before[1].event_count + 2)
        after = review._snapshot(self.registry, self.ledger)
        with self.assertRaisesRegex(ValidationError, "previous operational"):
            review.record_manuscript_review(self.registry, self.ledger,
                round_hash=self.round.sha256, slot="A", semantic_receipt_hash=raw)
        self.assertEqual(review._snapshot(self.registry, self.ledger), after)
        with self.assertRaisesRegex(ValidationError, "resampling"):
            review.manuscript_review_request(self.registry, self.ledger, round_hash=self.round.sha256, slot="A")
        body = self.read(self.decide_inert())["body"]
        self.assertEqual(body["status"], "NOT_READY")
        self.assertIn("REFUSED_OPERATIONAL_ATTEMPT", body["activity"]["A"]["issues"])

    def test_attempt_is_durable_before_manuscript_owner_rejects_freeze(self):
        def refuse(*args, **kwargs):
            attempts = [item for _, item in review._inventory(self.registry, self.ledger)
                        if item["kind"] == "attempt" and item["body"]["operation"] == "freeze_manuscript_review"]
            self.assertEqual(len(attempts), 2)  # initial fixture plus this refused submission
            raise ValidationError("inert owner refusal")
        with patch.object(review, "require_paper_manuscript_revision", side_effect=refuse) as owner:
            with self.assertRaisesRegex(ValidationError, "inert owner refusal"):
                review.freeze_manuscript_review(self.registry, self.ledger,
                    revision_artifact_hash=digest("absent-manuscript"), author_context_id="author",
                    reviewer_contexts=("reviewer-a", "reviewer-b", "reviewer-c"))
        owner.assert_called_once()
        campaigns = [r for r in self.registry.list_records() if r.logical_type == "manuscript_review_campaign"]
        self.assertEqual(campaigns, [self.campaign])

    def test_attempt_persistence_failure_prevents_validation_and_dispatch(self):
        provider = Mock()
        before = review._snapshot(self.registry, self.ledger)
        with patch.object(review, "_publish", side_effect=OSError("inert checkpoint persistence failure")), \
                patch.object(review, "_round") as callback:
            with self.assertRaises(OSError):
                provider(review.manuscript_review_request(self.registry, self.ledger,
                    round_hash=self.round.sha256, slot="A"))
        provider.assert_not_called()
        callback.assert_not_called()
        self.assertEqual(review._snapshot(self.registry, self.ledger), before)

    def test_freeze_persistence_failure_prevents_manuscript_validation(self):
        with patch.object(review, "_publish", side_effect=OSError("inert persistence refusal")), \
                patch.object(review, "require_paper_manuscript_revision") as owner:
            with self.assertRaises(OSError):
                review.freeze_manuscript_review(self.registry, self.ledger,
                    revision_artifact_hash=digest("new-manuscript"), author_context_id="author",
                    reviewer_contexts=("a", "b", "c"))
        owner.assert_not_called()

    def test_preparation_outcome_failure_prevents_dispatch_and_replay(self):
        provider = Mock()
        publish = review._publish
        def fail_outcome(*args, **kwargs):
            if kwargs["kind"] == "outcome":
                raise OSError("inert outcome failure")
            return publish(*args, **kwargs)
        with patch.object(review, "_publish", side_effect=fail_outcome):
            with self.assertRaises(OSError):
                provider(review.manuscript_review_request(self.registry, self.ledger,
                    round_hash=self.round.sha256, slot="A"))
        provider.assert_not_called()
        with self.assertRaisesRegex(ValidationError, "incomplete"):
            review.manuscript_review_request(self.registry, self.ledger, round_hash=self.round.sha256, slot="A")
        body = self.read(self.decide_inert())["body"]
        self.assertIn("INCOMPLETE_OPERATIONAL_ATTEMPT", body["activity"]["A"]["issues"])
        self.assertIsNone(body["activity"]["A"]["transport_attempts"])

    def test_outer_snapshot_denial_does_not_force_an_attempt_write(self):
        before = review._snapshot(self.registry, self.ledger)
        provider = Mock()
        with patch.object(review, "_snapshot", side_effect=ValidationError("outer admission denied")), \
                patch.object(review, "_publish") as publish:
            with self.assertRaisesRegex(ValidationError, "outer admission"):
                provider(review.manuscript_review_request(self.registry, self.ledger,
                    round_hash=self.round.sha256, slot="A"))
        publish.assert_not_called()
        provider.assert_not_called()
        self.assertEqual(review._snapshot(self.registry, self.ledger), before)

    def test_repeated_request_preparation_is_one_operation_and_no_provider_call(self):
        request = review.manuscript_review_request(self.registry, self.ledger, round_hash=self.round.sha256, slot="A")
        before = review._snapshot(self.registry, self.ledger)
        self.assertEqual(review.manuscript_review_request(self.registry, self.ledger,
            round_hash=self.round.sha256, slot="A"), request)
        self.assertEqual(review._snapshot(self.registry, self.ledger), before)
        body = self.read(self.decide_inert())["body"]
        self.assertEqual(len(body["activity"]["A"]["operational_attempts"]), 1)
        self.assertEqual(body["activity"]["A"]["observed_invocation_records"], 0)
        self.assertIsNone(body["activity"]["A"]["transport_attempts"])

    def test_descriptor_only_pre_custody_refusal_exhausts_slot(self):
        terminal = self.terminal()
        with self.assertRaisesRegex(ValidationError, "resampling"):
            review.manuscript_review_request(self.registry, self.ledger, round_hash=self.round.sha256, slot="A")
        body = self.read(self.decide_inert())["body"]
        activity = body["activity"]["A"]
        self.assertEqual(activity["terminals"], (terminal.sha256,))
        self.assertEqual(activity["pre_custody_refusals"], 1)
        self.assertEqual(activity["observed_invocation_records"], 0)
        self.assertEqual(activity["transport_attempts"], 0)  # explicit network_used=False and empty attempts
        self.assertIn("A_UNRECONCILED_ACTIVITY", body["blockers"])

    def test_invocation_without_terminal_or_output_is_unknown_and_not_unused(self):
        invocation = self.invocation()
        with self.assertRaisesRegex(ValidationError, "resampling"):
            review.manuscript_review_request(self.registry, self.ledger, round_hash=self.round.sha256, slot="A")
        body = self.read(self.decide_inert())["body"]
        self.assertEqual(body["activity"]["A"]["incomplete_invocations"], (invocation.sha256,))
        self.assertIsNone(body["activity"]["A"]["transport_attempts"])
        self.assertEqual(body["status"], "NOT_READY")

    def test_successful_retry_rows_join_one_invocation_output_and_review(self):
        rows = [{"attempt": 1, "status": "RESPONSE", "status_code": 503,
                 "body_sha256": digest("retry-response"), "raw_response_record_sha256": digest("retry-raw")},
                {"attempt": 2, "status": "RESPONSE", "status_code": 200,
                 "body_sha256": digest("success-response"), "raw_response_record_sha256": digest("success-raw")}]
        fixture = self.direct_receipt_fixture(rows=rows)
        result = review.record_manuscript_review(self.registry, self.ledger,
            round_hash=self.round.sha256, slot="A", semantic_receipt_hash=fixture.record.sha256)
        self.assertEqual(self.read(result)["body"]["status"], "RETAINED")
        decision = review.decide_manuscript_review(self.registry, self.ledger, round_hash=self.round.sha256)
        activity = self.read(decision)["body"]["activity"]["A"]
        self.assertEqual(activity["issues"], ())
        self.assertEqual(activity["transport_attempts"], 2)
        self.assertEqual(activity["transport_retries"], 1)
        self.assertEqual(len(activity["invocations"]), 1)
        self.assertEqual(len(activity["outputs"]), 1)
        self.assertEqual(len(activity["receipts"]), 1)
        self.assertEqual(self.read(decision)["body"]["status"], "NOT_READY")

    def test_terminal_and_gateway_retry_projection_is_not_double_counted(self):
        invocation = self.invocation()
        rows = [{"attempt": 1, "status": "TRANSPORT_FAILURE"},
                {"attempt": 2, "status": "RESPONSE", "status_code": 503}]
        gateway = self.put(canonical_json_bytes({"request_id": "inert-A-first", "network_used": False,
            "attempts": rows}), "external_response_receipt")
        subject = f"imr-{self.round.sha256[:40]}-A"
        parents = (invocation.sha256, gateway.sha256)
        self.put(canonical_json_bytes({"kind": "MODEL_INVOCATION_TERMINAL_RECEIPT",
            "invocation_id": {"sha256": digest(subject), "size": len(subject), "value_persisted": False},
            "provider_id": "inert-provider", "terminal_state": "FAILED", "failure_stage": "RESPONSE",
            "request_id": "inert-A-first", "network_used": False, "attempts": rows,
            "captured_parent_hashes": list(parents)}), "model_terminal_receipt", parents=parents)
        body = self.read(self.decide_inert())["body"]
        self.assertEqual(body["activity"]["A"]["transport_attempts"], 2)
        self.assertEqual(body["activity"]["A"]["transport_retries"], 1)
        self.assertEqual(body["activity"]["A"]["observed_invocation_records"], 1)
        self.assertEqual(body["status"], "NOT_READY")

    def test_failed_history_cannot_be_hidden_by_later_high_score(self):
        self.terminal()
        for slot in review.SLOTS:
            self.retain_inert_review(slot, 5)
        decision = self.decide_inert()
        body = self.read(decision)["body"]
        self.assertEqual(tuple(body["scores"]), (5, 5, 5))  # inert semantic stand-in; census is real
        self.assertIn("A_UNRECONCILED_ACTIVITY", body["blockers"])
        self.assertIn("MULTIPLE_REVIEW_CALLS_OR_OUTPUTS", body["activity"]["A"]["issues"])
        with patch.object(review, "_receipt_details", side_effect=self.inert_semantic), self.assertRaises(ValidationError):
            review.require_internal_review_pass(self.registry, self.ledger, decision_hash=decision.sha256,
                revision_artifact_hash=self.first.revision_record.sha256)

    def test_success_and_terminal_for_same_invocation_are_contradictory(self):
        fixture = self.direct_receipt_fixture()
        self.terminal(invocation=self.registry.get_metadata(fixture.receipt.invocation_artifact_hash))
        result = review.record_manuscript_review(self.registry, self.ledger,
            round_hash=self.round.sha256, slot="A", semantic_receipt_hash=fixture.record.sha256)
        self.assertEqual(self.read(result)["body"]["status"], "INVALID")
        body = self.read(review.decide_manuscript_review(self.registry, self.ledger,
            round_hash=self.round.sha256))["body"]
        self.assertIn("CONTRADICTORY_OR_REPEATED_CALL_OUTCOMES", body["activity"]["A"]["issues"])

    def test_unknown_transport_and_unsupported_cancelled_terminal_block(self):
        invocation = self.invocation()
        self.terminal(invocation=invocation, network_used=True, state="CANCELLED")
        body = self.read(self.decide_inert())["body"]
        self.assertIsNone(body["activity"]["A"]["transport_attempts"])
        self.assertIn("INVALID_TERMINAL", body["activity"]["A"]["issues"])
        self.assertIn("UNKNOWN_TRANSPORT_ATTEMPTS", body["activity"]["A"]["issues"])
        self.assertEqual(body["status"], "NOT_READY")

    def test_failed_provider_history_cannot_authorize_revision_resampling(self):
        for slot in review.SLOTS:
            self.retain_inert_review(slot, 3)
        self.terminal()
        with self.assertRaisesRegex(ValidationError, "unresolved"):
            self.rejected_plan()

    def test_conflicting_retry_projection_is_unknown_not_a_favorable_count(self):
        invocation = self.invocation()
        gateway = self.put(canonical_json_bytes({"request_id": "inert-A-first", "network_used": False,
            "attempts": [{"attempt": 1, "status": "RESPONSE", "status_code": 503}]}), "external_response_receipt")
        self.terminal(invocation=invocation, rows=[{"attempt": 1, "status": "RESPONSE", "status_code": 200}],
            extra_parents=(gateway.sha256,))
        body = self.read(self.decide_inert())["body"]
        self.assertIn("CONTRADICTORY_TRANSPORT_ATTEMPTS", body["activity"]["A"]["issues"])
        self.assertEqual(body["activity"]["A"]["observed_transport_attempts"], 1)
        self.assertIsNone(body["activity"]["A"]["transport_attempts"])
        self.assertIsNone(body["activity"]["A"]["transport_retries"])
        self.assertEqual(body["status"], "NOT_READY")

    def test_wrong_slot_parent_join_cannot_reconcile_an_output(self):
        invocation = self.invocation("B")
        self.output(invocation, "A")
        body = self.read(self.decide_inert())["body"]
        self.assertIn("UNRECONCILED_OUTPUT", body["activity"]["A"]["issues"])
        self.assertIn("INCOMPLETE_INVOCATION", body["activity"]["B"]["issues"])
        with self.assertRaisesRegex(ValidationError, "resampling"):
            review.manuscript_review_request(self.registry, self.ledger, round_hash=self.round.sha256, slot="A")

    def test_unassignable_provider_identity_blocks_request_and_readiness(self):
        self.put(canonical_json_bytes({"kind": "MODEL_INVOCATION", "invocation_id": {"size": 12}}), "model_invocation")
        with self.assertRaisesRegex(ValidationError, "resampling"):
            review.manuscript_review_request(self.registry, self.ledger, round_hash=self.round.sha256, slot="A")
        body = self.read(self.decide_inert())["body"]
        self.assertIn("UNASSIGNABLE_INVOCATION_IDENTITY", body["activity"]["A"]["issues"])
        self.assertEqual(body["status"], "NOT_READY")


if __name__ == "__main__":
    unittest.main()
