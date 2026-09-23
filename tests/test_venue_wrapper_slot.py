"""Offline contract tests for requirement-label equivalence in Venue slots.

The generic scientific owner is mocked explicitly. These are real local
registry envelopes but not provider custody, paper authority, completed
scientific rounds, or evidence of successful live Venue validation.
"""

from dataclasses import replace
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from scientist_one import paper_pipeline as paper
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ValidationError
from scientist_one.gates import JudgmentSubjectKind, SemanticJudgmentReceipt
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role


class VenueWrapperSlotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.registry = ArtifactRegistry(self.temporary.name)
        self.ledger = EventLedger(self.temporary.name, "runs/wrapper-slot/events.jsonl")
        self.run_id = "wrapper-slot"
        self.prefix = tuple(self.put({"branch": index}).sha256 for index in range(4))
        self.sources = tuple(self.put({"source": index}).sha256 for index in range(2))
        self.profile_sha = "a" * 64
        self.profile = SimpleNamespace(profile_id="contract-profile", sha256=self.profile_sha, artifact_requirements=("code",))
        self.bundle = SimpleNamespace(method_code_bindings=(SimpleNamespace(code_artifact_hash=self.sources[0]),))
        self.manifest = SimpleNamespace(
            schema_version="venue-readiness/v2", manuscript_content_artifact_hash=self.sources[1],
            source_artifact_hashes=self.sources,
            artifact_bindings=(SimpleNamespace(requirement="code", artifact_hashes=(self.sources[0],)),),
        )
        self.first_wrapper = self.wrapper("first")
        self.second_wrapper = self.wrapper("second")
        self.first_context = (*self.prefix, self.first_wrapper.sha256)
        self.second_context = (*self.prefix, self.second_wrapper.sha256)

    def put(self, value, **kwargs):
        options = dict(
            logical_type="wrapper_slot_contract", origin="offline contract fixture",
            creator_role=Role.SCIENTIFIC_REVIEWER, creation_command=("contract-fixture",),
            parent_artifacts=(), schema_version="1.0", mime_type="application/json",
            validation_result="PASS", frozen=True,
        )
        options.update(kwargs)
        return self.registry.put_json(value, **options)

    def wrapper(self, label, *, changes=None, metadata=None, extra=None):
        receipt = paper.VenueRequirementReceipt(
            receipt_id=label, run_id=self.run_id, requirement="code",
            candidate_artifact_hash=self.prefix[0], bundle_artifact_hash=self.prefix[1],
            profile_id=self.profile.profile_id, profile_sha256=self.profile_sha,
            profile_artifact_hash=self.prefix[2], readiness_manifest_hash=self.prefix[3],
            source_artifact_hashes=self.sources, semantic_judgment_hash=None,
        )
        receipt = replace(receipt, **(changes or {}))
        value = receipt.to_dict()
        value.update(extra or {})
        options = dict(
            logical_type="venue_requirement_receipt",
            origin="registry-resolved venue requirement over exact paper authority",
            creation_command=("scientist-one", "record-venue-requirement"),
            parent_artifacts=(
                receipt.candidate_artifact_hash, receipt.bundle_artifact_hash,
                receipt.profile_artifact_hash, receipt.readiness_manifest_hash,
                *((receipt.semantic_judgment_hash,) if receipt.semantic_judgment_hash else ()),
                *receipt.source_artifact_hashes,
            ),
        )
        options.update(metadata or {})
        return self.put(value, **options)

    def judgment(self, label, context, *, outcome="SCORE:0.8", evidence=None, subject=None):
        custody = tuple(self.put({"judgment": label, "item": index}).sha256 for index in range(7))
        receipt = SemanticJudgmentReceipt(
            judgment_id=f"judgment-{label}", subject_kind=JudgmentSubjectKind.VENUE_DIMENSION,
            subject_id=subject or paper.READINESS_DIMENSIONS[0], outcome=outcome,
            evidence_hashes=self.sources if evidence is None else evidence, context_hashes=context,
            instructions_artifact_hash=custody[0], input_artifact_hash=custody[1],
            output_schema_artifact_hash=custody[2], invocation_artifact_hash=custody[3],
            request_intent_artifact_hash=custody[4], provider_response_artifact_hash=custody[5],
            model_output_artifact_hash=custody[6], invocation_id=f"invocation-{label}",
            provider_id="contract-provider", provider_version="1.0", model="contract-model",
            model_version="1.0", prompt_template_id="contract-template", prompt_template_version="1.0",
            prompt_template_hash="b" * 64, structured_output_sha256="c" * 64,
            reviewer_id="contract-reviewer", reviewer_role=Role.SCIENTIFIC_REVIEWER,
            governing_rule="One outcome-independent venue slot.", rationale="Offline contract only.",
        )
        record = self.put(
            receipt.to_dict(), logical_type="scientific_semantic_judgment_receipt",
            origin="content-bound scientific review of a captured advisory model judgment",
            creation_command=("scientist-one", "record-semantic-judgment"),
            parent_artifacts=(*receipt.evidence_hashes, *receipt.context_hashes, *receipt.custody_artifact_hashes),
        )
        return record, receipt

    def invoke(self, selected, **kwargs):
        return paper._require_live_venue_semantic_judgment(
            self.registry, self.ledger, run_id=self.run_id,
            receipt_artifact_hash=selected.sha256, subject_kind=JudgmentSubjectKind.VENUE_DIMENSION,
            subject_id=paper.READINESS_DIMENSIONS[0], outcome="SCORE:0.8",
            evidence_hashes=self.sources, context_hashes=self.first_context, **kwargs,
        )

    def equivalent(self, other):
        return paper._venue_requirement_contexts_equivalent(
            self.registry, run_id=self.run_id, selected_context=self.first_context,
            candidate_context=other,
        )

    def test_labels_change_hash_but_preserve_full_requirement_resolver(self):
        self.assertNotEqual(self.first_wrapper.sha256, self.second_wrapper.sha256)
        resolved = tuple(paper._resolve_venue_requirement_receipt(
            self.registry, self.ledger, record.sha256, None, self.bundle, self.profile, self.manifest,
            run_id=self.run_id, candidate_artifact_hash=self.prefix[0], bundle_artifact_hash=self.prefix[1],
            profile_artifact_hash=self.prefix[2], readiness_manifest_hash=self.prefix[3],
        ) for record in (self.first_wrapper, self.second_wrapper))
        self.assertEqual(replace(resolved[0], receipt_id="same"), replace(resolved[1], receipt_id="same"))
        self.assertTrue(self.equivalent(self.second_context))

    def test_relabel_conflicts_for_different_and_same_outcomes_with_original_context(self):
        first, _ = self.judgment("first", self.first_context)
        second, _ = self.judgment("second", self.second_context, outcome="SCORE:0.9")
        with patch.object(paper, "require_scientific_semantic_judgment_receipt") as owner:
            with self.assertRaisesRegex(ValidationError, "conflicting live outcomes"):
                self.invoke(first)
            self.assertEqual(owner.call_args.kwargs["receipt_artifact_hash"], second.sha256)
            self.assertEqual(owner.call_args.kwargs["context_hashes"], self.second_context)
            self.assertEqual(owner.call_args_list[0].kwargs["context_hashes"], self.first_context)
            with self.assertRaisesRegex(ValidationError, "conflicting live outcomes"):
                self.invoke(first, _before_event_index=1)
        # An invalid later sibling cannot hide a further same-outcome sibling.
        same, _ = self.judgment("same", self.second_context)
        def replay(*args, **kwargs):
            if kwargs["receipt_artifact_hash"] == second.sha256:
                raise ValidationError("contract-only invalid live owner")
        with patch.object(paper, "require_scientific_semantic_judgment_receipt", side_effect=replay) as owner:
            with self.assertRaisesRegex(ValidationError, "conflicting live outcomes"):
                self.invoke(first)
            self.assertIn(same.sha256, [item.kwargs["receipt_artifact_hash"] for item in owner.call_args_list])

    def test_single_selected_and_invalid_sibling_retain_exact_binding(self):
        first, _ = self.judgment("first", self.first_context)
        with patch.object(paper, "require_scientific_semantic_judgment_receipt") as owner:
            self.invoke(first)
            self.assertEqual(owner.call_count, 1)
        second, _ = self.judgment("invalid", self.second_context)
        def replay(*args, **kwargs):
            if kwargs["receipt_artifact_hash"] == second.sha256:
                raise ValidationError("offline is not live authority")
        with patch.object(paper, "require_scientific_semantic_judgment_receipt", side_effect=replay):
            self.invoke(first)
        with patch.object(paper, "require_scientific_semantic_judgment_receipt", side_effect=ValidationError("selected exact binding failed")):
            with self.assertRaisesRegex(ValidationError, "selected exact binding failed"):
                self.invoke(first)

    def test_substantive_fields_order_and_branch_are_not_erased(self):
        other_semantic = self.put({"semantic": "different source"}).sha256
        for index, changes in enumerate((
            {"requirement": "data"}, {"profile_id": "other-profile"},
            {"profile_sha256": "d" * 64}, {"source_artifact_hashes": tuple(reversed(self.sources))},
            {"semantic_judgment_hash": other_semantic},
        )):
            with self.subTest(changes=changes):
                other = self.wrapper(f"substantive-{index}", changes=changes)
                self.assertFalse(self.equivalent((*self.prefix, other.sha256)))
        self.assertFalse(self.equivalent((*self.prefix[:3], self.sources[0], self.second_wrapper.sha256)))
        self.assertFalse(self.equivalent((*self.prefix, self.second_wrapper.sha256, self.first_wrapper.sha256)))
        self.assertFalse(self.equivalent(tuple(reversed(self.second_context))))
        with self.assertRaises(ValidationError):
            paper._venue_requirement_contexts_equivalent(
                self.registry, run_id="other-run", selected_context=self.first_context,
                candidate_context=self.second_context,
            )

    def test_multiple_wrappers_are_compared_in_order_with_no_label_tie_break(self):
        other_first = self.wrapper("other-first", changes={"requirement": "data"})
        other_second = self.wrapper("other-second", changes={"requirement": "data"})
        selected = (*self.first_context, other_first.sha256)
        equivalent = (*self.second_context, other_second.sha256)
        self.assertTrue(paper._venue_requirement_contexts_equivalent(
            self.registry, run_id=self.run_id, selected_context=selected,
            candidate_context=equivalent,
        ))
        self.assertFalse(paper._venue_requirement_contexts_equivalent(
            self.registry, run_id=self.run_id, selected_context=selected,
            candidate_context=(*self.prefix, other_second.sha256, self.second_wrapper.sha256),
        ))

    def test_invalid_envelopes_never_become_siblings(self):
        first, _ = self.judgment("first", self.first_context)
        cases = (
            {"metadata": {"creator_role": Role.PAPER_WRITER}},
            {"metadata": {"parent_artifacts": self.prefix}},
            {"metadata": {"schema_version": "2.0"}},
            {"extra": {"unexpected": "field"}},
            {"changes": {"run_id": "other-run"}},
        )
        for index, changes in enumerate(cases):
            wrapper = self.wrapper(f"invalid-{index}", **changes)
            self.judgment(f"invalid-{index}", (*self.prefix, wrapper.sha256))
        with patch.object(paper, "require_scientific_semantic_judgment_receipt") as owner:
            self.invoke(first)
            self.assertEqual(owner.call_count, 1)

    def test_other_dimension_and_evidence_do_not_conflict(self):
        first, _ = self.judgment("first", self.first_context)
        self.judgment("dimension", self.second_context, subject=paper.READINESS_DIMENSIONS[1])
        self.judgment("evidence", self.second_context, evidence=(self.sources[0],))
        with patch.object(paper, "require_scientific_semantic_judgment_receipt") as owner:
            self.invoke(first)
            self.assertEqual(owner.call_count, 1)

    def test_dimension_readback_reaches_shared_equivalence_boundary(self):
        first, _ = self.judgment("first", self.first_context)
        receipt = paper.VenueDimensionAssessmentReceipt(
            assessment_id="contract-dimension", run_id=self.run_id, dimension=paper.READINESS_DIMENSIONS[0],
            score=0.8, candidate_artifact_hash=self.prefix[0], bundle_artifact_hash=self.prefix[1],
            profile_id=self.profile.profile_id, profile_sha256=self.profile_sha,
            profile_artifact_hash=self.prefix[2], readiness_manifest_hash=self.prefix[3],
            requirement_receipt_hashes=(self.first_wrapper.sha256,), semantic_judgment_hash=first.sha256,
        )
        record = self.put(
            receipt.to_dict(), logical_type="venue_dimension_assessment",
            parent_artifacts=(*self.first_context, first.sha256, *self.sources),
        )
        def readback():
            return paper._resolve_venue_dimension_assessment(
                self.registry, self.ledger, record.sha256, None, self.bundle, self.profile,
                self.manifest, (self.first_wrapper.sha256,), run_id=self.run_id,
                candidate_artifact_hash=self.prefix[0], bundle_artifact_hash=self.prefix[1],
                profile_artifact_hash=self.prefix[2], readiness_manifest_hash=self.prefix[3],
            )
        with patch.object(paper, "require_scientific_semantic_judgment_receipt"):
            self.assertEqual(readback(), receipt)
            self.judgment("later", self.second_context, outcome="SCORE:0.9")
            with self.assertRaisesRegex(ValidationError, "conflicting live outcomes"):
                readback()


if __name__ == "__main__":
    unittest.main()
