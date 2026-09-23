"""Offline rejected-qualifier boundary regressions.

All judgments and fixture claims are synthetic and non-evidentiary. Narrow
semantic/custody owners are inert doubles; the canonical rejected-claim
boundary, semantic dispatcher, complete graph replay, and selector are real.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scientist_one.claims import ClaimEvidenceUse, EvidenceKind as GraphEvidenceKind
from scientist_one.gates import JudgmentSubjectKind, SemanticJudgmentReceipt
import scientist_one.research_state as research_state
from scientist_one.roles import Role


CLAIM_ID = "claim-canonical"
SLOT_ID = "qualifier-slot-hash"
RUN_ID = "synthetic-run"
STAMP = "2026-09-23T00:00:00Z"
HASHES = tuple(f"{index:064x}" for index in range(1, 15))


def _judgment(
    subject_kind: JudgmentSubjectKind,
    subject_id: str,
    *,
    outcome: str = "CLAIM_QUALIFIER_REJECTED",
    input_hash: str = HASHES[0],
    evidence_hash: str = HASHES[1],
    context_hash: str = HASHES[2],
    instructions_hash: str = HASHES[3],
    output_schema_hash: str = HASHES[4],
) -> SemanticJudgmentReceipt:
    return SemanticJudgmentReceipt(
        judgment_id="judgment-fixture",
        subject_kind=subject_kind,
        subject_id=subject_id,
        outcome=outcome,
        evidence_hashes=(evidence_hash,),
        context_hashes=(context_hash,),
        instructions_artifact_hash=instructions_hash,
        input_artifact_hash=input_hash,
        output_schema_artifact_hash=output_schema_hash,
        invocation_artifact_hash=HASHES[5],
        request_intent_artifact_hash=HASHES[6],
        provider_response_artifact_hash=HASHES[7],
        model_output_artifact_hash=HASHES[8],
        invocation_id="invocation-fixture",
        provider_id="synthetic-provider",
        provider_version="fixture-v1",
        model="synthetic-model",
        model_version="fixture-v1",
        prompt_template_id="qualifier-template",
        prompt_template_version="1",
        prompt_template_hash=HASHES[9],
        structured_output_sha256=HASHES[10],
        reviewer_id="synthetic-reviewer",
        reviewer_role=Role.SCIENTIFIC_REVIEWER,
        governing_rule="synthetic qualifier rejection fixture",
        rationale="synthetic negative decision",
    )


class _Registry:
    def __init__(self, payloads: dict[str, bytes]) -> None:
        self.payloads = payloads
        self.logical_types: dict[str, str] = {}

    def get_bytes(self, digest: str) -> bytes:
        return self.payloads[digest]

    def list_records(self):
        return self.records

    def get_metadata(self, digest: str):
        return SimpleNamespace(
            logical_type=self.logical_types.get(digest, "synthetic_evidence")
        )


def _load_state_fixture_helpers() -> dict[str, object]:
    """Reuse the complete graph builder without importing a test package."""

    return runpy.run_path(str(Path(__file__).with_name("test_vnext_state.py")))


class RejectedQualifierDispatcherTests(unittest.TestCase):
    def _dispatcher(
        self,
        judgment: SemanticJudgmentReceipt,
        retained_input: bytes | None = None,
    ):
        if retained_input is None:
            retained_input = research_state.canonical_json_bytes(
                {
                    "qualifier_projection": {
                        "claim_id": CLAIM_ID,
                        "claim_text": "Synthetic claim text.",
                        "claim_producer_role": Role.EXPERIMENT_RUNNER.value,
                        "claim_confirmatory": False,
                        "claim_evidence_use": ClaimEvidenceUse.SCIENTIFIC.value,
                    }
                }
            ) + b"\n"
        registry = _Registry(
            {
                HASHES[11]: research_state.canonical_json_bytes(judgment.to_dict())
                + b"\n",
                judgment.input_artifact_hash: retained_input,
                HASHES[1]: b'{"synthetic":true}',
            }
        )
        repository = SimpleNamespace(
            registry=registry,
            ledger=object(),
            run_id=RUN_ID,
        )
        claim = SimpleNamespace(
            object_id=CLAIM_ID,
            claim_text="Synthetic claim text.",
            producer=Role.EXPERIMENT_RUNNER,
            confirmatory=False,
            evidence_use=SimpleNamespace(value=ClaimEvidenceUse.SCIENTIFIC.value),
        )
        judgment_record = SimpleNamespace(sha256=HASHES[11], created_at=STAMP)
        return repository, claim, judgment_record, retained_input

    def test_qualifier_slot_hash_dispatches_to_qualifier_owner(self) -> None:
        judgment = _judgment(JudgmentSubjectKind.CLAIM_QUALIFIER, SLOT_ID)
        repository, claim, record, retained = self._dispatcher(judgment)
        semantics_record = SimpleNamespace(
            sha256=HASHES[12],
            parent_artifacts=(HASHES[13],),
        )
        semantics_receipt = SimpleNamespace(receipt_id="synthetic-semantics")
        request = SimpleNamespace(subject_id=SLOT_ID)
        resolved = SimpleNamespace(outcome="CLAIM_QUALIFIER_REJECTED")
        with (
            patch.object(
                research_state,
                "require_claim_semantics_receipt",
                return_value=semantics_receipt,
            ) as require_semantics,
            patch.object(
                research_state,
                "_claim_qualifier_request_from_retained_input",
                return_value=request,
            ) as replay_request,
            patch.object(
                research_state,
                "_require_unique_scientific_claim_qualifier_judgment",
                return_value=resolved,
            ) as unique_judgment,
        ):
            proposal, result = research_state.ResearchStateRepository._resolve_rejected_claim_semantic_basis(
                repository,
                claim,
                record,
                (semantics_record,),
            )

        self.assertIs(proposal, semantics_receipt)
        self.assertIs(result, resolved)
        require_semantics.assert_called_once_with(
            repository.registry,
            repository.ledger,
            receipt_artifact_hash=HASHES[12],
            expected_run_id=RUN_ID,
            expected_claim_graph_artifact_hash=HASHES[13],
            expected_claim_id=CLAIM_ID,
        )
        replay_request.assert_called_once_with(
            repository.registry,
            repository.ledger,
            run_id=RUN_ID,
            retained_input=retained,
        )
        unique_judgment.assert_called_once_with(
            repository.registry,
            repository.ledger,
            run_id=RUN_ID,
            request=request,
            selected_artifact_hash=HASHES[11],
            expected_outcome="CLAIM_QUALIFIER_REJECTED",
        )

    def test_claim_semantics_with_exact_claim_id_still_dispatches(self) -> None:
        judgment = _judgment(
            JudgmentSubjectKind.CLAIM_SEMANTICS,
            CLAIM_ID,
            outcome="CLAIM_SEMANTICS_REJECTED",
        )
        retained = research_state.canonical_json_bytes(
            {"proposal_artifact_hash": HASHES[13]}
        ) + b"\n"
        repository, claim, record, _retained = self._dispatcher(judgment, retained)
        proposal = SimpleNamespace(proposal_id="synthetic-claim-proposal")
        resolved = SimpleNamespace(rationale="synthetic exact-ID rejection")
        with patch.object(
            research_state,
            "_require_scientific_claim_semantics_judgment",
            return_value=(proposal, resolved),
        ) as semantic_owner:
            observed_proposal, observed_resolution = (
                research_state.ResearchStateRepository._resolve_rejected_claim_semantic_basis(
                    repository,
                    claim,
                    record,
                    (),
                )
            )
        self.assertIs(observed_proposal, proposal)
        self.assertIs(observed_resolution, resolved)
        semantic_owner.assert_called_once_with(
            repository.registry,
            repository.ledger,
            proposal_artifact_hash=HASHES[13],
            reference_support_semantic_judgment_artifact_hash=None,
            semantic_authority_artifact_hash=HASHES[11],
            expected_run_id=RUN_ID,
            expected_outcome="CLAIM_SEMANTICS_REJECTED",
        )

    def test_five_claim_projection_identity_mismatches_reject(self) -> None:
        canonical_projection = {
            "claim_id": CLAIM_ID,
            "claim_text": "Synthetic claim text.",
            "claim_producer_role": Role.EXPERIMENT_RUNNER.value,
            "claim_confirmatory": False,
            "claim_evidence_use": ClaimEvidenceUse.SCIENTIFIC.value,
        }
        for field, bad_value in (
            ("claim_id", "substituted-claim"),
            ("claim_text", "substituted prose"),
            ("claim_producer_role", Role.SCIENTIFIC_REVIEWER.value),
            ("claim_confirmatory", True),
            ("claim_evidence_use", "PRESENTATION_ONLY"),
        ):
            with self.subTest(field=field):
                projection = dict(canonical_projection)
                projection[field] = bad_value
                retained = research_state.canonical_json_bytes(
                    {"qualifier_projection": projection}
                ) + b"\n"
                judgment = _judgment(
                    JudgmentSubjectKind.CLAIM_QUALIFIER,
                    SLOT_ID,
                )
                repository, claim, record, _retained = self._dispatcher(
                    judgment,
                    retained,
                )
                semantics_record = SimpleNamespace(
                    sha256=HASHES[12],
                    parent_artifacts=(HASHES[13],),
                )
                with (
                    patch.object(
                        research_state,
                        "require_claim_semantics_receipt",
                        return_value=SimpleNamespace(),
                    ),
                    patch.object(
                        research_state,
                        "_claim_qualifier_request_from_retained_input",
                        return_value=SimpleNamespace(subject_id=SLOT_ID),
                    ),
                    patch.object(
                        research_state,
                        "_require_unique_scientific_claim_qualifier_judgment",
                        return_value=SimpleNamespace(),
                    ),
                ):
                    with self.assertRaisesRegex(
                        research_state.ValidationError,
                        "qualifier rejection differs from the canonical Claim",
                    ):
                        research_state.ResearchStateRepository._resolve_rejected_claim_semantic_basis(
                            repository,
                            claim,
                            record,
                            (semantics_record,),
                        )

    def test_sibling_semantic_subjects_keep_exact_claim_identity(self) -> None:
        for kind in (
            JudgmentSubjectKind.CLAIM_SEMANTICS,
            JudgmentSubjectKind.REFERENCE_SUPPORT,
        ):
            with self.subTest(kind=kind.value):
                judgment = _judgment(kind, SLOT_ID)
                repository, claim, record, _retained = self._dispatcher(judgment)
                with self.assertRaisesRegex(
                    research_state.ValidationError,
                    "names another claim",
                ):
                    research_state.ResearchStateRepository._resolve_rejected_claim_semantic_basis(
                        repository,
                        claim,
                        record,
                        (),
                    )

    def test_qualifier_rejection_requires_one_semantics_receipt(self) -> None:
        judgment = _judgment(JudgmentSubjectKind.CLAIM_QUALIFIER, SLOT_ID)
        repository, claim, record, _retained = self._dispatcher(judgment)
        for receipts in ((), (object(), object())):
            with self.subTest(receipt_count=len(receipts)):
                with self.assertRaisesRegex(
                    research_state.ValidationError,
                    "requires one accepted semantics receipt",
                ):
                    research_state.ResearchStateRepository._resolve_rejected_claim_semantic_basis(
                        repository,
                        claim,
                        record,
                        receipts,
                    )


class RejectedQualifierBoundaryTests(unittest.TestCase):
    """Use the repository's existing all-kind graph fixture at the boundary."""

    def setUp(self) -> None:
        helpers = _load_state_fixture_helpers()
        fixture_type = helpers["ResearchStateRepositoryTests"]
        self.fixture = fixture_type(
            "test_verified_claim_is_a_distinct_producer_view_of_checked_registry_graph"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.registry = self.fixture.registry
        self.ledger = self.fixture.ledger
        self.repository = self.fixture.repository
        self.claim, self.judgment_record, self.semantics_record = (
            self._fixture_claim()
        )

    def _put_json(self, value, logical_type: str, role: Role, parents=()):
        return self.registry.put_json(
            value,
            logical_type=logical_type,
            origin=f"synthetic non-evidentiary boundary fixture: {logical_type}",
            creator_role=role,
            creation_command=("scientist-one", "synthetic-rejection-fixture"),
            parent_artifacts=tuple(parents),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )

    def _fixture_claim(self):
        claim_text = "Synthetic fixture claim with a narrow scope."
        graph_artifact, _receipts = self.fixture.claim_graph_bundle(
            claim_id=CLAIM_ID,
            claim_text=claim_text,
            confirmatory=False,
            evidence_use=ClaimEvidenceUse.NON_EVIDENTIARY,
        )
        graph_wrapper = research_state.safe_json_loads(
            self.registry.get_bytes(graph_artifact.sha256)
        )
        graph = graph_wrapper["graph"]
        graph_claim = next(
            item for item in graph["claims"] if item["claim_id"] == CLAIM_ID
        )
        evidence_ids = tuple(
            link["evidence_id"] for link in graph_claim["evidence_links"]
        )
        graph_receipts = self.repository._claim_graph_receipt_closure(
            graph_artifact
        )
        semantics_record = self._put_json(
            {"synthetic": True, "semantics": "inert source-owner fixture"},
            research_state.CLAIM_SEMANTICS_RECEIPT_LOGICAL_TYPE,
            Role.CLAIM_VERIFIER,
            (graph_artifact.sha256,),
        )
        projection = {
            "claim_id": CLAIM_ID,
            "claim_text": claim_text,
            "claim_producer_role": graph_claim["producer_role"],
            "claim_confirmatory": graph_claim["confirmatory"],
            "claim_evidence_use": graph_claim["evidence_use"],
        }
        retained = self._put_json(
            {"qualifier_projection": projection},
            "scientific_semantic_judgment_input",
            Role.SCIENTIFIC_REVIEWER,
        )
        evidence_hashes = tuple(
            item["artifact_hash"] for item in graph["evidence"][:2]
        )
        custody = []
        for logical_type in (
            "scientific_semantic_judgment_instructions",
            "scientific_semantic_judgment_output_schema",
            "scientific_semantic_judgment_invocation",
            "scientific_semantic_judgment_request_intent",
            "scientific_semantic_judgment_provider_response",
            "scientific_semantic_judgment_model_output",
        ):
            custody.append(
                self._put_json(
                    {"synthetic": True, "slot": logical_type},
                    logical_type,
                    Role.SCIENTIFIC_REVIEWER,
                )
            )
        judgment = SemanticJudgmentReceipt(
            judgment_id="synthetic-qualifier-judgment",
            subject_kind=JudgmentSubjectKind.CLAIM_QUALIFIER,
            subject_id=SLOT_ID,
            outcome="CLAIM_QUALIFIER_REJECTED",
            evidence_hashes=(evidence_hashes[0],),
            context_hashes=(evidence_hashes[1],),
            instructions_artifact_hash=custody[0].sha256,
            input_artifact_hash=retained.sha256,
            output_schema_artifact_hash=custody[1].sha256,
            invocation_artifact_hash=custody[2].sha256,
            request_intent_artifact_hash=custody[3].sha256,
            provider_response_artifact_hash=custody[4].sha256,
            model_output_artifact_hash=custody[5].sha256,
            invocation_id="synthetic-qualifier-invocation",
            provider_id="synthetic-provider",
            provider_version="fixture-v1",
            model="synthetic-model",
            model_version="fixture-v1",
            prompt_template_id="synthetic-qualifier-template",
            prompt_template_version="1",
            prompt_template_hash="d" * 64,
            structured_output_sha256="e" * 64,
            reviewer_id="synthetic-reviewer",
            reviewer_role=Role.SCIENTIFIC_REVIEWER,
            governing_rule="synthetic offline qualifier boundary",
            rationale="Synthetic qualifier rejection; no provider authority.",
        )
        judgment_record = self._put_json(
            judgment.to_dict(),
            "scientific_semantic_judgment_receipt",
            Role.SCIENTIFIC_REVIEWER,
            judgment.custody_artifact_hashes,
        )
        sources = tuple(
            sorted(
                {
                    graph_artifact.sha256,
                    *graph_receipts,
                    semantics_record.sha256,
                    judgment_record.sha256,
                }
            )
        )
        claim = research_state.Claim(
            object_id=CLAIM_ID,
            producer=Role(graph_claim["producer_role"]),
            status=research_state.RecordStatus.REJECTED,
            created_at=STAMP,
            claim_type=research_state.ClaimType.QUALITATIVE,
            claim_text=claim_text,
            scope="SYNTHETIC_SCOPE",
            evidence_ids=evidence_ids,
            source_artifact_ids=sources,
            verification_method="SyntheticClaimQualifier.verify/v1",
            verification_status=research_state.VerificationStatus.REJECTED,
            confidence=0.0,
            expressed_strength=research_state.ClaimStrength.UNSUPPORTED,
            permitted_strength=research_state.ClaimStrength.UNSUPPORTED,
            failure_reason=judgment.rationale,
            review_history=(
                research_state.ClaimReview(
                    reviewer=Role.CLAIM_VERIFIER,
                    timestamp=STAMP,
                    verification_status=research_state.VerificationStatus.REJECTED,
                    reason=judgment.rationale,
                    evidence_ids=evidence_ids,
                    source_artifact_ids=sources,
                ),
            ),
            confirmatory=graph_claim["confirmatory"],
            evidence_use=ClaimEvidenceUse(graph_claim["evidence_use"]),
            authority_artifact_hashes=sources,
        )
        return claim, judgment_record, semantics_record

    def _owner_doubles(self):
        judgment = SemanticJudgmentReceipt.from_dict(
            research_state.safe_json_loads(
                self.registry.get_bytes(self.judgment_record.sha256)
            )
        )
        retained = self.registry.get_bytes(judgment.input_artifact_hash)
        request = SimpleNamespace(subject_id=SLOT_ID)
        semantics = SimpleNamespace(
            claim_type=self.claim.claim_type,
            scope=self.claim.scope,
            verification_method=self.claim.verification_method,
            dependency_claim_ids=(),
            dependency_bindings=(),
        )
        resolved = SimpleNamespace(rationale=self.claim.failure_reason)
        return retained, request, semantics, resolved

    def test_negative_qualifier_flows_through_real_canonical_boundary(self) -> None:
        retained, request, semantics, resolved = self._owner_doubles()
        with (
            patch.object(
                research_state,
                "require_claim_semantics_receipt",
                return_value=semantics,
            ) as require_semantics,
            patch.object(
                research_state,
                "_claim_qualifier_request_from_retained_input",
                return_value=request,
            ) as replay_request,
            patch.object(
                research_state,
                "_require_unique_scientific_claim_qualifier_judgment",
                return_value=resolved,
            ) as unique_judgment,
        ):
            by_content, _by_identity = self.repository._indexes(
                self.repository._stored_objects()
            )
            authority = self.repository._resolve_object_authority(
                self.claim,
                by_content,
            )

        self.assertFalse(authority.scientific_evidence_eligible)
        self.assertIsNone(authority.claim_semantics)
        require_semantics.assert_called_once_with(
            self.registry,
            self.ledger,
            receipt_artifact_hash=self.semantics_record.sha256,
            expected_run_id=self.repository.run_id,
            expected_claim_graph_artifact_hash=(
                self.semantics_record.parent_artifacts[0]
            ),
            expected_claim_id=CLAIM_ID,
        )
        replay_request.assert_called_once_with(
            self.registry,
            self.ledger,
            run_id=self.repository.run_id,
            retained_input=retained,
        )
        unique_judgment.assert_called_once_with(
            self.registry,
            self.ledger,
            run_id=self.repository.run_id,
            request=request,
            selected_artifact_hash=self.judgment_record.sha256,
            expected_outcome="CLAIM_QUALIFIER_REJECTED",
        )

    def test_proposal_field_evidence_closure_and_review_reason_mutations_fail(
        self,
    ) -> None:
        _retained, request, semantics, resolved = self._owner_doubles()
        verification_receipt_hash = next(
            digest
            for digest in self.claim.authority_artifact_hashes
            if self.registry.get_metadata(digest).logical_type
            == f"claim_evidence_verification_receipt.{GraphEvidenceKind.RESULT.value}"
        )
        pruned_closure = tuple(
            digest
            for digest in self.claim.authority_artifact_hashes
            if digest != verification_receipt_hash
        )
        mutations = (
            (
                replace(self.claim, scope="MUTATED_SCOPE", content_hash=None),
                "rejected Claim semantics differ from their reviewed proposal",
            ),
            (
                replace(
                    self.claim,
                    authority_artifact_hashes=pruned_closure,
                    source_artifact_ids=pruned_closure,
                    review_history=(
                        replace(
                            self.claim.review_history[0],
                            source_artifact_ids=pruned_closure,
                        ),
                    ),
                    content_hash=None,
                ),
                "rejected Claim differs from its exact independent review and closure",
            ),
            (
                replace(
                    self.claim,
                    review_history=(
                        replace(
                            self.claim.review_history[0],
                            reason="Mutated caller prose.",
                        ),
                    ),
                    content_hash=None,
                ),
                "rejected Claim differs from its exact independent review and closure",
            ),
        )
        for candidate, expected_error in mutations:
            with self.subTest(candidate=candidate.scope, reason=candidate.failure_reason):
                with (
                    patch.object(
                        research_state,
                        "require_claim_semantics_receipt",
                        return_value=semantics,
                    ),
                    patch.object(
                        research_state,
                        "_claim_qualifier_request_from_retained_input",
                        return_value=request,
                    ),
                    patch.object(
                        research_state,
                        "_require_unique_scientific_claim_qualifier_judgment",
                        return_value=resolved,
                    ),
                ):
                    by_content, _by_identity = self.repository._indexes(
                        self.repository._stored_objects()
                    )
                    with self.assertRaisesRegex(
                        research_state.ValidationError,
                        expected_error,
                    ):
                        self.repository._resolve_object_authority(
                            candidate,
                            by_content,
                        )


class UniqueQualifierSelectionTests(unittest.TestCase):
    """Exercise selector invariants with a narrow semantic-owner interface."""

    def _request(self):
        return SimpleNamespace(
            subject_id=SLOT_ID,
            prompt_template_id="qualifier-template",
            prompt_template_version="1",
            prompt_template_hash=HASHES[9],
            governing_rule="synthetic qualifier rejection fixture",
            evidence_hashes=(HASHES[1],),
            context_hashes=(HASHES[2],),
            accepted_outcome="CLAIM_QUALIFIER_ACCEPTED",
            instructions_bytes=b"synthetic instructions",
            input_bytes=b"retained-input",
            output_schema_bytes=b"synthetic output schema",
        )

    def _candidate(self, outcome: str, artifact_hash: str):
        receipt = _judgment(
            JudgmentSubjectKind.CLAIM_QUALIFIER,
            SLOT_ID,
            outcome=outcome,
        )
        artifact = SimpleNamespace(
            logical_type="scientific_semantic_judgment_receipt",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            sha256=artifact_hash,
        )
        resolved = SimpleNamespace(
            subject_id=SLOT_ID,
            outcome=outcome,
            evidence_hashes=(HASHES[1],),
            context_hashes=(HASHES[2],),
            input_artifact_hash=HASHES[0],
            instructions_artifact_hash=HASHES[3],
            output_schema_artifact_hash=HASHES[4],
        )
        return artifact, receipt, resolved

    def test_unique_rejected_selection_succeeds_with_exact_owner_arguments(
        self,
    ) -> None:
        from scientist_one import gates

        selected_hash = HASHES[11]
        selected, selected_receipt, selected_resolved = self._candidate(
            "CLAIM_QUALIFIER_REJECTED",
            selected_hash,
        )
        request = self._request()
        registry = _Registry(
            {
                selected_hash: research_state.canonical_json_bytes(
                    selected_receipt.to_dict()
                )
                + b"\n",
                HASHES[0]: request.input_bytes,
                HASHES[3]: request.instructions_bytes,
                HASHES[4]: request.output_schema_bytes,
            }
        )
        registry.records = (selected,)
        ledger = object()
        with (
            patch.object(
                gates,
                "require_scientific_semantic_judgment_receipt",
                return_value=selected_resolved,
            ) as resolve_source,
            patch.object(
                research_state,
                "_claim_qualifier_request_from_retained_input",
                return_value=request,
            ) as replay,
        ):
            observed = research_state._require_unique_scientific_claim_qualifier_judgment(
                registry,
                ledger,
                run_id=RUN_ID,
                request=request,
                selected_artifact_hash=selected_hash,
                expected_outcome="CLAIM_QUALIFIER_REJECTED",
            )
        self.assertIs(observed, selected_resolved)
        resolve_source.assert_called_once_with(
            registry,
            ledger,
            run_id=RUN_ID,
            receipt_artifact_hash=selected_hash,
            subject_kind=JudgmentSubjectKind.CLAIM_QUALIFIER,
            subject_id=SLOT_ID,
            outcome="CLAIM_QUALIFIER_REJECTED",
            evidence_hashes=(HASHES[1],),
            context_hashes=(HASHES[2],),
        )
        replay.assert_called_once_with(
            registry,
            ledger,
            run_id=RUN_ID,
            retained_input=request.input_bytes,
        )

    def test_unique_selection_rejects_wrong_request_or_competing_outcomes(self) -> None:
        from scientist_one import gates

        selected_hash = HASHES[11]
        accepted_hash = HASHES[12]
        selected, selected_receipt, selected_resolved = self._candidate(
            "CLAIM_QUALIFIER_REJECTED",
            selected_hash,
        )
        accepted, accepted_receipt, accepted_resolved = self._candidate(
            "CLAIM_QUALIFIER_ACCEPTED",
            accepted_hash,
        )

        def run_case(
            artifacts,
            receipt_values,
            resolved_values,
            replay_request,
            expected_error,
            requested_selection=selected_hash,
        ):
            request = self._request()
            payloads = {
                item.sha256: research_state.canonical_json_bytes(
                    receipt_values[item.sha256].to_dict()
                )
                + b"\n"
                for item in artifacts
            }
            payloads.update(
                {
                    HASHES[0]: request.input_bytes,
                    HASHES[3]: request.instructions_bytes,
                    HASHES[4]: request.output_schema_bytes,
                }
            )
            registry = _Registry(payloads)
            registry.records = tuple(artifacts)
            with (
                patch.object(
                    gates,
                    "require_scientific_semantic_judgment_receipt",
                    side_effect=lambda *args, **kwargs: resolved_values[
                        kwargs["receipt_artifact_hash"]
                    ],
                ) as resolve_source,
                patch.object(
                    research_state,
                    "_claim_qualifier_request_from_retained_input",
                    return_value=replay_request,
                ) as replay,
            ):
                with self.assertRaisesRegex(
                    research_state.ValidationError,
                    expected_error,
                ):
                    research_state._require_unique_scientific_claim_qualifier_judgment(
                        registry,
                        object(),
                        run_id=RUN_ID,
                        request=request,
                        selected_artifact_hash=requested_selection,
                        expected_outcome="CLAIM_QUALIFIER_REJECTED",
                    )
            self.assertTrue(resolve_source.call_args_list)
            self.assertTrue(replay.call_args_list)
            self.assertTrue(
                all(
                    call.kwargs["run_id"] == RUN_ID
                    and call.kwargs["retained_input"] == request.input_bytes
                    for call in replay.call_args_list
                )
            )

        wrong_request = self._request()
        wrong_request.subject_id = "substituted-slot"
        run_case(
            (selected,),
            {selected_hash: selected_receipt},
            {selected_hash: selected_resolved},
            wrong_request,
            "scientific claim-qualifier judgment branch is ambiguous",
        )
        run_case(
            (selected,),
            {selected_hash: selected_receipt},
            {selected_hash: selected_resolved},
            self._request(),
            "scientific claim-qualifier judgment branch is ambiguous",
            requested_selection=accepted_hash,
        )
        run_case(
            (selected, accepted),
            {
                selected_hash: selected_receipt,
                accepted_hash: accepted_receipt,
            },
            {
                selected_hash: selected_resolved,
                accepted_hash: accepted_resolved,
            },
            self._request(),
            "scientific claim-qualifier judgment branch is ambiguous",
        )
        accepted_only_registry = _Registry({})
        accepted_only_registry.records = (accepted,)
        with (
            patch.object(
                gates,
                "require_scientific_semantic_judgment_receipt",
                return_value=accepted_resolved,
            ),
            patch.object(
                research_state,
                "_claim_qualifier_request_from_retained_input",
                return_value=self._request(),
            ),
        ):
            accepted_only_registry.payloads.update(
                {
                    accepted_hash: research_state.canonical_json_bytes(
                        accepted_receipt.to_dict()
                    )
                    + b"\n",
                    HASHES[0]: b"retained-input",
                    HASHES[3]: b"synthetic instructions",
                    HASHES[4]: b"synthetic output schema",
                }
            )
            with self.assertRaisesRegex(
                research_state.ValidationError,
                "selected claim-qualifier judgment differs from the exact request outcome",
            ):
                research_state._require_unique_scientific_claim_qualifier_judgment(
                    accepted_only_registry,
                    object(),
                    run_id=RUN_ID,
                    request=self._request(),
                    selected_artifact_hash=accepted_hash,
                    expected_outcome="CLAIM_QUALIFIER_REJECTED",
                )
