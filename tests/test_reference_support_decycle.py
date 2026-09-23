from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import hashlib
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.claims import (
    CLAIM_GRAPH_RESOLVER_ID,
    REQUIRED_EVIDENCE_KINDS,
    ClaimDecision,
    ClaimEvidenceGraph,
    ClaimEvidenceUse,
    EvidenceKind,
    EvidenceLink,
    EvidenceNode,
    EvidenceSupportReceipt,
    MaterialClaim,
    artifact_registry_resolver,
)
from scientist_one.errors import ValidationError
from scientist_one.external import AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA
from scientist_one.gates import JudgmentSubjectKind, SemanticJudgmentReceipt
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from scientist_one import scientific_design as design_module
from scientist_one.scientific_design import (
    REFERENCE_SUPPORT_SEMANTIC_DECISION_SCHEMA,
    ClaimBoundReferenceSupportJudgmentRequest,
    ScientificPromotionError,
    build_claim_bound_reference_support_judgment_request,
    require_audited_claim_bound_reference_authority,
)
from scientist_one.research_os import _run_literature
from scientist_one.research_state import (
    ClaimStrength,
    ClaimType,
    register_claim_semantics_proposal,
    register_scientific_claim_evidence_projection,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class ReferenceSupportDecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.run_id = "reference-support-decycle"
        self.claim_id = "reference-support-claim"
        self.registry = ArtifactRegistry(
            self.temporary.name,
            f"runs/{self.run_id}/registry",
        )
        self.ledger = EventLedger(
            self.temporary.name,
            f"runs/{self.run_id}/events.jsonl",
        )
        self.literature = _run_literature(
            self.registry,
            timestamp="2026-08-29T12:00:00Z",
        )
        self.reference_hash = self.literature.reference_artifact.sha256
        self.reference_value = safe_json_loads(
            self.registry.get_bytes(self.reference_hash)
        )
        selected_record = next(
            acquisition.record
            for acquisition in self.literature.acquisitions
            if acquisition.record is not None
            and acquisition.record.request_id
            == self.reference_value["verification"]["retrieval_request_id"]
        )
        self.citation_node = next(
            node
            for node in self.literature.citation_graph.nodes
            if node.source is selected_record.source
            and node.source_record_id == selected_record.source_record_id
        )
        self.transport = self.registry.put_json(
            {
                "schema_version": AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
                "test_boundary": "NOT_A_REAL_EXTERNAL_EXECUTION",
            },
            logical_type="audited_transport_execution_authority",
            origin="explicitly stubbed producer-unit boundary",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "reference-support-unit-test"),
            parent_artifacts=(),
            schema_version=AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        self.source = register_scientific_claim_evidence_projection(
            self.registry,
            evidence_id="reference-support-source",
            evidence_kind=EvidenceKind.SOURCE_CITATION,
            claim_id=self.claim_id,
            claim_text=self.reference_value["claim_text"],
            producer_role=Role.PROBLEM_INVESTIGATOR,
            source_artifact_hashes=(
                self.reference_hash,
                self.literature.citation_graph_artifact.sha256,
                self.transport.sha256,
            ),
        )
        self.graph = self._claim_graph(self.source)
        self.proposal = register_claim_semantics_proposal(
            self.registry,
            self.ledger,
            proposal_id="reference-support-proposal",
            run_id=self.run_id,
            claim_graph_artifact_hash=self.graph.sha256,
            claim_id=self.claim_id,
            claim_type=ClaimType.CITATION,
            scope="The exact retained scholarly passage and surrounding context.",
            confidence=0.8,
            expressed_strength=ClaimStrength.LIMITED,
            permitted_strength=ClaimStrength.QUALIFIED,
            verification_method="L5 reference replay plus audited semantic review",
        )

    def _put_json(
        self,
        value: object,
        *,
        logical_type: str,
        role: Role,
        parents: tuple[str, ...] = (),
    ):
        return self.registry.put_json(
            value,
            logical_type=logical_type,
            origin="focused reference-support decycle fixture",
            creator_role=role,
            creation_command=("scientist-one", "reference-support-unit-test"),
            parent_artifacts=parents,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def _claim_graph(self, source_record):
        source_evidence_id = safe_json_loads(
            self.registry.get_bytes(source_record.sha256)
        )["evidence_id"]
        records = []
        provisional = []
        for index, kind in enumerate(
            sorted(REQUIRED_EVIDENCE_KINDS, key=lambda item: item.value),
            1,
        ):
            if kind is EvidenceKind.SOURCE_CITATION:
                record = source_record
            else:
                parents: tuple[str, ...] = ()
                if kind is EvidenceKind.FIGURE_OR_TABLE:
                    output = self.registry.put_bytes(
                        b"metric,value\nfixture,1\n",
                        logical_type="results_table",
                        origin="focused materialized table output",
                        creator_role=Role.EXPERIMENT_RUNNER,
                        creation_command=(
                            "scientist-one",
                            "reference-support-unit-test",
                        ),
                        parent_artifacts=(),
                        schema_version="1.0",
                        mime_type="text/csv",
                        validation_result="PASS",
                        frozen=True,
                    )
                    parents = (output.sha256,)
                record = self._put_json(
                    {
                        "claim_text": self.reference_value["claim_text"],
                        "evidence_kind": kind.value,
                        "producer_test_notice": "structural graph source only",
                    },
                    logical_type=f"claim_evidence.{kind.value}",
                    role=Role.PROBLEM_INVESTIGATOR,
                    parents=parents,
                )
            records.append(record)
            provisional.append(
                EvidenceNode(
                    evidence_id=(
                        source_evidence_id
                        if kind is EvidenceKind.SOURCE_CITATION
                        else f"reference-support-{index:02d}-{kind.value}"
                    ),
                    kind=kind,
                    artifact_hash=record.sha256,
                    description=f"Exact {kind.value} projection for the test claim.",
                    verified=True,
                    frozen=True,
                    supports_claim=True,
                    contradicts_claim=False,
                    locally_verifiable=True,
                )
            )
        claim = MaterialClaim(
            claim_id=self.claim_id,
            text=self.reference_value["claim_text"],
            evidence_links=tuple(
                EvidenceLink(node.evidence_id, node.kind)
                for node in provisional
            ),
            producer_role=Role.PROBLEM_INVESTIGATOR,
            confirmatory=False,
            evidence_use=ClaimEvidenceUse.SCIENTIFIC,
        )
        support_records = []
        nodes = []
        for node in provisional:
            support = EvidenceSupportReceipt.for_claim(
                claim,
                node,
                verifier_id="reference-support-claim-verifier",
                verification_result="PASS",
                supports_claim=True,
                contradicts_claim=False,
                locally_verifiable=True,
                rationale="The exact frozen projection supports this structural edge.",
            )
            support_record = self._put_json(
                support.to_dict(),
                logical_type=f"claim_support_receipt.{node.kind.value}",
                role=Role.CLAIM_VERIFIER,
                parents=(node.artifact_hash,),
            )
            self.assertEqual(support_record.sha256, support.sha256)
            support_records.append(support_record)
            nodes.append(
                replace(node, verification_receipt_hash=support_record.sha256)
            )
        resolver = artifact_registry_resolver(
            self.registry,
            resolver_id=CLAIM_GRAPH_RESOLVER_ID,
        )
        graph = ClaimEvidenceGraph(evidence_resolver=resolver)
        for node in nodes:
            graph.add_evidence(node)
        graph.add_claim(claim)
        decision = graph.verify_claim(
            self.claim_id,
            verifier_id="reference-support-claim-verifier",
            confirmatory_evidence_valid=False,
        )
        self.assertIs(decision.decision, ClaimDecision.ELIGIBLE)
        verification_records = []
        for node in nodes:
            receipt = resolver(claim, node)
            record = self.registry.put_bytes(
                receipt.canonical_bytes,
                logical_type=(
                    "claim_evidence_verification_receipt."
                    f"{node.kind.value}"
                ),
                origin="focused reference-support graph verification",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=(
                    "scientist-one",
                    "reference-support-unit-test",
                ),
                parent_artifacts=(
                    node.artifact_hash,
                    receipt.support_receipt_hash,
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertEqual(record.sha256, receipt.sha256)
            verification_records.append(record)
        return self._put_json(
            {"graph": graph.to_dict()},
            logical_type="claim_evidence_graph",
            role=Role.CLAIM_VERIFIER,
            parents=tuple(
                record.sha256
                for record in (
                    *records,
                    *support_records,
                    *verification_records,
                )
            ),
        )

    @contextmanager
    def _controlled_boundary(self):
        authority = SimpleNamespace(
            transport_execution_authority_artifact_sha256=(
                self.transport.sha256
            )
        )
        with mock.patch.object(
            design_module,
            "require_audited_live_controlled_literature_authority",
            return_value=authority,
        ), mock.patch.object(
            design_module,
            "ControlledLiteratureAuthority",
            SimpleNamespace,
        ):
            yield

    def _request(self) -> ClaimBoundReferenceSupportJudgmentRequest:
        with self._controlled_boundary():
            return build_claim_bound_reference_support_judgment_request(
                self.registry,
                self.ledger,
                expected_run_id=self.run_id,
                expected_claim_id=self.claim_id,
                expected_citation_node_id=self.citation_node.node_id,
                source_citation_evidence_artifact_sha256=self.source.sha256,
                claim_semantics_proposal_artifact_sha256=self.proposal.sha256,
            )

    def _semantic_receipt(
        self,
        request: ClaimBoundReferenceSupportJudgmentRequest,
        *,
        label: str,
        outcome: str = "REFERENCE_SUPPORT_ACCEPTED",
        semantic_support: bool = True,
        material_contextual_contradiction: bool = False,
        permitted_strength: str = "QUALIFIED",
    ) -> tuple[SemanticJudgmentReceipt, object]:
        custody = (
            self.registry.put_bytes(
                request.instructions_bytes,
                logical_type="model_judged_instructions",
                origin="stubbed semantic producer input",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "reference-support-unit-test"),
                schema_version="1.0",
                mime_type="text/plain",
                validation_result="PASS",
                frozen=True,
            ),
            self.registry.put_bytes(
                request.input_bytes,
                logical_type="model_judged_input",
                origin="stubbed semantic producer input",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "reference-support-unit-test"),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            ),
            self.registry.put_bytes(
                request.output_schema_bytes,
                logical_type="model_output_schema",
                origin="stubbed semantic producer input",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "reference-support-unit-test"),
                schema_version="1.0",
                mime_type="application/schema+json",
                validation_result="PASS",
                frozen=True,
            ),
            *tuple(
                self._put_json(
                    {"label": label, "custody_index": index},
                    logical_type=logical_type,
                    role=Role.SCIENTIFIC_REVIEWER,
                )
                for index, logical_type in enumerate(
                    (
                        "model_invocation",
                        "model_provider_request_intent",
                        "model_provider_response",
                        "model_output",
                    ),
                    1,
                )
            ),
        )
        frozen_projection = safe_json_loads(
            canonical_json_bytes(request.frozen_reference_projection)
        )
        decision = {
            "schema_version": REFERENCE_SUPPORT_SEMANTIC_DECISION_SCHEMA,
            "run_id": self.run_id,
            "claim_id": self.claim_id,
            "frozen_reference_projection": frozen_projection,
            "frozen_reference_projection_sha256": (
                request.frozen_reference_projection_sha256
            ),
            "semantic_support": semantic_support,
            "material_contextual_contradiction": (
                material_contextual_contradiction
            ),
            "permitted_strength": permitted_strength,
            "rationale": f"focused {label} decision",
            "outcome": outcome,
            "evidence_closure_sha256": request.evidence_closure_sha256,
            "human_authority": False,
            "e4_authority": False,
        }
        rationale = canonical_json_bytes(decision).decode("utf-8")
        receipt = SemanticJudgmentReceipt(
            judgment_id=f"reference-support-{label}",
            subject_kind=JudgmentSubjectKind.REFERENCE_SUPPORT,
            subject_id=request.subject_id,
            outcome=outcome,
            evidence_hashes=request.evidence_hashes,
            context_hashes=request.context_hashes,
            instructions_artifact_hash=custody[0].sha256,
            input_artifact_hash=custody[1].sha256,
            output_schema_artifact_hash=custody[2].sha256,
            invocation_artifact_hash=custody[3].sha256,
            request_intent_artifact_hash=custody[4].sha256,
            provider_response_artifact_hash=custody[5].sha256,
            model_output_artifact_hash=custody[6].sha256,
            invocation_id=f"reference-support-{label}",
            provider_id="stubbed-openai-boundary",
            provider_version="producer-unit-test",
            model="stubbed-model",
            model_version="producer-unit-test",
            prompt_template_id=request.prompt_template_id,
            prompt_template_version=request.prompt_template_version,
            prompt_template_hash=request.prompt_template_hash,
            structured_output_sha256=digest(f"structured-{label}"),
            reviewer_id="stubbed-scientific-reviewer",
            reviewer_role=Role.SCIENTIFIC_REVIEWER,
            governing_rule=request.governing_rule,
            rationale=rationale,
        )
        record = self._put_json(
            receipt.to_dict(),
            logical_type="scientific_semantic_judgment_receipt",
            role=Role.SCIENTIFIC_REVIEWER,
            parents=(
                *receipt.evidence_hashes,
                *receipt.context_hashes,
                *receipt.custody_artifact_hashes,
            ),
        )
        return receipt, record

    @staticmethod
    def _semantic_boundary(receipts: dict[str, SemanticJudgmentReceipt]):
        def require_stubbed_receipt(
            _registry,
            _ledger,
            *,
            receipt_artifact_hash,
            subject_kind,
            subject_id,
            outcome,
            evidence_hashes,
            context_hashes,
            **_kwargs,
        ):
            try:
                receipt = receipts[receipt_artifact_hash]
            except KeyError as exc:
                raise ValidationError("unknown stubbed semantic receipt") from exc
            if (
                receipt.subject_kind is not subject_kind
                or receipt.subject_id != subject_id
                or receipt.outcome != outcome
                or receipt.evidence_hashes != evidence_hashes
                or receipt.context_hashes != context_hashes
            ):
                raise ValidationError("stubbed semantic receipt mismatch")
            return receipt

        return mock.patch(
            "scientist_one.gates.require_scientific_semantic_judgment_receipt",
            side_effect=require_stubbed_receipt,
        )

    def test_public_builder_is_deterministic_and_breaks_the_parent_cycle(self) -> None:
        first = self._request()
        second = self._request()
        self.assertEqual(first, second)
        self.assertEqual(first.context_hashes, (self.proposal.sha256,))
        self.assertIn(self.source.sha256, first.evidence_hashes)
        self.assertNotIn(self.proposal.sha256, first.evidence_hashes)
        payload = safe_json_loads(first.input_bytes)
        self.assertEqual(
            payload["frozen_reference_projection"][
                "claim_semantics_proposal_artifact_sha256"
            ],
            self.proposal.sha256,
        )
        self.assertEqual(
            self.registry.get_metadata(self.source.sha256).parent_artifacts,
            (
                self.reference_hash,
                self.literature.citation_graph_artifact.sha256,
                self.transport.sha256,
            ),
        )

        with self._controlled_boundary():
            for label, changes in (
                ("wrong-run", {"expected_run_id": "another-run"}),
                ("wrong-claim", {"expected_claim_id": "another-claim"}),
                (
                    "wrong-node",
                    {
                        "expected_citation_node_id": (
                            f"citation-node:{digest('another-node')}"
                        )
                    },
                ),
                (
                    "wrong-proposal",
                    {
                        "claim_semantics_proposal_artifact_sha256": (
                            self.graph.sha256
                        )
                    },
                ),
            ):
                arguments = {
                    "expected_run_id": self.run_id,
                    "expected_claim_id": self.claim_id,
                    "expected_citation_node_id": self.citation_node.node_id,
                    "source_citation_evidence_artifact_sha256": self.source.sha256,
                    "claim_semantics_proposal_artifact_sha256": self.proposal.sha256,
                    **changes,
                }
                with self.subTest(case=label), self.assertRaises(ValidationError):
                    build_claim_bound_reference_support_judgment_request(
                        self.registry,
                        self.ledger,
                        **arguments,
                    )

    def test_resolver_replays_explicit_judgment_and_exact_complete_closure(self) -> None:
        request = self._request()
        receipt, record = self._semantic_receipt(request, label="accepted")
        with self._controlled_boundary(), self._semantic_boundary(
            {record.sha256: receipt}
        ):
            authority = require_audited_claim_bound_reference_authority(
                self.registry,
                self.ledger,
                expected_run_id=self.run_id,
                expected_claim_id=self.claim_id,
                expected_citation_node_id=self.citation_node.node_id,
                source_citation_evidence_artifact_sha256=self.source.sha256,
                claim_semantics_proposal_artifact_sha256=self.proposal.sha256,
                reference_support_semantic_judgment_artifact_sha256=(
                    record.sha256
                ),
            )
        self.assertEqual(
            authority.semantic_judgment_evidence_artifact_hashes,
            request.evidence_hashes,
        )
        self.assertEqual(
            authority.semantic_judgment_context_artifact_hashes,
            request.context_hashes,
        )
        self.assertEqual(
            authority.semantic_judgment_custody_artifact_hashes,
            receipt.custody_artifact_hashes,
        )
        expected_closure = tuple(
            sorted(
                {
                    self.source.sha256,
                    self.proposal.sha256,
                    record.sha256,
                    *receipt.evidence_hashes,
                    *receipt.context_hashes,
                    *receipt.custody_artifact_hashes,
                }
            )
        )
        self.assertEqual(authority.evidence_artifact_hashes, expected_closure)
        self.assertEqual(authority.permitted_strength, "QUALIFIED")

        unrelated = self._put_json(
            {"not": "a judgment"},
            logical_type="unrelated_artifact",
            role=Role.SCIENTIFIC_REVIEWER,
        )
        with self._controlled_boundary(), self._semantic_boundary(
            {record.sha256: receipt}
        ), self.assertRaisesRegex(
            ScientificPromotionError,
            "signed source-owned semantic authority",
        ):
            require_audited_claim_bound_reference_authority(
                self.registry,
                self.ledger,
                expected_run_id=self.run_id,
                expected_claim_id=self.claim_id,
                expected_citation_node_id=self.citation_node.node_id,
                source_citation_evidence_artifact_sha256=self.source.sha256,
                claim_semantics_proposal_artifact_sha256=self.proposal.sha256,
                reference_support_semantic_judgment_artifact_sha256=(
                    unrelated.sha256
                ),
            )

    def test_rejects_parent_splices_l4_and_stale_transport(self) -> None:
        extra = self._put_json(
            {"extra": True},
            logical_type="reference_support_extra_parent",
            role=Role.EVIDENCE_CURATOR,
        )
        parent_variants = (
            (
                "four-parent",
                (
                    self.reference_hash,
                    self.literature.citation_graph_artifact.sha256,
                    self.transport.sha256,
                    extra.sha256,
                ),
            ),
            (
                "reordered",
                (
                    self.literature.citation_graph_artifact.sha256,
                    self.reference_hash,
                    self.transport.sha256,
                ),
            ),
        )
        for label, parents in parent_variants:
            source = register_scientific_claim_evidence_projection(
                self.registry,
                evidence_id=f"reference-support-{label}",
                evidence_kind=EvidenceKind.SOURCE_CITATION,
                claim_id=self.claim_id,
                claim_text=self.reference_value["claim_text"],
                producer_role=Role.PROBLEM_INVESTIGATOR,
                source_artifact_hashes=parents,
            )
            with self.subTest(case=label), self._controlled_boundary(), self.assertRaises(
                ScientificPromotionError
            ):
                build_claim_bound_reference_support_judgment_request(
                    self.registry,
                    self.ledger,
                    expected_run_id=self.run_id,
                    expected_claim_id=self.claim_id,
                    expected_citation_node_id=self.citation_node.node_id,
                    source_citation_evidence_artifact_sha256=source.sha256,
                    claim_semantics_proposal_artifact_sha256=(
                        self.proposal.sha256
                    ),
                )

        for level, label in ((3, "support-false"), (4, "l4-contradiction")):
            forged_value = safe_json_loads(
                canonical_json_bytes(self.reference_value)
            )
            forged_value["verification"]["level"] = level
            forged_reference = self._put_json(
                forged_value,
                logical_type="reference_verification",
                role=Role.CLAIM_VERIFIER,
                parents=(
                    self.registry.get_metadata(self.reference_hash).parent_artifacts
                ),
            )
            source = register_scientific_claim_evidence_projection(
                self.registry,
                evidence_id=f"reference-support-{label}",
                evidence_kind=EvidenceKind.SOURCE_CITATION,
                claim_id=self.claim_id,
                claim_text=self.reference_value["claim_text"],
                producer_role=Role.PROBLEM_INVESTIGATOR,
                source_artifact_hashes=(
                    forged_reference.sha256,
                    self.literature.citation_graph_artifact.sha256,
                    self.transport.sha256,
                ),
            )
            with self.subTest(case=label), self._controlled_boundary(), self.assertRaises(
                ScientificPromotionError
            ):
                build_claim_bound_reference_support_judgment_request(
                    self.registry,
                    self.ledger,
                    expected_run_id=self.run_id,
                    expected_claim_id=self.claim_id,
                    expected_citation_node_id=self.citation_node.node_id,
                    source_citation_evidence_artifact_sha256=source.sha256,
                    claim_semantics_proposal_artifact_sha256=(
                        self.proposal.sha256
                    ),
                )

        stale_transport = self.registry.put_json(
            {
                "schema_version": AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
                "test_boundary": "STALE_NOT_A_REAL_EXTERNAL_EXECUTION",
            },
            logical_type="audited_transport_execution_authority",
            origin="explicitly stale producer-unit boundary",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "reference-support-unit-test"),
            parent_artifacts=(),
            schema_version=AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        stale_source = register_scientific_claim_evidence_projection(
            self.registry,
            evidence_id="reference-support-stale-source",
            evidence_kind=EvidenceKind.SOURCE_CITATION,
            claim_id=self.claim_id,
            claim_text=self.reference_value["claim_text"],
            producer_role=Role.PROBLEM_INVESTIGATOR,
            source_artifact_hashes=(
                self.reference_hash,
                self.literature.citation_graph_artifact.sha256,
                stale_transport.sha256,
            ),
        )
        stale_graph = self._claim_graph(stale_source)
        stale_proposal = register_claim_semantics_proposal(
            self.registry,
            self.ledger,
            proposal_id="reference-support-stale-proposal",
            run_id=self.run_id,
            claim_graph_artifact_hash=stale_graph.sha256,
            claim_id=self.claim_id,
            claim_type=ClaimType.CITATION,
            scope="The exact retained scholarly passage and surrounding context.",
            confidence=0.8,
            expressed_strength=ClaimStrength.LIMITED,
            permitted_strength=ClaimStrength.QUALIFIED,
            verification_method="L5 reference replay plus audited semantic review",
        )
        with self._controlled_boundary(), self.assertRaisesRegex(
            ScientificPromotionError,
            "another signed source execution",
        ):
            build_claim_bound_reference_support_judgment_request(
                self.registry,
                self.ledger,
                expected_run_id=self.run_id,
                expected_claim_id=self.claim_id,
                expected_citation_node_id=self.citation_node.node_id,
                source_citation_evidence_artifact_sha256=stale_source.sha256,
                claim_semantics_proposal_artifact_sha256=stale_proposal.sha256,
            )

    def test_rejects_negative_strength_and_conflicting_review_branches(self) -> None:
        request = self._request()
        for label, decision_changes in (
            ("support-false", {"semantic_support": False}),
            (
                "context-contradicted",
                {"material_contextual_contradiction": True},
            ),
            ("strength-downgrade", {"permitted_strength": "LIMITED"}),
        ):
            receipt, record = self._semantic_receipt(
                request,
                label=label,
                **decision_changes,
            )
            with self.subTest(case=label), self._controlled_boundary(), self._semantic_boundary(
                {record.sha256: receipt}
            ), self.assertRaises(ScientificPromotionError):
                require_audited_claim_bound_reference_authority(
                    self.registry,
                    self.ledger,
                    expected_run_id=self.run_id,
                    expected_claim_id=self.claim_id,
                    expected_citation_node_id=self.citation_node.node_id,
                    source_citation_evidence_artifact_sha256=self.source.sha256,
                    claim_semantics_proposal_artifact_sha256=(
                        self.proposal.sha256
                    ),
                    reference_support_semantic_judgment_artifact_sha256=(
                        record.sha256
                    ),
                )

        accepted, accepted_record = self._semantic_receipt(
            request,
            label="accepted-branch",
        )
        rejected, rejected_record = self._semantic_receipt(
            request,
            label="rejected-branch",
            outcome="REFERENCE_SUPPORT_REJECTED",
            semantic_support=False,
        )
        receipts = {
            accepted_record.sha256: accepted,
            rejected_record.sha256: rejected,
        }
        with self._controlled_boundary(), self._semantic_boundary(
            receipts
        ), self.assertRaisesRegex(
            ScientificPromotionError,
            "identity is ambiguous",
        ):
            require_audited_claim_bound_reference_authority(
                self.registry,
                self.ledger,
                expected_run_id=self.run_id,
                expected_claim_id=self.claim_id,
                expected_citation_node_id=self.citation_node.node_id,
                source_citation_evidence_artifact_sha256=self.source.sha256,
                claim_semantics_proposal_artifact_sha256=self.proposal.sha256,
                reference_support_semantic_judgment_artifact_sha256=(
                    accepted_record.sha256
                ),
            )


if __name__ == "__main__":
    unittest.main()
