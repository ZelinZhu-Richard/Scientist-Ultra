from __future__ import annotations

from dataclasses import replace
import tempfile
import unittest

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
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from scientist_one.research_state import (
    ClaimStrength,
    ClaimType,
    register_claim_semantics_proposal,
    require_claim_semantics_proposal,
)


class ClaimSemanticsProposalUniquenessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.run_id = "proposal-slot"
        self.claim_id = "proposal-slot-claim"
        self.claim_text = "The bounded candidate result exceeds its baseline."
        self.registry = ArtifactRegistry(
            self.temporary.name,
            f"runs/{self.run_id}/registry",
        )
        self.ledger = EventLedger(
            self.temporary.name,
            f"runs/{self.run_id}/events.jsonl",
        )
        self.graph = self._claim_graph()
        self.proposal_arguments = {
            "proposal_id": "proposal-slot-primary",
            "run_id": self.run_id,
            "claim_graph_artifact_hash": self.graph.sha256,
            "claim_id": self.claim_id,
            "claim_type": ClaimType.COMPARATIVE,
            "scope": "The exact bounded comparison only.",
            "confidence": 0.8,
            "expressed_strength": ClaimStrength.LIMITED,
            "permitted_strength": ClaimStrength.QUALIFIED,
            "verification_method": "Fresh exact graph replay.",
        }

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
            origin="focused claim-semantics proposal-slot fixture",
            creator_role=role,
            creation_command=("scientist-one", "proposal-slot-test"),
            parent_artifacts=parents,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def _claim_graph(self):
        table = self.registry.put_bytes(
            b"method,score\nbaseline,0.4\ncandidate,0.6\n",
            logical_type="results_table",
            origin="focused claim-semantics proposal-slot table",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "proposal-slot-test"),
            schema_version="1.0",
            mime_type="text/csv",
            validation_result="PASS",
            frozen=True,
        )
        evidence_records = []
        provisional = []
        for index, kind in enumerate(
            sorted(REQUIRED_EVIDENCE_KINDS, key=lambda item: item.value),
            1,
        ):
            parents = (
                (table.sha256,)
                if kind is EvidenceKind.FIGURE_OR_TABLE
                else ()
            )
            evidence_record = self._put_json(
                {
                    "claim_id": self.claim_id,
                    "claim_text": self.claim_text,
                    "evidence_kind": kind.value,
                    "fixture_boundary": "STRUCTURAL_ONLY",
                },
                logical_type=f"claim_evidence.{kind.value}",
                role=Role.EXPERIMENT_RUNNER,
                parents=parents,
            )
            evidence_records.append(evidence_record)
            provisional.append(
                EvidenceNode(
                    evidence_id=f"proposal-slot-evidence-{index:02d}",
                    kind=kind,
                    artifact_hash=evidence_record.sha256,
                    description=f"Exact bounded {kind.value} graph source.",
                    verified=True,
                    frozen=True,
                    supports_claim=True,
                    contradicts_claim=False,
                    locally_verifiable=True,
                )
            )
        claim = MaterialClaim(
            claim_id=self.claim_id,
            text=self.claim_text,
            evidence_links=tuple(
                EvidenceLink(node.evidence_id, node.kind)
                for node in provisional
            ),
            producer_role=Role.EXPERIMENT_RUNNER,
            confirmatory=False,
            evidence_use=ClaimEvidenceUse.SCIENTIFIC,
        )
        support_records = []
        nodes = []
        for node in provisional:
            support = EvidenceSupportReceipt.for_claim(
                claim,
                node,
                verifier_id="proposal-slot-verifier",
                verification_result="PASS",
                supports_claim=True,
                contradicts_claim=False,
                locally_verifiable=True,
                rationale="Exact frozen graph source supports this bounded edge.",
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
            verifier_id="proposal-slot-verifier",
            verifier_role=Role.CLAIM_VERIFIER,
            confirmatory_evidence_valid=False,
            raise_on_rejection=True,
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
                origin="focused claim-semantics proposal-slot verification",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "proposal-slot-test"),
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
                    *evidence_records,
                    *support_records,
                    *verification_records,
                )
            ),
        )

    def _register(self, **changes):
        arguments = dict(self.proposal_arguments)
        arguments.update(changes)
        return register_claim_semantics_proposal(
            self.registry,
            self.ledger,
            **arguments,
        )

    def test_exact_retry_returns_the_existing_content_address(self) -> None:
        first = self._register()
        records_before_retry = self.registry.list_records()

        second = self._register()

        self.assertEqual(second, first)
        self.assertEqual(self.registry.list_records(), records_before_retry)
        replayed = require_claim_semantics_proposal(
            self.registry,
            self.ledger,
            proposal_artifact_hash=first.sha256,
            expected_run_id=self.run_id,
            expected_claim_graph_artifact_hash=self.graph.sha256,
            expected_claim_id=self.claim_id,
        )
        self.assertEqual(replayed.proposal_id, "proposal-slot-primary")

    def test_different_id_scope_or_strength_is_rejected_before_write(self) -> None:
        self._register()
        cases = (
            ("id", {"proposal_id": "proposal-slot-different-id"}),
            ("scope", {"scope": "A competing proposed semantic scope."}),
            (
                "strength",
                {"expressed_strength": ClaimStrength.QUALIFIED},
            ),
        )
        for label, changes in cases:
            records_before_attempt = self.registry.list_records()
            with self.subTest(case=label), self.assertRaisesRegex(
                ValidationError,
                "slot already contains a different semantic branch",
            ):
                self._register(**changes)
            self.assertEqual(
                self.registry.list_records(),
                records_before_attempt,
            )

    def test_public_replay_rejects_a_direct_inserted_valid_conflict(self) -> None:
        original_record = self._register()
        original = require_claim_semantics_proposal(
            self.registry,
            self.ledger,
            proposal_artifact_hash=original_record.sha256,
            expected_run_id=self.run_id,
        )
        conflict = replace(
            original,
            proposal_id="proposal-slot-direct-conflict",
            scope="A directly inserted competing semantic scope.",
        )
        conflict_record = self.registry.put_json(
            conflict.to_dict(),
            logical_type=original_record.logical_type,
            origin=original_record.origin,
            creator_role=original_record.creator_role,
            creation_command=original_record.creation_command,
            parent_artifacts=original_record.parent_artifacts,
            schema_version=original_record.schema_version,
            mime_type=original_record.mime_type,
            validation_result=original_record.validation_result,
            frozen=original_record.frozen,
        )
        for proposal_hash in (original_record.sha256, conflict_record.sha256):
            with self.subTest(proposal_hash=proposal_hash), self.assertRaisesRegex(
                ValidationError,
                "slot contains multiple valid semantic branches",
            ):
                require_claim_semantics_proposal(
                    self.registry,
                    self.ledger,
                    proposal_artifact_hash=proposal_hash,
                    expected_run_id=self.run_id,
                    expected_claim_graph_artifact_hash=self.graph.sha256,
                    expected_claim_id=self.claim_id,
                )


if __name__ == "__main__":
    unittest.main()
