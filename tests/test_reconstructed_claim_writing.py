"""SEMANTIC_RECONSTRUCTION, 2026-09-19: frozen kernel B-09/B-14.

New tests, not recovered original364 bytes. Registry-backed fixtures use the
production resolver and synthetic local support judgments. Roles are logical
same-process roles, never independent scientific review, human authority or E4.
Renderer checks concern its bounded presentation contract, not claim authority.
"""

import csv
from dataclasses import replace
import io
from pathlib import Path
import tempfile
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.claims import (
    ClaimDecision, ClaimEvidenceGraph, ClaimNotEligibleError,
    ClaimValidationError, Contradiction, EvidenceKind, EvidenceLink,
    EvidenceNode, EvidenceSupportReceipt, MaterialClaim, artifact_registry_resolver,
)
from scientist_one.errors import AuthorizationError
from scientist_one.roles import Role
from scientist_one.writing import (
    render_demo_paper_bytes, render_results_table_bytes, render_svg_effect_figure_bytes,
)


class ReconstructedClaimWritingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.registry = ArtifactRegistry(self.root)
        self.resolver = artifact_registry_resolver(self.registry)

    def store(self, content, logical_type, **changes):
        metadata = {
            "logical_type": logical_type, "origin": "synthetic semantic reconstruction",
            "creator_role": Role.EVIDENCE_CURATOR,
            "creation_command": ("synthetic-claim-fixture",),
            "created_at": "2026-09-19T12:00:00Z",
        }
        metadata.update(changes)
        return self.registry.put_bytes(content, **metadata)

    def fixture(self, *, result_judgment=None, figure_parent=True):
        """Actual registry bytes/receipts; no test resolver or authority minting."""
        descriptions = {kind: "Synthetic local " + kind.value for kind in EvidenceKind}
        descriptions[EvidenceKind.RESULT] = "Synthetic result: observed difference is zero."
        descriptions[EvidenceKind.SCOPE_QUALIFIER] = "Only this synthetic fixture."
        descriptions[EvidenceKind.LIMITATION] = "No empirical or external novelty inference."
        nodes = []
        for kind in EvidenceKind:
            parents = ()
            if kind is EvidenceKind.FIGURE_OR_TABLE and figure_parent:
                table = self.store(b"task,effect_size\nnull,0.0\n", "results_table", mime_type="text/csv")
                parents = (table.sha256,)
            record = self.store(descriptions[kind].encode(), "claim_evidence." + kind.value,
                                parent_artifacts=parents)
            nodes.append(EvidenceNode("e-" + kind.value, kind, record.sha256,
                                      descriptions[kind], verified=True, frozen=True,
                                      supports_claim=True, locally_verifiable=True))
        claim = MaterialClaim("synthetic-null", "The synthetic fixture reports a zero difference.",
                              tuple(EvidenceLink(node.evidence_id, node.kind) for node in nodes),
                              Role.STATISTICIAN, confirmatory=False)
        bound = []
        for node in nodes:
            judgment = {"verification_result": "PASS", "supports_claim": True,
                        "contradicts_claim": False, "locally_verifiable": True}
            if node.kind is EvidenceKind.RESULT and result_judgment:
                judgment.update(result_judgment)
                node = replace(node, supports_claim=judgment["supports_claim"],
                               contradicts_claim=judgment["contradicts_claim"],
                               locally_verifiable=judgment["locally_verifiable"])
            receipt = EvidenceSupportReceipt.for_claim(
                claim, node, verifier_id="synthetic-logical-verifier",
                rationale="Fixture-only same-process logical support judgment; no external science.",
                **judgment,
            )
            record = self.store(receipt.canonical_bytes + b"\n",
                                "claim_support_receipt." + node.kind.value,
                                creator_role=Role.CLAIM_VERIFIER, mime_type="application/json",
                                parent_artifacts=(node.artifact_hash,))
            self.assertEqual(record.sha256, receipt.sha256)
            bound.append(replace(node, verification_receipt_hash=record.sha256))
        return self.graph(claim, bound), claim, tuple(bound)

    def graph(self, claim, nodes, *, resolved=True):
        graph = ClaimEvidenceGraph(evidence_resolver=self.resolver if resolved else None)
        for node in nodes:
            graph.add_evidence(node)
        graph.add_claim(claim)
        return graph

    def verify(self, graph, claim, **changes):
        return graph.verify_claim(claim.claim_id, verifier_id="synthetic-logical-verifier", **changes)

    def assert_rejected(self, graph, claim, expected=ClaimDecision.UNSUPPORTED):
        self.assertIs(self.verify(graph, claim).decision, expected)
        self.assertEqual(graph.writer_view(), ())
        with self.assertRaises(ClaimNotEligibleError):
            graph.require_eligible(claim.claim_id)

    def test_actual_registry_support_produces_scoped_null_writer_view(self):
        graph, claim, nodes = self.fixture()
        decision = self.verify(graph, claim)
        self.assertIs(decision.decision, ClaimDecision.ELIGIBLE)
        view, = graph.writer_view()
        self.assertEqual(view["text"], claim.text)
        self.assertEqual(view["scope_qualifier"], "Only this synthetic fixture.")
        self.assertEqual(view["limitations"], ["No empirical or external novelty inference."])
        self.assertFalse(view["confirmatory"])
        self.assertEqual(len(view["evidence_receipt_hashes"]), len(EvidenceKind))
        self.assertEqual(set(view["evidence_hashes"]), {node.artifact_hash for node in nodes})
        self.assertEqual(graph.require_eligible(claim.claim_id), decision)

    def test_sha_shapes_and_asserted_node_flags_without_resolver_are_insufficient(self):
        _, claim, nodes = self.fixture()
        graph = self.graph(claim, nodes, resolved=False)
        self.assert_rejected(graph, claim)
        self.assertIn("no trusted evidence resolver", graph.decisions[0].reason)

    def test_missing_typed_evidence_prevents_writer_eligibility(self):
        _, claim, nodes = self.fixture()
        graph = self.graph(claim, [node for node in nodes if node.kind is not EvidenceKind.ROBUSTNESS])
        self.assert_rejected(graph, claim)
        self.assertIn(EvidenceKind.ROBUSTNESS, graph.decisions[0].missing_kinds)

    def test_wrong_registry_logical_type_is_not_evidence(self):
        _, claim, nodes = self.fixture()
        result = next(node for node in nodes if node.kind is EvidenceKind.RESULT)
        wrong = self.store(b"synthetic content with wrong registered kind", "unrelated_note")
        changed = replace(result, artifact_hash=wrong.sha256)
        with self.assertRaisesRegex(ClaimValidationError, "evidence kind mismatch"):
            self.resolver(claim, changed)
        self.assert_rejected(self.graph(claim, [changed if node is result else node for node in nodes]), claim)

    def test_missing_support_receipt_cannot_be_replaced_by_verified_flags(self):
        _, claim, nodes = self.fixture()
        changed = tuple(replace(node, verification_receipt_hash=None)
                        if node.kind is EvidenceKind.RESULT else node for node in nodes)
        self.assert_rejected(self.graph(claim, changed), claim)

    def test_support_receipts_cannot_be_reused_for_another_claim_id_or_text(self):
        _, claim, nodes = self.fixture()
        for changed in (replace(claim, claim_id="other-claim"),
                        replace(claim, text="The synthetic fixture proves superiority.")):
            with self.subTest(claim=changed):
                with self.assertRaisesRegex(ClaimValidationError, "binding mismatch"):
                    self.resolver(changed, nodes[0])
                self.assert_rejected(self.graph(changed, nodes), changed)

    def test_writer_visible_evidence_description_is_bound_to_support_receipt(self):
        _, claim, nodes = self.fixture()
        changed = tuple(replace(node, description="Unsupported broad generalization.")
                        if node.kind is EvidenceKind.SCOPE_QUALIFIER else node for node in nodes)
        self.assert_rejected(self.graph(claim, changed), claim)

    def test_support_verifier_identity_must_match_eligibility_verifier(self):
        graph, claim, _ = self.fixture()
        result = graph.verify_claim(claim.claim_id, verifier_id="another-logical-verifier")
        self.assertIs(result.decision, ClaimDecision.UNSUPPORTED)
        self.assertIn("support receipt verifier mismatch", result.reason)
        self.assertEqual(graph.writer_view(), ())

    def test_negative_support_judgment_is_retained_and_blocks_material_claim(self):
        graph, claim, _ = self.fixture(result_judgment={"verification_result": "FAIL", "supports_claim": False})
        self.assert_rejected(graph, claim)
        result = next(node for node in graph.evidence if node.kind is EvidenceKind.RESULT)
        self.assertFalse(result.supports_claim)
        self.assertEqual(graph.claims, (claim,))
        self.assertEqual(len(graph.decision_history), 1)

    def test_contradictory_support_is_retained_without_writer_eligibility(self):
        graph, claim, _ = self.fixture(result_judgment={"supports_claim": False, "contradicts_claim": True})
        self.assert_rejected(graph, claim, ClaimDecision.CONTRADICTED)
        self.assertTrue(graph.decisions[0].contradictions)
        self.assertTrue(any(node.contradicts_claim for node in graph.evidence))

    def test_new_contradiction_makes_previously_eligible_view_stale(self):
        graph, claim, nodes = self.fixture()
        self.assertIs(self.verify(graph, claim).decision, ClaimDecision.ELIGIBLE)
        graph.add_contradiction(Contradiction(claim.claim_id, nodes[0].evidence_id,
                                            "Synthetic disconfirming observation retained."))
        self.assertEqual(graph.writer_view(), ())
        with self.assertRaisesRegex(ClaimNotEligibleError, "stale eligibility"):
            graph.require_eligible(claim.claim_id)
        self.assertIs(self.verify(graph, claim).decision, ClaimDecision.CONTRADICTED)
        self.assertEqual(tuple(item.decision for item in graph.decision_history),
                         (ClaimDecision.ELIGIBLE, ClaimDecision.CONTRADICTED))

    def test_invalid_confirmatory_status_overrides_other_evidence(self):
        _, claim, nodes = self.fixture()
        confirmatory = replace(claim, confirmatory=True)
        graph = self.graph(confirmatory, nodes)
        decision = self.verify(graph, confirmatory, confirmatory_evidence_valid=False)
        self.assertIs(decision.decision, ClaimDecision.INVALIDATED)
        self.assertEqual(graph.writer_view(), ())

    def test_serialized_eligibility_requires_fresh_resolution(self):
        graph, claim, _ = self.fixture()
        self.verify(graph, claim)
        restored = ClaimEvidenceGraph.from_dict(graph.to_dict(), evidence_resolver=self.resolver)
        self.assertEqual(restored.decisions, ())
        self.assertEqual(restored.writer_view(), ())
        with self.assertRaises(ClaimNotEligibleError):
            restored.require_eligible(claim.claim_id)
        self.assertIs(self.verify(restored, claim).decision, ClaimDecision.ELIGIBLE)

    def test_changed_artifact_bytes_revoke_writer_view_at_consumption(self):
        graph, claim, nodes = self.fixture()
        self.verify(graph, claim)
        result = next(node for node in nodes if node.kind is EvidenceKind.RESULT)
        record = self.registry.get_metadata(result.artifact_hash)
        # Deliberate corruption of our own ephemeral fixture, never project evidence.
        (self.root / record.relative_path).write_bytes(b"synthetic changed result")
        self.assertEqual(graph.writer_view(), ())
        with self.assertRaisesRegex(ClaimNotEligibleError, "stale eligibility"):
            graph.require_eligible(claim.claim_id)

    def test_figure_evidence_requires_real_materialized_output_parent(self):
        graph, claim, nodes = self.fixture(figure_parent=False)
        figure = next(node for node in nodes if node.kind is EvidenceKind.FIGURE_OR_TABLE)
        with self.assertRaisesRegex(ClaimValidationError, "materialized output parent"):
            self.resolver(claim, figure)
        self.assert_rejected(graph, claim)

    def test_producer_and_verifier_roles_are_separate_logical_authorities(self):
        graph, claim, _ = self.fixture()
        with self.assertRaises(AuthorizationError):
            replace(claim, producer_role=Role.CLAIM_VERIFIER)
        with self.assertRaises(AuthorizationError):
            self.verify(graph, claim, verifier_role=Role.STATISTICIAN)
        self.assertEqual(graph.writer_view(), ())

    def test_demo_renderer_omits_rejected_claims_and_keeps_honest_release_labels(self):
        # The renderer consumes a legacy structural projection, not graph authority.
        claims = [{"text": "UNSUPPORTED_SENTINEL", "verifier_decision": "UNSUPPORTED"},
                  {"text": "CONTRADICTED_SENTINEL", "verifier_decision": "CONTRADICTED"}]
        manifest = {"package_kind": "DEMO_RESEARCH_PACKAGE"}
        paper = render_demo_paper_bytes(manifest, claims, Path("results.csv"), Path("figure.svg")).decode()
        self.assertNotIn("UNSUPPORTED_SENTINEL", paper)
        self.assertNotIn("CONTRADICTED_SENTINEL", paper)
        self.assertIn("No material claim was eligible.", paper)
        self.assertIn("NOVELTY_UNVERIFIED", paper)
        self.assertIn("E4 approval is absent", paper)
        with self.assertRaises(ValueError):
            render_demo_paper_bytes({"package_kind": "REAL_RESEARCH"}, [], Path("r.csv"), Path("f.svg"))
        with self.assertRaises(ValueError):
            render_demo_paper_bytes(manifest, [{"text": "incomplete", "verifier_decision": "ELIGIBLE"}],
                                    Path("r.csv"), Path("f.svg"))

    def test_table_and_figure_preserve_null_and_negative_synthetic_outcomes(self):
        results = [{"task": "null", "effect_size": 0.0, "outcome": "NULL"},
                   {"task": "negative<&>", "effect_size": -2.0, "outcome": "REVERSAL"}]
        table = render_results_table_bytes(results)
        rows = list(csv.DictReader(io.StringIO(table.decode())))
        self.assertEqual([row["effect_size"] for row in rows], ["0.0", "-2.0"])
        self.assertEqual([row["outcome"] for row in rows], ["NULL", "REVERSAL"])
        self.assertEqual(table, render_results_table_bytes(results))
        figure = render_svg_effect_figure_bytes(results).decode()
        self.assertIn("negative&lt;&amp;&gt;", figure)
        self.assertIn('fill="#dc2626"', figure)
        self.assertIn("synthetic demo", figure)


if __name__ == "__main__":
    unittest.main()
