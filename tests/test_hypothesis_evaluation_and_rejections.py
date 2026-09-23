from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.claims import (
    CLAIM_GRAPH_RESOLVER_ID,
    ClaimDecision as GraphClaimDecision,
    ClaimEvidenceGraph,
    ClaimEvidenceUse,
    EvidenceKind as GraphEvidenceKind,
    EvidenceLink as GraphEvidenceLink,
    EvidenceNode as GraphEvidenceNode,
    EvidenceSupportReceipt,
    MaterialClaim,
    artifact_registry_resolver,
)
from scientist_one.errors import ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.research_state import (
    Claim,
    ClaimReview,
    ClaimStrength,
    ClaimType,
    Evidence,
    HypothesisEvaluationEvidenceScope,
    HypothesisStatus,
    ObjectReference,
    RecordStatus,
    ReferenceVerificationDepth,
    ResearchStateRepository,
    VerificationStatus,
    build_evaluated_hypothesis_revision,
    register_hypothesis_evaluation_authority,
    require_hypothesis_evaluation_authority,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    CHECKED_SUPERIORITY_CONTRACT_SCHEMA_V2,
    EVALUATION_CONTRACT_ARTIFACT_SCHEMA_V2,
    HypothesisEvaluationFacts,
    HypothesisEvaluationPolicy,
    HypothesisStatus as DesignHypothesisStatus,
    ScientificDesignError,
    evaluate_hypothesis_policy,
    register_frozen_evaluation_contract,
    require_frozen_evaluation_contract,
    require_rejected_claim_bound_reference_support,
    require_scientific_result_state_projections,
)
from scientist_one.security import safe_json_loads

import tests.test_reference_support_decycle as reference_support_test_module
from tests.test_scientific_design import make_contract
from tests.test_vnext_state import (
    SCIENTIFIC_V2_STATE_CODE_VERSION,
    _load_scientific_v2_producer_helpers,
    _scientific_v2_state_graph,
    _timestamp_after,
)


STAMP = "2026-08-29T12:00:00Z"
CONFIGURATION_HASH = "c" * 64


def _policies(contract: object) -> tuple[HypothesisEvaluationPolicy, ...]:
    return tuple(
        HypothesisEvaluationPolicy(
            policy_id=f"{hypothesis.hypothesis_id}-evaluation-v1",
            hypothesis_id=hypothesis.hypothesis_id,
            metric_id=contract.primary_metric.metric_id,
            meaningful_effect=0.10,
            falsification_effect=0.10,
            alpha=0.05,
            minimum_sample_size=20,
        )
        for hypothesis in contract.hypothesis_register.hypotheses
    )


def _mechanical_v2_source(root: Path) -> dict[str, object]:
    """Build the strongest existing fixture without calling it real science."""

    helpers = _load_scientific_v2_producer_helpers()
    registered_inputs = helpers["_registered_inputs"]
    promotion_candidate = helpers["_result_promotion_candidate"]
    helper_globals = registered_inputs.__globals__
    original_values = {
        name: helper_globals[name]
        for name in (
            "ArtifactRegistry",
            "_checked_contract",
            "_put_json",
            "CHECKED_SUPERIORITY_CONTRACT_SCHEMA",
        )
    }
    original_contract = original_values["_checked_contract"]
    original_put_json = original_values["_put_json"]

    def registry_factory(fixture_root: Path) -> ArtifactRegistry:
        return ArtifactRegistry(fixture_root, "runs/global-run-1/registry")

    def checked_contract(**kwargs: object) -> object:
        contract = original_contract(**kwargs)
        return replace(
            contract,
            hypothesis_evaluation_policies=_policies(contract),
        )

    def put_json(
        registry: ArtifactRegistry,
        value: object,
        *,
        logical_type: str,
        role: Role,
        parents: tuple[str, ...] = (),
        schema_version: str = "1.0",
    ) -> object:
        if logical_type != "evaluation_contract":
            return original_put_json(
                registry,
                value,
                logical_type=logical_type,
                role=role,
                parents=parents,
                schema_version=schema_version,
            )
        if (
            isinstance(value, dict)
            and value.get("schema_version")
            == CHECKED_SUPERIORITY_CONTRACT_SCHEMA_V2
        ):
            schema_version = EVALUATION_CONTRACT_ARTIFACT_SCHEMA_V2
        return registry.put_json(
            value,
            logical_type=logical_type,
            origin=f"focused scientific-authority boundary fixture: {logical_type}",
            creator_role=role,
            creation_command=(
                "scientist-one",
                "test-scientific-authority-boundary",
            ),
            parent_artifacts=parents,
            schema_version=schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    try:
        helper_globals["ArtifactRegistry"] = registry_factory
        helper_globals["_checked_contract"] = checked_contract
        helper_globals["_put_json"] = put_json
        helper_globals["CHECKED_SUPERIORITY_CONTRACT_SCHEMA"] = (
            CHECKED_SUPERIORITY_CONTRACT_SCHEMA_V2
        )
        values = registered_inputs(root)
    finally:
        helper_globals.update(original_values)

    candidate = promotion_candidate(values)
    registry = values["registry"]
    ledger = values["ledger"]
    projection = require_scientific_result_state_projections(
        registry,
        ledger,
        expected_ledger_run_id="global-run-1",
        expected_execution_run_id="confirmatory-run-1",
        expected_canonical_state_code_version=SCIENTIFIC_V2_STATE_CODE_VERSION,
        expected_result_id="result-1",
        result_state_projection_artifact_sha256=(
            candidate["result_projection_record"].sha256
        ),
        statistical_state_projection_artifact_sha256=(
            candidate["statistical_projection_record"].sha256
        ),
        promotion_receipt_artifact_sha256=candidate["receipt_record"].sha256,
    )
    spec = values["spec"]
    repository = ResearchStateRepository(
        registry,
        ledger,
        run_id="global-run-1",
        code_version=SCIENTIFIC_V2_STATE_CODE_VERSION,
        configuration_hash=spec.configuration_sha256,
        state=ledger.assert_valid().events[-1].requested_state_after,
    )
    return {
        "values": values,
        "candidate": candidate,
        "projection": projection,
        "registry": registry,
        "ledger": ledger,
        "repository": repository,
    }


def _negative_claim_graph(
    registry: ArtifactRegistry,
    *,
    claim_id: str = "claim-negative",
    evidence_id: str = "evidence-negative",
) -> dict[str, object]:
    claim_text = "The prose asserts success although the frozen result contradicts it."
    evidence_artifact = registry.put_json(
        {
            "claim_id": claim_id,
            "claim_text": claim_text,
            "evidence_kind": GraphEvidenceKind.RESULT.value,
            "supports_claim": False,
            "contradicts_claim": True,
        },
        logical_type=f"claim_evidence.{GraphEvidenceKind.RESULT.value}",
        origin="focused negative claim-evidence fixture",
        creator_role=Role.EXPERIMENT_RUNNER,
        creation_command=("scientist-one", "negative-claim-fixture"),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=STAMP,
    )
    provisional = GraphEvidenceNode(
        evidence_id=evidence_id,
        kind=GraphEvidenceKind.RESULT,
        artifact_hash=evidence_artifact.sha256,
        description="The frozen result contradicts the proposed success claim.",
        verified=True,
        frozen=True,
        supports_claim=False,
        contradicts_claim=True,
        locally_verifiable=True,
    )
    material_claim = MaterialClaim(
        claim_id=claim_id,
        text=claim_text,
        evidence_links=(
            GraphEvidenceLink(evidence_id, GraphEvidenceKind.RESULT),
        ),
        producer_role=Role.EXPERIMENT_RUNNER,
        confirmatory=False,
        evidence_use=ClaimEvidenceUse.SCIENTIFIC,
    )
    support = EvidenceSupportReceipt.for_claim(
        material_claim,
        provisional,
        verifier_id="negative-claim-verifier",
        verification_result="PASS",
        supports_claim=False,
        contradicts_claim=True,
        locally_verifiable=True,
        rationale="The exact frozen result contradicts the claim.",
    )
    support_artifact = registry.put_json(
        support.to_dict(),
        logical_type=f"claim_support_receipt.{provisional.kind.value}",
        origin="focused negative support receipt",
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=("scientist-one", "negative-claim-verify"),
        parent_artifacts=(provisional.artifact_hash,),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=STAMP,
    )
    node = replace(
        provisional,
        verification_receipt_hash=support_artifact.sha256,
    )
    resolver = artifact_registry_resolver(
        registry,
        resolver_id=CLAIM_GRAPH_RESOLVER_ID,
    )
    graph = ClaimEvidenceGraph(evidence_resolver=resolver)
    graph.add_evidence(node)
    graph.add_claim(material_claim)
    decision = graph.verify_claim(
        claim_id,
        verifier_id="negative-claim-verifier",
        verifier_role=Role.CLAIM_VERIFIER,
        confirmatory_evidence_valid=False,
        raise_on_rejection=False,
    )
    verification = resolver(material_claim, node)
    verification_artifact = registry.put_bytes(
        verification.canonical_bytes,
        logical_type=(
            "claim_evidence_verification_receipt."
            f"{GraphEvidenceKind.RESULT.value}"
        ),
        origin="focused negative graph verification receipt",
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=("scientist-one", "negative-claim-resolve"),
        parent_artifacts=(node.artifact_hash, support_artifact.sha256),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=STAMP,
    )
    graph_value = graph.to_dict()
    graph_artifact = registry.put_json(
        {"decision": graph_value["decisions"][0], "graph": graph_value},
        logical_type="claim_evidence_graph",
        origin="focused negative claim-evidence graph",
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=("scientist-one", "negative-claim-graph"),
        parent_artifacts=(
            evidence_artifact.sha256,
            support_artifact.sha256,
            verification_artifact.sha256,
        ),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=STAMP,
    )
    return {
        "claim": material_claim,
        "node": node,
        "decision": decision,
        "graph": graph,
        "graph_artifact": graph_artifact,
        "support_artifact": support_artifact,
        "verification_artifact": verification_artifact,
    }


class HypothesisEvaluationPolicyTests(unittest.TestCase):
    def test_policy_has_one_terminal_result_for_every_outcome_class(self) -> None:
        policy = HypothesisEvaluationPolicy(
            policy_id="policy-exhaustive",
            hypothesis_id="hypothesis-exhaustive",
            metric_id="metric-exhaustive",
            meaningful_effect=0.10,
            falsification_effect=0.10,
            alpha=0.05,
            minimum_sample_size=20,
        )
        cases = {
            DesignHypothesisStatus.FALSIFIED: HypothesisEvaluationFacts(
                -0.30, -0.40, -0.20, 0.01, 20
            ),
            DesignHypothesisStatus.SUPPORTED: HypothesisEvaluationFacts(
                0.30, 0.20, 0.40, 0.01, 20
            ),
            DesignHypothesisStatus.INCONCLUSIVE: HypothesisEvaluationFacts(
                0.00, -0.20, 0.20, 0.50, 20
            ),
            DesignHypothesisStatus.PARTIALLY_SUPPORTED: HypothesisEvaluationFacts(
                0.05, 0.01, 0.09, 0.01, 20
            ),
            DesignHypothesisStatus.NOT_SUPPORTED: HypothesisEvaluationFacts(
                0.05, 0.01, 0.09, 0.50, 20
            ),
        }
        observed = {
            evaluate_hypothesis_policy(policy, facts)
            for facts in cases.values()
        }
        self.assertEqual(observed, set(cases))
        for expected, facts in cases.items():
            with self.subTest(expected=expected):
                self.assertIs(evaluate_hypothesis_policy(policy, facts), expected)
        self.assertNotIn(DesignHypothesisStatus.UNTESTED, observed)
        self.assertNotIn(
            HypothesisStatus.POST_HOC.value,
            {item.value for item in observed},
        )
        self.assertIs(
            evaluate_hypothesis_policy(
                policy,
                HypothesisEvaluationFacts(0.30, 0.20, 0.40, 0.01, 19),
            ),
            DesignHypothesisStatus.INCONCLUSIVE,
        )

    def test_v2_contract_requires_complete_policy_set_and_replays_exactly(self) -> None:
        legacy = make_contract()
        with self.assertRaisesRegex(ScientificDesignError, "one policy for every"):
            replace(
                legacy,
                hypothesis_evaluation_policies=_policies(legacy)[:1],
            )
        contract = replace(
            legacy,
            hypothesis_evaluation_policies=_policies(legacy),
        )
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory)
            parent = registry.put_json(
                {"kind": "prospective-policy-fixture"},
                logical_type="frozen_scientific_inputs",
                origin="focused prospective policy fixture",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "policy-fixture"),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            record = register_frozen_evaluation_contract(
                registry,
                contract=contract,
                parent_artifact_sha256s=(parent.sha256,),
            )
            wrapper = safe_json_loads(registry.get_bytes(record.sha256))
            self.assertEqual(
                wrapper["schema_version"],
                CHECKED_SUPERIORITY_CONTRACT_SCHEMA_V2,
            )
            self.assertEqual(
                record.schema_version,
                EVALUATION_CONTRACT_ARTIFACT_SCHEMA_V2,
            )
            self.assertEqual(
                require_frozen_evaluation_contract(
                    registry,
                    contract_artifact_sha256=record.sha256,
                ),
                contract,
            )


class HypothesisEvaluationAuthorityTests(unittest.TestCase):
    def test_source_owned_mechanical_evaluation_is_append_only_and_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _mechanical_v2_source(Path(directory))
            graph = _scientific_v2_state_graph(source)
            repository = source["repository"]
            registry = source["registry"]
            ledger = source["ledger"]
            materialized = repository.materialize_scientific_result_bundle(
                ancestors=graph["ancestors"],
                result=graph["result"],
                statistical_test=graph["statistical_test"],
                reason="non-evidentiary hypothesis evaluation fixture",
            )
            prior = next(
                item
                for item in materialized
                if item.research_object.object_type == "Hypothesis"
                and item.research_object.object_id == "hypothesis-primary"
            )
            result = next(
                item
                for item in materialized
                if item.research_object.object_type == "Result"
            )
            statistical_test = next(
                item
                for item in materialized
                if item.research_object.object_type == "StatisticalTest"
            )
            evaluated_at = _timestamp_after(
                ledger.assert_valid().events[-1].timestamp,
                1,
            )
            contract_record = source["values"]["contract_record"]
            contract = require_frozen_evaluation_contract(
                registry,
                contract_artifact_sha256=contract_record.sha256,
            )
            altered_contract = replace(
                contract,
                hypothesis_evaluation_policies=(
                    replace(
                        contract.hypothesis_evaluation_policies[0],
                        meaningful_effect=0.20,
                    ),
                    *contract.hypothesis_evaluation_policies[1:],
                ),
            )
            before_substitution = (
                registry.verify_all(raise_on_error=True), ledger.assert_valid(),
            )
            with self.assertRaisesRegex(
                ScientificDesignError, "persisted amendment lineage",
            ):
                register_frozen_evaluation_contract(
                    registry,
                    contract=altered_contract,
                    parent_artifact_sha256s=contract_record.parent_artifacts,
                )
            self.assertEqual(
                (registry.verify_all(raise_on_error=True), ledger.assert_valid()),
                before_substitution,
            )
            # Keep the downstream wrong-contract refusal too: a distinct
            # prospective descriptor cannot replace the Result's exact source.
            # This registers no new freeze, result, or amendment authority.
            altered_contract = replace(
                altered_contract, contract_id="foreign-policy-substitution",
            )
            altered_contract_record = register_frozen_evaluation_contract(
                registry,
                contract=altered_contract,
                parent_artifact_sha256s=contract_record.parent_artifacts,
            )
            event_count = ledger.assert_valid().event_count
            with self.assertRaisesRegex(
                ValidationError,
                "another evaluation contract",
            ):
                register_hypothesis_evaluation_authority(
                    registry,
                    ledger,
                    authority_id="post-result-policy-substitution",
                    run_id="global-run-1",
                    prior_hypothesis_state_artifact_hash=prior.artifact.sha256,
                    result_state_artifact_hash=result.artifact.sha256,
                    statistical_test_state_artifact_hash=(
                        statistical_test.artifact.sha256
                    ),
                    evaluation_contract_artifact_hash=(
                        altered_contract_record.sha256
                    ),
                    evaluated_at=evaluated_at,
                )
            self.assertEqual(ledger.assert_valid().event_count, event_count)
            authority_record = register_hypothesis_evaluation_authority(
                registry,
                ledger,
                authority_id="hypothesis-primary-evaluation",
                run_id="global-run-1",
                prior_hypothesis_state_artifact_hash=prior.artifact.sha256,
                result_state_artifact_hash=result.artifact.sha256,
                statistical_test_state_artifact_hash=(
                    statistical_test.artifact.sha256
                ),
                evaluation_contract_artifact_hash=(
                    contract_record.sha256
                ),
                evaluated_at=evaluated_at,
            )
            authority = require_hypothesis_evaluation_authority(
                registry,
                ledger,
                authority_artifact_hash=authority_record.sha256,
                expected_run_id="global-run-1",
                expected_hypothesis_id="hypothesis-primary",
            )
            self.assertIs(authority.outcome, HypothesisStatus.SUPPORTED)
            self.assertIs(
                authority.evidence_scope,
                HypothesisEvaluationEvidenceScope.NON_EVIDENTIARY_MECHANICAL,
            )
            self.assertFalse(authority.scientific_evidence_eligible)
            self.assertIn(
                "BACKEND_SCIENTIFIC_EXECUTION_UNAVAILABLE",
                authority.blocker_codes,
            )
            event = ledger.assert_valid().events[authority.evaluation_event_index]
            self.assertEqual(
                event.metadata["hypothesis_evaluation"]["kind"],
                "HYPOTHESIS_EVALUATED",
            )
            self.assertFalse(
                any(
                    candidate.event_type == "CORRECTION"
                    and candidate.supersedes_event_id == event.event_id
                    for candidate in ledger.assert_valid().events
                )
            )
            with self.assertRaises(ValidationError):
                require_hypothesis_evaluation_authority(
                    registry,
                    ledger,
                    authority_artifact_hash=authority_record.sha256,
                    expected_run_id="another-run",
                )

            revision = build_evaluated_hypothesis_revision(
                registry,
                ledger,
                authority_artifact_hash=authority_record.sha256,
                expected_run_id="global-run-1",
                prior_hypothesis=prior.research_object,
                created_at=_timestamp_after(
                    ledger.assert_valid().events[-1].timestamp,
                    1,
                ),
            )
            forged_status = replace(
                revision,
                hypothesis_status=HypothesisStatus.FALSIFIED,
                content_hash=None,
            )
            with self.assertRaises(ValidationError):
                repository.materialize(forged_status)
            materialized_revision = repository.materialize(revision)
            self.assertEqual(materialized_revision.research_object.revision, 2)
            stored = repository._stored_objects()
            by_content, _by_identity = repository._indexes(stored)
            self.assertFalse(
                repository._resolve_object_authority(
                    materialized_revision.research_object,
                    by_content,
                ).scientific_evidence_eligible
            )
            self.assertTrue(repository.validate_state().valid)
            self.assertEqual(
                register_hypothesis_evaluation_authority(
                    registry,
                    ledger,
                    authority_id="hypothesis-primary-evaluation",
                    run_id="global-run-1",
                    prior_hypothesis_state_artifact_hash=prior.artifact.sha256,
                    result_state_artifact_hash=result.artifact.sha256,
                    statistical_test_state_artifact_hash=(
                        statistical_test.artifact.sha256
                    ),
                    evaluation_contract_artifact_hash=(
                        contract_record.sha256
                    ),
                    evaluated_at=evaluated_at,
                ),
                authority_record,
            )
            with self.assertRaisesRegex(
                ValidationError,
                "stale or ambiguously revised",
            ):
                register_hypothesis_evaluation_authority(
                    registry,
                    ledger,
                    authority_id="hypothesis-primary-evaluation-retry",
                    run_id="global-run-1",
                    prior_hypothesis_state_artifact_hash=prior.artifact.sha256,
                    result_state_artifact_hash=result.artifact.sha256,
                    statistical_test_state_artifact_hash=(
                        statistical_test.artifact.sha256
                    ),
                    evaluation_contract_artifact_hash=(
                        contract_record.sha256
                    ),
                    evaluated_at=_timestamp_after(
                        ledger.assert_valid().events[-1].timestamp,
                        1,
                    ),
                )

            forged_payload = authority.to_dict()
            forged_payload["authority_id"] = "ambiguous-hypothesis-evaluation"
            registry.put_json(
                forged_payload,
                logical_type="hypothesis_evaluation_authority",
                origin="source-owned prospective hypothesis evaluation authority",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "evaluate-hypothesis"),
                parent_artifacts=authority.source_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=evaluated_at,
            )
            with self.assertRaisesRegex(ValidationError, "ambiguous"):
                require_hypothesis_evaluation_authority(
                    registry,
                    ledger,
                    authority_artifact_hash=authority_record.sha256,
                    expected_run_id="global-run-1",
                )


class RejectedCanonicalStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.registry = ArtifactRegistry(
            self.temporary.name,
            "runs/run-1/registry",
        )
        self.ledger = EventLedger(
            self.temporary.name,
            "runs/run-1/events.jsonl",
        )
        self.repository = ResearchStateRepository(
            self.registry,
            self.ledger,
            run_id="run-1",
            code_version="code-v1",
            configuration_hash=CONFIGURATION_HASH,
            state=MacroState.GROUND,
        )

    def _records(self) -> tuple[Evidence, Claim, dict[str, object]]:
        fixture = _negative_claim_graph(self.registry)
        graph = fixture["graph_artifact"]
        node = fixture["node"]
        decision = fixture["decision"]
        material_claim = fixture["claim"]
        sources = tuple(
            sorted(
                (
                    graph.sha256,
                    fixture["support_artifact"].sha256,
                    fixture["verification_artifact"].sha256,
                )
            )
        )
        evidence = Evidence(
            object_id=node.evidence_id,
            producer=Role.CLAIM_VERIFIER,
            status=RecordStatus.REJECTED,
            created_at=graph.created_at,
            evidence_kind=node.kind.value,
            source_artifact_hashes=sources,
            contradicts_claim_ids=(material_claim.claim_id,),
            verification_depth=ReferenceVerificationDepth.LEVEL_0,
            locator=f"claim-graph:{graph.sha256}#{node.evidence_id}",
            verification_status=VerificationStatus.REJECTED,
            verified_at=graph.created_at,
            authority_artifact_hashes=sources,
        )
        evidence_ids = tuple(
            link.evidence_id for link in material_claim.evidence_links
        )
        claim = Claim(
            object_id=material_claim.claim_id,
            producer=material_claim.producer_role,
            status=RecordStatus.REJECTED,
            created_at=graph.created_at,
            parents=(
                ObjectReference(
                    "Evidence",
                    evidence.object_id,
                    evidence.content_hash,
                    "reviewed_against",
                    True,
                ),
            ),
            claim_type=ClaimType.QUALITATIVE,
            claim_text=material_claim.text,
            scope="REJECTED",
            evidence_ids=evidence_ids,
            source_artifact_ids=sources,
            verification_method="ClaimEvidenceGraph.verify_claim/v1",
            verification_status=VerificationStatus.REJECTED,
            confidence=0.0,
            expressed_strength=ClaimStrength.UNSUPPORTED,
            permitted_strength=ClaimStrength.UNSUPPORTED,
            failure_reason=decision.reason,
            review_history=(
                ClaimReview(
                    reviewer=Role.CLAIM_VERIFIER,
                    timestamp=graph.created_at,
                    verification_status=VerificationStatus.REJECTED,
                    reason=decision.reason,
                    evidence_ids=evidence_ids,
                    source_artifact_ids=sources,
                ),
            ),
            confirmatory=material_claim.confirmatory,
            evidence_use=material_claim.evidence_use,
            authority_artifact_hashes=sources,
        )
        return evidence, claim, fixture

    def test_negative_graph_materializes_rejected_evidence_and_claim_only(self) -> None:
        evidence, claim, fixture = self._records()
        self.assertIs(
            fixture["decision"].decision,
            GraphClaimDecision.CONTRADICTED,
        )
        self.repository.materialize(evidence)
        self.repository.materialize(claim)
        report = self.repository.validate_state()
        self.assertTrue(report.valid, report.issues)
        stored = self.repository._stored_objects()
        by_content, _by_identity = self.repository._indexes(stored)
        self.assertFalse(
            self.repository._resolve_object_authority(
                evidence,
                by_content,
            ).scientific_evidence_eligible
        )
        self.assertFalse(
            self.repository._resolve_object_authority(
                claim,
                by_content,
            ).scientific_evidence_eligible
        )

        prose_forgery = replace(
            claim,
            failure_reason="Caller prose declares falsification.",
            review_history=(
                replace(
                    claim.review_history[0],
                    reason="Caller prose declares falsification.",
                ),
            ),
            content_hash=None,
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(prose_forgery)

    def test_forged_or_ambiguous_negative_graph_has_no_rejection_authority(
        self,
    ) -> None:
        evidence, claim, fixture = self._records()
        graph_record = fixture["graph_artifact"]
        graph_payload = json.loads(self.registry.get_bytes(graph_record.sha256))
        graph_payload["graph"]["decisions"][0]["reason"] = "forged reason"
        forged_graph = self.registry.put_json(
            graph_payload,
            logical_type="claim_evidence_graph",
            origin="focused forged negative graph",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "negative-claim-graph"),
            parent_artifacts=graph_record.parent_artifacts,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        forged_sources = tuple(
            sorted(
                {
                    *claim.authority_artifact_hashes,
                    forged_graph.sha256,
                }
            )
        )
        ambiguous = replace(
            claim,
            source_artifact_ids=forged_sources,
            authority_artifact_hashes=forged_sources,
            review_history=(
                replace(
                    claim.review_history[0],
                    source_artifact_ids=forged_sources,
                ),
            ),
            content_hash=None,
        )
        self.repository.materialize(evidence)
        with self.assertRaisesRegex(ValidationError, "one exact"):
            self.repository.materialize(ambiguous)


class RejectedReferenceSupportTests(unittest.TestCase):
    def test_rejected_reference_owner_replays_but_never_grants_writer_status(
        self,
    ) -> None:
        fixture = reference_support_test_module.ReferenceSupportDecycleTests(
            "runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        request = fixture._request()
        semantic_receipt, semantic_record = fixture._semantic_receipt(
            request,
            label="canonical-rejected",
            outcome="REFERENCE_SUPPORT_REJECTED",
            semantic_support=False,
        )
        with fixture._controlled_boundary(), fixture._semantic_boundary(
            {semantic_record.sha256: semantic_receipt}
        ):
            rejected = require_rejected_claim_bound_reference_support(
                fixture.registry,
                fixture.ledger,
                expected_run_id=fixture.run_id,
                semantic_judgment_artifact_sha256=semantic_record.sha256,
                expected_claim_id=fixture.claim_id,
            )
            self.assertFalse(rejected.scientific_writer_eligible)
            self.assertFalse(rejected.semantic_support)

            repository = ResearchStateRepository(
                fixture.registry,
                fixture.ledger,
                run_id=fixture.run_id,
                code_version="reference-fixture-v1",
                configuration_hash=CONFIGURATION_HASH,
                state=MacroState.GROUND,
            )
            graph_value = safe_json_loads(
                fixture.registry.get_bytes(fixture.graph.sha256)
            )["graph"]
            graph = ClaimEvidenceGraph.from_dict(graph_value)
            graph_claim = next(
                item for item in graph.claims if item.claim_id == fixture.claim_id
            )
            evidence_ids = tuple(
                item.evidence_id for item in graph_claim.evidence_links
            )
            receipt_hashes = tuple(
                digest
                for digest in fixture.graph.parent_artifacts
                if fixture.registry.get_metadata(digest).logical_type.startswith(
                    (
                        "claim_support_receipt.",
                        "claim_evidence_verification_receipt.",
                    )
                )
            )
            sources = tuple(
                sorted(
                    (
                        fixture.graph.sha256,
                        *receipt_hashes,
                        semantic_record.sha256,
                    )
                )
            )
            proposal = rejected.proposal
            claim = Claim(
                object_id=fixture.claim_id,
                producer=proposal.claim_producer_role,
                status=RecordStatus.REJECTED,
                created_at=semantic_record.created_at,
                claim_type=proposal.claim_type,
                claim_text=proposal.claim_text,
                scope=proposal.scope,
                evidence_ids=evidence_ids,
                source_artifact_ids=sources,
                verification_method=proposal.verification_method,
                verification_status=VerificationStatus.REJECTED,
                confidence=0.0,
                expressed_strength=ClaimStrength.UNSUPPORTED,
                permitted_strength=ClaimStrength.UNSUPPORTED,
                failure_reason=rejected.rationale,
                review_history=(
                    ClaimReview(
                        reviewer=Role.CLAIM_VERIFIER,
                        timestamp=semantic_record.created_at,
                        verification_status=VerificationStatus.REJECTED,
                        reason=rejected.rationale,
                        evidence_ids=evidence_ids,
                        source_artifact_ids=sources,
                    ),
                ),
                confirmatory=graph_claim.confirmatory,
                evidence_use=graph_claim.evidence_use,
                authority_artifact_hashes=sources,
            )
            repository.materialize(claim)
            stored = repository._stored_objects()
            by_content, _by_identity = repository._indexes(stored)
            self.assertFalse(
                repository._resolve_object_authority(
                    claim,
                    by_content,
                ).scientific_evidence_eligible
            )


if __name__ == "__main__":
    unittest.main()
