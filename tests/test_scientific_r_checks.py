from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.domains import (
    DomainCheck,
    DomainEvidenceScope,
    DomainKind,
    DomainValidityOutcome,
    DomainValidityStatus,
)
from scientist_one.evaluators import (
    AuthorityScope,
    AuthorityStatus,
    EvaluatorClass,
    RCheck,
)
from scientist_one.gates import SemanticChallengeAuditStatus
from scientist_one.gates import _semantic_challenger_audit_content_projection
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.research_state import (
    MetricDirection as StateMetricDirection,
    RecordStatus,
    Result,
    StatisticalTest,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    ResearchGateOutcome,
    ScientificGateVerificationStatus,
)
from scientist_one.scientific_r_checks import (
    _derive_r1_assessment_only,
    _derive_r1_join,
    _exact_route,
    _resolve_r3_e0_domain,
    resolve_scientific_r_check_sources,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _record(label: str, logical_type: str) -> ArtifactRecord:
    digest = _digest(label)
    return ArtifactRecord(
        sha256=digest,
        path=f"state/artifacts/objects/{digest[:2]}/{digest}",
        relative_path=f"state/artifacts/objects/{digest[:2]}/{digest}",
        metadata_path=f"state/artifacts/metadata/{digest}.json",
        logical_type=logical_type,
        schema_version="1.0",
        mime_type="application/json",
        size=3,
        origin="test-only scientific R-check join",
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=("scientist-one", "test-r-check-join"),
        parent_artifacts=(),
        validation_result="PASS",
        frozen=True,
        created_at="2026-09-05T00:00:00Z",
    )


def _changed(value: SimpleNamespace, **changes) -> SimpleNamespace:
    return SimpleNamespace(**{**vars(value), **changes})


class ScientificR1JoinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assessment_record = _record(
            "assessment", "research_question_gate_assessment"
        )
        self.freeze_record = _record(
            "freeze", "evaluation_contract_freeze_gate_receipt"
        )
        self.contract_record = _record("contract", "evaluation_contract")
        self.audit_record = _record("audit", "semantic_challenge_audit_authority")
        self.brief_artifact_sha256 = _digest("research-brief")
        self.brief_record_hash = _digest("research-brief-record")
        self.contract_sha256 = _digest("contract-content")
        self.assessment = SimpleNamespace(
            run_id="r-check-run",
            ledger_path="runs/r-check-run/events.jsonl",
            gate_event_index=1,
            object_id="research-question",
            outcome=ResearchGateOutcome.PROCEED,
            verification_status=(ScientificGateVerificationStatus.SCIENTIFIC_EVIDENCE),
            scientific_evidence_eligible=True,
            research_brief_artifact_sha256=self.brief_artifact_sha256,
            research_brief_record_hash=self.brief_record_hash,
            research_brief_sha256=_digest("brief-content"),
        )
        self.contract = SimpleNamespace(
            research_brief_sha256=self.assessment.research_brief_sha256,
            sha256=self.contract_sha256,
        )
        self.freeze = SimpleNamespace(
            run_id="r-check-run",
            ledger_path="runs/r-check-run/events.jsonl",
            design_freeze_event_index=2,
            object_id="evaluation-contract",
            contract_artifact_sha256=self.contract_record.sha256,
            contract_record_hash=self.contract_record.record_hash,
            contract_sha256=self.contract_sha256,
        )

    def _join(
        self,
        *,
        evaluator_class: EvaluatorClass = EvaluatorClass.E0,
        assessment=None,
        freeze=None,
        audit=None,
        audit_record=None,
        audit_provenance_bindings=None,
        assessment_record=None,
        contract=None,
        contract_record=None,
    ):
        selected_assessment_record = (
            self.assessment_record if assessment_record is None else assessment_record
        )
        selected_contract = self.contract if contract is None else contract
        selected_contract_record = (
            self.contract_record if contract_record is None else contract_record
        )
        return _derive_r1_join(
            run_id="r-check-run",
            evaluator_class=evaluator_class,
            assessment=self.assessment if assessment is None else assessment,
            assessment_record=selected_assessment_record,
            freeze=self.freeze if freeze is None else freeze,
            freeze_record=self.freeze_record,
            contract=selected_contract,
            contract_record=selected_contract_record,
            audit=audit,
            audit_record=audit_record,
            audit_provenance_bindings=audit_provenance_bindings,
        )

    def test_e0_pass_requires_exact_scientific_gate_and_contract_join(self) -> None:
        result = self._join()
        self.assertIs(result.status, AuthorityStatus.PASS)
        self.assertIs(result.scope, AuthorityScope.SCIENTIFIC)
        self.assertEqual(
            result.reason_code,
            "SCIENTIFIC_RESEARCH_QUESTION_AND_CONTRACT_REPLAYED",
        )
        subject = dict(result.subject_key)
        self.assertEqual(
            subject["contract_artifact_sha256"], self.contract_record.sha256
        )
        self.assertEqual(
            subject["contract_record_hash"], self.contract_record.record_hash
        )

        reversed_order = _changed(self.freeze, design_freeze_event_index=1)
        rejected = self._join(freeze=reversed_order)
        self.assertIs(rejected.status, AuthorityStatus.FAIL)
        self.assertEqual(rejected.reason_code, "SCIENTIFIC_R1_SUBJECT_MISMATCH")

    def test_only_precise_novelty_adverse_fails_and_fixture_is_untested(self) -> None:
        adverse = _changed(
            self.assessment,
            outcome=ResearchGateOutcome.TERMINATE,
        )
        result = self._join(assessment=adverse)
        self.assertIs(result.status, AuthorityStatus.UNTESTED)
        self.assertIs(result.scope, AuthorityScope.SCIENTIFIC)

        novelty = _changed(
            self.assessment,
            outcome=ResearchGateOutcome.INSUFFICIENT_NOVELTY,
        )
        result = self._join(assessment=novelty)
        self.assertIs(result.status, AuthorityStatus.FAIL)
        self.assertIs(result.scope, AuthorityScope.SCIENTIFIC)

        fixture = _changed(
            adverse,
            verification_status=ScientificGateVerificationStatus.NON_EVIDENTIARY,
            scientific_evidence_eligible=False,
        )
        result = self._join(assessment=fixture)
        self.assertIs(result.status, AuthorityStatus.UNTESTED)
        self.assertIs(result.scope, AuthorityScope.SYSTEM_FIXTURE)
        self.assertEqual(result.reason_code, "NON_EVIDENTIARY_MECHANICAL")

    def test_assessment_only_retains_novelty_failure_but_not_missing_freeze(
        self,
    ) -> None:
        novelty = _changed(
            self.assessment,
            outcome=ResearchGateOutcome.INSUFFICIENT_NOVELTY,
        )
        result = _derive_r1_assessment_only(
            run_id="r-check-run",
            evaluator_class=EvaluatorClass.E0,
            assessment=novelty,
            assessment_record=self.assessment_record,
        )
        self.assertIs(result.status, AuthorityStatus.FAIL)
        self.assertIs(result.scope, AuthorityScope.SCIENTIFIC)

        proceed = _derive_r1_assessment_only(
            run_id="r-check-run",
            evaluator_class=EvaluatorClass.E0,
            assessment=self.assessment,
            assessment_record=self.assessment_record,
        )
        self.assertIs(proceed.status, AuthorityStatus.UNTESTED)
        self.assertEqual(
            proceed.reason_code,
            "R1_CONTRACT_FREEZE_AUTHORITY_UNAVAILABLE",
        )

    def test_e2_requires_experimental_design_audit_on_exact_subject(self) -> None:
        audit = SimpleNamespace(
            run_id="r-check-run",
            verification_event_index=3,
            input_artifact_hashes=(
                self.contract_record.sha256,
                self.brief_artifact_sha256,
            ),
            input_artifact_record_hashes=(
                self.contract_record.record_hash,
                self.brief_record_hash,
            ),
            status=SemanticChallengeAuditStatus.PASS,
            scientific_source_qualified=True,
        )
        result = self._join(
            evaluator_class=EvaluatorClass.E2,
            audit=audit,
            audit_record=self.audit_record,
            audit_provenance_bindings={
                self.contract_record.sha256: str(self.contract_record.record_hash),
                self.brief_artifact_sha256: self.brief_record_hash,
            },
        )
        self.assertIs(result.status, AuthorityStatus.PASS)
        self.assertIs(result.scope, AuthorityScope.SCIENTIFIC)

        failed = _changed(audit, status=SemanticChallengeAuditStatus.FAIL)
        result = self._join(
            evaluator_class=EvaluatorClass.E2,
            audit=failed,
            audit_record=self.audit_record,
            audit_provenance_bindings={
                self.contract_record.sha256: str(self.contract_record.record_hash),
                self.brief_artifact_sha256: self.brief_record_hash,
            },
        )
        self.assertIs(result.status, AuthorityStatus.FAIL)
        self.assertEqual(result.reason_code, "EXPERIMENTAL_DESIGN_AUDIT_FAILED")

        result = self._join(
            evaluator_class=EvaluatorClass.E2,
            audit=audit,
            audit_record=self.audit_record,
            audit_provenance_bindings={
                self.contract_record.sha256: _digest("wrong-contract-record"),
                self.brief_artifact_sha256: self.brief_record_hash,
            },
        )
        self.assertIs(result.status, AuthorityStatus.FAIL)
        self.assertEqual(
            result.reason_code,
            "SCIENTIFIC_R1_AUDIT_SUBJECT_MISMATCH",
        )

    def test_e2_uses_real_recursive_audit_parent_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(Path(directory), "state/registry")
            brief = registry.put_json(
                {"kind": "brief"},
                logical_type="research_brief",
                origin="test-only recursive R1 brief",
                creator_role=Role.PROBLEM_INVESTIGATOR,
                creation_command=("scientist-one", "test-r1-brief"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            contract_record = registry.put_json(
                {"kind": "contract"},
                logical_type="evaluation_contract",
                origin="test-only recursive R1 contract",
                creator_role=Role.PROTOCOL_DESIGNER,
                creation_command=("scientist-one", "test-r1-contract"),
                parent_artifacts=(brief.sha256,),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            snapshot = registry.put_json(
                {"kind": "canonical-snapshot"},
                logical_type="canonical_research_state_snapshot",
                origin="test-only recursive R1 snapshot",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "test-r1-snapshot"),
                parent_artifacts=(contract_record.sha256,),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            projection = _semantic_challenger_audit_content_projection(
                registry,
                (snapshot.sha256,),
            )
            bindings = {
                str(item["artifact_sha256"]): str(item["artifact_record_hash"])
                for item in projection
            }
            # The audit root names only the snapshot.  The exact contract and
            # brief become available solely through the real recursive walk.
            self.assertNotIn(contract_record.sha256, (snapshot.sha256,))
            self.assertEqual(
                bindings[contract_record.sha256], contract_record.record_hash
            )
            self.assertEqual(bindings[brief.sha256], brief.record_hash)

            assessment = _changed(
                self.assessment,
                research_brief_artifact_sha256=brief.sha256,
                research_brief_record_hash=str(brief.record_hash),
            )
            contract = _changed(self.contract)
            freeze = _changed(
                self.freeze,
                contract_artifact_sha256=contract_record.sha256,
                contract_record_hash=contract_record.record_hash,
            )
            audit = SimpleNamespace(
                run_id="r-check-run",
                verification_event_index=3,
                input_artifact_hashes=(snapshot.sha256,),
                input_artifact_record_hashes=(snapshot.record_hash,),
                status=SemanticChallengeAuditStatus.PASS,
                scientific_source_qualified=True,
            )
            result = self._join(
                evaluator_class=EvaluatorClass.E2,
                assessment=assessment,
                freeze=freeze,
                contract=contract,
                contract_record=contract_record,
                audit=audit,
                audit_record=self.audit_record,
                audit_provenance_bindings=bindings,
            )
            self.assertIs(result.status, AuthorityStatus.PASS)

    def test_selector_is_closed_over_exact_type_multisets(self) -> None:
        self.assertEqual(
            _exact_route(
                RCheck.R1,
                EvaluatorClass.E0,
                (self.assessment_record, self.freeze_record),
            ),
            "R1_E0",
        )
        self.assertIsNone(
            _exact_route(
                RCheck.R1,
                EvaluatorClass.E0,
                (self.assessment_record, self.freeze_record, self.audit_record),
            )
        )
        self.assertEqual(
            _exact_route(
                RCheck.R1,
                EvaluatorClass.E0,
                (self.assessment_record,),
            ),
            "R1_ASSESSMENT_E0",
        )
        self.assertIsNone(
            _exact_route(
                RCheck.R2,
                EvaluatorClass.E0,
                (self.assessment_record, self.freeze_record),
            )
        )


class ScientificRCheckResolverBoundaryTests(unittest.TestCase):
    def _canonical_pair(
        self,
        registry: ArtifactRegistry,
        *,
        v3: bool,
    ) -> tuple[ArtifactRecord, ArtifactRecord]:
        result = Result(
            object_id="result-primary",
            producer=Role.STATISTICIAN,
            status=RecordStatus.COMPLETE,
            created_at="2026-09-05T00:00:01Z",
            code_version="canonical-state-test",
            metadata=(
                {
                    "schema_version": "scientific-result-canonical-state/v3",
                    "checked_result_assessment_artifact_sha256": _digest("assessment"),
                    "hypothesis_id": "hypothesis-primary",
                    "hypothesis_status": "NOT_SUPPORTED",
                    "scientific_result_outcome": "NEGATIVE",
                    "superiority_authority_artifact_sha256": None,
                }
                if v3
                else {}
            ),
            run_ids=("execution-run",),
            metric_id="metric-primary",
            value={"improvement": -0.1},
            unit="FRACTION",
            direction=StateMetricDirection.HIGHER_IS_BETTER,
            uncertainty={"confidence_low": -0.2, "confidence_high": 0.0},
            source_artifact_hashes=(_digest("aggregate"),),
            evaluation_artifact_hashes=(_digest("promotion"),),
            code_revision="canonical-state-test",
            observed_at="2026-09-05T00:00:00Z",
        )
        statistical_test = StatisticalTest(
            object_id="statistical-primary",
            producer=Role.STATISTICIAN,
            status=RecordStatus.COMPLETE,
            created_at="2026-09-05T00:00:02Z",
            code_version="canonical-state-test",
            metadata=(
                {
                    "schema_version": "scientific-statistical-canonical-state/v3",
                    "hypothesis_id": "hypothesis-primary",
                    "hypothesis_status": "NOT_SUPPORTED",
                    "scientific_result_outcome": "NEGATIVE",
                }
                if v3
                else {}
            ),
            result_ids=(result.object_id,),
            test_name="two-sided exact paired test",
            null_hypothesis="zero",
            alternative="non-zero",
            method_configuration={"procedure": "test-only"},
            outcome={"effect": -0.1},
            source_artifact_hashes=(_digest("statistics"),),
        )
        result_record = registry.put_json(
            result.to_dict(),
            logical_type=result.logical_type,
            origin="test-only canonical R-check result",
            creator_role=result.producer,
            creation_command=("scientist-one", "test-r-check-canonical"),
            parent_artifacts=(),
            schema_version=result.schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=result.created_at,
        )
        test_record = registry.put_json(
            statistical_test.to_dict(),
            logical_type=statistical_test.logical_type,
            origin="test-only canonical R-check test",
            creator_role=statistical_test.producer,
            creation_command=("scientist-one", "test-r-check-canonical"),
            parent_artifacts=(),
            schema_version=statistical_test.schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=statistical_test.created_at,
        )
        return result_record, test_record

    def test_remaining_selector_routes_are_exact_and_bounded(self) -> None:
        result = _record("canonical-result", "research_state.result")
        statistical = _record("canonical-test", "research_state.statistical_test")
        run = _record("canonical-run", "research_state.run")
        implementation = _record(
            "canonical-implementation", "research_state.implementation"
        )
        method = _record("canonical-method", "research_state.method")
        spec = _record("frozen-spec", "frozen_run_spec")
        audit = _record("statistics-audit", "semantic_challenge_audit_authority")
        timeline = _record(
            "scientific-timeline-v2",
            "scientific_confirmatory_timeline_receipt_v2",
        )

        self.assertEqual(
            _exact_route(RCheck.R4, EvaluatorClass.E0, (result, statistical)),
            "R4_E0_CANONICAL_V3",
        )
        self.assertEqual(
            _exact_route(
                RCheck.R4,
                EvaluatorClass.E2,
                (result, statistical, audit),
            ),
            "R4_E2_CANONICAL_V3",
        )
        r2 = (result, statistical, run, implementation, method, spec)
        self.assertEqual(
            _exact_route(RCheck.R2, EvaluatorClass.E0, r2),
            "R2_E0_CANONICAL_V3",
        )
        self.assertEqual(
            _exact_route(RCheck.R2, EvaluatorClass.E2, (*r2, audit)),
            "R2_E2_CANONICAL_V3",
        )
        self.assertEqual(
            _exact_route(RCheck.R3, EvaluatorClass.E3, (timeline,)),
            "R3_E3_TIMELINE_V2",
        )
        self.assertIsNone(_exact_route(RCheck.R2, EvaluatorClass.E2, r2))
        self.assertIsNone(_exact_route(RCheck.R4, EvaluatorClass.E2, (result, audit)))

    def test_old_canonical_result_test_pair_retains_legacy_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/r-check-run/registry")
            ledger = EventLedger(root, "runs/r-check-run/events.jsonl")
            result, statistical = self._canonical_pair(registry, v3=False)
            ledger.record(
                run_id="r-check-run",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CALIBRATE,
                artifact_hashes=(),
                code_version=f"sha256:{_digest('canonical-code')}",
                configuration_hash=_digest("canonical-configuration"),
                reason="test-only old canonical R-check fallback",
            )
            self.assertIsNone(
                resolve_scientific_r_check_sources(
                    registry,
                    ledger,
                    run_id="r-check-run",
                    r_check=RCheck.R4,
                    evaluator_class=EvaluatorClass.E0,
                    source_artifact_sha256s=(result.sha256, statistical.sha256),
                )
            )

    def test_v3_labels_without_canonical_owner_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/r-check-run/registry")
            ledger = EventLedger(root, "runs/r-check-run/events.jsonl")
            result, statistical = self._canonical_pair(registry, v3=True)
            ledger.record(
                run_id="r-check-run",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CALIBRATE,
                artifact_hashes=(),
                code_version=f"sha256:{_digest('canonical-code')}",
                configuration_hash=_digest("canonical-configuration"),
                reason="test-only forged v3 canonical R-check",
            )
            resolution = resolve_scientific_r_check_sources(
                registry,
                ledger,
                run_id="r-check-run",
                r_check=RCheck.R4,
                evaluator_class=EvaluatorClass.E0,
                source_artifact_sha256s=(result.sha256, statistical.sha256),
            )
            assert resolution is not None
            self.assertIs(resolution.status, AuthorityStatus.FAIL)
            self.assertEqual(
                resolution.reason_code,
                "SCIENTIFIC_R4_OWNER_REPLAY_FAILED",
            )

    def test_mixed_canonical_schema_profiles_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/r-check-run/registry")
            ledger = EventLedger(root, "runs/r-check-run/events.jsonl")
            v3_result, _v3_statistical = self._canonical_pair(registry, v3=True)
            _old_result, old_statistical = self._canonical_pair(registry, v3=False)
            ledger.record(
                run_id="r-check-run",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CALIBRATE,
                artifact_hashes=(),
                code_version=f"sha256:{_digest('mixed-canonical-code')}",
                configuration_hash=_digest("mixed-canonical-configuration"),
                reason="test-only mixed canonical R-check",
            )
            resolution = resolve_scientific_r_check_sources(
                registry,
                ledger,
                run_id="r-check-run",
                r_check=RCheck.R4,
                evaluator_class=EvaluatorClass.E0,
                source_artifact_sha256s=(
                    v3_result.sha256,
                    old_statistical.sha256,
                ),
            )
            assert resolution is not None
            self.assertIs(resolution.status, AuthorityStatus.FAIL)
            self.assertEqual(
                resolution.reason_code,
                "CANONICAL_V3_SELECTOR_REPLAY_FAILED",
            )

    def test_malformed_v2_scientific_timeline_cannot_replace_custody(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/r-check-run/registry")
            ledger = EventLedger(root, "runs/r-check-run/events.jsonl")
            timeline = registry.put_json(
                {"schema_version": "scientific-confirmatory-timeline-receipt/v2"},
                logical_type="scientific_confirmatory_timeline_receipt_v2",
                origin="test-only forged independent custody timeline",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "test-r-check-timeline"),
                parent_artifacts=(),
                schema_version="2.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            ledger.record(
                run_id="r-check-run",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CALIBRATE,
                artifact_hashes=(),
                code_version=f"sha256:{_digest('timeline-code')}",
                configuration_hash=_digest("timeline-configuration"),
                reason="test-only forged timeline R-check",
            )
            resolution = resolve_scientific_r_check_sources(
                registry,
                ledger,
                run_id="r-check-run",
                r_check=RCheck.R3,
                evaluator_class=EvaluatorClass.E3,
                source_artifact_sha256s=(timeline.sha256,),
            )
            assert resolution is not None
            self.assertIs(resolution.status, AuthorityStatus.FAIL)
            self.assertEqual(
                resolution.reason_code,
                "SCIENTIFIC_CONFIRMATORY_TIMELINE_V2_REPLAY_FAILED",
            )

    def test_versioned_timeline_type_with_wrong_artifact_schema_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/r-check-run/registry")
            ledger = EventLedger(root, "runs/r-check-run/events.jsonl")
            timeline = registry.put_json(
                {"schema_version": "scientific-confirmatory-timeline-receipt/v1"},
                logical_type="scientific_confirmatory_timeline_receipt_v2",
                origin="test-only substituted timeline schema",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "test-r-check-timeline-schema"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            ledger.record(
                run_id="r-check-run",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CALIBRATE,
                artifact_hashes=(),
                code_version=f"sha256:{_digest('timeline-schema-code')}",
                configuration_hash=_digest("timeline-schema-configuration"),
                reason="test-only substituted timeline schema R-check",
            )
            resolution = resolve_scientific_r_check_sources(
                registry,
                ledger,
                run_id="r-check-run",
                r_check=RCheck.R3,
                evaluator_class=EvaluatorClass.E3,
                source_artifact_sha256s=(timeline.sha256,),
            )
            assert resolution is not None
            self.assertIs(resolution.status, AuthorityStatus.FAIL)
            self.assertEqual(
                resolution.reason_code,
                "SCIENTIFIC_CONFIRMATORY_TIMELINE_V2_REPLAY_FAILED",
            )

    def test_domain_v2_is_legacy_fallback_and_malformed_v3_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/r-check-run/registry")
            ledger = EventLedger(root, "runs/r-check-run/events.jsonl")
            ledger.record(
                run_id="r-check-run",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CALIBRATE,
                artifact_hashes=(),
                code_version=f"sha256:{_digest('domain-code')}",
                configuration_hash=_digest("domain-configuration"),
                reason="test-only domain R-check resolver boundary",
            )
            legacy = registry.put_json(
                {"schema_version": "domain-validity-receipt/v2", "legacy": True},
                logical_type="domain_validity.generic_ml",
                origin="test-only legacy domain receipt",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "test-legacy-domain-receipt"),
                parent_artifacts=(),
                schema_version="domain-validity-receipt/v2",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertIsNone(
                resolve_scientific_r_check_sources(
                    registry,
                    ledger,
                    run_id="r-check-run",
                    r_check=RCheck.R3,
                    evaluator_class=EvaluatorClass.E0,
                    source_artifact_sha256s=(legacy.sha256,),
                )
            )

            malformed = registry.put_json(
                {"schema_version": "domain-validity-receipt/v3", "malformed": True},
                logical_type="domain_validity.generic_ml",
                origin="test-only malformed v3 domain receipt",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "test-v3-domain-receipt"),
                parent_artifacts=(),
                schema_version="domain-validity-receipt/v3",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            result = resolve_scientific_r_check_sources(
                registry,
                ledger,
                run_id="r-check-run",
                r_check=RCheck.R3,
                evaluator_class=EvaluatorClass.E0,
                source_artifact_sha256s=(malformed.sha256,),
            )
            assert result is not None
            self.assertIs(result.status, AuthorityStatus.FAIL)
            self.assertEqual(
                result.reason_code,
                "PROJECTION_BACKED_DOMAIN_OWNER_REPLAY_FAILED",
            )

    def test_projection_backed_domain_blocker_remains_untested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(Path(directory), "state/registry")
            projection = registry.put_json(
                {"kind": "projection"},
                logical_type="generic_ml_paired_metric_projection_authority",
                origin="test-only domain projection",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "test-domain-projection"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            manifest = registry.put_json(
                {"kind": "manifest"},
                logical_type="domain_evidence_manifest.generic_ml",
                origin="test-only domain manifest",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "test-domain-manifest"),
                parent_artifacts=(projection.sha256,),
                schema_version="3.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            receipt = registry.put_json(
                {"kind": "receipt"},
                logical_type="domain_validity.generic_ml",
                origin="test-only domain receipt",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "test-domain-receipt"),
                parent_artifacts=(manifest.sha256,),
                schema_version="3.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            outcome = DomainValidityOutcome(
                domain=DomainKind.GENERIC_ML,
                adapter_version="test-only-v1",
                status=DomainValidityStatus.BLOCKED,
                checks=(
                    DomainCheck(
                        machine_code="ML_RESOURCE_COMPARABILITY",
                        status=DomainValidityStatus.BLOCKED,
                        message="test-only missing per-condition resources",
                        evidence_requirements=("per-condition resources",),
                    ),
                ),
            )
            resolved = SimpleNamespace(
                receipt_artifact_sha256=receipt.sha256,
                manifest_artifact_sha256=manifest.sha256,
                source_artifact_hashes=(projection.sha256,),
                run_id="r-check-run",
                domain=DomainKind.GENERIC_ML,
                object_id="domain-object",
                task_id="domain-task",
                scope=DomainEvidenceScope.SCIENTIFIC_EVIDENCE,
                limitations=(),
                evidence=object(),
                outcome=outcome,
                projection_artifact_sha256=projection.sha256,
            )
            with (
                patch(
                    "scientist_one.domains.resolve_domain_validity",
                    return_value=resolved,
                ),
                patch(
                    "scientist_one.domains.require_projection_backed_scientific_domain_validity"
                ) as require,
            ):
                result = _resolve_r3_e0_domain(
                    registry,
                    EventLedger(Path(directory), "runs/r-check-run/events.jsonl"),
                    run_id="r-check-run",
                    record=receipt,
                    payload={
                        "domain": DomainKind.GENERIC_ML.value,
                        "object_id": "domain-object",
                        "task_id": "domain-task",
                    },
                )
            self.assertIs(result.status, AuthorityStatus.UNTESTED)
            self.assertIs(result.scope, AuthorityScope.SCIENTIFIC)
            self.assertEqual(
                result.reason_code,
                "PROJECTION_BACKED_DOMAIN_VALIDITY_BLOCKED",
            )
            require.assert_not_called()

            self.assertEqual(
                _exact_route(RCheck.R3, EvaluatorClass.E0, (receipt,)),
                "R3_E0_DOMAIN",
            )
            self.assertIsNone(_exact_route(RCheck.R3, EvaluatorClass.E3, (receipt,)))

    def test_recognized_malformed_owner_is_fail_not_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/r-check-run/registry")
            ledger = EventLedger(root, "runs/r-check-run/events.jsonl")
            assessment = registry.put_json(
                {"malformed": "assessment"},
                logical_type="research_question_gate_assessment",
                origin="test-only malformed assessment",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "test-malformed-assessment"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            freeze = registry.put_json(
                {"malformed": "freeze"},
                logical_type="evaluation_contract_freeze_gate_receipt",
                origin="test-only malformed freeze",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "test-malformed-freeze"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            ledger.record(
                run_id="r-check-run",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CALIBRATE,
                artifact_hashes=(),
                code_version=f"sha256:{_digest('code')}",
                configuration_hash=_digest("configuration"),
                reason="test-only R-check resolver boundary",
            )
            result = resolve_scientific_r_check_sources(
                registry,
                ledger,
                run_id="r-check-run",
                r_check=RCheck.R1,
                evaluator_class=EvaluatorClass.E0,
                source_artifact_sha256s=(assessment.sha256, freeze.sha256),
            )
            assert result is not None
            self.assertIs(result.status, AuthorityStatus.FAIL)
            self.assertEqual(result.reason_code, "SCIENTIFIC_R1_OWNER_REPLAY_FAILED")

            extra = registry.put_json(
                {"kind": "extra"},
                logical_type="unrelated_scientific_input",
                origin="test-only unrelated input",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "test-unrelated-input"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertIsNone(
                resolve_scientific_r_check_sources(
                    registry,
                    ledger,
                    run_id="r-check-run",
                    r_check=RCheck.R1,
                    evaluator_class=EvaluatorClass.E0,
                    source_artifact_sha256s=(
                        assessment.sha256,
                        freeze.sha256,
                        extra.sha256,
                    ),
                )
            )


if __name__ == "__main__":
    unittest.main()
