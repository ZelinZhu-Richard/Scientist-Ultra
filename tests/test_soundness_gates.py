from __future__ import annotations

from dataclasses import fields, replace
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import scientist_one.gates as gates_module
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.claims import (
    ClaimDecision,
    ClaimEvidenceGraph,
    ClaimEvidenceUse,
    EvidenceKind,
    EvidenceLink,
    EvidenceNode,
    EvidenceSupportReceipt,
    MaterialClaim,
    REQUIRED_EVIDENCE_KINDS,
    artifact_registry_resolver,
)
from scientist_one.domains import (
    DomainEvidenceScope,
    DomainKind,
    DomainValidityStatus,
    MetricDirection,
    MetricScope,
    SystemsClaimScope,
    SystemsMeasurement,
    SystemsValidityEvidence,
    materialize_domain_validity,
    register_domain_evidence_source,
    register_domain_raw_fixture_source,
    resolve_domain_validity,
)
from scientist_one.errors import ValidationError
from scientist_one.external import (
    AUDITED_LIVE_TRANSPORT_AUTHORITY,
    EgressGateway,
    FixtureTransport,
    TransportResponse,
)
from scientist_one.experiments import (
    AcceleratorKind,
    CachePolicy,
    CheckpointPolicy,
    ComputeEscalationBudget,
    ComputeMode,
    ComputeProfile,
    EscalationDecision,
    EvidenceClass,
    ExperimentClass,
    ExperimentPhase,
    FrozenRunSpec,
    ResourceEstimate,
    SchedulerKind,
    ValidationStatus,
    make_gpu_cloud_submission_plan,
    register_compute_escalation_plan_authority,
    require_compute_escalation_plan_authority,
)
from scientist_one.gates import (
    ALTERNATIVE_EXPLANATIONS_AUTHORITY_LOGICAL_TYPE,
    AlternativeAttemptOutcome,
    AlternativeAttemptResult,
    AlternativeClaimScope,
    AlternativeExplanationsAuthority,
    AlternativeExplanationsPlan,
    AlternativeExplanationsStatus,
    AlternativeExperimentAuthorityBinding,
    AlternativeFalsificationAttempt,
    AlternativeFalsificationOperator,
    AlternativeFalsificationProjection,
    CompetingExplanation,
    AuthorizationOutcome,
    AutonomousDecisionRecord,
    ChallengeCategory,
    ChallengeFinding,
    ChallengeResolutionOutcome,
    ChallengeResolutionReceipt,
    ChallengeSeverity,
    ChallengeStatus,
    ChallengerAttackExecutionReceipt,
    ChallengerCategoryReview,
    ChallengerExecutionStatus,
    ChallengerExecutorKind,
    DimensionStatus,
    HumanGate,
    HumanGatePolicy,
    HumanGateProfile,
    JudgmentSubjectKind,
    MANDATORY_SOUNDNESS_DIMENSIONS,
    SemanticJudgmentReceipt,
    SoundnessAssessment,
    SoundnessAuthorityKind,
    SoundnessDimension,
    SoundnessDimensionEvidenceReceipt,
    SoundnessVerdict,
    assess_soundness,
    register_challenge_finding,
    register_challenge_resolution_receipt,
    register_challenger_attack_execution_receipt,
    register_challenger_category_review,
    register_scientific_soundness_assessment,
    register_semantic_judgment_receipt,
    register_soundness_dimension_receipt,
    require_scientific_semantic_judgment_receipt,
    require_alternative_explanations_authority,
    require_semantic_judgment_receipt,
    require_scientific_soundness_assessment,
)
from scientist_one.ledger import EventLedger
from scientist_one.research_state import RecordStatus, Run
from scientist_one.roles import Role
from scientist_one.providers import (
    ModelCapability,
    ModelInvocation,
    ModelRunStatus,
    OpenAIResponsesProvider,
    openai_responses_policy,
)
from scientist_one.provider_verification import require_provider_verifier
from scientist_one.security import canonical_json_bytes, safe_json_loads
from tests.provider_fixtures import deterministic_provider_result


class _CallerLabeledLiveFixtureTransport(FixtureTransport):
    """Adversarial protocol implementation claiming the built-in live labels."""

    network_used = True
    external_validation = "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"


class SoundnessGateAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.registry = ArtifactRegistry(
            Path(self.temporary.name), "runs/soundness-gates/registry"
        )
        self.ledger = EventLedger(
            Path(self.temporary.name), "runs/soundness-gates/events.jsonl"
        )
        self.graph_source = self._evidence("claim-graph-source")
        self.dimension_evidence = self._evidence("dimension-evidence")
        self.review_evidence = self._evidence("challenger-review-evidence")
        self.attack_evidence = self._evidence("challenger-attack-evidence")
        self.resolution_evidence = self._evidence("challenge-resolution-evidence")
        self.claim_ids = ("claim-central", "claim-secondary")
        self.graph = self._claim_graph("assessed-graph", self.claim_ids)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _evidence(
        self,
        label: str,
        *,
        logical_type: str = "soundness_gate_test_evidence",
        creator_role: Role = Role.EVIDENCE_CURATOR,
        parents: tuple[str, ...] = (),
        payload: dict[str, object] | None = None,
    ):
        return self.registry.put_json(
            payload or {"fixture": label},
            logical_type=logical_type,
            origin="focused soundness gate authority test",
            creator_role=creator_role,
            creation_command=("scientist-one", "test-soundness-gates", label),
            parent_artifacts=parents,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    @staticmethod
    def _compute_escalation_inputs():
        def digest(label: str) -> str:
            return hashlib.sha256(label.encode("utf-8")).hexdigest()

        source_profile = ComputeProfile(
            profile_id="soundness-local-pilot",
            mode=ComputeMode.LOCAL_MAC,
            accelerator=AcceleratorKind.CPU,
            scheduler=SchedulerKind.LOCAL,
            experiment_class=ExperimentClass.PILOT,
            cpu_cores=4,
            accelerator_count=0,
            memory_limit_bytes=8 * 1024**3,
            maximum_concurrency=4,
            minimum_batch_size=2,
            preferred_batch_size=16,
            maximum_batch_size=32,
            maximum_memory_fraction=0.5,
            validation_status=ValidationStatus.VALIDATED_LOCAL,
            hourly_cost=0.0,
        )
        target_profile = ComputeProfile(
            profile_id="soundness-gpu-plan",
            mode=ComputeMode.GPU_CLOUD,
            accelerator=AcceleratorKind.CUDA,
            scheduler=SchedulerKind.SLURM,
            experiment_class=ExperimentClass.EXPLORATORY,
            cpu_cores=8,
            accelerator_count=1,
            memory_limit_bytes=64 * 1024**3,
            maximum_concurrency=8,
            minimum_batch_size=8,
            preferred_batch_size=64,
            maximum_batch_size=256,
            accelerator_memory_limit_bytes=16 * 1024**3,
            disk_limit_bytes=64 * 1024**3,
            supports_checkpointing=True,
            supports_preemption=True,
            validation_status=ValidationStatus.UNTESTED,
            queue_name="research",
            hourly_cost=3.0,
        )
        local_estimate = ResourceEstimate(
            expected_scientific_value=2.0,
            expected_uncertainty_reduction=1.0,
            cpu_cores=4,
            gpu_count=0,
            ram_bytes=4 * 1024**3,
            vram_bytes=0,
            disk_bytes=1024**3,
            wall_clock_seconds=120.0,
            monetary_cost=0.0,
        )
        target_estimate = ResourceEstimate(
            expected_scientific_value=8.0,
            expected_uncertainty_reduction=4.0,
            cpu_cores=8,
            gpu_count=1,
            ram_bytes=32 * 1024**3,
            vram_bytes=12 * 1024**3,
            disk_bytes=4 * 1024**3,
            wall_clock_seconds=600.0,
            monetary_cost=2.5,
            escalation_reason=(
                "the local pilot cannot fit the frozen discriminating workload"
            ),
        )

        def spec(
            run_id: str,
            profile: ComputeProfile,
            estimate: ResourceEstimate,
            argv: tuple[str, ...],
        ) -> FrozenRunSpec:
            return FrozenRunSpec(
                run_id=run_id,
                experiment_id="experiment-soundness-compute",
                hypothesis_id="hypothesis-soundness-compute",
                phase=ExperimentPhase.EXPLORATORY,
                argv=argv,
                working_directory=".",
                code_sha256=digest("compute-code"),
                data_sha256=digest("compute-data"),
                configuration_sha256=digest("compute-configuration"),
                evaluator_sha256=digest("compute-evaluator"),
                seeds=(7, 11, 19),
                timeout_seconds=900.0,
                evidence_class=EvidenceClass.NON_EVIDENTIARY,
                scientific_purpose=(
                    "discriminate the frozen hypothesis using all planned seeds"
                ),
                expected_outputs=("output_manifest", "seed_results"),
                seed_policy="EXPLICIT_FIXED_SEEDS_NO_SELECTION",
                termination_conditions=(
                    "wall_clock_timeout",
                    "all_planned_seeds_reported",
                ),
                compute_profile=profile,
                resource_estimate=estimate,
                cache_policy=CachePolicy.CONTENT_ADDRESSABLE,
                checkpoint_policy=CheckpointPolicy.PER_SEED,
                bytes_per_sample=32 * 1024**2,
                worker_overhead_bytes=256 * 1024**2,
            )

        local = spec(
            "compute-local-pilot",
            source_profile,
            local_estimate,
            ("/usr/bin/true",),
        )
        cloud = spec(
            "compute-gpu-plan",
            target_profile,
            target_estimate,
            ("/opt/project/slurm-entrypoint",),
        )
        decision = EscalationDecision(
            decision_id="compute-escalation-decision",
            source_profile_sha256=source_profile.sha256,
            target_profile_sha256=target_profile.sha256,
            target_estimate_sha256=target_estimate.sha256,
            rationale=(
                "the bounded local pilot eliminated cheaper candidate configurations"
            ),
            scientific_equivalence_rationale=(
                "code data evaluator seeds and protocol remain exactly unchanged"
            ),
            expected_information_gain=4.0,
            lower_cost_alternatives_exhausted=True,
        )
        budget = ComputeEscalationBudget(
            budget_id="compute-escalation-budget",
            target_profile_sha256=target_profile.sha256,
            target_estimate_sha256=target_estimate.sha256,
            maximum_monetary_cost=3.0,
        )
        plan = make_gpu_cloud_submission_plan(local, cloud, decision, budget)
        return local, cloud, decision, plan, budget

    def _claim_graph(
        self,
        label: str,
        claim_ids: tuple[str, ...],
        *,
        evidence_use: ClaimEvidenceUse = ClaimEvidenceUse.NON_EVIDENTIARY,
    ):
        graph = ClaimEvidenceGraph()
        for claim_id in claim_ids:
            graph.add_claim(
                MaterialClaim(
                    claim_id=claim_id,
                    text=f"Material fixture claim {claim_id}.",
                    evidence_links=(),
                    producer_role=Role.HYPOTHESIS_DESIGNER,
                    confirmatory=False,
                    evidence_use=evidence_use,
                )
            )
            graph.verify_claim(claim_id, verifier_id="soundness-graph-verifier")
        return self.registry.put_json(
            {"fixture": label, "graph": graph.to_dict()},
            logical_type="claim_evidence_graph",
            origin="registry-resolved focused claim graph",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "test-soundness-claim-graph", label),
            parent_artifacts=(),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def _caller_authorized_confirmatory_graph(
        self,
        *,
        confirmatory: bool = True,
        omit_verification_parent: bool = False,
        wrong_verification_type: bool = False,
        wrong_verification_parents: bool = False,
    ):
        """Mint the legacy caller-boolean eligibility that gates must reject."""

        verifier_id = "forged-confirmatory-verifier"
        provisional: list[EvidenceNode] = []
        evidence_records = []
        for kind in sorted(REQUIRED_EVIDENCE_KINDS, key=lambda value: value.value):
            parents: tuple[str, ...] = ()
            if kind is EvidenceKind.FIGURE_OR_TABLE:
                table = self.registry.put_bytes(
                    b"metric,effect\nprimary,1.0\n",
                    logical_type="results_table",
                    origin="forged confirmatory graph fixture table",
                    creator_role=Role.PAPER_WRITER,
                    creation_command=(
                        "scientist-one",
                        "test-soundness-gates",
                        "confirmatory-table",
                    ),
                    schema_version="1.0",
                    mime_type="text/csv",
                    validation_result="PASS",
                    frozen=True,
                )
                parents = (table.sha256,)
            evidence = self._evidence(
                f"confirmatory-{kind.value}",
                logical_type=f"claim_evidence.{kind.value}",
                creator_role=Role.EVIDENCE_CURATOR,
                parents=parents,
                payload={"kind": kind.value, "bounded_fixture": True},
            )
            evidence_records.append(evidence)
            provisional.append(
                EvidenceNode(
                    evidence_id=f"confirmatory:{kind.value}",
                    kind=kind,
                    artifact_hash=evidence.sha256,
                    description=f"Bounded {kind.value} fixture evidence.",
                    verified=True,
                    frozen=True,
                    supports_claim=True,
                    contradicts_claim=False,
                    locally_verifiable=True,
                )
            )
        claim = MaterialClaim(
            claim_id="claim-confirmatory-forged",
            text="Caller asserts that the confirmatory result is eligible.",
            evidence_links=tuple(
                EvidenceLink(node.evidence_id, node.kind) for node in provisional
            ),
            producer_role=Role.HYPOTHESIS_DESIGNER,
            confirmatory=confirmatory,
            evidence_use=ClaimEvidenceUse.SCIENTIFIC,
        )
        nodes: list[EvidenceNode] = []
        support_records = []
        for node in provisional:
            support = EvidenceSupportReceipt.for_claim(
                claim,
                node,
                verifier_id=verifier_id,
                verification_result="PASS",
                supports_claim=True,
                contradicts_claim=False,
                locally_verifiable=True,
                rationale="The frozen fixture artifact matches this exact claim edge.",
            )
            support_record = self.registry.put_json(
                support.to_dict(),
                logical_type=f"claim_support_receipt.{node.kind.value}",
                origin="forged confirmatory graph support fixture",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=(
                    "scientist-one",
                    "test-soundness-gates",
                    "confirmatory-support",
                ),
                parent_artifacts=(node.artifact_hash,),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertEqual(support_record.sha256, support.sha256)
            support_records.append(support_record)
            nodes.append(replace(node, verification_receipt_hash=support_record.sha256))
        resolver = artifact_registry_resolver(
            self.registry,
            resolver_id="forged-confirmatory-registry",
        )
        graph = ClaimEvidenceGraph(evidence_resolver=resolver)
        for node in nodes:
            graph.add_evidence(node)
        graph.add_claim(claim)
        caller_decision = graph.verify_claim(
            claim.claim_id,
            verifier_id=verifier_id,
            confirmatory_evidence_valid=confirmatory,
        )
        self.assertIs(caller_decision.decision, ClaimDecision.ELIGIBLE)
        verification_records = []
        for index, node in enumerate(nodes):
            receipt = resolver(claim, node)
            verification = self.registry.put_bytes(
                receipt.canonical_bytes,
                logical_type=(
                    "claim_evidence_verification_receipt.wrong_kind"
                    if wrong_verification_type and index == 0
                    else f"claim_evidence_verification_receipt.{node.kind.value}"
                ),
                origin="materialized forged confirmatory graph resolver receipt",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=(
                    "scientist-one",
                    "test-soundness-gates",
                    "confirmatory-resolve",
                ),
                parent_artifacts=(
                    (node.artifact_hash,)
                    if wrong_verification_parents and index == 0
                    else (node.artifact_hash, receipt.support_receipt_hash)
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertEqual(verification.sha256, receipt.sha256)
            verification_records.append(verification)
        self.assertEqual(
            set(caller_decision.evidence_receipt_hashes),
            {record.sha256 for record in verification_records},
        )
        all_parent_records = (
            *evidence_records,
            *support_records,
            *verification_records,
        )
        if omit_verification_parent:
            all_parent_records = all_parent_records[:-1]
        return self.registry.put_json(
            {"fixture": "caller-confirmatory-boolean", "graph": graph.to_dict()},
            logical_type="claim_evidence_graph",
            origin="caller-authorized forged confirmatory claim graph",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=(
                "scientist-one",
                "test-soundness-gates",
                "confirmatory-graph",
            ),
            parent_artifacts=tuple(record.sha256 for record in all_parent_records),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def _semantic_judgment(
        self,
        *,
        label: str,
        subject_kind: JudgmentSubjectKind,
        subject_id: str,
        outcome: str,
        evidence_hashes: tuple[str, ...],
        context_hashes: tuple[str, ...],
        rationale: str,
        caller_labeled_live_transport: bool = False,
        expected_status: ModelRunStatus = ModelRunStatus.COMPLETED,
        instructions: str | None = None,
        prompt_template_id: str = "soundness-review",
        prompt_template_version: str = "1.0",
        deterministic_fixture: bool = False,
    ):
        exact_inputs = (*evidence_hashes, *context_hashes)
        instructions = instructions or (
            f"Review {subject_kind.value} using exact retained evidence."
        )
        judged_input = (
            f"subject_kind={subject_kind.value}\nsubject_id={subject_id}\n"
            + "\n".join(exact_inputs)
        )
        schema = {
            "type": "object",
            "properties": {
                name: {"type": "string", "maxLength": 8192}
                for name in ("subject_kind", "subject_id", "outcome", "rationale")
            },
            "required": ["subject_kind", "subject_id", "outcome", "rationale"],
            "additionalProperties": False,
        }
        invocation_id = f"semantic-{label}"
        structured = {
            "subject_kind": subject_kind.value,
            "subject_id": subject_id,
            "outcome": outcome,
            "rationale": rationale,
        }
        model = "gpt-5"
        envelope = {
            "id": f"response-{label}",
            "status": "completed",
            "model": model,
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": canonical_json_bytes(structured).decode("utf-8"),
                        }
                    ],
                }
            ],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 10,
                "total_tokens": 20,
            },
        }
        transport_type = (
            _CallerLabeledLiveFixtureTransport
            if caller_labeled_live_transport
            else FixtureTransport
        )
        transport = transport_type(
            (
                TransportResponse(
                    status_code=200,
                    headers=(("Content-Type", "application/json"),),
                    body=canonical_json_bytes(envelope),
                    effective_url="https://api.openai.com/v1/responses",
                ),
            )
        )
        gateway = EgressGateway(
            openai_responses_policy(maximum_attempts=1, maximum_requests=2),
            transport,
            registry=self.registry,
            secret_resolver=lambda _name: "focused-fixture-credential",
            sleeper=lambda _delay: None,
            timestamp=lambda: "2026-08-29T12:00:00.000000Z",
        )
        prompt_hash = hashlib.sha256(instructions.encode("utf-8")).hexdigest()
        result = OpenAIResponsesProvider(gateway).invoke(
            ModelInvocation(
                invocation_id=invocation_id,
                capability=ModelCapability.RESEARCH_SYNTHESIS,
                model=model,
                prompt_template_id=prompt_template_id,
                prompt_template_version=prompt_template_version,
                prompt_template_hash=prompt_hash,
                instructions=instructions,
                input_text=judged_input,
                output_schema=schema,
                input_artifact_hashes=exact_inputs,
                max_output_tokens=512,
            )
        )
        if deterministic_fixture and result.status is ModelRunStatus.COMPLETED:
            result = deterministic_provider_result(self.registry, result)
        self.assertIs(result.status, expected_status)
        if result.status is not ModelRunStatus.COMPLETED:
            return result, None
        records = {record.logical_type: record for record in result.artifacts}
        required = {
            "model_judged_instructions",
            "model_judged_input",
            "model_output_schema",
            "model_invocation",
            "model_provider_request_intent",
            "model_provider_response",
            "model_output",
            "external_request",
            "external_response_receipt",
        }
        self.assertTrue(required.issubset(records))
        provider_contract = require_provider_verifier(
            result.provider_id,
            records["model_invocation"].schema_version,
        )
        receipt = SemanticJudgmentReceipt(
            judgment_id=f"judgment-{label}",
            subject_kind=subject_kind,
            subject_id=subject_id,
            outcome=outcome,
            evidence_hashes=evidence_hashes,
            context_hashes=context_hashes,
            instructions_artifact_hash=records["model_judged_instructions"].sha256,
            input_artifact_hash=records["model_judged_input"].sha256,
            output_schema_artifact_hash=records["model_output_schema"].sha256,
            invocation_artifact_hash=records["model_invocation"].sha256,
            request_intent_artifact_hash=records[
                "model_provider_request_intent"
            ].sha256,
            provider_response_artifact_hash=records["model_provider_response"].sha256,
            model_output_artifact_hash=records["model_output"].sha256,
            invocation_id=invocation_id,
            provider_id=provider_contract.provider_id,
            provider_version=provider_contract.provider_version,
            model=model,
            model_version=model,
            prompt_template_id=prompt_template_id,
            prompt_template_version=prompt_template_version,
            prompt_template_hash=prompt_hash,
            structured_output_sha256=hashlib.sha256(
                canonical_json_bytes(structured)
            ).hexdigest(),
            reviewer_id="scientific-reviewer",
            reviewer_role=Role.SCIENTIFIC_REVIEWER,
            governing_rule="Exact captured semantic judgment is advisory reviewer evidence.",
            rationale=rationale,
        )
        return receipt, register_semantic_judgment_receipt(self.registry, receipt)

    def _dimension_record(
        self, dimension: SoundnessDimension, status: DimensionStatus
    ) -> str:
        kind = SoundnessAuthorityKind.NOT_EXECUTED
        authority = None
        evidence = (self.dimension_evidence.sha256,)
        if status is DimensionStatus.FAIL:
            self.assertEqual(dimension, SoundnessDimension.LIMITATIONS)
            _, semantic = self._semantic_judgment(
                label="limitations-fail",
                subject_kind=JudgmentSubjectKind.SOUNDNESS_DIMENSION,
                subject_id=dimension.value,
                outcome=status.value,
                evidence_hashes=evidence,
                context_hashes=(self.graph.sha256,),
                rationale="The exact graph omits a complete limitations treatment.",
            )
            kind = SoundnessAuthorityKind.SEMANTIC
            authority = semantic.sha256
        receipt = SoundnessDimensionEvidenceReceipt(
            receipt_id=(
                f"dimension-{dimension.value.lower().replace('_', '-')}-"
                f"{status.value.lower()}"
            ),
            dimension=dimension,
            status=status,
            authority_kind=kind,
            authority_artifact_hash=authority,
            evidence_hashes=evidence,
            governing_rule="Apply the closed mandatory Section 22 dimension rule.",
            rationale="Unsupported science remains incomplete; failure is content-bound.",
            reviewer_id="scientific-reviewer",
        )
        return register_soundness_dimension_receipt(self.registry, receipt).sha256

    def _non_evidentiary_systems_domain_receipt(self):
        run_id = "run-soundness-domain-fixture"
        object_id = "systems-domain-fixture"
        task_id = "systems-task-fixture"
        raw = register_domain_raw_fixture_source(
            self.registry,
            run_id=run_id,
            domain=DomainKind.SYSTEMS,
            object_id=object_id,
            task_id=task_id,
            source_id="systems-observations",
            creator_role=Role.EXPERIMENT_RUNNER,
            payload={"measurements": "bounded technical fixture"},
        )
        evidence = SystemsValidityEvidence(
            measurements=(
                SystemsMeasurement(
                    "latency_ms",
                    MetricScope.END_TO_END,
                    MetricDirection.LOWER_IS_BETTER,
                    (9.9, 10.0, 10.1),
                    (11.9, 12.0, 12.1),
                    True,
                ),
            ),
            claim_scope=SystemsClaimScope.SYSTEM_LEVEL,
            hardware_identity="host-cpu-v1",
            os_kernel_stack="os-kernel-v1",
            software_stack="runtime-v1",
            workload_manifest="workload-v1",
            workload_validated=True,
            warmup_completed=True,
            resource_isolation_verified=True,
            concurrency_documented=True,
            hardware_equivalent=True,
            runtime_environment_equivalent=True,
            tail_latency_reported=True,
            memory_reported=True,
            energy_relevant=True,
            energy_reported=True,
            evaluator_frozen_before_results=True,
            evaluator_observable_to_candidate=False,
            evaluator_specific_branching_detected=False,
        )
        source = register_domain_evidence_source(
            self.registry,
            run_id=run_id,
            domain=DomainKind.SYSTEMS,
            object_id=object_id,
            task_id=task_id,
            evidence=evidence,
            supporting_artifact_hashes=(raw.sha256,),
        )
        receipt = materialize_domain_validity(
            self.registry,
            source_artifact_sha256=source.sha256,
            expected_run_id=run_id,
            expected_domain=DomainKind.SYSTEMS,
            expected_object_id=object_id,
            expected_task_id=task_id,
        )
        resolved = resolve_domain_validity(
            self.registry,
            receipt.sha256,
            expected_run_id=run_id,
            expected_domain=DomainKind.SYSTEMS,
            expected_object_id=object_id,
            expected_task_id=task_id,
        )
        self.assertIs(resolved.outcome.status, DomainValidityStatus.PASS)
        self.assertIs(resolved.scope, DomainEvidenceScope.NON_EVIDENTIARY_FIXTURE)
        return receipt, (
            resolved.manifest_artifact_sha256,
            *resolved.source_artifact_hashes,
        )

    def _dimension_records(
        self,
        overrides: dict[SoundnessDimension, DimensionStatus] | None = None,
    ) -> tuple[str, ...]:
        overrides = overrides or {}
        return tuple(
            self._dimension_record(
                dimension, overrides.get(dimension, DimensionStatus.UNTESTED)
            )
            for dimension in SoundnessDimension
        )

    def _review_records(
        self,
        *,
        graph_hash: str | None = None,
        target_overrides: dict[ChallengeCategory, tuple[str, ...]] | None = None,
        finding_hashes: dict[ChallengeCategory, tuple[str, ...]] | None = None,
        prefix: str = "review",
    ) -> tuple[str, ...]:
        graph_hash = graph_hash or self.graph.sha256
        target_overrides = target_overrides or {}
        finding_hashes = finding_hashes or {}
        return tuple(
            register_challenger_category_review(
                self.registry,
                ChallengerCategoryReview(
                    review_id=f"{prefix}-{category.value.lower().replace('_', '-')}",
                    category=category,
                    execution_status=ChallengerExecutionStatus.UNTESTED,
                    target_claim_ids=target_overrides.get(category, self.claim_ids),
                    claim_graph_artifact_hash=graph_hash,
                    evidence_hashes=(self.review_evidence.sha256,),
                    finding_artifact_hashes=finding_hashes.get(category, ()),
                    execution_receipt_hash=None,
                    attack=f"Attempt the exact {category.value} Challenger attack.",
                    conclusion="No authentic category execution authority is available.",
                    deterministic=False,
                ),
            ).sha256
            for category in ChallengeCategory
        )

    def _assessment(
        self,
        assessment_id: str,
        *,
        dimension_overrides: dict[SoundnessDimension, DimensionStatus] | None = None,
        review_hashes: tuple[str, ...] | None = None,
        graph_hash: str | None = None,
        central_claim_ids: tuple[str, ...] | None = None,
        ledger: EventLedger | None = None,
        run_id: str | None = None,
        confirmatory_claim_authority_hashes: tuple[str, ...] = (),
    ) -> SoundnessAssessment:
        return assess_soundness(
            self.registry,
            assessment_id,
            self._dimension_records(dimension_overrides),
            review_hashes or self._review_records(prefix=assessment_id),
            claim_graph_artifact_hash=graph_hash or self.graph.sha256,
            central_claim_ids=central_claim_ids or self.claim_ids,
            reason="Registry-resolved focused soundness assessment.",
            ledger=ledger,
            run_id=run_id,
            confirmatory_claim_authority_hashes=(confirmatory_claim_authority_hashes),
        )

    def _finding(
        self,
        *,
        challenge_id: str = "challenge-seed",
        category: ChallengeCategory = ChallengeCategory.SEED_DEPENDENCE,
        severity: ChallengeSeverity = ChallengeSeverity.MAJOR,
        status: ChallengeStatus = ChallengeStatus.UNRESOLVED,
        target_claim_ids: tuple[str, ...] = ("claim-central",),
        graph_hash: str | None = None,
        attack: str = "Attempt to reproduce the effect across independent seeds.",
        resolution: str | None = None,
        resolution_receipt_hash: str | None = None,
        evidence_hashes: tuple[str, ...] | None = None,
    ) -> ChallengeFinding:
        return ChallengeFinding(
            challenge_id=challenge_id,
            category=category,
            severity=severity,
            status=status,
            target_claim_ids=target_claim_ids,
            claim_graph_artifact_hash=graph_hash or self.graph.sha256,
            evidence_hashes=evidence_hashes or (self.attack_evidence.sha256,),
            attack=attack,
            resolution=resolution,
            resolution_receipt_hash=resolution_receipt_hash,
            deterministic=True,
        )

    def _resolution(
        self,
        finding: ChallengeFinding,
        *,
        receipt_id: str = "resolution-seed",
    ) -> ChallengeResolutionReceipt:
        return ChallengeResolutionReceipt.for_finding(
            finding,
            receipt_id=receipt_id,
            resolution_evidence_hashes=(self.resolution_evidence.sha256,),
            governing_rule="Resolution requires evidence independent of attack evidence.",
            outcome=ChallengeResolutionOutcome.VERIFIED_RESOLVED,
            resolution="Independent reruns falsified the exact attack.",
        )

    def _external_execution(self, review_id: str = "review-external-validity"):
        run_id = "run-soundness-domain-fixture"
        source_snapshot = self._evidence(
            f"source-{review_id}",
            logical_type="vnext_source_snapshot",
            creator_role=Role.ORCHESTRATOR,
        )
        experiment_code = self._evidence(
            f"code-{review_id}",
            logical_type="experiment_code",
            creator_role=Role.IMPLEMENTER,
            parents=(source_snapshot.sha256,),
        )
        frozen_spec = self._evidence(
            f"spec-{review_id}",
            logical_type="frozen_run_spec",
            creator_role=Role.EXPERIMENT_RUNNER,
            parents=(experiment_code.sha256,),
            payload={
                "run_id": f"experiment-{review_id}",
                "code_sha256": experiment_code.sha256,
            },
        )
        environment = self._evidence(
            f"environment-{review_id}",
            logical_type="execution_environment",
            creator_role=Role.EXPERIMENT_RUNNER,
            parents=(source_snapshot.sha256,),
            payload={
                "run_id": run_id,
                "scientific_evidence_eligible": False,
                "os_enforced_network_sandbox": "UNAVAILABLE",
            },
        )
        gpu = self._evidence(
            f"gpu-{review_id}",
            logical_type="gpu_cloud_boundary_status",
            creator_role=Role.EXPERIMENT_RUNNER,
            parents=(frozen_spec.sha256,),
            payload={
                "run_id": run_id,
                "experiment_run_id": f"experiment-{review_id}",
                "frozen_run_spec_sha256": frozen_spec.sha256,
                "scientific_evidence": False,
                "network_used": False,
                "external_validation": "UNTESTED",
                "validation_status": "UNTESTED",
            },
        )
        domain, _domain_evidence = self._non_evidentiary_systems_domain_receipt()
        boundary_hashes = (environment.sha256, gpu.sha256, domain.sha256)
        finding = self._finding(
            challenge_id=f"finding-{review_id}",
            category=ChallengeCategory.EXTERNAL_VALIDITY,
            target_claim_ids=self.claim_ids,
            attack="External validity is absent at every exact execution boundary.",
            evidence_hashes=boundary_hashes,
        )
        finding_record = register_challenge_finding(self.registry, finding)
        receipt = ChallengerAttackExecutionReceipt(
            receipt_id=f"execution-{review_id}",
            review_id=review_id,
            run_id=run_id,
            category=ChallengeCategory.EXTERNAL_VALIDITY,
            claim_graph_artifact_hash=self.graph.sha256,
            target_claim_ids=self.claim_ids,
            evidence_hashes=boundary_hashes,
            executor_kind=ChallengerExecutorKind.DETERMINISTIC,
            executor_id="external-validity-challenger",
            executor_role=Role.ADVERSARIAL_REVIEWER,
            procedure_id="external-validity-boundary-audit",
            procedure_version="1.0",
            result_artifact_hashes=(),
            finding_artifact_hashes=(finding_record.sha256,),
            completed=True,
        )
        return receipt, finding_record

    def _pinned_semantic_execution(
        self,
        *,
        label: str,
        category: ChallengeCategory = ChallengeCategory.OVERCLAIMING,
        run_id: str = "run-semantic-challenger",
        evidence_hashes: tuple[str, ...] | None = None,
    ):
        evidence_hashes = evidence_hashes or (self.review_evidence.sha256,)
        contract = next(
            value
            for key, value in gates_module.CHALLENGER_ATTACK_RESOLVER_CONTRACTS.items()
            if key[0] is category and key[1] is ChallengerExecutorKind.SEMANTIC
        )
        finding = self._finding(
            challenge_id=f"finding-{label}",
            category=category,
            target_claim_ids=self.claim_ids,
            attack=f"Retain the unresolved {category.value} attack.",
        )
        finding_record = register_challenge_finding(self.registry, finding)
        judgment, judgment_record = self._semantic_judgment(
            label=label,
            subject_kind=JudgmentSubjectKind.CHALLENGER_CATEGORY,
            subject_id=category.value,
            outcome=ChallengerExecutionStatus.EXECUTED.value,
            evidence_hashes=evidence_hashes,
            context_hashes=(self.graph.sha256, finding_record.sha256),
            rationale="The exact category procedure ran; findings remain independent.",
            instructions=gates_module.challenger_semantic_procedure_instructions(
                category
            ),
            prompt_template_id=contract.procedure_id,
            prompt_template_version=contract.procedure_version,
        )
        assert judgment is not None and judgment_record is not None
        receipt = ChallengerAttackExecutionReceipt(
            receipt_id=f"execution-{label}",
            review_id=f"review-{label}",
            run_id=run_id,
            category=category,
            claim_graph_artifact_hash=self.graph.sha256,
            target_claim_ids=self.claim_ids,
            evidence_hashes=evidence_hashes,
            executor_kind=ChallengerExecutorKind.SEMANTIC,
            executor_id=f"semantic-{category.value.lower().replace('_', '-')}",
            executor_role=Role.ADVERSARIAL_REVIEWER,
            procedure_id=contract.procedure_id,
            procedure_version=contract.procedure_version,
            result_artifact_hashes=(),
            finding_artifact_hashes=(finding_record.sha256,),
            completed=True,
            semantic_judgment_hash=judgment_record.sha256,
        )
        return receipt, finding_record, judgment

    @staticmethod
    def _forge_assessment(valid: SoundnessAssessment, **overrides: object):
        values = {item.name: getattr(valid, item.name) for item in fields(valid)}
        values.update(overrides)
        return SoundnessAssessment._from_verified_authority(**values)

    def test_exact_mandatory_dimension_and_challenger_sets_are_closed(self) -> None:
        self.assertEqual(MANDATORY_SOUNDNESS_DIMENSIONS, frozenset(SoundnessDimension))
        self.assertEqual(len(MANDATORY_SOUNDNESS_DIMENSIONS), 15)
        self.assertEqual(len(tuple(ChallengeCategory)), 14)

    def test_source_owned_resolver_contract_maps_are_closed_and_immutable(self) -> None:
        dimension_keys = gates_module.SOUNDNESS_DIMENSION_RESOLVER_CONTRACTS
        supported_dimensions = {dimension for dimension, _ in dimension_keys}
        self.assertEqual(
            supported_dimensions,
            set(SoundnessDimension)
            - {
                SoundnessDimension.TECHNICAL_CORRECTNESS,
                SoundnessDimension.ROBUSTNESS,
                SoundnessDimension.END_TO_END_EVIDENCE,
            },
        )
        challenger_keys = gates_module.CHALLENGER_ATTACK_RESOLVER_CONTRACTS
        self.assertEqual(len(challenger_keys), 14)
        self.assertEqual(
            {key[0] for key in challenger_keys},
            set(ChallengeCategory),
        )
        self.assertEqual(
            sum(
                key[1] is ChallengerExecutorKind.DETERMINISTIC
                for key in challenger_keys
            ),
            2,
        )
        self.assertEqual(
            sum(key[1] is ChallengerExecutorKind.SEMANTIC for key in challenger_keys),
            12,
        )
        with self.assertRaises(TypeError):
            challenger_keys[next(iter(challenger_keys))] = next(  # type: ignore[index]
                iter(challenger_keys.values())
            )
        with self.assertRaises(TypeError):
            dimension_keys[next(iter(dimension_keys))] = next(  # type: ignore[index]
                iter(dimension_keys.values())
            )

    def test_canonical_statistical_test_resolver_can_grant_mechanical_pass(
        self,
    ) -> None:
        authority = self._evidence(
            "canonical-statistical-test",
            logical_type="research_state.statistical_test",
            creator_role=Role.STATISTICIAN,
            parents=(self.dimension_evidence.sha256,),
        )
        binding = SimpleNamespace(
            research_object=SimpleNamespace(object_type="StatisticalTest"),
            scientific_evidence_eligible=True,
        )
        scope = SimpleNamespace(
            binding_for_artifact=lambda digest: (
                binding if digest == authority.sha256 else None
            )
        )
        with patch(
            "scientist_one.research_state.resolve_current_research_state_bindings",
            return_value=scope,
        ) as owner:
            persisted = register_soundness_dimension_receipt(
                self.registry,
                SoundnessDimensionEvidenceReceipt(
                    receipt_id="statistics-owner-pass",
                    dimension=SoundnessDimension.STATISTICS,
                    status=DimensionStatus.PASS,
                    authority_kind=SoundnessAuthorityKind.DETERMINISTIC,
                    authority_artifact_hash=authority.sha256,
                    evidence_hashes=(self.dimension_evidence.sha256,),
                    governing_rule="Replay the exact current canonical StatisticalTest.",
                    rationale="The source owner reports scientific eligibility.",
                    reviewer_id="scientific-reviewer",
                ),
                ledger=self.ledger,
                run_id="run-statistics-owner",
            )
        self.assertTrue(self.registry.verify(persisted.sha256))
        owner.assert_called_once_with(
            self.registry,
            self.ledger,
            run_id="run-statistics-owner",
            state_artifact_hashes=(authority.sha256,),
        )

    def test_dimension_resolver_rejects_status_evidence_and_unknown_splices(
        self,
    ) -> None:
        authority = self._evidence(
            "canonical-statistical-test-mismatch",
            logical_type="research_state.statistical_test",
            creator_role=Role.STATISTICIAN,
            parents=(self.dimension_evidence.sha256,),
        )
        binding = SimpleNamespace(
            research_object=SimpleNamespace(object_type="StatisticalTest"),
            scientific_evidence_eligible=True,
        )
        scope = SimpleNamespace(binding_for_artifact=lambda _digest: binding)
        base = dict(
            dimension=SoundnessDimension.STATISTICS,
            authority_kind=SoundnessAuthorityKind.DETERMINISTIC,
            authority_artifact_hash=authority.sha256,
            governing_rule="Resolve the exact canonical statistics authority.",
            rationale="Reject caller status and evidence substitutions.",
            reviewer_id="scientific-reviewer",
        )
        with patch(
            "scientist_one.research_state.resolve_current_research_state_bindings",
            return_value=scope,
        ):
            with self.assertRaisesRegex(ValidationError, "status differs"):
                register_soundness_dimension_receipt(
                    self.registry,
                    SoundnessDimensionEvidenceReceipt(
                        receipt_id="statistics-status-mismatch",
                        status=DimensionStatus.UNTESTED,
                        evidence_hashes=(self.dimension_evidence.sha256,),
                        **base,
                    ),
                    ledger=self.ledger,
                    run_id="run-statistics-owner",
                )
            with self.assertRaisesRegex(
                ValidationError, "mismatched status or evidence"
            ):
                register_soundness_dimension_receipt(
                    self.registry,
                    SoundnessDimensionEvidenceReceipt(
                        receipt_id="statistics-evidence-splice",
                        status=DimensionStatus.PASS,
                        evidence_hashes=(self.attack_evidence.sha256,),
                        **base,
                    ),
                    ledger=self.ledger,
                    run_id="run-statistics-owner",
                )

        unknown = self._evidence(
            "unknown-statistics-resolver",
            logical_type="caller_labeled_statistical_authority",
            creator_role=Role.STATISTICIAN,
            parents=(self.dimension_evidence.sha256,),
        )
        with self.assertRaisesRegex(ValidationError, "no source-owned replay resolver"):
            register_soundness_dimension_receipt(
                self.registry,
                SoundnessDimensionEvidenceReceipt(
                    receipt_id="statistics-unknown-resolver",
                    dimension=SoundnessDimension.STATISTICS,
                    status=DimensionStatus.PASS,
                    authority_kind=SoundnessAuthorityKind.DETERMINISTIC,
                    authority_artifact_hash=unknown.sha256,
                    evidence_hashes=(self.dimension_evidence.sha256,),
                    governing_rule="Role labels do not grant statistics authority.",
                    rationale="The logical type is not in the closed map.",
                    reviewer_id="scientific-reviewer",
                ),
                ledger=self.ledger,
                run_id="run-statistics-owner",
            )

    def test_dimension_owner_replay_rejects_stale_and_cross_run_authority(self) -> None:
        authority = self._evidence(
            "canonical-statistical-test-live-replay",
            logical_type="research_state.statistical_test",
            creator_role=Role.STATISTICIAN,
            parents=(self.dimension_evidence.sha256,),
        )
        binding = SimpleNamespace(
            research_object=SimpleNamespace(object_type="StatisticalTest"),
            scientific_evidence_eligible=True,
        )
        scope = SimpleNamespace(binding_for_artifact=lambda _digest: binding)
        receipt = SoundnessDimensionEvidenceReceipt(
            receipt_id="statistics-live-replay",
            dimension=SoundnessDimension.STATISTICS,
            status=DimensionStatus.PASS,
            authority_kind=SoundnessAuthorityKind.DETERMINISTIC,
            authority_artifact_hash=authority.sha256,
            evidence_hashes=(self.dimension_evidence.sha256,),
            governing_rule="Reopen current same-run canonical state on every use.",
            rationale="Stale and cross-run bindings must fail closed.",
            reviewer_id="scientific-reviewer",
        )
        with patch(
            "scientist_one.research_state.resolve_current_research_state_bindings",
            return_value=scope,
        ):
            persisted = register_soundness_dimension_receipt(
                self.registry,
                receipt,
                ledger=self.ledger,
                run_id="run-statistics-owner",
            )
        for run_id, message in (
            ("run-statistics-owner", "superseded canonical StatisticalTest"),
            ("run-other", "canonical StatisticalTest names another run"),
        ):
            with (
                self.subTest(run_id=run_id),
                patch(
                    "scientist_one.research_state.resolve_current_research_state_bindings",
                    side_effect=ValidationError(message),
                ),
                self.assertRaisesRegex(ValidationError, message),
            ):
                gates_module._load_soundness_dimension_receipt(
                    self.registry,
                    persisted.sha256,
                    ledger=self.ledger,
                    run_id=run_id,
                )

    def test_honest_conservative_assessment_requires_more_experiments(self) -> None:
        result = self._assessment("honest-conservative")
        self.assertEqual(result.verdict, SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED)
        self.assertTrue(
            all(status is DimensionStatus.UNTESTED for _, status in result.dimensions)
        )
        self.assertTrue(
            all(
                review.execution_status is ChallengerExecutionStatus.UNTESTED
                for review in result.challenger_reviews
            )
        )

    def test_all_not_applicable_requires_more_experiments(self) -> None:
        result = self._assessment(
            "all-na",
            dimension_overrides={
                dimension: DimensionStatus.NOT_APPLICABLE
                for dimension in SoundnessDimension
            },
        )
        self.assertEqual(result.verdict, SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED)

    def test_one_not_applicable_requires_more_experiments(self) -> None:
        result = self._assessment(
            "one-na",
            dimension_overrides={
                SoundnessDimension.ROBUSTNESS: DimensionStatus.NOT_APPLICABLE
            },
        )
        self.assertEqual(result.verdict, SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED)

    def test_fail_precedes_mixed_not_applicable_and_untested(self) -> None:
        result = self._assessment(
            "mixed-na-fail-untested",
            dimension_overrides={
                SoundnessDimension.ROBUSTNESS: DimensionStatus.NOT_APPLICABLE,
                SoundnessDimension.LIMITATIONS: DimensionStatus.FAIL,
                SoundnessDimension.GENERALIZATION: DimensionStatus.UNTESTED,
            },
        )
        self.assertEqual(result.verdict, SoundnessVerdict.MAJOR_REVISION)

    def test_dimension_receipt_is_canonical_and_na_survives_readback(self) -> None:
        digest = self._dimension_record(
            SoundnessDimension.ROBUSTNESS, DimensionStatus.NOT_APPLICABLE
        )
        restored = SoundnessDimensionEvidenceReceipt.from_dict(
            safe_json_loads(self.registry.get_bytes(digest))
        )
        self.assertEqual(restored.status, DimensionStatus.NOT_APPLICABLE)
        self.assertEqual(
            self.registry.get_bytes(digest),
            canonical_json_bytes(restored.to_dict()) + b"\n",
        )

    def test_assessment_serialization_is_canonical_and_complete(self) -> None:
        assessment = self._assessment("canonical-assessment")
        serialized = assessment.to_dict()
        self.assertEqual(len(serialized["dimensions"]), 15)
        self.assertEqual(len(serialized["challenger_reviews"]), 14)
        self.assertEqual(
            hashlib.sha256(canonical_json_bytes(serialized)).hexdigest(),
            hashlib.sha256(canonical_json_bytes(assessment.to_dict())).hexdigest(),
        )

    def test_nonconfirmatory_soundness_may_bind_run_for_other_live_authorities(
        self,
    ) -> None:
        assessment = self._assessment(
            "run-bound-nonconfirmatory",
            ledger=self.ledger,
            run_id="run-bound-nonconfirmatory",
        )
        self.assertEqual(assessment.run_id, "run-bound-nonconfirmatory")
        self.assertEqual(assessment.confirmatory_claim_authority_hashes, ())
        self.assertEqual(
            assessment.verdict,
            SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED,
        )

    def test_forged_pass_and_conditional_pass_over_incomplete_reject(self) -> None:
        valid = self._assessment("valid-incomplete")
        for verdict in (SoundnessVerdict.PASS, SoundnessVerdict.CONDITIONAL_PASS):
            with self.subTest(verdict=verdict), self.assertRaises(ValidationError):
                self._forge_assessment(valid, verdict=verdict)

    def test_unsupported_deterministic_and_domain_authority_reject(self) -> None:
        domain = self._evidence(
            "forged-domain-pass",
            logical_type="domain_validity.generic_ml",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            parents=(self.graph_source.sha256,),
            payload={"status": "PASS"},
        )
        with self.assertRaises(ValidationError):
            register_soundness_dimension_receipt(
                self.registry,
                SoundnessDimensionEvidenceReceipt(
                    receipt_id="forged-domain-dimension",
                    dimension=SoundnessDimension.DATASET_VALIDITY,
                    status=DimensionStatus.PASS,
                    authority_kind=SoundnessAuthorityKind.DETERMINISTIC,
                    authority_artifact_hash=domain.sha256,
                    evidence_hashes=(self.dimension_evidence.sha256,),
                    governing_rule="A domain label is not replay authority.",
                    rationale="This must fail closed.",
                    reviewer_id="scientific-reviewer",
                ),
            )

    def test_replayed_non_evidentiary_domain_is_untested_never_pass(self) -> None:
        authority, evidence_hashes = self._non_evidentiary_systems_domain_receipt()
        for dimension in (
            SoundnessDimension.DATASET_VALIDITY,
            SoundnessDimension.GENERALIZATION,
        ):
            with self.subTest(dimension=dimension):
                persisted = register_soundness_dimension_receipt(
                    self.registry,
                    SoundnessDimensionEvidenceReceipt(
                        receipt_id=(
                            "fixture-domain-"
                            f"{dimension.value.lower().replace('_', '-')}"
                        ),
                        dimension=dimension,
                        status=DimensionStatus.UNTESTED,
                        authority_kind=SoundnessAuthorityKind.DETERMINISTIC,
                        authority_artifact_hash=authority.sha256,
                        evidence_hashes=evidence_hashes,
                        governing_rule=(
                            "Replay the exact domain source while preserving its "
                            "non-evidentiary scope."
                        ),
                        rationale=(
                            "A passing technical adapter fixture is not scientific "
                            "dataset or generalization evidence."
                        ),
                        reviewer_id="scientific-reviewer",
                    ),
                )
                self.assertTrue(self.registry.verify(persisted.sha256))
                with self.assertRaises(ValidationError):
                    register_soundness_dimension_receipt(
                        self.registry,
                        SoundnessDimensionEvidenceReceipt(
                            receipt_id=(
                                "laundered-domain-"
                                f"{dimension.value.lower().replace('_', '-')}"
                            ),
                            dimension=dimension,
                            status=DimensionStatus.PASS,
                            authority_kind=SoundnessAuthorityKind.DETERMINISTIC,
                            authority_artifact_hash=authority.sha256,
                            evidence_hashes=evidence_hashes,
                            governing_rule="Fixture scope cannot grant PASS.",
                            rationale="Reject adapter-label laundering.",
                            reviewer_id="scientific-reviewer",
                        ),
                    )

        with self.assertRaises(ValidationError):
            register_soundness_dimension_receipt(
                self.registry,
                SoundnessDimensionEvidenceReceipt(
                    receipt_id="cross-run-domain-dimension",
                    dimension=SoundnessDimension.DATASET_VALIDITY,
                    status=DimensionStatus.UNTESTED,
                    authority_kind=SoundnessAuthorityKind.DETERMINISTIC,
                    authority_artifact_hash=authority.sha256,
                    evidence_hashes=evidence_hashes,
                    governing_rule="Domain authority must belong to this exact run.",
                    rationale="Reject a freshly replayable authority from another run.",
                    reviewer_id="scientific-reviewer",
                ),
                run_id="run-other-soundness-assessment",
            )

    def test_semantic_authority_cannot_replace_deterministic_dimension(self) -> None:
        _, judgment = self._semantic_judgment(
            label="statistics-pass",
            subject_kind=JudgmentSubjectKind.SOUNDNESS_DIMENSION,
            subject_id=SoundnessDimension.STATISTICS.value,
            outcome=DimensionStatus.PASS.value,
            evidence_hashes=(self.dimension_evidence.sha256,),
            context_hashes=(self.graph.sha256,),
            rationale="A model cannot replace deterministic statistics.",
        )
        with self.assertRaises(ValidationError):
            register_soundness_dimension_receipt(
                self.registry,
                SoundnessDimensionEvidenceReceipt(
                    receipt_id="semantic-statistics-pass",
                    dimension=SoundnessDimension.STATISTICS,
                    status=DimensionStatus.PASS,
                    authority_kind=SoundnessAuthorityKind.SEMANTIC,
                    authority_artifact_hash=judgment.sha256,
                    evidence_hashes=(self.dimension_evidence.sha256,),
                    governing_rule="Statistics requires deterministic replay.",
                    rationale="Reject semantic substitution.",
                    reviewer_id="scientific-reviewer",
                ),
            )

    def test_fixture_semantic_judgment_cannot_grant_positive_soundness(self) -> None:
        raw_output = self._evidence(
            "raw-alternative-output",
            logical_type="experiment_output.fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
            parents=(self.graph_source.sha256,),
            payload={"observations": [1, 2, 3]},
        )
        _, judgment = self._semantic_judgment(
            label="alternative-pass",
            subject_kind=JudgmentSubjectKind.SOUNDNESS_DIMENSION,
            subject_id=SoundnessDimension.ALTERNATIVE_EXPLANATIONS.value,
            outcome=DimensionStatus.PASS.value,
            evidence_hashes=(raw_output.sha256,),
            context_hashes=(self.graph.sha256,),
            rationale="Exact raw outputs were judged against the claim graph.",
        )
        with self.assertRaisesRegex(
            ValidationError,
            "no source-owned replay resolver exists for positive "
            "alternative-explanations authority",
        ):
            register_soundness_dimension_receipt(
                self.registry,
                SoundnessDimensionEvidenceReceipt(
                    receipt_id="alternative-explanations-pass",
                    dimension=SoundnessDimension.ALTERNATIVE_EXPLANATIONS,
                    status=DimensionStatus.PASS,
                    authority_kind=SoundnessAuthorityKind.SEMANTIC,
                    authority_artifact_hash=judgment.sha256,
                    evidence_hashes=(raw_output.sha256,),
                    governing_rule="Interpret alternatives over exact raw outputs.",
                    rationale="Fixture provider custody cannot promote science.",
                    reviewer_id="scientific-reviewer",
                ),
            )

    def test_alternative_plan_requires_exact_claim_and_attempt_coverage(self) -> None:
        def digest(label: str) -> str:
            return hashlib.sha256(label.encode("utf-8")).hexdigest()

        with self.assertRaisesRegex(
            ValidationError,
            "exactly cover every central claim",
        ):
            AlternativeExplanationsPlan(
                plan_id="plan-incomplete-alternatives",
                assessment_id="assessment-incomplete-alternatives",
                run_id="run-incomplete-alternatives",
                claim_graph_artifact_hash=digest("alternative-graph"),
                central_claims=(
                    AlternativeClaimScope("claim-a", "Claim A."),
                    AlternativeClaimScope("claim-b", "Claim B."),
                ),
                contract_id="contract-alternatives",
                evaluation_contract_artifact_hash=digest("alternative-contract"),
                evaluation_contract_artifact_record_hash=digest(
                    "alternative-contract-record"
                ),
                contract_freeze_receipt_artifact_hash=digest("alternative-freeze"),
                contract_freeze_receipt_artifact_record_hash=digest(
                    "alternative-freeze-record"
                ),
                experiment=AlternativeExperimentAuthorityBinding(
                    experiment_id="experiment-alternatives",
                    experiment_artifact_hash=digest("alternative-experiment"),
                    experiment_artifact_record_hash=digest(
                        "alternative-experiment-record"
                    ),
                    evaluation_contract_artifact_hash=digest("alternative-contract"),
                    evaluation_contract_artifact_record_hash=digest(
                        "alternative-contract-record"
                    ),
                ),
                explanations=(
                    CompetingExplanation(
                        explanation_id="explanation-a",
                        finding_id="finding-a",
                        target_claim_ids=("claim-a",),
                        statement="Only claim A receives an explanation.",
                        mechanism="A bounded competing mechanism.",
                        distinguishing_prediction="A predeclared difference.",
                    ),
                ),
                attempts=(
                    AlternativeFalsificationAttempt(
                        attempt_id="attempt-a",
                        explanation_id="explanation-a",
                        experiment_id="experiment-alternatives",
                        result_id="result-a",
                        statistical_test_id="test-a",
                        statistic_field="effect",
                        operator=AlternativeFalsificationOperator.LESS_THAN,
                        threshold=0.0,
                    ),
                ),
                ledger_path="runs/soundness-gates/events.jsonl",
                plan_event_id="event-plan-alternatives",
                plan_event_hash=digest("alternative-plan-event"),
                plan_event_index=0,
            )

    def test_alternative_plan_must_predate_underlying_run_visibility(self) -> None:
        timestamp = "2026-08-30T00:00:00Z"
        canonical_run = Run(
            object_id="run-alternative-observed",
            producer=Role.EXPERIMENT_RUNNER,
            status=RecordStatus.COMPLETE,
            created_at=timestamp,
            experiment_id="experiment-alternatives",
            code_revision="test-revision",
            configuration_artifact_hash=hashlib.sha256(
                b"alternative-run-configuration"
            ).hexdigest(),
            evaluator_version="test-evaluator-v1",
            started_at=timestamp,
            completed_at=timestamp,
        )
        run_record = self.registry.put_json(
            canonical_run.to_dict(),
            logical_type="research_state.run",
            origin="focused alternative prospectivity Run",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=(
                "scientist-one",
                "test-alternative-prospectivity",
            ),
            parent_artifacts=(),
            schema_version=canonical_run.schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        result_record = self._evidence(
            "alternative-result-after-observed-run",
            logical_type="research_state.result",
            creator_role=Role.STATISTICIAN,
            parents=(run_record.sha256,),
        )
        run_event = SimpleNamespace(
            run_id="run-soundness-gates",
            artifact_hashes=(run_record.sha256,),
            metadata={
                "research_state_operation": "MATERIALIZED",
                "object_type": "Run",
                "object_id": canonical_run.object_id,
                "revision": canonical_run.revision,
                "content_hash": canonical_run.content_hash,
                "artifact_hash": run_record.sha256,
                "schema_version": canonical_run.schema_version,
                "supersedes_content_hash": canonical_run.supersedes_content_hash,
            },
        )
        plan_event = SimpleNamespace(
            run_id="run-soundness-gates",
            artifact_hashes=(),
            metadata={},
        )
        predecessor_event = SimpleNamespace(
            run_id="run-soundness-gates",
            artifact_hashes=(hashlib.sha256(b"earlier-run-revision").hexdigest(),),
            metadata={
                "research_state_operation": "MATERIALIZED",
                "object_type": "Run",
                "object_id": canonical_run.object_id,
            },
        )
        with self.assertRaisesRegex(
            ValidationError,
            "plan must predate every Result-bound canonical Run",
        ):
            gates_module._result_experiment_ids(
                self.registry,
                result_record.sha256,
                (canonical_run.object_id,),
                ledger_events=(run_event, plan_event),
                authority_run_id="run-soundness-gates",
                plan_event_index=1,
            )
        with self.assertRaisesRegex(
            ValidationError,
            "plan must predate every Result-bound canonical Run",
        ):
            gates_module._result_experiment_ids(
                self.registry,
                result_record.sha256,
                (canonical_run.object_id,),
                ledger_events=(predecessor_event, plan_event, run_event),
                authority_run_id="run-soundness-gates",
                plan_event_index=1,
            )
        self.assertEqual(
            gates_module._result_experiment_ids(
                self.registry,
                result_record.sha256,
                (canonical_run.object_id,),
                ledger_events=(plan_event, run_event),
                authority_run_id="run-soundness-gates",
                plan_event_index=0,
            ),
            frozenset({"experiment-alternatives"}),
        )

    def test_positive_soundness_requires_eligible_scientific_claims(self) -> None:
        self.assertEqual(
            gates_module._resolve_claim_graph_authority(
                self.registry,
                self.graph.sha256,
            ),
            frozenset(self.claim_ids),
        )
        scientific_but_unsupported = self._claim_graph(
            "unsupported-scientific-graph",
            self.claim_ids,
            evidence_use=ClaimEvidenceUse.SCIENTIFIC,
        )
        for graph in (self.graph, scientific_but_unsupported):
            with (
                self.subTest(graph=graph.sha256),
                self.assertRaisesRegex(
                    ValidationError,
                    "every central claim to be freshly ELIGIBLE scientific evidence",
                ),
            ):
                gates_module._resolve_claim_graph_authority(
                    self.registry,
                    graph.sha256,
                    confirmatory_claim_authority_hashes=(),
                    require_scientific_claims=True,
                )

    def test_direct_registry_alternative_authority_clone_is_not_science(self) -> None:
        fake_semantic = self._evidence("forged-alternative-semantic-authority")
        metadata = {
            record.sha256: str(record.record_hash)
            for record in (
                self.graph,
                self.dimension_evidence,
                self.review_evidence,
                self.attack_evidence,
                self.resolution_evidence,
                self.graph_source,
                fake_semantic,
            )
        }
        authority = AlternativeExplanationsAuthority(
            authority_id="forged-alternative-authority",
            assessment_id="forged-alternative-assessment",
            run_id="run-soundness-gates",
            claim_graph_artifact_hash=self.graph.sha256,
            central_claims=tuple(
                AlternativeClaimScope(claim_id, f"Text for {claim_id}.")
                for claim_id in self.claim_ids
            ),
            plan_artifact_hash=self.dimension_evidence.sha256,
            plan_artifact_record_hash=metadata[self.dimension_evidence.sha256],
            projection_artifact_hash=self.review_evidence.sha256,
            projection_artifact_record_hash=metadata[self.review_evidence.sha256],
            finding_artifact_hashes=(self.attack_evidence.sha256,),
            finding_artifact_record_hashes=(metadata[self.attack_evidence.sha256],),
            resolution_receipt_hashes=(),
            resolution_receipt_record_hashes=(),
            challenger_execution_artifact_hash=self.resolution_evidence.sha256,
            challenger_execution_artifact_record_hash=metadata[
                self.resolution_evidence.sha256
            ],
            challenger_review_artifact_hash=self.graph_source.sha256,
            challenger_review_artifact_record_hash=str(self.graph_source.record_hash),
            semantic_judgment_artifact_hash=fake_semantic.sha256,
            status=AlternativeExplanationsStatus.EXHAUSTIVELY_FALSIFIED,
            input_artifact_hashes=tuple(metadata),
            input_artifact_record_hashes=tuple(metadata.values()),
            ledger_path=self.ledger.relative_path.as_posix(),
            verification_event_id="event-forged-alternative",
            verification_event_hash=hashlib.sha256(
                b"event-forged-alternative"
            ).hexdigest(),
            verification_event_index=0,
        )
        restored = AlternativeExplanationsAuthority.from_dict(authority.to_dict())
        self.assertEqual(restored, authority)
        self.assertTrue(restored.scientific_gate_passed)
        forged = self.registry.put_json(
            authority.to_dict(),
            logical_type=ALTERNATIVE_EXPLANATIONS_AUTHORITY_LOGICAL_TYPE,
            origin="fresh registry-ledger alternative-explanations authority",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            creation_command=(
                "scientist-one",
                "verify-alternative-explanations",
            ),
            parent_artifacts=authority.input_artifact_hashes,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaises(ValidationError):
            require_alternative_explanations_authority(
                self.registry,
                self.ledger,
                authority_artifact_hash=forged.sha256,
                expected_assessment_id=authority.assessment_id,
                expected_run_id=authority.run_id,
                expected_claim_graph_artifact_hash=self.graph.sha256,
                expected_central_claim_ids=self.claim_ids,
            )

    def test_generic_frozen_bytes_cannot_execute_alternative_attack(self) -> None:
        finding = ChallengeFinding(
            challenge_id="finding-forged-alternative-execution",
            category=ChallengeCategory.ALTERNATIVE_EXPLANATION,
            severity=ChallengeSeverity.MAJOR,
            status=ChallengeStatus.UNRESOLVED,
            target_claim_ids=self.claim_ids,
            claim_graph_artifact_hash=self.graph.sha256,
            evidence_hashes=(self.attack_evidence.sha256,),
            attack="Caller-authored alternative attack.",
            deterministic=True,
        )
        finding_record = register_challenge_finding(self.registry, finding)
        fake_result = self._evidence("forged-alternative-projection")
        with self.assertRaises(ValidationError):
            register_challenger_attack_execution_receipt(
                self.registry,
                ChallengerAttackExecutionReceipt(
                    receipt_id="execution-forged-alternative",
                    review_id="review-forged-alternative",
                    run_id="run-soundness-gates",
                    category=ChallengeCategory.ALTERNATIVE_EXPLANATION,
                    claim_graph_artifact_hash=self.graph.sha256,
                    target_claim_ids=self.claim_ids,
                    evidence_hashes=(
                        self.dimension_evidence.sha256,
                        self.review_evidence.sha256,
                        self.resolution_evidence.sha256,
                        self.graph_source.sha256,
                    ),
                    executor_kind=ChallengerExecutorKind.DETERMINISTIC,
                    executor_id="adversarial-reviewer",
                    executor_role=Role.ADVERSARIAL_REVIEWER,
                    procedure_id="alternative-explanations-falsification",
                    procedure_version="1.0",
                    result_artifact_hashes=(fake_result.sha256,),
                    finding_artifact_hashes=(finding_record.sha256,),
                    completed=True,
                ),
                ledger=self.ledger,
            )

    def test_semantic_dimension_receipt_cannot_be_reused_across_graphs(self) -> None:
        other_graph = self._claim_graph("other-assessed-graph", self.claim_ids)
        reviews = self._review_records(
            graph_hash=other_graph.sha256,
            prefix="other-assessed-graph",
        )
        with self.assertRaisesRegex(
            ValidationError,
            "semantic dimension authority is bound to another claim graph",
        ):
            self._assessment(
                "cross-graph-semantic-dimension",
                dimension_overrides={
                    SoundnessDimension.LIMITATIONS: DimensionStatus.FAIL,
                },
                review_hashes=reviews,
                graph_hash=other_graph.sha256,
            )

    def test_semantic_receipt_public_revalidation_and_substitution(self) -> None:
        receipt, persisted = self._semantic_judgment(
            label="venue-requirement",
            subject_kind=JudgmentSubjectKind.VENUE_REQUIREMENT,
            subject_id="artifact-availability",
            outcome="SATISFIED",
            evidence_hashes=(self.dimension_evidence.sha256,),
            context_hashes=(self.graph.sha256,),
            rationale="Exact requirement evidence was reviewed.",
        )
        self.assertEqual(
            require_semantic_judgment_receipt(
                self.registry,
                receipt_artifact_hash=persisted.sha256,
                subject_kind=receipt.subject_kind,
                subject_id=receipt.subject_id,
                outcome=receipt.outcome,
                evidence_hashes=receipt.evidence_hashes,
                context_hashes=receipt.context_hashes,
            ),
            receipt,
        )
        with self.assertRaises(ValidationError):
            require_semantic_judgment_receipt(
                self.registry,
                receipt_artifact_hash=persisted.sha256,
                subject_kind=receipt.subject_kind,
                subject_id=receipt.subject_id,
                outcome="FAILED",
            )
        substituted_evidence = self._evidence("semantic-substituted-evidence")
        for label, substituted in (
            ("model", replace(receipt, model="gpt-substituted")),
            (
                "evidence",
                replace(receipt, evidence_hashes=(substituted_evidence.sha256,)),
            ),
        ):
            with self.subTest(label=label), self.assertRaises(ValidationError):
                register_semantic_judgment_receipt(self.registry, substituted)

    def test_semantic_receipt_rejects_raw_output_and_model_splices(self) -> None:
        receipt, _ = self._semantic_judgment(
            label="raw-output-splice",
            subject_kind=JudgmentSubjectKind.VENUE_REQUIREMENT,
            subject_id="artifact-availability",
            outcome="SATISFIED",
            evidence_hashes=(self.dimension_evidence.sha256,),
            context_hashes=(self.graph.sha256,),
            rationale="The retained raw response supports this exact outcome.",
        )
        output_record = self.registry.get_metadata(
            receipt.model_output_artifact_hash
        )
        output_value = safe_json_loads(
            self.registry.get_bytes(output_record.sha256)
        )

        forged_rationale = "A substituted output absent from retained raw bytes."
        forged_structured = dict(output_value["output"])
        forged_structured.update(
            {"outcome": "FAILED", "rationale": forged_rationale}
        )
        forged_output_value = dict(output_value)
        forged_output_value["output"] = forged_structured
        forged_output = self.registry.put_json(
            forged_output_value,
            logical_type=output_record.logical_type,
            origin=output_record.origin,
            creator_role=output_record.creator_role,
            creation_command=output_record.creation_command,
            parent_artifacts=output_record.parent_artifacts,
            schema_version=output_record.schema_version,
            mime_type=output_record.mime_type,
            validation_result=output_record.validation_result,
            frozen=output_record.frozen,
        )
        forged_receipt = replace(
            receipt,
            outcome="FAILED",
            rationale=forged_rationale,
            model_output_artifact_hash=forged_output.sha256,
            structured_output_sha256=hashlib.sha256(
                canonical_json_bytes(forged_structured)
            ).hexdigest(),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "raw response|structured output",
        ):
            register_semantic_judgment_receipt(self.registry, forged_receipt)

        forged_model_value = dict(output_value)
        forged_model_value["model_returned"] = "counterfeit-model-version"
        forged_model_output = self.registry.put_json(
            forged_model_value,
            logical_type=output_record.logical_type,
            origin=output_record.origin,
            creator_role=output_record.creator_role,
            creation_command=output_record.creation_command,
            parent_artifacts=output_record.parent_artifacts,
            schema_version=output_record.schema_version,
            mime_type=output_record.mime_type,
            validation_result=output_record.validation_result,
            frozen=output_record.frozen,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "structured output",
        ):
            register_semantic_judgment_receipt(
                self.registry,
                replace(
                    receipt,
                    model_version="counterfeit-model-version",
                    model_output_artifact_hash=forged_model_output.sha256,
                ),
            )

    def test_deterministic_provider_fixture_replays_as_unverified_advisory(self) -> None:
        receipt, persisted = self._semantic_judgment(
            label="deterministic-provider",
            subject_kind=JudgmentSubjectKind.VENUE_REQUIREMENT,
            subject_id="artifact-availability",
            outcome="SATISFIED",
            evidence_hashes=(self.dimension_evidence.sha256,),
            context_hashes=(self.graph.sha256,),
            rationale="A second deterministic provider fixture retained the same output.",
            deterministic_fixture=True,
        )
        reopened = require_semantic_judgment_receipt(
            self.registry,
            receipt_artifact_hash=persisted.sha256,
            subject_kind=receipt.subject_kind,
            subject_id=receipt.subject_id,
            outcome=receipt.outcome,
            evidence_hashes=receipt.evidence_hashes,
            context_hashes=receipt.context_hashes,
        )
        self.assertEqual(reopened, receipt)
        projection = gates_module._validate_semantic_judgment_custody(
            self.registry,
            receipt,
        )
        self.assertEqual(projection.provider_id, "deterministic-fixture")
        self.assertFalse(projection.network_used)
        self.assertEqual(projection.external_validation, "UNTESTED")
        self.assertFalse(projection.scientific_evidence)
        with self.assertRaisesRegex(ValidationError, "gateway issuance"):
            require_scientific_semantic_judgment_receipt(
                self.registry,
                self.ledger,
                run_id="soundness-gates",
                receipt_artifact_hash=persisted.sha256,
                subject_kind=receipt.subject_kind,
                subject_id=receipt.subject_id,
                outcome=receipt.outcome,
                evidence_hashes=receipt.evidence_hashes,
                context_hashes=receipt.context_hashes,
            )

    def test_caller_labeled_live_transport_cannot_grant_semantic_science(
        self,
    ) -> None:
        result, persisted = self._semantic_judgment(
            label="caller-labeled-live",
            subject_kind=JudgmentSubjectKind.VENUE_REQUIREMENT,
            subject_id="artifact-availability",
            outcome="SATISFIED",
            evidence_hashes=(self.dimension_evidence.sha256,),
            context_hashes=(self.graph.sha256,),
            rationale="A replaceable transport cannot assert audited live custody.",
            caller_labeled_live_transport=True,
            expected_status=ModelRunStatus.BLOCKED_EXTERNAL,
        )
        self.assertIsNone(persisted)
        self.assertEqual(result.external_validation, "BLOCKED_EXTERNAL")
        self.assertFalse(result.network_used)
        self.assertEqual(result.error_code, "PROVIDER_UNAVAILABLE")
        self.assertIsNotNone(result.terminal_receipt)
        logical_types = {record.logical_type for record in self.registry.list_records()}
        self.assertFalse(
            logical_types
            & {
                "external_request",
                "external_response_receipt",
                "raw_external_response",
                "audited_transport_execution_authority",
                "model_provider_request_intent",
                "model_provider_response",
                "model_output",
                "semantic_judgment_receipt",
            }
        )

    def test_direct_registry_live_marker_clone_cannot_grant_semantic_science(
        self,
    ) -> None:
        receipt, _ = self._semantic_judgment(
            label="direct-live-marker-clone",
            subject_kind=JudgmentSubjectKind.VENUE_REQUIREMENT,
            subject_id="artifact-availability",
            outcome="SATISFIED",
            evidence_hashes=(self.dimension_evidence.sha256,),
            context_hashes=(self.graph.sha256,),
            rationale="Registry strings cannot prove live gateway issuance.",
        )

        provider_record = self.registry.get_metadata(
            receipt.provider_response_artifact_hash
        )
        response_receipt_hash = provider_record.parent_artifacts[1]
        response_receipt_record = self.registry.get_metadata(response_receipt_hash)
        response_receipt_value = safe_json_loads(
            self.registry.get_bytes(response_receipt_hash)
        )
        response_receipt_value.update(
            {
                "network_used": True,
                "external_validation": (
                    "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                ),
                "transport_authority": AUDITED_LIVE_TRANSPORT_AUTHORITY,
            }
        )
        cloned_response_receipt = self.registry.put_json(
            response_receipt_value,
            logical_type=response_receipt_record.logical_type,
            origin=response_receipt_record.origin,
            creator_role=response_receipt_record.creator_role,
            creation_command=response_receipt_record.creation_command,
            parent_artifacts=response_receipt_record.parent_artifacts,
            schema_version=response_receipt_record.schema_version,
            mime_type=response_receipt_record.mime_type,
            validation_result=response_receipt_record.validation_result,
            frozen=response_receipt_record.frozen,
        )
        forged_transport_authority = self.registry.put_json(
            {
                "schema_version": "audited-transport-execution-authority/v1",
                "kind": "AUDITED_TRANSPORT_EXECUTION_AUTHORITY",
                "run_id": "soundness-gates",
                "forged": True,
            },
            logical_type="audited_transport_execution_authority",
            origin="caller-cloned live transport authority",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=(
                "scientist-one",
                "test-soundness-gates",
                "forge-live-transport",
            ),
            parent_artifacts=(cloned_response_receipt.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

        provider_value = safe_json_loads(
            self.registry.get_bytes(provider_record.sha256)
        )
        provider_value.update(
            {
                "network_used": True,
                "external_validation": (
                    "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                ),
                "transport_authority": AUDITED_LIVE_TRANSPORT_AUTHORITY,
                "transport_execution_authority_artifact_sha256": (
                    forged_transport_authority.sha256
                ),
            }
        )
        cloned_provider = self.registry.put_json(
            provider_value,
            logical_type=provider_record.logical_type,
            origin=provider_record.origin,
            creator_role=provider_record.creator_role,
            creation_command=provider_record.creation_command,
            parent_artifacts=(
                provider_record.parent_artifacts[0],
                cloned_response_receipt.sha256,
                forged_transport_authority.sha256,
            ),
            schema_version=provider_record.schema_version,
            mime_type=provider_record.mime_type,
            validation_result=provider_record.validation_result,
            frozen=provider_record.frozen,
        )

        output_record = self.registry.get_metadata(receipt.model_output_artifact_hash)
        output_value = safe_json_loads(self.registry.get_bytes(output_record.sha256))
        output_value.update(
            {
                "network_used": True,
                "external_validation": (
                    "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                ),
                "transport_authority": AUDITED_LIVE_TRANSPORT_AUTHORITY,
                "transport_execution_authority_artifact_sha256": (
                    forged_transport_authority.sha256
                ),
            }
        )
        cloned_output = self.registry.put_json(
            output_value,
            logical_type=output_record.logical_type,
            origin=output_record.origin,
            creator_role=output_record.creator_role,
            creation_command=output_record.creation_command,
            parent_artifacts=(
                output_record.parent_artifacts[0],
                output_record.parent_artifacts[1],
                cloned_provider.sha256,
            ),
            schema_version=output_record.schema_version,
            mime_type=output_record.mime_type,
            validation_result=output_record.validation_result,
            frozen=output_record.frozen,
        )
        cloned_receipt = replace(
            receipt,
            provider_response_artifact_hash=cloned_provider.sha256,
            model_output_artifact_hash=cloned_output.sha256,
        )
        cloned = register_semantic_judgment_receipt(
            self.registry,
            cloned_receipt,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "source-owned gateway issuance replay",
        ):
            require_scientific_semantic_judgment_receipt(
                self.registry,
                self.ledger,
                run_id="soundness-gates",
                receipt_artifact_hash=cloned.sha256,
                subject_kind=cloned_receipt.subject_kind,
                subject_id=cloned_receipt.subject_id,
                outcome=cloned_receipt.outcome,
                evidence_hashes=cloned_receipt.evidence_hashes,
                context_hashes=cloned_receipt.context_hashes,
            )

    def test_claim_kinds_require_the_same_scientific_custody(
        self,
    ) -> None:
        for subject_kind, label in (
            (JudgmentSubjectKind.CLAIM_QUALIFIER, "claim-qualifier-fixture"),
            (JudgmentSubjectKind.CLAIM_SEMANTICS, "claim-semantics-fixture"),
        ):
            with self.subTest(subject_kind=subject_kind):
                receipt, persisted = self._semantic_judgment(
                    label=label,
                    subject_kind=subject_kind,
                    subject_id="claim-central",
                    outcome=f"sha256:{hashlib.sha256(label.encode()).hexdigest()}",
                    evidence_hashes=(
                        self.graph.sha256,
                        self.dimension_evidence.sha256,
                    ),
                    context_hashes=(self.graph_source.sha256,),
                    rationale=(
                        "The retained output is advisory until live custody replays."
                    ),
                )
                self.assertEqual(
                    require_semantic_judgment_receipt(
                        self.registry,
                        receipt_artifact_hash=persisted.sha256,
                        subject_kind=subject_kind,
                        subject_id="claim-central",
                        outcome=receipt.outcome,
                        evidence_hashes=receipt.evidence_hashes,
                        context_hashes=receipt.context_hashes,
                    ),
                    receipt,
                )
                with self.assertRaisesRegex(
                    ValidationError,
                    "gateway issuance",
                ):
                    require_scientific_semantic_judgment_receipt(
                        self.registry,
                        self.ledger,
                        run_id="soundness-gates",
                        receipt_artifact_hash=persisted.sha256,
                        subject_kind=subject_kind,
                        subject_id="claim-central",
                        outcome=receipt.outcome,
                        evidence_hashes=receipt.evidence_hashes,
                        context_hashes=receipt.context_hashes,
                    )

    def test_caller_subset_unknown_and_duplicate_central_claims_reject(self) -> None:
        for claim_ids in (
            ("claim-central",),
            ("claim-caller-only",),
            ("claim-central", "claim-central"),
        ):
            with self.subTest(claim_ids=claim_ids), self.assertRaises(ValidationError):
                self._assessment("invalid-central", central_claim_ids=claim_ids)

    def test_caller_boolean_cannot_mint_confirmatory_graph_authority(self) -> None:
        forged_graph = self._caller_authorized_confirmatory_graph()
        target_overrides = {
            category: ("claim-confirmatory-forged",) for category in ChallengeCategory
        }
        review_hashes = self._review_records(
            graph_hash=forged_graph.sha256,
            target_overrides=target_overrides,
            prefix="forged-confirmatory",
        )
        role_labeled_forgery = self._evidence(
            "forged-confirmatory-authority",
            logical_type="confirmatory_claim_authority",
            creator_role=Role.CLAIM_VERIFIER,
            parents=(forged_graph.sha256,),
            payload={
                "claim_id": "claim-confirmatory-forged",
                "run_id": "run-forged-confirmatory",
                "scope": "SCIENTIFIC_EVIDENCE",
                "scientific_gate_passed": True,
            },
        )
        for authority_hash in (
            self.graph_source.sha256,
            role_labeled_forgery.sha256,
        ):
            with (
                self.subTest(authority_hash=authority_hash),
                self.assertRaisesRegex(
                    ValidationError,
                    "each confirmatory claim requires one exact scientific authority",
                ),
            ):
                self._assessment(
                    "forged-confirmatory-assessment",
                    graph_hash=forged_graph.sha256,
                    central_claim_ids=("claim-confirmatory-forged",),
                    review_hashes=review_hashes,
                    ledger=self.ledger,
                    run_id="run-forged-confirmatory",
                    confirmatory_claim_authority_hashes=(authority_hash,),
                )

    def test_confirmatory_graph_requires_live_claim_scoped_authority(self) -> None:
        graph = self._caller_authorized_confirmatory_graph(confirmatory=False)
        # Reusing the complete evidence closure with a confirmatory flag but no
        # positive caller decision is still not a substitute for live custody.
        value = safe_json_loads(self.registry.get_bytes(graph.sha256))
        value["graph"]["claims"][0]["confirmatory"] = True
        confirmatory_graph = self.registry.put_json(
            value,
            logical_type="claim_evidence_graph",
            origin="confirmatory graph without live claim authority",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=(
                "scientist-one",
                "test-soundness-gates",
                "missing-confirmatory-authority",
            ),
            parent_artifacts=self.registry.get_metadata(graph.sha256).parent_artifacts,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        target_overrides = {
            category: ("claim-confirmatory-forged",) for category in ChallengeCategory
        }
        review_hashes = self._review_records(
            graph_hash=confirmatory_graph.sha256,
            target_overrides=target_overrides,
            prefix="missing-confirmatory-authority",
        )
        with self.assertRaisesRegex(
            ValidationError,
            "confirmatory soundness requires its exact live EventLedger and run ID",
        ):
            self._assessment(
                "missing-confirmatory-authority",
                graph_hash=confirmatory_graph.sha256,
                central_claim_ids=("claim-confirmatory-forged",),
                review_hashes=review_hashes,
            )

    def test_nonconfirmatory_soundness_rejects_unrelated_claim_authority(self) -> None:
        reviews = self._review_records(prefix="nonconfirmatory-extra-authority")
        with self.assertRaisesRegex(
            ValidationError,
            "non-confirmatory soundness cannot carry confirmatory claim authority",
        ):
            self._assessment(
                "nonconfirmatory-extra-authority",
                review_hashes=reviews,
                ledger=self.ledger,
                run_id="run-unrelated",
                confirmatory_claim_authority_hashes=(self.graph_source.sha256,),
            )

    def test_claim_graph_cannot_omit_a_verification_parent(self) -> None:
        incomplete_graph = self._caller_authorized_confirmatory_graph(
            confirmatory=False,
            omit_verification_parent=True,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "parents differ from its exact evidence closure",
        ):
            register_challenger_category_review(
                self.registry,
                ChallengerCategoryReview(
                    review_id="review-incomplete-graph-lineage",
                    category=ChallengeCategory.PRIOR_ART,
                    execution_status=ChallengerExecutionStatus.UNTESTED,
                    target_claim_ids=("claim-confirmatory-forged",),
                    claim_graph_artifact_hash=incomplete_graph.sha256,
                    evidence_hashes=(self.review_evidence.sha256,),
                    finding_artifact_hashes=(),
                    execution_receipt_hash=None,
                    attack="Attempt to use a graph with an omitted resolver parent.",
                    conclusion="Incomplete graph lineage must fail closed.",
                    deterministic=False,
                ),
            )

    def test_claim_graph_rejects_extra_provenance_parent(self) -> None:
        graph = self._caller_authorized_confirmatory_graph(confirmatory=False)
        value = safe_json_loads(self.registry.get_bytes(graph.sha256))
        value["splice_attempt"] = True
        extra_parent = self._evidence("unrelated-claim-graph-parent")
        spliced = self.registry.put_json(
            value,
            logical_type="claim_evidence_graph",
            origin="claim graph with an unrelated provenance parent",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=(
                "scientist-one",
                "test-soundness-gates",
                "splice-claim-graph-parent",
            ),
            parent_artifacts=(
                *self.registry.get_metadata(graph.sha256).parent_artifacts,
                extra_parent.sha256,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "parents differ from its exact evidence closure",
        ):
            register_challenger_category_review(
                self.registry,
                ChallengerCategoryReview(
                    review_id="review-spliced-graph-parent",
                    category=ChallengeCategory.PRIOR_ART,
                    execution_status=ChallengerExecutionStatus.UNTESTED,
                    target_claim_ids=("claim-confirmatory-forged",),
                    claim_graph_artifact_hash=spliced.sha256,
                    evidence_hashes=(self.review_evidence.sha256,),
                    finding_artifact_hashes=(),
                    execution_receipt_hash=None,
                    attack="Attempt to splice an unrelated provenance parent.",
                    conclusion="Exact graph parent closure must reject the splice.",
                    deterministic=False,
                ),
            )

    def test_claim_verification_receipt_type_must_match_evidence_kind(self) -> None:
        graph = self._caller_authorized_confirmatory_graph(
            confirmatory=False,
            wrong_verification_type=True,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "type or parents differ from its typed payload",
        ):
            register_challenger_category_review(
                self.registry,
                ChallengerCategoryReview(
                    review_id="review-wrong-verification-type",
                    category=ChallengeCategory.PRIOR_ART,
                    execution_status=ChallengerExecutionStatus.UNTESTED,
                    target_claim_ids=("claim-confirmatory-forged",),
                    claim_graph_artifact_hash=graph.sha256,
                    evidence_hashes=(self.review_evidence.sha256,),
                    finding_artifact_hashes=(),
                    execution_receipt_hash=None,
                    attack="Substitute a verification-receipt type suffix.",
                    conclusion="Typed receipt identity must be exact.",
                    deterministic=False,
                ),
            )

    def test_claim_verification_receipt_parents_are_exact(self) -> None:
        graph = self._caller_authorized_confirmatory_graph(
            confirmatory=False,
            wrong_verification_parents=True,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "type or parents differ from its typed payload",
        ):
            register_challenger_category_review(
                self.registry,
                ChallengerCategoryReview(
                    review_id="review-wrong-verification-parents",
                    category=ChallengeCategory.PRIOR_ART,
                    execution_status=ChallengerExecutionStatus.UNTESTED,
                    target_claim_ids=("claim-confirmatory-forged",),
                    claim_graph_artifact_hash=graph.sha256,
                    evidence_hashes=(self.review_evidence.sha256,),
                    finding_artifact_hashes=(),
                    execution_receipt_hash=None,
                    attack="Omit a verification receipt support parent.",
                    conclusion="Typed receipt parents must be exact.",
                    deterministic=False,
                ),
            )

    def test_every_category_must_cover_every_graph_claim(self) -> None:
        reviews = self._review_records(
            target_overrides={ChallengeCategory.REPRODUCTION: ("claim-central",)},
            prefix="omitted-secondary",
        )
        with self.assertRaises(ValidationError):
            self._assessment("omitted-secondary", review_hashes=reviews)

    def test_duplicate_or_omitted_category_reviews_reject(self) -> None:
        reviews = self._review_records(prefix="category-completeness")
        for invalid in (reviews[:-1], (*reviews[:-1], reviews[0])):
            with self.subTest(length=len(invalid)), self.assertRaises(ValidationError):
                self._assessment("invalid-category-set", review_hashes=invalid)

    def test_fabricated_review_and_finding_targets_reject(self) -> None:
        with self.assertRaises(ValidationError):
            register_challenger_category_review(
                self.registry,
                ChallengerCategoryReview(
                    review_id="fabricated-review-target",
                    category=ChallengeCategory.PRIOR_ART,
                    execution_status=ChallengerExecutionStatus.UNTESTED,
                    target_claim_ids=("claim-not-in-graph",),
                    claim_graph_artifact_hash=self.graph.sha256,
                    evidence_hashes=(self.review_evidence.sha256,),
                    finding_artifact_hashes=(),
                    execution_receipt_hash=None,
                    attack="Attempt a fabricated claim target.",
                    conclusion="Registration must reject it.",
                ),
            )
        with self.assertRaises(ValidationError):
            register_challenge_finding(
                self.registry, self._finding(target_claim_ids=("claim-not-in-graph",))
            )

    def test_unrelated_claim_graph_reviews_cannot_authorize_assessment(self) -> None:
        unrelated = self._claim_graph("unrelated-graph", self.claim_ids)
        reviews = self._review_records(
            graph_hash=unrelated.sha256, prefix="unrelated-graph"
        )
        with self.assertRaises(ValidationError):
            self._assessment("unrelated-graph", review_hashes=reviews)

    def test_external_validity_execution_is_replayed_and_bound(self) -> None:
        receipt, finding = self._external_execution()
        execution = register_challenger_attack_execution_receipt(self.registry, receipt)
        review = ChallengerCategoryReview(
            review_id=receipt.review_id,
            category=receipt.category,
            execution_status=ChallengerExecutionStatus.EXECUTED,
            target_claim_ids=receipt.target_claim_ids,
            claim_graph_artifact_hash=receipt.claim_graph_artifact_hash,
            evidence_hashes=receipt.evidence_hashes,
            finding_artifact_hashes=(finding.sha256,),
            execution_receipt_hash=execution.sha256,
            attack="Replay external validity boundaries.",
            conclusion="The exact negative boundary attack executed.",
            deterministic=True,
        )
        persisted = register_challenger_category_review(self.registry, review)
        self.assertTrue(self.registry.verify(persisted.sha256))

    def test_external_validity_run_and_source_substitution_reject(self) -> None:
        receipt, _finding = self._external_execution("review-external-lineage")
        with self.assertRaises(ValidationError):
            register_challenger_attack_execution_receipt(
                self.registry,
                replace(
                    receipt,
                    receipt_id="execution-wrong-run",
                    run_id="run-substituted",
                ),
            )

        environment = self.registry.get_metadata(receipt.evidence_hashes[0])
        environment_payload = safe_json_loads(
            self.registry.get_bytes(environment.sha256)
        )
        self.assertIsInstance(environment_payload, dict)
        substituted_source = self._evidence(
            "substituted-source-lineage",
            logical_type="vnext_source_snapshot",
            creator_role=Role.ORCHESTRATOR,
        )
        substituted_environment_payload = dict(environment_payload)
        substituted_environment_payload["lineage_probe"] = "substituted"
        substituted_environment = self._evidence(
            "substituted-environment-lineage",
            logical_type="execution_environment",
            creator_role=Role.EXPERIMENT_RUNNER,
            parents=(substituted_source.sha256,),
            payload=substituted_environment_payload,
        )
        evidence_hashes = (
            substituted_environment.sha256,
            *receipt.evidence_hashes[1:],
        )
        substituted_finding = register_challenge_finding(
            self.registry,
            self._finding(
                challenge_id="finding-substituted-source-lineage",
                category=ChallengeCategory.EXTERNAL_VALIDITY,
                target_claim_ids=self.claim_ids,
                attack="Attempt to splice an unrelated source snapshot.",
                evidence_hashes=evidence_hashes,
            ),
        )
        with self.assertRaises(ValidationError):
            register_challenger_attack_execution_receipt(
                self.registry,
                replace(
                    receipt,
                    receipt_id="execution-substituted-source-lineage",
                    review_id="review-substituted-source-lineage",
                    evidence_hashes=evidence_hashes,
                    finding_artifact_hashes=(substituted_finding.sha256,),
                ),
            )

    def test_execution_receipt_reuse_wrong_role_type_and_parents_reject(self) -> None:
        receipt, finding = self._external_execution("review-external-substitution")
        valid = register_challenger_attack_execution_receipt(self.registry, receipt)
        with self.assertRaises(ValidationError):
            register_challenger_category_review(
                self.registry,
                ChallengerCategoryReview(
                    review_id="different-review-id",
                    category=receipt.category,
                    execution_status=ChallengerExecutionStatus.EXECUTED,
                    target_claim_ids=receipt.target_claim_ids,
                    claim_graph_artifact_hash=receipt.claim_graph_artifact_hash,
                    evidence_hashes=receipt.evidence_hashes,
                    finding_artifact_hashes=(finding.sha256,),
                    execution_receipt_hash=valid.sha256,
                    attack="Attempt receipt reuse.",
                    conclusion="Receipt reuse must fail.",
                    deterministic=True,
                ),
            )
        parents = (
            receipt.claim_graph_artifact_hash,
            *receipt.evidence_hashes,
            *receipt.finding_artifact_hashes,
        )
        cases = (
            (
                "wrong-role",
                Role.SCIENTIFIC_REVIEWER,
                "challenger_attack_execution_receipt",
                parents,
            ),
            (
                "wrong-type",
                Role.ADVERSARIAL_REVIEWER,
                "not_attack_execution",
                parents,
            ),
            (
                "wrong-parents",
                Role.ADVERSARIAL_REVIEWER,
                "challenger_attack_execution_receipt",
                tuple(reversed(parents)),
            ),
        )
        for label, role, logical_type, raw_parents in cases:
            raw_receipt = receipt.to_dict() | {"receipt_id": f"execution-{label}"}
            raw = self.registry.put_json(
                raw_receipt,
                logical_type=logical_type,
                origin="registry-replayed exact Challenger attack execution",
                creator_role=role,
                creation_command=("scientist-one", "record-challenger-execution"),
                parent_artifacts=raw_parents,
                schema_version="2.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.subTest(label=label), self.assertRaises(ValidationError):
                register_challenger_category_review(
                    self.registry,
                    ChallengerCategoryReview(
                        review_id=receipt.review_id,
                        category=receipt.category,
                        execution_status=ChallengerExecutionStatus.EXECUTED,
                        target_claim_ids=receipt.target_claim_ids,
                        claim_graph_artifact_hash=receipt.claim_graph_artifact_hash,
                        evidence_hashes=receipt.evidence_hashes,
                        finding_artifact_hashes=(finding.sha256,),
                        execution_receipt_hash=raw.sha256,
                        attack="Attempt malformed execution authority.",
                        conclusion="Malformed authority must fail.",
                        deterministic=True,
                    ),
                )

    def test_semantic_challenger_execution_is_fail_closed_without_live_owner(
        self,
    ) -> None:
        finding = self._finding(
            challenge_id="semantic-overclaiming",
            category=ChallengeCategory.OVERCLAIMING,
            target_claim_ids=self.claim_ids,
        )
        finding_record = register_challenge_finding(self.registry, finding)
        _, judgment = self._semantic_judgment(
            label="challenger-overclaiming",
            subject_kind=JudgmentSubjectKind.CHALLENGER_CATEGORY,
            subject_id=ChallengeCategory.OVERCLAIMING.value,
            outcome=ChallengerExecutionStatus.EXECUTED.value,
            evidence_hashes=(self.review_evidence.sha256,),
            context_hashes=(self.graph.sha256, finding_record.sha256),
            rationale="A semantic label lacks a category-specific resolver.",
        )
        with self.assertRaisesRegex(ValidationError, "exact live EventLedger"):
            register_challenger_attack_execution_receipt(
                self.registry,
                ChallengerAttackExecutionReceipt(
                    receipt_id="semantic-overclaiming-execution",
                    review_id="review-semantic-overclaiming",
                    run_id="run-semantic-overclaiming",
                    category=ChallengeCategory.OVERCLAIMING,
                    claim_graph_artifact_hash=self.graph.sha256,
                    target_claim_ids=self.claim_ids,
                    evidence_hashes=(self.review_evidence.sha256,),
                    executor_kind=ChallengerExecutorKind.SEMANTIC,
                    executor_id="semantic-challenger",
                    executor_role=Role.ADVERSARIAL_REVIEWER,
                    procedure_id="semantic-overclaiming-review",
                    procedure_version="1.0",
                    result_artifact_hashes=(),
                    finding_artifact_hashes=(finding_record.sha256,),
                    completed=True,
                    semantic_judgment_hash=judgment.sha256,
                ),
            )

    def test_valid_pinned_semantic_challenger_resolver_records_execution_only(
        self,
    ) -> None:
        receipt, finding, judgment = self._pinned_semantic_execution(
            label="pinned-overclaiming"
        )
        with patch.object(
            gates_module,
            "require_scientific_semantic_judgment_receipt",
            return_value=judgment,
        ) as owner:
            execution = register_challenger_attack_execution_receipt(
                self.registry,
                receipt,
                ledger=self.ledger,
            )
            review = register_challenger_category_review(
                self.registry,
                ChallengerCategoryReview(
                    review_id=receipt.review_id,
                    category=receipt.category,
                    execution_status=ChallengerExecutionStatus.EXECUTED,
                    target_claim_ids=receipt.target_claim_ids,
                    claim_graph_artifact_hash=receipt.claim_graph_artifact_hash,
                    evidence_hashes=receipt.evidence_hashes,
                    finding_artifact_hashes=(finding.sha256,),
                    execution_receipt_hash=execution.sha256,
                    attack="Run the exact pinned OVERCLAIMING semantic procedure.",
                    conclusion=(
                        "The procedure ran; the unresolved finding remains blocking."
                    ),
                    deterministic=False,
                ),
                ledger=self.ledger,
            )
            review_hashes = list(
                self._review_records(prefix="pinned-semantic-incomplete")
            )
            review_hashes[list(ChallengeCategory).index(receipt.category)] = (
                review.sha256
            )
            assessment = assess_soundness(
                self.registry,
                "pinned-semantic-incomplete",
                self._dimension_records(),
                tuple(review_hashes),
                claim_graph_artifact_hash=self.graph.sha256,
                central_claim_ids=self.claim_ids,
                reason=(
                    "A valid execution receipt is not a scientific PASS authority."
                ),
                ledger=self.ledger,
                run_id=receipt.run_id,
            )
        self.assertGreaterEqual(owner.call_count, 3)
        owner.assert_any_call(
            self.registry,
            self.ledger,
            run_id=receipt.run_id,
            receipt_artifact_hash=receipt.semantic_judgment_hash,
            subject_kind=JudgmentSubjectKind.CHALLENGER_CATEGORY,
            subject_id=receipt.category.value,
            outcome=ChallengerExecutionStatus.EXECUTED.value,
            evidence_hashes=receipt.evidence_hashes,
            context_hashes=(
                receipt.claim_graph_artifact_hash,
                *receipt.result_artifact_hashes,
                *receipt.finding_artifact_hashes,
            ),
        )
        self.assertEqual(
            assessment.verdict,
            SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED,
        )
        self.assertIn(
            (finding.sha256,),
            tuple(
                review.finding_artifact_hashes
                for review in assessment.challenger_reviews
            ),
        )

    def test_semantic_challenger_rejects_unknown_stale_cross_run_and_splice(
        self,
    ) -> None:
        receipt, _finding, judgment = self._pinned_semantic_execution(
            label="semantic-resolver-negative-cases"
        )
        with self.assertRaisesRegex(ValidationError, "no pinned source-owned resolver"):
            register_challenger_attack_execution_receipt(
                self.registry,
                replace(
                    receipt,
                    receipt_id="semantic-unknown-procedure",
                    procedure_version="2.0",
                ),
                ledger=self.ledger,
            )

        other_finding = register_challenge_finding(
            self.registry,
            self._finding(
                challenge_id="finding-semantic-splice",
                category=receipt.category,
                target_claim_ids=self.claim_ids,
            ),
        )
        with self.assertRaisesRegex(ValidationError, "pinned category contract"):
            register_challenger_attack_execution_receipt(
                self.registry,
                replace(
                    receipt,
                    receipt_id="semantic-context-splice",
                    finding_artifact_hashes=(other_finding.sha256,),
                ),
                ledger=self.ledger,
            )

        with (
            patch.object(
                gates_module,
                "require_scientific_semantic_judgment_receipt",
                side_effect=ValidationError("stale audited transport authority"),
            ),
            self.assertRaisesRegex(ValidationError, "stale audited transport"),
        ):
            register_challenger_attack_execution_receipt(
                self.registry,
                replace(receipt, receipt_id="semantic-stale-owner"),
                ledger=self.ledger,
            )

        cross_run_input = self._evidence(
            "semantic-cross-run-input",
            payload={"run_id": "run-other", "observations": [1, 2, 3]},
        )
        cross_run, _cross_finding, cross_judgment = self._pinned_semantic_execution(
            label="semantic-cross-run",
            evidence_hashes=(cross_run_input.sha256,),
        )
        with (
            patch.object(
                gates_module,
                "require_scientific_semantic_judgment_receipt",
                return_value=cross_judgment,
            ),
            self.assertRaisesRegex(ValidationError, "explicitly names another run"),
        ):
            register_challenger_attack_execution_receipt(
                self.registry,
                cross_run,
                ledger=self.ledger,
            )

    def test_unresolved_finding_is_preserved_under_conservative_verdict(self) -> None:
        finding = self._finding()
        finding_record = register_challenge_finding(self.registry, finding)
        reviews = self._review_records(
            finding_hashes={finding.category: (finding_record.sha256,)},
            prefix="unresolved",
        )
        result = self._assessment("unresolved", review_hashes=reviews)
        self.assertEqual(result.verdict, SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED)
        self.assertEqual(result.findings, (finding,))

    def test_resolved_finding_requires_independent_typed_receipt(self) -> None:
        unresolved = self._finding()
        with self.assertRaises(ValidationError):
            self._finding(
                status=ChallengeStatus.RESOLVED,
                resolution="Prose alone is not resolution authority.",
            )
        with self.assertRaises(ValidationError):
            ChallengeResolutionReceipt.for_finding(
                unresolved,
                receipt_id="attack-evidence-reuse",
                resolution_evidence_hashes=unresolved.evidence_hashes,
                governing_rule="Attack evidence cannot resolve itself.",
                outcome=ChallengeResolutionOutcome.VERIFIED_RESOLVED,
                resolution="Invalid self-resolution.",
            )
        spoofed_identity = self._resolution(unresolved).to_dict()
        spoofed_identity["resolver_id"] = "caller-selected-reviewer"
        with self.assertRaisesRegex(
            ValidationError,
            "resolver identity is not source-owned",
        ):
            ChallengeResolutionReceipt.from_dict(spoofed_identity)

    def test_deterministic_resolution_identity_registers_and_reloads(self) -> None:
        contract = self._evidence(
            "closed-resolution-contract",
            logical_type="evaluation_contract",
            creator_role=Role.PROTOCOL_DESIGNER,
        )
        freeze = self._evidence(
            "closed-resolution-freeze",
            logical_type="evaluation_contract_freeze_gate_receipt",
            creator_role=Role.CLAIM_VERIFIER,
        )
        experiment = self._evidence(
            "closed-resolution-experiment",
            logical_type="research_state.experiment",
            creator_role=Role.PROTOCOL_DESIGNER,
        )
        result = self._evidence(
            "closed-resolution-result",
            logical_type="research_state.result",
            creator_role=Role.STATISTICIAN,
        )
        statistical_test = self._evidence(
            "closed-resolution-statistical-test",
            logical_type="research_state.statistical_test",
            creator_role=Role.STATISTICIAN,
        )
        explanation = CompetingExplanation(
            explanation_id="closed-resolution-explanation",
            finding_id="closed-resolution-finding",
            target_claim_ids=("claim-central",),
            statement="A bounded competing mechanism could explain the effect.",
            mechanism="The competing mechanism acts on the declared endpoint.",
            distinguishing_prediction="The exact statistic falls below zero.",
        )
        attempt = AlternativeFalsificationAttempt(
            attempt_id="closed-resolution-attempt",
            explanation_id=explanation.explanation_id,
            experiment_id="closed-resolution-experiment",
            result_id="closed-resolution-result",
            statistical_test_id="closed-resolution-statistical-test",
            statistic_field="effect",
            operator=AlternativeFalsificationOperator.LESS_THAN,
            threshold=0.0,
        )
        plan = AlternativeExplanationsPlan(
            plan_id="closed-resolution-plan",
            assessment_id="closed-resolution-assessment",
            run_id="run-soundness-gates",
            claim_graph_artifact_hash=self.graph.sha256,
            central_claims=(
                AlternativeClaimScope(
                    "claim-central",
                    "The central bounded fixture claim.",
                ),
            ),
            contract_id="closed-resolution-contract",
            evaluation_contract_artifact_hash=contract.sha256,
            evaluation_contract_artifact_record_hash=str(contract.record_hash),
            contract_freeze_receipt_artifact_hash=freeze.sha256,
            contract_freeze_receipt_artifact_record_hash=str(freeze.record_hash),
            experiment=AlternativeExperimentAuthorityBinding(
                experiment_id="closed-resolution-experiment",
                experiment_artifact_hash=experiment.sha256,
                experiment_artifact_record_hash=str(experiment.record_hash),
                evaluation_contract_artifact_hash=contract.sha256,
                evaluation_contract_artifact_record_hash=str(contract.record_hash),
            ),
            explanations=(explanation,),
            attempts=(attempt,),
            ledger_path=self.ledger.relative_path.as_posix(),
            plan_event_id="closed-resolution-plan-event",
            plan_event_hash=hashlib.sha256(b"closed-resolution-plan-event").hexdigest(),
            plan_event_index=0,
        )
        plan_record = self.registry.put_json(
            plan.to_dict(),
            logical_type="alternative_explanations_falsification_plan",
            origin="prospective registry-and-ledger competing-explanations plan",
            creator_role=Role.ADVERSARIAL_REVIEWER,
            creation_command=(
                "scientist-one",
                "freeze-alternative-explanations-plan",
            ),
            parent_artifacts=plan.parent_artifact_hashes,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        projection = AlternativeFalsificationProjection(
            projection_id="closed-resolution-projection",
            plan_artifact_hash=plan_record.sha256,
            plan_artifact_record_hash=str(plan_record.record_hash),
            experiment_artifact_hash=experiment.sha256,
            experiment_artifact_record_hash=str(experiment.record_hash),
            attempt_results=(
                AlternativeAttemptResult(
                    attempt_id=attempt.attempt_id,
                    result_artifact_hash=result.sha256,
                    result_artifact_record_hash=str(result.record_hash),
                    statistical_test_artifact_hash=statistical_test.sha256,
                    statistical_test_artifact_record_hash=str(
                        statistical_test.record_hash
                    ),
                    observed_value=-1.0,
                    outcome=AlternativeAttemptOutcome.FALSIFIED,
                ),
            ),
        )
        projection_record = self.registry.put_json(
            projection.to_dict(),
            logical_type="alternative_explanations_falsification_projection",
            origin="deterministically replayed alternative-explanations outcomes",
            creator_role=Role.ADVERSARIAL_REVIEWER,
            creation_command=(
                "scientist-one",
                "project-alternative-falsification",
            ),
            parent_artifacts=projection.parent_artifact_hashes,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        alternative = self._finding(
            challenge_id=explanation.finding_id,
            category=ChallengeCategory.ALTERNATIVE_EXPLANATION,
            attack=gates_module._alternative_attack_text(explanation, attempt),
            evidence_hashes=(plan_record.sha256, projection_record.sha256),
        )
        receipt = ChallengeResolutionReceipt.for_finding(
            alternative,
            receipt_id="source-owned-alternative-resolver",
            resolution_evidence_hashes=(result.sha256, statistical_test.sha256),
            governing_rule=(
                "Resolve only an exact predeclared alternative after deterministic "
                "Result and StatisticalTest replay."
            ),
            outcome=ChallengeResolutionOutcome.VERIFIED_RESOLVED,
            resolution=gates_module._alternative_resolution_text(
                explanation,
                attempt,
            ),
        )
        with (
            patch.object(
                gates_module,
                "require_alternative_explanations_plan",
                return_value=plan,
            ),
            patch.object(
                gates_module,
                "require_alternative_falsification_projection",
                return_value=projection,
            ),
        ):
            record = register_challenge_resolution_receipt(
                self.registry,
                receipt,
                ledger=self.ledger,
            )
            restored = gates_module._load_challenge_resolution_receipt(
                self.registry,
                record.sha256,
                ledger=self.ledger,
            )
        self.assertEqual(restored, receipt)
        self.assertEqual(
            restored.resolver_id,
            gates_module.ALTERNATIVE_CHALLENGE_RESOLVER_ID,
        )
        self.assertEqual(
            restored.resolver_role,
            gates_module.ALTERNATIVE_CHALLENGE_RESOLVER_ROLE,
        )
        self.assertIs(
            self.registry.get_metadata(record.sha256).creator_role,
            Role.CLAIM_VERIFIER,
        )

        spoofed = receipt.to_dict()
        spoofed["resolver_role"] = Role.SCIENTIFIC_REVIEWER.value
        forged = self.registry.put_json(
            spoofed,
            logical_type="challenger_finding_resolution_receipt",
            origin="source-owned deterministic alternative-explanation resolution",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=(
                "scientist-one",
                "resolve-alternative-explanation",
            ),
            parent_artifacts=record.parent_artifacts,
            schema_version="2.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "resolver identity is not source-owned",
        ):
            gates_module._load_challenge_resolution_receipt(
                self.registry,
                forged.sha256,
                ledger=self.ledger,
            )

    def test_generic_positive_resolution_is_rejected_and_stays_unresolved(self) -> None:
        unresolved = self._finding()
        receipt = self._resolution(unresolved)
        with self.assertRaisesRegex(
            ValidationError,
            "unsupported challenge resolution must remain UNRESOLVED",
        ):
            register_challenge_resolution_receipt(self.registry, receipt)
        finding_record = register_challenge_finding(self.registry, unresolved)
        reviews = self._review_records(
            finding_hashes={unresolved.category: (finding_record.sha256,)},
            prefix="generic-resolution-rejected",
        )
        result = self._assessment(
            "generic-resolution-rejected",
            review_hashes=reviews,
        )
        self.assertEqual(result.verdict, SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED)
        self.assertEqual(result.findings, (unresolved,))
        self.assertEqual(result.resolution_receipt_hashes, ())

    def test_resolution_receipt_substitution_reuse_wrong_metadata_reject(self) -> None:
        unresolved = self._finding()
        receipt = self._resolution(unresolved)
        correct_parents = (
            receipt.claim_graph_artifact_hash,
            *receipt.attack_evidence_hashes,
            *receipt.resolution_evidence_hashes,
        )
        receipt_record = self.registry.put_json(
            receipt.to_dict(),
            logical_type="challenger_finding_resolution_receipt",
            origin="source-owned deterministic alternative-explanation resolution",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "resolve-alternative-explanation"),
            parent_artifacts=correct_parents,
            schema_version="2.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        substitutions = (
            self._finding(
                status=ChallengeStatus.RESOLVED,
                resolution=receipt.resolution,
                resolution_receipt_hash=receipt_record.sha256,
            ),
            self._finding(
                challenge_id="different-challenge",
                status=ChallengeStatus.RESOLVED,
                resolution=receipt.resolution,
                resolution_receipt_hash=receipt_record.sha256,
            ),
            self._finding(
                severity=ChallengeSeverity.MINOR,
                status=ChallengeStatus.RESOLVED,
                resolution=receipt.resolution,
                resolution_receipt_hash=receipt_record.sha256,
            ),
            self._finding(
                attack="A flipped attack procedure.",
                status=ChallengeStatus.RESOLVED,
                resolution=receipt.resolution,
                resolution_receipt_hash=receipt_record.sha256,
            ),
            self._finding(
                status=ChallengeStatus.RESOLVED,
                resolution="Flipped resolution text.",
                resolution_receipt_hash=receipt_record.sha256,
            ),
        )
        for finding in substitutions:
            with self.subTest(finding=finding), self.assertRaises(ValidationError):
                register_challenge_finding(self.registry, finding)

        cases = (
            (
                "wrong-role",
                Role.ADVERSARIAL_REVIEWER,
                "challenger_finding_resolution_receipt",
                correct_parents,
            ),
            (
                "wrong-type",
                Role.CLAIM_VERIFIER,
                "not_a_resolution_receipt",
                correct_parents,
            ),
            (
                "wrong-parents",
                Role.CLAIM_VERIFIER,
                "challenger_finding_resolution_receipt",
                tuple(reversed(correct_parents)),
            ),
        )
        for label, role, logical_type, parents in cases:
            wrong = self.registry.put_json(
                receipt.to_dict() | {"receipt_id": f"resolution-{label}"},
                logical_type=logical_type,
                origin=(
                    "source-owned deterministic alternative-explanation resolution"
                ),
                creator_role=role,
                creation_command=(
                    "scientist-one",
                    "resolve-alternative-explanation",
                ),
                parent_artifacts=parents,
                schema_version="2.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.subTest(label=label), self.assertRaises(ValidationError):
                register_challenge_finding(
                    self.registry,
                    self._finding(
                        status=ChallengeStatus.RESOLVED,
                        resolution=receipt.resolution,
                        resolution_receipt_hash=wrong.sha256,
                    ),
                )

    def test_human_gate_rejects_literal_bool_and_shallow_authority(self) -> None:
        policy = HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS)
        with self.assertRaises(TypeError):
            policy.evaluate(  # type: ignore[call-arg]
                self.registry,
                HumanGate.RESEARCH_QUESTION,
                scientific_gate_passed=True,
                expected_object_id="brief-fixture",
            )
        fake = self._evidence(
            "fake-research-brief",
            logical_type="research_brief",
            creator_role=Role.PROBLEM_INVESTIGATOR,
            payload={
                "research_brief": {
                    "brief_id": "brief-fixture",
                    "assessment": {"outcome": "PROCEED"},
                }
            },
        )
        with self.assertRaises(ValidationError):
            policy.evaluate(
                self.registry,
                HumanGate.RESEARCH_QUESTION,
                scientific_authority_hash=fake.sha256,
                expected_object_id="brief-fixture",
                ledger=self.ledger,
                expected_run_id="run-soundness-gates",
            )

    def test_every_human_gate_fails_closed_without_or_with_wrong_authority(
        self,
    ) -> None:
        policy = HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS)
        wrong = self._evidence("wrong-human-gate-authority")
        for gate in HumanGate:
            with self.subTest(gate=gate):
                blocked = policy.evaluate(
                    self.registry,
                    gate,
                    scientific_authority_hash=None,
                    expected_object_id="gate-object",
                )
                self.assertIs(
                    blocked.outcome,
                    AuthorizationOutcome.BLOCKED_SCIENTIFICALLY,
                )
                self.assertFalse(blocked.scientific_gate_passed)
                with self.assertRaises(ValidationError):
                    policy.evaluate(
                        self.registry,
                        gate,
                        scientific_authority_hash=wrong.sha256,
                        expected_object_id="gate-object",
                        ledger=self.ledger,
                        expected_run_id="run-soundness-gates",
                    )

    def test_confirmation_reveal_rejects_role_labeled_receipt_forgery(self) -> None:
        forged = self._evidence(
            "forged-confirmation-reveal-gate",
            logical_type="confirmation_reveal_gate_receipt",
            creator_role=Role.CLAIM_VERIFIER,
            payload={
                "run_id": "run-soundness-gates",
                "object_id": "confirmation-reveal-object",
                "evidence_class": "SCIENTIFIC_EVIDENCE",
                "verification_status": "VERIFIED_INDEPENDENT_CUSTODY",
                "scientific_gate_passed": True,
            },
        )
        with self.assertRaises(ValidationError):
            HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS).evaluate(
                self.registry,
                HumanGate.CONFIRMATION_REVEAL,
                scientific_authority_hash=forged.sha256,
                expected_object_id="confirmation-reveal-object",
                ledger=self.ledger,
                expected_run_id="run-soundness-gates",
            )

    def test_contract_freeze_rejects_role_labeled_receipt_forgery(self) -> None:
        forged = self._evidence(
            "forged-contract-freeze-gate",
            logical_type="evaluation_contract_freeze_gate_receipt",
            creator_role=Role.CLAIM_VERIFIER,
            payload={
                "run_id": "run-soundness-gates",
                "object_id": "evaluation-contract-object",
                "freeze_scope": "DESIGN_FREEZE_VALIDITY_ONLY",
                "design_frozen_before_execution": True,
                "result_validity_authorized": False,
                "scientific_gate_passed": True,
            },
        )
        with self.assertRaises(ValidationError):
            HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS).evaluate(
                self.registry,
                HumanGate.EVALUATION_CONTRACT_FREEZE,
                scientific_authority_hash=forged.sha256,
                expected_object_id="evaluation-contract-object",
                ledger=self.ledger,
                expected_run_id="run-soundness-gates",
            )

    def test_compute_escalation_plan_authority_is_exact_but_execution_untested(
        self,
    ) -> None:
        local, cloud, escalation, plan, budget = self._compute_escalation_inputs()
        record = register_compute_escalation_plan_authority(
            self.registry,
            self.ledger,
            authority_id="compute-escalation-plan-authority",
            run_id="run-soundness-gates",
            local_spec=local,
            cloud_spec=cloud,
            decision=escalation,
            submission_plan=plan,
            budget=budget,
            human_gate_policy=HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS),
        )
        authority = require_compute_escalation_plan_authority(
            self.registry,
            self.ledger,
            authority_artifact_sha256=record.sha256,
            expected_run_id="run-soundness-gates",
            expected_decision_id=escalation.decision_id,
        )
        self.assertTrue(authority.scientific_gate_passed)
        self.assertIs(authority.external_validation, ValidationStatus.UNTESTED)
        self.assertFalse(authority.live_gpu_availability_verified)
        self.assertFalse(authority.gpu_execution_validated)
        decision = AutonomousDecisionRecord(
            decision_id="authorize-compute-escalation-plan",
            gate=HumanGate.COMPUTE_ESCALATION,
            scientific_authority_hash=record.sha256,
            alternatives=("continue-local", "stop-experiment"),
            evidence_hashes=(record.sha256,),
            governing_rule="Escalate only an equivalent plan within frozen budget.",
            uncertainty="GPU availability and execution remain externally untested.",
            reason="The exact plan passed protocol and budget replay.",
            downstream_consequences=(
                "A separate backend boundary must validate any execution.",
            ),
        )
        authorization = HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS).evaluate(
            self.registry,
            HumanGate.COMPUTE_ESCALATION,
            scientific_authority_hash=record.sha256,
            expected_object_id=escalation.decision_id,
            ledger=self.ledger,
            expected_run_id="run-soundness-gates",
            autonomous_decision=decision,
        )
        self.assertIs(
            authorization.outcome,
            AuthorizationOutcome.AUTHORIZED_AUTONOMOUSLY,
        )
        self.assertTrue(authorization.scientific_gate_passed)

    def test_compute_escalation_rejects_budget_science_and_source_substitution(
        self,
    ) -> None:
        local, cloud, escalation, plan, budget = self._compute_escalation_inputs()
        with self.assertRaises(ValidationError):
            register_compute_escalation_plan_authority(
                self.registry,
                self.ledger,
                authority_id="over-budget-compute-escalation",
                run_id="run-soundness-gates",
                local_spec=local,
                cloud_spec=cloud,
                decision=escalation,
                submission_plan=plan,
                budget=replace(budget, maximum_monetary_cost=1.0),
            )
        with self.assertRaises(ValidationError):
            register_compute_escalation_plan_authority(
                self.registry,
                self.ledger,
                authority_id="changed-science-compute-escalation",
                run_id="run-soundness-gates",
                local_spec=local,
                cloud_spec=replace(
                    cloud,
                    evaluator_sha256=hashlib.sha256(
                        b"substituted-evaluator"
                    ).hexdigest(),
                ),
                decision=escalation,
                submission_plan=plan,
                budget=budget,
            )
        mismatched_information_decision = replace(
            escalation,
            expected_information_gain=(escalation.expected_information_gain + 1.0),
        )
        with self.assertRaises(ValidationError):
            register_compute_escalation_plan_authority(
                self.registry,
                self.ledger,
                authority_id="mismatched-information-compute-escalation",
                run_id="run-soundness-gates",
                local_spec=local,
                cloud_spec=cloud,
                decision=mismatched_information_decision,
                submission_plan=make_gpu_cloud_submission_plan(
                    local,
                    cloud,
                    mismatched_information_decision,
                    budget,
                ),
                budget=budget,
            )

        record = register_compute_escalation_plan_authority(
            self.registry,
            self.ledger,
            authority_id="valid-compute-escalation-for-forgery",
            run_id="run-soundness-gates",
            local_spec=local,
            cloud_spec=cloud,
            decision=escalation,
            submission_plan=plan,
            budget=budget,
        )
        authority = require_compute_escalation_plan_authority(
            self.registry,
            self.ledger,
            authority_artifact_sha256=record.sha256,
            expected_run_id="run-soundness-gates",
            expected_decision_id=escalation.decision_id,
        )
        forged_value = authority.to_dict()
        forged_value["authority_id"] = "substituted-compute-source-authority"
        forged_value["submission_plan_artifact_sha256"] = self.dimension_evidence.sha256
        forged_parents = (
            *authority.input_artifact_hashes[:-1],
            self.dimension_evidence.sha256,
        )
        forged = self.registry.put_json(
            forged_value,
            logical_type="compute_escalation_plan_authority",
            origin="fresh registry-and-ledger compute-escalation plan verification",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "verify-compute-escalation-plan"),
            parent_artifacts=forged_parents,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaises(ValidationError):
            require_compute_escalation_plan_authority(
                self.registry,
                self.ledger,
                authority_artifact_sha256=forged.sha256,
                expected_run_id="run-soundness-gates",
                expected_decision_id=escalation.decision_id,
            )
        with self.assertRaises(ValidationError):
            require_compute_escalation_plan_authority(
                self.registry,
                self.ledger,
                authority_artifact_sha256=record.sha256,
                expected_run_id="wrong-run",
                expected_decision_id=escalation.decision_id,
            )

    def test_compute_escalation_rejects_corrected_plan_checkpoint(self) -> None:
        local, cloud, escalation, plan, budget = self._compute_escalation_inputs()
        record = register_compute_escalation_plan_authority(
            self.registry,
            self.ledger,
            authority_id="corrected-compute-escalation-plan",
            run_id="run-soundness-gates",
            local_spec=local,
            cloud_spec=cloud,
            decision=escalation,
            submission_plan=plan,
            budget=budget,
        )
        authority = require_compute_escalation_plan_authority(
            self.registry,
            self.ledger,
            authority_artifact_sha256=record.sha256,
            expected_run_id="run-soundness-gates",
            expected_decision_id=escalation.decision_id,
        )
        self.ledger.append_correction(
            authority.ledger_event_id,
            actor_role=Role.SCIENTIFIC_REVIEWER,
            reason="Withdraw the compute-escalation plan authority.",
            corrected_fields={"authority": "WITHDRAWN"},
        )
        with self.assertRaises(ValidationError):
            require_compute_escalation_plan_authority(
                self.registry,
                self.ledger,
                authority_artifact_sha256=record.sha256,
                expected_run_id="run-soundness-gates",
                expected_decision_id=escalation.decision_id,
            )

    def test_compute_escalation_rejects_retrospective_plan_authority(self) -> None:
        local, cloud, escalation, plan, budget = self._compute_escalation_inputs()
        self.registry.put_bytes(
            canonical_json_bytes(plan.to_dict()),
            logical_type="gpu_cloud_submission_plan",
            origin="already-submitted-gpu-plan",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "gpu-cloud-submit"),
            parent_artifacts=(),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "cannot be created after GPU execution",
        ):
            register_compute_escalation_plan_authority(
                self.registry,
                self.ledger,
                authority_id="retrospective-compute-escalation-plan",
                run_id="run-soundness-gates",
                local_spec=local,
                cloud_spec=cloud,
                decision=escalation,
                submission_plan=plan,
                budget=budget,
            )

    def test_compute_escalation_registrar_cannot_reopen_after_execution(self) -> None:
        local, cloud, escalation, plan, budget = self._compute_escalation_inputs()
        record = register_compute_escalation_plan_authority(
            self.registry,
            self.ledger,
            authority_id="prospective-compute-plan-before-execution",
            run_id="run-soundness-gates",
            local_spec=local,
            cloud_spec=cloud,
            decision=escalation,
            submission_plan=plan,
            budget=budget,
        )
        self.assertTrue(self.registry.verify(record.sha256))
        self.registry.put_bytes(
            canonical_json_bytes(plan.to_dict()),
            logical_type="gpu_cloud_submission_plan",
            origin="subsequent-gpu-plan",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "gpu-cloud-submit"),
            parent_artifacts=(),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "cannot be created after GPU execution",
        ):
            register_compute_escalation_plan_authority(
                self.registry,
                self.ledger,
                authority_id="prospective-compute-plan-before-execution",
                run_id="run-soundness-gates",
                local_spec=local,
                cloud_spec=cloud,
                decision=escalation,
                submission_plan=plan,
                budget=budget,
            )
        self.assertEqual(
            require_compute_escalation_plan_authority(
                self.registry,
                self.ledger,
                authority_artifact_sha256=record.sha256,
                expected_run_id="run-soundness-gates",
                expected_decision_id=escalation.decision_id,
            ).authority_id,
            safe_json_loads(self.registry.get_bytes(record.sha256))["authority_id"],
        )

    def test_soundness_human_gate_freshly_rederives_and_blocks_incomplete(self) -> None:
        assessment = self._assessment("human-soundness-incomplete")
        authority = register_scientific_soundness_assessment(
            self.registry,
            assessment,
        )
        self.assertEqual(
            require_scientific_soundness_assessment(
                self.registry,
                assessment_artifact_hash=authority.sha256,
                expected_assessment_id=assessment.assessment_id,
            ),
            assessment,
        )
        result = HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS).evaluate(
            self.registry,
            HumanGate.SOUNDNESS_PROMOTION,
            scientific_authority_hash=authority.sha256,
            expected_object_id=assessment.assessment_id,
        )
        self.assertEqual(result.outcome, AuthorizationOutcome.BLOCKED_SCIENTIFICALLY)
        self.assertFalse(result.scientific_gate_passed)

    def test_forged_assessment_is_rejected_before_registration(self) -> None:
        assessment = self._assessment("forged-registration-source")
        forged_dimensions = tuple(
            (
                dimension,
                (
                    DimensionStatus.FAIL
                    if dimension is SoundnessDimension.TECHNICAL_CORRECTNESS
                    else status
                ),
            )
            for dimension, status in assessment.dimensions
        )
        forged = self._forge_assessment(
            assessment,
            dimensions=forged_dimensions,
            verdict=SoundnessVerdict.MAJOR_REVISION,
        )
        before = tuple(self.registry.list_records())
        with self.assertRaisesRegex(
            ValidationError,
            "registration differs from fresh derivation",
        ):
            register_scientific_soundness_assessment(self.registry, forged)
        self.assertEqual(tuple(self.registry.list_records()), before)

    def test_autonomous_decision_must_bind_exact_scientific_authority(self) -> None:
        with self.assertRaises(ValidationError):
            AutonomousDecisionRecord(
                decision_id="decision-unbound",
                gate=HumanGate.SOUNDNESS_PROMOTION,
                scientific_authority_hash="a" * 64,
                alternatives=("continue",),
                evidence_hashes=("b" * 64,),
                governing_rule="Use exact scientific authority.",
                uncertainty="Incomplete external science.",
                reason="Attempt an unbound decision.",
                downstream_consequences=("Do not promote.",),
            )


if __name__ == "__main__":
    unittest.main()
