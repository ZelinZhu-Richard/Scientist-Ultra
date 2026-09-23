from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
import threading
import tempfile
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.bounded_mean_inference import (
    BOUNDED_MEAN_CONDITIONAL_SCOPE,
    BOUNDED_MEAN_DECISION_RULE_ID,
    BOUNDED_MEAN_INTERVAL_METHOD_ID,
    BOUNDED_MEAN_PROCEDURE_ID,
    BOUNDED_MEAN_PROFILE_ID,
    BOUNDED_MEAN_SCHEMA,
    BOUNDED_MEAN_SIGN_METHOD_ID,
    BOUNDED_MEAN_ZERO_P_METHOD_ID,
    BoundedMeanInferencePlan,
)
from scientist_one.dataset_statistical_use import (
    DATASET_BOUNDED_MEAN_PROMPT_TEMPLATE_ID,
    DATASET_STATISTICAL_USE_BOOTSTRAP_RESAMPLES,
    DATASET_STATISTICAL_USE_BOOTSTRAP_SEED,
    DATASET_STATISTICAL_USE_PROMPT_TEMPLATE_ID,
    DatasetSamplingEvidenceKind,
    DatasetSamplingSourceBinding,
    DatasetStatisticalPopulationScope,
    DatasetBoundedMeanStatisticalUseDeclaration,
    DatasetStatisticalUseDeclaration,
    DatasetStatisticalUseJudgmentRequest,
    DatasetStatisticalUseReview,
    DatasetStatisticalUseReviewOutcome,
    _AUTHORITY_KEYS,
    _BOUNDED_MEAN_AUTHORITY_KEYS,
    _BOUNDED_MEAN_PROPOSAL_KEYS,
    _ResolvedSamplingSource,
    _ResolvedSources,
    _authority_payload,
    _bounded_mean_contract_profile,
    _commit_dataset_statistical_use_publication,
    _inventory_dataset_statistical_use_review_attempt,
    _sampling_source_preflight_records,
    _sampling_source_records,
    _sampling_source_value,
    _validate_contract_profile,
    build_dataset_statistical_use_judgment_request,
    register_dataset_statistical_use_authority,
    register_dataset_statistical_use_proposal,
    require_dataset_statistical_use_proposal,
    require_dataset_statistical_use_review,
)
from scientist_one.errors import ValidationError
from scientist_one.execution_admissibility import (
    FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA,
    ScientificExecutionAdmissibilityPolicy,
)
from scientist_one.gates import JudgmentSubjectKind, SemanticJudgmentReceipt
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.providers import _text_descriptor
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    BOUNDED_MEAN_HYPOTHESIS_OUTCOME_ORDER,
    Hypothesis,
    HypothesisEvaluationPolicy,
    HypothesisRole,
    HypothesisStatus,
    HypothesisTiming,
    MetricDirection,
    MetricScope,
    MetricSpec,
    MetricUnit,
)


RUN_ID = "statistical-use-run"
STAMP_0 = "2026-09-05T12:00:00Z"
STAMP_1 = "2026-09-05T12:00:01Z"
CONFIGURATION_HASH = "c" * 64


class DatasetStatisticalUseTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.registry = ArtifactRegistry(self.root, f"runs/{RUN_ID}/registry")
        self.ledger = EventLedger(self.root, f"runs/{RUN_ID}/events.jsonl")

        self.raw = self._put(
            {"rows": [{"unit_id": "unit-1"}, {"unit_id": "unit-2"}]},
            logical_type="external_response_body",
            role=Role.EVIDENCE_CURATOR,
        )
        self.contract_record = self._put(
            {"contract_id": "contract-1"},
            logical_type="evaluation_contract",
            role=Role.PROTOCOL_DESIGNER,
        )
        self.dataset_record = self._put(
            {"dataset_id": "dataset-1"},
            logical_type="scientific_dataset_authority",
            role=Role.EVIDENCE_CURATOR,
            parents=(self.raw.sha256, self.contract_record.sha256),
        )
        self.split_record = self._put(
            {"split_id": "confirmatory-1"},
            logical_type="scientific_dataset_split_authority",
            role=Role.PROTOCOL_DESIGNER,
            parents=(self.dataset_record.sha256, self.contract_record.sha256),
            created_at=STAMP_1,
        )
        self.sampling_record = self._put(
            {
                "schema_version": "scientific-dataset-sampling-source/v1",
                "dataset_binding": {
                    "dataset_id": "dataset-1",
                    "dataset_version": "2026-09-05",
                    "dataset_authority_artifact_sha256": self.dataset_record.sha256,
                    "raw_data_sha256": self.raw.sha256,
                },
                "evidence_statements": [
                    {
                        "evidence_kind": kind.value,
                        "statement": (
                            "The source describes the eligible clinic population, "
                            "prospective collection process, and one independently "
                            "formed patient record without household clustering."
                        ),
                    }
                    for kind in DatasetSamplingEvidenceKind
                ],
            },
            logical_type="external_response_raw",
            role=Role.EVIDENCE_CURATOR,
            mime_type="application/octet-stream",
        )
        self.sampling_request_record = self._put(
            {
                "schema_version": "controlled-egress-request/v2",
                "kind": "REDACTED_EXTERNAL_REQUEST",
                "request_id": "sampling-source-request",
                "policy_id": "sampling-source-policy",
                "adapter_id": "sampling-source-adapter",
                "url": "https://publisher.example/sampling.json",
            },
            logical_type="external_request",
            role=Role.ORCHESTRATOR,
            parents=(
                self.dataset_record.sha256,
                self.raw.sha256,
                self.contract_record.sha256,
            ),
            schema_version="controlled-egress-request/v2",
        )
        self.sampling_receipt_record = self._put(
            {
                "schema_version": "controlled-egress-response/v2",
                "kind": "EXTERNAL_RESPONSE_RECEIPT",
                "request_id": "sampling-source-request",
            },
            logical_type="external_response_receipt",
            role=Role.EVIDENCE_CURATOR,
            parents=(self.sampling_request_record.sha256, self.sampling_record.sha256),
            schema_version="controlled-egress-response/v2",
        )
        self.sampling_authority_record = self._put(
            {
                "schema_version": "audited-transport-authority/v2",
                "request_id": "sampling-source-request",
            },
            logical_type="audited_transport_execution_authority",
            role=Role.EVIDENCE_CURATOR,
            parents=(self.sampling_receipt_record.sha256,),
            schema_version="audited-transport-authority/v2",
        )
        first = self.ledger.record(
            run_id=RUN_ID,
            actor_role=Role.EVIDENCE_CURATOR,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=(self.dataset_record.sha256,),
            code_version="fixture-code",
            configuration_hash=CONFIGURATION_HASH,
            reason="registered exact Dataset authority fixture",
            event_id="dataset-authority-fixture",
            timestamp=STAMP_0,
            event_type="CHECKPOINT",
        )
        split_event = self.ledger.record(
            run_id=RUN_ID,
            actor_role=Role.PROTOCOL_DESIGNER,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=(self.split_record.sha256,),
            code_version=first.code_version,
            configuration_hash=first.configuration_hash,
            reason="registered exact confirmatory split fixture",
            event_id="confirmatory-split-fixture",
            timestamp=STAMP_1,
            event_type="CHECKPOINT",
        )
        unit_ids = ("unit-1", "unit-2")
        unit_hashes = ("1" * 64, "2" * 64)
        statistical_plan = SimpleNamespace(
            primary_test="two-sided exact paired sign test with ties removed",
            alpha=0.05,
            effect_size="paired mean directional difference",
            confidence_interval="paired bootstrap 95 percent interval",
            resampling_unit="patient",
            comparison_family_size=1,
            multiplicity_correction="not applicable",
            minimum_effect=0.01,
            minimum_sample_size=2,
            power_or_sensitivity="The exact two-unit fixture is structurally bounded.",
        )
        seed_reporting = SimpleNamespace(
            seeds=(7, 11),
            regime=SimpleNamespace(value="ALL_SEEDS"),
            selection_defined_before_results=True,
            preserve_all_runs=True,
        )
        contract = SimpleNamespace(
            sha256="a" * 64,
            statistical_plan=statistical_plan,
            seed_reporting=seed_reporting,
            dataset=SimpleNamespace(
                dataset_id="dataset-1",
                confirmatory_split_id="confirmatory-1",
            ),
        )
        dataset_authority = SimpleNamespace(
            run_id=RUN_ID,
            dataset_id="dataset-1",
            version="2026-09-05",
            authority_artifact_hash=self.dataset_record.sha256,
            authority_record_hash=str(self.dataset_record.record_hash),
            raw_data_artifact_hash=self.raw.sha256,
            raw_data_record_hash=str(self.raw.record_hash),
            raw_data_sha256=self.raw.sha256,
            evaluation_contract_artifact_hash=self.contract_record.sha256,
            evaluation_contract_record_hash=str(self.contract_record.record_hash),
            ledger_event_index=0,
        )
        split = SimpleNamespace(
            run_id=RUN_ID,
            dataset_id="dataset-1",
            dataset_version="2026-09-05",
            split_id="confirmatory-1",
            unit_type="unit_id",
            member_unit_ids=unit_ids,
            member_unit_hashes=unit_hashes,
            partition_sha256="b" * 64,
            dataset_authority_artifact_hash=self.dataset_record.sha256,
            evaluation_contract_artifact_hash=self.contract_record.sha256,
            record_hash=str(self.split_record.record_hash),
            ledger_event_id=split_event.event_id,
            ledger_event_hash=str(split_event.event_hash),
            ledger_event_index=1,
        )
        plan_value = {
            "primary_test": statistical_plan.primary_test,
            "alpha": statistical_plan.alpha,
            "effect_size": statistical_plan.effect_size,
            "confidence_interval": statistical_plan.confidence_interval,
            "resampling_unit": statistical_plan.resampling_unit,
            "comparison_family_size": statistical_plan.comparison_family_size,
            "multiplicity_correction": statistical_plan.multiplicity_correction,
            "minimum_effect": statistical_plan.minimum_effect,
            "minimum_sample_size": statistical_plan.minimum_sample_size,
            "power_or_sensitivity": statistical_plan.power_or_sensitivity,
        }
        from scientist_one.security import canonical_json_bytes, sha256_bytes

        binding = DatasetSamplingSourceBinding(
            artifact_sha256=self.sampling_record.sha256,
            transport_authority_artifact_sha256=(self.sampling_authority_record.sha256),
            response_receipt_artifact_sha256=self.sampling_receipt_record.sha256,
            evidence_kinds=tuple(DatasetSamplingEvidenceKind),
        )
        resolved_sampling = _ResolvedSamplingSource(
            binding=binding,
            raw_record=self.sampling_record,
            transport_authority_record=self.sampling_authority_record,
            response_receipt_record=self.sampling_receipt_record,
            request_record=self.sampling_request_record,
            source_value={},
            request_id="sampling-source-request",
            policy_id="sampling-source-policy",
            adapter_id="sampling-source-adapter",
            source_url="https://publisher.example/sampling.json",
            transport_key_id="d" * 64,
            transport_event_id="sampling-source-event",
            transport_event_hash="e" * 64,
            transport_event_index=1,
        )
        self.sources = _ResolvedSources(
            dataset_authority=dataset_authority,
            dataset_authority_record=self.dataset_record,
            raw_data_record=self.raw,
            contract=contract,
            contract_record=self.contract_record,
            statistical_plan=plan_value,
            statistical_plan_sha256=sha256_bytes(canonical_json_bytes(plan_value)),
            split=split,
            split_record=self.split_record,
            sampling_sources=(resolved_sampling,),
        )
        self.declaration = DatasetStatisticalUseDeclaration(
            population_scope=(
                DatasetStatisticalPopulationScope.SUPERPOPULATION_OR_FUTURE_UNITS
            ),
            intended_population=(
                "Future eligible patients drawn from the same defined clinic population."
            ),
            sampling_frame=(
                "The clinic enrollment frame described in the retained publisher record."
            ),
            sampling_mechanism=(
                "Prospective one-record-per-patient enrollment under the published protocol."
            ),
            analysis_unit_definition=(
                "One exact confirmatory Dataset row keyed by a unique patient unit_id."
            ),
            independence_rationale=(
                "The source states that patients are enrolled once without household clusters."
            ),
            bootstrap_exchangeability_rationale=(
                "The declared frame and common collection protocol support row-level exchangeability."
            ),
            sign_exchangeability_rationale=(
                "The same prospective mechanism applies to each non-tied patient effect sign."
            ),
            sampling_sources=(binding,),
        )
        bounded_statistical_plan = SimpleNamespace(
            primary_test=BOUNDED_MEAN_ZERO_P_METHOD_ID,
            alpha=0.05,
            effect_size="paired mean directional difference",
            confidence_interval=BOUNDED_MEAN_INTERVAL_METHOD_ID,
            resampling_unit="unit_id",
            comparison_family_size=1,
            multiplicity_correction="not applicable",
            minimum_effect=0.1,
            minimum_sample_size=3,
            power_or_sensitivity=(
                "The exact two-row grid remains fixed and yields INCONCLUSIVE "
                "when its preregistered minimum of three is not met."
            ),
        )
        bounded_primary = Hypothesis(
            hypothesis_id="bounded-mean-primary",
            role=HypothesisRole.PRIMARY,
            statement="The candidate has a beneficial common-population mean row effect.",
            motivation="Test one prospectively frozen directional mean comparison.",
            prior_evidence_ids=("prior-evidence",),
            prediction="The bounded interval supports the frozen benefit margin.",
            falsification_condition="The bounded interval supports the frozen harm margin.",
            planned_experiment="bounded-mean-experiment",
            status=HypothesisStatus.UNTESTED,
            timing=HypothesisTiming.PRE_SPECIFIED,
        )
        bounded_policy = HypothesisEvaluationPolicy(
            policy_id="bounded-mean-primary-policy",
            hypothesis_id=bounded_primary.hypothesis_id,
            metric_id="micro-accuracy",
            meaningful_effect=0.1,
            falsification_effect=0.2,
            alpha=0.05,
            minimum_sample_size=3,
            rule_id=BOUNDED_MEAN_DECISION_RULE_ID,
            outcome_order=BOUNDED_MEAN_HYPOTHESIS_OUTCOME_ORDER,
        )
        bounded_metric = MetricSpec(
            metric_id="micro-accuracy",
            name="Exact micro accuracy",
            definition="Exact integer-label correctness averaged over Dataset rows.",
            direction=MetricDirection.HIGHER_IS_BETTER,
            unit=MetricUnit.FRACTION,
            scope=MetricScope.END_TO_END,
            aggregation="MICRO_EXAMPLE_MEAN",
        )
        bounded_contract = SimpleNamespace(
            sha256="9" * 64,
            statistical_plan=bounded_statistical_plan,
            seed_reporting=seed_reporting,
            dataset=contract.dataset,
            hypothesis_register=SimpleNamespace(primary=bounded_primary),
            primary_metric=bounded_metric,
            scientific_execution_admissibility_policy=(
                ScientificExecutionAdmissibilityPolicy()
            ),
            stopping_criteria=FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA,
            hypothesis_evaluation_policy=lambda hypothesis_id: (
                bounded_policy
                if hypothesis_id == bounded_primary.hypothesis_id
                else None
            ),
        )
        bounded_profile = _bounded_mean_contract_profile(bounded_contract, split)
        bounded_plan_value = {
            "primary_test": bounded_statistical_plan.primary_test,
            "alpha": bounded_statistical_plan.alpha,
            "effect_size": bounded_statistical_plan.effect_size,
            "confidence_interval": bounded_statistical_plan.confidence_interval,
            "resampling_unit": bounded_statistical_plan.resampling_unit,
            "comparison_family_size": (bounded_statistical_plan.comparison_family_size),
            "multiplicity_correction": (
                bounded_statistical_plan.multiplicity_correction
            ),
            "minimum_effect": bounded_statistical_plan.minimum_effect,
            "minimum_sample_size": bounded_statistical_plan.minimum_sample_size,
            "power_or_sensitivity": bounded_statistical_plan.power_or_sensitivity,
        }
        self.bounded_sources = replace(
            self.sources,
            contract=bounded_contract,
            statistical_plan=bounded_plan_value,
            statistical_plan_sha256=sha256_bytes(
                canonical_json_bytes(bounded_plan_value)
            ),
            bounded_mean_plan=bounded_profile["plan"],
            bounded_mean_hypothesis_id=bounded_profile["hypothesis_id"],
            bounded_mean_policy_id=bounded_profile["policy_id"],
            bounded_mean_policy_sha256=bounded_profile["policy_sha256"],
            bounded_mean_metric_id=bounded_profile["metric_id"],
            bounded_mean_metric_contract=bounded_profile["metric_contract"],
            bounded_mean_admissibility_policy=bounded_profile["admissibility_policy"],
        )
        self.bounded_declaration = DatasetBoundedMeanStatisticalUseDeclaration(
            population_scope=(
                DatasetStatisticalPopulationScope.SUPERPOPULATION_OR_FUTURE_UNITS
            ),
            intended_population=(
                "Future eligible patients drawn from the same defined clinic population."
            ),
            sampling_frame=(
                "The clinic enrollment frame described in the retained publisher record."
            ),
            sampling_mechanism=(
                "Prospective one-record-per-patient enrollment under the published protocol."
            ),
            analysis_unit_definition=(
                "One exact confirmatory Dataset row keyed by a unique patient unit_id."
            ),
            independence_rationale=(
                "The source states that patients are enrolled once without household clusters."
            ),
            common_population_rationale=(
                "Every eligible row follows the same clinic frame and prospective collection mechanism."
            ),
            fixed_conditioning_rationale=(
                "The comparison conditions, training data, models, seed order, and protocol are frozen."
            ),
            auxiliary_sign_exchangeability_rationale=(
                "The common prospective mechanism applies independently to every nonzero row sign."
            ),
            sampling_sources=(binding,),
        )

    def _put(
        self,
        value: object,
        *,
        logical_type: str,
        role: Role,
        parents: tuple[str, ...] = (),
        created_at: str = STAMP_0,
        schema_version: str = "1.0",
        mime_type: str = "application/json",
    ):
        return self.registry.put_json(
            value,
            logical_type=logical_type,
            origin=f"Dataset statistical-use fixture {logical_type}",
            creator_role=role,
            creation_command=("test", "dataset-statistical-use"),
            parent_artifacts=parents,
            schema_version=schema_version,
            mime_type=mime_type,
            validation_result="PASS",
            frozen=True,
            created_at=created_at,
        )

    def _review_request(
        self,
        *,
        extra_evidence_hashes: tuple[str, ...] = (),
    ) -> DatasetStatisticalUseJudgmentRequest:
        return DatasetStatisticalUseJudgmentRequest(
            invocation_id="dataset-statistical-use-review-fixture",
            subject_id="statistical-use-proposal-fixture",
            accepted_outcome="DATASET_STATISTICAL_USE_SUPPORTED:" + "a" * 64,
            evidence_hashes=(self.raw.sha256, *extra_evidence_hashes),
            context_hashes=(self.contract_record.sha256,),
            instructions="Review the exact statistical-use proposal and retained sources.",
            input_text='{"review":"statistical use"}',
            output_schema={
                "type": "object",
                "additionalProperties": False,
                "properties": {"outcome": {"type": "string"}},
                "required": ["outcome"],
            },
            prompt_template_id="scientific-dataset-statistical-use-review",
            prompt_template_version="1.0",
            prompt_template_hash="f" * 64,
            governing_rule="Only source-supported scoped assumptions may pass.",
        )

    def _put_review_exchange_controls(
        self,
        request: DatasetStatisticalUseJudgmentRequest,
        *,
        include_receipt: bool = True,
        receipt_outcome: str = "DATASET_STATISTICAL_USE_REJECTED:fixture",
        raw_invocation_identifiers: bool = False,
        include_transport_topology: bool = False,
    ):
        expected_inputs = (*request.evidence_hashes, *request.context_hashes)
        invocation_identifier = (
            request.invocation_id
            if raw_invocation_identifiers
            else _text_descriptor(request.invocation_id)
        )
        prompt_id = (
            request.prompt_template_id
            if raw_invocation_identifiers
            else _text_descriptor(request.prompt_template_id)
        )
        prompt_version = (
            request.prompt_template_version
            if raw_invocation_identifiers
            else _text_descriptor(request.prompt_template_version)
        )
        invocation = self.registry.put_json(
            {
                "schema_version": "1.0",
                "kind": "MODEL_INVOCATION",
                "invocation_id": invocation_identifier,
                "input_artifact_hashes": list(expected_inputs),
                "prompt_template": {
                    "id": prompt_id,
                    "version": prompt_version,
                    "sha256": request.prompt_template_hash,
                },
            },
            logical_type="model_invocation",
            origin="capability-oriented model invocation",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=expected_inputs,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        request_intent = self.registry.put_json(
            {
                "schema_version": "1.0",
                "kind": "MODEL_PROVIDER_REQUEST_INTENT",
                "invocation_artifact_sha256": invocation.sha256,
            },
            logical_type="model_provider_request_intent",
            origin="redacted model-provider request intent",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(invocation.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        provider_response_parents = (request_intent.sha256,)
        if include_transport_topology:
            # Inert topology only: Q<-T, C<-(Q,R), A<-C, P<-(R,C,A).
            # None of these stand-ins is an audited transport authority.
            gateway_request = self._put(
                {"scope": "NON_EVIDENTIARY_GATEWAY_REQUEST"},
                logical_type="non_evidentiary_inventory_gateway_request",
                role=Role.ORCHESTRATOR,
                parents=(request_intent.sha256,),
            )
            raw_response = self.registry.put_bytes(
                b"non-evidentiary raw response",
                logical_type="external_response_raw",
                origin="pure topology raw input",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("test", "inventory-topology"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/octet-stream",
                validation_result="PASS",
                frozen=True,
            )
            gateway_receipt = self._put(
                {"scope": "NON_EVIDENTIARY_GATEWAY_RECEIPT"},
                logical_type="non_evidentiary_inventory_gateway_receipt",
                role=Role.ORCHESTRATOR,
                parents=(gateway_request.sha256, raw_response.sha256),
            )
            endpoint = self._put(
                {"scope": "NON_EVIDENTIARY_TRANSPORT_ENDPOINT"},
                logical_type="non_evidentiary_inventory_transport_endpoint",
                role=Role.ORCHESTRATOR,
                parents=(gateway_receipt.sha256,),
            )
            provider_response_parents = (
                raw_response.sha256,
                gateway_receipt.sha256,
                endpoint.sha256,
            )
        provider_response = self.registry.put_json(
            {
                "schema_version": "1.0",
                "kind": "MODEL_PROVIDER_RESPONSE",
            },
            logical_type="model_provider_response",
            origin="strictly parsed model-provider response envelope",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=provider_response_parents,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        model_output = self.registry.put_json(
            {
                "schema_version": "1.0",
                "kind": "MODEL_OUTPUT",
                "invocation_id": request.invocation_id,
            },
            logical_type="model_output",
            origin="schema-validated advisory model output",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(invocation.sha256, provider_response.sha256),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        receipt = None
        if include_receipt:
            receipt = self.registry.put_json(
                {
                    "schema_version": "1.0",
                    "judgment_id": "statistical-use-judgment-fixture",
                    "invocation_id": request.invocation_id,
                    "evidence_hashes": list(request.evidence_hashes),
                    "context_hashes": list(request.context_hashes),
                    "outcome": receipt_outcome,
                },
                logical_type="scientific_semantic_judgment_receipt",
                origin=(
                    "content-bound scientific review of a captured advisory "
                    "model judgment"
                ),
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "record-semantic-judgment"),
                parent_artifacts=(
                    *expected_inputs,
                    invocation.sha256,
                    request_intent.sha256,
                    provider_response.sha256,
                    model_output.sha256,
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
        return invocation, request_intent, provider_response, model_output, receipt

    def _put_offline_provider_exchange(self, request):
        """Actual provider-shaped advisory capture, never scientific authority."""
        from tests.test_external_providers import (
            invocation,
            openai_envelope,
            openai_provider,
        )
        from scientist_one.providers import ModelRunStatus
        from scientist_one.security import canonical_json_bytes

        outcome = "DATASET_STATISTICAL_USE_REJECTED:fixture"
        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {"outcome": {"type": "string", "enum": [outcome]}},
            "required": ["outcome"],
        }
        provider, _transport = openai_provider(
            openai_envelope(canonical_json_bytes({"outcome": outcome})),
            registry=self.registry,
        )
        result = provider.invoke(
            invocation(
                invocation_id=request.invocation_id,
                input_artifact_hashes=(
                    *request.evidence_hashes,
                    *request.context_hashes,
                ),
                prompt_template_id=request.prompt_template_id,
                prompt_template_version=request.prompt_template_version,
                prompt_template_hash=request.prompt_template_hash,
                instructions=request.instructions,
                input_text=request.input_text,
                output_schema=schema,
            )
        )
        self.assertEqual(result.status, ModelRunStatus.COMPLETED)
        self.assertFalse(result.network_used)
        self.assertEqual(result.external_validation, "UNTESTED")
        self.assertIsNone(result.transport_execution_authority_artifact_sha256)
        records = {record.logical_type: record for record in result.artifacts}
        controls = tuple(
            records[name]
            for name in (
                "model_invocation",
                "model_provider_request_intent",
                "model_provider_response",
                "model_output",
            )
        )
        # This intentionally incomplete REJECTED view tests inventory only.
        # The ordinary scientific semantic owner must never accept this record.
        receipt = self.registry.put_json(
            {
                "schema_version": "1.0",
                "judgment_id": request.invocation_id,
                "invocation_id": request.invocation_id,
                "evidence_hashes": list(request.evidence_hashes),
                "context_hashes": list(request.context_hashes),
                "outcome": outcome,
                "fixture_scope": "NON_EVIDENTIARY_INVENTORY_ONLY",
            },
            logical_type="scientific_semantic_judgment_receipt",
            origin="content-bound scientific review of a captured advisory model judgment",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            creation_command=("test", "non-evidentiary-inventory"),
            parent_artifacts=tuple(record.sha256 for record in controls),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        return (*controls, receipt)

    def _resolve_sampling_binding(self, binding: DatasetSamplingSourceBinding):
        return _sampling_source_records(
            self.registry,
            self.ledger,
            (binding,),
            run_id=RUN_ID,
            dataset_id="dataset-1",
            dataset_version="2026-09-05",
            dataset_authority_record=self.dataset_record,
            raw_data_record=self.raw,
            contract_record=self.contract_record,
            raw_data_sha256=self.raw.sha256,
            dataset_authority_event_index=0,
            split_event_index=2,
            forbidden_hashes=frozenset(
                {
                    self.dataset_record.sha256,
                    self.raw.sha256,
                    self.contract_record.sha256,
                    self.split_record.sha256,
                }
            ),
        )

    def _register_proposal(self):
        with patch(
            "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
            return_value=self.sources,
        ):
            return register_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_id="statistical-use-proposal-1",
                dataset_authority_artifact_hash=self.dataset_record.sha256,
                evaluation_contract_artifact_hash=self.contract_record.sha256,
                confirmatory_split_authority_artifact_hash=self.split_record.sha256,
                declaration=self.declaration,
            )

    def _register_bounded_proposal(self):
        with patch(
            "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
            return_value=self.bounded_sources,
        ):
            return register_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_id="bounded-mean-statistical-use-proposal-1",
                dataset_authority_artifact_hash=self.dataset_record.sha256,
                evaluation_contract_artifact_hash=self.contract_record.sha256,
                confirmatory_split_authority_artifact_hash=self.split_record.sha256,
                declaration=self.bounded_declaration,
            )

    def test_proposal_checkpoint_binds_exact_units_seeds_and_distinct_estimands(
        self,
    ) -> None:
        proposal_record = self._register_proposal()
        with patch(
            "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
            return_value=self.sources,
        ):
            proposal = require_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_artifact_hash=proposal_record.sha256,
            )
            request = build_dataset_statistical_use_judgment_request(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_artifact_hash=proposal_record.sha256,
            )
        self.assertEqual(proposal.seed_order, (7, 11))
        self.assertEqual(proposal.member_unit_ids, ("unit-1", "unit-2"))
        self.assertIsNone(proposal.bounded_mean_plan)
        self.assertEqual(
            request.prompt_template_id,
            DATASET_STATISTICAL_USE_PROMPT_TEMPLATE_ID,
        )
        self.assertNotEqual(
            request.prompt_template_id, "scientific-dataset-usage-review"
        )
        self.assertIn("P(D > 0 | D != 0) = 0.5", request.input_text)
        self.assertIn("not H0: E[D] = 0", request.input_text)
        self.assertIn("E[D]", request.input_text)
        self.assertIn(str(DATASET_STATISTICAL_USE_BOOTSTRAP_SEED), request.input_text)
        self.assertIn(
            str(DATASET_STATISTICAL_USE_BOOTSTRAP_RESAMPLES), request.input_text
        )
        self.assertEqual(len(request.output_schema["properties"]["outcome"]["enum"]), 3)
        from scientist_one.security import safe_json_loads

        review_input = safe_json_loads(request.input_bytes)
        self.assertEqual(request.invocation_id, proposal.review_invocation_id)
        self.assertIs(
            review_input["source_custody_establishes_origin_not_truth"],
            True,
        )
        retained_by_hash = {
            item["artifact_sha256"]: item for item in review_input["source_artifacts"]
        }
        self.assertIs(retained_by_hash[self.raw.sha256]["content_retained"], False)
        for digest in (
            self.sampling_record.sha256,
            self.sampling_authority_record.sha256,
            self.sampling_receipt_record.sha256,
            self.sampling_request_record.sha256,
        ):
            self.assertIs(retained_by_hash[digest]["content_retained"], True)
            self.assertIn(digest, request.evidence_hashes)

    def test_bounded_mean_v2_proposal_is_distinct_and_keeps_subminimum_grid(
        self,
    ) -> None:
        proposal_record = self._register_bounded_proposal()
        with patch(
            "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
            return_value=self.bounded_sources,
        ):
            proposal = require_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_artifact_hash=proposal_record.sha256,
            )
            request = build_dataset_statistical_use_judgment_request(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_artifact_hash=proposal_record.sha256,
            )
        from scientist_one.security import safe_json_loads

        value = safe_json_loads(self.registry.get_bytes(proposal_record.sha256))
        self.assertIsInstance(value, dict)
        assert isinstance(value, dict)
        self.assertEqual(proposal_record.schema_version, "2.0")
        self.assertEqual(set(value), _BOUNDED_MEAN_PROPOSAL_KEYS)
        self.assertEqual(proposal.profile_id, BOUNDED_MEAN_PROFILE_ID)
        self.assertEqual(
            proposal.bounded_mean_plan, self.bounded_sources.bounded_mean_plan
        )
        self.assertEqual(proposal.bounded_mean_plan.minimum_unit_count, 3)
        self.assertEqual(len(proposal.member_unit_ids), 2)
        self.assertIs(value["minimum_unit_count_met_by_fixed_grid"], False)
        self.assertIs(value["additional_sampling_after_result_permitted"], False)
        self.assertEqual(value["procedure_id"], BOUNDED_MEAN_PROCEDURE_ID)
        self.assertEqual(value["interval_method_id"], BOUNDED_MEAN_INTERVAL_METHOD_ID)
        self.assertEqual(value["mean_zero_p_method_id"], BOUNDED_MEAN_ZERO_P_METHOD_ID)
        self.assertEqual(value["decision_rule_id"], BOUNDED_MEAN_DECISION_RULE_ID)
        self.assertEqual(value["numeric_result_schema"], BOUNDED_MEAN_SCHEMA)
        self.assertEqual(value["auxiliary_sign_method_id"], BOUNDED_MEAN_SIGN_METHOD_ID)
        self.assertEqual(value["conditional_scope"], BOUNDED_MEAN_CONDITIONAL_SCOPE)
        self.assertEqual(value["mean_estimand"], "E[D]")
        self.assertEqual(value["mean_zero_null"], "E[D]=0")
        self.assertEqual(value["confidence_interval_estimand"], "E[D]")
        self.assertEqual(value["auxiliary_sign_null"], "P(D>0 | D!=0)=1/2")
        self.assertEqual(value["support"], [-1.0, 1.0])
        for legacy_only in (
            "bootstrap_seed",
            "bootstrap_resamples",
            "bootstrap_exchangeability_assumption",
            "bootstrap_exchangeability_rationale",
            "tie_rule",
            "tie_tolerance",
        ):
            self.assertNotIn(legacy_only, value)
        self.assertEqual(
            request.prompt_template_id,
            DATASET_BOUNDED_MEAN_PROMPT_TEMPLATE_ID,
        )
        self.assertNotEqual(
            request.prompt_template_id,
            DATASET_STATISTICAL_USE_PROMPT_TEMPLATE_ID,
        )
        self.assertIn('"mean_zero_null":"E[D]=0"', request.input_text)
        self.assertIn("never permits post-result sampling", request.instructions)
        self.assertIn(
            "AUXILIARY_ONLY_NO_MEAN_DECISION_OR_JOINT_ERROR_CONTROL",
            request.input_text,
        )
        proposal_event = self.ledger.events()[-1]
        event_value = proposal_event.metadata["dataset_statistical_use_proposal"]
        self.assertEqual(
            event_value["schema_version"],
            "scientific-dataset-statistical-use-proposal-event/v2",
        )
        self.assertEqual(
            event_value["slot"]["schema_version"],
            "scientific-dataset-statistical-use-slot/v2",
        )

    def test_bounded_mean_contract_dispatch_uses_structured_source_fields(
        self,
    ) -> None:
        contract = self.bounded_sources.contract
        resolved = _bounded_mean_contract_profile(contract, self.sources.split)
        plan = resolved["plan"]
        self.assertIsInstance(plan, BoundedMeanInferencePlan)
        self.assertEqual(plan.minimum_unit_count, 3)
        self.assertEqual(plan.unit_ids, ("unit-1", "unit-2"))
        self.assertEqual(plan.seed_order, (7, 11))
        self.assertIs(
            resolved["metric_contract"]["post_execution_projection_still_required"],
            True,
        )
        self.assertEqual(
            resolved["metric_contract"]["required_projection_semantics"],
            "EXACT_INTEGER_LABEL_MATCH",
        )

        wrong_metric = SimpleNamespace(**vars(contract))
        wrong_metric.primary_metric = replace(
            contract.primary_metric,
            name="Micro accuracy",
            aggregation="MACRO_LABEL_MEAN",
        )
        with self.assertRaisesRegex(ValidationError, "micro-accuracy profile"):
            _bounded_mean_contract_profile(wrong_metric, self.sources.split)

        no_admissibility = SimpleNamespace(**vars(contract))
        no_admissibility.scientific_execution_admissibility_policy = None
        with self.assertRaisesRegex(ValidationError, "micro-accuracy profile"):
            _bounded_mean_contract_profile(no_admissibility, self.sources.split)

        wrong_multiplicity = SimpleNamespace(**vars(contract))
        wrong_multiplicity.statistical_plan = SimpleNamespace(
            **{
                **vars(contract.statistical_plan),
                "multiplicity_correction": "Not Applicable",
            }
        )
        with self.assertRaisesRegex(ValidationError, "micro-accuracy profile"):
            _bounded_mean_contract_profile(wrong_multiplicity, self.sources.split)

        wrong_alpha = SimpleNamespace(**vars(contract))
        wrong_alpha.hypothesis_evaluation_policy = lambda _hypothesis_id: replace(
            contract.hypothesis_evaluation_policy("bounded-mean-primary"),
            alpha=0.04,
        )
        with self.assertRaisesRegex(ValidationError, "micro-accuracy profile"):
            _bounded_mean_contract_profile(wrong_alpha, self.sources.split)

        wrong_primary = SimpleNamespace(**vars(contract))
        wrong_primary.hypothesis_register = SimpleNamespace(
            primary=replace(
                contract.hypothesis_register.primary, role=HypothesisRole.SECONDARY
            )
        )
        with self.assertRaisesRegex(ValidationError, "micro-accuracy profile"):
            _bounded_mean_contract_profile(wrong_primary, self.sources.split)

        legacy_contract = SimpleNamespace(**vars(self.sources.contract))
        legacy_contract.statistical_plan = SimpleNamespace(
            **{
                **vars(self.sources.contract.statistical_plan),
                "minimum_sample_size": 3,
            }
        )
        with self.assertRaisesRegex(ValidationError, "smaller than"):
            _validate_contract_profile(
                legacy_contract,
                self.sources.split,
                profile_id="INDEPENDENT_CONFIRMATORY_ROW_UNIT_FIXED_SEEDS_V1",
            )

    def test_bounded_mean_authority_projection_has_no_legacy_placeholders(
        self,
    ) -> None:
        proposal_record = self._register_bounded_proposal()
        with patch(
            "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
            return_value=self.bounded_sources,
        ):
            proposal = require_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_artifact_hash=proposal_record.sha256,
            )
        from scientist_one.security import safe_json_loads

        proposal_value = safe_json_loads(
            self.registry.get_bytes(proposal_record.sha256)
        )
        review = DatasetStatisticalUseReview(
            outcome=DatasetStatisticalUseReviewOutcome.SUPPORTED,
            outcome_token=(
                f"DATASET_STATISTICAL_USE_SUPPORTED:{proposal_record.sha256}"
            ),
            proposal_artifact_hash=proposal_record.sha256,
            semantic_judgment_artifact_hash="3" * 64,
            semantic_judgment_record_hash="4" * 64,
            invocation_id=proposal.review_invocation_id,
            invocation_artifact_hash="6" * 64,
            model_output_artifact_hash="7" * 64,
            semantic_transport_authority_artifact_hash="5" * 64,
            semantic_transport_event_id="semantic-review-fixture",
            semantic_transport_event_hash="8" * 64,
            semantic_transport_event_index=3,
            rationale="The source evidence supports the exact scoped assumptions.",
        )
        assert isinstance(proposal_value, dict)
        payload = _authority_payload(proposal, proposal_value, review)
        self.assertEqual(set(payload), _BOUNDED_MEAN_AUTHORITY_KEYS)
        self.assertEqual(
            payload["bounded_mean_plan"], proposal.bounded_mean_plan.to_dict()
        )
        self.assertIs(payload["metric_projection_execution_claimed"], False)
        self.assertIs(payload["mean_decision_uses_auxiliary_sign"], False)
        self.assertIs(payload["joint_mean_sign_error_control_claimed"], False)
        for legacy_only in (
            "bootstrap_seed",
            "bootstrap_resamples",
            "bootstrap_exchangeability_assumption",
            "tie_rule",
            "tie_tolerance",
        ):
            self.assertNotIn(legacy_only, payload)

    def test_bounded_mean_v2_proposal_reuses_paired_idempotent_slot(self) -> None:
        first = self._register_bounded_proposal()
        with patch(
            "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
            return_value=self.bounded_sources,
        ):
            repeated = register_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_id="bounded-mean-statistical-use-proposal-1",
                dataset_authority_artifact_hash=self.dataset_record.sha256,
                evaluation_contract_artifact_hash=self.contract_record.sha256,
                confirmatory_split_authority_artifact_hash=self.split_record.sha256,
                declaration=self.bounded_declaration,
            )
        self.assertEqual(repeated, first)
        self.assertEqual(
            len(
                tuple(
                    event
                    for event in self.ledger.events()
                    if "dataset_statistical_use_proposal" in event.metadata
                )
            ),
            1,
        )

    def test_registration_is_idempotent_and_recovers_orphaned_proposal(self) -> None:
        original_append = self.ledger._append_locked
        attempts = 0

        def fail_once(guard, build_event):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("simulated ledger interruption")
            return original_append(guard, build_event)

        with (
            patch(
                "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
                return_value=self.sources,
            ),
            patch.object(self.ledger, "_append_locked", side_effect=fail_once),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated ledger interruption"):
                register_dataset_statistical_use_proposal(
                    self.registry,
                    self.ledger,
                    run_id=RUN_ID,
                    proposal_id="statistical-use-proposal-1",
                    dataset_authority_artifact_hash=self.dataset_record.sha256,
                    evaluation_contract_artifact_hash=self.contract_record.sha256,
                    confirmatory_split_authority_artifact_hash=self.split_record.sha256,
                    declaration=self.declaration,
                )
            orphaned = tuple(
                record
                for record in self.registry.list_records()
                if record.logical_type == "scientific_dataset_statistical_use_proposal"
            )
            self.assertEqual(len(orphaned), 1)
            self.assertEqual(len(self.ledger.events()), 2)
            recovered = register_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_id="statistical-use-proposal-1",
                dataset_authority_artifact_hash=self.dataset_record.sha256,
                evaluation_contract_artifact_hash=self.contract_record.sha256,
                confirmatory_split_authority_artifact_hash=self.split_record.sha256,
                declaration=self.declaration,
            )
            repeated = register_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_id="statistical-use-proposal-1",
                dataset_authority_artifact_hash=self.dataset_record.sha256,
                evaluation_contract_artifact_hash=self.contract_record.sha256,
                confirmatory_split_authority_artifact_hash=self.split_record.sha256,
                declaration=self.declaration,
            )
        self.assertEqual(recovered, repeated)
        self.assertEqual(recovered, orphaned[0])
        self.assertEqual(len(self.ledger.events()), 3)

    def test_competing_proposal_publications_have_one_paired_winner(self) -> None:
        changed = DatasetStatisticalUseDeclaration(
            population_scope=self.declaration.population_scope,
            intended_population=(
                "Future eligible patients from a competing population definition."
            ),
            sampling_frame=self.declaration.sampling_frame,
            sampling_mechanism=self.declaration.sampling_mechanism,
            analysis_unit_definition=self.declaration.analysis_unit_definition,
            independence_rationale=self.declaration.independence_rationale,
            bootstrap_exchangeability_rationale=(
                self.declaration.bootstrap_exchangeability_rationale
            ),
            sign_exchangeability_rationale=(
                self.declaration.sign_exchangeability_rationale
            ),
            sampling_sources=self.declaration.sampling_sources,
        )
        barrier = threading.Barrier(2)

        def synchronized_commit(*args, **kwargs):
            barrier.wait(timeout=5)
            return _commit_dataset_statistical_use_publication(*args, **kwargs)

        def publish(proposal_id, declaration):
            try:
                return register_dataset_statistical_use_proposal(
                    self.registry,
                    self.ledger,
                    run_id=RUN_ID,
                    proposal_id=proposal_id,
                    dataset_authority_artifact_hash=self.dataset_record.sha256,
                    evaluation_contract_artifact_hash=self.contract_record.sha256,
                    confirmatory_split_authority_artifact_hash=self.split_record.sha256,
                    declaration=declaration,
                )
            except ValidationError as exc:
                return exc

        with (
            patch(
                "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
                return_value=self.sources,
            ),
            patch(
                "scientist_one.dataset_statistical_use._commit_dataset_statistical_use_publication",
                side_effect=synchronized_commit,
            ),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            results = tuple(
                executor.map(
                    lambda args: publish(*args),
                    (
                        ("statistical-use-proposal-a", self.declaration),
                        ("statistical-use-proposal-b", changed),
                    ),
                )
            )
        self.assertEqual(sum(not isinstance(item, Exception) for item in results), 1)
        self.assertEqual(sum(isinstance(item, ValidationError) for item in results), 1)
        proposal_records = tuple(
            record
            for record in self.registry.list_records()
            if record.logical_type == "scientific_dataset_statistical_use_proposal"
        )
        proposal_events = tuple(
            event
            for event in self.ledger.events()
            if "dataset_statistical_use_proposal" in event.metadata
        )
        self.assertEqual(len(proposal_records), 1)
        self.assertEqual(len(proposal_events), 1)

    def test_finite_split_scope_is_descriptive_only(self) -> None:
        finite = DatasetStatisticalUseDeclaration(
            population_scope=(
                DatasetStatisticalPopulationScope.FINITE_CONFIRMATORY_SPLIT_DESCRIPTIVE_ONLY
            ),
            intended_population=self.declaration.intended_population,
            sampling_frame=self.declaration.sampling_frame,
            sampling_mechanism=self.declaration.sampling_mechanism,
            analysis_unit_definition=self.declaration.analysis_unit_definition,
            independence_rationale=self.declaration.independence_rationale,
            bootstrap_exchangeability_rationale=(
                self.declaration.bootstrap_exchangeability_rationale
            ),
            sign_exchangeability_rationale=self.declaration.sign_exchangeability_rationale,
            sampling_sources=self.declaration.sampling_sources,
        )
        with self.assertRaisesRegex(ValidationError, "descriptive only"):
            register_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_id="finite-use-proposal",
                dataset_authority_artifact_hash=self.dataset_record.sha256,
                evaluation_contract_artifact_hash=self.contract_record.sha256,
                confirmatory_split_authority_artifact_hash=self.split_record.sha256,
                declaration=finite,
            )
        bounded_finite = replace(
            self.bounded_declaration,
            population_scope=(
                DatasetStatisticalPopulationScope.FINITE_CONFIRMATORY_SPLIT_DESCRIPTIVE_ONLY
            ),
        )
        with self.assertRaisesRegex(ValidationError, "descriptive only"):
            register_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_id="finite-bounded-mean-use-proposal",
                dataset_authority_artifact_hash=self.dataset_record.sha256,
                evaluation_contract_artifact_hash=self.contract_record.sha256,
                confirmatory_split_authority_artifact_hash=self.split_record.sha256,
                declaration=bounded_finite,
            )

    def test_proposal_cannot_be_created_after_a_matching_frozen_run_spec(self) -> None:
        self.registry.put_json(
            {"run_id": "execution-run", "contract": self.contract_record.sha256},
            logical_type="frozen_run_spec",
            origin="already frozen run-spec fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("test", "late-statistical-use"),
            parent_artifacts=(self.contract_record.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at="2026-09-05T12:00:02Z",
        )
        with (
            patch(
                "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
                return_value=self.sources,
            ),
            self.assertRaisesRegex(ValidationError, "precede FrozenRunSpec"),
        ):
            register_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_id="late-statistical-use-proposal",
                dataset_authority_artifact_hash=self.dataset_record.sha256,
                evaluation_contract_artifact_hash=self.contract_record.sha256,
                confirmatory_split_authority_artifact_hash=self.split_record.sha256,
                declaration=self.declaration,
            )

    def test_ids_only_sampling_profile_is_rejected_deterministically(self) -> None:
        ids_only = {
            "schema_version": "scientific-dataset-sampling-source/v1",
            "dataset_binding": {
                "dataset_id": "dataset-1",
                "dataset_version": "2026-09-05",
                "dataset_authority_artifact_sha256": self.dataset_record.sha256,
                "raw_data_sha256": self.raw.sha256,
            },
            "evidence_statements": [
                {
                    "evidence_kind": kind.value,
                    "statement": "dataset-1 unit-1 unit-2 hash identifiers only",
                }
                for kind in DatasetSamplingEvidenceKind
            ],
        }
        from scientist_one.security import canonical_json_bytes

        with self.assertRaisesRegex(ValidationError, "identifiers-only"):
            _sampling_source_value(
                canonical_json_bytes(ids_only),
                dataset_id="dataset-1",
                dataset_version="2026-09-05",
                dataset_authority_artifact_hash=self.dataset_record.sha256,
                raw_data_sha256=self.raw.sha256,
                evidence_kinds=tuple(DatasetSamplingEvidenceKind),
            )

    def test_arbitrary_curator_prose_cannot_satisfy_source_custody(self) -> None:
        prose = self._put(
            {
                "sampling_documentation": (
                    "A curator says each patient appears once and records have no "
                    "shared clusters, but this is not an audited source response."
                )
            },
            logical_type="external_response_body",
            role=Role.EVIDENCE_CURATOR,
        )
        binding = DatasetSamplingSourceBinding(
            artifact_sha256=prose.sha256,
            transport_authority_artifact_sha256=(self.sampling_authority_record.sha256),
            response_receipt_artifact_sha256=self.sampling_receipt_record.sha256,
            evidence_kinds=tuple(DatasetSamplingEvidenceKind),
        )
        with (
            patch(
                "scientist_one.external.require_audited_live_transport_execution"
            ) as owner,
            self.assertRaisesRegex(
                ValidationError, "audited external-acquisition metadata"
            ),
        ):
            self._resolve_sampling_binding(binding)
        owner.assert_not_called()

    def test_fake_acquisition_metadata_cannot_replace_gateway_trust_root(self) -> None:
        with self.assertRaisesRegex(
            ValidationError, "closed authenticated acquisition custody"
        ):
            self._resolve_sampling_binding(self.declaration.sampling_sources[0])

    def test_sampling_profile_must_bind_exact_dataset(self) -> None:
        from scientist_one.security import canonical_json_bytes

        valid = _sampling_source_value(
            self.registry.get_bytes(self.sampling_record.sha256),
            dataset_id="dataset-1",
            dataset_version="2026-09-05",
            dataset_authority_artifact_hash=self.dataset_record.sha256,
            raw_data_sha256=self.raw.sha256,
            evidence_kinds=tuple(
                sorted(DatasetSamplingEvidenceKind, key=lambda item: item.value)
            ),
        )
        self.assertEqual(
            valid["schema_version"],
            "scientific-dataset-sampling-source/v1",
        )
        value = dict(self.sources.sampling_sources[0].source_value)
        if not value:
            value = {
                "schema_version": "scientific-dataset-sampling-source/v1",
                "dataset_binding": {
                    "dataset_id": "another-dataset",
                    "dataset_version": "2026-09-05",
                    "dataset_authority_artifact_sha256": self.dataset_record.sha256,
                    "raw_data_sha256": self.raw.sha256,
                },
                "evidence_statements": [
                    {
                        "evidence_kind": kind.value,
                        "statement": (
                            "The publisher describes prospective patient enrollment "
                            "and one independent record for each eligible clinic unit."
                        ),
                    }
                    for kind in DatasetSamplingEvidenceKind
                ],
            }
        with self.assertRaisesRegex(ValidationError, "exact Dataset"):
            _sampling_source_value(
                canonical_json_bytes(value),
                dataset_id="dataset-1",
                dataset_version="2026-09-05",
                dataset_authority_artifact_hash=self.dataset_record.sha256,
                raw_data_sha256=self.raw.sha256,
                evidence_kinds=tuple(DatasetSamplingEvidenceKind),
            )

    def test_sampling_byte_limits_fail_before_source_body_reads(self) -> None:
        oversized_raw = self.registry.put_bytes(
            b"x" * (128 * 1024 + 1),
            logical_type="external_response_raw",
            origin="oversized sampling source fixture",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("test", "oversized-source"),
            schema_version="1.0",
            mime_type="application/octet-stream",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP_0,
        )
        oversized_binding = DatasetSamplingSourceBinding(
            artifact_sha256=oversized_raw.sha256,
            transport_authority_artifact_sha256=(self.sampling_authority_record.sha256),
            response_receipt_artifact_sha256=self.sampling_receipt_record.sha256,
            evidence_kinds=tuple(DatasetSamplingEvidenceKind),
        )
        with (
            patch.object(
                self.registry,
                "get_bytes",
                side_effect=AssertionError("source body was read before admission"),
            ),
            self.assertRaisesRegex(ValidationError, "bounded audited"),
        ):
            _sampling_source_preflight_records(
                self.registry,
                (oversized_binding,),
                forbidden_hashes=frozenset(),
            )

        expanding_authority = self._put(
            {"padding": "z" * (175 * 1024)},
            logical_type="audited_transport_execution_authority",
            role=Role.EVIDENCE_CURATOR,
            parents=(self.sampling_receipt_record.sha256,),
            schema_version="audited-transport-authority/v2",
        )
        expanding_binding = DatasetSamplingSourceBinding(
            artifact_sha256=self.sampling_record.sha256,
            transport_authority_artifact_sha256=expanding_authority.sha256,
            response_receipt_artifact_sha256=self.sampling_receipt_record.sha256,
            evidence_kinds=tuple(DatasetSamplingEvidenceKind),
        )
        with (
            patch.object(
                self.registry,
                "get_bytes",
                side_effect=AssertionError(
                    "source body was read before expansion check"
                ),
            ),
            self.assertRaisesRegex(ValidationError, "encoded evidence"),
        ):
            _sampling_source_preflight_records(
                self.registry,
                (expanding_binding,),
                forbidden_hashes=frozenset(),
            )

    def test_second_semantic_branch_cannot_replace_prospective_proposal(self) -> None:
        self._register_proposal()
        changed = DatasetStatisticalUseDeclaration(
            population_scope=self.declaration.population_scope,
            intended_population=(
                "A different future population that would change the inferential target."
            ),
            sampling_frame=self.declaration.sampling_frame,
            sampling_mechanism=self.declaration.sampling_mechanism,
            analysis_unit_definition=self.declaration.analysis_unit_definition,
            independence_rationale=self.declaration.independence_rationale,
            bootstrap_exchangeability_rationale=(
                self.declaration.bootstrap_exchangeability_rationale
            ),
            sign_exchangeability_rationale=self.declaration.sign_exchangeability_rationale,
            sampling_sources=self.declaration.sampling_sources,
        )
        with (
            patch(
                "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
                return_value=self.sources,
            ),
            self.assertRaisesRegex(ValidationError, "different branch"),
        ):
            register_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_id="statistical-use-proposal-1",
                dataset_authority_artifact_hash=self.dataset_record.sha256,
                evaluation_contract_artifact_hash=self.contract_record.sha256,
                confirmatory_split_authority_artifact_hash=self.split_record.sha256,
                declaration=changed,
            )

    def test_review_inventory_accepts_complete_rejected_outcome_neutrally(self) -> None:
        request = self._review_request()
        *_, receipt = self._put_review_exchange_controls(
            request,
            receipt_outcome="DATASET_STATISTICAL_USE_REJECTED:fixture",
        )
        assert receipt is not None
        inventory = _inventory_dataset_statistical_use_review_attempt(
            self.registry,
            self.registry.verify_all(raise_on_error=True).records,
            request=request,
            selected_receipt_artifact_hash=receipt.sha256,
        )
        self.assertEqual(inventory.semantic_receipt_record, receipt)

    def test_review_inventory_accepts_actual_offline_provider_descriptors(self) -> None:
        request = self._review_request()
        invocation, _, _, _, receipt = self._put_offline_provider_exchange(request)
        inventory = _inventory_dataset_statistical_use_review_attempt(
            self.registry,
            self.registry.verify_all(raise_on_error=True).records,
            request=request,
            selected_receipt_artifact_hash=receipt.sha256,
        )
        self.assertEqual(inventory.invocation_record, invocation)
        self.assertEqual(inventory.semantic_receipt_record, receipt)

    def test_review_inventory_keeps_internal_control_reuse_unsupported(self) -> None:
        request = self._review_request()
        _, _, response, output, receipt = self._put_offline_provider_exchange(request)
        later_request = replace(
            request,
            invocation_id="later-independent-review",
            evidence_hashes=(response.sha256, output.sha256, receipt.sha256),
        )
        self._put_offline_provider_exchange(later_request)
        with self.assertRaisesRegex(ValidationError, "another invocation identity"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
            )

    def test_review_inventory_separates_completed_endpoint_consumers(self) -> None:
        request = self._review_request()
        invocation, _, response, _, receipt = self._put_offline_provider_exchange(
            request
        )
        # A graph-only endpoint stand-in, deliberately not a transport authority.
        # No public scientific resolver accepts or returns this fixture record.
        endpoint = self._put(
            {"scope": "NON_EVIDENTIARY_ENDPOINT_TOPOLOGY_ONLY"},
            logical_type="non_evidentiary_inventory_endpoint",
            role=Role.ORCHESTRATOR,
            parents=(response.sha256,),
        )
        later_request = replace(
            request,
            invocation_id="later-endpoint-review",
            evidence_hashes=(receipt.sha256, endpoint.sha256),
        )
        *_, later_receipt = self._put_offline_provider_exchange(later_request)
        self.registry.put_bytes(
            b"non-evidentiary later result bytes",
            logical_type="non_evidentiary_downstream_bytes",
            origin="pure inventory topology control",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("test", "endpoint-reference"),
            parent_artifacts=(later_receipt.sha256,),
            schema_version="1.0",
            mime_type="application/octet-stream",
            validation_result="PASS",
            frozen=True,
        )
        inventory = _inventory_dataset_statistical_use_review_attempt(
            self.registry,
            self.registry.verify_all(raise_on_error=True).records,
            request=request,
            selected_receipt_artifact_hash=receipt.sha256,
            owner_replayed_transport_authority_artifact_hash=endpoint.sha256,
        )
        self.assertEqual(inventory.semantic_receipt_record, receipt)
        # A malformed descriptor retaining this exchange's SHA remains an
        # original-slot alias, even if it parents a completed endpoint only.
        self.registry.put_json(
            {
                "schema_version": "1.0",
                "kind": "MODEL_INVOCATION_TERMINAL_RECEIPT",
                "invocation_id": {
                    **_text_descriptor(request.invocation_id),
                    "size": 99999,
                },
                "terminal_state": "FAILED",
            },
            logical_type="model_terminal_receipt",
            origin="terminal model-provider invocation outcome",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(receipt.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ValidationError, "another invocation identity"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
                owner_replayed_transport_authority_artifact_hash=endpoint.sha256,
            )
        self.assertEqual(invocation.logical_type, "model_invocation")

    def test_review_inventory_rejects_abandoned_or_unpublished_attempt(self) -> None:
        request = self._review_request()
        invocation, *_ = self._put_review_exchange_controls(
            request,
            include_receipt=False,
        )
        with self.assertRaisesRegex(ValidationError, "semantic receipt custody"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash="a" * 64,
            )
        self.assertEqual(
            invocation.parent_artifacts,
            (*request.evidence_hashes, *request.context_hashes),
        )

    def test_review_inventory_endpoint_cut_retains_alternate_response_path(
        self,
    ) -> None:
        request = self._review_request()
        _, _, response, output, receipt = self._put_review_exchange_controls(
            request,
            include_transport_topology=True,
        )
        assert receipt is not None
        endpoint = next(
            record
            for record in self.registry.list_records()
            if record.logical_type == "non_evidentiary_inventory_transport_endpoint"
        )
        self.assertEqual(response.parent_artifacts[2], endpoint.sha256)
        self.assertEqual(endpoint.parent_artifacts, (response.parent_artifacts[1],))
        for parents in (
            (receipt.sha256,),
            (endpoint.sha256,),
            (receipt.sha256, endpoint.sha256),
        ):
            consumer = self._put(
                {
                    "scope": "NON_EVIDENTIARY_ENDPOINT_CONSUMER",
                    "parents": list(parents),
                },
                logical_type="non_evidentiary_endpoint_consumer",
                role=Role.ORCHESTRATOR,
                parents=parents,
            )
            self.registry.put_bytes(
                b"later bytes for " + consumer.sha256.encode("ascii"),
                logical_type="non_evidentiary_later_bytes",
                origin="pure topology consumer",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("test", "endpoint-consumer"),
                parent_artifacts=(consumer.sha256,),
                schema_version="1.0",
                mime_type="application/octet-stream",
                validation_result="PASS",
                frozen=True,
            )
            inventory = _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
                owner_replayed_transport_authority_artifact_hash=endpoint.sha256,
            )
            self.assertEqual(inventory.provider_response_record, response)
            self.assertEqual(inventory.model_output_record, output)
        self.registry.put_json(
            {
                "schema_version": "1.0",
                "judgment_id": "second-branch",
                "invocation_id": request.invocation_id,
                "evidence_hashes": list(request.evidence_hashes),
                "context_hashes": list(request.context_hashes),
                "outcome": "DATASET_STATISTICAL_USE_INSUFFICIENT_EVIDENCE:fixture",
            },
            logical_type="scientific_semantic_judgment_receipt",
            origin="content-bound scientific review of a captured advisory model judgment",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            creation_command=("test", "second-branch"),
            parent_artifacts=(receipt.sha256, endpoint.sha256),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ValidationError, "ambiguous semantic receipt"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
                owner_replayed_transport_authority_artifact_hash=endpoint.sha256,
            )

    def test_review_inventory_endpoint_cut_cannot_hide_binary_attempt(self) -> None:
        request = self._review_request()
        invocation, _, _, _, receipt = self._put_review_exchange_controls(
            request,
            include_transport_topology=True,
        )
        assert receipt is not None
        endpoint = next(
            record
            for record in self.registry.list_records()
            if record.logical_type == "non_evidentiary_inventory_transport_endpoint"
        )
        self.registry.put_bytes(
            b"renamed failed attempt",
            logical_type="renamed_control",
            origin="renamed origin",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("test", "renamed-attempt"),
            parent_artifacts=(invocation.sha256, endpoint.sha256, receipt.sha256),
            schema_version="1.0",
            mime_type="application/octet-stream",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ValidationError, "non-JSON attempt descendant"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
                owner_replayed_transport_authority_artifact_hash=endpoint.sha256,
            )

    def test_review_inventory_rejects_nonproducer_raw_invocation_identifiers(
        self,
    ) -> None:
        request = self._review_request()
        *_, receipt = self._put_review_exchange_controls(
            request,
            raw_invocation_identifiers=True,
        )
        assert receipt is not None
        with self.assertRaisesRegex(ValidationError, "invocation identity"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
            )

    def test_review_inventory_detects_descriptor_terminal_without_parent_link(
        self,
    ) -> None:
        request = self._review_request()
        *_, receipt = self._put_review_exchange_controls(request)
        assert receipt is not None
        self.registry.put_json(
            {
                "schema_version": "1.0",
                "kind": "MODEL_INVOCATION_TERMINAL_RECEIPT",
                "invocation_id": _text_descriptor(request.invocation_id),
                "terminal_state": "FAILED",
            },
            logical_type="model_terminal_receipt",
            origin="terminal model-provider invocation outcome",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ValidationError, "terminal attempt"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
            )

    def test_review_inventory_rejects_renamed_terminal_alias(self) -> None:
        request = self._review_request()
        invocation, *_rest = self._put_review_exchange_controls(request)
        terminal = self.registry.put_json(
            {
                "schema_version": "1.0",
                "kind": "MODEL_INVOCATION_TERMINAL_RECEIPT",
                "invocation_id": _text_descriptor(request.invocation_id),
                "terminal_state": "FAILED",
            },
            logical_type="renamed_terminal_alias",
            origin="terminal model-provider invocation outcome",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(invocation.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        receipt = _rest[-1]
        assert receipt is not None
        with self.assertRaisesRegex(ValidationError, "terminal attempt"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
            )
        self.assertEqual(terminal.logical_type, "renamed_terminal_alias")

    def test_review_inventory_ignores_unrelated_malformed_but_rejects_related(
        self,
    ) -> None:
        request = self._review_request()
        self.registry.put_bytes(
            b"{",
            logical_type="model_output",
            origin="schema-validated advisory model output",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        invocation, *_rest = self._put_review_exchange_controls(request)
        receipt = _rest[-1]
        assert receipt is not None
        _inventory_dataset_statistical_use_review_attempt(
            self.registry,
            self.registry.verify_all(raise_on_error=True).records,
            request=request,
            selected_receipt_artifact_hash=receipt.sha256,
        )

        self.registry.put_bytes(
            b"{x",
            logical_type="renamed_related_output",
            origin="schema-validated advisory model output",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(invocation.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ValidationError, "unreadable related custody"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
            )

    def test_review_inventory_rejects_related_invocation_with_wrong_mime(self) -> None:
        request = self._review_request()
        self.registry.put_bytes(
            b'{"kind":"MODEL_INVOCATION","fixture":"wrong-mime"}\n',
            logical_type="model_invocation",
            origin="capability-oriented model invocation",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(*request.evidence_hashes, *request.context_hashes),
            schema_version="1.0",
            mime_type="text/plain",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ValidationError, "invalid MIME"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash="a" * 64,
            )

    def test_review_inventory_rejects_related_output_with_wrong_mime(self) -> None:
        request = self._review_request()
        invocation, *_rest = self._put_review_exchange_controls(request)
        receipt = _rest[-1]
        assert receipt is not None
        self.registry.put_bytes(
            b'{"kind":"MODEL_OUTPUT","fixture":"wrong-mime"}\n',
            logical_type="renamed_output_control",
            origin="schema-validated advisory model output",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(invocation.sha256,),
            schema_version="1.0",
            mime_type="text/plain",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ValidationError, "non-JSON attempt descendant"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
            )

    def test_review_inventory_rejects_related_terminal_with_wrong_mime(self) -> None:
        request = self._review_request()
        invocation, *_rest = self._put_review_exchange_controls(request)
        receipt = _rest[-1]
        assert receipt is not None
        self.registry.put_bytes(
            b'{"kind":"MODEL_INVOCATION_TERMINAL_RECEIPT","fixture":"wrong-mime"}\n',
            logical_type="model_terminal_receipt",
            origin="terminal model-provider invocation outcome",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(invocation.sha256,),
            schema_version="1.0",
            mime_type="application/octet-stream",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ValidationError, "non-JSON attempt descendant"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
            )

    def test_review_inventory_rejects_double_renamed_binary_terminal(self) -> None:
        request = self._review_request()
        invocation, *_rest = self._put_review_exchange_controls(request)
        receipt = _rest[-1]
        assert receipt is not None
        self.registry.put_bytes(
            b'{"kind":"MODEL_INVOCATION_TERMINAL_RECEIPT","terminal_state":"FAILED"}',
            logical_type="renamed_control",
            origin="renamed origin",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(invocation.sha256,),
            schema_version="1.0",
            mime_type="application/octet-stream",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ValidationError, "non-JSON attempt descendant"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
            )

    def test_review_inventory_rejects_raw_response_alias_as_attempt_descendant(
        self,
    ) -> None:
        request = self._review_request()
        invocation, *_rest = self._put_review_exchange_controls(request)
        receipt = _rest[-1]
        assert receipt is not None
        self.registry.put_bytes(
            b'{"kind":"MODEL_OUTPUT","invocation_id":"renamed-attempt"}',
            logical_type="external_response_raw",
            origin="controlled external egress raw response",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(invocation.sha256,),
            schema_version="1.0",
            mime_type="application/octet-stream",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ValidationError, "non-JSON attempt descendant"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
            )

    def test_review_inventory_allows_gateway_binary_raw_response_input(self) -> None:
        raw_response = self.registry.put_bytes(
            b"\x00provider-response\xff",
            logical_type="external_response_raw",
            origin="controlled external egress raw response",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(),
            schema_version="1.0",
            mime_type="application/octet-stream",
            validation_result="PASS",
            frozen=True,
        )
        request = self._review_request(
            extra_evidence_hashes=(raw_response.sha256,),
        )
        *_, receipt = self._put_review_exchange_controls(request)
        assert receipt is not None
        inventory = _inventory_dataset_statistical_use_review_attempt(
            self.registry,
            self.registry.verify_all(raise_on_error=True).records,
            request=request,
            selected_receipt_artifact_hash=receipt.sha256,
        )
        self.assertEqual(inventory.semantic_receipt_record, receipt)

    def test_review_inventory_rejects_known_origin_control_without_kind(self) -> None:
        request = self._review_request()
        invocation, *_rest = self._put_review_exchange_controls(request)
        receipt = _rest[-1]
        assert receipt is not None
        self.registry.put_json(
            {
                "schema_version": "1.0",
                "invocation_id": request.invocation_id,
                "fixture": "missing-kind",
            },
            logical_type="renamed_output_control",
            origin="schema-validated advisory model output",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(invocation.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ValidationError, "kind is absent or substituted"):
            _inventory_dataset_statistical_use_review_attempt(
                self.registry,
                self.registry.verify_all(raise_on_error=True).records,
                request=request,
                selected_receipt_artifact_hash=receipt.sha256,
            )

    def test_review_inventory_allows_related_raw_json_without_control_descriptor(
        self,
    ) -> None:
        request = self._review_request()
        invocation, *_rest = self._put_review_exchange_controls(request)
        receipt = _rest[-1]
        assert receipt is not None
        self.registry.put_json(
            {"schema_version": "1.0", "provider_body": {"status": "ok"}},
            logical_type="external_response_projection_fixture",
            origin="untrusted provider JSON response fixture",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "controlled-egress"),
            parent_artifacts=(invocation.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        inventory = _inventory_dataset_statistical_use_review_attempt(
            self.registry,
            self.registry.verify_all(raise_on_error=True).records,
            request=request,
            selected_receipt_artifact_hash=receipt.sha256,
        )
        self.assertEqual(inventory.semantic_receipt_record, receipt)

    def test_dataset_license_receipt_is_categorically_not_statistical_authority(
        self,
    ) -> None:
        proposal_record = self._register_proposal()
        with patch(
            "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
            return_value=self.sources,
        ):
            request = build_dataset_statistical_use_judgment_request(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_artifact_hash=proposal_record.sha256,
            )
        invocation, request_intent, provider_response, model_output, _ = (
            self._put_review_exchange_controls(request, include_receipt=False)
        )
        instructions = self._put(
            {"instructions": "license"},
            logical_type="license_instructions_fixture",
            role=Role.ORCHESTRATOR,
        )
        judged_input = self._put(
            {"input": "license"},
            logical_type="license_input_fixture",
            role=Role.ORCHESTRATOR,
        )
        output_schema = self._put(
            {"schema": "license"},
            logical_type="license_schema_fixture",
            role=Role.ORCHESTRATOR,
        )
        receipt = SemanticJudgmentReceipt(
            judgment_id="license-review-fixture",
            subject_kind=JudgmentSubjectKind.DATASET_USAGE,
            subject_id=request.subject_id,
            outcome=f"DATASET_USAGE_ACCEPTED:{proposal_record.sha256}",
            evidence_hashes=request.evidence_hashes,
            context_hashes=request.context_hashes,
            instructions_artifact_hash=instructions.sha256,
            input_artifact_hash=judged_input.sha256,
            output_schema_artifact_hash=output_schema.sha256,
            invocation_artifact_hash=invocation.sha256,
            request_intent_artifact_hash=request_intent.sha256,
            provider_response_artifact_hash=provider_response.sha256,
            model_output_artifact_hash=model_output.sha256,
            invocation_id=request.invocation_id,
            provider_id="fixture-provider",
            provider_version="1.0",
            model="fixture-model",
            model_version="1.0",
            prompt_template_id="scientific-dataset-usage-review",
            prompt_template_version="2.0",
            prompt_template_hash="e" * 64,
            structured_output_sha256="f" * 64,
            reviewer_id="scientific-reviewer",
            reviewer_role=Role.SCIENTIFIC_REVIEWER,
            governing_rule="Review a public Dataset license, not statistical assumptions.",
            rationale="The public license applies to the captured Dataset bytes.",
        )
        receipt_record = self.registry.put_json(
            receipt.to_dict(),
            logical_type="scientific_semantic_judgment_receipt",
            origin="non-authoritative license receipt fixture",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            creation_command=("test", "license-receipt"),
            parent_artifacts=(
                *request.evidence_hashes,
                *request.context_hashes,
                *receipt.custody_artifact_hashes,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with (
            patch(
                "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
                return_value=self.sources,
            ),
            self.assertRaisesRegex(
                ValidationError, "license review authority cannot be reused"
            ),
        ):
            require_dataset_statistical_use_review(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_artifact_hash=proposal_record.sha256,
                semantic_judgment_artifact_hash=receipt_record.sha256,
            )

    def test_rejected_and_insufficient_reviews_never_mint_authority(self) -> None:
        proposal_record = self._register_proposal()
        proposal_event = self.ledger.events()[-1]
        for outcome in (
            DatasetStatisticalUseReviewOutcome.REJECTED,
            DatasetStatisticalUseReviewOutcome.INSUFFICIENT_EVIDENCE,
        ):
            with self.subTest(outcome=outcome):
                review = DatasetStatisticalUseReview(
                    outcome=outcome,
                    outcome_token=f"DATASET_STATISTICAL_USE_{outcome.value}:{proposal_record.sha256}",
                    proposal_artifact_hash=proposal_record.sha256,
                    semantic_judgment_artifact_hash="3" * 64,
                    semantic_judgment_record_hash="4" * 64,
                    invocation_id="dataset-statistical-use-review-fixture",
                    invocation_artifact_hash="6" * 64,
                    model_output_artifact_hash="7" * 64,
                    semantic_transport_authority_artifact_hash="5" * 64,
                    semantic_transport_event_id="semantic-review-fixture",
                    semantic_transport_event_hash=str(proposal_event.event_hash),
                    semantic_transport_event_index=2,
                    rationale="The retained sampling sources do not support every assumption.",
                )
                with (
                    patch(
                        "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
                        return_value=self.sources,
                    ),
                    patch(
                        "scientist_one.dataset_statistical_use.require_dataset_statistical_use_review",
                        return_value=review,
                    ),
                    self.assertRaisesRegex(ValidationError, "cannot mint authority"),
                ):
                    register_dataset_statistical_use_authority(
                        self.registry,
                        self.ledger,
                        run_id=RUN_ID,
                        proposal_artifact_hash=proposal_record.sha256,
                        semantic_judgment_artifact_hash="3" * 64,
                    )

    def test_authority_projection_binds_review_and_full_source_custody(self) -> None:
        proposal_record = self._register_proposal()
        with patch(
            "scientist_one.dataset_statistical_use._resolve_dataset_statistical_sources",
            return_value=self.sources,
        ):
            proposal = require_dataset_statistical_use_proposal(
                self.registry,
                self.ledger,
                run_id=RUN_ID,
                proposal_artifact_hash=proposal_record.sha256,
            )
        from scientist_one.security import safe_json_loads

        proposal_value = safe_json_loads(
            self.registry.get_bytes(proposal_record.sha256)
        )
        review = DatasetStatisticalUseReview(
            outcome=DatasetStatisticalUseReviewOutcome.SUPPORTED,
            outcome_token=(
                f"DATASET_STATISTICAL_USE_SUPPORTED:{proposal_record.sha256}"
            ),
            proposal_artifact_hash=proposal_record.sha256,
            semantic_judgment_artifact_hash="3" * 64,
            semantic_judgment_record_hash="4" * 64,
            invocation_id=proposal.review_invocation_id,
            invocation_artifact_hash="6" * 64,
            model_output_artifact_hash="7" * 64,
            semantic_transport_authority_artifact_hash="5" * 64,
            semantic_transport_event_id="semantic-review-fixture",
            semantic_transport_event_hash="8" * 64,
            semantic_transport_event_index=3,
            rationale="The source evidence supports the exact scoped assumptions.",
        )
        assert isinstance(proposal_value, dict)
        payload = _authority_payload(proposal, proposal_value, review)
        self.assertEqual(set(payload), _AUTHORITY_KEYS)
        self.assertEqual(payload["review_invocation_id"], proposal.review_invocation_id)
        self.assertEqual(
            payload["sampling_source_transport_authority_artifact_sha256s"],
            [self.sampling_authority_record.sha256],
        )
        self.assertEqual(
            payload["sampling_source_request_artifact_sha256s"],
            [self.sampling_request_record.sha256],
        )


if __name__ == "__main__":
    unittest.main()
