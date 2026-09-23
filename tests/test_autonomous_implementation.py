from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, replace
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scientist_one.autonomous_implementation as autonomous_module
import scientist_one.provider_verification as provider_verification_module
import scientist_one.provider_wire as provider_wire_module
from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.autonomous_implementation import (
    AdmissionStatus,
    AutonomousImplementationController,
    AutonomousImplementationError,
    ImplementationContext,
    PreparedImplementationRun,
    ReviewedWorkerTemplate,
    create_reviewed_catalog,
    template_review_payload,
)
from scientist_one.external import (
    AUDITED_LIVE_TRANSPORT_AUTHORITY,
    AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
    AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
    AuditedTransportExecutionAuthority,
    EgressGateway,
    EgressPolicyError,
    EgressRequest,
    FixtureTransport,
    TransportResponse,
    UNVERIFIED_TRANSPORT_AUTHORITY,
)
from scientist_one.experiments import (
    ExecutionResult,
    ExperimentIntegrityError,
    LocalMacBackend,
    LocalMacExecutionMode,
    NetworkUseStatus,
    RunState,
)
from scientist_one.ledger import EventLedger
from scientist_one.providers import (
    ModelCapability,
    ModelInvocation,
    ModelProviderError,
    ModelResult,
    ModelRunStatus,
    OpenAIResponsesConfig,
    OpenAIResponsesProvider,
    openai_responses_policy,
)
from scientist_one.provider_verification import (
    DETERMINISTIC_FIXTURE_PROVIDER_ID,
    MODEL_PROVIDER_CUSTODY_SCHEMA_V1,
    OPENAI_PROVIDER_ID,
    ProviderExecutionProjection,
    ProviderVerificationError,
    require_provider_verifier,
)
from scientist_one.roles import Role
from scientist_one.research_state import (
    ComputeProfile as StateComputeProfile,
    Experiment as StateExperiment,
    Implementation as StateImplementation,
    MetricDirection as StateMetricDirection,
    Method as StateMethod,
    RecordStatus,
    Result as StateResult,
    Run as StateRun,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads
from tests.provider_fixtures import deterministic_provider_result


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class AutonomousImplementationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.registry = ArtifactRegistry(self.root, "runs/component/registry")
        reviews = {}
        for template in ReviewedWorkerTemplate:
            record = self.registry.put_json(
                template_review_payload(template),
                logical_type="autonomous_implementation.template_review",
                origin=f"fixture adversarial review of {template.value}",
                creator_role=Role.ADVERSARIAL_REVIEWER,
                creation_command=("scientist-one", "fixture-template-review"),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            reviews[template] = record.sha256
        self.catalog = create_reviewed_catalog(self.registry, reviews)
        self.data = self.registry.put_json(
            {"values": [1.0, 2.0, 3.0, 4.0]},
            logical_type="dataset.fixture_values",
            origin="deterministic autonomous implementation component fixture",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "create-component-fixture"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        self.evaluator = self.registry.put_json(
            {
                "metric": "template_defined_scalar",
                "metric_id": "metric-autonomous-template-scalar",
                "direction": "HIGHER_IS_BETTER",
            },
            logical_type="evaluator.fixture_scalar",
            origin="deterministic autonomous implementation evaluator fixture",
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("scientist-one", "create-component-evaluator"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        self.context = ImplementationContext(
            experiment_id="experiment-autonomous-component",
            hypothesis_id="hypothesis-autonomous-component",
            data_artifact_sha256=self.data.sha256,
            evaluator_artifact_sha256=self.evaluator.sha256,
            seeds=(3, 7),
        )
        self.controller = AutonomousImplementationController(self.registry, self.catalog)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invocation(
        self,
        identifier: str,
        *,
        input_hashes: tuple[str, ...] | None = None,
        output_schema: dict[str, object] | None = None,
        capability: ModelCapability = ModelCapability.CODING,
    ) -> ModelInvocation:
        return ModelInvocation(
            invocation_id=identifier,
            capability=capability,
            model="gpt-5",
            prompt_template_id="bounded-implementation-proposal",
            prompt_template_version="1.0",
            prompt_template_hash=digest("bounded-implementation-proposal-v1"),
            instructions="Select only a reviewed declarative experiment template.",
            input_text="Propose one bounded implementation from the supplied evidence.",
            output_schema=output_schema or self.catalog.proposal_schema(),
            input_artifact_hashes=input_hashes
            if input_hashes is not None
            else (self.data.sha256, self.evaluator.sha256),
            max_output_tokens=1024,
        )

    def proposal(
        self,
        identifier: str,
        template: ReviewedWorkerTemplate = ReviewedWorkerTemplate.AFFINE_MEAN_V1,
        *,
        evidence: tuple[str, ...] | None = None,
    ) -> dict[str, object]:
        parameters = (
            [{"name": "bias", "value": 1.0}, {"name": "scale", "value": 2.0}]
            if template is ReviewedWorkerTemplate.AFFINE_MEAN_V1
            else [
                {"name": "positive_weight", "value": 2.0},
                {"name": "threshold", "value": 3.0},
            ]
        )
        return {
            "schema_version": "AUTONOMOUS_IMPLEMENTATION_PROPOSAL_V1",
            "proposal_id": f"proposal-{identifier}",
            "implementation_id": f"implementation-{identifier}",
            "template_id": template.value,
            "parameters": parameters,
            "parent_evidence_sha256s": list(
                evidence
                if evidence is not None
                else (self.data.sha256, self.evaluator.sha256)
            ),
            "rationale": "Exercise a bounded deterministic component fixture.",
        }

    def result(
        self,
        invocation: ModelInvocation,
        output: dict[str, object],
        *,
        retry_once: bool = False,
    ) -> ModelResult:
        response = canonical_json_bytes(
            {
                "id": f"resp-{invocation.invocation_id}",
                "model": invocation.model,
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": canonical_json_bytes(output).decode("utf-8"),
                            }
                        ],
                    }
                ],
                "usage": {
                    "input_tokens": 17,
                    "input_tokens_details": {
                        "cached_tokens": 3,
                        "cache_write_tokens": 2,
                    },
                    "output_tokens": 11,
                    "output_tokens_details": {"reasoning_tokens": 4},
                    "total_tokens": 28,
                },
            }
        )
        successful_response = TransportResponse(
            200,
            (("Content-Type", "application/json"),),
            response,
            "https://api.openai.com/v1/responses",
        )
        responses = (
            (
                TransportResponse(
                    429,
                    (("Content-Type", "application/json"),),
                    b'{"error":"bounded fixture retry"}',
                    "https://api.openai.com/v1/responses",
                ),
                successful_response,
            )
            if retry_once
            else (successful_response,)
        )
        clock_values = iter(float(value) for value in range(16))
        gateway = EgressGateway(
            openai_responses_policy(
                maximum_requests=len(responses),
                maximum_attempts=len(responses),
            ),
            FixtureTransport(responses),
            registry=self.registry,
            secret_resolver=lambda _name: "component-fixture-credential",
            clock=lambda: next(clock_values),
            sleeper=lambda _seconds: None,
            timestamp=lambda: "2026-08-29T00:00:00.000000Z",
        )
        return OpenAIResponsesProvider(gateway).invoke(invocation)

    @staticmethod
    def captured_record(result: ModelResult, logical_type: str) -> ArtifactRecord:
        records = tuple(
            record for record in result.artifacts if record.logical_type == logical_type
        )
        if len(records) != 1:
            raise AssertionError(f"expected one {logical_type} record, found {len(records)}")
        return records[0]

    def replace_record(
        self,
        result: ModelResult,
        logical_type: str,
        replacement: ArtifactRecord,
    ) -> ModelResult:
        original = self.captured_record(result, logical_type)
        return replace(
            result,
            artifacts=tuple(
                replacement if record.sha256 == original.sha256 else record
                for record in result.artifacts
            ),
        )

    def altered_record(
        self,
        record: ArtifactRecord,
        marker: str,
        *,
        logical_type: str | None = None,
        creator_role: Role | None = None,
        validation_result: str | None = None,
        frozen: bool | None = None,
    ) -> ArtifactRecord:
        return self.registry.put_bytes(
            self.registry.get_bytes(record.sha256)
            + f"\ninvalid-metadata-fixture:{marker}".encode("utf-8"),
            logical_type=logical_type or record.logical_type,
            origin=f"adversarial altered provider record {marker}",
            creator_role=creator_role or record.creator_role,
            creation_command=("test", "alter-provider-record", marker),
            parent_artifacts=record.parent_artifacts,
            schema_version=record.schema_version,
            mime_type=record.mime_type,
            validation_result=(
                validation_result
                if validation_result is not None
                else record.validation_result
            ),
            frozen=frozen if frozen is not None else record.frozen,
        )

    def rewritten_json_record(
        self,
        record: ArtifactRecord,
        value: dict[str, object],
        *,
        parents: tuple[str, ...] | None = None,
    ) -> ArtifactRecord:
        return self.registry.put_json(
            value,
            logical_type=record.logical_type,
            origin=record.origin,
            creator_role=record.creator_role,
            creation_command=record.creation_command,
            parent_artifacts=(
                record.parent_artifacts if parents is None else parents
            ),
            schema_version=record.schema_version,
            mime_type=record.mime_type,
            validation_result=record.validation_result,
            frozen=record.frozen,
            created_at=record.created_at,
        )

    def forged_live_result(
        self,
        invocation: ModelInvocation,
        *,
        marker: str,
        claimed_run_id: str,
    ) -> ModelResult:
        """Clone a coherent live-looking graph without gateway authentication."""

        captured = self.result(invocation, self.proposal(marker))
        receipt_record = self.captured_record(
            captured,
            "external_response_receipt",
        )
        receipt = dict(
            safe_json_loads(self.registry.get_bytes(receipt_record.sha256))
        )
        receipt.update(
            {
                "network_used": True,
                "external_validation": (
                    "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                ),
                "transport_authority": AUDITED_LIVE_TRANSPORT_AUTHORITY,
            }
        )
        live_receipt = self.rewritten_json_record(receipt_record, receipt)
        authority = self.registry.put_json(
            {
                "schema_version": AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
                "kind": "AUDITED_TRANSPORT_EXECUTION_AUTHORITY",
                "run_id": claimed_run_id,
                "marker": marker,
            },
            logical_type=AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
            origin="gateway-signed audited HTTPS transport execution authority",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=(
                "scientist-one",
                "issue-audited-transport-execution-authority",
            ),
            parent_artifacts=(live_receipt.sha256,),
            schema_version=AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at="2026-08-29T00:00:00.000000Z",
        )

        provider_record = self.captured_record(captured, "model_provider_response")
        provider_response = dict(
            safe_json_loads(self.registry.get_bytes(provider_record.sha256))
        )
        provider_response.update(
            {
                "network_used": True,
                "external_validation": (
                    "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                ),
                "transport_authority": AUDITED_LIVE_TRANSPORT_AUTHORITY,
                "transport_execution_authority_artifact_sha256": (
                    authority.sha256
                ),
            }
        )
        raw_record = self.captured_record(captured, "external_response_raw")
        live_provider = self.rewritten_json_record(
            provider_record,
            provider_response,
            parents=(raw_record.sha256, live_receipt.sha256, authority.sha256),
        )

        output_record = self.captured_record(captured, "model_output")
        output = dict(
            safe_json_loads(self.registry.get_bytes(output_record.sha256))
        )
        output.update(
            {
                "network_used": True,
                "external_validation": (
                    "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
                ),
                "transport_authority": AUDITED_LIVE_TRANSPORT_AUTHORITY,
                "transport_execution_authority_artifact_sha256": (
                    authority.sha256
                ),
            }
        )
        live_output = self.rewritten_json_record(
            output_record,
            output,
            parents=(
                self.captured_record(captured, "model_invocation").sha256,
                self.captured_record(
                    captured,
                    "model_provider_request_body",
                ).sha256,
                live_provider.sha256,
            ),
        )
        replacements = {
            receipt_record.sha256: live_receipt,
            provider_record.sha256: live_provider,
            output_record.sha256: live_output,
        }
        return replace(
            captured,
            external_validation=(
                "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
            ),
            network_used=True,
            transport_authority=AUDITED_LIVE_TRANSPORT_AUTHORITY,
            transport_execution_authority_artifact_sha256=authority.sha256,
            artifacts=(
                *tuple(
                    replacements.get(record.sha256, record)
                    for record in captured.artifacts
                ),
                authority,
            ),
        )

    def live_verifier_projection(
        self,
        result: ModelResult,
        *,
        run_id: str,
    ) -> AuditedTransportExecutionAuthority:
        """Build only the public verifier's return projection for contract tests."""

        authority = self.captured_record(
            result,
            AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
        )
        receipt = self.captured_record(result, "external_response_receipt")
        request = self.captured_record(result, "external_request")
        raw = self.captured_record(result, "external_response_raw")
        response = safe_json_loads(self.registry.get_bytes(receipt.sha256))
        raw_bytes = self.registry.get_bytes(raw.sha256)
        return AuditedTransportExecutionAuthority(
            authority_artifact=authority,
            response_receipt_artifact=receipt,
            request_artifact=request,
            raw_response_artifact=raw,
            run_id=run_id,
            request_id=result.request_id or "",
            policy_id="openai-responses-v1",
            body_sha256=hashlib.sha256(raw_bytes).hexdigest(),
            body_size=len(raw_bytes),
            status_code=response["status_code"],
            content_type="application/json",
            ledger_prefix_head_hash=digest("ledger-prefix"),
            ledger_prefix_event_count=1,
            ledger_event_id="event-live-provider-authority",
            ledger_event_hash=digest("ledger-event"),
            key_id=digest("authority-key"),
        )

    def admit(
        self,
        identifier: str,
        template: ReviewedWorkerTemplate = ReviewedWorkerTemplate.AFFINE_MEAN_V1,
    ):
        invocation = self.invocation(f"invocation-{identifier}")
        return self.controller.admit_model_result(
            invocation,
            self.result(invocation, self.proposal(identifier, template)),
            self.context,
        )

    def test_two_declarative_variants_execute_only_as_admitted_frozen_local_runs(self) -> None:
        backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/python3",),
            observed_available_memory_bytes=2 * 1024**3,
        )
        expected = (
            (ReviewedWorkerTemplate.AFFINE_MEAN_V1, 6.0),
            (ReviewedWorkerTemplate.THRESHOLD_RATE_V1, 1.0),
        )
        code_hashes: set[str] = set()
        for index, (template, expected_metric) in enumerate(expected, start=1):
            with self.subTest(template=template.value):
                admission = self.admit(f"valid-{index}", template)
                self.assertEqual(admission.status, AdmissionStatus.ADMITTED)
                self.assertTrue(admission.admitted)
                self.assertIsNotNone(admission.implementation)
                implementation = admission.implementation
                assert implementation is not None
                self.assertEqual(
                    admission.provider_attempt_artifact,
                    implementation.provider_attempt_artifact,
                )
                self.assertEqual(
                    admission.provider_admission_link,
                    implementation.provider_admission_link,
                )
                self.assertEqual(
                    admission.actionable_proposal_artifact,
                    implementation.proposal_artifact,
                )
                self.assertEqual(
                    admission.action_validation_receipt,
                    implementation.validation_receipt,
                )
                self.assertNotEqual(
                    admission.provider_attempt_artifact,
                    admission.actionable_proposal_artifact,
                )
                self.assertNotEqual(
                    admission.provider_admission_link,
                    admission.action_validation_receipt,
                )
                code_hashes.add(implementation.worker_code_artifact.sha256)
                prepared = self.controller.prepare_local_run(
                    implementation,
                    run_id=f"run-autonomous-variant-{index}",
                )
                self.assertFalse(prepared.spec.network_allowed)
                self.assertFalse(prepared.spec.shell_allowed)
                self.assertEqual(prepared.spec.evidence_class.value, "NON_EVIDENTIARY")
                self.assertEqual(
                    prepared.spec.metadata["model_output_scientific_evidence"], False
                )
                executed = self.controller.execute_prepared_local_run(
                    prepared,
                    backend,
                    idempotency_key=f"autonomous-variant-{index}",
                )
                self.assertEqual(executed.submission.state, RunState.SUCCEEDED)
                self.assertFalse(executed.submission.network_used)
                self.assertFalse(executed.submission.scientific_evidence)
                self.assertIsNotNone(executed.collected)
                assert executed.collected is not None
                self.assertFalse(executed.collected.scientific_evidence)
                self.assertEqual(
                    {item.metric for item in executed.collected.manifest.seed_results},
                    {expected_metric},
                )
                self.assertTrue(self.registry.verify(executed.execution_receipt.sha256))
        self.assertEqual(len(code_hashes), 2)
        self.assertTrue(self.registry.verify_all(raise_on_error=True).valid)

    def test_arbitrary_code_shell_network_and_control_fields_are_rejected_and_recorded(self) -> None:
        hostile_fields = {
            "source_code": "provider supplied source text",
            "argv": ["provider", "controlled", "arguments"],
            "network_requested": True,
            "shell_command": "provider supplied shell text",
        }
        for index, (field, value) in enumerate(hostile_fields.items(), start=1):
            with self.subTest(field=field):
                invocation = self.invocation(f"invocation-hostile-{index}")
                proposal = self.proposal(f"hostile-{index}")
                proposal[field] = value
                captured = self.result(invocation, proposal)
                self.assertEqual(captured.status, ModelRunStatus.INVALID_RESPONSE)
                outcome = self.controller.admit_model_result(
                    invocation,
                    captured,
                    self.context,
                )
                self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
                self.assertEqual(outcome.reason_code, "PROVIDER_RESULT_NOT_COMPLETED")
                self.assertTrue(self.registry.verify(outcome.proposal_artifact.sha256))
                self.assertTrue(self.registry.verify(outcome.validation_receipt.sha256))
                self.assertIsNone(outcome.implementation)

    def test_unknown_template_and_path_escape_are_rejected(self) -> None:
        invocation = self.invocation("invocation-unknown-template")
        unknown = self.proposal("unknown-template")
        unknown["template_id"] = "unreviewed-arbitrary-worker"
        rejected = self.controller.admit_model_result(
            invocation,
            self.result(invocation, unknown),
            self.context,
        )
        self.assertEqual(rejected.reason_code, "PROVIDER_RESULT_NOT_COMPLETED")

        invocation = self.invocation("invocation-path-escape")
        escape = self.proposal("path-escape")
        escape["implementation_id"] = "../../outside-project"
        rejected = self.controller.admit_model_result(
            invocation,
            self.result(invocation, escape),
            self.context,
        )
        self.assertEqual(rejected.reason_code, "DECLARATIVE_PROPOSAL_INVALID")
        self.assertFalse((self.root.parent / "outside-project").exists())

    def test_schema_confusion_is_rejected_before_output_can_gain_authority(self) -> None:
        confused_schema = {
            "type": "object",
            "properties": {
                "freeform": {"type": "string", "minLength": 1, "maxLength": 100}
            },
            "required": ["freeform"],
            "additionalProperties": False,
        }
        invocation = self.invocation(
            "invocation-schema-confusion",
            output_schema=confused_schema,
        )
        outcome = self.controller.admit_model_result(
            invocation,
            self.result(invocation, {"freeform": "pretend this is implementation code"}),
            self.context,
        )
        self.assertEqual(outcome.reason_code, "PROVIDER_SCHEMA_CONFUSION")
        self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
        receipt = self.registry.get_bytes(outcome.validation_receipt.sha256)
        self.assertIn(b'"scientific_evidence":false', receipt)

    def test_fixture_evaluator_requires_exact_metric_identity(self) -> None:
        invalid_values = (
            {
                "metric": "template_defined_scalar",
                "direction": "HIGHER_IS_BETTER",
            },
            {
                "metric": "template_defined_scalar",
                "metric_id": "metric-substituted-by-caller",
                "direction": "HIGHER_IS_BETTER",
            },
        )
        for index, evaluator_value in enumerate(invalid_values, start=1):
            with self.subTest(evaluator=evaluator_value):
                evaluator = self.registry.put_json(
                    evaluator_value,
                    logical_type="evaluator.fixture_scalar",
                    origin="adversarial autonomous implementation evaluator fixture",
                    creator_role=Role.PROTOCOL_DESIGNER,
                    creation_command=("test", "create-invalid-component-evaluator"),
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                )
                context = replace(
                    self.context,
                    evaluator_artifact_sha256=evaluator.sha256,
                )
                evidence = (self.data.sha256, evaluator.sha256)
                invocation = self.invocation(
                    f"invocation-invalid-evaluator-{index}",
                    input_hashes=evidence,
                )

                outcome = self.controller.admit_model_result(
                    invocation,
                    self.result(
                        invocation,
                        self.proposal(
                            f"invalid-evaluator-{index}",
                            evidence=evidence,
                        ),
                    ),
                    context,
                )

                self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
                self.assertEqual(outcome.reason_code, "FIXTURE_INPUT_SCHEMA_INVALID")
                self.assertIsNone(outcome.implementation)

    def test_nondeterministic_generation_is_rejected_and_cannot_be_prepared(self) -> None:
        invocation = self.invocation("invocation-nondeterministic")
        proposal = self.proposal("nondeterministic")
        from scientist_one import autonomous_implementation as implementation_module

        reviewed = implementation_module._render_worker(
            ReviewedWorkerTemplate.AFFINE_MEAN_V1
        )
        with mock.patch.object(
            implementation_module,
            "_render_worker",
            side_effect=(reviewed, reviewed + b"\n"),
        ):
            outcome = self.controller.admit_model_result(
                invocation,
                self.result(invocation, proposal),
                self.context,
            )
        self.assertEqual(outcome.reason_code, "WORKER_GENERATION_NONDETERMINISTIC")
        self.assertIsNone(outcome.implementation)
        with self.assertRaises(AutonomousImplementationError):
            self.controller.prepare_local_run(None, run_id="run-rejected")  # type: ignore[arg-type]

    def test_missing_parent_evidence_fails_closed_with_persisted_rejection(self) -> None:
        absent = digest("absent-parent-evidence")
        evidence = (self.data.sha256, self.evaluator.sha256, absent)
        invocation = self.invocation(
            "invocation-missing-evidence",
            input_hashes=evidence,
        )
        captured_invocation = self.invocation("invocation-missing-evidence")
        outcome = self.controller.admit_model_result(
            invocation,
            self.result(
                captured_invocation,
                self.proposal("missing-evidence", evidence=evidence),
            ),
            self.context,
        )
        self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
        self.assertEqual(outcome.reason_code, "PROVIDER_PROVENANCE_INVALID")
        self.assertNotIn(absent, outcome.proposal_artifact.parent_artifacts)
        self.assertTrue(self.registry.verify(outcome.validation_receipt.sha256))

    def test_wrong_provider_capability_and_parameter_schema_fail_closed(self) -> None:
        invocation = self.invocation(
            "invocation-wrong-capability",
            capability=ModelCapability.PLANNING,
        )
        outcome = self.controller.admit_model_result(
            invocation,
            self.result(invocation, self.proposal("wrong-capability")),
            self.context,
        )
        self.assertEqual(outcome.reason_code, "WRONG_PROVIDER_CAPABILITY")

        invocation = self.invocation("invocation-parameter-confusion")
        proposal = self.proposal("parameter-confusion")
        proposal["parameters"] = [
            {"name": "bias", "value": 1.0},
            {"name": "threshold", "value": 2.0},
        ]
        outcome = self.controller.admit_model_result(
            invocation,
            self.result(invocation, proposal),
            self.context,
        )
        self.assertEqual(outcome.reason_code, "DECLARATIVE_PROPOSAL_INVALID")

    def test_completed_uncaptured_model_result_is_rejected(self) -> None:
        invocation = self.invocation("invocation-uncaptured")
        result = ModelResult(
            invocation_id=invocation.invocation_id,
            provider_id="fixture-provider",
            capability=ModelCapability.CODING,
            model_requested=invocation.model,
            status=ModelRunStatus.COMPLETED,
            external_validation="FIXTURE_ONLY",
            network_used=False,
            output=self.proposal("uncaptured"),
            model_returned=invocation.model,
            provider_response_id="fixture-response",
        )

        outcome = self.controller.admit_model_result(
            invocation,
            result,
            self.context,
        )

        self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
        self.assertEqual(outcome.reason_code, "PROVIDER_PROVENANCE_INVALID")
        self.assertIsNone(outcome.implementation)
        self.assertTrue(self.registry.verify(outcome.validation_receipt.sha256))

    def test_realistic_responses_capture_is_the_complete_admission_authority(self) -> None:
        invocation = self.invocation("invocation-complete-provider-capture")
        captured = self.result(
            invocation,
            self.proposal("complete-provider-capture"),
        )

        self.assertEqual(captured.status, ModelRunStatus.COMPLETED)
        self.assertEqual(captured.provider_id, "openai")
        self.assertEqual(captured.provenance_status, "CAPTURED")
        self.assertEqual(
            captured.usage,
            {
                "input_tokens": 17,
                "input_tokens_details": {
                    "cached_tokens": 3,
                    "cache_write_tokens": 2,
                },
                "output_tokens": 11,
                "output_tokens_details": {"reasoning_tokens": 4},
                "total_tokens": 28,
            },
        )
        required = {
            "model_judged_instructions",
            "model_judged_input",
            "model_output_schema",
            "model_invocation",
            "model_provider_request_body",
            "model_provider_request_intent",
            "external_request",
            "external_response_raw",
            "external_response_receipt",
            "model_provider_response",
            "model_output",
        }
        self.assertEqual({record.logical_type for record in captured.artifacts}, required)
        outcome = self.controller.admit_model_result(invocation, captured, self.context)
        self.assertTrue(outcome.admitted)
        self.assertEqual(
            set(outcome.proposal_artifact.parent_artifacts),
            {
                self.data.sha256,
                self.evaluator.sha256,
                *(record.sha256 for record in captured.artifacts),
            },
        )

    def test_live_authority_context_is_exact_but_optional_for_fixtures(self) -> None:
        ledger = EventLedger(self.root, "runs/component/events.jsonl")
        with self.assertRaises(AutonomousImplementationError):
            AutonomousImplementationController(
                self.registry,
                self.catalog,
                expected_run_id="component",
            )
        with self.assertRaises(AutonomousImplementationError):
            AutonomousImplementationController(
                self.registry,
                self.catalog,
                authority_ledger=ledger,
            )
        with self.assertRaises(AutonomousImplementationError):
            AutonomousImplementationController(
                self.registry,
                self.catalog,
                expected_run_id="invalid run ID",
                authority_ledger=ledger,
            )
        with tempfile.TemporaryDirectory() as other_root:
            with self.assertRaises(AutonomousImplementationError):
                AutonomousImplementationController(
                    self.registry,
                    self.catalog,
                    expected_run_id="component",
                    authority_ledger=EventLedger(other_root),
                )
        with self.assertRaises(AutonomousImplementationError):
            AutonomousImplementationController(
                self.registry,
                self.catalog,
                expected_run_id="component",
                authority_ledger=EventLedger(
                    self.root,
                    "runs/alternate/events.jsonl",
                ),
            )

        controller = AutonomousImplementationController(
            self.registry,
            self.catalog,
            expected_run_id="component",
            authority_ledger=ledger,
        )
        invocation = self.invocation("invocation-context-fixture-control")
        outcome = controller.admit_model_result(
            invocation,
            self.result(invocation, self.proposal("context-fixture-control")),
            self.context,
        )
        self.assertTrue(outcome.admitted)
        with self.assertRaises(AutonomousImplementationError):
            controller._expected_run_id = "alternate"
        with self.assertRaises(AutonomousImplementationError):
            controller._authority_ledger = EventLedger(
                self.root,
                "runs/alternate/events.jsonl",
            )

    def test_cloned_live_graph_requires_real_same_run_gateway_authority(self) -> None:
        invocation = self.invocation("invocation-forged-live-authority")
        forged = self.forged_live_result(
            invocation,
            marker="forged-live-authority",
            claimed_run_id="component",
        )

        with mock.patch.object(
            autonomous_module,
            "require_audited_live_transport_execution",
            wraps=autonomous_module.require_audited_live_transport_execution,
        ) as verifier:
            missing_context = self.controller.admit_model_result(
                invocation,
                forged,
                self.context,
            )
        self.assertEqual(
            missing_context.reason_code,
            "PROVIDER_PROVENANCE_INVALID",
        )
        verifier.assert_not_called()

        ledger = EventLedger(self.root, "runs/component/events.jsonl")
        controller = AutonomousImplementationController(
            self.registry,
            self.catalog,
            expected_run_id="component",
            authority_ledger=ledger,
        )
        authority = self.captured_record(
            forged,
            AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
        )
        receipt = self.captured_record(forged, "external_response_receipt")
        with mock.patch.object(
            autonomous_module,
            "require_audited_live_transport_execution",
            wraps=autonomous_module.require_audited_live_transport_execution,
        ) as verifier:
            missing_key = controller.admit_model_result(
                invocation,
                forged,
                self.context,
            )
        self.assertEqual(missing_key.reason_code, "PROVIDER_PROVENANCE_INVALID")
        verifier.assert_called_once_with(
            self.registry,
            ledger,
            run_id="component",
            authority_artifact_sha256=authority.sha256,
            response_receipt_artifact_sha256=receipt.sha256,
        )

    def test_live_verifier_identity_mismatches_and_failures_are_rejected(self) -> None:
        run_id = "component"
        ledger = EventLedger(self.root, "runs/component/events.jsonl")
        controller = AutonomousImplementationController(
            self.registry,
            self.catalog,
            expected_run_id=run_id,
            authority_ledger=ledger,
        )
        invocation = self.invocation("invocation-live-provider-identity")
        forged = self.forged_live_result(
            invocation,
            marker="live-provider-identity",
            claimed_run_id=run_id,
        )
        other_invocation = self.invocation("invocation-live-provider-other")
        other = self.forged_live_result(
            other_invocation,
            marker="live-provider-other",
            claimed_run_id=run_id,
        )
        authenticated = self.live_verifier_projection(
            forged,
            run_id=run_id,
        )
        mismatches = {
            "wrong-run": replace(authenticated, run_id="run-other-provider"),
            "wrong-policy": replace(authenticated, policy_id="other-policy"),
            "swapped-authority": replace(
                authenticated,
                authority_artifact=self.captured_record(
                    other,
                    AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
                ),
            ),
            "swapped-receipt": replace(
                authenticated,
                response_receipt_artifact=self.captured_record(
                    other,
                    "external_response_receipt",
                ),
            ),
            "swapped-request": replace(
                authenticated,
                request_artifact=self.captured_record(other, "external_request"),
            ),
            "swapped-raw": replace(
                authenticated,
                raw_response_artifact=self.captured_record(
                    other,
                    "external_response_raw",
                ),
            ),
        }
        for marker, mismatch in mismatches.items():
            with self.subTest(marker=marker), mock.patch.object(
                autonomous_module,
                "require_audited_live_transport_execution",
                return_value=mismatch,
            ):
                outcome = controller.admit_model_result(
                    invocation,
                    forged,
                    self.context,
                )
                self.assertEqual(
                    outcome.reason_code,
                    "PROVIDER_PROVENANCE_INVALID",
                )

        for marker in (
            "wrong-ledger",
            "wrong-key",
            "corrected-or-stale-event",
            "ambiguous-authority-event",
        ):
            with self.subTest(marker=marker), mock.patch.object(
                autonomous_module,
                "require_audited_live_transport_execution",
                side_effect=EgressPolicyError(marker),
            ):
                outcome = controller.admit_model_result(
                    invocation,
                    forged,
                    self.context,
                )
                self.assertEqual(
                    outcome.reason_code,
                    "PROVIDER_PROVENANCE_INVALID",
                )

    def test_live_authority_is_reverified_before_preparation(self) -> None:
        run_id = "component"
        ledger = EventLedger(self.root, "runs/component/events.jsonl")
        controller = AutonomousImplementationController(
            self.registry,
            self.catalog,
            expected_run_id=run_id,
            authority_ledger=ledger,
        )
        invocation = self.invocation("invocation-live-provider-replay")
        forged = self.forged_live_result(
            invocation,
            marker="live-provider-replay",
            claimed_run_id=run_id,
        )
        projection = self.live_verifier_projection(forged, run_id=run_id)
        with mock.patch.object(
            autonomous_module,
            "require_audited_live_transport_execution",
            return_value=projection,
        ):
            admitted = controller.admit_model_result(
                invocation,
                forged,
                self.context,
            )
        self.assertTrue(admitted.admitted)
        assert admitted.implementation is not None

        with mock.patch.object(
            autonomous_module,
            "require_audited_live_transport_execution",
            side_effect=EgressPolicyError("authority event was corrected"),
        ) as verifier:
            with self.assertRaises(AutonomousImplementationError):
                controller.prepare_local_run(
                    admitted.implementation,
                    run_id="run-live-provider-replay-local",
                )
        verifier.assert_called_once()

    def test_mutated_live_ledger_context_is_rejected_before_execution(self) -> None:
        run_id = "component"
        ledger = EventLedger(self.root, "runs/component/events.jsonl")
        controller = AutonomousImplementationController(
            self.registry,
            self.catalog,
            expected_run_id=run_id,
            authority_ledger=ledger,
        )
        invocation = self.invocation("invocation-live-provider-mutated-ledger")
        forged = self.forged_live_result(
            invocation,
            marker="live-provider-mutated-ledger",
            claimed_run_id=run_id,
        )
        projection = self.live_verifier_projection(forged, run_id=run_id)
        with mock.patch.object(
            autonomous_module,
            "require_audited_live_transport_execution",
            return_value=projection,
        ) as verifier:
            admitted = controller.admit_model_result(
                invocation,
                forged,
                self.context,
            )
            self.assertTrue(admitted.admitted)
            assert admitted.implementation is not None
            prepared = controller.prepare_local_run(
                admitted.implementation,
                run_id="run-live-provider-mutated-ledger-local",
            )
        self.assertEqual(verifier.call_count, 2)

        alternate = EventLedger(self.root, "runs/alternate/events.jsonl")
        vars(ledger).update(vars(alternate))
        backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/python3",),
            observed_available_memory_bytes=2 * 1024**3,
        )
        with mock.patch.object(
            autonomous_module,
            "require_audited_live_transport_execution",
            return_value=projection,
        ) as verifier:
            with self.assertRaises(AutonomousImplementationError):
                controller.execute_prepared_local_run(
                    prepared,
                    backend,
                    idempotency_key="live-provider-mutated-ledger-execution",
                )
        verifier.assert_not_called()

    def test_completed_retry_capture_retains_every_raw_response_parent(self) -> None:
        invocation = self.invocation("invocation-completed-provider-retry")
        captured = self.result(
            invocation,
            self.proposal("completed-provider-retry"),
            retry_once=True,
        )
        raw_records = tuple(
            record
            for record in captured.artifacts
            if record.logical_type == "external_response_raw"
        )

        self.assertEqual(captured.status, ModelRunStatus.COMPLETED)
        self.assertEqual(len(raw_records), 2)
        outcome = self.controller.admit_model_result(invocation, captured, self.context)
        self.assertTrue(outcome.admitted)
        implementation = outcome.implementation
        assert implementation is not None
        self.controller.prepare_local_run(
            implementation,
            run_id="run-completed-provider-retry",
        )
        self.assertTrue(
            {record.sha256 for record in raw_records}.issubset(
                outcome.proposal_artifact.parent_artifacts
            )
        )

    def test_legacy_two_record_provider_fabrication_is_rejected(self) -> None:
        invocation = self.invocation("invocation-legacy-two-records")
        captured = self.result(invocation, self.proposal("legacy-two-records"))
        legacy = replace(
            captured,
            artifacts=(
                self.captured_record(captured, "model_invocation"),
                self.captured_record(captured, "model_output"),
            ),
        )

        outcome = self.controller.admit_model_result(invocation, legacy, self.context)

        self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
        self.assertEqual(outcome.reason_code, "PROVIDER_PROVENANCE_INVALID")
        self.assertIsNone(outcome.implementation)

    def test_provider_capture_metadata_must_be_exact_passed_and_frozen(self) -> None:
        scenarios = (
            ("wrong-type", {"logical_type": "wrong.provider_record"}),
            ("wrong-role", {"creator_role": Role.IMPLEMENTER}),
            (
                "failed-validation",
                {"validation_result": "FAIL", "frozen": False},
            ),
            ("not-frozen", {"frozen": False}),
        )
        for marker, changes in scenarios:
            with self.subTest(marker=marker):
                invocation = self.invocation(f"invocation-provider-metadata-{marker}")
                captured = self.result(
                    invocation,
                    self.proposal(f"provider-metadata-{marker}"),
                )
                original = self.captured_record(captured, "model_judged_input")
                altered = self.altered_record(original, marker, **changes)
                substituted = self.replace_record(
                    captured,
                    "model_judged_input",
                    altered,
                )

                outcome = self.controller.admit_model_result(
                    invocation,
                    substituted,
                    self.context,
                )

                self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
                self.assertEqual(outcome.reason_code, "PROVIDER_PROVENANCE_INVALID")
                self.assertIsNone(outcome.implementation)

    def test_spliced_run_provider_request_and_response_are_rejected(self) -> None:
        run_invocation = self.invocation("invocation-spliced-run-expected")
        other_invocation = self.invocation("invocation-spliced-run-other")
        other_result = self.result(
            other_invocation,
            self.proposal("spliced-run-other"),
        )
        run_outcome = self.controller.admit_model_result(
            run_invocation,
            other_result,
            self.context,
        )
        self.assertEqual(run_outcome.reason_code, "PROVIDER_RESULT_BINDING_MISMATCH")

        provider_invocation = self.invocation("invocation-spliced-provider")
        provider_result = self.result(
            provider_invocation,
            self.proposal("spliced-provider"),
        )
        provider_outcome = self.controller.admit_model_result(
            provider_invocation,
            replace(provider_result, provider_id="alternate-provider"),
            self.context,
        )
        self.assertEqual(provider_outcome.reason_code, "PROVIDER_PROVENANCE_INVALID")

        for logical_type in (
            "model_provider_request_intent",
            "external_request",
            "external_response_raw",
            "external_response_receipt",
            "model_provider_response",
            "model_output",
        ):
            with self.subTest(logical_type=logical_type):
                suffix = logical_type.replace("_", "-")
                invocation = self.invocation(f"invocation-spliced-{suffix}-expected")
                other = self.invocation(f"invocation-spliced-{suffix}-other")
                captured = self.result(invocation, self.proposal(f"spliced-{suffix}"))
                other_capture = self.result(
                    other,
                    self.proposal(f"spliced-{suffix}-other"),
                )
                spliced = self.replace_record(
                    captured,
                    logical_type,
                    self.captured_record(other_capture, logical_type),
                )

                outcome = self.controller.admit_model_result(
                    invocation,
                    spliced,
                    self.context,
                )

                self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
                self.assertEqual(outcome.reason_code, "PROVIDER_PROVENANCE_INVALID")

    def test_template_input_schema_token_and_request_body_substitution_are_rejected(
        self,
    ) -> None:
        unreviewed_template = replace(
            self.invocation("invocation-unreviewed-prompt-template"),
            prompt_template_id="unreviewed-implementation-template",
            prompt_template_hash=digest("unreviewed-implementation-template-v1"),
        )
        unreviewed_capture = self.result(
            unreviewed_template,
            self.proposal("unreviewed-prompt-template"),
        )
        unreviewed_outcome = self.controller.admit_model_result(
            unreviewed_template,
            unreviewed_capture,
            self.context,
        )
        self.assertEqual(
            unreviewed_outcome.reason_code,
            "PROVIDER_PROVENANCE_INVALID",
        )

        substitutions = (
            ("prompt_template_id", "substituted-implementation-template"),
            ("instructions", "Use substituted unreviewed instructions."),
            ("input_text", "Substitute the exact judged provider input."),
            (
                "output_schema",
                {
                    "type": "object",
                    "properties": {
                        "freeform": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 100,
                        }
                    },
                    "required": ["freeform"],
                    "additionalProperties": False,
                },
            ),
            ("max_output_tokens", 2048),
        )
        for field, value in substitutions:
            with self.subTest(field=field):
                invocation = self.invocation(f"invocation-substituted-{field}-custody")
                captured = self.result(
                    invocation,
                    self.proposal(f"substituted-{field}-custody"),
                )
                substituted_invocation = replace(invocation, **{field: value})

                outcome = self.controller.admit_model_result(
                    substituted_invocation,
                    captured,
                    self.context,
                )

                self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
                self.assertEqual(outcome.reason_code, "PROVIDER_PROVENANCE_INVALID")

        invocation = self.invocation("invocation-substituted-request-body")
        captured = self.result(invocation, self.proposal("substituted-request-body"))
        other_invocation = replace(
            self.invocation("invocation-substituted-request-body-other"),
            input_text="Different exact provider request body input.",
        )
        other_capture = self.result(
            other_invocation,
            self.proposal("substituted-request-body-other"),
        )
        substituted_body = self.replace_record(
            captured,
            "model_provider_request_body",
            self.captured_record(other_capture, "model_provider_request_body"),
        )

        outcome = self.controller.admit_model_result(
            invocation,
            substituted_body,
            self.context,
        )

        self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
        self.assertEqual(outcome.reason_code, "PROVIDER_PROVENANCE_INVALID")

    def test_model_identity_substitution_is_rejected(self) -> None:
        for field in ("model_requested", "model_returned"):
            with self.subTest(field=field):
                invocation = self.invocation(f"invocation-substituted-{field}")
                captured = self.result(
                    invocation,
                    self.proposal(f"substituted-{field}"),
                )
                substituted = replace(captured, **{field: "substituted-model"})

                outcome = self.controller.admit_model_result(
                    invocation,
                    substituted,
                    self.context,
                )

                self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
                self.assertEqual(outcome.reason_code, "PROVIDER_PROVENANCE_INVALID")
                self.assertIsNone(outcome.implementation)

        for field, value in (
            ("model_returned", "spliced-model"),
            ("output", self.proposal("spliced-model-output")),
            (
                "usage",
                {
                    "input_tokens": 1,
                    "output_tokens": 1,
                    "total_tokens": 2,
                },
            ),
        ):
            with self.subTest(model_output_field=field):
                invocation = self.invocation(
                    f"invocation-spliced-model-output-{field}"
                )
                captured = self.result(
                    invocation,
                    self.proposal(f"spliced-model-output-{field}"),
                )
                output_record = self.captured_record(captured, "model_output")
                output_value = safe_json_loads(
                    self.registry.get_bytes(output_record.sha256)
                )
                self.assertIsInstance(output_value, dict)
                output_value[field] = value
                rewritten = self.rewritten_json_record(
                    output_record,
                    output_value,
                )
                outcome = self.controller.admit_model_result(
                    invocation,
                    self.replace_record(captured, "model_output", rewritten),
                    self.context,
                )
                self.assertEqual(outcome.status, AdmissionStatus.REJECTED)
                self.assertEqual(
                    outcome.reason_code,
                    "PROVIDER_PROVENANCE_INVALID",
                )

    def test_runtime_worker_mutation_cannot_mint_template_review(self) -> None:
        from scientist_one import autonomous_implementation as implementation_module

        reviewed = implementation_module._render_worker(
            ReviewedWorkerTemplate.AFFINE_MEAN_V1
        )
        with mock.patch.object(
            implementation_module,
            "_render_worker",
            return_value=reviewed + b"\n# unreviewed runtime mutation\n",
        ):
            with self.assertRaisesRegex(
                AutonomousImplementationError,
                "pinned independent review",
            ):
                template_review_payload(ReviewedWorkerTemplate.AFFINE_MEAN_V1)

    def test_admitted_context_substitution_is_rejected_before_prepare(self) -> None:
        admission = self.admit("context-substitution")
        self.assertTrue(admission.admitted)
        implementation = admission.implementation
        assert implementation is not None
        substituted = replace(
            implementation,
            context=replace(
                implementation.context,
                experiment_id="experiment-substituted-after-admission",
            ),
        )

        with self.assertRaises(AutonomousImplementationError):
            self.controller.prepare_local_run(
                substituted,
                run_id="run-context-substitution",
            )

    def test_forged_prepared_spec_and_worker_path_are_rejected(self) -> None:
        admission = self.admit("forged-prepared")
        self.assertTrue(admission.admitted)
        implementation = admission.implementation
        assert implementation is not None
        prepared = self.controller.prepare_local_run(
            implementation,
            run_id="run-forged-prepared",
        )
        backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/python3",),
            observed_available_memory_bytes=2 * 1024**3,
        )
        for label, forged in (
            (
                "spec",
                PreparedImplementationRun(
                    implementation=implementation,
                    spec=replace(prepared.spec, timeout_seconds=29.0),
                    spec_artifact=prepared.spec_artifact,
                    materialized_worker_path=prepared.materialized_worker_path,
                ),
            ),
            (
                "path",
                PreparedImplementationRun(
                    implementation=implementation,
                    spec=prepared.spec,
                    spec_artifact=prepared.spec_artifact,
                    materialized_worker_path=implementation.configuration_artifact.path,
                ),
            ),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    AutonomousImplementationError,
                    "frozen run spec artifact is corrupt",
                ):
                    self.controller.execute_prepared_local_run(
                        forged,
                        backend,
                        idempotency_key=f"forged-{label}",
                    )

    def test_custom_local_execution_runner_is_rejected(self) -> None:
        admission = self.admit("custom-runner")
        self.assertTrue(admission.admitted)
        implementation = admission.implementation
        assert implementation is not None
        prepared = self.controller.prepare_local_run(
            implementation,
            run_id="run-custom-runner",
        )

        def custom_runner(*_args: object, **_kwargs: object) -> ExecutionResult:
            return ExecutionResult(returncode=0)

        backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/python3",),
            execution_runner=custom_runner,
            execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            observed_available_memory_bytes=2 * 1024**3,
        )
        with self.assertRaisesRegex(
            AutonomousImplementationError,
            "exact built-in local runner policy",
        ):
            self.controller.execute_prepared_local_run(
                prepared,
                backend,
                idempotency_key="custom-runner",
            )

    def test_local_backend_subclass_and_instance_dispatch_overrides_are_rejected(
        self,
    ) -> None:
        admission = self.admit("backend-dispatch-override")
        implementation = admission.implementation
        assert implementation is not None
        prepared = self.controller.prepare_local_run(
            implementation,
            run_id="run-backend-dispatch-override",
        )

        class HostileLocalBackend(LocalMacBackend):
            def submit(self, *_args: object, **_kwargs: object) -> object:
                raise AssertionError("hostile submit reached")

        with self.assertRaisesRegex(
            ExperimentIntegrityError,
            "exact built-in",
        ):
            HostileLocalBackend(
                self.root,
                allowed_executables=("/usr/bin/python3",),
            )

        instance_backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/python3",),
        )
        hostile_submit = mock.Mock(side_effect=AssertionError("hostile submit reached"))
        instance_backend.submit = hostile_submit  # type: ignore[method-assign]
        with self.assertRaisesRegex(
            AutonomousImplementationError,
            "exact built-in local runner policy",
        ):
            self.controller.execute_prepared_local_run(
                prepared,
                instance_backend,
                idempotency_key="hostile-instance",
            )
        hostile_submit.assert_not_called()

        private_override_backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/python3",),
        )
        hostile_private = mock.Mock(
            side_effect=AssertionError("hostile private dispatch reached")
        )
        private_override_backend._validate_local_profile = hostile_private  # type: ignore[method-assign]
        with self.assertRaisesRegex(
            AutonomousImplementationError,
            "exact built-in local runner policy",
        ):
            self.controller.execute_prepared_local_run(
                prepared,
                private_override_backend,
                idempotency_key="hostile-private-dispatch",
            )
        hostile_private.assert_not_called()

    def test_evidence_mismatch_receipt_does_not_launder_invocation_parents(self) -> None:
        invocation = self.invocation("invocation-evidence-mismatch-receipt")
        declared = (self.data.sha256, self.catalog.artifact.sha256)
        proposal = self.proposal("evidence-mismatch-receipt", evidence=declared)

        outcome = self.controller.admit_model_result(
            invocation,
            self.result(invocation, proposal),
            self.context,
        )

        self.assertEqual(outcome.reason_code, "PARENT_EVIDENCE_BINDING_MISMATCH")
        receipt = safe_json_loads(
            self.registry.get_bytes(outcome.validation_receipt.sha256)
        )
        self.assertEqual(
            set(receipt["declared_parent_evidence_sha256s"]),
            set(declared),
        )
        self.assertEqual(
            set(receipt["verified_parent_evidence_sha256s"]),
            set(declared),
        )
        self.assertNotIn(
            self.evaluator.sha256,
            outcome.validation_receipt.parent_artifacts,
        )

    def test_extra_public_result_artifact_is_not_proposal_authority(self) -> None:
        invocation = self.invocation("invocation-extra-result-artifact")
        captured = self.result(
            invocation,
            self.proposal("extra-result-artifact"),
        )
        unrelated = self.registry.put_json(
            {"unrelated": True},
            logical_type="unrelated.public_result_artifact",
            origin="adversarial extra public ModelResult artifact",
            creator_role=Role.IMPLEMENTER,
            creation_command=("test", "create-unrelated-artifact"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        result_with_extra = replace(
            captured,
            artifacts=(*captured.artifacts, unrelated),
        )

        outcome = self.controller.admit_model_result(
            invocation,
            result_with_extra,
            self.context,
        )

        self.assertTrue(outcome.admitted)
        self.assertNotIn(unrelated.sha256, outcome.proposal_artifact.parent_artifacts)
        self.assertEqual(
            set(outcome.proposal_artifact.parent_artifacts),
            {
                self.data.sha256,
                self.evaluator.sha256,
                *(record.sha256 for record in captured.artifacts),
            },
        )

    def test_repeated_identical_outputs_share_provider_neutral_core_identity(self) -> None:
        proposal = self.proposal("repeated-output")
        admissions = []
        for attempt in ("first", "second"):
            invocation = self.invocation(f"invocation-repeated-{attempt}")
            admissions.append(
                self.controller.admit_model_result(
                    invocation,
                    self.result(invocation, proposal),
                    self.context,
                )
            )

        self.assertTrue(all(admission.admitted for admission in admissions))
        first = admissions[0].implementation
        second = admissions[1].implementation
        assert first is not None and second is not None
        self.assertNotEqual(
            first.provider_attempt_artifact.sha256,
            second.provider_attempt_artifact.sha256,
        )
        self.assertNotEqual(
            first.provider_admission_link.sha256,
            second.provider_admission_link.sha256,
        )
        self.assertEqual(first.proposal, second.proposal)
        for left, right in (
            (first.proposal_artifact, second.proposal_artifact),
            (first.worker_code_artifact, second.worker_code_artifact),
            (first.configuration_artifact, second.configuration_artifact),
            (first.validation_receipt, second.validation_receipt),
            (first.descriptor_artifact, second.descriptor_artifact),
        ):
            self.assertEqual(left.sha256, right.sha256)
            self.assertEqual(
                self.registry.get_bytes(left.sha256),
                self.registry.get_bytes(right.sha256),
            )
        first_prepared = self.controller.prepare_local_run(
            first,
            run_id="run-provider-neutral-repeated-output",
        )
        second_prepared = self.controller.prepare_local_run(
            second,
            run_id="run-provider-neutral-repeated-output",
        )
        self.assertEqual(first_prepared.spec, second_prepared.spec)
        self.assertEqual(
            first_prepared.spec_artifact.sha256,
            second_prepared.spec_artifact.sha256,
        )

    def test_distinct_provider_fixture_changes_only_advisory_provenance(self) -> None:
        invocation = self.invocation("invocation-provider-neutral-fixture")
        source_result = self.result(
            invocation,
            self.proposal("provider-neutral-fixture"),
        )
        fixture_result = deterministic_provider_result(
            self.registry,
            source_result,
        )

        source_request_bytes = self.registry.get_bytes(
            self.captured_record(
                source_result,
                "model_provider_request_body",
            ).sha256
        )
        fixture_request_bytes = self.registry.get_bytes(
            self.captured_record(
                fixture_result,
                "model_provider_request_body",
            ).sha256
        )
        source_raw_bytes = self.registry.get_bytes(
            self.captured_record(source_result, "external_response_raw").sha256
        )
        fixture_raw_bytes = self.registry.get_bytes(
            self.captured_record(fixture_result, "external_response_raw").sha256
        )
        self.assertNotEqual(source_request_bytes, fixture_request_bytes)
        self.assertNotEqual(source_raw_bytes, fixture_raw_bytes)
        source_request_value = safe_json_loads(source_request_bytes)
        fixture_request_value = safe_json_loads(fixture_request_bytes)
        source_raw_value = safe_json_loads(source_raw_bytes)
        fixture_raw_value = safe_json_loads(fixture_raw_bytes)
        self.assertEqual(
            set(source_request_value),
            {
                "model",
                "instructions",
                "input",
                "max_output_tokens",
                "store",
                "text",
                "tool_choice",
                "tools",
                "truncation",
            },
        )
        self.assertEqual(
            set(fixture_request_value),
            {
                "fixture_protocol",
                "engine",
                "system",
                "prompt",
                "response_contract",
                "limit",
            },
        )
        self.assertEqual(
            set(source_raw_value),
            {"id", "model", "status", "output", "usage"},
        )
        self.assertEqual(
            set(fixture_raw_value),
            {
                "fixture_protocol",
                "request_ref",
                "engine",
                "response_ref",
                "state",
                "result_json",
                "metering",
            },
        )

        source = self.controller.admit_model_result(
            invocation,
            source_result,
            self.context,
        )
        fixture = self.controller.admit_model_result(
            invocation,
            fixture_result,
            self.context,
        )

        self.assertTrue(source.admitted)
        self.assertTrue(fixture.admitted)
        source_implementation = source.implementation
        fixture_implementation = fixture.implementation
        assert source_implementation is not None
        assert fixture_implementation is not None
        self.assertEqual(
            source_implementation.proposal,
            fixture_implementation.proposal,
        )
        self.assertNotEqual(
            source_implementation.provider_attempt_artifact.sha256,
            fixture_implementation.provider_attempt_artifact.sha256,
        )
        self.assertNotEqual(
            source_implementation.provider_admission_link.sha256,
            fixture_implementation.provider_admission_link.sha256,
        )
        for left, right in (
            (
                source_implementation.proposal_artifact,
                fixture_implementation.proposal_artifact,
            ),
            (
                source_implementation.worker_code_artifact,
                fixture_implementation.worker_code_artifact,
            ),
            (
                source_implementation.configuration_artifact,
                fixture_implementation.configuration_artifact,
            ),
            (
                source_implementation.validation_receipt,
                fixture_implementation.validation_receipt,
            ),
            (
                source_implementation.descriptor_artifact,
                fixture_implementation.descriptor_artifact,
            ),
        ):
            self.assertEqual(left.sha256, right.sha256)
            self.assertEqual(
                self.registry.get_bytes(left.sha256),
                self.registry.get_bytes(right.sha256),
            )

        def core_state_payloads(implementation):
            timestamp = "2026-09-04T00:00:00.000000Z"
            method = StateMethod(
                object_id="method-provider-neutral-fixture",
                producer=Role.HYPOTHESIS_DESIGNER,
                status=RecordStatus.FROZEN,
                created_at=timestamp,
                code_version="provider-neutral-fixture-code",
                authority_artifact_hashes=(
                    implementation.validation_receipt.sha256,
                    implementation.descriptor_artifact.sha256,
                ),
                name="Provider-neutral reviewed action",
                description="The same normalized reviewed-template action.",
                assumptions=("Non-scientific fixture only.",),
                component_ids=("component-provider-neutral-fixture",),
                metadata={
                    "proposal_artifact_sha256": (
                        implementation.proposal_artifact.sha256
                    ),
                    "scientific_evidence": False,
                },
            )
            state_implementation = StateImplementation(
                object_id=implementation.proposal.implementation_id,
                producer=Role.IMPLEMENTER,
                status=RecordStatus.FROZEN,
                created_at=timestamp,
                code_version="provider-neutral-fixture-code",
                authority_artifact_hashes=(
                    implementation.worker_code_artifact.sha256,
                    implementation.configuration_artifact.sha256,
                    implementation.descriptor_artifact.sha256,
                    implementation.validation_receipt.sha256,
                ),
                method_id=method.object_id,
                code_artifact_hashes=(
                    implementation.worker_code_artifact.sha256,
                ),
                code_revision="provider-neutral-fixture-code",
                configuration_artifact_hashes=(
                    implementation.configuration_artifact.sha256,
                    implementation.descriptor_artifact.sha256,
                    implementation.validation_receipt.sha256,
                ),
                metadata={
                    "proposal_id": implementation.proposal.proposal_id,
                    "scientific_evidence": False,
                },
            )
            experiment = StateExperiment(
                object_id=implementation.context.experiment_id,
                producer=Role.PROTOCOL_DESIGNER,
                status=RecordStatus.FROZEN,
                created_at=timestamp,
                code_version="provider-neutral-fixture-code",
                authority_artifact_hashes=(
                    implementation.configuration_artifact.sha256,
                    implementation.descriptor_artifact.sha256,
                    self.evaluator.sha256,
                ),
                hypothesis_ids=(implementation.context.hypothesis_id,),
                scientific_purpose="Non-scientific provider-neutral fixture.",
                implementation_id=state_implementation.object_id,
                configuration_artifact_hashes=(
                    implementation.configuration_artifact.sha256,
                    implementation.descriptor_artifact.sha256,
                    self.evaluator.sha256,
                ),
                compute_profile=StateComputeProfile.LOCAL_MAC,
                seed_policy={"seeds": list(implementation.context.seeds)},
                expected_output_types=("fixture_result",),
                evaluator=f"artifact:{self.evaluator.sha256}",
                budget={"class": "COMPONENT_FIXTURE"},
                termination_conditions={"all_seeds": True},
                metadata={
                    "proposal_artifact_sha256": (
                        implementation.proposal_artifact.sha256
                    ),
                    "scientific_evidence": False,
                },
            )
            state_run = StateRun(
                object_id="run-provider-neutral-core-state",
                producer=Role.EXPERIMENT_RUNNER,
                status=RecordStatus.COMPLETE,
                created_at=timestamp,
                code_version="provider-neutral-fixture-code",
                authority_artifact_hashes=(
                    implementation.configuration_artifact.sha256,
                    implementation.descriptor_artifact.sha256,
                    implementation.validation_receipt.sha256,
                ),
                experiment_id=experiment.object_id,
                code_revision="provider-neutral-fixture-code",
                configuration_artifact_hash=(
                    implementation.configuration_artifact.sha256
                ),
                compute_profile=StateComputeProfile.LOCAL_MAC,
                random_seeds=implementation.context.seeds,
                output_artifact_hashes=(
                    implementation.descriptor_artifact.sha256,
                ),
                evaluator_version=f"artifact:{self.evaluator.sha256}",
                started_at=timestamp,
                completed_at=timestamp,
                metadata={
                    "proposal_artifact_sha256": (
                        implementation.proposal_artifact.sha256
                    ),
                    "scientific_evidence": False,
                },
            )
            state_result = StateResult(
                object_id="result-provider-neutral-core-state",
                producer=Role.STATISTICIAN,
                status=RecordStatus.COMPLETE,
                created_at=timestamp,
                code_version="provider-neutral-fixture-code",
                authority_artifact_hashes=(
                    implementation.descriptor_artifact.sha256,
                    implementation.validation_receipt.sha256,
                ),
                run_ids=(state_run.object_id,),
                metric_id="metric-provider-neutral-core-state",
                value={"advisory_fixture_value": 0.0},
                unit="dimensionless",
                direction=StateMetricDirection.DESCRIPTIVE_ONLY,
                uncertainty={"scientific_evidence": False},
                source_artifact_hashes=(
                    implementation.descriptor_artifact.sha256,
                ),
                evaluation_artifact_hashes=(
                    implementation.validation_receipt.sha256,
                ),
                code_revision="provider-neutral-fixture-code",
                observed_at=timestamp,
                metadata={
                    "proposal_artifact_sha256": (
                        implementation.proposal_artifact.sha256
                    ),
                    "scientific_evidence": False,
                },
            )
            return method, state_implementation, experiment, state_run, state_result

        source_state = core_state_payloads(source_implementation)
        fixture_state = core_state_payloads(fixture_implementation)
        for source_object, fixture_object in zip(
            source_state,
            fixture_state,
            strict=True,
        ):
            self.assertEqual(
                source_object.canonical_bytes(),
                fixture_object.canonical_bytes(),
            )
            self.assertEqual(source_object.content_hash, fixture_object.content_hash)
        source_prepared = self.controller.prepare_local_run(
            source_implementation,
            run_id="run-provider-neutral-second-provider",
        )
        fixture_prepared = self.controller.prepare_local_run(
            fixture_implementation,
            run_id="run-provider-neutral-second-provider",
        )
        self.assertEqual(source_prepared.spec, fixture_prepared.spec)
        self.assertEqual(
            source_prepared.spec_artifact.sha256,
            fixture_prepared.spec_artifact.sha256,
        )
        self.assertFalse(fixture_result.network_used)
        self.assertEqual(fixture_result.external_validation, "UNTESTED")
        self.assertFalse(fixture_result.scientific_evidence)

    def test_provider_verifier_dispatch_is_closed_and_detects_supported_mutation(
        self,
    ) -> None:
        openai = require_provider_verifier(
            OPENAI_PROVIDER_ID,
            MODEL_PROVIDER_CUSTODY_SCHEMA_V1,
        )
        deterministic = require_provider_verifier(
            DETERMINISTIC_FIXTURE_PROVIDER_ID,
            MODEL_PROVIDER_CUSTODY_SCHEMA_V1,
        )
        self.assertNotEqual(openai.key, deterministic.key)
        with self.assertRaises(ProviderVerificationError):
            require_provider_verifier("unknown-provider", "1.0")
        with self.assertRaises(ProviderVerificationError):
            require_provider_verifier(OPENAI_PROVIDER_ID, "2.0")
        self.assertFalse(
            hasattr(provider_verification_module, "register_provider_verifier")
        )
        with self.assertRaises(FrozenInstanceError):
            openai.provider_id = "replacement"  # type: ignore[misc]

        output_schema = {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["offline-only"]},
            },
            "required": ["status"],
            "additionalProperties": False,
        }
        structured_output = {"status": "offline-only"}
        instructions = "Return one bounded fixture object."
        judged_input = "Exercise the closed provider verifier."

        def native_projections(contract, invocation_id: str):
            body = contract.build_request_body(
                retained_instructions=instructions,
                retained_input=judged_input,
                retained_schema=output_schema,
                model_requested="gpt-5",
                maximum_output_tokens=64,
            )
            request_projection = contract.validate_and_project_request(
                body_bytes=body,
                retained_instructions=instructions,
                retained_input=judged_input,
                retained_schema=output_schema,
                invocation_id=invocation_id,
                model_requested="gpt-5",
                maximum_output_tokens=64,
            )
            if contract.provider_id == OPENAI_PROVIDER_ID:
                raw_value = {
                    "id": "response-openai-closed-dispatch",
                    "model": "gpt-5",
                    "status": "completed",
                    "output_text": canonical_json_bytes(structured_output).decode(
                        "utf-8"
                    ),
                    "usage": {
                        "input_tokens": 2,
                        "output_tokens": 1,
                        "total_tokens": 3,
                    },
                }
            else:
                raw_value = {
                    "fixture_protocol": contract.wire_protocol,
                    "request_ref": request_projection.request_id,
                    "engine": "gpt-5",
                    "response_ref": "response-deterministic-closed-dispatch",
                    "state": "done",
                    "result_json": canonical_json_bytes(structured_output).decode(
                        "utf-8"
                    ),
                    "metering": {
                        "prompt_units": 2,
                        "prompt_unit_details": None,
                        "result_units": 1,
                        "result_unit_details": None,
                        "total_units": 3,
                    },
                }
            raw = canonical_json_bytes(raw_value)
            response_projection = contract.parse_and_project_response(
                raw_bytes=raw,
                requested_model="gpt-5",
                output_schema=output_schema,
                maximum_output_bytes=4096,
                expected_request_id=request_projection.request_id,
            )
            return body, raw, request_projection, response_projection

        openai_native = native_projections(openai, "unverified-network-splice")
        deterministic_native = native_projections(
            deterministic,
            "deterministic-fixture-invocation",
        )
        openai_body, openai_raw, openai_request, openai_response = openai_native
        (
            deterministic_body,
            deterministic_raw,
            deterministic_request,
            deterministic_response,
        ) = deterministic_native
        self.assertNotEqual(openai_body, deterministic_body)
        self.assertNotEqual(openai_raw, deterministic_raw)
        self.assertNotEqual(openai_request.wire_protocol, deterministic_request.wire_protocol)
        self.assertNotEqual(openai_response.raw_sha256, deterministic_response.raw_sha256)

        with self.assertRaises(ProviderVerificationError):
            openai.verify_execution(
                provider_version=openai.provider_version,
                endpoint=openai.endpoint,
                credential_env_name=openai.credential_env_name,
                credential_present=openai.credential_present,
                invocation_id="unverified-network-splice",
                request_projection=openai_request,
                response_projection=openai_response,
                request_body_bytes=openai_body,
                raw_response_bytes=openai_raw,
                retained_instructions=instructions,
                retained_input=judged_input,
                retained_schema=output_schema,
                maximum_output_bytes=4096,
                network_used=True,
                external_validation="UNTESTED",
                transport_authority=UNVERIFIED_TRANSPORT_AUTHORITY,
                transport_execution_authority_artifact_sha256=None,
                custody_artifact_hashes=(digest("unverified-network-custody"),),
            )
        projection = deterministic.verify_execution(
            provider_version=deterministic.provider_version,
            endpoint=deterministic.endpoint,
            credential_env_name=None,
            credential_present=False,
            invocation_id="deterministic-fixture-invocation",
            request_projection=deterministic_request,
            response_projection=deterministic_response,
            request_body_bytes=deterministic_body,
            raw_response_bytes=deterministic_raw,
            retained_instructions=instructions,
            retained_input=judged_input,
            retained_schema=output_schema,
            maximum_output_bytes=4096,
            network_used=False,
            external_validation="UNTESTED",
            transport_authority=UNVERIFIED_TRANSPORT_AUTHORITY,
            transport_execution_authority_artifact_sha256=None,
            custody_artifact_hashes=(digest("deterministic-fixture-custody"),),
        )
        self.assertIsInstance(projection, ProviderExecutionProjection)
        with self.assertRaises(TypeError):
            projection.structured_output["proposal"] = {}  # type: ignore[index]

        with self.assertRaises(ProviderVerificationError):
            openai.verify_execution(
                provider_version=openai.provider_version,
                endpoint=openai.endpoint,
                credential_env_name=openai.credential_env_name,
                credential_present=openai.credential_present,
                invocation_id="unverified-network-splice",
                request_projection=deterministic_request,
                response_projection=deterministic_response,
                request_body_bytes=deterministic_body,
                raw_response_bytes=deterministic_raw,
                retained_instructions=instructions,
                retained_input=judged_input,
                retained_schema=output_schema,
                maximum_output_bytes=4096,
                network_used=False,
                external_validation="UNTESTED",
                transport_authority=UNVERIFIED_TRANSPORT_AUTHORITY,
                transport_execution_authority_artifact_sha256=None,
                custody_artifact_hashes=(digest("cross-contract-custody"),),
            )
        with self.assertRaises(ProviderVerificationError):
            deterministic.verify_execution(
                provider_version=deterministic.provider_version,
                endpoint=deterministic.endpoint,
                credential_env_name=None,
                credential_present=False,
                invocation_id="deterministic-fixture-invocation",
                request_projection=deterministic_request,
                response_projection=openai_response,
                request_body_bytes=deterministic_body,
                raw_response_bytes=openai_raw,
                retained_instructions=instructions,
                retained_input=judged_input,
                retained_schema=output_schema,
                maximum_output_bytes=4096,
                network_used=False,
                external_validation="UNTESTED",
                transport_authority=UNVERIFIED_TRANSPORT_AUTHORITY,
                transport_execution_authority_artifact_sha256=None,
                custody_artifact_hashes=(
                    digest("deterministic-fixture-custody-list"),
                ),
            )
        with self.assertRaises(ProviderVerificationError):
            openai.validate_and_project_request(
                body_bytes=deterministic_body,
                retained_instructions=instructions,
                retained_input=judged_input,
                retained_schema=output_schema,
                invocation_id="unverified-network-splice",
                model_requested="gpt-5",
                maximum_output_tokens=64,
            )
        with self.assertRaises(ProviderVerificationError):
            deterministic.validate_and_project_request(
                body_bytes=openai_body,
                retained_instructions=instructions,
                retained_input=judged_input,
                retained_schema=output_schema,
                invocation_id="deterministic-fixture-invocation",
                model_requested="gpt-5",
                maximum_output_tokens=64,
            )
        with self.assertRaises(ProviderVerificationError):
            openai.parse_and_project_response(
                raw_bytes=deterministic_raw,
                requested_model="gpt-5",
                output_schema=output_schema,
                maximum_output_bytes=4096,
                expected_request_id=openai_request.request_id,
            )
        with self.assertRaises(ProviderVerificationError):
            deterministic.parse_and_project_response(
                raw_bytes=openai_raw,
                requested_model="gpt-5",
                output_schema=output_schema,
                maximum_output_bytes=4096,
                expected_request_id=deterministic_request.request_id,
            )

        with mock.patch.object(
            provider_wire_module,
            "_parse_output_text",
            return_value=structured_output,
        ):
            with self.assertRaises(ProviderVerificationError):
                openai.parse_and_project_response(
                    raw_bytes=openai_raw,
                    requested_model="gpt-5",
                    output_schema=output_schema,
                    maximum_output_bytes=4096,
                    expected_request_id=openai_request.request_id,
                )
        self.assertFalse(hasattr(openai, "_response_parser"))
        with self.assertRaises(AttributeError):
            object.__setattr__(openai, "_response_parser", lambda: None)
        original_provider_id = openai.provider_id
        try:
            object.__setattr__(
                openai,
                "provider_id",
                deterministic.provider_id,
            )
            with self.assertRaises(ProviderVerificationError):
                openai.parse_and_project_response(
                    raw_bytes=openai_raw,
                    requested_model="gpt-5",
                    output_schema=output_schema,
                    maximum_output_bytes=4096,
                    expected_request_id=openai_request.request_id,
                )
        finally:
            object.__setattr__(openai, "provider_id", original_provider_id)
        replayed = openai.parse_and_project_response(
            raw_bytes=openai_raw,
            requested_model="gpt-5",
            output_schema=output_schema,
            maximum_output_bytes=4096,
            expected_request_id=openai_request.request_id,
        )
        self.assertEqual(replayed, openai_response)

        mutation_probe = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                """
from scientist_one.provider_verification import (
    DETERMINISTIC_FIXTURE_PROVIDER_ID,
    MODEL_PROVIDER_CUSTODY_SCHEMA_V1,
    OPENAI_PROVIDER_ID,
    ProviderVerifierContract,
    ProviderVerificationError,
    require_provider_verifier,
)
import scientist_one.provider_verification as verification_module
from scientist_one.security import canonical_json_bytes

schema = {
    "type": "object",
    "properties": {"status": {"type": "string", "enum": ["offline-only"]}},
    "required": ["status"],
    "additionalProperties": False,
}
openai = require_provider_verifier(OPENAI_PROVIDER_ID, MODEL_PROVIDER_CUSTODY_SCHEMA_V1)
fixture = require_provider_verifier(
    DETERMINISTIC_FIXTURE_PROVIDER_ID,
    MODEL_PROVIDER_CUSTODY_SCHEMA_V1,
)
if hasattr(verification_module, "_ProviderVerifierImplementation"):
    raise SystemExit("executable implementation type leaked from closed dispatch")
for method_name in ("parse_and_project_response", "verify_execution"):
    try:
        setattr(
            ProviderVerifierContract,
            method_name,
            lambda *_args, **_kwargs: None,
        )
    except TypeError:
        pass
    else:
        raise SystemExit("public contract method replacement was accepted")
body = fixture.build_request_body(
    retained_instructions="Return one bounded fixture object.",
    retained_input="Exercise the closed provider verifier.",
    retained_schema=schema,
    model_requested="gpt-5",
    maximum_output_tokens=64,
)
request = fixture.validate_and_project_request(
    body_bytes=body,
    retained_instructions="Return one bounded fixture object.",
    retained_input="Exercise the closed provider verifier.",
    retained_schema=schema,
    invocation_id="subprocess-parser-swap",
    model_requested="gpt-5",
    maximum_output_tokens=64,
)
raw = canonical_json_bytes({
    "fixture_protocol": fixture.wire_protocol,
    "request_ref": request.request_id,
    "engine": "gpt-5",
    "response_ref": "fixture-relabeled-openai",
    "state": "done",
    "result_json": '{"status":"offline-only"}',
    "metering": {
        "prompt_units": 2,
        "prompt_unit_details": None,
        "result_units": 1,
        "result_unit_details": None,
        "total_units": 3,
    },
})
try:
    object.__setattr__(openai, "_response_parser", lambda *_args, **_kwargs: None)
except AttributeError:
    pass
else:
    raise SystemExit("public contract unexpectedly accepted a parser field")
for name in (
    "provider_id",
    "provenance_schema_version",
    "provider_version",
    "endpoint",
    "credential_env_name",
    "credential_present",
    "audited_live_allowed",
    "wire_protocol",
):
    object.__setattr__(openai, name, getattr(fixture, name))
try:
    openai.parse_and_project_response(
        raw_bytes=raw,
        requested_model="gpt-5",
        output_schema=schema,
        maximum_output_bytes=4096,
        expected_request_id=request.request_id,
    )
except ProviderVerificationError:
    pass
else:
    raise SystemExit("mutated facade relabeled deterministic wire as OpenAI")
""",
            ],
            cwd=self.root,
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            mutation_probe.returncode,
            0,
            mutation_probe.stdout + mutation_probe.stderr,
        )

    def test_openai_verifier_matches_reference_provider_wire_contract(self) -> None:
        contract = require_provider_verifier(
            OPENAI_PROVIDER_ID,
            MODEL_PROVIDER_CUSTODY_SCHEMA_V1,
        )
        config = OpenAIResponsesConfig()
        with self.assertRaises(ModelProviderError):
            OpenAIResponsesConfig(schema_name="caller_selected_output")
        policy = openai_responses_policy()
        self.assertEqual(contract.provider_id, config.provider_id)
        self.assertEqual(contract.endpoint, config.endpoint)
        self.assertEqual(contract.provider_id, policy.adapter_id)
        self.assertEqual(contract.provider_version, policy.policy_id)
        self.assertEqual(contract.credential_env_name, policy.credential_env_name)
        body = canonical_json_bytes({"wire": "contract-parity"})
        request = EgressRequest(
            adapter_id=contract.provider_id,
            method="POST",
            url=contract.endpoint,
            headers=(
                ("Accept", "application/json"),
                ("User-Agent", "Scientist-One-vNext/1"),
            ),
            body=body,
            content_type="application/json",
            idempotency_key="provider-contract-parity",
        )
        self.assertEqual(
            contract.expected_request_id(body, "provider-contract-parity"),
            request.request_id,
        )

    def test_reversed_valid_parameter_array_is_admitted_and_preparable(self) -> None:
        invocation = self.invocation("invocation-reversed-parameters")
        proposal = self.proposal("reversed-parameters")
        proposal["parameters"] = list(reversed(proposal["parameters"]))  # type: ignore[arg-type]

        outcome = self.controller.admit_model_result(
            invocation,
            self.result(invocation, proposal),
            self.context,
        )

        self.assertTrue(outcome.admitted)
        implementation = outcome.implementation
        assert implementation is not None
        prepared = self.controller.prepare_local_run(
            implementation,
            run_id="run-reversed-parameters",
        )
        self.assertEqual(
            prepared.spec.configuration_sha256,
            implementation.configuration_artifact.sha256,
        )

    def test_execution_receipt_reports_unattested_network_status(self) -> None:
        admission = self.admit("network-status")
        self.assertTrue(admission.admitted)
        implementation = admission.implementation
        assert implementation is not None
        prepared = self.controller.prepare_local_run(
            implementation,
            run_id="run-network-status",
        )
        backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/python3",),
            observed_available_memory_bytes=2 * 1024**3,
        )

        executed = self.controller.execute_prepared_local_run(
            prepared,
            backend,
            idempotency_key="network-status",
        )

        self.assertEqual(
            executed.submission.network_use_status,
            NetworkUseStatus.UNKNOWN_UNATTESTED,
        )
        self.assertFalse(executed.submission.network_isolation_attested)
        receipt = safe_json_loads(
            self.registry.get_bytes(executed.execution_receipt.sha256)
        )
        self.assertEqual(receipt["network_use_status"], "UNKNOWN_UNATTESTED")
        self.assertFalse(receipt["network_isolation_attested"])

    def test_reviewed_worker_uses_parent_descriptors_and_exclusive_outputs(self) -> None:
        from scientist_one import autonomous_implementation as implementation_module

        code = implementation_module._render_worker(
            ReviewedWorkerTemplate.AFFINE_MEAN_V1
        )
        data = canonical_json_bytes({"values": [1.0, 2.0, 3.0]}) + b"\n"
        evaluator = canonical_json_bytes(
            {
                "direction": "HIGHER_IS_BETTER",
                "metric": "template_defined_scalar",
                "metric_id": "metric-autonomous-template-scalar",
            }
        ) + b"\n"
        configuration = canonical_json_bytes(
            {
                "schema_version": "AUTONOMOUS_IMPLEMENTATION_CONFIGURATION_V1",
                "experiment_id": "experiment-worker-descriptor-test",
                "hypothesis_id": "hypothesis-worker-descriptor-test",
                "implementation_id": "implementation-worker-descriptor-test",
                "phase": "EXPLORATORY",
                "proposal_id": "proposal-worker-descriptor-test",
                "proposal_artifact_sha256": digest("proposal-worker-descriptor-test"),
                "template_id": ReviewedWorkerTemplate.AFFINE_MEAN_V1.value,
                "template_version": "1.0",
                "parameters": {"bias": 1.0, "scale": 2.0},
                "parent_evidence_sha256s": [digest("worker-parent")],
                "data_sha256": hashlib.sha256(data).hexdigest(),
                "evaluator_sha256": hashlib.sha256(evaluator).hexdigest(),
                "seeds": [3],
            }
        ) + b"\n"
        worker_path = self.root / "reviewed-worker.py"
        config_path = self.root / "worker-config.json"
        data_path = self.root / "worker-data.json"
        evaluator_path = self.root / "worker-evaluator.json"
        job_path = self.root / "trusted-job"
        job_path.mkdir(mode=0o700)
        worker_path.write_bytes(code)
        config_path.write_bytes(configuration)
        data_path.write_bytes(data)
        evaluator_path.write_bytes(evaluator)
        outside = self.root / "outside.json"
        outside.write_bytes(b"safe")
        (job_path / "seed-3.json").symlink_to(outside)

        descriptors = {
            "SCIENTIST_ONE_JOB_DIR_FD": os.open(
                job_path,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            ),
            "SCIENTIST_ONE_INPUT_CODE_FD": os.open(worker_path, os.O_RDONLY),
            "SCIENTIST_ONE_INPUT_CONFIGURATION_FD": os.open(
                config_path, os.O_RDONLY
            ),
            "SCIENTIST_ONE_INPUT_DATA_FD": os.open(data_path, os.O_RDONLY),
            "SCIENTIST_ONE_INPUT_EVALUATOR_FD": os.open(
                evaluator_path, os.O_RDONLY
            ),
        }
        environment = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "SCIENTIST_ONE_RUN_ID": "run-worker-descriptor-test",
            "SCIENTIST_ONE_SPEC_SHA256": digest("worker-descriptor-spec"),
            **{name: str(value) for name, value in descriptors.items()},
        }
        command = (
            "/usr/bin/python3",
            "-I",
            "-S",
            "-B",
            str(worker_path),
            "--config",
            "ignored-path",
            "--data",
            "ignored-path",
        )
        try:
            rejected = subprocess.run(
                command,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=tuple(descriptors.values()),
                check=False,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(outside.read_bytes(), b"safe")
            self.assertFalse((job_path / "output-manifest.json").exists())

            (job_path / "seed-3.json").unlink()
            completed = subprocess.run(
                command,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=tuple(descriptors.values()),
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            manifest = safe_json_loads(
                (job_path / "output-manifest.json").read_bytes()
            )
            self.assertEqual(manifest["code_sha256"], hashlib.sha256(code).hexdigest())
            self.assertEqual(
                manifest["configuration_sha256"],
                hashlib.sha256(configuration).hexdigest(),
            )
            self.assertEqual(manifest["data_sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(
                manifest["evaluator_sha256"],
                hashlib.sha256(evaluator).hexdigest(),
            )
        finally:
            for descriptor in descriptors.values():
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
