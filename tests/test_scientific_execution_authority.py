"""Non-evidentiary boundary tests for scientific-execution authority.

These fixtures only exercise custody and validation paths.  They neither run a
backend nor assert that any scientific result exists.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.experiments import (
    EvidenceClass,
    ExperimentError,
    FrozenRunSpec,
    SCIENTIFIC_BACKEND_ATTESTATION_ENVELOPE_SCHEMA,
    SCIENTIFIC_BACKEND_ATTESTATION_LOGICAL_TYPE,
    SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE,
    SCIENTIFIC_EXECUTION_ENVIRONMENT_LOGICAL_TYPE,
    SCIENTIFIC_EXECUTION_ENVIRONMENT_SCHEMA,
    SCIENTIFIC_EXECUTION_ISOLATION_LOGICAL_TYPE,
    SCIENTIFIC_EXECUTION_ISOLATION_SCHEMA,
    SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE,
    ScientificBackendAttestationProfile,
    ScientificExecutionAuthority,
    ScientificExecutionAuthorityUnavailable,
    ScientificExecutionOutcome,
    ScientificExecutionVerificationStatus,
    SeedRunStatus,
    _scientific_execution_authority_slot_matches,
    derive_scientific_execution_outcome,
    register_scientific_execution_authority,
    register_scientific_execution_preparation,
    require_scientific_execution_authority,
    require_scientific_execution_preparation,
    resolve_scientific_execution_authority,
    validate_scientific_execution_attestation_claim,
)
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    ExperimentPlan,
    ExperimentStage,
    record_scientific_design_freeze,
    register_frozen_evaluation_contract,
    register_frozen_experiment_plan,
    register_frozen_run_spec,
)
from scientist_one.security import canonical_json_bytes

try:
    from .test_scientific_design import _register_timeline_outputs, make_contract
except ImportError:  # Direct unittest discovery can load this module at top level.
    from test_scientific_design import _register_timeline_outputs, make_contract  # type: ignore[no-redef]


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class ScientificExecutionAuthorityTests(unittest.TestCase):
    """Every fixture is explicitly non-evidentiary and local to its temp root."""

    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="scientific-execution-authority-")
        self.root = Path(self.temporary.name)
        self.registry = ArtifactRegistry(
            self.root, "runs/scientific-execution/registry"
        )
        self.ledger = EventLedger(self.root, "runs/scientific-execution/events.jsonl")
        self.ledger_run_id = "scientific-execution-ledger"
        contract = make_contract()
        evidence = self._fixture_artifact(
            b'{"fixture":"non-evidentiary"}\n',
            "timeline_contract_evidence",
            Role.EVIDENCE_CURATOR,
        )
        contract_record = register_frozen_evaluation_contract(
            self.registry,
            contract=contract,
            parent_artifact_sha256s=(evidence.sha256,),
        )
        code = self._fixture_artifact(
            b"print('non-evidentiary')\n", "experiment_code", Role.IMPLEMENTER
        )
        data = self._fixture_artifact(
            b'{"dataset":"non-evidentiary"}\n',
            "experiment_dataset",
            Role.EVIDENCE_CURATOR,
        )
        configuration = self._fixture_artifact(
            b'{"configuration":"non-evidentiary"}\n',
            "experiment_configuration",
            Role.PROTOCOL_DESIGNER,
        )
        evaluator = self._fixture_artifact(
            b'{"evaluator":"non-evidentiary"}\n',
            "evaluator_implementation",
            Role.PROTOCOL_DESIGNER,
        )
        plans = tuple(
            ExperimentPlan(
                experiment_id="experiment-primary",
                hypothesis_id="hypothesis-primary",
                stage=ExperimentStage.EXPLORATORY,
                contract_sha256=contract.sha256,
                dataset_split_id="development-v1",
                seed=seed,
                evaluator_id="evaluator-v1",
                uses_protected_resource=False,
                results_seen_before_plan=False,
            )
            for seed in contract.seed_reporting.seeds
        )
        plan_records = tuple(
            register_frozen_experiment_plan(
                self.registry,
                contract=contract,
                contract_artifact_sha256=contract_record.sha256,
                plan=plan,
            )
            for plan in plans
        )
        self.spec = FrozenRunSpec(
            run_id="scientific-execution-fixture",
            experiment_id="experiment-primary",
            hypothesis_id="hypothesis-primary",
            phase=ExperimentStage.EXPLORATORY.value,
            argv=("/usr/bin/python3", "-I", "non-evidentiary-fixture.py"),
            working_directory=".",
            code_sha256=code.sha256,
            data_sha256=data.sha256,
            configuration_sha256=configuration.sha256,
            evaluator_sha256=evaluator.sha256,
            seeds=contract.seed_reporting.seeds,
            required_ablations=("ablation-core",),
            evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
            metadata={"evaluation_split": "development-v1"},
        )
        self.spec_record = register_frozen_run_spec(
            self.registry,
            contract=contract,
            contract_artifact_sha256=contract_record.sha256,
            experiment_plan_artifact_sha256s=tuple(item.sha256 for item in plan_records),
            spec=self.spec,
        )
        record_scientific_design_freeze(
            self.registry,
            self.ledger,
            run_id=self.ledger_run_id,
            contract=contract,
            contract_artifact_sha256=contract_record.sha256,
            experiment_plan_artifact_sha256s=tuple(item.sha256 for item in plan_records),
            frozen_run_spec_artifact_sha256=self.spec_record.sha256,
        )
        self.values = {
            "registry": self.registry,
            "spec": self.spec,
            "spec_record": self.spec_record,
            "contract": contract,
            "contract_record": contract_record,
            "plan_records": plan_records,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _fixture_artifact(
        self, payload: bytes, logical_type: str, role: Role
    ) -> ArtifactRecord:
        return self.registry.put_bytes(
            payload,
            logical_type=logical_type,
            origin="explicitly non-evidentiary scientific-execution test fixture",
            creator_role=role,
            creation_command=("test", "scientific-execution-authority"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    @staticmethod
    def _profile(backend_id: str) -> ScientificBackendAttestationProfile:
        return ScientificBackendAttestationProfile(
            backend_id=backend_id,
            attestation_schema="non-evidentiary-test-attestation/v1",
            verifier_id="test-verifier",
            trust_root_id="test-trust-root",
        )

    def _plan(self):
        from scientist_one.experiments import plan_adaptive_execution

        profile = self.spec.compute_profile
        return plan_adaptive_execution(
            profile,
            self.spec.resource_estimate,
            observed_available_memory_bytes=profile.memory_limit_bytes,
            pending_tasks=len(self.spec.seeds),
            bytes_per_sample=self.spec.bytes_per_sample,
            worker_overhead_bytes=self.spec.worker_overhead_bytes,
        )

    def _prepare(self, backend_id: str = "unknown-real-like-backend") -> ArtifactRecord:
        return register_scientific_execution_preparation(
            self.registry,
            self.ledger,
            ledger_run_id=self.ledger_run_id,
            frozen_run_spec_artifact_sha256=self.spec_record.sha256,
            adaptive_execution_plan=self._plan(),
            backend_profile=self._profile(backend_id),
        )

    def _candidate_closure(
        self, backend_id: str = "unknown-real-like-backend"
    ) -> dict[str, ArtifactRecord]:
        preparation_record = self._prepare(backend_id)
        preparation = require_scientific_execution_preparation(
            self.registry,
            self.ledger,
            preparation_artifact_sha256=preparation_record.sha256,
            expected_ledger_run_id=self.ledger_run_id,
            expected_execution_run_id=self.spec.run_id,
        )
        _register_timeline_outputs(self.values)
        manifest_record: ArtifactRecord = self.values["manifest_record"]
        output_records = tuple(self.values["output_records"])
        profile = preparation.backend_profile.to_dict()
        environment_value = {
            "schema_version": SCIENTIFIC_EXECUTION_ENVIRONMENT_SCHEMA,
            "ledger_run_id": self.ledger_run_id,
            "execution_run_id": self.spec.run_id,
            "backend_profile": profile,
            "environment_fingerprint": _digest("non-evidentiary-environment"),
            "host_instance_id": "non-evidentiary-host",
            "boot_session_id": "non-evidentiary-boot",
            "hardware_fingerprint": _digest("non-evidentiary-hardware"),
            "writable_storage_id": "non-evidentiary-storage",
            "claims": {},
        }
        environment_record = self.registry.put_json(
            environment_value,
            logical_type=SCIENTIFIC_EXECUTION_ENVIRONMENT_LOGICAL_TYPE,
            origin="non-evidentiary scientific-execution test fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("test", "scientific-execution-authority"),
            parent_artifacts=(preparation_record.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        isolation_value = {
            "schema_version": SCIENTIFIC_EXECUTION_ISOLATION_SCHEMA,
            "ledger_run_id": self.ledger_run_id,
            "execution_run_id": self.spec.run_id,
            "backend_profile": profile,
            "environment_artifact_sha256": environment_record.sha256,
            "isolation_policy_sha256": _digest("non-evidentiary-isolation-policy"),
            "network_used": False,
            "network_isolation_attested": True,
            "shared_writable_state_ids": [],
            "cache_used": False,
            "checkpoint_used": False,
            "resumed_from_checkpoint": False,
            "claims": {},
        }
        isolation_record = self.registry.put_json(
            isolation_value,
            logical_type=SCIENTIFIC_EXECUTION_ISOLATION_LOGICAL_TYPE,
            origin="non-evidentiary scientific-execution test fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("test", "scientific-execution-authority"),
            parent_artifacts=(preparation_record.sha256, environment_record.sha256),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        claim = {
            "schema_version": "scientific-backend-execution-claim/v1",
            "ledger_run_id": self.ledger_run_id,
            "execution_run_id": self.spec.run_id,
            "backend_profile": profile,
            "backend_job_id": "non-evidentiary-job",
            "provider_invocation_id": "non-evidentiary-invocation",
            "challenge_nonce": preparation.challenge_nonce,
            "preparation_artifact_sha256": preparation_record.sha256,
            "frozen_run_spec_artifact_sha256": self.spec_record.sha256,
            "frozen_run_spec_sha256": self.spec.sha256,
            "scientific_binding_sha256": self.spec.scientific_binding_sha256,
            "execution_plan_artifact_sha256": preparation.execution_plan_artifact_sha256,
            "execution_plan_sha256": preparation.execution_plan_sha256,
            "execution_input_binding_artifact_sha256": preparation.execution_input_binding_artifact_sha256,
            "input_artifact_sha256s": list(preparation.input_artifact_sha256s),
            "input_artifact_record_hashes": list(preparation.input_artifact_record_hashes),
            "argv": list(self.spec.argv),
            "seeds": list(self.spec.seeds),
            "output_manifest_artifact_sha256": manifest_record.sha256,
            "output_manifest_record_hash": str(manifest_record.record_hash),
            "output_artifact_sha256s": [item.sha256 for item in output_records],
            "output_artifact_record_hashes": [str(item.record_hash) for item in output_records],
            "environment_artifact_sha256": environment_record.sha256,
            "environment_record_hash": str(environment_record.record_hash),
            "environment_fingerprint": environment_value["environment_fingerprint"],
            "isolation_attestation_artifact_sha256": isolation_record.sha256,
            "isolation_attestation_record_hash": str(isolation_record.record_hash),
            "isolation_policy_sha256": isolation_value["isolation_policy_sha256"],
            "network_used": False,
            "cache_used": False,
            "checkpoint_used": False,
            "resumed_from_checkpoint": False,
            "attested_started_at": preparation_record.created_at,
            "attested_completed_at": manifest_record.created_at,
            "outcome": ScientificExecutionOutcome.COMPLETED.value,
        }
        attestation_record = self.registry.put_json(
            {
                "schema_version": SCIENTIFIC_BACKEND_ATTESTATION_ENVELOPE_SCHEMA,
                "backend_profile": profile,
                "claim": claim,
                "signature": "non-evidentiary-test-signature",
            },
            logical_type=SCIENTIFIC_BACKEND_ATTESTATION_LOGICAL_TYPE,
            origin="non-evidentiary scientific-execution test fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("test", "scientific-execution-authority"),
            parent_artifacts=(
                preparation_record.sha256,
                manifest_record.sha256,
                environment_record.sha256,
                isolation_record.sha256,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        return {
            "preparation": preparation_record,
            "manifest": manifest_record,
            "environment": environment_record,
            "isolation": isolation_record,
            "attestation": attestation_record,
        }

    def _resolve(self, closure: dict[str, ArtifactRecord]):
        return resolve_scientific_execution_authority(
            self.registry,
            self.ledger,
            preparation_artifact_sha256=closure["preparation"].sha256,
            output_manifest_artifact_sha256=closure["manifest"].sha256,
            environment_artifact_sha256=closure["environment"].sha256,
            isolation_attestation_artifact_sha256=closure["isolation"].sha256,
            backend_attestation_artifact_sha256=closure["attestation"].sha256,
            expected_ledger_run_id=self.ledger_run_id,
            expected_execution_run_id=self.spec.run_id,
        )

    def test_backend_profile_requires_exact_schema_and_roundtrips(self) -> None:
        profile = self._profile("unknown-real-like-backend")
        self.assertEqual(
            ScientificBackendAttestationProfile.from_mapping(profile.to_dict()), profile
        )
        with self.assertRaises(ExperimentError):
            ScientificBackendAttestationProfile.from_mapping(
                {"backend_id": "unknown-real-like-backend"}
            )

    def test_preparation_roundtrip_is_prospective_and_reopens_exact_inputs(self) -> None:
        record = self._prepare()
        preparation = require_scientific_execution_preparation(
            self.registry,
            self.ledger,
            preparation_artifact_sha256=record.sha256,
            expected_ledger_run_id=self.ledger_run_id,
            expected_execution_run_id=self.spec.run_id,
        )
        self.assertFalse(preparation.scientific_evidence)
        self.assertEqual(preparation.authority_scope, "PROSPECTIVE_PROTOCOL_ONLY")
        self.assertEqual(preparation.frozen_run_spec_artifact_sha256, self.spec_record.sha256)
        self.assertEqual(len(preparation.input_artifact_sha256s), 4)
        event = self.ledger.events()[preparation.ledger_event_index]
        self.assertEqual(event.event_id, preparation.ledger_event_id)
        self.assertEqual(event.event_hash, preparation.ledger_event_hash)
        self.assertEqual(event.event_type, "CHECKPOINT")
        self.assertIn("scientific_execution_preparation", event.metadata)

    def test_crash_after_event_before_artifact_recovers_same_nonce_and_event(self) -> None:
        original_put_bytes_locked = ArtifactRegistry._put_bytes_locked

        def crash_before_preparation_artifact(instance, guard, data, **kwargs):
            if kwargs["logical_type"] == SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE:
                raise RuntimeError("test-only simulated crash after ledger event")
            return original_put_bytes_locked(instance, guard, data, **kwargs)

        with patch.object(
            ArtifactRegistry,
            "_put_bytes_locked",
            new=crash_before_preparation_artifact,
        ):
            with self.assertRaisesRegex(RuntimeError, "test-only simulated crash"):
                self._prepare()
        admitted = self.ledger.events()
        self.assertEqual(len(admitted), 2)  # design freeze, then preparation admission
        admitted_binding = admitted[-1].metadata["scientific_execution_preparation"]
        record = self._prepare()
        preparation = require_scientific_execution_preparation(
            self.registry,
            self.ledger,
            preparation_artifact_sha256=record.sha256,
            expected_ledger_run_id=self.ledger_run_id,
            expected_execution_run_id=self.spec.run_id,
        )
        self.assertEqual(len(self.ledger.events()), len(admitted))
        self.assertEqual(preparation.challenge_nonce, admitted_binding["challenge_nonce"])
        self.assertEqual(preparation.ledger_event_id, admitted[-1].event_id)
        self.assertEqual(self._prepare().sha256, record.sha256)

    def test_partial_support_artifact_recovers_but_competing_plan_is_rejected(
        self,
    ) -> None:
        original_put_bytes_locked = ArtifactRegistry._put_bytes_locked

        def crash_before_input_binding(instance, guard, data, **kwargs):
            if kwargs["logical_type"] == "scientific_execution_input_binding":
                raise RuntimeError("test-only simulated crash after plan")
            return original_put_bytes_locked(instance, guard, data, **kwargs)

        with patch.object(
            ArtifactRegistry,
            "_put_bytes_locked",
            new=crash_before_input_binding,
        ):
            with self.assertRaisesRegex(RuntimeError, "after plan"):
                self._prepare()
        self.assertEqual(
            sum(
                item.logical_type == "scientific_execution_plan"
                for item in self.registry.list_records()
            ),
            1,
        )
        with self.assertRaisesRegex(ExperimentError, "plan slot is competing"):
            self._prepare("another-unknown-real-like-backend")
        record = self._prepare()
        self.assertEqual(self._prepare().sha256, record.sha256)

    def test_preparation_capacity_fails_before_any_partial_admission(self) -> None:
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        with patch(
            "scientist_one.experiments.MAX_REGISTRY_RECORDS",
            len(before_records) + 2,
        ):
            with self.assertRaisesRegex(ExperimentError, "registry capacity"):
                self._prepare()
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)
        with patch(
            "scientist_one.experiments.MAX_LEDGER_EVENTS",
            len(before_events),
        ):
            with self.assertRaisesRegex(ExperimentError, "ledger event capacity"):
                self._prepare()
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)

    def test_preparation_translates_actual_contract_readback_race_without_writes(self) -> None:
        import scientist_one.evaluation_contract_amendment as amendment

        before = (self.registry.verify_all(raise_on_error=True), self.ledger.assert_valid())
        actual = amendment._contract_identity_roots
        injected = []

        def inventory_then_append(*args, **kwargs):
            roots = actual(*args, **kwargs)
            if not injected:
                injected.append(self._fixture_artifact(
                    b'{"fixture":"concurrent non-evidentiary source"}\n',
                    "concurrent_contract_readback_control",
                    Role.EVIDENCE_CURATOR,
                ))
            return roots

        with patch.object(amendment, "_contract_identity_roots", new=inventory_then_append):
            with self.assertRaisesRegex(
                ExperimentError, "prospective source validation failed",
            ) as caught:
                self._prepare()
        self.assertIsInstance(caught.exception.__cause__, amendment.EvaluationContractAmendmentError)
        self.assertIn("changed during readback", str(caught.exception.__cause__))
        self.assertEqual(len(injected), 1)
        after = self.registry.verify_all(raise_on_error=True)
        self.assertEqual(
            {record.sha256: record for record in after.records},
            {record.sha256: record for record in (*before[0].records, *injected)},
        )
        self.assertEqual(after.count, before[0].count + 1)
        self.assertEqual(after.orphan_paths, before[0].orphan_paths)
        self.assertEqual(self.ledger.assert_valid(), before[1])

    def test_concurrent_preparation_never_creates_competing_partial_slots(self) -> None:
        def prepare_once():
            try:
                return self._prepare()
            except ExperimentError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(lambda _: prepare_once(), range(2)))
        records = tuple(
            item
            for item in self.registry.list_records()
            if item.logical_type
            in {
                "scientific_execution_plan",
                "scientific_execution_input_binding",
                SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE,
            }
        )
        self.assertTrue(any(isinstance(item, ArtifactRecord) for item in outcomes))
        self.assertTrue(
            all(isinstance(item, (ArtifactRecord, ExperimentError)) for item in outcomes)
        )
        self.assertEqual(
            tuple(item.logical_type for item in records).count(
                "scientific_execution_plan"
            ),
            1,
        )
        self.assertEqual(
            tuple(item.logical_type for item in records).count(
                "scientific_execution_input_binding"
            ),
            1,
        )
        self.assertEqual(
            tuple(item.logical_type for item in records).count(
                SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE
            ),
            1,
        )
        self.assertEqual(
            sum(
                "scientific_execution_preparation" in item.metadata
                for item in self.ledger.events()
            ),
            1,
        )

    def _assert_unsupported_backend(self, backend_id: str) -> None:
        closure = self._candidate_closure(backend_id)
        resolution = self._resolve(closure)
        self.assertEqual(
            resolution.status, ScientificExecutionVerificationStatus.UNSUPPORTED
        )
        self.assertIsNone(resolution.authority_artifact_sha256)
        self.assertFalse(resolution.scientific_evidence_eligible)
        self.assertEqual(
            sum(
                item.logical_type == SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE
                for item in self.registry.list_records()
            ),
            0,
        )

    def test_local_mac_backend_is_unsupported_without_artifacts(self) -> None:
        self._assert_unsupported_backend("local-mac")

    def test_fake_gpu_backend_is_unsupported_without_artifacts(self) -> None:
        self._assert_unsupported_backend("fake-gpu-cloud")

    def test_scheduled_gpu_backend_is_unsupported_without_artifacts(self) -> None:
        self._assert_unsupported_backend("scheduled-gpu-cloud")

    def test_unknown_backend_is_blocked_and_register_cannot_issue_artifact(self) -> None:
        closure = self._candidate_closure()
        resolution = self._resolve(closure)
        self.assertEqual(
            resolution.status, ScientificExecutionVerificationStatus.BLOCKED_EXTERNAL
        )
        self.assertEqual(
            resolution.reason_code, "BACKEND_ATTESTATION_VERIFIER_UNAVAILABLE"
        )
        with self.assertRaises(ScientificExecutionAuthorityUnavailable):
            register_scientific_execution_authority(
                self.registry,
                self.ledger,
                preparation_artifact_sha256=closure["preparation"].sha256,
                output_manifest_artifact_sha256=closure["manifest"].sha256,
                environment_artifact_sha256=closure["environment"].sha256,
                isolation_attestation_artifact_sha256=closure["isolation"].sha256,
                backend_attestation_artifact_sha256=closure["attestation"].sha256,
                expected_ledger_run_id=self.ledger_run_id,
                expected_execution_run_id=self.spec.run_id,
            )
        self.assertFalse(
            any(
                item.logical_type == SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE
                for item in self.registry.list_records()
            )
        )

    def test_empty_production_map_rejects_even_a_typed_authority_artifact(self) -> None:
        authority = self._authority_for_timestamp_tests()
        record = self.registry.put_json(
            authority.to_dict(),
            logical_type=SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE,
            origin="source-owned independently attested scientific execution",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "verify-scientific-execution"),
            parent_artifacts=authority.source_artifact_hashes,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaises(ScientificExecutionAuthorityUnavailable):
            require_scientific_execution_authority(
                self.registry,
                self.ledger,
                authority_artifact_sha256=record.sha256,
                expected_ledger_run_id=self.ledger_run_id,
                expected_execution_run_id=self.spec.run_id,
            )

    def test_malformed_cross_run_and_tampered_closures_raise_not_invalid_resolution(self) -> None:
        closure = self._candidate_closure()
        with self.assertRaises(ExperimentError):
            resolve_scientific_execution_authority(
                self.registry,
                self.ledger,
                preparation_artifact_sha256=closure["preparation"].sha256,
                output_manifest_artifact_sha256=closure["manifest"].sha256,
                environment_artifact_sha256=closure["environment"].sha256,
                isolation_attestation_artifact_sha256=closure["isolation"].sha256,
                backend_attestation_artifact_sha256=closure["attestation"].sha256,
                expected_ledger_run_id="other-run",
                expected_execution_run_id=self.spec.run_id,
            )
        malformed = self.registry.put_json(
            {"schema_version": SCIENTIFIC_BACKEND_ATTESTATION_ENVELOPE_SCHEMA},
            logical_type=SCIENTIFIC_BACKEND_ATTESTATION_LOGICAL_TYPE,
            origin="non-evidentiary malformed closure fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("test", "scientific-execution-authority"),
            parent_artifacts=(
                closure["preparation"].sha256,
                closure["manifest"].sha256,
                closure["environment"].sha256,
                closure["isolation"].sha256,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        closure["attestation"] = malformed
        with self.assertRaises(ExperimentError):
            self._resolve(closure)
        # A valid JSON envelope with a changed closure field also fails closed.
        envelope = json.loads(self.registry.get_bytes(
            next(
                record.sha256
                for record in self.registry.list_records()
                if record.logical_type == SCIENTIFIC_BACKEND_ATTESTATION_LOGICAL_TYPE
                and record.sha256 != malformed.sha256
            )
        ))
        envelope["claim"]["challenge_nonce"] = "0" * 64
        tampered = self.registry.put_json(
            envelope,
            logical_type=SCIENTIFIC_BACKEND_ATTESTATION_LOGICAL_TYPE,
            origin="non-evidentiary tampered closure fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("test", "scientific-execution-authority"),
            parent_artifacts=(
                closure["preparation"].sha256,
                closure["manifest"].sha256,
                closure["environment"].sha256,
                closure["isolation"].sha256,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        closure["attestation"] = tampered
        with self.assertRaises(ExperimentError):
            self._resolve(closure)

    def test_system_fixture_and_test_artifact_inputs_are_rejected(self) -> None:
        for logical_type in ("scientific_execution_system_fixture", "test_artifact"):
            with self.subTest(logical_type=logical_type):
                record = self.registry.put_json(
                    {"non_evidentiary": True, "kind": logical_type},
                    logical_type=logical_type,
                    origin="explicitly non-evidentiary test-only input",
                    creator_role=Role.IMPLEMENTER,
                    creation_command=("test", "scientific-execution-authority"),
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                )
                bad_spec = replace(self.spec, code_sha256=record.sha256)
                bad_spec_record = self.registry.put_json(
                    bad_spec.to_dict(),
                    logical_type="frozen_run_spec",
                    origin="run spec frozen after scientific-plan admission and before execution",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    creation_command=("scientist-one", "freeze-run-spec"),
                    parent_artifacts=(
                        self.values["contract_record"].sha256,
                        *(item.sha256 for item in self.values["plan_records"]),
                        record.sha256,
                        bad_spec.data_sha256,
                        bad_spec.configuration_sha256,
                        bad_spec.evaluator_sha256,
                    ),
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                )
                with self.assertRaises(ExperimentError):
                    register_scientific_execution_preparation(
                        self.registry,
                        self.ledger,
                        ledger_run_id=self.ledger_run_id,
                        frozen_run_spec_artifact_sha256=bad_spec_record.sha256,
                        adaptive_execution_plan=self._plan(),
                        backend_profile=self._profile("unknown-real-like-backend"),
                    )

    def test_pure_claim_validator_binds_exact_bytes_and_timestamp_order_is_chronological(self) -> None:
        claim = {"fixture": "non-evidentiary", "value": 1}
        before = len(self.registry.list_records())
        self.assertEqual(
            validate_scientific_execution_attestation_claim(claim, dict(claim)),
            _digest(claim),
        )
        self.assertEqual(len(self.registry.list_records()), before)
        with self.assertRaises(ExperimentError):
            validate_scientific_execution_attestation_claim(claim, {"fixture": "other"})
        base = self._authority_for_timestamp_tests()
        # Lexically, '.9Z' sorts before 'Z'; chronologically it is later.
        with self.assertRaisesRegex(ExperimentError, "timestamps are reversed"):
            replace(
                base,
                attested_started_at="2026-09-04T00:00:00.9Z",
                attested_completed_at="2026-09-04T00:00:00Z",
            )
        # Lexically, a bare 'Z' sorts after '.1Z'; this valid chronology must pass.
        accepted = replace(
            base,
            attested_started_at="2026-09-04T00:00:00Z",
            attested_completed_at="2026-09-04T00:00:00.1Z",
        )
        self.assertEqual(accepted.attested_completed_at, "2026-09-04T00:00:00.1Z")

    def test_authority_slot_selection_closes_each_one_use_identity(self) -> None:
        target = {
            "ledger_run_id": "ledger-run",
            "execution_run_id": "execution-run",
            "preparation_artifact_sha256": _digest("preparation"),
            "challenge_nonce": "a" * 64,
        }
        expected = {
            "ledger_run_id": target["ledger_run_id"],
            "execution_run_id": target["execution_run_id"],
            "preparation_artifact_sha256": target["preparation_artifact_sha256"],
            "challenge_nonce": target["challenge_nonce"],
        }
        for candidate in (
            {
                "preparation_artifact_sha256": expected[
                    "preparation_artifact_sha256"
                ],
                "challenge_nonce": "b" * 64,
                "ledger_run_id": "other-ledger",
                "execution_run_id": "other-execution",
            },
            {
                "preparation_artifact_sha256": _digest("other-preparation"),
                "challenge_nonce": expected["challenge_nonce"],
                "ledger_run_id": "other-ledger",
                "execution_run_id": "other-execution",
            },
            {
                "preparation_artifact_sha256": _digest("other-preparation"),
                "challenge_nonce": "b" * 64,
                "ledger_run_id": expected["ledger_run_id"],
                "execution_run_id": expected["execution_run_id"],
            },
        ):
            with self.subTest(candidate=candidate):
                self.assertTrue(
                    _scientific_execution_authority_slot_matches(
                        candidate,
                        **expected,
                    )
                )
        for candidate in (
            {
                "preparation_artifact_sha256": _digest("other-preparation"),
                "challenge_nonce": "b" * 64,
                "ledger_run_id": "other-ledger",
                "execution_run_id": "other-execution",
            },
            {
                "preparation_artifact_sha256": _digest("other-preparation"),
                "challenge_nonce": "b" * 64,
                "ledger_run_id": "other-ledger",
                "execution_run_id": expected["execution_run_id"],
            },
        ):
            with self.subTest(candidate=candidate):
                self.assertFalse(
                    _scientific_execution_authority_slot_matches(
                        candidate,
                        **expected,
                    )
                )

    def test_manifest_outcome_derivation_is_closed_and_outcome_neutral(self) -> None:
        _register_timeline_outputs(self.values)
        manifest = self.values["manifest"]
        self.assertEqual(self.spec.expected_outputs, ("output_manifest",))
        self.assertTrue(manifest.artifacts)
        self.assertTrue(
            {
                item.logical_type for item in manifest.artifacts
            }.isdisjoint(self.spec.expected_outputs)
        )
        self.assertEqual(
            derive_scientific_execution_outcome(self.spec, manifest),
            ScientificExecutionOutcome.COMPLETED,
        )
        for status in (SeedRunStatus.NEGATIVE, SeedRunStatus.NULL):
            with self.subTest(status=status):
                seed_results = list(manifest.seed_results)
                seed_results[0] = replace(seed_results[0], status=status)
                self.assertEqual(
                    derive_scientific_execution_outcome(
                        self.spec,
                        replace(manifest, seed_results=tuple(seed_results)),
                    ),
                    ScientificExecutionOutcome.COMPLETED,
                )
        for status, expected in (
            (SeedRunStatus.FAILED, ScientificExecutionOutcome.FAILED),
            (SeedRunStatus.INVALID, ScientificExecutionOutcome.INVALID_OUTPUT),
        ):
            with self.subTest(status=status):
                seed_results = list(manifest.seed_results)
                seed_results[0] = replace(
                    seed_results[0],
                    status=status,
                    reason="non-evidentiary outcome fixture",
                )
                self.assertEqual(
                    derive_scientific_execution_outcome(
                        self.spec,
                        replace(manifest, seed_results=tuple(seed_results)),
                    ),
                    expected,
                )
        missing_output_spec = replace(
            self.spec,
            expected_outputs=("output_manifest", "required_summary"),
        )
        with self.assertRaisesRegex(ExperimentError, "expected output"):
            derive_scientific_execution_outcome(
                missing_output_spec,
                replace(manifest, spec_sha256=missing_output_spec.sha256),
            )

    def _authority_for_timestamp_tests(self) -> ScientificExecutionAuthority:
        closure = self._candidate_closure()
        preparation = require_scientific_execution_preparation(
            self.registry,
            self.ledger,
            preparation_artifact_sha256=closure["preparation"].sha256,
            expected_ledger_run_id=self.ledger_run_id,
            expected_execution_run_id=self.spec.run_id,
        )
        event = self.ledger.events()[preparation.ledger_event_index]
        return ScientificExecutionAuthority(
            authority_id="non-evidentiary-authority",
            ledger_run_id=self.ledger_run_id,
            execution_run_id=self.spec.run_id,
            ledger_path=self.ledger.relative_path.as_posix(),
            preparation_artifact_sha256=closure["preparation"].sha256,
            preparation_record_hash=str(closure["preparation"].record_hash),
            frozen_run_spec_artifact_sha256=self.spec_record.sha256,
            frozen_run_spec_sha256=self.spec.sha256,
            scientific_binding_sha256=self.spec.scientific_binding_sha256,
            execution_plan_artifact_sha256=preparation.execution_plan_artifact_sha256,
            execution_input_binding_artifact_sha256=preparation.execution_input_binding_artifact_sha256,
            output_manifest_artifact_sha256=closure["manifest"].sha256,
            output_manifest_record_hash=str(closure["manifest"].record_hash),
            environment_artifact_sha256=closure["environment"].sha256,
            environment_record_hash=str(closure["environment"].record_hash),
            isolation_attestation_artifact_sha256=closure["isolation"].sha256,
            isolation_attestation_record_hash=str(closure["isolation"].record_hash),
            backend_attestation_artifact_sha256=closure["attestation"].sha256,
            backend_attestation_record_hash=str(closure["attestation"].record_hash),
            backend_profile=preparation.backend_profile,
            backend_job_id="non-evidentiary-job",
            provider_invocation_id="non-evidentiary-invocation",
            challenge_nonce=preparation.challenge_nonce,
            backend_claim_sha256=_digest("non-evidentiary-backend-claim"),
            output_artifact_sha256s=tuple(
                item.sha256 for item in self.values["output_records"]
            ),
            output_artifact_record_hashes=tuple(
                str(item.record_hash) for item in self.values["output_records"]
            ),
            environment_fingerprint=_digest("non-evidentiary-environment"),
            isolation_policy_sha256=_digest("non-evidentiary-isolation-policy"),
            attested_started_at="2026-09-04T00:00:00Z",
            attested_completed_at="2026-09-04T00:00:00Z",
            outcome=ScientificExecutionOutcome.COMPLETED,
            network_used=False,
            cache_used=False,
            checkpoint_used=False,
            resumed_from_checkpoint=False,
            ledger_event_id=event.event_id,
            ledger_event_hash=event.event_hash,
            ledger_event_index=preparation.ledger_event_index,
            ledger_prefix_head_hash=event.event_hash,
        )
