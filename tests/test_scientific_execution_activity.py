"""Mechanical, non-evidentiary coverage for execution activity replay.

These fixtures exercise only typed activity custody and replay.  They do not
invoke a backend verifier or issue scientific-execution authority.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
from types import SimpleNamespace
import unittest

from scientist_one.artifacts import ArtifactRecord
from scientist_one.experiments import (
    COMPLETE_GENERIC_ML_ACTIVITY_PROFILE,
    SCIENTIFIC_BACKEND_EXECUTION_CLAIM_SCHEMA_V2,
    SCIENTIFIC_EXECUTION_ACTIVITY_LOGICAL_TYPE,
    SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA,
    SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA_V2,
    ExperimentError,
    ScientificDatasetAccessPurpose,
    ScientificExecutionActivity,
    ScientificExecutionActivityKind,
    ScientificExecutionActivityRow,
    ScientificExecutionActivityTerminal,
    ScientificExecutionArtifactBinding,
    ScientificExecutionAuthority,
    ScientificExecutionOutcome,
    ScientificExecutionTerminalKind,
    _scientific_execution_expected_claim,
    require_scientific_execution_activity,
    require_scientific_execution_preparation,
)
from scientist_one.roles import Role

try:
    from .test_scientific_design import _register_timeline_outputs
    from . import test_scientific_execution_authority as _execution_authority_tests
except ImportError:  # Direct unittest discovery can load this module at top level.
    from test_scientific_design import _register_timeline_outputs  # type: ignore[no-redef]
    import test_scientific_execution_authority as _execution_authority_tests  # type: ignore[no-redef]


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class ScientificExecutionActivityTests(unittest.TestCase):
    """Activity logs are non-evidentiary until a closed verifier authenticates them."""

    def setUp(self) -> None:
        # Reuse the existing exact prospective preparation/spec/manifest fixture,
        # but stop before its test-only attestation envelope and any authority path.
        self.fixture = _execution_authority_tests.ScientificExecutionAuthorityTests(
            methodName="runTest"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.registry = self.fixture.registry
        self.ledger_run_id = self.fixture.ledger_run_id
        self.spec = self.fixture.spec
        self.spec_record = self.fixture.spec_record
        self.preparation_record = self.fixture._prepare()
        self.preparation = require_scientific_execution_preparation(
            self.registry,
            self.fixture.ledger,
            preparation_artifact_sha256=self.preparation_record.sha256,
            expected_ledger_run_id=self.ledger_run_id,
            expected_execution_run_id=self.spec.run_id,
        )
        _register_timeline_outputs(self.fixture.values)
        self.manifest_record: ArtifactRecord = self.fixture.values["manifest_record"]  # type: ignore[assignment]
        self.output_records: tuple[ArtifactRecord, ...] = tuple(
            self.fixture.values["output_records"]  # type: ignore[arg-type]
        )
        self.dataset_record = self._fixture_json(
            {"fixture": "non-evidentiary dataset authority"},
            "scientific_dataset_authority",
            Role.EVIDENCE_CURATOR,
        )
        self.confirmatory_split_record = self._fixture_json(
            {
                "dataset_authority_artifact_sha256": self.dataset_record.sha256,
                "split_role": "CONFIRMATORY",
            },
            "scientific_dataset_split_authority",
            Role.PROTOCOL_DESIGNER,
        )
        self.development_split_record = self._fixture_json(
            {
                "dataset_authority_artifact_sha256": self.dataset_record.sha256,
                "split_role": "DEVELOPMENT",
            },
            "scientific_dataset_split_authority",
            Role.PROTOCOL_DESIGNER,
        )

    def _fixture_json(self, value: object, logical_type: str, role: Role) -> ArtifactRecord:
        return self.registry.put_json(
            value,
            logical_type=logical_type,
            origin="explicitly non-evidentiary scientific activity test fixture",
            creator_role=role,
            creation_command=("test", "scientific-execution-activity"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    @staticmethod
    def _binding(record: ArtifactRecord) -> ScientificExecutionArtifactBinding:
        assert record.record_hash is not None
        return ScientificExecutionArtifactBinding(
            artifact_sha256=record.sha256,
            artifact_record_hash=str(record.record_hash),
        )

    def _activity(self) -> ScientificExecutionActivity:
        rows: list[ScientificExecutionActivityRow] = [
            ScientificExecutionActivityRow(
                sequence=0,
                kind=ScientificExecutionActivityKind.DATASET_READ,
                seed=None,
                condition_id=None,
                ablation_id=None,
                input_artifact_bindings=(),
                output_artifact_bindings=(),
                dataset_artifact_binding=self._binding(self.dataset_record),
                split_artifact_binding=self._binding(self.confirmatory_split_record),
                # Structural/replay custody retains this; admissibility is separate.
                dataset_access_purpose=ScientificDatasetAccessPurpose.CONFIRMATORY_LABELS,
            )
        ]
        for index, (seed, record) in enumerate(
            zip(self.spec.seeds, self.output_records[:-1]), start=1
        ):
            rows.append(
                ScientificExecutionActivityRow(
                    sequence=index,
                    kind=ScientificExecutionActivityKind.PREDICTION_GENERATION,
                    seed=seed,
                    condition_id="candidate",
                    ablation_id=None,
                    input_artifact_bindings=(),
                    output_artifact_bindings=(self._binding(record),),
                    dataset_artifact_binding=None,
                    split_artifact_binding=None,
                    dataset_access_purpose=None,
                )
            )
        rows.append(
            ScientificExecutionActivityRow(
                sequence=len(rows),
                kind=ScientificExecutionActivityKind.ABLATION_EXECUTION,
                seed=None,
                condition_id=None,
                ablation_id="ablation-core",
                input_artifact_bindings=(),
                output_artifact_bindings=(self._binding(self.output_records[-1]),),
                dataset_artifact_binding=None,
                split_artifact_binding=None,
                dataset_access_purpose=None,
            )
        )
        return ScientificExecutionActivity(
            activity_id="non-evidentiary-activity",
            ledger_run_id=self.ledger_run_id,
            execution_run_id=self.spec.run_id,
            preparation_artifact_sha256=self.preparation_record.sha256,
            preparation_record_hash=str(self.preparation_record.record_hash),
            frozen_run_spec_artifact_sha256=self.spec_record.sha256,
            frozen_run_spec_record_hash=str(self.spec_record.record_hash),
            output_manifest_artifact_sha256=self.manifest_record.sha256,
            output_manifest_record_hash=str(self.manifest_record.record_hash),
            capture_profile=COMPLETE_GENERIC_ML_ACTIVITY_PROFILE,
            activity_rows=tuple(rows),
            terminal=ScientificExecutionActivityTerminal(
                sequence=len(rows),
                kind=ScientificExecutionTerminalKind.ALL_PLANNED_WORK_COMPLETED,
                occurred_at="2026-09-04T00:00:00Z",
            ),
        )

    def _store_activity(self, activity: ScientificExecutionActivity) -> ArtifactRecord:
        return self.registry.put_json(
            activity.to_dict(),
            logical_type=SCIENTIFIC_EXECUTION_ACTIVITY_LOGICAL_TYPE,
            origin="backend-captured exhaustive scientific execution activity",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "capture-scientific-execution-activity"),
            parent_artifacts=activity.source_artifact_hashes,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def _replay(self, activity: ScientificExecutionActivity) -> ScientificExecutionActivity:
        record = self._store_activity(activity)
        return require_scientific_execution_activity(
            self.registry,
            activity_artifact_sha256=record.sha256,
            expected_ledger_run_id=self.ledger_run_id,
            expected_execution_run_id=self.spec.run_id,
            expected_preparation_artifact_sha256=self.preparation_record.sha256,
            expected_frozen_run_spec_artifact_sha256=self.spec_record.sha256,
            expected_output_manifest_artifact_sha256=self.manifest_record.sha256,
        )

    def test_canonical_activity_replays_and_retains_confirmatory_labels(self) -> None:
        activity = self._activity()

        self.assertEqual(self._replay(activity), activity)
        self.assertIs(
            activity.activity_rows[0].dataset_access_purpose,
            ScientificDatasetAccessPurpose.CONFIRMATORY_LABELS,
        )

    def test_dto_rejects_noncontiguous_rows_and_duplicate_producers(self) -> None:
        activity = self._activity()
        rows = list(activity.activity_rows)
        rows[1] = replace(rows[1], sequence=8)
        with self.assertRaisesRegex(ExperimentError, "contiguous"):
            replace(activity, activity_rows=tuple(rows))

        rows = list(activity.activity_rows)
        rows[2] = replace(
            rows[2], output_artifact_bindings=rows[1].output_artifact_bindings
        )
        with self.assertRaisesRegex(ExperimentError, "duplicate output producers"):
            replace(activity, activity_rows=tuple(rows))

    def test_replay_rejects_future_consumption_and_manifest_closure_changes(self) -> None:
        activity = self._activity()
        rows = list(activity.activity_rows)
        rows[1] = replace(
            rows[1], input_artifact_bindings=rows[2].output_artifact_bindings
        )
        with self.assertRaisesRegex(ExperimentError, "before it is produced"):
            self._replay(replace(activity, activity_rows=tuple(rows)))

        unexpected = self._fixture_json(
            {"fixture": "unexpected non-evidentiary output"},
            "experiment_output.extra",
            Role.EXPERIMENT_RUNNER,
        )
        rows = list(activity.activity_rows)
        rows[-1] = replace(
            rows[-1],
            output_artifact_bindings=(
                *rows[-1].output_artifact_bindings,
                self._binding(unexpected),
            ),
        )
        with self.assertRaisesRegex(ExperimentError, "exact manifest closure"):
            self._replay(replace(activity, activity_rows=tuple(rows)))

        rows = list(activity.activity_rows)
        rows[-1] = replace(rows[-1], output_artifact_bindings=())
        with self.assertRaisesRegex(ExperimentError, "exact manifest closure"):
            self._replay(replace(activity, activity_rows=tuple(rows)))

    def test_replay_rejects_dataset_split_purpose_mismatch(self) -> None:
        activity = self._activity()
        rows = list(activity.activity_rows)
        rows[0] = replace(
            rows[0], split_artifact_binding=self._binding(self.development_split_record)
        )

        with self.assertRaisesRegex(ExperimentError, "dataset purpose"):
            self._replay(replace(activity, activity_rows=tuple(rows)))

    def test_v2_expected_claim_rejects_terminal_completion_mismatch(self) -> None:
        """The pure expected-claim path detects this before any verifier call."""
        activity = self._activity()
        activity_record = self._store_activity(activity)
        environment_record = self._fixture_json(
            {"fixture": "non-evidentiary environment"},
            "non_evidentiary_environment",
            Role.EXPERIMENT_RUNNER,
        )
        isolation_record = self._fixture_json(
            {"fixture": "non-evidentiary isolation"},
            "non_evidentiary_isolation",
            Role.EXPERIMENT_RUNNER,
        )
        started = self.preparation_record.created_at
        claim = {
            "schema_version": SCIENTIFIC_BACKEND_EXECUTION_CLAIM_SCHEMA_V2,
            "ledger_run_id": self.ledger_run_id,
            "execution_run_id": self.spec.run_id,
            "backend_profile": self.preparation.backend_profile.to_dict(),
            "backend_job_id": "non-evidentiary-job",
            "provider_invocation_id": "non-evidentiary-invocation",
            "challenge_nonce": self.preparation.challenge_nonce,
            "preparation_artifact_sha256": self.preparation_record.sha256,
            "frozen_run_spec_artifact_sha256": self.spec_record.sha256,
            "frozen_run_spec_sha256": self.spec.sha256,
            "scientific_binding_sha256": self.spec.scientific_binding_sha256,
            "execution_plan_artifact_sha256": self.preparation.execution_plan_artifact_sha256,
            "execution_plan_sha256": self.preparation.execution_plan_sha256,
            "execution_input_binding_artifact_sha256": self.preparation.execution_input_binding_artifact_sha256,
            "input_artifact_sha256s": list(self.preparation.input_artifact_sha256s),
            "input_artifact_record_hashes": list(self.preparation.input_artifact_record_hashes),
            "argv": list(self.spec.argv),
            "seeds": list(self.spec.seeds),
            "output_manifest_artifact_sha256": self.manifest_record.sha256,
            "output_manifest_record_hash": str(self.manifest_record.record_hash),
            "output_artifact_sha256s": [record.sha256 for record in self.output_records],
            "output_artifact_record_hashes": [str(record.record_hash) for record in self.output_records],
            "environment_artifact_sha256": environment_record.sha256,
            "environment_record_hash": str(environment_record.record_hash),
            "environment_fingerprint": _digest("non-evidentiary-environment"),
            "isolation_attestation_artifact_sha256": isolation_record.sha256,
            "isolation_attestation_record_hash": str(isolation_record.record_hash),
            "isolation_policy_sha256": _digest("non-evidentiary-isolation"),
            "network_used": False,
            "cache_used": False,
            "checkpoint_used": False,
            "resumed_from_checkpoint": False,
            "attested_started_at": started,
            "attested_completed_at": started,
            "outcome": ScientificExecutionOutcome.COMPLETED.value,
            "execution_activity_artifact_sha256": activity_record.sha256,
            "execution_activity_record_hash": str(activity_record.record_hash),
            "execution_activity_capture_profile": activity.capture_profile,
        }
        candidate = SimpleNamespace(
            claim=claim,
            activity=activity,
            activity_record=activity_record,
            preparation=self.preparation,
            preparation_record=self.preparation_record,
            spec=self.spec,
            spec_record=self.spec_record,
            manifest=self.fixture.values["manifest"],
            manifest_record=self.manifest_record,
            output_records=self.output_records,
            environment_record=environment_record,
            environment={"environment_fingerprint": claim["environment_fingerprint"]},
            isolation_record=isolation_record,
            isolation={
                "isolation_policy_sha256": claim["isolation_policy_sha256"],
                "network_used": False,
                "cache_used": False,
                "checkpoint_used": False,
                "resumed_from_checkpoint": False,
            },
        )

        with self.assertRaisesRegex(ExperimentError, "terminal differs"):
            _scientific_execution_expected_claim(candidate)

    def test_authority_v1_omits_activity_and_v2_roundtrips_exact_fields(self) -> None:
        def value(name: str) -> str:
            return _digest(f"non-evidentiary-{name}")

        authority = ScientificExecutionAuthority(
            authority_id="non-evidentiary-authority",
            ledger_run_id="non-evidentiary-ledger",
            execution_run_id="non-evidentiary-execution",
            ledger_path="runs/non-evidentiary/events.jsonl",
            preparation_artifact_sha256=value("preparation"),
            preparation_record_hash=value("preparation-record"),
            frozen_run_spec_artifact_sha256=value("spec"),
            frozen_run_spec_sha256=value("spec-content"),
            scientific_binding_sha256=value("binding"),
            execution_plan_artifact_sha256=value("plan"),
            execution_input_binding_artifact_sha256=value("input-binding"),
            output_manifest_artifact_sha256=value("manifest"),
            output_manifest_record_hash=value("manifest-record"),
            environment_artifact_sha256=value("environment"),
            environment_record_hash=value("environment-record"),
            isolation_attestation_artifact_sha256=value("isolation"),
            isolation_attestation_record_hash=value("isolation-record"),
            backend_attestation_artifact_sha256=value("attestation"),
            backend_attestation_record_hash=value("attestation-record"),
            backend_profile=self.fixture._profile("unknown-real-like-backend"),
            backend_job_id="non-evidentiary-job",
            provider_invocation_id="non-evidentiary-invocation",
            challenge_nonce="c" * 64,
            backend_claim_sha256=value("claim"),
            output_artifact_sha256s=(value("output"),),
            output_artifact_record_hashes=(value("output-record"),),
            environment_fingerprint=value("fingerprint"),
            isolation_policy_sha256=value("policy"),
            attested_started_at="2026-09-04T00:00:00Z",
            attested_completed_at="2026-09-04T00:00:00Z",
            outcome=ScientificExecutionOutcome.COMPLETED,
            network_used=False,
            cache_used=False,
            checkpoint_used=False,
            resumed_from_checkpoint=False,
            ledger_event_id="non-evidentiary-event",
            ledger_event_hash=value("event"),
            ledger_event_index=0,
            ledger_prefix_head_hash=value("prefix"),
        )
        v1 = authority.to_dict()
        self.assertEqual(v1["schema_version"], SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA)
        self.assertNotIn("execution_activity_artifact_sha256", v1)
        self.assertNotIn("execution_activity_record_hash", v1)
        self.assertEqual(ScientificExecutionAuthority.from_mapping(v1), authority)

        v2_authority = replace(
            authority,
            execution_activity_artifact_sha256=value("activity"),
            execution_activity_record_hash=value("activity-record"),
        )
        v2 = v2_authority.to_dict()
        self.assertEqual(v2["schema_version"], SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA_V2)
        self.assertEqual(v2["execution_activity_artifact_sha256"], value("activity"))
        self.assertEqual(v2["execution_activity_record_hash"], value("activity-record"))
        self.assertEqual(ScientificExecutionAuthority.from_mapping(v2), v2_authority)


if __name__ == "__main__":
    unittest.main()
