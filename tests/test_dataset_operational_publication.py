"""Inert private publisher controls; no fabricated scientific source authority."""

from __future__ import annotations

from dataclasses import replace
import tempfile
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.roles import Role
from scientist_one import research_state as owner


class DatasetOperationalPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="dataset-operational-cas-")
        self.addCleanup(temporary.cleanup)
        self.registry = ArtifactRegistry(temporary.name, "runs/exposure/registry")
        self.ledger = EventLedger(temporary.name, "runs/exposure/events.jsonl")
        self.append()
        self.plan = owner._scientific_dataset_artifact_plan(
            self.registry,
            {"inert-control": True},
            logical_type="dataset_publication_control",
            origin="inert private publisher control; no scientific authority",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "inert-control"),
            parent_artifacts=(),
            schema_version="1.0",
            created_at=self.ledger.events()[0].timestamp,
        )

    def append(self):
        return self.ledger.append_event(
            run_id="exposure", actor_role=Role.PROTOCOL_DESIGNER,
            state_before=MacroState.GROUND, requested_state_after=MacroState.GROUND,
            artifact_hashes=(), code_version="NON_EVIDENTIARY_PRIVATE_COMMIT_CONTROL",
            configuration_hash="c" * 64,
            reason="Inert publication interleaving, no scientific authority.",
            event_type="CHECKPOINT",
        )

    def snapshot(self):
        return self.registry.verify_all(), self.ledger.assert_valid()

    def preflight(self):
        snapshot = owner._scientific_dataset_publication_snapshot(
            self.registry, self.ledger, run_id="exposure",
        )
        missing, event = owner._preflight_scientific_dataset_publication(
            self.registry, self.ledger, run_id="exposure", plans=(self.plan,),
            event_id="inert-dataset-event", actor_role=Role.EVIDENCE_CURATOR,
            event_artifact_hashes=(self.plan[1].sha256,),
            event_timestamp=self.plan[1].created_at,
            reason="Inert private publication; not source-owned science.", metadata={},
        )
        return dict(
            plans=(self.plan,), missing=missing, event_to_append=event,
            source_snapshot=snapshot,
        )

    def commit(self, arguments):
        return owner._commit_scientific_dataset_publication(
            self.registry, self.ledger, **arguments,
        )

    def reserve(self):
        return self.registry.put_bytes(
            b"inert unfinished operational reservation",
            logical_type="operational_seed_admission", origin="inert control",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "inert-control"), schema_version="1.0",
            validation_result="PENDING", frozen=False,
        )

    def test_actual_publication_and_completed_replay_are_exact(self) -> None:
        self.assertEqual(self.commit(self.preflight()), (self.plan[1],))
        before = self.snapshot()
        self.assertEqual(self.commit(self.preflight()), (self.plan[1],))
        self.assertEqual(self.snapshot(), before)

    def test_record_only_operational_interleaving_is_zero_write_refusal(self) -> None:
        arguments = self.preflight()
        self.reserve()
        before = self.snapshot()
        with self.assertRaisesRegex(ValidationError, "sources changed"):
            self.commit(arguments)
        self.assertEqual(self.snapshot(), before)

    def test_record_only_exposure_prevents_new_preflight_and_completed_retry(self) -> None:
        self.commit(self.preflight())
        self.reserve()
        before = self.snapshot()
        with self.assertRaisesRegex(ValidationError, "possible exposure"):
            self.preflight()
        self.assertEqual(self.snapshot(), before)

    def test_unrelated_ledger_drift_does_not_leave_partial_artifacts(self) -> None:
        arguments = self.preflight()
        self.append()
        before = self.snapshot()
        with self.assertRaisesRegex(ValidationError, "sources changed"):
            self.commit(arguments)
        self.assertEqual(self.snapshot(), before)

    def test_artifact_only_failure_recovers_exactly_without_duplicate_content(self) -> None:
        arguments = self.preflight()
        with patch.object(self.ledger, "_append_locked", side_effect=RuntimeError("interrupted")):
            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                self.commit(arguments)
        before = self.snapshot()
        self.assertEqual(before[0].records, (self.plan[1],))
        self.assertEqual(before[1].event_count, 1)
        self.assertEqual(self.commit(self.preflight()), (self.plan[1],))
        after = self.snapshot()
        self.assertEqual(after[0], before[0])
        self.assertEqual(after[1].event_count, 2)

    def test_substituted_planned_bytes_refuse_before_any_publication(self) -> None:
        arguments = self.preflight()
        arguments["plans"] = ((b"substituted", self.plan[1]),)
        before = self.snapshot()
        with self.assertRaisesRegex(ValidationError, "planned artifact differs"):
            self.commit(arguments)
        self.assertEqual(self.snapshot(), before)

    def test_rehashed_wrong_run_or_state_event_refuses_before_artifact_write(self) -> None:
        for changes in (
            {"run_id": "another-run"},
            {"state_before": MacroState.PREFLIGHT, "requested_state_after": MacroState.PREFLIGHT},
        ):
            with self.subTest(changes=changes):
                arguments = self.preflight()
                arguments["event_to_append"] = replace(
                    arguments["event_to_append"], **changes, event_hash=None,
                )
                before = self.snapshot()
                with self.assertRaises(ValidationError):
                    self.commit(arguments)
                self.assertEqual(self.snapshot(), before)

    def test_rehashed_wrong_storage_path_refuses_before_artifact_write(self) -> None:
        arguments = self.preflight()
        wrong = "runs/exposure/registry/objects/00/" + "0" * 64
        arguments["plans"] = ((self.plan[0], replace(
            self.plan[1], path=wrong, relative_path=wrong, record_hash=None,
        )),)
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            self.commit(arguments)
        self.assertEqual(self.snapshot(), before)


class DatasetAcquisitionPublicationTests(unittest.TestCase):
    """Real prospective plans; no source fetch, license approval or Dataset authority."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="dataset-acquisition-cas-")
        self.addCleanup(temporary.cleanup)
        self.registry = ArtifactRegistry(temporary.name, "runs/acquisition/registry")
        self.ledger = EventLedger(temporary.name, "runs/acquisition/events.jsonl")
        self.ledger.append_event(
            run_id="acquisition", actor_role=Role.PROTOCOL_DESIGNER,
            state_before=MacroState.GROUND, requested_state_after=MacroState.GROUND,
            artifact_hashes=(), code_version="PROSPECTIVE_PLAN_ONLY",
            configuration_hash="c" * 64, reason="Initialize prospective plan test.",
            event_type="CHECKPOINT",
        )

    def snapshot(self):
        return self.registry.verify_all(), self.ledger.assert_valid()

    def reserve(self):
        return self.registry.put_bytes(
            b"inert unresolved reservation, no actual execution",
            logical_type="operational_seed_admission", origin="inert refusal control",
            creator_role=Role.EXPERIMENT_RUNNER,
            validation_result="PENDING", frozen=False,
        )

    def register(self):
        return owner.register_scientific_dataset_acquisition_plan(
            self.registry, self.ledger, run_id="acquisition", dataset_id="prospective-data",
            name="Prospective source only", version="v1",
            source_url="https://datasets.example.org/public/data.json?version=v1",
            expected_body_sha256="d" * 64,
            license_identifier="CC-BY-4.0",
            license_url="https://creativecommons.org/licenses/by/4.0/",
            intended_use="Evaluate a prospectively declared hypothesis.",
            processing_scope=("parse declared numeric fields",),
            derivative_output_scope=("aggregate statistics",),
            redistribution_plan="DERIVED_AGGREGATES_ONLY",
            attribution_notice="Attribute the declared source publisher.",
        )

    def test_actual_plan_and_completed_retry_preserve_exact_record_and_event(self) -> None:
        plan = self.register()
        before = self.snapshot()
        self.assertEqual(self.register(), plan)
        self.assertEqual(self.snapshot(), before)
        resolved = owner.require_scientific_dataset_acquisition_plan(
            self.registry, self.ledger, run_id="acquisition", plan_artifact_hash=plan.sha256,
        )
        self.assertEqual(resolved.artifact_hash, plan.sha256)
        self.assertEqual(before[1].events[-1].timestamp, plan.created_at)
        self.assertEqual(before[1].events[-1].artifact_hashes, (plan.sha256,))

    def test_record_only_reservation_prevents_first_plan(self) -> None:
        self.reserve()
        before = self.snapshot()
        with self.assertRaisesRegex(ValidationError, "possible exposure"):
            self.register()
        self.assertEqual(self.snapshot(), before)

    def test_reservation_after_entry_snapshot_refuses_without_plan_or_event(self) -> None:
        original = owner._scientific_dataset_acquisition_plan_payload
        after_reservation = []

        def interleave(**kwargs):
            value = original(**kwargs)
            self.reserve()
            after_reservation.append(self.snapshot())
            return value

        with patch.object(owner, "_scientific_dataset_acquisition_plan_payload", side_effect=interleave):
            with self.assertRaisesRegex(ValidationError, "sources changed|possible exposure"):
                self.register()
        self.assertEqual(len(after_reservation), 1)
        self.assertEqual(self.snapshot(), after_reservation[0])

    def test_actual_artifact_only_interruption_reuses_original_timestamp(self) -> None:
        with patch.object(self.ledger, "_append_locked", side_effect=RuntimeError("interrupted")):
            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                self.register()
        orphan = self.snapshot()
        self.assertEqual(orphan[0].count, 1)
        self.assertEqual(orphan[1].event_count, 1)
        plan = self.register()
        self.assertEqual(plan, orphan[0].records[0])
        self.assertEqual(self.snapshot()[0], orphan[0])
        self.assertEqual(self.ledger.events()[-1].timestamp, plan.created_at)

    def test_current_reservation_blocks_retry_without_poisoning_historical_reader(self) -> None:
        plan = self.register()
        self.reserve()
        before = self.snapshot()
        with self.assertRaisesRegex(ValidationError, "possible exposure"):
            self.register()
        self.assertEqual(
            owner.require_scientific_dataset_acquisition_plan(
                self.registry, self.ledger, run_id="acquisition", plan_artifact_hash=plan.sha256,
            ).artifact_hash,
            plan.sha256,
        )
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
