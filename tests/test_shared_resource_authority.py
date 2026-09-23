"""Native external accounting helpers, not custody or release authority.

Runtime states are deterministic accounting inputs. CHECKPOINT/STARTED-shaped
events exercise only the shared resource collector, never a successful custody
admission, controller observation, scientific evaluation or two-release run.
"""

from pathlib import Path
import tempfile
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState, TerminalState
import scientist_one.orchestrator as orchestration
from scientist_one.resources import ResourceRuntimeState
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes, secure_directory, sha256_bytes


RUN_ID = "shared-resource-helper-test"


class SharedResourceAuthorityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="shared-resource-authority-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.relative = Path(".scientist-one-build/resource-authority") / RUN_ID
        secure_directory(self.root, self.relative, create=True)
        self.registry = ArtifactRegistry(self.root)
        self.artifacts = {}
        self.ledger_index = 0

    def state(self, index):
        return ResourceRuntimeState(
            schema_version="1.0",
            run_id=RUN_ID,
            config_sha256="a" * 64,
            wall_elapsed_seconds=float(index),
            checkpoint_elapsed_seconds=0.0,
            progress_elapsed_seconds=0.0,
            worker_crashes={},
            wall_started_at_epoch_seconds=100.0,
            wall_observed_at_epoch_seconds=100.0 + index,
            validity_total_units=40,
            exploratory_used=0,
            confirmatory_used=0,
        ).to_dict()

    def publish(self, logical_type, index):
        value = orchestration._persist_resource_authority_for(
            self.root, RUN_ID, logical_type, self.state(index)
        )
        record = self.registry.put_bytes(
            canonical_json_bytes(value["state"]) + b"\n",
            logical_type=logical_type,
            origin="resource helper accounting fixture",
            creator_role=Role.ORCHESTRATOR,
            mime_type="application/json",
        )
        self.assertEqual(record.sha256, value["state_sha256"])
        self.artifacts[record.sha256] = record
        return value

    def history(self):
        return orchestration._read_resource_authority_records(self.root, RUN_ID)

    def filesystem_snapshot(self):
        return tuple(
            (
                path.name,
                path.read_bytes(),
                path.stat().st_ino,
                path.stat().st_size,
                path.stat().st_mtime_ns,
                path.stat().st_ctime_ns,
            )
            for path in sorted((self.root / self.relative).iterdir())
        )

    def ledger(self):
        self.ledger_index += 1
        return EventLedger(self.root, f"events-{self.ledger_index}.jsonl")

    def descriptor(self, authority):
        return orchestration._resource_authority_descriptors_for(
            self.history()[: authority["sequence"] + 1]
        )[-1]

    def append(
        self,
        ledger,
        authority=None,
        *,
        metadata=None,
        event_type="CHECKPOINT",
        simulated=False,
        artifacts=None,
        state_after=None,
    ):
        events = ledger.assert_valid().events
        state = events[-1].requested_state_after if events else MacroState.PROTOCOL
        body = {}
        hashes = ()
        if authority is not None:
            record = self.artifacts[authority["state_sha256"]]
            hashes = (record.sha256,)
            body = {
                "artifact_types": [authority["logical_type"]],
                "artifact_record_hashes": [record.record_hash],
                "resource_authority_checkpoint": self.descriptor(authority),
            }
        if simulated:
            body.update(
                {
                    "evidence_class": "ARCHITECTURE_CONTROL",
                    "execution_kind": "SIMULATED_ARCHITECTURE_CONTROL_STARTED",
                }
            )
        if metadata:
            body.update(metadata)
        return ledger.record(
            run_id=RUN_ID,
            event_id=f"helper-event-{len(events)}",
            timestamp="2026-01-01T00:00:00Z",
            actor_role=Role.ORCHESTRATOR,
            state_before=state,
            requested_state_after=state if state_after is None else state_after,
            artifact_hashes=hashes if artifacts is None else artifacts,
            code_version="shared-resource-helper-fixture",
            configuration_hash="a" * 64,
            dataset_identifiers=(),
            random_seeds=(),
            evaluator_outputs=(),
            reason="Resource collector structure only; no custody execution.",
            event_type=event_type,
            metadata=body,
        )

    def validate(self, ledger, *, mappings=False, records=None):
        snapshot = ledger.assert_valid()
        events = (
            tuple(event.to_dict() for event in snapshot.events)
            if mappings
            else snapshot.events
        )
        return orchestration._validate_resource_authority_ledger_for(
            self.history() if records is None else records, events
        )

    def test_exact_native_external_bytes_and_readback(self):
        first = self.publish("resource_runtime_initial", 0)
        second = self.publish("resource_runtime_pilot_charge", 1)
        self.assertEqual(self.history(), (first, second))
        for index, value in enumerate((first, second)):
            raw = canonical_json_bytes(value) + b"\n"
            path = self.root / self.relative / f"{index:04d}-{sha256_bytes(raw)}.json"
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(
                value["state_sha256"],
                sha256_bytes(canonical_json_bytes(value["state"]) + b"\n"),
            )
        self.assertEqual(
            second["prior_authority_sha256"],
            sha256_bytes(canonical_json_bytes(first) + b"\n"),
        )

    def test_exact_newest_idempotency_does_not_duplicate_or_rewrite(self):
        first = self.publish("resource_runtime_initial", 0)
        before = self.filesystem_snapshot()
        self.assertEqual(
            orchestration._persist_resource_authority_for(
                self.root, RUN_ID, "resource_runtime_initial", self.state(0)
            ),
            first,
        )
        self.assertEqual(self.filesystem_snapshot(), before)

    def test_invalid_stage_types_and_names_are_refused_before_file_publication(self):
        for logical_type in (None, "", "not-a-resource-stage", 7, False, [], {}):
            case = SharedResourceAuthorityTests()
            case.setUp()
            try:
                before = case.filesystem_snapshot()
                with self.subTest(logical_type=logical_type):
                    with self.assertRaises(orchestration.OrchestrationError):
                        orchestration._persist_resource_authority_for(
                            case.root, RUN_ID, logical_type, case.state(0)
                        )
                    self.assertEqual(len(case.filesystem_snapshot()), 0)
                    self.assertEqual(case.filesystem_snapshot(), before)
                    self.assertEqual(case.history(), ())
            finally:
                case.doCleanups()

    def test_authority_envelope_reader_capacity_is_checked_before_publication(self):
        before = self.filesystem_snapshot()
        with self.assertRaises(orchestration.OrchestrationError):
            orchestration._persist_resource_authority_for(
                self.root,
                RUN_ID,
                "resource_runtime_codec_boundary",
                {"payload": "x" * (1024 * 1024)},
            )
        self.assertEqual(len(self.filesystem_snapshot()), 0)
        self.assertEqual(self.filesystem_snapshot(), before)
        self.assertEqual(self.history(), ())

    def test_authority_envelope_just_under_reader_capacity_remains_valid(self):
        stage = "resource_runtime_codec_boundary"
        empty = {"payload": ""}
        # Exact native envelope overhead, including its newline. The state
        # digest changes with contents but always occupies64 ASCII characters.
        empty_envelope = {
            "schema_version": "1.0",
            "kind": "RESOURCE_RUNTIME_AUTHORITY",
            "run_id": RUN_ID,
            "sequence": 0,
            "logical_type": stage,
            "state_sha256": sha256_bytes(canonical_json_bytes(empty) + b"\n"),
            "state": empty,
            "prior_authority_sha256": None,
        }
        overhead = len(canonical_json_bytes(empty_envelope) + b"\n")
        state = {"payload": "x" * (1024 * 1024 - overhead - 1)}
        value = orchestration._persist_resource_authority_for(
            self.root, RUN_ID, stage, state
        )
        self.assertEqual(len(canonical_json_bytes(value) + b"\n"), 1024 * 1024 - 1)
        self.assertEqual(self.history(), (value,))
        before = self.filesystem_snapshot()
        self.assertEqual(
            orchestration._persist_resource_authority_for(
                self.root, RUN_ID, stage, state
            ),
            value,
        )
        self.assertEqual(self.filesystem_snapshot(), before)

    def test_newest_collision_and_earlier_stage_replay_are_zero_write(self):
        self.publish("resource_runtime_initial", 0)
        self.publish("resource_runtime_pilot_charge", 1)
        for stage, index in (
            ("resource_runtime_pilot_charge", 2),
            ("resource_runtime_initial", 0),
        ):
            with self.subTest(stage=stage):
                before = self.filesystem_snapshot()
                with self.assertRaises(orchestration.OrchestrationError):
                    orchestration._persist_resource_authority_for(
                        self.root, RUN_ID, stage, self.state(index)
                    )
                self.assertEqual(self.filesystem_snapshot(), before)

    def test_sixteenth_head_replays_but_seventeenth_is_prewrite_refused(self):
        # Unique fixture stages test the generic existing resource namespace;
        # they are not a new allowed orchestration or custody stage profile.
        values = [
            self.publish(f"resource_runtime_fixture_{index:02d}", index)
            for index in range(16)
        ]
        before = self.filesystem_snapshot()
        self.assertEqual(
            orchestration._persist_resource_authority_for(
                self.root, RUN_ID, "resource_runtime_fixture_15", self.state(15)
            ),
            values[-1],
        )
        with self.assertRaises(orchestration.OrchestrationError):
            orchestration._persist_resource_authority_for(
                self.root, RUN_ID, "resource_runtime_fixture_16", self.state(16)
            )
        self.assertEqual(len(self.filesystem_snapshot()), 16)
        self.assertEqual(self.filesystem_snapshot(), before)
        self.assertEqual(self.history(), tuple(values))

    def test_exact_direct_checkpoints_support_native_events_and_mappings(self):
        first = self.publish("resource_runtime_initial", 0)
        second = self.publish("resource_runtime_confirmatory_charge", 1)
        ledger = self.ledger()
        self.append(ledger, first)
        self.append(ledger, second)
        before = ledger.assert_valid(), self.filesystem_snapshot()
        self.validate(ledger)
        self.validate(ledger, mappings=True)
        self.assertEqual((ledger.assert_valid(), self.filesystem_snapshot()), before)

    def test_two_distinct_sequences_allow_one_exact_simulated_repeat_each(self):
        first = self.publish("resource_runtime_pilot_completion", 0)
        second = self.publish("resource_runtime_confirmatory_charge", 1)
        ledger = self.ledger()
        for authority in (first, second):
            self.append(ledger, authority)
            self.append(ledger, authority, simulated=True)
        # Collector-level exact repeats only: this does not establish that a
        # pilot checkpoint could satisfy the full confirmatory charge owner.
        self.validate(ledger)
        self.validate(ledger, mappings=True)

    def test_multiple_repeat_of_one_sequence_is_refused(self):
        authority = self.publish("resource_runtime_confirmatory_charge", 0)
        ledger = self.ledger()
        self.append(ledger, authority)
        self.append(ledger, authority, simulated=True)
        self.append(ledger, authority, simulated=True)
        with self.assertRaises(orchestration.OrchestrationError):
            self.validate(ledger)

    def test_repeat_cannot_reference_an_older_sequence(self):
        first = self.publish("resource_runtime_pilot_completion", 0)
        second = self.publish("resource_runtime_confirmatory_charge", 1)
        ledger = self.ledger()
        self.append(ledger, first)
        self.append(ledger, second)
        self.append(ledger, first, simulated=True)
        with self.assertRaises(orchestration.OrchestrationError):
            self.validate(ledger)

    def test_missing_extra_and_reordered_direct_checkpoints_are_refused(self):
        first = self.publish("resource_runtime_initial", 0)
        second = self.publish("resource_runtime_confirmatory_charge", 1)
        for order in ((first,), (first, first, second), (second, first)):
            with self.subTest(order=tuple(value["sequence"] for value in order)):
                ledger = self.ledger()
                for authority in order:
                    self.append(ledger, authority)
                with self.assertRaises(orchestration.OrchestrationError):
                    self.validate(ledger)

    def test_malformed_and_unbound_checkpoint_descriptors_are_refused(self):
        authority = self.publish("resource_runtime_initial", 0)
        descriptor = self.descriptor(authority)
        cases = (
            ({"artifact_types": "resource_runtime_initial"}, None),
            (
                {
                    "artifact_types": [
                        "resource_runtime_initial",
                        "resource_runtime_extra",
                    ]
                },
                None,
            ),
            ({"artifact_types": []}, None),
            ({"resource_authority_checkpoint": None}, None),
            (
                {
                    "resource_authority_checkpoint": {
                        **descriptor,
                        "authority_sha256": "f" * 64,
                    }
                },
                None,
            ),
            ({}, ()),
            ({}, ("f" * 64,)),
        )
        for metadata, hashes in cases:
            with self.subTest(metadata=metadata, hashes=hashes):
                ledger = self.ledger()
                self.append(ledger, authority, metadata=metadata, artifacts=hashes)
                with self.assertRaises(orchestration.OrchestrationError):
                    self.validate(ledger)

    def test_simulated_repeat_requires_exact_execution_class(self):
        authority = self.publish("resource_runtime_confirmatory_charge", 0)
        for metadata, event_type in (
            (
                {
                    "evidence_class": "SCIENTIFIC_EVIDENCE",
                    "execution_kind": "SIMULATED_ARCHITECTURE_CONTROL_STARTED",
                },
                "CHECKPOINT",
            ),
            (
                {
                    "evidence_class": "ARCHITECTURE_CONTROL",
                    "execution_kind": "RENAMED_START",
                },
                "CHECKPOINT",
            ),
            (
                {
                    "evidence_class": "ARCHITECTURE_CONTROL",
                    "execution_kind": "SIMULATED_ARCHITECTURE_CONTROL_STARTED",
                },
                "CONFIRMATORY_STARTED",
            ),
        ):
            with self.subTest(metadata=metadata, event_type=event_type):
                ledger = self.ledger()
                self.append(ledger, authority)
                self.append(ledger, authority, metadata=metadata, event_type=event_type)
                with self.assertRaises(orchestration.OrchestrationError):
                    self.validate(ledger)

    def test_exact_security_stop_reconciliation_retains_external_chain(self):
        first = self.publish("resource_runtime_initial", 0)
        self.publish("resource_runtime_confirmatory_charge", 1)
        ledger = self.ledger()
        self.append(ledger, first)
        self.append(
            ledger,
            metadata={
                "resource_authority_chain": orchestration._resource_authority_descriptors_for(
                    self.history()
                )
            },
            event_type="SECURITY_STOP",
            state_after=TerminalState.STOP_SECURITY,
        )
        self.validate(ledger)
        self.validate(ledger, mappings=True)

    def test_reconciliation_rejects_malformed_sequence_shapes(self):
        authority = self.publish("resource_runtime_initial", 0)
        descriptors = orchestration._resource_authority_descriptors_for(self.history())
        for malformed in ("authority-chain", {"0": descriptors[0]}, False, 1, [None]):
            with self.subTest(malformed=malformed):
                ledger = self.ledger()
                self.append(ledger, authority)
                self.append(
                    ledger,
                    metadata={"resource_authority_chain": malformed},
                    event_type="SECURITY_STOP",
                    state_after=TerminalState.STOP_SECURITY,
                )
                with self.assertRaises(orchestration.OrchestrationError):
                    self.validate(ledger)
                with self.assertRaises(orchestration.OrchestrationError):
                    self.validate(ledger, mappings=True)

    def test_reconciliation_requires_exact_chain_security_class_and_one_occurrence(
        self,
    ):
        authority = self.publish("resource_runtime_initial", 0)
        descriptors = orchestration._resource_authority_descriptors_for(self.history())
        for wrong_chain, wrong_type, duplicate in (
            (True, False, False),
            (False, True, False),
            (False, False, True),
        ):
            with self.subTest(
                wrong_chain=wrong_chain, wrong_type=wrong_type, duplicate=duplicate
            ):
                ledger = self.ledger()
                self.append(ledger, authority)
                metadata = {
                    "resource_authority_chain": [] if wrong_chain else descriptors
                }
                event_type = "CHECKPOINT" if wrong_type else "SECURITY_STOP"
                after = None if wrong_type else TerminalState.STOP_SECURITY
                self.append(
                    ledger, metadata=metadata, event_type=event_type, state_after=after
                )
                if duplicate:
                    self.append(
                        ledger,
                        metadata=metadata,
                        event_type=event_type,
                        state_after=after,
                    )
                with self.assertRaises(orchestration.OrchestrationError):
                    self.validate(ledger)


if __name__ == "__main__":
    unittest.main()
