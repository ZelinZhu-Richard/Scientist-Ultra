"""Pinned allocation bookkeeping; no release, scientific result or E4 fixture."""

from dataclasses import replace
import tempfile
import unittest
from unittest import mock

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import LedgerError
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from scientist_one.scientific_design import register_frozen_evaluation_contract
from scientist_one.security import canonical_json_bytes, safe_json_loads
import scientist_one.simulated_reserve as reserve_module
from scientist_one.simulated_reserve import (
    SimulatedReserveError,
    register_simulated_reserve_population,
    register_simulated_confirmatory_reserve,
    require_simulated_confirmatory_reserve,
)
from tests.test_protocol_contract_crosswalk import matching_protocol
from tests.test_scientific_design import make_contract


RUN = "simulated-reserve-test"


class SimulatedReserveTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="simulated-reserve-")
        self.addCleanup(directory.cleanup)
        self.root = directory.name
        self.registry = ArtifactRegistry(self.root)
        self.ledger = EventLedger(self.root, "events.jsonl")
        self.evidence = self.registry.put_json(
            {"kind": "NON_EVIDENTIARY_RESERVE_COMPONENT_FIXTURE"},
            logical_type="reserve_test_evidence",
            origin="reserve component test",
            creator_role=Role.EVIDENCE_CURATOR,
        )
        self.contract = make_contract()
        self.contract_record = register_frozen_evaluation_contract(
            self.registry,
            contract=self.contract,
            parent_artifact_sha256s=(self.evidence.sha256,),
        )
        self.protocol = matching_protocol(self.contract)
        self.protocol_record = self.put_protocol(self.protocol)
        self.population = register_simulated_reserve_population(self.registry)

    def put_protocol(self, protocol):
        return self.registry.put_json(
            {
                "kind": "FROZEN_SYNTHETIC_PROTOCOL",
                "frozen": True,
                "protocol": protocol.canonical_dict,
                "protocol_sha256": protocol.sha256,
                "baseline_equivalence": [],
                "blind_patterns": ["NON_EVIDENTIARY"],
                "reproduction_tolerance": 1e-12,
            },
            logical_type="frozen_protocol",
            origin="parentless component protocol",
            creator_role=Role.PROTOCOL_DESIGNER,
            mime_type="application/json",
        )

    def publish(self, **changes):
        values = dict(
            expected_run_id=RUN,
            protocol_artifact_sha256=self.protocol_record.sha256,
            contract_artifact_sha256=self.contract_record.sha256,
            population_artifact_sha256=self.population.sha256,
            window_index=1,
        )
        values.update(changes)
        return register_simulated_confirmatory_reserve(
            self.registry, self.ledger, **values
        )

    def require(self, publication):
        return require_simulated_confirmatory_reserve(
            self.registry,
            self.ledger,
            expected_run_id=RUN,
            reservation_artifact_sha256=publication.record.sha256,
        )

    def snapshot(self):
        return self.registry.verify_all(raise_on_error=True), self.ledger.assert_valid()

    def test_pinned_population_and_actual_first_reservation(self):
        population = safe_json_loads(self.registry.get_bytes(self.population.sha256))
        self.assertEqual(
            population["case_sha256"],
            "a4427436f98e924cd68e90cc7918699ee5daaa2a499e559fc2a47918e18f832d",
        )
        self.assertEqual(len(population["members"]), 16)
        first = self.publish()
        self.assertEqual(
            first.member_ids, ("c01", "c02", "c03", "c04", "t01", "t02", "t03", "t04")
        )
        self.assertEqual(
            safe_json_loads(first.evaluator_payload),
            {
                "control": [-0.15, 0.12, -0.04, 0.09],
                "treatment": [-0.15, 0.12, -0.04, 0.09],
            },
        )
        self.assertEqual(first.protocol, self.protocol)
        self.assertEqual(first.contract, self.contract)
        self.assertEqual(first.record.logical_type, "frozen_confirmatory_split")
        self.assertEqual(
            first.record.parent_artifacts,
            (
                self.population.sha256,
                self.protocol_record.sha256,
                self.contract_record.sha256,
            ),
        )
        self.assertEqual(self.require(first), first)
        self.assertEqual(self.publish(), first)
        self.assertEqual(
            register_simulated_reserve_population(self.registry), self.population
        )

    def test_window_two_requires_actual_predecessor_and_revision(self):
        for prior in (None, self.evidence.sha256):
            before = self.snapshot()
            with self.assertRaises(SimulatedReserveError):
                self.publish(window_index=2, prior_reservation_artifact_sha256=prior)
            self.assertEqual(self.snapshot(), before)
        first = self.publish()
        before = self.snapshot()
        with self.assertRaises(SimulatedReserveError):
            self.publish(
                window_index=2, prior_reservation_artifact_sha256=first.record.sha256
            )
        self.assertEqual(self.snapshot(), before)

    def test_native_two_window_membership_component_without_release(self):
        # This exercises allocation/lineage only. There is deliberately no
        # custody observation, resource charge, evaluator execution or release.
        from scientist_one.evaluation_contract_amendment import (
            register_evaluation_contract_amendment,
        )
        from scientist_one.scientific_protocol_revision import (
            register_scientific_protocol_revision,
        )

        first = self.publish()
        child = replace(
            self.contract,
            version=2,
            success_criteria=("Revised membership-only component criterion.",),
        )
        reason = "Allocate public known-answer component rows without a release."
        amendment = register_evaluation_contract_amendment(
            self.registry,
            self.ledger,
            run_id=RUN,
            amendment_id="reserve-component-amendment",
            parent_contract_artifact_sha256=self.contract_record.sha256,
            child_contract=child,
            author_id=self.contract.frozen_by,
            reason=reason,
            child_evidence_parent_artifact_sha256s=(self.evidence.sha256,),
        )
        revision = register_scientific_protocol_revision(
            self.registry,
            self.ledger,
            expected_run_id=RUN,
            amendment_artifact_sha256=amendment.amendment_record.sha256,
            parent_protocol_artifact_sha256=self.protocol_record.sha256,
            protocol=replace(
                self.protocol,
                study_version=2,
                parent_protocol_hash=self.protocol.sha256,
                revision_reason=reason,
            ),
        )
        second = self.publish(
            protocol_artifact_sha256=revision.protocol_record.sha256,
            contract_artifact_sha256=amendment.contract_record.sha256,
            window_index=2,
            prior_reservation_artifact_sha256=first.record.sha256,
        )
        self.assertEqual(
            second.member_ids,
            ("c05", "c06", "c07", "c08", "t05", "t06", "t07", "t08"),
        )
        self.assertFalse(set(first.member_ids) & set(second.member_ids))
        self.assertEqual(
            safe_json_loads(second.evaluator_payload),
            {
                "control": [0.01, -0.07, 0.05, -0.02],
                "treatment": [0.01, -0.07, 0.05, -0.02],
            },
        )
        self.assertEqual(second.record.parent_artifacts[-1], first.record.sha256)
        self.assertEqual(self.require(second), second)
        self.assertEqual(self.require(first).record, first.record)
        # Sealed P/A replay cannot obtain prospective authority from live
        # public amendment validation or its current snapshots.
        with mock.patch(
            "scientist_one.evaluation_contract_amendment."
            "require_evaluation_contract_amendment",
            side_effect=AssertionError("unexpected live amendment owner"),
        ):
            self.assertEqual(self.require(second), second)

    def test_exact_integer_window_and_protocol_crosswalk(self):
        for index in (True, 1.0, 0, 3):
            before = self.snapshot()
            with self.assertRaises(SimulatedReserveError):
                self.publish(window_index=index)
            self.assertEqual(self.snapshot(), before)
        wrong = self.put_protocol(replace(self.protocol, primary_metric="other-metric"))
        before = self.snapshot()
        with self.assertRaises(SimulatedReserveError):
            self.publish(protocol_artifact_sha256=wrong.sha256)
        self.assertEqual(self.snapshot(), before)

    def append_note(self, metadata=None, *, event_id="reserve-note", artifacts=()):
        from scientist_one.models import MacroState, utc_now

        before = self.ledger.assert_valid()
        state = (
            before.events[-1].requested_state_after
            if before.events
            else MacroState.PROTOCOL
        )
        return self.ledger.record(
            run_id=RUN,
            event_id=event_id,
            timestamp=utc_now(),
            actor_role=Role.ORCHESTRATOR,
            state_before=state,
            requested_state_after=state,
            artifact_hashes=artifacts,
            code_version="reserve-test",
            configuration_hash=self.contract.sha256,
            dataset_identifiers=(),
            random_seeds=(),
            evaluator_outputs=(),
            reason="inert test checkpoint",
            event_type="CHECKPOINT",
            metadata={} if metadata is None else metadata,
        )

    def test_exact_orphan_recovery_consumes_window_without_reallocation(self):
        before = self.snapshot()
        with mock.patch.object(
            EventLedger,
            "_append_locked",
            side_effect=LedgerError("inert append failure"),
        ):
            with self.assertRaises(SimulatedReserveError):
                self.publish()
        after = self.snapshot()
        self.assertEqual(after[0].count, before[0].count + 1)
        self.assertEqual(after[1], before[1])
        orphan = next(
            record
            for record in after[0].records
            if record.logical_type == "frozen_confirmatory_split"
        )
        with self.assertRaises(SimulatedReserveError):
            require_simulated_confirmatory_reserve(
                self.registry,
                self.ledger,
                expected_run_id=RUN,
                reservation_artifact_sha256=orphan.sha256,
            )
        resumed = self.publish()
        self.assertEqual(resumed.record, orphan)
        self.assertEqual(self.snapshot()[0], after[0])
        self.assertEqual(self.publish(), resumed)

    def test_orphan_source_drift_is_irreversible_and_refuses_recovery(self):
        with mock.patch.object(
            EventLedger,
            "_append_locked",
            side_effect=LedgerError("inert append failure"),
        ):
            with self.assertRaises(SimulatedReserveError):
                self.publish()
        self.registry.put_json(
            {"note": "later"},
            logical_type="later_note",
            origin="later note",
            creator_role=Role.ORCHESTRATOR,
        )
        before = self.snapshot()
        with self.assertRaises(SimulatedReserveError):
            self.publish()
        with self.assertRaises(SimulatedReserveError):
            self.publish(window_index=2)
        self.assertEqual(self.snapshot(), before)

    def test_unrelated_appends_preserve_historical_readback(self):
        first = self.publish()
        self.registry.put_json(
            {"note": "later"},
            logical_type="later_note",
            origin="later note",
            creator_role=Role.ORCHESTRATOR,
        )
        self.append_note()
        before = self.snapshot()
        reopened = self.require(first)
        self.assertEqual(reopened.record, first.record)
        self.assertEqual(
            reopened.source_registry_identities, first.source_registry_identities
        )
        self.assertEqual((reopened.registry_snapshot, reopened.ledger_snapshot), before)
        self.assertEqual(self.snapshot(), before)

    def test_completed_readback_detects_final_registry_race(self):
        first = self.publish()
        real = reserve_module._require_at_snapshot
        injected = []

        def drift(*args, **kwargs):
            result = real(*args, **kwargs)
            injected.append(
                self.registry.put_json(
                    {"note": "concurrent"},
                    logical_type="later_note",
                    origin="later note",
                    creator_role=Role.ORCHESTRATOR,
                )
            )
            return result

        with mock.patch.object(
            reserve_module, "_require_at_snapshot", side_effect=drift
        ):
            with self.assertRaises(SimulatedReserveError):
                self.require(first)
        self.assertEqual(len(injected), 1)

    def test_population_and_split_aliases_refuse_zero_write(self):
        for payload in (
            {"schema_version": "sim-reserve-pop/v1"},
            {"renamed": {"schema_version": "sim-reserve/v1"}},
            {"kind": "FROZEN_CONFIRMATORY_SPLIT"},
            {"renamed": {"profile": "PINNED_CAL_TRUE_NULL_TWO_WINDOWS_V1"}},
        ):
            with self.subTest(payload=payload):
                case = SimulatedReserveTests()
                case.setUp()
                try:
                    case.registry.put_json(
                        payload,
                        logical_type="renamed_alias",
                        origin="inert alias",
                        creator_role=Role.ORCHESTRATOR,
                    )
                    before = case.snapshot()
                    with self.assertRaises(SimulatedReserveError):
                        case.publish()
                    self.assertEqual(case.snapshot(), before)
                finally:
                    case.doCleanups()

    def test_unmatched_reserved_events_refuse_initial_and_completed(self):
        for after in (False, True):
            for metadata, event_id in (
                ({}, "sim-reserve-unmatched"),
                (
                    {"renamed": {"simulated_confirmatory_reserve": None}},
                    "renamed-reserve",
                ),
                (
                    {"renamed": {"schema_version": "sim-reserve-event/v1"}},
                    "renamed-schema",
                ),
            ):
                with self.subTest(after=after, metadata=metadata):
                    case = SimulatedReserveTests()
                    case.setUp()
                    try:
                        publication = case.publish() if after else None
                        case.append_note(metadata, event_id=event_id)
                        before = case.snapshot()
                        with self.assertRaises(SimulatedReserveError):
                            case.require(publication) if after else case.publish()
                        self.assertEqual(case.snapshot(), before)
                    finally:
                        case.doCleanups()

    def test_record_capacity_and_clock_denials_do_not_publish(self):
        before = self.snapshot()
        with mock.patch.object(reserve_module, "MAX_REGISTRY_RECORDS", before[0].count):
            with self.assertRaises(SimulatedReserveError):
                self.publish()
        with mock.patch.object(
            reserve_module, "utc_now", return_value="2020-01-01T00:00:00Z"
        ):
            with self.assertRaises(SimulatedReserveError):
                self.publish()
        self.assertEqual(self.snapshot(), before)

    def test_corrected_reservation_consumes_slot_without_use_authority(self):
        from scientist_one.models import utc_now

        first = self.publish()
        self.ledger.record(
            run_id=RUN,
            event_id="reserve-correction",
            timestamp=utc_now(),
            actor_role=Role.ORCHESTRATOR,
            state_before=first.event.requested_state_after,
            requested_state_after=first.event.requested_state_after,
            artifact_hashes=(),
            code_version="reserve-test",
            configuration_hash=self.contract.sha256,
            dataset_identifiers=(),
            random_seeds=(),
            evaluator_outputs=(),
            reason="inert corrective annotation",
            event_type="CORRECTION",
            supersedes_event_id=first.event.event_id,
            metadata={},
        )
        before = self.snapshot()
        with self.assertRaises(SimulatedReserveError):
            self.require(first)
        with self.assertRaises(SimulatedReserveError):
            self.publish()
        self.assertEqual(self.snapshot(), before)

    def test_substituted_membership_and_duplicate_window_are_not_reallocated(self):
        first = self.publish()
        value = safe_json_loads(self.registry.get_bytes(first.record.sha256))
        value["member_ids"][0] = "c08"
        self.registry.put_json(
            value,
            logical_type="frozen_confirmatory_split",
            origin="inert conflicting allocation",
            creator_role=Role.PROTOCOL_DESIGNER,
            schema_version="sim-reserve/v1",
            mime_type="application/json",
            parent_artifacts=first.record.parent_artifacts,
        )
        before = self.snapshot()
        with self.assertRaises(SimulatedReserveError):
            self.require(first)
        with self.assertRaises(SimulatedReserveError):
            self.publish()
        self.assertEqual(self.snapshot(), before)

    def test_legacy_split_and_unbound_custody_refuse_migration(self):
        for family in (
            "frozen_confirmatory_split",
            "custody_record",
            "fresh_custody_receipt",
        ):
            with self.subTest(family=family):
                case = SimulatedReserveTests()
                case.setUp()
                try:
                    case.registry.put_json(
                        {"kind": "legacy", "fixture": True},
                        logical_type=family,
                        origin="inert legacy migration",
                        creator_role=Role.PROTOCOL_DESIGNER,
                    )
                    before = case.snapshot()
                    with self.assertRaises(SimulatedReserveError):
                        case.publish()
                    self.assertEqual(case.snapshot(), before)
                finally:
                    case.doCleanups()

    def test_native_population_source_substitution_is_rejected(self):
        real = reserve_module.load_calibration_cases

        def substituted():
            return tuple(
                replace(case, seed=case.seed + 1)
                if case.case_id == "cal-true-null-v1"
                else case
                for case in real()
            )

        before = self.snapshot()
        with mock.patch.object(
            reserve_module, "load_calibration_cases", side_effect=substituted
        ):
            with self.assertRaises(SimulatedReserveError):
                self.publish()
        self.assertEqual(self.snapshot(), before)

    def test_ledger_capacity_and_payload_bounds_are_prewrite(self):
        before = self.snapshot()
        for name, bound in (
            ("MAX_LEDGER_EVENTS", 0),
            ("MAX_LEDGER_BYTES", 1),
            ("MAX_SIMULATED_RESERVE_BYTES", 100),
            ("MAX_SIMULATED_RESERVE_SCAN_BYTES", 100),
        ):
            with (
                self.subTest(bound=name),
                mock.patch.object(reserve_module, name, bound),
            ):
                with self.assertRaises(SimulatedReserveError):
                    self.publish()
            self.assertEqual(self.snapshot(), before)

    def test_prewrite_pair_cas_detects_actual_concurrent_artifact(self):
        real = reserve_module._body
        injections = []

        def concurrent(*args, **kwargs):
            result = real(*args, **kwargs)
            injections.append(
                self.registry.put_json(
                    {"note": "in-flight"},
                    logical_type="concurrent_note",
                    origin="concurrent note",
                    creator_role=Role.ORCHESTRATOR,
                )
            )
            return result

        with mock.patch.object(reserve_module, "_body", side_effect=concurrent):
            with self.assertRaises(SimulatedReserveError):
                self.publish()
        self.assertEqual(len(injections), 1)
        self.assertFalse(
            any(
                record.logical_type == "frozen_confirmatory_split"
                for record in self.snapshot()[0].records
            )
        )

    def test_native_event_preflight_refuses_duplicate_before_artifact_write(self):
        event = self.append_note()
        before = self.snapshot()
        with mock.patch.object(reserve_module, "_event", return_value=event):
            with self.assertRaises(SimulatedReserveError):
                self.publish()
        self.assertEqual(self.snapshot(), before)

    def test_cross_run_and_foreign_registry_are_refused(self):
        first = self.publish()
        before = self.snapshot()
        with self.assertRaises(SimulatedReserveError):
            require_simulated_confirmatory_reserve(
                self.registry,
                self.ledger,
                expected_run_id="foreign-run",
                reservation_artifact_sha256=first.record.sha256,
            )
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(SimulatedReserveError):
                require_simulated_confirmatory_reserve(
                    self.registry,
                    EventLedger(other),
                    expected_run_id=RUN,
                    reservation_artifact_sha256=first.record.sha256,
                )
        self.assertEqual(self.snapshot(), before)

    def test_sealed_snapshot_replay_does_not_use_current_lineage(self):
        first = self.publish()
        with mock.patch.object(
            reserve_module,
            "_require_current_evaluation_contract_lineage",
            side_effect=AssertionError("historical replay widened to currentness"),
        ):
            self.assertEqual(self.require(first), first)

    def test_typed_marker_event_and_reference_only_aliases_are_not_unrelated(self):
        for metadata, artifacts in (
            ({"artifact_types": ["frozen_confirmatory_split"]}, False),
            ({"logical_type": "frozen_confirmatory_split"}, False),
            ({}, True),
        ):
            with self.subTest(metadata=metadata, artifact_ref=artifacts):
                case = SimulatedReserveTests()
                case.setUp()
                try:
                    first = case.publish()
                    case.append_note(
                        metadata, artifacts=(first.record.sha256,) if artifacts else ()
                    )
                    before = case.snapshot()
                    with self.assertRaises(SimulatedReserveError):
                        case.require(first)
                    self.assertEqual(case.snapshot(), before)
                finally:
                    case.doCleanups()

    def test_population_rows_and_scope_are_exact_not_scientific_authority(self):
        from scientist_one.security import sha256_bytes

        population = safe_json_loads(self.registry.get_bytes(self.population.sha256))
        for member in population["members"]:
            self.assertEqual(member["member_id"], member["row"]["unit_id"])
            self.assertEqual(
                member["row_sha256"], sha256_bytes(canonical_json_bytes(member["row"]))
            )
        first = self.publish()
        value = safe_json_loads(self.registry.get_bytes(first.record.sha256))
        self.assertEqual(value["reservation_units"], 8)
        self.assertTrue(value["allocation_consumed_on_record_publication"])
        self.assertEqual(value["evidence_class"], "NON_EVIDENTIARY")
        self.assertEqual(value["custody_independence"], "NON_INDEPENDENT")
        for key in (
            "scientific_evidence",
            "scientific_freshness_authorized",
            "result_validity_authorized",
            "blinding_authorized",
            "release_authorized",
            "e4_authorized",
        ):
            self.assertIs(value[key], False)
        self.assertNotEqual(first.evaluator_payload_sha256, first.split_manifest_hash)
        self.assertNotEqual(first.record.sha256, first.split_manifest_hash)

    def test_superseded_parent_cannot_allocate_first_window(self):
        from scientist_one.evaluation_contract_amendment import (
            register_evaluation_contract_amendment,
        )

        child = replace(
            self.contract,
            version=2,
            success_criteria=("Changed before allocation; no results observed.",),
        )
        register_evaluation_contract_amendment(
            self.registry,
            self.ledger,
            run_id=RUN,
            amendment_id="before-first-reserve",
            parent_contract_artifact_sha256=self.contract_record.sha256,
            child_contract=child,
            author_id=self.contract.frozen_by,
            reason="Preallocation currentness control with no executed release.",
            child_evidence_parent_artifact_sha256s=(self.evidence.sha256,),
        )
        before = self.snapshot()
        with self.assertRaises(SimulatedReserveError):
            self.publish()
        self.assertEqual(self.snapshot(), before)

    def _put_hostile_reservation_history(self, old_sources):
        """Construct an attacker record, never a successful owner substitute."""
        from scientist_one.models import utc_now

        pair = self.snapshot()
        value = reserve_module._body(
            self.ledger, pair, old_sources, run_id=RUN, index=1, at=utc_now()
        )
        planned = reserve_module._plan_record(
            self.registry,
            value,
            parents=reserve_module._parents(old_sources),
            at=value["recorded_at"],
        )
        record = self.registry.put_bytes(
            canonical_json_bytes(value) + b"\n",
            logical_type=planned.logical_type,
            origin=planned.origin,
            creator_role=planned.creator_role,
            creation_command=planned.creation_command,
            parent_artifacts=planned.parent_artifacts,
            schema_version=planned.schema_version,
            mime_type=planned.mime_type,
            validation_result=planned.validation_result,
            frozen=planned.frozen,
            created_at=planned.created_at,
        )
        self.assertEqual(record, planned)
        event = reserve_module._event(value, record, pair[1])
        self.ledger.append(event)
        return record

    def _original_sources(self):
        return reserve_module._sources(
            self.registry,
            self.ledger,
            self.snapshot(),
            run_id=RUN,
            protocol_sha=self.protocol_record.sha256,
            contract_sha=self.contract_record.sha256,
            population_sha=self.population.sha256,
            index=1,
            prior_sha=None,
        )

    def test_historical_owner_reestablishes_current_at_reservation(self):
        from scientist_one.evaluation_contract_amendment import (
            register_evaluation_contract_amendment,
        )

        old_sources = self._original_sources()
        register_evaluation_contract_amendment(
            self.registry,
            self.ledger,
            run_id=RUN,
            amendment_id="before-hostile-reserve",
            parent_contract_artifact_sha256=self.contract_record.sha256,
            child_contract=replace(
                self.contract,
                version=2,
                success_criteria=("Superseded before hostile record construction.",),
            ),
            author_id=self.contract.frozen_by,
            reason="Historical negative control; no release or valid reservation.",
            child_evidence_parent_artifact_sha256s=(self.evidence.sha256,),
        )
        hostile = self._put_hostile_reservation_history(old_sources)
        before = self.snapshot()
        with self.assertRaises(SimulatedReserveError):
            require_simulated_confirmatory_reserve(
                self.registry,
                self.ledger,
                expected_run_id=RUN,
                reservation_artifact_sha256=hostile.sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_historical_owner_reestablishes_unique_contract_root(self):
        old_sources = self._original_sources()
        # The real genesis owner already refuses this collision. Deliberately
        # inject hostile canonical registry bytes to test historical readback.
        value = safe_json_loads(self.registry.get_bytes(self.contract_record.sha256))
        value["evaluation_contract"]["success_criteria"] = ["Competing same-ID root."]
        self.registry.put_json(
            value,
            logical_type=self.contract_record.logical_type,
            origin=self.contract_record.origin,
            creator_role=self.contract_record.creator_role,
            creation_command=self.contract_record.creation_command,
            parent_artifacts=self.contract_record.parent_artifacts,
            schema_version=self.contract_record.schema_version,
            mime_type=self.contract_record.mime_type,
        )
        hostile = self._put_hostile_reservation_history(old_sources)
        before = self.snapshot()
        with self.assertRaises(SimulatedReserveError):
            require_simulated_confirmatory_reserve(
                self.registry,
                self.ledger,
                expected_run_id=RUN,
                reservation_artifact_sha256=hostile.sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_best_of_n_contract_cannot_replace_all_seeds(self):
        from scientist_one.scientific_design import ReportingRegime

        contract = replace(
            self.contract,
            contract_id="best-only-contract",
            seed_reporting=replace(
                self.contract.seed_reporting,
                regime=ReportingRegime.BEST_OF_N,
                best_of_n=3,
            ),
        )
        contract_record = register_frozen_evaluation_contract(
            self.registry,
            contract=contract,
            parent_artifact_sha256s=(self.evidence.sha256,),
        )
        protocol_record = self.put_protocol(matching_protocol(contract))
        before = self.snapshot()
        with self.assertRaisesRegex(SimulatedReserveError, "ALL_SEEDS"):
            self.publish(
                contract_artifact_sha256=contract_record.sha256,
                protocol_artifact_sha256=protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_historical_lower_edge_does_not_enumerate_later_reservations(self):
        first = self.publish()
        self.append_note({"simulated_confirmatory_reserve": None})
        pair = self.snapshot()
        historical = reserve_module._require_simulated_confirmatory_reserve_at_snapshot(
            self.registry,
            self.ledger,
            expected_run_id=RUN,
            reservation_artifact_sha256=first.record.sha256,
            registry_snapshot=pair[0],
            ledger_snapshot=pair[1],
        )
        self.assertEqual(historical.record, first.record)
        # A historical descriptor is not new-use authority: ordinary current
        # readback still refuses the unowned possible-consumption event.
        with self.assertRaises(SimulatedReserveError):
            self.require(first)

    def test_unknown_large_inventory_refuses_before_registration(self):
        self.registry.put_bytes(
            b"x" * (reserve_module.MAX_SIMULATED_RESERVE_BYTES + 1),
            logical_type="unknown_large",
            origin="bounded inventory negative control",
            creator_role=Role.ORCHESTRATOR,
        )
        before = self.snapshot()
        with self.assertRaises(SimulatedReserveError):
            self.publish()
        self.assertEqual(self.snapshot(), before)

    def exposure_guard(self, records, events=(), *, complete=True):
        return reserve_module.reject_simulated_reserve_exposure(
            self.registry,
            tuple(records),
            tuple(events),
            complete_registry_population=complete,
        )

    def test_negative_exposure_guard_preserves_unsealed_history(self):
        before = self.snapshot()
        self.exposure_guard(before[0].records, complete=False)
        with self.assertRaises(SimulatedReserveError):
            self.exposure_guard(before[0].records)
        first = self.publish()
        pair = self.snapshot()
        # A later record-only population cannot poison an earlier empty prefix.
        self.exposure_guard(pair[0].records, complete=False)
        with self.assertRaises(SimulatedReserveError):
            self.exposure_guard(pair[0].records, (first.event,), complete=False)
        self.assertEqual(self.snapshot(), pair)

    def test_negative_exposure_guard_preserves_legacy_split_and_prose(self):
        legacy = self.registry.put_json(
            {"kind": "FROZEN_CONFIRMATORY_SPLIT", "profile": "LEGACY"},
            logical_type="frozen_confirmatory_split",
            origin="legacy nonauthoritative split",
            creator_role=Role.PROTOCOL_DESIGNER,
        )
        records = (legacy,)
        self.exposure_guard(records)
        event = self.append_note(
            {
                "artifact_types": ["frozen_confirmatory_split"],
                "prose": reserve_module.SIMULATED_RESERVE_SCHEMA,
                "schema_version": "unrelated-schema/v1",
            },
            artifacts=(legacy.sha256,),
        )
        self.exposure_guard(records, (event,))
        self.exposure_guard(records, (event,), complete=False)

    def test_negative_exposure_guard_selects_aliases_and_typed_references(self):
        for index, value in enumerate(
            (
                {
                    "renamed": {
                        "schema_version": reserve_module.SIMULATED_RESERVE_SCHEMA
                    }
                },
                {"renamed": {"profile": reserve_module.SIMULATED_RESERVE_PROFILE}},
                {"renamed": {"simulated_confirmatory_reserve": None}},
                {"logical_type": {"renamed": ["simulated_reserve_population"]}},
            )
        ):
            alias = self.registry.put_json(
                value,
                logical_type="unrelated_alias",
                origin=f"adverse alias {index}",
                creator_role=Role.ORCHESTRATOR,
            )
            with self.subTest(index=index):
                with self.assertRaises(SimulatedReserveError):
                    self.exposure_guard((alias,))
                self.exposure_guard((alias,), complete=False)
                event = self.append_note(
                    {"renamed": {"artifact_record_hash": alias.record_hash}},
                    event_id=f"exposure-alias-{index}",
                )
                with self.assertRaises(SimulatedReserveError):
                    self.exposure_guard((alias,), (event,), complete=False)

    def test_negative_exposure_guard_selects_event_only_markers(self):
        for index, metadata in enumerate(
            (
                {"renamed": {"simulated_confirmatory_reserve": None}},
                {"schema_version": reserve_module.SIMULATED_RESERVE_EVENT_SCHEMA},
                {"renamed": {"artifact_types": ["simulated_reserve_population"]}},
                {"renamed": {"profile": reserve_module.SIMULATED_RESERVE_PROFILE}},
            )
        ):
            event = self.append_note(metadata, event_id=f"exposure-event-{index}")
            with self.subTest(index=index), self.assertRaises(SimulatedReserveError):
                self.exposure_guard((), (event,), complete=False)

    def test_negative_exposure_guard_runs_inside_real_outer_pair_locks(self):
        from pathlib import Path
        import subprocess
        import sys
        import textwrap

        script = textwrap.dedent("""
            import sys
            from pathlib import Path
            repository = Path(sys.argv[1])
            sys.path[:0] = [str(repository / 'src'), str(repository)]
            from tests.test_simulated_reserve import SimulatedReserveTests
            case = SimulatedReserveTests()
            case.setUp()
            try:
                pair = case.snapshot()
                records = tuple(r for r in pair[0].records if r != case.population)
                rg = case.registry._open_mutation_lock()
                try:
                    lg = case.ledger._open_lock()
                    try:
                        case.exposure_guard(records)
                    finally:
                        case.ledger._unlock(lg)
                finally:
                    case.registry._unlock_mutation(rg)
                print('exact selected payload read completed under held pair')
            finally:
                case.doCleanups()
        """)
        child = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-",
                str(Path(__file__).resolve().parents[1]),
            ],
            input=script,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertIn("completed under held pair", child.stdout)

    def test_allocator_refuses_prior_native_design_and_operational_aliases(self):
        for index, payload in enumerate(
            (
                {"schema_version": "SCIENTIST_ONE_FROZEN_RUN_SPEC_V1"},
                {"renamed": {"scientific_timeline": None}},
                {"schema_version": "op-seed-admission/v1"},
            )
        ):
            # Isolated actual native registry populations for each refusal.
            case = SimulatedReserveTests()
            case.setUp()
            try:
                case.registry.put_json(
                    payload,
                    logical_type="unrelated_alias",
                    origin=f"prior native work marker {index}",
                    creator_role=Role.ORCHESTRATOR,
                )
                before = case.snapshot()
                with (
                    self.subTest(index=index),
                    self.assertRaises(SimulatedReserveError),
                ):
                    case.publish()
                self.assertEqual(case.snapshot(), before)
            finally:
                case.doCleanups()

    def test_allocator_refuses_prior_event_only_design(self):
        self.append_note({"renamed": {"scientific_timeline": None}})
        before = self.snapshot()
        with self.assertRaises(SimulatedReserveError):
            self.publish()
        self.assertEqual(self.snapshot(), before)

    def test_new_population_event_aliases_are_consumed_not_unrelated(self):
        shapes = (
            {
                "renamed": {
                    "schema_version": reserve_module.SIMULATED_RESERVE_POPULATION_SCHEMA
                }
            },
            {
                "renamed": {
                    "artifact_types": [
                        reserve_module.SIMULATED_RESERVE_POPULATION_LOGICAL_TYPE
                    ]
                }
            },
            {"renamed": {"profile": reserve_module.SIMULATED_RESERVE_PROFILE}},
        )
        for completed in (False, True):
            for metadata in shapes:
                case = SimulatedReserveTests()
                case.setUp()
                try:
                    first = case.publish() if completed else None
                    case.append_note(metadata)
                    before = case.snapshot()
                    with self.subTest(completed=completed, metadata=metadata):
                        with self.assertRaises(SimulatedReserveError):
                            case.require(first) if first else case.publish()
                        self.assertEqual(case.snapshot(), before)
                finally:
                    case.doCleanups()

    def test_malformed_typed_schema_containers_select_every_native_surface(self):
        shapes = (
            {"schema_version": ["sim-reserve/v1"]},
            {"schema_version": {"sim-reserve-event/v1": None}},
            {"profile": [reserve_module.SIMULATED_RESERVE_PROFILE]},
            {"kind": {"renamed": ["FROZEN_CONFIRMATORY_SPLIT"]}},
        )
        for value in shapes:
            for record_surface in (False, True):
                case = SimulatedReserveTests()
                case.setUp()
                try:
                    if record_surface:
                        record = case.registry.put_json(
                            value,
                            logical_type="renamed_typed_shape",
                            origin="malformed typed field control",
                            creator_role=Role.ORCHESTRATOR,
                        )
                        selected, events = (record,), ()
                    else:
                        event = case.append_note(value)
                        selected, events = (), (event,)
                    before = case.snapshot()
                    with self.subTest(value=value, record_surface=record_surface):
                        # Shared legacy kind is not new simulated science
                        # exposure, but it still makes allocation unsupported.
                        if "kind" not in value:
                            with self.assertRaises(SimulatedReserveError):
                                case.exposure_guard(selected, events)
                        with self.assertRaises(SimulatedReserveError):
                            case.publish()
                        self.assertEqual(case.snapshot(), before)
                finally:
                    case.doCleanups()

    def test_allocator_refuses_custody_and_consumption_event_aliases(self):
        shapes = (
            {"fresh_custody": None},
            {"renamed": {"fresh_custody": None}},
            {"artifact_types": ["custody_record"]},
            {"renamed": {"logical_type": "fresh_custody_receipt"}},
            {"execution_kind": "SIMULATED_ARCHITECTURE_CONTROL_STARTED"},
        )
        for metadata in shapes:
            case = SimulatedReserveTests()
            case.setUp()
            try:
                case.append_note(metadata)
                before = case.snapshot()
                with self.subTest(metadata=metadata):
                    with self.assertRaises(SimulatedReserveError):
                        case.publish()
                    self.assertEqual(case.snapshot(), before)
            finally:
                case.doCleanups()

    def test_allocator_refuses_malformed_raw_and_renamed_native_record_aliases(self):
        payloads = (
            b'{"kind":"SIMULATED_HOLDOUT_CUSTODY"}',
            b'{"schema_version":"SCIENTIST_ONE_FROZEN_RUN_SPEC_V1"',
            b'{"simulated_confirmatory_reserve":',
            b'{"schema_version":"sim-reserve-event/v1"}',
        )
        for raw in payloads:
            case = SimulatedReserveTests()
            case.setUp()
            try:
                record = case.registry.put_bytes(
                    raw,
                    logical_type="renamed_raw_alias",
                    origin="incomplete native record",
                    creator_role=Role.ORCHESTRATOR,
                    mime_type="text/plain",
                )
                before = case.snapshot()
                with self.subTest(raw=raw):
                    with self.assertRaises(SimulatedReserveError):
                        case.publish()
                    if (
                        b"simulated_confirmatory_reserve" in raw
                        or b"sim-reserve-event" in raw
                    ):
                        with self.assertRaises(SimulatedReserveError):
                            case.exposure_guard((record,))
                    self.assertEqual(case.snapshot(), before)
            finally:
                case.doCleanups()

    def test_general_negative_guard_does_not_limit_unrelated_payload_capacity(self):
        oversized = self.registry.put_bytes(
            b"x" * (3 * 1024 * 1024),
            logical_type="unrelated_large",
            origin="ordinary large data, no simulated markers",
            creator_role=Role.ORCHESTRATOR,
        )
        self.exposure_guard((oversized,))
        # More than the allocator's total32MiB, each within its individual cap.
        records = tuple(
            self.registry.put_bytes(
                b"x" * (2 * 1024 * 1024 - 16) + f"{index:016}".encode(),
                logical_type="unrelated_bounded",
                origin="ordinary bounded data",
                creator_role=Role.ORCHESTRATOR,
            )
            for index in range(17)
        )
        self.exposure_guard(records)
        selected = self.registry.put_bytes(
            b"z" * (3 * 1024 * 1024),
            logical_type="unrelated_large",
            schema_version=reserve_module.SIMULATED_RESERVE_SCHEMA,
            origin="large metadata-selected simulated control",
            creator_role=Role.ORCHESTRATOR,
        )
        with self.assertRaises(SimulatedReserveError):
            self.exposure_guard((selected,))

    def test_population_reference_only_events_have_no_supported_producer(self):
        for completed in (False, True):
            for field in (None, "artifact_record_hash", "population_record_hash"):
                case = SimulatedReserveTests()
                case.setUp()
                try:
                    first = case.publish() if completed else None
                    metadata = (
                        {}
                        if field is None
                        else {"renamed": {field: case.population.record_hash}}
                    )
                    event = case.append_note(
                        metadata,
                        artifacts=(case.population.sha256,) if field is None else (),
                    )
                    before = case.snapshot()
                    with self.subTest(completed=completed, field=field):
                        with self.assertRaises(SimulatedReserveError):
                            case.exposure_guard(
                                (case.population,), (event,), complete=False
                            )
                        with self.assertRaises(SimulatedReserveError):
                            case.require(first) if first else case.publish()
                        self.assertEqual(case.snapshot(), before)
                finally:
                    case.doCleanups()

    def test_malformed_typed_custody_family_fragments_are_not_prose(self):
        fragments = (
            b'{"artifact_types":["custody_record"]',
            b'{"logical_type":"fresh_custody_receipt"',
        )
        for raw in fragments:
            case = SimulatedReserveTests()
            case.setUp()
            try:
                case.registry.put_bytes(
                    raw,
                    logical_type="inert_unresolved_alias",
                    origin="truncated native typed custody family",
                    creator_role=Role.ORCHESTRATOR,
                )
                before = case.snapshot()
                with self.subTest(raw=raw):
                    with self.assertRaises(SimulatedReserveError):
                        case.publish()
                    self.assertEqual(case.snapshot(), before)
            finally:
                case.doCleanups()
        # Quoted values inside ordinary, valid prose are not typed markers.
        self.registry.put_json(
            {"note": [raw.decode() for raw in fragments]},
            logical_type="inert_ordinary_prose",
            origin="valid prose control",
            creator_role=Role.ORCHESTRATOR,
        )
        first = self.publish()
        self.assertEqual(self.require(first), first)


if __name__ == "__main__":
    unittest.main()
