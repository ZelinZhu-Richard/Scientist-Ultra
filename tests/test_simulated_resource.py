"""Real native I0 bookkeeping, not release, source attestation or science."""

from dataclasses import replace
from pathlib import Path
import os
import tempfile
import unittest
from unittest import mock

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import MacroState, utc_now
from scientist_one.roles import Role
from scientist_one.resources import ResourceConfig, ResourceController
from scientist_one.scientific_design import register_frozen_evaluation_contract
from scientist_one.security import (
    canonical_json_bytes,
    safe_json_loads,
    secure_directory,
)
from scientist_one.simulated_reserve import register_simulated_reserve_population
from scientist_one import simulated_resource as module
from scientist_one import orchestrator
from tests.test_scientific_design import make_contract
from tests.test_protocol_contract_crosswalk import matching_protocol
from tests.test_resource_prepared_cases import (
    prepared_initialization_root, prepared_initialization_tests,
    prepared_initialization_setup, initialization_phase, initialization_shapes,
    emit_initialization_request, original_external_files,
)


@prepared_initialization_tests
class SimulatedResourceTests(unittest.TestCase):
    def setUp(self):
        if not prepared_initialization_setup(self):
            self.prepare()

    def prepare(
        self,
        config=None,
        *,
        freeze=True,
        protocol_fraction=None,
        prepared_root=None,
    ):
        if prepared_root is None:
            prepared_root = prepared_initialization_root(
                self, config=config, freeze=freeze, protocol_fraction=protocol_fraction
            )
        if prepared_root is None:
            directory = tempfile.TemporaryDirectory(prefix="simulated-resource-test-")
            self.addCleanup(directory.cleanup)
            self.root = Path(directory.name).resolve()
            prepared = False
        else:
            self.root = Path(prepared_root).resolve(strict=True)
            # This is an accidental-misuse guard for a parent-created test
            # directory, not scientific or production security authority.
            if (
                self.root != Path.cwd().resolve(strict=True)
                or self.root.name != "ScientistOne"
                or not self.root.parent.name.startswith("prepared-resource-child-")
                or self.root.parent.parent != Path(tempfile.gettempdir()).resolve()
                or (self.root / "runs").exists()
                or (self.root / ".scientist-one-build/resource-authority").exists()
            ):
                raise ValueError("prepared resource root must be a fresh captured test root")
            marker = self.root / ".prepared-resource-fixture"
            expected_config = (
                canonical_json_bytes((config or ResourceConfig()).to_dict()) + b"\n"
            )
            config_path = self.root / "configs/resource_limits.json"
            if (
                not marker.is_file()
                or marker.is_symlink()
                or marker.read_text(encoding="utf-8") != "prepared-root-fixture-20260920\n"
                or not config_path.is_file()
                or config_path.is_symlink()
            ):
                raise ValueError("prepared resource root is not a labelled fixture")
            if config_path.read_bytes() != expected_config:
                raise ValueError("prepared resource config differs from expected bytes")
            prepared = True
        self.run = module.canonical_simulated_resource_run_id()
        self.registry = ArtifactRegistry(
            self.root, Path("runs") / self.run / "registry"
        )
        self.ledger = EventLedger(self.root, Path("runs") / self.run / "events.jsonl")
        if not prepared:
            for name, payload in (
                (
                    "src/scientist_one/bookkeeping_fixture.py",
                    b"# Bookkeeping inventory, not executed science.\n",
                ),
                (
                    "scripts/scientist_one_cli.py",
                    b"# Inventory-only inert launcher fixture.\n",
                ),
                (
                    "configs/resource_limits.json",
                    canonical_json_bytes((config or ResourceConfig()).to_dict()) + b"\n",
                ),
            ):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
        evidence = self.registry.put_json(
            {"kind": "NON_EVIDENTIARY_RESOURCE_INITIALIZATION_FIXTURE"},
            logical_type="resource_initialization_fixture",
            origin="native I0 bookkeeping test",
            creator_role=Role.EVIDENCE_CURATOR,
        )
        self.contract = make_contract()
        self.contract_record = register_frozen_evaluation_contract(
            self.registry,
            contract=self.contract,
            parent_artifact_sha256s=(evidence.sha256,),
        )
        self.protocol = matching_protocol(self.contract)
        if protocol_fraction is not None:
            self.protocol = replace(
                self.protocol, validity_reserve_fraction=protocol_fraction
            )
        self.protocol_record = self.registry.put_json(
            {
                "kind": "FROZEN_SYNTHETIC_PROTOCOL",
                "frozen": True,
                "protocol": self.protocol.canonical_dict,
                "protocol_sha256": self.protocol.sha256,
                "baseline_equivalence": [],
                "blind_patterns": ["NON_EVIDENTIARY"],
                "reproduction_tolerance": 1e-12,
            },
            logical_type="frozen_protocol",
            origin="parentless component protocol",
            creator_role=Role.PROTOCOL_DESIGNER,
            mime_type="application/json",
        )
        self.population = register_simulated_reserve_population(self.registry)
        if not freeze:
            return
        self.source, self.configuration = (
            module.register_simulated_resource_initial_inventories(self.registry)
        )
        self.args = {
            "expected_run_id": self.run,
            "protocol_artifact_sha256": self.protocol_record.sha256,
            "contract_artifact_sha256": self.contract_record.sha256,
            "population_artifact_sha256": self.population.sha256,
            "frozen_source_inventory_artifact_sha256": self.source.sha256,
            "frozen_configuration_inventory_artifact_sha256": self.configuration.sha256,
        }

    def initialize(self, **changes):
        return module.initialize_simulated_resource_authority(
            self.registry, self.ledger, **{**self.args, **changes}
        )

    def require(self, publication):
        return module.require_simulated_resource_initialization(
            self.registry,
            self.ledger,
            expected_run_id=self.run,
            initialization_artifact_sha256=publication.record.sha256,
        )

    def external(self):
        relative = Path(".scientist-one-build/resource-authority") / self.run
        secure_directory(self.root, relative, create=True)
        return orchestrator._read_resource_authority_records(self.root, self.run)

    def files(self):
        base = self.root / ".scientist-one-build/resource-authority" / self.run
        return tuple(
            (path.name, path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
            for path in sorted(base.glob("*.json"))
        )

    def snapshot(self):
        return self.registry.verify_all(raise_on_error=True), self.ledger.assert_valid()

    def test_actual_initialization_fixed_budget_and_native_external_checkpoint(self):
        before = self.registry.verify_all(raise_on_error=True)
        result = self.initialize()
        state = result.runtime_state
        self.assertEqual(
            (
                state.validity_total_units,
                state.confirmatory_used,
                state.exploratory_used,
            ),
            (40, 0, 0),
        )
        self.assertEqual(result.config.validity_reserve_fraction, 0.4)
        self.assertEqual(state.wall_elapsed_seconds, 0)
        self.assertGreater(state.wall_started_at_epoch_seconds, 0)
        self.assertEqual(
            state.wall_started_at_epoch_seconds, state.wall_observed_at_epoch_seconds
        )
        self.assertEqual(dict(state.worker_crashes), {})
        self.assertEqual(result.event_index, 0)
        self.assertEqual(result.registry_snapshot.count, before.count + 1)
        self.assertEqual(result.ledger_snapshot.event_count, 1)
        value = safe_json_loads(self.registry.get_bytes(result.record.sha256))
        self.assertFalse(value["scientific_authority"])
        self.assertFalse(value["release_authority"])
        self.assertEqual(self.external()[0]["state_sha256"], result.record.sha256)
        orchestrator._validate_resource_authority_ledger_for(
            self.external(), result.ledger_snapshot.events
        )
        # Detached mutable native projection cannot change stored evidence.
        state.worker_crashes["inert"] = 1
        self.assertEqual(dict(result.runtime_state.worker_crashes), {})

    def test_exact_idempotence_preserves_native_file_identity(self):
        result = self.initialize()
        before, files = self.snapshot(), self.files()
        self.assertEqual(self.initialize(), result)
        self.assertEqual(self.require(result), result)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.files(), files)

    def test_inventory_real_producer_idempotence(self):
        before = self.registry.verify_all(raise_on_error=True)
        self.assertEqual(
            module.register_simulated_resource_initial_inventories(self.registry),
            (self.source, self.configuration),
        )
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)

    def test_alternate_run_and_paths_refuse_without_authority(self):
        with self.assertRaises(ValueError):
            self.initialize(expected_run_id="caller-reset")
        other_registry = ArtifactRegistry(self.root, "alternate/registry")
        with self.assertRaises(ValueError):
            module.initialize_simulated_resource_authority(
                other_registry, self.ledger, **self.args
            )
        other_ledger = EventLedger(self.root, "alternate/events.jsonl")
        with self.assertRaises(ValueError):
            module.initialize_simulated_resource_authority(
                self.registry, other_ledger, **self.args
            )
        self.assertEqual(self.external(), ())

    def test_actual_legacy_ten_cannot_reset_to_forty(self):
        self.external()
        state = (
            ResourceController(
                ResourceConfig(), self.root, validity_budget_units=10, run_id=self.run
            )
            .export_state()
            .to_dict()
        )
        orchestrator._persist_resource_authority_for(
            self.root, self.run, "resource_runtime_initial", state
        )
        before = self.files()
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.files(), before)

    def test_native_external_capacity_never_creates_seventeenth(self):
        self.external()
        for index in range(16):
            orchestrator._persist_resource_authority_for(
                self.root, self.run, f"resource_runtime_test_{index}", {"index": index}
            )
        before = self.files()
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.files(), before)

    def test_source_and_config_drift_refuse_before_external_advancement(self):
        # One original default setup, then two captured refusal phases on the
        # SAME project/registry. The parent owns the exact original mutations
        # and restores each input in finally between completed child processes.
        phase = initialization_phase()
        if phase == "seed":
            emit_initialization_request(self)
            return
        relative = {
            "source_drift": "src/scientist_one/bookkeeping_fixture.py",
            "config_drift": "configs/resource_limits.json",
        }[phase]
        with self.subTest(relative=relative):
            with self.assertRaises(ValueError):
                self.initialize()
            self.assertEqual(self.external(), ())

    def test_real_non_point_four_config_refuses(self):
        # This scenario's original prepare now runs in its fresh child's setUp.
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.external(), ())

    def test_wrong_source_digest_refuses(self):
        with self.assertRaises(ValueError):
            self.initialize(population_artifact_sha256=self.contract_record.sha256)
        self.assertEqual(self.external(), ())

    def test_external_write_failure_before_and_after_native_commit(self):
        real = orchestrator.atomic_write_bytes
        for after in (False, True):
            with self.subTest(after=after):

                def fail(root, path, payload, **kwargs):
                    if "resource-authority" in str(path):
                        if after:
                            real(root, path, payload, **kwargs)
                        raise OSError("actual external publication fault")
                    return real(root, path, payload, **kwargs)

                with mock.patch.object(orchestrator, "atomic_write_bytes", new=fail):
                    with self.assertRaises(orchestrator.OrchestrationError):
                        self.initialize()
                self.assertEqual(len(self.external()), int(after))
        original = self.external()[0]
        recovered = self.initialize()
        self.assertEqual(self.external(), (original,))
        self.assertEqual(
            recovered.runtime_state.to_dict(), original["state"]["runtime_state"]
        )

    def test_artifact_failure_recovers_original_external_state(self):
        original_put = self.registry._put_bytes_locked

        def fail(*args, **kwargs):
            raise OSError("actual artifact publication fault")

        with mock.patch.object(self.registry, "_put_bytes_locked", new=fail):
            with self.assertRaises(orchestrator.OrchestrationError):
                self.initialize()
        external, files = self.external(), self.files()
        self.assertEqual(len(external), 1)
        self.assertEqual(self.ledger.assert_valid().event_count, 0)
        self.assertIsNotNone(original_put)
        recovered = self.initialize()
        self.assertEqual(self.files(), files)
        self.assertEqual(
            recovered.runtime_state.to_dict(), external[0]["state"]["runtime_state"]
        )

    def test_event_failure_recovers_exact_artifact_suffix(self):
        with mock.patch.object(
            self.ledger,
            "_append_locked",
            side_effect=OSError("actual ledger append fault"),
        ):
            with self.assertRaises(orchestrator.OrchestrationError):
                self.initialize()
        before, files = self.snapshot(), self.files()
        self.assertEqual(before[1].event_count, 0)
        self.assertEqual(
            len(module._candidate_records(self.registry, before[0].records)), 1
        )
        recovered = self.initialize()
        self.assertEqual(recovered.registry_snapshot, before[0])
        self.assertEqual(self.files(), files)

    def test_post_append_failure_is_idempotently_readable(self):
        real = self.ledger._append_locked

        def append_then_fail(*args, **kwargs):
            real(*args, **kwargs)
            raise OSError("post-append fault")

        with mock.patch.object(self.ledger, "_append_locked", new=append_then_fail):
            with self.assertRaises(orchestrator.OrchestrationError):
                self.initialize()
        before, files = self.snapshot(), self.files()
        result = self.initialize()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.files(), files)
        self.assertEqual(result.ledger_snapshot.event_count, 1)

    def note(self, metadata=None, *, supersedes=None):
        current = self.ledger.assert_valid()
        return self.ledger.record(
            run_id=self.run,
            event_id="inert-note-" + str(current.event_count),
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.CALIBRATE,
            requested_state_after=MacroState.CALIBRATE,
            artifact_hashes=(),
            code_version="bookkeeping",
            configuration_hash="a" * 64,
            dataset_identifiers=(),
            random_seeds=(),
            evaluator_outputs=(),
            reason="inert native test event",
            event_type="CHECKPOINT",
            metadata=metadata or {},
            supersedes_event_id=supersedes,
        )

    def test_prior_event_zero_slot_refuses_before_external_write(self):
        module._pair(self.registry, self.ledger, ensure=True)
        self.note({"renamed": {module.SIMULATED_RESOURCE_INITIAL_EVENT_KEY: None}})
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.external(), ())
        self.assertEqual(self.snapshot(), before)

    def test_native_record_alias_refuses_before_external_write(self):
        self.registry.put_json(
            {"renamed": {"artifact_types": ["resource_runtime_initial"]}},
            logical_type="inert_alias",
            origin="unresolved marker fixture",
            creator_role=Role.ORCHESTRATOR,
        )
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.external(), ())

    def test_orphan_recovery_refuses_new_registry_work(self):
        with mock.patch.object(
            self.ledger, "_append_locked", side_effect=OSError("append fault")
        ):
            with self.assertRaises(orchestrator.OrchestrationError):
                self.initialize()
        self.registry.put_json(
            {"inert": True},
            logical_type="inert_new_work",
            origin="fixture",
            creator_role=Role.ORCHESTRATOR,
        )
        before, files = self.snapshot(), self.files()
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.files(), files)

    def test_recovery_source_drift_retains_original_time(self):
        # The seed child creates the genuine first orphan. No files are copied
        # or refrozen before the next child captures the changed inert source.
        if initialization_phase() == "seed":
            with mock.patch.object(
                self.ledger, "_append_locked", side_effect=OSError("append fault")
            ):
                with self.assertRaises(orchestrator.OrchestrationError):
                    self.initialize()
            before = self.files()
            emit_initialization_request(self, external_files=before)
            return
        before = original_external_files()
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.files(), before)

    def test_completed_extra_event_refuses_but_historical_selected_pair_replays(self):
        result = self.initialize()
        self.note(
            {
                "renamed": {
                    "schema_version": module.SIMULATED_RESOURCE_INITIAL_EVENT_SCHEMA
                }
            }
        )
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.require(result)
        historical = module._require_simulated_resource_initialization_at_snapshot(
            self.registry,
            self.ledger,
            expected_run_id=self.run,
            initialization_artifact_sha256=result.record.sha256,
            registry_snapshot=result.registry_snapshot,
            ledger_snapshot=result.ledger_snapshot,
        )
        self.assertEqual(historical, result)
        self.assertEqual(self.snapshot(), before)

    def test_complete_record_alias_refuses(self):
        result = self.initialize()
        self.registry.put_json(
            {"schema_version": module.SIMULATED_RESOURCE_INITIAL_SCHEMA},
            logical_type="inert_alias",
            origin="fixture",
            creator_role=Role.ORCHESTRATOR,
        )
        with self.assertRaises(ValueError):
            self.require(result)

    def test_original_state_cannot_be_rebound_to_other_protocol(self):
        result = self.initialize()
        changed = replace(self.protocol, study_id="different-study")
        other = self.registry.put_json(
            {"kind": "inert-protocol", "protocol": changed.canonical_dict},
            logical_type="inert_different_protocol",
            origin="fixture",
            creator_role=Role.PROTOCOL_DESIGNER,
        )
        before = self.files()
        with self.assertRaises(ValueError):
            self.initialize(protocol_artifact_sha256=other.sha256)
        self.assertEqual(self.files(), before)
        self.assertEqual(result.runtime_state.validity_total_units, 40)

    def test_native_text_selectors_reject_subclass_overrides(self):
        class EqualText(str):
            def __eq__(self, other):
                return True

            __hash__ = str.__hash__

        for key, value in (
            ("expected_run_id", EqualText("not-native")),
            ("protocol_artifact_sha256", EqualText(self.protocol_record.sha256)),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.initialize(**{key: value})
        self.assertEqual(self.external(), ())

    def test_actual_configuration_capacity_rejects_before_external_publication(self):
        # Native ResourceConfig accepts nonempty schema text. Its file remains
        # within the existing 1 MiB config reader; the full I envelope cannot.
        # This scenario's original prepare now runs in its fresh child's setUp.
        before = self.registry.verify_all(raise_on_error=True)
        self.assertLess(
            (self.root / "configs/resource_limits.json").stat().st_size, 1024 * 1024
        )
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)
        self.assertEqual(self.external(), ())

    def test_actual_inventory_partial_write_recovers_original_first_record(self):
        # Original freeze=False prepare now runs in this fresh child's setUp.
        real = self.registry._put_bytes_locked

        def fail_second(*args, **kwargs):
            if kwargs.get("logical_type") == "frozen_configuration_inventory":
                raise OSError("second actual inventory write fault")
            return real(*args, **kwargs)

        with mock.patch.object(self.registry, "_put_bytes_locked", new=fail_second):
            with self.assertRaises(orchestrator.OrchestrationError):
                module.register_simulated_resource_initial_inventories(self.registry)
        before = self.registry.verify_all(raise_on_error=True)
        source = next(
            record
            for record in before.records
            if record.logical_type == "frozen_source_inventory"
        )
        result = module.register_simulated_resource_initial_inventories(self.registry)
        self.assertEqual(result[0], source)
        self.assertEqual(
            self.registry.verify_all(raise_on_error=True).count, before.count + 1
        )

    def test_actual_initialization_correction_refuses(self):
        result = self.initialize()
        self.ledger.append_correction(
            supersedes_event_id=result.event.event_id,
            actor_role=Role.ORCHESTRATOR,
            corrected_fields={"reason": "inert correction fixture"},
            reason="initialization is disputed",
        )
        before, files = self.snapshot(), self.files()
        with self.assertRaises(ValueError):
            self.require(result)
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.files(), files)

    def test_actual_inventory_native_metadata_substitution_refuses(self):
        # Rewrite a metadata file to another internally valid native record;
        # no registry owner is mocked into accepting counterfeit metadata.
        changed = replace(
            self.source, origin="unowned inventory producer", record_hash=None
        )
        path = self.root / self.source.metadata_path
        path.write_bytes(canonical_json_bytes(changed.to_dict()) + b"\n")
        self.assertTrue(self.registry.verify_all(raise_on_error=True))
        before = self.registry.verify_all(raise_on_error=True)
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)
        self.assertEqual(self.external(), ())

    def test_actual_extra_artifact_write_is_detected_by_final_pair(self):
        real = self.registry._put_bytes_locked

        def write_extra(guard, *args, **kwargs):
            record = real(guard, *args, **kwargs)
            real(
                guard,
                canonical_json_bytes({"inert_extra": True}) + b"\n",
                logical_type="inert_extra",
                origin="adverse extra native write",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("native-test",),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=utc_now(),
            )
            return record

        with mock.patch.object(self.registry, "_put_bytes_locked", new=write_extra):
            with self.assertRaises(ValueError):
                self.initialize()
        files = self.files()
        self.assertEqual(len(files), 1)
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.files(), files)

    def test_actual_extra_ledger_write_is_detected_by_final_pair(self):
        real = self.ledger._append_locked

        def append_extra(guard, build):
            event = real(guard, build)

            def extra(snapshot):
                return LedgerEvent.create(
                    run_id=self.run,
                    event_id="inert-extra-write",
                    actor_role=Role.ORCHESTRATOR,
                    state_before=MacroState.CALIBRATE,
                    requested_state_after=MacroState.CALIBRATE,
                    artifact_hashes=(),
                    code_version=event.code_version,
                    configuration_hash=event.configuration_hash,
                    dataset_identifiers=(),
                    random_seeds=(),
                    evaluator_outputs=(),
                    reason="actual extra native write",
                    prior_event_hash=snapshot.head_hash,
                    event_type="CHECKPOINT",
                    metadata={},
                )

            real(guard, extra)
            return event

        with mock.patch.object(self.ledger, "_append_locked", new=append_extra):
            with self.assertRaises(ValueError):
                self.initialize()
        self.assertEqual(self.ledger.assert_valid().event_count, 2)
        files = self.files()
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.files(), files)

    def test_actual_external_extra_stage_is_detected_without_refund(self):
        real = self.registry._put_bytes_locked

        def advance_external(guard, *args, **kwargs):
            record = real(guard, *args, **kwargs)
            orchestrator._persist_resource_authority_for(
                self.root,
                self.run,
                "resource_runtime_adverse_extra_stage",
                {"adverse": True},
            )
            return record

        with mock.patch.object(
            self.registry, "_put_bytes_locked", new=advance_external
        ):
            with self.assertRaises(ValueError):
                self.initialize()
        self.assertEqual(len(self.external()), 2)
        files = self.files()
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.files(), files)

    def test_raw_external_byte_substitution_refuses_without_rewrite(self):
        self.initialize()
        path = next(
            (self.root / ".scientist-one-build/resource-authority" / self.run).glob(
                "*.json"
            )
        )
        path.write_bytes(
            path.read_bytes().replace(
                b'"validity_total_units":40', b'"validity_total_units":41', 1
            )
        )
        changed = self.files()
        with self.assertRaises(orchestrator.OrchestrationError):
            self.initialize()
        self.assertEqual(self.files(), changed)

    def test_inventory_marker_command_cannot_be_reused_by_renamed_initial_record(self):
        self.registry.put_json(
            {"inert": "marker-only producer alias"},
            logical_type="renamed_initialization",
            origin="inert",
            creator_role=Role.ORCHESTRATOR,
            creation_command=module.SIMULATED_RESOURCE_INITIAL_COMMAND,
        )
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.external(), ())

    def test_matching_prose_does_not_select_authority(self):
        self.registry.put_json(
            {
                "note": "simulated_resource_initialization resource_runtime_initial sim-resource-initial/v1"
            },
            logical_type="inert_note",
            origin="ordinary prose",
            creator_role=Role.EVIDENCE_CURATOR,
        )
        result = self.initialize()
        self.assertEqual(self.require(result), result)

    def test_historical_config_replay_does_not_read_later_live_bytes(self):
        result = self.initialize()
        (self.root / "configs/resource_limits.json").write_bytes(
            b'{"validity_reserve_fraction":0.3}\n'
        )
        with self.assertRaises(ValueError):
            self.require(result)
        historical = module._require_simulated_resource_initialization_at_snapshot(
            self.registry,
            self.ledger,
            expected_run_id=self.run,
            initialization_artifact_sha256=result.record.sha256,
            registry_snapshot=result.registry_snapshot,
            ledger_snapshot=result.ledger_snapshot,
        )
        self.assertEqual(historical, result)

    def test_renamed_inventory_schema_alias_refuses_before_external_write(self):
        self.registry.put_json(
            {"renamed": {"kind": "FROZEN_SOURCE_INVENTORY"}},
            logical_type="inert_inventory_alias",
            origin="ambiguous source marker",
            creator_role=Role.ORCHESTRATOR,
        )
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.external(), ())

    def test_valid_caller_input_hashes_do_not_override_native_source_provenance(self):
        # Original freeze=False prepare now runs in this fresh child's setUp.
        value = orchestrator._source_inventory(self.root)
        self.registry.put_json(
            value,
            logical_type="renamed_inventory",
            origin="caller digest, not owned inventory",
            creator_role=Role.ORCHESTRATOR,
        )
        with self.assertRaises(ValueError):
            module.register_simulated_resource_initial_inventories(self.registry)
        self.assertEqual(self.external(), ())

    def historical(self, publication, pair=None):
        pair = self.snapshot() if pair is None else pair
        return module._require_simulated_resource_initialization_at_snapshot(
            self.registry,
            self.ledger,
            expected_run_id=self.run,
            initialization_artifact_sha256=publication.record.sha256,
            registry_snapshot=pair[0],
            ledger_snapshot=pair[1],
        )

    def test_protocol_fraction_must_match_actual_fixed_config_before_publication(self):
        # This scenario's original prepare now runs in its fresh child's setUp.
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.external(), ())

    def test_historical_outer_selection_consumes_each_initialization_alias(self):
        for shape in initialization_shapes(("nested-null-event", "native-event-copy", "schema-record")):
            with self.subTest(shape=shape):
                # Original per-shape prepare ran in this fresh child's setUp.
                result = self.initialize()
                if shape == "nested-null-event":
                    self.note(
                        {"nested": {module.SIMULATED_RESOURCE_INITIAL_EVENT_KEY: None}}
                    )
                elif shape == "native-event-copy":
                    value = result.event.to_dict()
                    value.update(
                        event_id="inert-copied-initialization",
                        prior_event_hash=self.ledger.assert_valid().head_hash,
                        event_hash=None,
                    )
                    self.ledger.append(LedgerEvent.from_dict(value))
                else:
                    self.registry.put_json(
                        {"schema_version": module.SIMULATED_RESOURCE_INITIAL_SCHEMA},
                        logical_type="inert_initialization_alias",
                        origin="inert review marker",
                        creator_role=Role.ORCHESTRATOR,
                    )
                before, files = self.snapshot(), self.files()
                with self.assertRaises(ValueError):
                    self.historical(result, before)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.files(), files)
                # The exact earlier selected pair is not retroactively widened.
                self.assertEqual(
                    self.historical(
                        result, (result.registry_snapshot, result.ledger_snapshot)
                    ),
                    result,
                )

    def test_last_live_inventory_read_cannot_hide_native_source_metadata_drift(self):
        result = self.initialize()
        config_identity = (self.root / "configs/resource_limits.json").stat()
        self.assert_late_metadata_drift_refuses(result, config_identity)

    def test_last_external_read_cannot_hide_native_source_metadata_drift(self):
        result = self.initialize()
        external_identity = next(
            (self.root / ".scientist-one-build/resource-authority" / self.run).glob(
                "*.json"
            )
        ).stat()
        self.assert_late_metadata_drift_refuses(result, external_identity)

    def assert_late_metadata_drift_refuses(self, result, watched_identity):
        old = next(
            record
            for record in self.snapshot()[0].records
            if record.logical_type == "resource_initialization_fixture"
        )
        changed = replace(
            old, origin="actual late valid metadata substitution", record_hash=None
        )
        target = self.root / old.metadata_path
        count, injected = 0, False
        real_close, real_fstat = os.close, os.fstat

        def close_and_inject(descriptor):
            nonlocal count, injected
            try:
                info = real_fstat(descriptor)
                is_config = (info.st_dev, info.st_ino) == (
                    watched_identity.st_dev,
                    watched_identity.st_ino,
                )
            except OSError:
                is_config = False
            returned = real_close(descriptor)
            if is_config:
                count += 1
                if count == 3:
                    target.write_bytes(canonical_json_bytes(changed.to_dict()) + b"\n")
                    injected = True
            return returned

        files = self.files()
        with mock.patch.object(os, "close", new=close_and_inject):
            with self.assertRaises(ValueError):
                self.require(result)
        self.assertTrue(injected)
        self.assertEqual(count, 3)
        self.assertIn(changed, self.snapshot()[0].records)
        self.assertEqual(self.files(), files)

    def test_selected_history_allows_later_unrelated_work_without_granting_it_authority(
        self,
    ):
        result = self.initialize()
        self.registry.put_json(
            {"kind": "INERT_UNOWNED_LATER_STAGE_MARKER"},
            logical_type="resource_runtime_confirmatory_charge",
            origin="test family marker only, no Q owner or release claim",
            creator_role=Role.ORCHESTRATOR,
        )
        self.note({"note": "sim-resource-initial/v1 mentioned only as prose"})
        before = self.snapshot()
        historical = self.historical(result, before)
        self.assertEqual(historical.record, result.record)
        self.assertEqual(historical.runtime_state_bytes, result.runtime_state_bytes)
        self.assertEqual(historical.registry_snapshot, before[0])
        self.assertEqual(self.snapshot(), before)

    def test_selected_initialization_marker_containers_and_reference_events_refuse(
        self,
    ):
        for shape in initialization_shapes((
            "schema-list",
            "schema-map",
            "typed-map",
            "origin-only",
            "command-only",
            "event-prefix-only",
            "event-typed-list",
            "event-record-reference",
        )):
            with self.subTest(shape=shape):
                # Original per-shape prepare ran in this fresh child's setUp.
                result = self.initialize()
                if shape == "event-prefix-only":
                    value = result.event.to_dict()
                    value.update(
                        event_id="sim-resource-initial-unmatched",
                        prior_event_hash=self.ledger.assert_valid().head_hash,
                        artifact_hashes=[],
                        metadata={},
                        event_hash=None,
                    )
                    self.ledger.append(LedgerEvent.from_dict(value))
                elif shape == "event-typed-list":
                    self.note(
                        {
                            "nested": {
                                "artifact_types": [
                                    module.SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE
                                ]
                            }
                        }
                    )
                elif shape == "event-record-reference":
                    self.note(
                        {"nested": {"artifact_record_hash": result.record.record_hash}}
                    )
                else:
                    payload = {
                        "schema-list": {
                            "schema_version": [module.SIMULATED_RESOURCE_INITIAL_SCHEMA]
                        },
                        "schema-map": {
                            "schema_version": {
                                module.SIMULATED_RESOURCE_INITIAL_EVENT_SCHEMA: None
                            }
                        },
                        "typed-map": {
                            "artifact_types": {
                                module.SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE: None
                            }
                        },
                        "origin-only": {"inert": "origin-only"},
                        "command-only": {"inert": "command-only"},
                    }[shape]
                    self.registry.put_json(
                        payload,
                        logical_type="inert_selected_alias",
                        origin=module.SIMULATED_RESOURCE_INITIAL_ORIGIN
                        if shape == "origin-only"
                        else "inert selected alias",
                        creation_command=module.SIMULATED_RESOURCE_INITIAL_COMMAND
                        if shape == "command-only"
                        else ("inert-native-test",),
                        creator_role=Role.ORCHESTRATOR,
                    )
                before, files = self.snapshot(), self.files()
                with self.assertRaises(ValueError):
                    self.historical(result, before)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.files(), files)
