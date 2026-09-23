"""Actual-child operational owner controls, not scientific validation."""

from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ValidationError
from scientist_one.experiments import ExperimentError, ExperimentIntegrityError
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    ExperimentPlan,
    ExperimentStage,
    ReportingRegime,
    SeedReportingPlan,
    record_scientific_design_freeze,
    register_evaluation_contract_freeze_gate_receipt,
    register_frozen_evaluation_contract,
    register_frozen_experiment_plan,
    register_frozen_run_spec,
    require_evaluation_contract_freeze_gate_receipt,
)
from scientist_one.seed_reporting import (
    OPERATIONAL_SEED_POLICY_METADATA_KEY,
    OPERATIONAL_SELECTION_RULE,
    OPERATIONAL_RETRY_RULE,
    operational_seed_policy,
    execute_operational_best_of_n,
    recover_operational_best_of_n,
    OperationalSeedReportingError,
    operational_seed_progress_descriptors,
    reject_operational_seed_exposure,
)
import scientist_one.seed_reporting as reporting
from tests import test_local_terminal_observation as terminal_fixtures
from tests.test_scientific_design import make_contract


class OperationalSeedReportingTests(unittest.TestCase):
    def fixture(self, mode="success", *, timeout=3.0, worker=None, metric=None):
        case = terminal_fixtures.LocalTerminalObservationTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        with mock.patch.object(
            terminal_fixtures, "WORKER", worker or terminal_fixtures.WORKER
        ):
            initial, paths = case.fixture(mode, timeout=timeout)
        run_id = "operational-owner"
        registry = ArtifactRegistry(case.root, f"runs/{run_id}/registry")
        ledger = EventLedger(case.root, f"runs/{run_id}/events.jsonl")

        def put(payload, logical_type, role):
            return registry.put_bytes(
                payload,
                logical_type=logical_type,
                creator_role=role,
                origin="non-evidentiary actual-child operational fixture",
            )

        evidence = put(
            b"synthetic design fixture only\n",
            "fixture_evidence",
            Role.EVIDENCE_CURATOR,
        )
        extra = {"primary_metric": metric} if metric else {}
        contract = make_contract(
            seed_reporting=SeedReportingPlan(
                seeds=initial.seeds,
                regime=ReportingRegime.BEST_OF_N,
                best_of_n=len(initial.seeds),
                selection_policy=OPERATIONAL_SELECTION_RULE,
                technical_retry_rule=OPERATIONAL_RETRY_RULE,
                selection_defined_before_results=True,
                preserve_all_runs=True,
            ),
            ablations=(),
            **extra,
        )
        contract_record = register_frozen_evaluation_contract(
            registry,
            contract=contract,
            parent_artifact_sha256s=(evidence.sha256,),
        )
        for kind, family, role in (
            ("code", "experiment_code", Role.IMPLEMENTER),
            ("data", "experiment_dataset", Role.EVIDENCE_CURATOR),
            ("configuration", "experiment_configuration", Role.PROTOCOL_DESIGNER),
            ("evaluator", "evaluator_implementation", Role.PROTOCOL_DESIGNER),
        ):
            record = put((case.root / paths[kind]).read_bytes(), family, role)
            self.assertEqual(record.sha256, getattr(initial, kind + "_sha256"))
        plans = tuple(
            register_frozen_experiment_plan(
                registry,
                contract=contract,
                contract_artifact_sha256=contract_record.sha256,
                plan=ExperimentPlan(
                    experiment_id="experiment-primary",
                    hypothesis_id="hypothesis-primary",
                    stage=ExperimentStage.EXPLORATORY,
                    contract_sha256=contract.sha256,
                    dataset_split_id="development-v1",
                    seed=seed,
                    evaluator_id="evaluator-v1",
                    uses_protected_resource=False,
                    results_seen_before_plan=False,
                ),
            )
            for seed in initial.seeds
        )
        initial = replace(
            initial,
            experiment_id="experiment-primary",
            hypothesis_id="hypothesis-primary",
            seed_policy=OPERATIONAL_SELECTION_RULE,
            metadata={
                **dict(initial.metadata),
                "evaluation_split": "development-v1",
                OPERATIONAL_SEED_POLICY_METADATA_KEY: operational_seed_policy(
                    "cohort-one",
                    (initial.run_id, "terminal-retry"),
                ),
            },
        )
        retry = replace(
            initial, run_id="terminal-retry", attempt=2, retry_of_run_id=initial.run_id
        )
        receipts = []
        specs = (initial, retry)
        for index, spec in enumerate(specs):
            spec_record = register_frozen_run_spec(
                registry,
                contract=contract,
                contract_artifact_sha256=contract_record.sha256,
                experiment_plan_artifact_sha256s=tuple(p.sha256 for p in plans),
                spec=spec,
            )
            arguments = dict(
                run_id=run_id,
                contract=contract,
                contract_artifact_sha256=contract_record.sha256,
                experiment_plan_artifact_sha256s=tuple(p.sha256 for p in plans),
                frozen_run_spec_artifact_sha256=spec_record.sha256,
            )
            record_scientific_design_freeze(registry, ledger, **arguments)
            receipts.append(
                register_evaluation_contract_freeze_gate_receipt(
                    registry,
                    ledger,
                    receipt_id=f"freeze-{index}",
                    **arguments,
                )
            )
        return case, registry, ledger, contract, specs, tuple(receipts), paths

    def execute(self, fixture, *, backend=None):
        case, registry, ledger, _contract, _specs, receipts, paths = fixture
        return execute_operational_best_of_n(
            registry,
            ledger,
            expected_run_id="operational-owner",
            initial_freeze_receipt_artifact_sha256=receipts[0].sha256,
            retry_freeze_receipt_artifact_sha256=receipts[1].sha256,
            backend=backend or case.backend(),
            input_artifact_paths=paths,
        )

    def test_real_mixed_population_and_fresh_zero_dispatch_replay(self):
        fixture = self.fixture()
        result = self.execute(fixture)
        self.assertEqual(
            result.report["observed_numeric_distribution"], (1.0, 0.0, 0.0, 9.0, 10.0)
        )
        self.assertEqual(result.report["eligible_distribution"], (1.0, 0.0, 0.0))
        self.assertEqual(result.report["selected"]["seed"], 11)
        self.assertEqual(result.report["planned_n"], 5)
        self.assertFalse(result.report["scientific_evidence"])
        case, registry, ledger, contract, _specs, receipts, _paths = fixture
        before = (registry.verify_all(), ledger.validate())
        replay = recover_operational_best_of_n(
            registry,
            ledger,
            expected_run_id="operational-owner",
            initial_admission_artifact_sha256=result.admission_records[0].sha256,
            backend=case.backend(),
        )
        self.assertEqual(replay, result)
        self.assertEqual((registry.verify_all(), ledger.validate()), before)
        for receipt in receipts:
            require_evaluation_contract_freeze_gate_receipt(
                registry,
                ledger,
                receipt_artifact_sha256=receipt.sha256,
                expected_run_id="operational-owner",
                expected_contract_id=contract.contract_id,
            )

    def test_nonzero_and_malformed_do_not_invent_seed_failures(self):
        for mode in ("empty-failure", "manifest-failure", "malformed", "bad-seed"):
            with self.subTest(mode=mode):
                result = self.execute(self.fixture(mode))
                self.assertIsNone(result.report["selected"])
                self.assertEqual(result.report["eligible_distribution"], ())
                self.assertEqual(len(result.terminal_records), 1)
                if mode == "manifest-failure":
                    self.assertEqual(
                        len(result.report["observed_numeric_distribution"]), 5
                    )
                if mode in {"empty-failure", "malformed"}:
                    self.assertEqual(result.report["attempts"][0]["seed_rows"], ())
                    self.assertEqual(
                        result.report["attempts"][0]["seed_coverage"], "UNOBSERVED"
                    )

    def test_all_adverse_keeps_numeric_distribution_without_selection(self):
        worker = terminal_fixtures.WORKER.replace(
            '("SUCCESS", "NEGATIVE", "NULL", "FAILED", "INVALID")',
            '("FAILED", "INVALID", "FAILED", "INVALID", "FAILED")',
        )
        result = self.execute(self.fixture(worker=worker))
        self.assertIsNone(result.report["selected"])
        self.assertEqual(len(result.report["observed_numeric_distribution"]), 5)
        self.assertEqual(result.report["eligible_distribution"], ())

    def test_real_queue_retry_is_separate_from_frozen_n(self):
        fixture = self.fixture()
        case, registry, ledger, _contract, specs, _receipts, _paths = fixture
        backend = case.backend(queue_timeout_seconds=0.05)
        blocker, blocker_paths = case.fixture(
            "timeout", name="queue-blocker", timeout=30
        )
        outcomes, errors = [], []

        def run_blocker():
            try:
                outcomes.append(
                    backend.submit(
                        blocker,
                        idempotency_key="blocker",
                        input_artifact_paths=blocker_paths,
                    )
                )
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=run_blocker)
        thread.start()
        self.addCleanup(thread.join, 10)
        case.wait_for_launch(blocker)
        marker = (
            case.root
            / ".scientist-one-build/experiments/local-mac"
            / f"local-{specs[0].sha256[:20]}"
            / "terminal-observation.json"
        )

        def release():
            deadline = time.monotonic() + 15
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            backend.cancel(f"local-{blocker.sha256[:20]}")

        release_thread = threading.Thread(target=release)
        release_thread.start()
        self.addCleanup(release_thread.join, 10)
        result = self.execute(fixture, backend=backend)
        release_thread.join(10)
        thread.join(10)
        self.assertEqual(errors, [])
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(len(result.admission_records), 2)
        self.assertEqual(result.report["planned_n"], 5)
        self.assertEqual(
            [a["invocation_count"] for a in result.report["attempts"]], [0, 1]
        )
        self.assertEqual(result.report["attempts"][0]["seed_rows"], ())
        self.assertEqual(result.report["selected"]["attempt"], 2)
        replay = recover_operational_best_of_n(
            registry,
            ledger,
            expected_run_id="operational-owner",
            initial_admission_artifact_sha256=result.admission_records[0].sha256,
            backend=case.backend(),
        )
        self.assertEqual(replay, result)

    def test_target_tie_uses_frozen_seed_order(self):
        from tests.test_scientific_design import make_metric
        from scientist_one.scientific_design import MetricDirection

        worker = terminal_fixtures.WORKER.replace(
            "(1., 0., 0., 9., 10.)", "(2., 0., 5., 9., 10.)"
        )
        result = self.execute(
            self.fixture(
                worker=worker,
                metric=make_metric(
                    direction=MetricDirection.TARGET_IS_BEST, target_value=1.0
                ),
            )
        )
        self.assertEqual(result.report["selected"]["seed"], 11)

    def test_timeout_is_not_a_technical_retry(self):
        result = self.execute(self.fixture("timeout", timeout=0.1))
        self.assertEqual(len(result.admission_records), 1)
        self.assertEqual(result.report["attempts"][0]["reason"], "WALL_CLOCK_TIMEOUT")
        self.assertIsNone(result.report["selected"])

    def test_preexisting_runtime_refuses_retrospective_admission(self):
        fixture = self.fixture()
        case, registry, ledger, _contract, specs, _receipts, paths = fixture
        case.backend().submit(
            specs[0], idempotency_key="earlier-execution", input_artifact_paths=paths
        )
        before = (registry.verify_all(), ledger.validate())
        with self.assertRaises(OperationalSeedReportingError):
            self.execute(fixture)
        self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_report_record_only_orphan_recovers_without_another_child(self):
        fixture = self.fixture()
        case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        real_append = EventLedger._append_locked

        def fail_report(self, guard, builder):
            current = self._validate_bytes(self._read_raw_locked(guard))
            event = builder(current)
            if reporting.OPERATIONAL_BEST_OF_N_REPORT_EVENT_KEY in event.metadata:
                raise OSError("intentional report publication failure")
            return real_append(self, guard, builder)

        with mock.patch.object(EventLedger, "_append_locked", new=fail_report):
            with self.assertRaises(OSError):
                self.execute(fixture)
        admissions = [
            r
            for r in registry.list_records()
            if r.logical_type == reporting.OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE
        ]
        reports = [
            r
            for r in registry.list_records()
            if r.logical_type == reporting.OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
        ]
        self.assertEqual(len(reports), 1)
        result = recover_operational_best_of_n(
            registry,
            ledger,
            expected_run_id="operational-owner",
            initial_admission_artifact_sha256=admissions[0].sha256,
            backend=case.backend(),
        )
        self.assertEqual(result.report_record, reports[0])
        self.assertEqual(result.report["attempts"][0]["invocation_count"], 1)

    def test_passive_selected_snapshot_does_not_call_full_owners(self):
        fixture = self.fixture()
        result = self.execute(fixture)
        _case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        snapshot = (registry.verify_all().records, ledger.validate().events)
        with (
            mock.patch.object(
                reporting,
                "require_evaluation_contract_freeze_gate_receipt",
                side_effect=AssertionError("full owner called"),
            ),
            mock.patch.object(
                reporting,
                "require_frozen_evaluation_contract",
                side_effect=AssertionError("full owner called"),
            ),
        ):
            descriptors = operational_seed_progress_descriptors(
                registry, records=snapshot[0], events=snapshot[1]
            )
        self.assertEqual(descriptors[0].admission_record, result.admission_records[0])
        with self.assertRaises(OperationalSeedReportingError):
            reject_operational_seed_exposure(
                registry, *snapshot, complete_registry_population=True
            )
        reject_operational_seed_exposure(
            registry, snapshot[0], snapshot[1][:2], complete_registry_population=False
        )

    def test_completed_replay_allows_unrelated_append_but_not_raw_drift(self):
        fixture = self.fixture()
        self.append_selector_event(
            fixture[2],
            event_id="ordinary-note-before-admission",
            metadata={"schema_version": "ordinary-unrelated-note/v1"},
        )
        result = self.execute(fixture)
        case, registry, ledger, _contract, specs, _receipts, _paths = fixture
        registry.put_bytes(
            b"unrelated later bytes",
            logical_type="fixture_unrelated",
            origin="unrelated",
            creator_role=Role.IMPLEMENTER,
        )
        self.append_selector_event(
            ledger,
            event_id="ordinary-note-before-completed-replay",
            metadata={"renamed": {"schema_version": "ordinary-unrelated-note/v2"}},
        )
        before = (registry.verify_all(), ledger.validate())
        replay = self.execute(fixture)
        self.assertEqual(replay, result)
        self.assertEqual((registry.verify_all(), ledger.validate()), before)
        output = (
            case.root
            / ".scientist-one-build/experiments/local-mac"
            / f"local-{specs[0].sha256[:20]}"
            / "metrics.bin"
        )
        output.write_bytes(b"changed")
        with self.assertRaises(ExperimentIntegrityError):
            self.execute(fixture)

    def test_admission_prewrite_cas_refuses_intervening_registry_mutation(self):
        fixture = self.fixture()
        case, registry, ledger, _contract, specs, _receipts, _paths = fixture
        before_events = ledger.validate()
        real = reporting._planned_record
        changed = []

        def mutate(registry, body, family):
            planned = real(registry, body, family)
            if (
                not changed
                and family == reporting.OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE
            ):
                changed.append(True)
                registry.put_bytes(
                    b"concurrent source append",
                    logical_type="fixture_unrelated",
                    origin="CAS negative control",
                    creator_role=Role.IMPLEMENTER,
                )
            return planned

        with mock.patch.object(reporting, "_planned_record", new=mutate):
            with self.assertRaises(OperationalSeedReportingError):
                self.execute(fixture)
        self.assertEqual(ledger.validate(), before_events)
        self.assertFalse(
            any(
                r.logical_type == reporting.OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE
                for r in registry.list_records()
            )
        )
        self.assertFalse(
            (
                case.root
                / ".scientist-one-build/experiments/local-mac"
                / f"local-{specs[0].sha256[:20]}"
            ).exists()
        )

    def test_real_child_failed_terminal_publication_never_redispatches(self):
        import scientist_one.experiments as experiments

        fixture = self.fixture()
        case, registry, ledger, _contract, specs, _receipts, _paths = fixture
        real_write = experiments.atomic_write_bytes

        def fail(root, path, payload, **kwargs):
            if str(path).endswith("stdout.log"):
                raise OSError("intentional terminal publication fault")
            return real_write(root, path, payload, **kwargs)

        backend = case.backend()
        with mock.patch.object(experiments, "atomic_write_bytes", new=fail):
            with self.assertRaises(ExperimentIntegrityError):
                self.execute(fixture, backend=backend)
        job = backend._jobs[f"local-{specs[0].sha256[:20]}"]
        self.assertEqual(job.terminal_popen_launch_count, 1)
        self.assertEqual(job.terminal_result.returncode, 0)
        admission = next(
            r
            for r in registry.list_records()
            if r.logical_type == reporting.OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE
        )
        before = (registry.verify_all(), ledger.validate())
        with self.assertRaises(ExperimentIntegrityError):
            recover_operational_best_of_n(
                registry,
                ledger,
                expected_run_id="operational-owner",
                initial_admission_artifact_sha256=admission.sha256,
                backend=case.backend(),
            )
        self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_falsey_marker_and_typed_alias_never_disappear_from_passive_inventory(self):
        fixture = self.fixture()
        result = self.execute(fixture)
        _case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        original = result.report_event
        for metadata in (
            {reporting.OPERATIONAL_SEED_ADMISSION_EVENT_KEY: None},
            {reporting.OPERATIONAL_SEED_ADMISSION_EVENT_KEY: {}},
            {"renamed": {"artifact_sha256": result.admission_records[0].sha256}},
        ):
            with self.subTest(metadata=metadata):
                alias = replace(
                    original,
                    event_id="renamed-falsey",
                    artifact_hashes=(),
                    metadata=metadata,
                    event_hash=None,
                )
                with self.assertRaises(OperationalSeedReportingError):
                    reject_operational_seed_exposure(
                        registry,
                        registry.verify_all().records,
                        (alias,),
                        complete_registry_population=False,
                    )

    def test_native_archive_preserves_near_capacity_exact_bytes(self):
        fixture = self.fixture("capture-capacity")
        result = self.execute(fixture)
        case, registry, _ledger, _contract, specs, _receipts, _paths = fixture
        native = case.backend().recover_terminal_observation(
            specs[0], idempotency_key="archive-readback"
        )
        self.assertEqual(
            registry.get_bytes(result.terminal_records[0].sha256), native.payload
        )
        self.assertLessEqual(
            len(native.payload), terminal_fixtures.LOCAL_TERMINAL_MAX_JSON_BYTES
        )
        self.assertEqual(
            result.report["population_scope"],
            "FROZEN_COHORT_AND_REGISTERED_ATTEMPTS_ONLY",
        )
        self.assertEqual(
            result.report["primary_metric"]["direction"], "HIGHER_IS_BETTER"
        )

    def test_popen_exception_is_observed_invocation_not_safe_queue_retry(self):
        import scientist_one.experiments as experiments

        fixture = self.fixture()
        backend = fixture[0].backend()
        with mock.patch.object(
            experiments.subprocess,
            "Popen",
            side_effect=OSError("intentional process creation fault"),
        ):
            result = self.execute(fixture, backend=backend)
        self.assertEqual(len(result.admission_records), 1)
        attempt = result.report["attempts"][0]
        self.assertEqual(
            (attempt["invocation_count"], attempt["proven_popen_launch_count"]), (1, 0)
        )
        self.assertEqual(attempt["launch_observation"], "UNKNOWN_AFTER_INVOCATION")
        self.assertIsNone(result.report["selected"])

    def test_declared_integer_metric_is_retained_without_boolean_coercion(self):
        worker = terminal_fixtures.WORKER.replace(
            "(1., 0., 0., 9., 10.)", "(1, 0, 0, 9, 10)"
        )
        result = self.execute(self.fixture(worker=worker))
        self.assertEqual(
            result.report["observed_numeric_distribution"], (1.0, 0.0, 0.0, 9.0, 10.0)
        )
        self.assertEqual(result.report["selected"]["seed"], 11)

    def test_passive_owner_rejects_reference_only_renamed_event(self):
        fixture = self.fixture()
        result = self.execute(fixture)
        _case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        alias = replace(
            result.report_event,
            event_id="renamed-owner-reference",
            artifact_hashes=(),
            metadata={
                "unrecognized": {
                    "artifact_record_hash": result.admission_records[0].record_hash
                }
            },
            event_hash=None,
        )
        with self.assertRaises(OperationalSeedReportingError):
            operational_seed_progress_descriptors(
                registry,
                records=registry.verify_all().records,
                events=(*ledger.validate().events, alias),
            )

    def test_passive_owner_selects_payload_schema_under_wrong_family_and_mime(self):
        fixture = self.fixture()
        result = self.execute(fixture)
        _case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        body = reporting.thaw_json(result.report)
        body["selected"]["metric"] = True
        registry.put_bytes(
            reporting._raw(body),
            logical_type="wrong_family",
            origin="renamed",
            creator_role=Role.IMPLEMENTER,
            parent_artifacts=result.report_record.parent_artifacts,
            mime_type="application/octet-stream",
        )
        with self.assertRaises(OperationalSeedReportingError):
            operational_seed_progress_descriptors(
                registry,
                records=registry.verify_all().records,
                events=ledger.validate().events,
            )

    def test_payload_alias_is_current_exposure_not_unreferenced_legacy_history(self):
        fixture = self.fixture()
        _case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        registry.put_bytes(
            b'{"schema_version":"op-best-of-n/v1"}\n',
            logical_type="wrong_family",
            mime_type="application/octet-stream",
            origin="incomplete alias negative control",
            creator_role=Role.IMPLEMENTER,
        )
        records, events = registry.verify_all().records, ledger.validate().events
        with self.assertRaises(OperationalSeedReportingError):
            reject_operational_seed_exposure(
                registry, records, events, complete_registry_population=True
            )
        reject_operational_seed_exposure(
            registry, records, events, complete_registry_population=False
        )

    def test_actual_cancellation_retains_one_terminal_attempt(self):
        fixture = self.fixture("timeout", timeout=15)
        case, _registry, _ledger, _contract, specs, _receipts, _paths = fixture
        backend = case.backend()
        outcomes, errors = [], []

        def run():
            try:
                outcomes.append(self.execute(fixture, backend=backend))
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=run)
        thread.start()
        self.addCleanup(thread.join, 20)
        case.wait_for_launch(specs[0])
        backend.cancel(f"local-{specs[0].sha256[:20]}")
        thread.join(20)
        self.assertEqual(errors, [])
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(len(outcomes[0].admission_records), 1)
        self.assertEqual(outcomes[0].report["attempts"][0]["state"], "CANCELLED")
        self.assertIsNone(outcomes[0].report["selected"])

    def test_exact_target_distance_avoids_overflow_false_ties(self):
        from tests.test_scientific_design import make_metric
        from scientist_one.scientific_design import MetricDirection

        worker = terminal_fixtures.WORKER.replace(
            "(1., 0., 0., 9., 10.)", "(1.7e308, 1.6e308, 1.5e308, 9., 10.)"
        )
        result = self.execute(
            self.fixture(
                worker=worker,
                metric=make_metric(
                    direction=MetricDirection.TARGET_IS_BEST, target_value=-1.7e308
                ),
            )
        )
        self.assertEqual(result.report["selected"]["seed"], 33)

    def test_run_wide_protected_family_and_payload_alias_refuse_before_dispatch(self):
        for family, value in (
            ("scientific_execution_plan", {"deliberately": "incomplete"}),
            ("frozen_confirmatory_split", {"deliberately": "incomplete"}),
            ("research_state.result", {"deliberately": "incomplete"}),
            ("wrong_family", {"schema_version": "scientific-dataset-source/v1"}),
            ("wrong_family", {"schema_version": "scientific-execution-preparation/v1"}),
        ):
            with self.subTest(family=family, value=value):
                fixture = self.fixture()
                case, registry, ledger, _contract, specs, _receipts, _paths = fixture
                registry.put_json(
                    value,
                    logical_type=family,
                    origin="negative incomplete resource fixture",
                    creator_role=Role.IMPLEMENTER,
                )
                before = (registry.verify_all(), ledger.validate())
                with self.assertRaises(OperationalSeedReportingError):
                    self.execute(fixture)
                self.assertEqual((registry.verify_all(), ledger.validate()), before)
                self.assertFalse(
                    (
                        case.root
                        / ".scientist-one-build/experiments/local-mac"
                        / f"local-{specs[0].sha256[:20]}"
                    ).exists()
                )

    def test_initial_admission_refuses_malformed_and_shared_spec_aliases(self):
        aliases = (
            (b'{"schema_version":"SCIENTIST_ONE_FROZEN_RUN_SPEC_V1"}', "alias"),
            (b'{"schema_version":"scientific-dataset-source/v1",', "alias"),
            (
                b'{"incomplete":true}',
                "run spec frozen after scientific-plan admission and before execution",
            ),
        )
        for raw, origin in aliases:
            with self.subTest(raw=raw, origin=origin):
                fixture = self.fixture()
                case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
                registry.put_bytes(
                    raw,
                    logical_type="wrong_family",
                    origin=origin,
                    mime_type="application/octet-stream",
                    creator_role=Role.IMPLEMENTER,
                )
                before = (registry.verify_all(), ledger.validate())
                backend = case.backend()
                with self.assertRaises(OperationalSeedReportingError):
                    self.execute(fixture, backend=backend)
                self.assertEqual((registry.verify_all(), ledger.validate()), before)
                self.assertEqual(backend._jobs, {})

    def test_initial_admission_rejects_later_actual_contract_amendment(self):
        from scientist_one.evaluation_contract_amendment import (
            EvaluationContractAmendmentError,
            register_evaluation_contract_amendment,
        )

        fixture = self.fixture()
        case, registry, ledger, contract, specs, receipts, _paths = fixture
        parent = registry.get_metadata(receipts[0].parent_artifacts[0])
        publication = register_evaluation_contract_amendment(
            registry,
            ledger,
            run_id="operational-owner",
            amendment_id="later-contract-revision",
            parent_contract_artifact_sha256=parent.sha256,
            child_contract=replace(
                contract,
                version=contract.version + 1,
                success_criteria=("Later criterion, no confirmation authority.",),
            ),
            author_id=contract.frozen_by,
            reason="Actual source-owned prospective revision after the old design.",
            child_evidence_parent_artifact_sha256s=parent.parent_artifacts,
        )
        self.assertIsNotNone(publication.event)
        # Historical receipt validity is not current initial-admission freshness.
        for receipt in receipts:
            require_evaluation_contract_freeze_gate_receipt(
                registry,
                ledger,
                receipt_artifact_sha256=receipt.sha256,
                expected_run_id="operational-owner",
                expected_contract_id=contract.contract_id,
            )
        before = (registry.verify_all(), ledger.validate())
        backend = case.backend()
        with self.assertRaisesRegex(EvaluationContractAmendmentError, "superseded"):
            self.execute(fixture, backend=backend)
        self.assertEqual((registry.verify_all(), ledger.validate()), before)
        self.assertEqual(backend._jobs, {})
        for spec in specs:
            self.assertFalse(
                (
                    case.root
                    / ".scientist-one-build/experiments/local-mac"
                    / f"local-{spec.sha256[:20]}"
                ).exists()
            )

    def test_initial_admission_refuses_prior_native_legacy_result_families(self):
        for family in (
            "experiment_output_manifest",
            "experiment_output.metrics",
            "aggregate_experiment_result",
            "statistical_analysis",
        ):
            with self.subTest(family=family):
                fixture = self.fixture()
                case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
                registry.put_json(
                    {"deliberately_incomplete_result_work": family},
                    logical_type=family,
                    origin="negative prior-work selector fixture; no owner PASS",
                    creator_role=Role.IMPLEMENTER,
                )
                before = (registry.verify_all(), ledger.validate())
                backend = case.backend()
                with self.assertRaises(OperationalSeedReportingError):
                    self.execute(fixture, backend=backend)
                self.assertEqual((registry.verify_all(), ledger.validate()), before)
                self.assertEqual(backend._jobs, {})

    def test_negative_guard_is_safe_inside_actual_paired_commit_locks(self):
        fixture = self.fixture()
        case, registry, _ledger, _contract, _specs, _receipts, _paths = fixture
        script = r"""
import os, sys
sys.path.insert(0, sys.argv[1])
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.seed_reporting import (
    reject_operational_seed_exposure, OperationalSeedReportingError,
)
registry = ArtifactRegistry(sys.argv[2], "runs/operational-owner/registry")
ledger = EventLedger(sys.argv[2], "runs/operational-owner/events.jsonl")
records, events = registry.verify_all().records, ledger.assert_valid().events
if len(sys.argv) > 3:
    target = next(r for r in records if r.logical_type == "fixture_evidence")
    path = registry.policy.root / target.path
    os.unlink(path)
    os.mkfifo(path)
guard = registry._open_mutation_lock()
try:
    lock = ledger._open_lock()
    try:
        try:
            reject_operational_seed_exposure(
                registry, records, events, complete_registry_population=True,
            )
        except OperationalSeedReportingError:
            print("REJECTED", flush=True)
        else:
            print("NO_RESERVATION_IN_SELECTED_SNAPSHOT", flush=True)
    finally:
        ledger._unlock(lock)
finally:
    registry._unlock_mutation(guard)
"""

        def run_locked(expected, *, root=None, fifo=False):
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        "-c",
                        script,
                        str(Path(__file__).resolve().parents[1] / "src"),
                        str(root or case.root),
                        *(("fifo",) if fifo else ()),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                self.fail(
                    "negative exposure hook re-entered an actual held commit lock"
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), expected)

        run_locked("NO_RESERVATION_IN_SELECTED_SNAPSHOT")
        registry.put_json(
            {"schema_version": "op-best-of-n/v1"},
            logical_type="wrong_family",
            origin="negative payload-only alias",
            creator_role=Role.IMPLEMENTER,
            mime_type="application/octet-stream",
        )
        run_locked("REJECTED")
        unsafe_fixture = self.fixture()
        run_locked("REJECTED", root=unsafe_fixture[0].root, fifo=True)

    def test_lock_free_negative_guard_rejects_selected_metadata_and_content_drift(self):
        from scientist_one.security import atomic_write_bytes

        for changed in ("metadata", "content"):
            with self.subTest(changed=changed):
                fixture = self.fixture()
                case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
                record = registry.put_json(
                    {"inert": "selected source"},
                    logical_type="fixture_plain_source",
                    origin="negative source-byte drift fixture",
                    creator_role=Role.IMPLEMENTER,
                )
                records, events = (
                    registry.verify_all().records,
                    ledger.validate().events,
                )
                if changed == "metadata":
                    path = record.metadata_path
                    raw = (
                        (case.root / path)
                        .read_bytes()
                        .replace(b"negative", b"tampered")
                    )
                else:
                    path = record.path
                    raw = (
                        (case.root / path)
                        .read_bytes()
                        .replace(b"selected", b"tampered")
                    )
                atomic_write_bytes(case.root, path, raw, overwrite=True)
                with (
                    mock.patch.object(
                        ArtifactRegistry,
                        "_open_mutation_lock",
                        side_effect=AssertionError(
                            "negative guard cannot acquire registry locks"
                        ),
                    ),
                    self.assertRaises(OperationalSeedReportingError),
                ):
                    reject_operational_seed_exposure(
                        registry, records, events, complete_registry_population=True
                    )

    def test_report_orphan_cannot_recover_after_unrelated_source_append(self):
        fixture = self.fixture()
        case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        real = EventLedger._append_locked

        def fail(self, guard, builder):
            event = builder(self._validate_bytes(self._read_raw_locked(guard)))
            if reporting.OPERATIONAL_BEST_OF_N_REPORT_EVENT_KEY in event.metadata:
                raise OSError("report event fault")
            return real(self, guard, builder)

        with mock.patch.object(EventLedger, "_append_locked", new=fail):
            with self.assertRaises(OSError):
                self.execute(fixture)
        admission = next(
            r
            for r in registry.list_records()
            if r.logical_type == reporting.OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE
        )
        registry.put_bytes(
            b"after orphan",
            logical_type="fixture_unrelated",
            origin="unrelated",
            creator_role=Role.IMPLEMENTER,
        )
        before = (registry.verify_all(), ledger.validate())
        with self.assertRaises(OperationalSeedReportingError):
            recover_operational_best_of_n(
                registry,
                ledger,
                expected_run_id="operational-owner",
                initial_admission_artifact_sha256=admission.sha256,
                backend=case.backend(),
            )
        self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_admission_record_only_repair_never_dispatches(self):
        fixture = self.fixture()
        case, registry, ledger, _contract, specs, _receipts, _paths = fixture
        with mock.patch.object(
            EventLedger, "_append_locked", side_effect=OSError("admission event fault")
        ):
            with self.assertRaises(OSError):
                self.execute(fixture)
        admission = next(
            r
            for r in registry.list_records()
            if r.logical_type == reporting.OPERATIONAL_SEED_ADMISSION_LOGICAL_TYPE
        )
        with self.assertRaises((ValidationError, ExperimentError)):
            recover_operational_best_of_n(
                registry,
                ledger,
                expected_run_id="operational-owner",
                initial_admission_artifact_sha256=admission.sha256,
                backend=case.backend(),
            )
        events = ledger.validate().events
        self.assertEqual(
            sum(
                reporting.OPERATIONAL_SEED_ADMISSION_EVENT_KEY in e.metadata
                for e in events
            ),
            1,
        )
        self.assertFalse(
            (
                case.root
                / ".scientist-one-build/experiments/local-mac"
                / f"local-{specs[0].sha256[:20]}"
            ).exists()
        )
        with self.assertRaises((ValidationError, ExperimentError)):
            self.execute(fixture)

    def test_report_capacity_preserves_actual_native_terminal_without_report(self):
        fixture = self.fixture()
        _case, registry, _ledger, _contract, _specs, _receipts, _paths = fixture
        real = reporting._planned_record

        def capacity(registry, body, family):
            if family == reporting.OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE:
                with mock.patch.object(reporting, "MAX_OPERATIONAL_REPORT_BYTES", 1):
                    return real(registry, body, family)
            return real(registry, body, family)

        with mock.patch.object(reporting, "_planned_record", new=capacity):
            with self.assertRaises(OperationalSeedReportingError):
                self.execute(fixture)
        records = registry.list_records()
        self.assertEqual(
            sum(
                r.logical_type == reporting.LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE
                for r in records
            ),
            1,
        )
        self.assertEqual(
            sum(
                r.logical_type == reporting.OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
                for r in records
            ),
            0,
        )
        result = self.execute(fixture)
        self.assertEqual(result.report["attempts"][0]["invocation_count"], 1)

    def test_reserved_event_typed_reference_alias_is_exposure(self):
        fixture = self.fixture()
        result = self.execute(fixture)
        _case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        original = result.report_event
        alias = replace(
            original,
            event_id="renamed-reference-only",
            artifact_hashes=(),
            metadata={
                "unrecognized": {
                    "artifact_record_hash": result.admission_records[0].record_hash
                }
            },
            event_hash=None,
        )
        with self.assertRaises(OperationalSeedReportingError):
            reject_operational_seed_exposure(
                registry,
                registry.verify_all().records,
                (alias,),
                complete_registry_population=False,
            )

    def test_nested_falsey_reserved_event_keys_refuse_negative_and_passive_reads(self):
        fixture = self.fixture()
        _case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        from scientist_one.ledger import LedgerEvent

        for key in (
            reporting.OPERATIONAL_SEED_ADMISSION_EVENT_KEY,
            reporting.OPERATIONAL_BEST_OF_N_REPORT_EVENT_KEY,
        ):
            for value in (None, False, [], 0):
                with self.subTest(key=key, value=value):
                    events = ledger.assert_valid().events
                    event = LedgerEvent.create(
                        run_id="operational-owner",
                        event_id=f"renamed-incomplete-marker-{len(events)}",
                        actor_role=Role.EXPERIMENT_RUNNER,
                        state_before=events[-1].requested_state_after,
                        requested_state_after=events[-1].requested_state_after,
                        artifact_hashes=(),
                        code_version="negative-marker-control",
                        configuration_hash=events[-1].configuration_hash,
                        dataset_identifiers=(),
                        random_seeds=(),
                        evaluator_outputs=(),
                        reason="Negative unresolved marker, not executed work.",
                        prior_event_hash=events[-1].event_hash,
                        event_type="CHECKPOINT",
                        metadata={"renamed": [{"nested": {key: value}}]},
                    )
                    ledger.append(event)
                    selected = ledger.assert_valid().events
                    records = registry.verify_all().records
                    with self.assertRaises(OperationalSeedReportingError):
                        reject_operational_seed_exposure(
                            registry,
                            records,
                            selected,
                            complete_registry_population=False,
                        )
                    with self.assertRaises(OperationalSeedReportingError):
                        operational_seed_progress_descriptors(
                            registry, records=records, events=selected
                        )

    def append_selector_event(self, ledger, *, event_id, metadata, artifact_hashes=()):
        head = ledger.assert_valid().events[-1]
        return ledger.record(
            run_id="operational-owner",
            event_id=event_id,
            actor_role=Role.EXPERIMENT_RUNNER,
            state_before=head.requested_state_after,
            requested_state_after=head.requested_state_after,
            artifact_hashes=artifact_hashes,
            code_version=head.code_version,
            configuration_hash=head.configuration_hash,
            dataset_identifiers=(),
            random_seeds=(),
            evaluator_outputs=(),
            reason="Incomplete selector negative control; no execution authority.",
            event_type="CHECKPOINT",
            metadata=metadata,
        )

    def test_completed_recovery_refuses_unmatched_reserved_event_id(self):
        self.check_completed_selector_alias("evt-op-seed-inert-unmatched-slot", {})

    def test_completed_recovery_refuses_schema_only_reserved_event(self):
        self.check_completed_selector_alias(
            "renamed-schema-only",
            {"renamed": {"schema_version": "op-seed-admission/v1"}},
        )

    def check_completed_selector_alias(self, event_id, metadata):
        fixture = self.fixture()
        result = self.execute(fixture)
        case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        self.append_selector_event(ledger, event_id=event_id, metadata=metadata)
        before = (registry.verify_all(), ledger.assert_valid())
        backend = case.backend()
        with self.assertRaises(OperationalSeedReportingError):
            recover_operational_best_of_n(
                registry,
                ledger,
                expected_run_id="operational-owner",
                initial_admission_artifact_sha256=result.admission_records[0].sha256,
                backend=backend,
            )
        self.assertEqual((registry.verify_all(), ledger.assert_valid()), before)
        self.assertTrue(all(j.execution_count == 1 for j in backend._jobs.values()))

    def test_initial_admission_refuses_nested_fresh_custody_event_key(self):
        self.check_protected_event_alias({"renamed": {"fresh_custody": None}})

    def test_initial_admission_refuses_scientific_prepared_event_schema(self):
        self.check_protected_event_alias(
            {"renamed": {"schema_version": "scientific-execution-prepared-event/v1"}}
        )

    def test_initial_admission_refuses_incomplete_native_timeline_key(self):
        for value in (
            None,
            {"kind": "DESIGN_FROZEN", "output_manifest_artifact_sha256": "e" * 64},
        ):
            with self.subTest(value=value):
                self.check_protected_event_alias({"scientific_timeline": value})

    def test_initial_admission_refuses_copied_native_design_fragments(self):
        from scientist_one.scientific_design import ScientificPromotionError

        for placement in ("nested", "top-level-copy"):
            with self.subTest(placement=placement):
                fixture = self.fixture()
                case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
                design = ledger.assert_valid().events[0]
                copied = reporting.thaw_json(design.metadata)
                self.append_selector_event(
                    ledger,
                    event_id="renamed-copy-of-native-design",
                    metadata={"renamed": copied} if placement == "nested" else copied,
                )
                before = (registry.verify_all(), ledger.assert_valid())
                backend = case.backend()
                expected_error = (
                    OperationalSeedReportingError
                    if placement == "nested"
                    else ScientificPromotionError
                )
                with self.assertRaises(expected_error):
                    self.execute(fixture, backend=backend)
                self.assertEqual((registry.verify_all(), ledger.assert_valid()), before)
                self.assertEqual(backend._jobs, {})

    def test_family_names_in_prose_do_not_select_operational_or_protected_events(self):
        fixture = self.fixture()
        case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        metadata = {
            "notes": [
                "operational_seed_admission",
                "local_terminal_observation",
                "operational_best_of_n_report",
                "scientific_execution_preparation",
                "frozen_confirmatory_split",
            ],
            "schema_version": "ordinary-unrelated-prose/v1",
        }
        self.append_selector_event(
            ledger,
            event_id="ordinary-family-name-prose-before-admission",
            metadata=metadata,
        )
        result = self.execute(fixture)
        event = self.append_selector_event(
            ledger,
            event_id="ordinary-family-name-prose-after-report",
            metadata=metadata,
        )
        before = (registry.verify_all(), ledger.assert_valid())
        reject_operational_seed_exposure(
            registry, before[0].records, (event,), complete_registry_population=False
        )
        replay = recover_operational_best_of_n(
            registry,
            ledger,
            expected_run_id="operational-owner",
            initial_admission_artifact_sha256=result.admission_records[0].sha256,
            backend=case.backend(),
        )
        self.assertEqual(replay, result)
        self.assertEqual((registry.verify_all(), ledger.assert_valid()), before)

    def test_completed_recovery_refuses_typed_operational_family_fields(self):
        for field, value in (
            ("artifact_types", ["operational_seed_admission"]),
            ("logical_type", "operational_seed_admission"),
        ):
            with self.subTest(field=field):
                self.check_completed_selector_alias(
                    "renamed-typed-operational-family", {"renamed": {field: value}}
                )

    def test_initial_admission_refuses_typed_protected_family_fields(self):
        for family in ("scientific_execution_preparation", "frozen_confirmatory_split"):
            for field, value in (
                ("artifact_types", [family]),
                ("logical_type", family),
            ):
                with self.subTest(family=family, field=field):
                    self.check_protected_event_alias({"renamed": {field: value}})

    def test_event_only_negative_guard_selects_typed_operational_family_fields(self):
        fixture = self.fixture()
        _case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        for index, (field, value) in enumerate(
            (
                ("artifact_types", ["operational_seed_admission"]),
                ("logical_type", "operational_best_of_n_report"),
                ("artifact_types", {"operational_seed_admission": None}),
                ("logical_type", {"renamed": [["local_terminal_observation"]]}),
            )
        ):
            with self.subTest(field=field):
                event = self.append_selector_event(
                    ledger,
                    event_id=f"renamed-family-{index}",
                    metadata={"renamed": {field: value}},
                )
                with self.assertRaises(OperationalSeedReportingError):
                    reject_operational_seed_exposure(
                        registry,
                        registry.verify_all().records,
                        (event,),
                        complete_registry_population=False,
                    )

    def test_malformed_typed_family_containers_preserve_reserved_markers(self):
        for family in (
            "operational_seed_admission",
            "local_terminal_observation",
            "operational_best_of_n_report",
            "scientific_execution_preparation",
        ):
            for field in ("artifact_types", "logical_type"):
                for value in ({family: None}, {"renamed": [[family]]}):
                    with self.subTest(family=family, field=field, value=value):
                        keys, _strings, _mappings, families = (
                            reporting._metadata_selectors({"renamed": [{field: value}]})
                        )
                        self.assertIn(field, keys)
                        self.assertIn(family, families)

    def test_initial_admission_protected_event_schema_and_result_kind_table(self):
        schemas = (
            "protocol-revision-event/v1",
            "scientific-dataset-acquisition-plan-event/v1",
            "scientific-dataset-authority-event/v2",
            "scientific-dataset-split-event/v1",
            "scientific-experiment-dataset/v1",
            "scientific-dataset-statistical-use-proposal-event/v1",
            "scientific-dataset-statistical-use-proposal-event/v2",
            "scientific-dataset-statistical-use-authority-event/v1",
            "scientific-dataset-statistical-use-authority-event/v2",
            "scientific-execution-attested-event/v1",
            "scientific-execution-attested-event/v2",
            "scientific-execution-authority-publication/v1",
            "scientific-confirmatory-protocol-binding-event/v1",
            "scientific-confirmatory-timeline-publication/v2",
            "scientific-result-state-projection-event/v1",
            "scientific-result-promotion-authority-event/v3",
        )
        for index, schema in enumerate(schemas):
            with self.subTest(schema=schema):
                value = {"schema_version": schema}
                self.check_protected_event_alias(
                    value if index % 2 else {"renamed": [{"deeper": value}]}
                )
        for value in (
            {"kind": "RESULT_OBSERVED"},
            {"schema_version": "scientific-timeline-event/v1"},
            {
                "schema_version": "scientific-timeline-event/v1",
                "kind": "RESULT_OBSERVED",
            },
            {
                "schema_version": "scientific-timeline-event/v1",
                "kind": "DESIGN_FROZEN",
                "output_manifest_artifact_sha256": "0" * 64,
            },
        ):
            with self.subTest(value=value):
                self.check_protected_event_alias({"renamed": {"deeper": value}})

    def check_protected_event_alias(self, metadata):
        fixture = self.fixture()
        case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        self.append_selector_event(
            ledger, event_id="renamed-protected-event", metadata=metadata
        )
        before = (registry.verify_all(), ledger.assert_valid())
        backend = case.backend()
        with self.assertRaises(OperationalSeedReportingError):
            self.execute(fixture, backend=backend)
        self.assertEqual((registry.verify_all(), ledger.assert_valid()), before)
        self.assertEqual(backend._jobs, {})

    def test_completed_recovery_refuses_terminal_only_event_references(self):
        for kind in ("artifact", "typed-record"):
            with self.subTest(kind=kind):
                fixture = self.fixture()
                result = self.execute(fixture)
                case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
                terminal = result.terminal_records[0]
                self.append_selector_event(
                    ledger,
                    event_id="renamed-terminal-only-event",
                    metadata={"renamed": {"artifact_record_hash": terminal.record_hash}}
                    if kind == "typed-record"
                    else {},
                    artifact_hashes=(terminal.sha256,) if kind == "artifact" else (),
                )
                before = (registry.verify_all(), ledger.assert_valid())
                with self.assertRaises(OperationalSeedReportingError):
                    recover_operational_best_of_n(
                        registry,
                        ledger,
                        expected_run_id="operational-owner",
                        initial_admission_artifact_sha256=result.admission_records[
                            0
                        ].sha256,
                        backend=case.backend(),
                    )
                self.assertEqual((registry.verify_all(), ledger.assert_valid()), before)

    def test_future_report_event_id_reserved_after_real_terminal_refuses_without_report(
        self,
    ):
        fixture = self.fixture()
        _case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        real = reporting._archive
        snapshots = []

        def reserve_future_id(*args, **kwargs):
            record, native = real(*args, **kwargs)
            if not snapshots:
                admission = registry.get_metadata(record.parent_artifacts[0])
                body = reporting.safe_json_loads(registry.get_bytes(admission.sha256))
                self.append_selector_event(
                    ledger,
                    event_id=reporting._event_id(
                        body, reporting.OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
                    ),
                    metadata={},
                )
                snapshots.append((registry.verify_all(), ledger.assert_valid()))
            return record, native

        with mock.patch.object(reporting, "_archive", new=reserve_future_id):
            with self.assertRaises(OperationalSeedReportingError):
                self.execute(fixture)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual((registry.verify_all(), ledger.assert_valid()), snapshots[0])
        self.assertEqual(
            sum(
                r.logical_type == reporting.LOCAL_TERMINAL_ARCHIVE_LOGICAL_TYPE
                for r in snapshots[0][0].records
            ),
            1,
        )
        self.assertFalse(
            any(
                r.logical_type == reporting.OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
                for r in snapshots[0][0].records
            )
        )

    def test_prospective_report_event_validation_precedes_artifact_write(self):
        from scientist_one.ledger import LedgerError

        fixture = self.fixture()
        _case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        real = reporting._event
        snapshots = []

        def invalid_native_event(body, record, events):
            event = real(body, record, events)
            if (
                record.logical_type
                == reporting.OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
            ):
                snapshots.append((registry.verify_all(), ledger.assert_valid()))
                # A negative plan fault after real A/T, not a fabricated positive
                # owner result: the native prospective event has a duplicate ID.
                return replace(event, event_id=events[-1].event_id, event_hash=None)
            return event

        with mock.patch.object(reporting, "_event", new=invalid_native_event):
            with self.assertRaises((OperationalSeedReportingError, LedgerError)):
                self.execute(fixture)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual((registry.verify_all(), ledger.assert_valid()), snapshots[0])

    def test_boolean_report_metric_and_renamed_cohort_alias_refuse(self):
        for change in ("boolean", "renamed"):
            with self.subTest(change=change):
                fixture = self.fixture()
                result = self.execute(fixture)
                _case, registry, ledger, _contract, _specs, _receipts, _paths = fixture
                body = reporting.thaw_json(result.report)
                if change == "boolean":
                    body["selected"]["metric"] = True
                else:
                    body["source_binding"]["cohort_id"] = "renamed-cohort"
                planned = reporting._planned_record(
                    registry, body, reporting.OPERATIONAL_BEST_OF_N_REPORT_LOGICAL_TYPE
                )
                registry.put_bytes(
                    reporting._raw(body),
                    logical_type=planned.logical_type,
                    origin=planned.origin,
                    creator_role=planned.creator_role,
                    schema_version=planned.schema_version,
                    mime_type=planned.mime_type,
                    creation_command=planned.creation_command,
                    parent_artifacts=planned.parent_artifacts,
                    created_at=planned.created_at,
                )
                with self.assertRaises(OperationalSeedReportingError):
                    operational_seed_progress_descriptors(
                        registry,
                        records=registry.verify_all().records,
                        events=ledger.validate().events,
                    )


if __name__ == "__main__":
    unittest.main()
