"""Actual native observation is not an unseen amendment checkpoint.

Private integration diagnostics; no scientific authority is manufactured.
The retained observation fixture contains actual native execution, not a
substituted success response. Rollback restores only the test run subtree.
"""
from dataclasses import replace
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one import evaluation_contract_amendment as amendments
from scientist_one import orchestrator
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
import tests.test_evaluation_contract_amendment as legacy_fixtures
import tests.test_simulated_observation as fixture

from tests.test_resource_prepared_cases import (
    prepared_observed_tests, prepared_uninventoried_component,
)


@prepared_observed_tests
class ObservedAmendmentTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.SimulatedObservationTests()
        self.addCleanup(self.case.doCleanups)
        self.case.setUp()

    def amend_v1(self, registry=None, ledger=None):
        case = self.case
        parent = case.reservation.contract
        return amendments.register_evaluation_contract_amendment(
            registry or case.registry, ledger or case.ledger, run_id=case.case.run,
            amendment_id="post-native-observation-v1-probe",
            parent_contract_artifact_sha256=case.reservation.contract_record.sha256,
            child_contract=replace(parent, version=parent.version + 1,
                                   success_criteria=("Changed after actual native observation.",)),
            author_id=parent.frozen_by,
            reason="Negative-only default amendment boundary after native observation",
        )

    def assert_default_refuses_without_publication(self, registry, ledger):
        before = registry.verify_all(raise_on_error=True), ledger.validate()
        publication = None
        error = None
        try:
            publication = self.amend_v1(registry, ledger)
        except amendments.EvaluationContractAmendmentError as exc:
            error = exc
        after = registry.verify_all(raise_on_error=True), ledger.validate()
        print("ACTUAL_DEFAULT_AMENDMENT", {
            "records_before": before[0].count, "records_after": after[0].count,
            "events_before": before[1].event_count, "events_after": after[1].event_count,
            "results_seen": None if publication is None else publication.authority.amendment.results_already_seen,
            "fresh_reserve_required": None if publication is None else publication.authority.amendment.requires_new_confirmatory_reserve,
            "error": None if error is None else str(error),
        }, flush=True)
        with self.subTest(check="reject unsupported observation authority"):
            self.assertIsInstance(error, amendments.EvaluationContractAmendmentError)
        self.assertEqual(after, before)

    def test_default_amendment_after_actual_J_never_publishes_unseen(self):
        self.case.run_observation(self.case.prepare())
        self.assert_default_refuses_without_publication(self.case.registry, self.case.ledger)

    def test_default_amendment_after_run_rollback_cannot_ignore_external_attempt(self):
        case = self.case
        with tempfile.TemporaryDirectory(prefix="amendment-run-rollback-") as backup:
            run_dir = case.root / "runs" / case.case.run
            snapshot = Path(backup) / "run-snapshot"
            shutil.copytree(run_dir, snapshot)
            case.run_observation(case.prepare())
            displaced = Path(backup) / "observed-run"
            shutil.move(str(run_dir), str(displaced))
            shutil.copytree(snapshot, run_dir)
            registry = ArtifactRegistry(case.root, base_path=case.registry.base_path)
            ledger = EventLedger(case.root, case.ledger.relative_path)
            self.assert_default_refuses_without_publication(registry, ledger)

    def test_preobservation_Q_amendment_keeps_existing_v1_wire(self):
        publication = self.amend_v1()
        self.assertEqual(publication.authority.schema_version, "evaluation-contract-amendment/v1")
        self.assertEqual(publication.amendment_record.schema_version, "eval-contract-amendment/v1")
        self.assertFalse(publication.authority.amendment.results_already_seen)
        self.assertFalse(publication.authority.amendment.requires_new_confirmatory_reserve)
        self.assertFalse(publication.authority.confirmation_authorized)

    def test_completed_v1_replay_uses_sealed_population_not_current_external_tail(self):
        publication = self.amend_v1()
        self.case.registry.put_json(
            {"renamed": {"schema_version": "sim-reserve-attempt/v1"}},
            logical_type="inert_adversarial_later_alias", origin="negative history test",
            creator_role=Role.ORCHESTRATOR,
        )
        before = self.case.snapshot()
        with mock.patch.object(orchestrator, "_read_resource_authority_records",
                               side_effect=AssertionError("historical A consulted current external tail")):
            read = amendments.require_evaluation_contract_amendment(
                self.case.registry, self.case.ledger,
                amendment_artifact_sha256=publication.amendment_record.sha256,
                expected_run_id=self.case.case.run,
            )
            repeated = self.amend_v1()
        self.assertEqual(read, publication)
        self.assertEqual(repeated, publication)
        self.assertEqual(self.case.snapshot(), before)

    def test_current_amendment_serializes_native_attempt_before_candidate_publication(self):
        prep = self.case.prepare()
        before_external = self.case.case.files()
        original = amendments._source_chronology
        attempts = []

        def concurrent_attempt(*args, **kwargs):
            if not attempts:
                attempts.append(True)
                with self.assertRaisesRegex(Exception, "project resource execution lock failed"):
                    self.case.native_attempt(prep)
                self.assertEqual(self.case.case.files(), before_external)
            return original(*args, **kwargs)

        with mock.patch.object(amendments, "_source_chronology", concurrent_attempt):
            publication = self.amend_v1()
        self.assertEqual(attempts, [True])
        self.assertFalse(publication.authority.amendment.results_already_seen)
        self.assertEqual(self.case.case.files(), before_external)

    def test_pre_I_absent_external_storage_keeps_default_amendment(self):
        case = fixture.fixtures.SimulatedResourceTests()
        self.addCleanup(case.doCleanups)
        with prepared_uninventoried_component(self, case):
            case.prepare(freeze=False)
            self.assertEqual(case.contract_record.sha256, self.case.reservation.contract_record.sha256)
            self.assertFalse((case.root / ".scientist-one-build/resource-authority").exists())
            publication = self.amend_v1(case.registry, case.ledger)
            self.assertFalse(publication.authority.amendment.results_already_seen)
            self.assertFalse((case.root / ".scientist-one-build/resource-authority").exists())

    def test_post_Q_absent_or_wrong_kind_external_storage_refuses(self):
        path = self.case.root / ".scientist-one-build/resource-authority" / self.case.case.run
        with tempfile.TemporaryDirectory(prefix="amendment-external-preservation-") as backup:
            shutil.move(str(path), str(Path(backup) / "authority"))
            self.assert_default_refuses_without_publication(self.case.registry, self.case.ledger)
            path.write_bytes(b"wrong-kind authority sentinel")
            self.assert_default_refuses_without_publication(self.case.registry, self.case.ledger)

    def test_default_v1_refuses_renamed_null_malformed_and_metadata_attempt_aliases(self):
        markers = (
            "sim-reserve-attempt/v1", "sim-reserve-started/v1", "sim-reserve-observation/v1",
        )
        for marker in markers:
            for form in ("renamed", "malformed", "metadata"):
                with self.subTest(marker=marker, form=form):
                    case = legacy_fixtures.EvaluationContractAmendmentTests()
                    self.addCleanup(case.doCleanups)
                    case.setUp()
                    raw = canonical_json_bytes({"renamed": {"schema_version": marker}})
                    if form == "malformed":
                        raw = raw[:-1]
                    if form == "metadata":
                        raw = b"{}"
                    case.registry.put_bytes(raw, logical_type="inert_renamed_alias",
                        origin="adversarial alias test", creator_role=Role.ORCHESTRATOR,
                        schema_version=marker if form == "metadata" else "1.0")
                    before = case.registry.verify_all(raise_on_error=True), case.ledger.validate()
                    with self.assertRaises(amendments.EvaluationContractAmendmentError):
                        case.publish()
                    self.assertEqual((case.registry.verify_all(raise_on_error=True), case.ledger.validate()), before)
        for key in ("simulated_reserve_attempt", "simulated_reserve_started", "simulated_reserve_observation"):
            with self.subTest(null_key=key):
                case = legacy_fixtures.EvaluationContractAmendmentTests()
                self.addCleanup(case.doCleanups)
                case.setUp()
                case.registry.put_json({"nested": {key: None}}, logical_type="inert_null_marker",
                                       origin="adversarial alias test", creator_role=Role.ORCHESTRATOR)
                before = case.registry.verify_all(raise_on_error=True), case.ledger.validate()
                with self.assertRaises(amendments.EvaluationContractAmendmentError):
                    case.publish()
                self.assertEqual((case.registry.verify_all(raise_on_error=True), case.ledger.validate()), before)

    def test_unsealed_history_does_not_read_later_record_only_attempt_alias(self):
        self.case.registry.put_json({"schema_version": "sim-reserve-attempt/v1"},
            logical_type="inert_future_marker", origin="negative history scope test",
            creator_role=Role.ORCHESTRATOR)
        records = self.case.registry.verify_all(raise_on_error=True).records
        with mock.patch.object(orchestrator, "_read_resource_authority_records",
                               side_effect=AssertionError("snapshot helper consulted external storage")):
            amendments.reject_simulated_reserve_attempt_exposure(
                self.case.registry, records, (), complete_registry_population=False)
            with self.assertRaises(amendments.EvaluationContractAmendmentError):
                amendments.reject_simulated_reserve_attempt_exposure(
                    self.case.registry, records, (), complete_registry_population=True)

    def test_untyped_marker_prose_and_large_unrelated_data_do_not_change_v1(self):
        case = legacy_fixtures.EvaluationContractAmendmentTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.registry.put_json({"note": ["sim-reserve-attempt/v1", "sim-reserve-observation/v1"]},
            logical_type="ordinary_prose", origin="negative selection scope test", creator_role=Role.ORCHESTRATOR)
        case.registry.put_bytes(b"ordinary data\n" * 170000, logical_type="ordinary_large_data",
            origin="negative selection size scope test", creator_role=Role.ORCHESTRATOR)
        publication = case.publish()
        self.assertEqual(publication.authority.schema_version, "evaluation-contract-amendment/v1")
        self.assertFalse(publication.authority.amendment.results_already_seen)
