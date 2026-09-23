"""NON_EVIDENTIARY conditional Dataset publication/currentness checks.

External acquisition and semantic acceptance use explicit inert fixtures. The
registry, ledger, contract/amendment/current-lineage and Dataset publication
owners remain real. These tests confer no scientific, reserve or E4 authority.
Historical exact retries stay distinct from new publication. Discovery owns one
class and eighteen methods; helper fixture tests are not inherited or repeated.
"""
from dataclasses import replace
import unittest
from unittest.mock import patch

from scientist_one import evaluation_contract_amendment as amendment
from scientist_one import research_state as state
from scientist_one import scientific_design as design
from scientist_one.errors import ValidationError
from scientist_one.models import utc_now
from scientist_one.roles import Role
from tests import test_dataset_publication_atomicity as dataset_fixture
from tests.test_dataset_publication_atomicity import RUN_ID


class DatasetPublicationCurrentnessTests(unittest.TestCase):

    def setUp(self):
        # Reuse the real-contract atomicity fixture without inheriting its tests.
        self.case = dataset_fixture.DatasetPublicationAtomicityTests()
        self.addCleanup(self.case.doCleanups)
        self.fixture = self.case._fixture()
        self.registry = self.fixture["registry"]
        self.ledger = self.fixture["ledger"]
        self.parent = self.fixture["contract_record"]
        self.case.real_contract = self.fixture["contract"]
        self.case.evidence = self.registry.get_metadata(self.parent.parent_artifacts[0])
        self.assertEqual(design.require_frozen_evaluation_contract(
            self.registry, contract_artifact_sha256=self.parent.sha256),
            self.case.real_contract)

    def snapshot(self):
        return self.registry.verify_all(raise_on_error=True), self.ledger.assert_valid()

    def current(self, record):
        return amendment._require_current_evaluation_contract_lineage(
            self.registry, self.ledger, expected_run_id=dataset_fixture.RUN_ID,
            contract_artifact_sha256=record.sha256,
        )

    def supersede(self):
        child = replace(self.case.real_contract,
            version=self.case.real_contract.version + 1,
            success_criteria=("NON_EVIDENTIARY changed prospective criterion.",))
        publication = amendment.register_evaluation_contract_amendment(
            self.registry, self.ledger, run_id=dataset_fixture.RUN_ID,
            amendment_id="dataset-currentness-successor",
            parent_contract_artifact_sha256=self.parent.sha256,
            child_contract=child, author_id=child.frozen_by,
            reason="Private offline currentness probe; no scientific authority.",
            child_evidence_parent_artifact_sha256s=(self.case.evidence.sha256,),
        )
        self.assertEqual(amendment.require_evaluation_contract_amendment(
            self.registry, self.ledger, expected_run_id=dataset_fixture.RUN_ID,
            amendment_artifact_sha256=publication.amendment_record.sha256), publication)
        with self.assertRaisesRegex(amendment.EvaluationContractAmendmentError, "superseded"):
            self.current(self.parent)
        self.assertEqual(self.current(publication.contract_record).contract, child)
        self.assertEqual(design.require_frozen_evaluation_contract(
            self.registry, contract_artifact_sha256=self.parent.sha256),
            self.case.real_contract)
        return publication

    def publish(self):
        return state.register_scientific_dataset_authority(
            self.registry, self.ledger, run_id=dataset_fixture.RUN_ID,
            usage_proposal_artifact_hash=self.fixture["proposal"].sha256,
            semantic_authority_artifact_hash=self.fixture["semantic"].sha256,
        )

    def fixture_semantic_review(self):
        return patch.object(state, "_require_scientific_dataset_usage_semantic_authority",
                            return_value=self.fixture["semantic_resolution"])

    def test_current_publication_and_later_historical_read_remain_valid(self):
        self.assertEqual(self.current(self.parent).contract_record, self.parent)
        with self.fixture_semantic_review():
            record = self.publish()
            self.supersede()
            before = self.snapshot()
            resolved = state.require_scientific_dataset_authority(
                self.registry, self.ledger, run_id=dataset_fixture.RUN_ID,
                authority_artifact_hash=record.sha256,
            )
            self.assertEqual(resolved.evaluation_contract_artifact_hash, self.parent.sha256)
            self.assertEqual(self.publish(), record)  # exact completed retry
            self.assertEqual(self.snapshot(), before)

    def test_review_then_amendment_blocks_new_publication_without_writes(self):
        self.supersede()
        before = self.snapshot()
        with self.fixture_semantic_review(), self.assertRaisesRegex(
            ValidationError, "immediately after usage review"
        ):
            self.publish()
        self.assertEqual(self.snapshot(), before)

    def test_amendment_then_old_contract_review_must_refuse_new_publication(self):
        self.supersede()
        # A later inert review event supplies accepted external/semantic sources
        # for C1 at the single documented mock boundary. No real review is claimed.
        stamp = utc_now()
        review = self.case._put_json(self.registry,
            {"fixture": "NON_EVIDENTIARY later review of historical C1"},
            logical_type="audited_provider_transport_authority",
            role=Role.CLAIM_VERIFIER, created_at=stamp)
        head = self.ledger.events()[-1]
        self.ledger.record(
            run_id=dataset_fixture.RUN_ID, actor_role=Role.CLAIM_VERIFIER,
            state_before=head.requested_state_after,
            requested_state_after=head.requested_state_after,
            artifact_hashes=(review.sha256,), code_version=head.code_version,
            configuration_hash=head.configuration_hash,
            reason="NON_EVIDENTIARY mocked later usage-review source for C1.",
            event_id="dataset-later-fixture-review", timestamp=stamp,
            event_type="CHECKPOINT", metadata={"fixture": "NOT external authority"},
        )
        sources = list(self.fixture["semantic_resolution"])
        sources[7] = review.sha256
        self.fixture["semantic_resolution"] = tuple(sources)
        with self.assertRaisesRegex(amendment.EvaluationContractAmendmentError, "superseded"):
            self.current(self.parent)
        before = self.snapshot()
        with self.fixture_semantic_review():
            try:
                published = self.publish()
            except ValidationError:
                self.assertEqual(self.snapshot(), before)
                return
            resolved = state.require_scientific_dataset_authority(
                self.registry, self.ledger, run_id=dataset_fixture.RUN_ID,
                authority_artifact_hash=published.sha256,
            )
        after = self.snapshot()
        self.assertEqual(resolved.evaluation_contract_artifact_hash, self.parent.sha256)
        print("CONDITIONAL_STALE_PUBLICATION", {
            "registry_delta": after[0].count - before[0].count,
            "ledger_delta": after[1].event_count - before[1].event_count,
            "authority_sha256": published.sha256,
            "current_parent_refused": True,
            "semantic_acquisition_fixture_only": True,
        }, flush=True)
        self.fail("Superseded C1 received a new Dataset publication after a later mocked review")

    def project(self, authority):
        from scientist_one import research_state as state
        return state.register_scientific_experiment_dataset_projection(
            self.registry, self.ledger, run_id=RUN_ID,
            dataset_authority_artifact_hash=authority.sha256,
            evaluation_contract_artifact_hash=self.parent.sha256,
        )

    def split(self, authority):
        from scientist_one import research_state as state
        return state.register_scientific_dataset_split_authorities(
            self.registry, self.ledger, run_id=RUN_ID,
            dataset_authority_artifact_hash=authority.sha256,
            evaluation_contract_artifact_hash=self.parent.sha256,
        )

    def refuse_new(self, operation):
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            operation()
        self.assertEqual(self.snapshot(), before)

    def test_superseded_contract_cannot_publish_new_projection(self):
        with self.fixture_semantic_review():
            authority = self.publish()
            self.supersede()
            self.refuse_new(lambda: self.project(authority))

    def test_superseded_contract_cannot_publish_new_split_family(self):
        with self.fixture_semantic_review():
            authority = self.publish()
            self.supersede()
            self.refuse_new(lambda: self.split(authority))

    def test_completed_historical_projection_and_splits_remain_readable_noops(self):
        from scientist_one import research_state as state
        with self.fixture_semantic_review():
            authority = self.publish()
            projection = self.project(authority)
            splits = self.split(authority)
            self.supersede()
            before = self.snapshot()
            self.assertEqual(self.project(authority), projection)
            self.assertEqual(self.split(authority), splits)
            self.assertEqual(state.require_scientific_experiment_dataset_projection(
                self.registry, self.ledger, run_id=RUN_ID,
                projection_artifact_hash=projection.sha256,
                expected_evaluation_contract_artifact_hash=self.parent.sha256,
            ), projection)
            for split in splits:
                resolved = state.require_scientific_dataset_split_authority(
                    self.registry, self.ledger, run_id=RUN_ID,
                    split_authority_artifact_hash=split.sha256,
                )
                self.assertEqual(resolved.evaluation_contract_artifact_hash, self.parent.sha256)
            self.assertEqual(self.snapshot(), before)

    def orphan_then_supersede(self, operation):
        with self.fixture_semantic_review():
            authority = self.publish()
            before = self.snapshot()
            with patch.object(self.ledger, "_append_locked",
                              side_effect=RuntimeError("root injected publication interruption")):
                with self.assertRaisesRegex(RuntimeError, "root injected"):
                    operation(authority)
            orphan = self.snapshot()
            self.assertGreater(orphan[0].count, before[0].count)
            self.assertEqual(orphan[1], before[1])
            self.supersede()
            self.refuse_new(lambda: operation(authority))

    def test_orphan_projection_cannot_finish_under_superseded_contract(self):
        self.orphan_then_supersede(self.project)

    def test_orphan_split_family_cannot_finish_under_superseded_contract(self):
        self.orphan_then_supersede(self.split)

    def helper(self, *, missing, event, record=None, pair=None):
        return state._require_current_scientific_dataset_publication_contract(
            self.registry, self.ledger, run_id=RUN_ID,
            contract_record=self.parent if record is None else record,
            missing=missing, event_to_append=event,
            source_snapshot=self.snapshot() if pair is None else pair,
        )

    def test_exact_record_mismatch_is_refused_without_writes(self):
        before = self.snapshot()
        substituted = replace(self.parent, origin="NON_EVIDENTIARY substituted metadata", record_hash=None)
        with self.assertRaisesRegex(ValidationError, "current contract record differs"):
            self.helper(missing=frozenset({"f" * 64}), event=None, record=substituted)
        self.assertEqual(self.snapshot(), before)

    def test_missing_only_branch_requires_current_contract(self):
        before = self.snapshot()
        self.helper(missing=frozenset({"f" * 64}), event=None)
        self.assertEqual(self.snapshot(), before)
        self.supersede()
        before = self.snapshot()
        with self.assertRaisesRegex(ValidationError, "superseded"):
            self.helper(missing=frozenset({"f" * 64}), event=None)
        self.assertEqual(self.snapshot(), before)

    def test_authority_event_only_orphan_lower_level_currentness_guard(self):
        # The public stale-authority retry also has review-adjacency refusal.
        # Capture the actual event-only orphan and test the helper separately,
        # so this does NOT credit adjacency with exercising the new OR branch.
        captured = []
        native = state._require_current_scientific_dataset_publication_contract
        def observe(*args, **kwargs):
            captured.append(dict(kwargs))
            return native(*args, **kwargs)
        with self.fixture_semantic_review(), patch.object(
            state, "_require_current_scientific_dataset_publication_contract", observe
        ):
            with patch.object(self.ledger, "_append_locked", side_effect=RuntimeError("event interruption")):
                with self.assertRaisesRegex(RuntimeError, "event interruption"):
                    self.publish()
            orphan = self.snapshot()
            # Stop before commit to inspect a real preflighted empty-missing
            # retry without completing it; guard itself forwards unchanged.
            with patch.object(state, "_commit_scientific_dataset_publication",
                              side_effect=RuntimeError("retain exact orphan")):
                with self.assertRaisesRegex(RuntimeError, "retain exact orphan"):
                    self.publish()
            self.assertEqual(self.snapshot(), orphan)
        event_only = captured[-1]
        self.assertEqual(event_only["missing"], frozenset())
        self.assertIsNotNone(event_only["event_to_append"])
        self.supersede()
        before = self.snapshot()
        with self.fixture_semantic_review(), self.assertRaisesRegex(
            ValidationError, "immediately after usage review"
        ):
            self.publish()
        self.assertEqual(self.snapshot(), before)
        # Actual lineage replay of C1, not a supplied currentness answer.
        with self.assertRaisesRegex(ValidationError, "superseded"):
            native(self.registry, self.ledger, **event_only)
        self.assertEqual(self.snapshot(), before)

    def test_current_event_only_authority_orphan_recovers_without_new_records(self):
        with self.fixture_semantic_review():
            with patch.object(self.ledger, "_append_locked", side_effect=RuntimeError("event interruption")):
                with self.assertRaisesRegex(RuntimeError, "event interruption"):
                    self.publish()
            before = self.snapshot()
            self.publish()
            after = self.snapshot()
            self.assertEqual(before[0], after[0])
            self.assertEqual(after[1].event_count, before[1].event_count + 1)

    def _operation(self, family):
        if family == "authority":
            return self.publish
        authority = self.publish()
        return lambda: getattr(self, family)(authority)

    def _append_unrelated(self):
        head = self.ledger.events()[-1]
        self.ledger.record(
            run_id=RUN_ID, actor_role=Role.ORCHESTRATOR,
            state_before=head.requested_state_after,
            requested_state_after=head.requested_state_after,
            artifact_hashes=(), code_version=head.code_version,
            configuration_hash=head.configuration_hash,
            event_type="CHECKPOINT", reason="NON_EVIDENTIARY injected source append",
            metadata={"fixture": "paired-snapshot drift only"},
        )

    def _drift_during_lineage(self, family):
        with self.fixture_semantic_review():
            operation = self._operation(family)
            before = self.snapshot()
            injected = []
            native = amendment._require_current_evaluation_contract_lineage
            def changed(*args, **kwargs):
                self._append_unrelated()
                injected.append(self.snapshot())
                return native(*args, **kwargs)
            with patch.object(amendment, "_require_current_evaluation_contract_lineage", changed):
                with self.assertRaisesRegex(ValidationError, "sources changed during current-contract resolution"):
                    operation()
            self.assertEqual(len(injected), 1)
            self.assertEqual(self.snapshot(), injected[0])
            self.assertEqual(injected[0][0], before[0])
            self.assertEqual(injected[0][1].event_count, before[1].event_count + 1)

    def _amend_after_check(self, family):
        with self.fixture_semantic_review():
            operation = self._operation(family)
            before = self.snapshot()
            injected = []
            native = state._commit_scientific_dataset_publication
            def changed(*args, **kwargs):
                self.supersede()
                injected.append(self.snapshot())
                return native(*args, **kwargs)
            with patch.object(state, "_commit_scientific_dataset_publication", changed):
                with self.assertRaisesRegex(ValidationError, "sources changed before publication"):
                    operation()
            self.assertEqual(len(injected), 1)
            self.assertEqual(self.snapshot(), injected[0])
            self.assertEqual(injected[0][0].count, before[0].count + 2)
            self.assertEqual(injected[0][1].event_count, before[1].event_count + 1)

    def test_authority_original_pair_not_refreshed(self):
        self._drift_during_lineage("authority")

    def test_projection_original_pair_not_refreshed(self):
        self._drift_during_lineage("project")

    def test_splits_original_pair_not_refreshed(self):
        self._drift_during_lineage("split")

    def test_authority_late_amendment_is_caught_by_original_CAS(self):
        self._amend_after_check("authority")

    def test_projection_late_amendment_is_caught_by_original_CAS(self):
        self._amend_after_check("project")

    def test_splits_late_amendment_is_caught_by_original_CAS(self):
        self._amend_after_check("split")
