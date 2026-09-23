"""Focused operational tests for persisted Evaluation Contract amendments.

Synthetic timeline outputs in this module are explicitly NON_EVIDENTIARY.  No
test issues scientific, confirmation, reserve, human, or release authority.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import scientist_one.evaluation_contract_amendment as amendment_module
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.evaluation_contract_amendment import (
    EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE,
    EvaluationContractAmendmentError,
    EvaluationContractAmendmentPublication,
    _child_bytes,
    _require_evaluation_contract_child_lineage,
    _require_evaluation_contract_family_before_design,
    _require_evaluation_contract_registry_lineage,
    _require_registry_record_map,
    _registry_record_map,
    register_evaluation_contract_amendment,
    require_evaluation_contract_amendment,
)
from scientist_one.errors import ArtifactError, LedgerError
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    HypothesisRole,
    HypothesisTiming,
    _evaluation_contract_artifact_schema,
    record_scientific_design_freeze,
    record_scientific_result_observed,
    register_frozen_evaluation_contract,
    register_frozen_experiment_plan,
    register_frozen_run_spec,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads, sha256_bytes
from tests import test_scientific_design as timeline_fixtures


_RUN_ID = "amendment-test-run"


class EvaluationContractAmendmentTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="contract-amendment-")
        self.addCleanup(directory.cleanup)
        self.root = directory.name
        self.registry = ArtifactRegistry(self.root)
        self.ledger = EventLedger(self.root, "runs/amendments/events.jsonl")
        self.evidence = timeline_fixtures._timeline_artifact(
            self.registry,
            b'{"fixture":"NON_EVIDENTIARY amendment evidence"}\n',
            "timeline_contract_evidence",
            Role.EVIDENCE_CURATOR,
        )
        self.parent = timeline_fixtures.make_contract()
        self.parent_record = register_frozen_evaluation_contract(
            self.registry,
            contract=self.parent,
            parent_artifact_sha256s=(self.evidence.sha256,),
        )

    def child(self, **changes):
        values = {
            "version": self.parent.version + 1,
            "success_criteria": (
                "Changed criterion recorded without confirmation authority.",
            ),
        }
        values.update(changes)
        return replace(self.parent, **values)

    def publish(self, *, child=None, amendment_id="amendment-1"):
        return register_evaluation_contract_amendment(
            self.registry,
            self.ledger,
            run_id=_RUN_ID,
            amendment_id=amendment_id,
            parent_contract_artifact_sha256=self.parent_record.sha256,
            child_contract=self.child() if child is None else child,
            author_id=self.parent.frozen_by,
            reason="Record a bounded prospective contract change.",
            child_evidence_parent_artifact_sha256s=(self.evidence.sha256,),
        )

    def inert_contract_record(self, contract, *, parents=None):
        return self.registry.put_bytes(
            _child_bytes(contract),
            logical_type="evaluation_contract",
            origin="canonical frozen evaluation contract authority",
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("scientist-one", "freeze-evaluation-contract"),
            parent_artifacts=(self.evidence.sha256,) if parents is None else parents,
            schema_version=_evaluation_contract_artifact_schema(contract),
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    @staticmethod
    def freeze_timeline_design(values):
        return record_scientific_design_freeze(
            values["registry"],
            values["ledger"],
            run_id="timeline-run",
            contract=values["contract"],
            contract_artifact_sha256=values["contract_record"].sha256,
            experiment_plan_artifact_sha256s=tuple(
                item.sha256 for item in values["plan_records"]
            ),
            frozen_run_spec_artifact_sha256=values["spec_record"].sha256,
        )

    @staticmethod
    def observe_timeline_result(values):
        timeline_fixtures._register_timeline_outputs(values)
        return record_scientific_result_observed(
            values["registry"],
            values["ledger"],
            run_id="timeline-run",
            contract=values["contract"],
            contract_artifact_sha256=values["contract_record"].sha256,
            experiment_plan_artifact_sha256s=tuple(
                item.sha256 for item in values["plan_records"]
            ),
            frozen_run_spec_artifact_sha256=values["spec_record"].sha256,
            output_manifest_artifact_sha256=values["manifest_record"].sha256,
        )

    @classmethod
    def complete_timeline_result(cls, values):
        design = cls.freeze_timeline_design(values)
        result = cls.observe_timeline_result(values)
        return design, result

    def test_pre_result_publication_is_exact_idempotent_change_record(self):
        before_registry = self.registry.verify_all(raise_on_error=True)
        publication = self.publish()
        self.assertIs(type(publication), EvaluationContractAmendmentPublication)
        self.assertFalse(publication.authority.confirmation_authorized)
        self.assertFalse(publication.authority.amendment.results_already_seen)
        self.assertFalse(
            publication.authority.amendment.requires_new_confirmatory_reserve
        )
        self.assertEqual(
            publication.authority.amendment.changed_fields,
            ("success_criteria",),
        )
        self.assertEqual(
            publication.amendment_record.parent_artifacts,
            (self.parent_record.sha256,),
        )
        self.assertEqual(
            publication.contract_record.parent_artifacts,
            (publication.amendment_record.sha256, self.evidence.sha256),
        )
        self.assertEqual(
            publication.amendment_record.created_at,
            publication.contract_record.created_at,
        )
        self.assertEqual(
            publication.event.timestamp, publication.contract_record.created_at
        )
        self.assertEqual(
            self.registry.verify_all(raise_on_error=True).count,
            before_registry.count + 2,
        )
        self.assertEqual(self.ledger.assert_valid().event_count, 1)
        wrapper = safe_json_loads(
            self.registry.get_bytes(publication.contract_record.sha256)
        )
        self.assertEqual(
            self.registry.get_bytes(publication.contract_record.sha256),
            canonical_json_bytes(wrapper) + b"\n",
        )
        self.assertEqual(
            require_evaluation_contract_amendment(
                self.registry,
                self.ledger,
                amendment_artifact_sha256=publication.amendment_record.sha256,
                expected_run_id=_RUN_ID,
                expected_child_contract_artifact_sha256=(
                    publication.contract_record.sha256
                ),
            ),
            publication,
        )
        snapshot = (
            self.registry.verify_all(raise_on_error=True),
            self.ledger.assert_valid(),
        )
        self.assertEqual(self.publish(), publication)
        self.assertEqual(
            (
                self.registry.verify_all(raise_on_error=True),
                self.ledger.assert_valid(),
            ),
            snapshot,
        )
        self.assertEqual(
            publication.amendment_record.logical_type,
            EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE,
        )

    def test_post_result_publication_derives_complete_non_evidentiary_visibility(self):
        with tempfile.TemporaryDirectory(prefix="visible-contract-amendment-") as root:
            values = timeline_fixtures._prepared_timeline(root)
            design_event = timeline_fixtures.record_scientific_design_freeze(
                values["registry"],
                values["ledger"],
                run_id="timeline-run",
                contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                experiment_plan_artifact_sha256s=tuple(
                    item.sha256 for item in values["plan_records"]
                ),
                frozen_run_spec_artifact_sha256=values["spec_record"].sha256,
            )
            timeline_fixtures._register_timeline_outputs(values)
            result_event = timeline_fixtures.record_scientific_result_observed(
                values["registry"],
                values["ledger"],
                run_id="timeline-run",
                contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                experiment_plan_artifact_sha256s=tuple(
                    item.sha256 for item in values["plan_records"]
                ),
                frozen_run_spec_artifact_sha256=values["spec_record"].sha256,
                output_manifest_artifact_sha256=values["manifest_record"].sha256,
            )
            child = replace(
                values["contract"],
                version=values["contract"].version + 1,
                success_criteria=(
                    "Changed only in an append-only post-visibility record.",
                ),
            )
            publication = register_evaluation_contract_amendment(
                values["registry"],
                values["ledger"],
                run_id="timeline-run",
                amendment_id="visible-amendment",
                parent_contract_artifact_sha256=values["contract_record"].sha256,
                child_contract=child,
                author_id=values["contract"].frozen_by,
                reason="Record changed criteria after synthetic visibility.",
                child_evidence_parent_artifact_sha256s=(values["evidence"].sha256,),
            )
            authority = publication.authority
            self.assertTrue(authority.amendment.results_already_seen)
            self.assertTrue(authority.amendment.requires_new_confirmatory_reserve)
            self.assertFalse(authority.confirmation_authorized)
            self.assertEqual(len(authority.visible_results), 1)
            visible = authority.visible_results[0]
            self.assertEqual(
                visible.output_manifest_artifact_sha256,
                values["manifest_record"].sha256,
            )
            self.assertEqual(visible.design_event_hash, design_event.event_hash)
            self.assertEqual(visible.result_event_hash, result_event.event_hash)
            self.assertEqual(
                publication.amendment_record.parent_artifacts,
                (
                    values["contract_record"].sha256,
                    values["manifest_record"].sha256,
                ),
            )
            self.assertEqual(publication.event_index, 2)
            family = _require_evaluation_contract_family_before_design(
                values["registry"],
                values["ledger"],
                expected_run_id="timeline-run",
                contract_artifact_sha256=publication.contract_record.sha256,
                input_artifact_sha256s=(
                    values["code"].sha256,
                    values["data"].sha256,
                    values["configuration"].sha256,
                    values["evaluator"].sha256,
                ),
                design_event_index=values["ledger"].assert_valid().event_count,
            )
            self.assertEqual(
                family.visible_ancestor_manifest_artifact_sha256s,
                (values["manifest_record"].sha256,),
            )
            self.assertTrue(family.requires_new_confirmatory_reserve)
            self.assertFalse(family.confirmation_authorized)

    def test_registry_only_lineage_uses_persisted_ledger_only_for_amended_child(self):
        genesis = _require_evaluation_contract_registry_lineage(
            self.registry,
            contract_artifact_sha256=self.parent_record.sha256,
        )
        self.assertIsNone(genesis.ledger_snapshot)
        self.assertFalse(any(Path(self.root).rglob("*.jsonl")))

        publication = self.publish()
        replay = _require_evaluation_contract_registry_lineage(
            self.registry,
            contract_artifact_sha256=publication.contract_record.sha256,
        )
        self.assertEqual(replay.contract_record, publication.contract_record)
        self.assertEqual(
            replay.selected_amendment_artifact_sha256,
            publication.amendment_record.sha256,
        )
        self.assertEqual(replay.ledger_snapshot, self.ledger.assert_valid())

    def test_child_lineage_refuses_another_run_or_persisted_ledger_path(self):
        publication = self.publish()
        before = (
            self.registry.verify_all(raise_on_error=True),
            self.ledger.assert_valid(),
        )
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError,
            "another run",
        ):
            _require_evaluation_contract_child_lineage(
                self.registry,
                self.ledger,
                expected_run_id="another-amendment-run",
                contract_artifact_sha256=publication.contract_record.sha256,
            )

        other_ledger = EventLedger(self.root, "runs/other-ledger/events.jsonl")
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError,
            "another exact ledger path",
        ):
            _require_evaluation_contract_child_lineage(
                self.registry,
                other_ledger,
                expected_run_id=_RUN_ID,
                contract_artifact_sha256=publication.contract_record.sha256,
            )
        self.assertEqual(
            (
                self.registry.verify_all(raise_on_error=True),
                self.ledger.assert_valid(),
            ),
            before,
        )

    def test_identity_inventory_prefilters_unrelated_malformed_wrapper(self):
        self.registry.put_json(
            {
                "schema_version": "malformed-but-unrelated/v1",
                "evaluation_contract": {"contract_id": "other-contract"},
            },
            logical_type="evaluation_contract",
            origin="canonical frozen evaluation contract authority",
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("scientist-one", "freeze-evaluation-contract"),
            parent_artifacts=(self.evidence.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        replay = _require_evaluation_contract_registry_lineage(
            self.registry,
            contract_artifact_sha256=self.parent_record.sha256,
        )
        self.assertEqual(replay.contract_record, self.parent_record)

        self.registry.put_json(
            {
                "schema_version": "malformed-related/v1",
                "evaluation_contract": {"contract_id": self.parent.contract_id},
            },
            logical_type="evaluation_contract",
            origin="canonical frozen evaluation contract authority",
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("scientist-one", "freeze-evaluation-contract"),
            parent_artifacts=(self.evidence.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaises(EvaluationContractAmendmentError):
            _require_evaluation_contract_registry_lineage(
                self.registry,
                contract_artifact_sha256=self.parent_record.sha256,
            )

    def test_competing_unamended_same_id_root_is_rejected(self):
        competing = replace(
            self.parent,
            version=self.parent.version + 1,
            success_criteria=("Inert competing genesis bytes.",),
        )
        self.inert_contract_record(competing)
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError,
            "competing unamended roots",
        ):
            _require_evaluation_contract_registry_lineage(
                self.registry,
                contract_artifact_sha256=self.parent_record.sha256,
            )

    def test_later_reference_and_descendant_preserve_historical_readback(self):
        first = self.publish()
        state = first.event.state_after
        self.ledger.record(
            run_id=_RUN_ID,
            actor_role=Role.PROTOCOL_DESIGNER,
            state_before=state,
            requested_state_after=state,
            artifact_hashes=(
                first.amendment_record.sha256,
                first.contract_record.sha256,
            ),
            code_version="test-reference-only",
            configuration_hash=self.evidence.sha256,
            reason="Retain the completed amendment as an ordinary later source.",
            event_type="CHECKPOINT",
            metadata={"reference_only": True},
        )
        second_child = replace(
            first.child_contract,
            version=first.child_contract.version + 1,
            failure_criteria=("A later bounded descendant criterion.",),
        )
        second = register_evaluation_contract_amendment(
            self.registry,
            self.ledger,
            run_id=_RUN_ID,
            amendment_id="amendment-2",
            parent_contract_artifact_sha256=first.contract_record.sha256,
            child_contract=second_child,
            author_id=self.parent.frozen_by,
            reason="Record a later descendant without rewriting its parent.",
            child_evidence_parent_artifact_sha256s=(self.evidence.sha256,),
        )
        self.assertEqual(
            require_evaluation_contract_amendment(
                self.registry,
                self.ledger,
                amendment_artifact_sha256=first.amendment_record.sha256,
                expected_run_id=_RUN_ID,
            ),
            first,
        )
        self.assertEqual(
            _require_evaluation_contract_child_lineage(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                contract_artifact_sha256=second.contract_record.sha256,
            ).lineage_contract_records,
            (self.parent_record, first.contract_record, second.contract_record),
        )

    def test_sealed_design_population_replays_before_later_descendant(self):
        inputs = tuple(
            timeline_fixtures._timeline_artifact(
                self.registry,
                canonical_json_bytes({"input": index}) + b"\n",
                f"contract_family_input_{index}",
                Role.EVIDENCE_CURATOR,
            )
            for index in range(4)
        )
        first = self.publish()
        sealed = self.registry.verify_all(raise_on_error=True).records
        design_index = self.ledger.assert_valid().event_count
        second_child = replace(
            first.child_contract,
            version=first.child_contract.version + 1,
            failure_criteria=("Later descendant after sealed design cut.",),
        )
        register_evaluation_contract_amendment(
            self.registry,
            self.ledger,
            run_id=_RUN_ID,
            amendment_id="later-than-sealed-design",
            parent_contract_artifact_sha256=first.contract_record.sha256,
            child_contract=second_child,
            author_id=self.parent.frozen_by,
            reason="Create a later descendant outside the sealed design cut.",
        )
        family = _require_evaluation_contract_family_before_design(
            self.registry,
            self.ledger,
            expected_run_id=_RUN_ID,
            contract_artifact_sha256=first.contract_record.sha256,
            input_artifact_sha256s=tuple(item.sha256 for item in inputs),
            design_event_index=design_index,
            sealed_design_source_records=sealed,
        )
        self.assertEqual(family.contract_record, first.contract_record)
        self.assertEqual(
            family.registry_snapshot,
            self.registry.verify_all(raise_on_error=True),
        )
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError,
            "requires a sealed design source map",
        ):
            _require_evaluation_contract_family_before_design(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                contract_artifact_sha256=first.contract_record.sha256,
                input_artifact_sha256s=tuple(item.sha256 for item in inputs),
                design_event_index=design_index,
            )

    def test_family_admission_rejects_registry_drift_during_replay(self):
        inputs = tuple(
            timeline_fixtures._timeline_artifact(
                self.registry,
                canonical_json_bytes({"input": index}) + b"\n",
                f"contract_family_race_input_{index}",
                Role.EVIDENCE_CURATOR,
            )
            for index in range(4)
        )
        original = amendment_module._input_binding
        mutation_count = 0

        def inject_unrelated_append(registry, input_artifact_sha256s):
            nonlocal mutation_count
            binding = original(registry, input_artifact_sha256s)
            mutation_count += 1
            timeline_fixtures._timeline_artifact(
                registry,
                canonical_json_bytes({"concurrent": mutation_count}) + b"\n",
                "mechanical_concurrent_registry_append",
                Role.EVIDENCE_CURATOR,
            )
            return binding

        before = (
            self.registry.verify_all(raise_on_error=True),
            self.ledger.assert_valid(),
        )
        with mock.patch.object(
            amendment_module,
            "_input_binding",
            side_effect=inject_unrelated_append,
        ):
            with self.assertRaisesRegex(
                EvaluationContractAmendmentError,
                "sources changed during admission replay",
            ):
                _require_evaluation_contract_family_before_design(
                    self.registry,
                    self.ledger,
                    expected_run_id=_RUN_ID,
                    contract_artifact_sha256=self.parent_record.sha256,
                    input_artifact_sha256s=tuple(item.sha256 for item in inputs),
                    design_event_index=0,
                )
        self.assertEqual(mutation_count, 1)
        self.assertEqual(self.ledger.assert_valid(), before[1])
        self.assertEqual(
            self.registry.verify_all(raise_on_error=True).count,
            before[0].count + 1,
        )

    def test_legacy_historical_genesis_ignores_later_completed_child(self):
        inputs = tuple(
            timeline_fixtures._timeline_artifact(
                self.registry,
                canonical_json_bytes({"legacy_input": index}) + b"\n",
                f"legacy_contract_family_input_{index}",
                Role.EVIDENCE_CURATOR,
            )
            for index in range(4)
        )
        self.publish()
        historical = _require_evaluation_contract_family_before_design(
            self.registry,
            self.ledger,
            expected_run_id=_RUN_ID,
            contract_artifact_sha256=self.parent_record.sha256,
            input_artifact_sha256s=tuple(item.sha256 for item in inputs),
            design_event_index=0,
        )
        self.assertEqual(historical.contract_record, self.parent_record)
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError,
            "superseded before this design point",
        ):
            _require_evaluation_contract_family_before_design(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                contract_artifact_sha256=self.parent_record.sha256,
                input_artifact_sha256s=tuple(item.sha256 for item in inputs),
                design_event_index=self.ledger.assert_valid().event_count,
            )

    def test_legacy_historical_genesis_ignores_later_incomplete_child(self):
        inputs = tuple(
            timeline_fixtures._timeline_artifact(
                self.registry,
                canonical_json_bytes({"legacy_orphan_input": index}) + b"\n",
                f"legacy_orphan_contract_family_input_{index}",
                Role.EVIDENCE_CURATOR,
            )
            for index in range(4)
        )
        with mock.patch.object(
            self.ledger,
            "_append_locked",
            side_effect=LedgerError("mechanical orphan event fault"),
        ):
            with self.assertRaises(LedgerError):
                self.publish()
        self.ledger.record(
            run_id=_RUN_ID,
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.PROTOCOL,
            requested_state_after=MacroState.PROTOCOL,
            artifact_hashes=(),
            code_version="legacy-history-reference",
            configuration_hash=self.evidence.sha256,
            reason="Later event separating the historical design prefix.",
            event_type="CHECKPOINT",
            metadata={"legacy_history_control": True},
        )
        historical = _require_evaluation_contract_family_before_design(
            self.registry,
            self.ledger,
            expected_run_id=_RUN_ID,
            contract_artifact_sha256=self.parent_record.sha256,
            input_artifact_sha256s=tuple(item.sha256 for item in inputs),
            design_event_index=0,
        )
        self.assertEqual(historical.contract_record, self.parent_record)
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError,
            "incomplete child amendment",
        ):
            _require_evaluation_contract_family_before_design(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                contract_artifact_sha256=self.parent_record.sha256,
                input_artifact_sha256s=tuple(item.sha256 for item in inputs),
                design_event_index=self.ledger.assert_valid().event_count,
            )

    def test_correction_of_publication_is_explicitly_rejected(self):
        publication = self.publish()
        self.ledger.append_correction(
            publication.event.event_id,
            actor_role=Role.PROTOCOL_DESIGNER,
            reason="Mechanically correct the amendment publication event.",
            corrected_fields={"status": "RETRACTED"},
        )
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError,
            "publication was corrected",
        ):
            require_evaluation_contract_amendment(
                self.registry,
                self.ledger,
                amendment_artifact_sha256=publication.amendment_record.sha256,
                expected_run_id=_RUN_ID,
            )

    def test_second_typed_publication_event_is_ambiguous(self):
        publication = self.publish()
        state = publication.event.state_after
        self.ledger.record(
            run_id=_RUN_ID,
            actor_role=Role.PROTOCOL_DESIGNER,
            state_before=state,
            requested_state_after=state,
            artifact_hashes=publication.event.artifact_hashes,
            code_version=publication.event.code_version,
            configuration_hash=publication.event.configuration_hash,
            reason="NON_EVIDENTIARY duplicate publication event control.",
            event_type="CHECKPOINT",
            metadata=publication.event.metadata,
        )
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError,
            "one exact publication event",
        ):
            require_evaluation_contract_amendment(
                self.registry,
                self.ledger,
                amendment_artifact_sha256=publication.amendment_record.sha256,
                expected_run_id=_RUN_ID,
            )

    def test_parent_slot_is_single_and_refuses_sibling(self):
        first = self.publish()
        before = (
            self.registry.verify_all(raise_on_error=True),
            self.ledger.assert_valid(),
        )
        sibling = replace(
            self.parent,
            version=self.parent.version + 1,
            success_criteria=("Different sibling change.",),
        )
        with self.assertRaises(EvaluationContractAmendmentError):
            self.publish(child=sibling, amendment_id="sibling-amendment")
        self.assertEqual(
            (
                self.registry.verify_all(raise_on_error=True),
                self.ledger.assert_valid(),
            ),
            before,
        )
        self.assertEqual(
            first.contract_record,
            self.registry.get_metadata(first.contract_record.sha256),
        )

    def test_reserved_child_evidence_and_nonconsecutive_version_refuse_prewrite(self):
        before = (
            self.registry.verify_all(raise_on_error=True),
            self.ledger.assert_valid(),
        )
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError,
            "child evidence cannot create a competing contract lineage",
        ):
            register_evaluation_contract_amendment(
                self.registry,
                self.ledger,
                run_id=_RUN_ID,
                amendment_id="reserved-evidence",
                parent_contract_artifact_sha256=self.parent_record.sha256,
                child_contract=self.child(),
                author_id=self.parent.frozen_by,
                reason="Negative reserved-parent control.",
                child_evidence_parent_artifact_sha256s=(
                    self.parent_record.sha256,
                ),
            )
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError,
            "advance exactly one",
        ):
            self.publish(child=replace(self.child(), version=self.parent.version + 2))
        self.assertEqual(
            (
                self.registry.verify_all(raise_on_error=True),
                self.ledger.assert_valid(),
            ),
            before,
        )

    def test_higher_initial_payload_version_is_genesis_not_implicit_amendment(self):
        with tempfile.TemporaryDirectory(prefix="high-version-amendment-") as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root, "custom/lineage/events.jsonl")
            evidence = timeline_fixtures._timeline_artifact(
                registry,
                b'{"fixture":"high initial version"}\n',
                "timeline_contract_evidence",
                Role.EVIDENCE_CURATOR,
            )
            parent = replace(self.parent, version=7)
            parent_record = register_frozen_evaluation_contract(
                registry,
                contract=parent,
                parent_artifact_sha256s=(evidence.sha256,),
            )
            publication = register_evaluation_contract_amendment(
                registry,
                ledger,
                run_id="high-version-run",
                amendment_id="high-version-amendment",
                parent_contract_artifact_sha256=parent_record.sha256,
                child_contract=replace(
                    parent,
                    version=8,
                    success_criteria=("Explicit revision after high-version genesis.",),
                ),
                author_id=parent.frozen_by,
                reason="Preserve payload-generation version compatibility.",
            )
            self.assertEqual(publication.authority.amendment.from_version, 7)
            self.assertEqual(publication.authority.amendment.to_version, 8)

    def test_incomplete_pair_recovers_only_without_source_drift(self):
        original_append = self.ledger._append_locked
        with mock.patch.object(
            self.ledger,
            "_append_locked",
            side_effect=LedgerError("mechanical event publication fault"),
        ):
            with self.assertRaises(LedgerError):
                self.publish()
        self.assertEqual(self.ledger.assert_valid().event_count, 0)
        self.assertEqual(
            sum(
                record.logical_type == EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE
                for record in self.registry.verify_all(raise_on_error=True).records
            ),
            1,
        )
        with mock.patch.object(self.ledger, "_append_locked", original_append):
            recovered = self.publish()
        self.assertEqual(self.ledger.assert_valid().event_count, 1)
        self.assertEqual(recovered.event, self.ledger.assert_valid().events[-1])

        # A later unrelated source makes a different incomplete slot stale.
        second_child = replace(
            recovered.child_contract,
            version=recovered.child_contract.version + 1,
            failure_criteria=("Second orphan candidate.",),
        )
        original_append = self.ledger._append_locked
        with mock.patch.object(
            self.ledger,
            "_append_locked",
            side_effect=LedgerError("second mechanical event publication fault"),
        ):
            with self.assertRaises(LedgerError):
                register_evaluation_contract_amendment(
                    self.registry,
                    self.ledger,
                    run_id=_RUN_ID,
                    amendment_id="stale-orphan",
                    parent_contract_artifact_sha256=recovered.contract_record.sha256,
                    child_contract=second_child,
                    author_id=self.parent.frozen_by,
                    reason="Create a recoverable pair before source drift.",
                )
        timeline_fixtures._timeline_artifact(
            self.registry,
            b'{"later":"unrelated"}\n',
            "unrelated_later_record",
            Role.EVIDENCE_CURATOR,
        )
        before = (
            self.registry.verify_all(raise_on_error=True),
            self.ledger.assert_valid(),
        )
        with mock.patch.object(self.ledger, "_append_locked", original_append):
            with self.assertRaisesRegex(
                EvaluationContractAmendmentError,
                "cannot recover after source exposure or drift",
            ):
                register_evaluation_contract_amendment(
                    self.registry,
                    self.ledger,
                    run_id=_RUN_ID,
                    amendment_id="stale-orphan",
                    parent_contract_artifact_sha256=recovered.contract_record.sha256,
                    child_contract=second_child,
                    author_id=self.parent.frozen_by,
                    reason="Create a recoverable pair before source drift.",
                )
        self.assertEqual(
            (
                self.registry.verify_all(raise_on_error=True),
                self.ledger.assert_valid(),
            ),
            before,
        )

    def test_single_authority_orphan_recovers_exact_child_and_event(self):
        original_put = self.registry._put_bytes_locked
        calls = 0

        def fail_second_put(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ArtifactError("mechanical child publication fault")
            return original_put(*args, **kwargs)

        before_count = self.registry.verify_all(raise_on_error=True).count
        with mock.patch.object(
            self.registry,
            "_put_bytes_locked",
            side_effect=fail_second_put,
        ):
            with self.assertRaises(ArtifactError):
                self.publish()
        orphan_snapshot = self.registry.verify_all(raise_on_error=True)
        self.assertEqual(orphan_snapshot.count, before_count + 1)
        self.assertEqual(self.ledger.assert_valid().event_count, 0)
        publication = self.publish()
        self.assertEqual(
            self.registry.verify_all(raise_on_error=True).count,
            before_count + 2,
        )
        self.assertEqual(publication.event_index, 0)

    def test_capacity_refusal_is_prewrite(self):
        before = (
            self.registry.verify_all(raise_on_error=True),
            self.ledger.assert_valid(),
        )
        child_size = len(_child_bytes(self.child()))
        with mock.patch.object(
            amendment_module,
            "_MAX_CONTRACT_BYTES",
            child_size - 1,
        ):
            with self.assertRaisesRegex(
                EvaluationContractAmendmentError,
                "artifact byte capacity",
            ):
                self.publish()
        self.assertEqual(
            (
                self.registry.verify_all(raise_on_error=True),
                self.ledger.assert_valid(),
            ),
            before,
        )
        for name, value, error in (
            ("_MAX_AMENDMENT_BYTES", 1, "amendment exceeds byte capacity"),
            ("MAX_LEDGER_EVENTS", 0, "ledger event capacity"),
            ("MAX_LEDGER_BYTES", 1, "ledger byte capacity"),
        ):
            with self.subTest(limit=name), mock.patch.object(
                amendment_module,
                name,
                value,
            ):
                with self.assertRaisesRegex(EvaluationContractAmendmentError, error):
                    self.publish()
            self.assertEqual(
                (
                    self.registry.verify_all(raise_on_error=True),
                    self.ledger.assert_valid(),
                ),
                before,
            )
        with mock.patch(
            "scientist_one.evaluation_contract_amendment.MAX_REGISTRY_RECORDS",
            before[0].count + 1,
        ):
            with self.assertRaisesRegex(
                EvaluationContractAmendmentError,
                "registry capacity",
            ):
                self.publish()
        self.assertEqual(
            (
                self.registry.verify_all(raise_on_error=True),
                self.ledger.assert_valid(),
            ),
            before,
        )

    def test_sealed_source_map_is_exact_parent_closed_and_allows_later_append(self):
        before = self.registry.verify_all(raise_on_error=True)
        publication = self.publish()
        self.assertEqual(
            publication.authority.source_registry_record_identities,
            _registry_record_map(before.records),
        )
        self.registry.put_bytes(
            b'{"later":"append-only"}\n',
            logical_type="later_unrelated_source",
            origin="NON_EVIDENTIARY later append regression control",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "inert-regression-control"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at="2020-01-01T00:00:00Z",
        )
        self.assertEqual(
            require_evaluation_contract_amendment(
                self.registry,
                self.ledger,
                amendment_artifact_sha256=publication.amendment_record.sha256,
                expected_run_id=_RUN_ID,
            ),
            publication,
        )
        incomplete_map = tuple(
            identity
            for identity in publication.authority.source_registry_record_identities
            if identity[0] != self.evidence.sha256
        )
        fingerprint = sha256_bytes(
            canonical_json_bytes([list(identity) for identity in incomplete_map])
        )
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError,
            "not parent-closed",
        ):
            _require_registry_record_map(
                self.registry.verify_all(raise_on_error=True).records,
                source_record_map=incomplete_map,
                source_record_count=len(incomplete_map),
                source_record_map_fingerprint=fingerprint,
            )

    def test_later_malformed_lineage_spec_cannot_change_historical_replay(self):
        publication = self.publish()
        self.registry.put_json(
            {
                "schema_version": "SCIENTIST_ONE_FROZEN_RUN_SPEC_V1",
                "run_id": "later-malformed-spec",
            },
            logical_type="frozen_run_spec",
            origin="NON_EVIDENTIARY later malformed regression control",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "inert-regression-control"),
            parent_artifacts=(self.parent_record.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at="2020-01-01T00:00:00Z",
        )
        self.assertEqual(
            require_evaluation_contract_amendment(
                self.registry,
                self.ledger,
                amendment_artifact_sha256=publication.amendment_record.sha256,
                expected_run_id=_RUN_ID,
            ),
            publication,
        )

    def test_unlogged_related_manifest_refuses_amendment_until_result_event(self):
        with tempfile.TemporaryDirectory(prefix="unlogged-result-amendment-") as root:
            values = timeline_fixtures._prepared_timeline(root)
            record_scientific_design_freeze(
                values["registry"],
                values["ledger"],
                run_id="timeline-run",
                contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                experiment_plan_artifact_sha256s=tuple(
                    item.sha256 for item in values["plan_records"]
                ),
                frozen_run_spec_artifact_sha256=values["spec_record"].sha256,
            )
            timeline_fixtures._register_timeline_outputs(values)
            child = replace(
                values["contract"],
                version=values["contract"].version + 1,
                success_criteria=("Record only after actual visibility event.",),
            )
            before = (
                values["registry"].verify_all(raise_on_error=True),
                values["ledger"].assert_valid(),
            )
            with self.assertRaisesRegex(
                EvaluationContractAmendmentError,
                "lacks one exact visibility event",
            ):
                register_evaluation_contract_amendment(
                    values["registry"],
                    values["ledger"],
                    run_id="timeline-run",
                    amendment_id="unlogged-result-amendment",
                    parent_contract_artifact_sha256=(
                        values["contract_record"].sha256
                    ),
                    child_contract=child,
                    author_id=values["contract"].frozen_by,
                    reason="Do not omit a registered result manifest.",
                )
            self.assertEqual(
                (
                    values["registry"].verify_all(raise_on_error=True),
                    values["ledger"].assert_valid(),
                ),
                before,
            )

    def test_post_observation_hypotheses_are_additive_secondary_post_hoc_only(self):
        with tempfile.TemporaryDirectory(prefix="posthoc-contract-amendment-") as root:
            values = timeline_fixtures._prepared_timeline(root)
            self.complete_timeline_result(values)
            parent = values["contract"]
            primary = parent.hypothesis_register.primary
            invalid_new = replace(
                primary,
                hypothesis_id="hypothesis-new-secondary",
                role=HypothesisRole.SECONDARY,
                statement="A new hypothesis formed after synthetic observation.",
                planned_experiment="experiment-new-secondary",
            )
            invalid_register = replace(
                parent.hypothesis_register,
                hypotheses=(*parent.hypothesis_register.hypotheses, invalid_new),
            )
            invalid_child = replace(
                parent,
                version=parent.version + 1,
                hypothesis_register=invalid_register,
            )
            rewritten_primary = replace(
                primary,
                statement="Rewritten after observing the synthetic result.",
            )
            rewritten_child = replace(
                parent,
                version=parent.version + 1,
                hypothesis_register=replace(
                    parent.hypothesis_register,
                    hypotheses=(rewritten_primary,),
                ),
            )
            with self.assertRaisesRegex(
                EvaluationContractAmendmentError,
                "cannot rewrite, remove, reorder, or promote",
            ):
                register_evaluation_contract_amendment(
                    values["registry"],
                    values["ledger"],
                    run_id="timeline-run",
                    amendment_id="rewritten-primary-amendment",
                    parent_contract_artifact_sha256=(
                        values["contract_record"].sha256
                    ),
                    child_contract=rewritten_child,
                    author_id=parent.frozen_by,
                    reason="Negative primary-rewrite timing control.",
                )
            with self.assertRaisesRegex(
                EvaluationContractAmendmentError,
                "SECONDARY, POST_HOC, and UNTESTED",
            ):
                register_evaluation_contract_amendment(
                    values["registry"],
                    values["ledger"],
                    run_id="timeline-run",
                    amendment_id="invalid-posthoc-amendment",
                    parent_contract_artifact_sha256=(
                        values["contract_record"].sha256
                    ),
                    child_contract=invalid_child,
                    author_id=parent.frozen_by,
                    reason="Negative post-observation timing control.",
                )
            valid_new = replace(
                invalid_new,
                timing=HypothesisTiming.POST_HOC,
                formed_after_observation=True,
            )
            valid_child = replace(
                invalid_child,
                hypothesis_register=replace(
                    invalid_register,
                    hypotheses=(*parent.hypothesis_register.hypotheses, valid_new),
                ),
            )
            publication = register_evaluation_contract_amendment(
                values["registry"],
                values["ledger"],
                run_id="timeline-run",
                amendment_id="valid-posthoc-amendment",
                parent_contract_artifact_sha256=values["contract_record"].sha256,
                child_contract=valid_child,
                author_id=parent.frozen_by,
                reason="Record explicit post-observation hypothesis timing.",
            )
            self.assertTrue(publication.authority.amendment.results_already_seen)
            self.assertFalse(publication.authority.confirmation_authorized)

    def test_current_native_result_controls_cannot_hide_unclassifiable_inputs(self):
        def context(root):
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root, "runs/family/events.jsonl")
            evidence = timeline_fixtures._timeline_artifact(
                registry,
                b'{"fixture":"NON_EVIDENTIARY family evidence"}\n',
                "timeline_contract_evidence",
                Role.EVIDENCE_CURATOR,
            )
            contract = timeline_fixtures.make_contract()
            contract_record = register_frozen_evaluation_contract(
                registry,
                contract=contract,
                parent_artifact_sha256s=(evidence.sha256,),
            )
            foreign = replace(contract, contract_id="foreign-contract")
            foreign_record = register_frozen_evaluation_contract(
                registry,
                contract=foreign,
                parent_artifact_sha256s=(evidence.sha256,),
            )
            inputs = tuple(
                timeline_fixtures._timeline_artifact(
                    registry,
                    canonical_json_bytes({"input": index}) + b"\n",
                    f"native_family_input_{index}",
                    Role.EVIDENCE_CURATOR,
                )
                for index in range(4)
            )
            return registry, ledger, evidence, contract_record, foreign_record, inputs

        for extra_parent, malformed_value in (
            (False, {"run_id": "foreign-missing-inputs"}),
            (
                True,
                {
                    "run_id": "foreign-malformed-inputs",
                    "code_sha256": "not-a-sha256",
                    "data_sha256": "not-a-sha256",
                    "configuration_sha256": "not-a-sha256",
                    "evaluator_sha256": "not-a-sha256",
                },
            ),
        ):
            with self.subTest(extra_parent=extra_parent), tempfile.TemporaryDirectory(
                prefix="unclassifiable-native-manifest-"
            ) as root:
                registry, ledger, evidence, contract_record, foreign_record, inputs = (
                    context(root)
                )
                spec_record = registry.put_json(
                    malformed_value,
                    logical_type="frozen_run_spec",
                    origin="NON_EVIDENTIARY malformed native-result control",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    creation_command=("scientist-one", "inert-regression-control"),
                    parent_artifacts=(foreign_record.sha256,),
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                )
                parents = (spec_record.sha256,)
                if extra_parent:
                    parents = (*parents, evidence.sha256)
                registry.put_json(
                    {"fixture": "NON_EVIDENTIARY unclassifiable manifest"},
                    logical_type="experiment_output_manifest",
                    origin="NON_EVIDENTIARY malformed native-result control",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    creation_command=("scientist-one", "inert-regression-control"),
                    parent_artifacts=parents,
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                )
                before = (
                    registry.verify_all(raise_on_error=True),
                    ledger.assert_valid(),
                )
                with self.assertRaisesRegex(
                    EvaluationContractAmendmentError,
                    "malformed native frozen run spec|malformed provenance",
                ):
                    _require_evaluation_contract_family_before_design(
                        registry,
                        ledger,
                        expected_run_id="family-run",
                        contract_artifact_sha256=contract_record.sha256,
                        input_artifact_sha256s=tuple(item.sha256 for item in inputs),
                        design_event_index=0,
                    )
                self.assertEqual(
                    (
                        registry.verify_all(raise_on_error=True),
                        ledger.assert_valid(),
                    ),
                    before,
                )

        def prepared_nonmatching_timeline(root):
            values = timeline_fixtures._prepared_timeline(root)
            registry = values["registry"]
            foreign = replace(values["contract"], contract_id="foreign-contract")
            foreign_record = register_frozen_evaluation_contract(
                registry,
                contract=foreign,
                parent_artifact_sha256s=(values["evidence"].sha256,),
            )
            foreign_inputs = (
                timeline_fixtures._timeline_artifact(
                    registry,
                    b"print('foreign timeline')\n",
                    "experiment_code",
                    Role.IMPLEMENTER,
                ),
                timeline_fixtures._timeline_artifact(
                    registry,
                    b'{"dataset":"foreign"}\n',
                    "experiment_dataset",
                    Role.EVIDENCE_CURATOR,
                ),
                timeline_fixtures._timeline_artifact(
                    registry,
                    b'{"configuration":"foreign"}\n',
                    "experiment_configuration",
                    Role.PROTOCOL_DESIGNER,
                ),
                timeline_fixtures._timeline_artifact(
                    registry,
                    b'{"evaluator":"foreign"}\n',
                    "evaluator_implementation",
                    Role.PROTOCOL_DESIGNER,
                ),
            )
            foreign_plans = tuple(
                replace(plan, contract_sha256=foreign.sha256)
                for plan in values["plans"]
            )
            foreign_plan_records = tuple(
                register_frozen_experiment_plan(
                    registry,
                    contract=foreign,
                    contract_artifact_sha256=foreign_record.sha256,
                    plan=plan,
                )
                for plan in foreign_plans
            )
            foreign_spec = replace(
                values["spec"],
                run_id="foreign-timeline-execution",
                code_sha256=foreign_inputs[0].sha256,
                data_sha256=foreign_inputs[1].sha256,
                configuration_sha256=foreign_inputs[2].sha256,
                evaluator_sha256=foreign_inputs[3].sha256,
            )
            foreign_spec_record = register_frozen_run_spec(
                registry,
                contract=foreign,
                contract_artifact_sha256=foreign_record.sha256,
                experiment_plan_artifact_sha256s=tuple(
                    record.sha256 for record in foreign_plan_records
                ),
                spec=foreign_spec,
            )
            foreign_values = {
                "registry": registry,
                "ledger": values["ledger"],
                "contract": foreign,
                "contract_record": foreign_record,
                "plans": foreign_plans,
                "plan_records": foreign_plan_records,
                "spec": foreign_spec,
                "spec_record": foreign_spec_record,
            }
            return values, foreign_values

        with tempfile.TemporaryDirectory(
            prefix="contradictory-nonmatching-native-manifest-"
        ) as root:
            values, foreign_values = prepared_nonmatching_timeline(root)
            timeline_fixtures._register_timeline_outputs(foreign_values)
            contradictory = foreign_values["manifest"].to_dict()
            contradictory["data_sha256"] = values["data"].sha256
            values["registry"].put_json(
                contradictory,
                logical_type="experiment_output_manifest",
                origin="NON_EVIDENTIARY contradictory native-result control",
                creator_role=Role.EXPERIMENT_RUNNER,
                creation_command=("scientist-one", "inert-regression-control"),
                parent_artifacts=(foreign_values["spec_record"].sha256,),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            before = (
                values["registry"].verify_all(raise_on_error=True),
                values["ledger"].assert_valid(),
            )
            with self.assertRaisesRegex(
                EvaluationContractAmendmentError,
                "manifest or output custody is malformed",
            ):
                _require_evaluation_contract_family_before_design(
                    values["registry"],
                    values["ledger"],
                    expected_run_id="timeline-run",
                    contract_artifact_sha256=values["contract_record"].sha256,
                    input_artifact_sha256s=(
                        values["code"].sha256,
                        values["data"].sha256,
                        values["configuration"].sha256,
                        values["evaluator"].sha256,
                    ),
                    design_event_index=0,
                )
            self.assertEqual(
                (
                    values["registry"].verify_all(raise_on_error=True),
                    values["ledger"].assert_valid(),
                ),
                before,
            )

        with tempfile.TemporaryDirectory(
            prefix="malformed-nonmatching-native-result-event-"
        ) as root:
            values, foreign_values = prepared_nonmatching_timeline(root)
            design = self.freeze_timeline_design(foreign_values)
            timeline_fixtures._register_timeline_outputs(foreign_values)
            manifest_record = foreign_values["manifest_record"]
            foreign_values["ledger"].record(
                run_id="timeline-run",
                actor_role=Role.EXPERIMENT_RUNNER,
                state_before=design.state_after,
                requested_state_after=design.state_after,
                artifact_hashes=(manifest_record.sha256,),
                code_version="NON_EVIDENTIARY",
                configuration_hash=foreign_values["spec"].configuration_sha256,
                reason="Mechanical malformed nonmatching result-event control.",
                event_type="CHECKPOINT",
                metadata={
                    "scientific_timeline": {
                        "kind": "RESULT_OBSERVED",
                        "contract_artifact_sha256": foreign_values[
                            "contract_record"
                        ].sha256,
                        "frozen_run_spec_artifact_sha256": foreign_values[
                            "spec_record"
                        ].sha256,
                        "output_manifest_artifact_sha256": manifest_record.sha256,
                        "design_freeze_event_id": design.event_id,
                    }
                },
            )
            before = (
                values["registry"].verify_all(raise_on_error=True),
                values["ledger"].assert_valid(),
            )
            with self.assertRaisesRegex(
                EvaluationContractAmendmentError,
                "malformed native source bindings",
            ):
                _require_evaluation_contract_family_before_design(
                    values["registry"],
                    values["ledger"],
                    expected_run_id="timeline-run",
                    contract_artifact_sha256=values["contract_record"].sha256,
                    input_artifact_sha256s=(
                        values["code"].sha256,
                        values["data"].sha256,
                        values["configuration"].sha256,
                        values["evaluator"].sha256,
                    ),
                    design_event_index=values["ledger"].assert_valid().event_count,
                )
            self.assertEqual(
                (
                    values["registry"].verify_all(raise_on_error=True),
                    values["ledger"].assert_valid(),
                ),
                before,
            )

        with tempfile.TemporaryDirectory(
            prefix="fully-replayed-nonmatching-native-result-"
        ) as root:
            values, foreign_values = prepared_nonmatching_timeline(root)
            self.complete_timeline_result(foreign_values)
            family = _require_evaluation_contract_family_before_design(
                values["registry"],
                values["ledger"],
                expected_run_id="timeline-run",
                contract_artifact_sha256=values["contract_record"].sha256,
                input_artifact_sha256s=(
                    values["code"].sha256,
                    values["data"].sha256,
                    values["configuration"].sha256,
                    values["evaluator"].sha256,
                ),
                design_event_index=values["ledger"].assert_valid().event_count,
            )
            self.assertEqual(family.contract_record, values["contract_record"])
            self.assertFalse(family.visible_ancestor_manifest_artifact_sha256s)

    def test_same_input_visible_contract_outside_lineage_refuses_family_admission(self):
        with tempfile.TemporaryDirectory(prefix="outside-lineage-visibility-") as root:
            values = timeline_fixtures._prepared_timeline(root)
            registry = values["registry"]
            ledger = values["ledger"]
            parent = values["contract"]
            other = replace(parent, contract_id="other-contract")
            other_record = register_frozen_evaluation_contract(
                registry,
                contract=other,
                parent_artifact_sha256s=(values["evidence"].sha256,),
            )
            other_plans = tuple(
                replace(plan, contract_sha256=other.sha256)
                for plan in values["plans"]
            )
            other_plan_records = tuple(
                register_frozen_experiment_plan(
                    registry,
                    contract=other,
                    contract_artifact_sha256=other_record.sha256,
                    plan=plan,
                )
                for plan in other_plans
            )
            other_spec = replace(values["spec"], run_id="other-execution")
            other_spec_record = register_frozen_run_spec(
                registry,
                contract=other,
                contract_artifact_sha256=other_record.sha256,
                experiment_plan_artifact_sha256s=tuple(
                    item.sha256 for item in other_plan_records
                ),
                spec=other_spec,
            )
            other_values = {
                "registry": registry,
                "ledger": ledger,
                "contract": other,
                "contract_record": other_record,
                "plans": other_plans,
                "plan_records": other_plan_records,
                "spec": other_spec,
                "spec_record": other_spec_record,
            }
            # Freeze both genuine prospective histories before either synthetic
            # result is visible.  The amendment guard must not be bypassed by
            # creating the second contract only after the first observation.
            self.freeze_timeline_design(values)
            self.freeze_timeline_design(other_values)
            self.observe_timeline_result(values)
            self.observe_timeline_result(other_values)
            child = replace(
                parent,
                version=parent.version + 1,
                success_criteria=("Changed after both visible same-input results.",),
            )
            publication = register_evaluation_contract_amendment(
                registry,
                ledger,
                run_id="timeline-run",
                amendment_id="outside-lineage-amendment",
                parent_contract_artifact_sha256=values["contract_record"].sha256,
                child_contract=child,
                author_id=parent.frozen_by,
                reason="Record all same-input visibility without granting reuse.",
            )
            self.assertEqual(len(publication.authority.visible_results), 2)
            inputs = (
                values["code"].sha256,
                values["data"].sha256,
                values["configuration"].sha256,
                values["evaluator"].sha256,
            )
            with self.assertRaisesRegex(
                EvaluationContractAmendmentError,
                "outside this lineage",
            ):
                _require_evaluation_contract_family_before_design(
                    registry,
                    ledger,
                    expected_run_id="timeline-run",
                    contract_artifact_sha256=publication.contract_record.sha256,
                    input_artifact_sha256s=inputs,
                    design_event_index=ledger.assert_valid().event_count,
                )


if __name__ == "__main__":
    unittest.main()
