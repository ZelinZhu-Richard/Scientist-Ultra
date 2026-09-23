"""Actual amendment/freeze integration with NON_EVIDENTIARY observations.

These tests exercise the ordinary source owners, not prevalidated helper DTOs.
The imported timeline outputs are synthetic; no workload, confirmation,
scientific Result, protected reserve or E4 authority is produced. The sole
fault hook aborts a real ledger append after the public publisher's actual
record writes. It never mocks successful scientific source validation.
"""

from __future__ import annotations

from dataclasses import replace
import tempfile
import unittest
from unittest.mock import patch

import scientist_one.evaluation_contract_amendment as amendment
from scientist_one.errors import LedgerError
from scientist_one.roles import Role
import scientist_one.scientific_design as design
from tests import test_scientific_design as fixtures


class EvaluationContractLineageIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="contract-lineage-integration-")
        self.addCleanup(temporary.cleanup)
        self.values = fixtures._prepared_timeline(temporary.name)
        self.registry = self.values["registry"]
        self.ledger = self.values["ledger"]

    def snapshot(self):
        return (
            self.registry.verify_all(raise_on_error=True),
            self.ledger.validate(raise_on_error=True),
        )

    @staticmethod
    def arguments(values):
        return {
            "run_id": "timeline-run",
            "contract": values["contract"],
            "contract_artifact_sha256": values["contract_record"].sha256,
            "experiment_plan_artifact_sha256s": tuple(
                record.sha256 for record in values["plan_records"]
            ),
            "frozen_run_spec_artifact_sha256": values["spec_record"].sha256,
        }

    def freeze(self, values):
        event = design.record_scientific_design_freeze(
            self.registry, self.ledger, **self.arguments(values),
        )
        record = design.register_evaluation_contract_freeze_gate_receipt(
            self.registry, self.ledger,
            receipt_id=f"freeze-{values['spec'].run_id}", **self.arguments(values),
        )
        receipt = self.read_freeze(values, record)
        self.assertEqual(receipt.design_freeze_event_hash, event.event_hash)
        return event, record, receipt

    def read_freeze(self, values, record):
        receipt = design.require_evaluation_contract_freeze_gate_receipt(
            self.registry, self.ledger,
            receipt_artifact_sha256=record.sha256,
            expected_run_id="timeline-run",
            expected_contract_id=values["contract"].contract_id,
        )
        self.assertIs(type(receipt), design.EvaluationContractFreezeGateReceipt)
        self.assertEqual(receipt.freeze_scope, "DESIGN_FREEZE_VALIDITY_ONLY")
        self.assertFalse(receipt.result_validity_authorized)
        return receipt

    def observe(self, values):
        # Explicitly synthetic NON_EVIDENTIARY fixture bytes; no run is executed.
        fixtures._register_timeline_outputs(values)
        event = design.record_scientific_result_observed(
            self.registry, self.ledger, **self.arguments(values),
            output_manifest_artifact_sha256=values["manifest_record"].sha256,
        )
        self.assertEqual(event.metadata["scientific_timeline"]["kind"], "RESULT_OBSERVED")
        return event

    @staticmethod
    def child_contract(parent, label):
        return replace(
            parent, version=parent.version + 1,
            success_criteria=(f"NON_EVIDENTIARY changed criterion for {label}.",),
        )

    def publish(self, values, *, amendment_id, child=None):
        child = self.child_contract(values["contract"], amendment_id) if child is None else child
        publication = amendment.register_evaluation_contract_amendment(
            self.registry, self.ledger,
            run_id="timeline-run", amendment_id=amendment_id,
            parent_contract_artifact_sha256=values["contract_record"].sha256,
            child_contract=child, author_id=child.frozen_by,
            reason="Record a scoped contract change; confer no scientific authority.",
            child_evidence_parent_artifact_sha256s=(self.values["evidence"].sha256,),
        )
        self.assertIs(type(publication), amendment.EvaluationContractAmendmentPublication)
        self.assertFalse(publication.authority.confirmation_authorized)
        self.assertEqual(publication.authority.amendment.changed_fields, ("success_criteria",))
        self.assertEqual(publication.child_contract, child)
        self.assertEqual(child.version, values["contract"].version + 1)
        self.assertEqual(child.contract_id, values["contract"].contract_id)
        return publication

    def descendant_inputs(self, parent, publication, *, execution_id):
        return self.bound_plan_spec(
            parent, contract=publication.child_contract,
            contract_record=publication.contract_record, execution_id=execution_id,
        )

    def bound_plan_spec(self, parent, *, contract, contract_record, execution_id):
        values = dict(parent)
        values["contract"] = contract
        values["contract_record"] = contract_record
        values["plans"] = tuple(
            replace(plan, contract_sha256=contract.sha256)
            for plan in parent["plans"]
        )
        values["plan_records"] = tuple(
            design.register_frozen_experiment_plan(
                self.registry,
                contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                plan=plan,
            )
            for plan in values["plans"]
        )
        values["spec"] = replace(parent["spec"], run_id=execution_id)
        self.assertNotEqual(execution_id, parent["spec"].run_id)
        self.assertEqual(
            replace(values["spec"], run_id=parent["spec"].run_id), parent["spec"],
        )
        self.assertEqual(values["contract"].separation, parent["contract"].separation)
        values["spec_record"] = design.register_frozen_run_spec(
            self.registry, contract=values["contract"],
            contract_artifact_sha256=values["contract_record"].sha256,
            experiment_plan_artifact_sha256s=tuple(
                record.sha256 for record in values["plan_records"]
            ),
            spec=values["spec"],
        )
        return values

    def read_amendment(self, publication):
        return amendment.require_evaluation_contract_amendment(
            self.registry, self.ledger,
            amendment_artifact_sha256=publication.amendment_record.sha256,
            expected_run_id="timeline-run",
            expected_child_contract_artifact_sha256=publication.contract_record.sha256,
        )

    def test_two_generations_replay_both_amendments_and_historical_design_receipts(self):
        parent_design = self.freeze(self.values)
        parent_result = self.observe(self.values)
        first = self.publish(self.values, amendment_id="integration-amendment-1")
        child = self.descendant_inputs(
            self.values, first, execution_id="timeline-child-execution",
        )
        child_design = self.freeze(child)
        child_result = self.observe(child)
        second = self.publish(child, amendment_id="integration-amendment-2")
        grandchild = self.descendant_inputs(
            child, second, execution_id="timeline-grandchild-execution",
        )
        grandchild_design = self.freeze(grandchild)

        self.assertEqual(self.ledger.validate().events, (
            parent_design[0], parent_result, first.event,
            child_design[0], child_result, second.event, grandchild_design[0],
        ))
        self.assertEqual(first.authority.lineage_depth, 1)
        self.assertEqual(second.authority.lineage_depth, 2)
        self.assertEqual(second.lineage_contract_records, (
            self.values["contract_record"], first.contract_record, second.contract_record,
        ))
        self.assertEqual(second.lineage_amendment_records, (
            first.amendment_record, second.amendment_record,
        ))
        self.assertEqual(
            {item.output_manifest_artifact_sha256 for item in first.authority.visible_results},
            {self.values["manifest_record"].sha256},
        )
        self.assertEqual(
            {item.output_manifest_artifact_sha256 for item in second.authority.visible_results},
            {self.values["manifest_record"].sha256, child["manifest_record"].sha256},
        )
        for publication in (first, second):
            self.assertTrue(publication.authority.amendment.results_already_seen)
            self.assertTrue(publication.authority.amendment.requires_new_confirmatory_reserve)
            self.assertFalse(publication.authority.confirmation_authorized)

        # These complete public replays exercise the actual backward source
        # closure after descendants exist; this is not a general acyclicity proof.
        before = self.snapshot()
        self.assertEqual(self.read_amendment(first), first)
        self.assertEqual(self.read_amendment(second), second)
        for values, (_, record, receipt) in (
            (self.values, parent_design), (child, child_design),
            (grandchild, grandchild_design),
        ):
            self.assertEqual(self.read_freeze(values, record), receipt)
            self.assertEqual(design.require_frozen_evaluation_contract(
                self.registry, contract_artifact_sha256=values["contract_record"].sha256,
            ), values["contract"])
        self.assertEqual(self.snapshot(), before)

    def test_late_renamed_design_cannot_use_direct_scientific_timeline_consumer(self):
        self.freeze(self.values)
        self.observe(self.values)
        renamed = replace(
            self.values["contract"], contract_id="adversarial-late-renamed-contract",
            success_criteria=("NON_EVIDENTIARY invalid late renamed design control.",),
        )
        record = design.register_frozen_evaluation_contract(
            self.registry, contract=renamed,
            parent_artifact_sha256s=(self.values["evidence"].sha256,),
        )
        late = self.bound_plan_spec(
            self.values, contract=renamed, contract_record=record,
            execution_id="adversarial-late-renamed-execution",
        )
        (contract_record, projection, plans, plan_records, spec_record, spec,
         _manifest_record, _manifest, _outputs) = design._require_scientific_timeline_inputs(
            self.registry, contract=renamed,
            contract_artifact_sha256=record.sha256,
            experiment_plan_artifact_sha256s=tuple(r.sha256 for r in late["plan_records"]),
            frozen_run_spec_artifact_sha256=late["spec_record"].sha256,
            output_manifest_artifact_sha256=None,
        )
        before_event = self.snapshot()
        artifacts = (contract_record, *plan_records, spec_record)
        binding = design._timeline_binding(
            kind="DESIGN_FROZEN", contract_record=contract_record,
            projection=projection, plan_records=plan_records,
            spec_record=spec_record, spec=spec,
            manifest_record=None, design_event=None,
        )
        # Deliberately invalid design authority: bypass the guarded publisher
        # only in this adverse fixture. All native actor/hash/binding/map fields
        # are otherwise exact, so the real downstream family predicate is hit.
        state = before_event[1].events[-1].requested_state_after
        adversarial_design = self.ledger.record(
            run_id="timeline-run", actor_role=Role.PROTOCOL_DESIGNER,
            state_before=state, requested_state_after=state,
            artifact_hashes=tuple(r.sha256 for r in artifacts),
            code_version=f"sha256:{spec.code_sha256}",
            configuration_hash=spec.configuration_sha256,
            dataset_identifiers=(projection.dataset_id, plans[0].dataset_split_id),
            random_seeds=spec.seeds, evaluator_outputs=(),
            reason="froze exact contract, per-seed plans, and run spec before submission",
            event_type="CHECKPOINT",
            metadata={
                "artifact_types": [r.logical_type for r in artifacts],
                "artifact_record_hashes": [str(r.record_hash) for r in artifacts],
                "scientific_timeline": binding,
                "evaluation_contract_design_population": (
                    design._design_registry_population_value(before_event)
                ),
            },
        )
        self.assertEqual(adversarial_design.prior_event_hash, before_event[1].head_hash)
        # Recording factual NON_EVIDENTIARY visibility is outcome-neutral; it
        # must not be mistaken for scientific design or timeline authority.
        observed = self.observe(late)
        self.assertEqual(
            observed.metadata["scientific_timeline"]["design_freeze_event_hash"],
            adversarial_design.event_hash,
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            amendment.EvaluationContractAmendmentError,
            "visible same-input result belongs to a contract outside this lineage",
        ):
            design.register_scientific_timeline_receipt(
                self.registry, self.ledger,
                receipt_id="refused-late-renamed-scientific-timeline",
                **self.arguments(late),
                output_manifest_artifact_sha256=late["manifest_record"].sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_parent_visibility_after_amendment_refuses_child_design_without_delta(self):
        parent_design = self.freeze(self.values)
        publication = self.publish(self.values, amendment_id="before-parent-visibility")
        self.assertFalse(publication.authority.amendment.results_already_seen)
        self.assertEqual(publication.authority.visible_results, ())
        observed = self.observe(self.values)
        child = self.descendant_inputs(
            self.values, publication, execution_id="late-exposure-child-execution",
        )
        before = self.snapshot()
        self.assertEqual(before[1].events, (parent_design[0], publication.event, observed))
        with self.assertRaisesRegex(
            amendment.EvaluationContractAmendmentError,
            "new result exposure occurred after the selected amendment",
        ):
            design.record_scientific_design_freeze(
                self.registry, self.ledger, **self.arguments(child),
            )
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.read_amendment(publication), publication)
        self.assertEqual(self.read_freeze(self.values, parent_design[1]), parent_design[2])
        self.assertEqual(self.snapshot(), before)

    def test_distinct_genesis_id_cannot_use_contract_or_amendment_evidence_parent(self):
        publication = self.publish(self.values, amendment_id="reserved-parent-control")
        for kind, reserved in (
            ("contract", self.values["contract_record"]),
            ("amendment", publication.amendment_record),
        ):
            for first in (True, False):
                with self.subTest(kind=kind, reserved_first=first):
                    candidate = replace(
                        self.values["contract"],
                        contract_id=f"distinct-genesis-{kind}-{int(first)}",
                    )
                    self.assertNotEqual(candidate.contract_id, self.values["contract"].contract_id)
                    parents = (reserved.sha256, self.values["evidence"].sha256)
                    if not first:
                        parents = tuple(reversed(parents))
                    before = self.snapshot()
                    with self.assertRaisesRegex(
                        design.ScientificPromotionError,
                        "genesis evidence cannot hide a contract or amendment lineage parent",
                    ):
                        design.register_frozen_evaluation_contract(
                            self.registry, contract=candidate,
                            parent_artifact_sha256s=parents,
                        )
                    self.assertEqual(self.snapshot(), before)

    def test_real_amendment_child_orphan_is_refused_by_all_three_contract_owners(self):
        child = self.child_contract(self.values["contract"], "orphan")
        before = self.snapshot()
        with patch.object(
            self.ledger, "_append_locked",
            side_effect=LedgerError("mechanical amendment event append fault"),
        ) as append_fault:
            with self.assertRaisesRegex(LedgerError, "mechanical amendment event append fault"):
                self.publish(self.values, amendment_id="integration-orphan", child=child)
        self.assertEqual(append_fault.call_count, 1)
        after_fault = self.snapshot()
        old_records = {record.sha256: record for record in before[0].records}
        retained = tuple(record for record in after_fault[0].records if record.sha256 not in old_records)
        self.assertEqual(len(retained), 2)
        self.assertEqual(after_fault[0].count, before[0].count + 2)
        self.assertEqual(after_fault[0].orphan_paths, before[0].orphan_paths)
        self.assertEqual(after_fault[1], before[1])
        self.assertEqual(
            {record.sha256: record for record in after_fault[0].records
             if record.sha256 in old_records}, old_records,
        )
        by_type = {record.logical_type: record for record in retained}
        self.assertEqual(set(by_type), {
            amendment.EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE, "evaluation_contract",
        })
        child_record = by_type["evaluation_contract"]
        self.assertEqual(child_record.parent_artifacts, (
            by_type[amendment.EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE].sha256,
            self.values["evidence"].sha256,
        ))
        owners = (
            ("public frozen", lambda: design.require_frozen_evaluation_contract(
                self.registry, contract_artifact_sha256=child_record.sha256,
            )),
            ("temporal", lambda: design._require_temporal_contract(
                self.registry, child_record.sha256, contract=child,
            )),
            ("checked contract", lambda: design._require_checked_contract_artifact(
                self.registry, child, child_record.sha256,
            )),
        )
        for name, owner in owners:
            with self.subTest(owner=name), self.assertRaisesRegex(
                amendment.EvaluationContractAmendmentError,
                "amendment requires one exact publication event",
            ):
                owner()
            self.assertEqual(self.snapshot(), after_fault)
        parent = self.values["contract"]
        parent_record = self.values["contract_record"]
        self.assertEqual(design.require_frozen_evaluation_contract(
            self.registry, contract_artifact_sha256=parent_record.sha256,
        ), parent)
        self.assertEqual(design._require_temporal_contract(
            self.registry, parent_record.sha256, contract=parent,
        )[0], parent_record)
        self.assertEqual(design._require_checked_contract_artifact(
            self.registry, parent, parent_record.sha256,
        ), parent_record)
        self.assertEqual(self.snapshot(), after_fault)


if __name__ == "__main__":
    unittest.main()
