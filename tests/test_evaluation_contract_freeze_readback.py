"""Real freeze readback interleavings with NON_EVIDENTIARY fixture outputs.

Hooks first execute the actual source owner, then append one real correction or
one complete synthetic output set. They never replace successful scientific
validation or supply a completed authority DTO. No workload, confirmation,
protected reserve, scientific Result or E4 authority is produced.
"""

from __future__ import annotations

from dataclasses import replace
import tempfile
import unittest
from unittest.mock import patch

import scientist_one.evaluation_contract_amendment as amendment
from scientist_one.roles import Role
import scientist_one.scientific_design as design
from tests import test_scientific_design as fixtures


class EvaluationContractFreezeReadbackTests(unittest.TestCase):
    def snapshot(self, values):
        return (
            values["registry"].verify_all(raise_on_error=True),
            values["ledger"].validate(raise_on_error=True),
        )

    @staticmethod
    def arguments(values):
        return {
            "run_id": "timeline-run", "contract": values["contract"],
            "contract_artifact_sha256": values["contract_record"].sha256,
            "experiment_plan_artifact_sha256s": tuple(
                record.sha256 for record in values["plan_records"]
            ),
            "frozen_run_spec_artifact_sha256": values["spec_record"].sha256,
        }

    def prepare(self, *, companion=None, observed=False):
        temporary = tempfile.TemporaryDirectory(prefix="freeze-readback-")
        self.addCleanup(temporary.cleanup)
        values = fixtures._prepared_timeline(temporary.name)
        other = None
        if companion is not None:
            other = dict(values)
            other["spec"] = replace(
                values["spec"],
                run_id=(values["spec"].run_id if companion == "alias"
                        else "clearly-other-execution"),
                metadata={
                    **dict(values["spec"].metadata),
                    "non_evidentiary_variant": companion,
                },
            )
            other["spec_record"] = design.register_frozen_run_spec(
                values["registry"],
                contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                experiment_plan_artifact_sha256s=tuple(
                    record.sha256 for record in values["plan_records"]
                ),
                spec=other["spec"],
            )
            self.assertNotEqual(other["spec_record"].sha256, values["spec_record"].sha256)
        values["design_event"] = design.record_scientific_design_freeze(
            values["registry"], values["ledger"], **self.arguments(values),
        )
        values["receipt_record"] = design.register_evaluation_contract_freeze_gate_receipt(
            values["registry"], values["ledger"],
            receipt_id="freeze-readback-receipt", **self.arguments(values),
        )
        values["receipt"] = self.read(values)
        if other is not None:
            other["design_event"] = design.record_scientific_design_freeze(
                values["registry"], values["ledger"], **self.arguments(other),
            )
            self.assertEqual(
                tuple(event.metadata["scientific_timeline"]["kind"]
                      for event in values["ledger"].validate().events),
                ("DESIGN_FROZEN", "DESIGN_FROZEN"),
            )
        if observed:
            self.observe(values)
            values["visibility"] = self.visibility(values)
        return values, other

    def read(self, values, *, route="public"):
        if route == "scientific-use":
            return design._require_scientific_visibility_design_admission(
                values["registry"], values["ledger"], run_id="timeline-run",
                visibility=values["visibility"],
            )
        receipt = design.require_evaluation_contract_freeze_gate_receipt(
            values["registry"], values["ledger"],
            receipt_artifact_sha256=values["receipt_record"].sha256,
            expected_run_id="timeline-run",
            expected_contract_id=values["contract"].contract_id,
        )
        self.assertIs(type(receipt), design.EvaluationContractFreezeGateReceipt)
        self.assertEqual(receipt.freeze_scope, "DESIGN_FREEZE_VALIDITY_ONLY")
        self.assertFalse(receipt.result_validity_authorized)
        return receipt

    def observe(self, values):
        # The fixture produces complete synthetic bytes, not an executed run.
        fixtures._register_timeline_outputs(values)
        values["observed_event"] = design.record_scientific_result_observed(
            values["registry"], values["ledger"], **self.arguments(values),
            output_manifest_artifact_sha256=values["manifest_record"].sha256,
        )
        return values["observed_event"]

    @staticmethod
    def visibility(values):
        return design._resolve_registered_scientific_visibility(
            values["registry"], values["ledger"].validate(raise_on_error=True).events,
            contract_record=values["contract_record"],
            manifest_record=values["manifest_record"],
        )

    @staticmethod
    def correct(values, event):
        return values["ledger"].append_correction(
            event.event_id, actor_role=Role.SCIENTIFIC_REVIEWER,
            reason="Withdraw this NON_EVIDENTIARY source during readback.",
            corrected_fields={"authority": "WITHDRAWN"},
        )

    def assert_only_delta(self, values, before, *, records=(), event=None):
        after = self.snapshot(values)
        expected = {record.sha256: record for record in before[0].records}
        for record in records:
            self.assertNotIn(record.sha256, expected)
            expected[record.sha256] = record
        self.assertEqual({record.sha256: record for record in after[0].records}, expected)
        self.assertEqual(after[0].count, before[0].count + len(records))
        self.assertEqual(after[0].orphan_paths, before[0].orphan_paths)
        if event is None:
            self.assertEqual(after[1], before[1])
        else:
            self.assertEqual(after[1].events, (*before[1].events, event))
            self.assertEqual(event.prior_event_hash, before[1].head_hash)
            self.assertEqual(after[1].head_hash, event.event_hash)
        return after

    def test_correction_after_actual_family_replay_refuses_both_readers(self):
        for route in ("public", "scientific-use"):
            with self.subTest(route=route):
                values, _ = self.prepare(observed=True)
                self.read(values, route=route)
                before = self.snapshot(values)
                actual = amendment._require_evaluation_contract_family_before_design
                forwarded = []
                injected = []

                def replay_then_correct(*args, **kwargs):
                    result = actual(*args, **kwargs)
                    if not forwarded:
                        forwarded.append(result)
                        injected.append(self.correct(values, values["design_event"]))
                    return result

                with patch.object(
                    amendment, "_require_evaluation_contract_family_before_design",
                    new=replay_then_correct,
                ):
                    with self.assertRaisesRegex(
                        design.ScientificPromotionError, "changed|snapshot|superseded",
                    ):
                        self.read(values, route=route)
                self.assertEqual(len(forwarded), 1)
                self.assertEqual(forwarded[0].contract_record, values["contract_record"])
                self.assertEqual(
                    (forwarded[0].registry_snapshot, forwarded[0].ledger_snapshot), before,
                )
                self.assertEqual(len(injected), 1)
                after = self.assert_only_delta(values, before, event=injected[0])
                with self.assertRaisesRegex(design.ScientificPromotionError, "superseded"):
                    self.read(values, route=route)
                self.assertEqual(self.snapshot(values), after)

    def test_output_append_after_actual_selected_inventory_refuses_both_readers(self):
        for route in ("public", "scientific-use"):
            with self.subTest(route=route):
                values, alias = self.prepare(companion="alias", observed=True)
                self.read(values, route=route)
                before = self.snapshot(values)
                actual = design._matching_selected_execution_result_manifests
                forwarded = []

                def inventory_then_append(*args, **kwargs):
                    result = actual(*args, **kwargs)
                    if not forwarded:
                        forwarded.append(result)
                        fixtures._register_timeline_outputs(alias)
                    return result

                with patch.object(
                    design, "_matching_selected_execution_result_manifests",
                    new=inventory_then_append,
                ):
                    with self.assertRaisesRegex(
                        design.ScientificPromotionError, "changed|snapshot",
                    ):
                        self.read(values, route=route)
                self.assertEqual(forwarded, [(values["manifest_record"],)])
                injected = (alias["manifest_record"], *alias["output_records"])
                self.assertEqual(len(injected), 5)
                after = self.assert_only_delta(values, before, records=injected)
                with self.assertRaisesRegex(
                    design.ScientificPromotionError,
                    "matching result manifest requires exactly one",
                ):
                    self.read(values, route=route)
                self.assertEqual(self.snapshot(values), after)

    def test_same_execution_alias_is_unlogged_logged_and_corrected_not_excluded(self):
        values, alias = self.prepare(companion="alias", observed=True)
        self.assertEqual(
            (alias["spec"].run_id, alias["spec"].experiment_id, alias["spec"].hypothesis_id),
            (values["spec"].run_id, values["spec"].experiment_id,
             values["spec"].hypothesis_id),
        )
        fixtures._register_timeline_outputs(alias)
        before = self.snapshot(values)
        for route in ("public", "scientific-use"):
            with self.assertRaisesRegex(
                design.ScientificPromotionError,
                "matching result manifest requires exactly one",
            ):
                self.read(values, route=route)
        self.assertEqual(self.snapshot(values), before)
        # Actual publication of visibility, not a replacement owner result.
        observed = design.record_scientific_result_observed(
            values["registry"], values["ledger"], **self.arguments(alias),
            output_manifest_artifact_sha256=alias["manifest_record"].sha256,
        )
        before = self.snapshot(values)
        self.assertEqual(self.read(values), values["receipt"])
        self.assertIsNone(self.read(values, route="scientific-use"))
        self.assertEqual(self.snapshot(values), before)
        self.correct(values, observed)
        before = self.snapshot(values)
        for route in ("public", "scientific-use"):
            with self.assertRaisesRegex(design.ScientificPromotionError, "superseded"):
                self.read(values, route=route)
        self.assertEqual(self.snapshot(values), before)

    def test_complete_different_execution_outputs_do_not_revoke_selected_design(self):
        values, other = self.prepare(companion="different", observed=True)
        self.assertNotEqual(other["spec"].run_id, values["spec"].run_id)
        fixtures._register_timeline_outputs(other)
        self.assertEqual(len(other["output_records"]), len(other["manifest"].artifacts))
        self.assertNotIn(
            other["manifest_record"].sha256,
            {digest for event in values["ledger"].validate().events
             for digest in event.artifact_hashes},
        )
        before = self.snapshot(values)
        self.assertEqual(self.read(values), values["receipt"])
        self.assertIsNone(self.read(values, route="scientific-use"))
        self.assertEqual(self.snapshot(values), before)

    def test_malformed_or_contradictory_native_progress_cannot_hide_as_other_execution(self):
        for variant in ("malformed-spec", "contradictory-manifest"):
            with self.subTest(variant=variant):
                values, other = self.prepare(companion="different", observed=True)
                fixtures._register_timeline_outputs(other)
                self.assertEqual(self.read(values), values["receipt"])
                parent = other["spec_record"]
                wire = other["manifest"].to_dict()
                if variant == "malformed-spec":
                    malformed = other["spec"].to_dict()
                    del malformed["phase"]
                    parent = values["registry"].put_json(
                        malformed, logical_type="frozen_run_spec",
                        origin="NON_EVIDENTIARY malformed native progress control",
                        creator_role=Role.EXPERIMENT_RUNNER,
                        creation_command=("test", "freeze-readback-adverse-spec"),
                        parent_artifacts=other["spec_record"].parent_artifacts,
                        schema_version="1.0", mime_type="application/json",
                        validation_result="PASS", frozen=True,
                    )
                    wire["spec_sha256"] = parent.sha256
                else:
                    # Actual parent says another run; the native body claims
                    # this selected run. A one-field exclusion cannot own it.
                    wire["run_id"] = values["spec"].run_id
                values["registry"].put_json(
                    wire, logical_type="experiment_output_manifest",
                    origin="NON_EVIDENTIARY contradictory native progress control",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    creation_command=("test", "freeze-readback-adverse-manifest"),
                    parent_artifacts=(parent.sha256,),
                    schema_version="1.0", mime_type="application/json",
                    validation_result="PASS", frozen=True,
                )
                before = self.snapshot(values)
                for route in ("public", "scientific-use"):
                    with self.subTest(route=route), self.assertRaises(
                        design.ScientificDesignError,
                    ):
                        self.read(values, route=route)
                self.assertEqual(self.snapshot(values), before)


if __name__ == "__main__":
    unittest.main()
