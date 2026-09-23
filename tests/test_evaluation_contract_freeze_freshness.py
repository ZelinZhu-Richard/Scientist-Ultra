"""Real legacy freeze interleavings; synthetic NON_EVIDENTIARY inputs only.

Each hook forwards the complete actual source reader and returns its unchanged
result, after one real registry/ledger mutation. No scientific owner is mocked
to PASS, no authority DTO is supplied, and no workload or protected resource is
executed. Successful controls establish DESIGN_FREEZE_VALIDITY_ONLY, never
scientific result validity. Ordinary public registry and ledger APIs own all
mutations, without clocks, private issuers, keys or trust-map modifications.
"""

from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from scientist_one.models import MacroState
from scientist_one.roles import Role
import scientist_one.scientific_design as design
from tests import test_scientific_design as fixtures


class EvaluationContractFreezeFreshnessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="freeze-freshness-")
        self.addCleanup(temporary.cleanup)
        self.values = fixtures._prepared_timeline(temporary.name)
        self.registry = self.values["registry"]
        self.ledger = self.values["ledger"]
        self.assertEqual(tuple(self.values["spec"].metadata), ("evaluation_split",))

    def snapshot(self):
        return (
            self.registry.verify_all(raise_on_error=True),
            self.ledger.validate(raise_on_error=True),
        )

    def arguments(self):
        return {
            "run_id": "timeline-run",
            "contract": self.values["contract"],
            "contract_artifact_sha256": self.values["contract_record"].sha256,
            "experiment_plan_artifact_sha256s": tuple(
                record.sha256 for record in self.values["plan_records"]
            ),
            "frozen_run_spec_artifact_sha256": self.values["spec_record"].sha256,
        }

    def freeze(self):
        return design.record_scientific_design_freeze(
            self.registry, self.ledger, **self.arguments(),
        )

    def register_receipt(self):
        return design.register_evaluation_contract_freeze_gate_receipt(
            self.registry, self.ledger,
            receipt_id="freeze-freshness-receipt", **self.arguments(),
        )

    def require_receipt(self, record):
        receipt = design.require_evaluation_contract_freeze_gate_receipt(
            self.registry, self.ledger,
            receipt_artifact_sha256=record.sha256,
            expected_run_id="timeline-run",
            expected_contract_id=self.values["contract"].contract_id,
        )
        self.assertIs(type(receipt), design.EvaluationContractFreezeGateReceipt)
        self.assertEqual(receipt.freeze_scope, "DESIGN_FREEZE_VALIDITY_ONLY")
        self.assertTrue(receipt.design_frozen_before_execution)
        self.assertFalse(receipt.result_validity_authorized)
        return receipt

    @staticmethod
    def publications(snapshot):
        return (
            tuple(
                record for record in snapshot[0].records
                if record.logical_type
                == design.EVALUATION_CONTRACT_FREEZE_GATE_RECEIPT_LOGICAL_TYPE
            ),
            tuple(
                event for event in snapshot[1].events
                if event.metadata.get("scientific_timeline", {}).get("kind")
                == "DESIGN_FROZEN"
            ),
        )

    def append_inert_artifact(self):
        return self.registry.put_json(
            {"fixture": "NON_EVIDENTIARY freeze interleaving; no authority"},
            logical_type="non_evidentiary_interleaving",
            origin="actual inert append after actual freeze source replay",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("test", "freeze-source-interleaving"),
            schema_version="1.0", mime_type="application/json",
            validation_result="FAIL", frozen=False,
        )

    def append_inert_checkpoint(self):
        events = self.ledger.validate(raise_on_error=True).events
        state = events[-1].requested_state_after if events else MacroState.PROTOCOL
        return self.ledger.record(
            run_id="timeline-run", actor_role=Role.ORCHESTRATOR,
            state_before=state, requested_state_after=state,
            artifact_hashes=(self.values["evidence"].sha256,),
            code_version="non-evidentiary-freeze-interleaving",
            configuration_hash=self.values["spec"].configuration_sha256,
            reason="NON_EVIDENTIARY unrelated checkpoint; no scientific admission",
            event_type="CHECKPOINT", metadata={"non_evidentiary_fixture": True},
        )

    def correct(self, event):
        return self.ledger.append_correction(
            event.event_id, actor_role=Role.SCIENTIFIC_REVIEWER,
            reason="Withdraw this source during the actual freeze-admission read.",
            corrected_fields={"authority": "WITHDRAWN"},
        )

    def assert_only_injected_delta(self, before, *, artifact=None, event=None):
        after = self.snapshot()
        expected_records = {record.sha256: record for record in before[0].records}
        if artifact is not None:
            self.assertNotIn(artifact.sha256, expected_records)
            expected_records[artifact.sha256] = artifact
        self.assertEqual(
            {record.sha256: record for record in after[0].records}, expected_records,
        )
        self.assertEqual(after[0].count, before[0].count + int(artifact is not None))
        self.assertEqual(after[0].orphan_paths, before[0].orphan_paths)
        if event is None:
            self.assertEqual(after[1], before[1])
        else:
            self.assertEqual(after[1].events, (*before[1].events, event))
            self.assertEqual(event.prior_event_hash, before[1].head_hash)
            self.assertEqual(after[1].head_hash, event.event_hash)
        self.assertEqual(self.publications(after), self.publications(before))
        return after

    def _design_interleaving(self, kind):
        target = self.append_inert_checkpoint() if kind == "correction" else None
        before = self.snapshot()
        actual_sources = design._require_scientific_timeline_inputs
        forwarded = []
        injected = []

        def replay_then_mutate(*args, **kwargs):
            result = actual_sources(*args, **kwargs)
            if not forwarded:
                forwarded.append(result)
                if kind == "registry":
                    injected.append(self.append_inert_artifact())
                elif kind == "ledger":
                    injected.append(self.append_inert_checkpoint())
                else:
                    injected.append(self.correct(target))
            return result

        with patch.object(
            design, "_require_scientific_timeline_inputs", new=replay_then_mutate,
        ):
            with self.assertRaisesRegex(design.ScientificPromotionError, "changed|snapshot"):
                self.freeze()
        self.assertEqual(len(forwarded), 1)
        self.assertEqual(forwarded[0][0], self.values["contract_record"])
        self.assertEqual(forwarded[0][4], self.values["spec_record"])
        self.assertEqual(len(injected), 1)
        self.assert_only_injected_delta(
            before,
            artifact=injected[0] if kind == "registry" else None,
            event=injected[0] if kind != "registry" else None,
        )
        # Replaying against the new stable snapshot may admit the same initial
        # design. The corrected preparatory fixture was not a design authority.
        event = self.freeze()
        record = self.register_receipt()
        self.assertEqual(self.require_receipt(record).design_freeze_event_hash, event.event_hash)

    def _receipt_interleaving(self, kind):
        design_event = self.freeze()
        before = self.snapshot()
        actual_derive = design._derive_evaluation_contract_freeze_gate_receipt
        forwarded = []
        injected = []

        def derive_then_mutate(*args, **kwargs):
            result = actual_derive(*args, **kwargs)
            if not forwarded:
                forwarded.append(result)
                if kind == "registry":
                    injected.append(self.append_inert_artifact())
                elif kind == "ledger":
                    injected.append(self.append_inert_checkpoint())
                else:
                    injected.append(self.correct(design_event))
            return result

        with patch.object(
            design, "_derive_evaluation_contract_freeze_gate_receipt", new=derive_then_mutate,
        ):
            with self.assertRaisesRegex(
                design.ScientificPromotionError, "changed|snapshot|superseded",
            ):
                self.register_receipt()
        self.assertEqual(len(forwarded), 1)
        self.assertEqual(forwarded[0][0].design_freeze_event_hash, design_event.event_hash)
        self.assertFalse(forwarded[0][0].result_validity_authorized)
        self.assertEqual(len(injected), 1)
        after = self.assert_only_injected_delta(
            before,
            artifact=injected[0] if kind == "registry" else None,
            event=injected[0] if kind != "registry" else None,
        )
        if kind == "correction":
            with self.assertRaisesRegex(design.ScientificPromotionError, "superseded"):
                self.register_receipt()
            self.assertEqual(self.snapshot(), after)
        else:
            record = self.register_receipt()
            self.assertEqual(
                self.require_receipt(record).design_freeze_event_hash, design_event.event_hash,
            )

    def test_design_refuses_registry_append_after_actual_source_replay(self):
        self._design_interleaving("registry")

    def test_design_refuses_ledger_append_after_actual_source_replay(self):
        self._design_interleaving("ledger")

    def test_design_refuses_ledger_correction_after_actual_source_replay(self):
        self._design_interleaving("correction")

    def test_receipt_refuses_registry_append_after_actual_full_derivation(self):
        self._receipt_interleaving("registry")

    def test_receipt_refuses_ledger_append_after_actual_full_derivation(self):
        self._receipt_interleaving("ledger")

    def test_receipt_refuses_design_correction_before_any_receipt_write(self):
        self._receipt_interleaving("correction")

    def test_unchanged_legacy_design_and_receipt_have_exact_publication_deltas(self):
        before = self.snapshot()
        event = self.freeze()
        frozen = self.snapshot()
        self.assertEqual(frozen[0], before[0])
        self.assertEqual(frozen[1].events, (*before[1].events, event))
        record = self.register_receipt()
        published = self.snapshot()
        expected = {item.sha256: item for item in frozen[0].records}
        expected[record.sha256] = record
        self.assertEqual({item.sha256: item for item in published[0].records}, expected)
        self.assertEqual(published[0].count, frozen[0].count + 1)
        self.assertEqual(published[1], frozen[1])
        self.assertEqual(self.require_receipt(record).design_freeze_event_hash, event.event_hash)
        self.assertEqual(self.register_receipt(), record)
        self.assertEqual(self.snapshot(), published)

    def test_existing_receipt_retry_after_harmless_appends_is_exact_and_read_only(self):
        self.freeze()
        record = self.register_receipt()
        receipt = self.require_receipt(record)
        raw = self.registry.get_bytes(record.sha256)
        self.append_inert_artifact()
        self.append_inert_checkpoint()
        before = self.snapshot()
        self.assertEqual(self.register_receipt(), record)
        self.assertEqual(self.require_receipt(record), receipt)
        self.assertEqual(self.registry.get_metadata(record.sha256), record)
        self.assertEqual(self.registry.get_bytes(record.sha256), raw)
        self.assertEqual(self.snapshot(), before)

    def test_historical_receipt_retry_after_recorded_synthetic_visibility_is_exact(self):
        self.freeze()
        record = self.register_receipt()
        receipt = self.require_receipt(record)
        # These are explicitly synthetic NON_EVIDENTIARY fixture outputs, not
        # executed results. The actual visibility owner still replays them.
        fixtures._register_timeline_outputs(self.values)
        observed = design.record_scientific_result_observed(
            self.registry, self.ledger, **self.arguments(),
            output_manifest_artifact_sha256=self.values["manifest_record"].sha256,
        )
        before = self.snapshot()
        self.assertEqual(observed.metadata["scientific_timeline"]["kind"], "RESULT_OBSERVED")
        self.assertEqual(self.register_receipt(), record)
        self.assertEqual(self.require_receipt(record), receipt)
        self.assertFalse(receipt.result_validity_authorized)
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
