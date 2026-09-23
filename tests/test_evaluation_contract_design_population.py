"""Native design-population controls with NON_EVIDENTIARY fixture sources.

Actual public registrars produce the control contract, plans, spec, checkpoint
and freeze receipt. No workload, Result, statistical authority or scientific
success is produced. Adverse ledgers copy the actual native prefix and append
a rehashed native event with only the tested field changed; the original
ledger is never rewritten. No successful scientific owner is mocked.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import tempfile
import unittest
from unittest.mock import patch

import scientist_one.evaluation_contract_amendment as amendment
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState, thaw_json
from scientist_one.roles import Role
import scientist_one.scientific_design as design
from scientist_one.security import canonical_json_bytes
from tests import test_scientific_design as fixtures


_KEY = "evaluation_contract_design_population"
_SCHEMA = "evaluation-contract-design-population/v1"


def _fingerprint(record_map):
    # Independent literal wire preimage, not the production map builder.
    return hashlib.sha256(canonical_json_bytes(record_map)).hexdigest()


def _update_map_witness(value):
    value["source_registry_record_count"] = len(value["source_registry_record_map"])
    value["source_registry_record_map_fingerprint"] = _fingerprint(
        value["source_registry_record_map"]
    )


class EvaluationContractDesignPopulationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="design-population-")
        self.addCleanup(directory.cleanup)
        self.root = directory.name
        self.values = fixtures._prepared_timeline(self.root)
        self.registry = self.values["registry"]
        self.ledger = self.values["ledger"]
        self.ledger_number = 0

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

    def snapshot(self, ledger=None):
        return (
            self.registry.verify_all(raise_on_error=True),
            (self.ledger if ledger is None else ledger).validate(raise_on_error=True),
        )

    def freeze(self):
        return design.record_scientific_design_freeze(
            self.registry, self.ledger, **self.arguments(),
        )

    def register_receipt(self, *, ledger=None, receipt_id="population-freeze-receipt"):
        return design.register_evaluation_contract_freeze_gate_receipt(
            self.registry, self.ledger if ledger is None else ledger,
            receipt_id=receipt_id, **self.arguments(),
        )

    def require_receipt(self, record, *, ledger=None):
        return design.require_evaluation_contract_freeze_gate_receipt(
            self.registry, self.ledger if ledger is None else ledger,
            receipt_artifact_sha256=record.sha256,
            expected_run_id="timeline-run",
            expected_contract_id=self.values["contract"].contract_id,
        )

    def prepare_design(self, *, with_prefix=True):
        if with_prefix:
            self.ledger.record(
                run_id="timeline-run", actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.PROTOCOL,
                requested_state_after=MacroState.PROTOCOL,
                artifact_hashes=(self.values["evidence"].sha256,),
                code_version="non-evidentiary-population-prefix",
                configuration_hash=self.values["spec"].configuration_sha256,
                reason="NON_EVIDENTIARY preparatory checkpoint; no scientific outcome",
                event_type="CHECKPOINT", metadata={"non_evidentiary_fixture": True},
            )
        self.source_snapshot = self.snapshot()
        self.event = self.freeze()
        self.record = self.register_receipt()
        receipt = self.require_receipt(self.record)
        self.assertEqual(receipt.design_freeze_event_hash, self.event.event_hash)
        self.assertEqual(receipt.freeze_scope, "DESIGN_FREEZE_VALIDITY_ONLY")
        self.assertFalse(receipt.result_validity_authorized)
        return receipt

    def copied_ledger(self, metadata, *, actor_role=None):
        self.ledger_number += 1
        ledger = EventLedger(
            self.root, f"runs/population-copy-{self.ledger_number}/events.jsonl",
        )
        for event in self.source_snapshot[1].events:
            self.assertEqual(ledger.append(event), event)
        event = replace(
            self.event, metadata=metadata, event_hash=None,
            actor_role=self.event.actor_role if actor_role is None else actor_role,
        )
        self.assertEqual(ledger.append(event), event)
        validated = ledger.validate(raise_on_error=True)
        self.assertEqual(validated.events, (*self.source_snapshot[1].events, event))
        self.assertEqual(event.prior_event_hash, self.source_snapshot[1].head_hash)
        self.assertEqual(event.artifact_hashes, self.event.artifact_hashes)
        self.assertEqual(event.metadata["scientific_timeline"], self.event.metadata["scientific_timeline"])
        return ledger, event

    def reject_metadata(self, metadata, message, *, actor_role=None):
        original = self.snapshot()
        ledger, event = self.copied_ledger(metadata, actor_role=actor_role)
        self.assertNotEqual(event.event_hash, self.event.event_hash)
        before = self.snapshot(ledger)
        # The full public reader reaches the event/population predicate before
        # any reconstructed-receipt equality or alternate ledger-path mismatch.
        with self.assertRaisesRegex(design.ScientificPromotionError, message):
            self.require_receipt(self.record, ledger=ledger)
        self.assertEqual(self.snapshot(ledger), before)
        with self.assertRaisesRegex(design.ScientificPromotionError, message):
            self.register_receipt(
                ledger=ledger, receipt_id=f"rejected-population-{self.ledger_number}",
            )
        self.assertEqual(self.snapshot(ledger), before)
        self.assertEqual(self.snapshot(), original)

    def test_new_map_exactly_seals_sorted_record_identities_and_pre_event_prefix(self):
        self.prepare_design()
        value = thaw_json(self.event.metadata)[_KEY]
        record_map = [
            [record.sha256, record.record_hash]
            for record in sorted(self.source_snapshot[0].records, key=lambda record: record.sha256)
        ]
        self.assertEqual(value, {
            "schema_version": _SCHEMA,
            "source_registry_record_map": record_map,
            "source_registry_record_count": len(record_map),
            "source_registry_record_map_fingerprint": _fingerprint(record_map),
            "source_ledger_event_count": self.source_snapshot[1].event_count,
            "source_ledger_head_hash": self.source_snapshot[1].head_hash,
        })
        self.assertEqual(value["source_ledger_event_count"], 1)
        self.assertEqual(self.event.prior_event_hash, value["source_ledger_head_hash"])
        self.assertNotIn(self.record.sha256, {identity[0] for identity in record_map})
        self.assertEqual(self.event.actor_role, Role.PROTOCOL_DESIGNER)
        self.assertEqual(set(thaw_json(self.event.metadata)), {
            "artifact_types", "artifact_record_hashes", "scientific_timeline", _KEY,
        })

    def test_empty_owned_prefix_has_exact_zero_count_and_null_head(self):
        self.prepare_design(with_prefix=False)
        value = thaw_json(self.event.metadata)[_KEY]
        self.assertIs(type(value["source_ledger_event_count"]), int)
        self.assertEqual(value["source_ledger_event_count"], 0)
        self.assertIsNone(value["source_ledger_head_hash"])
        self.assertIsNone(self.event.prior_event_hash)

    def test_later_unrelated_records_do_not_expand_or_rewrite_historical_map(self):
        receipt = self.prepare_design()
        metadata_bytes = canonical_json_bytes(self.event.metadata)
        later = self.registry.put_json(
            {"fixture": "NON_EVIDENTIARY unrelated record after design"},
            logical_type="non_evidentiary_later_source",
            origin="inert post-design append; not source authority",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("test", "design-population-later-source"),
            schema_version="1.0", mime_type="application/json",
            validation_result="FAIL", frozen=False,
        )
        before = self.snapshot()
        self.assertEqual(self.require_receipt(self.record), receipt)
        self.assertEqual(self.register_receipt(), self.record)
        self.assertEqual(self.snapshot(), before)
        current = before[1].events[self.source_snapshot[1].event_count]
        self.assertEqual(canonical_json_bytes(current.metadata), metadata_bytes)
        value = thaw_json(current.metadata)[_KEY]
        self.assertEqual(value["source_registry_record_count"], self.source_snapshot[0].count)
        self.assertNotIn(later.sha256, {identity[0] for identity in value["source_registry_record_map"]})

    def test_omitted_required_spec_refuses_even_with_recomputed_count_and_fingerprint(self):
        self.prepare_design()
        metadata = thaw_json(self.event.metadata)
        value = metadata[_KEY]
        value["source_registry_record_map"] = [
            identity for identity in value["source_registry_record_map"]
            if identity[0] != self.values["spec_record"].sha256
        ]
        _update_map_witness(value)
        self.reject_metadata(metadata, "design population omits required source")

    def test_omitted_actual_parent_refuses_even_with_recomputed_witness(self):
        self.prepare_design()
        metadata = thaw_json(self.event.metadata)
        value = metadata[_KEY]
        value["source_registry_record_map"] = [
            identity for identity in value["source_registry_record_map"]
            if identity[0] != self.values["evidence"].sha256
        ]
        _update_map_witness(value)
        self.reject_metadata(metadata, "not parent-closed")

    def test_wrong_actual_record_hash_refuses_after_recomputed_fingerprint(self):
        self.prepare_design()
        metadata = thaw_json(self.event.metadata)
        value = metadata[_KEY]
        row = next(identity for identity in value["source_registry_record_map"]
                   if identity[0] == self.values["spec_record"].sha256)
        row[1] = self.values["contract_record"].record_hash
        self.assertNotEqual(row[1], self.values["spec_record"].record_hash)
        _update_map_witness(value)
        self.reject_metadata(metadata, "sealed registry source is missing or changed")

    def test_closed_population_count_fingerprint_head_index_schema_and_keys(self):
        self.prepare_design()
        cases = (
            ("source_registry_record_count", self.source_snapshot[0].count + 1,
             "count or fingerprint differs"),
            ("source_registry_record_map_fingerprint", self.event.event_hash,
             "count or fingerprint differs"),
            ("source_ledger_head_hash", self.event.event_hash,
             "prefix head is substituted"),
            ("source_ledger_event_count", 0, "another owned event prefix"),
            ("source_ledger_event_count", True, "another owned event prefix"),
            ("schema_version", "evaluation-contract-design-population/v2",
             "another owned event prefix"),
            ("caller_declared_complete", True, "design population witness.*unknown fields"),
        )
        for field, replacement, message in cases:
            with self.subTest(field=field, replacement=replacement):
                metadata = thaw_json(self.event.metadata)
                metadata[_KEY][field] = replacement
                self.reject_metadata(metadata, message)

    def test_unsorted_and_duplicate_maps_are_refused_with_recomputed_witness(self):
        self.prepare_design()
        for mode in ("unsorted", "duplicate"):
            with self.subTest(mode=mode):
                metadata = thaw_json(self.event.metadata)
                value = metadata[_KEY]
                if mode == "unsorted":
                    value["source_registry_record_map"].reverse()
                else:
                    value["source_registry_record_map"].append(
                        list(value["source_registry_record_map"][-1])
                    )
                _update_map_witness(value)
                self.reject_metadata(metadata, "unordered or duplicated")

    def test_exact_legacy_event_without_population_retains_only_original_semantics(self):
        self.prepare_design()
        metadata = thaw_json(self.event.metadata)
        del metadata[_KEY]
        self.assertEqual(set(metadata), {
            "artifact_types", "artifact_record_hashes", "scientific_timeline",
        })
        ledger, event = self.copied_ledger(metadata)
        record = self.register_receipt(ledger=ledger, receipt_id="legacy-population-absent")
        before = self.snapshot(ledger)
        receipt = self.require_receipt(record, ledger=ledger)
        self.assertEqual(receipt.design_freeze_event_hash, event.event_hash)
        self.assertEqual(receipt.ledger_path, ledger.relative_path.as_posix())
        self.assertFalse(receipt.result_validity_authorized)
        self.assertEqual(self.register_receipt(
            ledger=ledger, receipt_id="legacy-population-absent",
        ), record)
        self.assertEqual(self.snapshot(ledger), before)
        extra = dict(metadata, caller_declared_complete=True)
        self.reject_metadata(extra, "scientific timeline event metadata.*unknown fields")
        self.reject_metadata(
            metadata, "substituted type, role, artifacts, or binding",
            actor_role=Role.EVIDENCE_CURATOR,
        )

    def test_all_population_capacity_preflights_refuse_without_admission_delta(self):
        before = self.snapshot()
        cases = (
            (design, "_MAX_EVALUATION_CONTRACT_DESIGN_EVENT_BYTES", 1,
             "complete design population exceeds ledger capacity"),
            (design, "MAX_LEDGER_EVENTS", 0,
             "complete design population exceeds ledger capacity"),
            (design, "MAX_LEDGER_BYTES", 0,
             "complete design population exceeds ledger capacity"),
            (amendment, "MAX_REGISTRY_RECORDS", before[0].count - 1,
             "registry record map exceeds the supported bound"),
        )
        for module, name, limit, message in cases:
            with self.subTest(limit=name), patch.object(module, name, limit):
                with self.assertRaisesRegex(design.ScientificPromotionError, message):
                    self.freeze()
            self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
