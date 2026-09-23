"""Inert controls for the private v2 confirmatory-timeline source companion.

The companion is a replay result, not a new authority or issuance path.  The
fixtures below contain no independent custody, scientific execution, or live
provider source.  They exercise only the closed DTO shape, wrapper delegation,
and refusal by the actual full source owner.
"""

import ast
from dataclasses import FrozenInstanceError, fields
import hashlib
import inspect
from tempfile import TemporaryDirectory
import textwrap
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from tests import test_scientific_confirmatory_timeline_v2 as timeline_fixtures
import scientist_one.scientific_design as scientific_design


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _function_tree(function):
    return ast.parse(textwrap.dedent(inspect.getsource(function))).body[0]


def _calls(tree, name):
    return tuple(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
    )


def _binding():
    def source(name: str) -> str:
        return _digest(f"inert-timeline-binding:{name}")

    split_hashes = tuple(source(f"split-{index}") for index in range(4))
    split_records = tuple(source(f"split-record-{index}") for index in range(4))
    direct_hashes = (
        source("freeze"),
        source("contract"),
        source("preparation"),
        source("run-spec"),
        source("protocol"),
        source("custody"),
        source("dataset"),
        *split_hashes,
    )
    direct_records = (
        source("freeze-record"),
        source("contract-record"),
        source("preparation-record"),
        source("run-spec-record"),
        source("protocol-record"),
        source("custody-record"),
        source("dataset-record"),
        *split_records,
    )
    return scientific_design.ScientificConfirmatoryProtocolBinding(
        binding_id="inert-timeline-binding",
        ledger_run_id="inert-timeline-ledger",
        execution_run_id="inert-timeline-execution",
        evaluation_contract_freeze_receipt_artifact_sha256=direct_hashes[0],
        evaluation_contract_freeze_receipt_record_hash=direct_records[0],
        contract_artifact_sha256=direct_hashes[1],
        contract_record_hash=direct_records[1],
        contract_sha256=source("contract-body"),
        scientific_execution_preparation_artifact_sha256=direct_hashes[2],
        scientific_execution_preparation_record_hash=direct_records[2],
        frozen_run_spec_artifact_sha256=direct_hashes[3],
        frozen_run_spec_record_hash=direct_records[3],
        frozen_run_spec_sha256=source("run-spec-body"),
        protocol_artifact_sha256=direct_hashes[4],
        protocol_record_hash=direct_records[4],
        protocol_sha256=source("protocol-body"),
        fresh_custody_receipt_artifact_sha256=direct_hashes[5],
        fresh_custody_receipt_record_hash=direct_records[5],
        dataset_authority_artifact_sha256=direct_hashes[6],
        dataset_authority_record_hash=direct_records[6],
        split_authority_artifact_sha256s=split_hashes,
        split_authority_record_hashes=split_records,
        study_id="inert-timeline-study",
        study_version=1,
        hypothesis_id="inert-timeline-hypothesis",
        experiment_id="inert-timeline-experiment",
        metric_id="inert-timeline-metric",
        metric_unit=scientific_design.MetricUnit.FRACTION,
        metric_direction=scientific_design.MetricDirection.HIGHER_IS_BETTER,
        metric_scope=scientific_design.MetricScope.END_TO_END,
        evaluator_id="inert-timeline-evaluator",
        dataset_id="inert-timeline-dataset",
        split_ids=tuple(f"inert-split-{index}" for index in range(4)),
        seed_order=(0, 1),
        source_artifact_sha256s=direct_hashes,
        source_artifact_record_hashes=direct_records,
    )


def _runtime(directory):
    return (
        ArtifactRegistry(directory, "runs/inert-timeline/registry"),
        EventLedger(directory, "runs/inert-timeline/events.jsonl"),
    )


def _inert_registered_receipt(directory):
    registry, ledger = _runtime(directory)
    source_records = tuple(
        registry.put_json(
            {"inert_source": name},
            logical_type="inert_confirmatory_timeline_source",
            origin="INERT_CONFIRMATORY_TIMELINE_SOURCE_ONLY",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("fixture-only", "timeline-source"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        for name in ("binding", "execution", "projection", "legacy", "reveal")
    )
    receipt = timeline_fixtures.ScientificConfirmatoryTimelineV2Tests()._receipt()
    receipt = scientific_design.ScientificConfirmatoryTimelineReceiptV2(
        **{
            **{
                field.name: getattr(receipt, field.name)
                for field in fields(receipt)
            },
            "protocol_binding_artifact_sha256": source_records[0].sha256,
            "protocol_binding_record_hash": str(source_records[0].record_hash),
            "scientific_execution_authority_artifact_sha256": source_records[1].sha256,
            "scientific_execution_authority_record_hash": str(
                source_records[1].record_hash
            ),
            "generic_ml_projection_artifact_sha256": source_records[2].sha256,
            "generic_ml_projection_record_hash": str(source_records[2].record_hash),
            "confirmatory_timeline_receipt_artifact_sha256": source_records[3].sha256,
            "confirmatory_timeline_receipt_record_hash": str(
                source_records[3].record_hash
            ),
            "confirmation_reveal_gate_receipt_artifact_sha256": source_records[4].sha256,
            "confirmation_reveal_gate_receipt_record_hash": str(
                source_records[4].record_hash
            ),
            "direct_source_artifact_sha256s": tuple(
                item.sha256 for item in source_records
            ),
            "direct_source_artifact_record_hashes": tuple(
                str(item.record_hash) for item in source_records
            ),
        }
    )
    record = registry.put_json(
        receipt.to_dict(),
        logical_type=(
            scientific_design.SCIENTIFIC_CONFIRMATORY_TIMELINE_RECEIPT_LOGICAL_TYPE_V2
        ),
        origin=scientific_design._SCIENTIFIC_CONFIRMATORY_TIMELINE_ORIGIN_V2,
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=scientific_design._SCIENTIFIC_CONFIRMATORY_TIMELINE_COMMAND_V2,
        parent_artifacts=receipt.direct_source_artifact_sha256s,
        schema_version="2.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )
    return registry, ledger, receipt, record


class ScientificTimelineSourceCompanionTests(unittest.TestCase):
    def test_public_wrapper_has_exact_private_signature_and_one_receipt_projection(self):
        public = scientific_design.require_scientific_confirmatory_timeline_receipt_v2
        private = scientific_design._require_scientific_confirmatory_timeline_source_v2
        self.assertEqual(inspect.signature(public).parameters, inspect.signature(private).parameters)
        for function in (public, private):
            signature = inspect.signature(function)
            self.assertFalse(
                any(
                    parameter.kind
                    in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
                    for parameter in signature.parameters.values()
                )
            )
            for name in (
                "skip_validation",
                "source_override",
                "context",
                "entry_snapshot",
                "protocol_binding",
            ):
                self.assertNotIn(name, signature.parameters)

        tree = _function_tree(public)
        calls = tuple(node for node in ast.walk(tree) if isinstance(node, ast.Call))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].func.id, private.__name__)
        expected_keywords = set(inspect.signature(private).parameters) - {
            "registry",
            "ledger",
        }
        self.assertEqual(
            {keyword.arg for keyword in calls[0].keywords}, expected_keywords
        )
        self.assertTrue(
            all(
                isinstance(keyword.value, ast.Name)
                and keyword.value.id == keyword.arg
                for keyword in calls[0].keywords
            )
        )
        returned = tree.body[-1].value
        self.assertIsInstance(returned, ast.Attribute)
        self.assertEqual(returned.attr, "receipt")
        self.assertIs(returned.value, calls[0])

    def test_private_owner_constructs_companion_only_after_complete_validation_tail(self):
        private = scientific_design._require_scientific_confirmatory_timeline_source_v2
        tree = _function_tree(private)
        constructor_calls = _calls(
            tree, "_ScientificConfirmatoryTimelineReplayV2"
        )
        self.assertEqual(len(constructor_calls), 1)
        self.assertEqual(len(tuple(node for node in ast.walk(tree) if isinstance(node, ast.Return))), 1)
        self.assertIs(tree.body[-1].value.func, constructor_calls[0].func)
        self.assertEqual(
            {keyword.arg: ast.unparse(keyword.value) for keyword in constructor_calls[0].keywords},
            {
                "receipt": "receipt",
                "record": "record",
                "publication_event_id": "event.event_id",
                "publication_event_hash": "event.event_hash",
                "publication_event_index": "event_index",
                "entry_snapshot": "before",
                "protocol_binding": "sources.binding",
            },
        )
        self.assertEqual(
            len(_calls(tree, "_scientific_confirmatory_timeline_sources")), 1
        )
        self.assertEqual(
            len(_calls(tree, "_matching_scientific_confirmatory_timeline_records")), 1
        )
        self.assertEqual(
            len(_calls(tree, "_matching_scientific_confirmatory_timeline_events")), 1
        )
        self.assertEqual(
            len(_calls(tree, "_validate_scientific_confirmatory_timeline_event")), 1
        )
        snapshot_calls = _calls(tree, "_locked_checked_result_authority_snapshot")
        self.assertEqual(len(snapshot_calls), 2)
        self.assertGreater(
            constructor_calls[0].lineno,
            max(call.lineno for call in snapshot_calls),
        )
        self.assertGreater(
            constructor_calls[0].lineno,
            _calls(tree, "_validate_scientific_confirmatory_timeline_event")[0].lineno,
        )
        self.assertEqual(
            [field.name for field in fields(scientific_design._ScientificConfirmatoryTimelineReplayV2)],
            [
                "receipt",
                "record",
                "publication_event_id",
                "publication_event_hash",
                "publication_event_index",
                "entry_snapshot",
                "protocol_binding",
            ],
        )

    def test_inert_companion_is_frozen_and_keeps_replayed_source_identity(self):
        with TemporaryDirectory(prefix="inert-timeline-companion-") as directory:
            registry, ledger = _runtime(directory)
            record = registry.put_json(
                {"inert": "timeline-companion"},
                logical_type="inert_timeline_companion_record",
                origin="INERT_CONFIRMATORY_TIMELINE_COMPANION",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("fixture-only", "timeline-companion"),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            receipt = timeline_fixtures.ScientificConfirmatoryTimelineV2Tests()._receipt()
            binding = _binding()
            entry_snapshot = (
                registry.verify_all(raise_on_error=True),
                ledger.validate(raise_on_error=True),
            )
            companion = scientific_design._ScientificConfirmatoryTimelineReplayV2(
                receipt=receipt,
                record=record,
                publication_event_id="inert-timeline-publication",
                publication_event_hash=_digest("inert-timeline-publication"),
                publication_event_index=0,
                entry_snapshot=entry_snapshot,
                protocol_binding=binding,
            )
            self.assertIs(companion.receipt, receipt)
            self.assertIs(companion.record, record)
            self.assertIs(companion.protocol_binding, binding)
            self.assertEqual(companion.entry_snapshot, entry_snapshot)
            with self.assertRaises(FrozenInstanceError):
                companion.protocol_binding = None
            with self.assertRaisesRegex(
                scientific_design.ScientificPromotionError,
                "protocol binding",
            ):
                scientific_design._ScientificConfirmatoryTimelineReplayV2(
                    receipt=receipt,
                    record=record,
                    publication_event_id="inert-timeline-publication",
                    publication_event_hash=_digest("inert-timeline-publication"),
                    publication_event_index=0,
                    entry_snapshot=entry_snapshot,
                    protocol_binding=None,
                )

    def test_real_full_owner_refuses_inert_registered_receipt_without_writes(self):
        with TemporaryDirectory(prefix="inert-timeline-owner-") as directory:
            registry, ledger, receipt, record = _inert_registered_receipt(directory)
            before = (
                registry.verify_all(raise_on_error=True),
                ledger.validate(raise_on_error=True),
            )
            arguments = dict(
                receipt_artifact_sha256=record.sha256,
                expected_ledger_run_id=receipt.ledger_run_id,
                expected_execution_run_id=receipt.execution_run_id,
                expected_contract_artifact_sha256=receipt.contract_artifact_sha256,
                expected_preparation_artifact_sha256=(
                    receipt.scientific_execution_preparation_artifact_sha256
                ),
                expected_execution_authority_artifact_sha256=(
                    receipt.scientific_execution_authority_artifact_sha256
                ),
                expected_output_manifest_artifact_sha256=receipt.output_manifest_artifact_sha256,
                expected_generic_ml_projection_artifact_sha256=(
                    receipt.generic_ml_projection_artifact_sha256
                ),
            )
            errors = []
            for owner in (
                scientific_design._require_scientific_confirmatory_timeline_source_v2,
                scientific_design.require_scientific_confirmatory_timeline_receipt_v2,
            ):
                with self.assertRaises(scientific_design.ScientificPromotionError) as caught:
                    owner(registry, ledger, **arguments)
                errors.append((type(caught.exception), str(caught.exception)))
                self.assertEqual(
                    (
                        registry.verify_all(raise_on_error=True),
                        ledger.validate(raise_on_error=True),
                    ),
                    before,
                )
            self.assertEqual(errors[0], errors[1])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
