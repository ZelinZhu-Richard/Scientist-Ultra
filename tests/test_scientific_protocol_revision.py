"""Focused tests for non-authorizing persisted protocol revisions.

The parentless legacy protocol records below are ordinary canonical artifacts
used to exercise revision lineage.  They are not scientific admission,
confirmatory custody, fresh-reserve, result, human, or release authority.
"""

from __future__ import annotations

from dataclasses import replace
import tempfile
import unittest
from unittest import mock

import scientist_one.scientific_protocol_revision as revision_module
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import LedgerError
from scientist_one.evaluation_contract_amendment import (
    register_evaluation_contract_amendment,
)
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from scientist_one.scientific_design import register_frozen_evaluation_contract
from scientist_one.scientific_design import (
    record_scientific_design_freeze,
    record_scientific_result_observed,
)
from scientist_one.scientific_protocol_revision import (
    SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA,
    SCIENTIFIC_PROTOCOL_REVISION_EVENT_KEY,
    ScientificProtocolRevisionError,
    ScientificProtocolRevisionPublication,
    register_scientific_protocol_revision,
    require_scientific_protocol_revision,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads
from tests import test_scientific_design as timeline_fixtures
from tests.test_protocol_contract_crosswalk import matching_protocol
from tests.test_scientific_design import _timeline_artifact, make_contract


_RUN_ID = "protocol-revision-test-run"
_REASON = "Record the exact prospective protocol revision for the amendment."


class ScientificProtocolRevisionTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="protocol-revision-")
        self.addCleanup(directory.cleanup)
        self.root = directory.name
        self.registry = ArtifactRegistry(self.root)
        self.ledger = EventLedger(
            self.root, "runs/protocol-revisions/events.jsonl"
        )
        self.evidence = _timeline_artifact(
            self.registry,
            b'{"fixture":"NON_AUTHORIZING protocol revision evidence"}\n',
            "timeline_contract_evidence",
            Role.EVIDENCE_CURATOR,
        )
        self.parent_contract = make_contract()
        self.parent_contract_record = register_frozen_evaluation_contract(
            self.registry,
            contract=self.parent_contract,
            parent_artifact_sha256s=(self.evidence.sha256,),
        )
        self.parent_protocol = matching_protocol(self.parent_contract)
        self.parent_protocol_record = self._legacy_protocol_record(
            self.parent_protocol
        )
        self.child_contract = replace(
            self.parent_contract,
            version=self.parent_contract.version + 1,
            success_criteria=(
                "Changed contract criterion recorded without confirmation authority.",
            ),
        )
        self.amendment = register_evaluation_contract_amendment(
            self.registry,
            self.ledger,
            run_id=_RUN_ID,
            amendment_id="protocol-amendment-1",
            parent_contract_artifact_sha256=self.parent_contract_record.sha256,
            child_contract=self.child_contract,
            author_id=self.parent_contract.frozen_by,
            reason=_REASON,
            child_evidence_parent_artifact_sha256s=(self.evidence.sha256,),
        )
        # This is intentionally a contract-only scientific delta: the protocol
        # still advances exactly one immutable lineage version and records A.
        self.child_protocol = replace(
            self.parent_protocol,
            study_version=self.parent_protocol.study_version + 1,
            parent_protocol_hash=self.parent_protocol.sha256,
            revision_reason=_REASON,
        )

    def _legacy_protocol_record(self, protocol, *, marker="root", registry=None):
        target = self.registry if registry is None else registry
        return target.put_json(
            {
                "kind": "FROZEN_SYNTHETIC_PROTOCOL",
                "frozen": True,
                "protocol": protocol.canonical_dict,
                "protocol_sha256": protocol.sha256,
                "baseline_equivalence": [],
                "blind_patterns": [f"NON_AUTHORIZING test fixture {marker}"],
                "reproduction_tolerance": 1e-12,
            },
            logical_type="frozen_protocol",
            origin="NON_AUTHORIZING parentless legacy protocol fixture",
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("scientist-one", "protocol-revision-test-fixture"),
            parent_artifacts=(),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def publish(self, *, protocol=None, parent_protocol_record=None):
        return register_scientific_protocol_revision(
            self.registry,
            self.ledger,
            expected_run_id=_RUN_ID,
            amendment_artifact_sha256=self.amendment.amendment_record.sha256,
            parent_protocol_artifact_sha256=(
                self.parent_protocol_record.sha256
                if parent_protocol_record is None
                else parent_protocol_record.sha256
            ),
            protocol=self.child_protocol if protocol is None else protocol,
        )

    def snapshot(self):
        return (
            self.registry.verify_all(raise_on_error=True),
            self.ledger.assert_valid(),
        )

    def _put_malformed_protocol_semantic_control(
        self,
        publication,
        *,
        semantic_sha256,
        protocol_present,
        protocol_value=None,
        mime_type="application/json",
    ):
        value = {
            "schema_version": publication.authority.schema_version,
            "protocol_semantic_sha256": semantic_sha256,
        }
        if protocol_present:
            value["protocol"] = protocol_value
        return self.registry.put_bytes(
            canonical_json_bytes(value) + b"\n",
            logical_type="frozen_protocol",
            origin="unrelated malformed protocol semantic control",
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=(
                "scientist-one",
                "malformed-protocol-semantic-control",
            ),
            parent_artifacts=(),
            schema_version=SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA,
            mime_type=mime_type,
            validation_result="PASS",
            frozen=True,
        )

    def _assert_malformed_protocol_preserves_semantic_selector(
        self,
        *,
        protocol_present,
        protocol_value=None,
        mime_type="application/json",
    ):
        publication = self.publish()
        self._put_malformed_protocol_semantic_control(
            publication,
            semantic_sha256=self.evidence.sha256,
            protocol_present=protocol_present,
            protocol_value=protocol_value,
            mime_type=mime_type,
        )
        self.assertEqual(
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            ).protocol_record,
            publication.protocol_record,
        )
        self._put_malformed_protocol_semantic_control(
            publication,
            semantic_sha256=publication.authority.protocol_semantic_sha256,
            protocol_present=protocol_present,
            protocol_value=protocol_value,
            mime_type=mime_type,
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError,
            "related protocol revision slot record is malformed",
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), before)
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError,
            "related protocol revision slot record is malformed",
        ):
            self.publish()
        self.assertEqual(self.snapshot(), before)

    def _append_wrong_slot_alias_event(
        self,
        publication,
        *,
        outer_artifact,
        metadata_artifact,
        metadata_record,
        metadata_semantic=False,
    ):
        metadata = dict(publication.event.metadata)
        binding = dict(metadata[SCIENTIFIC_PROTOCOL_REVISION_EVENT_KEY])
        binding["study_id"] = "renamed-study"
        if not metadata_semantic:
            binding["protocol_semantic_sha256"] = self.evidence.sha256
        if not metadata_artifact:
            binding["protocol_artifact_sha256"] = self.evidence.sha256
        if not metadata_record:
            binding["protocol_record_hash"] = self.evidence.record_hash
        metadata[SCIENTIFIC_PROTOCOL_REVISION_EVENT_KEY] = binding
        metadata["artifact_record_hashes"] = []
        state = publication.event.state_after
        self.ledger.record(
            run_id=_RUN_ID,
            actor_role=Role.PROTOCOL_DESIGNER,
            state_before=state,
            requested_state_after=state,
            artifact_hashes=(
                (publication.protocol_record.sha256,) if outer_artifact else ()
            ),
            code_version=publication.event.code_version,
            configuration_hash=publication.event.configuration_hash,
            reason="Wrong-slot alias for one exact protocol output identity.",
            event_type="CHECKPOINT",
            metadata=metadata,
        )

    def test_contract_only_revision_publishes_and_replays_idempotently(self):
        before = self.snapshot()
        publication = self.publish()
        self.assertIs(type(publication), ScientificProtocolRevisionPublication)
        self.assertFalse(publication.authority.confirmation_authorized)
        self.assertFalse(publication.authority.results_seen_at_amendment)
        self.assertFalse(
            publication.authority.requires_new_confirmatory_reserve_at_amendment
        )
        self.assertEqual(publication.authority.changed_protocol_fields, ())
        self.assertEqual(
            publication.protocol_record.parent_artifacts,
            (
                self.parent_protocol_record.sha256,
                self.parent_contract_record.sha256,
                self.amendment.contract_record.sha256,
                self.amendment.amendment_record.sha256,
            ),
        )
        self.assertEqual(
            publication.protocol_record.schema_version,
            SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA,
        )
        self.assertEqual(
            publication.event.metadata[SCIENTIFIC_PROTOCOL_REVISION_EVENT_KEY]
            ["confirmation_authorized"],
            False,
        )
        wire = self.registry.get_bytes(publication.protocol_record.sha256)
        self.assertEqual(wire, canonical_json_bytes(safe_json_loads(wire)) + b"\n")
        self.assertEqual(
            self.registry.verify_all(raise_on_error=True).count,
            before[0].count + 1,
        )
        self.assertEqual(
            self.ledger.assert_valid().event_count,
            before[1].event_count + 1,
        )
        self.assertEqual(
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
                expected_amendment_artifact_sha256=(
                    self.amendment.amendment_record.sha256
                ),
            ),
            publication,
        )
        completed = self.snapshot()
        self.assertEqual(self.publish(), publication)
        self.assertEqual(self.snapshot(), completed)

    def test_two_generation_revision_replays_after_unrelated_append(self):
        first = self.publish()
        second_contract = replace(
            self.child_contract,
            version=self.child_contract.version + 1,
            stopping_criteria=("Use the prospectively revised stopping rule.",),
        )
        second_reason = "Record the second exact prospective protocol revision."
        second_amendment = register_evaluation_contract_amendment(
            self.registry,
            self.ledger,
            run_id=_RUN_ID,
            amendment_id="protocol-amendment-2",
            parent_contract_artifact_sha256=self.amendment.contract_record.sha256,
            child_contract=second_contract,
            author_id=self.parent_contract.frozen_by,
            reason=second_reason,
        )
        second_protocol = replace(
            first.protocol,
            study_version=first.protocol.study_version + 1,
            parent_protocol_hash=first.protocol.sha256,
            revision_reason=second_reason,
            stopping_rules=second_contract.stopping_criteria,
        )
        second = register_scientific_protocol_revision(
            self.registry,
            self.ledger,
            expected_run_id=_RUN_ID,
            amendment_artifact_sha256=second_amendment.amendment_record.sha256,
            parent_protocol_artifact_sha256=first.protocol_record.sha256,
            protocol=second_protocol,
        )
        self.assertEqual(second.parent_protocol_record, first.protocol_record)
        self.assertEqual(second.parent_protocol, first.protocol)
        self.assertEqual(second.authority.changed_protocol_fields, ("stopping_rules",))
        _timeline_artifact(
            self.registry,
            b'{"later":"unrelated append"}\n',
            "unrelated_protocol_revision_history_control",
            Role.EVIDENCE_CURATOR,
        )
        state = self.ledger.assert_valid().events[-1].state_after
        self.ledger.record(
            run_id=_RUN_ID,
            actor_role=Role.ORCHESTRATOR,
            state_before=state,
            requested_state_after=state,
            artifact_hashes=(first.protocol_record.sha256,),
            code_version="NON_AUTHORIZING-test",
            configuration_hash=self.child_contract.sha256,
            reason="Later unrelated protocol history control.",
            event_type="CHECKPOINT",
            metadata={
                "fixture": "NON_AUTHORIZING later protocol reference",
                "artifact_types": ["frozen_protocol"],
                "artifact_record_hashes": [first.protocol_record.record_hash],
            },
        )
        self.assertEqual(
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=first.protocol_record.sha256,
            ),
            first,
        )
        self.assertEqual(
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=second.protocol_record.sha256,
            ),
            second,
        )

    def test_actual_synthetic_visibility_is_labeled_only_at_amendment(self):
        with tempfile.TemporaryDirectory(prefix="visible-protocol-revision-") as root:
            values = timeline_fixtures._prepared_timeline(root)
            registry = values["registry"]
            ledger = values["ledger"]
            parent_contract = values["contract"]
            parent_protocol = matching_protocol(parent_contract)
            parent_record = registry.put_json(
                {
                    "kind": "FROZEN_SYNTHETIC_PROTOCOL",
                    "frozen": True,
                    "protocol": parent_protocol.canonical_dict,
                    "protocol_sha256": parent_protocol.sha256,
                    "baseline_equivalence": [],
                    "blind_patterns": ["NON_AUTHORIZING visibility fixture"],
                    "reproduction_tolerance": 1e-12,
                },
                logical_type="frozen_protocol",
                origin="NON_AUTHORIZING parentless legacy protocol fixture",
                creator_role=Role.PROTOCOL_DESIGNER,
                creation_command=(
                    "scientist-one",
                    "protocol-revision-visibility-fixture",
                ),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            record_scientific_design_freeze(
                registry,
                ledger,
                run_id="timeline-run",
                contract=parent_contract,
                contract_artifact_sha256=values["contract_record"].sha256,
                experiment_plan_artifact_sha256s=tuple(
                    item.sha256 for item in values["plan_records"]
                ),
                frozen_run_spec_artifact_sha256=values["spec_record"].sha256,
            )
            timeline_fixtures._register_timeline_outputs(values)
            record_scientific_result_observed(
                registry,
                ledger,
                run_id="timeline-run",
                contract=parent_contract,
                contract_artifact_sha256=values["contract_record"].sha256,
                experiment_plan_artifact_sha256s=tuple(
                    item.sha256 for item in values["plan_records"]
                ),
                frozen_run_spec_artifact_sha256=values["spec_record"].sha256,
                output_manifest_artifact_sha256=values["manifest_record"].sha256,
            )
            child_contract = replace(
                parent_contract,
                version=parent_contract.version + 1,
                success_criteria=("Post-observation prospective criterion.",),
            )
            reason = "Record a protocol revision after synthetic visibility."
            amendment = register_evaluation_contract_amendment(
                registry,
                ledger,
                run_id="timeline-run",
                amendment_id="visible-protocol-amendment",
                parent_contract_artifact_sha256=values["contract_record"].sha256,
                child_contract=child_contract,
                author_id=parent_contract.frozen_by,
                reason=reason,
            )
            protocol = replace(
                parent_protocol,
                study_version=parent_protocol.study_version + 1,
                parent_protocol_hash=parent_protocol.sha256,
                revision_reason=reason,
            )
            publication = register_scientific_protocol_revision(
                registry,
                ledger,
                expected_run_id="timeline-run",
                amendment_artifact_sha256=amendment.amendment_record.sha256,
                parent_protocol_artifact_sha256=parent_record.sha256,
                protocol=protocol,
            )
            self.assertTrue(publication.authority.results_seen_at_amendment)
            self.assertTrue(
                publication.authority.requires_new_confirmatory_reserve_at_amendment
            )
            self.assertFalse(publication.authority.confirmation_authorized)

    def test_transition_and_crosswalk_substitutions_refuse_prewrite(self):
        cases = (
            (replace(self.child_protocol, study_id="other-study"), "does not exactly"),
            (
                replace(self.child_protocol, study_version=3),
                "does not exactly",
            ),
            (
                replace(
                    self.child_protocol,
                    parent_protocol_hash=self.evidence.sha256,
                ),
                "does not exactly",
            ),
            (
                replace(self.child_protocol, revision_reason="Different reason."),
                "does not exactly",
            ),
            (
                replace(self.child_protocol, primary_metric="different-metric"),
                "crosswalk is invalid",
            ),
        )
        for protocol, message in cases:
            with self.subTest(message=message, protocol=protocol), self.assertRaisesRegex(
                ScientificProtocolRevisionError, message
            ):
                before = self.snapshot()
                self.publish(protocol=protocol)
            self.assertEqual(self.snapshot(), before)

        late_alternate = self._legacy_protocol_record(
            self.parent_protocol, marker="late alternate wrapper"
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError,
            "was not frozen before the amendment",
        ):
            self.publish(parent_protocol_record=late_alternate)
        self.assertEqual(self.snapshot(), before)

    def test_mutated_exact_protocol_is_reparsed_before_any_write(self):
        mutated = replace(self.child_protocol)
        object.__setattr__(mutated, "validity_reserve_fraction", 0.10)
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError,
            "not a valid canonical ResearchProtocol",
        ):
            self.publish(protocol=mutated)
        self.assertEqual(self.snapshot(), before)

    def test_native_predecessor_cannot_cross_contract_families(self):
        first = self.publish()
        foreign_parent = replace(self.parent_contract, contract_id="contract-foreign")
        foreign_parent_record = register_frozen_evaluation_contract(
            self.registry,
            contract=foreign_parent,
            parent_artifact_sha256s=(self.evidence.sha256,),
        )
        foreign_child = replace(
            foreign_parent,
            version=foreign_parent.version + 1,
            success_criteria=("Foreign but crosswalk-equivalent contract change.",),
        )
        reason = "Do not cross a crosswalk-equivalent contract family."
        foreign_amendment = register_evaluation_contract_amendment(
            self.registry,
            self.ledger,
            run_id=_RUN_ID,
            amendment_id="foreign-family-amendment",
            parent_contract_artifact_sha256=foreign_parent_record.sha256,
            child_contract=foreign_child,
            author_id=foreign_parent.frozen_by,
            reason=reason,
        )
        candidate = replace(
            first.protocol,
            study_version=first.protocol.study_version + 1,
            parent_protocol_hash=first.protocol.sha256,
            revision_reason=reason,
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError,
            "crosses an unrelated Evaluation Contract family",
        ):
            register_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                amendment_artifact_sha256=foreign_amendment.amendment_record.sha256,
                parent_protocol_artifact_sha256=first.protocol_record.sha256,
                protocol=candidate,
            )
        self.assertEqual(self.snapshot(), before)

    def test_high_initial_contract_version_and_exact_predecessor_retry(self):
        with tempfile.TemporaryDirectory(prefix="high-version-protocol-") as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root, "custom/protocol-history/events.jsonl")
            evidence = _timeline_artifact(
                registry,
                b'{"fixture":"high initial version protocol"}\n',
                "timeline_contract_evidence",
                Role.EVIDENCE_CURATOR,
            )
            parent_contract = replace(make_contract(), version=7)
            parent_contract_record = register_frozen_evaluation_contract(
                registry,
                contract=parent_contract,
                parent_artifact_sha256s=(evidence.sha256,),
            )
            parent_protocol = matching_protocol(parent_contract)
            first_parent = self._legacy_protocol_record(
                parent_protocol,
                marker="first high-version parent",
                registry=registry,
            )
            alternate_parent = self._legacy_protocol_record(
                parent_protocol,
                marker="alternate high-version parent",
                registry=registry,
            )
            child_contract = replace(
                parent_contract,
                version=8,
                success_criteria=("Explicit high-version contract revision.",),
            )
            reason = "Record high-version genesis as an explicit amendment."
            amendment = register_evaluation_contract_amendment(
                registry,
                ledger,
                run_id="high-version-protocol-run",
                amendment_id="high-version-protocol-amendment",
                parent_contract_artifact_sha256=parent_contract_record.sha256,
                child_contract=child_contract,
                author_id=parent_contract.frozen_by,
                reason=reason,
            )
            protocol = replace(
                parent_protocol,
                study_version=2,
                parent_protocol_hash=parent_protocol.sha256,
                revision_reason=reason,
            )
            publication = register_scientific_protocol_revision(
                registry,
                ledger,
                expected_run_id="high-version-protocol-run",
                amendment_artifact_sha256=amendment.amendment_record.sha256,
                parent_protocol_artifact_sha256=first_parent.sha256,
                protocol=protocol,
            )
            self.assertEqual(
                publication.amendment_publication.authority.amendment.from_version,
                7,
            )
            before = (
                registry.verify_all(raise_on_error=True),
                ledger.assert_valid(),
            )
            with self.assertRaisesRegex(
                ScientificProtocolRevisionError,
                "completed protocol revision slot belongs to another request",
            ):
                register_scientific_protocol_revision(
                    registry,
                    ledger,
                    expected_run_id="high-version-protocol-run",
                    amendment_artifact_sha256=amendment.amendment_record.sha256,
                    parent_protocol_artifact_sha256=alternate_parent.sha256,
                    protocol=protocol,
                )
            self.assertEqual(
                (
                    registry.verify_all(raise_on_error=True),
                    ledger.assert_valid(),
                ),
                before,
            )

    def test_same_amendment_can_record_two_distinct_non_authorizing_studies(self):
        with tempfile.TemporaryDirectory(prefix="two-study-protocol-") as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root, "runs/two-study/events.jsonl")
            evidence = _timeline_artifact(
                registry,
                b'{"fixture":"two non-authorizing protocol studies"}\n',
                "timeline_contract_evidence",
                Role.EVIDENCE_CURATOR,
            )
            parent_contract = make_contract()
            parent_contract_record = register_frozen_evaluation_contract(
                registry,
                contract=parent_contract,
                parent_artifact_sha256s=(evidence.sha256,),
            )
            template = matching_protocol(parent_contract)
            parents = tuple(
                replace(template, study_id=study_id)
                for study_id in ("protocol-study-a", "protocol-study-b")
            )
            parent_records = tuple(
                self._legacy_protocol_record(
                    protocol,
                    marker=protocol.study_id,
                    registry=registry,
                )
                for protocol in parents
            )
            child_contract = replace(
                parent_contract,
                version=parent_contract.version + 1,
                success_criteria=("Shared contract-only amendment.",),
            )
            reason = "Record two separate non-authorizing protocol lineages."
            amendment = register_evaluation_contract_amendment(
                registry,
                ledger,
                run_id="two-study-protocol-run",
                amendment_id="two-study-amendment",
                parent_contract_artifact_sha256=parent_contract_record.sha256,
                child_contract=child_contract,
                author_id=parent_contract.frozen_by,
                reason=reason,
            )
            publications = tuple(
                register_scientific_protocol_revision(
                    registry,
                    ledger,
                    expected_run_id="two-study-protocol-run",
                    amendment_artifact_sha256=amendment.amendment_record.sha256,
                    parent_protocol_artifact_sha256=parent_record.sha256,
                    protocol=replace(
                        parent,
                        study_version=parent.study_version + 1,
                        parent_protocol_hash=parent.sha256,
                        revision_reason=reason,
                    ),
                )
                for parent, parent_record in zip(parents, parent_records, strict=True)
            )
            self.assertEqual(
                tuple(item.protocol.study_id for item in publications),
                ("protocol-study-a", "protocol-study-b"),
            )
            self.assertEqual(
                len({item.protocol_record.sha256 for item in publications}),
                2,
            )
            self.assertTrue(
                all(not item.authority.confirmation_authorized for item in publications)
            )

    def test_unrelated_malformed_protocol_is_ignored_but_related_slot_refuses(self):
        self.registry.put_bytes(
            b"not-json",
            logical_type="frozen_protocol",
            origin="unrelated malformed protocol fixture",
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("scientist-one", "unrelated-malformed-fixture"),
            parent_artifacts=(),
            schema_version="2.0",
            mime_type="application/octet-stream",
            validation_result="PASS",
            frozen=True,
        )
        publication = self.publish()
        self.registry.put_bytes(
            canonical_json_bytes(
                {
                    "protocol": {
                        "study_id": publication.protocol.study_id,
                        "study_version": publication.protocol.study_version,
                    }
                }
            )
            + b"\n",
            logical_type="frozen_protocol",
            origin=(
                "append-only scientific protocol revision "
                f"{publication.protocol.study_id}:{publication.protocol.study_version}"
            ),
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("scientist-one", "malformed-slot-control"),
            parent_artifacts=publication.protocol_record.parent_artifacts,
            schema_version="2.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        before = self.snapshot()
        with self.assertRaises(ScientificProtocolRevisionError):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_related_wrong_metadata_protocol_slot_refuses_readback(self):
        publication = self.publish()
        value = publication.authority.to_dict()
        value["recorded_at"] = "2099-01-01T00:00:00Z"
        self.registry.put_bytes(
            canonical_json_bytes(value) + b"\n",
            logical_type="frozen_protocol",
            origin=(
                "append-only scientific protocol revision "
                f"{publication.protocol.study_id}:{publication.protocol.study_version}"
            ),
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "wrong-metadata-slot-control"),
            parent_artifacts=publication.protocol_record.parent_artifacts,
            schema_version="2.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError, "record metadata"
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_rehashed_renamed_study_with_exact_lineage_parents_refuses(self):
        publication = self.publish()
        value = safe_json_loads(
            self.registry.get_bytes(publication.protocol_record.sha256)
        )
        value["protocol"]["study_id"] = "renamed-study"
        self.registry.put_bytes(
            canonical_json_bytes(value) + b"\n",
            logical_type="frozen_protocol",
            origin=publication.protocol_record.origin,
            creator_role=publication.protocol_record.creator_role,
            creation_command=publication.protocol_record.creation_command,
            parent_artifacts=publication.protocol_record.parent_artifacts,
            schema_version=publication.protocol_record.schema_version,
            mime_type=publication.protocol_record.mime_type,
            validation_result=publication.protocol_record.validation_result,
            frozen=publication.protocol_record.frozen,
            created_at=publication.protocol_record.created_at,
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError,
            "related protocol revision slot record is malformed",
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_semantic_selector_survives_absent_protocol(self):
        self._assert_malformed_protocol_preserves_semantic_selector(
            protocol_present=False,
        )

    def test_semantic_selector_survives_null_protocol(self):
        self._assert_malformed_protocol_preserves_semantic_selector(
            protocol_present=True,
            protocol_value=None,
        )

    def test_semantic_selector_survives_invalid_study_hint(self):
        self._assert_malformed_protocol_preserves_semantic_selector(
            protocol_present=True,
            protocol_value={
                "study_id": None,
                "study_version": self.child_protocol.study_version,
            },
        )

    def test_semantic_selector_survives_wrong_mime_type(self):
        self._assert_malformed_protocol_preserves_semantic_selector(
            protocol_present=True,
            protocol_value=None,
            mime_type="application/octet-stream",
        )

    def test_semantic_only_wrong_slot_event_refuses_readback_and_retry(self):
        publication = self.publish()
        # An unrelated semantic output must remain harmless even if its typed
        # native binding is otherwise malformed.
        self._append_wrong_slot_alias_event(
            publication,
            outer_artifact=False,
            metadata_artifact=False,
            metadata_record=False,
            metadata_semantic=False,
        )
        before = self.snapshot()
        self.assertEqual(
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            ).protocol_record,
            publication.protocol_record,
        )
        self.assertEqual(self.snapshot(), before)
        self._append_wrong_slot_alias_event(
            publication,
            outer_artifact=False,
            metadata_artifact=False,
            metadata_record=False,
            metadata_semantic=True,
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError, "one exact publication event"
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), before)
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError, "one exact publication event"
        ):
            self.publish()
        self.assertEqual(self.snapshot(), before)

    def test_correction_refuses_readback(self):
        publication = self.publish()
        self.ledger.append_correction(
            publication.event.event_id,
            actor_role=Role.PROTOCOL_DESIGNER,
            reason="Retract the non-authorizing protocol revision record.",
            corrected_fields={"status": "RETRACTED"},
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError, "stale or corrected"
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_amendment_correction_and_expected_amendment_substitution_refuse(self):
        publication = self.publish()
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError, "names another amendment"
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
                expected_amendment_artifact_sha256=self.evidence.sha256,
            )
        self.assertEqual(self.snapshot(), before)
        self.ledger.append_correction(
            self.amendment.event.event_id,
            actor_role=Role.PROTOCOL_DESIGNER,
            reason="Retract the source contract amendment.",
            corrected_fields={"status": "RETRACTED"},
        )
        corrected = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError, "amendment source is invalid"
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), corrected)

    def test_outer_artifact_only_wrong_slot_alias_event_refuses_readback(self):
        publication = self.publish()
        self._append_wrong_slot_alias_event(
            publication,
            outer_artifact=True,
            metadata_artifact=False,
            metadata_record=False,
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError, "one exact publication event"
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_metadata_artifact_only_wrong_slot_alias_event_refuses_readback(self):
        publication = self.publish()
        self._append_wrong_slot_alias_event(
            publication,
            outer_artifact=False,
            metadata_artifact=True,
            metadata_record=False,
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError, "one exact publication event"
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_metadata_record_only_wrong_slot_alias_event_refuses_readback(self):
        publication = self.publish()
        self._append_wrong_slot_alias_event(
            publication,
            outer_artifact=False,
            metadata_artifact=False,
            metadata_record=True,
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError, "one exact publication event"
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_present_null_related_event_refuses_but_unrelated_null_does_not(self):
        publication = self.publish()
        state = publication.event.state_after
        self.ledger.record(
            run_id=_RUN_ID,
            actor_role=Role.ORCHESTRATOR,
            state_before=state,
            requested_state_after=state,
            artifact_hashes=(),
            code_version="NON_AUTHORIZING-test",
            configuration_hash=self.child_contract.sha256,
            reason="Unrelated malformed native-key control.",
            event_type="CHECKPOINT",
            metadata={SCIENTIFIC_PROTOCOL_REVISION_EVENT_KEY: None},
        )
        self.assertEqual(
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            ).protocol_record,
            publication.protocol_record,
        )
        state = self.ledger.assert_valid().events[-1].state_after
        self.ledger.record(
            run_id=_RUN_ID,
            actor_role=Role.ORCHESTRATOR,
            state_before=state,
            requested_state_after=state,
            artifact_hashes=(publication.protocol_record.sha256,),
            code_version="NON_AUTHORIZING-test",
            configuration_hash=self.child_contract.sha256,
            reason="Related explicitly null native-key control.",
            event_type="CHECKPOINT",
            metadata={SCIENTIFIC_PROTOCOL_REVISION_EVENT_KEY: None},
        )
        before = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError, "event binding is malformed"
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        self.assertEqual(self.snapshot(), before)

    def test_publication_cas_and_capacity_refusals_are_prewrite(self):
        before = self.snapshot()
        original_snapshot = revision_module._locked_checked_result_authority_snapshot
        calls = 0

        def drift_on_second_snapshot(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                _timeline_artifact(
                    self.registry,
                    b'{"race":"real registry append"}\n',
                    "protocol_revision_cas_race",
                    Role.EVIDENCE_CURATOR,
                )
            return original_snapshot(*args, **kwargs)

        with mock.patch.object(
            revision_module,
            "_locked_checked_result_authority_snapshot",
            side_effect=drift_on_second_snapshot,
        ), self.assertRaisesRegex(
            ScientificProtocolRevisionError, "changed during preflight"
        ):
            self.publish()
        after_race = self.snapshot()
        self.assertEqual(after_race[0].count, before[0].count + 1)
        self.assertEqual(after_race[1], before[1])
        self.assertFalse(
            any(
                record.schema_version == SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA
                and record.logical_type == "frozen_protocol"
                for record in after_race[0].records
            )
        )

        for name, limit, message in (
            (
                "_MAX_REVISION_BYTES",
                self.parent_protocol_record.size,
                "payload exceeds its byte bound",
            ),
            ("MAX_LEDGER_EVENTS", after_race[1].event_count, "event capacity"),
            ("MAX_LEDGER_BYTES", 1, "byte capacity"),
            ("MAX_REGISTRY_RECORDS", after_race[0].count, "registry capacity"),
        ):
            with self.subTest(limit=name), mock.patch.object(
                revision_module, name, limit
            ), self.assertRaisesRegex(ScientificProtocolRevisionError, message):
                stable = self.snapshot()
                self.publish()
            self.assertEqual(self.snapshot(), stable)

    def test_backdated_native_publication_refuses_with_zero_delta(self):
        before = self.snapshot()
        with mock.patch.object(
            revision_module,
            "utc_now",
            return_value="2000-01-01T00:00:00Z",
        ), self.assertRaisesRegex(
            ScientificProtocolRevisionError,
            "publication predates one of its exact sources",
        ):
            self.publish()
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(
            any(
                record.schema_version == SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA
                and record.logical_type == "frozen_protocol"
                for record in before[0].records
            )
        )

    def test_publication_ledger_cas_race_is_prewrite(self):
        before = self.snapshot()
        original_snapshot = revision_module._locked_checked_result_authority_snapshot
        calls = 0

        def drift_on_second_snapshot(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                state = self.ledger.assert_valid().events[-1].state_after
                self.ledger.record(
                    run_id=_RUN_ID,
                    actor_role=Role.ORCHESTRATOR,
                    state_before=state,
                    requested_state_after=state,
                    artifact_hashes=(),
                    code_version="NON_AUTHORIZING-test",
                    configuration_hash=self.child_contract.sha256,
                    reason="Real ledger append during protocol preflight.",
                    event_type="CHECKPOINT",
                    metadata={"fixture": "NON_AUTHORIZING ledger race"},
                )
            return original_snapshot(*args, **kwargs)

        with mock.patch.object(
            revision_module,
            "_locked_checked_result_authority_snapshot",
            side_effect=drift_on_second_snapshot,
        ), self.assertRaisesRegex(
            ScientificProtocolRevisionError, "changed during preflight"
        ):
            self.publish()
        after = self.snapshot()
        self.assertEqual(after[0], before[0])
        self.assertEqual(after[1].event_count, before[1].event_count + 1)
        self.assertFalse(
            any(
                record.schema_version == SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA
                and record.logical_type == "frozen_protocol"
                for record in after[0].records
            )
        )

    def test_readback_paired_snapshot_refuses_real_registry_race(self):
        publication = self.publish()
        before = self.snapshot()
        original_snapshot = revision_module._locked_checked_result_authority_snapshot
        calls = 0

        def append_during_exit_snapshot(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                _timeline_artifact(
                    self.registry,
                    b'{"race":"protocol readback append"}\n',
                    "protocol_revision_readback_race",
                    Role.EVIDENCE_CURATOR,
                )
            return original_snapshot(*args, **kwargs)

        with mock.patch.object(
            revision_module,
            "_locked_checked_result_authority_snapshot",
            side_effect=append_during_exit_snapshot,
        ), self.assertRaisesRegex(
            ScientificProtocolRevisionError, "changed during readback"
        ):
            require_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            )
        after = self.snapshot()
        self.assertEqual(after[0].count, before[0].count + 1)
        self.assertEqual(after[1], before[1])

    def test_exact_record_only_orphan_recovers_and_drift_refuses(self):
        original_append = self.ledger._append_locked
        with mock.patch.object(
            self.ledger,
            "_append_locked",
            side_effect=LedgerError("mechanical protocol event fault"),
        ):
            with self.assertRaises(LedgerError):
                self.publish()
        orphan = self.snapshot()
        self.assertEqual(orphan[1].event_count, 1)
        self.assertEqual(
            sum(
                record.logical_type == "frozen_protocol"
                and record.schema_version == SCIENTIFIC_PROTOCOL_REVISION_ARTIFACT_SCHEMA
                for record in orphan[0].records
            ),
            1,
        )
        with mock.patch.object(self.ledger, "_append_locked", original_append):
            recovered = self.publish()
        self.assertEqual(recovered.event_index, 1)

        second_contract = replace(
            self.child_contract,
            version=self.child_contract.version + 1,
            failure_criteria=("A second bounded contract-only change.",),
        )
        second_reason = "Create another exact recoverable protocol revision."
        second_amendment = register_evaluation_contract_amendment(
            self.registry,
            self.ledger,
            run_id=_RUN_ID,
            amendment_id="protocol-amendment-orphan-2",
            parent_contract_artifact_sha256=self.amendment.contract_record.sha256,
            child_contract=second_contract,
            author_id=self.parent_contract.frozen_by,
            reason=second_reason,
        )
        second_protocol = replace(
            recovered.protocol,
            study_version=recovered.protocol.study_version + 1,
            parent_protocol_hash=recovered.protocol.sha256,
            revision_reason=second_reason,
        )
        with mock.patch.object(
            self.ledger,
            "_append_locked",
            side_effect=LedgerError("second mechanical protocol event fault"),
        ):
            with self.assertRaises(LedgerError):
                register_scientific_protocol_revision(
                    self.registry,
                    self.ledger,
                    expected_run_id=_RUN_ID,
                    amendment_artifact_sha256=(
                        second_amendment.amendment_record.sha256
                    ),
                    parent_protocol_artifact_sha256=recovered.protocol_record.sha256,
                    protocol=second_protocol,
                )
        _timeline_artifact(
            self.registry,
            b'{"drift":"after protocol orphan"}\n',
            "protocol_revision_orphan_drift",
            Role.EVIDENCE_CURATOR,
        )
        before_retry = self.snapshot()
        with self.assertRaisesRegex(
            ScientificProtocolRevisionError,
            "incomplete protocol revision",
        ):
            register_scientific_protocol_revision(
                self.registry,
                self.ledger,
                expected_run_id=_RUN_ID,
                amendment_artifact_sha256=second_amendment.amendment_record.sha256,
                parent_protocol_artifact_sha256=recovered.protocol_record.sha256,
                protocol=second_protocol,
            )
        self.assertEqual(self.snapshot(), before_retry)


if __name__ == "__main__":
    unittest.main()
