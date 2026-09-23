"""Execution-protocol lineage controls, never scientific execution evidence.

The legitimate control uses the existing mechanical producer and public
canonical/Hypothesis owners.  No execution verifier is installed or replaced,
and no positive scientific Run is manufactured.  Direct private-helper calls
test protocol/lineage comparisons only; the public Run owner still rejects
this non-evidentiary fixture.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import scientist_one.research_state as state
from scientist_one.errors import ValidationError
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
from tests.test_hypothesis_evaluation_and_rejections import _mechanical_v2_source
from tests.test_vnext_state import _scientific_v2_state_graph, _timestamp_after


class ScientificExecutionRunLineageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.source = _mechanical_v2_source(Path(cls.directory.name))
        cls.graph = _scientific_v2_state_graph(cls.source)
        cls.repository = cls.source["repository"]
        cls.registry = cls.source["registry"]
        cls.ledger = cls.source["ledger"]
        materialized = cls.repository.materialize_scientific_result_bundle(
            ancestors=cls.graph["ancestors"],
            result=cls.graph["result"],
            statistical_test=cls.graph["statistical_test"],
        )
        cls.materialized = {
            item.research_object.object_type: item for item in materialized
        }
        cls.before_evaluation = cls.ledger.events()
        cls.before_evaluation_stored = cls.repository._stored_objects()
        authority_record = state.register_hypothesis_evaluation_authority(
            cls.registry,
            cls.ledger,
            authority_id="mechanical-run-lineage-evaluation",
            run_id=cls.repository.run_id,
            prior_hypothesis_state_artifact_hash=(
                cls.materialized["Hypothesis"].artifact.sha256
            ),
            result_state_artifact_hash=cls.materialized["Result"].artifact.sha256,
            statistical_test_state_artifact_hash=(
                cls.materialized["StatisticalTest"].artifact.sha256
            ),
            evaluation_contract_artifact_hash=(
                cls.source["values"]["contract_record"].sha256
            ),
            evaluated_at=_timestamp_after(cls.ledger.events()[-1].timestamp, 1),
        )
        cls.hypothesis_authority = state.require_hypothesis_evaluation_authority(
            cls.registry,
            cls.ledger,
            authority_artifact_hash=authority_record.sha256,
            expected_run_id=cls.repository.run_id,
        )
        successor = state.build_evaluated_hypothesis_revision(
            cls.registry,
            cls.ledger,
            authority_artifact_hash=authority_record.sha256,
            expected_run_id=cls.repository.run_id,
            prior_hypothesis=cls.graph["hypothesis"],
            created_at=_timestamp_after(cls.ledger.events()[-1].timestamp, 1),
        )
        cls.successor = cls.repository.materialize(successor)

    def setUp(self) -> None:
        self.records_before = self.registry.verify_all(raise_on_error=True)
        self.ledger_before = self.ledger.validate(raise_on_error=True)
        self.by_content, _ = self.repository._indexes(
            self.repository._stored_objects()
        )
        spec = self.source["values"]["spec"]
        run = self.graph["run"]
        self.protocol = state._ScientificExecutionProtocolContext(
            contract_artifact_sha256=(
                self.source["values"]["contract_record"].sha256
            ),
            frozen_run_spec_artifact_sha256=run.output_artifact_hashes[0],
            output_manifest_artifact_sha256=run.output_artifact_hashes[1],
            raw_source_artifact_hashes=run.output_artifact_hashes[2:],
            run_id=run.object_id,
            experiment_id=spec.experiment_id,
            hypothesis_id=spec.hypothesis_id,
            execution_code_revision=run.code_revision,
            run_started_at=run.started_at,
            run_completed_at=run.completed_at,
        )

    def tearDown(self) -> None:
        self.assertEqual(
            self.registry.verify_all(raise_on_error=True), self.records_before
        )
        self.assertEqual(
            self.ledger.validate(raise_on_error=True), self.ledger_before
        )

    def _protocol_replay(self, by_content=None) -> None:
        state._require_scientific_execution_protocol_lineage(
            self.repository,
            run=self.graph["run"],
            protocol_source=self.protocol,
            by_content=self.by_content if by_content is None else by_content,
        )

    def _validated_event_alias(self, item, **changes):
        original = self.repository._materialization_event(
            item.artifact.sha256, item.research_object
        )
        self.assertIsNotNone(original)
        return self._validated_appended_event(original, **changes)

    def _validated_appended_event(self, original, **changes):
        events = self.ledger.events()
        alias = replace(
            original,
            event_id="non-evidentiary-materialization-alias",
            prior_event_hash=events[-1].event_hash,
            event_hash=None,
            **changes,
        )
        vector = (*events, alias)
        validation = EventLedger._validate_bytes(
            b"".join(canonical_json_bytes(event.to_dict()) + b"\n" for event in vector)
        )
        self.assertTrue(validation.valid, validation.error)
        self.assertEqual(validation.events, vector)
        return vector

    def test_duplicate_semantic_materialization_is_rejected_for_each_ancestor(
        self,
    ) -> None:
        for object_type in (
            "Run", "Experiment", "Implementation", "Method", "Hypothesis",
            "Dataset", "Split", "Metric", "Baseline",
        ):
            item = next(
                item for item in self.by_content.values()
                if item.research_object.object_type == object_type
                and item.research_object.revision == 1
            )
            vector = self._validated_event_alias(item)
            with (
                self.subTest(object_type=object_type),
                patch.object(self.ledger, "events", return_value=vector),
                self.assertRaisesRegex(ValidationError, "exact materialization"),
            ):
                self._protocol_replay()

    def test_successor_parent_materialization_alias_is_rejected(self) -> None:
        for object_type in ("Result", "StatisticalTest"):
            item = next(
                item for item in self.by_content.values()
                if item.research_object.object_type == object_type
            )
            vector = self._validated_event_alias(item)
            with (
                self.subTest(object_type=object_type),
                patch.object(self.ledger, "events", return_value=vector),
                self.assertRaisesRegex(ValidationError, "exact materialization"),
            ):
                self._protocol_replay()

    def test_successor_parent_correction_invalidates_historical_exception(self) -> None:
        for object_type in ("Result", "StatisticalTest"):
            item = next(
                item for item in self.by_content.values()
                if item.research_object.object_type == object_type
            )
            original = self.repository._materialization_event(
                item.artifact.sha256, item.research_object
            )
            vector = self._validated_event_alias(
                item,
                event_type="CORRECTION",
                supersedes_event_id=original.event_id,
                metadata={"kind": "NON_EVIDENTIARY_EVALUATION_SOURCE_CORRECTION"},
            )
            with (
                self.subTest(object_type=object_type),
                patch.object(self.ledger, "events", return_value=vector),
                self.assertRaisesRegex(ValidationError, "successor parent.*corrected"),
            ):
                self._protocol_replay()

    def test_successor_parent_revision_invalidates_historical_exception(self) -> None:
        # Inert inventory additions exercise the same no-extra-revision rule
        # as the public Hypothesis source owner.  Nothing is registered, and
        # neither this graph nor the extra revision is scientific evidence.
        for object_type in ("Result", "StatisticalTest"):
            item = next(
                item for item in self.by_content.values()
                if item.research_object.object_type == object_type
            )
            revised = replace(
                item.research_object,
                revision=2,
                supersedes_content_hash=item.research_object.content_hash,
                created_at=_timestamp_after(self.ledger.events()[-1].timestamp, 1),
                content_hash=None,
            )
            by_content = dict(self.by_content)
            by_content[revised.content_hash] = replace(item, research_object=revised)
            with self.subTest(object_type=object_type), self.assertRaisesRegex(
                ValidationError, "successor parent.*stale or revised"
            ):
                self._protocol_replay(by_content)

    def test_successor_materialization_alias_is_rejected(self) -> None:
        # The alias corrects r2, not r1; checking only r1's one authorized
        # correction therefore cannot detect this duplicate r2 materialization.
        event = self.repository._materialization_event(
            self.successor.artifact.sha256, self.successor.research_object
        )
        vector = self._validated_event_alias(
            self.successor, supersedes_event_id=event.event_id
        )
        with (
            patch.object(self.ledger, "events", return_value=vector),
            self.assertRaisesRegex(ValidationError, "exact materialization"),
        ):
            self._protocol_replay()

    def test_approved_successor_requires_exact_registry_custody(self) -> None:
        successor = self.successor.research_object
        original = self.by_content[successor.content_hash]
        for changes in (
            {"parent_artifacts": ()},
            {"origin": "non-evidentiary-substituted-origin"},
            {"creation_command": ("non-evidentiary-substituted-command",)},
        ):
            by_content = dict(self.by_content)
            by_content[successor.content_hash] = replace(
                original,
                artifact=replace(original.artifact, record_hash=None, **changes),
            )
            with self.subTest(changes=changes), self.assertRaisesRegex(
                ValidationError, "successor.*(parents|metadata)"
            ):
                self._protocol_replay(by_content)

    def test_corrected_successor_cannot_authorize_historical_revision(self) -> None:
        vector = self._validated_event_alias(
            self.successor,
            supersedes_event_id=self.successor.event.event_id,
            metadata={"kind": "NON_EVIDENTIARY_SUCCESSOR_CORRECTION"},
        )
        with (
            patch.object(self.ledger, "events", return_value=vector),
            self.assertRaisesRegex(ValidationError, "successor.*corrected"),
        ):
            self._protocol_replay()

    def test_non_materializing_artifact_reference_remains_allowed(self) -> None:
        method = next(
            item for item in self.by_content.values()
            if isinstance(item.research_object, state.Method)
        )
        vector = self._validated_event_alias(
            method, metadata={"kind": "NON_EVIDENTIARY_ARTIFACT_REFERENCE"}
        )
        with patch.object(self.ledger, "events", return_value=vector):
            self._protocol_replay()

    def test_historical_evaluation_event_must_remain_unique_and_uncorrected(
        self,
    ) -> None:
        original = next(
            event for event in self.ledger.events()
            if event.event_id == self.hypothesis_authority.evaluation_event_id
        )
        for changes in (
            {},
            {
                "event_type": "CORRECTION",
                "supersedes_event_id": original.event_id,
                "metadata": {"kind": "NON_EVIDENTIARY_EVALUATION_CORRECTION"},
            },
        ):
            vector = self._validated_appended_event(original, **changes)
            with (
                self.subTest(kind="correction" if changes else "slot-alias"),
                patch.object(self.ledger, "events", return_value=vector),
                self.assertRaisesRegex(ValidationError, "evaluation.*(ambiguous|corrected)"),
            ):
                self._protocol_replay()

    def test_materialized_protocol_replays_without_downstream_result_discovery(
        self,
    ) -> None:
        self.assertTrue(
            any(isinstance(item.research_object, state.Result)
                for item in self.by_content.values())
        )
        with (
            patch.object(
                self.repository,
                "_resolve_scientific_result_ancestor_authority",
                side_effect=AssertionError("downstream Result discovery is forbidden"),
            ),
            patch.object(
                self.repository,
                "_resolve_object_authority",
                side_effect=AssertionError("general semantic replay is forbidden"),
            ),
            patch.object(
                state,
                "require_hypothesis_evaluation_authority",
                side_effect=AssertionError("historical r1 must not replay r2 semantics"),
            ),
        ):
            self.assertIsNone(self._protocol_replay())
        self.assertFalse(self.hypothesis_authority.scientific_evidence_eligible)
        self.assertIs(
            self.hypothesis_authority.evidence_scope,
            state.HypothesisEvaluationEvidenceScope.NON_EVIDENTIARY_MECHANICAL,
        )

    def test_existing_approved_hypothesis_successor_remains_historical(self) -> None:
        prior = self.graph["hypothesis"]
        revisions = tuple(
            item.research_object
            for item in self.by_content.values()
            if isinstance(item.research_object, state.Hypothesis)
            and item.research_object.object_id == prior.object_id
        )
        successor = self.repository._source_bound_hypothesis_evaluation_successor(
            prior, revisions, self.by_content, self.ledger.events()
        )
        self.assertIsNotNone(successor)
        self.assertEqual(successor.artifact, self.successor.artifact)
        self.assertEqual(successor.research_object, self.successor.research_object)
        self._protocol_replay()
        self.assertTrue(self.repository.validate_state().valid)

    def test_unapproved_hypothesis_successor_cannot_relax_current_lineage(self) -> None:
        successor = self.successor.research_object
        altered = replace(
            successor,
            hypothesis_status=state.HypothesisStatus.FALSIFIED,
            content_hash=None,
        )
        by_content = dict(self.by_content)
        stored = by_content.pop(successor.content_hash)
        by_content[altered.content_hash] = replace(stored, research_object=altered)
        with self.assertRaisesRegex(ValidationError, "stale or revised"):
            self._protocol_replay(by_content)

    def test_protocol_comparison_does_not_require_a_result_or_statistical_test(
        self,
    ) -> None:
        # Use the actual canonical materialization prefix ending at Run.  This
        # private comparison is not a public current-state/scientific authority.
        run_event = self.repository._materialization_event(
            self.materialized["Run"].artifact.sha256, self.graph["run"]
        )
        run_index = next(
            index for index, event in enumerate(self.before_evaluation)
            if event.event_id == run_event.event_id
        )
        before_result = tuple(
            item for item in self.before_evaluation_stored
            if not isinstance(item.research_object, (state.Result, state.StatisticalTest))
        )
        by_content, _ = self.repository._indexes(before_result)
        with patch.object(
            self.ledger, "events", return_value=self.before_evaluation[:run_index + 1]
        ):
            self._protocol_replay(by_content)

    def test_mechanical_run_cannot_gain_execution_scope_from_protocol_replay(
        self,
    ) -> None:
        self._protocol_replay()
        with (
            patch.object(
                state,
                "_resolve_current_research_state_bindings",
                side_effect=AssertionError("scientific Run must not use general replay"),
            ),
            self.assertRaisesRegex(ValidationError, "current scientific execution"),
        ):
            state.require_current_scientific_execution_run(
                self.registry,
                self.ledger,
                run_id=self.repository.run_id,
                run_state_artifact_sha256=self.materialized["Run"].artifact.sha256,
                expected_execution_run_id=self.graph["run"].object_id,
            )

    def test_wrong_run_context_and_unpublished_target_fail_closed(self) -> None:
        for run_id, target, expected in (
            ("another-ledger", self.materialized["Run"].artifact.sha256,
             self.graph["run"].object_id),
            (self.repository.run_id, self.materialized["Run"].artifact.sha256,
             "another-execution"),
            (self.repository.run_id, self.source["values"]["spec_record"].sha256,
             self.graph["run"].object_id),
        ):
            with self.subTest(run_id=run_id, target=target, expected=expected):
                with self.assertRaises(ValidationError):
                    state.require_current_scientific_execution_run(
                        self.registry,
                        self.ledger,
                        run_id=run_id,
                        run_state_artifact_sha256=target,
                        expected_execution_run_id=expected,
                    )

    def test_shared_protocol_rejects_coherently_relinked_semantic_splices(self) -> None:
        # Inert prospective records are only comparison inputs here.  No
        # substituted canonical bytes, verdict, or owner are admitted.
        split_id = self.source["values"]["contract"].dataset.confirmatory_split_id
        cases = (
            {"Hypothesis": {"prediction": "a substituted prediction"}},
            {"Experiment": {"scientific_purpose": "a substituted purpose"}},
            {"Method": {"name": "a substituted method"}},
            {"Implementation": {
                "code_revision": "another-revision", "code_version": "another-revision"
            }},
            {"Dataset": {"version": "another-dataset-version"}},
            {f"Split:{split_id}": {"unit_type": "invented-independent-unit"}},
            {"Experiment": {"seed_policy": {"seeds": [999]}}},
        )
        for mutations in cases:
            with self.subTest(mutations=mutations):
                graph = _scientific_v2_state_graph(self.source, mutations)
                records = self.repository._prospective_scientific_bundle_artifacts(
                    graph["ancestors"]
                )
                stored = tuple(
                    state._StoredObject(item, records[item.content_hash])
                    for item in graph["ancestors"]
                )
                by_content, _ = self.repository._indexes(stored)
                with self.assertRaises(ValidationError):
                    self.repository._validate_scientific_protocol_parent_join(
                        run=graph["run"],
                        protocol_source=self.protocol,
                        by_content=by_content,
                        require_materialized_lineage=False,
                    )

    def test_result_only_baseline_and_primary_metric_checks_remain_required(
        self,
    ) -> None:
        projection = self.source["projection"].result_state_projection
        metric = next(item for item in self.graph["metrics"]
                      if item.object_id == projection.metric_id)
        for changes in (
            {"baseline_id": "a-baseline-outside-the-contract"},
            {"metric_id": "a-metric-outside-the-contract"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                self.repository._validate_scientific_result_parent_join(
                    record=self.graph["result"],
                    run=self.graph["run"],
                    metric=metric,
                    result_projection=replace(projection, **changes),
                    by_content=self.by_content,
                )

    def test_missing_or_substituted_materialization_lineage_is_rejected(self) -> None:
        run = self.graph["run"]
        stored_run = self.by_content[run.content_hash]
        missing = dict(self.by_content)
        missing.pop(run.content_hash)
        substituted = dict(self.by_content)
        substituted[run.content_hash] = replace(
            stored_run,
            artifact=replace(stored_run.artifact, parent_artifacts=(), record_hash=None),
        )
        for by_content in (missing, substituted):
            with self.subTest(kind="missing" if by_content is missing else "parents"):
                with self.assertRaises(ValidationError):
                    self._protocol_replay(by_content)

    def test_non_lineage_correction_is_rejected_without_result_replay(self) -> None:
        run = self.graph["run"]
        event = self.repository._materialization_event(
            self.materialized["Run"].artifact.sha256, run
        )
        events = self.ledger.events()
        correction = LedgerEvent.create(
            run_id=self.repository.run_id,
            actor_role=Role.SCIENTIFIC_REVIEWER,
            state_before=events[-1].requested_state_after,
            requested_state_after=events[-1].requested_state_after,
            artifact_hashes=(self.materialized["Run"].artifact.sha256,),
            code_version=self.repository.code_version,
            configuration_hash=self.repository.configuration_hash,
            reason="non-evidentiary in-memory correction injection",
            event_id="lineage-negative-correction",
            timestamp=_timestamp_after(events[-1].timestamp, 1),
            event_type="CORRECTION",
            supersedes_event_id=event.event_id,
            prior_event_hash=events[-1].event_hash,
        )
        # This event is not published; only the historical-lineage predicate
        # receives the adverse event vector, with no authority PASS stub.
        with (
            patch.object(self.ledger, "events", return_value=(*events, correction)),
            self.assertRaisesRegex(ValidationError, "materialization was corrected"),
        ):
            self._protocol_replay()


if __name__ == "__main__":
    unittest.main()
