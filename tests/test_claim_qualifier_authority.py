from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import runpy
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import scientist_one.research_state as research_state_module
from scientist_one.claims import (
    ClaimEvidenceUse,
    EvidenceKind as GraphEvidenceKind,
)
from scientist_one.errors import AuthorizationError, ValidationError
from scientist_one.research_state import (
    ScientificClaimQualifierAuthority,
    build_scientific_claim_qualifier_judgment_request,
    register_scientific_claim_evidence_projection,
    register_scientific_claim_qualifier_authority,
)
from scientist_one.roles import Role


def _load_state_fixture_helpers() -> dict[str, object]:
    """Load the frozen public Result-v2 fixture without importing a test package."""

    return runpy.run_path(str(Path(__file__).with_name("test_vnext_state.py")))


class ScientificClaimQualifierAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        helpers = _load_state_fixture_helpers()
        cls.source = helpers["_scientific_v2_source_fixture"](
            Path(cls.temporary.name)
        )
        cls.graph = helpers["_scientific_v2_state_graph"](cls.source)
        cls.materialized = cls.source[
            "repository"
        ].materialize_scientific_result_bundle(
            ancestors=cls.graph["ancestors"],
            result=cls.graph["result"],
            reason="focused qualifier boundary fixture",
        )
        cls.result_materialized = next(
            item
            for item in cls.materialized
            if item.research_object.object_type == "Result"
        )
        cls.run_materialized = next(
            item
            for item in cls.materialized
            if item.research_object.object_type == "Run"
        )
        cls.bundle_completion = next(
            item
            for item in cls.source["registry"].list_records()
            if item.logical_type == "scientific_result_state_bundle_completion"
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_non_evidentiary_result_cannot_mint_qualifier_authority(self) -> None:
        registry = self.source["registry"]
        ledger = self.source["ledger"]
        record_count = len(registry.list_records())
        event_count = ledger.assert_valid().event_count
        arguments = {
            "run_id": "global-run-1",
            "evidence_id": "scope-qualifier-fixture",
            "evidence_kind": GraphEvidenceKind.SCOPE_QUALIFIER,
            "claim_id": "claim-qualifier-fixture",
            "claim_text": "The bounded fixture result has a narrow scope.",
            "claim_producer_role": Role.EXPERIMENT_RUNNER,
            "claim_confirmatory": True,
            "claim_evidence_use": ClaimEvidenceUse.SCIENTIFIC,
            "assertion_text": "This conclusion is limited to the frozen fixture.",
            "result_state_artifact_hash": self.result_materialized.artifact.sha256,
        }

        with self.assertRaisesRegex(
            ValidationError,
            "scientifically eligible Result",
        ):
            build_scientific_claim_qualifier_judgment_request(
                registry,
                ledger,
                **arguments,
            )
        with self.assertRaisesRegex(
            ValidationError,
            "scientifically eligible Result",
        ):
            register_scientific_claim_qualifier_authority(
                registry,
                ledger,
                **arguments,
                semantic_judgment_artifact_hash="0" * 64,
            )
        self.assertEqual(len(registry.list_records()), record_count)
        self.assertEqual(ledger.assert_valid().event_count, event_count)

    def test_qualifier_replay_uses_cycle_free_scoped_state(self) -> None:
        """Later Claim replay must never re-enter whole-state validation."""

        registry = self.source["registry"]
        ledger = self.source["ledger"]
        arguments = {
            "run_id": "global-run-1",
            "evidence_id": "scope-qualifier-scoped-replay",
            "evidence_kind": GraphEvidenceKind.SCOPE_QUALIFIER,
            "claim_id": "claim-qualifier-scoped-replay",
            "claim_text": "The bounded result has a narrow scope.",
            "claim_producer_role": Role.EXPERIMENT_RUNNER,
            "claim_confirmatory": True,
            "claim_evidence_use": ClaimEvidenceUse.SCIENTIFIC,
            "assertion_text": "The scope is limited to the exact evaluated run.",
            "result_state_artifact_hash": self.result_materialized.artifact.sha256,
        }
        scoped_resolver = (
            research_state_module.resolve_current_research_state_bindings
        )
        with (
            patch.object(
                research_state_module,
                "resolve_current_research_state_bindings",
                wraps=scoped_resolver,
            ) as scoped,
            patch.object(
                research_state_module,
                "_require_canonical_state_source",
                side_effect=AssertionError(
                    "qualifier replay re-entered whole-state validation"
                ),
            ) as whole_state,
        ):
            with self.assertRaisesRegex(
                ValidationError,
                "scientifically eligible Result",
            ):
                build_scientific_claim_qualifier_judgment_request(
                    registry,
                    ledger,
                    **arguments,
                )
        scoped.assert_called_once_with(
            registry,
            ledger,
            run_id="global-run-1",
            state_artifact_hashes=(self.result_materialized.artifact.sha256,),
        )
        whole_state.assert_not_called()

    def test_all_claim_state_sources_use_cycle_free_scoped_replay(self) -> None:
        """Every canonical kind used by K must avoid later Claim recursion."""

        self.source["repository"].materialize_scientific_result_bundle(
            ancestors=self.graph["ancestors"],
            result=self.graph["result"],
            statistical_test=self.graph["statistical_test"],
            reason="complete scoped ClaimSemantics source fixture",
        )
        targets = {
            item.research_object.object_type: item
            for item in self.source["repository"]._stored_objects()
            if item.research_object.object_type
            in {
                "Hypothesis",
                "Dataset",
                "Implementation",
                "Experiment",
                "Run",
                "Result",
                "StatisticalTest",
            }
        }
        self.assertEqual(
            set(targets),
            {
                "Hypothesis",
                "Dataset",
                "Implementation",
                "Experiment",
                "Run",
                "Result",
                "StatisticalTest",
            },
        )
        with patch.object(
            research_state_module,
            "_require_canonical_state_source",
            side_effect=AssertionError(
                "ClaimSemantics source re-entered whole-state validation"
            ),
        ) as whole_state:
            for object_type, target in sorted(targets.items()):
                record, _resolved, _by_content, _repository = (
                    research_state_module._require_scoped_canonical_state_source(
                        self.source["registry"],
                        self.source["ledger"],
                        run_id="global-run-1",
                        state_artifact_hash=target.artifact.sha256,
                    )
                )
                self.assertEqual(record.object_type, object_type)
        whole_state.assert_not_called()

    def test_direct_result_and_extra_parent_qualifiers_are_inert(self) -> None:
        registry = self.source["registry"]
        ledger = self.source["ledger"]
        common = {
            "claim_id": "claim-qualifier-direct-parent",
            "claim_text": "The exact bounded result has one stated limitation.",
            "producer_role": Role.EXPERIMENT_RUNNER,
        }
        direct = register_scientific_claim_evidence_projection(
            registry,
            evidence_id="limitation-direct-result",
            evidence_kind=GraphEvidenceKind.LIMITATION,
            source_artifact_hashes=(self.result_materialized.artifact.sha256,),
            **common,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "lacks source-owned qualifier authority",
        ):
            research_state_module._require_scientific_state_evidence_source(
                registry,
                ledger,
                run_id="global-run-1",
                evidence_kind=GraphEvidenceKind.LIMITATION,
                evidence_artifact=direct,
                evidence_id="limitation-direct-result",
                claim_id=common["claim_id"],
                claim_text=common["claim_text"],
                claim_producer_role=common["producer_role"],
                claim_confirmatory=True,
                claim_evidence_use=ClaimEvidenceUse.SCIENTIFIC,
                assertion_text="The direct Result label is not qualifier authority.",
            )

        fake_authority = registry.put_json(
            {"caller_asserted": "scientific qualifier authority"},
            logical_type="scientific_claim_qualifier_authority",
            origin="caller-labelled qualifier authority",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            creation_command=("scientist-one", "qualifier-boundary-test"),
            parent_artifacts=(
                self.result_materialized.artifact.sha256,
                self.run_materialized.artifact.sha256,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        extra_parent = register_scientific_claim_evidence_projection(
            registry,
            evidence_id="limitation-extra-parent",
            evidence_kind=GraphEvidenceKind.LIMITATION,
            source_artifact_hashes=(
                fake_authority.sha256,
                self.result_materialized.artifact.sha256,
            ),
            **common,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "exactly one qualifier authority parent",
        ):
            research_state_module._require_scientific_state_evidence_source(
                registry,
                ledger,
                run_id="global-run-1",
                evidence_kind=GraphEvidenceKind.LIMITATION,
                evidence_artifact=extra_parent,
                evidence_id="limitation-extra-parent",
                claim_id=common["claim_id"],
                claim_text=common["claim_text"],
                claim_producer_role=common["producer_role"],
                claim_confirmatory=True,
                claim_evidence_use=ClaimEvidenceUse.SCIENTIFIC,
                assertion_text="An extra parent cannot be hidden.",
            )

    def test_coarse_slot_collides_semantic_and_completion_variants(self) -> None:
        """This structural fixture test creates no scientific authority."""

        source = research_state_module._ScientificClaimQualifierSource(
            result=self.graph["result"],
            result_artifact=self.result_materialized.artifact,
            result_event=SimpleNamespace(
                event_id="result-materialization-schema",
                event_hash="1" * 64,
            ),
            execution_run=self.graph["run"],
            run_artifact=self.run_materialized.artifact,
            run_event=SimpleNamespace(
                event_id="run-materialization-schema",
                event_hash="2" * 64,
            ),
            bundle_completion_artifact=self.bundle_completion,
            bundle_completion_event=SimpleNamespace(
                event_id="bundle-completion-schema",
                event_hash="3" * 64,
            ),
            bundle_completion_event_index=42,
            bundle_statistical_test_id=None,
            source_closure=(),
        )
        subject_one, projection_one = (
            research_state_module._scientific_claim_qualifier_projection(
                run_id="global-run-1",
                evidence_id="scope-favorable",
                evidence_kind=GraphEvidenceKind.SCOPE_QUALIFIER,
                claim_id="claim-coarse-qualifier-slot",
                claim_text="A broad caller-authored claim.",
                claim_producer_role=Role.EXPERIMENT_RUNNER,
                claim_confirmatory=False,
                claim_evidence_use=ClaimEvidenceUse.NON_EVIDENTIARY,
                assertion_text="The favorable qualifier assertion.",
                source=source,
            )
        )
        subject_two, projection_two = (
            research_state_module._scientific_claim_qualifier_projection(
                run_id="global-run-1",
                evidence_id="scope-favorable",
                evidence_kind=GraphEvidenceKind.SCOPE_QUALIFIER,
                claim_id="claim-coarse-qualifier-slot",
                claim_text="A broad caller-authored claim.",
                claim_producer_role=Role.EXPERIMENT_RUNNER,
                claim_confirmatory=True,
                claim_evidence_use=ClaimEvidenceUse.SCIENTIFIC,
                assertion_text="The favorable qualifier assertion.",
                source=source,
            )
        )
        self.assertEqual(subject_one, subject_two)
        self.assertNotEqual(projection_one, projection_two)

        subject_variant, projection_variant = (
            research_state_module._scientific_claim_qualifier_projection(
                run_id="global-run-1",
                evidence_id="scope-restrictive",
                evidence_kind=GraphEvidenceKind.SCOPE_QUALIFIER,
                claim_id="claim-coarse-qualifier-slot",
                claim_text="A differently worded caller-authored claim.",
                claim_producer_role=Role.EXPERIMENT_RUNNER,
                claim_confirmatory=False,
                claim_evidence_use=ClaimEvidenceUse.NON_EVIDENTIARY,
                assertion_text="The restrictive qualifier assertion.",
                source=source,
            )
        )
        self.assertEqual(subject_one, subject_variant)
        self.assertNotEqual(projection_one, projection_variant)

        self.source["repository"].materialize_scientific_result_bundle(
            ancestors=self.graph["ancestors"],
            result=self.graph["result"],
            statistical_test=self.graph["statistical_test"],
            reason="extend focused qualifier fixture with StatisticalTest",
        )
        changed_completion = next(
            item
            for item in self.source["registry"].list_records()
            if item.logical_type == "scientific_result_state_bundle_completion"
            and json.loads(self.source["registry"].get_bytes(item.sha256))[
                "statistical_test_id"
            ]
            == self.graph["statistical_test"].object_id
        )
        completion_event_id = f"rsb-{changed_completion.sha256[:48]}"
        completion_event_index, completion_event = next(
            (index, event)
            for index, event in enumerate(self.source["ledger"].events())
            if event.event_id == completion_event_id
        )
        stored = self.source["repository"]._stored_objects()
        by_content, _by_identity = self.source["repository"]._indexes(stored)
        current_completion = self.source[
            "repository"
        ]._require_scientific_result_bundle_completion(
            self.graph["result"],
            by_content,
            promotion_record=self.source["candidate"]["receipt_record"],
            expected_scientific_evidence_eligible=False,
        )
        self.assertEqual(current_completion.sha256, changed_completion.sha256)
        self.assertNotEqual(current_completion.sha256, self.bundle_completion.sha256)
        extended_source = replace(
            source,
            bundle_completion_artifact=changed_completion,
            bundle_completion_event=completion_event,
            bundle_completion_event_index=completion_event_index,
            bundle_statistical_test_id=self.graph["statistical_test"].object_id,
        )
        subject_three, projection_three = (
            research_state_module._scientific_claim_qualifier_projection(
                run_id="global-run-1",
                evidence_id="scope-favorable",
                evidence_kind=GraphEvidenceKind.SCOPE_QUALIFIER,
                claim_id="claim-coarse-qualifier-slot",
                claim_text="A broad caller-authored claim.",
                claim_producer_role=Role.EXPERIMENT_RUNNER,
                claim_confirmatory=False,
                claim_evidence_use=ClaimEvidenceUse.NON_EVIDENTIARY,
                assertion_text="The favorable qualifier assertion.",
                source=extended_source,
            )
        )
        self.assertEqual(subject_one, subject_three)
        self.assertNotEqual(projection_one, projection_three)

    def test_authority_value_rejects_wrong_kind_role_and_closure_lengths(self) -> None:
        common = {
            "run_id": "global-run-1",
            "subject_id": "claim-qualifier-" + "a" * 64,
            "evidence_id": "qualifier-value",
            "evidence_kind": GraphEvidenceKind.SCOPE_QUALIFIER,
            "claim_id": "claim-qualifier-value",
            "claim_text": "The exact result has one bounded scope.",
            "claim_producer_role": Role.EXPERIMENT_RUNNER,
            "claim_confirmatory": True,
            "claim_evidence_use": ClaimEvidenceUse.SCIENTIFIC,
            "assertion_text": "The scope is bounded to the evaluated run.",
            "qualifier_projection_sha256": "b" * 64,
            "result_id": "result-1",
            "result_content_hash": "c" * 64,
            "result_state_artifact_hash": "d" * 64,
            "result_state_record_hash": "e" * 64,
            "result_materialization_event_id": "result-event-1",
            "result_materialization_event_hash": "f" * 64,
            "execution_run_id": "run-1",
            "run_content_hash": "1" * 64,
            "run_state_artifact_hash": "2" * 64,
            "run_state_record_hash": "3" * 64,
            "run_materialization_event_id": "run-event-1",
            "run_materialization_event_hash": "4" * 64,
            "bundle_completion_artifact_hash": "5" * 64,
            "bundle_completion_record_hash": "6" * 64,
            "bundle_completion_event_id": "bundle-event-1",
            "bundle_completion_event_hash": "7" * 64,
            "bundle_completion_event_index": 10,
            "bundle_statistical_test_id": None,
            "source_artifact_hashes": ("8" * 64, "9" * 64),
            "source_artifact_record_hashes": ("a" * 64, "b" * 64),
            "semantic_judgment_artifact_hash": "c" * 64,
            "semantic_judgment_record_hash": "d" * 64,
            "authority_artifact_hash": "e" * 64,
            "authority_record_hash": "f" * 64,
        }
        with self.assertRaisesRegex(ValidationError, "scope or limitation"):
            ScientificClaimQualifierAuthority(
                **{**common, "evidence_kind": GraphEvidenceKind.RESULT}
            )
        with self.assertRaises(AuthorizationError):
            ScientificClaimQualifierAuthority(
                **{**common, "claim_producer_role": Role.CLAIM_VERIFIER}
            )
        with self.assertRaisesRegex(
            ValidationError,
            "artifacts and record hashes differ",
        ):
            ScientificClaimQualifierAuthority(
                **{**common, "source_artifact_record_hashes": ("7" * 64,)}
            )


if __name__ == "__main__":
    unittest.main()
