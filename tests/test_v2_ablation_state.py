from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import json
from pathlib import Path
import tempfile
import unittest

import scientist_one.research_state as research_state_module
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.claims import (
    ClaimEvidenceUse,
    EvidenceKind as GraphEvidenceKind,
)
from scientist_one.errors import ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.research_os import run_research_os_fixture
from scientist_one.research_state import (
    Ablation,
    ObjectReference,
    RecordStatus,
    ResearchStateRepository,
    register_scientific_claim_evidence_projection,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    ScientificAblationAuthority,
    ScientificPromotionError,
    register_scientific_ablation_authority,
    scientific_ablation_component_id,
)

try:
    from .test_research_os_e2e import _copy_fixture_tree
    from .test_vnext_state import (
        SCIENTIFIC_V2_STATE_CODE_VERSION,
        _scientific_v2_source_fixture,
        _scientific_v2_state_graph,
        _timestamp_after,
    )
except ImportError:  # pragma: no cover - direct unittest discovery fallback.
    from test_research_os_e2e import _copy_fixture_tree  # type: ignore[no-redef]
    from test_vnext_state import (  # type: ignore[no-redef]
        SCIENTIFIC_V2_STATE_CODE_VERSION,
        _scientific_v2_source_fixture,
        _scientific_v2_state_graph,
        _timestamp_after,
    )


class ScientificAblationStateTests(unittest.TestCase):
    def _materialized_v2_source(self, root: Path) -> dict[str, object]:
        source = _scientific_v2_source_fixture(root)
        graph = _scientific_v2_state_graph(source)
        repository: ResearchStateRepository = source["repository"]  # type: ignore[assignment]
        materialized = repository.materialize_scientific_result_bundle(
            ancestors=graph["ancestors"],  # type: ignore[arg-type]
            result=graph["result"],  # type: ignore[arg-type]
            statistical_test=graph["statistical_test"],  # type: ignore[arg-type]
            reason="materialize the exact v2 state before ablation review",
        )
        state_by_type = {
            item.research_object.object_type: item for item in materialized
        }
        return {
            **source,
            "graph": graph,
            "state_by_type": state_by_type,
        }

    @staticmethod
    def _registration_arguments(source: dict[str, object]) -> dict[str, object]:
        values = source["values"]
        candidate = source["candidate"]
        state_by_type = source["state_by_type"]
        contract = values["contract"]
        ablation_spec = contract.ablations[0]
        ablation_records = values["ablation_records"]
        matches = tuple(
            item
            for item in ablation_records
            if json.loads(values["registry"].get_bytes(item.sha256))[
                "ablation_id"
            ]
            == ablation_spec.ablation_id
        )
        if len(matches) != 1:
            raise AssertionError("fixture lacks one exact raw ablation output")
        return {
            "expected_ledger_run_id": "global-run-1",
            "expected_execution_run_id": "confirmatory-run-1",
            "expected_ablation_id": ablation_spec.ablation_id,
            "contract_artifact_sha256": values["contract_record"].sha256,
            "checked_superiority_receipt_artifact_sha256": candidate[
                "checked_record"
            ].sha256,
            "scientific_result_promotion_receipt_artifact_sha256": candidate[
                "receipt_record"
            ].sha256,
            "aggregate_result_artifact_sha256": values[
                "aggregate_record"
            ].sha256,
            "ablation_output_artifact_sha256": matches[0].sha256,
            "result_state_artifact_sha256": state_by_type["Result"].artifact.sha256,
            "run_state_artifact_sha256": state_by_type["Run"].artifact.sha256,
            "method_state_artifact_sha256": state_by_type["Method"].artifact.sha256,
            "experiment_state_artifact_sha256": state_by_type[
                "Experiment"
            ].artifact.sha256,
        }

    def test_v2_ablation_materializes_exact_structure_but_cannot_promote(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-v2-ablation-state-"
        ) as raw_root:
            source = self._materialized_v2_source(Path(raw_root))
            registry: ArtifactRegistry = source["registry"]  # type: ignore[assignment]
            ledger: EventLedger = source["ledger"]  # type: ignore[assignment]
            repository: ResearchStateRepository = source["repository"]  # type: ignore[assignment]
            values = source["values"]
            contract = values["contract"]
            ablation_spec = contract.ablations[0]
            secondary_hypotheses = tuple(
                item
                for item in contract.hypothesis_register.hypotheses
                if item.hypothesis_id != ablation_spec.hypothesis_id
            )
            self.assertEqual(len(secondary_hypotheses), 1)
            secondary_hypothesis = secondary_hypotheses[0]
            self.assertNotEqual(
                secondary_hypothesis.planned_experiment,
                contract.hypothesis_register.primary.planned_experiment,
            )
            arguments = self._registration_arguments(source)

            authority_record = register_scientific_ablation_authority(
                registry,
                ledger,
                **arguments,  # type: ignore[arg-type]
            )
            authority = ScientificAblationAuthority.from_dict(
                json.loads(registry.get_bytes(authority_record.sha256))
            )
            expected_component_id = scientific_ablation_component_id(
                ablation_spec.ablation_id,
                ablation_spec.component_changed,
            )
            self.assertEqual(authority.component_id, expected_component_id)
            self.assertFalse(authority.scientific_evidence_eligible)
            self.assertEqual(
                tuple(item.object_type for item in authority.state_bindings),
                ("Result", "Run", "Method", "Experiment"),
            )

            method = source["state_by_type"]["Method"].research_object
            experiment = source["state_by_type"]["Experiment"].research_object
            result = source["state_by_type"]["Result"].research_object
            self.assertEqual(
                method.component_ids,
                tuple(
                    scientific_ablation_component_id(
                        item.ablation_id,
                        item.component_changed,
                    )
                    for item in contract.ablations
                ),
            )
            created_after = max(
                (
                    ledger.assert_valid().events[-1].timestamp,
                    authority_record.created_at,
                ),
                key=lambda value: datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                ),
            )
            ablation = Ablation(
                object_id=ablation_spec.ablation_id,
                producer=Role.STATISTICIAN,
                status=RecordStatus.COMPLETE,
                created_at=_timestamp_after(created_after, 1),
                code_version=SCIENTIFIC_V2_STATE_CODE_VERSION,
                authority_artifact_hashes=(authority_record.sha256,),
                parents=(
                    ObjectReference(
                        "Experiment",
                        experiment.object_id,
                        experiment.content_hash,
                        "ablates",
                        True,
                    ),
                    ObjectReference(
                        "Result",
                        result.object_id,
                        result.content_hash,
                        "evaluates",
                        True,
                    ),
                ),
                hypothesis_id=ablation_spec.hypothesis_id,
                experiment_ids=(experiment.object_id,),
                removed_component_ids=(expected_component_id,),
                result_ids=(result.object_id,),
            )

            registry_count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            # Merely being registered by the same Evaluation Contract does not
            # put the secondary hypothesis in the primary Result's Experiment.
            # The primary ablation authority therefore cannot be relabelled as
            # evidence for that distinct planned experiment.
            secondary_hypothesis_splice = replace(
                ablation,
                content_hash=None,
                hypothesis_id=secondary_hypothesis.hypothesis_id,
            )
            with self.assertRaisesRegex(
                ValidationError,
                "canonical ablation fields differ from evaluated parents",
            ):
                repository.materialize(secondary_hypothesis_splice)
            self.assertEqual(len(registry.list_records()), registry_count)
            self.assertEqual(ledger.assert_valid().event_count, event_count)

            invalid_values = (
                replace(
                    ablation,
                    content_hash=None,
                    removed_component_ids=(expected_component_id, "extra-component"),
                ),
                replace(
                    ablation,
                    content_hash=None,
                    removed_component_ids=("another-component",),
                ),
                replace(
                    ablation,
                    content_hash=None,
                    result_ids=("result-splice",),
                ),
                replace(
                    ablation,
                    content_hash=None,
                    producer=Role.EXPERIMENT_RUNNER,
                ),
                replace(
                    ablation,
                    content_hash=None,
                    status=RecordStatus.FAILED,
                ),
                replace(
                    ablation,
                    content_hash=None,
                    parents=(
                        ablation.parents[0],
                        replace(ablation.parents[1], relation="contextualizes"),
                    ),
                ),
            )
            for invalid in invalid_values:
                with self.subTest(invalid=invalid.content_hash):
                    with self.assertRaises(ValidationError):
                        repository.materialize(invalid)
                    self.assertEqual(len(registry.list_records()), registry_count)
                    self.assertEqual(ledger.assert_valid().event_count, event_count)

            materialized = repository.materialize(
                ablation,
                reason="materialize exact source-owned v2 ablation state",
            )
            self.assertEqual(materialized.research_object, ablation)

            projection = register_scientific_claim_evidence_projection(
                registry,
                evidence_id="robustness-v2-ablation",
                evidence_kind=GraphEvidenceKind.ROBUSTNESS,
                claim_id="claim-v2-ablation",
                claim_text="The required frozen ablation was executed.",
                producer_role=Role.STATISTICIAN,
                source_artifact_hashes=(materialized.artifact.sha256,),
            )
            with self.assertRaisesRegex(
                ValidationError,
                "robustness ablation is not scientifically eligible",
            ):
                research_state_module._require_scientific_state_evidence_source(
                    registry,
                    ledger,
                    run_id="global-run-1",
                    evidence_kind=GraphEvidenceKind.ROBUSTNESS,
                    evidence_artifact=projection,
                    evidence_id="robustness-v2-ablation",
                    claim_id="claim-v2-ablation",
                    claim_text="The required frozen ablation was executed.",
                    claim_producer_role=Role.STATISTICIAN,
                    claim_confirmatory=True,
                    claim_evidence_use=ClaimEvidenceUse.SCIENTIFIC,
                    assertion_text=(
                        "The required frozen ablation was executed."
                    ),
                )

    def test_invalid_ablation_sources_are_rejected_before_authority_write(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-v2-ablation-source-"
        ) as raw_root:
            source = self._materialized_v2_source(Path(raw_root))
            registry: ArtifactRegistry = source["registry"]  # type: ignore[assignment]
            ledger: EventLedger = source["ledger"]  # type: ignore[assignment]
            values = source["values"]
            arguments = self._registration_arguments(source)
            output = json.loads(
                registry.get_bytes(arguments["ablation_output_artifact_sha256"])
            )
            output["status"] = "FAIL"
            failed_output = registry.put_json(
                output,
                logical_type="experiment_output.ablation_output",
                origin="failed ablation source regression",
                creator_role=Role.EXPERIMENT_RUNNER,
                creation_command=("scientist-one", "test-v2-ablation-state"),
                parent_artifacts=(
                    values["manifest_record"].sha256,
                    values["spec_record"].sha256,
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            authority_count = sum(
                item.logical_type == "scientific_ablation_authority"
                for item in registry.list_records()
            )
            event_count = ledger.assert_valid().event_count
            failed_arguments = {
                **arguments,
                "ablation_output_artifact_sha256": failed_output.sha256,
            }
            with self.assertRaises((ScientificPromotionError, ValidationError)):
                register_scientific_ablation_authority(
                    registry,
                    ledger,
                    **failed_arguments,  # type: ignore[arg-type]
                )
            spliced_arguments = {
                **arguments,
                "run_state_artifact_sha256": arguments[
                    "method_state_artifact_sha256"
                ],
            }
            with self.assertRaises((ScientificPromotionError, ValidationError)):
                register_scientific_ablation_authority(
                    registry,
                    ledger,
                    **spliced_arguments,  # type: ignore[arg-type]
                )
            self.assertEqual(
                sum(
                    item.logical_type == "scientific_ablation_authority"
                    for item in registry.list_records()
                ),
                authority_count,
            )
            self.assertEqual(ledger.assert_valid().event_count, event_count)

    def test_legacy_synthetic_reproduction_cannot_satisfy_robustness(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-v2-reproduction-boundary-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            run_id = "legacy-reproduction-boundary"
            result = run_research_os_fixture(root, run_id=run_id)
            self.assertEqual(result["status"], "PASS")
            registry = ArtifactRegistry(root, f"runs/{run_id}/registry")
            ledger = EventLedger(root, f"runs/{run_id}/events.jsonl")
            packages = tuple(
                item
                for item in registry.list_records()
                if item.logical_type == "research_state.reproducibility_package"
            )
            self.assertEqual(len(packages), 1)
            package = packages[0]
            (
                package_object,
                package_resolution,
                by_content,
                repository,
            ) = research_state_module._require_scoped_canonical_state_source(
                registry,
                ledger,
                run_id=run_id,
                state_artifact_hash=package.sha256,
            )
            object_id = json.loads(registry.get_bytes(package.sha256))["object_id"]
            self.assertEqual(package_object.object_id, object_id)
            self.assertFalse(package_resolution.scientific_evidence_eligible)

            downstream_objects = {
                object_type: min(
                    (
                        item.research_object
                        for item in by_content.values()
                        if item.research_object.object_type == object_type
                    ),
                    key=lambda item: (item.object_id, item.content_hash),
                )
                for object_type in ("Claim", "Critique")
            }
            run_parent_index = next(
                index
                for index, parent in enumerate(package_object.parents)
                if parent.object_type == "Run"
            )
            invalid_parent_shapes: list[
                tuple[str, tuple[ObjectReference, ...]]
            ] = []
            for object_type, downstream in downstream_objects.items():
                invalid_parent_shapes.append(
                    (
                        f"downstream-{object_type.casefold()}",
                        (
                            *package_object.parents,
                            ObjectReference(
                                object_type,
                                downstream.object_id,
                                downstream.content_hash,
                                "contextualizes",
                                True,
                            ),
                        ),
                    )
                )
            invalid_parent_shapes.extend(
                (
                    (
                        "wrong-run-relation",
                        tuple(
                            replace(parent, relation="contextualizes")
                            if index == run_parent_index
                            else parent
                            for index, parent in enumerate(package_object.parents)
                        ),
                    ),
                    (
                        "unevaluated-run",
                        tuple(
                            replace(parent, evaluated=False)
                            if index == run_parent_index
                            else parent
                            for index, parent in enumerate(package_object.parents)
                        ),
                    ),
                )
            )
            existing_result_ids = {
                parent.object_id
                for parent in package_object.parents
                if parent.object_type == "Result"
            }
            additional_results = sorted(
                (
                    item.research_object
                    for item in by_content.values()
                    if item.research_object.object_type == "Result"
                    and item.research_object.object_id not in existing_result_ids
                ),
                key=lambda item: (item.object_id, item.content_hash),
            )
            if additional_results:
                second_result = additional_results[0]
                invalid_parent_shapes.append(
                    (
                        "second-result",
                        (
                            *package_object.parents,
                            ObjectReference(
                                "Result",
                                second_result.object_id,
                                second_result.content_hash,
                                "reproduces",
                                True,
                            ),
                        ),
                    )
                )

            registry_count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            for label, parents in invalid_parent_shapes:
                invalid_package = replace(
                    package_object,
                    object_id=f"repro-invalid-{label}",
                    content_hash=None,
                    parents=parents,
                )
                with self.subTest(parent_shape=label):
                    with self.assertRaisesRegex(
                        ValidationError,
                        "reproduction package has an invalid canonical parent shape",
                    ):
                        repository.materialize(invalid_package)
                    self.assertEqual(len(registry.list_records()), registry_count)
                    self.assertEqual(
                        ledger.assert_valid().event_count,
                        event_count,
                    )

            self.assertFalse(
                package_resolution.scientific_evidence_eligible
            )
            projection = register_scientific_claim_evidence_projection(
                registry,
                evidence_id="robustness-legacy-reproduction",
                evidence_kind=GraphEvidenceKind.ROBUSTNESS,
                claim_id="claim-legacy-reproduction",
                claim_text="The synthetic fixture reproduced its own output.",
                producer_role=Role.REPRODUCTION_VERIFIER,
                source_artifact_hashes=(package.sha256,),
            )
            with self.assertRaisesRegex(
                ValidationError,
                "robustness reproduction is not scientifically eligible",
            ):
                research_state_module._require_scientific_state_evidence_source(
                    registry,
                    ledger,
                    run_id=run_id,
                    evidence_kind=GraphEvidenceKind.ROBUSTNESS,
                    evidence_artifact=projection,
                    evidence_id="robustness-legacy-reproduction",
                    claim_id="claim-legacy-reproduction",
                    claim_text=(
                        "The synthetic fixture reproduced its own output."
                    ),
                    claim_producer_role=Role.REPRODUCTION_VERIFIER,
                    claim_confirmatory=False,
                    claim_evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
                    assertion_text=(
                        "The synthetic fixture reproduced its own output."
                    ),
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
