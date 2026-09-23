from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.research_state import (
    RecordStatus,
    ReproducibilityPackage,
    ReproductionStatus,
    ResearchStateRepository,
)
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
from scientist_one.scientific_design import (
    SCIENTIFIC_ABLATION_AUTHORITY_LOGICAL_TYPE,
    AblationSpec,
    ScientificAblationAuthorityOutcome,
    ScientificPromotionError,
    build_scientific_ablation_authority,
    register_scientific_ablation_authority,
    require_scientific_ablation_authority,
    require_scientific_result_state_projections,
    scientific_ablation_component_id,
)

try:
    from .test_vnext_state import (
        SCIENTIFIC_V2_STATE_CODE_VERSION,
        _load_scientific_v2_producer_helpers,
        _scientific_v2_source_fixture,
        _scientific_v2_state_graph,
    )
except ImportError:  # unittest discovery loads tests as top-level modules.
    from test_vnext_state import (  # type: ignore[no-redef]
        SCIENTIFIC_V2_STATE_CODE_VERSION,
        _load_scientific_v2_producer_helpers,
        _scientific_v2_source_fixture,
        _scientific_v2_state_graph,
    )


def _registered_multi_hypothesis_inputs(
    root: Path,
    *,
    secondary_required: bool,
) -> tuple[dict[str, object], dict[str, object]]:
    """Build an exact primary run under a multi-hypothesis contract."""

    helpers = _load_scientific_v2_producer_helpers()
    registered_inputs = helpers["_registered_inputs"]
    helper_globals = registered_inputs.__globals__  # type: ignore[union-attr]
    original_registry = helper_globals["ArtifactRegistry"]
    original_contract = helper_globals["_checked_contract"]
    original_run_spec = helper_globals["FrozenRunSpec"]

    def registry_factory(fixture_root: Path) -> ArtifactRegistry:
        return ArtifactRegistry(fixture_root, "runs/global-run-1/registry")

    def contract_factory(
        *,
        metric_direction: object,
        baseline_value: float = 0.0,
        outcome_neutral: bool = False,
        target_value: float = 1.0,
    ) -> object:
        contract = original_contract(
            metric_direction=metric_direction,
            baseline_value=baseline_value,
            outcome_neutral=outcome_neutral,
            target_value=target_value,
        )
        return replace(
            contract,
            ablations=(
                *contract.ablations,
                AblationSpec(
                    ablation_id="ablation-ordered-second",
                    hypothesis_id="hypothesis-secondary",
                    component_changed="ordered secondary component",
                    intervention="Remove only the ordered secondary component.",
                    expected_observation=(
                        "The secondary directed contribution should diminish."
                    ),
                    required=secondary_required,
                ),
            ),
        )

    def primary_run_spec_factory(*args: object, **kwargs: object) -> object:
        required = tuple(kwargs["required_ablations"])
        kwargs["required_ablations"] = tuple(
            item for item in required if item != "ablation-ordered-second"
        )
        return original_run_spec(*args, **kwargs)

    try:
        helper_globals["ArtifactRegistry"] = registry_factory
        helper_globals["_checked_contract"] = contract_factory
        if secondary_required:
            helper_globals["FrozenRunSpec"] = primary_run_spec_factory
        values = registered_inputs(root)  # type: ignore[operator]
    finally:
        helper_globals["ArtifactRegistry"] = original_registry
        helper_globals["_checked_contract"] = original_contract
        helper_globals["FrozenRunSpec"] = original_run_spec
    return values, helpers


def _multi_ablation_source_fixture(root: Path) -> dict[str, object]:
    """Build the real producer fixture with two ordered frozen ablations."""

    values, helpers = _registered_multi_hypothesis_inputs(
        root,
        secondary_required=False,
    )
    promotion_candidate = helpers["_result_promotion_candidate"]
    candidate = promotion_candidate(values)  # type: ignore[operator]
    registry = values["registry"]
    ledger = values["ledger"]
    projection = require_scientific_result_state_projections(
        registry,  # type: ignore[arg-type]
        ledger,  # type: ignore[arg-type]
        expected_ledger_run_id="global-run-1",
        expected_execution_run_id="confirmatory-run-1",
        expected_canonical_state_code_version=(
            SCIENTIFIC_V2_STATE_CODE_VERSION
        ),
        expected_result_id="result-1",
        result_state_projection_artifact_sha256=(
            candidate["result_projection_record"].sha256
        ),
        statistical_state_projection_artifact_sha256=(
            candidate["statistical_projection_record"].sha256
        ),
        promotion_receipt_artifact_sha256=candidate["receipt_record"].sha256,
    )
    spec = values["spec"]
    repository = ResearchStateRepository(
        registry,  # type: ignore[arg-type]
        ledger,  # type: ignore[arg-type]
        run_id="global-run-1",
        code_version=SCIENTIFIC_V2_STATE_CODE_VERSION,
        configuration_hash=spec.configuration_sha256,
        state=ledger.assert_valid().events[-1].requested_state_after,
    )
    return {
        "values": values,
        "candidate": candidate,
        "projection": projection,
        "registry": registry,
        "ledger": ledger,
        "repository": repository,
    }


def _materialized_fixture(
    root: Path,
    *,
    multiple_ablations: bool = False,
) -> dict[str, object]:
    source = (
        _multi_ablation_source_fixture(root)
        if multiple_ablations
        else _scientific_v2_source_fixture(root)
    )
    graph = _scientific_v2_state_graph(source)
    materialized = source["repository"].materialize_scientific_result_bundle(
        ancestors=graph["ancestors"],
        result=graph["result"],
        reason="focused scientific ablation authority fixture",
    )
    by_type = {
        item.research_object.object_type: item
        for item in materialized
        if item.research_object.object_type
        in {"Result", "Run", "Method", "Experiment"}
    }
    values = source["values"]
    candidate = source["candidate"]
    arguments = {
        "expected_ledger_run_id": "global-run-1",
        "expected_execution_run_id": "confirmatory-run-1",
        "expected_ablation_id": "ablation-core",
        "contract_artifact_sha256": values["contract_record"].sha256,
        "checked_superiority_receipt_artifact_sha256": (
            candidate["checked_record"].sha256
        ),
        "scientific_result_promotion_receipt_artifact_sha256": (
            candidate["receipt_record"].sha256
        ),
        "aggregate_result_artifact_sha256": values["aggregate_record"].sha256,
        "ablation_output_artifact_sha256": values["ablation_records"][0].sha256,
        "result_state_artifact_sha256": by_type["Result"].artifact.sha256,
        "run_state_artifact_sha256": by_type["Run"].artifact.sha256,
        "method_state_artifact_sha256": by_type["Method"].artifact.sha256,
        "experiment_state_artifact_sha256": by_type["Experiment"].artifact.sha256,
    }
    return {
        **source,
        "graph": graph,
        "materialized": materialized,
        "by_type": by_type,
        "arguments": arguments,
    }


class ScientificAblationAuthorityTests(unittest.TestCase):
    def test_public_build_register_require_and_all_outcome_uniqueness(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = _materialized_fixture(
                Path(directory),
                multiple_ablations=True,
            )
            registry = fixture["registry"]
            ledger = fixture["ledger"]
            arguments = fixture["arguments"]
            contract = fixture["values"]["contract"]
            method = fixture["graph"]["method"]
            expected_components = tuple(
                scientific_ablation_component_id(
                    item.ablation_id,
                    item.component_changed,
                )
                for item in contract.ablations
            )
            self.assertEqual(method.component_ids, expected_components)
            self.assertEqual(
                tuple(item.hypothesis_id for item in contract.ablations),
                ("hypothesis-primary", "hypothesis-secondary"),
            )
            self.assertEqual(
                fixture["graph"]["experiment"].hypothesis_ids,
                ("hypothesis-primary",),
            )

            before_optional_records = tuple(registry.list_records())
            before_optional_events = ledger.assert_valid().events
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "not one required frozen contract obligation",
            ):
                register_scientific_ablation_authority(
                    registry,
                    ledger,
                    **{
                        **arguments,
                        "expected_ablation_id": "ablation-ordered-second",
                    },
                )
            self.assertEqual(tuple(registry.list_records()), before_optional_records)
            self.assertEqual(ledger.assert_valid().events, before_optional_events)

            constructed = build_scientific_ablation_authority(
                registry,
                ledger,
                **arguments,
            )
            self.assertTrue(constructed.authoritative)
            self.assertFalse(constructed.scientific_evidence_eligible)
            self.assertEqual(
                tuple(item.object_type for item in constructed.state_bindings),
                ("Result", "Run", "Method", "Experiment"),
            )
            self.assertEqual(
                tuple(
                    item.artifact_sha256 for item in constructed.state_bindings
                ),
                tuple(
                    fixture["by_type"][name].artifact.sha256
                    for name in ("Result", "Run", "Method", "Experiment")
                ),
            )
            self.assertEqual(
                constructed.custody_artifact_hashes,
                tuple(sorted(constructed.custody_artifact_hashes)),
            )
            self.assertNotIn(
                "experiment_output.ablation_result",
                {
                    registry.get_metadata(digest).logical_type
                    for digest in constructed.custody_artifact_hashes
                },
            )

            persisted = register_scientific_ablation_authority(
                registry,
                ledger,
                **arguments,
            )
            self.assertEqual(
                persisted.parent_artifacts,
                constructed.source_artifact_hashes,
            )
            resolved = require_scientific_ablation_authority(
                registry,
                ledger,
                expected_ledger_run_id="global-run-1",
                expected_execution_run_id="confirmatory-run-1",
                expected_ablation_id="ablation-core",
                authority_artifact_sha256=persisted.sha256,
            )
            self.assertEqual(resolved, constructed)

            rejected = replace(
                resolved,
                outcome=ScientificAblationAuthorityOutcome.REJECTED,
            )
            registry.put_json(
                rejected.to_dict(),
                logical_type=SCIENTIFIC_ABLATION_AUTHORITY_LOGICAL_TYPE,
                origin="source-owned deterministic scientific ablation authority",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=(
                    "scientist-one",
                    "validate-scientific-ablation",
                ),
                parent_artifacts=rejected.source_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "outcome branch is ambiguous",
            ):
                require_scientific_ablation_authority(
                    registry,
                    ledger,
                    expected_ledger_run_id="global-run-1",
                    expected_execution_run_id="confirmatory-run-1",
                    expected_ablation_id="ablation-core",
                    authority_artifact_sha256=persisted.sha256,
                )

    def test_metadata_content_collision_is_zero_write(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = _materialized_fixture(Path(directory))
            registry = fixture["registry"]
            ledger = fixture["ledger"]
            arguments = fixture["arguments"]
            constructed = build_scientific_ablation_authority(
                registry,
                ledger,
                **arguments,
            )
            collision = registry.put_json(
                constructed.to_dict(),
                logical_type="synthetic_ablation_authority_collision",
                origin="caller-selected metadata collision regression",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "test-collision"),
                parent_artifacts=constructed.source_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            before_records = tuple(registry.list_records())
            before_events = ledger.assert_valid().events
            with self.assertRaises((ArtifactError, ScientificPromotionError, ValidationError)):
                register_scientific_ablation_authority(
                    registry,
                    ledger,
                    **arguments,
                )
            self.assertEqual(tuple(registry.list_records()), before_records)
            self.assertEqual(ledger.assert_valid().events, before_events)
            self.assertEqual(
                collision.sha256,
                hashlib.sha256(
                    canonical_json_bytes(constructed.to_dict()) + b"\n"
                ).hexdigest(),
            )

    def test_wrong_run_ablation_output_and_repro_package_state_are_zero_write(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            fixture = _materialized_fixture(Path(directory))
            registry = fixture["registry"]
            ledger = fixture["ledger"]
            arguments = fixture["arguments"]
            legacy = registry.put_json(
                {
                    "ablation_id": "ablation-core",
                    "executed": True,
                    "status": "PASS",
                },
                logical_type="experiment_output.ablation_result",
                origin="legacy ablation laundering regression",
                creator_role=Role.EXPERIMENT_RUNNER,
                creation_command=("scientist-one", "legacy-ablation"),
                parent_artifacts=(
                    fixture["values"]["manifest_record"].sha256,
                    fixture["values"]["spec_record"].sha256,
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            failed_payload = json.loads(
                registry.get_bytes(arguments["ablation_output_artifact_sha256"])
            )
            failed_payload["status"] = "FAIL"
            failed_output = registry.put_json(
                failed_payload,
                logical_type="experiment_output.ablation_output",
                origin="failed checked ablation output regression",
                creator_role=Role.EXPERIMENT_RUNNER,
                creation_command=("scientist-one", "failed-ablation-output"),
                parent_artifacts=(
                    fixture["values"]["manifest_record"].sha256,
                    fixture["values"]["spec_record"].sha256,
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            package = ReproducibilityPackage(
                object_id="synthetic-repro-launder",
                producer=Role.REPRODUCTION_VERIFIER,
                status=RecordStatus.ACTIVE,
                created_at=fixture["values"]["manifest_record"].created_at,
                code_version=SCIENTIFIC_V2_STATE_CODE_VERSION,
                authority_artifact_hashes=tuple(
                    sorted(
                        (
                            fixture["values"]["manifest_record"].sha256,
                            fixture["values"]["evaluator_implementation"].sha256,
                        )
                    )
                ),
                run_ids=("confirmatory-run-1",),
                manifest_artifact_hashes=(
                    fixture["values"]["manifest_record"].sha256,
                ),
                environment_artifact_hashes=(
                    fixture["values"]["evaluator_implementation"].sha256,
                ),
                source_revision="synthetic-fixture-revision",
                evaluator_version="synthetic-fixture-evaluator",
                reproduction_status=ReproductionStatus.NOT_RUN,
            )
            package_record = registry.put_bytes(
                package.canonical_bytes(),
                logical_type=package.logical_type,
                origin="synthetic ReproducibilityPackage laundering regression",
                creator_role=package.producer,
                creation_command=("scientist-one", "research-state", "materialize"),
                parent_artifacts=package.authority_artifact_hashes,
                schema_version=package.schema_version,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=package.created_at,
            )
            invalid_cases = (
                {"expected_ablation_id": "ablation-not-frozen"},
                {"expected_execution_run_id": "confirmatory-run-substituted"},
                {"ablation_output_artifact_sha256": legacy.sha256},
                {"ablation_output_artifact_sha256": failed_output.sha256},
                {"method_state_artifact_sha256": package_record.sha256},
            )
            for changes in invalid_cases:
                with self.subTest(changes=changes):
                    before_records = tuple(registry.list_records())
                    before_events = ledger.assert_valid().events
                    with self.assertRaises(ScientificPromotionError):
                        register_scientific_ablation_authority(
                            registry,
                            ledger,
                            **{**arguments, **changes},
                        )
                    self.assertEqual(tuple(registry.list_records()), before_records)
                    self.assertEqual(ledger.assert_valid().events, before_events)

    def test_required_foreign_hypothesis_ablation_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            values, helpers = _registered_multi_hypothesis_inputs(
                Path(directory),
                secondary_required=True,
            )
            registry = values["registry"]
            ledger = values["ledger"]
            before_records = tuple(registry.list_records())
            before_events = ledger.assert_valid().events
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "cannot satisfy required ablations for another hypothesis: "
                "ablation-ordered-second",
            ):
                helpers["_attempt_checked"](values)  # type: ignore[operator]
            self.assertEqual(tuple(registry.list_records()), before_records)
            self.assertEqual(ledger.assert_valid().events, before_events)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
