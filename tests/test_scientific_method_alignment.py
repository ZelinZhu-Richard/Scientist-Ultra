"""Prospective Method-intention bindings for scientific execution.

These tests use only deterministic, non-evidentiary fixtures.  They prove an
exact source association; they deliberately do not claim that code implements
the bound Method or that any result is scientifically eligible.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ValidationError
from scientist_one.experiments import (
    EvidenceClass,
    FrozenRunSpec,
    SCIENTIFIC_EXECUTION_INPUT_BINDING_LOGICAL_TYPE,
    SCIENTIFIC_METHOD_DEFINITION_BINDING_METADATA_KEY,
    SCIENTIFIC_METHOD_DEFINITION_BINDING_PROFILE,
    SCIENTIFIC_METHOD_DEFINITION_BINDING_SCHEMA,
    ScientificBackendAttestationProfile,
    plan_adaptive_execution,
    register_scientific_execution_preparation,
    require_scientific_execution_preparation,
    require_scientific_execution_run_spec,
    resolve_scientific_method_definition_binding,
)
from scientist_one.research_state import (
    Implementation,
    Method,
    ResearchStateRepository,
    Result,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    record_scientific_design_freeze,
    register_frozen_run_spec,
    require_scientific_result_state_projections,
    scientific_ablation_component_id,
)
from scientist_one.security import safe_json_loads
from tests.test_scientific_design import _prepared_timeline
from tests.test_vnext_state import (
    SCIENTIFIC_V2_STATE_CODE_VERSION,
    _load_scientific_v2_producer_helpers,
    _scientific_v2_state_graph,
)


def _method_definition(
    values: dict[str, object],
    *,
    creator_role: Role = Role.HYPOTHESIS_DESIGNER,
    parent_sha256: str | None = None,
):
    registry: ArtifactRegistry = values["registry"]  # type: ignore[assignment]
    contract = values["contract"]
    configuration = values["configuration"]
    component_ids = tuple(
        scientific_ablation_component_id(item.ablation_id, item.component_changed)
        for item in contract.ablations  # type: ignore[union-attr]
    )
    return registry.put_json(
        {
            "method_id": "method-source-owned-primary",
            "name": "Prospectively declared method",
            "description": (
                "The intended candidate procedure frozen before execution; "
                "code conformance requires a separate scientific audit."
            ),
            "assumptions": [
                "The declared confirmatory units satisfy the frozen design."
            ],
            "component_ids": list(component_ids),
            "audit_scope": "PROSPECTIVE_INTENTION_ONLY",
        },
        logical_type="method_definition",
        origin="non-evidentiary prospective Method-intention fixture",
        creator_role=creator_role,
        creation_command=("test", "scientific-method-intention"),
        parent_artifacts=(parent_sha256 or configuration.sha256,),  # type: ignore[union-attr]
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _prospective_spec(
    spec: FrozenRunSpec,
    method_record,
) -> FrozenRunSpec:
    metadata = dict(spec.to_dict()["metadata"])
    metadata[SCIENTIFIC_METHOD_DEFINITION_BINDING_METADATA_KEY] = {
        "schema_version": SCIENTIFIC_METHOD_DEFINITION_BINDING_SCHEMA,
        "profile": SCIENTIFIC_METHOD_DEFINITION_BINDING_PROFILE,
        "method_definition_artifact_sha256": method_record.sha256,
        "method_definition_record_hash": str(method_record.record_hash),
    }
    return replace(spec, metadata=metadata)


def _register_prospective_spec(
    values: dict[str, object],
    *,
    evidence_class: EvidenceClass | None = None,
):
    method_record = _method_definition(values)
    spec = _prospective_spec(values["spec"], method_record)  # type: ignore[arg-type]
    if evidence_class is not None:
        spec = replace(spec, evidence_class=evidence_class)
    record = register_frozen_run_spec(
        values["registry"],  # type: ignore[arg-type]
        contract=values["contract"],  # type: ignore[arg-type]
        contract_artifact_sha256=values["contract_record"].sha256,  # type: ignore[union-attr]
        experiment_plan_artifact_sha256s=tuple(
            item.sha256 for item in values["plan_records"]  # type: ignore[union-attr]
        ),
        spec=spec,
    )
    return method_record, spec, record


def _prepared_canonical_timeline(root: str) -> dict[str, object]:
    """Reuse the small design fixture with the required paired run paths."""

    helper_globals = _prepared_timeline.__globals__
    original_registry = helper_globals["ArtifactRegistry"]

    def registry_factory(fixture_root: str) -> ArtifactRegistry:
        return ArtifactRegistry(fixture_root, "runs/timeline/registry")

    try:
        helper_globals["ArtifactRegistry"] = registry_factory
        return _prepared_timeline(root)
    finally:
        helper_globals["ArtifactRegistry"] = original_registry


def _source_owned_result_fixture(root: Path) -> dict[str, object]:
    """Run the existing inert producer with a prospective Method spec."""

    helpers = _load_scientific_v2_producer_helpers()
    registered_inputs = helpers["_registered_inputs"]
    promotion_candidate = helpers["_result_promotion_candidate"]
    component_ids = ("source-owned-method-component",)
    captured: dict[str, object] = {}
    helper_globals = registered_inputs.__globals__  # type: ignore[union-attr]
    original_registry = helper_globals["ArtifactRegistry"]
    original_spec = helper_globals["FrozenRunSpec"]

    def registry_factory(fixture_root: Path) -> ArtifactRegistry:
        registry = ArtifactRegistry(
            fixture_root,
            "runs/global-run-1/registry",
        )
        captured["registry"] = registry
        return registry

    def prospective_spec_factory(**arguments: object) -> FrozenRunSpec:
        registry: ArtifactRegistry = captured["registry"]  # type: ignore[assignment]
        method_record = registry.put_json(
            {
                "method_id": "method-source-owned-result",
                "name": "Source-owned Result method",
                "description": (
                    "The prospective scientific intention associated with this "
                    "non-evidentiary fixture."
                ),
                "assumptions": ["The frozen analysis unit remains the subject."],
                "component_ids": list(component_ids),
                "audit_scope": "PROSPECTIVE_INTENTION_ONLY",
            },
            logical_type="method_definition",
            origin="non-evidentiary Result Method-intention fixture",
            creator_role=Role.HYPOTHESIS_DESIGNER,
            creation_command=("test", "scientific-method-result-fixture"),
            parent_artifacts=(str(arguments["configuration_sha256"]),),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        metadata = dict(arguments["metadata"])  # type: ignore[arg-type]
        metadata[SCIENTIFIC_METHOD_DEFINITION_BINDING_METADATA_KEY] = {
            "schema_version": SCIENTIFIC_METHOD_DEFINITION_BINDING_SCHEMA,
            "profile": SCIENTIFIC_METHOD_DEFINITION_BINDING_PROFILE,
            "method_definition_artifact_sha256": method_record.sha256,
            "method_definition_record_hash": str(method_record.record_hash),
        }
        arguments["metadata"] = metadata
        spec = original_spec(**arguments)
        captured["method_record"] = method_record
        captured["spec"] = spec
        return spec

    try:
        helper_globals["ArtifactRegistry"] = registry_factory
        helper_globals["FrozenRunSpec"] = prospective_spec_factory
        values = registered_inputs(root)
    finally:
        helper_globals["ArtifactRegistry"] = original_registry
        helper_globals["FrozenRunSpec"] = original_spec

    candidate = promotion_candidate(values)
    registry = values["registry"]
    ledger = values["ledger"]
    projection = require_scientific_result_state_projections(
        registry,
        ledger,
        expected_ledger_run_id="global-run-1",
        expected_execution_run_id="confirmatory-run-1",
        expected_canonical_state_code_version=SCIENTIFIC_V2_STATE_CODE_VERSION,
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
        registry,
        ledger,
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
        **captured,
    }


class ScientificMethodAlignmentTests(unittest.TestCase):
    def test_historical_profile_preserves_exact_run_spec_bytes_and_parents(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            values = _prepared_timeline(directory)
            spec = values["spec"]
            record = values["spec_record"]

            self.assertEqual(
                spec.sha256,
                "5324680420e09ea0df74b8c6fc211280090bc589988ddfe6fdad6d5c2f3e16dc",
            )
            self.assertEqual(
                record.sha256,
                "872825580a15142a0f951aff470dc8210980298ea7cb14813d3b95704835baf6",
            )
            self.assertEqual(
                record.parent_artifacts,
                (
                    values["contract_record"].sha256,
                    *(item.sha256 for item in values["plan_records"]),
                    values["code"].sha256,
                    values["data"].sha256,
                    values["configuration"].sha256,
                    values["evaluator"].sha256,
                ),
            )
            self.assertIsNone(
                resolve_scientific_method_definition_binding(
                    values["registry"],
                    spec=spec,
                )
            )

    def test_prospective_profile_pins_exact_method_before_four_inputs(self) -> None:
        with TemporaryDirectory() as directory:
            values = _prepared_timeline(directory)
            method_record, spec, spec_record = _register_prospective_spec(values)
            binding = resolve_scientific_method_definition_binding(
                values["registry"],  # type: ignore[arg-type]
                spec=spec,
            )

            self.assertIsNotNone(binding)
            assert binding is not None
            self.assertEqual(binding.method_id, "method-source-owned-primary")
            self.assertEqual(binding.profile, SCIENTIFIC_METHOD_DEFINITION_BINDING_PROFILE)
            self.assertEqual(
                spec_record.parent_artifacts,
                (
                    values["contract_record"].sha256,
                    *(item.sha256 for item in values["plan_records"]),
                    method_record.sha256,
                    values["code"].sha256,
                    values["data"].sha256,
                    values["configuration"].sha256,
                    values["evaluator"].sha256,
                ),
            )

    def test_registration_and_replay_reject_missing_or_substituted_method(self) -> None:
        cases = (
            "wrong-role",
            "wrong-parent",
            "wrong-record-hash",
            "null-binding",
        )
        for case in cases:
            with self.subTest(case=case), TemporaryDirectory() as directory:
                values = _prepared_timeline(directory)
                if case == "wrong-role":
                    method_record = _method_definition(
                        values,
                        creator_role=Role.PROTOCOL_DESIGNER,
                    )
                elif case == "wrong-parent":
                    unrelated = values["registry"].put_json(
                        {"unrelated": True},
                        logical_type="fixture.unrelated",
                        origin="wrong Method configuration parent",
                        creator_role=Role.PROTOCOL_DESIGNER,
                        creation_command=("test", "scientific-method-intention"),
                        frozen=True,
                    )
                    method_record = _method_definition(
                        values,
                        parent_sha256=unrelated.sha256,
                    )
                else:
                    method_record = _method_definition(values)
                spec = _prospective_spec(values["spec"], method_record)  # type: ignore[arg-type]
                if case == "wrong-record-hash":
                    metadata = dict(spec.to_dict()["metadata"])
                    binding = dict(
                        metadata[SCIENTIFIC_METHOD_DEFINITION_BINDING_METADATA_KEY]
                    )
                    binding["method_definition_record_hash"] = "0" * 64
                    metadata[SCIENTIFIC_METHOD_DEFINITION_BINDING_METADATA_KEY] = binding
                    spec = replace(spec, metadata=metadata)
                elif case == "null-binding":
                    metadata = dict(spec.to_dict()["metadata"])
                    metadata[SCIENTIFIC_METHOD_DEFINITION_BINDING_METADATA_KEY] = None
                    spec = replace(spec, metadata=metadata)
                count = len(values["registry"].list_records())
                with self.assertRaises(ValidationError):
                    register_frozen_run_spec(
                        values["registry"],  # type: ignore[arg-type]
                        contract=values["contract"],  # type: ignore[arg-type]
                        contract_artifact_sha256=values["contract_record"].sha256,
                        experiment_plan_artifact_sha256s=tuple(
                            item.sha256 for item in values["plan_records"]
                        ),
                        spec=spec,
                    )
                self.assertEqual(len(values["registry"].list_records()), count)

        with TemporaryDirectory() as directory:
            values = _prepared_timeline(directory)
            method_record = _method_definition(values)
            spec = _prospective_spec(values["spec"], method_record)  # type: ignore[arg-type]
            spec = replace(
                spec,
                evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
            )
            forged = values["registry"].put_json(
                spec.to_dict(),
                logical_type="frozen_run_spec",
                origin="run spec frozen after scientific-plan admission and before execution",
                creator_role=Role.EXPERIMENT_RUNNER,
                creation_command=("scientist-one", "freeze-run-spec"),
                parent_artifacts=(
                    values["contract_record"].sha256,
                    *(item.sha256 for item in values["plan_records"]),
                    # The declared Method parent is deliberately omitted.
                    values["code"].sha256,
                    values["data"].sha256,
                    values["configuration"].sha256,
                    values["evaluator"].sha256,
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaises(ValidationError):
                require_scientific_execution_run_spec(
                    values["registry"],  # type: ignore[arg-type]
                    frozen_run_spec_artifact_sha256=forged.sha256,
                )

    def test_preparation_keeps_four_direct_execution_inputs(self) -> None:
        with TemporaryDirectory() as directory:
            values = _prepared_canonical_timeline(directory)
            method_record, spec, spec_record = _register_prospective_spec(
                values,
                evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
            )
            ledger = values["ledger"]
            record_scientific_design_freeze(
                values["registry"],  # type: ignore[arg-type]
                ledger,  # type: ignore[arg-type]
                run_id="timeline-method-run",
                contract=values["contract"],  # type: ignore[arg-type]
                contract_artifact_sha256=values["contract_record"].sha256,
                experiment_plan_artifact_sha256s=tuple(
                    item.sha256 for item in values["plan_records"]
                ),
                frozen_run_spec_artifact_sha256=spec_record.sha256,
            )
            profile = spec.compute_profile
            plan = plan_adaptive_execution(
                profile,
                spec.resource_estimate,
                observed_available_memory_bytes=profile.memory_limit_bytes,
                pending_tasks=len(spec.seeds),
                bytes_per_sample=spec.bytes_per_sample,
                worker_overhead_bytes=spec.worker_overhead_bytes,
            )
            backend = ScientificBackendAttestationProfile(
                backend_id="non-evidentiary-method-fixture",
                attestation_schema="non-evidentiary-method-fixture/v1",
                verifier_id="non-evidentiary-verifier",
                trust_root_id="non-evidentiary-trust-root",
            )
            preparation_record = register_scientific_execution_preparation(
                values["registry"],  # type: ignore[arg-type]
                ledger,  # type: ignore[arg-type]
                ledger_run_id="timeline-method-run",
                frozen_run_spec_artifact_sha256=spec_record.sha256,
                adaptive_execution_plan=plan,
                backend_profile=backend,
            )
            preparation = require_scientific_execution_preparation(
                values["registry"],  # type: ignore[arg-type]
                ledger,  # type: ignore[arg-type]
                preparation_artifact_sha256=preparation_record.sha256,
                expected_ledger_run_id="timeline-method-run",
                expected_execution_run_id=spec.run_id,
            )
            expected_inputs = (
                values["code"].sha256,
                values["data"].sha256,
                values["configuration"].sha256,
                values["evaluator"].sha256,
            )
            self.assertEqual(preparation.input_artifact_sha256s, expected_inputs)
            self.assertNotIn(method_record.sha256, preparation.input_artifact_sha256s)
            input_binding_record = values["registry"].get_metadata(
                preparation.execution_input_binding_artifact_sha256
            )
            self.assertEqual(
                input_binding_record.logical_type,
                SCIENTIFIC_EXECUTION_INPUT_BINDING_LOGICAL_TYPE,
            )
            input_binding = safe_json_loads(
                values["registry"].get_bytes(input_binding_record.sha256)
            )
            self.assertEqual(
                [item["kind"] for item in input_binding["inputs"]],
                ["code", "data", "configuration", "evaluator"],
            )

    def test_result_ancestry_projects_source_method_and_code_config_implementation(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            source = _source_owned_result_fixture(Path(directory))
            method_record = source["method_record"]
            method_value = safe_json_loads(
                source["registry"].get_bytes(method_record.sha256)
            )
            graph = _scientific_v2_state_graph(
                source,
                {
                    "Method": {
                        "object_id": method_value["method_id"],
                        "producer": Role.HYPOTHESIS_DESIGNER,
                        "authority_artifact_hashes": (method_record.sha256,),
                        "name": method_value["name"],
                        "description": method_value["description"],
                        "assumptions": tuple(method_value["assumptions"]),
                        "component_ids": tuple(method_value["component_ids"]),
                    }
                },
            )
            repository: ResearchStateRepository = source["repository"]  # type: ignore[assignment]
            completed = repository.materialize_scientific_result_bundle(
                ancestors=graph["ancestors"],
                result=graph["result"],
                reason="materialize non-evidentiary source-owned Method fixture",
            )
            materialized_method = next(
                item.research_object
                for item in completed
                if isinstance(item.research_object, Method)
            )
            implementation = next(
                item.research_object
                for item in completed
                if isinstance(item.research_object, Implementation)
            )
            result = next(
                item.research_object
                for item in completed
                if isinstance(item.research_object, Result)
            )
            values = source["values"]
            spec_record = values["spec_record"]
            self.assertEqual(materialized_method.object_id, method_value["method_id"])
            self.assertIs(materialized_method.producer, Role.HYPOTHESIS_DESIGNER)
            self.assertEqual(
                materialized_method.authority_artifact_hashes,
                (method_record.sha256,),
            )
            self.assertEqual(implementation.method_id, materialized_method.object_id)
            self.assertEqual(
                implementation.code_artifact_hashes,
                (values["code_record"].sha256,),
            )
            self.assertEqual(
                implementation.configuration_artifact_hashes,
                (values["configuration_record"].sha256,),
            )
            self.assertEqual(
                spec_record.parent_artifacts[-5:],
                (
                    method_record.sha256,
                    values["code_record"].sha256,
                    values["data_record"].sha256,
                    values["configuration_record"].sha256,
                    values["evaluator_implementation"].sha256,
                ),
            )
            # The fixture intentionally remains non-evidentiary, and the
            # Method binding contains no code-correctness or upstream claim.
            stored = repository._stored_objects()
            by_content, _ = repository._indexes(stored)
            resolution = repository._resolve_object_authority(result, by_content)
            self.assertFalse(resolution.scientific_evidence_eligible)
            self.assertNotIn("correct", method_value)
            self.assertNotIn("upstream", method_value)
            self.assertTrue(repository.validate_state().valid)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
