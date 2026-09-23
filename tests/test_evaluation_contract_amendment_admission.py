"""Actual freeze-admission regressions, using NON_EVIDENTIARY visibility.

The imported timeline helper registers synthetic outputs; it runs no workload
and establishes no scientific result authority.  These tests exercise ordinary
contract/plan/spec registration, timeline events and full freeze-receipt replay.
Even the accepted prospective controls authorize design-freeze validity ONLY.
The three post-visibility cases require amendment admission to reject them
before publishing a new DESIGN_FROZEN event or freeze receipt. Their original
failures are retained in the local integration ledger.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import tempfile
from typing import Any, TypeVar
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import FrozenArtifactError
from scientist_one.execution_admissibility import (
    FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA,
    ScientificExecutionAdmissibilityPolicy,
)
from scientist_one.experiments import ExperimentPhase, FrozenRunSpec
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
import scientist_one.scientific_design as design
from scientist_one.security import safe_json_loads
from tests import test_scientific_design as timeline_fixtures
from tests import test_superiority_authority as superiority_fixtures


_LEDGER_RUN_ID = "timeline-run"
_T = TypeVar("_T")


def _snapshot(values: dict[str, Any]):
    return (
        values["registry"].verify_all(raise_on_error=True),
        values["ledger"].validate(raise_on_error=True),
    )


def _freeze_arguments(values: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": _LEDGER_RUN_ID,
        "contract": values["contract"],
        "contract_artifact_sha256": values["contract_record"].sha256,
        "experiment_plan_artifact_sha256s": tuple(
            record.sha256 for record in values["plan_records"]
        ),
        "frozen_run_spec_artifact_sha256": values["spec_record"].sha256,
    }


def _freeze(values: dict[str, Any]):
    return design.record_scientific_design_freeze(
        values["registry"], values["ledger"], **_freeze_arguments(values)
    )


def _register_freeze_receipt(values: dict[str, Any], receipt_id: str):
    return design.register_evaluation_contract_freeze_gate_receipt(
        values["registry"], values["ledger"],
        receipt_id=receipt_id, **_freeze_arguments(values),
    )


def _read_freeze_receipt(values: dict[str, Any], record):
    # No caller-supplied contract: replay the stored wrapper and exact sources.
    return design.require_evaluation_contract_freeze_gate_receipt(
        values["registry"], values["ledger"],
        receipt_artifact_sha256=record.sha256,
        expected_run_id=_LEDGER_RUN_ID,
        expected_contract_id=values["contract"].contract_id,
    )


def _freeze_publications(snapshot):
    registry_state, ledger_state = snapshot
    return (
        tuple(
            event for event in ledger_state.events
            if event.metadata.get("scientific_timeline", {}).get("kind")
            == "DESIGN_FROZEN"
        ),
        tuple(
            record for record in registry_state.records
            if record.logical_type
            == design.EVALUATION_CONTRACT_FREEZE_GATE_RECEIPT_LOGICAL_TYPE
        ),
    )


def _non_evidentiary_parent(registry: ArtifactRegistry):
    return timeline_fixtures._timeline_artifact(
        registry,
        b'{"fixture":"NON_EVIDENTIARY contract-admission bytes"}\n',
        "timeline_contract_evidence",
        Role.EVIDENCE_CURATOR,
    )


def _initial_version_inputs(root: str, version: int) -> dict[str, Any]:
    """Fresh registry: no lower-version contract or earlier design admission."""

    registry = ArtifactRegistry(root)
    ledger = EventLedger(root, "runs/timeline/events.jsonl")
    evidence = _non_evidentiary_parent(registry)
    contract = timeline_fixtures.make_contract(version=version)
    contract_record = design.register_frozen_evaluation_contract(
        registry, contract=contract, parent_artifact_sha256s=(evidence.sha256,),
    )
    code = timeline_fixtures._timeline_artifact(
        registry, b"print('NON_EVIDENTIARY; never executed')\n",
        "experiment_code", Role.IMPLEMENTER,
    )
    data = timeline_fixtures._timeline_artifact(
        registry, b'{"fixture":"NON_EVIDENTIARY dataset"}\n',
        "experiment_dataset", Role.EVIDENCE_CURATOR,
    )
    configuration = timeline_fixtures._timeline_artifact(
        registry, b'{"fixture":"NON_EVIDENTIARY configuration"}\n',
        "experiment_configuration", Role.PROTOCOL_DESIGNER,
    )
    evaluator = timeline_fixtures._timeline_artifact(
        registry, b'{"fixture":"NON_EVIDENTIARY evaluator"}\n',
        "evaluator_implementation", Role.PROTOCOL_DESIGNER,
    )
    plans = tuple(
        design.ExperimentPlan(
            experiment_id="experiment-primary",
            hypothesis_id="hypothesis-primary",
            stage=design.ExperimentStage.EXPLORATORY,
            contract_sha256=contract.sha256,
            dataset_split_id="development-v1",
            seed=seed,
            evaluator_id="evaluator-v1",
            uses_protected_resource=False,
            results_seen_before_plan=False,
        )
        for seed in contract.seed_reporting.seeds
    )
    plan_records = tuple(
        design.register_frozen_experiment_plan(
            registry, contract=contract,
            contract_artifact_sha256=contract_record.sha256, plan=plan,
        )
        for plan in plans
    )
    spec = FrozenRunSpec(
        run_id="timeline-execution",
        experiment_id="experiment-primary",
        hypothesis_id="hypothesis-primary",
        phase=ExperimentPhase.EXPLORATORY,
        argv=("/usr/bin/python3", "-I", "fixture.py"),
        working_directory=".",
        code_sha256=code.sha256, data_sha256=data.sha256,
        configuration_sha256=configuration.sha256,
        evaluator_sha256=evaluator.sha256,
        seeds=contract.seed_reporting.seeds,
        required_ablations=("ablation-core",),
        metadata={"evaluation_split": "development-v1"},
    )
    spec_record = design.register_frozen_run_spec(
        registry, contract=contract,
        contract_artifact_sha256=contract_record.sha256,
        experiment_plan_artifact_sha256s=tuple(r.sha256 for r in plan_records),
        spec=spec,
    )
    return locals()


class _AdmissionRefused(Exception):
    """Test-local control flow, raised only after zero-delta refusal checks."""


class EvaluationContractAmendmentAdmissionTests(unittest.TestCase):
    def _assert_prospective_only(self, values, record):
        receipt = _read_freeze_receipt(values, record)
        self.assertIs(type(receipt), design.EvaluationContractFreezeGateReceipt)
        self.assertTrue(receipt.scientific_gate_passed)
        self.assertEqual(receipt.freeze_scope, "DESIGN_FREEZE_VALIDITY_ONLY")
        self.assertFalse(receipt.result_validity_authorized)
        return receipt

    def _require_post_visibility_refusal(self, *, version: int, contract_id: str):
        with tempfile.TemporaryDirectory(prefix="amendment-admission-") as root:
            values = timeline_fixtures._prepared_timeline(root)
            first_freeze = _freeze(values)
            first_receipt_record = _register_freeze_receipt(values, "initial-freeze")
            self._assert_prospective_only(values, first_receipt_record)

            # Synthetic NON_EVIDENTIARY visibility only: no workload, projection,
            # statistical authority, Result, E4 or scientific success is created.
            timeline_fixtures._register_timeline_outputs(values)
            observed = design.record_scientific_result_observed(
                values["registry"], values["ledger"],
                output_manifest_artifact_sha256=values["manifest_record"].sha256,
                **_freeze_arguments(values),
            )
            initial = _snapshot(values)
            self.assertEqual(initial[1].events, (first_freeze, observed))
            self.assertEqual(
                observed.metadata["scientific_timeline"]["kind"], "RESULT_OBSERVED",
            )
            self._assert_prospective_only(values, first_receipt_record)
            initial_publications = _freeze_publications(initial)

            child = dict(values)
            child_contract = replace(
                values["contract"], version=version, contract_id=contract_id,
                success_criteria=(
                    "Changed success criterion after synthetic result visibility.",
                ),
            )
            child_spec = replace(values["spec"], run_id="timeline-changed-execution")
            self.assertNotEqual(child_contract.sha256, values["contract"].sha256)
            self.assertEqual(child_contract.separation, values["contract"].separation)
            self.assertEqual(
                replace(child_spec, run_id=values["spec"].run_id), values["spec"],
            )
            self.assertEqual(
                replace(
                    child_contract, version=values["contract"].version,
                    contract_id=values["contract"].contract_id,
                    success_criteria=values["contract"].success_criteria,
                ),
                values["contract"],
            )
            for field in (
                "code_sha256", "data_sha256", "configuration_sha256", "evaluator_sha256",
            ):
                digest = getattr(child_spec, field)
                self.assertEqual(digest, getattr(values["spec"], field))
                self.assertTrue(values["registry"].verify(digest, raise_on_error=True))

            def admit(label: str, operation: Callable[[], _T]) -> _T:
                before = _snapshot(values)
                try:
                    return operation()
                except design.ScientificDesignError as exc:
                    after = _snapshot(values)
                    self.assertEqual(after, before, f"{label} refusal wrote state")
                    self.assertEqual(
                        _freeze_publications(after), initial_publications,
                        f"{label} refused only after a new freeze publication",
                    )
                    self._assert_prospective_only(values, first_receipt_record)
                    raise _AdmissionRefused(label) from exc

            try:
                child["contract"] = child_contract
                child["contract_record"] = admit(
                    "contract registration",
                    lambda: design.register_frozen_evaluation_contract(
                        values["registry"], contract=child_contract,
                        parent_artifact_sha256s=(values["evidence"].sha256,),
                    ),
                )
                child["plans"] = tuple(
                    replace(plan, contract_sha256=child_contract.sha256)
                    for plan in values["plans"]
                )
                child["plan_records"] = tuple(
                    admit(
                        f"seed {plan.seed} plan registration",
                        lambda plan=plan: design.register_frozen_experiment_plan(
                            values["registry"], contract=child_contract,
                            contract_artifact_sha256=child["contract_record"].sha256,
                            plan=plan,
                        ),
                    )
                    for plan in child["plans"]
                )
                child["spec"] = child_spec
                child["spec_record"] = admit(
                    "run spec registration",
                    lambda: design.register_frozen_run_spec(
                        values["registry"], contract=child_contract,
                        contract_artifact_sha256=child["contract_record"].sha256,
                        experiment_plan_artifact_sha256s=tuple(
                            record.sha256 for record in child["plan_records"]
                        ),
                        spec=child_spec,
                    ),
                )
                later_freeze = admit("DESIGN_FROZEN admission", lambda: _freeze(child))
                later_record = admit(
                    "freeze receipt publication",
                    lambda: _register_freeze_receipt(child, "changed-design-freeze"),
                )
                receipt = admit(
                    "full freeze receipt readback",
                    lambda: self._assert_prospective_only(child, later_record),
                )
            except _AdmissionRefused:
                return

            self.assertEqual(receipt.design_freeze_event_hash, later_freeze.event_hash)
            self.assertGreater(receipt.design_freeze_event_index, 1)
            self.fail(
                "Post-visibility changed design was admitted without amendment "
                f"authority: contract_id={contract_id}, version={version}; "
                "new DESIGN_FROZEN and full receipt replay both accepted "
                "(result_validity_authorized remains False)."
            )

    def test_next_version_same_id_after_visibility_requires_amendment(self):
        self._require_post_visibility_refusal(version=2, contract_id="contract-1")

    def test_same_version_same_id_after_visibility_requires_amendment(self):
        self._require_post_visibility_refusal(version=1, contract_id="contract-1")

    def test_renamed_same_version_after_visibility_requires_amendment(self):
        self._require_post_visibility_refusal(version=1, contract_id="renamed-contract")

    def _assert_initial_version_allowed(self, version: int):
        with tempfile.TemporaryDirectory(prefix="initial-contract-version-") as root:
            values = _initial_version_inputs(root, version)
            self.assertEqual(_snapshot(values)[1].event_count, 0)
            self.assertEqual(
                tuple(
                    r.sha256 for r in values["registry"].list_records()
                    if r.logical_type == "evaluation_contract"
                ),
                (values["contract_record"].sha256,),
            )
            # The numeric version does not select wrapper schema evolution.
            self.assertEqual(values["contract_record"].schema_version, "1.0")
            wrapper = safe_json_loads(
                values["registry"].get_bytes(values["contract_record"].sha256)
            )
            self.assertEqual(wrapper["schema_version"], "checked-superiority-contract/v1")
            _freeze(values)
            record = _register_freeze_receipt(values, "initial-higher-version-freeze")
            receipt = self._assert_prospective_only(values, record)
            self.assertEqual(receipt.contract_version, version)
            self.assertEqual(_snapshot(values)[1].event_count, 1)

    def test_initial_numeric_version_two_can_freeze_with_v1_wrapper(self):
        self._assert_initial_version_allowed(2)

    def test_initial_numeric_version_three_can_freeze_with_v1_wrapper(self):
        self._assert_initial_version_allowed(3)

    def test_unchanged_contract_new_execution_before_observation_remains_prospective(self):
        with tempfile.TemporaryDirectory(prefix="pre-observation-reuse-") as root:
            values = timeline_fixtures._prepared_timeline(root)
            _freeze(values)
            first = _register_freeze_receipt(values, "first-prospective-freeze")
            self._assert_prospective_only(values, first)
            later = dict(values)
            later["spec"] = replace(values["spec"], run_id="second-prospective-execution")
            later["spec_record"] = design.register_frozen_run_spec(
                values["registry"], contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                experiment_plan_artifact_sha256s=tuple(
                    r.sha256 for r in values["plan_records"]
                ),
                spec=later["spec"],
            )
            _freeze(later)
            record = _register_freeze_receipt(later, "second-prospective-freeze")
            self._assert_prospective_only(later, record)
            self.assertEqual(len(_freeze_publications(_snapshot(values))[0]), 2)

    def _assert_initial_policy_wrapper_readback(self, *, admissibility: bool):
        with tempfile.TemporaryDirectory(prefix="initial-policy-wrapper-") as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root, "runs/timeline/events.jsonl")
            evidence = _non_evidentiary_parent(registry)
            contract = superiority_fixtures._checked_contract(outcome_neutral=True)
            self.assertEqual(contract.version, 2)
            expected_schema = "checked-superiority-contract/v2"
            expected_record_schema = "2.0"
            if admissibility:
                contract = replace(
                    contract, version=3,
                    stopping_criteria=FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA,
                    scientific_execution_admissibility_policy=(
                        ScientificExecutionAdmissibilityPolicy()
                    ),
                )
                expected_schema = "checked-superiority-contract/v3"
                expected_record_schema = "3.0"
            record = design.register_frozen_evaluation_contract(
                registry, contract=contract, parent_artifact_sha256s=(evidence.sha256,),
            )
            before = (registry.verify_all(raise_on_error=True), ledger.validate())
            replayed = design.require_frozen_evaluation_contract(
                registry, contract_artifact_sha256=record.sha256,
            )
            self.assertEqual(replayed, contract)
            self.assertEqual(record.schema_version, expected_record_schema)
            self.assertEqual(
                safe_json_loads(registry.get_bytes(record.sha256))["schema_version"],
                expected_schema,
            )
            self.assertEqual(
                (registry.verify_all(raise_on_error=True), ledger.validate()), before,
            )
            self.assertEqual(before[1].event_count, 0)
            # Registration/readback only: missing scientific sources are not
            # manufactured to obtain an evolved-profile freeze or execution.
            self.assertEqual(_freeze_publications(before), ((), ()))

    def test_initial_outcome_neutral_contract_preserves_actual_v2_policy_wrapper(self):
        self._assert_initial_policy_wrapper_readback(admissibility=False)

    def test_initial_admissibility_contract_preserves_actual_v3_policy_wrapper(self):
        self._assert_initial_policy_wrapper_readback(admissibility=True)


class EvaluationContractGenesisAdmissionTests(unittest.TestCase):
    """Real registry admission/CAS, not execution or scientific authority.

    The deterministic interleavings return the actual registry snapshot and
    perform real public writes after it.  They never replace a scientific
    source owner, manufacture its success, or inject an authority DTO.
    """

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="contract-genesis-admission-")
        self.addCleanup(directory.cleanup)
        self.root = directory.name
        self.registry = ArtifactRegistry(self.root)
        self.ledger = EventLedger(self.root, "runs/timeline/events.jsonl")
        self.evidence = _non_evidentiary_parent(self.registry)
        self.contract = timeline_fixtures.make_contract()

    def snapshot(self):
        return _snapshot({"registry": self.registry, "ledger": self.ledger})

    def register(self, *, contract=None, parents=None):
        return design.register_frozen_evaluation_contract(
            self.registry,
            contract=self.contract if contract is None else contract,
            parent_artifact_sha256s=(self.evidence.sha256,) if parents is None else parents,
        )

    def assert_only_record_added(self, before, record):
        after = self.snapshot()
        expected = {item.sha256: item for item in before[0].records}
        self.assertNotIn(record.sha256, expected)
        expected[record.sha256] = record
        self.assertEqual({item.sha256: item for item in after[0].records}, expected)
        self.assertEqual(after[0].count, before[0].count + 1)
        self.assertEqual(after[0].orphan_paths, before[0].orphan_paths)
        self.assertEqual(after[1], before[1])
        self.assertEqual(_freeze_publications(after), ((), ()))

    def test_exact_genesis_repeat_preserves_record_metadata_and_all_state(self):
        first = self.register()
        before = self.snapshot()
        raw = self.registry.get_bytes(first.sha256)
        self.assertEqual(self.register(), first)
        self.assertEqual(self.register(), first)
        self.assertEqual(self.registry.get_metadata(first.sha256), first)
        self.assertEqual(self.registry.get_bytes(first.sha256), raw)
        self.assertEqual(
            design.require_frozen_evaluation_contract(
                self.registry, contract_artifact_sha256=first.sha256,
            ),
            self.contract,
        )
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(before[1].event_count, 0)

    def test_same_body_different_parents_refuses_without_changing_original(self):
        first = self.register()
        other_parent = timeline_fixtures._timeline_artifact(
            self.registry, b'{"fixture":"NON_EVIDENTIARY other parent"}\n',
            "timeline_contract_evidence", Role.EVIDENCE_CURATOR,
        )
        before = self.snapshot()
        raw = self.registry.get_bytes(first.sha256)
        for parents in (
            (other_parent.sha256,),
            (self.evidence.sha256, other_parent.sha256),
        ):
            with self.subTest(parents=parents), self.assertRaisesRegex(
                FrozenArtifactError, "frozen artifact metadata cannot be changed",
            ):
                self.register(parents=parents)
            self.assertEqual(self.snapshot(), before)
            self.assertEqual(self.registry.get_metadata(first.sha256), first)
            self.assertEqual(self.registry.get_bytes(first.sha256), raw)
        self.assertEqual(self.register(), first)
        self.assertEqual(self.snapshot(), before)

    def test_inert_same_bytes_incompatible_metadata_cannot_be_upgraded(self):
        # Obtain bytes from an ordinary registration in a separate registry.
        # The target registry retains only checked inert bytes under an invalid
        # producer/origin. Byte-validation PASS is not scientific authority.
        template = ArtifactRegistry(self.root, "runs/template/registry")
        template_parent = _non_evidentiary_parent(template)
        template_record = design.register_frozen_evaluation_contract(
            template, contract=self.contract,
            parent_artifact_sha256s=(template_parent.sha256,),
        )
        raw = template.get_bytes(template_record.sha256)
        inert = self.registry.put_bytes(
            raw,
            logical_type="evaluation_contract",
            origin="NON_EVIDENTIARY incompatible frozen metadata fixture",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("test", "non-evidentiary-contract-metadata"),
            parent_artifacts=(self.evidence.sha256,),
            schema_version="1.0", mime_type="application/json",
            validation_result="PASS", frozen=True,
        )
        self.assertEqual(inert.sha256, template_record.sha256)
        before = self.snapshot()
        with self.assertRaisesRegex(
            FrozenArtifactError, "frozen artifact metadata cannot be changed",
        ):
            self.register()
        with self.assertRaisesRegex(design.ScientificPromotionError, "frozen PASS artifact"):
            design.require_frozen_evaluation_contract(
                self.registry, contract_artifact_sha256=inert.sha256,
            )
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.registry.get_metadata(inert.sha256), inert)
        self.assertEqual(self.registry.get_bytes(inert.sha256), raw)

    def test_competing_same_id_genesis_after_real_snapshot_has_one_winner(self):
        competitor = replace(
            self.contract,
            success_criteria=("A distinct prospectively declared genesis criterion.",),
        )
        self.assertEqual(competitor.contract_id, self.contract.contract_id)
        self.assertNotEqual(competitor.sha256, self.contract.sha256)
        before = self.snapshot()
        actual_verify_all = ArtifactRegistry.verify_all
        forwarded = []
        winners = []

        def snapshot_then_compete(registry, *, raise_on_error=False):
            snapshot = actual_verify_all(registry, raise_on_error=raise_on_error)
            if registry is self.registry and not forwarded:
                forwarded.append(snapshot)  # Set before nested public admission.
                winners.append(self.register(contract=competitor))
            return snapshot

        with patch.object(ArtifactRegistry, "verify_all", new=snapshot_then_compete):
            with self.assertRaisesRegex(
                design.ScientificPromotionError, "sources changed before admission",
            ):
                self.register()
        self.assertEqual(forwarded, [before[0]])
        self.assertEqual(len(winners), 1)
        self.assert_only_record_added(before, winners[0])
        self.assertEqual(
            design.require_frozen_evaluation_contract(
                self.registry, contract_artifact_sha256=winners[0].sha256,
            ),
            competitor,
        )
        self.assertEqual(
            tuple(r for r in self.registry.list_records() if r.logical_type == "evaluation_contract"),
            tuple(winners),
        )
        after_winner = self.snapshot()
        with self.assertRaisesRegex(design.ScientificPromotionError, "persisted amendment lineage"):
            self.register()
        self.assertEqual(self.snapshot(), after_winner)
        self.assertEqual(self.register(contract=competitor), winners[0])
        self.assertEqual(self.snapshot(), after_winner)

    def test_real_inert_append_between_snapshot_and_commit_leaves_no_candidate(self):
        before = self.snapshot()
        actual_verify_all = ArtifactRegistry.verify_all
        forwarded = []
        injected = []

        def snapshot_then_append(registry, *, raise_on_error=False):
            snapshot = actual_verify_all(registry, raise_on_error=raise_on_error)
            if registry is self.registry and not forwarded:
                forwarded.append(snapshot)
                injected.append(registry.put_json(
                    {"fixture": "NON_EVIDENTIARY snapshot interleaving; no authority"},
                    logical_type="non_evidentiary_interleaving",
                    origin="actual adverse registry append after actual snapshot",
                    creator_role=Role.EVIDENCE_CURATOR,
                    creation_command=("test", "non-evidentiary-interleaving"),
                    schema_version="1.0", mime_type="application/json",
                    validation_result="FAIL", frozen=False,
                ))
            return snapshot

        with patch.object(ArtifactRegistry, "verify_all", new=snapshot_then_append):
            with self.assertRaisesRegex(
                design.ScientificPromotionError, "sources changed before admission",
            ):
                self.register()
        self.assertEqual(forwarded, [before[0]])
        self.assertEqual(len(injected), 1)
        self.assert_only_record_added(before, injected[0])
        self.assertFalse(any(
            r.logical_type == "evaluation_contract" for r in self.registry.list_records()
        ))
        self.assertEqual(self.registry.get_metadata(injected[0].sha256), injected[0])


if __name__ == "__main__":
    unittest.main()
