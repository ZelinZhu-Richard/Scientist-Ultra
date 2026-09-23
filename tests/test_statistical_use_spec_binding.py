"""Non-evidentiary spec selectors and fail-closed prospective admission.

No test signs a source, provisions a key, or patches an authority to PASS.
Positive controls are historical spec replay and a non-authoritative path
selector; a scientific statistical-use binding still needs its real owners.
"""

from dataclasses import replace
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scientist_one.bounded_mean_inference import (
    BOUNDED_MEAN_DECISION_RULE_ID,
    BOUNDED_MEAN_INTERVAL_METHOD_ID,
    BOUNDED_MEAN_PROFILE_ID,
    BOUNDED_MEAN_ZERO_P_METHOD_ID,
)
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.experiments import (
    EvidenceClass,
    ExperimentError,
    SCIENTIFIC_STATISTICAL_USE_BINDING_METADATA_KEY,
    SCIENTIFIC_STATISTICAL_USE_BINDING_SCHEMA,
    _scientific_statistical_use_context,
    require_scientific_execution_run_spec,
    resolve_scientific_statistical_use_binding,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    BOUNDED_MEAN_HYPOTHESIS_OUTCOME_ORDER,
    register_frozen_evaluation_contract,
    register_frozen_experiment_plan,
    register_frozen_run_spec,
)
from tests.test_hypothesis_evaluation_and_rejections import _policies
from tests.test_scientific_method_alignment import _prepared_canonical_timeline


def _declaration(**changes):
    value = {
        "schema_version": SCIENTIFIC_STATISTICAL_USE_BINDING_SCHEMA,
        "profile_id": BOUNDED_MEAN_PROFILE_ID,
        "ledger_run_id": "timeline",
        "statistical_use_authority_artifact_sha256": "a" * 64,
        "statistical_use_authority_record_hash": "b" * 64,
    }
    value.update(changes)
    return value


def _spec(spec, declaration):
    return replace(
        spec,
        metadata={
            **dict(spec.to_dict()["metadata"]),
            SCIENTIFIC_STATISTICAL_USE_BINDING_METADATA_KEY: declaration,
        },
    )


class StatisticalUseSpecBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.values = _prepared_canonical_timeline(self.temporary.name)
        self.registry = self.values["registry"]
        self.spec = self.values["spec"]

    def _resolve(self, spec, contract_record=None):
        return resolve_scientific_statistical_use_binding(
            self.registry,
            spec=spec,
            expected_contract_artifact_sha256=(
                contract_record or self.values["contract_record"]
            ).sha256,
        )

    def _new_contract(self, marker):
        original = self.values["contract"]
        # These are independent prospective policy-marker specimens, not
        # revisions of the prepared contract. No freeze or result is present.
        # Same-ID changes now require real persisted amendment lineage; do not
        # exercise that unrelated lifecycle merely to test missing-use refusal.
        self.assertEqual(self.values["ledger"].assert_valid().events, ())
        original = replace(original, contract_id=f"statistical-marker-{marker}")
        if marker == "policy":
            contract = replace(
                original,
                hypothesis_evaluation_policies=tuple(
                    replace(
                        policy,
                        rule_id=BOUNDED_MEAN_DECISION_RULE_ID,
                        outcome_order=BOUNDED_MEAN_HYPOTHESIS_OUTCOME_ORDER,
                    )
                    for policy in _policies(original)
                ),
            )
        else:
            contract = replace(
                original,
                statistical_plan=replace(
                    original.statistical_plan,
                    **{
                        marker: BOUNDED_MEAN_ZERO_P_METHOD_ID
                        if marker == "primary_test"
                        else BOUNDED_MEAN_INTERVAL_METHOD_ID
                    },
                ),
            )
        record = register_frozen_evaluation_contract(
            self.registry,
            contract=contract,
            parent_artifact_sha256s=(self.values["evidence"].sha256,),
        )
        return contract, record

    def test_absent_binding_preserves_legacy_spec_and_registration_bytes(self):
        self.assertIsNone(self._resolve(self.spec))
        before = self.registry.verify_all(raise_on_error=True)
        record = register_frozen_run_spec(
            self.registry,
            contract=self.values["contract"],
            contract_artifact_sha256=self.values["contract_record"].sha256,
            experiment_plan_artifact_sha256s=tuple(
                row.sha256 for row in self.values["plan_records"]
            ),
            spec=self.spec,
        )
        self.assertEqual(record, self.values["spec_record"])
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)

    def test_each_new_contract_marker_prevents_missing_binding_downgrade(self):
        for marker in ("policy", "primary_test", "confidence_interval"):
            with self.subTest(marker=marker):
                _contract, record = self._new_contract(marker)
                with self.assertRaisesRegex(
                    ExperimentError, "requires its prospective"
                ):
                    self._resolve(self.spec, record)

    def test_new_contract_missing_binding_is_zero_write_at_registration(self):
        contract, contract_record = self._new_contract("policy")
        plan_records = tuple(
            register_frozen_experiment_plan(
                self.registry,
                contract=contract,
                contract_artifact_sha256=contract_record.sha256,
                plan=replace(plan, contract_sha256=contract.sha256),
            )
            for plan in self.values["plans"]
        )
        before = self.registry.verify_all(raise_on_error=True)
        with self.assertRaisesRegex(ExperimentError, "requires its prospective"):
            register_frozen_run_spec(
                self.registry,
                contract=contract,
                contract_artifact_sha256=contract_record.sha256,
                experiment_plan_artifact_sha256s=tuple(
                    row.sha256 for row in plan_records
                ),
                spec=self.spec,
            )
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)

    def test_registry_only_public_getter_cannot_downgrade_new_contract(self):
        _contract, contract_record = self._new_contract("policy")
        spec = replace(
            self.spec, evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE
        )
        # Deliberately inert, caller-authored spec: exact ordinary descriptors
        # are insufficient to bypass the missing reviewed statistical-use join.
        record = self.registry.put_json(
            spec.to_dict(),
            logical_type="frozen_run_spec",
            origin="run spec frozen after scientific-plan admission and before execution",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "freeze-run-spec"),
            parent_artifacts=(
                contract_record.sha256,
                *(row.sha256 for row in self.values["plan_records"]),
                spec.code_sha256,
                spec.data_sha256,
                spec.configuration_sha256,
                spec.evaluator_sha256,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        with self.assertRaisesRegex(ExperimentError, "requires its prospective"):
            require_scientific_execution_run_spec(
                self.registry,
                frozen_run_spec_artifact_sha256=record.sha256,
            )

    def test_reserved_binding_is_closed_not_an_optional_hint(self):
        complete = _declaration()
        invalid = [None, {}, {**complete, "extra": True}]
        invalid.extend(
            {key: value for key, value in complete.items() if key != omitted}
            for omitted in complete
        )
        invalid.extend(
            (
                _declaration(profile_id="old-bootstrap-profile"),
                _declaration(schema_version="unreviewed/v2"),
                _declaration(statistical_use_authority_record_hash="invalid"),
            )
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    self._resolve(_spec(self.spec, value))

    def test_wrong_run_is_rejected_before_ledger_construction(self):
        for run_id in ("another-run", self.spec.run_id, "../timeline"):
            with self.subTest(run_id=run_id):
                with patch("scientist_one.experiments.EventLedger") as constructor:
                    with self.assertRaises(ValidationError):
                        _scientific_statistical_use_context(
                            self.registry,
                            _spec(self.spec, _declaration(ledger_run_id=run_id)),
                        )
                    constructor.assert_not_called()

    def test_selector_uses_ledger_run_not_execution_run_without_granting_authority(
        self,
    ):
        spec = _spec(self.spec, _declaration())
        ledger, run_id, digest, record_hash = _scientific_statistical_use_context(
            self.registry, spec
        )
        self.assertNotEqual(run_id, spec.run_id)
        self.assertEqual(ledger.relative_path.as_posix(), "runs/timeline/events.jsonl")
        self.assertEqual(ledger.policy.root, self.registry.policy.root)
        self.assertEqual((digest, record_hash), ("a" * 64, "b" * 64))
        before = self.registry.verify_all(raise_on_error=True)
        with self.assertRaises((ValidationError, ArtifactError)):
            self._resolve(spec)
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)

    def test_missing_authority_cannot_create_prospective_spec(self):
        before = self.registry.verify_all(raise_on_error=True)
        with self.assertRaises((ValidationError, ArtifactError)):
            register_frozen_run_spec(
                self.registry,
                contract=self.values["contract"],
                contract_artifact_sha256=self.values["contract_record"].sha256,
                experiment_plan_artifact_sha256s=tuple(
                    row.sha256 for row in self.values["plan_records"]
                ),
                spec=_spec(self.spec, _declaration()),
            )
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)


if __name__ == "__main__":
    unittest.main()
