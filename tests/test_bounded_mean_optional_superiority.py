"""Bounded-mean optional-superiority boundary tests.

The numerical cases below call the real bounded-mean arithmetic, but they do
not claim scientific authority: the numeric DTO is not a source-owned
execution, dataset, sampling, or custody attestation.  Registry fixtures are
also deliberately inert.  They exercise only closed receipt codecs and the
mechanical slot/preflight boundary; no fixture is passed to a scientific
source owner as a positive result.
"""

from __future__ import annotations

from dataclasses import fields, replace
from fractions import Fraction
import hashlib
import math
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.bounded_mean_inference import (
    BOUNDED_MEAN_INTERVAL_METHOD_ID,
    BOUNDED_MEAN_ZERO_P_METHOD_ID,
    BoundedMeanInferencePlan,
    PairedRowCorrectnessCounts,
    analyze_fixed_complete_bounded_mean,
)
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
import scientist_one.scientific_design as sd
from scientist_one.scientific_design import (
    BOUNDED_MEAN_HYPOTHESIS_OUTCOME_ORDER,
    CHECKED_SUPERIORITY_RECEIPT_SCHEMA_V2,
    CHECKED_SUPERIORITY_RECEIPT_SCHEMA_V3,
    CheckedSuperiorityPromotionV2,
    CheckedSuperiorityPromotionV3,
    HypothesisEvaluationPolicy,
    ScientificPromotionError,
    StatisticalPlan,
    SuperiorityValidationStatus,
)
from unittest import mock
from tests import test_bounded_mean_hypothesis_static_review as inert_roots


_FIXED_CREATED_AT = "2026-09-06T12:00:00Z"


def _policy(*, margin: float, minimum: int) -> HypothesisEvaluationPolicy:
    return HypothesisEvaluationPolicy(
        policy_id="bounded-policy",
        hypothesis_id="hypothesis-primary",
        metric_id="accuracy",
        meaningful_effect=margin,
        falsification_effect=margin,
        alpha=0.05,
        minimum_sample_size=minimum,
        rule_id=sd.BOUNDED_MEAN_DECISION_RULE_ID,
        outcome_order=BOUNDED_MEAN_HYPOTHESIS_OUTCOME_ORDER,
    )


def _statistical_plan(*, margin: float, minimum: int) -> StatisticalPlan:
    return StatisticalPlan(
        primary_test=BOUNDED_MEAN_ZERO_P_METHOD_ID,
        alpha=0.05,
        effect_size="exact conditional mean difference",
        confidence_interval=BOUNDED_MEAN_INTERVAL_METHOD_ID,
        resampling_unit="confirmatory-unit",
        comparison_family_size=1,
        multiplicity_correction="not applicable",
        minimum_effect=margin,
        minimum_sample_size=minimum,
        power_or_sensitivity="fixed bounded-mean boundary fixture",
    )


def _native_numeric(
    differences: tuple[int, ...],
    *,
    seed_count: int,
    margin: float,
    minimum: int | None = None,
):
    minimum = len(differences) if minimum is None else minimum
    unit_ids = tuple(f"unit-{index}" for index in range(len(differences)))
    plan = BoundedMeanInferencePlan(
        alpha=0.05,
        benefit_margin=margin,
        harm_margin=margin,
        minimum_unit_count=minimum,
        unit_ids=unit_ids,
        seed_order=tuple(range(seed_count)),
    )
    rows = tuple(
        PairedRowCorrectnessCounts(
            unit_id,
            seed_count,
            max(difference, 0),
            max(-difference, 0),
        )
        for unit_id, difference in zip(unit_ids, differences, strict=True)
    )
    result = analyze_fixed_complete_bounded_mean(plan=plan, rows=rows)
    policy = _policy(margin=margin, minimum=minimum)
    statistical_plan = _statistical_plan(margin=margin, minimum=minimum)
    return policy, statistical_plan, result


def _all_rows(count: int, difference: int) -> tuple[int, ...]:
    return (difference,) * count


def _support_record(registry: ArtifactRegistry, index: int):
    return registry.put_json(
        {"inert_support": index},
        logical_type="inert_optional_superiority_support",
        origin="inert optional-superiority boundary fixture",
        creator_role=Role.ORCHESTRATOR,
        creation_command=("test", "inert-optional-support"),
        parent_artifacts=(),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=_FIXED_CREATED_AT,
    )


def _v3_receipt(
    supports,
    *,
    receipt_id: str = "bounded-receipt",
    assessment_index: int = 0,
    execution_index: int = 1,
    contract_index: int = 2,
    statistical_use_index: int = 3,
    improvement_effect: float = 0.25,
    confidence_low: float = 0.10,
    confidence_high: float = 0.30,
    mean_zero_p_upper: float = 0.001,
    sample_size: int = 100,
) -> CheckedSuperiorityPromotionV3:
    assessment = supports[assessment_index]
    execution = supports[execution_index]
    contract = supports[contract_index]
    statistical_use = supports[statistical_use_index]
    return CheckedSuperiorityPromotionV3(
        receipt_id=receipt_id,
        checked_result_assessment_artifact_sha256=assessment.sha256,
        checked_result_assessment_record_hash=str(assessment.record_hash),
        scientific_execution_authority_artifact_sha256=execution.sha256,
        scientific_execution_authority_record_hash=str(execution.record_hash),
        contract_artifact_sha256=contract.sha256,
        contract_record_hash=str(contract.record_hash),
        statistical_use_authority_artifact_sha256=statistical_use.sha256,
        statistical_use_authority_record_hash=str(statistical_use.record_hash),
        frozen_policy_sha256=supports[4].sha256,
        improvement_effect=improvement_effect,
        confidence_low=confidence_low,
        confidence_high=confidence_high,
        mean_zero_p_upper=mean_zero_p_upper,
        sample_size=sample_size,
    )


def _v2_receipt(
    supports,
    *,
    receipt_id: str = "legacy-receipt",
    assessment_index: int = 0,
    execution_index: int = 1,
) -> CheckedSuperiorityPromotionV2:
    assessment = supports[assessment_index]
    execution = supports[execution_index]
    return CheckedSuperiorityPromotionV2(
        receipt_id=receipt_id,
        checked_result_assessment_artifact_sha256=assessment.sha256,
        checked_result_assessment_record_hash=str(assessment.record_hash),
        scientific_execution_authority_artifact_sha256=execution.sha256,
        scientific_execution_authority_record_hash=str(execution.record_hash),
        improvement_effect=0.25,
        confidence_low=0.10,
        confidence_high=0.30,
        adjusted_p_value=0.001,
        sample_size=100,
    )


def _put_optional_record(registry: ArtifactRegistry, receipt):
    schema, origin, command = sd._optional_superiority_metadata(receipt)
    return registry.put_json(
        receipt.to_dict(),
        logical_type=sd.CHECKED_SUPERIORITY_RECEIPT_LOGICAL_TYPE_V2,
        origin=origin,
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=command,
        parent_artifacts=receipt.source_artifact_hashes,
        schema_version=schema,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=_FIXED_CREATED_AT,
    )


class _FloatSubclass(float):
    pass


class _IntSubclass(int):
    pass


class _HostileEqStr(str):
    equality_calls = 0

    def __eq__(self, other: object) -> bool:
        type(self).equality_calls += 1
        raise AssertionError("hostile equality hook was evaluated")


class _HostileFloat(float):
    float_calls = 0

    def __float__(self) -> float:
        type(self).float_calls += 1
        raise AssertionError("hostile float hook was evaluated")


class BoundedMeanOptionalSuperiorityTests(unittest.TestCase):
    def test_native_partial_gate_uses_exact_mean_not_established_margin(self) -> None:
        policy, statistical_plan, numeric = _native_numeric(
            _all_rows(4096, 3), seed_count=24, margin=0.125
        )
        self.assertEqual(numeric.decision.value, "PARTIALLY_SUPPORTED")
        self.assertGreater(numeric.confidence_low, 0.0)
        self.assertLess(numeric.confidence_low, 0.125)
        accepted = sd._require_bounded_mean_optional_superiority_numeric(
            policy, numeric, statistical_plan
        )
        self.assertEqual(
            Fraction(accepted.mean_numerator, accepted.mean_denominator),
            Fraction(1, 8),
        )

    def test_native_fraction_gate_rejects_display_equal_binary64_margin(self) -> None:
        margin = 0.1
        policy, statistical_plan, numeric = _native_numeric(
            _all_rows(4096, 1), seed_count=10, margin=margin
        )
        self.assertEqual(numeric.mean_estimate, margin)
        self.assertLess(
            Fraction(numeric.mean_numerator, numeric.mean_denominator),
            Fraction.from_float(margin),
        )
        with self.assertRaises(ScientificPromotionError):
            sd._require_bounded_mean_optional_superiority_numeric(
                policy, numeric, statistical_plan
            )

        next_margin = math.nextafter(margin, 0.0)
        policy, statistical_plan, numeric = _native_numeric(
            _all_rows(4096, 1), seed_count=10, margin=next_margin
        )
        accepted = sd._require_bounded_mean_optional_superiority_numeric(
            policy, numeric, statistical_plan
        )
        self.assertEqual(accepted.mean_estimate, 0.1)

    def test_native_supported_gate_ignores_auxiliary_sign_p_value(self) -> None:
        differences = (24,) * 2048 + (-1,) * 2048
        policy, statistical_plan, numeric = _native_numeric(
            differences, seed_count=24, margin=0.125
        )
        self.assertEqual(numeric.decision.value, "SUPPORTED")
        self.assertEqual(numeric.auxiliary_sign.p_value_upper, 1.0)
        accepted = sd._require_bounded_mean_optional_superiority_numeric(
            policy, numeric, statistical_plan
        )
        self.assertGreater(accepted.confidence_low, 0.125)

    def test_native_inconclusive_mean_rejects_despite_tiny_sign_p(self) -> None:
        policy, statistical_plan, numeric = _native_numeric(
            _all_rows(1000, 1), seed_count=24, margin=0.02
        )
        self.assertEqual(numeric.decision.value, "INCONCLUSIVE")
        self.assertLess(numeric.auxiliary_sign.p_value_upper, 1e-300)
        self.assertAlmostEqual(numeric.mean_zero_p_upper, 0.8395339395462083)
        with self.assertRaises(ScientificPromotionError):
            sd._require_bounded_mean_optional_superiority_numeric(
                policy, numeric, statistical_plan
            )

    def test_native_positive_ci_inside_equivalence_margins_remains_null(self) -> None:
        policy, statistical_plan, numeric = _native_numeric(
            _all_rows(4096, 2), seed_count=24, margin=0.20
        )
        self.assertGreater(numeric.confidence_low, 0.0)
        self.assertLess(numeric.confidence_high, 0.20)
        self.assertEqual(numeric.decision.value, "EQUIVALENT_WITHIN_MARGINS")
        self.assertEqual(
            sd.derive_bounded_mean_result_assessment(policy, numeric).outcome,
            sd.ScientificResultOutcome.NULL,
        )
        with self.assertRaises(ScientificPromotionError):
            sd._require_bounded_mean_optional_superiority_numeric(
                policy, numeric, statistical_plan
            )

    def test_native_minimum_size_shortfall_is_not_optional_superiority(self) -> None:
        policy, statistical_plan, numeric = _native_numeric(
            _all_rows(1000, 24), seed_count=24, margin=0.125, minimum=1001
        )
        self.assertEqual(numeric.decision.value, "INCONCLUSIVE")
        with self.assertRaises(ScientificPromotionError):
            sd._require_bounded_mean_optional_superiority_numeric(
                policy, numeric, statistical_plan
            )

    def test_native_positive_min_subnormal_is_preserved_as_a_positive_bound(self) -> None:
        policy, statistical_plan, numeric = _native_numeric(
            _all_rows(4096, 24), seed_count=24, margin=0.125
        )
        self.assertEqual(numeric.mean_zero_p_upper, math.nextafter(0.0, 1.0))
        self.assertGreater(numeric.mean_zero_p_upper, 0.0)
        accepted = sd._require_bounded_mean_optional_superiority_numeric(
            policy, numeric, statistical_plan
        )
        self.assertEqual(accepted.mean_zero_p_upper, math.nextafter(0.0, 1.0))

    def test_gate_reconstructs_native_derived_facts_and_rejects_tampering(self) -> None:
        policy, statistical_plan, numeric = _native_numeric(
            _all_rows(4096, 3), seed_count=24, margin=0.125
        )
        for name, value in (
            ("mean_estimate", 0.5),
            ("mean_numerator", 1),
            ("confidence_low", 0.5),
            ("mean_zero_p_upper", 0.5),
        ):
            with self.subTest(name=name):
                candidate = analyze_fixed_complete_bounded_mean(
                    plan=numeric.plan, rows=numeric.rows
                )
                object.__setattr__(candidate, name, value)
                with self.assertRaises(sd.ScientificDesignError):
                    sd._require_bounded_mean_optional_superiority_numeric(
                        policy, candidate, statistical_plan
                    )

    def test_numeric_gate_rejects_non_native_leaf_hooks_before_coercion(self) -> None:
        policy, statistical_plan, numeric = _native_numeric(
            _all_rows(4096, 3), seed_count=24, margin=0.125
        )
        _HostileFloat.float_calls = 0
        object.__setattr__(numeric, "mean_estimate", _HostileFloat(0.125))
        with self.assertRaises(ScientificPromotionError):
            sd._require_bounded_mean_optional_superiority_numeric(
                policy, numeric, statistical_plan
            )
        self.assertEqual(_HostileFloat.float_calls, 0)

        policy, statistical_plan, numeric = _native_numeric(
            _all_rows(4096, 3), seed_count=24, margin=0.125
        )
        _HostileEqStr.equality_calls = 0
        object.__setattr__(policy, "policy_id", _HostileEqStr(policy.policy_id))
        with self.assertRaises(ScientificPromotionError):
            sd._require_bounded_mean_optional_superiority_numeric(
                policy, numeric, statistical_plan
            )
        self.assertEqual(_HostileEqStr.equality_calls, 0)

    def test_numeric_gate_requires_the_frozen_native_method_profile(self) -> None:
        policy, statistical_plan, numeric = _native_numeric(
            _all_rows(4096, 3), seed_count=24, margin=0.125
        )
        for name, changes in (
            ("primary_test", {"primary_test": "two-sided exact sign"}),
            ("confidence_interval", {"confidence_interval": "paired bootstrap"}),
            (
                "comparison_family_size",
                {"comparison_family_size": 2, "multiplicity_correction": "Holm"},
            ),
            (
                "minimum_effect",
                {"minimum_effect": math.nextafter(0.125, math.inf)},
            ),
        ):
            with self.subTest(name=name):
                candidate = replace(statistical_plan, **changes)
                with self.assertRaises(ScientificPromotionError):
                    sd._require_bounded_mean_optional_superiority_numeric(
                        policy, numeric, candidate
                    )

    def test_v3_codec_is_closed_and_has_only_conditional_fields(self) -> None:
        with TemporaryDirectory(prefix="bounded-v3-codec-") as directory:
            registry = ArtifactRegistry(directory)
            supports = tuple(_support_record(registry, index) for index in range(6))
            receipt = _v3_receipt(supports)
        payload = receipt.to_dict()
        self.assertEqual(set(payload), set(CheckedSuperiorityPromotionV3.__dataclass_fields__) | {"schema_version"})
        self.assertEqual(payload["schema_version"], CHECKED_SUPERIORITY_RECEIPT_SCHEMA_V3)
        self.assertNotIn("adjusted_p_value", payload)
        self.assertNotIn("raw_p_value", payload)
        self.assertNotIn("sign_p_value", payload)
        self.assertNotIn("bootstrap_seed", payload)
        self.assertNotIn("bootstrap_resamples", payload)
        self.assertEqual(CheckedSuperiorityPromotionV3.from_dict(payload), receipt)
        for field_name in payload:
            candidate = dict(payload)
            del candidate[field_name]
            with self.subTest(missing=field_name):
                with self.assertRaises(ScientificPromotionError):
                    CheckedSuperiorityPromotionV3.from_dict(candidate)
        for alias in (
            "adjusted_p_value",
            "raw_p_value",
            "sign_p_value",
            "mean_p_value",
            "bootstrap_seed",
            "candidate_value",
            "baseline_value",
        ):
            with self.subTest(alias=alias), self.assertRaises(ScientificPromotionError):
                CheckedSuperiorityPromotionV3.from_dict({**payload, alias: None})

    def test_v3_codec_rejects_mixed_schema_and_scope_aliases(self) -> None:
        with TemporaryDirectory(prefix="bounded-v3-mixed-") as directory:
            registry = ArtifactRegistry(directory)
            supports = tuple(_support_record(registry, index) for index in range(6))
            payload = _v3_receipt(supports).to_dict()
        for schema in (
            CHECKED_SUPERIORITY_RECEIPT_SCHEMA_V2,
            "checked-superiority-promotion/v1",
            "checked-superiority-promotion/v99",
        ):
            with self.subTest(schema=schema), self.assertRaises(ScientificPromotionError):
                CheckedSuperiorityPromotionV3.from_dict(
                    {**payload, "schema_version": schema}
                )
        for name, value in (
            ("inference_profile_id", "unsupported-profile"),
            ("claim_scope", "END_TO_END"),
            ("conditional_scope", "UNCONDITIONAL"),
            ("scientific_evidence_eligible", False),
            ("status", SuperiorityValidationStatus.DIAGNOSTIC_ONLY.value),
            ("sample_size", 0),
        ):
            with self.subTest(name=name), self.assertRaises(ScientificPromotionError):
                CheckedSuperiorityPromotionV3.from_dict({**payload, name: value})

    def test_v3_codec_requires_exact_native_finite_scalars_and_no_hooks(self) -> None:
        with TemporaryDirectory(prefix="bounded-v3-scalars-") as directory:
            registry = ArtifactRegistry(directory)
            supports = tuple(_support_record(registry, index) for index in range(6))
            payload = _v3_receipt(supports).to_dict()
        for name in (
            "receipt_id",
            "checked_result_assessment_artifact_sha256",
            "checked_result_assessment_record_hash",
            "scientific_execution_authority_artifact_sha256",
            "scientific_execution_authority_record_hash",
            "contract_artifact_sha256",
            "contract_record_hash",
            "statistical_use_authority_artifact_sha256",
            "statistical_use_authority_record_hash",
            "frozen_policy_sha256",
            "inference_profile_id",
            "claim_scope",
            "conditional_scope",
        ):
            candidate = dict(payload)
            candidate[name] = _HostileEqStr(candidate[name])
            with self.subTest(name=name), self.assertRaises(ScientificPromotionError):
                CheckedSuperiorityPromotionV3.from_dict(candidate)
        for name in (
            "improvement_effect",
            "confidence_low",
            "confidence_high",
            "mean_zero_p_upper",
        ):
            for value in (None, True, "0", math.nan, math.inf, -math.inf, _FloatSubclass(0.2)):
                candidate = dict(payload)
                candidate[name] = value
                with self.subTest(name=name, value=repr(value)), self.assertRaises(ScientificPromotionError):
                    CheckedSuperiorityPromotionV3.from_dict(candidate)
        candidate = dict(payload)
        candidate["sample_size"] = _IntSubclass(100)
        with self.assertRaises(ScientificPromotionError):
            CheckedSuperiorityPromotionV3.from_dict(candidate)

        receipt = CheckedSuperiorityPromotionV3.from_dict(payload)
        _HostileEqStr.equality_calls = 0
        object.__setattr__(receipt, "receipt_id", _HostileEqStr(receipt.receipt_id))
        with self.assertRaises(ScientificPromotionError):
            sd._optional_superiority_canonical_bytes(receipt)
        self.assertEqual(_HostileEqStr.equality_calls, 0)
        receipt = CheckedSuperiorityPromotionV3.from_dict(payload)
        _HostileFloat.float_calls = 0
        object.__setattr__(receipt, "improvement_effect", _HostileFloat(0.2))
        with self.assertRaises(ScientificPromotionError):
            sd._optional_superiority_canonical_bytes(receipt)
        self.assertEqual(_HostileFloat.float_calls, 0)

    def test_v3_source_artifacts_are_four_ordered_nonaliased_parents(self) -> None:
        with TemporaryDirectory(prefix="bounded-v3-alias-") as directory:
            registry = ArtifactRegistry(directory)
            supports = tuple(_support_record(registry, index) for index in range(6))
            receipt = _v3_receipt(supports)
            self.assertEqual(
                receipt.source_artifact_hashes,
                tuple(supports[index].sha256 for index in (0, 1, 2, 3)),
            )
            self.assertEqual(len(set(receipt.source_artifact_hashes)), 4)
            for name in (
                "checked_result_assessment_artifact_sha256",
                "scientific_execution_authority_artifact_sha256",
                "contract_artifact_sha256",
                "statistical_use_authority_artifact_sha256",
            ):
                candidate = (
                    receipt.source_artifact_hashes[1]
                    if name == "checked_result_assessment_artifact_sha256"
                    else receipt.source_artifact_hashes[0]
                )
                arguments = {
                    field.name: getattr(receipt, field.name)
                    for field in fields(receipt)
                }
                arguments[name] = candidate
                with self.subTest(name=name), self.assertRaises(ScientificPromotionError):
                    CheckedSuperiorityPromotionV3(**arguments)

    def test_v2_payload_bytes_remain_the_exact_legacy_golden(self) -> None:
        golden = CheckedSuperiorityPromotionV2(
            receipt_id="legacy-receipt",
            checked_result_assessment_artifact_sha256="a" * 64,
            checked_result_assessment_record_hash="b" * 64,
            scientific_execution_authority_artifact_sha256="c" * 64,
            scientific_execution_authority_record_hash="d" * 64,
            improvement_effect=0.25,
            confidence_low=0.10,
            confidence_high=0.30,
            adjusted_p_value=0.001,
            sample_size=100,
        )
        expected = (
            b'{"adjusted_p_value":0.001,"checked_result_assessment_artifact_sha256":"'
            + b"a" * 64
            + b'","checked_result_assessment_record_hash":"'
            + b"b" * 64
            + b'","confidence_high":0.3,"confidence_low":0.1,"improvement_effect":0.25,'
            b'"receipt_id":"legacy-receipt","sample_size":100,"schema_version":"checked-superiority-promotion/v2",'
            b'"scientific_evidence_eligible":true,"scientific_execution_authority_artifact_sha256":"'
            + b"c" * 64
            + b'","scientific_execution_authority_record_hash":"'
            + b"d" * 64
            + b'","status":"SCIENTIFIC_PROMOTION_AUTHORIZED"}\n'
        )
        raw = canonical_json_bytes(golden.to_dict()) + b"\n"
        self.assertEqual(raw, expected)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "e3ee100920ab371803b96c9d141b5e85cd4d2311ab55b93ee02df5becc3d4001",
        )
        self.assertEqual(CheckedSuperiorityPromotionV2.from_dict(golden.to_dict()), golden)

    def test_private_preflight_is_idempotent_read_only_and_checks_slot_identity(self) -> None:
        with TemporaryDirectory(prefix="bounded-v3-slots-") as directory:
            registry = ArtifactRegistry(directory)
            supports = tuple(_support_record(registry, index) for index in range(6))
            receipt = _v3_receipt(supports)
            before = registry.verify_all(raise_on_error=True)
            raw, existing = sd._preflight_optional_superiority_publication(
                registry, before, receipt
            )
            self.assertIsNone(existing)
            self.assertEqual(raw, canonical_json_bytes(receipt.to_dict()) + b"\n")
            self.assertEqual(registry.verify_all(raise_on_error=True), before)
            record = _put_optional_record(registry, receipt)
            before = registry.verify_all(raise_on_error=True)
            raw, existing = sd._preflight_optional_superiority_publication(
                registry, before, receipt
            )
            self.assertEqual(existing, record)
            self.assertEqual(raw, registry.get_bytes(record.sha256))
            self.assertEqual(registry.verify_all(raise_on_error=True), before)
            for name, change in (
                ("receipt_id", {"receipt_id": "other-receipt"}),
                (
                    "assessment",
                    {
                        "checked_result_assessment_artifact_sha256": supports[5].sha256,
                        "checked_result_assessment_record_hash": str(supports[5].record_hash),
                    },
                ),
                (
                    "execution",
                    {
                        "scientific_execution_authority_artifact_sha256": supports[5].sha256,
                        "scientific_execution_authority_record_hash": str(supports[5].record_hash),
                    },
                ),
            ):
                candidate = replace(receipt, improvement_effect=0.26, **change)
                with self.subTest(identity=name):
                    with self.assertRaisesRegex(ScientificPromotionError, "identity slot is occupied"):
                        sd._preflight_optional_superiority_publication(
                            registry, before, candidate
                        )
                    self.assertEqual(registry.verify_all(raise_on_error=True), before)

    def test_cross_version_each_identity_dimension_is_an_ambiguous_shared_slot(self) -> None:
        for identity in ("receipt", "assessment", "execution"):
            with self.subTest(identity=identity), TemporaryDirectory(
                prefix="bounded-cross-version-slot-"
            ) as directory:
                registry = ArtifactRegistry(directory)
                supports = tuple(_support_record(registry, index) for index in range(10))
                if identity == "receipt":
                    v2 = _v2_receipt(supports, receipt_id="shared")
                    v3 = _v3_receipt(
                        supports,
                        receipt_id="shared",
                        assessment_index=2,
                        execution_index=3,
                        contract_index=4,
                        statistical_use_index=5,
                    )
                elif identity == "assessment":
                    v2 = _v2_receipt(supports, receipt_id="legacy", assessment_index=0, execution_index=1)
                    v3 = _v3_receipt(
                        supports,
                        receipt_id="bounded",
                        assessment_index=0,
                        execution_index=3,
                        contract_index=2,
                        statistical_use_index=4,
                    )
                else:
                    v2 = _v2_receipt(supports, receipt_id="legacy", assessment_index=0, execution_index=1)
                    v3 = _v3_receipt(
                        supports,
                        receipt_id="bounded",
                        assessment_index=2,
                        execution_index=1,
                        contract_index=3,
                        statistical_use_index=4,
                    )
                _put_optional_record(registry, v2)
                v3_record = _put_optional_record(registry, v3)
                snapshot = registry.verify_all(raise_on_error=True)
                with self.assertRaisesRegex(ScientificPromotionError, "ambiguous"):
                    sd._preflight_optional_superiority_publication(
                        registry, snapshot, v3
                    )
                self.assertEqual(
                    sd._parse_optional_superiority_record(registry, v3_record), v3
                )

    def test_malformed_optional_records_fail_closed_before_any_preflight_write(self) -> None:
        for malformed in ("unknown-schema", "wrong-origin", "wrong-command", "wrong-role", "parent-order", "payload-schema"):
            with self.subTest(malformed=malformed), TemporaryDirectory(
                prefix="bounded-malformed-slot-"
            ) as directory:
                registry = ArtifactRegistry(directory)
                supports = tuple(_support_record(registry, index) for index in range(6))
                receipt = _v3_receipt(supports)
                payload = receipt.to_dict()
                origin, command = sd._CHECKED_SUPERIORITY_V3_ORIGIN, sd._CHECKED_SUPERIORITY_V3_COMMAND
                schema, role, parents = "2.0", Role.CLAIM_VERIFIER, receipt.source_artifact_hashes
                if malformed == "unknown-schema":
                    schema = "9.0"
                elif malformed == "wrong-origin":
                    origin = "wrong optional-superiority origin"
                elif malformed == "wrong-command":
                    command = ("wrong", "optional-superiority")
                elif malformed == "wrong-role":
                    role = Role.ORCHESTRATOR
                elif malformed == "parent-order":
                    parents = tuple(reversed(parents))
                else:
                    payload["schema_version"] = "checked-superiority-promotion/v99"
                record = registry.put_json(
                    payload,
                    logical_type=sd.CHECKED_SUPERIORITY_RECEIPT_LOGICAL_TYPE_V2,
                    origin=origin,
                    creator_role=role,
                    creation_command=command,
                    parent_artifacts=parents,
                    schema_version=schema,
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                    created_at=_FIXED_CREATED_AT,
                )
                before = registry.verify_all(raise_on_error=True)
                with self.assertRaises(ScientificPromotionError):
                    sd._parse_optional_superiority_record(registry, record)
                self.assertEqual(registry.verify_all(raise_on_error=True), before)

    def test_preflight_capacity_is_fail_closed_without_a_registry_write(self) -> None:
        with TemporaryDirectory(prefix="bounded-capacity-") as directory:
            registry = ArtifactRegistry(directory)
            supports = tuple(_support_record(registry, index) for index in range(6))
            receipt = _v3_receipt(supports)
            snapshot = registry.verify_all(raise_on_error=True)
            raw = sd._optional_superiority_canonical_bytes(receipt)
            with mock.patch.object(sd, "MAX_ARTIFACT_OBJECT_BYTES", len(raw) - 1):
                with self.assertRaisesRegex(ScientificPromotionError, "capacity"):
                    sd._preflight_optional_superiority_publication(
                        registry, snapshot, receipt
                    )
            with mock.patch.object(sd, "MAX_ARTIFACT_PARENTS", 3):
                with self.assertRaisesRegex(ScientificPromotionError, "capacity"):
                    sd._preflight_optional_superiority_publication(
                        registry, snapshot, receipt
                    )
            self.assertEqual(registry.verify_all(raise_on_error=True), snapshot)

    def test_public_source_owners_reject_inert_roots_without_admission_delta(self) -> None:
        with TemporaryDirectory(prefix="bounded-source-owner-rejection-") as directory:
            repository, _authority, _stored, projection, support = inert_roots._inert_static_fixture(directory)
            registry, ledger = repository.registry, repository.ledger
            # Initialize storage before the attempted calls so lock-file creation
            # cannot be mistaken for a scientific admission write.
            registry_before = registry.verify_all(raise_on_error=True)
            ledger_before = ledger.validate(raise_on_error=True)
            assessment_record = next(
                record
                for record in registry_before.records
                if record.logical_type == sd.CHECKED_RESULT_ASSESSMENT_LOGICAL_TYPE
            )
            arguments = {
                "receipt_id": "inert-source-owner-receipt",
                "assessment_artifact_sha256": assessment_record.sha256,
                "expected_ledger_run_id": projection.ledger_run_id,
                "expected_execution_run_id": projection.execution_run_id,
            }
            with self.assertRaises(sd.ScientificDesignError):
                sd.register_checked_superiority_promotion_v2(
                    registry, ledger, **arguments
                )
            self.assertEqual(registry.verify_all(raise_on_error=True), registry_before)
            self.assertEqual(ledger.validate(raise_on_error=True), ledger_before)

            inert_receipt = _v3_receipt(tuple(support.values()), receipt_id="inert-readback")
            inert_record = _put_optional_record(registry, inert_receipt)
            registry_before = registry.verify_all(raise_on_error=True)
            ledger_before = ledger.validate(raise_on_error=True)
            with self.assertRaises(sd.ScientificDesignError):
                sd.require_checked_superiority_promotion_v2(
                    registry,
                    ledger,
                    receipt_artifact_sha256=inert_record.sha256,
                    expected_ledger_run_id=projection.ledger_run_id,
                    expected_execution_run_id=projection.execution_run_id,
                )
            self.assertEqual(registry.verify_all(raise_on_error=True), registry_before)
            self.assertEqual(ledger.validate(raise_on_error=True), ledger_before)


if __name__ == "__main__":
    unittest.main()
