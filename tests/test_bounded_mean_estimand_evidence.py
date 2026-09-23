"""Inert native bounded-mean ESTIMAND joins and source-owner refusals.

The assessment and contract used below are read from the existing static
fixture.  The contract is reopened with the registry-only frozen parser; no
positive execution, assessment, promotion, issuer, trust map, or signature
owner is patched or called.  A successful private join therefore proves only
that already owner-produced-looking sources have an exact native closure.  It
does not validate arbitrary caller-owned DTOs or confer scientific authority.
"""

from dataclasses import replace
from tempfile import TemporaryDirectory
import unittest

from scientist_one.claims import ClaimEvidenceUse, EvidenceKind
from scientist_one.errors import ValidationError
from scientist_one.roles import Role
from scientist_one.security import safe_json_loads
import scientist_one.research_state as rs
import scientist_one.scientific_design as sd
from tests import test_bounded_mean_hypothesis_evaluation as evaluation_fixtures
from tests import test_bounded_mean_hypothesis_static_review as static_fixtures
from tests import test_bounded_mean_policy as numeric_fixtures


def _frozen_sources(repository):
    records = repository.registry.verify_all(raise_on_error=True).records
    assessment_record = next(
        item for item in records if item.logical_type == "checked_result_assessment"
    )
    contract_record = next(
        item for item in records if item.logical_type == "evaluation_contract"
    )
    assessment = sd.CheckedResultAssessment.from_dict(
        safe_json_loads(repository.registry.get_bytes(assessment_record.sha256))
    )
    contract = sd.require_frozen_evaluation_contract(
        repository.registry,
        contract_artifact_sha256=contract_record.sha256,
    )
    return assessment, contract, assessment_record, contract_record


def _case_bundle(
    base_projection,
    base_assessment,
    contract,
    contract_record,
    *,
    n,
    candidate,
    reference,
):
    numeric = numeric_fixtures._result(
        base_projection.hypothesis_policy,
        n=n,
        candidate=candidate,
        reference=reference,
        seeds=5,
    )
    decision = sd.derive_bounded_mean_result_assessment(
        base_projection.hypothesis_policy,
        numeric,
    )
    projection = replace(
        base_projection,
        candidate_value=candidate / 5,
        baseline_value=reference / 5,
        improvement_effect=numeric.mean_estimate,
        confidence_low=numeric.confidence_low,
        confidence_high=numeric.confidence_high,
        mean_zero_p_upper=numeric.mean_zero_p_upper,
        sample_size=n,
        hypothesis_status=decision.hypothesis_status,
        outcome=decision.outcome,
        numeric_result=numeric,
        seed_order=numeric.plan.seed_order,
    )
    # Keep the checked assessment aligned with each inert projection.  It is
    # still fixture data and never passes a current scientific source owner.
    assessment = replace(
        base_assessment,
        candidate_value=candidate / 5,
        baseline_value=reference / 5,
        improvement_effect=numeric.mean_estimate,
        confidence_low=numeric.confidence_low,
        confidence_high=numeric.confidence_high,
        mean_zero_p_upper=numeric.mean_zero_p_upper,
        sample_size=n,
        hypothesis_status=decision.hypothesis_status,
        outcome=decision.outcome,
    )
    result, statistical_test = evaluation_fixtures._pair(projection)
    # The reused canonical result fixture deliberately retains its historical
    # metric identity; bind it to the static fixture's contract metric here.
    result = replace(result, metric_id=projection.metric_id, content_hash=None)
    return {
        "result": result,
        "statistical_test": statistical_test,
        "projection": projection,
        "assessment": assessment,
        "contract": contract,
        "contract_record": contract_record,
        "experiment_id": projection.experiment_id,
    }


def _join(bundle):
    return rs._require_bounded_estimand_source_bindings(
        result=bundle["result"],
        statistical_test=bundle["statistical_test"],
        projection=bundle["projection"],
        assessment=bundle["assessment"],
        contract=bundle["contract"],
        contract_record=bundle["contract_record"],
        experiment_id=bundle["experiment_id"],
    )


def _admission_snapshot(repository):
    registry = tuple(
        (item.sha256, str(item.record_hash), item.logical_type)
        for item in repository.registry.list_records()
    )
    ledger = tuple((item.event_id, item.event_hash) for item in repository.ledger.events())
    return registry, ledger


def _unit_mismatched_contract(contract):
    primary_metric = replace(
        contract.primary_metric,
        unit=sd.MetricUnit.PERCENT,
    )
    candidate_conditions = replace(
        contract.candidate_conditions,
        metric_unit=sd.MetricUnit.PERCENT,
    )
    baseline_registry = sd.BaselineRegistry(
        tuple(
            replace(
                item,
                conditions=replace(
                    item.conditions,
                    metric_unit=sd.MetricUnit.PERCENT,
                ),
            )
            for item in contract.baseline_registry.entries
        )
    )
    return replace(
        contract,
        primary_metric=primary_metric,
        candidate_conditions=candidate_conditions,
        baseline_registry=baseline_registry,
    )


class BoundedMeanEstimandEvidenceTests(unittest.TestCase):
    """Native ESTIMAND linkage remains inert until real owners are replayed."""

    def test_private_join_accepts_all_native_mean_outcomes_without_admission(self):
        with TemporaryDirectory(prefix="inert-estimand-outcomes-") as directory:
            fixture = static_fixtures._inert_static_fixture(directory)
            repository, _, _, base_projection, _ = fixture
            assessment, contract, _, contract_record = _frozen_sources(repository)
            before = _admission_snapshot(repository)
            cases = (
                ("positive", 1000, 4, 0, sd.ScientificResultOutcome.POSITIVE),
                ("negative", 1000, 2, 3, sd.ScientificResultOutcome.NEGATIVE),
                ("null", 1000, 2, 2, sd.ScientificResultOutcome.NULL),
                ("falsified", 1000, 0, 5, sd.ScientificResultOutcome.FALSIFIED),
                ("inconclusive", 20, 3, 2, sd.ScientificResultOutcome.INCONCLUSIVE),
            )
            for label, n, candidate, reference, expected_outcome in cases:
                with self.subTest(outcome=label):
                    bundle = _case_bundle(
                        base_projection,
                        assessment,
                        contract,
                        contract_record,
                        n=n,
                        candidate=candidate,
                        reference=reference,
                    )
                    self.assertIs(bundle["projection"].outcome, expected_outcome)
                    self.assertIsNone(_join(bundle))
            self.assertEqual(_admission_snapshot(repository), before)

    def test_native_independent_unit_has_no_frozen_resampling_alias(self):
        with TemporaryDirectory(prefix="inert-estimand-unit-") as directory:
            fixture = static_fixtures._inert_static_fixture(directory)
            repository, _, _, projection, _ = fixture
            assessment, contract, _, contract_record = _frozen_sources(repository)
            bundle = _case_bundle(
                projection,
                assessment,
                contract,
                contract_record,
                n=1000,
                candidate=3,
                reference=2,
            )
            configuration = bundle["statistical_test"].method_configuration
            self.assertEqual(
                configuration["independent_unit"],
                "PROSPECTIVELY_REVIEWED_DATASET_ROW",
            )
            self.assertNotIn("resampling_unit", configuration)
            self.assertEqual(contract.statistical_plan.resampling_unit, "subject")
            self.assertNotEqual(
                configuration["independent_unit"],
                contract.statistical_plan.resampling_unit,
            )
            self.assertIsNone(_join(bundle))

    def test_mixed_or_legacy_and_generic_native_fields_are_rejected(self):
        with TemporaryDirectory(prefix="inert-estimand-schema-") as directory:
            fixture = static_fixtures._inert_static_fixture(directory)
            repository, _, _, projection, _ = fixture
            assessment, contract, _, contract_record = _frozen_sources(repository)
            bundle = _case_bundle(
                projection,
                assessment,
                contract,
                contract_record,
                n=1000,
                candidate=3,
                reference=2,
            )

            mutations = []
            result_metadata = dict(bundle["result"].metadata)
            result_metadata["schema_version"] = "scientific-result-canonical-state/v3"
            mutations.append(
                (
                    "mixed-result-schema",
                    {"result": replace(bundle["result"], metadata=result_metadata, content_hash=None)},
                )
            )
            test_metadata = dict(bundle["statistical_test"].metadata)
            test_metadata["schema_version"] = "scientific-statistical-canonical-state/v3"
            mutations.append(
                (
                    "mixed-test-schema",
                    {
                        "statistical_test": replace(
                            bundle["statistical_test"],
                            metadata=test_metadata,
                            content_hash=None,
                        )
                    },
                )
            )
            for field_name in ("independent_unit", "mean_estimand"):
                method_configuration = dict(
                    bundle["statistical_test"].method_configuration
                )
                method_configuration.pop(field_name)
                mutations.append(
                    (
                        f"missing-{field_name}",
                        {
                            "statistical_test": replace(
                                bundle["statistical_test"],
                                method_configuration=method_configuration,
                                content_hash=None,
                            )
                        },
                    )
                )
            for field_name in (
                "resampling_unit",
                "adjusted_p_value",
                "bootstrap_seed",
                "bootstrap_resamples",
                "sign_for_mean_p_value",
            ):
                method_configuration = dict(
                    bundle["statistical_test"].method_configuration
                )
                method_configuration[field_name] = 0
                mutations.append(
                    (
                        f"extra-{field_name}",
                        {
                            "statistical_test": replace(
                                bundle["statistical_test"],
                                method_configuration=method_configuration,
                                content_hash=None,
                            )
                        },
                    )
                )
            outcome = dict(bundle["statistical_test"].outcome)
            outcome["sign_for_mean_p_value"] = 0
            mutations.append(
                (
                    "extra-outcome-sign-for-mean",
                    {
                        "statistical_test": replace(
                            bundle["statistical_test"],
                            outcome=outcome,
                            content_hash=None,
                        )
                    },
                )
            )
            mean_substitution = dict(bundle["statistical_test"].outcome)
            mean_substitution["mean_zero_p_upper"] = (
                bundle["projection"].numeric_result.auxiliary_sign.p_value_upper
            )
            self.assertNotEqual(
                mean_substitution["mean_zero_p_upper"],
                bundle["projection"].mean_zero_p_upper,
            )
            mutations.append(
                (
                    "auxiliary-sign-substituted-for-mean-bound",
                    {"statistical_test": replace(
                        bundle["statistical_test"],
                        outcome=mean_substitution,
                        content_hash=None,
                    )},
                )
            )

            for label, changes in mutations:
                candidate = {**bundle, **changes}
                with self.subTest(mutation=label), self.assertRaises(ValidationError):
                    _join(candidate)

    def test_exact_closure_mismatches_and_unrelated_bindings_are_rejected(self):
        with TemporaryDirectory(prefix="inert-estimand-closure-") as directory:
            fixture = static_fixtures._inert_static_fixture(directory)
            repository, _, _, projection, support = fixture
            assessment, contract, _, contract_record = _frozen_sources(repository)
            bundle = _case_bundle(
                projection,
                assessment,
                contract,
                contract_record,
                n=1000,
                candidate=3,
                reference=2,
            )
            # Mutate this exact passing N=1000 bundle, not the original N=20
            # projection: otherwise an unrelated numeric-view mismatch could
            # mask a missing contract/source-identity guard.
            self.assertIsNone(_join(bundle))
            projection = bundle["projection"]
            assessment = bundle["assessment"]
            unrelated = support["timeline"]
            mutations = [
                (
                    "projection-contract-artifact",
                    {"projection": replace(projection, contract_artifact_sha256=unrelated.sha256)},
                ),
                (
                    "assessment-contract-artifact",
                    {"assessment": replace(assessment, contract_artifact_sha256=unrelated.sha256)},
                ),
                (
                    "assessment-contract-record",
                    {"assessment": replace(assessment, contract_record_hash="a" * 64)},
                ),
                (
                    "contract-record-substitution",
                    {"contract_record": unrelated},
                ),
                (
                    "contract-body",
                    {"contract": replace(contract, version=contract.version + 1)},
                ),
                (
                    "assessment-hypothesis",
                    {"assessment": replace(assessment, hypothesis_id="other-hypothesis")},
                ),
                (
                    "assessment-metric",
                    {"assessment": replace(assessment, metric_id="other-metric")},
                ),
                (
                    "statistical-use-assessment-artifact",
                    {
                        "assessment": replace(
                            assessment,
                            statistical_use_authority_artifact_sha256=unrelated.sha256,
                        )
                    },
                ),
                (
                    "statistical-use-assessment-record",
                    {
                        "assessment": replace(
                            assessment,
                            statistical_use_authority_record_hash=unrelated.record_hash,
                        )
                    },
                ),
            ]
            unit_contract = _unit_mismatched_contract(contract)
            mutations.append(
                (
                    "contract-unit",
                    {
                        "contract": unit_contract,
                        "assessment": replace(
                            assessment,
                            contract_sha256=unit_contract.sha256,
                        ),
                    },
                )
            )
            scope_contract = replace(
                contract,
                primary_metric=replace(
                    contract.primary_metric,
                    scope=sd.MetricScope.PROXY,
                ),
            )
            mutations.append(
                (
                    "contract-scope",
                    {
                        "contract": scope_contract,
                        "assessment": replace(
                            assessment,
                            contract_sha256=scope_contract.sha256,
                        ),
                    },
                )
            )
            policy_contract = replace(
                contract,
                hypothesis_evaluation_policies=tuple(
                    replace(item, meaningful_effect=item.meaningful_effect + 0.01)
                    if item.hypothesis_id == projection.hypothesis_id
                    else item
                    for item in contract.hypothesis_evaluation_policies
                ),
            )
            mutations.append(("contract-policy", {"contract": policy_contract}))

            for label, changes in mutations:
                candidate = {**bundle, **changes}
                with self.subTest(mismatch=label), self.assertRaises(ValidationError):
                    _join(candidate)

            with self.assertRaises(ValidationError):
                _join({**bundle, "experiment_id": "other-experiment"})

            substituted_projection = replace(
                projection,
                statistical_use_authority_artifact_sha256=unrelated.sha256,
                statistical_use_authority_record_hash=unrelated.record_hash,
            )
            result, statistical_test = evaluation_fixtures._pair(substituted_projection)
            substituted = {
                **bundle,
                "result": replace(
                    result,
                    metric_id=substituted_projection.metric_id,
                    content_hash=None,
                ),
                "statistical_test": statistical_test,
                "projection": substituted_projection,
            }
            with self.assertRaises(ValidationError):
                _join(substituted)

    def test_public_estimand_owner_refuses_inert_v4_without_admission_delta(self):
        with TemporaryDirectory(prefix="inert-estimand-owner-") as directory:
            fixture = static_fixtures._inert_static_fixture(directory)
            repository, _, _, _, _ = fixture
            _, by_content, _, _ = static_fixtures._historical_successor(fixture)
            test_stored = next(
                item
                for item in by_content.values()
                if type(item.research_object) is rs.StatisticalTest
            )
            evidence = rs.register_scientific_claim_evidence_projection(
                repository.registry,
                evidence_id="inert-estimand-source",
                evidence_kind=EvidenceKind.ESTIMAND,
                claim_id="inert-estimand-claim",
                claim_text="An inert V4 statistical source is not scientific evidence.",
                producer_role=Role.STATISTICIAN,
                source_artifact_hashes=(test_stored.artifact.sha256,),
            )
            before = _admission_snapshot(repository)
            with self.assertRaises(ValidationError):
                rs._require_scientific_state_evidence_source(
                    repository.registry,
                    repository.ledger,
                    run_id=repository.run_id,
                    evidence_kind=EvidenceKind.ESTIMAND,
                    evidence_artifact=evidence,
                    evidence_id="inert-estimand-source",
                    claim_id="inert-estimand-claim",
                    claim_text="An inert V4 statistical source is not scientific evidence.",
                    claim_producer_role=Role.STATISTICIAN,
                    claim_confirmatory=True,
                    claim_evidence_use=ClaimEvidenceUse.SCIENTIFIC,
                    assertion_text="Inert source must not enter the evidence graph.",
                )
            self.assertEqual(_admission_snapshot(repository), before)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
