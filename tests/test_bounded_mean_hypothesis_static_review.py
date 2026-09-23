"""Independent inert regressions for bounded-hypothesis historical custody.

These fixtures exercise only the nonrecursive static exception, codecs and
native arithmetic. Registry PASS metadata means stored bytes are intact; it
does not establish scientific validity. All execution, Dataset, projection,
sampling and review roots are deliberate inert stand-ins. The hypothesis DTO
stays NON_EVIDENTIARY_MECHANICAL / scientific_evidence_eligible=False.

No production source resolver is mocked, no signature/key/trust map is used,
and no scientific execution, projection, assessment or promotion issuer is
called. The one actual contract reader is registry-only. Expected rejections
were independently reproduced as missing controls in research_state.py
6315b00694a402a80e6049bcfbe5d667831cd2df99cbb5bf0985e5b7d8980c31.
A valid private static topology is not a positive scientific lifecycle test.
"""

from dataclasses import replace
from tempfile import TemporaryDirectory
import unittest

from scientist_one.errors import ValidationError
import scientist_one.research_state as rs
import scientist_one.scientific_design as sd
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes, sha256_bytes
from scientist_one.bounded_mean_inference import (
    BOUNDED_MEAN_PROFILE_ID,
    BOUNDED_MEAN_CONDITIONAL_SCOPE,
    BOUNDED_MEAN_ZERO_P_METHOD_ID,
    BOUNDED_MEAN_INTERVAL_METHOD_ID,
)
from scientist_one.execution_admissibility import (
    ScientificExecutionAdmissibilityPolicy,
    FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA,
)
from tests.test_scientific_design import make_contract
from tests.test_bounded_mean_canonical_projection import _projection
from tests.test_bounded_mean_hypothesis_evaluation import _bounded_authority, _pair
from tests import test_projection_checked_result_assessment as projection_fixtures


def _inert_static_fixture(
    root, *, assessment_change=None, statistics_change=None, promotion_schema="1.0"
):
    registry = ArtifactRegistry(root, "runs/ledger-run/registry")
    ledger = EventLedger(root, "runs/ledger-run/events.jsonl")

    def put(
        value,
        logical="inert_static_fixture",
        role=Role.ORCHESTRATOR,
        parents=(),
        schema="1.0",
        stamp="2026-09-04T12:00:00Z",
    ):
        # These metadata spellings reproduce producer contracts only. All roots
        # remain inert, and no scientific source owner or issuer is invoked.
        metadata = {
            "checked_result_assessment": (
                sd._CHECKED_RESULT_ASSESSMENT_V3_ORIGIN,
                sd._CHECKED_RESULT_ASSESSMENT_V3_COMMAND,
            ),
            "statistical_analysis": (
                sd._CHECKED_RESULT_STATISTICS_V3_ORIGIN,
                sd._CHECKED_RESULT_STATISTICS_V3_COMMAND,
            ),
            "scientific_result_promotion_authority_v3": (
                sd._SCIENTIFIC_RESULT_PROMOTION_V3_ORIGIN,
                sd._SCIENTIFIC_RESULT_PROMOTION_V3_COMMAND,
            ),
            "evaluation_contract": (
                "canonical frozen evaluation contract authority",
                ("scientist-one", "freeze-evaluation-contract"),
            ),
        }
        origin, command = metadata.get(
            logical,
            (
                "INERT_STATIC_V2_PROBE_ONLY_NO_SCIENTIFIC_AUTHORITY",
                ("test", "inert-static-v2"),
            ),
        )
        return registry.put_json(
            value,
            logical_type=logical,
            origin=origin,
            creator_role=role,
            creation_command=command,
            parent_artifacts=parents,
            schema_version=schema,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=stamp,
        )

    support = {
        k: put(
            {"inert_kind": k},
            logical=(
                "aggregate_experiment_result"
                if k == "aggregate"
                else "inert_static_fixture"
            ),
            role=(Role.STATISTICIAN if k == "aggregate" else Role.ORCHESTRATOR),
            schema=("3.0" if k == "aggregate" else "1.0"),
        )
        for k in (
            "evidence",
            "execution",
            "projection",
            "admissibility",
            "domain",
            "statistical-use",
            "aggregate",
            "timeline",
            "confirmation",
        )
    }
    projection = _projection(n=20)
    contract = make_contract()
    projection = replace(
        projection,
        baseline_id=contract.baseline_registry.entries[0].baseline_id,
        metric_id=contract.primary_metric.metric_id,
        hypothesis_policy=replace(
            projection.hypothesis_policy, metric_id=contract.primary_metric.metric_id
        ),
    )
    policy = projection.hypothesis_policy
    contract = replace(
        contract,
        hypothesis_evaluation_policies=tuple(
            replace(
                policy,
                hypothesis_id=h.hypothesis_id,
                policy_id=policy.policy_id
                if h.hypothesis_id == policy.hypothesis_id
                else "secondary-inert-policy",
            )
            for h in contract.hypothesis_register.hypotheses
        ),
        statistical_plan=replace(
            contract.statistical_plan,
            primary_test=BOUNDED_MEAN_ZERO_P_METHOD_ID,
            confidence_interval=BOUNDED_MEAN_INTERVAL_METHOD_ID,
            effect_size="paired mean directional difference",
            minimum_effect=policy.meaningful_effect,
            minimum_sample_size=policy.minimum_sample_size,
        ),
        seed_reporting=replace(contract.seed_reporting, seeds=projection.seed_order),
        scientific_execution_admissibility_policy=ScientificExecutionAdmissibilityPolicy(),
        stopping_criteria=FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA,
    )
    cr = put(
        {
            "schema_version": sd._evaluation_contract_schema(contract),
            "evaluation_contract": sd._evaluation_contract_value(contract),
        },
        "evaluation_contract",
        Role.PROTOCOL_DESIGNER,
        (support["evidence"].sha256,),
        sd._evaluation_contract_artifact_schema(contract),
    )
    assert (
        sd.require_frozen_evaluation_contract(
            registry, contract_artifact_sha256=cr.sha256
        )
        == contract
    )
    statistics = {
        "schema_version": "checked-result-statistics/v3",
        "contract_artifact_sha256": cr.sha256,
        "contract_record_hash": cr.record_hash,
        "aggregate_result_sha256": support["aggregate"].sha256,
        "aggregate_record_hash": support["aggregate"].record_hash,
        "generic_ml_projection_artifact_sha256": support["projection"].sha256,
        "generic_ml_projection_record_hash": support["projection"].record_hash,
        "statistical_use_authority_artifact_sha256": support["statistical-use"].sha256,
        "statistical_use_authority_record_hash": support["statistical-use"].record_hash,
        "frozen_policy_sha256": policy.sha256,
        "numeric_result": projection.numeric_result.to_dict(),
        "inference_scope": BOUNDED_MEAN_CONDITIONAL_SCOPE,
        "scientific_authority": False,
    }
    if statistics_change:
        statistics_change(statistics)
    sr = put(
        statistics,
        "statistical_analysis",
        Role.STATISTICIAN,
        (
            cr.sha256,
            support["aggregate"].sha256,
            support["projection"].sha256,
            support["statistical-use"].sha256,
        ),
        "3.0",
    )
    assessment = (
        projection_fixtures.ProjectionCheckedResultAssessmentTests()._assessment(
            projection_backed=True
        )
    )
    assessment = replace(
        assessment,
        ledger_run_id=projection.ledger_run_id,
        execution_run_id=projection.execution_run_id,
        hypothesis_id=projection.hypothesis_id,
        contract_artifact_sha256=cr.sha256,
        contract_record_hash=cr.record_hash,
        contract_sha256=contract.sha256,
        scientific_execution_authority_artifact_sha256=support["execution"].sha256,
        scientific_execution_authority_record_hash=support["execution"].record_hash,
        generic_ml_paired_metric_projection_authority_artifact_sha256=support[
            "projection"
        ].sha256,
        generic_ml_paired_metric_projection_authority_record_hash=support[
            "projection"
        ].record_hash,
        scientific_execution_admissibility_authority_artifact_sha256=support[
            "admissibility"
        ].sha256,
        scientific_execution_admissibility_authority_record_hash=support[
            "admissibility"
        ].record_hash,
        domain_validity_receipt_artifact_sha256=support["domain"].sha256,
        domain_validity_receipt_record_hash=support["domain"].record_hash,
        statistical_use_authority_artifact_sha256=support["statistical-use"].sha256,
        statistical_use_authority_record_hash=support["statistical-use"].record_hash,
        aggregate_result_sha256=support["aggregate"].sha256,
        aggregate_record_hash=support["aggregate"].record_hash,
        statistical_analysis_sha256=sr.sha256,
        statistical_record_hash=sr.record_hash,
        metric_id=projection.metric_id,
        metric_unit=projection.metric_unit,
        metric_scope=projection.metric_scope,
        baseline_id=projection.baseline_id,
        candidate_value=projection.candidate_value,
        baseline_value=projection.baseline_value,
        improvement_effect=projection.improvement_effect,
        confidence_low=projection.confidence_low,
        confidence_high=projection.confidence_high,
        adjusted_p_value=None,
        mean_zero_p_upper=projection.mean_zero_p_upper,
        inference_profile_id=BOUNDED_MEAN_PROFILE_ID,
        sample_size=projection.sample_size,
        hypothesis_status=projection.hypothesis_status,
        outcome=projection.outcome,
        scientific_evidence_eligible=True,
    )
    if assessment_change:
        assessment = replace(assessment, **assessment_change)
    ar = put(
        assessment.to_dict(),
        "checked_result_assessment",
        Role.CLAIM_VERIFIER,
        assessment.source_artifact_hashes,
        "3.0",
    )
    promotion = sd.ScientificResultPromotionReceiptV3(
        receipt_id="inert-static-promotion",
        ledger_run_id=projection.ledger_run_id,
        execution_run_id=projection.execution_run_id,
        result_id=projection.result_id,
        contract_artifact_sha256=cr.sha256,
        checked_result_assessment_artifact_sha256=ar.sha256,
        scientific_execution_authority_artifact_sha256=support["execution"].sha256,
        scientific_timeline_receipt_artifact_sha256=support["timeline"].sha256,
        domain_validity_receipt_artifact_sha256=support["domain"].sha256,
        confirmation_authority_artifact_sha256=support["confirmation"].sha256,
    )
    pr = put(
        promotion.to_dict(),
        "scientific_result_promotion_authority_v3",
        Role.CLAIM_VERIFIER,
        promotion.source_artifact_hashes,
        promotion_schema,
    )
    projection = replace(
        projection,
        contract_artifact_sha256=cr.sha256,
        checked_result_assessment_artifact_sha256=ar.sha256,
        promotion_receipt_artifact_sha256=pr.sha256,
        statistical_analysis_sha256=sr.sha256,
        scientific_execution_authority_artifact_sha256=support["execution"].sha256,
        aggregate_result_sha256=support["aggregate"].sha256,
        statistical_use_authority_artifact_sha256=support["statistical-use"].sha256,
        statistical_use_authority_record_hash=support["statistical-use"].record_hash,
    )
    result, test = _pair(projection)
    result = replace(
        result,
        metric_id=projection.metric_id,
        value={
            "baseline": assessment.baseline_value,
            "candidate": assessment.candidate_value,
            "improvement": assessment.improvement_effect,
        },
        evaluation_artifact_hashes=(pr.sha256,),
        authority_artifact_hashes=tuple(
            sorted((pr.sha256, support["aggregate"].sha256))
        ),
        source_artifact_hashes=(support["aggregate"].sha256,),
        content_hash=None,
    )
    test = replace(
        test,
        authority_artifact_hashes=tuple(sorted((sr.sha256, pr.sha256))),
        source_artifact_hashes=(sr.sha256, pr.sha256),
        parents=(
            rs.ObjectReference(
                "Result", result.object_id, result.content_hash, "tests", True
            ),
        ),
        content_hash=None,
    )
    design_hypothesis = contract.hypothesis_register.hypothesis(policy.hypothesis_id)
    prior = rs.Hypothesis(
        object_id=policy.hypothesis_id,
        producer=Role.HYPOTHESIS_DESIGNER,
        status=rs.RecordStatus.FROZEN,
        created_at="2026-09-04T12:00:00Z",
        code_version=projection.canonical_state_code_version,
        statement=design_hypothesis.statement,
        motivation=design_hypothesis.motivation,
        prior_evidence_ids=design_hypothesis.prior_evidence_ids,
        prediction=design_hypothesis.prediction,
        falsification_condition=design_hypothesis.falsification_condition,
        planned_experiment_ids=(design_hypothesis.planned_experiment,),
    )
    objects = [prior, result, test]
    records = [
        put(
            obj.to_dict(),
            obj.logical_type,
            obj.producer,
            (),
            obj.schema_version,
            stamp=obj.created_at,
        )
        for obj in objects
    ]
    repository = rs.ResearchStateRepository(
        registry,
        ledger,
        run_id="ledger-run",
        code_version=projection.canonical_state_code_version,
        configuration_hash="b" * 64,
        state=MacroState.CONFIRM,
    )
    authority = replace(
        _bounded_authority(),
        authority_id="inert-static-hyp-eval",
        run_id="ledger-run",
        hypothesis_id=prior.object_id,
        prior_hypothesis_content_hash=prior.content_hash,
        prior_hypothesis_state_artifact_hash=records[0].sha256,
        prior_hypothesis_state_record_hash=records[0].record_hash,
        result_id=result.object_id,
        result_content_hash=result.content_hash,
        result_state_artifact_hash=records[1].sha256,
        result_state_record_hash=records[1].record_hash,
        statistical_test_id=test.object_id,
        statistical_test_content_hash=test.content_hash,
        statistical_test_state_artifact_hash=records[2].sha256,
        statistical_test_state_record_hash=records[2].record_hash,
        evaluation_contract_artifact_hash=cr.sha256,
        evaluation_contract_record_hash=cr.record_hash,
        evaluation_contract_sha256=contract.sha256,
        evaluation_policy_id=policy.policy_id,
        evaluation_policy_sha256=policy.sha256,
        metric_id=policy.metric_id,
        improvement_effect=projection.improvement_effect,
        confidence_low=projection.confidence_low,
        confidence_high=projection.confidence_high,
        mean_zero_p_upper=projection.mean_zero_p_upper,
        sample_size=projection.sample_size,
        outcome=rs.HypothesisStatus(projection.hypothesis_status.value),
        result_authority_artifact_hashes=result.authority_artifact_hashes,
        result_authority_record_hashes=tuple(
            registry.get_metadata(d).record_hash
            for d in result.authority_artifact_hashes
        ),
        statistical_authority_artifact_hashes=test.authority_artifact_hashes,
        statistical_authority_record_hashes=tuple(
            registry.get_metadata(d).record_hash for d in test.authority_artifact_hashes
        ),
        scientific_result_promotion_authority_artifact_hash=pr.sha256,
        backend_execution_authority_artifact_hash=support["execution"].sha256,
        scientific_timeline_authority_artifact_hash=support["timeline"].sha256,
        confirmation_authority_artifact_hash=support["confirmation"].sha256,
        domain_validity_authority_artifact_hash=support["domain"].sha256,
        statistical_analysis_authority_artifact_hash=sr.sha256,
        checked_result_assessment_artifact_hash=ar.sha256,
        checked_result_assessment_record_hash=ar.record_hash,
        paired_metric_projection_authority_artifact_hash=support["projection"].sha256,
        paired_metric_projection_authority_record_hash=support[
            "projection"
        ].record_hash,
        statistical_use_authority_artifact_hash=support["statistical-use"].sha256,
        statistical_use_authority_record_hash=support["statistical-use"].record_hash,
    )
    stored = tuple(rs._StoredObject(obj, rec) for obj, rec in zip(objects, records))
    return repository, authority, stored, projection, support


def _replay_static(f):
    repository, authority, stored, *_ = f
    return rs._require_bounded_hypothesis_successor_bindings(
        repository, authority, *stored
    )


def _historical_successor(f, *, before_parents=False, reverse_parents=False):
    repository, authority, stored, projection, support = f
    registry, ledger = repository.registry, repository.ledger
    prior, result, test = (item.research_object for item in stored)
    ledger.record(
        run_id=repository.run_id,
        actor_role=Role.ORCHESTRATOR,
        state_before=repository.state,
        requested_state_after=repository.state,
        artifact_hashes=(support["evidence"].sha256,),
        code_version=repository.code_version,
        configuration_hash=repository.configuration_hash,
        reason="INERT historical topology only",
        event_type="CHECKPOINT",
        timestamp="2026-09-04T12:00:00Z",
    )

    def materialize(item, predecessor=None):
        obj, rec = item.research_object, item.artifact
        return ledger.record(
            run_id=repository.run_id,
            actor_role=obj.producer,
            state_before=repository.state,
            requested_state_after=repository.state,
            artifact_hashes=(rec.sha256,),
            code_version=repository.code_version,
            configuration_hash=repository.configuration_hash,
            reason="INERT historical topology only",
            event_type="CHECKPOINT" if obj.revision == 1 else "CORRECTION",
            event_id=f"rs-{rec.sha256[:48]}",
            timestamp=obj.created_at,
            supersedes_event_id=predecessor,
            metadata={
                "research_state_operation": "MATERIALIZED"
                if obj.revision == 1
                else "SUPERSEDED",
                "object_type": obj.object_type,
                "object_id": obj.object_id,
                "revision": obj.revision,
                "content_hash": obj.content_hash,
                "artifact_hash": rec.sha256,
                "schema_version": obj.schema_version,
                "supersedes_content_hash": obj.supersedes_content_hash,
            },
        )

    materialize(stored[0])
    if not before_parents:
        for item in stored[1:]:
            materialize(item)
    event_index = len(ledger.events())
    binding = authority.evaluation_binding
    event = ledger.record(
        run_id=repository.run_id,
        actor_role=Role.SCIENTIFIC_REVIEWER,
        state_before=repository.state,
        requested_state_after=repository.state,
        artifact_hashes=authority.source_artifact_hashes,
        code_version=repository.code_version,
        configuration_hash=repository.configuration_hash,
        reason="evaluated one preregistered hypothesis under its frozen policy",
        event_type="CHECKPOINT",
        timestamp="2026-09-04T12:00:04Z",
        event_id="hyp-eval-" + sha256_bytes(canonical_json_bytes(binding))[:40],
        metadata={"hypothesis_evaluation": binding},
    )
    authority = replace(
        authority,
        evaluation_event_id=event.event_id,
        evaluation_event_hash=event.event_hash,
        evaluation_event_index=event_index,
        ledger_prefix_head_hash=event.event_hash,
    )
    ar = registry.put_json(
        authority.to_dict(),
        logical_type="hypothesis_evaluation_authority",
        origin="source-owned prospective hypothesis evaluation authority",
        creator_role=Role.SCIENTIFIC_REVIEWER,
        creation_command=("scientist-one", "evaluate-hypothesis"),
        parent_artifacts=authority.source_artifact_hashes,
        schema_version="2.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=event.timestamp,
    )
    if before_parents:
        for item in stored[1:]:
            materialize(item)
    parents = (
        rs.ObjectReference(
            "Result", result.object_id, result.content_hash, "evaluated_by", True
        ),
        rs.ObjectReference(
            "StatisticalTest", test.object_id, test.content_hash, "evaluated_by", True
        ),
    )
    if reverse_parents:
        parents = tuple(reversed(parents))
    successor = rs.revise_research_object(
        prior,
        producer=Role.SCIENTIFIC_REVIEWER,
        status=rs.RecordStatus.COMPLETE,
        created_at="2026-09-04T12:00:05Z",
        parents=parents,
        authority_artifact_hashes=(ar.sha256,),
        hypothesis_status=authority.outcome,
    )
    record = registry.put_bytes(
        successor.canonical_bytes(),
        logical_type=successor.logical_type,
        origin=f"research-state:Hypothesis:{prior.object_id}:r2",
        creator_role=successor.producer,
        creation_command=repository.creation_command,
        parent_artifacts=tuple(
            sorted((ar.sha256, *(item.artifact.sha256 for item in stored)))
        ),
        schema_version=successor.schema_version,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=successor.created_at,
    )
    successor_stored = rs._StoredObject(successor, record)
    materialize(successor_stored, predecessor=f"rs-{stored[0].artifact.sha256[:48]}")
    by_content = {
        item.research_object.content_hash: item for item in (*stored, successor_stored)
    }
    events = ledger.validate(raise_on_error=True).events
    answer = repository._source_bound_hypothesis_evaluation_successor(
        prior, (prior, successor), by_content, events
    )
    return answer, by_content, events, authority


class BoundedHypothesisStaticReviewTests(unittest.TestCase):
    """Static acceptance is NOT scientific acceptance, execution or E4 evidence."""

    def test_exact_inert_static_closure_and_outer_successor(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(directory)
            before = fixture[0].registry.verify_all(raise_on_error=True)
            _replay_static(fixture)
            self.assertEqual(
                fixture[0].registry.verify_all(raise_on_error=True), before
            )
            answer, _, _, authority = _historical_successor(fixture)
            self.assertIsNotNone(answer)
            self.assertFalse(authority.scientific_evidence_eligible)
            self.assertIs(
                authority.evidence_scope,
                rs.HypothesisEvaluationEvidenceScope.NON_EVIDENTIARY_MECHANICAL,
            )
            before = rs._locked_research_state_source_snapshot(
                fixture[0].registry, fixture[0].ledger, run_id="ledger-run"
            )
            # Genuine source replay must reject the inert upstream roots.
            with self.assertRaises(ValidationError):
                rs.require_hypothesis_evaluation_authority(
                    fixture[0].registry,
                    fixture[0].ledger,
                    authority_artifact_hash=answer.research_object.authority_artifact_hashes[
                        0
                    ],
                    expected_run_id="ledger-run",
                )
            self.assertEqual(
                rs._locked_research_state_source_snapshot(
                    fixture[0].registry, fixture[0].ledger, run_id="ledger-run"
                ),
                before,
            )

    def test_outer_successor_refuses_reversed_evaluated_by_parent_order(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(directory)
            answer, _, _, _ = _historical_successor(fixture, reverse_parents=True)
            self.assertIsNone(answer)
            self.assertTrue(fixture[0].ledger.validate(raise_on_error=True).valid)

    def test_outer_successor_refuses_evaluation_before_result_test_materialization(
        self,
    ):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(directory)
            answer, _, _, _ = _historical_successor(fixture, before_parents=True)
            self.assertIsNone(answer)
            self.assertTrue(fixture[0].ledger.validate(raise_on_error=True).valid)

    def test_static_refuses_shifted_candidate_reference_with_unchanged_row_counts(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(
                directory,
                assessment_change={"candidate_value": 0.8, "baseline_value": 0.6},
            )
            self.assertEqual(fixture[3].candidate_value, 0.6)
            self.assertEqual(fixture[3].baseline_value, 0.4)
            with self.assertRaises(ValidationError):
                _replay_static(fixture)

    def test_outer_successor_refuses_shifted_candidate_reference(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(
                directory,
                assessment_change={"candidate_value": 0.8, "baseline_value": 0.6},
            )
            answer, _, _, _ = _historical_successor(fixture)
            self.assertIsNone(answer)

    def test_static_refuses_non_fraction_assessment(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(
                directory, assessment_change={"metric_unit": sd.MetricUnit.PERCENT}
            )
            with self.assertRaises(ValidationError):
                _replay_static(fixture)

    def test_static_refuses_proxy_assessment(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(
                directory, assessment_change={"metric_scope": sd.MetricScope.PROXY}
            )
            with self.assertRaises(ValidationError):
                _replay_static(fixture)

    def test_static_refuses_assessment_from_another_ledger(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(
                directory, assessment_change={"ledger_run_id": "another-ledger"}
            )
            with self.assertRaises(ValidationError):
                _replay_static(fixture)

    def test_static_refuses_wrong_promotion_registry_schema(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            # Actual V3 promotion uses payload v3 / registry 1.0, not 3.0.
            fixture = _inert_static_fixture(directory, promotion_schema="3.0")
            with self.assertRaises(ValidationError):
                _replay_static(fixture)

    def test_static_refuses_statistics_with_another_aggregate(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(
                directory,
                statistics_change=lambda value: value.update(
                    aggregate_result_sha256="e" * 64
                ),
            )
            with self.assertRaises(ValidationError):
                _replay_static(fixture)

    def test_static_refuses_statistics_with_generic_p_field(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(
                directory,
                statistics_change=lambda value: value.update(adjusted_p_value=0.001),
            )
            with self.assertRaises(ValidationError):
                _replay_static(fixture)

    def test_static_refuses_edited_native_p_and_profile(self):
        for change in ({"mean_zero_p_upper": 0.1}, {"profile_id": "wrong"}):
            with (
                self.subTest(change=change),
                TemporaryDirectory(prefix="inert-hyp-static-") as directory,
            ):
                fixture = _inert_static_fixture(
                    directory,
                    statistics_change=lambda value: value["numeric_result"].update(
                        change
                    ),
                )
                with self.assertRaises(ValidationError):
                    _replay_static(fixture)

    def test_static_refuses_changed_exact_source_record(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(directory)
            changed = replace(fixture[1], result_state_record_hash="a" * 64)
            with self.assertRaises(ValidationError):
                _replay_static((fixture[0], changed, *fixture[2:]))

    def test_outer_successor_refuses_shared_authority_id_on_another_event_slot(self):
        with TemporaryDirectory(prefix="inert-hyp-static-") as directory:
            fixture = _inert_static_fixture(directory)
            answer, by_content, _, authority = _historical_successor(fixture)
            self.assertIsNotNone(answer)
            repository = fixture[0]
            binding = authority.evaluation_binding
            binding["hypothesis_id"] = "another-hypothesis"
            binding["prior_hypothesis_content_hash"] = "7" * 64
            repository.ledger.record(
                run_id=repository.run_id,
                actor_role=Role.SCIENTIFIC_REVIEWER,
                state_before=repository.state,
                requested_state_after=repository.state,
                artifact_hashes=authority.source_artifact_hashes,
                code_version=repository.code_version,
                configuration_hash=repository.configuration_hash,
                reason="INERT conflicting v2 ID slot",
                event_type="CHECKPOINT",
                timestamp="2026-09-04T12:00:06Z",
                event_id="inert-other-semantic-same-authority-id",
                metadata={"hypothesis_evaluation": binding},
            )
            events = repository.ledger.validate(raise_on_error=True).events
            # The ordinary v2 event owner already refuses the retained conflict.
            with self.assertRaises(ValidationError):
                rs._hypothesis_evaluation_event(
                    repository.ledger,
                    run_id=repository.run_id,
                    repository=repository,
                    binding=authority.evaluation_binding,
                    source_hashes=authority.source_artifact_hashes,
                    evaluated_at=None,
                    prospective=True,
                )
            prior = fixture[2][0].research_object
            self.assertIsNone(
                repository._source_bound_hypothesis_evaluation_successor(
                    prior,
                    (prior, answer.research_object),
                    by_content,
                    events,
                )
            )

    def test_native_pure_projection_refuses_scalar_subclass_before_coercion(self):
        calls = []

        class CoercionProbe(float):
            def __float__(self):
                calls.append("float_coercion")
                return float.__float__(self)

        projection = _projection(n=20)
        result, test = _pair(projection)
        object.__setattr__(
            projection, "candidate_value", CoercionProbe(projection.candidate_value)
        )
        try:
            with self.assertRaises(ValidationError):
                rs._bounded_hypothesis_projection_outcome(
                    projection,
                    projection.hypothesis_policy,
                    result,
                    test,
                )
        finally:
            self.assertEqual(
                calls,
                [],
                "Pure helper must reject before invoking caller numeric coercion",
            )


if __name__ == "__main__":
    unittest.main()
