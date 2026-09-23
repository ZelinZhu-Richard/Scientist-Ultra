"""Inert cohort-shape controls, never issued scientific audit evidence.

The typed snapshot/slot DTOs here are deliberately caller-constructed and
unqualified. They exercise the pure inventory projection only. The real
entrypoint is separately required to refuse absent source authority; no owner
is patched, no private issuer or provider is called, and no approval is made.
"""

import ast
from dataclasses import replace
import hashlib
import inspect
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import textwrap
import unittest

from scientist_one import gates, research_state as rs
from scientist_one.errors import ArtifactCorruptionError, ValidationError
from scientist_one.evaluators import AuthorityScope, AuthorityStatus, EvaluatorClass, RCheck
from scientist_one.models import thaw_json
from scientist_one.roles import Role
from scientist_one.scientific_r_checks import (
    _ScientificSourceAdmission,
    _canonical_source_admissions,
    _domain_admission_after_full_replay,
    _require_scientific_audit_cohort,
    _resolve_r3_e3_timeline,
    _scientific_audit_cohort_from_source,
    _with_owned_r1_sources,
    ScientificRCheckResolution,
    resolve_scientific_r_check_sources,
)
from scientist_one.scientific_design import ResearchGateOutcome, ResearchQuestionGateAssessment, ScientificGateVerificationStatus
from tests import test_semantic_audit_source_companion as audit_fixtures
from tests import test_semantic_reproduction_cohort_audit as plural_fixtures
from tests import test_scientific_r_checks as check_fixtures


STAMP = "2026-09-06T00:00:00Z"


def _digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _ref(value, relation):
    return rs.ObjectReference(value.object_type, value.object_id, value.content_hash, relation, True)


def _binding(value):
    return rs.ResearchStateAuthorityBinding(
        research_object=value,
        artifact_sha256=_digest(value.object_id),
        artifact_record_hash=_digest(f"record-{value.object_id}"),
        materialization_event_id=f"inert-event-{value.object_id}",
        materialization_event_hash=_digest(f"event-{value.object_id}"),
        materialization_event_index=1,
        authority_artifact_hashes=(), authority_artifact_record_hashes=(),
        authority_logical_types=(), authority_creator_roles=(),
        scientific_evidence_eligible=False, claim_semantics=None,
    )


def _member(label, outcome, version):
    common = dict(producer=Role.ORCHESTRATOR, created_at=STAMP, code_version="inert-cohort")
    method = rs.Method(object_id=f"method-{label}", name=f"Method {label}",
                       description="Non-evidentiary shape", **common)
    implementation = rs.Implementation(
        object_id=f"implementation-{label}", method_id=method.object_id,
        parents=(_ref(method, "implements"),), code_revision="inert-cohort",
        code_artifact_hashes=(_digest(f"code-{label}"),),
        configuration_artifact_hashes=(_digest(f"configuration-{label}"),), **common,
    )
    dataset = rs.Dataset(object_id=f"dataset-{label}", name=f"Dataset {label}", version="inert", **common)
    experiment = rs.Experiment(
        object_id=f"experiment-{label}", hypothesis_ids=(f"hypothesis-{label}",),
        scientific_purpose="Non-evidentiary structural probe",
        implementation_id=implementation.object_id, dataset_ids=(dataset.object_id,),
        parents=(_ref(implementation, "uses"), _ref(dataset, "uses")),
        evaluator="inert-evaluator", **common,
    )
    run = rs.Run(
        object_id=f"run-{label}", experiment_id=experiment.object_id,
        parents=(_ref(experiment, "executes"),), code_revision="inert-cohort",
        dataset_ids=(dataset.object_id,), random_seeds=(len(label),),
        configuration_artifact_hash=_digest(f"configuration-{label}"),
        evaluator_version="inert", started_at=STAMP, **common,
    )
    metric = rs.Metric(object_id=f"metric-{label}", name=f"Metric {label}", **common)
    result = rs.Result(
        object_id=f"result-{label}", run_ids=(run.object_id,),
        parents=(_ref(run, "aggregates"), _ref(metric, "reports")), metric_id=metric.object_id,
        source_artifact_hashes=(_digest(f"numeric-{label}"),),
        code_revision="inert-cohort", observed_at=STAMP,
        metadata={"schema_version": f"scientific-result-canonical-state/v{version}",
                  "scientific_result_outcome": outcome, "inert_shape_only": True}, **common,
    )
    test = rs.StatisticalTest(
        object_id=f"test-{label}", result_ids=(result.object_id,),
        parents=(_ref(result, "tests"),), test_name="inert-test", null_hypothesis="inert null",
        alternative="inert alternative", source_artifact_hashes=(_digest(f"numeric-{label}"),),
        metadata={"schema_version": f"scientific-statistical-canonical-state/v{version}",
                  "inert_shape_only": True}, **common,
    )
    return tuple(map(_binding, (method, implementation, dataset, experiment, run, metric, result, test)))


class ScientificAuditCohortTests(unittest.TestCase):
    def setUp(self):
        self.fixture = audit_fixtures.SemanticAuditSourceCompanionTests()
        self.fixture.setUp()
        self.entries = tuple(
            binding
            for index, outcome in enumerate(("POSITIVE", "NEGATIVE", "NULL", "INCONCLUSIVE", "FALSIFIED"))
            for binding in _member(str(index), outcome, 3 if index == 0 else 4)
        )
        claims = tuple(_binding(rs.Claim(
            object_id=f"claim-{label}", producer=Role.ORCHESTRATOR,
            claim_text="Inert unverified claim", scope="NONE", created_at=STAMP,
            verification_method="NONE_NON_EVIDENTIARY_SHAPE_ONLY",
        )) for label in ("a", "b"))
        question = _binding(rs.ResearchQuestion(
            object_id="question-a", producer=Role.PROBLEM_INVESTIGATOR, created_at=STAMP,
            research_goal="Inert goal", question="Inert question?", falsification_condition="Inert condition",
        ))
        first_run = next(item.research_object for item in self.entries if item.research_object.object_id == "run-0")
        extra_run = replace(first_run, object_id="extra-run-without-result", content_hash=None)
        package = _binding(rs.ReproducibilityPackage(
            object_id="inert-failed-package", producer=Role.REPRODUCTION_VERIFIER, created_at=STAMP,
            run_ids=(first_run.object_id, extra_run.object_id),
            manifest_artifact_hashes=(_digest("manifest"),), environment_artifact_hashes=(_digest("environment"),),
            source_revision="inert", evaluator_version="inert",
            reproduction_status=rs.ReproductionStatus.FAIL, reproduced_at=STAMP,
        ))
        self.entries = (*self.entries, *claims, question, _binding(extra_run), package)
        self.source = self._source(self.entries)

    def _source(self, entries, *, rebind_scope=True):
        slot = self.fixture.slot
        if rebind_scope:
            result_tests = sorted(
                (item.artifact_sha256, item.artifact_record_hash)
                for item in entries if item.research_object.object_type in {"Result", "StatisticalTest"}
            )
            slot = replace(slot,
                result_artifact_hashes=tuple(item[0] for item in result_tests),
                result_artifact_record_hashes=tuple(item[1] for item in result_tests),
            )
        state = rs.ResearchStateAuthoritySnapshot(
            run_id=slot.run_id, snapshot_artifact_sha256=slot.research_state_snapshot_artifact_hash,
            snapshot_artifact_record_hash=slot.research_state_snapshot_artifact_record_hash,
            ledger_head_hash=_digest("inert-head"), ledger_event_count=2,
            code_version="inert-cohort", configuration_hash=_digest("inert-configuration"), entries=entries,
        )
        scope = gates._SemanticChallengerAuditCanonicalScope(
            state=state, central_claim_ids=slot.central_claim_ids,
            evidence_artifact_hashes=slot.evidence_artifact_hashes,
            evidence_artifact_record_hashes=slot.evidence_artifact_record_hashes,
            result_artifact_hashes=slot.result_artifact_hashes,
            result_artifact_record_hashes=slot.result_artifact_record_hashes,
            reproducibility_package_artifact_hash=None, scientific_source_qualified=False,
            package_authority=None,
        )
        return gates._SemanticChallengeAuditReplay(
            authority=self.fixture._authority(slot), record=None, slot=slot, canonical_scope=scope,
            publication_event_id="inert-publication", publication_event_hash=_digest("inert-publication"),
            publication_event_index=10, entry_snapshot=(None, None),
        )

    def _changed_object(self, object_id, **changes):
        return tuple(
            replace(item, research_object=replace(item.research_object, content_hash=None, **changes))
            if item.research_object.object_id == object_id else item
            for item in self.entries
        )

    def test_whole_inventory_retains_all_outcomes_and_unpaired_runs(self):
        cohort = _scientific_audit_cohort_from_source(self.source)
        self.assertEqual(len(cohort.results), 5)
        self.assertEqual(len(cohort.executions), 6)
        self.assertEqual(len(cohort.claims), 2)
        self.assertEqual(len(cohort.questions), 1)
        self.assertEqual(len(cohort.packages), 1)
        self.assertIs(cohort.packages[0].research_object.reproduction_status, rs.ReproductionStatus.FAIL)
        self.assertFalse(cohort.audit_source.authority.scientific_source_qualified)
        self.assertTrue(all(not item.result.scientific_evidence_eligible for item in cohort.results))
        self.assertEqual(
            {thaw_json(item.result.research_object.metadata)["scientific_result_outcome"] for item in cohort.results},
            {"POSITIVE", "NEGATIVE", "NULL", "INCONCLUSIVE", "FALSIFIED"},
        )
        self.assertEqual(
            tuple(item.result.artifact_sha256 for item in cohort.results),
            tuple(sorted(item.result.artifact_sha256 for item in cohort.results)),
        )
        # Distinct per-member datasets, implementations, configurations and
        # code artifacts are legitimate; no global subject-equality rule.
        self.assertEqual(len({item.execution.dataset.artifact_sha256 for item in cohort.results}), 5)
        self.assertEqual(len({item.execution.implementation.artifact_sha256 for item in cohort.results}), 5)
        self.assertEqual(len({item.execution.run.research_object.configuration_artifact_hash for item in cohort.results}), 5)

    def test_inventory_order_is_canonical_not_caller_or_leaf_order(self):
        a = _scientific_audit_cohort_from_source(self.source)
        b = _scientific_audit_cohort_from_source(self._source(tuple(reversed(self.entries))))
        self.assertEqual(a.results, b.results)
        self.assertEqual(a.executions, b.executions)
        self.assertEqual(a.round_key, b.round_key)

    def test_plural_profile_keeps_the_same_complete_category_independent_cohort(self):
        # Inert profile projection only: these DTOs and absent package owners
        # cannot satisfy the production entrypoint or issue scientific status.
        common = self.source.slot
        rows = tuple(gates.ReproductionResultPackageBinding(
            item.result.artifact_sha256, item.result.artifact_record_hash,
            _digest(f"inert-package-{index}"), _digest(f"inert-package-record-{index}"),
        ) for index, item in enumerate(_scientific_audit_cohort_from_source(self.source).results))
        evidence = sorted({
            *zip(common.evidence_artifact_hashes, common.evidence_artifact_record_hashes, strict=True),
            *((row.reproducibility_package_artifact_sha256, row.reproducibility_package_artifact_record_hash)
              for row in rows),
        })
        slot = replace(plural_fixtures._slot(5),
            assessment_id=common.assessment_id, run_id=common.run_id,
            research_state_snapshot_artifact_hash=common.research_state_snapshot_artifact_hash,
            research_state_snapshot_artifact_record_hash=common.research_state_snapshot_artifact_record_hash,
            claim_graph_artifact_hash=common.claim_graph_artifact_hash,
            claim_graph_artifact_record_hash=common.claim_graph_artifact_record_hash,
            central_claim_ids=common.central_claim_ids,
            evidence_artifact_hashes=tuple(item[0] for item in evidence),
            evidence_artifact_record_hashes=tuple(item[1] for item in evidence),
            result_artifact_hashes=common.result_artifact_hashes,
            result_artifact_record_hashes=common.result_artifact_record_hashes,
            reproduction_package_bindings=rows,
        )
        source = gates._SemanticReproductionCohortAuditReplay(
            authority=plural_fixtures._authority(slot), record=None, slot=slot,
            canonical_scope=replace(plural_fixtures._scope(slot), state=self.source.canonical_scope.state),
            publication_event_id="inert-plural-publication", publication_event_hash=_digest("inert-plural-publication"),
            publication_event_index=10, entry_snapshot=(None, None),
        )
        plural = _scientific_audit_cohort_from_source(source)
        singular = _scientific_audit_cohort_from_source(self.source)
        self.assertEqual(plural.round_key, singular.round_key)
        self.assertEqual(plural.results, singular.results)
        self.assertEqual(plural.executions, singular.executions)
        self.assertFalse(plural.audit_source.authority.scientific_gate_passed)
        self.assertFalse(hasattr(plural.audit_source.authority, "reproducibility_package_artifact_hash"))

    def test_real_cohort_dispatch_retains_closed_profiles_and_both_full_owners(self):
        tree = ast.parse(textwrap.dedent(inspect.getsource(_require_scientific_audit_cohort)))
        calls = tuple(node for node in ast.walk(tree) if isinstance(node, ast.Call))
        for owner, mapping in (
            ("_require_semantic_challenge_audit_source", "expected_reproducibility_package_artifact_hash"),
            ("_require_semantic_reproduction_cohort_audit_source", "expected_reproduction_package_bindings"),
        ):
            selected = tuple(node for node in calls if isinstance(node.func, ast.Name) and node.func.id == owner)
            self.assertEqual(len(selected), 1)
            keys = {kw.arg for kw in selected[0].keywords}
            self.assertIn(mapping, keys)
        self.assertEqual(sum(isinstance(node.func, ast.Name) and node.func.id == "_r_check_read_snapshot"
                             for node in calls), 2)
        self.assertIn("SemanticReproductionCohortAuditAuthority.from_dict(payload)", ast.unparse(tree))
        self.assertIn("SemanticChallengeAuditAuthority.from_dict(payload)", ast.unparse(tree))

    def test_omitted_audited_claim_result_or_test_is_not_a_smaller_cohort(self):
        for object_id in ("claim-b", "result-4", "test-4"):
            changed = tuple(item for item in self.entries if item.research_object.object_id != object_id)
            source = replace(self.source, canonical_scope=replace(
                self.source.canonical_scope, state=replace(self.source.canonical_scope.state, entries=changed),
            ))
            with self.subTest(object_id=object_id), self.assertRaisesRegex(ValueError, "audited Claim/Result/Test"):
                _scientific_audit_cohort_from_source(source)

    def test_missing_or_duplicate_test_fails_even_if_scope_is_rebound(self):
        missing = tuple(item for item in self.entries if item.research_object.object_id != "test-4")
        test = next(item.research_object for item in self.entries if item.research_object.object_id == "test-4")
        duplicate = (*self.entries, _binding(replace(test, object_id="test-duplicate", content_hash=None)))
        for entries in (missing, duplicate):
            with self.subTest(count=len(entries)), self.assertRaisesRegex(ValueError, "untested|one exact Test"):
                _scientific_audit_cohort_from_source(self._source(entries))

    def test_same_run_wrong_result_and_stale_revision_are_rejected(self):
        target = next(item.research_object for item in self.entries if item.research_object.object_id == "result-0")
        changes = (
            dict(result_ids=("result-0",)),
            dict(parents=(_ref(target, "tests"),)),
            dict(parents=(replace(_ref(target, "tests"), content_hash=_digest("stale")),)),
            dict(parents=(replace(_ref(target, "tests"), evaluated=False),)),
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises((ValueError, ValidationError)):
                _scientific_audit_cohort_from_source(self._source(self._changed_object("test-1", **change)))

    def test_additional_run_cannot_disappear_because_it_has_no_result(self):
        for changes in (dict(dataset_ids=("dataset-1",)), dict(experiment_id="experiment-1")):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "execution ancestry"):
                _scientific_audit_cohort_from_source(self._source(
                    self._changed_object("extra-run-without-result", **changes),
                ))

    def test_unknown_or_crossed_canonical_profiles_do_not_drop_members(self):
        for version in ("v3", "v9", "legacy"):
            entries = self._changed_object("test-4", metadata={
                "schema_version": f"scientific-statistical-canonical-state/{version}",
            })
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "unsupported or mixed"):
                _scientific_audit_cohort_from_source(self._source(entries))

    def test_owned_result_shape_requires_ordered_run_and_metric_parents(self):
        baseline = _scientific_audit_cohort_from_source(self.source)
        self.assertTrue(all(len(item.result.research_object.parents) == 2 for item in baseline.results))
        result = next(item.research_object for item in self.entries if item.research_object.object_id == "result-0")
        for changes in (
            dict(parents=result.parents[:1]),
            dict(parents=tuple(reversed(result.parents))),
            dict(parents=(result.parents[0], replace(result.parents[1], relation="evaluated_by"))),
            dict(metric_id="metric-1"),
        ):
            changed_result = replace(result, **changes, content_hash=None)
            # Rebind the inert Test to this changed Result, so a stale Test
            # reference cannot mask the actual Run/Metric shape guard.
            entries = tuple(
                replace(item, research_object=changed_result)
                if item.research_object.object_id == "result-0"
                else replace(item, research_object=replace(
                    item.research_object, parents=(_ref(changed_result, "tests"),), content_hash=None,
                )) if item.research_object.object_id == "test-0" else item
                for item in self.entries
            )
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "parent|execution/Metric"):
                _scientific_audit_cohort_from_source(self._source(entries))

    def test_round_splice_and_unowned_namespace_are_not_companions(self):
        with self.assertRaisesRegex(ValueError, "complete audit source companion"):
            _scientific_audit_cohort_from_source(SimpleNamespace(canonical_scope=self.source.canonical_scope))
        for field, value in (("assessment_id", "other-assessment"), ("claim_graph_artifact_hash", _digest("other-graph"))):
            source = replace(self.source, authority=replace(self.source.authority, **{field: value}))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "another audit round"):
                _scientific_audit_cohort_from_source(source)

    def test_real_cohort_entry_rejects_missing_audit_without_mutation(self):
        with TemporaryDirectory(prefix="inert-cohort-owner-refusal-") as directory:
            registry, ledger = self.fixture.fixture._runtime(Path(directory))
            before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
            with self.assertRaises((ValueError, ValidationError, ArtifactCorruptionError)):
                _require_scientific_audit_cohort(
                    registry, ledger, run_id="audit-run", semantic_audit_artifact_sha256=_digest("absent-audit"),
                )
            self.assertEqual((registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)), before)

    def test_inert_source_admission_requires_exact_hash_and_event_types(self):
        admission = _ScientificSourceAdmission(
            _digest("artifact"), _digest("record"), "event-inert", _digest("event"), 3,
        )
        for field, value in (
            ("artifact_sha256", "bad"), ("artifact_record_hash", None),
            ("ledger_event_hash", "bad"), ("ledger_event_id", "invalid id"),
            ("ledger_event_index", True), ("ledger_event_index", -1),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                replace(admission, **{field: value})

    def test_timeline_join_uses_full_owner_publication_and_retained_protocol(self):
        tree = ast.parse(textwrap.dedent(inspect.getsource(_resolve_r3_e3_timeline)))
        calls = tuple(node for node in ast.walk(tree) if isinstance(node, ast.Call))
        source_calls = tuple(node for node in calls if isinstance(node.func, ast.Name)
                             and node.func.id == "_require_scientific_confirmatory_timeline_source_v2")
        self.assertEqual(len(source_calls), 1)
        self.assertFalse(any(isinstance(node.func, ast.Name) and node.func.id ==
                             "require_scientific_confirmatory_protocol_binding" for node in calls))
        admission_calls = tuple(node for node in calls if isinstance(node.func, ast.Name)
                                and node.func.id == "_ScientificSourceAdmission")
        self.assertEqual(len(admission_calls), 1)
        self.assertEqual(
            {kw.arg: ast.unparse(kw.value) for kw in admission_calls[0].keywords},
            dict(artifact_sha256="record.sha256", artifact_record_hash="str(record.record_hash)",
                 ledger_event_id="source.publication_event_id", ledger_event_hash="source.publication_event_hash",
                 ledger_event_index="source.publication_event_index"),
        )

    def test_inert_canonical_materializations_are_transported_without_reference_search(self):
        selected = tuple(item for item in self.entries if item.research_object.object_id in {"result-0", "test-0"})
        # This exercises only conversion of unqualified inert bindings. It is
        # not a call to the scientific Result or Test source owner.
        values = _canonical_source_admissions(
            None, None, run_id="audit-run",
            subject=SimpleNamespace(scoped=SimpleNamespace(entries=selected)),
            include_frozen_spec=False,
        )
        self.assertEqual(len(values), 2)
        for admission, binding in zip(values, selected, strict=True):
            self.assertEqual(admission.artifact_sha256, binding.artifact_sha256)
            self.assertEqual(admission.artifact_record_hash, binding.artifact_record_hash)
            self.assertEqual(admission.ledger_event_id, binding.materialization_event_id)
            self.assertEqual(admission.ledger_event_hash, binding.materialization_event_hash)
            self.assertEqual(admission.ledger_event_index, binding.materialization_event_index)

    def test_spec_admission_replays_the_promoted_timeline_and_exact_freeze_owner(self):
        tree = ast.parse(textwrap.dedent(inspect.getsource(_canonical_source_admissions)))
        calls = tuple(node for node in ast.walk(tree) if isinstance(node, ast.Call))
        for owner in ("_require_scientific_confirmatory_timeline_source_v2",
                      "require_evaluation_contract_freeze_gate_receipt"):
            self.assertEqual(sum(isinstance(node.func, ast.Name) and node.func.id == owner for node in calls), 1)
        self.assertFalse(any(isinstance(node.func, ast.Name) and node.func.id == "_event_binding" for node in calls))
        admissions = tuple(node for node in calls if isinstance(node.func, ast.Name)
                           and node.func.id == "_ScientificSourceAdmission")
        self.assertEqual(len(admissions), 2)
        fields = next({kw.arg: ast.unparse(kw.value) for kw in node.keywords}
                      for node in admissions if any(ast.unparse(kw.value) == "freeze.design_freeze_event_id" for kw in node.keywords))
        self.assertEqual(fields["artifact_sha256"], "subject.spec_record.sha256")
        self.assertEqual(fields["ledger_event_hash"], "freeze.design_freeze_event_hash")
        self.assertEqual(fields["ledger_event_index"], "freeze.design_freeze_event_index")

    def test_inert_r1_projection_keeps_brief_and_assessment_ids_distinct_from_question(self):
        roots = {name: _digest(name) for name in (
            "goal_artifact_sha256", "goal_record_hash", "goal_sha256",
            "investigation_state_artifact_sha256", "investigation_state_record_hash", "investigation_state_sha256",
            "research_brief_artifact_sha256", "research_brief_record_hash", "research_brief_sha256",
        )}
        assessment = ResearchQuestionGateAssessment(
            assessment_id="inert-assessment-id", object_id="inert-brief-id", run_id="audit-run",
            ledger_path="runs/audit-run/events.jsonl", gate_event_id="inert-assessment-event",
            gate_event_hash=_digest("assessment-event"), gate_event_index=2,
            outcome=ResearchGateOutcome.REFORMULATE,
            verification_status=ScientificGateVerificationStatus.NON_EVIDENTIARY,
            selected_direction_id="inert-direction", criteria_projection_sha256=_digest("criteria"),
            semantic_judgment_artifact_sha256=None, semantic_judgment_record_hash=None,
            semantic_judgment_structured_output_sha256=None,
            evidence_artifact_hashes=(_digest("inert-evidence"),),
            evidence_record_hashes=(_digest("inert-evidence-record"),), **roots,
        )
        record = check_fixtures._record("inert-r1-assessment", "research_question_gate_assessment")
        resolution = ScientificRCheckResolution(
            r_check=RCheck.R1, evaluator_class=EvaluatorClass.E0,
            status=AuthorityStatus.UNTESTED, scope=AuthorityScope.SYSTEM_FIXTURE,
            reason_code="INERT_NON_EVIDENTIARY", checks=(), subject_key=(("run_id", "audit-run"),),
        )
        carried = _with_owned_r1_sources(resolution, assessment=assessment, assessment_record=record)
        subject = dict(carried.subject_key)
        self.assertEqual(subject["research_brief_id"], "inert-brief-id")
        self.assertEqual(subject["research_question_assessment_id"], "inert-assessment-id")
        self.assertNotIn("research_question_id", subject)
        self.assertEqual({name: subject[name] for name in roots}, roots)
        self.assertEqual(subject["research_question_assessment_event_id"], "inert-assessment-event")
        self.assertEqual(subject["research_question_assessment_outcome"], "REFORMULATE")
        self.assertIs(carried.status, AuthorityStatus.UNTESTED)
        self.assertIs(carried.scope, AuthorityScope.SYSTEM_FIXTURE)
        self.assertEqual(carried.source_admissions[0].ledger_event_index, 2)
        for changes in (dict(freeze=SimpleNamespace()), dict(audit_source=SimpleNamespace())):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                _with_owned_r1_sources(resolution, assessment=assessment, assessment_record=record, **changes)

    def test_inert_domain_admission_uses_only_the_owner_publication_identity(self):
        from scientist_one.domains import _scientific_domain_validity_event_id

        record = check_fixtures._record("inert-domain", "domain_validity.generic_ml")
        publication = SimpleNamespace(
            event_id=_scientific_domain_validity_event_id(record.sha256), event_hash=_digest("inert-domain-event"),
        )
        reference = SimpleNamespace(event_id="later-reference", event_hash=_digest("later-event"),
                                    artifact_hashes=(record.sha256,))
        # Inert selector conversion only; these are not validated ledger events.
        admission = _domain_admission_after_full_replay(record=record, events=(reference, publication, reference))
        self.assertEqual(admission.ledger_event_index, 1)
        self.assertEqual(admission.ledger_event_hash, publication.event_hash)
        for events in ((reference,), (publication, publication)):
            with self.subTest(count=len(events)), self.assertRaisesRegex(ValueError, "unique owner-validated"):
                _domain_admission_after_full_replay(record=record, events=events)

    def test_real_domain_route_does_not_admit_an_inert_receipt(self):
        from scientist_one.domains import SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3

        with TemporaryDirectory(prefix="inert-domain-admission-refusal-") as directory:
            registry, ledger = self.fixture.fixture._runtime(Path(directory))
            record = registry.put_json(
                {"scientific_evidence": False, "fixture_only": True},
                logical_type="domain_validity.generic_ml",
                schema_version=SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3,
                origin="NON_EVIDENTIARY_OWNER_REFUSAL", creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("test-only",), frozen=True,
            )
            before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
            result = resolve_scientific_r_check_sources(
                registry, ledger, run_id="audit-run", r_check=RCheck.R3,
                evaluator_class=EvaluatorClass.E0, source_artifact_sha256s=(record.sha256,),
            )
            self.assertIs(result.status, AuthorityStatus.FAIL)
            self.assertEqual(result.source_admissions, ())
            self.assertEqual((registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)), before)


if __name__ == "__main__":
    unittest.main()
