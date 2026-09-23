"""Bounded D-059 cohort-design controls.

These tests exercise only the private, already-typed joins around the cohort
design obligation.  The fixture source is intentionally unqualified: it is a
structural ``SYSTEM_FIXTURE``/``UNTESTED`` inventory, never a scientific
owner, issuer, trust root, or provider result.
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

from scientist_one.evaluators import AuthorityScope, AuthorityStatus, EvaluatorClass, RCheck
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.research_state import ResearchQuestionOutcome
from scientist_one.scientific_design import ResearchGateOutcome
from scientist_one.scientific_r_checks import (
    _ScientificCohortDesignObligation,
    _ScientificCohortDesignSource,
    _ScientificCohortExecution,
    _ScientificCohortQuestion,
    _ScientificCohortResult,
    _ScientificSourceAdmission,
    _cohort_design_questions,
    _cohort_execution_subject,
    _cohort_protocol_publication_selector,
    _cohort_r3_leaf_matches_execution,
    _cohort_r1_leaf_matches_design,
    _cohort_result_leaf_matches_member,
    _require_scientific_cohort_designs,
    _scientific_audit_cohort_from_source,
    ScientificRCheckResolution,
)
from tests import test_scientific_audit_cohort as audit_fixtures
from tests import test_challenger_audit_authority as authority_fixtures
from tests import test_scientific_r_checks as check_fixtures


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _function_tree(function):
    return ast.parse(textwrap.dedent(inspect.getsource(function))).body[0]


class ScientificCohortDesignTests(unittest.TestCase):
    """Inert cohort joins and real source-owner refusal boundaries."""

    def setUp(self) -> None:
        self.fixture = audit_fixtures.ScientificAuditCohortTests()
        self.fixture.setUp()
        self.cohort = _scientific_audit_cohort_from_source(self.fixture.source)

    def _runtime(self, directory: str):
        return authority_fixtures.SemanticChallengerAuditAuthorityTests()._runtime(Path(directory))

    def _paired_cohort(self, registry, ledger, **changes):
        before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
        source = replace(self.cohort.audit_source, entry_snapshot=before)
        return replace(self.cohort, audit_source=source, **changes)

    def test_inert_complete_inventory_retains_no_result_run_as_unmet(self) -> None:
        """Every unqualified Run remains an obligation; no Result is discovered."""

        with TemporaryDirectory(prefix="inert-cohort-design-inventory-") as directory:
            registry, ledger = self._runtime(directory)
            obligations = _require_scientific_cohort_designs(
                registry, ledger, cohort=self._paired_cohort(registry, ledger),
            )
            self.assertEqual(len(obligations), 6)
            self.assertEqual(
                {item.execution.run.research_object.object_id for item in obligations},
                {f"run-{index}" for index in range(5)} | {"extra-run-without-result"},
            )
            self.assertTrue(all(item.source is None for item in obligations))
            self.assertTrue(all(item.questions == () for item in obligations))
            self.assertTrue(all(
                item.unmet_reason == "SCIENTIFIC_EXECUTION_AUTHORITY_UNAVAILABLE"
                for item in obligations
            ))

    def test_paired_snapshot_is_required_and_read_only_on_stale_source(self) -> None:
        with TemporaryDirectory(prefix="inert-cohort-design-snapshot-") as directory:
            registry, ledger = self._runtime(directory)
            before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
            stale = replace(self.cohort.audit_source, entry_snapshot=(None, before[1]))
            with self.assertRaisesRegex(ValueError, "source changed"):
                _require_scientific_cohort_designs(
                    registry, ledger, cohort=replace(self.cohort, audit_source=stale),
                )
            self.assertEqual(
                (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)),
                before,
            )

    def test_non_proceed_question_inventory_cannot_supply_a_scientific_gate(self) -> None:
        question = self.cohort.questions[0]
        non_proceed = replace(
            question,
            research_object=replace(
                question.research_object,
                content_hash=None,
                gate_outcome=ResearchQuestionOutcome.TERMINATE,
            ),
            scientific_evidence_eligible=True,
        )
        with TemporaryDirectory(prefix="inert-cohort-design-question-") as directory:
            registry, ledger = self._runtime(directory)
            cohort = self._paired_cohort(registry, ledger, questions=(non_proceed,))
            obligations = _require_scientific_cohort_designs(registry, ledger, cohort=cohort)
            self.assertEqual(len(obligations), 6)
            self.assertTrue(all(item.questions == () for item in obligations))
            self.assertTrue(all(item.source is None for item in obligations))

    def test_protocol_selector_is_exactly_execution_id_bound_and_closed(self) -> None:
        digest = _digest("protocol-binding")
        events = (
            SimpleNamespace(metadata={
                "scientific_confirmatory_protocol_binding": {
                    "execution_run_id": "other-run", "binding_artifact_sha256": _digest("other"),
                },
            }),
            SimpleNamespace(metadata={
                "result": {"execution_run_id": "target-run", "binding_artifact_sha256": _digest("result")},
            }),
            SimpleNamespace(metadata={
                "scientific_confirmatory_protocol_binding": {
                    "execution_run_id": "target-run", "binding_artifact_sha256": digest,
                },
            }),
        )
        self.assertEqual(
            _cohort_protocol_publication_selector(events, execution_run_id="target-run"),
            digest,
        )
        self.assertIsNone(_cohort_protocol_publication_selector(events, execution_run_id="missing-run"))
        for metadata in (
            {"scientific_confirmatory_protocol_binding": {
                "execution_run_id": "target-run", "binding_artifact_sha256": _digest("one"),
            }},
            {"scientific_confirmatory_protocol_binding": {
                "execution_run_id": "target-run", "binding_artifact_sha256": "not-a-digest",
            }},
        ):
            selected = (*events, SimpleNamespace(metadata=metadata))
            with self.subTest(metadata=metadata), self.assertRaisesRegex(ValueError, "protocol"):
                _cohort_protocol_publication_selector(selected, execution_run_id="target-run")
        # A malformed single candidate must fail on its own; a second slot
        # must not mask the selector-shape check.
        for value in (None, "not-a-digest", 17):
            single = (SimpleNamespace(metadata={
                "scientific_confirmatory_protocol_binding": {
                    "execution_run_id": "target-run", "binding_artifact_sha256": value,
                },
            }),)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "selector is malformed"):
                _cohort_protocol_publication_selector(single, execution_run_id="target-run")

    def test_shared_brief_questions_are_all_memberships_before_freeze_only(self) -> None:
        source = SimpleNamespace(
            contract=SimpleNamespace(research_brief_sha256=_digest("shared-brief")),
            freeze=SimpleNamespace(design_freeze_event_index=10),
        )

        def question(label, brief, index):
            return _ScientificCohortQuestion(
                question=SimpleNamespace(object_id=f"question-{label}"),
                gate_record=check_fixtures._record(f"gate-{label}", "research_question_gate_receipt"),
                gate=SimpleNamespace(research_brief_sha256=brief, gate_event_index=index),
            )

        members = (
            question("before-a", _digest("shared-brief"), 2),
            question("before-b", _digest("shared-brief"), 9),
            question("at-freeze", _digest("shared-brief"), 10),
            question("after", _digest("shared-brief"), 11),
            question("unrelated", _digest("other-brief"), 1),
        )
        selected = _cohort_design_questions(source, members)
        self.assertEqual(tuple(item.question.object_id for item in selected), (
            "question-before-a", "question-before-b",
        ))

    def test_design_helper_replays_all_source_owners_without_result_or_brief_search(self) -> None:
        """Structure-only check: inert DTOs do not bypass the actual owners."""

        tree = _function_tree(_require_scientific_cohort_designs)
        calls = tuple(node for node in ast.walk(tree) if isinstance(node, ast.Call))
        call_names = tuple(
            node.func.id for node in calls if isinstance(node.func, ast.Name)
        )
        for owner in (
            "require_current_scientific_execution_run",
            "require_scientific_execution_authority",
            "require_scientific_confirmatory_protocol_binding",
            "require_frozen_evaluation_contract",
            "require_evaluation_contract_freeze_gate_receipt",
            "require_research_question_gate_receipt",
            "_matching_scientific_confirmatory_protocol_events",
        ):
            self.assertIn(owner, call_names)
        self.assertNotIn("require_scientific_result", call_names)
        self.assertNotIn("require_scientific_statistical", " ".join(call_names))
        source = textwrap.dedent(inspect.getsource(_require_scientific_cohort_designs))
        self.assertNotIn("list_records", source)
        self.assertIn("run.research_object.object_id", source)
        self.assertIn("scientific_confirmatory_protocol_binding", inspect.getsource(_cohort_protocol_publication_selector))
        _resolution, obligation, _question = self._matching_obligation()
        self.assertIs(type(obligation.source.protocol_publication), _ScientificSourceAdmission)
        self.assertEqual(
            obligation.source.protocol_publication.artifact_sha256,
            obligation.source.protocol_record.sha256,
        )

    def test_eligible_inert_run_refuses_missing_real_source_without_writes(self) -> None:
        """A mechanically eligible DTO cannot become an execution authority."""

        execution = self.cohort.executions[0]
        eligible_run = replace(execution.run, scientific_evidence_eligible=True)
        eligible_execution = replace(execution, run=eligible_run)
        with TemporaryDirectory(prefix="inert-cohort-design-owner-refusal-") as directory:
            registry, ledger = self._runtime(directory)
            cohort = self._paired_cohort(
                registry, ledger,
                executions=(eligible_execution, *self.cohort.executions[1:]),
            )
            before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
            with self.assertRaises((ValueError, ValidationError, ArtifactError)):
                _require_scientific_cohort_designs(registry, ledger, cohort=cohort)
            self.assertEqual(
                (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)),
                before,
            )

    def _matching_obligation(self):
        digest = _digest
        brief_roots = {
            "goal_artifact_sha256": digest("goal-artifact"),
            "goal_record_hash": digest("goal-record"),
            "goal_sha256": digest("goal-content"),
            "investigation_state_artifact_sha256": digest("investigation-artifact"),
            "investigation_state_record_hash": digest("investigation-record"),
            "investigation_state_sha256": digest("investigation-content"),
            "research_brief_artifact_sha256": digest("brief-artifact"),
            "research_brief_record_hash": digest("brief-record"),
            "research_brief_sha256": digest("brief-content"),
        }
        execution = SimpleNamespace(ledger_run_id="inert-cohort-run")
        protocol_record = check_fixtures._record("inert-protocol", "scientific_confirmatory_protocol_binding")
        freeze_record = check_fixtures._record("inert-freeze", "evaluation_contract_freeze_gate_receipt")
        contract_record = check_fixtures._record("inert-contract", "evaluation_contract")
        source = _ScientificCohortDesignSource(
            execution_record=check_fixtures._record("inert-execution", "scientific_execution_authority"),
            execution=SimpleNamespace(
                ledger_run_id="inert-cohort-run",
                execution_run_id="inert-execution-run",
            ),
            protocol_record=protocol_record,
            protocol=SimpleNamespace(
                frozen_run_spec_artifact_sha256=digest("frozen-spec-artifact"),
                frozen_run_spec_record_hash=digest("frozen-spec-record"),
                frozen_run_spec_sha256=digest("frozen-spec-content"),
                dataset_id="inert-dataset-id",
                dataset_authority_artifact_sha256=digest("dataset-artifact"),
                dataset_authority_record_hash=digest("dataset-record"),
            ),
            protocol_publication=_ScientificSourceAdmission(
                artifact_sha256=protocol_record.sha256,
                artifact_record_hash=str(protocol_record.record_hash),
                ledger_event_id="inert-protocol-publication",
                ledger_event_hash=digest("protocol-publication"),
                ledger_event_index=8,
            ),
            freeze_record=freeze_record,
            freeze=SimpleNamespace(
                design_freeze_event_id="inert-freeze-event",
                design_freeze_event_hash=digest("freeze-event"),
                design_freeze_event_index=7,
            ),
            contract_record=contract_record,
            contract=SimpleNamespace(
                contract_id="inert-contract-id",
                sha256=digest("contract-content"),
                research_brief_sha256=brief_roots["research_brief_sha256"],
            ),
        )
        gate = SimpleNamespace(
            object_id="inert-brief-id",
            gate_event_index=4,
            selected_direction_id="inert-direction",
            criteria_projection_sha256=digest("criteria"),
            outcome=ResearchGateOutcome.PROCEED,
            **brief_roots,
        )
        question = _ScientificCohortQuestion(
            question=SimpleNamespace(object_id="inert-question"),
            gate_record=check_fixtures._record("inert-gate", "research_question_gate_receipt"),
            gate=gate,
        )
        obligation = _ScientificCohortDesignObligation(
            execution=execution, source=source, questions=(question,), unmet_reason=None,
        )
        assessment_record = check_fixtures._record("inert-assessment", "research_question_gate_assessment")
        values = {
            "run_id": execution.ledger_run_id,
            "research_brief_id": gate.object_id,
            "contract_id": source.contract.contract_id,
            "research_question_assessment_artifact_sha256": assessment_record.sha256,
            "research_question_assessment_record_hash": str(assessment_record.record_hash),
            "research_question_assessment_event_id": "inert-assessment-event",
            "research_question_assessment_event_hash": digest("assessment-event"),
            "research_question_assessment_event_index": "3",
            "contract_artifact_sha256": contract_record.sha256,
            "contract_record_hash": str(contract_record.record_hash),
            "contract_sha256": source.contract.sha256,
            "contract_freeze_artifact_sha256": freeze_record.sha256,
            "contract_freeze_record_hash": str(freeze_record.record_hash),
            "frozen_run_spec_artifact_sha256": source.protocol.frozen_run_spec_artifact_sha256,
            "frozen_run_spec_record_hash": source.protocol.frozen_run_spec_record_hash,
            "frozen_run_spec_sha256": source.protocol.frozen_run_spec_sha256,
            "design_freeze_event_id": source.freeze.design_freeze_event_id,
            "design_freeze_event_hash": source.freeze.design_freeze_event_hash,
            "design_freeze_event_index": str(source.freeze.design_freeze_event_index),
            "selected_direction_id": gate.selected_direction_id,
            "criteria_projection_sha256": gate.criteria_projection_sha256,
            "research_question_assessment_outcome": gate.outcome.value,
            **brief_roots,
        }
        admissions = (
            _ScientificSourceAdmission(
                artifact_sha256=assessment_record.sha256,
                artifact_record_hash=str(assessment_record.record_hash),
                ledger_event_id="inert-assessment-event",
                ledger_event_hash=digest("assessment-event"),
                ledger_event_index=3,
            ),
            _ScientificSourceAdmission(
                artifact_sha256=freeze_record.sha256,
                artifact_record_hash=str(freeze_record.record_hash),
                ledger_event_id=source.freeze.design_freeze_event_id,
                ledger_event_hash=source.freeze.design_freeze_event_hash,
                ledger_event_index=source.freeze.design_freeze_event_index,
            ),
        )
        resolution = ScientificRCheckResolution(
            r_check=RCheck.R1,
            evaluator_class=EvaluatorClass.E0,
            status=AuthorityStatus.UNTESTED,
            scope=AuthorityScope.SYSTEM_FIXTURE,
            reason_code="INERT_NON_EVIDENTIARY",
            checks=(),
            subject_key=tuple(values.items()),
            source_admissions=admissions,
        )
        return resolution, obligation, question

    def _matching_result_member(self):
        resolution, obligation, _question = self._matching_obligation()
        digest = _digest

        def binding(label, logical_type):
            record = check_fixtures._record(label, logical_type)
            return SimpleNamespace(
                artifact_sha256=record.sha256,
                artifact_record_hash=str(record.record_hash),
                materialization_event_id=f"{label}-event",
                materialization_event_hash=digest(f"{label}-event-hash"),
                materialization_event_index=2,
            )

        execution = _ScientificCohortExecution(
            run=binding("inert-run", "research_state.run"),
            experiment=SimpleNamespace(),
            implementation=binding("inert-implementation", "research_state.implementation"),
            method=binding("inert-method", "research_state.method"),
            dataset=binding("inert-dataset", "research_state.dataset"),
        )
        result = binding("inert-result", "research_state.result")
        statistical_test = binding("inert-statistical-test", "research_state.statistical_test")
        member = _ScientificCohortResult(
            result=result,
            statistical_test=statistical_test,
            execution=execution,
            metric=SimpleNamespace(),
        )
        obligation = replace(obligation, execution=execution)
        expected = _cohort_execution_subject(obligation.source)
        expected.update({
            "canonical_result_artifact_sha256": result.artifact_sha256,
            "canonical_result_record_hash": result.artifact_record_hash,
            "canonical_statistical_test_artifact_sha256": statistical_test.artifact_sha256,
            "canonical_statistical_test_record_hash": statistical_test.artifact_record_hash,
            "canonical_run_artifact_sha256": execution.run.artifact_sha256,
            "canonical_run_record_hash": execution.run.artifact_record_hash,
            "canonical_implementation_artifact_sha256": execution.implementation.artifact_sha256,
            "canonical_implementation_record_hash": execution.implementation.artifact_record_hash,
            "canonical_method_artifact_sha256": execution.method.artifact_sha256,
            "canonical_method_record_hash": execution.method.artifact_record_hash,
            "canonical_dataset_artifact_sha256": execution.dataset.artifact_sha256,
            "canonical_dataset_record_hash": execution.dataset.artifact_record_hash,
        })

        def admission(value):
            return _ScientificSourceAdmission(
                artifact_sha256=value.artifact_sha256,
                artifact_record_hash=value.artifact_record_hash,
                ledger_event_id=value.materialization_event_id,
                ledger_event_hash=value.materialization_event_hash,
                ledger_event_index=value.materialization_event_index,
            )

        r2_admissions = (
            admission(result), admission(statistical_test), admission(execution.run),
            admission(execution.implementation), admission(execution.method),
            _ScientificSourceAdmission(
                artifact_sha256=obligation.source.protocol.frozen_run_spec_artifact_sha256,
                artifact_record_hash=obligation.source.protocol.frozen_run_spec_record_hash,
                ledger_event_id=obligation.source.freeze.design_freeze_event_id,
                ledger_event_hash=obligation.source.freeze.design_freeze_event_hash,
                ledger_event_index=obligation.source.freeze.design_freeze_event_index,
            ),
        )
        return resolution, obligation, member, expected, r2_admissions

    def test_result_leaf_matchers_are_exact_and_keep_unresolved_status(self) -> None:
        resolution, obligation, member, expected, r2_admissions = self._matching_result_member()
        r2 = replace(
            resolution,
            r_check=RCheck.R2,
            source_admissions=r2_admissions,
            subject_key=tuple(expected.items()),
        )
        self.assertTrue(_cohort_result_leaf_matches_member(r2, member, obligation))
        self.assertIs(r2.status, AuthorityStatus.UNTESTED)
        self.assertIs(r2.scope, AuthorityScope.SYSTEM_FIXTURE)

        r4 = replace(
            r2,
            r_check=RCheck.R4,
            status=AuthorityStatus.FAIL,
            scope=AuthorityScope.SCIENTIFIC,
            source_admissions=r2_admissions[:2],
        )
        self.assertTrue(_cohort_result_leaf_matches_member(r4, member, obligation))
        self.assertIs(r4.status, AuthorityStatus.FAIL)

        for field in (
            "canonical_result_record_hash", "canonical_statistical_test_artifact_sha256",
            "dataset_id", "frozen_run_spec_sha256",
        ):
            changed = dict(expected)
            changed[field] = _digest(f"wrong-{field}") if field.endswith("sha256") or field.endswith("hash") else "wrong-dataset"
            altered = replace(r2, subject_key=tuple(changed.items()))
            with self.subTest(field=field):
                self.assertFalse(_cohort_result_leaf_matches_member(altered, member, obligation))
        self.assertFalse(_cohort_result_leaf_matches_member(
            replace(r2, source_admissions=r2_admissions[1:]), member, obligation,
        ))
        self.assertFalse(_cohort_result_leaf_matches_member(
            replace(r2, source_admissions=r2_admissions[:-1]), member, obligation,
        ))
        wrong_event = replace(
            r2,
            source_admissions=(replace(r2_admissions[0], ledger_event_id="wrong-event"), *r2_admissions[1:]),
        )
        self.assertFalse(_cohort_result_leaf_matches_member(wrong_event, member, obligation))
        other_member = replace(
            member,
            execution=replace(
                member.execution,
                run=SimpleNamespace(**{
                    **vars(member.execution.run), "artifact_sha256": _digest("other-run"),
                }),
            ),
        )
        self.assertFalse(_cohort_result_leaf_matches_member(r2, other_member, obligation))

    def test_r3_execution_match_covers_resultless_run_and_named_owner_admission(self) -> None:
        _resolution, obligation, _member, _expected, _r2_admissions = self._matching_result_member()
        # Neither R3 producer names a Result or StatisticalTest. Exercise
        # exactly that absence, rather than inheriting those fields from R2.
        expected = _cohort_execution_subject(obligation.source)
        domain_record = check_fixtures._record("inert-domain", "domain_validity.generic_ml")
        timeline_record = check_fixtures._record("inert-timeline", "scientific_confirmatory_timeline_receipt_v2")

        domain_values = {
            **expected,
            "canonical_run_artifact_sha256": obligation.execution.run.artifact_sha256,
            "canonical_run_record_hash": obligation.execution.run.artifact_record_hash,
            "domain_validity_artifact_sha256": domain_record.sha256,
            "domain_validity_record_hash": str(domain_record.record_hash),
        }
        domain_resolution = replace(
            _resolution,
            r_check=RCheck.R3,
            evaluator_class=EvaluatorClass.E0,
            source_admissions=(
                _ScientificSourceAdmission(
                    artifact_sha256=domain_record.sha256,
                    artifact_record_hash=str(domain_record.record_hash),
                    ledger_event_id="inert-domain-event",
                    ledger_event_hash=_digest("domain-event"),
                    ledger_event_index=12,
                ),
            ),
            subject_key=tuple(domain_values.items()),
        )
        self.assertTrue(_cohort_r3_leaf_matches_execution(domain_resolution, obligation))
        self.assertIs(domain_resolution.status, AuthorityStatus.UNTESTED)
        self.assertFalse(any("result" in key or "statistical_test" in key for key in domain_values))
        self.assertFalse(_cohort_r3_leaf_matches_execution(
            replace(domain_resolution, source_admissions=()), obligation,
        ))

        timeline_values = {
            **expected,
            "protocol_binding_artifact_sha256": obligation.source.protocol_record.sha256,
            "protocol_binding_record_hash": str(obligation.source.protocol_record.record_hash),
            "scientific_confirmatory_timeline_artifact_sha256": timeline_record.sha256,
            "scientific_confirmatory_timeline_record_hash": str(timeline_record.record_hash),
        }
        timeline_resolution = replace(
            domain_resolution,
            evaluator_class=EvaluatorClass.E3,
            status=AuthorityStatus.FAIL,
            scope=AuthorityScope.SCIENTIFIC,
            source_admissions=(
                _ScientificSourceAdmission(
                    artifact_sha256=timeline_record.sha256,
                    artifact_record_hash=str(timeline_record.record_hash),
                    ledger_event_id="inert-timeline-event",
                    ledger_event_hash=_digest("timeline-event"),
                    ledger_event_index=13,
                ),
            ),
            subject_key=tuple(timeline_values.items()),
        )
        self.assertTrue(_cohort_r3_leaf_matches_execution(timeline_resolution, obligation))
        self.assertIs(timeline_resolution.status, AuthorityStatus.FAIL)
        for field in ("dataset_id", "protocol_binding_record_hash", "scientific_confirmatory_timeline_record_hash"):
            changed = dict(timeline_values)
            changed[field] = _digest(f"wrong-{field}") if field.endswith("hash") else "wrong-dataset"
            with self.subTest(field=field):
                self.assertFalse(_cohort_r3_leaf_matches_execution(
                    replace(timeline_resolution, subject_key=tuple(changed.items())), obligation,
                ))

    def test_r1_leaf_match_is_exact_coverage_only_and_preserves_adverse_status(self) -> None:
        resolution, obligation, question = self._matching_obligation()
        self.assertTrue(_cohort_r1_leaf_matches_design(resolution, obligation, question))
        self.assertIs(resolution.status, AuthorityStatus.UNTESTED)
        self.assertIs(resolution.scope, AuthorityScope.SYSTEM_FIXTURE)

        adverse = replace(resolution, status=AuthorityStatus.FAIL, scope=AuthorityScope.SCIENTIFIC)
        self.assertTrue(_cohort_r1_leaf_matches_design(adverse, obligation, question))
        self.assertIs(adverse.status, AuthorityStatus.FAIL)
        self.assertFalse(_cohort_r1_leaf_matches_design(
            resolution, obligation,
            replace(question, question=SimpleNamespace(object_id="other-question")),
        ))

    def test_r1_leaf_match_rejects_root_join_admission_and_rerun_freeze_substitutions(self) -> None:
        resolution, obligation, question = self._matching_obligation()
        values = dict(resolution.subject_key)
        for field in (
            "research_brief_id", "contract_id", "contract_artifact_sha256",
            "contract_record_hash", "contract_sha256", "frozen_run_spec_artifact_sha256",
            "frozen_run_spec_record_hash", "frozen_run_spec_sha256",
            "design_freeze_event_id", "design_freeze_event_hash", "design_freeze_event_index",
            "selected_direction_id", "criteria_projection_sha256",
            "research_question_assessment_outcome", "goal_sha256", "research_brief_sha256",
        ):
            changed = dict(values)
            changed[field] = "999" if field.endswith("_index") else (
                _digest(f"wrong-{field}") if field.endswith("_sha256") or field.endswith("_hash") else "wrong-value"
            )
            with self.subTest(field=field):
                altered = replace(resolution, subject_key=tuple(changed.items()))
                self.assertFalse(_cohort_r1_leaf_matches_design(altered, obligation, question))

        missing_assessment = replace(resolution, source_admissions=(resolution.source_admissions[1],))
        self.assertFalse(_cohort_r1_leaf_matches_design(missing_assessment, obligation, question))
        late_assessment = replace(
            resolution,
            source_admissions=(replace(resolution.source_admissions[0], ledger_event_index=7), resolution.source_admissions[1]),
            subject_key=tuple({**values, "research_question_assessment_event_index": "7"}.items()),
        )
        self.assertFalse(_cohort_r1_leaf_matches_design(late_assessment, obligation, question))
        late_question = replace(question, gate=SimpleNamespace(**{
            **vars(question.gate), "gate_event_index": 7,
        }))
        self.assertFalse(_cohort_r1_leaf_matches_design(
            resolution, replace(obligation, questions=(late_question,)), late_question,
        ))

        rerun_source = replace(
            obligation.source,
            freeze=SimpleNamespace(
                design_freeze_event_id="rerun-freeze-event",
                design_freeze_event_hash=_digest("rerun-freeze-event"),
                design_freeze_event_index=8,
            ),
        )
        rerun_obligation = replace(obligation, source=rerun_source)
        self.assertFalse(_cohort_r1_leaf_matches_design(resolution, rerun_obligation, question))


if __name__ == "__main__":
    unittest.main()
