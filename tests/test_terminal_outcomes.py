from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.claims import ClaimEvidenceGraph, ClaimEvidenceUse, MaterialClaim
from scientist_one.compute_terminal import COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE
from scientist_one.discovery import BranchStatus
from scientist_one.errors import ValidationError
from scientist_one.experiments import (
    ComputeMode,
    ReproductionStatus as ExperimentReproductionStatus,
    ValidationStatus as ComputeValidationStatus,
    default_local_cpu_profile,
)
from scientist_one.gates import (
    ChallengeCategory,
    ChallengerCategoryReview,
    ChallengerExecutionStatus,
    DimensionStatus,
    SoundnessAuthorityKind,
    SoundnessDimension,
    SoundnessDimensionEvidenceReceipt,
    SoundnessVerdict,
    assess_soundness,
    register_challenger_category_review,
    register_soundness_dimension_receipt,
)
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState, TerminalState
from scientist_one.paper_pipeline import HardBlocker, PaperVerification
from scientist_one.research_state import (
    Decision,
    HypothesisStatus as CanonicalHypothesisStatus,
    ReproductionStatus as CanonicalReproductionStatus,
    ResearchStateRepository,
)
from scientist_one.reproduction import (
    SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
    ScientificCleanRerunOutcome,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    HypothesisStatus as DesignHypothesisStatus,
    LiteratureRecord,
    ProblemInvestigator,
    RESEARCH_QUESTION_GATE_ASSESSMENT_LOGICAL_TYPE,
    ResearchDirection,
    ResearchGateOutcome,
    ResearchQuestionCriteria,
    SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
    ScientificResultOutcome,
    register_research_question_gate_assessment,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads
from scientist_one.terminal_outcomes import (
    LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
    LEGACY_TERMINAL_OUTCOME_SCHEMA_VERSION,
    PAPER_PUBLICATION_TERMINAL_MAPPING_ID,
    ResearchTerminalOutcome,
    ResearchTerminalRecord,
    TERMINAL_DECISION_TYPE,
    TERMINAL_OUTCOME_LOGICAL_TYPE,
    TERMINAL_OUTCOME_MAPPING_ID,
    TERMINAL_OUTCOME_SCHEMA_VERSION,
    TERMINAL_PAPER_VERIFICATION_SOURCE_LOGICAL_TYPE,
    TERMINAL_SOUNDNESS_SOURCE_LOGICAL_TYPE,
    TERMINAL_SOUNDNESS_SOURCE_SCHEMA_VERSION,
    TerminalAuthorityScope,
    TerminalOutcomeDerivation,
    TerminalPhase,
    TerminalSourceBinding,
    TerminalSourceKind,
    derive_from_canonical_reproduction,
    derive_from_compute_profile,
    derive_from_compute_status,
    derive_from_discovery_branch,
    derive_from_experiment_reproduction,
    derive_from_hypothesis_status,
    derive_from_legacy_terminal,
    derive_from_paper_verification,
    derive_from_registered_paper_verification,
    derive_from_registered_research_gate_assessment,
    derive_from_registered_scientific_clean_rerun,
    derive_from_registered_scientific_result,
    derive_from_registered_soundness,
    derive_from_research_gate,
    derive_from_scientific_result_outcome,
    derive_from_soundness,
    load_terminal_outcome,
    materialize_terminal_outcome,
    register_soundness_terminal_source,
)
from scientist_one import terminal_outcomes as terminal_outcomes_module
from scientist_one import gates as gates_module


STAMP = "2026-08-29T18:00:00Z"
CONFIG_HASH = "c" * 64


def _soundness(
):
    with tempfile.TemporaryDirectory() as directory:
        registry = ArtifactRegistry(Path(directory), "runs/terminal-soundness/registry")
        evidence = registry.put_json(
            {"fixture": "typed terminal soundness evidence"},
            logical_type="terminal_soundness_test_evidence",
            origin="typed terminal soundness fixture",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "test-terminal-soundness"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        graph = ClaimEvidenceGraph()
        graph.add_claim(
            MaterialClaim(
                claim_id="claim-terminal",
                text="The terminal fixture has one scoped material claim.",
                evidence_links=(),
                producer_role=Role.HYPOTHESIS_DESIGNER,
                confirmatory=False,
                evidence_use=ClaimEvidenceUse.NON_EVIDENTIARY,
            )
        )
        graph.verify_claim(
            "claim-terminal",
            verifier_id="terminal-claim-verifier",
        )
        graph_artifact = registry.put_json(
            {"fixture": "terminal soundness claim graph", "graph": graph.to_dict()},
            logical_type="claim_evidence_graph",
            origin="focused terminal soundness claim graph",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "test-terminal-soundness-graph"),
            parent_artifacts=(),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        dimension_receipts = tuple(
            register_soundness_dimension_receipt(
                registry,
                SoundnessDimensionEvidenceReceipt(
                    receipt_id=f"terminal-{dimension.value.lower().replace('_', '-')}",
                    dimension=dimension,
                    status=DimensionStatus.UNTESTED,
                    authority_kind=SoundnessAuthorityKind.NOT_EXECUTED,
                    authority_artifact_hash=None,
                    evidence_hashes=(evidence.sha256,),
                    governing_rule="Map the registered typed fixture status.",
                    rationale="Exercise terminal derivation from verified gate authority.",
                    reviewer_id="terminal-scientific-reviewer",
                ),
            ).sha256
            for dimension in SoundnessDimension
        )
        challenger_reviews = tuple(
            register_challenger_category_review(
                registry,
                ChallengerCategoryReview(
                    review_id=f"terminal-{category.value.lower().replace('_', '-')}",
                    category=category,
                    execution_status=ChallengerExecutionStatus.UNTESTED,
                    target_claim_ids=("claim-terminal",),
                    claim_graph_artifact_hash=graph_artifact.sha256,
                    evidence_hashes=(evidence.sha256,),
                    finding_artifact_hashes=(),
                    execution_receipt_hash=None,
                    attack=f"Execute terminal fixture check for {category.value}.",
                    conclusion="No separate finding was produced by this typed fixture check.",
                    deterministic=False,
                ),
            ).sha256
            for category in ChallengeCategory
        )
        return assess_soundness(
            registry,
            "soundness-terminal-fixture",
            dimension_receipts,
            challenger_reviews,
            claim_graph_artifact_hash=graph_artifact.sha256,
            central_claim_ids=("claim-terminal",),
            reason="Typed terminal mapping fixture.",
        )


class TerminalOutcomeVocabularyTests(unittest.TestCase):
    def test_publication_mapping_retains_every_blocker_without_scientific_conclusion(self) -> None:
        for blockers in (
            (HardBlocker.UNSUPPORTED_CENTRAL_CLAIM,),
            (HardBlocker.UNSUPPORTED_NOVELTY,),
            (HardBlocker.FAILED_CLEAN_REPRODUCTION,),
            tuple(HardBlocker),
            (),
        ):
            with self.subTest(blockers=blockers):
                verification = PaperVerification(
                    passed=False,
                    blockers=blockers,
                    discrepancies=("mechanical-publication-control",),
                    verified_claim_ids=(),
                )
                diagnostic = derive_from_paper_verification(verification)
                assert diagnostic is not None
                publication = terminal_outcomes_module._derivation(
                    TerminalSourceKind.PAPER_VERIFICATION,
                    diagnostic.source_statuses,
                    mapping_id=PAPER_PUBLICATION_TERMINAL_MAPPING_ID,
                )
                self.assertIs(publication.outcome, ResearchTerminalOutcome.NOT_PUBLISHABLE)
                self.assertIs(publication.phase, TerminalPhase.PAPER_READINESS)
                self.assertEqual(publication.source_statuses, diagnostic.source_statuses)
                self.assertEqual(diagnostic.mapping_id, TERMINAL_OUTCOME_MAPPING_ID)
                self.assertEqual(
                    TerminalOutcomeDerivation.from_dict(publication.to_dict()), publication
                )

    def test_publication_mapping_is_closed_to_paper_and_canonical_failure_statuses(self) -> None:
        for source_kind, statuses in (
            (TerminalSourceKind.SOUNDNESS_GATE, ("VERDICT:MAJOR_REVISION", "ROBUSTNESS:PASS")),
            (TerminalSourceKind.RESEARCH_GATE, ("INSUFFICIENT_NOVELTY",)),
            (TerminalSourceKind.PAPER_VERIFICATION, ("PASSED",)),
            (TerminalSourceKind.PAPER_VERIFICATION, ("FAILED", "invented")),
            (TerminalSourceKind.PAPER_VERIFICATION, (
                "FAILED", HardBlocker.FAILED_CLEAN_REPRODUCTION.value,
                HardBlocker.UNSUPPORTED_NOVELTY.value,
            )),
            (TerminalSourceKind.PAPER_VERIFICATION, (
                "FAILED", HardBlocker.UNSUPPORTED_NOVELTY.value,
                HardBlocker.UNSUPPORTED_NOVELTY.value,
            )),
        ):
            with self.subTest(source_kind=source_kind, statuses=statuses):
                with self.assertRaises(ValidationError):
                    terminal_outcomes_module._derivation(
                        source_kind, statuses,
                        mapping_id=PAPER_PUBLICATION_TERMINAL_MAPPING_ID,
                    )

    def test_exact_mission_vocabulary_has_no_success_pseudoterminal(self) -> None:
        self.assertEqual(
            {item.value for item in ResearchTerminalOutcome},
            {
                "NOT_PUBLISHABLE",
                "INSUFFICIENT_NOVELTY",
                "INCONCLUSIVE",
                "HYPOTHESIS_FALSIFIED",
                "NEGATIVE_RESULT",
                "NO_MEANINGFUL_GAIN",
                "RESULT_NOT_ROBUST",
                "REPRODUCIBILITY_FAILED",
                "INSUFFICIENT_COMPUTE",
                "FULL_VALIDATION_REQUIRES_GPU_CLOUD",
                "MORE_EXPERIMENTS_REQUIRED",
            },
        )
        self.assertEqual(len(ResearchTerminalOutcome), 11)
        self.assertNotIn("SUCCESS", {item.value for item in ResearchTerminalOutcome})
        self.assertNotIn("PASS", {item.value for item in ResearchTerminalOutcome})

    def test_diagnostic_mapping_codomain_covers_every_terminal_label(self) -> None:
        paper = PaperVerification(
            passed=False,
            blockers=(HardBlocker.UNSUPPORTED_CENTRAL_CLAIM,),
            discrepancies=(),
            verified_claim_ids=(),
        )
        robustness_derivation = TerminalOutcomeDerivation(
            source_kind=TerminalSourceKind.SOUNDNESS_GATE,
            source_statuses=(
                f"VERDICT:{SoundnessVerdict.MAJOR_REVISION.value}",
                f"ROBUSTNESS:{DimensionStatus.FAIL.value}",
            ),
            phase=TerminalPhase.ROBUSTNESS,
            outcome=ResearchTerminalOutcome.RESULT_NOT_ROBUST,
        )
        derivations = (
            derive_from_paper_verification(paper),
            derive_from_research_gate(ResearchGateOutcome.INSUFFICIENT_NOVELTY),
            derive_from_hypothesis_status(DesignHypothesisStatus.INCONCLUSIVE),
            derive_from_hypothesis_status(DesignHypothesisStatus.FALSIFIED),
            derive_from_discovery_branch(BranchStatus.NEGATIVE_RESULT),
            derive_from_scientific_result_outcome(ScientificResultOutcome.NULL),
            robustness_derivation,
            derive_from_experiment_reproduction(
                ExperimentReproductionStatus.OUTSIDE_TOLERANCE
            ),
            derive_from_research_gate(
                ResearchGateOutcome.INFEASIBLE_WITH_CURRENT_RESOURCES
            ),
            derive_from_compute_status(
                ComputeMode.GPU_CLOUD,
                ComputeValidationStatus.UNTESTED,
            ),
            derive_from_soundness(_soundness()),
        )
        self.assertNotIn(None, derivations)
        self.assertTrue(
            all(
                item.source_binding is None and item.authority_scope is None
                for item in derivations
                if item is not None
            )
        )
        self.assertEqual(
            {item.outcome for item in derivations if item is not None},
            set(ResearchTerminalOutcome),
        )

    def test_pass_and_intermediate_statuses_are_explicitly_nonterminal(self) -> None:
        for value in (
            ResearchGateOutcome.PROCEED,
            ResearchGateOutcome.REFORMULATE,
            ResearchGateOutcome.MORE_LITERATURE_REQUIRED,
        ):
            self.assertIsNone(derive_from_research_gate(value))
        for value in (
            DesignHypothesisStatus.UNTESTED,
            DesignHypothesisStatus.SUPPORTED,
            DesignHypothesisStatus.PARTIALLY_SUPPORTED,
            CanonicalHypothesisStatus.POST_HOC,
        ):
            self.assertIsNone(derive_from_hypothesis_status(value))
        for value in (
            ScientificResultOutcome.POSITIVE,
            ScientificResultOutcome.TECHNICAL_FAILURE,
        ):
            self.assertIsNone(derive_from_scientific_result_outcome(value))
        bare_not_supported = derive_from_hypothesis_status(
            DesignHypothesisStatus.NOT_SUPPORTED
        )
        assert bare_not_supported is not None
        self.assertIs(
            bare_not_supported.outcome,
            ResearchTerminalOutcome.INCONCLUSIVE,
        )
        self.assertIsNone(
            derive_from_experiment_reproduction(ExperimentReproductionStatus.PASS)
        )
        self.assertIsNone(
            derive_from_canonical_reproduction(CanonicalReproductionStatus.PASS)
        )
        self.assertIsNone(
            derive_from_compute_status(
                ComputeMode.LOCAL_MAC,
                ComputeValidationStatus.VALIDATED_LOCAL,
            )
        )
        self.assertIsNone(derive_from_compute_profile(default_local_cpu_profile()))
        self.assertIsNone(derive_from_legacy_terminal(TerminalState.STOP_SECURITY))
        self.assertIsNone(
            derive_from_legacy_terminal(TerminalState.READY_FOR_HUMAN_REVIEW)
        )

    def test_outcome_neutral_result_semantics_do_not_infer_from_hypothesis_label(self) -> None:
        expected = {
            ScientificResultOutcome.NEGATIVE: (
                ResearchTerminalOutcome.NEGATIVE_RESULT
            ),
            ScientificResultOutcome.NULL: (
                ResearchTerminalOutcome.NO_MEANINGFUL_GAIN
            ),
            ScientificResultOutcome.INCONCLUSIVE: (
                ResearchTerminalOutcome.INCONCLUSIVE
            ),
            ScientificResultOutcome.FALSIFIED: (
                ResearchTerminalOutcome.HYPOTHESIS_FALSIFIED
            ),
        }
        self.assertEqual(
            {
                outcome: derive_from_scientific_result_outcome(outcome).outcome
                for outcome in expected
            },
            expected,
        )
        not_supported = derive_from_hypothesis_status(
            DesignHypothesisStatus.NOT_SUPPORTED
        )
        assert not_supported is not None
        self.assertIs(
            not_supported.outcome,
            ResearchTerminalOutcome.INCONCLUSIVE,
        )
        self.assertIsNot(
            not_supported.outcome,
            ResearchTerminalOutcome.NO_MEANINGFUL_GAIN,
        )

    def test_historical_v1_not_supported_mapping_remains_literal_and_read_only(self) -> None:
        historical = {
            "mapping_id": LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
            "source_kind": TerminalSourceKind.HYPOTHESIS_REGISTER.value,
            "source_statuses": [DesignHypothesisStatus.NOT_SUPPORTED.value],
            "phase": TerminalPhase.HYPOTHESIS_EVALUATION.value,
            "outcome": ResearchTerminalOutcome.NO_MEANINGFUL_GAIN.value,
            "source_binding": None,
        }
        parsed = TerminalOutcomeDerivation.from_dict(historical)
        self.assertEqual(parsed.to_dict(), historical)
        self.assertIs(
            parsed.outcome,
            ResearchTerminalOutcome.NO_MEANINGFUL_GAIN,
        )
        self.assertEqual(
            canonical_json_bytes(parsed.to_dict()) + b"\n",
            (
                b'{"mapping_id":"research-os-terminal-outcome-map/v1",'
                b'"outcome":"NO_MEANINGFUL_GAIN","phase":"HYPOTHESIS_EVALUATION",'
                b'"source_binding":null,"source_kind":"HYPOTHESIS_REGISTER",'
                b'"source_statuses":["NOT_SUPPORTED"]}\n'
            ),
        )
        current = derive_from_hypothesis_status(
            DesignHypothesisStatus.NOT_SUPPORTED
        )
        assert current is not None
        self.assertEqual(current.mapping_id, TERMINAL_OUTCOME_MAPPING_ID)
        self.assertIs(current.outcome, ResearchTerminalOutcome.INCONCLUSIVE)
        with self.assertRaises(ValidationError):
            TerminalOutcomeDerivation(
                source_kind=TerminalSourceKind.SCIENTIFIC_RESULT,
                source_statuses=(ScientificResultOutcome.NULL.value,),
                phase=TerminalPhase.HYPOTHESIS_EVALUATION,
                outcome=ResearchTerminalOutcome.NO_MEANINGFUL_GAIN,
                mapping_id=LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
            )

    def test_specific_failure_precedence_is_deterministic(self) -> None:
        failed_reproduction = PaperVerification(
            passed=False,
            blockers=(
                HardBlocker.UNSUPPORTED_NOVELTY,
                HardBlocker.FAILED_CLEAN_REPRODUCTION,
            ),
            discrepancies=(),
            verified_claim_ids=(),
        )
        self.assertEqual(
            derive_from_paper_verification(failed_reproduction).outcome,
            ResearchTerminalOutcome.REPRODUCIBILITY_FAILED,
        )
        robustness = TerminalOutcomeDerivation(
            source_kind=TerminalSourceKind.SOUNDNESS_GATE,
            source_statuses=(
                f"VERDICT:{SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED.value}",
                f"ROBUSTNESS:{DimensionStatus.FAIL.value}",
            ),
            phase=TerminalPhase.ROBUSTNESS,
            outcome=ResearchTerminalOutcome.RESULT_NOT_ROBUST,
        )
        self.assertEqual(robustness.outcome, ResearchTerminalOutcome.RESULT_NOT_ROBUST)
        self.assertEqual(
            derive_from_legacy_terminal(TerminalState.STOP_BUDGET).outcome,
            ResearchTerminalOutcome.INSUFFICIENT_COMPUTE,
        )

    def test_untyped_or_impossible_source_statuses_fail_closed(self) -> None:
        invalid_calls = (
            lambda: derive_from_research_gate("INSUFFICIENT_NOVELTY"),
            lambda: derive_from_hypothesis_status("FALSIFIED"),
            lambda: derive_from_scientific_result_outcome("NULL"),
            lambda: derive_from_discovery_branch("NEGATIVE_RESULT"),
            lambda: derive_from_experiment_reproduction("OUTSIDE_TOLERANCE"),
            lambda: derive_from_canonical_reproduction("FAIL"),
            lambda: derive_from_compute_status("GPU_CLOUD", "UNTESTED"),
            lambda: derive_from_compute_status(
                ComputeMode.LOCAL_MAC,
                ComputeValidationStatus.UNTESTED,
            ),
            lambda: derive_from_compute_status(
                ComputeMode.GPU_CLOUD,
                ComputeValidationStatus.VALIDATED_LOCAL,
            ),
            lambda: derive_from_soundness("MORE_EXPERIMENTS_REQUIRED"),
            lambda: derive_from_paper_verification("BLOCKED"),
            lambda: derive_from_legacy_terminal("NEGATIVE_RESULT"),
        )
        for call in invalid_calls:
            with self.subTest(call=call):
                with self.assertRaises(ValidationError):
                    call()


class TerminalOutcomeRecordTests(unittest.TestCase):
    def derivation(self) -> TerminalOutcomeDerivation:
        result = derive_from_hypothesis_status(DesignHypothesisStatus.FALSIFIED)
        assert result is not None
        return result

    def record(self, **changes: object) -> ResearchTerminalRecord:
        values: dict[str, object] = {
            "record_id": "terminal-hypothesis-1",
            "run_id": "run-terminal-1",
            "phase": TerminalPhase.HYPOTHESIS_EVALUATION,
            "outcome": ResearchTerminalOutcome.HYPOTHESIS_FALSIFIED,
            "reason": "The preregistered falsification condition was met.",
            "evidence_artifact_hashes": ("b" * 64, "a" * 64),
            "derivation": self.derivation(),
            "producer": Role.SCIENTIFIC_REVIEWER,
            "uncertainty": 0.1,
            "created_at": STAMP,
        }
        values.update(changes)
        return ResearchTerminalRecord(**values)

    def test_record_is_immutable_canonical_and_strictly_round_trips(self) -> None:
        record = self.record()
        self.assertEqual(record.evidence_artifact_hashes, ("a" * 64, "b" * 64))
        self.assertEqual(ResearchTerminalRecord.from_dict(record.to_dict()), record)
        self.assertEqual(len(record.sha256), 64)
        self.assertTrue(record.canonical_bytes().endswith(b"\n"))
        with self.assertRaises(FrozenInstanceError):
            record.reason = "rewritten"  # type: ignore[misc]

        changed = replace(record, reason="A distinct truthful reason.")
        self.assertNotEqual(record.sha256, changed.sha256)
        unknown = record.to_dict()
        unknown["legacy_state"] = "NEGATIVE_RESULT"
        with self.assertRaises(ValidationError):
            ResearchTerminalRecord.from_dict(unknown)

    def test_record_rejects_missing_duplicate_or_forged_evidence_and_derivation(self) -> None:
        with self.assertRaises(ValidationError):
            self.record(evidence_artifact_hashes=())
        with self.assertRaises(ValidationError):
            self.record(evidence_artifact_hashes=("a" * 64, "a" * 64))
        with self.assertRaises(ValidationError):
            self.record(evidence_artifact_hashes=("not-a-hash",))
        with self.assertRaises(ValidationError):
            self.record(outcome=ResearchTerminalOutcome.NEGATIVE_RESULT)
        with self.assertRaises(ValidationError):
            self.record(phase=TerminalPhase.DISCOVERY)
        with self.assertRaises(ValidationError):
            self.record(reason="\x00")
        with self.assertRaises(ValidationError):
            self.record(created_at="2026-08-29")
        with self.assertRaises(ValidationError):
            self.record(producer=Role.HUMAN_RELEASE)
        with self.assertRaises(ValidationError):
            self.record(producer=Role.EXPERIMENT_RUNNER)
        with self.assertRaises(ValidationError):
            TerminalOutcomeDerivation(
                source_kind=TerminalSourceKind.HYPOTHESIS_REGISTER,
                source_statuses=(DesignHypothesisStatus.FALSIFIED.value,),
                phase=TerminalPhase.HYPOTHESIS_EVALUATION,
                outcome=ResearchTerminalOutcome.NEGATIVE_RESULT,
            )
        with self.assertRaises(ValidationError):
            replace(self.derivation(), mapping_id="unreviewed-map/v2")
        with self.assertRaises(ValidationError):
            TerminalOutcomeDerivation(
                source_kind=TerminalSourceKind.PAPER_VERIFICATION,
                source_statuses=(
                    "FAILED",
                    HardBlocker.FAILED_CLEAN_REPRODUCTION.value,
                    HardBlocker.UNSUPPORTED_NOVELTY.value,
                ),
                phase=TerminalPhase.REPRODUCTION,
                outcome=ResearchTerminalOutcome.REPRODUCIBILITY_FAILED,
            )


class TerminalOutcomeIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.registry = ArtifactRegistry(self.root, "runs/run-terminal/registry")
        self.ledger = EventLedger(self.root, "runs/run-terminal/events.jsonl")
        self.repository = ResearchStateRepository(
            self.registry,
            self.ledger,
            run_id="run-terminal",
            code_version="code-terminal-v1",
            configuration_hash=CONFIG_HASH,
            state=MacroState.CONFIRM,
            creation_command=("scientist-one", "terminal-outcome-fixture"),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _paper_publication_value_fixture(self, blockers: tuple[HardBlocker, ...]):
        # This is only a typed normalization/serialization input.  It has no
        # issued paper authority and cannot pass public materialization.
        source = self.evidence("non-authoritative paper mapping DTO control")
        statuses = ("FAILED",) + tuple(
            blocker.value for blocker in HardBlocker if blocker in blockers
        )
        binding = TerminalSourceBinding(
            source_kind=TerminalSourceKind.PAPER_VERIFICATION,
            source_artifact_sha256=source.sha256,
            source_record_hash=source.record_hash,
            source_logical_type=source.logical_type,
            source_creator_role=source.creator_role,
            source_run_id=self.repository.run_id,
            source_object_id="paper-candidate-dto-control",
            source_claim_ids=(),
            source_statuses=statuses,
            source_parent_artifact_hashes=source.parent_artifacts,
        )
        return terminal_outcomes_module._derivation(
            TerminalSourceKind.PAPER_VERIFICATION, statuses,
            source_binding=binding,
            authority_scope=TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL,
            mapping_id=PAPER_PUBLICATION_TERMINAL_MAPPING_ID,
        )

    def test_publication_record_round_trip_keeps_record_identity_and_mechanical_scope(self) -> None:
        current = self._paper_publication_value_fixture(tuple(HardBlocker))
        record = self.record(current, record_id="paper-publication-dto-control")
        payload = record.to_dict()
        self.assertEqual(ResearchTerminalRecord.from_dict(payload), record)
        self.assertEqual(
            payload["derivation"]["source_binding"]["source_record_hash"],
            current.source_binding.source_record_hash,
        )
        self.assertEqual(
            payload["derivation"]["authority_scope"], "NON_EVIDENTIARY_MECHANICAL"
        )
        del payload["derivation"]["source_binding"]["source_record_hash"]
        with self.assertRaises(ValidationError):
            ResearchTerminalRecord.from_dict(payload)
        with self.assertRaisesRegex(ValidationError, "mechanical only"):
            replace(current, authority_scope=TerminalAuthorityScope.SCIENTIFIC_EVIDENCE)
        with self.assertRaisesRegex(ValidationError, "mechanical only"):
            replace(current, authority_scope=TerminalAuthorityScope.OPERATIONAL_BLOCKER)
        with self.assertRaisesRegex(ValidationError, "no closed source-owner resolver"):
            materialize_terminal_outcome(record, self.repository)

    def test_publication_normalization_preserves_exact_generic_v2_only(self) -> None:
        current = self._paper_publication_value_fixture((HardBlocker.UNRESOLVED_AUTHORITY,))
        historical = replace(current, mapping_id=TERMINAL_OUTCOME_MAPPING_ID)
        resolved = terminal_outcomes_module._normalize_replayed_paper_terminal(
            current, historical
        )
        self.assertEqual(resolved.derivation, historical)
        self.assertIs(resolved.authority_scope, TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL)
        dropped_statuses = ("FAILED",)
        dropped = replace(
            historical,
            source_statuses=dropped_statuses,
            source_binding=replace(historical.source_binding, source_statuses=dropped_statuses),
        )
        replayed = terminal_outcomes_module._normalize_replayed_paper_terminal(current, dropped)
        self.assertNotEqual(replayed.derivation, dropped)
        legacy = replace(
            historical, mapping_id=LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
            source_binding=replace(historical.source_binding, source_record_hash=None),
            authority_scope=None,
        )
        with self.assertRaisesRegex(ValidationError, "no historical authority owner"):
            terminal_outcomes_module._normalize_replayed_paper_terminal(current, legacy)

    def test_publication_normalization_cannot_launder_old_specific_diagnostics(self) -> None:
        for blocker in (HardBlocker.UNSUPPORTED_NOVELTY, HardBlocker.FAILED_CLEAN_REPRODUCTION):
            with self.subTest(blocker=blocker):
                current = self._paper_publication_value_fixture((blocker,))
                diagnostic = terminal_outcomes_module._derivation(
                    current.source_kind, current.source_statuses,
                    source_binding=current.source_binding,
                    authority_scope=TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL,
                )
                with self.assertRaisesRegex(ValidationError, "source-specific"):
                    terminal_outcomes_module._normalize_replayed_paper_terminal(current, diagnostic)
                # Even a generic recorded status cannot hide freshly replayed
                # reproduction/novelty blockers to gain old-map authority.
                generic = self._paper_publication_value_fixture((HardBlocker.UNRESOLVED_AUTHORITY,))
                with self.assertRaisesRegex(ValidationError, "source-specific"):
                    terminal_outcomes_module._normalize_replayed_paper_terminal(
                        current, replace(generic, mapping_id=TERMINAL_OUTCOME_MAPPING_ID)
                    )

    def evidence(self, label: str):
        return self.registry.put_json(
            {"fixture": label},
            logical_type="terminal_soundness_test_evidence",
            origin="focused terminal outcome authority fixture",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "terminal-outcome-fixture", label),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )

    def assessment(
        self,
        assessment_id: str = "soundness-terminal-authority",
        *,
        run_id: str | None = None,
    ):
        evidence = self.evidence("shared soundness evidence")
        graph = ClaimEvidenceGraph()
        graph.add_claim(
            MaterialClaim(
                claim_id="claim-terminal",
                text="The terminal fixture lacks complete scientific validation.",
                evidence_links=(),
                producer_role=Role.HYPOTHESIS_DESIGNER,
                confirmatory=False,
                evidence_use=ClaimEvidenceUse.NON_EVIDENTIARY,
            )
        )
        graph.verify_claim(
            "claim-terminal",
            verifier_id="terminal-claim-verifier",
        )
        graph_artifact = self.registry.put_json(
            {"fixture": "terminal claim graph", "graph": graph.to_dict()},
            logical_type="claim_evidence_graph",
            origin="focused terminal outcome claim graph",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "terminal-outcome-claim-graph"),
            parent_artifacts=(),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        dimensions = tuple(
            register_soundness_dimension_receipt(
                self.registry,
                SoundnessDimensionEvidenceReceipt(
                    receipt_id=f"terminal-{dimension.value.lower().replace('_', '-')}",
                    dimension=dimension,
                    status=DimensionStatus.UNTESTED,
                    authority_kind=SoundnessAuthorityKind.NOT_EXECUTED,
                    authority_artifact_hash=None,
                    evidence_hashes=(evidence.sha256,),
                    governing_rule="Do not infer an unexecuted soundness dimension.",
                    rationale="This focused fixture deliberately leaves the dimension untested.",
                    reviewer_id="terminal-scientific-reviewer",
                ),
            ).sha256
            for dimension in SoundnessDimension
        )
        reviews = tuple(
            register_challenger_category_review(
                self.registry,
                ChallengerCategoryReview(
                    review_id=f"terminal-{category.value.lower().replace('_', '-')}",
                    category=category,
                    execution_status=ChallengerExecutionStatus.UNTESTED,
                    target_claim_ids=("claim-terminal",),
                    claim_graph_artifact_hash=graph_artifact.sha256,
                    evidence_hashes=(evidence.sha256,),
                    finding_artifact_hashes=(),
                    execution_receipt_hash=None,
                    attack=f"No {category.value} attack was executed in this fixture.",
                    conclusion="UNTESTED; no attack authority is claimed.",
                    deterministic=False,
                ),
            ).sha256
            for category in ChallengeCategory
        )
        return assess_soundness(
            self.registry,
            assessment_id,
            dimensions,
            reviews,
            claim_graph_artifact_hash=graph_artifact.sha256,
            central_claim_ids=("claim-terminal",),
            reason=f"Registry-resolved incomplete soundness assessment {assessment_id}.",
            ledger=self.ledger if run_id is not None else None,
            run_id=run_id,
        )

    def authority(
        self,
        assessment_id: str = "soundness-terminal-authority",
        *,
        run_id: str | None = None,
    ):
        assessment = self.assessment(assessment_id, run_id=run_id)
        source = register_soundness_terminal_source(self.repository, assessment)
        derivation = derive_from_registered_soundness(
            self.repository,
            source.sha256,
            expected_assessment_id=assessment.assessment_id,
            expected_claim_ids=assessment.central_claim_ids,
        )
        self.assertIsNotNone(derivation)
        return assessment, source, derivation

    def record(
        self,
        derivation: TerminalOutcomeDerivation,
        *,
        record_id: str = "terminal-decision-1",
        reason: str = "Incomplete soundness authority requires more experiments.",
        evidence_artifact_hashes: tuple[str, ...] | None = None,
        source_object_id: str | None = None,
        source_claim_ids: tuple[str, ...] | None = None,
        producer: Role | None = None,
    ) -> ResearchTerminalRecord:
        binding = derivation.source_binding
        assert binding is not None
        return ResearchTerminalRecord(
            record_id=record_id,
            run_id="run-terminal",
            phase=derivation.phase,
            outcome=derivation.outcome,
            reason=reason,
            evidence_artifact_hashes=(
                binding.required_evidence_artifact_hashes
                if evidence_artifact_hashes is None
                else evidence_artifact_hashes
            ),
            derivation=derivation,
            producer=producer or Role.SCIENTIFIC_REVIEWER,
            source_object_id=(
                binding.source_object_id
                if source_object_id is None
                else source_object_id
            ),
            source_claim_ids=(
                binding.source_claim_ids
                if source_claim_ids is None
                else source_claim_ids
            ),
            uncertainty=1.0,
            created_at=STAMP,
        )

    def clone_source_payload(
        self,
        source_sha256: str,
        assessment_id: str,
    ) -> dict[str, object]:
        payload = safe_json_loads(self.registry.get_bytes(source_sha256))
        self.assertIsInstance(payload, dict)
        assessment = dict(payload["assessment"])
        assessment["assessment_id"] = assessment_id
        assessment["reason"] = f"Registry-recomputed cloned assessment {assessment_id}."
        payload = dict(payload)
        payload["assessment"] = assessment
        return payload

    def put_source_payload(
        self,
        payload: dict[str, object],
        *,
        logical_type: str = TERMINAL_SOUNDNESS_SOURCE_LOGICAL_TYPE,
        creator_role: Role = Role.SCIENTIFIC_REVIEWER,
        parents: tuple[str, ...] | None = None,
    ):
        assessment = payload["assessment"]
        assert isinstance(assessment, dict)
        assessment_id = assessment["assessment_id"]
        assert isinstance(assessment_id, str)
        return self.registry.put_json(
            payload,
            logical_type=logical_type,
            origin="registry-rederived complete scientific soundness assessment",
            creator_role=creator_role,
            creation_command=(
                "scientist-one",
                "record-scientific-soundness-assessment",
            ),
            parent_artifacts=(
                tuple(assessment["evidence_hashes"])
                if parents is None
                else parents
            ),
            schema_version=TERMINAL_SOUNDNESS_SOURCE_SCHEMA_VERSION,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )

    def test_closed_owner_dispatch_contains_only_source_owned_replay_apis(
        self,
    ) -> None:
        soundness_key = (
            TerminalSourceKind.SOUNDNESS_GATE,
            TERMINAL_SOUNDNESS_SOURCE_LOGICAL_TYPE,
        )
        result_key = (
            TerminalSourceKind.SCIENTIFIC_RESULT,
            SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
        )
        paper_key = (
            TerminalSourceKind.PAPER_VERIFICATION,
            TERMINAL_PAPER_VERIFICATION_SOURCE_LOGICAL_TYPE,
        )
        clean_rerun_key = (
            TerminalSourceKind.CANONICAL_REPRODUCTION,
            SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
        )
        research_gate_key = (
            TerminalSourceKind.RESEARCH_GATE,
            RESEARCH_QUESTION_GATE_ASSESSMENT_LOGICAL_TYPE,
        )
        compute_key = (
            TerminalSourceKind.COMPUTE_STATUS,
            COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE,
        )
        resolvers = terminal_outcomes_module._TERMINAL_OWNER_RESOLVERS
        self.assertEqual(
            set(resolvers),
            {
                research_gate_key,
                soundness_key,
                result_key,
                paper_key,
                clean_rerun_key,
                compute_key,
            },
        )
        soundness_outcomes = {
            terminal_outcomes_module._expected_derivation(
                TerminalSourceKind.SOUNDNESS_GATE,
                statuses,
                mapping_id=TERMINAL_OUTCOME_MAPPING_ID,
            ).outcome
            for statuses in (
                (
                    f"VERDICT:{SoundnessVerdict.REJECT_RESEARCH_DIRECTION.value}",
                    f"ROBUSTNESS:{DimensionStatus.PASS.value}",
                ),
                (
                    f"VERDICT:{SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED.value}",
                    f"ROBUSTNESS:{DimensionStatus.UNTESTED.value}",
                ),
                (
                    f"VERDICT:{SoundnessVerdict.MAJOR_REVISION.value}",
                    f"ROBUSTNESS:{DimensionStatus.FAIL.value}",
                ),
            )
        }
        self.assertEqual(
            soundness_outcomes,
            {
                ResearchTerminalOutcome.NOT_PUBLISHABLE,
                ResearchTerminalOutcome.MORE_EXPERIMENTS_REQUIRED,
                ResearchTerminalOutcome.RESULT_NOT_ROBUST,
            },
        )
        with self.assertRaises(TypeError):
            resolvers[soundness_key] = lambda *_args: None  # type: ignore[index,assignment]

    def test_self_labelled_result_v3_artifact_cannot_authorize_terminal_scope(
        self,
    ) -> None:
        source = self.registry.put_json(
            {
                "schema_version": "scientific-result-promotion-authority/v3",
                "outcome": ScientificResultOutcome.NEGATIVE.value,
                "scientific_evidence_eligible": True,
            },
            logical_type=SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
            origin="source-owned outcome-neutral scientific result promotion",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=(
                "scientist-one",
                "promote-scientific-result-v3",
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "absent, corrupt, or unauthorized",
        ):
            derive_from_registered_scientific_result(
                self.repository,
                source.sha256,
                expected_result_id="result-self-labelled",
            )

        diagnostic = derive_from_scientific_result_outcome(
            ScientificResultOutcome.NEGATIVE
        )
        assert diagnostic is not None
        binding = TerminalSourceBinding(
            source_kind=TerminalSourceKind.SCIENTIFIC_RESULT,
            source_artifact_sha256=source.sha256,
            source_record_hash=source.record_hash,
            source_logical_type=source.logical_type,
            source_creator_role=source.creator_role,
            source_run_id=self.repository.run_id,
            source_object_id="result-self-labelled",
            source_claim_ids=(),
            source_statuses=diagnostic.source_statuses,
            source_parent_artifact_hashes=source.parent_artifacts,
        )
        forged = replace(
            diagnostic,
            source_binding=binding,
            authority_scope=TerminalAuthorityScope.SCIENTIFIC_EVIDENCE,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "absent, corrupt, or unauthorized",
        ):
            materialize_terminal_outcome(
                self.record(
                    forged,
                    record_id="terminal-self-labelled-result-v3",
                ),
                self.repository,
            )

    def test_self_labelled_paper_receipt_cannot_authorize_not_publishable(
        self,
    ) -> None:
        source = self.registry.put_json(
            {
                "schema_version": "paper-verification/v1",
                "run_id": self.repository.run_id,
                "candidate_artifact_hash": "a" * 64,
                "bundle_artifact_hash": "b" * 64,
                "verification": {
                    "passed": False,
                    "blockers": [HardBlocker.UNSUPPORTED_CENTRAL_CLAIM.value],
                    "discrepancies": ["self_labelled"],
                    "verified_claim_ids": [],
                },
            },
            logical_type=TERMINAL_PAPER_VERIFICATION_SOURCE_LOGICAL_TYPE,
            origin="fresh registry-and-ledger replay of exact paper authority",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            creation_command=("scientist-one", "verify-paper-authority"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "absent, corrupt, or unauthorized",
        ):
            derive_from_registered_paper_verification(
                self.repository,
                source.sha256,
                expected_candidate_id="candidate-self-labelled",
            )

        diagnostic = derive_from_paper_verification(
            PaperVerification(
                passed=False,
                blockers=(HardBlocker.UNSUPPORTED_CENTRAL_CLAIM,),
                discrepancies=(),
                verified_claim_ids=(),
            )
        )
        assert diagnostic is not None
        binding = TerminalSourceBinding(
            source_kind=TerminalSourceKind.PAPER_VERIFICATION,
            source_artifact_sha256=source.sha256,
            source_record_hash=source.record_hash,
            source_logical_type=source.logical_type,
            source_creator_role=source.creator_role,
            source_run_id=self.repository.run_id,
            source_object_id="candidate-self-labelled",
            source_claim_ids=(),
            source_statuses=diagnostic.source_statuses,
            source_parent_artifact_hashes=source.parent_artifacts,
        )
        forged = replace(
            diagnostic,
            source_binding=binding,
            authority_scope=TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "absent, corrupt, or unauthorized",
        ):
            materialize_terminal_outcome(
                self.record(
                    forged,
                    record_id="terminal-self-labelled-paper",
                ),
                self.repository,
            )

    def test_self_labelled_clean_rerun_cannot_authorize_reproduction_failure(
        self,
    ) -> None:
        source = self.registry.put_json(
            {
                "schema_version": "scientific_clean_rerun_authority/v1",
                "authority_id": "self-labelled-clean-rerun",
                "ledger_run_id": self.repository.run_id,
                "outcome": ScientificCleanRerunOutcome.FAIL.value,
                "scientific_evidence": True,
            },
            logical_type=SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
            origin=(
                "source-owned independently attested scientific clean-rerun "
                "comparison"
            ),
            creator_role=Role.REPRODUCTION_VERIFIER,
            creation_command=("scientist-one", "verify-scientific-clean-rerun"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "absent, corrupt, or unauthorized",
        ):
            derive_from_registered_scientific_clean_rerun(
                self.repository,
                source.sha256,
                expected_authority_id="self-labelled-clean-rerun",
            )

        diagnostic = derive_from_canonical_reproduction(
            CanonicalReproductionStatus.FAIL
        )
        assert diagnostic is not None
        binding = TerminalSourceBinding(
            source_kind=TerminalSourceKind.CANONICAL_REPRODUCTION,
            source_artifact_sha256=source.sha256,
            source_record_hash=source.record_hash,
            source_logical_type=source.logical_type,
            source_creator_role=source.creator_role,
            source_run_id=self.repository.run_id,
            source_object_id="self-labelled-clean-rerun",
            source_claim_ids=(),
            source_statuses=diagnostic.source_statuses,
            source_parent_artifact_hashes=source.parent_artifacts,
        )
        forged = replace(
            diagnostic,
            source_binding=binding,
            authority_scope=TerminalAuthorityScope.SCIENTIFIC_EVIDENCE,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "absent, corrupt, or unauthorized",
        ):
            materialize_terminal_outcome(
                self.record(
                    forged,
                    record_id="terminal-self-labelled-clean-rerun",
                ),
                self.repository,
            )

    def test_owner_backed_terminate_gate_does_not_infer_paper_ineligibility(
        self,
    ) -> None:
        from scientist_one.research_os import _build_design, _run_literature

        literature = _run_literature(
            self.registry,
            timestamp="2026-08-29T12:00:00Z",
        )
        design = _build_design(
            literature,
            self.registry,
            timestamp="2026-08-29T12:00:00Z",
        )
        negative_brief = replace(
            design.brief,
            assessment=replace(design.brief.assessment, importance=False),
        )
        brief_record = self.registry.put_json(
            {
                "fixture_notice": "Synthetic integration fixture only.",
                "research_brief": safe_json_loads(
                    canonical_json_bytes(negative_brief)
                ),
            },
            logical_type="research_brief",
            origin="focused terminal negative-gate fixture brief",
            creator_role=Role.PROBLEM_INVESTIGATOR,
            creation_command=("scientist-one", "terminal-negative-gate-test"),
            parent_artifacts=(
                literature.investigation_state_artifact.sha256,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        source = register_research_question_gate_assessment(
            self.registry,
            self.ledger,
            assessment_id="terminal-negative-gate-assessment",
            run_id=self.repository.run_id,
            goal_artifact_sha256=literature.goal_artifact.sha256,
            investigation_state_artifact_sha256=(
                literature.investigation_state_artifact.sha256
            ),
            research_brief_artifact_sha256=brief_record.sha256,
        )
        repository = ResearchStateRepository(
            self.registry,
            self.ledger,
            run_id=self.repository.run_id,
            code_version=self.repository.code_version,
            configuration_hash=self.ledger.events()[-1].configuration_hash,
            state=self.ledger.events()[-1].state_after,
            creation_command=("scientist-one", "terminal-negative-gate-test"),
        )
        self.assertIsNone(
            derive_from_registered_research_gate_assessment(
                repository,
                source.sha256,
                expected_object_id=negative_brief.brief_id,
            )
        )

    def test_owner_backed_destroyed_gap_materializes_insufficient_novelty(
        self,
    ) -> None:
        from scientist_one import research_os as research_os_module

        def gap_destroying_record(*args: object, **kwargs: object) -> LiteratureRecord:
            if kwargs.get("source_id") == "paper-4":
                kwargs["destroys_gap"] = True
            return LiteratureRecord(*args, **kwargs)  # type: ignore[arg-type]

        with patch.object(
            research_os_module,
            "LiteratureRecord",
            gap_destroying_record,
        ):
            literature = research_os_module._run_literature(
                self.registry,
                timestamp="2026-08-29T12:00:00Z",
            )
        direction = ResearchDirection(
            direction_id="direction-threshold",
            question=(
                "Does the pinned threshold improve synthetic development accuracy?"
            ),
            unresolved_weakness=(
                "The frozen constant baseline ignores the supplied signal."
            ),
            candidate_gap=research_os_module.FIXTURE_CANDIDATE_GAP,
            source_ids=("paper-0", "paper-1", "paper-2", "paper-3"),
            disconfirming_source_ids=("paper-4",),
            experimentally_distinguishable=True,
            feasible_with_resources=True,
        )
        brief = ProblemInvestigator().build_checked_brief(
            brief_id="brief-terminal-destroyed-gap",
            goal=literature.goal,
            literature_records=literature.design_records,
            directions=(direction,),
            selected_direction_id=direction.direction_id,
            existing_approaches=("Bound gap-destroying prior work",),
            evaluation_conventions=("Exact fixture-only replay",),
            criteria=ResearchQuestionCriteria(
                precision=True,
                falsifiability=True,
                importance=True,
                tractability=True,
                resource_availability=True,
                identifiable_contribution=True,
            ),
            investigation_state=literature.investigation_state,
            investigation_state_artifact_hash=(
                literature.investigation_state_artifact.sha256
            ),
        )
        self.assertIs(
            brief.gate_outcome,
            ResearchGateOutcome.INSUFFICIENT_NOVELTY,
        )
        self.assertEqual(brief.gap_destroying_source_ids, ("paper-4",))
        brief_record = self.registry.put_json(
            {
                "fixture_notice": "Synthetic integration fixture only.",
                "research_brief": safe_json_loads(canonical_json_bytes(brief)),
            },
            logical_type="research_brief",
            origin="focused terminal destroyed-gap fixture brief",
            creator_role=Role.PROBLEM_INVESTIGATOR,
            creation_command=("scientist-one", "terminal-destroyed-gap-test"),
            parent_artifacts=(
                literature.investigation_state_artifact.sha256,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        source = register_research_question_gate_assessment(
            self.registry,
            self.ledger,
            assessment_id="terminal-destroyed-gap-assessment",
            run_id=self.repository.run_id,
            goal_artifact_sha256=literature.goal_artifact.sha256,
            investigation_state_artifact_sha256=(
                literature.investigation_state_artifact.sha256
            ),
            research_brief_artifact_sha256=brief_record.sha256,
        )
        repository = ResearchStateRepository(
            self.registry,
            self.ledger,
            run_id=self.repository.run_id,
            code_version=self.repository.code_version,
            configuration_hash=self.ledger.events()[-1].configuration_hash,
            state=self.ledger.events()[-1].state_after,
            creation_command=("scientist-one", "terminal-destroyed-gap-test"),
        )
        derivation = derive_from_registered_research_gate_assessment(
            repository,
            source.sha256,
            expected_object_id=brief.brief_id,
        )
        assert derivation is not None
        self.assertIs(
            derivation.outcome,
            ResearchTerminalOutcome.INSUFFICIENT_NOVELTY,
        )
        self.assertIs(
            derivation.authority_scope,
            TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL,
        )
        record = replace(
            self.record(
                derivation,
                record_id="terminal-owner-backed-insufficient-novelty",
                reason=(
                    "Exact fixture roots contain bound gap-destroying prior work."
                ),
            ),
            created_at=source.created_at,
        )
        state_before = repository.state
        materialized = materialize_terminal_outcome(record, repository)
        self.assertEqual(repository.state, state_before)
        self.assertEqual(
            load_terminal_outcome(
                self.registry,
                materialized.terminal_artifact.sha256,
                repository=repository,
            ),
            record,
        )

    def test_current_scope_is_source_derived_and_cannot_be_relabelled(self) -> None:
        _assessment, source, derivation = self.authority()
        assert derivation is not None
        assert derivation.source_binding is not None
        self.assertEqual(
            derivation.source_binding.source_record_hash,
            source.record_hash,
        )
        self.assertEqual(
            derivation.to_dict()["source_binding"]["source_record_hash"],
            source.record_hash,
        )
        self.assertIs(
            derivation.authority_scope,
            TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL,
        )
        record = self.record(derivation)
        self.assertIs(
            record.authority_scope,
            TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL,
        )
        self.assertEqual(
            record.to_dict()["authority_scope"],
            TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL.value,
        )
        forged_derivation = replace(
            derivation,
            authority_scope=TerminalAuthorityScope.SCIENTIFIC_EVIDENCE,
        )
        forged = self.record(forged_derivation)
        with self.assertRaises(ValidationError):
            materialize_terminal_outcome(forged, self.repository)

    def test_round_terminal_view_replays_complete_soundness_binding_without_cycle(self) -> None:
        # Source-owned mechanical assessment; no scientific or independent
        # semantic-audit authority is issued by this boundary composition test.
        assessment, source, derivation = self.authority()
        assert derivation is not None and derivation.source_binding is not None
        soundness = SimpleNamespace(
            record=source, assessment=assessment,
            semantic_peers=(SimpleNamespace(publication_event_index=1),),
        )

        def admits(value):
            record = self.record(value, record_id="round-terminal-view")
            artifact = self.registry.put_bytes(
                record.canonical_bytes(), logical_type=TERMINAL_OUTCOME_LOGICAL_TYPE,
                origin=f"research-terminal:{record.run_id}:{record.record_id}",
                creator_role=record.producer,
                creation_command=self.repository.creation_command,
                parent_artifacts=record.evidence_artifact_hashes,
                schema_version=record.schema_version, mime_type="application/json",
                validation_result="PASS", frozen=True, created_at=record.created_at,
            )
            decision = terminal_outcomes_module._terminal_decision(
                record, self.repository, artifact.sha256,
            )
            with patch.object(
                gates_module, "require_scientific_soundness_assessment",
                side_effect=AssertionError("recursive soundness owner replay"),
            ):
                return gates_module._semantic_challenger_audit_exact_decision_projection(
                    self.registry, self.repository, decision,
                    event_index=2, soundness=soundness, accepted_objects={},
                    code_version=self.repository.code_version,
                )

        self.assertTrue(admits(derivation))
        for field, value in (
            ("source_record_hash", "e" * 64),
            ("source_parent_artifact_hashes", ()),
            ("source_object_id", "another-assessment"),
        ):
            with self.subTest(field=field):
                changed = replace(derivation, source_binding=replace(
                    derivation.source_binding, **{field: value},
                ))
                self.assertFalse(admits(changed))
        # Cross-run substitutions were already rejected by the typed envelope.
        with self.assertRaises(ValidationError):
            self.record(replace(derivation, source_binding=replace(
                derivation.source_binding, source_run_id="another-run",
            )))
        changed_statuses = (derivation.source_statuses[0], "ROBUSTNESS:PASS")
        self.assertFalse(admits(replace(
            derivation, source_statuses=changed_statuses,
            source_binding=replace(derivation.source_binding, source_statuses=changed_statuses),
        )))
        self.assertFalse(admits(replace(
            derivation, authority_scope=TerminalAuthorityScope.SCIENTIFIC_EVIDENCE,
        )))

    def test_round_terminal_view_rejects_same_payload_under_wrong_origin(self) -> None:
        assessment, source, derivation = self.authority()
        assert derivation is not None
        record = self.record(derivation)
        artifact = self.registry.put_bytes(
            record.canonical_bytes(), logical_type=TERMINAL_OUTCOME_LOGICAL_TYPE,
            origin="unrelated caller origin", creator_role=record.producer,
            creation_command=self.repository.creation_command,
            parent_artifacts=record.evidence_artifact_hashes,
            schema_version=record.schema_version, mime_type="application/json",
            validation_result="PASS", frozen=True, created_at=record.created_at,
        )
        decision = terminal_outcomes_module._terminal_decision(
            record, self.repository, artifact.sha256,
        )
        self.assertFalse(gates_module._semantic_challenger_audit_exact_decision_projection(
            self.registry, self.repository, decision, event_index=2,
            soundness=SimpleNamespace(
                record=source, assessment=assessment,
                semantic_peers=(SimpleNamespace(publication_event_index=1),),
            ),
            accepted_objects={}, code_version=self.repository.code_version,
        ))

    def test_round_paper_terminal_has_no_source_hash_only_exemption(self) -> None:
        # A typed failed paper value and matching soundness ancestry are not
        # full paper/bundle source replay. This is a deliberate unissued input.
        assessment, source, _ = self.authority()
        paper = self.registry.put_json(
            {"unissued_paper_probe": True}, logical_type="paper_verification",
            origin="non-evidentiary source-closure probe", creator_role=Role.SCIENTIFIC_REVIEWER,
            creation_command=("scientist-one", "test-terminal-soundness"),
            parent_artifacts=(source.sha256,), schema_version="1.0",
            mime_type="application/json", validation_result="PASS", frozen=True,
        )
        diagnostic = derive_from_paper_verification(PaperVerification(
            passed=False, blockers=(HardBlocker.UNRESOLVED_AUTHORITY,),
            discrepancies=("authoritative_bundle_does_not_resolve",), verified_claim_ids=(),
        ))
        assert diagnostic is not None
        binding = TerminalSourceBinding(
            source_kind=TerminalSourceKind.PAPER_VERIFICATION,
            source_artifact_sha256=paper.sha256, source_record_hash=paper.record_hash,
            source_logical_type=paper.logical_type, source_creator_role=paper.creator_role,
            source_run_id=self.repository.run_id, source_object_id="unissued-paper-candidate",
            source_claim_ids=(), source_statuses=diagnostic.source_statuses,
            source_parent_artifact_hashes=paper.parent_artifacts,
        )
        for index, mapping_id in enumerate((
            TERMINAL_OUTCOME_MAPPING_ID, PAPER_PUBLICATION_TERMINAL_MAPPING_ID,
        )):
            with self.subTest(mapping_id=mapping_id):
                record = self.record(replace(
                    diagnostic, source_binding=binding, mapping_id=mapping_id,
                    authority_scope=TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL,
                ), record_id=f"terminal-paper-round-mapping-{index}")
                artifact = self.registry.put_bytes(
                    record.canonical_bytes(), logical_type=TERMINAL_OUTCOME_LOGICAL_TYPE,
                    origin=f"research-terminal:{record.run_id}:{record.record_id}",
                    creator_role=record.producer, creation_command=self.repository.creation_command,
                    parent_artifacts=record.evidence_artifact_hashes, schema_version=record.schema_version,
                    mime_type="application/json", validation_result="PASS", frozen=True,
                    created_at=record.created_at,
                )
                decision = terminal_outcomes_module._terminal_decision(record, self.repository, artifact.sha256)
                self.assertFalse(gates_module._semantic_challenger_audit_exact_decision_projection(
                    self.registry, self.repository, decision, event_index=2,
                    soundness=SimpleNamespace(record=source, assessment=assessment,
                                              semantic_peers=(SimpleNamespace(publication_event_index=1),)),
                    accepted_objects={}, code_version=self.repository.code_version,
                ))

    def test_run_binding_does_not_upgrade_non_evidentiary_claim_scope(self) -> None:
        assessment, _source, derivation = self.authority(
            "soundness-run-bound-non-evidentiary",
            run_id=self.repository.run_id,
        )
        assert derivation is not None
        self.assertEqual(assessment.run_id, self.repository.run_id)
        self.assertIs(
            derivation.authority_scope,
            TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL,
        )
        materialized = materialize_terminal_outcome(
            self.record(
                derivation,
                record_id="terminal-run-bound-non-evidentiary",
            ),
            self.repository,
        )
        self.assertEqual(
            materialized.canonical_decision.research_object.metadata[
                "terminal_authority_scope"
            ],
            TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL.value,
        )

    def test_dispatch_uses_actual_registry_logical_type_not_bound_text(self) -> None:
        _assessment, _source, derivation = self.authority()
        assert derivation is not None and derivation.source_binding is not None
        forged_binding = replace(
            derivation.source_binding,
            source_logical_type="caller-claimed-soundness-type",
        )
        forged_derivation = replace(
            derivation,
            source_binding=forged_binding,
        )
        forged = self.record(forged_derivation)
        with self.assertRaisesRegex(
            ValidationError,
            "actual registry metadata",
        ):
            materialize_terminal_outcome(forged, self.repository)

        forged_record_hash = replace(
            derivation,
            source_binding=replace(
                derivation.source_binding,
                source_record_hash="f" * 64,
            ),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "actual registry metadata",
        ):
            materialize_terminal_outcome(
                self.record(
                    forged_record_hash,
                    record_id="terminal-wrong-source-record-hash",
                ),
                self.repository,
            )

    def test_legacy_v2_soundness_bytes_and_decision_remain_readable(self) -> None:
        _assessment, _source, current = self.authority()
        assert current is not None
        legacy_derivation = replace(
            current,
            mapping_id=LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
            source_binding=replace(
                current.source_binding,
                source_record_hash=None,
            ),
            authority_scope=None,
        )
        legacy = ResearchTerminalRecord(
            record_id="terminal-legacy-v2",
            run_id="run-terminal",
            phase=legacy_derivation.phase,
            outcome=legacy_derivation.outcome,
            reason="Historical soundness authority requires more experiments.",
            evidence_artifact_hashes=(
                legacy_derivation.source_binding.required_evidence_artifact_hashes
            ),
            derivation=legacy_derivation,
            producer=Role.SCIENTIFIC_REVIEWER,
            authority_scope=None,
            source_object_id=legacy_derivation.source_binding.source_object_id,
            source_claim_ids=legacy_derivation.source_binding.source_claim_ids,
            uncertainty=1.0,
            created_at=STAMP,
            schema_version=LEGACY_TERMINAL_OUTCOME_SCHEMA_VERSION,
        )
        self.assertNotIn("authority_scope", legacy.to_dict())
        self.assertNotIn("authority_scope", legacy.derivation.to_dict())
        legacy_with_scope = legacy.to_dict()
        legacy_with_scope["authority_scope"] = (
            TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL.value
        )
        with self.assertRaises(ValidationError):
            ResearchTerminalRecord.from_dict(legacy_with_scope)
        legacy_with_record_hash = legacy.to_dict()
        legacy_source_binding = legacy_with_record_hash["derivation"][
            "source_binding"
        ]
        legacy_source_binding["source_record_hash"] = "f" * 64
        with self.assertRaises(ValidationError):
            ResearchTerminalRecord.from_dict(legacy_with_record_hash)
        current_without_scope = self.record(
            current,
            record_id="terminal-current-missing-scope",
        ).to_dict()
        del current_without_scope["authority_scope"]
        with self.assertRaises(ValidationError):
            ResearchTerminalRecord.from_dict(current_without_scope)
        current_without_record_hash = self.record(
            current,
            record_id="terminal-current-missing-source-record-hash",
        ).to_dict()
        current_source_binding = current_without_record_hash["derivation"][
            "source_binding"
        ]
        del current_source_binding["source_record_hash"]
        with self.assertRaises(ValidationError):
            ResearchTerminalRecord.from_dict(current_without_record_hash)
        materialized = materialize_terminal_outcome(legacy, self.repository)
        self.assertEqual(
            materialized.terminal_artifact.schema_version,
            LEGACY_TERMINAL_OUTCOME_SCHEMA_VERSION,
        )
        decision = materialized.canonical_decision.research_object
        self.assertEqual(
            decision.governing_rule,
            LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
        )
        self.assertNotIn("terminal_authority_scope", decision.metadata)
        self.assertEqual(
            load_terminal_outcome(
                self.registry,
                materialized.terminal_artifact.sha256,
                repository=self.repository,
            ),
            legacy,
        )

    def test_registry_and_canonical_decision_integration_preserve_macro_state(self) -> None:
        assessment, source, derivation = self.authority()
        assert derivation is not None
        self.assertEqual(
            source.logical_type,
            TERMINAL_SOUNDNESS_SOURCE_LOGICAL_TYPE,
        )
        self.assertEqual(
            source.schema_version,
            TERMINAL_SOUNDNESS_SOURCE_SCHEMA_VERSION,
        )
        record = self.record(derivation)
        materialized = materialize_terminal_outcome(record, self.repository)

        self.assertEqual(
            materialized.terminal_artifact.logical_type,
            TERMINAL_OUTCOME_LOGICAL_TYPE,
        )
        self.assertEqual(
            materialized.terminal_artifact.parent_artifacts,
            record.evidence_artifact_hashes,
        )
        self.assertEqual(
            load_terminal_outcome(
                self.registry,
                materialized.terminal_artifact.sha256,
                repository=self.repository,
            ),
            record,
        )
        decision = materialized.canonical_decision.research_object
        self.assertIsInstance(decision, Decision)
        self.assertEqual(decision.decision_type, TERMINAL_DECISION_TYPE)
        self.assertEqual(decision.outcome, "MORE_EXPERIMENTS_REQUIRED")
        self.assertEqual(
            decision.source_artifact_hashes,
            (materialized.terminal_artifact.sha256,),
        )
        self.assertEqual(
            decision.authority_artifact_hashes,
            decision.source_artifact_hashes,
        )
        self.assertEqual(decision.governing_rule, TERMINAL_OUTCOME_MAPPING_ID)
        self.assertEqual(
            decision.metadata["terminal_authority_scope"],
            TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL.value,
        )
        self.assertEqual(
            decision.metadata["terminal_source_object_id"],
            assessment.assessment_id,
        )
        self.assertEqual(
            tuple(decision.metadata["terminal_source_claim_ids"]),
            assessment.central_claim_ids,
        )

        event = materialized.canonical_decision.event
        self.assertIs(event.state_before, MacroState.CONFIRM)
        self.assertIs(event.requested_state_after, MacroState.CONFIRM)
        self.assertIs(self.repository.state, MacroState.CONFIRM)
        self.assertEqual(len(TerminalState), 7)
        self.assertEqual(len(self.ledger.validate(raise_on_error=True).events), 1)
        self.assertTrue(self.repository.validate_state().valid)

        repeated = materialize_terminal_outcome(record, self.repository)
        self.assertEqual(
            repeated.terminal_artifact.sha256,
            materialized.terminal_artifact.sha256,
        )
        self.assertEqual(
            repeated.canonical_decision.event.event_hash,
            materialized.canonical_decision.event.event_hash,
        )
        self.assertEqual(len(self.ledger.validate(raise_on_error=True).events), 1)

    def test_value_only_and_generic_pass_artifacts_cannot_authorize(self) -> None:
        generic = self.evidence("generic PASS bytes")
        diagnostic = derive_from_hypothesis_status(
            CanonicalHypothesisStatus.FALSIFIED
        )
        assert diagnostic is not None
        record = ResearchTerminalRecord(
            record_id="diagnostic-hypothesis-label",
            run_id="run-terminal",
            phase=diagnostic.phase,
            outcome=diagnostic.outcome,
            reason="A value-only label is diagnostic, not authority.",
            evidence_artifact_hashes=(generic.sha256,),
            derivation=diagnostic,
            producer=Role.SCIENTIFIC_REVIEWER,
            uncertainty=1.0,
            created_at=STAMP,
        )
        with self.assertRaises(ValidationError):
            materialize_terminal_outcome(record, self.repository)

        binding = TerminalSourceBinding(
            source_kind=TerminalSourceKind.HYPOTHESIS_REGISTER,
            source_artifact_sha256=generic.sha256,
            source_record_hash=generic.record_hash,
            source_logical_type=generic.logical_type,
            source_creator_role=generic.creator_role,
            source_run_id="run-terminal",
            source_object_id="hypothesis-forged",
            source_claim_ids=(),
            source_statuses=diagnostic.source_statuses,
            source_parent_artifact_hashes=generic.parent_artifacts,
        )
        forged = replace(
            diagnostic,
            source_binding=binding,
            authority_scope=TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL,
        )
        forged_record = ResearchTerminalRecord(
            record_id="forged-hypothesis-authority",
            run_id="run-terminal",
            phase=forged.phase,
            outcome=forged.outcome,
            reason="Generic registry bytes cannot authorize a hypothesis outcome.",
            evidence_artifact_hashes=binding.required_evidence_artifact_hashes,
            derivation=forged,
            producer=Role.SCIENTIFIC_REVIEWER,
            source_object_id=binding.source_object_id,
            source_claim_ids=(),
            uncertainty=1.0,
            created_at=STAMP,
        )
        self.assertIs(
            forged_record.derivation.source_binding.source_creator_role,
            generic.creator_role,
        )
        self.assertIs(forged_record.producer, Role.SCIENTIFIC_REVIEWER)
        with self.assertRaises(ValidationError):
            materialize_terminal_outcome(forged_record, self.repository)

    def test_source_metadata_run_object_claim_status_and_parent_substitution_fail(self) -> None:
        assessment, source, _derivation = self.authority()

        cases: list[tuple[str, object, str]] = []
        wrong_type_payload = self.clone_source_payload(source.sha256, "soundness-wrong-type")
        cases.append(
            (
                "wrong-type",
                self.put_source_payload(
                    wrong_type_payload,
                    logical_type="unrelated_terminal_source",
                ),
                "soundness-wrong-type",
            )
        )
        wrong_role_payload = self.clone_source_payload(source.sha256, "soundness-wrong-role")
        cases.append(
            (
                "wrong-role",
                self.put_source_payload(
                    wrong_role_payload,
                    creator_role=Role.EXPERIMENT_RUNNER,
                ),
                "soundness-wrong-role",
            )
        )
        wrong_run_payload = self.clone_source_payload(
            source.sha256,
            "soundness-wrong-run",
        )
        wrong_run_payload["run_id"] = "other-run"
        cases.append(
            (
                "wrong-run",
                self.put_source_payload(wrong_run_payload),
                "soundness-wrong-run",
            )
        )
        wrong_parent_payload = self.clone_source_payload(
            source.sha256,
            "soundness-wrong-parent",
        )
        parent_values = tuple(wrong_parent_payload["assessment"]["evidence_hashes"])
        cases.append(
            (
                "wrong-parent",
                self.put_source_payload(
                    wrong_parent_payload,
                    parents=parent_values[1:],
                ),
                "soundness-wrong-parent",
            )
        )
        wrong_status_payload = self.clone_source_payload(
            source.sha256,
            "soundness-wrong-status",
        )
        wrong_status_payload["assessment"]["verdict"] = SoundnessVerdict.PASS.value
        cases.append(
            (
                "wrong-status",
                self.put_source_payload(wrong_status_payload),
                "soundness-wrong-status",
            )
        )

        for label, artifact, expected_id in cases:
            with self.subTest(label=label):
                with self.assertRaises(ValidationError):
                    derive_from_registered_soundness(
                        self.repository,
                        artifact.sha256,
                        expected_assessment_id=expected_id,
                        expected_claim_ids=assessment.central_claim_ids,
                    )

        with self.assertRaises(ValidationError):
            derive_from_registered_soundness(
                self.repository,
                source.sha256,
                expected_assessment_id="different-assessment",
                expected_claim_ids=assessment.central_claim_ids,
            )
        with self.assertRaises(ValidationError):
            derive_from_registered_soundness(
                self.repository,
                source.sha256,
                expected_assessment_id=assessment.assessment_id,
                expected_claim_ids=("different-claim",),
            )

        wrong_run_repository = ResearchStateRepository(
            self.registry,
            self.ledger,
            run_id="other-run",
            code_version="code-terminal-v1",
            configuration_hash=CONFIG_HASH,
            state=MacroState.CONFIRM,
        )
        with self.assertRaisesRegex(ValidationError, "run-scoped"):
            derive_from_registered_soundness(
                wrong_run_repository,
                source.sha256,
                expected_assessment_id=assessment.assessment_id,
                expected_claim_ids=assessment.central_claim_ids,
            )

        with tempfile.TemporaryDirectory() as other_directory:
            other_root = Path(other_directory)
            other_registry = ArtifactRegistry(
                other_root,
                "runs/run-terminal/registry",
            )
            other_repository = ResearchStateRepository(
                other_registry,
                EventLedger(other_root, "runs/run-terminal/events.jsonl"),
                run_id="run-terminal",
                code_version="code-terminal-v1",
                configuration_hash=CONFIG_HASH,
                state=MacroState.CONFIRM,
            )
            with self.assertRaises(ValidationError):
                derive_from_registered_soundness(
                    other_repository,
                    source.sha256,
                    expected_assessment_id=assessment.assessment_id,
                    expected_claim_ids=assessment.central_claim_ids,
                )

    def test_record_rejects_source_substitution_parent_omission_and_cross_run(self) -> None:
        assessment_a, _source_a, derivation_a = self.authority("soundness-source-a")
        _assessment_b, _source_b, derivation_b = self.authority("soundness-source-b")
        assert derivation_a is not None and derivation_b is not None
        binding_a = derivation_a.source_binding
        assert binding_a is not None

        with self.assertRaises(ValidationError):
            self.record(
                derivation_b,
                source_object_id=assessment_a.assessment_id,
            )
        with self.assertRaises(ValidationError):
            self.record(
                derivation_a,
                evidence_artifact_hashes=(binding_a.source_artifact_sha256,),
            )
        extra = self.evidence("unrelated extra evidence")
        with self.assertRaises(ValidationError):
            self.record(
                derivation_a,
                evidence_artifact_hashes=(
                    *binding_a.required_evidence_artifact_hashes,
                    extra.sha256,
                ),
            )
        with self.assertRaises(ValidationError):
            self.record(derivation_a, producer=Role.STATISTICIAN)
        with self.assertRaises(ValidationError):
            replace(self.record(derivation_a), run_id="other-run")

    def test_conflicting_record_and_terminal_without_decision_fail_closed(self) -> None:
        _assessment, _source, derivation = self.authority()
        assert derivation is not None
        first = self.record(derivation)
        materialize_terminal_outcome(first, self.repository)
        conflict = self.record(
            derivation,
            reason="A different record cannot reuse the immutable decision identity.",
        )
        with self.assertRaises(ValidationError):
            materialize_terminal_outcome(conflict, self.repository)

        no_decision = self.record(
            derivation,
            record_id="terminal-without-canonical-decision",
        )
        artifact = self.registry.put_bytes(
            no_decision.canonical_bytes(),
            logical_type=TERMINAL_OUTCOME_LOGICAL_TYPE,
            origin="adversarial terminal artifact without canonical Decision",
            creator_role=no_decision.producer,
            creation_command=("scientist-one", "terminal-no-decision-adversary"),
            parent_artifacts=no_decision.evidence_artifact_hashes,
            schema_version=TERMINAL_OUTCOME_SCHEMA_VERSION,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        with self.assertRaises(ValidationError):
            load_terminal_outcome(
                self.registry,
                artifact.sha256,
                repository=self.repository,
            )

    def test_authoritative_readback_rejects_label_and_source_tampering(self) -> None:
        _assessment, _source, derivation = self.authority()
        assert derivation is not None
        valid = self.record(
            derivation,
            record_id="terminal-readback-adversary",
        ).to_dict()
        variants: list[dict[str, object]] = []

        wrong_outcome = dict(valid)
        wrong_outcome["outcome"] = ResearchTerminalOutcome.NEGATIVE_RESULT.value
        variants.append(wrong_outcome)

        wrong_phase = dict(valid)
        wrong_phase["phase"] = TerminalPhase.DISCOVERY.value
        variants.append(wrong_phase)

        wrong_status = dict(valid)
        wrong_status["derivation"] = dict(valid["derivation"])
        wrong_status["derivation"]["source_statuses"] = [
            f"VERDICT:{SoundnessVerdict.PASS.value}",
            f"ROBUSTNESS:{DimensionStatus.PASS.value}",
        ]
        variants.append(wrong_status)

        wrong_object = dict(valid)
        wrong_object["source_object_id"] = "substituted-assessment"
        variants.append(wrong_object)

        for index, payload in enumerate(variants, 1):
            artifact = self.registry.put_bytes(
                canonical_json_bytes(payload) + b"\n",
                logical_type=TERMINAL_OUTCOME_LOGICAL_TYPE,
                origin=f"adversarial terminal substitution {index}",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "terminal-outcome-adversary"),
                parent_artifacts=tuple(valid["evidence_artifact_hashes"]),
                schema_version=TERMINAL_OUTCOME_SCHEMA_VERSION,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=STAMP,
            )
            with self.subTest(index=index):
                with self.assertRaises(ValidationError):
                    load_terminal_outcome(
                        self.registry,
                        artifact.sha256,
                        repository=self.repository,
                    )


if __name__ == "__main__":
    unittest.main()
