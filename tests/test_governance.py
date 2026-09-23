from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.evaluators import (
    AuditSummary,
    Decision,
    Evaluation,
    EvaluatorClass,
    RCheck,
    require_gate,
)
from scientist_one.readiness import (
    evaluate_readiness,
    register_frozen_readiness_rubric,
)
from scientist_one.roles import Role, make_role_bundle, write_role_prompts
from scientist_one.writing import (
    load_machine_results,
    render_demo_paper_bytes,
    render_results_table_bytes,
    render_svg_effect_figure_bytes,
    write_demo_paper,
    write_results_table,
    write_svg_effect_figure,
)


ROOT = Path(__file__).resolve().parents[1]


class GovernanceTests(unittest.TestCase):
    def test_role_bundle_is_frozen_and_hash_validated(self) -> None:
        original = {"seed": 7, "nested": [1, 2]}
        bundle = make_role_bundle(Role.STATISTICIAN, "run-1", ["a" * 64], original)
        digest = bundle.sha256
        original["nested"].append(3)
        self.assertEqual(digest, bundle.sha256)
        self.assertEqual(len(bundle.sha256), 64)
        with self.assertRaises(ValueError):
            make_role_bundle(Role.STATISTICIAN, "run-1", ["not-a-hash"], {})

    def test_independent_role_cannot_review_own_output(self) -> None:
        with self.assertRaises(ValueError):
            make_role_bundle(
                Role.SCIENTIFIC_REVIEWER,
                "run-1",
                ["b" * 64],
                {},
                producer_role=Role.SCIENTIFIC_REVIEWER,
            )

    def test_e1_cannot_authorize_and_e4_is_human_only(self) -> None:
        with self.assertRaises(ValueError):
            Evaluation(EvaluatorClass.E1, Role.IMPLEMENTER, Decision.PASS, (), "self pass")
        with self.assertRaises(ValueError):
            Evaluation(EvaluatorClass.E4, Role.ORCHESTRATOR, Decision.PASS, (), "fake approval")

    def test_required_evaluator_gate(self) -> None:
        evaluation = Evaluation(
            EvaluatorClass.E2,
            Role.SCIENTIFIC_REVIEWER,
            Decision.PASS,
            ("c" * 64,),
            "frozen bundle passes",
            (RCheck.R1,),
            producer_role=Role.PROTOCOL_DESIGNER,
        )
        audit = AuditSummary([evaluation])
        self.assertEqual(
            audit.descriptive_status_by_r_check()[RCheck.R1.value],
            "DESCRIPTIVE_ONLY",
        )
        with self.assertRaisesRegex(ValueError, "no R-check authority bundle"):
            require_gate(
                audit,
                (EvaluatorClass.E2,),
                r_checks=(RCheck.R1,),
                registry=object(),
                ledger=object(),
                run_id="run-1",
            )

    def test_r0_r7_require_authoritative_passes(self) -> None:
        audit = AuditSummary()
        for check in RCheck:
            audit.add(
                Evaluation(
                    EvaluatorClass.E0,
                    Role.ORCHESTRATOR,
                    Decision.PASS,
                    (),
                    "deterministic validation",
                    (check,),
                )
            )
        self.assertFalse(audit.mandatory_pass())
        for check in RCheck:
            for evaluator_class in __import__("scientist_one.evaluators", fromlist=["REQUIRED_R_AUTHORITIES"]).REQUIRED_R_AUTHORITIES[check]:
                if evaluator_class is EvaluatorClass.E0:
                    continue
                role = Role.SCIENTIFIC_REVIEWER if evaluator_class is EvaluatorClass.E2 else Role.ADVERSARIAL_REVIEWER
                audit.add(
                    Evaluation(
                        evaluator_class,
                        role,
                        Decision.PASS,
                        (),
                        "independent frozen review",
                        (check,),
                        producer_role=Role.ORCHESTRATOR,
                    )
                )
        self.assertFalse(audit.mandatory_pass())
        self.assertEqual(
            set(audit.status_by_r_check().values()),
            {"MISSING_AUTHORITY"},
        )

    def test_synthetic_readiness_is_never_submission_ready(self) -> None:
        audit = AuditSummary()
        for check in RCheck:
            audit.add(Evaluation(EvaluatorClass.E0, Role.ORCHESTRATOR, Decision.PASS, (), "ok", (check,)))
        for check in RCheck:
            from scientist_one.evaluators import REQUIRED_R_AUTHORITIES

            for evaluator_class in REQUIRED_R_AUTHORITIES[check]:
                if evaluator_class is EvaluatorClass.E0:
                    continue
                role = Role.SCIENTIFIC_REVIEWER if evaluator_class is EvaluatorClass.E2 else Role.ADVERSARIAL_REVIEWER
                audit.add(Evaluation(evaluator_class, role, Decision.PASS, (), "review", (check,), producer_role=Role.ORCHESTRATOR))
        with self.assertRaisesRegex(ValueError, "authority bundle"):
            evaluate_readiness(
                audit,
                registry=object(),
                ledger=object(),
                run_id="run-1",
            )

    def test_readiness_rubric_rejects_outside_links_and_unsafe_json(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            base = Path(directory)
            registry = ArtifactRegistry(base, "registry")
            with self.assertRaisesRegex(ValueError, "not safe JSON"):
                register_frozen_readiness_rubric(
                    registry,
                    b'{"schema_version":"1.0","schema_version":"1.0"}',
                )
            with self.assertRaisesRegex(ValueError, "not safe JSON"):
                register_frozen_readiness_rubric(
                    registry,
                    b'{"candidate_threshold":NaN}',
                )

    def test_readiness_scores_the_exact_pinned_rubric_bytes(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            base = Path(directory)
            pinned = (ROOT / "configs/paper_readiness_rubric.json").read_bytes()
            registry = ArtifactRegistry(base, "registry")
            record = register_frozen_readiness_rubric(registry, pinned)
            self.assertEqual(registry.get_bytes(record.sha256), pinned)

    def test_prompts_tables_figure_and_demo_paper_are_generated(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            base = Path(directory)
            hashes = write_role_prompts(base / "prompts", root=base)
            self.assertEqual(len(hashes), len(Role))
            results = [{"task": "signal", "effect_size": 1.5, "p_value": 0.01}]
            table = write_results_table(results, base / "table.csv", root=base)
            figure = write_svg_effect_figure(results, base / "figure.svg", root=base)
            paper = write_demo_paper(
                {"package_kind": "DEMO_RESEARCH_PACKAGE", "protocol_hash": "d" * 64},
                [{
                    "text": "The synthetic detector recovered the planted signal.",
                    "scope_qualifier": "deterministic local fixture only",
                    "limitations": ["This result does not imply external validity."],
                    "verifier_decision": "ELIGIBLE",
                    "hypothesis_id": "synthetic-h1",
                    "estimand_id": "mean-difference",
                    "dataset_or_fixture_id": "fixture-signal-v1",
                    "protocol_hash": "1" * 64,
                    "code_hash": "2" * 64,
                    "result_artifact_hash": "3" * 64,
                    "statistical_analysis_hash": "4" * 64,
                    "robustness_evidence_hashes": ["5" * 64],
                    "figure_or_table_ids": ["table-results"],
                    "source_citation_ids": ["local-fixture:signal-v1"],
                    "verifier_artifact_hash": "6" * 64,
                }],
                table,
                figure,
                base / "paper.md",
                root=base,
            )
            self.assertIn("NOVELTY_UNVERIFIED", paper.read_text())
            self.assertTrue(figure.read_text().startswith("<svg"))

    def test_pure_renderers_exactly_match_immutable_writer_bytes(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            base = Path(directory)
            results = [{"task": "signal<&", "effect_size": 1.5, "p_value": 0.01}]
            manifest = {
                "package_kind": "DEMO_RESEARCH_PACKAGE",
                "protocol_hash": "d" * 64,
            }
            claims = [{
                "text": "The local signal is deterministic.",
                "scope_qualifier": "synthetic fixture only",
                "limitations": ["No external validity."],
                "verifier_decision": "ELIGIBLE",
                "hypothesis_id": "synthetic-h1",
                "estimand_id": "mean-difference",
                "dataset_or_fixture_id": "fixture-signal-v1",
                "protocol_hash": "1" * 64,
                "code_hash": "2" * 64,
                "result_artifact_hash": "3" * 64,
                "statistical_analysis_hash": "4" * 64,
                "robustness_evidence_hashes": ["5" * 64],
                "figure_or_table_ids": ["table-results"],
                "source_citation_ids": ["local-fixture:signal-v1"],
                "verifier_artifact_hash": "6" * 64,
            }]
            table_bytes = render_results_table_bytes(results)
            figure_bytes = render_svg_effect_figure_bytes(results)
            table = write_results_table(results, base / "table.csv", root=base)
            figure = write_svg_effect_figure(results, base / "figure.svg", root=base)
            paper_bytes = render_demo_paper_bytes(
                manifest,
                claims,
                table.relative_to(base),
                figure.relative_to(base),
            )
            paper = write_demo_paper(
                manifest,
                claims,
                table.relative_to(base),
                figure.relative_to(base),
                base / "paper.md",
                root=base,
            )
            self.assertEqual(table.read_bytes(), table_bytes)
            self.assertEqual(figure.read_bytes(), figure_bytes)
            self.assertEqual(paper.read_bytes(), paper_bytes)
            self.assertIn(b"signal&lt;&amp;", figure_bytes)

    def test_writer_rejects_string_eligibility_without_graph(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            base = Path(directory)
            with self.assertRaises(ValueError):
                write_demo_paper(
                    {"package_kind": "DEMO_RESEARCH_PACKAGE"},
                    [{"text": "unsupported", "verifier_decision": "ELIGIBLE"}],
                    base / "results.json",
                    base / "figure.svg",
                    base / "paper.md",
                    root=base,
                )

    def test_writer_rejects_outside_root_output(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            base = Path(directory)
            with self.assertRaises(ValueError):
                write_results_table([{"task": "x"}], ROOT / "outside.csv", root=base)

    def test_writers_reject_preplanted_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            base = Path(directory)
            sentinel = base / "sentinel.txt"
            sentinel.write_text("unchanged")
            target = base / "table.csv"
            target.symlink_to(sentinel)
            with self.assertRaises(ValueError):
                write_results_table([{"task": "x"}], target, root=base)
            self.assertEqual(sentinel.read_text(), "unchanged")

            real_prompts = base / "real-prompts"
            real_prompts.mkdir()
            (base / "prompts").symlink_to(real_prompts, target_is_directory=True)
            with self.assertRaises(ValueError):
                write_role_prompts(base / "prompts", root=base)
            self.assertEqual(list(real_prompts.iterdir()), [])

    def test_machine_results_loader_rejects_unsafe_json_and_links(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            base = Path(directory)
            malformed = base / "duplicate.json"
            malformed.write_text('[{"task":"a","task":"b"}]')
            with self.assertRaises(ValueError):
                load_machine_results(malformed, root=base)

            source = base / "source.json"
            source.write_text('[{"task":"signal"}]')
            linked = base / "linked.json"
            linked.symlink_to(source)
            with self.assertRaises(ValueError):
                load_machine_results(linked, root=base)

            outside = ROOT / "configs" / "resource_limits.json"
            with self.assertRaises(ValueError):
                load_machine_results(outside, root=base)
            with self.assertRaises(ValueError):
                load_machine_results(Path("../outside.json"), root=base)

    def test_machine_results_loader_caps_descriptor_read_before_materialization(self) -> None:
        import scientist_one.writing as writing_module

        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            base = Path(directory)
            oversized = base / "oversized.json"
            with oversized.open("wb") as handle:
                handle.seek(8 * 1024 * 1024)
                handle.write(b"[]")
            with mock.patch.object(
                writing_module,
                "read_confined_bytes",
                wraps=writing_module.read_confined_bytes,
            ) as reader, self.assertRaises(ValueError):
                load_machine_results(oversized, root=base)

        reader.assert_called_once_with(
            base,
            Path("oversized.json"),
            reject_hardlinks=True,
            max_bytes=8 * 1024 * 1024,
        )


if __name__ == "__main__":
    unittest.main()
