"""SEMANTIC_RECONSTRUCTION: three real frozen-kernel API outcome lifecycles.

Root must stage this module with the unchanged recovered source/configuration,
the two inert calibration fixtures, and an explicit NEW_TEST_FIXTURE bootstrap
in a fresh canonical ScientistOne project. Execute through that project's actual
unchanged captured test-suite launcher. Each method creates one unique run in
the legitimately admitted project; no capability flags or loaders are changed.

This is API integration under the test launcher, not CLI scenario support (the
frozen CLI has no scenario flag), historical test recovery, or external science.
"""

import hashlib
import json
from pathlib import Path
import stat
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
import scientist_one.orchestrator as orchestrator_module
from scientist_one.orchestrator import OrchestrationError, ScientistOneOrchestrator


class ReconstructedNonpositiveLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.root = Path.cwd().resolve()
        # The root stages a physical copy BEFORE invoking the real launcher.
        # A copied-source overlay or a different temporary root is not accepted.
        self.assertEqual(Path(orchestrator_module.__file__).resolve().parents[2], self.root)
        bootstrap = json.loads((self.root / "state/APP_SESSION_BOOTSTRAP.json").read_bytes())
        self.assertEqual(bootstrap["classification"], "NEW_TEST_FIXTURE")
        self.assertIs(bootstrap["historical_authority"], False)
        self.assertEqual(bootstrap["canonical_project_root"], str(self.root))
        self.input_before = self.inventory(("src", "scripts", "configs", "fixtures"))
        self.orchestrator = ScientistOneOrchestrator(self.root)

    def inventory(self, directories):
        """Capture exact bytes/size/mtime, without modifying any file."""
        result = {}
        for directory in directories:
            base = self.root / directory
            if not base.exists():
                continue
            for path in sorted(base.rglob("*")):
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    continue
                self.assertTrue(stat.S_ISREG(metadata.st_mode), str(path))
                self.assertEqual(metadata.st_nlink, 1, str(path))
                content = path.read_bytes()
                result[path.relative_to(self.root).as_posix()] = (
                    len(content), hashlib.sha256(content).hexdigest(), metadata.st_mtime_ns)
        return result

    def payload(self, registry, manifest, logical_type):
        descriptor = manifest["artifacts"][logical_type]
        record = registry.get_metadata(descriptor["sha256"])
        self.assertTrue(registry.verify(record.sha256, raise_on_error=True))
        self.assertEqual(record.logical_type, logical_type)
        self.assertEqual(record.record_hash, descriptor["registry_record_hash"])
        self.assertTrue(record.frozen)
        self.assertEqual(record.validation_result, "PASS")
        return json.loads(registry.get_bytes(record.sha256))

    def check_scenario(self, scenario, terminal, treatment, estimate):
        runs_before = {path.name for path in (self.root / "runs").iterdir() if path.is_dir()}
        previous_run_bytes = self.inventory(("runs",))
        self.orchestrator.set_command_context((
            "api-integration-under-captured-test-suite", "ScientistOneOrchestrator.demo", scenario))
        result = self.orchestrator.demo(synthetic_scenario=scenario)
        run_id = result["run_id"]
        self.assertNotIn(run_id, runs_before)
        runs_after = {path.name for path in (self.root / "runs").iterdir() if path.is_dir()}
        self.assertEqual(runs_after - runs_before, {run_id})
        all_run_bytes = self.inventory(("runs",))
        self.assertEqual({path: all_run_bytes[path] for path in previous_run_bytes}, previous_run_bytes)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["current_state"], terminal)
        self.assertEqual(result["terminal_state"], terminal)
        self.assertEqual(result["outcome"], terminal)
        self.assertFalse(result["resumable"])
        self.assertIsNone(result["package"])
        self.assertIsNone(result["reproduction"])

        manifest = self.orchestrator.load_manifest(run_id)
        self.assertEqual(manifest["synthetic_scenario"], scenario)
        self.assertEqual(manifest["package_kind"], "DEMO_RESEARCH_PACKAGE")
        self.assertEqual(manifest["novelty"], "NOVELTY_UNVERIFIED")
        self.assertEqual(manifest["external_integrations_used"], [])
        self.assertEqual(manifest["current_state"], terminal)
        self.assertEqual(manifest["terminal_state"], terminal)
        self.assertEqual(manifest["outcome"], terminal)
        self.assertIsNone(manifest["package"])
        self.assertIsNone(manifest["reproduction"])
        for name in ("claim_graph", "results_table", "results_figure", "demo_paper",
                     "release_candidate", "reproduction_result", "reproduction_manifest"):
            self.assertNotIn(name, manifest["artifacts"])
        self.assertEqual(manifest["completed_transitions"][-1], "CONFIRM->" + terminal)
        self.assertFalse(any(edge.split("->")[-1] in {"CLAIMS", "WRITE", "AUDIT", "RELEASE"}
                             for edge in manifest["completed_transitions"]))
        self.assertTrue(manifest["typed_transition_receipts"])
        self.assertTrue(manifest["evaluator_decisions"])
        self.assertTrue(all(receipt["evaluator_class"] != "E4"
                            for receipt in manifest["evaluator_decisions"].values()))

        registry = ArtifactRegistry(self.root, Path("runs") / run_id / "registry")
        intent = self.payload(registry, manifest, "run_intent")
        self.assertEqual(intent["synthetic_scenario"], scenario)
        machine = self.payload(registry, manifest, "machine_results")
        self.assertEqual(machine["evidence_class"], "SYNTHETIC_CONFIRMATORY_FIXTURE")
        self.assertEqual(machine["outcome_pattern"], scenario)
        self.assertEqual(machine["frozen_fixture"], {
            "control": [0.0, 1.0, 2.0, 3.0], "treatment": treatment})
        self.assertEqual(machine["primary_estimate"], estimate)
        recomputed = sum(treatment) / len(treatment) - 1.5
        self.assertEqual(machine["primary_estimate"], recomputed)
        self.assertEqual(machine["confirmatory_access_count"], 1)
        self.assertIs(machine["tuned_after_reveal"], False)
        self.assertEqual(machine["input_hashes"]["custody_record"],
                         manifest["artifacts"]["custody_record"]["sha256"])
        custody = self.payload(registry, manifest, "custody_record")
        self.assertEqual(custody["custody_independence"], "SIMULATED_NON_INDEPENDENT")
        self.assertIs(custody["genuine_independence_claimed"], False)
        self.assertEqual(custody["authorized_access_count"], 1)
        terminal_report = self.payload(registry, manifest, "terminal_report")
        self.assertEqual(terminal_report["source_state"], "CONFIRM")
        self.assertEqual(terminal_report["terminal_state"], terminal)
        self.assertIs(terminal_report["honest_negative_or_inconclusive"], True)
        self.assertEqual(terminal_report["evidence"]["outcome_pattern"], scenario)
        self.assertEqual(terminal_report["evidence"]["machine_results_sha256"],
                         manifest["artifacts"]["machine_results"]["sha256"])

        ledger = EventLedger(self.root, Path("runs") / run_id / "events.jsonl")
        validated = ledger.validate(raise_on_error=True)
        self.assertTrue(validated.valid)
        self.assertEqual(sum(event.event_type == "CONFIRMATORY_STARTED" for event in validated.events), 1)
        self.assertEqual(sum(event.event_type == "CONFIRMATORY_COMPLETED" for event in validated.events), 1)
        self.assertEqual(validated.events[-1].requested_state_after.value, terminal)
        verified = self.orchestrator.verify(run_id)
        self.assertEqual(verified["status"], "PASS", verified)
        self.assertEqual(verified["recovery"]["action"], "SKIP_COMPLETED")
        self.assertEqual(verified["recovery"]["replay_event_count"], 0)
        self.assertIn("CONFIRMATORY_RERUN_PROHIBITED", verified["recovery"]["reasons"])

        # Real terminal resume/package APIs must leave all project authorities
        # unchanged, including prior runs, custody, resources and checkpoints.
        authority_before = self.inventory(("runs", "state", "artifacts", ".scientist-one-build"))
        resumed = self.orchestrator.resume(run_id)
        self.assertEqual(resumed["current_state"], terminal)
        self.assertEqual(resumed["event_count"], result["event_count"])
        self.assertFalse(resumed["resumable"])
        self.assertEqual(self.inventory(("runs", "state", "artifacts", ".scientist-one-build")), authority_before)
        with self.assertRaisesRegex(OrchestrationError, "complete AUDIT before packaging"):
            self.orchestrator.package(run_id)
        self.assertEqual(self.inventory(("runs", "state", "artifacts", ".scientist-one-build")), authority_before)
        self.assertEqual(ledger.validate(raise_on_error=True).head_hash, validated.head_hash)
        self.assertEqual(self.payload(registry, manifest, "machine_results"), machine)
        self.assertEqual(self.inventory(("src", "scripts", "configs", "fixtures")), self.input_before)

    def test_null_result_terminates_negative_without_promotion_or_rerun(self):
        self.check_scenario("null", "NEGATIVE_RESULT", [0.0, 1.0, 2.0, 3.0], 0.0)

    def test_reversal_terminates_inconclusive_without_promotion_or_rerun(self):
        self.check_scenario("reversal", "INCONCLUSIVE", [-1.0, 0.0, 1.0, 2.0], -1.0)

    def test_unstable_result_terminates_inconclusive_despite_positive_mean(self):
        self.check_scenario("unstable", "INCONCLUSIVE", [-100.0, 102.0, -98.0, 104.0], 0.5)


if __name__ == "__main__":
    unittest.main()
