"""Non-evidentiary selected-output capacity and source-placement controls.

Metadata records below are unregistered PENDING values, not scientific
sources. AST controls inspect the actual loader without mocking full owners
into success. A real empty-registry refusal retains the ordinary owner path.
The 8 MiB acceptance cap is not an atomic allocation/memory-race guarantee:
outer snapshots and recursive verification can read bodies under older caps.
"""

import ast
from dataclasses import replace
import inspect
from pathlib import Path
from tempfile import TemporaryDirectory
import textwrap
from types import SimpleNamespace
import unittest

from scientist_one import experiments
from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.experiments import ExperimentError, OutputArtifact
from scientist_one.generic_ml_ablation_output import MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role


def _pair(size, *, record_size=None, index=1, logical_type="any_selected_output"):
    digest = f"{index:064x}"
    path = f"inert/output-{index}.json"
    descriptor = OutputArtifact(path=path, sha256=digest, size=size, logical_type=logical_type)
    record = ArtifactRecord(
        sha256=digest, path=path, relative_path=path, metadata_path=f"{path}.metadata.json",
        logical_type=f"experiment_output.{logical_type}", schema_version="1.0",
        mime_type="application/json", size=size if record_size is None else record_size,
        origin="unregistered non-evidentiary capacity metadata",
        creator_role=Role.EXPERIMENT_RUNNER, creation_command=("test", "pure-capacity"),
        parent_artifacts=(), validation_result="PENDING", frozen=False,
        created_at="2026-01-01T00:00:00.000000Z",
    )
    return descriptor, record


def _function(value):
    return ast.parse(textwrap.dedent(inspect.getsource(value))).body[0]


def _calls(node, name):
    return [item for item in ast.walk(node) if isinstance(item, ast.Call)
            and isinstance(item.func, ast.Name) and item.func.id == name]


def _registry_calls(node, name):
    return [item for item in ast.walk(node) if isinstance(item, ast.Call)
            and isinstance(item.func, ast.Attribute) and item.func.attr == name
            and isinstance(item.func.value, ast.Name) and item.func.value.id == "registry"]


class NumericAblationOutputCapacityTests(unittest.TestCase):
    def test_each_selected_output_accepts_only_one_through_the_exact_eight_mib_cap(self):
        limit = MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES
        self.assertEqual(limit, 8 * 1024 * 1024)
        for size in (1, limit - 1, limit):
            with self.subTest(size=size):
                self.assertIsNone(experiments._require_numeric_ablation_selected_output_capacity((_pair(size),)))
        for size in (0, limit + 1, experiments.MAX_OUTPUT_ARTIFACT_BYTES):
            with self.subTest(size=size), self.assertRaisesRegex(ExperimentError, "selected output size"):
                experiments._require_numeric_ablation_selected_output_capacity((_pair(size),))

    def test_current_metadata_size_must_match_descriptor_and_remain_within_cap(self):
        limit = MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES
        for descriptor_size, record_size in ((1, 0), (1, 2), (limit, limit - 1),
                                             (limit, limit + 1), (limit + 1, limit)):
            with self.subTest(descriptor_size=descriptor_size, record_size=record_size):
                with self.assertRaisesRegex(ExperimentError, "selected output size"):
                    experiments._require_numeric_ablation_selected_output_capacity(
                        (_pair(descriptor_size, record_size=record_size),))
        descriptor, record = _pair(1)
        self.assertIsNone(experiments._require_numeric_ablation_selected_output_capacity(((descriptor, record),)))
        # A fresh metadata record after the full-set pass cannot silently grow
        # even though the prior metadata pair was within the cap.
        current_record = replace(record, size=2, record_hash=None)
        with self.assertRaisesRegex(ExperimentError, "selected output size"):
            experiments._require_numeric_ablation_selected_output_capacity(((descriptor, current_record),))

    def test_existing_512_mib_total_is_inclusive_and_complete_set_is_counted(self):
        limit = MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES
        self.assertEqual(experiments.MAX_RETURNED_ARTIFACT_TOTAL_BYTES, 512 * 1024 * 1024)
        selected = tuple(_pair(limit, index=index + 1) for index in range(64))
        self.assertIsNone(experiments._require_numeric_ablation_selected_output_capacity(selected))
        with self.assertRaisesRegex(ExperimentError, "existing total byte bound"):
            experiments._require_numeric_ablation_selected_output_capacity((*selected, _pair(1, index=65)))
        below = (*selected[:-1], _pair(limit - 1, index=64), _pair(1, index=65))
        self.assertIsNone(experiments._require_numeric_ablation_selected_output_capacity(below))

    def test_no_logical_type_filter_can_exempt_an_oversized_selected_output(self):
        for logical_type in ("generic_ml_ablation", "model", "predictions", "metrics", "log", "unrelated_name"):
            with self.subTest(logical_type=logical_type):
                selected = (_pair(1), _pair(MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES + 1,
                                           index=2, logical_type=logical_type))
                with self.assertRaisesRegex(ExperimentError, "selected output size"):
                    experiments._require_numeric_ablation_selected_output_capacity(selected)

    def test_collection_shape_bound_and_empty_set_add_no_new_evidence_semantics(self):
        pair = _pair(1)
        # Missing scientific outputs are still rejected by their ordinary
        # owners; this helper only counts selected metadata and grants nothing.
        self.assertIsNone(experiments._require_numeric_ablation_selected_output_capacity(()))
        for wrong in ([pair], (pair[0],), ((pair[0],),), ((pair[0], pair[1], pair[1]),),
                      pair * 2, (pair,) * (experiments.MAX_OUTPUT_ARTIFACTS + 1)):
            with self.subTest(type=type(wrong)), self.assertRaises(ExperimentError):
                experiments._require_numeric_ablation_selected_output_capacity(wrong)

    def test_size_scalars_and_container_subclasses_are_rejected_before_hooks(self):
        hooks = []
        def trap(*args, **kwargs):
            hooks.append("called")
            raise AssertionError("capacity arithmetic invoked a custom hook")
        class IntHook(int):
            __eq__ = __lt__ = __le__ = __gt__ = __ge__ = __add__ = __radd__ = trap
        class TupleHook(tuple):
            __iter__ = __len__ = __getitem__ = trap
        for position in (0, 1):
            for wrong in (True, False, 1.0, None, IntHook(1)):
                pair = _pair(1)
                object.__setattr__(pair[position], "size", wrong)
                with self.subTest(position=position, type=type(wrong)), self.assertRaises(ExperimentError):
                    experiments._require_numeric_ablation_selected_output_capacity((pair,))
        for wrong in (TupleHook((_pair(1),)), (TupleHook(_pair(1)),)):
            with self.assertRaises(ExperimentError):
                experiments._require_numeric_ablation_selected_output_capacity(wrong)
        self.assertEqual(hooks, [])

    def test_profile_presence_and_complete_metadata_pass_follow_full_source_identity(self):
        function = _function(experiments._load_scientific_execution_candidate)
        spec_call, = _calls(function, "_require_scientific_execution_spec_and_inputs")
        preparation_call, = _calls(function, "require_scientific_execution_preparation")
        selector, = [node for node in function.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "numeric_ablation_outputs"
                             for target in node.targets)]
        self.assertEqual(ast.unparse(selector.value),
                         "SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY in thaw_json(spec.metadata)")
        identity_guard, = [node for node in function.body if isinstance(node, ast.If)
                           and "manifest_record.parent_artifacts" in ast.unparse(node.test)]
        full_pass, = [node for node in function.body if isinstance(node, ast.If)
                      and isinstance(node.test, ast.Name) and node.test.id == "numeric_ablation_outputs"]
        output_loop, = [node for node in function.body if isinstance(node, ast.For)
                        and ast.unparse(node.iter) == "manifest.artifacts"]
        self.assertLess(preparation_call.lineno, spec_call.lineno)
        self.assertLess(spec_call.lineno, identity_guard.lineno)
        self.assertLess(identity_guard.end_lineno, selector.lineno)
        self.assertLess(selector.lineno, full_pass.lineno)
        self.assertLess(full_pass.end_lineno, output_loop.lineno)
        get_metadata, = _registry_calls(full_pass, "get_metadata")
        capacity, = _calls(full_pass, "_require_numeric_ablation_selected_output_capacity")
        count_guard = full_pass.body[0]
        self.assertIsInstance(count_guard, ast.If)
        self.assertEqual(ast.unparse(count_guard.test),
                         "len(manifest.artifacts) > 4 * len(spec.seeds) + len(spec.required_ablations) or len(manifest.ablations) > len(spec.required_ablations)")
        self.assertLess(count_guard.end_lineno, get_metadata.lineno)
        self.assertEqual(count_guard.orelse, [])
        self.assertEqual(len(count_guard.body), 1)
        self.assertIsInstance(count_guard.body[0], ast.Raise)
        # Evaluate the actual, exact asserted predicate on inert count-only
        # objects, not a replacement scientific owner. Empty/partial FAILED or
        # TIMEOUT observations survive these upper bounds; later owners must
        # establish complete identities and numeric eligibility independently.
        predicate = compile(ast.Expression(body=count_guard.test), "<actual-count-bound>", "eval")
        for seed_count, required_count in ((1, 0), (1, 1), (2, 3), (24, 1000)):
            maximum = 4 * seed_count + required_count
            spec = SimpleNamespace(seeds=(None,) * seed_count, required_ablations=(None,) * required_count)
            for output_count, ablation_count, rejected in (
                (0, 0, False), (1, 0, False), (maximum // 2, required_count // 2, False),
                (maximum, required_count, False), (maximum + 1, 0, True),
                (0, required_count + 1, True), (maximum + 1, required_count + 1, True),
            ):
                manifest = SimpleNamespace(artifacts=(None,) * output_count, ablations=(None,) * ablation_count)
                with self.subTest(seed_count=seed_count, required_count=required_count,
                                  output_count=output_count, ablation_count=ablation_count):
                    self.assertIs(eval(predicate, {"__builtins__": {}, "len": len},
                                       {"spec": spec, "manifest": manifest}), rejected)
        self.assertLess(get_metadata.lineno, capacity.lineno)
        self.assertEqual(ast.unparse(capacity.args[0]), "selected_output_metadata")
        generator, = [node for node in ast.walk(full_pass) if isinstance(node, ast.GeneratorExp)]
        self.assertEqual(ast.unparse(generator.elt), "(descriptor, registry.get_metadata(descriptor.sha256))")
        self.assertEqual(len(generator.generators), 1)
        self.assertEqual(ast.unparse(generator.generators[0].iter), "manifest.artifacts")
        self.assertEqual(generator.generators[0].ifs, [])
        self.assertEqual(_registry_calls(full_pass, "verify"), [])
        self.assertEqual(_registry_calls(full_pass, "get_bytes"), [])
        spec_owner = _function(experiments._require_scientific_execution_spec_and_inputs)
        policy_call, = _calls(spec_owner, "resolve_scientific_numeric_ablation_binding")
        self.assertEqual(ast.unparse(policy_call),
                         "resolve_scientific_numeric_ablation_binding(registry, spec=spec, expected_contract_artifact_sha256=spec_record.parent_artifacts[0])")

    def test_per_read_recheck_and_legacy_absence_preserve_existing_owner_sequence(self):
        function = _function(experiments._load_scientific_execution_candidate)
        output_loop, = [node for node in function.body if isinstance(node, ast.For)
                        and ast.unparse(node.iter) == "manifest.artifacts"]
        read_try = output_loop.body[0]
        self.assertIsInstance(read_try, ast.Try)
        self.assertEqual(len(read_try.body), 4)
        self.assertEqual(ast.unparse(read_try.body[0]), "registry.verify(descriptor.sha256, raise_on_error=True)")
        self.assertEqual(ast.unparse(read_try.body[1]), "output_record = registry.get_metadata(descriptor.sha256)")
        guard = read_try.body[2]
        self.assertIsInstance(guard, ast.If)
        self.assertEqual(ast.unparse(guard.test), "numeric_ablation_outputs")
        self.assertEqual(guard.orelse, [])
        call, = _calls(guard, "_require_numeric_ablation_selected_output_capacity")
        self.assertEqual(ast.unparse(call), "_require_numeric_ablation_selected_output_capacity(((descriptor, output_record),))")
        self.assertEqual(ast.unparse(read_try.body[3]), "output_bytes = registry.get_bytes(descriptor.sha256)")
        # Both new calls occur only under the same presence-selected guard;
        # absent legacy metadata therefore preserves the original read path.
        self.assertEqual(len(_calls(function, "_require_numeric_ablation_selected_output_capacity")), 2)
        full_pass, = [node for node in function.body if isinstance(node, ast.If)
                      and isinstance(node.test, ast.Name) and node.test.id == "numeric_ablation_outputs"]
        self.assertEqual(full_pass.orelse, [])
        metadata_guard = output_loop.body[1]
        expected = ast.parse(textwrap.dedent('''
            output_record.logical_type != f"experiment_output.{descriptor.logical_type}" \\
                or output_record.creator_role is not Role.EXPERIMENT_RUNNER \\
                or output_record.size != descriptor.size \\
                or output_record.size != len(output_bytes) \\
                or output_record.validation_result != "PASS" \\
                or not output_record.frozen \\
                or output_record.parent_artifacts != (manifest_record.sha256, spec_record.sha256)
        '''), mode="eval").body
        self.assertEqual(ast.dump(metadata_guard.test), ast.dump(expected))

    def test_capacity_helper_is_pure_and_does_not_relabel_registry_allocation_guarantees(self):
        function = _function(experiments._require_numeric_ablation_selected_output_capacity)
        self.assertEqual(_registry_calls(function, "get_bytes"), [])
        self.assertEqual(_registry_calls(function, "get_metadata"), [])
        self.assertEqual(_registry_calls(function, "verify"), [])
        self.assertNotIn("logical_type", {node.attr for node in ast.walk(function) if isinstance(node, ast.Attribute)})
        doc = ast.get_docstring(function)
        self.assertIn("not allocations", doc)
        self.assertIn("Neither this preflight", doc)
        self.assertIn("is an atomic first-allocation/race guard", doc)

    def test_real_missing_preparation_refuses_before_any_admission_without_owner_mocks(self):
        with TemporaryDirectory(prefix="numeric-output-capacity-negative-") as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "registry")
            ledger = EventLedger(root, "events.jsonl")
            before_records = registry.list_records()
            before_events = ledger.events()
            with self.assertRaisesRegex(ExperimentError, "cannot be reopened"):
                experiments._load_scientific_execution_candidate(
                    registry, ledger,
                    preparation_artifact_sha256="1" * 64,
                    output_manifest_artifact_sha256="2" * 64,
                    environment_artifact_sha256="3" * 64,
                    isolation_attestation_artifact_sha256="4" * 64,
                    backend_attestation_artifact_sha256="5" * 64,
                    execution_activity_artifact_sha256=None,
                    expected_ledger_run_id="capacity-ledger", expected_execution_run_id="capacity-execution",
                )
            self.assertEqual(registry.list_records(), before_records)
            self.assertEqual(ledger.events(), before_events)


if __name__ == "__main__":
    unittest.main()
