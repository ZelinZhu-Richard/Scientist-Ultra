"""Pure compact byte-relation controls, not execution or scientific evidence.

All grids are actually derived with the pure integer operator. Source hashes
are inert strings: no registry, authority, issuer, mocks, provider or keys are
used. Matching these bytes does not authenticate any of those sources.
"""

from dataclasses import fields, replace
import inspect
import json
import unittest

from scientist_one.generic_ml_ablation import (
    GENERIC_ML_FEATURE_INTERVENTION_SCOPE,
    GenericMLAblationGrid,
    GenericMLFeatureIntervention,
    derive_generic_ml_ablation_grid,
)
from scientist_one.artifacts import ArtifactRecord
from scientist_one.models import Role
from scientist_one.generic_ml_ablation_output import (
    GENERIC_ML_ABLATION_OUTPUT_SCHEMA,
    MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES,
    GenericMLAblationOutputError,
    build_generic_ml_ablation_output,
    require_generic_ml_ablation_output,
)
from scientist_one.generic_ml_projection import (
    GENERIC_ML_DATASET_ROW_SCHEMA,
    MAX_GENERIC_ML_INTEGER_MAGNITUDE,
    GenericMLClassificationRow,
    GenericMLLinearModel,
)
from scientist_one.security import (
    DEFAULT_MAX_JSON_BYTES,
    DEFAULT_MAX_JSON_ITEMS,
    UnsafeSerializationError,
    canonical_json_bytes,
    sha256_bytes,
)


HASH_CONTEXT_FIELDS = (
    "frozen_run_spec_artifact_sha256", "frozen_run_spec_record_hash", "frozen_run_spec_sha256",
    "configuration_artifact_sha256", "configuration_record_hash", "evaluator_artifact_sha256",
    "evaluator_record_hash", "confirmatory_split_authority_artifact_sha256",
    "confirmatory_split_authority_record_hash", "method_definition_artifact_sha256",
    "method_definition_record_hash",
)
MODEL_FIELDS = (
    "candidate_model_artifact_sha256", "baseline_model_artifact_sha256",
)


def _hash(number):
    return f"{number:064x}"


def _context(seeds=(7, 3)):
    return {
        "execution_run_id": "execution-run-a",
        **{name: _hash(index + 1) for index, name in enumerate(HASH_CONTEXT_FIELDS)},
        "seed_model_bindings": tuple((seed, *(_hash(100 + 2 * index + offset) for offset in range(2)))
                                     for index, seed in enumerate(seeds)),
    }


def _row(unit_id, features, label):
    body = {"schema_version": GENERIC_ML_DATASET_ROW_SCHEMA,
            "unit_id": unit_id, "features": list(features), "label": label}
    return GenericMLClassificationRow(unit_id, sha256_bytes(canonical_json_bytes(body)), features, label)


def _grid(*, seeds=(7, 3), rows=None, labels=(0, 1)):
    if rows is None:
        rows = (_row("unit-a", (0,), labels[0]),
                _row("unit-b", (1,), labels[0]),
                _row("unit-c", (-1,), labels[1]))
    intervention = GenericMLFeatureIntervention(
        ablation_id="ablation-a", hypothesis_id="hypothesis-a", component_id="feature-group-a",
        candidate_condition_id="candidate-a", baseline_condition_id="baseline-a",
        intervention_condition_id="candidate-a-zero-feature", feature_indices=(0,),
    )
    pairs = tuple((
        GenericMLLinearModel(seed, "CANDIDATE", "candidate-a", labels, ((-1,), (1,)), (0, 0), 4),
        GenericMLLinearModel(seed, "BASELINE", "baseline-a", labels, ((0,), (0,)), (0, 0), 4),
    ) for seed in seeds)
    return derive_generic_ml_ablation_grid(
        intervention, model_pairs=pairs, rows=rows, expected_seed_order=seeds,
        expected_unit_ids=tuple(row.unit_id for row in rows),
        expected_unit_hashes=tuple(row.unit_hash for row in rows),
    )


def _json_item_count(value):
    # Independent count of JSON values/containers, matching the documented
    # item budget's convention (object keys are not separate value items).
    if type(value) is dict:
        return 1 + sum(_json_item_count(item) for item in value.values())
    if type(value) is list:
        return 1 + sum(_json_item_count(item) for item in value)
    return 1


class GenericMLAblationOutputTests(unittest.TestCase):
    def test_exact_closed_wire_and_successful_pure_byte_relation(self):
        grid, context = _grid(), _context()
        expected = {
            "schema_version": "generic-ml-ablation-output/v1",
            "scope": "DECLARED_FEATURE_CONTRIBUTION_INTERVENTION_ONLY",
            **{name: value for name, value in context.items() if name != "seed_model_bindings"},
            "intervention": grid.intervention.to_dict(),
            "unit_ids": ["unit-a", "unit-b", "unit-c"],
            "unit_hashes": list(grid.unit_hashes),
            "seed_outputs": [
                {"seed": binding[0], **dict(zip(MODEL_FIELDS, binding[1:], strict=True)),
                 "ablated_predictions": [0, 0, 0]}
                for binding in context["seed_model_bindings"]
            ],
        }
        raw = build_generic_ml_ablation_output(grid, **context)
        self.assertEqual(raw, canonical_json_bytes(expected) + b"\n")
        self.assertEqual(json.loads(raw), expected)
        self.assertIsNone(require_generic_ml_ablation_output(raw, grid, **context))
        self.assertEqual(GENERIC_ML_ABLATION_OUTPUT_SCHEMA, expected["schema_version"])
        self.assertEqual(GENERIC_ML_FEATURE_INTERVENTION_SCOPE, expected["scope"])
        self.assertIs(type(raw), bytes)
        self.assertTrue(raw.endswith(b"}\n"))

    def test_every_context_field_is_exactly_bound_and_not_normalized(self):
        grid, context = _grid(), _context()
        raw = build_generic_ml_ablation_output(grid, **context)
        for name in ("execution_run_id", *HASH_CONTEXT_FIELDS):
            changed = {**context, name: "different-run" if name == "execution_run_id" else _hash(900)}
            with self.subTest(name=name):
                self.assertNotEqual(build_generic_ml_ablation_output(grid, **changed), raw)
                with self.assertRaisesRegex(GenericMLAblationOutputError, "rebuilt compact bytes"):
                    require_generic_ml_ablation_output(raw, grid, **changed)
        for seed_index in range(2):
            for offset in range(1, 3):
                changed_bindings = list(context["seed_model_bindings"])
                changed_row = list(changed_bindings[seed_index])
                changed_row[offset] = _hash(999)
                changed_bindings[seed_index] = tuple(changed_row)
                changed = {**context, "seed_model_bindings": tuple(changed_bindings)}
                with self.subTest(seed_index=seed_index, offset=offset):
                    with self.assertRaisesRegex(GenericMLAblationOutputError, "rebuilt compact bytes"):
                        require_generic_ml_ablation_output(raw, grid, **changed)

    def test_model_bindings_require_complete_exact_seed_order_and_three_native_fields(self):
        grid, context = _grid(), _context()
        bindings = context["seed_model_bindings"]
        invalid = ((), bindings[:1], (*bindings, bindings[0]), bindings[::-1],
                   (bindings[0], bindings[0]), list(bindings), (list(bindings[0]), bindings[1]),
                   (bindings[0][:2], bindings[1]), ((*bindings[0], _hash(4)), bindings[1]),
                   ((bindings[0][0], bindings[0][1], _hash(800), bindings[0][2], _hash(801)), bindings[1]),
                   ((True, *bindings[0][1:]), bindings[1]),
                   ((7.0, *bindings[0][1:]), bindings[1]),
                   ((-1, *bindings[0][1:]), bindings[1]),
                   ((MAX_GENERIC_ML_INTEGER_MAGNITUDE + 1, *bindings[0][1:]), bindings[1]))
        for index, wrong in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(GenericMLAblationOutputError):
                build_generic_ml_ablation_output(grid, **{**context, "seed_model_bindings": wrong})
        for offset in range(1, 3):
            for wrong in ("f" * 63, "F" * 64, "g" * 64, "", 1, True, None, b"a" * 64):
                row = list(bindings[0])
                row[offset] = wrong
                with self.subTest(offset=offset, wrong=wrong), self.assertRaises(GenericMLAblationOutputError):
                    build_generic_ml_ablation_output(grid, **{**context, "seed_model_bindings": (tuple(row), bindings[1])})

    def test_context_requires_native_identifier_and_exact_lowercase_hashes(self):
        grid, context = _grid(), _context()
        for name in ("execution_run_id", *HASH_CONTEXT_FIELDS):
            invalid = ("", " bad value ", None, True, 1, b"native-bytes-are-not-text")
            if name != "execution_run_id":
                invalid += ("F" * 64, "g" * 64, "a" * 63, "a" * 65)
            for wrong in invalid:
                with self.subTest(name=name, wrong=wrong), self.assertRaises(GenericMLAblationOutputError):
                    build_generic_ml_ablation_output(grid, **{**context, name: wrong})

    def test_missing_extra_tampered_and_reordered_observed_fields_are_rejected(self):
        grid, context = _grid(), _context()
        raw = build_generic_ml_ablation_output(grid, **context)
        original = json.loads(raw)
        for name in original:
            changed = json.loads(raw)
            del changed[name]
            with self.subTest(missing=name), self.assertRaises(GenericMLAblationOutputError):
                require_generic_ml_ablation_output(canonical_json_bytes(changed) + b"\n", grid, **context)
        for name in original["seed_outputs"][0]:
            changed = json.loads(raw)
            del changed["seed_outputs"][0][name]
            with self.subTest(seed_missing=name), self.assertRaises(GenericMLAblationOutputError):
                require_generic_ml_ablation_output(canonical_json_bytes(changed) + b"\n", grid, **context)
        mutations = (
            lambda value: value.update(schema_version="generic-ml-ablation-output/v2"),
            lambda value: value.update(scope="MECHANISTIC_PROOF"),
            lambda value: value.update(labels=[0, 0, 1]),
            lambda value: value.update(status="PASS"),
            lambda value: value.update(policy={"metric": "accuracy"}),
            lambda value: value.update(metadata={"caller": "extra"}),
            lambda value: value.update(output_artifact_sha256=_hash(1000)),
            lambda value: value["unit_ids"].reverse(),
            lambda value: value["unit_hashes"].reverse(),
            lambda value: value["seed_outputs"].reverse(),
            lambda value: value["seed_outputs"].pop(),
            lambda value: value["seed_outputs"][0]["ablated_predictions"].pop(),
            lambda value: value["seed_outputs"][0]["ablated_predictions"].__setitem__(0, 1),
            lambda value: value["seed_outputs"][0].update(candidate_predictions=[0, 1, 0]),
            lambda value: value["seed_outputs"][0].update(candidate_model_record_hash=_hash(900)),
            lambda value: value["seed_outputs"][0].update(baseline_model_record_hash=_hash(901)),
            lambda value: value["intervention"].update(feature_indices=[1]),
        )
        for index, mutate in enumerate(mutations):
            changed = json.loads(raw)
            mutate(changed)
            with self.subTest(index=index), self.assertRaises(GenericMLAblationOutputError):
                require_generic_ml_ablation_output(canonical_json_bytes(changed) + b"\n", grid, **context)

    def test_canonical_spelling_order_and_exactly_one_newline_are_required(self):
        grid, context = _grid(), _context()
        raw = build_generic_ml_ablation_output(grid, **context)
        observed = json.loads(raw)
        reordered = dict(reversed(tuple(observed.items())))
        for wrong in (raw[:-1], raw + b"\n", raw[:-1] + b"\r\n", b" " + raw, raw + b" ",
                      json.dumps(observed, indent=2).encode() + b"\n",
                      json.dumps(reordered, separators=(",", ":")).encode() + b"\n",
                      raw.replace(b'"seed":7', b'"seed":7.0'),
                      raw.replace(b'"seed":7', b'"seed":7,"seed":7'),
                      b"\xff\xfe\n", b'{"unclosed":\n', b"null\n"):
            with self.subTest(wrong=wrong[:80]), self.assertRaisesRegex(GenericMLAblationOutputError, "rebuilt compact bytes"):
                require_generic_ml_ablation_output(wrong, grid, **context)

    def test_grid_internal_leaf_and_arithmetic_replay_is_unconditional(self):
        context = _context()
        for mutation in (
            lambda grid: object.__setattr__(grid, "reference_labels", (1, 0, 1)),
            lambda grid: object.__setattr__(grid.unit_counts[0], "candidate_correct_count", 0),
            lambda grid: object.__setattr__(grid.seed_results[0], "candidate_predictions", (1, 1, 0)),
            lambda grid: object.__setattr__(grid.seed_results[0].ablated_model, "weights", ((1,), (0,))),
            lambda grid: object.__setattr__(grid.intervention, "scope", "MECHANISTIC_PROOF"),
        ):
            grid = _grid()
            raw = build_generic_ml_ablation_output(grid, **context)
            mutation(grid)
            with self.assertRaisesRegex(GenericMLAblationOutputError, "supplied grid is invalid"):
                build_generic_ml_ablation_output(grid, **context)
            with self.assertRaisesRegex(GenericMLAblationOutputError, "supplied grid is invalid"):
                require_generic_ml_ablation_output(raw, grid, **context)

    def test_zero_reversed_and_positive_descriptive_effects_are_all_serialized(self):
        context = _context((7,))
        for features, label, expected in (((0,), 0, 0), ((1,), 0, -1), ((1,), 1, 1)):
            grid = _grid(seeds=(7,), rows=(_row("unit-a", features, label),))
            with self.subTest(features=features, label=label):
                self.assertEqual(grid.candidate_minus_ablated_numerator, expected)
                raw = build_generic_ml_ablation_output(grid, **context)
                self.assertEqual(json.loads(raw)["seed_outputs"][0]["ablated_predictions"], [0])
                self.assertIsNone(require_generic_ml_ablation_output(raw, grid, **context))

    def test_unsupported_metadata_and_policy_arguments_are_not_accepted(self):
        grid, context = _grid(), _context()
        raw = build_generic_ml_ablation_output(grid, **context)
        for name in ("metadata", "policy", "metric_id", "status", "authority_id", "output_artifact_sha256"):
            with self.subTest(name=name):
                with self.assertRaises(TypeError):
                    build_generic_ml_ablation_output(grid, **context, **{name: {"not": "a source"}})
                with self.assertRaises(TypeError):
                    require_generic_ml_ablation_output(raw, grid, **context, **{name: {"not": "a source"}})
        build = inspect.signature(build_generic_ml_ablation_output)
        require = inspect.signature(require_generic_ml_ablation_output)
        self.assertEqual(set(build.parameters), {"grid", "execution_run_id", *HASH_CONTEXT_FIELDS, "seed_model_bindings"})
        self.assertEqual(set(require.parameters), {"raw", *build.parameters})
        self.assertFalse(any(value.kind is inspect.Parameter.VAR_KEYWORD for value in build.parameters.values()))

    def test_raw_type_size_preflight_is_before_any_grid_rebuilding(self):
        context = _context()
        self.assertEqual(MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES, DEFAULT_MAX_JSON_BYTES)
        for raw in (b"", None, bytearray(b"{}\n"), memoryview(b"{}\n"), "{}\n",
                    b"x" * (DEFAULT_MAX_JSON_BYTES + 1)):
            # An invalid grid gives a distinct error if rebuilding is reached.
            with self.subTest(type=type(raw)), self.assertRaisesRegex(GenericMLAblationOutputError, "raw output requires native bytes"):
                require_generic_ml_ablation_output(raw, object(), **context)
        # Exactly the ceiling includes LF and is admitted to rebuilding, not
        # silently given a ceiling+1 exception for the newline.
        raw = b"x" * (DEFAULT_MAX_JSON_BYTES - 1) + b"\n"
        with self.assertRaisesRegex(GenericMLAblationOutputError, "exact native GenericMLAblationGrid"):
            require_generic_ml_ablation_output(raw, object(), **context)

    def test_hostile_native_subclasses_never_invoke_hooks(self):
        hooks = []
        def trap(*args, **kwargs):
            hooks.append("called")
            raise AssertionError("hostile hook was invoked")
        class StrHook(str):
            __str__ = __eq__ = __hash__ = trap
        class IntHook(int):
            __int__ = __index__ = __eq__ = __lt__ = __le__ = __gt__ = __ge__ = __hash__ = trap
        class TupleHook(tuple):
            __iter__ = __len__ = __getitem__ = trap
        class BytesHook(bytes):
            __len__ = __eq__ = trap
        class GridHook(GenericMLAblationGrid):
            __getattribute__ = trap
        grid, context = _grid(), _context()
        raw = build_generic_ml_ablation_output(grid, **context)
        bindings = context["seed_model_bindings"]
        wrong_grid = object.__new__(GridHook)
        calls = [
            lambda: build_generic_ml_ablation_output(wrong_grid, **context),
            lambda: require_generic_ml_ablation_output(BytesHook(raw), grid, **context),
            lambda: build_generic_ml_ablation_output(grid, **{**context, "seed_model_bindings": TupleHook(bindings)}),
            lambda: build_generic_ml_ablation_output(grid, **{**context, "seed_model_bindings": (TupleHook(bindings[0]), bindings[1])}),
            lambda: build_generic_ml_ablation_output(grid, **{**context, "seed_model_bindings": ((IntHook(7), *bindings[0][1:]), bindings[1])}),
        ]
        for name in ("execution_run_id", *HASH_CONTEXT_FIELDS):
            calls.append(lambda name=name: build_generic_ml_ablation_output(grid, **{**context, name: StrHook(context[name])}))
        for offset in range(1, 3):
            changed = list(bindings[0])
            changed[offset] = StrHook(changed[offset])
            changed = tuple(changed)
            calls.append(lambda changed=changed: build_generic_ml_ablation_output(grid, **{**context, "seed_model_bindings": (changed, bindings[1])}))
        for index, call in enumerate(calls):
            with self.subTest(index=index), self.assertRaises(GenericMLAblationOutputError):
                call()
        for mutation in (
            lambda current: object.__setattr__(current, "seed_results", TupleHook(current.seed_results)),
            lambda current: object.__setattr__(current.intervention, "ablation_id", StrHook("ablation-a")),
            lambda current: object.__setattr__(current.seed_results[0], "ablated_predictions", (IntHook(0), 0, 0)),
            lambda current: object.__setattr__(current.unit_counts[0], "candidate_correct_count", IntHook(2)),
            lambda current: object.__setattr__(current.seed_results[0].ablated_model, "bias", (IntHook(0), 0)),
        ):
            current = _grid()
            mutation(current)
            with self.assertRaises(GenericMLAblationOutputError):
                build_generic_ml_ablation_output(current, **context)
        self.assertEqual(hooks, [])

    def test_source_objects_are_not_mutated_and_no_scores_or_authority_enter_wire(self):
        grid, context = _grid(), _context()
        before = grid.to_dict()
        raw = build_generic_ml_ablation_output(grid, **context)
        require_generic_ml_ablation_output(raw, grid, **context)
        self.assertEqual(grid.to_dict(), before)
        value = json.loads(raw)
        self.assertEqual(set(value), {"schema_version", "scope", "intervention", "unit_ids", "unit_hashes", "seed_outputs",
                                     "execution_run_id", *HASH_CONTEXT_FIELDS})
        self.assertEqual(set(value["seed_outputs"][0]), {"seed", *MODEL_FIELDS, "ablated_predictions"})
        self.assertEqual(set(value["intervention"]), {field.name for field in fields(grid.intervention)})
        for output in value["seed_outputs"]:
            for predicted in output["ablated_predictions"]:
                self.assertIs(type(predicted), int)

    def test_maximum_real_4096_by_24_grid_fits_compact_existing_serializer_limits(self):
        limit = MAX_GENERIC_ML_INTEGER_MAGNITUDE
        labels = (-limit, limit)
        rows = tuple(_row(f"unit-{index:04d}-" + "x" * 118, (1 if index % 2 else -1,), labels[index % 2])
                     for index in range(4096))
        self.assertTrue(all(len(row.unit_id) == 128 for row in rows))
        seeds = tuple(range(24))
        grid = _grid(seeds=seeds, rows=rows, labels=labels)
        self.assertEqual(grid.reference_product_count, 589_824)
        context = _context(seeds)
        raw = build_generic_ml_ablation_output(grid, **context)
        self.assertIsNone(require_generic_ml_ablation_output(raw, grid, **context))
        wire = json.loads(raw)
        self.assertEqual(len(wire["unit_ids"]), 4096)
        self.assertEqual(len(wire["unit_hashes"]), 4096)
        self.assertEqual(tuple(output["seed"] for output in wire["seed_outputs"]), seeds)
        self.assertTrue(all(len(output["ablated_predictions"]) == 4096 for output in wire["seed_outputs"]))
        self.assertTrue(all(prediction == -limit for output in wire["seed_outputs"] for prediction in output["ablated_predictions"]))
        self.assertLessEqual(len(raw), DEFAULT_MAX_JSON_BYTES)
        self.assertLessEqual(_json_item_count(wire), DEFAULT_MAX_JSON_ITEMS)
        # Demonstrates why the compact profile is necessary without patching
        # the serializer or granting any source/scientific owner a PASS.
        with self.assertRaisesRegex(UnsafeSerializationError, "item limit"):
            canonical_json_bytes(grid.to_dict())

    def test_output_metadata_fits_and_same_execution_record_hashes_are_not_future_inputs(self):
        # Inert byte/metadata construction only, not a registered execution or
        # source owner. Construct A bytes BEFORE the manifest and model records.
        grid, context = _grid(seeds=(7,)), _context((7,))
        raw = build_generic_ml_ablation_output(grid, **context)
        output_sha = sha256_bytes(raw)
        manifest_sha = sha256_bytes(canonical_json_bytes({
            "inert_output_hashes": [*context["seed_model_bindings"][0][1:], output_sha],
        }))
        def record(digest, schema, logical_type, size):
            return ArtifactRecord(
                sha256=digest, path=f"objects/{digest}", relative_path=f"objects/{digest}",
                metadata_path=f"metadata/{digest}.json", logical_type=logical_type,
                schema_version=schema, mime_type="application/json", size=size,
                origin="inert pure metadata acyclicity test", creator_role=Role.EXPERIMENT_RUNNER,
                creation_command=("inert-byte-relation",),
                parent_artifacts=(manifest_sha, context["frozen_run_spec_artifact_sha256"]),
                validation_result="PASS", frozen=True, created_at="2026-09-06T00:00:00Z",
            )
        output_record = record(output_sha, GENERIC_ML_ABLATION_OUTPUT_SCHEMA, "experiment_output.ablation_output", len(raw))
        model_record = record(context["seed_model_bindings"][0][1], "1.0", "experiment_output.generic_ml_model", 1)
        changed_model_record = replace(model_record, parent_artifacts=(_hash(500), context["frozen_run_spec_artifact_sha256"]), record_hash=None)
        self.assertNotEqual(model_record.record_hash, changed_model_record.record_hash)
        self.assertEqual(output_record.sha256, output_sha)
        self.assertEqual(output_record.parent_artifacts[0], manifest_sha)
        self.assertLessEqual(len(output_record.schema_version), 32)
        self.assertNotIn(b'"candidate_model_record_hash"', raw)
        self.assertNotIn(b'"baseline_model_record_hash"', raw)
        self.assertEqual(build_generic_ml_ablation_output(grid, **context), raw)


if __name__ == "__main__":
    unittest.main()
