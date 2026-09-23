"""Finite pure controls: no scientific authority, execution or adequacy evidence.

No registry, ledger, private issuer, owner-PASS stub, provider or trust root is
used. The local source labels/hashes are deliberately caller-reproducible.
"""

from dataclasses import FrozenInstanceError, fields, replace
from fractions import Fraction
import itertools
import unittest

from scientist_one import generic_ml_ablation as ablation
from scientist_one.generic_ml_projection import (
    GENERIC_ML_DATASET_ROW_SCHEMA,
    MAX_GENERIC_ML_INTEGER_MAGNITUDE,
    GenericMLClassificationRow,
    GenericMLLinearModel,
)
from scientist_one.security import canonical_json_bytes, sha256_bytes


def _intervention(**changes):
    return replace(ablation.GenericMLFeatureIntervention(
        ablation_id="ablation-a", hypothesis_id="hypothesis-a", component_id="feature-group-a",
        candidate_condition_id="candidate", baseline_condition_id="baseline",
        intervention_condition_id="candidate-zero-feature-a", feature_indices=(0,),
    ), **changes)


def _row(unit_id="unit-a", features=(-1, 0), label=0):
    body = {"schema_version": GENERIC_ML_DATASET_ROW_SCHEMA, "unit_id": unit_id,
            "features": list(features), "label": label}
    return GenericMLClassificationRow(unit_id, sha256_bytes(canonical_json_bytes(body)),
                                      features, label)


def _model(*, seed=7, role="CANDIDATE", condition=None, weights=((-1, 3), (1, -2)),
           bias=(0, 0), labels=(0, 1)):
    return GenericMLLinearModel(
        seed=seed, role=role, condition_id=condition or ("candidate" if role == "CANDIDATE" else "baseline"),
        class_labels=labels, weights=weights, bias=bias,
        parameter_count=len(labels) * (len(weights[0]) + 1),
    )


def _pairs(seeds=(7,)):
    return tuple((_model(seed=seed), _model(seed=seed, role="BASELINE",
                                          weights=((0, 2), (0, -3)), bias=(1, -1)))
                 for seed in seeds)


def _rows():
    return (_row(), _row("unit-b", (1, 0), 1), _row("unit-c", (0, 1), 0))


def _derive(*, intervention=None, pairs=None, rows=None, **changes):
    selected_rows = _rows() if rows is None else rows
    args = {"model_pairs": _pairs() if pairs is None else pairs, "rows": selected_rows,
            "expected_seed_order": (7,), "expected_unit_ids": tuple(row.unit_id for row in selected_rows),
            "expected_unit_hashes": tuple(row.unit_hash for row in selected_rows)}
    args.update(changes)
    return ablation.derive_generic_ml_ablation_grid(
        _intervention() if intervention is None else intervention, **args)


def _reference_predict(model, features):
    # Independent finite arithmetic, not a call to the implementation predictor.
    scores = []
    for class_index in range(len(model.class_labels)):
        score = model.bias[class_index]
        for feature_index in range(len(features)):
            score += model.weights[class_index][feature_index] * features[feature_index]
        scores.append(score)
    best_index = 0
    for class_index in range(1, len(scores)):
        if scores[class_index] > scores[best_index]:
            best_index = class_index
    return model.class_labels[best_index]


class GenericMLFeatureInterventionTests(unittest.TestCase):
    def test_closed_intervention_codec_and_golden_bytes(self):
        value = _intervention()
        self.assertEqual(ablation.GenericMLFeatureIntervention.from_dict(value.to_dict()), value)
        self.assertEqual(canonical_json_bytes(value.to_dict()), (
            b'{"ablation_id":"ablation-a","baseline_condition_id":"baseline",'
            b'"candidate_condition_id":"candidate","component_id":"feature-group-a",'
            b'"feature_indices":[0],"hypothesis_id":"hypothesis-a",'
            b'"intervention_condition_id":"candidate-zero-feature-a",'
            b'"operator":"ZERO_DECLARED_INPUT_FEATURE_WEIGHTS_V1",'
            b'"schema_version":"generic-ml-feature-intervention/v1",'
            b'"scope":"DECLARED_FEATURE_CONTRIBUTION_INTERVENTION_ONLY"}'
        ))
        for name in ("schema_version", "operator", "scope"):
            with self.subTest(name=name), self.assertRaises(ablation.GenericMLAblationError):
                _intervention(**{name: "another-profile"})
        for name in value.to_dict():
            wire = value.to_dict()
            del wire[name]
            with self.subTest(missing=name), self.assertRaises(ablation.GenericMLAblationError):
                ablation.GenericMLFeatureIntervention.from_dict(wire)
        wire = value.to_dict()
        wire["scientific_evidence_eligible"] = True
        with self.assertRaises(ablation.GenericMLAblationError):
            ablation.GenericMLFeatureIntervention.from_dict(wire)
        wire = value.to_dict()
        wire["feature_indices"] = (0,)
        with self.assertRaises(ablation.GenericMLAblationError):
            ablation.GenericMLFeatureIntervention.from_dict(wire)

    def test_feature_group_is_nonempty_sorted_unique_and_bounded(self):
        for indices in ((), (1, 0), (0, 0), (-1,), (1024,), (True,), (0.0,), [0],
                        tuple(range(1025))):
            with self.subTest(indices=indices), self.assertRaises(ablation.GenericMLAblationError):
                _intervention(feature_indices=indices)
        self.assertEqual(_intervention(feature_indices=tuple(range(1024))).feature_indices[-1], 1023)
        with self.assertRaisesRegex(ablation.GenericMLAblationError, "outside the model shape"):
            _derive(intervention=_intervention(feature_indices=(2,)))

    def test_native_identifiers_and_three_distinct_conditions(self):
        for name in ("ablation_id", "hypothesis_id", "component_id", "candidate_condition_id",
                     "baseline_condition_id", "intervention_condition_id"):
            for wrong in ("", "spaces are invalid", True, None):
                with self.subTest(name=name, wrong=wrong), self.assertRaises(ablation.GenericMLAblationError):
                    _intervention(**{name: wrong})
        for change in ({"candidate_condition_id": "baseline"},
                       {"intervention_condition_id": "candidate"},
                       {"intervention_condition_id": "baseline"}):
            with self.subTest(change=change), self.assertRaisesRegex(ablation.GenericMLAblationError, "distinct"):
                _intervention(**change)

    def test_immutable_value_and_detached_codec_view(self):
        value = _intervention()
        with self.assertRaises(FrozenInstanceError):
            value.feature_indices = (1,)
        wire = value.to_dict()
        wire["feature_indices"][0] = 1
        self.assertEqual(value.feature_indices, (0,))
        self.assertFalse(any("artifact" in field.name or "hash" in field.name for field in fields(value)))


class GenericMLAblationArithmeticTests(unittest.TestCase):
    def test_derived_grid_owns_declaration_despite_later_caller_mutation(self):
        intervention = _intervention()
        result = _derive(intervention=intervention)
        before = canonical_json_bytes(result.to_dict())
        self.assertIsNot(result.intervention, intervention)
        self.assertEqual(result.intervention, intervention)
        object.__setattr__(intervention, "component_id", "changed-component")
        object.__setattr__(intervention, "feature_indices", (1,))
        self.assertEqual(result.intervention.component_id, "feature-group-a")
        self.assertEqual(result.intervention.feature_indices, (0,))
        self.assertEqual(canonical_json_bytes(result.to_dict()), before)

    def test_only_declared_coefficients_change_bias_baseline_and_inputs_preserved(self):
        pairs, rows = _pairs(), _rows()
        before = repr((pairs, rows))
        result = _derive(pairs=pairs, rows=rows)
        candidate, baseline = pairs[0]
        projected = result.seed_results[0]
        self.assertEqual(projected.ablated_model.weights, ((0, 3), (0, -2)))
        self.assertEqual(projected.ablated_model.bias, candidate.bias)
        self.assertEqual(projected.ablated_model.class_labels, candidate.class_labels)
        self.assertEqual(projected.ablated_model.parameter_count, candidate.parameter_count)
        self.assertEqual(projected.ablated_model.role, "ABLATION")
        self.assertEqual(projected.ablated_model.condition_id, "candidate-zero-feature-a")
        self.assertEqual(projected.changed_coefficient_count, 2)
        self.assertEqual(projected.candidate_predictions, (0, 1, 0))
        self.assertEqual(projected.baseline_predictions, (0, 0, 0))
        self.assertEqual(projected.ablated_predictions, (0, 0, 0))
        self.assertEqual(projected.baseline_predictions,
                         tuple(_reference_predict(baseline, row.features) for row in rows))
        self.assertEqual(repr((pairs, rows)), before)
        self.assertEqual(result.reference_product_count, 36)
        self.assertEqual((result.candidate_minus_ablated_numerator,
                          result.ablated_minus_baseline_numerator,
                          result.candidate_minus_baseline_numerator, result.effect_denominator),
                         (1, 0, 1, 3))
        self.assertEqual([(unit.candidate_correct_count, unit.baseline_correct_count,
                           unit.ablated_correct_count) for unit in result.unit_counts],
                         [(1, 1, 1), (1, 0, 0), (1, 1, 1)])

    def test_multifeature_group_all_classes_preserves_nondeclared_weights_and_nonzero_bias(self):
        candidate = _model(weights=((1, 2, 3), (-4, 5, 6), (7, 8, -9)),
                           bias=(5, -7, 11), labels=(-2, 4, 9))
        baseline = replace(candidate, role="BASELINE", condition_id="baseline")
        result = _derive(intervention=_intervention(feature_indices=(0, 2)),
                         pairs=((candidate, baseline),), rows=(_row(features=(1, -1, 1), label=4),))
        model = result.seed_results[0].ablated_model
        self.assertEqual(model.weights, ((0, 2, 0), (0, 5, 0), (0, 8, 0)))
        self.assertEqual(model.bias, (5, -7, 11))
        self.assertEqual(model.class_labels, (-2, 4, 9))
        self.assertEqual(result.seed_results[0].changed_coefficient_count, 6)

    def test_ties_use_first_class_and_confirmatory_grid_may_omit_other_classes(self):
        candidate = _model(weights=((1, 0), (1, 0), (1, 0)), bias=(2, 2, 2), labels=(-3, 2, 8))
        baseline = replace(candidate, role="BASELINE", condition_id="baseline")
        result = _derive(pairs=((candidate, baseline),), rows=(_row(features=(1, 0), label=-3),))
        seed = result.seed_results[0]
        self.assertEqual(seed.candidate_predictions, (-3,))
        self.assertEqual(seed.ablated_predictions, (-3,))
        self.assertEqual(result.candidate_minus_ablated_numerator, 0)

    def test_zero_and_reversed_accuracy_effects_remain_valid(self):
        cases = (((0, 0), 0, 0), ((1, 0), 0, -1), ((1, 0), 1, 1))
        for features, label, effect in cases:
            with self.subTest(features=features, label=label):
                result = _derive(rows=(_row(features=features, label=label),))
                self.assertEqual(result.candidate_minus_ablated_numerator, effect)
                self.assertEqual(result.effect_denominator, 1)
                self.assertEqual(result.seed_results[0].changed_coefficient_count, 2)

    def test_seed_no_change_is_retained_but_whole_grid_coefficient_noop_is_refused(self):
        pairs = list(_pairs((7, 3)))
        pairs[1] = (replace(pairs[1][0], weights=((0, 3), (0, -2))), pairs[1][1])
        result = _derive(pairs=tuple(pairs), expected_seed_order=(7, 3))
        self.assertEqual(result.seed_order, (7, 3))
        self.assertEqual(tuple(seed.changed_coefficient_count for seed in result.seed_results), (2, 0))
        self.assertEqual(result.seed_results[1].candidate_predictions,
                         result.seed_results[1].ablated_predictions)
        self.assertEqual(tuple(unit.seed_count for unit in result.unit_counts), (2, 2, 2))
        self.assertEqual((result.candidate_minus_ablated_numerator, result.effect_denominator), (1, 6))
        with self.assertRaisesRegex(ablation.GenericMLAblationError, "whole requested seed grid.*no-op"):
            _derive(pairs=(pairs[1],), expected_seed_order=(3,))

    def test_finite_independent_oracle_and_exact_rational_effects(self):
        rows = tuple(_row(f"unit-{index}", values, index % 2) for index, values in
                     enumerate(itertools.product((-1, 0, 1), repeat=2)))
        for weight in (-2, -1, 1, 2):
            pairs = tuple((
                _model(seed=seed, weights=((weight, seed - 3), (-weight, 1)), bias=(2, -1)),
                _model(seed=seed, role="BASELINE", weights=((1, 0), (0, 1)), bias=(-1, 2)),
            ) for seed in (7, 3))
            result = _derive(pairs=pairs, rows=rows, expected_seed_order=(7, 3))
            expected_counts = [[0, 0, 0] for _ in rows]
            for seed_index, (candidate, baseline) in enumerate(pairs):
                changed = replace(candidate, weights=((0, candidate.weights[0][1]),
                                                       (0, candidate.weights[1][1])))
                expected_predictions = []
                for condition, model in enumerate((candidate, baseline, changed)):
                    predictions = tuple(_reference_predict(model, row.features) for row in rows)
                    expected_predictions.append(predictions)
                    for index, prediction in enumerate(predictions):
                        expected_counts[index][condition] += int(prediction == rows[index].label)
                actual = result.seed_results[seed_index]
                self.assertEqual((actual.candidate_predictions, actual.baseline_predictions,
                                  actual.ablated_predictions), tuple(expected_predictions))
            for unit, expected in zip(result.unit_counts, expected_counts, strict=True):
                self.assertEqual((unit.candidate_correct_count, unit.baseline_correct_count,
                                  unit.ablated_correct_count), tuple(expected))
                self.assertEqual(Fraction(unit.candidate_minus_ablated_numerator, unit.effect_denominator),
                                 Fraction(expected[0] - expected[2], 2))
            self.assertEqual(Fraction(result.candidate_minus_ablated_numerator, result.effect_denominator),
                             sum((Fraction(c - a, 2) for c, _, a in expected_counts), Fraction()) / len(rows))
            self.assertEqual(result.candidate_minus_baseline_numerator,
                             result.candidate_minus_ablated_numerator + result.ablated_minus_baseline_numerator)

    def test_extreme_integer_products_are_exact_without_float_conversion(self):
        limit = MAX_GENERIC_ML_INTEGER_MAGNITUDE
        candidate = _model(weights=((-limit, limit), (limit, -limit)), bias=(limit, -limit))
        baseline = replace(candidate, role="BASELINE", condition_id="baseline")
        rows = (_row(features=(limit, -limit), label=1), _row("unit-b", (-limit, limit), 0))
        result = _derive(pairs=((candidate, baseline),), rows=rows)
        self.assertEqual(result.seed_results[0].candidate_predictions, (1, 0))
        self.assertEqual(result.seed_results[0].ablated_predictions, (1, 0))
        self.assertEqual(result.candidate_minus_ablated_numerator, 0)

    def test_output_is_immutable_consistent_and_has_no_inference_or_authority_fields(self):
        result = _derive()
        with self.assertRaises(FrozenInstanceError):
            result.reference_labels = ()
        with self.assertRaises(FrozenInstanceError):
            result.seed_results[0].ablated_model.bias = (1, 1)
        with self.assertRaises(FrozenInstanceError):
            result.unit_counts[0].candidate_correct_count = 0
        view = result.to_dict()
        view["seed_results"][0]["ablated_model"]["weights"][0][0] = 9
        view["unit_counts"][0]["candidate_correct_count"] = -1
        self.assertEqual(result.seed_results[0].ablated_model.weights[0][0], 0)
        self.assertEqual(result.unit_counts[0].candidate_correct_count, 1)
        forbidden = {"p_value", "adjusted_p_value", "alpha", "status", "decision", "scientific_evidence_eligible",
                     "authority_id", "artifact_sha256", "record_hash", "interval_low", "interval_high"}
        def walk(value):
            if isinstance(value, dict):
                self.assertFalse(forbidden.intersection(value))
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
            else:
                self.assertIsNot(type(value), float)
        walk(result.to_dict())
        for change in ({"reference_labels": (1, 1, 0)},
                       {"unit_counts": (replace(result.unit_counts[0], candidate_correct_count=0),
                                        *result.unit_counts[1:])},
                       {"seed_results": ()}):
            with self.subTest(change=change), self.assertRaises(ablation.GenericMLAblationError):
                replace(result, **change)


class GenericMLAblationClosureTests(unittest.TestCase):
    def test_seed_permutation_missing_duplicate_and_wrong_role_or_condition_rejected(self):
        pairs = _pairs((7, 3))
        changes = (pairs[::-1], pairs[:1], (pairs[0], pairs[0]),
                   ((pairs[0][1], pairs[0][0]), pairs[1]),
                   ((replace(pairs[0][0], condition_id="another-candidate"), pairs[0][1]), pairs[1]))
        for wrong in changes:
            with self.subTest(wrong=wrong), self.assertRaises(ablation.GenericMLAblationError):
                _derive(pairs=wrong, expected_seed_order=(7, 3))
        for seeds in ((7, 7), (True,), (7.0,), (-1,), (MAX_GENERIC_ML_INTEGER_MAGNITUDE + 1,), (), [7]):
            with self.subTest(seeds=seeds), self.assertRaises(ablation.GenericMLAblationError):
                _derive(expected_seed_order=seeds)

    def test_unit_permutation_missing_duplicate_and_expected_identity_changes_rejected(self):
        rows = _rows()
        ids, hashes = tuple(row.unit_id for row in rows), tuple(row.unit_hash for row in rows)
        for wrong in (rows[::-1], rows[:2], (rows[0], rows[0], rows[2])):
            with self.subTest(wrong=wrong), self.assertRaises(ablation.GenericMLAblationError):
                _derive(rows=wrong, expected_unit_ids=ids, expected_unit_hashes=hashes)
        for changes in ({"expected_unit_ids": (ids[0], ids[0], ids[2])},
                        {"expected_unit_hashes": (hashes[0], hashes[0], hashes[2])},
                        {"expected_unit_ids": ids[::-1]},
                        {"expected_unit_hashes": hashes[::-1]},
                        {"expected_unit_ids": ids[:2]}, {"expected_unit_ids": ()},
                        {"expected_unit_ids": list(ids)}, {"expected_unit_hashes": list(hashes)}):
            with self.subTest(changes=changes), self.assertRaises(ablation.GenericMLAblationError):
                _derive(rows=rows, **changes)

    def test_unit_hash_content_label_and_shape_closure_are_recomputed(self):
        row = _row()
        for wrong in (replace(row, features=(1, 0)), replace(row, label=1),
                      replace(row, unit_hash="a" * 64), replace(row, unit_hash="A" * 64),
                      replace(row, features=(1,)), replace(row, features=(1, 0, 0)),
                      _row(label=2), replace(row, label=True), replace(row, features=(False, 0)),
                      replace(row, features=(float("nan"), 0)),
                      replace(row, features=(MAX_GENERIC_ML_INTEGER_MAGNITUDE + 1, 0)),
                      replace(row, features=[1, 0])):
            with self.subTest(wrong=wrong), self.assertRaises(ablation.GenericMLAblationError):
                _derive(rows=(wrong,))

    def test_models_require_full_equal_class_shape_and_exact_parameter_count(self):
        candidate, baseline = _pairs()[0]
        for wrong in (replace(candidate, class_labels=(1, 0)), replace(candidate, class_labels=(0, 0)),
                      replace(candidate, class_labels=(0,)), replace(candidate, class_labels=(True, 1)),
                      replace(candidate, weights=((1, 2),)), replace(candidate, weights=((1,), (2, 3))),
                      replace(candidate, bias=(0,)), replace(candidate, bias=(False, 0)),
                      replace(candidate, weights=((1.0, 0), (0, 1))),
                      replace(candidate, weights=((MAX_GENERIC_ML_INTEGER_MAGNITUDE + 1, 0), (0, 1))),
                      replace(candidate, parameter_count=5), replace(candidate, parameter_count=6.0),
                      replace(candidate, parameter_count=True), replace(candidate, role="ABLATION")):
            with self.subTest(wrong=wrong), self.assertRaises(ablation.GenericMLAblationError):
                _derive(pairs=((wrong, baseline),))
        for wrong in (replace(baseline, class_labels=(-1, 1)),
                      _model(role="BASELINE", weights=((1,), (2,)), bias=(0, 0)),
                      _model(role="BASELINE", labels=(0, 1, 2), weights=((1, 0), (2, 0), (3, 0)), bias=(0, 0, 0))):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(ablation.GenericMLAblationError, "closure differs"):
                _derive(pairs=((candidate, wrong),))

    def test_native_subclasses_rejected_without_coercion_iteration_comparison_or_prediction_hooks(self):
        hooks = []
        def trap(*args, **kwargs):
            hooks.append("called")
            raise AssertionError("custom scalar/container/model hook was invoked")
        class IntHook(int):
            __int__ = __index__ = __eq__ = __lt__ = __le__ = __gt__ = __ge__ = __mul__ = __add__ = trap
            __hash__ = trap
        class StrHook(str):
            __str__ = __eq__ = __hash__ = trap
        class TupleHook(tuple):
            __len__ = __iter__ = __getitem__ = trap
        class DictHook(dict):
            __len__ = __iter__ = __getitem__ = trap
        class ListHook(list):
            __len__ = __iter__ = __getitem__ = trap
        class ModelHook(GenericMLLinearModel):
            predict = trap
        class RowHook(GenericMLClassificationRow):
            __getattribute__ = trap
        candidate, baseline = _pairs()[0]
        rows = _rows()
        model_values = {name: getattr(candidate, name) for name in candidate.__dataclass_fields__}
        row_values = {name: getattr(rows[0], name) for name in rows[0].__dataclass_fields__}
        calls = [
            lambda: _intervention(ablation_id=StrHook("ablation-a")),
            lambda: _intervention(feature_indices=(IntHook(0),)),
            lambda: _intervention(feature_indices=TupleHook((0,))),
            lambda: _derive(expected_seed_order=(IntHook(7),)),
            lambda: _derive(expected_seed_order=TupleHook((7,))),
            lambda: _derive(expected_unit_ids=(StrHook("unit-a"), "unit-b", "unit-c")),
            lambda: _derive(expected_unit_hashes=(StrHook(rows[0].unit_hash), *tuple(r.unit_hash for r in rows[1:]))),
            lambda: _derive(pairs=TupleHook(_pairs())),
            lambda: _derive(pairs=((ModelHook(**model_values), baseline),)),
            lambda: _derive(pairs=((replace(candidate, weights=((IntHook(-1), 3), (1, -2))), baseline),)),
            lambda: _derive(pairs=((replace(candidate, class_labels=(IntHook(0), 1)), baseline),)),
            lambda: _derive(pairs=((replace(candidate, bias=(IntHook(0), 0)), baseline),)),
            lambda: _derive(pairs=((replace(candidate, role=StrHook("CANDIDATE")), baseline),)),
            lambda: _derive(pairs=((replace(candidate, parameter_count=IntHook(6)), baseline),)),
            lambda: ablation.derive_generic_ml_ablation_grid(
                _intervention(), model_pairs=_pairs(), rows=(RowHook(**row_values), *rows[1:]),
                expected_seed_order=(7,), expected_unit_ids=tuple(r.unit_id for r in rows),
                expected_unit_hashes=tuple(r.unit_hash for r in rows)),
            lambda: ablation.GenericMLFeatureIntervention.from_dict(DictHook(_intervention().to_dict())),
            lambda: ablation.GenericMLFeatureIntervention.from_dict(
                {**_intervention().to_dict(), "feature_indices": ListHook([0])}),
        ]
        # Bypass the _derive test convenience's own reads of row identity.
        for field, wrong in (("unit_id", StrHook("unit-a")), ("unit_hash", StrHook(rows[0].unit_hash)),
                             ("label", IntHook(0)), ("features", (IntHook(-1), 0)),
                             ("features", TupleHook((-1, 0)))):
            tampered = replace(rows[0], **{field: wrong})
            calls.append(lambda tampered=tampered: ablation.derive_generic_ml_ablation_grid(
                _intervention(), model_pairs=_pairs(), rows=(tampered, *rows[1:]), expected_seed_order=(7,),
                expected_unit_ids=tuple(r.unit_id for r in rows), expected_unit_hashes=tuple(r.unit_hash for r in rows)))
        for index, call in enumerate(calls):
            with self.subTest(index=index), self.assertRaises(ablation.GenericMLAblationError):
                call()
        self.assertEqual(hooks, [])

    def test_object_setattr_tampered_declaration_revalidated_before_arithmetic(self):
        intervention = _intervention()
        object.__setattr__(intervention, "feature_indices", (True,))
        with self.assertRaises(ablation.GenericMLAblationError):
            _derive(intervention=intervention)

    def test_mutable_containers_do_not_enter_immutable_inputs_or_output(self):
        candidate, baseline = _pairs()[0]
        for changes in ({"model_pairs": list(_pairs())}, {"model_pairs": ([candidate, baseline],)},
                        {"rows": list(_rows())}):
            with self.subTest(changes=changes), self.assertRaises(ablation.GenericMLAblationError):
                _derive(**changes)
        for name, wrong in (("class_labels", [0, 1]), ("weights", [[-1, 3], [1, -2]]),
                            ("weights", ([-1, 3], (1, -2))), ("bias", [0, 0])):
            with self.subTest(name=name), self.assertRaises(ablation.GenericMLAblationError):
                _derive(pairs=((replace(candidate, **{name: wrong}), baseline),))
        result = _derive()
        for name in ("seed_results", "unit_counts", "reference_labels"):
            with self.subTest(name=name), self.assertRaises(ablation.GenericMLAblationError):
                replace(result, **{name: list(getattr(result, name))})

    def test_descriptive_output_rejects_wrong_seed_model_grid_and_counts(self):
        result = _derive()
        seed = result.seed_results[0]
        for change in ({"seed": 3}, {"changed_coefficient_count": True},
                       {"candidate_predictions": (True, 1, 0)}, {"baseline_predictions": (0,)},
                       {"ablated_predictions": (0, 2, 0)}):
            with self.subTest(change=change), self.assertRaises(ablation.GenericMLAblationError):
                replace(seed, **change)
        for model in (replace(seed.ablated_model, condition_id="wrong-intervention"),
                      replace(seed.ablated_model, weights=((1, 3), (0, -2)))):
            with self.subTest(model=model), self.assertRaises(ablation.GenericMLAblationError):
                replace(result, seed_results=(replace(seed, ablated_model=model),))
        for count in (False, -1, 2, 1.0):
            with self.subTest(count=count), self.assertRaises(ablation.GenericMLAblationError):
                replace(result.unit_counts[0], candidate_correct_count=count)
        with self.assertRaisesRegex(ablation.GenericMLAblationError, "no-op"):
            replace(result, seed_results=(replace(seed, changed_coefficient_count=0),))


class GenericMLAblationCapacityTests(unittest.TestCase):
    def test_exact_row_and_seed_caps_preserve_complete_small_dimension_grids(self):
        rows = tuple(_row(f"unit-{index}", (0, 0), 0) for index in range(4096))
        result = _derive(rows=rows)
        self.assertEqual(len(result.unit_counts), 4096)
        self.assertEqual(result.effect_denominator, 4096)
        with self.assertRaises(ablation.GenericMLAblationError):
            _derive(rows=(*rows, _row("unit-extra")))
        seeds = tuple(range(24))
        result = _derive(rows=(_row(),), pairs=_pairs(seeds), expected_seed_order=seeds)
        self.assertEqual(result.seed_order, seeds)
        with self.assertRaises(ablation.GenericMLAblationError):
            _derive(pairs=_pairs(tuple(range(25))), expected_seed_order=tuple(range(25)))

    def test_model_and_source_grid_parameter_caps(self):
        # 64*(1023+1)=65,536 per model and two seeds/two source roles reach
        # exactly 262,144 source parameters. Derived third grids add work,
        # not a silent third frozen source-model allocation allowance.
        weights = tuple((1,) * 1023 for _ in range(64))
        candidate = _model(weights=weights, labels=tuple(range(64)), bias=(0,) * 64)
        baseline = replace(candidate, role="BASELINE", condition_id="baseline")
        pairs = ((candidate, baseline), (replace(candidate, seed=3), replace(baseline, seed=3)))
        result = _derive(rows=(_row(features=(0,) * 1023),), pairs=pairs, expected_seed_order=(7, 3))
        self.assertEqual(result.seed_results[0].ablated_model.parameter_count, 65536)
        with self.assertRaisesRegex(ablation.GenericMLAblationError, "source grid parameter capacity"):
            _derive(rows=(_row(features=(0,) * 1023),), pairs=(*pairs, (replace(candidate, seed=1), replace(baseline, seed=1))),
                    expected_seed_order=(7, 3, 1))
        candidate = _model(weights=tuple((1,) * 1024 for _ in range(64)), labels=tuple(range(64)), bias=(0,) * 64)
        with self.assertRaisesRegex(ablation.GenericMLAblationError, "parameter"):
            _derive(pairs=((candidate, replace(candidate, role="BASELINE", condition_id="baseline")),))

    def test_reference_product_ceiling_exact_arithmetic_and_pre_prediction_refusal(self):
        # 3*2,730*1*2*1,024 = 16,773,120 is below; one more row is above.
        self.assertEqual(ablation._require_grid_capacity(2730, 1, 2, 1024), 16_773_120)
        with self.assertRaisesRegex(ablation.GenericMLAblationError, "reference-product capacity"):
            ablation._require_grid_capacity(2731, 1, 2, 1024)
        candidate = _model(weights=((1,) * 1024, (0,) * 1024))
        baseline = replace(candidate, role="BASELINE", condition_id="baseline")
        rows = tuple(_row(f"unit-{index}", (0,) * 1024) for index in range(2731))
        # Real native source shapes, not a mocked predictor or authority. The
        # expected capacity exception is selected before row hashes/predictions.
        with self.assertRaisesRegex(ablation.GenericMLAblationError, "reference-product capacity"):
            _derive(pairs=((candidate, baseline),), rows=rows)

    def test_class_feature_and_native_dimension_bounds(self):
        for dimensions in ((1, 1, 1, 1), (1, 1, 1025, 1), (1, 1, 2, 0), (1, 1, 2, 1025),
                           (True, 1, 2, 1), (1, 1.0, 2, 1), (0, 1, 2, 1), (4097, 1, 2, 1),
                           (1, 25, 2, 1)):
            with self.subTest(dimensions=dimensions), self.assertRaises(ablation.GenericMLAblationError):
                ablation._require_grid_capacity(*dimensions)
        self.assertEqual(ablation._require_grid_capacity(1, 1, 1024, 1), 3072)


if __name__ == "__main__":
    unittest.main()
