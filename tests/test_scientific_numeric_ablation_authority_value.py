"""Pure inert numeric-ablation value controls, never scientific publication.

All source/custody hashes and state bindings are constructed shape fixtures.
No registry owner, issuer, trust root, signature or positive source mock is
used. The only ArtifactRecord is unregistered, PENDING and unfrozen.
"""

from dataclasses import FrozenInstanceError, fields, replace
from fractions import Fraction
import json
import unittest

from scientist_one import scientific_numeric_ablation_authority_value as values
from scientist_one.artifacts import ArtifactRecord
from scientist_one.errors import ValidationError
from scientist_one.generic_ml_ablation import GenericMLFeatureIntervention
from scientist_one.generic_ml_projection import MAX_GENERIC_ML_INTEGER_MAGNITUDE
from scientist_one.roles import Role
from scientist_one.scientific_design import ScientificAblationStateBinding
from scientist_one.security import canonical_json_bytes, sha256_bytes


def _h(number):
    return f"{number:064x}"


def _arguments():
    intervention = GenericMLFeatureIntervention(
        ablation_id="ablation-a", hypothesis_id="hypothesis-a", component_id="feature-a",
        candidate_condition_id="experiment-a", baseline_condition_id="baseline-a",
        intervention_condition_id="intervention-a", feature_indices=(0,),
    )
    states = tuple(ScientificAblationStateBinding(
        object_type=kind, object_id=object_id, revision=1, content_hash=_h(201 + index),
        artifact_sha256=_h(7 + index), artifact_record_hash=_h(107 + index),
        materialization_event_id=f"event-{event_index}", materialization_event_hash=_h(301 + index),
        materialization_event_index=event_index,
    ) for index, (kind, object_id, event_index) in enumerate((
        ("Result", "result-a", 4), ("Run", "execution-a", 3),
        ("Method", "method-a", 1), ("Experiment", "experiment-a", 2),
    )))
    result = {
        "authority_id": "numeric-ablation-authority:" + values.numeric_ablation_slot_hash(
            ledger_run_id="ledger-a", execution_run_id="execution-a", result_artifact_sha256=_h(7),
            contract_artifact_sha256=_h(1), ablation_id="ablation-a",
        ),
        "ledger_run_id": "ledger-a", "execution_run_id": "execution-a",
        "intervention": intervention, "metric_id": "accuracy",
        "state_bindings": states, "unit_count": 3, "seed_order": (7, 3),
        "changed_coefficient_counts": (1, 0), "activity_sequence": 5,
        "candidate_correct_total": 4, "baseline_correct_total": 3, "ablated_correct_total": 2,
        "source_artifact_hashes": tuple(_h(index) for index in range(1, 11)),
        "source_artifact_record_hashes": tuple(_h(index) for index in range(101, 111)),
        "custody_artifact_hashes": tuple(_h(index) for index in range(1, 11)),
        "custody_artifact_record_hashes": tuple(_h(index) for index in range(101, 111)),
    }
    for index, (artifact_name, record_name) in enumerate((
        ("contract_artifact_sha256", "contract_record_hash"),
        ("promotion_artifact_sha256", "promotion_record_hash"),
        ("assessment_artifact_sha256", "assessment_record_hash"),
        ("execution_artifact_sha256", "execution_record_hash"),
        ("projection_artifact_sha256", "projection_record_hash"),
        ("ablation_output_artifact_sha256", "ablation_output_record_hash"),
    )):
        result[artifact_name], result[record_name] = _h(index + 1), _h(index + 101)
    return result


def _value(**changes):
    return values.ScientificNumericAblationAuthority(**{**_arguments(), **changes})


def _authority(**changes):
    """Shared inert value fixture; no source or publication authority exists."""
    return _value(**changes)


class ScientificNumericAblationAuthorityValueTests(unittest.TestCase):
    def test_slot_golden_and_five_identity_axes_exclude_outcomes_records_and_time(self):
        args = {"ledger_run_id": "ledger-a", "execution_run_id": "execution-a",
                "result_artifact_sha256": _h(7), "contract_artifact_sha256": _h(1), "ablation_id": "ablation-a"}
        golden = "dccd26dadcdd80ae11371df50db1d8573b2d1b294ad2385b94d38a3ff9bab8c0"
        self.assertEqual(values.numeric_ablation_slot_hash(**args), golden)
        self.assertEqual(values.numeric_ablation_slot_hash(**args), sha256_bytes(canonical_json_bytes({
            "schema_version": "scientific-ablation-authority/v2", **args,
        })))
        keys = {golden}
        for name in args:
            changed = _h(999) if "sha256" in name else "different-identity"
            keys.add(values.numeric_ablation_slot_hash(**{**args, name: changed}))
        self.assertEqual(len(keys), 6)
        for name in ("candidate_correct_total", "contract_record_hash", "timestamp", "activity_sequence"):
            with self.subTest(name=name), self.assertRaises(TypeError):
                values.numeric_ablation_slot_hash(**args, **{name: 1})
        value = _value()
        self.assertEqual(value.authority_id, "numeric-ablation-authority:" + golden)
        self.assertEqual(value.canonical_object_id, "numeric-ablation:" + golden)
        changed_records = tuple(_h(999) if index == 0 else digest
                                for index, digest in enumerate(value.source_artifact_record_hashes))
        changed = replace(value, contract_record_hash=_h(999), source_artifact_record_hashes=changed_records,
                          custody_artifact_record_hashes=changed_records, candidate_correct_total=0,
                          baseline_correct_total=0, ablated_correct_total=6, activity_sequence=9)
        self.assertEqual(changed.authority_id, value.authority_id)
        self.assertEqual(changed.canonical_object_id, value.canonical_object_id)
        self.assertNotEqual(changed.canonical_bytes(), value.canonical_bytes())

    def test_closed_payload_roundtrip_and_exact_canonical_metadata(self):
        value = _value()
        wire = value.to_dict()
        self.assertEqual(set(wire), {field.name for field in fields(value)})
        self.assertEqual(wire["schema_version"], "scientific-ablation-authority/v2")
        self.assertEqual(values.ScientificNumericAblationAuthority.from_dict(wire), value)
        self.assertEqual(value.canonical_bytes(), canonical_json_bytes(wire) + b"\n")
        self.assertEqual(json.loads(value.canonical_bytes()), wire)
        expected_metadata = {
            "schema_version": "scientific-numeric-ablation-canonical/v1",
            "authority_id": value.authority_id, "intervention": value.intervention.to_dict(),
            "metric_id": "accuracy", "unit_count": 3, "seed_order": [7, 3],
            "changed_coefficient_counts": [1, 0], "activity_sequence": 5,
            "candidate_correct_total": 4, "baseline_correct_total": 3, "ablated_correct_total": 2,
            "scope": "DECLARED_FEATURE_CONTRIBUTION_INTERVENTION_ONLY",
            "replay_status": "DESCRIPTIVE_OUTPUT_VERIFIED", "scientific_evidence_eligible": False,
        }
        self.assertEqual(value.canonical_metadata(), expected_metadata)
        self.assertEqual(len(expected_metadata), 14)
        self.assertFalse(any("artifact" in name or "record_hash" in name for name in expected_metadata))
        self.assertFalse(hasattr(values, "is_numeric_ablation_metadata"))
        self.assertFalse(hasattr(value, "authoritative"))
        for name in ("status", "outcome", "p_value", "effect_size", "adjusted_p_value", "result_summary"):
            self.assertNotIn(name, wire)
            self.assertNotIn(name, expected_metadata)

    def test_negative_zero_and_positive_effects_remain_descriptive_and_ineligible(self):
        for candidate, baseline, ablated in ((4, 3, 2), (0, 2, 6), (3, 3, 3), (0, 0, 0), (6, 6, 6)):
            value = _value(candidate_correct_total=candidate, baseline_correct_total=baseline,
                           ablated_correct_total=ablated)
            with self.subTest(candidate=candidate, baseline=baseline, ablated=ablated):
                self.assertEqual(value.candidate_minus_ablated_numerator, candidate - ablated)
                self.assertEqual(value.ablated_minus_baseline_numerator, ablated - baseline)
                self.assertEqual(value.candidate_minus_baseline_numerator, candidate - baseline)
                self.assertEqual(value.effect_denominator, 6)
                self.assertEqual(Fraction(value.candidate_minus_ablated_numerator, value.effect_denominator),
                                 Fraction(candidate - ablated, 6))
                self.assertIs(value.scientific_evidence_eligible, False)
                self.assertEqual(value.replay_status, "DESCRIPTIVE_OUTPUT_VERIFIED")
        for wrong in (True, 0, None, "False"):
            with self.subTest(eligible=wrong), self.assertRaises(ValidationError):
                _value(scientific_evidence_eligible=wrong)
        for name in ("schema_version", "scope", "replay_status"):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                _value(**{name: "PASS"})

    def test_native_scalar_seed_changed_count_and_total_bounds(self):
        for name, bad_values in (
            ("unit_count", (0, -1, 4097, True, 3.0)),
            ("activity_sequence", (-1, 10000, True, 5.0)),
            ("candidate_correct_total", (-1, 7, True, 4.0)),
            ("baseline_correct_total", (-1, 7, True, 3.0)),
            ("ablated_correct_total", (-1, 7, True, 2.0)),
            ("seed_order", ((), (7, 7), (True, 3), (-1, 3), (MAX_GENERIC_ML_INTEGER_MAGNITUDE + 1, 3), list((7, 3)), tuple(range(25)))),
            ("changed_coefficient_counts", ((), (1,), (0, 0), (1, -1), (1, 65537), (1, True), [1, 0])),
        ):
            for wrong in bad_values:
                with self.subTest(name=name, wrong=wrong), self.assertRaises(ValidationError):
                    _value(**{name: wrong})
        value = _value(unit_count=4096, seed_order=tuple(range(24)), changed_coefficient_counts=(65536,) + (0,) * 23,
                       activity_sequence=9999, candidate_correct_total=4096 * 24,
                       baseline_correct_total=0, ablated_correct_total=4096 * 24)
        self.assertEqual(value.effect_denominator, 98_304)
        self.assertEqual(value.changed_coefficient_counts[1:], (0,) * 23)
        self.assertEqual(_value(seed_order=(MAX_GENERIC_ML_INTEGER_MAGNITUDE, 0)).seed_order,
                         (MAX_GENERIC_ML_INTEGER_MAGNITUDE, 0))

    def test_state_order_run_identity_topology_and_actual_revision_event_bounds(self):
        args = _arguments()
        original = args["state_bindings"]
        wrongs = (original[::-1], original[:3], (*original, original[0]),
                  (original[0], replace(original[1], object_id="another-run"), *original[2:]),
                  (replace(original[0], materialization_event_index=3), *original[1:]),
                  (*original[:2], replace(original[2], materialization_event_index=3), original[3]))
        for wrong in wrongs:
            with self.subTest(wrong=wrong), self.assertRaises(ValidationError):
                _value(state_bindings=wrong)
        for name, wrong in (("revision", True), ("revision", 1_000_001),
                            ("materialization_event_index", True), ("materialization_event_index", 10000)):
            states = _arguments()["state_bindings"]
            object.__setattr__(states[0], name, wrong)
            with self.subTest(name=name, wrong=wrong), self.assertRaises(ValidationError):
                _value(state_bindings=states)
        states = (replace(original[0], revision=1_000_000, materialization_event_index=9999),
                  original[1], replace(original[2], materialization_event_index=0), original[3])
        self.assertEqual(_value(state_bindings=states).state_bindings[0].revision, 1_000_000)

    def test_direct_sources_are_exact_ordered_six_pairs_then_four_state_roots(self):
        value = _value()
        for field in ("source_artifact_hashes", "source_artifact_record_hashes"):
            original = getattr(value, field)
            for wrong in (original[::-1], original[:-1], (*original, _h(999)),
                          (*original[:-1], original[0]), (*original[:-1], _h(999))):
                with self.subTest(field=field, wrong=wrong), self.assertRaises(ValidationError):
                    replace(value, **{field: wrong})
        for field in ("contract_artifact_sha256", "promotion_artifact_sha256", "assessment_artifact_sha256",
                      "execution_artifact_sha256", "projection_artifact_sha256", "ablation_output_artifact_sha256",
                      "contract_record_hash", "promotion_record_hash", "assessment_record_hash", "execution_record_hash",
                      "projection_record_hash", "ablation_output_record_hash"):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                replace(value, **{field: _h(999)})

    def test_custody_requires_sorted_unique_complete_shape_and_exact_direct_record_mapping(self):
        value = _value()
        for hashes, records in (
            (value.custody_artifact_hashes[::-1], value.custody_artifact_record_hashes[::-1]),
            (value.custody_artifact_hashes[:-1], value.custody_artifact_record_hashes[:-1]),
            ((*value.custody_artifact_hashes[:-1], _h(999)), value.custody_artifact_record_hashes),
            (value.custody_artifact_hashes, value.custody_artifact_record_hashes[::-1]),
            (value.custody_artifact_hashes, (*value.custody_artifact_record_hashes[:-1], _h(999))),
            ((*value.custody_artifact_hashes, value.custody_artifact_hashes[-1]), (*value.custody_artifact_record_hashes, _h(999))),
            ((*value.custody_artifact_hashes, _h(999)), (*value.custody_artifact_record_hashes, value.custody_artifact_record_hashes[-1])),
        ):
            with self.subTest(hashes=hashes, records=records), self.assertRaises(ValidationError):
                replace(value, custody_artifact_hashes=hashes, custody_artifact_record_hashes=records)
        # Extra shape-consistent ancestors are not independently authenticated:
        # their actual completeness/parents remain the full owner's obligation.
        extra = replace(value, custody_artifact_hashes=(*value.custody_artifact_hashes, _h(11)),
                        custody_artifact_record_hashes=(*value.custody_artifact_record_hashes, _h(111)))
        self.assertEqual(len(extra.custody_artifact_hashes), 11)
        self.assertEqual(extra.authority_id, value.authority_id)

    def test_native_codec_is_closed_at_every_level(self):
        value = _value()
        wire = value.to_dict()
        for name in wire:
            changed = value.to_dict()
            del changed[name]
            with self.subTest(missing=name), self.assertRaises(ValidationError):
                values.ScientificNumericAblationAuthority.from_dict(changed)
        for mutate in (
            lambda item: item.update(status="PASS"),
            lambda item: item["intervention"].update(meaningful_component_removal=True),
            lambda item: item["state_bindings"][0].update(scientific_evidence_eligible=True),
            lambda item: item["state_bindings"][0].pop("artifact_record_hash"),
            lambda item: item.update(seed_order=(7, 3)),
            lambda item: item.update(state_bindings=tuple(item["state_bindings"])),
            lambda item: item.update(authority_id="numeric-ablation-authority:" + _h(999)),
        ):
            changed = value.to_dict()
            mutate(changed)
            with self.assertRaises(ValidationError):
                values.ScientificNumericAblationAuthority.from_dict(changed)

    def test_input_leaf_detachment_frozen_values_and_returned_view_isolation(self):
        args = _arguments()
        value = values.ScientificNumericAblationAuthority(**args)
        before = value.canonical_bytes()
        self.assertIsNot(value.intervention, args["intervention"])
        self.assertTrue(all(left is not right for left, right in zip(value.state_bindings, args["state_bindings"], strict=True)))
        object.__setattr__(args["intervention"], "component_id", "relabeled-component")
        object.__setattr__(args["state_bindings"][0], "materialization_event_index", 9999)
        self.assertEqual(value.canonical_bytes(), before)
        with self.assertRaises(FrozenInstanceError):
            value.candidate_correct_total = 0
        changed = value.to_dict()
        changed["intervention"]["feature_indices"][0] = 1
        changed["state_bindings"][0]["object_id"] = "another-result"
        changed["custody_artifact_record_hashes"][0] = _h(999)
        metadata = value.canonical_metadata()
        metadata["seed_order"].reverse()
        self.assertEqual(value.canonical_bytes(), before)

    def test_foreign_native_subclasses_and_tampered_leaves_reject_without_hooks(self):
        hooks = []
        def trap(*args, **kwargs):
            hooks.append("called")
            raise AssertionError("foreign native hook invoked")
        class StrHook(str):
            __str__ = __eq__ = __hash__ = trap
        class IntHook(int):
            __int__ = __index__ = __eq__ = __lt__ = __le__ = __gt__ = __ge__ = __add__ = __sub__ = __hash__ = trap
        class TupleHook(tuple):
            __len__ = __iter__ = __getitem__ = trap
        class ListHook(list):
            __len__ = __iter__ = __getitem__ = trap
        class DictHook(dict):
            __len__ = __iter__ = __getitem__ = trap
        class StateHook(ScientificAblationStateBinding):
            __getattribute__ = trap
        class AuthorityHook(values.ScientificNumericAblationAuthority):
            __getattribute__ = trap
        value = _value()
        for field, wrong in (("authority_id", StrHook(value.authority_id)), ("metric_id", StrHook("accuracy")),
                             ("unit_count", IntHook(3)), ("seed_order", (IntHook(7), 3)),
                             ("candidate_correct_total", IntHook(4)), ("activity_sequence", IntHook(5)),
                             ("changed_coefficient_counts", (IntHook(1), 0)),
                             ("source_artifact_hashes", TupleHook(value.source_artifact_hashes)),
                             ("source_artifact_hashes", (StrHook(_h(1)), *value.source_artifact_hashes[1:])),
                             ("state_bindings", (object.__new__(StateHook), *value.state_bindings[1:]))):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                replace(value, **{field: wrong})
        for field, wrong in (("object_type", StrHook("Result")), ("revision", IntHook(1)),
                             ("artifact_record_hash", StrHook(_h(107))), ("materialization_event_index", IntHook(4))):
            args = _arguments()
            object.__setattr__(args["state_bindings"][0], field, wrong)
            with self.subTest(state_field=field), self.assertRaises(ValidationError):
                values.ScientificNumericAblationAuthority(**args)
        for wrong in (DictHook(value.to_dict()), {**value.to_dict(), "seed_order": ListHook([7, 3])},
                      {**value.to_dict(), "state_bindings": [DictHook(value.state_bindings[0].to_dict()),
                                                           *value.to_dict()["state_bindings"][1:]]}):
            with self.assertRaises(ValidationError):
                values.ScientificNumericAblationAuthority.from_dict(wrong)
        foreign = object.__new__(AuthorityHook)
        for method in (values.ScientificNumericAblationAuthority.to_dict,
                       values.ScientificNumericAblationAuthority.canonical_bytes,
                       values.ScientificNumericAblationAuthority.canonical_metadata,
                       values.ScientificNumericAblationAuthority.effect_denominator.fget,
                       values.ScientificNumericAblationAuthority.canonical_object_id.fget):
            with self.assertRaises(ValidationError):
                method(foreign)
        tampered = _value()
        object.__setattr__(tampered, "candidate_correct_total", IntHook(4))
        with self.assertRaises(ValidationError):
            _ = tampered.candidate_minus_ablated_numerator
        with self.assertRaises(ValidationError):
            tampered.canonical_metadata()
        self.assertEqual(hooks, [])

    def test_maximum_custody_and_existing_serialization_budgets(self):
        maximum = values.MAX_SCIENTIFIC_NUMERIC_ABLATION_CUSTODY_RECORDS
        self.assertEqual(maximum, 10_000)
        value = _value(custody_artifact_hashes=tuple(_h(index) for index in range(1, maximum + 1)),
                       custody_artifact_record_hashes=tuple(_h(index + 100) for index in range(1, maximum + 1)))
        self.assertLessEqual(len(value.canonical_bytes()), 4 * 1024 * 1024)
        with self.assertRaises(ValidationError):
            replace(value, custody_artifact_hashes=(*value.custody_artifact_hashes, _h(maximum + 1)),
                    custody_artifact_record_hashes=(*value.custody_artifact_record_hashes, _h(maximum + 101)))
        # Direct tests of the pure shared budget helper, not an invented
        # large authority or a changed serializer cap.
        self.assertIsInstance(values._bounded_bytes({"v": [0] * 49_998}), bytes)
        with self.assertRaisesRegex(ValidationError, "item"):
            values._bounded_bytes({"v": [0] * 49_999})
        cap = values.MAX_SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_BYTES
        self.assertEqual(cap, 4 * 1024 * 1024)
        self.assertEqual(len(values._bounded_bytes({"v": "x" * (cap - 9)})), cap)
        with self.assertRaisesRegex(ValidationError, "byte bound"):
            values._bounded_bytes({"v": "x" * (cap - 8)})

    def test_real_artifact_record_accepts_short_metadata_schema_without_any_publication(self):
        value = _value()
        raw = value.canonical_bytes()
        record = ArtifactRecord(
            sha256=sha256_bytes(raw), path="inert/authority.json", relative_path="inert/authority.json",
            metadata_path="inert/authority.metadata.json",
            logical_type=values.SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_LOGICAL_TYPE,
            schema_version=values.SCIENTIFIC_NUMERIC_ABLATION_AUTHORITY_ARTIFACT_SCHEMA_VERSION,
            mime_type="application/json", size=len(raw), origin="unregistered inert numeric value fixture",
            creator_role=Role.CLAIM_VERIFIER, creation_command=("test", "inert-value-metadata"),
            parent_artifacts=value.source_artifact_hashes, validation_result="PENDING", frozen=False,
            created_at="2026-01-01T00:00:00.000000Z",
        )
        self.assertEqual(record.schema_version, "2.0")
        self.assertLessEqual(len(record.schema_version), 32)
        self.assertEqual(record.logical_type, "scientific_ablation_authority")
        self.assertEqual(record.validation_result, "PENDING")
        self.assertFalse(record.frozen)
        self.assertIs(value.scientific_evidence_eligible, False)


if __name__ == "__main__":
    unittest.main()
