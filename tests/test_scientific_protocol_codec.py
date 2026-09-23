"""Real protocol JSON codec controls; no scientific authority or custody."""

from copy import deepcopy
from dataclasses import replace
import unittest

from scientist_one.security import canonical_json_bytes, safe_json_loads
from scientist_one.scientific_design import (
    ScientificPromotionError,
    _parse_scientific_confirmatory_protocol,
    _require_exact_keys,
)
from tests.test_protocol_contract_crosswalk import matching_protocol
from tests.test_scientific_design import make_contract


class ScientificProtocolCodecTests(unittest.TestCase):
    def setUp(self):
        self.protocol = matching_protocol(make_contract())
        # The persisted owner consumes decoded JSON, not dataclass asdict(),
        # whose immutable sequences are still tuples.
        self.encoded = canonical_json_bytes(self.protocol.canonical_dict)
        self.value = safe_json_loads(self.encoded)

    def test_real_initial_protocol_json_roundtrip(self):
        before = deepcopy(self.value)
        parsed = _parse_scientific_confirmatory_protocol(self.value)
        self.assertEqual(parsed, self.protocol)
        self.assertEqual(parsed.sha256, self.protocol.sha256)
        self.assertEqual(canonical_json_bytes(parsed.canonical_dict), self.encoded)
        self.assertEqual(self.value, before)

    def test_revised_protocol_json_preserves_actual_parent_hash_and_reason(self):
        parent = self.protocol
        for version in (2, 3):
            with self.subTest(version=version):
                child = replace(
                    parent,
                    study_version=version,
                    parent_protocol_hash=parent.sha256,
                    revision_reason=f"Prospective revision {version}.",
                )
                value = safe_json_loads(canonical_json_bytes(child.canonical_dict))
                parsed = _parse_scientific_confirmatory_protocol(value)
                self.assertEqual(parsed, child)
                self.assertEqual(parsed.parent_protocol_hash, parent.sha256)
                self.assertEqual(parsed.sha256, child.sha256)
                self.assertNotEqual(parsed.sha256, parent.sha256)
                parent = child

    def test_shared_exact_key_helper_remains_validator_only(self):
        self.assertIsNone(_require_exact_keys({"field": 1}, {"field"}, "control"))
        for value in ({}, {"field": 1, "extra": 2}, [], None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ScientificPromotionError, "schema"):
                    _require_exact_keys(value, {"field"}, "control")

    def test_top_level_requires_exact_mapping(self):
        missing = deepcopy(self.value)
        del missing["study_id"]
        for value in (None, [], "not a mapping", missing, {**self.value, "extra": 1}):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(ScientificPromotionError, "schema"):
                    _parse_scientific_confirmatory_protocol(value)

    def test_every_nested_model_requires_exact_keys(self):
        paths = (
            ("data_roles",),
            ("candidate_conditions",),
            ("baseline_set", 0),
            ("baseline_set", 0, "conditions"),
            ("domain_nulls", 0),
            ("statistical_tests", 0),
            ("confidence_intervals", 0),
            ("seed_policy",),
            ("compute_budget",),
            ("interpretation_rules",),
        )
        for path in paths:
            for mutation in ("missing", "extra", "wrong-type"):
                with self.subTest(path=path, mutation=mutation):
                    value = deepcopy(self.value)
                    container = value
                    for key in path[:-1]:
                        container = container[key]
                    nested = container[path[-1]]
                    if mutation == "missing":
                        del nested[next(iter(nested))]
                    elif mutation == "extra":
                        nested["unexpected"] = True
                    else:
                        container[path[-1]] = []
                    with self.assertRaisesRegex(ScientificPromotionError, "is malformed") as caught:
                        _parse_scientific_confirmatory_protocol(value)
                    self.assertIn("schema", str(caught.exception.__cause__))

    def test_all_protocol_sequences_require_json_arrays(self):
        paths = (
            *((key,) for key in (
                "secondary_metrics", "data_exclusions", "baseline_set",
                "ablation_set", "negative_controls", "domain_nulls",
                "statistical_tests", "confidence_intervals", "stopping_rules",
                "decision_ladder",
            )),
            *(("data_roles", role) for role in (
                "train", "development", "validation", "holdout",
            )),
            ("seed_policy", "seeds"),
            ("domain_nulls", 0, "structures_preserved"),
            ("domain_nulls", 0, "assumptions"),
        )
        for path in paths:
            with self.subTest(path=path):
                value = deepcopy(self.value)
                container = value
                for key in path[:-1]:
                    container = container[key]
                container[path[-1]] = tuple(container[path[-1]])
                with self.assertRaisesRegex(ScientificPromotionError, "is malformed") as caught:
                    _parse_scientific_confirmatory_protocol(value)
                self.assertIn("JSON array", str(caught.exception.__cause__))

    def test_valid_codec_still_invokes_existing_semantic_guards(self):
        cases = (
            (("study_version",), True, "positive integer"),
            (("data_roles", "holdout"), self.value["data_roles"]["train"], "appears in both"),
            (("statistical_tests", 0, "alpha"), True, "alpha must be numeric"),
            (("domain_nulls", 0, "exchangeability_justified"), False, "exchangeability justification"),
            (("seed_policy", "seeds"), [7, 7], "seeds must be unique"),
            (("compute_budget", "max_gpu_jobs"), 2, "at most one GPU"),
            (("validity_reserve_fraction",), 0.1, "validity_reserve_fraction"),
            (("baseline_set", 0, "conditions", "preprocessing"), "different", "baseline equivalence failed"),
            (("parent_protocol_hash",), "invalid", "SHA-256"),
            (("revision_reason",), "Not an initial version.", "initial protocol"),
        )
        for path, replacement, cause in cases:
            with self.subTest(path=path):
                value = deepcopy(self.value)
                container = value
                for key in path[:-1]:
                    container = container[key]
                container[path[-1]] = replacement
                before = deepcopy(value)
                with self.assertRaisesRegex(ScientificPromotionError, "is malformed") as caught:
                    _parse_scientific_confirmatory_protocol(value)
                self.assertIn(cause, str(caught.exception.__cause__))
                self.assertEqual(value, before)


if __name__ == "__main__":
    unittest.main()
