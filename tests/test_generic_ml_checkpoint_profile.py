"""Non-evidentiary policy admission checks; no full source owner is replaced."""

import ast
import inspect
import unittest

from scientist_one import domains
from scientist_one.generic_ml_projection import GENERIC_ML_OBSERVATIONS_FORMAT_VERSION


class GenericMLCheckpointProfileTests(unittest.TestCase):
    def matches(self, checkpoint: object, version: str) -> bool:
        return domains._generic_ml_checkpoint_selection_matches_profile(
            checkpoint,
            source_format_version=version,
            split_ids={"train", "development", "validation", "confirmatory"},
        )

    def test_fixed_model_profile_requires_absence_not_a_selected_split(self) -> None:
        version = GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
        self.assertTrue(self.matches(None, version))
        for checkpoint in (
            "train", "development", "validation", "confirmatory", "unknown",
            "", True, False, 0, [], {},
        ):
            with self.subTest(checkpoint=checkpoint):
                self.assertFalse(self.matches(checkpoint, version))

    def test_legacy_profile_keeps_split_requirement(self) -> None:
        version = domains.SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
        for checkpoint in ("train", "development", "validation", "confirmatory"):
            self.assertTrue(self.matches(checkpoint, version))
        for checkpoint in (None, "unknown", "", True, 0, [], {}):
            with self.subTest(checkpoint=checkpoint):
                self.assertFalse(self.matches(checkpoint, version))

    def test_unknown_profile_never_acquires_a_null_policy_exception(self) -> None:
        for version in ("0.0", "3.0", "2", "", None, True):
            for checkpoint in (None, "validation"):
                with self.subTest(version=version, checkpoint=checkpoint):
                    self.assertFalse(self.matches(checkpoint, version))

    def test_full_owner_uses_exact_profile_and_split_inventory_predicate(self) -> None:
        # Structural call-site coverage only. It does not mock the full
        # registry, Dataset, contract, split, run-spec or execution owners.
        tree = ast.parse(inspect.getsource(domains._replay_scientific_domain_plan_sources))
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_generic_ml_checkpoint_selection_matches_profile"
        ]
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            ast.unparse(calls[0].args[0]),
            "domain_policy.get('checkpoint_selection_split_id')",
        )
        self.assertEqual(
            {keyword.arg: ast.unparse(keyword.value) for keyword in calls[0].keywords},
            {"source_format_version": "source_format_version", "split_ids": "split_ids"},
        )
        self.assertTrue(any(
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, ast.Not)
            and node.operand is calls[0]
            for node in ast.walk(tree)
        ))


if __name__ == "__main__":
    unittest.main()
