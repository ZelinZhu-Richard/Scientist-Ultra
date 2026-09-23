"""Inert condition/call-order checks, not scientific domain authority tests.

All admitted Generic-ML profiles are within-Dataset only. Evaluate the exact
extracted pure guard; never mock the source owner into scientific PASS.
"""

import ast
import inspect
from types import SimpleNamespace
import unittest

from scientist_one import gates
from scientist_one.domains import (
    DomainEvidenceScope,
    DomainKind,
    DomainValidityLimitation,
    DomainValidityStatus,
)


class FixedModelGeneralizationGuardTests(unittest.TestCase):
    def _guard(self):
        function = ast.parse(inspect.getsource(gates._resolve_generalization_authority)).body[0]
        branch = next(node for node in function.body if isinstance(node, ast.If))
        expression = compile(ast.Expression(branch.test), "<inert-generalization-guard>", "eval")
        return function, branch, expression

    def _unavailable(self, *, version, status, scope=DomainEvidenceScope.SCIENTIFIC_EVIDENCE, limitations=(), domain=DomainKind.GENERIC_ML):
        _, _, expression = self._guard()
        resolved = SimpleNamespace(
            domain=domain,
            scope=scope,
            limitations=limitations,
            outcome=SimpleNamespace(adapter_version=version, status=status),
        )
        return eval(expression, {
            "__builtins__": {},
            "DomainEvidenceScope": DomainEvidenceScope,
            "DomainValidityLimitation": DomainValidityLimitation,
            "DomainKind": DomainKind,
        }, {"resolved": resolved})

    def test_all_generic_ml_profiles_retain_untested_generalization(self):
        for version in ("1.0", "2.0", "3.0", "future-unowned-profile"):
            for status in DomainValidityStatus:
                with self.subTest(version=version, status=status):
                    self.assertTrue(self._unavailable(version=version, status=status))

    def test_legacy_scope_and_limitation_conditions_are_preserved(self):
        # Other domains retain their existing owner-specific behavior. This
        # inert condition control is not proof of their scientific admission.
        self.assertFalse(self._unavailable(
            version="2.0", status=DomainValidityStatus.PASS, domain=DomainKind.SYSTEMS,
        ))
        self.assertTrue(self._unavailable(
            version="2.0", status=DomainValidityStatus.PASS,
            scope=DomainEvidenceScope.NON_EVIDENTIARY_FIXTURE,
            domain=DomainKind.SYSTEMS,
        ))
        for limitation in (
            DomainValidityLimitation.REAL_WORKLOAD_UNTESTED,
            DomainValidityLimitation.EXTERNAL_VALIDATION_UNTESTED,
            DomainValidityLimitation.CLINICAL_VALIDATION_UNTESTED,
        ):
            with self.subTest(limitation=limitation):
                self.assertTrue(self._unavailable(
                    version="2.0", status=DomainValidityStatus.PASS,
                    limitations=(limitation,),
                    domain=DomainKind.SYSTEMS,
                ))

    def test_actual_resolver_replays_owner_then_returns_untested_with_retained_sources(self):
        function, branch, _ = self._guard()
        owner = next(
            node for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_resolve_domain_authority_common"
        )
        self.assertLess(owner.lineno, branch.lineno)
        self.assertEqual(len(branch.body), 1)
        self.assertIsInstance(branch.body[0], ast.Return)
        self.assertEqual(ast.unparse(branch.body[0].value), "(DimensionStatus.UNTESTED, evidence_hashes)")


if __name__ == "__main__":
    unittest.main()
