"""Bounded controls for the paper bundle-replay source companion.

The companion is exercised with inert DTOs and an unavailable legacy bundle.
These tests do not patch a positive owner chain, construct an issued bundle,
or synthesize paper approval.
"""

from __future__ import annotations

from dataclasses import fields, FrozenInstanceError, is_dataclass
import hashlib
import inspect
from types import SimpleNamespace
import unittest

from scientist_one.errors import ValidationError
from scientist_one.paper_pipeline import (
    HardBlocker,
    PaperCandidate,
    PaperClaim,
    PaperVerification,
    _PaperVerificationBundleSource,
    _require_paper_verification_bundle_source,
    _resolve_paper_bound_state,
    verify_paper,
)
from scientist_one.research_state import ClaimStrength, ClaimType
from tests import test_gates_paper as paper_fixtures


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _inert_candidate() -> PaperCandidate:
    evidence_hash = _digest("inert-paper-evidence")
    return PaperCandidate(
        candidate_id="inert-paper-candidate",
        title="Inert paper verification boundary",
        claims=(
            PaperClaim(
                claim_id="inert-claim",
                text="This claim is only a typed unavailable-boundary fixture.",
                strength=ClaimStrength.QUALIFIED,
                evidence_hashes=(evidence_hash,),
                claim_type=ClaimType.QUALITATIVE,
                scope="inert fixture scope",
                confidence=0.5,
                verification_method="inert fixture only",
                permitted_strength=ClaimStrength.QUALIFIED,
            ),
        ),
        numeric_assertions=(),
        references=(),
        assets=(),
        method_code_bindings=(),
        limitations=("No scientific authority is asserted.",),
        source_bundle_hashes=(_digest("inert-paper-bundle"),),
    )


class PaperBundleSourceCompanionStructureTests(unittest.TestCase):
    def test_companion_is_frozen_and_has_only_replay_fields(self) -> None:
        self.assertTrue(is_dataclass(_PaperVerificationBundleSource))
        self.assertEqual(
            tuple(item.name for item in fields(_PaperVerificationBundleSource)),
            ("state_authority", "bundle", "issued_bundle"),
        )
        companion = _PaperVerificationBundleSource(
            state_authority=SimpleNamespace(kind="inert-state"),
            bundle=SimpleNamespace(kind="inert-bundle"),
            issued_bundle=SimpleNamespace(kind="inert-issued-record"),
        )
        with self.assertRaises(FrozenInstanceError):
            companion.bundle = SimpleNamespace(kind="replacement")

    def test_private_helper_has_only_exact_round_context_and_no_public_injection(self) -> None:
        parameters = inspect.signature(
            _require_paper_verification_bundle_source
        ).parameters
        self.assertEqual(tuple(parameters), ("registry", "ledger", "bundle", "_round_replay"))
        self.assertIs(parameters["_round_replay"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIsNone(parameters["_round_replay"].default)
        self.assertNotIn("_round_replay", inspect.signature(verify_paper).parameters)
        source = inspect.getsource(_require_paper_verification_bundle_source)
        for required_call in (
            "_resolve_paper_bound_state",
            "_build_authoritative_research_bundle",
            "_find_issued_authoritative_bundle",
        ):
            with self.subTest(required_call=required_call):
                self.assertIn(required_call, source)
        self.assertIn("if resolved != bundle", source)
        self.assertIn("return _PaperVerificationBundleSource", source)
        routing = inspect.getsource(_resolve_paper_bound_state)
        self.assertIn("return resolve_bound_research_state_authority", routing)
        self.assertIn("return _resolve_bound_research_state_authority", routing)
        self.assertIn("_require_paper_round_sources", routing)

    def test_public_wrapper_keeps_typed_preflight_and_diagnostic_boundary(self) -> None:
        source = inspect.getsource(verify_paper)
        self.assertIn("if not isinstance(candidate, PaperCandidate)", source)
        self.assertIn("if registry is None:", source)
        self.assertIn("_require_paper_verification_bundle_source", source)
        self.assertIn("except Exception:", source)

        result = verify_paper(
            _inert_candidate(),
            paper_fixtures.legacy_placeholder_bundle(),
            registry=None,
        )
        self.assertEqual(
            result,
            PaperVerification(
                passed=False,
                blockers=(HardBlocker.UNRESOLVED_AUTHORITY,),
                discrepancies=("authoritative_registry_required",),
                verified_claim_ids=(),
            ),
        )

    def test_helper_rejects_unavailable_bundle_before_any_owner_replay(self) -> None:
        bundle = paper_fixtures.legacy_placeholder_bundle()
        with self.assertRaisesRegex(
            ValidationError,
            "paper bundle lacks its frozen research-state projection",
        ):
            _require_paper_verification_bundle_source(
                registry=SimpleNamespace(),
                ledger=SimpleNamespace(),
                bundle=bundle,
            )


class PaperBundleSourceCompanionBoundaryTests(unittest.TestCase):
    def test_companion_transport_does_not_upgrade_inert_dtos(self) -> None:
        companion = _PaperVerificationBundleSource(
            state_authority=SimpleNamespace(
                scope="SYSTEM_FIXTURE",
                status="UNTESTED",
            ),
            bundle=SimpleNamespace(
                scope="SYSTEM_FIXTURE",
                status="UNTESTED",
            ),
            issued_bundle=SimpleNamespace(
                logical_type="inert-only-record",
                validation_result="UNTESTED",
            ),
        )
        self.assertEqual(companion.state_authority.scope, "SYSTEM_FIXTURE")
        self.assertEqual(companion.bundle.status, "UNTESTED")
        self.assertEqual(companion.issued_bundle.validation_result, "UNTESTED")

    def test_unavailable_bundle_is_not_reinterpreted_as_a_paper_pass(self) -> None:
        result = verify_paper(
            _inert_candidate(),
            paper_fixtures.legacy_placeholder_bundle(),
            registry=None,
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.blockers, (HardBlocker.UNRESOLVED_AUTHORITY,))
        self.assertEqual(result.verified_claim_ids, ())


if __name__ == "__main__":
    unittest.main()
