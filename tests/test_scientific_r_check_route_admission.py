"""Bounded controls for the guarded scientific R-check source routes.

These tests deliberately use inert records and mechanically constructed
resolution DTOs.  They do not mock a source owner, issue a positive
scientific receipt, mutate trust maps, or treat a fixture as scientific
evidence.  The registry cases only prove that malformed new routes fail
closed before an R-check authority can be admitted.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
from pathlib import Path
from types import SimpleNamespace
from tempfile import TemporaryDirectory
import unittest

from scientist_one.evaluators import (
    AuthorityScope,
    AuthorityStatus,
    EvaluatorClass,
    RCheck,
    _COHORT_ONLY_SOURCE_TYPES,
    _SOURCE_ROLES,
    _derive_r_check_authority_bundle,
    _derive_r_check_authority_source,
    _owned_scientific_source_bindings,
    _require_legacy_bundle_source_profile,
    register_r_check_authority,
)
from scientist_one.roles import Role
from scientist_one.scientific_r_checks import (
    ScientificRCheckResolution,
    _ScientificSourceAdmission,
)
from tests import test_evaluator_authority as evaluator_fixtures
from tests import test_scientific_r_checks as check_fixtures


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event(label: str) -> SimpleNamespace:
    # Deliberately omit artifact hashes.  The private transport checks the
    # owner's event identity; the owner, not this helper, proves the source
    # checkpoint and later artifact relationship.
    return SimpleNamespace(
        event_id=f"inert-event-{label}",
        event_hash=_digest(f"inert-event-hash-{label}"),
        metadata={},
        artifact_hashes=(),
    )


def _resolution(
    admissions: tuple[_ScientificSourceAdmission, ...],
    *,
    r_check: RCheck = RCheck.R4,
) -> ScientificRCheckResolution:
    return ScientificRCheckResolution(
        r_check=r_check,
        evaluator_class=EvaluatorClass.E0,
        status=AuthorityStatus.UNTESTED,
        scope=AuthorityScope.SYSTEM_FIXTURE,
        reason_code="INERT_NON_EVIDENTIARY",
        checks=(),
        subject_key=(("run_id", "inert-route"),),
        source_admissions=admissions,
    )


def _admission(record: object, event: SimpleNamespace, index: int) -> _ScientificSourceAdmission:
    return _ScientificSourceAdmission(
        artifact_sha256=record.sha256,
        artifact_record_hash=str(record.record_hash),
        ledger_event_id=event.event_id,
        ledger_event_hash=event.event_hash,
        ledger_event_index=index,
    )


def _admission_snapshot(harness: evaluator_fixtures.AuthorityHarness) -> tuple[object, ...]:
    harness.registry.verify_all(raise_on_error=True)
    result = harness.ledger.validate(raise_on_error=True)
    return (
        tuple(
            (record.sha256, str(record.record_hash), record.logical_type)
            for record in harness.registry.list_records()
        ),
        tuple(
            (event.event_id, event.event_hash, event.artifact_hashes)
            for event in result.events
        ),
    )


def _malformed_canonical_sources(
    harness: evaluator_fixtures.AuthorityHarness,
    *,
    include_implementation: bool,
    method_role: Role = Role.HYPOTHESIS_DESIGNER,
) -> tuple[object, ...]:
    """Create exact route-shaped, non-canonical records with no owner proof."""

    def source(logical_type: str, role: Role) -> object:
        return harness.source(
            logical_type,
            role,
            {
                "fixture_notice": "inert route-admission control",
                "logical_type": logical_type,
            },
        )

    result = source("research_state.result", Role.STATISTICIAN)
    statistical_test = source(
        "research_state.statistical_test", Role.STATISTICIAN
    )
    if not include_implementation:
        return (result, statistical_test)
    return (
        source("frozen_run_spec", Role.EXPERIMENT_RUNNER),
        source("research_state.implementation", Role.IMPLEMENTER),
        source("research_state.method", method_role),
        result,
        source("research_state.run", Role.EXPERIMENT_RUNNER),
        statistical_test,
    )


class ScientificSourceBindingTransportTests(unittest.TestCase):
    """Exercise only the private, non-authoritative source join transport."""

    def setUp(self) -> None:
        self.records = (
            check_fixtures._record("route-binding-a", "aggregate_experiment_result"),
            check_fixtures._record("route-binding-b", "machine_results"),
        )
        self.events = (_event("prefix"), _event("a"), _event("b"))
        self.admissions = (
            _admission(self.records[0], self.events[1], 1),
            _admission(self.records[1], self.events[2], 2),
        )

    def test_valid_inert_join_accepts_checkpoint_without_direct_artifact(self) -> None:
        bindings = _owned_scientific_source_bindings(
            self.events,
            self.records,
            _resolution(self.admissions),
        )
        self.assertEqual(
            tuple(binding.artifact_sha256 for binding in bindings),
            tuple(record.sha256 for record in self.records),
        )
        self.assertEqual(
            tuple(binding.ledger_event_index for binding in bindings), (1, 2)
        )
        self.assertEqual(bindings[0].parent_artifacts, ())

    def test_transport_rejects_wrong_resolution_type_and_admission_cardinality(self) -> None:
        cases = {
            "wrong resolution type": SimpleNamespace(
                source_admissions=self.admissions
            ),
            "missing admissions": _resolution(()),
            "missing one admission": _resolution(self.admissions[:1]),
            "extra admission": _resolution(
                self.admissions
                + (
                    _admission(
                        check_fixtures._record(
                            "route-binding-extra", "machine_results"
                        ),
                        _event("extra"),
                        0,
                    ),
                )
            ),
            "duplicate record identity": _resolution(self.admissions),
        }
        for label, resolution in cases.items():
            records = (self.records[0], self.records[0]) if label == "duplicate record identity" else self.records
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    _owned_scientific_source_bindings(self.events, records, resolution)

    def test_transport_rejects_record_and_checkpoint_substitutions(self) -> None:
        substitutions = (
            ("record hash", {"artifact_record_hash": _digest("wrong-record")}),
            ("event id", {"ledger_event_id": "inert-event-other"}),
            ("event hash", {"ledger_event_hash": _digest("wrong-event")}),
            ("event index", {"ledger_event_index": 99}),
        )
        for label, changes in substitutions:
            with self.subTest(label=label):
                admissions = (
                    replace(self.admissions[0], **changes),
                    self.admissions[1],
                )
                with self.assertRaises(ValueError):
                    _owned_scientific_source_bindings(
                        self.events, self.records, _resolution(admissions)
                    )


class LegacyBundleProfileTests(unittest.TestCase):
    def test_historical_v1_source_families_remain_allowed(self) -> None:
        _require_legacy_bundle_source_profile(
            (
                SimpleNamespace(
                    logical_type="aggregate_experiment_result",
                    schema_version="1.0",
                ),
                SimpleNamespace(
                    logical_type="domain_validity.generic_ml",
                    schema_version="domain-validity-receipt/v3",
                ),
                SimpleNamespace(
                    logical_type="semantic_challenge_audit_authority",
                    schema_version="1.0",
                ),
            )
        )

    def test_every_new_family_and_plural_audit_are_rejected(self) -> None:
        for logical_type in sorted(_COHORT_ONLY_SOURCE_TYPES):
            with self.subTest(logical_type=logical_type):
                with self.assertRaises(ValueError):
                    _require_legacy_bundle_source_profile(
                        (
                            SimpleNamespace(
                                logical_type=logical_type,
                                schema_version="1.0",
                            ),
                        )
                    )
        with self.assertRaises(ValueError):
            _require_legacy_bundle_source_profile(
                (
                    SimpleNamespace(
                        logical_type="semantic_challenge_audit_authority",
                        schema_version="2.0",
                    ),
                )
            )


class ScientificRouteStructureTests(unittest.TestCase):
    def test_new_routes_resolve_owner_before_owned_binding_transport(self) -> None:
        source = inspect.getsource(_derive_r_check_authority_source)
        self.assertIn("cohort_route", source)
        self.assertIn("resolve_scientific_r_check_sources", source)
        self.assertIn("_owned_scientific_source_bindings", source)
        self.assertLess(
            source.index("resolve_scientific_r_check_sources"),
            source.index("_owned_scientific_source_bindings"),
        )
        self.assertIn("Role.HYPOTHESIS_DESIGNER", source)
        self.assertIn("Role.PROTOCOL_DESIGNER", source)
        self.assertIs(_SOURCE_ROLES["research_state.result"], Role.STATISTICIAN)
        self.assertIs(
            _SOURCE_ROLES["research_state.statistical_test"], Role.STATISTICIAN
        )
        self.assertIs(_SOURCE_ROLES["research_state.run"], Role.EXPERIMENT_RUNNER)
        self.assertIs(
            _SOURCE_ROLES["research_state.implementation"], Role.IMPLEMENTER
        )
        self.assertIs(
            _SOURCE_ROLES["scientific_confirmatory_timeline_receipt_v2"],
            Role.CLAIM_VERIFIER,
        )

    def test_v1_bundle_derivation_runs_legacy_profile_guard_after_readback(self) -> None:
        source = inspect.getsource(_derive_r_check_authority_bundle)
        self.assertIn("resolve_r_check_authority", source)
        self.assertIn("_require_legacy_bundle_source_profile", source)
        self.assertLess(
            source.index("resolve_r_check_authority"),
            source.index("_require_legacy_bundle_source_profile"),
        )


class MalformedScientificRouteAdmissionTests(unittest.TestCase):
    def _assert_route_refuses_without_admission(
        self,
        *,
        r_check: RCheck,
        evaluator_class: EvaluatorClass,
        logical_type: str | None = None,
        source_artifacts: tuple[object, ...] | None = None,
    ) -> None:
        with TemporaryDirectory(prefix="scientific-r-route-") as directory:
            harness = evaluator_fixtures.AuthorityHarness(Path(directory))
            if source_artifacts is None:
                if logical_type is None:
                    raise AssertionError("route source shape is unspecified")
                source_artifacts = (
                    harness.source(
                        logical_type,
                        Role.CLAIM_VERIFIER,
                        {"fixture_notice": "inert malformed timeline route"},
                    ),
                )
            before = _admission_snapshot(harness)
            with self.assertRaisesRegex(ValueError, "owner admissions are incomplete"):
                register_r_check_authority(
                    harness.registry,
                    harness.ledger,
                    run_id=harness.run_id,
                    r_check=r_check,
                    evaluator_class=evaluator_class,
                    source_artifact_sha256s=tuple(
                        record.sha256 for record in source_artifacts
                    ),
                )
            self.assertEqual(_admission_snapshot(harness), before)

    def test_malformed_r2_and_r4_canonical_routes_fail_closed(self) -> None:
        for r_check, include_implementation in (
            (RCheck.R2, True),
            (RCheck.R4, False),
        ):
            with self.subTest(r_check=r_check):
                with TemporaryDirectory(prefix="scientific-r-canonical-") as directory:
                    harness = evaluator_fixtures.AuthorityHarness(Path(directory))
                    records = _malformed_canonical_sources(
                        harness,
                        include_implementation=include_implementation,
                    )
                    before = _admission_snapshot(harness)
                    with self.assertRaisesRegex(ValueError, "owner admissions are incomplete"):
                        register_r_check_authority(
                            harness.registry,
                            harness.ledger,
                            run_id=harness.run_id,
                            r_check=r_check,
                            evaluator_class=EvaluatorClass.E0,
                            source_artifact_sha256s=tuple(
                                record.sha256 for record in records
                            ),
                        )
                    self.assertEqual(_admission_snapshot(harness), before)

    def test_malformed_timeline_route_fails_closed_before_generic_event_binding(self) -> None:
        self._assert_route_refuses_without_admission(
            r_check=RCheck.R3,
            evaluator_class=EvaluatorClass.E3,
            logical_type="scientific_confirmatory_timeline_receipt_v2",
        )

    def test_method_creator_role_is_closed_before_owner_replay(self) -> None:
        with TemporaryDirectory(prefix="scientific-r-role-") as directory:
            harness = evaluator_fixtures.AuthorityHarness(Path(directory))
            records = _malformed_canonical_sources(
                harness,
                include_implementation=True,
                method_role=Role.CLAIM_VERIFIER,
            )
            before = _admission_snapshot(harness)
            with self.assertRaisesRegex(ValueError, "wrong creator role"):
                register_r_check_authority(
                    harness.registry,
                    harness.ledger,
                    run_id=harness.run_id,
                    r_check=RCheck.R2,
                    evaluator_class=EvaluatorClass.E0,
                    source_artifact_sha256s=tuple(
                        record.sha256 for record in records
                    ),
                )
            self.assertEqual(_admission_snapshot(harness), before)


if __name__ == "__main__":
    unittest.main()
