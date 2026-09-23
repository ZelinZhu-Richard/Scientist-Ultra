from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.claims import (
    ClaimDecision,
    ClaimEvidenceUse,
    ClaimEvidenceGraph,
    ClaimNotEligibleError,
    Contradiction,
    EvidenceKind,
    EvidenceLink,
    EvidenceNode,
    EvidenceResolver,
    EvidenceSupportReceipt,
    EvidenceVerificationReceipt,
    MaterialClaim,
    REQUIRED_EVIDENCE_KINDS,
    artifact_registry_resolver,
    text_evidence,
    verify_claims,
)
from scientist_one.errors import (
    ArtifactError,
    AuthorizationError,
    PathSecurityError,
    ValidationError,
)
from scientist_one.holdout import (
    ConfirmatoryEvaluatorSpec,
    CustodyIndependence,
    HoldoutAccessViolation,
    HoldoutCustodyError,
    HoldoutJournalError,
    HumanControlledHoldoutCustody,
    IndependentServiceHoldoutCustody,
    RevealExecutionClass,
    SimulatedHoldoutCustody,
)
from scientist_one.protocol import (
    DEFAULT_VALIDITY_RESERVE,
    BaselineSpec,
    ConfidenceIntervalSpec,
    DataRoles,
    DomainNullSpec,
    ExecutionConditions,
    InterpretationRules,
    ProtocolComputeBudget,
    ProtocolStateError,
    ProtocolValidationError,
    ResearchProtocol,
    SeedPolicy,
    StatisticalTestSpec,
    freeze_protocol,
    record_confirmatory_reveal,
    revise_study_version,
    validate_study_lineage,
)
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
from scientist_one.statistics import (
    DomainNullDesign,
    MultiplicityMethod,
    NullMethod,
    StatisticalUnitDesign,
    StatisticalValidationError,
    UnitObservation,
    adjust_pvalues,
    analyze_two_group,
    bootstrap_mean_difference_ci,
    hedges_g,
    mean_difference,
    validate_domain_null,
    validate_multiplicity_plan,
    validate_statistical_units,
)


ROOT = Path(__file__).resolve().parents[1]
HASHES = {name: hashlib.sha256(name.encode()).hexdigest() for name in (
    "split", "code", "config", "blind", "release", "holdout", "result",
)}


def rewrite_custody_journal(path: Path, events: list[dict[str, object]]) -> None:
    prior = "0" * 64
    encoded: list[bytes] = []
    for index, event in enumerate(events):
        event["event_index"] = index
        event["prior_event_hash"] = prior
        unsigned = {key: value for key, value in event.items() if key != "event_hash"}
        digest = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
        event["event_hash"] = digest
        prior = digest
        encoded.append(canonical_json_bytes(event) + b"\n")
    path.write_bytes(b"".join(encoded))


def resolve_test_evidence(
    claim: MaterialClaim,
    node: EvidenceNode,
) -> EvidenceVerificationReceipt:
    """Test-only prevalidated receipt for content-addressed text evidence."""

    return EvidenceVerificationReceipt(
        evidence_id=node.evidence_id,
        evidence_kind=node.kind,
        artifact_hash=node.artifact_hash,
        content_sha256=hashlib.sha256(node.description.encode()).hexdigest(),
        registry_record_hash=hashlib.sha256(
            ("test-receipt:" + node.artifact_hash).encode()
        ).hexdigest(),
        support_receipt_hash=hashlib.sha256(
            ("test-support:" + claim.claim_id + node.artifact_hash).encode()
        ).hexdigest(),
        support_receipt_record_hash=hashlib.sha256(
            ("test-support-record:" + claim.claim_id + node.artifact_hash).encode()
        ).hexdigest(),
        support_verifier_id="verifier-1",
        support_verifier_role=Role.CLAIM_VERIFIER,
        resolver_id="test-evidence-verifier",
        validation_result="PASS" if node.verified else "FAIL",
        frozen=node.frozen,
        supports_claim=node.supports_claim,
        contradicts_claim=node.contradicts_claim,
        locally_verifiable=node.locally_verifiable,
    )


def conditions(**changes: object) -> ExecutionConditions:
    values: dict[str, object] = {
        "preprocessing": "frozen-standardize-v1",
        "data_access": "identical-train-development-only",
        "tuning_budget": 12,
        "early_stopping": "validation patience 5",
        "compute_budget": 100.0,
        "feature_set": "features-v1",
        "implementation_verified": True,
    }
    values.update(changes)
    return ExecutionConditions(**values)  # type: ignore[arg-type]


def make_protocol(**changes: object) -> ResearchProtocol:
    candidate = conditions()
    values: dict[str, object] = {
        "study_id": "synthetic-study",
        "study_version": 1,
        "primary_hypothesis": "Treatment improves the preregistered score.",
        "primary_estimand": "Mean treatment-minus-control score at subject level.",
        "primary_metric": "score",
        "secondary_metrics": ("absolute_error",),
        "unit_of_analysis": "subject",
        "resampling_unit": "subject",
        "data_exclusions": ("exclude malformed fixture rows before splitting",),
        "data_roles": DataRoles(
            train=("train-v1",),
            development=("development-v1",),
            validation=("validation-v1",),
            holdout=("confirmatory-v1",),
        ),
        "candidate_conditions": candidate,
        "baseline_set": (BaselineSpec("strong-baseline", candidate),),
        "ablation_set": ("remove-signal-feature",),
        "negative_controls": ("shuffled-noncausal-feature",),
        "domain_nulls": (
            DomainNullSpec(
                "subject-label-null",
                "label_permutation",
                "subject",
                ("subject grouping",),
                ("subjects are randomized and exchangeable under the null",),
                True,
            ),
        ),
        "statistical_tests": (
            StatisticalTestSpec("primary-test", "permutation", "subject-label-null", "two-sided"),
        ),
        "confidence_intervals": (
            ConfidenceIntervalSpec("subject bootstrap", 0.95, "subject"),
        ),
        "multiple_comparison_correction": "Holm family-wise error correction",
        "seed_policy": SeedPolicy((7, 11, 19), "all seeds reported", "retry only process crash"),
        "compute_budget": ProtocolComputeBudget(20, 3600.0, 4, 1),
        "stopping_rules": ("stop after the frozen seed set",),
        "decision_ladder": ("fix implementation defects on development data only",),
        "claim_scope_contract": "synthetic fixture and frozen population only",
        "interpretation_rules": InterpretationRules(
            positive="Report positive only if primary test and robustness pass.",
            null="Report a null result without searching secondary stories.",
            contradictory="Report contradiction and block the positive claim.",
            unstable="Report inconclusive if uncertainty or subgroups are unstable.",
        ),
    }
    values.update(changes)
    return ResearchProtocol(**values)  # type: ignore[arg-type]


def seal_custody(test_case: unittest.TestCase) -> tuple[SimulatedHoldoutCustody, bytes]:
    payload = b'{"confirmatory": [1, 2, 3]}'
    temporary = tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp")
    custody = SimulatedHoldoutCustody(
        ("experiment-runner",),
        journal_root=ROOT,
        journal_path=Path(temporary.name).relative_to(ROOT) / "custody.jsonl",
    )
    test_case.addCleanup(temporary.cleanup)
    custody.seal(
        payload,
        split_manifest_hash=HASHES["split"],
        protocol_hash=make_protocol().sha256,
        code_hash=HASHES["code"],
        configuration_hash=HASHES["config"],
        pre_unblinding_interpretation_hash=HASHES["blind"],
        sealed_at="2026-08-12T12:00:00Z",
    )
    return custody, payload


def direct_session_release(session: object, **changes: object):
    """Attempt the caller-controlled bypass that production must reject."""

    values: dict[str, object] = {
        "coordinator": object(),
        "ledger_path": "state/events.jsonl",
        "study_version": object(),
        "fresh_custody_evidence": object(),
        "reveal_authority": object(),
        "artifact_registry": object(),
        "custody_provider": getattr(session, "_provider", object()),
        "validity_snapshot": object(),
        "start_event": object(),
        "evaluator_spec": ConfirmatoryEvaluatorSpec(),
        "execution_class": (
            RevealExecutionClass.SIMULATED_ARCHITECTURE_CONTROL
        ),
        "requester": "experiment-runner",
        "reason": "single preregistered confirmatory evaluation",
        "requested_at": "2026-08-12T13:00:00Z",
    }
    values.update(changes)
    return session._release(**values)  # type: ignore[attr-defined]


def make_claim_graph(
    *,
    claim_id: str = "claim-1",
    omit: EvidenceKind | None = None,
    overrides: dict[EvidenceKind, dict[str, object]] | None = None,
    confirmatory: bool = False,
    evidence_use: ClaimEvidenceUse = ClaimEvidenceUse.SCIENTIFIC,
    evidence_resolver: EvidenceResolver | None = resolve_test_evidence,
) -> ClaimEvidenceGraph:
    graph = ClaimEvidenceGraph(evidence_resolver=evidence_resolver)
    links = []
    overrides = overrides or {}
    for kind in sorted(REQUIRED_EVIDENCE_KINDS, key=lambda value: value.value):
        if kind is omit:
            continue
        evidence_id = f"{claim_id}:{kind.value}"
        properties = overrides.get(kind, {})
        declared: dict[str, object] = {
            "verified": True,
            "frozen": True,
            "supports_claim": True,
            "locally_verifiable": True,
        }
        declared.update(properties)
        node = text_evidence(
            evidence_id,
            kind,
            f"verified local {kind.value} for {claim_id}",
            **declared,
        )
        graph.add_evidence(node)
        links.append(EvidenceLink(evidence_id, kind))
    graph.add_claim(
        MaterialClaim(
            claim_id,
            "The frozen synthetic treatment has a positive mean effect.",
            tuple(links),
            Role.EXPERIMENT_RUNNER,
            confirmatory=confirmatory,
            evidence_use=evidence_use,
        )
    )
    return graph


def register_support_receipt(
    registry: ArtifactRegistry,
    claim: MaterialClaim,
    node: EvidenceNode,
    **changes: object,
) -> EvidenceNode:
    values: dict[str, object] = {
        "verifier_id": "verifier-1",
        "verification_result": "PASS",
        "supports_claim": True,
        "contradicts_claim": False,
        "locally_verifiable": True,
        "rationale": "independent test verifier inspected the frozen evidence",
    }
    values.update(changes)
    receipt = EvidenceSupportReceipt.for_claim(
        claim,
        node,
        **values,  # type: ignore[arg-type]
    )
    record = registry.put_json(
        receipt.to_dict(),
        logical_type=f"claim_support_receipt.{node.kind.value}",
        origin="scientific-core-support-receipt-test",
        creator_role=Role.CLAIM_VERIFIER,
        parent_artifacts=(node.artifact_hash,),
    )
    self_hash = hashlib.sha256(receipt.canonical_bytes + b"\n").hexdigest()
    if record.sha256 != receipt.sha256 or record.sha256 != self_hash:
        raise AssertionError("test support receipt hash mismatch")
    return replace(node, verification_receipt_hash=record.sha256)


class ProtocolTests(unittest.TestCase):
    def test_protocol_is_complete_frozen_hash_stable_and_reserve_defaults_to_40_percent(self) -> None:
        protocol = make_protocol()
        same = make_protocol()
        self.assertEqual(protocol.validity_reserve_fraction, DEFAULT_VALIDITY_RESERVE)
        self.assertEqual(protocol.sha256, same.sha256)
        self.assertEqual(len(protocol.sha256), 64)
        with self.assertRaises(FrozenInstanceError):
            protocol.primary_metric = "changed"  # type: ignore[misc]
        self.assertIsInstance(ProtocolValidationError("x"), ValidationError)

    def test_reserve_must_remain_between_30_and_50_percent(self) -> None:
        for fraction in (0.299, 0.501):
            with self.subTest(fraction=fraction), self.assertRaises(ProtocolValidationError):
                make_protocol(validity_reserve_fraction=fraction)
        self.assertEqual(make_protocol(validity_reserve_fraction=0.30).validity_reserve_fraction, 0.30)
        self.assertEqual(make_protocol(validity_reserve_fraction=0.50).validity_reserve_fraction, 0.50)

    def test_data_roles_are_disjoint(self) -> None:
        with self.assertRaisesRegex(ProtocolValidationError, "both train and holdout"):
            DataRoles(("same",), ("dev",), ("valid",), ("same",))

    def test_baseline_equivalence_catches_every_fairness_dimension(self) -> None:
        changed = conditions(tuning_budget=99)
        with self.assertRaisesRegex(ProtocolValidationError, "tuning_budget"):
            make_protocol(baseline_set=(BaselineSpec("unfair", changed),))
        unverified = conditions(implementation_verified=False)
        with self.assertRaisesRegex(ProtocolValidationError, "implementation_verified"):
            make_protocol(baseline_set=(BaselineSpec("broken", unverified),))

    def test_protocol_rejects_pseudoreplication_invalid_null_and_no_multiplicity_plan(self) -> None:
        with self.assertRaisesRegex(ProtocolValidationError, "seeds, folds"):
            make_protocol(
                resampling_unit="seed",
                confidence_intervals=(ConfidenceIntervalSpec("bootstrap", 0.95, "seed"),),
            )
        bad_null = replace(make_protocol().domain_nulls[0], exchangeability_justified=False)
        with self.assertRaisesRegex(ProtocolValidationError, "exchangeability"):
            make_protocol(domain_nulls=(bad_null,))
        with self.assertRaisesRegex(ProtocolValidationError, "correction"):
            make_protocol(multiple_comparison_correction="none")

    def test_protocol_rejects_unknown_null_and_ci_resampling_mismatch(self) -> None:
        unknown = StatisticalTestSpec("bad", "permutation", "not-registered", "two-sided")
        with self.assertRaisesRegex(ProtocolValidationError, "unknown nulls"):
            make_protocol(statistical_tests=(unknown,))
        with self.assertRaisesRegex(ProtocolValidationError, "resampling units"):
            make_protocol(confidence_intervals=(ConfidenceIntervalSpec("bootstrap", 0.95, "row"),))

    def test_reveal_is_one_shot_and_revision_creates_new_lineage(self) -> None:
        original = freeze_protocol(make_protocol())
        revealed = record_confirmatory_reveal(
            original, release_hash=HASHES["release"], revealed_at="2026-08-12T13:00:00Z"
        )
        self.assertFalse(original.confirmatory_revealed)
        self.assertTrue(revealed.confirmatory_revealed)
        with self.assertRaises(ProtocolStateError):
            record_confirmatory_reveal(
                revealed, release_hash=HASHES["release"], revealed_at="later"
            )
        revision = revise_study_version(
            revealed,
            revision_reason="new preregistered follow-up after reveal",
            changes={"primary_metric": "followup_score"},
        )
        validate_study_lineage(revealed, revision)
        self.assertEqual(revision.version, 2)
        self.assertEqual(revision.protocol.parent_protocol_hash, revealed.protocol_hash)
        self.assertTrue(revision.requires_fresh_confirmatory_reserve)
        self.assertFalse(revision.confirmatory_revealed)
        self.assertEqual(revealed.protocol.primary_metric, "score")

    def test_version_lineage_rejects_controller_field_tampering(self) -> None:
        study = freeze_protocol(make_protocol())
        with self.assertRaises(ProtocolStateError):
            revise_study_version(study, revision_reason="tamper", changes={"study_id": "other"})

    def test_empty_exclusion_and_secondary_sets_are_frozen_and_cpu_only_budget_is_valid(self) -> None:
        protocol = make_protocol(
            secondary_metrics=(),
            data_exclusions=(),
            compute_budget=ProtocolComputeBudget(1, 30.0, 1, 0),
        )
        self.assertEqual(protocol.secondary_metrics, ())
        self.assertEqual(protocol.data_exclusions, ())
        with self.assertRaisesRegex(ProtocolValidationError, "at most one GPU"):
            ProtocolComputeBudget(1, 30.0, 1, 2)


class HoldoutTests(unittest.TestCase):
    def durable_custody(
        self,
        directory: str,
        *,
        seal: bool = True,
    ) -> tuple[SimulatedHoldoutCustody, bytes]:
        payload = b'{"confirmatory": [1, 2, 3]}'
        custody = SimulatedHoldoutCustody(
            ("experiment-runner",),
            journal_root=ROOT,
            journal_path=Path(directory).relative_to(ROOT) / "custody.jsonl",
        )
        if seal:
            custody.seal(
                payload,
                split_manifest_hash=HASHES["split"],
                protocol_hash=make_protocol().sha256,
                code_hash=HASHES["code"],
                configuration_hash=HASHES["config"],
                pre_unblinding_interpretation_hash=HASHES["blind"],
                sealed_at="2026-08-12T12:00:00Z",
            )
        return custody, payload

    def test_seal_records_all_identity_and_frozen_hashes_and_nonindependence(self) -> None:
        custody, payload = seal_custody(self)
        seal = custody.seal_record
        assert seal is not None
        self.assertEqual(seal.holdout_identity_hash, hashlib.sha256(payload).hexdigest())
        self.assertEqual(seal.split_manifest_hash, HASHES["split"])
        self.assertEqual(seal.code_hash, HASHES["code"])
        self.assertEqual(seal.configuration_hash, HASHES["config"])
        self.assertEqual(seal.pre_unblinding_interpretation_hash, HASHES["blind"])
        self.assertEqual(seal.custody_independence, CustodyIndependence.NON_INDEPENDENT)
        self.assertEqual(custody.custody_label, "SIMULATED_NON_INDEPENDENT")

    def test_direct_guard_release_requires_exact_coordinator_and_session_expires(self) -> None:
        custody, _ = seal_custody(self)
        before = custody.admission_snapshot()
        with custody._reveal_admission_guard() as session:
            self.assertFalse(session.snapshot.revealed)
            with self.assertRaisesRegex(HoldoutAccessViolation, "coordinator"):
                direct_session_release(session)
        with self.assertRaisesRegex(HoldoutJournalError, "no longer active"):
            direct_session_release(session, reason="expired session must fail")
        after = custody.admission_snapshot()
        self.assertEqual(after.journal_head_hash, before.journal_head_hash)
        self.assertEqual(after.journal_bytes, before.journal_bytes)
        self.assertFalse(custody.status.revealed)
        self.assertFalse(custody.status.invalidated)
        self.assertEqual(custody.status.authorized_access_count, 0)

    def test_fake_coordinator_fails_before_requester_policy_without_mutation(self) -> None:
        custody, _ = seal_custody(self)
        before = custody.admission_snapshot()
        with custody._reveal_admission_guard() as session:
            with self.assertRaisesRegex(HoldoutAccessViolation, "coordinator"):
                direct_session_release(session, requester="paper-writer")
        after = custody.admission_snapshot()
        self.assertEqual(after.journal_head_hash, before.journal_head_hash)
        self.assertEqual(after.journal_bytes, before.journal_bytes)
        self.assertFalse(custody.status.invalidated)
        self.assertFalse(custody.status.confirmatory_claims_valid)
        self.assertEqual(custody.status.authorized_access_count, 0)
        self.assertEqual(custody.access_records, ())

    def test_fake_and_replayed_coordinator_inputs_cannot_authorize_release(self) -> None:
        custody, _ = seal_custody(self)
        before = custody.admission_snapshot()
        for fake_coordinator in (object(), object()):
            with custody._reveal_admission_guard() as session:
                with self.assertRaisesRegex(HoldoutAccessViolation, "coordinator"):
                    direct_session_release(
                        session,
                        coordinator=fake_coordinator,
                    )
        after = custody.admission_snapshot()
        self.assertEqual(after.journal_head_hash, before.journal_head_hash)
        self.assertEqual(after.journal_bytes, before.journal_bytes)
        self.assertFalse(custody.status.revealed)
        self.assertFalse(custody.status.invalidated)

    def test_reported_accidental_access_invalidates_unrevealed_holdout(self) -> None:
        custody, _ = seal_custody(self)
        custody.record_violation(
            requester="local-process",
            reason="accidental inspection of sealed labels",
            occurred_at="2026-08-12T13:01:00Z",
        )
        self.assertFalse(custody.status.revealed)
        self.assertTrue(custody.status.invalidated)
        with self.assertRaises(HoldoutAccessViolation):
            custody.assert_confirmatory_claims_valid()

    def test_seal_identity_mismatch_and_second_seal_fail_closed(self) -> None:
        custody = SimulatedHoldoutCustody(("runner",))
        kwargs = dict(
            split_manifest_hash=HASHES["split"],
            protocol_hash=make_protocol().sha256,
            code_hash=HASHES["code"],
            configuration_hash=HASHES["config"],
            pre_unblinding_interpretation_hash=HASHES["blind"],
        )
        with self.assertRaisesRegex(HoldoutCustodyError, "expected identity"):
            custody.seal(b"actual", expected_holdout_identity_hash="0" * 64, **kwargs)
        custody.seal(b"actual", **kwargs)
        with self.assertRaisesRegex(HoldoutCustodyError, "reseal|already sealed"):
            custody.seal(b"other", **kwargs)

    def test_future_human_and_service_contracts_cannot_be_faked_or_instantiated(self) -> None:
        self.assertEqual(HumanControlledHoldoutCustody.independence, CustodyIndependence.HUMAN_INDEPENDENT)
        self.assertEqual(
            IndependentServiceHoldoutCustody.independence,
            CustodyIndependence.SERVICE_INDEPENDENT,
        )
        with self.assertRaises(TypeError):
            HumanControlledHoldoutCustody()  # type: ignore[abstract]
        with self.assertRaises(TypeError):
            IndependentServiceHoldoutCustody()  # type: ignore[abstract]

    def test_no_public_caller_attestation_or_direct_reveal_api_remains(self) -> None:
        custody, _ = seal_custody(self)
        self.assertFalse(hasattr(custody, "request_reveal"))
        self.assertFalse(hasattr(custody, "run_confirmatory"))
        import scientist_one.holdout as holdout_module
        import scientist_one.recovery as recovery_module

        self.assertFalse(hasattr(holdout_module, "_admit_confirmatory_reveal"))
        self.assertFalse(
            hasattr(holdout_module, "_consume_confirmatory_reveal_capability")
        )
        self.assertFalse(
            hasattr(holdout_module, "_build_confirmatory_reveal_capability")
        )
        self.assertFalse(hasattr(recovery_module, "_admit_confirmatory_reveal"))
        self.assertNotIn("_issue_reveal_capability", vars(custody))

        probe = f"""
import inspect
import sys
sys.path.insert(0, {str(ROOT / 'src')!r})
import scientist_one.holdout as holdout
assert 'scientist_one.recovery' not in sys.modules
assert not hasattr(holdout, '_build_confirmatory_reveal_capability')
assert not hasattr(holdout, '_admit_confirmatory_reveal')
assert not hasattr(holdout, '_consume_confirmatory_reveal_capability')
try:
    getattr(holdout, '_admit_confirmatory_reveal')
except AttributeError:
    pass
else:
    raise AssertionError('holdout-only import exposed a stealable issuer')
import scientist_one.recovery as recovery
assert not hasattr(recovery, '_build_confirmatory_reveal_capability')
assert not hasattr(recovery, '_admit_confirmatory_reveal')
assert not hasattr(recovery, '_consume_confirmatory_reveal_capability')
assert hasattr(recovery.RecoveryManager, 'run_confirmatory_authorized')
run = recovery.RecoveryManager.run_confirmatory_authorized
assert run.__closure__ is None
assert not inspect.getclosurevars(run).nonlocals
assert 'admission_callback' not in inspect.signature(run).parameters
assert 'evaluator' not in inspect.signature(run).parameters
assert 'evaluator_spec' in inspect.signature(run).parameters
fixture_run = recovery.RecoveryManager.run_non_evidentiary_simulated_fixture
assert fixture_run.__closure__ is None
assert not inspect.getclosurevars(fixture_run).nonlocals
assert 'admission_callback' not in inspect.signature(fixture_run).parameters
assert 'evaluator' not in inspect.signature(fixture_run).parameters
assert 'evaluator_spec' in inspect.signature(fixture_run).parameters
assert '_issue_reveal_capability' not in run.__code__.co_names
assert '_consume_confirmatory_reveal_capability' not in run.__code__.co_names
assert holdout._SimulatedRevealSession._release.__closure__ is None
assert not hasattr(holdout.SimulatedHoldoutCustody, '_evaluate_confirmatory_payload')
assert 'RegisteredArtifactSelector' in recovery.__all__
assert 'ConfirmatoryRevealAuthority' in recovery.__all__
"""
        completed = subprocess.run(
            (sys.executable, "-I", "-S", "-B", "-c", probe),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}",
        )

    def test_durable_journal_reloads_seal_and_allows_only_matching_reseal(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            first, payload = self.durable_custody(directory)
            head = first.verify_journal()
            self.assertIsNotNone(head)
            reloaded, _ = self.durable_custody(directory, seal=False)
            self.assertTrue(reloaded.status.sealed)
            self.assertFalse(reloaded.status.revealed)
            restored = reloaded.seal(
                payload,
                split_manifest_hash=HASHES["split"],
                protocol_hash=make_protocol().sha256,
                code_hash=HASHES["code"],
                configuration_hash=HASHES["config"],
                pre_unblinding_interpretation_hash=HASHES["blind"],
                sealed_at="2026-08-12T12:00:00Z",
            )
            self.assertEqual(restored, first.seal_record)
            self.assertEqual(reloaded.verify_journal(), head)

    def test_denied_direct_release_never_persists_across_reload(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            custody, _ = self.durable_custody(directory)
            seal_head = custody.verify_journal()
            with custody._reveal_admission_guard() as session:
                with self.assertRaisesRegex(HoldoutAccessViolation, "coordinator"):
                    direct_session_release(session)
            self.assertEqual(custody.verify_journal(), seal_head)
            self.assertTrue(custody.status.durable_journal)
            reloaded, _ = self.durable_custody(directory, seal=False)
            status = reloaded.status
            self.assertFalse(status.revealed)
            self.assertFalse(status.invalidated)
            self.assertEqual(status.authorized_access_count, 0)
            self.assertEqual(status.journal_head_hash, seal_head)

    def test_durable_unauthorized_violation_survives_reload(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            custody, _ = self.durable_custody(directory)
            custody.record_violation(
                requester="paper-writer",
                reason="unauthorized out-of-band access",
                occurred_at="2026-08-12T12:30:00Z",
            )
            reloaded, _ = self.durable_custody(directory, seal=False)
            self.assertTrue(reloaded.status.invalidated)
            reloaded.seal(
                b'{"confirmatory": [1, 2, 3]}',
                split_manifest_hash=HASHES["split"],
                protocol_hash=make_protocol().sha256,
                code_hash=HASHES["code"],
                configuration_hash=HASHES["config"],
                pre_unblinding_interpretation_hash=HASHES["blind"],
                sealed_at="2026-08-12T12:00:00Z",
            )
            with self.assertRaises(HoldoutAccessViolation):
                reloaded.assert_confirmatory_claims_valid()

    def test_reload_rejects_rehashed_access_omission_addition_and_mismatch(self) -> None:
        def omit_reason(payload: dict[str, object]) -> None:
            payload.pop("violation_reason")

        def add_attestation(payload: dict[str, object]) -> None:
            payload["caller_attested_valid"] = True

        def mismatch_reason(payload: dict[str, object]) -> None:
            payload["violation_reason"] = "substituted explanation"

        def mismatch_identity(payload: dict[str, object]) -> None:
            payload["record"]["event_id"] = "0" * 64  # type: ignore[index]

        for name, mutate in (
            ("omission", omit_reason),
            ("addition", add_attestation),
            ("reason-mismatch", mismatch_reason),
            ("identity-mismatch", mismatch_identity),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                dir=ROOT / ".scientist-one-build/tmp"
            ) as directory:
                custody, _ = self.durable_custody(directory)
                custody.record_violation(
                    requester="paper-writer",
                    reason="out-of-band access",
                    occurred_at="2026-08-12T12:30:00Z",
                )
                journal = custody.journal_path
                assert journal is not None
                events = [
                    json.loads(line)
                    for line in journal.read_text(encoding="utf-8").splitlines()
                ]
                mutate(events[-1]["payload"])
                rewrite_custody_journal(journal, events)
                with self.assertRaises(HoldoutJournalError):
                    SimulatedHoldoutCustody(
                        (Role.EXPERIMENT_RUNNER.value,),
                        journal_root=directory,
                        journal_path="custody.jsonl",
                    )

    def test_live_admission_guard_refreshes_after_later_violation(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            custody, _ = self.durable_custody(directory)
            expected_seal = custody.seal_record
            assert expected_seal is not None
            started = threading.Event()
            completed = threading.Event()

            def violate() -> None:
                started.set()
                custody.record_violation(
                    requester="local-process",
                    reason="later out-of-band inspection",
                    occurred_at="2026-08-12T12:30:00Z",
                )
                completed.set()

            with custody.admission_guard() as before:
                self.assertEqual(before.seal, expected_seal)
                self.assertEqual(before.custody_label, "SIMULATED_NON_INDEPENDENT")
                self.assertTrue(before.durable_journal)
                self.assertTrue(before.sealed)
                self.assertFalse(before.revealed)
                self.assertEqual(before.protocol_hash, make_protocol().sha256)
                self.assertEqual(before.code_hash, HASHES["code"])
                self.assertEqual(before.configuration_hash, HASHES["config"])
                self.assertEqual(before.split_manifest_hash, HASHES["split"])
                self.assertEqual(
                    before.pre_unblinding_interpretation_hash,
                    HASHES["blind"],
                )
                self.assertEqual(before.authorized_access_count, 0)
                self.assertFalse(before.status.invalidated)
                self.assertEqual(
                    hashlib.sha256(before.journal_bytes).hexdigest(),
                    before.journal_sha256,
                )
                self.assertEqual(before.journal_size, len(before.journal_bytes))
                self.assertEqual(len(before.journal_identity_sha256), 64)
                worker = threading.Thread(target=violate)
                worker.start()
                self.assertTrue(started.wait(1.0))
                self.assertFalse(completed.wait(0.05))

            worker.join(1.0)
            self.assertFalse(worker.is_alive())
            self.assertTrue(completed.is_set())
            after = custody.admission_snapshot()
            self.assertNotEqual(after.journal_head_hash, before.journal_head_hash)
            self.assertTrue(after.status.invalidated)
            self.assertFalse(after.status.confirmatory_claims_valid)
            self.assertEqual(after.authorized_access_count, 0)
            self.assertIn("later out-of-band inspection", after.status.violation_reasons)

    def test_admission_guard_rejects_journal_namespace_aba_and_stale_anchor(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            custody, _ = self.durable_custody(directory)
            stale_head = custody.verify_journal()
            journal = custody.journal_path
            assert journal is not None
            stale_bytes = journal.read_bytes()
            custody.record_violation(
                requester="test-adapter",
                reason="advance the journal past its stale external anchor",
                occurred_at="2026-08-12T12:30:00Z",
            )
            anchored = custody.admission_snapshot()
            current_head = anchored.journal_head_hash
            current_identity = anchored.journal_identity_sha256
            current_bytes = journal.read_bytes()
            self.assertNotEqual(stale_head, current_head)
            self.assertNotEqual(stale_bytes, current_bytes)
            with self.assertRaises(HoldoutJournalError):
                with custody.admission_guard(
                    expected_journal_head_hash=stale_head
                ):
                    self.fail("a rolled-back external journal anchor was accepted")

            authentic = journal.with_name(journal.name + ".authentic")
            try:
                with self.assertRaises(HoldoutJournalError):
                    with custody.admission_guard(
                        expected_journal_head_hash=current_head,
                        expected_journal_identity_sha256=current_identity,
                    ) as evidence:
                        self.assertEqual(evidence.journal_bytes, current_bytes)
                        self.assertNotEqual(evidence.journal_bytes, stale_bytes)
                        os.replace(journal, authentic)
                        journal.write_bytes(stale_bytes)
                        self.assertEqual(journal.read_bytes(), stale_bytes)
            finally:
                if journal.exists():
                    journal.unlink()
                if authentic.exists():
                    os.replace(authentic, journal)
            self.assertEqual(custody.verify_journal(), current_head)

            # A byte-identical replacement retains the external head/content
            # hashes but creates a different lock domain; the identity anchor
            # must still reject it.
            os.replace(journal, authentic)
            journal.write_bytes(current_bytes)
            try:
                with self.assertRaises(HoldoutJournalError):
                    with custody.admission_guard(
                        expected_journal_head_hash=current_head,
                        expected_journal_identity_sha256=current_identity,
                    ):
                        self.fail("a replacement journal inode was accepted")
            finally:
                journal.unlink()
                os.replace(authentic, journal)

    def test_namespace_lock_blocks_replace_restore_second_adapter_release_attempt(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            custody, payload = self.durable_custody(directory)
            journal = custody.journal_path
            assert journal is not None
            sealed_only_bytes = journal.read_bytes()
            custody.record_violation(
                requester="test-adapter",
                reason="advance authentic custody state",
                occurred_at="2026-08-12T12:30:00Z",
            )
            anchored = custody.admission_snapshot()
            authentic = journal.with_name(journal.name + ".authentic")
            started = threading.Event()
            completed = threading.Event()
            rival_errors: list[BaseException] = []

            def rival_release_attempt() -> None:
                started.set()
                try:
                    rival = SimulatedHoldoutCustody(
                        ("experiment-runner",),
                        journal_root=ROOT,
                        journal_path=journal.relative_to(ROOT),
                    )
                    rival.seal(
                        payload,
                        split_manifest_hash=HASHES["split"],
                        protocol_hash=make_protocol().sha256,
                        code_hash=HASHES["code"],
                        configuration_hash=HASHES["config"],
                        pre_unblinding_interpretation_hash=HASHES["blind"],
                        sealed_at="2026-08-12T12:00:00Z",
                    )
                    with rival._reveal_admission_guard() as session:
                        direct_session_release(session)
                except BaseException as exc:
                    rival_errors.append(exc)
                finally:
                    completed.set()

            worker: threading.Thread | None = None
            with custody.admission_guard(
                expected_journal_head_hash=anchored.journal_head_hash,
                expected_journal_identity_sha256=anchored.journal_identity_sha256,
            ) as evidence:
                self.assertEqual(evidence.journal_bytes, anchored.journal_bytes)
                os.replace(journal, authentic)
                journal.write_bytes(sealed_only_bytes)
                worker = threading.Thread(target=rival_release_attempt)
                worker.start()
                self.assertTrue(started.wait(1.0))
                self.assertFalse(completed.wait(0.05))
                journal.unlink()
                os.replace(authentic, journal)

            assert worker is not None
            worker.join(1.0)
            self.assertFalse(worker.is_alive())
            self.assertTrue(completed.is_set())
            self.assertEqual(len(rival_errors), 1)
            self.assertIsInstance(rival_errors[0], HoldoutAccessViolation)
            after = custody.admission_snapshot()
            self.assertEqual(after.journal_head_hash, anchored.journal_head_hash)
            self.assertEqual(
                after.journal_identity_sha256,
                anchored.journal_identity_sha256,
            )

    def test_durable_journal_tampering_and_outside_path_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".scientist-one-build/tmp") as directory:
            custody, _ = self.durable_custody(directory)
            journal = custody.journal_path
            assert journal is not None
            content = journal.read_bytes()
            journal.write_bytes(content.replace(b'"SEAL"', b'"ACCESS"', 1))
            with self.assertRaises(HoldoutJournalError):
                custody.verify_journal()
        with self.assertRaises(PathSecurityError):
            SimulatedHoldoutCustody(
                ("runner",),
                journal_root=ROOT,
                journal_path="../outside-custody.jsonl",
            )


class StatisticsTests(unittest.TestCase):
    def test_seed_fold_checkpoint_resampling_requires_real_justification(self) -> None:
        observations = (
            UnitObservation(1.0, "subject-a", "seed-1"),
            UnitObservation(2.0, "subject-b", "seed-2"),
        )
        design = StatisticalUnitDesign("subject", "seed", observations, "seeds were reruns")
        with self.assertRaisesRegex(StatisticalValidationError, "pseudo-replication"):
            validate_statistical_units(design)
        justified = replace(design, pseudo_unit_independence_justified=True)
        self.assertTrue(validate_statistical_units(justified).valid)

    def test_same_analysis_or_dependency_unit_cannot_be_split_across_resamples(self) -> None:
        split_subject = StatisticalUnitDesign(
            "subject",
            "subject",
            (
                UnitObservation(1, "subject-a", "bootstrap-a", "subject-a"),
                UnitObservation(2, "subject-a", "bootstrap-b", "subject-a"),
            ),
            "subjects are sampled independently",
            repeated_measures=True,
        )
        report = validate_statistical_units(split_subject, raise_on_failure=False)
        self.assertFalse(report.valid)
        self.assertTrue(any("analysis unit" in issue for issue in report.issues))
        self.assertTrue(any("dependent observations" in issue for issue in report.issues))

    def test_valid_repeated_measure_design_resamples_whole_subjects(self) -> None:
        observations = (
            UnitObservation(1, "subject-a", "subject-a", "subject-a"),
            UnitObservation(2, "subject-a", "subject-a", "subject-a"),
            UnitObservation(3, "subject-b", "subject-b", "subject-b"),
            UnitObservation(4, "subject-b", "subject-b", "subject-b"),
        )
        design = StatisticalUnitDesign(
            "subject-time measurement",
            "subject",
            observations,
            "randomized subjects are independent; time points stay clustered",
            repeated_measures=True,
        )
        report = validate_statistical_units(design)
        self.assertTrue(report.valid)
        self.assertEqual(report.independent_unit_count, 2)
        self.assertEqual(report.observation_count, 4)

    def test_domain_invalid_label_permutation_is_rejected(self) -> None:
        invalid = DomainNullDesign(
            "time-series-label-shuffle",
            NullMethod.LABEL_PERMUTATION,
            "time block",
            ("temporal autocorrelation",),
            (),
            "labels follow time-dependent regimes",
            labels_exchangeable=False,
        )
        report = validate_domain_null(invalid, raise_on_failure=False)
        self.assertFalse(report.valid)
        self.assertTrue(any("not exchangeable" in issue for issue in report.issues))
        self.assertTrue(any("temporal autocorrelation" in issue for issue in report.issues))

    def test_block_null_preserves_domain_structure_and_matches_resampling_unit(self) -> None:
        units = StatisticalUnitDesign(
            "site",
            "site",
            (UnitObservation(1, "a", "a"), UnitObservation(2, "b", "b")),
            "sites are independently assigned",
        )
        null = DomainNullDesign(
            "site-block-null",
            NullMethod.BLOCK_PERMUTATION,
            "site",
            ("site", "season"),
            ("site", "season"),
            "assignments are exchangeable only within preregistered blocks",
            labels_exchangeable=False,
        )
        self.assertTrue(validate_domain_null(null, units).valid)
        with self.assertRaisesRegex(StatisticalValidationError, "does not match"):
            validate_domain_null(replace(null, exchangeability_unit="row"), units)

    def test_effect_size_uncertainty_and_test_are_reported_and_deterministic(self) -> None:
        treatment = (3.0, 4.0, 5.0, 6.0)
        control = (1.0, 2.0, 2.0, 3.0)
        first = analyze_two_group(
            treatment,
            control,
            bootstrap_resamples=400,
            permutation_resamples=400,
            seed=17,
        )
        second = analyze_two_group(
            treatment,
            control,
            bootstrap_resamples=400,
            permutation_resamples=400,
            seed=17,
        )
        self.assertEqual(first, second)
        self.assertEqual(first.estimate, mean_difference(treatment, control))
        self.assertIsNotNone(first.standardized_effect)
        self.assertLessEqual(first.ci_lower, first.estimate)
        self.assertGreaterEqual(first.ci_upper, first.estimate)
        self.assertGreaterEqual(first.p_value, 0)
        self.assertLessEqual(first.p_value, 1)

    def test_bootstrap_is_seeded_and_zero_variance_standardized_effect_is_explicit(self) -> None:
        one = bootstrap_mean_difference_ci((2, 3, 4), (0, 1, 2), resamples=200, seed=3)
        two = bootstrap_mean_difference_ci((2, 3, 4), (0, 1, 2), resamples=200, seed=3)
        self.assertEqual(one, two)
        self.assertIsNone(hedges_g((2, 2), (1, 1)))

    def test_holm_bonferroni_and_bh_multiplicity_are_monotone_and_bounded(self) -> None:
        p_values = (0.01, 0.03, 0.20)
        holm = adjust_pvalues(p_values, method=MultiplicityMethod.HOLM)
        bonferroni = adjust_pvalues(p_values, method=MultiplicityMethod.BONFERRONI)
        bh = adjust_pvalues(p_values, method=MultiplicityMethod.BENJAMINI_HOCHBERG)
        self.assertEqual(tuple(round(item.adjusted_p_value, 3) for item in holm), (0.03, 0.06, 0.2))
        self.assertEqual(tuple(round(item.adjusted_p_value, 3) for item in bonferroni), (0.03, 0.09, 0.6))
        self.assertEqual(tuple(round(item.adjusted_p_value, 3) for item in bh), (0.03, 0.045, 0.2))
        self.assertTrue(all(0 <= item.adjusted_p_value <= 1 for family in (holm, bonferroni, bh) for item in family))

    def test_multiplicity_plan_and_numeric_inputs_fail_closed(self) -> None:
        with self.assertRaisesRegex(StatisticalValidationError, "require a correction"):
            validate_multiplicity_plan(family_size=4, method=None)
        self.assertIsNone(validate_multiplicity_plan(family_size=1, method=None))
        with self.assertRaises(StatisticalValidationError):
            adjust_pvalues((0.1, float("nan")), method="holm")
        with self.assertRaises(StatisticalValidationError):
            adjust_pvalues((True, 0.1), method="holm")
        with self.assertRaises(StatisticalValidationError):
            mean_difference((True, 1.0), (0.0, 1.0))


class ClaimGraphTests(unittest.TestCase):
    def test_confirmatory_claim_defaults_fail_closed_at_verification_and_consumption(
        self,
    ) -> None:
        graph = make_claim_graph(confirmatory=True)
        defaulted = graph.verify_claim("claim-1", verifier_id="verifier-1")
        self.assertIs(defaulted.decision, ClaimDecision.INVALIDATED)
        self.assertEqual(graph.writer_view(), ())

        explicit = graph.verify_claim(
            "claim-1",
            verifier_id="verifier-1",
            confirmatory_evidence_valid=True,
        )
        self.assertIs(explicit.decision, ClaimDecision.ELIGIBLE)
        self.assertEqual(graph.writer_view(), ())
        self.assertEqual(
            len(graph.writer_view(confirmatory_evidence_valid=True)),
            1,
        )
        with self.assertRaisesRegex(
            ClaimNotEligibleError,
            "lacks freshly revalidated confirmatory authority",
        ):
            graph.require_eligible("claim-1")
        self.assertEqual(
            graph.require_eligible(
                "claim-1",
                confirmatory_evidence_valid=True,
            ),
            explicit,
        )

        batch_graph = make_claim_graph(confirmatory=True)
        self.assertIs(
            verify_claims(batch_graph, verifier_id="verifier-1")[0].decision,
            ClaimDecision.INVALIDATED,
        )

    def test_omitted_evidence_use_cannot_grant_scientific_writer_eligibility(self) -> None:
        scientific_template = make_claim_graph()
        template_claim = scientific_template.claims[0]
        # Sole intentional constructor omission: exercise the fail-closed default.
        omitted_classification = MaterialClaim(
            claim_id="omitted-classification",
            text=template_claim.text,
            evidence_links=template_claim.evidence_links,
            producer_role=template_claim.producer_role,
            confirmatory=template_claim.confirmatory,
        )
        self.assertIs(
            omitted_classification.evidence_use,
            ClaimEvidenceUse.NON_EVIDENTIARY,
        )

        graph = ClaimEvidenceGraph(evidence_resolver=resolve_test_evidence)
        for node in scientific_template.evidence:
            graph.add_evidence(node)
        graph.add_claim(omitted_classification)
        decision = graph.verify_claim(
            omitted_classification.claim_id,
            verifier_id="verifier-1",
        )

        self.assertIs(decision.decision, ClaimDecision.ELIGIBLE)
        self.assertEqual(graph.writer_view(), ())
        diagnostic = graph.writer_view(include_nonscientific=True)
        self.assertEqual(len(diagnostic), 1)
        self.assertEqual(
            diagnostic[0]["evidence_use"],
            ClaimEvidenceUse.NON_EVIDENTIARY.value,
        )

        serialized = graph.to_dict()
        self.assertEqual(
            serialized["claims"][0]["evidence_use"],
            ClaimEvidenceUse.NON_EVIDENTIARY.value,
        )
        rehydrated = ClaimEvidenceGraph.from_dict(
            serialized,
            evidence_resolver=resolve_test_evidence,
        )
        self.assertIs(
            rehydrated.claims[0].evidence_use,
            ClaimEvidenceUse.NON_EVIDENTIARY,
        )
        self.assertEqual(rehydrated.writer_view(), ())

        missing_serialized_classification = graph.to_dict()
        del missing_serialized_classification["claims"][0]["evidence_use"]
        with self.assertRaisesRegex(
            ValidationError,
            "serialized material claim schema is invalid",
        ):
            ClaimEvidenceGraph.from_dict(
                missing_serialized_classification,
                evidence_resolver=resolve_test_evidence,
            )

    def test_default_writer_view_excludes_eligible_nonscientific_claims(self) -> None:
        for evidence_use in (
            ClaimEvidenceUse.SYSTEM_FIXTURE,
            ClaimEvidenceUse.NON_EVIDENTIARY,
        ):
            with self.subTest(evidence_use=evidence_use):
                graph = make_claim_graph(evidence_use=evidence_use)
                decision = graph.verify_claim(
                    "claim-1",
                    verifier_id="verifier-1",
                )
                self.assertEqual(decision.decision, ClaimDecision.ELIGIBLE)
                self.assertEqual(graph.writer_view(), ())

    def test_explicit_nonscientific_writer_view_is_diagnostic_and_typed(self) -> None:
        graph = make_claim_graph(evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE)
        graph.verify_claim("claim-1", verifier_id="verifier-1")

        diagnostic = graph.writer_view(include_nonscientific=True)
        self.assertEqual(len(diagnostic), 1)
        self.assertEqual(
            diagnostic[0]["evidence_use"],
            ClaimEvidenceUse.SYSTEM_FIXTURE.value,
        )

        scientific = make_claim_graph()
        scientific.verify_claim("claim-1", verifier_id="verifier-1")
        self.assertNotIn("evidence_use", scientific.writer_view()[0])
        self.assertEqual(
            scientific.writer_view(include_nonscientific=True)[0]["evidence_use"],
            ClaimEvidenceUse.SCIENTIFIC.value,
        )

    def test_serialized_claim_class_flip_cannot_reuse_support_receipts(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            registry = ArtifactRegistry(directory, "claim-use-registry")
            resolver = artifact_registry_resolver(
                registry,
                resolver_id="claim-use-test-resolver",
            )
            graph = ClaimEvidenceGraph(evidence_resolver=resolver)
            nodes: list[EvidenceNode] = []
            links: list[EvidenceLink] = []
            for kind in sorted(REQUIRED_EVIDENCE_KINDS, key=lambda item: item.value):
                parents: tuple[str, ...] = ()
                if kind is EvidenceKind.FIGURE_OR_TABLE:
                    table = registry.put_bytes(
                        b"metric,effect_size\nprimary,1.0\n",
                        logical_type="results_table",
                        origin="claim-use-class-flip-test",
                        creator_role=Role.PAPER_WRITER,
                        mime_type="text/csv",
                    )
                    parents = (table.sha256,)
                content = f"bounded {kind.value} fixture evidence".encode()
                record = registry.put_bytes(
                    content,
                    logical_type=f"claim_evidence.{kind.value}",
                    origin="claim-use-class-flip-test",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    parent_artifacts=parents,
                )
                node = EvidenceNode(
                    f"fixture:{kind.value}",
                    kind,
                    record.sha256,
                    content.decode(),
                    verified=True,
                    frozen=True,
                    supports_claim=True,
                    locally_verifiable=True,
                )
                nodes.append(node)
                links.append(EvidenceLink(node.evidence_id, kind))
            claim = MaterialClaim(
                "fixture-claim",
                "The bounded system fixture exercises the complete claim graph.",
                tuple(links),
                Role.EXPERIMENT_RUNNER,
                confirmatory=False,
                evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
            )
            for node in nodes:
                graph.add_evidence(register_support_receipt(registry, claim, node))
            graph.add_claim(claim)
            self.assertEqual(
                graph.verify_claim(
                    claim.claim_id,
                    verifier_id="verifier-1",
                ).decision,
                ClaimDecision.ELIGIBLE,
            )
            self.assertEqual(graph.writer_view(), ())

            serialized = graph.to_dict()
            self.assertEqual(
                serialized["claims"][0]["evidence_use"],
                ClaimEvidenceUse.SYSTEM_FIXTURE.value,
            )
            serialized["claims"][0]["evidence_use"] = (
                ClaimEvidenceUse.SCIENTIFIC.value
            )
            relabeled = ClaimEvidenceGraph.from_dict(
                serialized,
                evidence_resolver=resolver,
            )
            decision = relabeled.verify_claim(
                claim.claim_id,
                verifier_id="verifier-1",
            )
            self.assertEqual(decision.decision, ClaimDecision.UNSUPPORTED)
            self.assertIn("trusted resolver failed", decision.reason)
            self.assertEqual(
                relabeled.writer_view(include_nonscientific=True),
                (),
            )

    def test_arbitrary_registered_bytes_and_true_node_flags_need_support_receipt(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            registry = ArtifactRegistry(directory, "claim-registry")
            record = registry.put_bytes(
                b"arbitrary bytes with no independent semantic review",
                logical_type="claim_evidence.result_artifact",
                origin="scientific-core-arbitrary-evidence-test",
                creator_role=Role.EXPERIMENT_RUNNER,
            )
            node = EvidenceNode(
                "arbitrary-result",
                EvidenceKind.RESULT,
                record.sha256,
                "caller asserts these arbitrary bytes support the claim",
                verified=True,
                frozen=True,
                supports_claim=True,
                locally_verifiable=True,
            )
            claim = MaterialClaim(
                "arbitrary-claim",
                "Arbitrary registered bytes establish the scientific result.",
                (EvidenceLink(node.evidence_id, node.kind),),
                Role.EXPERIMENT_RUNNER,
                confirmatory=False,
                evidence_use=ClaimEvidenceUse.SCIENTIFIC,
            )
            graph = ClaimEvidenceGraph(
                evidence_resolver=artifact_registry_resolver(registry)
            )
            graph.add_evidence(node)
            graph.add_claim(claim)
            decision = graph.verify_claim(
                claim.claim_id,
                verifier_id="verifier-1",
            )
            self.assertEqual(decision.decision, ClaimDecision.UNSUPPORTED)
            self.assertIn("trusted resolver failed", decision.reason)
            self.assertEqual(graph.writer_view(), ())

    def test_support_receipt_binds_exact_claim_text_evidence_and_verifier(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            registry = ArtifactRegistry(directory, "claim-registry")
            record = registry.put_bytes(
                b"materialized bounded result",
                logical_type="claim_evidence.result_artifact",
                origin="scientific-core-support-binding-test",
                creator_role=Role.EXPERIMENT_RUNNER,
            )
            node = EvidenceNode(
                "bound-result",
                EvidenceKind.RESULT,
                record.sha256,
                "materialized bounded result",
                verified=True,
                frozen=True,
                supports_claim=True,
                locally_verifiable=True,
            )
            claim = MaterialClaim(
                "bound-claim",
                "The exact materialized result supports this exact claim.",
                (EvidenceLink(node.evidence_id, node.kind),),
                Role.EXPERIMENT_RUNNER,
                confirmatory=False,
                evidence_use=ClaimEvidenceUse.SCIENTIFIC,
            )
            wrong_claim = replace(claim, text="A different claim text.")
            wrong_receipt_node = register_support_receipt(
                registry,
                wrong_claim,
                node,
            )
            resolver = artifact_registry_resolver(registry)
            with self.assertRaisesRegex(ValidationError, "binding mismatch"):
                resolver(claim, wrong_receipt_node)

            bound_node = register_support_receipt(registry, claim, node)
            writer_semantics_tampered = replace(
                bound_node,
                description="This result generalizes without limitation.",
            )
            with self.assertRaisesRegex(ValidationError, "binding mismatch"):
                resolver(claim, writer_semantics_tampered)

            conflicting_semantics_node = register_support_receipt(
                registry,
                claim,
                node,
                supports_claim=False,
            )
            conflicting_graph = ClaimEvidenceGraph(evidence_resolver=resolver)
            conflicting_graph.add_evidence(conflicting_semantics_node)
            conflicting_graph.add_claim(claim)
            conflicting_decision = conflicting_graph.verify_claim(
                claim.claim_id,
                verifier_id="verifier-1",
            )
            self.assertEqual(
                conflicting_decision.decision,
                ClaimDecision.UNSUPPORTED,
            )
            self.assertIn("support status conflicts", conflicting_decision.reason)

            other_verifier_node = register_support_receipt(
                registry,
                claim,
                node,
                verifier_id="different-claim-verifier",
            )
            graph = ClaimEvidenceGraph(evidence_resolver=resolver)
            graph.add_evidence(other_verifier_node)
            graph.add_claim(claim)
            decision = graph.verify_claim(
                claim.claim_id,
                verifier_id="verifier-1",
            )
            self.assertEqual(decision.decision, ClaimDecision.UNSUPPORTED)
            self.assertIn("verifier mismatch", decision.reason)

    def test_sha_shaped_placeholders_fail_closed_without_evidence_resolver(self) -> None:
        placeholder = EvidenceNode(
            "placeholder",
            EvidenceKind.RESULT,
            "f" * 64,
            "unresolved SHA-shaped placeholder",
        )
        self.assertFalse(placeholder.verified)
        self.assertFalse(placeholder.frozen)
        self.assertFalse(placeholder.supports_claim)
        self.assertFalse(placeholder.locally_verifiable)

        graph = make_claim_graph(evidence_resolver=None)
        decision = graph.verify_claim("claim-1", verifier_id="verifier-1")
        self.assertEqual(decision.decision, ClaimDecision.UNSUPPORTED)
        self.assertIn("no trusted evidence resolver", decision.reason)
        self.assertEqual(decision.evidence_receipt_hashes, ())
        self.assertEqual(graph.writer_view(), ())

    def test_forged_or_mismatched_evidence_receipts_are_rejected(self) -> None:
        def forged_receipt(
            claim: MaterialClaim,
            node: EvidenceNode,
        ) -> EvidenceVerificationReceipt:
            del claim
            return EvidenceVerificationReceipt(
                evidence_id=node.evidence_id,
                evidence_kind=node.kind,
                artifact_hash=node.artifact_hash,
                content_sha256="0" * 64,
                registry_record_hash="1" * 64,
                support_receipt_hash="2" * 64,
                support_receipt_record_hash="3" * 64,
                support_verifier_id="verifier-1",
                support_verifier_role=Role.CLAIM_VERIFIER,
                resolver_id="forged-receipt",
                validation_result="PASS",
                frozen=True,
                supports_claim=True,
                contradicts_claim=False,
                locally_verifiable=True,
            )

        graph = make_claim_graph(evidence_resolver=forged_receipt)
        decision = graph.verify_claim("claim-1", verifier_id="verifier-1")
        self.assertEqual(decision.decision, ClaimDecision.UNSUPPORTED)
        self.assertIn("resolved bytes do not match", decision.reason)
        self.assertEqual(graph.writer_view(), ())

        malformed = make_claim_graph(
            evidence_resolver=lambda claim, node: True,  # type: ignore[arg-type,return-value]
        )
        malformed_decision = malformed.verify_claim(
            "claim-1",
            verifier_id="verifier-1",
        )
        self.assertEqual(malformed_decision.decision, ClaimDecision.UNSUPPORTED)
        self.assertIn("no valid receipt", malformed_decision.reason)

        def semantic_conflict(
            claim: MaterialClaim,
            node: EvidenceNode,
        ) -> EvidenceVerificationReceipt:
            receipt = resolve_test_evidence(claim, node)
            return replace(receipt, supports_claim=False)

        conflicted = make_claim_graph(evidence_resolver=semantic_conflict)
        conflict_decision = conflicted.verify_claim(
            "claim-1",
            verifier_id="verifier-1",
        )
        self.assertEqual(conflict_decision.decision, ClaimDecision.UNSUPPORTED)
        self.assertIn("support status conflicts", conflict_decision.reason)

    def test_registry_resolver_binds_kind_frozen_metadata_and_bytes_and_detects_corruption(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            registry = ArtifactRegistry(directory, "claim-registry")
            resolver = artifact_registry_resolver(
                registry,
                resolver_id="test-artifact-registry",
            )
            graph = ClaimEvidenceGraph(evidence_resolver=resolver)
            links: list[EvidenceLink] = []
            records = {}
            nodes: list[EvidenceNode] = []
            for kind in sorted(REQUIRED_EVIDENCE_KINDS, key=lambda value: value.value):
                content = f"materialized {kind.value} evidence".encode()
                parents: tuple[str, ...] = ()
                if kind is EvidenceKind.FIGURE_OR_TABLE:
                    table = registry.put_bytes(
                        b"metric,effect_size\nprimary,1.0\n",
                        logical_type="results_table",
                        origin="scientific-core-registry-test",
                        creator_role=Role.PAPER_WRITER,
                        mime_type="text/csv",
                    )
                    parents = (table.sha256,)
                record = registry.put_bytes(
                    content,
                    logical_type=f"claim_evidence.{kind.value}",
                    origin="scientific-core-registry-test",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    parent_artifacts=parents,
                )
                evidence_id = f"registry:{kind.value}"
                nodes.append(
                    EvidenceNode(
                        evidence_id,
                        kind,
                        record.sha256,
                        content.decode(),
                        verified=True,
                        frozen=True,
                        supports_claim=True,
                        locally_verifiable=True,
                    )
                )
                links.append(EvidenceLink(evidence_id, kind))
                records[kind] = record
            claim = MaterialClaim(
                "registry-claim",
                "The materialized synthetic evidence supports this bounded claim.",
                tuple(links),
                Role.EXPERIMENT_RUNNER,
                confirmatory=False,
                evidence_use=ClaimEvidenceUse.SCIENTIFIC,
            )
            for node in nodes:
                graph.add_evidence(register_support_receipt(registry, claim, node))
            graph.add_claim(claim)
            decision = graph.verify_claim(
                "registry-claim",
                verifier_id="verifier-1",
            )
            self.assertEqual(decision.decision, ClaimDecision.ELIGIBLE)
            self.assertEqual(
                len(decision.evidence_receipt_hashes),
                len(REQUIRED_EVIDENCE_KINDS),
            )
            writer = graph.writer_view()
            self.assertEqual(len(writer), 1)
            self.assertEqual(
                writer[0]["evidence_receipt_hashes"],
                list(decision.evidence_receipt_hashes),
            )

            serialized = graph.to_dict()
            rehydrated = ClaimEvidenceGraph.from_dict(
                serialized,
                evidence_resolver=resolver,
            )
            self.assertEqual(rehydrated.decisions, ())
            self.assertEqual(rehydrated.writer_view(), ())
            refreshed = rehydrated.verify_claim(
                "registry-claim",
                verifier_id="verifier-1",
            )
            self.assertEqual(refreshed.decision, ClaimDecision.ELIGIBLE)
            self.assertEqual(rehydrated.writer_view(), writer)

            unknown_field = graph.to_dict()
            unknown_field["evidence"][0]["unexpected"] = True
            with self.assertRaisesRegex(ValidationError, "schema"):
                ClaimEvidenceGraph.from_dict(
                    unknown_field,
                    evidence_resolver=resolver,
                )
            unknown_decision_field = graph.to_dict()
            unknown_decision_field["decisions"][0]["caller_eligible"] = True
            with self.assertRaisesRegex(ValidationError, "decision schema"):
                ClaimEvidenceGraph.from_dict(
                    unknown_decision_field,
                    evidence_resolver=resolver,
                )
            forged_decision = graph.to_dict()
            forged_decision["decisions"][0]["reason"] = "forged eligibility"
            with self.assertRaisesRegex(ValidationError, "hash mismatch"):
                ClaimEvidenceGraph.from_dict(
                    forged_decision,
                    evidence_resolver=resolver,
                )

            result_record = records[EvidenceKind.RESULT]
            (Path(directory) / result_record.path).write_bytes(b"corrupt result bytes")
            self.assertEqual(graph.writer_view(), ())
            self.assertEqual(rehydrated.writer_view(), ())
            with self.assertRaisesRegex(ClaimNotEligibleError, "stale"):
                graph.require_eligible("registry-claim")
            with self.assertRaisesRegex(ClaimNotEligibleError, "stale"):
                rehydrated.require_eligible("registry-claim")

    def test_support_receipt_corruption_after_serialization_revokes_fresh_writer_view(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            registry = ArtifactRegistry(directory, "claim-registry")
            resolver = artifact_registry_resolver(registry)
            graph = ClaimEvidenceGraph(evidence_resolver=resolver)
            nodes: list[EvidenceNode] = []
            links: list[EvidenceLink] = []
            for kind in sorted(REQUIRED_EVIDENCE_KINDS, key=lambda item: item.value):
                parents: tuple[str, ...] = ()
                if kind is EvidenceKind.FIGURE_OR_TABLE:
                    table = registry.put_bytes(
                        b"metric,effect_size\nprimary,1.0\n",
                        logical_type="results_table",
                        origin="support-receipt-corruption-test",
                        creator_role=Role.PAPER_WRITER,
                        mime_type="text/csv",
                    )
                    parents = (table.sha256,)
                record = registry.put_bytes(
                    f"bounded {kind.value}".encode(),
                    logical_type=f"claim_evidence.{kind.value}",
                    origin="support-receipt-corruption-test",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    parent_artifacts=parents,
                )
                node = EvidenceNode(
                    f"post-claims:{kind.value}",
                    kind,
                    record.sha256,
                    f"bounded {kind.value}",
                    verified=True,
                    frozen=True,
                    supports_claim=True,
                    locally_verifiable=True,
                )
                nodes.append(node)
                links.append(EvidenceLink(node.evidence_id, kind))
            claim = MaterialClaim(
                "post-claims-corruption",
                "All frozen evidence supports this bounded synthetic claim.",
                tuple(links),
                Role.EXPERIMENT_RUNNER,
                confirmatory=False,
                evidence_use=ClaimEvidenceUse.SCIENTIFIC,
            )
            for node in nodes:
                graph.add_evidence(register_support_receipt(registry, claim, node))
            graph.add_claim(claim)
            self.assertEqual(
                graph.verify_claim(
                    claim.claim_id,
                    verifier_id="verifier-1",
                ).decision,
                ClaimDecision.ELIGIBLE,
            )
            serialized = graph.to_dict()
            receipt_hash = graph.evidence[0].verification_receipt_hash
            self.assertIsNotNone(receipt_hash)
            receipt_record = registry.get_metadata(receipt_hash)  # type: ignore[arg-type]
            (Path(directory) / receipt_record.path).write_bytes(b"corrupt receipt bytes")

            rehydrated = ClaimEvidenceGraph.from_dict(
                serialized,
                evidence_resolver=resolver,
            )
            refreshed = rehydrated.verify_claim(
                claim.claim_id,
                verifier_id="verifier-1",
            )
            self.assertEqual(refreshed.decision, ClaimDecision.UNSUPPORTED)
            self.assertEqual(rehydrated.writer_view(), ())

    def test_registry_resolver_rejects_unmaterialized_figure_and_kind_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            registry = ArtifactRegistry(directory, "claim-registry")
            arbitrary_record = registry.put_bytes(
                b"arbitrary bytes with no independent semantic review",
                logical_type="claim_evidence.figure_or_table",
                origin="scientific-core-arbitrary-evidence-test",
                creator_role=Role.EXPERIMENT_RUNNER,
            )
            arbitrary_node = EvidenceNode(
                "arbitrary-figure",
                EvidenceKind.FIGURE_OR_TABLE,
                arbitrary_record.sha256,
                "caller asserts these arbitrary bytes support the claim",
                verified=True,
                frozen=True,
                supports_claim=True,
                locally_verifiable=True,
            )
            arbitrary_claim = MaterialClaim(
                "arbitrary-claim",
                "Arbitrary registered bytes establish the scientific result.",
                (EvidenceLink(arbitrary_node.evidence_id, arbitrary_node.kind),),
                Role.EXPERIMENT_RUNNER,
                confirmatory=False,
                evidence_use=ClaimEvidenceUse.SCIENTIFIC,
            )
            arbitrary_graph = ClaimEvidenceGraph(
                evidence_resolver=artifact_registry_resolver(registry)
            )
            arbitrary_graph.add_evidence(
                register_support_receipt(
                    registry,
                    arbitrary_claim,
                    arbitrary_node,
                )
            )
            arbitrary_graph.add_claim(arbitrary_claim)
            arbitrary_decision = arbitrary_graph.verify_claim(
                arbitrary_claim.claim_id,
                verifier_id="verifier-1",
            )
            self.assertEqual(arbitrary_decision.decision, ClaimDecision.UNSUPPORTED)
            self.assertIn("trusted resolver failed", arbitrary_decision.reason)
            self.assertEqual(arbitrary_graph.writer_view(), ())

            wrong_kind_record = registry.put_bytes(
                b"table and figure",
                logical_type="claim_evidence.result_artifact",
                origin="scientific-core-kind-test",
                creator_role=Role.EXPERIMENT_RUNNER,
            )
            node = EvidenceNode(
                "figure-placeholder",
                EvidenceKind.FIGURE_OR_TABLE,
                wrong_kind_record.sha256,
                "table and figure",
                verified=True,
                frozen=True,
                supports_claim=True,
                locally_verifiable=True,
            )
            claim = MaterialClaim(
                "kind-claim",
                "The figure depicts the result.",
                (EvidenceLink(node.evidence_id, node.kind),),
                Role.EXPERIMENT_RUNNER,
                confirmatory=False,
                evidence_use=ClaimEvidenceUse.SCIENTIFIC,
            )
            resolver = artifact_registry_resolver(registry)
            with self.assertRaisesRegex(ValidationError, "kind mismatch"):
                resolver(claim, node)

            materialized_table = registry.put_bytes(
                b"metric,effect_size\nprimary,1.0\n",
                logical_type="results_table",
                origin="scientific-core-unfrozen-test",
                creator_role=Role.PAPER_WRITER,
                mime_type="text/csv",
            )
            unfrozen_record = registry.put_bytes(
                b"unfrozen figure evidence",
                logical_type="claim_evidence.figure_or_table",
                origin="scientific-core-unfrozen-test",
                creator_role=Role.EXPERIMENT_RUNNER,
                parent_artifacts=(materialized_table.sha256,),
                frozen=False,
            )
            unfrozen_node = replace(
                node,
                evidence_id="unfrozen-figure",
                artifact_hash=unfrozen_record.sha256,
            )
            unfrozen_claim = replace(
                claim,
                evidence_links=(
                    EvidenceLink(unfrozen_node.evidence_id, unfrozen_node.kind),
                ),
            )
            unfrozen_node = register_support_receipt(
                registry,
                unfrozen_claim,
                unfrozen_node,
            )
            unfrozen_graph = ClaimEvidenceGraph(evidence_resolver=resolver)
            unfrozen_graph.add_evidence(unfrozen_node)
            unfrozen_graph.add_claim(unfrozen_claim)
            unfrozen_decision = unfrozen_graph.verify_claim(
                unfrozen_claim.claim_id,
                verifier_id="verifier-1",
            )
            self.assertEqual(unfrozen_decision.decision, ClaimDecision.UNSUPPORTED)
            self.assertIn("not frozen", unfrozen_decision.reason)

            unmaterialized = EvidenceNode(
                "unmaterialized-figure",
                EvidenceKind.FIGURE_OR_TABLE,
                "a" * 64,
                "SHA placeholder without bytes",
                verified=True,
                frozen=True,
                supports_claim=True,
                locally_verifiable=True,
            )
            with self.assertRaises(ArtifactError):
                resolver(claim, unmaterialized)

    def test_claim_requires_every_typed_link(self) -> None:
        graph = make_claim_graph(omit=EvidenceKind.ROBUSTNESS)
        decision = graph.verify_claim("claim-1", verifier_id="verifier-1")
        self.assertEqual(decision.decision, ClaimDecision.UNSUPPORTED)
        self.assertEqual(decision.missing_kinds, (EvidenceKind.ROBUSTNESS,))
        self.assertEqual(graph.writer_view(), ())
        with self.assertRaises(ClaimNotEligibleError):
            graph.require_eligible("claim-1")

    def test_only_claim_verifier_can_issue_eligibility(self) -> None:
        graph = make_claim_graph()
        with self.assertRaises(AuthorizationError):
            graph.verify_claim(
                "claim-1",
                verifier_id="writer-1",
                verifier_role=Role.PAPER_WRITER,
            )
        with self.assertRaises(AuthorizationError):
            MaterialClaim(
                "bad",
                "text",
                (),
                Role.CLAIM_VERIFIER,
                evidence_use=ClaimEvidenceUse.SCIENTIFIC,
            )

    def test_complete_verified_graph_produces_narrow_eligible_writer_view(self) -> None:
        graph = make_claim_graph()
        decision = graph.verify_claim("claim-1", verifier_id="verifier-1")
        self.assertEqual(decision.status, ClaimDecision.ELIGIBLE)
        view = graph.writer_view()
        self.assertEqual(len(view), 1)
        self.assertEqual(view[0]["verifier_decision"], "ELIGIBLE")
        self.assertEqual(view[0]["claim_id"], "claim-1")
        self.assertTrue(view[0]["scope_qualifier"])
        self.assertTrue(view[0]["limitations"])
        self.assertEqual(len(graph.sha256), 64)

    def test_unfrozen_unverified_or_unverifiable_evidence_rejects_claim(self) -> None:
        for properties in (
            {"frozen": False},
            {"verified": False},
            {"locally_verifiable": False},
        ):
            with self.subTest(properties=properties):
                graph = make_claim_graph(overrides={EvidenceKind.SOURCE_CITATION: properties})
                decision = graph.verify_claim("claim-1", verifier_id="verifier-1")
                self.assertEqual(decision.decision, ClaimDecision.UNSUPPORTED)
                self.assertFalse(graph.writer_view())

    def test_explicit_and_node_contradictions_are_rejected(self) -> None:
        graph = make_claim_graph(
            overrides={EvidenceKind.RESULT: {"supports_claim": False, "contradicts_claim": True}}
        )
        decision = graph.verify_claim("claim-1", verifier_id="verifier-1")
        self.assertEqual(decision.decision, ClaimDecision.CONTRADICTED)
        other = make_claim_graph()
        contradiction_node = text_evidence(
            "contradictory-result",
            EvidenceKind.RESULT,
            "A frozen robustness result reverses the effect.",
            supports_claim=False,
            contradicts_claim=True,
        )
        other.add_evidence(contradiction_node)
        other.add_contradiction(
            Contradiction("claim-1", "contradictory-result", "robustness sign reversal")
        )
        self.assertEqual(
            other.verify_claim("claim-1", verifier_id="verifier-1").decision,
            ClaimDecision.CONTRADICTED,
        )

    def test_holdout_violation_replaces_prior_eligibility_and_removes_writer_claim(self) -> None:
        graph = make_claim_graph(confirmatory=True)
        graph.verify_claim(
            "claim-1",
            verifier_id="verifier-1",
            confirmatory_evidence_valid=True,
        )
        custody, _ = seal_custody(self)
        custody.record_violation(requester="agent", reason="out-of-band inspection")
        decisions = graph.apply_custody_status(custody.status)
        self.assertEqual(decisions[0].decision, ClaimDecision.INVALIDATED)
        self.assertEqual(graph.writer_view(), ())

    def test_writer_view_contains_only_eligible_claims(self) -> None:
        eligible = make_claim_graph(claim_id="eligible")
        incomplete = make_claim_graph(claim_id="incomplete", omit=EvidenceKind.LIMITATION)
        for node in incomplete.evidence:
            eligible.add_evidence(node)
        for claim in incomplete.claims:
            eligible.add_claim(claim)
        eligible.verify_claim("eligible", verifier_id="verifier-1")
        eligible.verify_claim("incomplete", verifier_id="verifier-1")
        self.assertEqual([item["claim_id"] for item in eligible.writer_view()], ["eligible"])

    def test_evidence_and_claim_ids_are_immutable_content_bindings(self) -> None:
        graph = make_claim_graph()
        existing = graph.evidence[0]
        with self.assertRaisesRegex(ValidationError, "different immutable evidence"):
            graph.add_evidence(
                EvidenceNode(
                    existing.evidence_id,
                    existing.kind,
                    "f" * 64,
                    "different evidence",
                )
            )

    def test_nested_evidence_metadata_is_deeply_frozen(self) -> None:
        supplied = {"nested": {"values": [1, 2]}}
        node = EvidenceNode(
            "deep-metadata",
            EvidenceKind.RESULT,
            "e" * 64,
            "deeply frozen metadata",
            metadata=supplied,  # type: ignore[arg-type]
        )
        supplied["nested"]["values"].append(3)  # type: ignore[index,union-attr]
        self.assertEqual(node.metadata_dict, {"nested": {"values": [1, 2]}})
        exposed = node.metadata_dict
        exposed["nested"]["values"].append(4)
        self.assertEqual(node.metadata_dict, {"nested": {"values": [1, 2]}})

    def test_stale_eligibility_is_rejected_and_decision_history_preserves_invalidation(self) -> None:
        graph = make_claim_graph(confirmatory=True)
        graph.verify_claim(
            "claim-1",
            verifier_id="verifier-1",
            confirmatory_evidence_valid=True,
        )
        contradiction = text_evidence(
            "later-contradiction",
            EvidenceKind.RESULT,
            "later frozen result reverses the finding",
            supports_claim=False,
            contradicts_claim=True,
        )
        graph.add_evidence(contradiction)
        graph.add_contradiction(
            Contradiction("claim-1", contradiction.evidence_id, "later robustness reversal")
        )
        with self.assertRaisesRegex(ClaimNotEligibleError, "stale"):
            graph.require_eligible(
                "claim-1", confirmatory_evidence_valid=True
            )
        graph.invalidate_confirmatory_claims(reason="custody violation")
        self.assertEqual(
            tuple(item.decision for item in graph.decision_history),
            (ClaimDecision.ELIGIBLE, ClaimDecision.INVALIDATED),
        )

    def test_confirmatory_validity_flag_cannot_use_truthy_untyped_data(self) -> None:
        graph = make_claim_graph()
        with self.assertRaisesRegex(ValidationError, "must be boolean"):
            graph.verify_claim(
                "claim-1",
                verifier_id="verifier-1",
                confirmatory_evidence_valid="false",  # type: ignore[arg-type]
            )

        class UntypedCustodyStatus:
            confirmatory_claims_valid = "false"
            violation_reasons: tuple[str, ...] = ()

        with self.assertRaisesRegex(ValidationError, "must be boolean"):
            graph.apply_custody_status(UntypedCustodyStatus())


if __name__ == "__main__":
    unittest.main()
