from __future__ import annotations

from dataclasses import asdict, dataclass, fields, is_dataclass, replace
from enum import Enum
import hashlib
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
from typing import Any, Mapping
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.claims import (
    CLAIM_GRAPH_RESOLVER_ID,
    ClaimDecision,
    ClaimEvidenceGraph,
    ClaimEvidenceUse,
    EvidenceKind,
    EvidenceLink,
    EvidenceNode,
    EvidenceSupportReceipt,
    EvidenceVerificationReceipt,
    MaterialClaim,
    REQUIRED_EVIDENCE_KINDS,
    artifact_registry_resolver,
)
from scientist_one.errors import ArtifactError, FrozenArtifactError, ValidationError
from scientist_one.external import AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA
from scientist_one.domains import (
    DomainKind,
    GenericMLExample,
    GenericMLValidityEvidence,
    SplitRole,
    materialize_domain_validity,
    register_domain_evidence_source,
    register_domain_raw_fixture_source,
)
from scientist_one.holdout import ConfirmatoryEvaluatorSpec, SimulatedHoldoutCustody
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import MacroState, utc_now
from scientist_one.recovery import (
    ConfirmatoryRevealAuthority,
    FreshCustodyEvidence,
    RecoveryManager,
    RegisteredArtifactSelector,
)
from scientist_one.resources import ResourceRuntimeState, ValidityBudgetSnapshot
from scientist_one.gates import (
    AuthorizationOutcome,
    AutonomousDecisionRecord,
    ChallengeCategory,
    ChallengeFinding,
    ChallengeSeverity,
    ChallengeStatus,
    ChallengerCategoryReview,
    ChallengerExecutionStatus,
    DimensionStatus,
    HumanGate,
    HumanGatePolicy,
    HumanGateProfile,
    JudgmentSubjectKind,
    SemanticJudgmentReceipt,
    SoundnessAssessment,
    SoundnessAuthorityKind,
    SoundnessDimension,
    SoundnessDimensionEvidenceReceipt,
    SoundnessVerdict,
    assess_soundness,
    register_challenge_finding,
    register_challenger_category_review,
    register_scientific_soundness_assessment,
    register_soundness_dimension_receipt,
    require_scientific_soundness_assessment,
)
from scientist_one.paper_pipeline import (
    ArtifactReadinessBinding,
    AuthoritativeClaim,
    AuthoritativeMetric,
    AuthoritativeResearchBundle,
    ClaimPaperRequirements,
    ConfirmatoryAuthorityScope,
    ConfirmatoryClaimAuthority,
    EvidenceSourceBinding,
    GeneratedAsset,
    HardBlocker,
    ManuscriptSection,
    MetricDirection,
    MetricEvidenceStatus,
    MethodCodeBinding,
    PaperCandidate,
    PaperClaim,
    PaperNumericAssertion,
    PaperVerification,
    READINESS_DIMENSIONS,
    ReferenceAuthorityBinding,
    ReferenceDepth,
    ReferenceUse,
    VenueFamily,
    VenueFit,
    VenueProfile,
    assess_venue,
    _authoritative_bundle_from_json,
    _derive_method_bindings,
    _exact_numeric_equal,
    _derive_claim_paper_requirements,
    _paper_candidate_from_json,
    _required_paper_evidence_hashes,
    _resolve_candidate_bundle_artifacts,
    _require_live_venue_semantic_judgment,
    _require_scientific_reference_source_authority,
    _verify_reference_use,
    build_authoritative_research_bundle,
    default_venue_profiles,
    register_authoritative_research_bundle,
    register_approved_venue_profile,
    register_paper_verification,
    register_confirmatory_claim_authority,
    register_paper_manuscript,
    register_venue_readiness_manifest,
    register_venue_requirement_receipt,
    require_approved_venue_profile,
    require_confirmatory_claim_authority,
    verify_paper,
)
from scientist_one.research_os import _run_literature, run_research_os_fixture
from scientist_one.protocol import (
    BaselineSpec,
    ConfidenceIntervalSpec,
    DataRoles,
    DomainNullSpec,
    ExecutionConditions,
    InterpretationRules,
    ProtocolComputeBudget,
    ResearchProtocol,
    SeedPolicy,
    StudyVersion,
    StatisticalTestSpec,
    validate_protocol,
)
from scientist_one.research_state import (
    Claim as StateClaim,
    ClaimReview,
    ClaimSemanticsReceipt,
    ClaimSemanticsEvidenceScope,
    ClaimStrength,
    ClaimType,
    Evidence as StateEvidence,
    Implementation as StateImplementation,
    Method as StateMethod,
    Metric as StateMetric,
    MetricDirection as StateMetricDirection,
    MetricLevel,
    ObjectReference,
    RecordStatus,
    ReferenceVerificationDepth,
    ResearchQuestion,
    ResearchStateRepository,
    ResearchStateAuthorityBinding,
    ResearchStateAuthoritySnapshot,
    register_claim_semantics_receipt,
    register_research_state_snapshot,
    register_scientific_claim_evidence_projection,
    resolve_research_state_authority,
    Result as StateResult,
    Run as StateRun,
    VerificationStatus,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    require_audited_claim_bound_reference_authority,
    require_confirmatory_timeline_receipt,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def bundle_fixture_id(bundle: AuthoritativeResearchBundle) -> str:
    return (
        "paper-bundle-"
        + hashlib.sha256(canonical_json_bytes(bundle)).hexdigest()[:32]
    )


PROJECT_ROOT = Path(__file__).resolve().parents[1]
_CACHED_AUTHORITY_TEMPORARY: tempfile.TemporaryDirectory[str] | None = None
_CACHED_AUTHORITY_FIXTURE: "PaperAuthorityFixture | None" = None


def tearDownModule() -> None:
    global _CACHED_AUTHORITY_FIXTURE, _CACHED_AUTHORITY_TEMPORARY
    _CACHED_AUTHORITY_FIXTURE = None
    if _CACHED_AUTHORITY_TEMPORARY is not None:
        _CACHED_AUTHORITY_TEMPORARY.cleanup()
        _CACHED_AUTHORITY_TEMPORARY = None


def autonomous_decision(
    gate: HumanGate,
    scientific_authority_hash: str,
) -> AutonomousDecisionRecord:
    return AutonomousDecisionRecord(
        decision_id=f"decision-{gate.value.lower().replace('_', '-')}",
        gate=gate,
        scientific_authority_hash=scientific_authority_hash,
        alternatives=("proceed", "stop"),
        evidence_hashes=(scientific_authority_hash,),
        governing_rule="Scientific gate must pass before authorization is considered.",
        uncertainty="Fixture evidence does not establish external validity.",
        reason="The deterministic local gate passed.",
        downstream_consequences=("The next non-release stage may begin.",),
    )


def dimensions(status: DimensionStatus = DimensionStatus.PASS):
    return {item: status for item in SoundnessDimension}


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {item.name: _jsonable(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(child) for child in value]
    return value


def _put_json(
    registry: ArtifactRegistry,
    value: Mapping[str, Any],
    logical_type: str,
    role: Role,
    parents: tuple[str, ...] = (),
):
    return registry.put_json(
        dict(value),
        logical_type=logical_type,
        origin="paper-authority-test",
        creator_role=role,
        parent_artifacts=parents,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _put_state(
    registry: ArtifactRegistry,
    value: Any,
    parents: tuple[str, ...] = (),
):
    return registry.put_bytes(
        value.canonical_bytes(),
        logical_type=value.logical_type,
        origin=f"paper-authority-test:{value.object_type}:{value.object_id}",
        creator_role=value.producer,
        parent_artifacts=parents,
        schema_version=value.schema_version,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=value.created_at,
    )


@dataclass(frozen=True)
class ConfirmatoryArtifacts:
    run_id: str
    ledger: EventLedger
    protocol_hash: str
    blind_hash: str
    source_inventory_hash: str
    configuration_inventory_hash: str
    split_manifest_hash: str
    midrun_review_hash: str
    resource_charge_hash: str
    fresh_custody_hash: str
    custody_hash: str
    result_hash: str
    timeline_receipt_hash: str


def _confirmatory_protocol(run_label: str) -> ResearchProtocol:
    conditions = ExecutionConditions(
        "identity-v1",
        "frozen role-specific fixtures",
        1,
        "not applicable; deterministic bounded pass",
        120.0,
        "synthetic scalar outcome",
        True,
    )
    protocol = ResearchProtocol(
        study_id=f"{run_label}-study-v1",
        study_version=1,
        primary_hypothesis="the treatment fixture mean exceeds control by 0.75",
        primary_estimand="treatment_mean_minus_control_mean",
        primary_metric="arithmetic_mean_difference",
        secondary_metrics=(),
        unit_of_analysis="synthetic_unit_id",
        resampling_unit="synthetic_unit_id",
        data_exclusions=(),
        data_roles=DataRoles(
            ("train-fixture-v1",),
            ("workflow-development-v1",),
            ("workflow-validation-v1",),
            ("synthetic-confirmatory-v1",),
        ),
        candidate_conditions=conditions,
        baseline_set=(BaselineSpec("known-answer-contract-v1", conditions),),
        ablation_set=("trap_detection_by_scenario",),
        negative_controls=("true_null",),
        domain_nulls=(
            DomainNullSpec(
                "paired-synthetic-unit-null",
                "paired unit-respecting sign reversal",
                "synthetic_unit_id",
                ("paired unit",),
                ("paired units are exchangeable under the null",),
                True,
            ),
        ),
        statistical_tests=(
            StatisticalTestSpec(
                "primary-difference",
                "deterministic difference of arithmetic means",
                "paired-synthetic-unit-null",
                "greater",
            ),
        ),
        confidence_intervals=(
            ConfidenceIntervalSpec("unit bootstrap", 0.95, "synthetic_unit_id"),
        ),
        multiple_comparison_correction="Holm across registered metrics",
        seed_policy=SeedPolicy(
            (20260812,),
            "single frozen seed",
            "mechanical execution failure only",
        ),
        compute_budget=ProtocolComputeBudget(1, 120.0, 1, 1),
        stopping_rules=("stop on any mandatory gate failure",),
        decision_ladder=("positive", "negative", "inconclusive", "invalid"),
        claim_scope_contract="claims apply only to deterministic synthetic behavior",
        interpretation_rules=InterpretationRules(
            "bounded positive synthetic claim",
            "NEGATIVE_RESULT",
            "INCONCLUSIVE",
            "STOP_SCIENTIFIC_INVALIDITY",
        ),
        validity_reserve_fraction=0.40,
        reserve_basis="data_and_compute",
    )
    validate_protocol(protocol)
    return protocol


def register_confirmatory_artifacts(
    registry: ArtifactRegistry,
    root: str,
    *,
    code_hash: str,
    run_label: str,
) -> ConfirmatoryArtifacts:
    protocol = _confirmatory_protocol(run_label)
    study = StudyVersion(protocol)
    protocol_record = _put_json(
        registry,
        {
            "kind": "FROZEN_SYNTHETIC_PROTOCOL",
            "frozen": True,
            "protocol": protocol.canonical_dict,
            "protocol_sha256": protocol.sha256,
            "baseline_equivalence": [
                asdict(item) for item in validate_protocol(protocol)
            ],
            "blind_patterns": ["positive", "negative", "inconclusive"],
            "reproduction_tolerance": 1e-12,
        },
        "frozen_protocol",
        Role.PROTOCOL_DESIGNER,
    )

    def inventory(
        kind: str,
        entries: list[dict[str, object]],
    ) -> dict[str, object]:
        entries = sorted(entries, key=lambda item: str(item["path"]))
        aggregate = hashlib.sha256(canonical_json_bytes(entries) + b"\n").hexdigest()
        return {
            "schema_version": "1.0",
            "kind": kind,
            "entries": entries,
            "aggregate_sha256": aggregate,
        }

    source_entries: list[dict[str, object]] = [
        {
            "path": "src/scientist_one/paper_fixture.py",
            "sha256": code_hash,
            "size": 1,
        }
    ]
    for relative_path in (
        "src/scientist_one/holdout.py",
        "src/scientist_one/recovery.py",
    ):
        encoded = (PROJECT_ROOT / relative_path).read_bytes()
        copied = Path(root) / relative_path
        copied.parent.mkdir(parents=True, exist_ok=True)
        copied.write_bytes(encoded)
        source_entries.append(
            {
                "path": relative_path,
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "size": len(encoded),
            }
        )
    source_payload = inventory("FROZEN_SOURCE_INVENTORY", source_entries)
    configuration_payload = inventory(
        "FROZEN_CONFIGURATION_INVENTORY",
        [
            {
                "path": "configs/paper-fixture.json",
                "sha256": digest(f"{run_label}:configuration-entry"),
                "size": 1,
            }
        ],
    )
    source_inventory = _put_json(
        registry,
        source_payload,
        "frozen_source_inventory",
        Role.ORCHESTRATOR,
    )
    configuration_inventory = _put_json(
        registry,
        configuration_payload,
        "frozen_configuration_inventory",
        Role.ORCHESTRATOR,
    )
    inventory_parents = (
        source_inventory.sha256,
        configuration_inventory.sha256,
    )
    blind = _put_json(
        registry,
        {
            "kind": "FROZEN_BLIND_INTERPRETATION",
            "frozen_before_reveal": True,
            "source_inventory_sha256": source_inventory.sha256,
            "configuration_inventory_sha256": configuration_inventory.sha256,
            "patterns": {
                "positive": "bounded positive",
                "negative": "NEGATIVE_RESULT",
                "inconclusive": "INCONCLUSIVE",
            },
        },
        "blind_interpretation",
        Role.STATISTICIAN,
        inventory_parents,
    )
    fixture = {
        "control": [0.0, 0.0, 0.0, 0.0],
        "treatment": [0.75, 0.75, 0.75, 0.75],
    }
    fixture_bytes = canonical_json_bytes(fixture)
    split_id = protocol.data_roles.holdout[0]
    split_hash = hashlib.sha256(
        canonical_json_bytes({"id": split_id, "role": "holdout"}) + b"\n"
    ).hexdigest()
    split = _put_json(
        registry,
        {
            "schema_version": "1.0",
            "kind": "FROZEN_CONFIRMATORY_SPLIT",
            "study_id": protocol.study_id,
            "study_version": protocol.study_version,
            "split_id": split_id,
            "role": "holdout",
            "split_manifest_hash": split_hash,
        },
        "frozen_confirmatory_split",
        Role.PROTOCOL_DESIGNER,
        (protocol_record.sha256,),
    )
    midrun = _put_json(
        registry,
        {
            "kind": "FROZEN_MIDRUN_REVIEW",
            "passed": True,
            "drift": False,
            "leakage": False,
            "baseline_equivalent": True,
            "validity_reserve_intact": True,
            "code_fingerprint": source_payload["aggregate_sha256"],
            "configuration_sha256": configuration_payload["aggregate_sha256"],
            "source_inventory_sha256": source_inventory.sha256,
            "configuration_inventory_sha256": configuration_inventory.sha256,
        },
        "midrun_review",
        Role.SCIENTIFIC_REVIEWER,
        inventory_parents,
    )
    custody = SimulatedHoldoutCustody(
        (Role.EXPERIMENT_RUNNER.value,),
        journal_root=root,
        journal_path=f"custody/{run_label}.jsonl",
    )
    seal = custody.seal(
        fixture_bytes,
        split_manifest_hash=split_hash,
        protocol_hash=protocol.sha256,
        code_hash=str(source_payload["aggregate_sha256"]),
        configuration_hash=str(configuration_payload["aggregate_sha256"]),
        pre_unblinding_interpretation_hash=blind.sha256,
        sealed_at="2026-08-29T12:00:00Z",
    )
    with custody.admission_guard() as sealed:
        fresh_payload = {
            "schema_version": "1.0",
            "study_id": protocol.study_id,
            "study_version": protocol.study_version,
            "seal": asdict(sealed.seal),
            "status": asdict(sealed.status),
            "journal_head_hash": sealed.journal_head_hash,
            "journal_identity_sha256": sealed.journal_identity_sha256,
        }
    fresh_parents = (
        protocol_record.sha256,
        blind.sha256,
        source_inventory.sha256,
        configuration_inventory.sha256,
        split.sha256,
        midrun.sha256,
    )
    fresh = _put_json(
        registry,
        fresh_payload,
        "fresh_custody_receipt",
        Role.HOLDOUT_CUSTODIAN,
        fresh_parents,
    )

    initial_resource = ResourceRuntimeState(
        schema_version="1.0",
        run_id=run_label,
        config_sha256=str(configuration_payload["aggregate_sha256"]),
        wall_elapsed_seconds=10.0,
        checkpoint_elapsed_seconds=5.0,
        progress_elapsed_seconds=5.0,
        worker_crashes={},
        wall_started_at_epoch_seconds=100.0,
        wall_observed_at_epoch_seconds=110.0,
        validity_total_units=10,
        exploratory_used=2,
        confirmatory_used=0,
    )
    prior_resource = _put_json(
        registry,
        initial_resource.to_dict(),
        "resource_runtime_pilot_completion",
        Role.ORCHESTRATOR,
    )
    charged_resource = ResourceRuntimeState(
        **{**initial_resource.to_dict(), "confirmatory_used": 4}
    )
    charge = _put_json(
        registry,
        charged_resource.to_dict(),
        "resource_runtime_confirmatory_charge",
        Role.ORCHESTRATOR,
        (prior_resource.sha256,),
    )
    authority_directory = (
        Path(root)
        / ".scientist-one-build"
        / "resource-authority"
        / run_label
    )
    authority_directory.mkdir(parents=True)

    def persist_resource_authority(
        sequence: int,
        logical_type: str,
        state: dict[str, object],
        prior_digest: str | None,
    ) -> tuple[str, dict[str, object]]:
        state_sha256 = hashlib.sha256(
            canonical_json_bytes(state) + b"\n"
        ).hexdigest()
        authority_record = {
            "schema_version": "1.0",
            "kind": "RESOURCE_RUNTIME_AUTHORITY",
            "run_id": run_label,
            "sequence": sequence,
            "logical_type": logical_type,
            "state_sha256": state_sha256,
            "state": state,
            "prior_authority_sha256": prior_digest,
        }
        encoded = canonical_json_bytes(authority_record) + b"\n"
        authority_digest = hashlib.sha256(encoded).hexdigest()
        (authority_directory / f"{sequence:04d}-{authority_digest}.json").write_bytes(
            encoded
        )
        return authority_digest, {
            "sequence": sequence,
            "logical_type": logical_type,
            "state_sha256": state_sha256,
            "authority_sha256": authority_digest,
            "prior_authority_sha256": prior_digest,
        }

    prior_authority_digest, prior_authority_checkpoint = (
        persist_resource_authority(
            0,
            "resource_runtime_pilot_completion",
            initial_resource.to_dict(),
            None,
        )
    )
    _, authority_checkpoint = persist_resource_authority(
        1,
        "resource_runtime_confirmatory_charge",
        charged_resource.to_dict(),
        prior_authority_digest,
    )
    if (
        prior_authority_checkpoint["state_sha256"] != prior_resource.sha256
        or authority_checkpoint["state_sha256"] != charge.sha256
    ):
        raise AssertionError("resource authority state identity mismatch")
    ledger = EventLedger(root, f"runs/{run_label}/events.jsonl")
    fresh_binding = {
        "artifact_sha256": fresh.sha256,
        "artifact_record_hash": str(fresh.record_hash),
        "journal_head_hash": fresh_payload["journal_head_hash"],
        "journal_identity_sha256": fresh_payload["journal_identity_sha256"],
        "protocol_hash": protocol.sha256,
        "seal_hash": seal.seal_hash,
        "study_version": protocol.study_version,
    }
    ledger.record(
        run_id=run_label,
        actor_role=Role.ORCHESTRATOR,
        state_before=MacroState.CANDIDATE,
        requested_state_after=MacroState.CANDIDATE,
        artifact_hashes=(prior_resource.sha256,),
        code_version=str(source_payload["aggregate_sha256"]),
        configuration_hash=str(configuration_payload["aggregate_sha256"]),
        reason="publish pilot-completion resource authority",
        event_id=f"prior-resource-{run_label}",
        timestamp="2026-08-29T12:00:00Z",
        event_type="CHECKPOINT",
        metadata={
            "artifact_types": ["resource_runtime_pilot_completion"],
            "artifact_record_hashes": [str(prior_resource.record_hash)],
            "resource_authority_checkpoint": prior_authority_checkpoint,
        },
    )
    ledger.record(
        run_id=run_label,
        actor_role=Role.HOLDOUT_CUSTODIAN,
        state_before=MacroState.CANDIDATE,
        requested_state_after=MacroState.CANDIDATE,
        artifact_hashes=(fresh.sha256,),
        code_version=str(source_payload["aggregate_sha256"]),
        configuration_hash=str(configuration_payload["aggregate_sha256"]),
        reason="freeze exact fresh custody authority",
        event_id=f"fresh-custody-{run_label}",
        timestamp="2026-08-29T12:00:01Z",
        event_type="CHECKPOINT",
        metadata={
            "artifact_types": ["fresh_custody_receipt"],
            "artifact_record_hashes": [str(fresh.record_hash)],
            "fresh_custody": fresh_binding,
        },
    )
    ledger.record(
        run_id=run_label,
        actor_role=Role.ORCHESTRATOR,
        state_before=MacroState.CANDIDATE,
        requested_state_after=MacroState.CANDIDATE,
        artifact_hashes=(charge.sha256,),
        code_version=str(source_payload["aggregate_sha256"]),
        configuration_hash=str(configuration_payload["aggregate_sha256"]),
        reason="charge protected confirmatory validity reserve",
        event_id=f"confirmatory-charge-{run_label}",
        timestamp="2026-08-29T12:00:02Z",
        event_type="CHECKPOINT",
        metadata={
            "artifact_types": ["resource_runtime_confirmatory_charge"],
            "artifact_record_hashes": [str(charge.record_hash)],
            "resource_authority_checkpoint": authority_checkpoint,
        },
    )

    def selector(record: object) -> RegisteredArtifactSelector:
        return RegisteredArtifactSelector(
            record.sha256, str(record.record_hash)  # type: ignore[attr-defined]
        )

    reveal_authority = ConfirmatoryRevealAuthority(
        selector(protocol_record),
        selector(source_inventory),
        selector(configuration_inventory),
        selector(split),
        selector(blind),
        selector(midrun),
        selector(charge),
        f"confirmatory-charge-{run_label}",
        4,
    )
    started_event_id = f"confirmatory-started-{run_label}"

    def make_started_event() -> LedgerEvent:
        selectors = (
            ("frozen_protocol", reveal_authority.protocol),
            ("frozen_source_inventory", reveal_authority.source_inventory),
            (
                "frozen_configuration_inventory",
                reveal_authority.configuration_inventory,
            ),
            ("frozen_confirmatory_split", reveal_authority.split_manifest),
            ("blind_interpretation", reveal_authority.blind_interpretation),
            ("midrun_review", reveal_authority.midrun_review),
            (
                "resource_runtime_confirmatory_charge",
                reveal_authority.resource_charge,
            ),
            ("fresh_custody_receipt", selector(fresh)),
        )
        return LedgerEvent.create(
            run_id=run_label,
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.CANDIDATE,
            requested_state_after=MacroState.CANDIDATE,
            artifact_hashes=tuple(item.artifact_sha256 for _, item in selectors),
            code_version=str(source_payload["aggregate_sha256"]),
            configuration_hash=str(configuration_payload["aggregate_sha256"]),
            reason="publish irreversible confirmatory start",
            prior_event_hash=ledger.assert_valid().head_hash,
            event_id=started_event_id,
            timestamp="2026-08-29T12:00:03Z",
            event_type="CHECKPOINT",
            metadata={
                "artifact_types": [name for name, _ in selectors],
                "artifact_record_hashes": [
                    item.artifact_record_hash for _, item in selectors
                ],
                "fresh_custody": fresh_binding,
                "resource_authority_checkpoint": authority_checkpoint,
                "evidence_class": "ARCHITECTURE_CONTROL",
                "execution_kind": "SIMULATED_ARCHITECTURE_CONTROL_STARTED",
            },
        )

    recovery = RecoveryManager(root)
    release, released_fixture = recovery.run_non_evidentiary_simulated_fixture(
        ledger_path=ledger.path,
        study_version=study,
        fresh_custody_evidence=FreshCustodyEvidence(
            fresh.sha256,
            str(fresh.record_hash),
            f"fresh-custody-{run_label}",
        ),
        reveal_authority=reveal_authority,
        artifact_registry=registry,
        custody_provider=custody,
        validity_snapshot=ValidityBudgetSnapshot(10, 6, 4, 2, 4),
        start_event=make_started_event(),
        evaluator_spec=ConfirmatoryEvaluatorSpec(),
        requester=Role.EXPERIMENT_RUNNER.value,
        reason="single frozen confirmatory run",
        requested_at="2026-08-29T12:00:04Z",
    )
    expected_fixture_result = {
        "schema_version": "1.0",
        "kind": "SIMULATED_TWO_GROUP_MEAN_DIFFERENCE",
        "control_mean": 0.0,
        "treatment_mean": 0.75,
        "primary_estimate": 0.75,
        "n_control": 4,
        "n_treatment": 4,
    }
    if released_fixture != expected_fixture_result:
        raise AssertionError("simulated evaluator result was substituted")
    access_records = custody.access_records
    with custody.admission_guard() as revealed:
        if revealed.confirmatory_claims_valid:
            raise AssertionError(
                "simulated confirmatory fixture acquired scientific authority"
            )
        custody_payload = {
            "kind": "SIMULATED_HOLDOUT_CUSTODY",
            "study_id": protocol.study_id,
            "study_version": protocol.study_version,
            "custody_independence": custody.custody_label,
            "holdout_identity_hash": seal.holdout_identity_hash,
            "split_manifest_hash": seal.split_manifest_hash,
            "sealing_time": seal.sealed_at,
            "authorized_access_count": revealed.authorized_access_count,
            "access_requester": release.requester,
            "access_reason": release.reason,
            "protocol_hash": seal.protocol_hash,
            "code_hash": seal.code_hash,
            "configuration_hash": seal.configuration_hash,
            "source_inventory_sha256": source_inventory.sha256,
            "configuration_inventory_sha256": configuration_inventory.sha256,
            "split_manifest_artifact_sha256": split.sha256,
            "midrun_review_sha256": midrun.sha256,
            "resource_charge_artifact_sha256": charge.sha256,
            "resource_charge_ledger_event_id": f"confirmatory-charge-{run_label}",
            "fresh_custody_receipt_sha256": fresh.sha256,
            "fresh_custody_receipt_event_id": f"fresh-custody-{run_label}",
            "confirmatory_started_event_id": started_event_id,
            "confirmatory_validity_units": 4,
            "pre_unblinding_interpretation_hash": seal.pre_unblinding_interpretation_hash,
            "seal_hash": seal.seal_hash,
            "release_event": asdict(release),
            "access_records": [asdict(item) for item in access_records],
            "confirmatory_claims_valid": revealed.confirmatory_claims_valid,
            "durable_journal": revealed.durable_journal,
            "journal_path": f"custody/{run_label}.jsonl",
            "journal_head_hash": revealed.journal_head_hash,
            "journal_sha256": revealed.journal_sha256,
            "journal_size": revealed.journal_size,
            "journal_identity_sha256": revealed.journal_identity_sha256,
            "genuine_independence_claimed": False,
        }
    custody_record = _put_json(
        registry,
        custody_payload,
        "custody_record",
        Role.HOLDOUT_CUSTODIAN,
        (
            protocol_record.sha256,
            source_inventory.sha256,
            configuration_inventory.sha256,
            split.sha256,
            blind.sha256,
            midrun.sha256,
            charge.sha256,
            fresh.sha256,
        ),
    )
    result_core = {
        "primary_estimate": 0.75,
        "control_mean": 0.0,
        "treatment_mean": 0.75,
        "n_control": 4,
        "n_treatment": 4,
    }
    result = _put_json(
        registry,
        {
            "kind": "MACHINE_READABLE_RESULTS",
            "evidence_class": "SYNTHETIC_CONFIRMATORY_FIXTURE",
            "outcome_pattern": "positive",
            "dataset_fixture_ids": list(protocol.data_roles.holdout),
            "random_seeds": list(protocol.seed_policy.seeds),
            "code_fingerprint": source_payload["aggregate_sha256"],
            "configuration_sha256": configuration_payload["aggregate_sha256"],
            "input_hashes": {
                "frozen_protocol": protocol_record.sha256,
                "blind_interpretation": blind.sha256,
                "custody_record": custody_record.sha256,
                "frozen_source_inventory": source_inventory.sha256,
                "frozen_configuration_inventory": configuration_inventory.sha256,
            },
            "scientific_protocol_sha256": protocol.sha256,
            "frozen_fixture": fixture,
            **result_core,
            "output_hashes": {
                "result_core": hashlib.sha256(
                    canonical_json_bytes(result_core)
                ).hexdigest()
            },
            "confirmatory_access_count": 1,
            "tuned_after_reveal": False,
        },
        "machine_results",
        Role.EXPERIMENT_RUNNER,
        (
            protocol_record.sha256,
            blind.sha256,
            custody_record.sha256,
            source_inventory.sha256,
            configuration_inventory.sha256,
        ),
    )
    ledger.record(
        run_id=run_label,
        actor_role=Role.ORCHESTRATOR,
        state_before=MacroState.CANDIDATE,
        requested_state_after=MacroState.CANDIDATE,
        artifact_hashes=(custody_record.sha256, result.sha256),
        code_version=str(source_payload["aggregate_sha256"]),
        configuration_hash=str(configuration_payload["aggregate_sha256"]),
        reason="record non-evidentiary simulated fixture custody and result",
        event_id=f"confirmatory-completed-{run_label}",
        timestamp="2026-08-29T12:00:05Z",
        event_type="CHECKPOINT",
        metadata={
            "artifact_types": ["custody_record", "machine_results"],
            "artifact_record_hashes": [
                str(custody_record.record_hash),
                str(result.record_hash),
            ],
            "execution_kind": "SIMULATED_ARCHITECTURE_CONTROL_COMPLETED",
            "scientific_evidence": False,
        },
    )
    timeline = _put_json(
        registry,
        {
            "schema_version": "non-evidentiary-confirmatory-fixture/v1",
            "run_id": run_label,
            "study_id": protocol.study_id,
            "study_version": protocol.study_version,
            "execution_class": "SIMULATED_ARCHITECTURE_CONTROL",
            "scientific_gate_passed": False,
        },
        "non_evidentiary_confirmatory_timeline_fixture",
        Role.HOLDOUT_CUSTODIAN,
        (
            protocol_record.sha256,
            fresh.sha256,
            custody_record.sha256,
            result.sha256,
        ),
    )
    return ConfirmatoryArtifacts(
        run_label,
        ledger,
        protocol_record.sha256,
        blind.sha256,
        source_inventory.sha256,
        configuration_inventory.sha256,
        split.sha256,
        midrun.sha256,
        charge.sha256,
        fresh.sha256,
        custody_record.sha256,
        result.sha256,
        timeline.sha256,
    )


@dataclass(frozen=True)
class PaperAuthorityFixture:
    registry: ArtifactRegistry
    ledger: EventLedger
    bundle: AuthoritativeResearchBundle
    candidate: PaperCandidate
    result_hash: str
    asset_hash: str
    reference_hash: str
    method_hash: str
    code_hash: str
    claim_graph_hash: str
    research_state_hash: str
    soundness_hash: str
    confirmatory_artifacts: ConfirmatoryArtifacts | None


@dataclass(frozen=True)
class VenueAuthorityFixture:
    bundle_artifact_hash: str
    candidate_artifact_hash: str
    profile_artifact_hash: str
    manuscript_artifact_hash: str
    readiness_manifest_hash: str


def _one_registry_record(registry: ArtifactRegistry, logical_type: str):
    matches = tuple(
        record
        for record in registry.list_records()
        if record.logical_type == logical_type
    )
    if len(matches) != 1:
        raise AssertionError(f"expected one {logical_type} record, found {len(matches)}")
    return matches[0]


def _cached_canonical_authority_fixture() -> PaperAuthorityFixture:
    """Build one real captured-run state, then add one focused scientific claim."""

    global _CACHED_AUTHORITY_FIXTURE, _CACHED_AUTHORITY_TEMPORARY
    if _CACHED_AUTHORITY_FIXTURE is not None:
        return _CACHED_AUTHORITY_FIXTURE

    temporary = tempfile.TemporaryDirectory(prefix="paper-canonical-authority-")
    root = Path(temporary.name)
    shutil.copytree(
        PROJECT_ROOT / "src" / "scientist_one",
        root / "src" / "scientist_one",
    )
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(
        PROJECT_ROOT / "scripts" / "vnext_fixture_experiment.py",
        root / "scripts" / "vnext_fixture_experiment.py",
    )
    (root / "fixtures").mkdir(parents=True)
    shutil.copy2(
        PROJECT_ROOT / "fixtures" / "vnext_research_dataset.json",
        root / "fixtures" / "vnext_research_dataset.json",
    )
    shutil.copytree(PROJECT_ROOT / "configs", root / "configs")
    run_id = "paper-authority-canonical-run"
    summary = run_research_os_fixture(root, run_id=run_id)
    registry_summary = summary["artifact_registry"]
    ledger_summary = summary["event_ledger"]
    assert isinstance(registry_summary, Mapping)
    assert isinstance(ledger_summary, Mapping)
    registry = ArtifactRegistry(root, str(registry_summary["base_path"]))
    ledger = EventLedger(root, str(ledger_summary["path"]))

    base_bundle_record = _one_registry_record(
        registry, "authoritative_research_bundle"
    )
    base_candidate_record = _one_registry_record(registry, "paper_candidate")
    base_bundle_value = safe_json_loads(registry.get_bytes(base_bundle_record.sha256))
    base_candidate_value = safe_json_loads(
        registry.get_bytes(base_candidate_record.sha256)
    )
    assert isinstance(base_bundle_value, Mapping)
    assert isinstance(base_candidate_value, Mapping)
    base_bundle = _authoritative_bundle_from_json(base_bundle_value["bundle"])
    base_candidate = _paper_candidate_from_json(base_candidate_value["candidate"])
    final_state_record = _one_registry_record(
        registry,
        "canonical_research_state_final_snapshot",
    )
    state_authority = resolve_research_state_authority(
        registry,
        ledger,
        run_id=run_id,
        snapshot_artifact_hash=final_state_record.sha256,
    )
    repository = ResearchStateRepository(
        registry,
        ledger,
        run_id=run_id,
        code_version=state_authority.code_version,
        configuration_hash=state_authority.configuration_hash,
        # Whole-state replay requires the original canonical repository identity.
        state=MacroState.GROUND,
        creation_command=(
            "scientist-one",
            "research-os-fixture",
            "materialize-state",
        ),
    )
    timestamp = utc_now()

    code = registry.put_bytes(
        b"def predict(value): return int(value >= 0.5)\n",
        logical_type="experiment_code",
        origin="focused paper canonical method",
        creator_role=Role.IMPLEMENTER,
        mime_type="text/x-python",
        frozen=True,
    )
    method_configuration = _put_json(
        registry,
        {"configuration_id": "paper-canonical-method-configuration"},
        "experiment_configuration",
        Role.PROTOCOL_DESIGNER,
        (code.sha256,),
    )
    raw_method = _put_json(
        registry,
        {
            "method_id": "method-paper-canonical",
            "name": "Pinned threshold",
            "description": "Predict one at or above the frozen threshold.",
            "assumptions": ["Input is numeric."],
            "component_ids": ["threshold-component"],
        },
        "method_definition",
        Role.HYPOTHESIS_DESIGNER,
        (method_configuration.sha256,),
    )
    method = StateMethod(
        object_id="method-paper-canonical",
        producer=Role.HYPOTHESIS_DESIGNER,
        status=RecordStatus.FROZEN,
        created_at=timestamp,
        code_version=state_authority.code_version,
        name="Pinned threshold",
        description="Predict one at or above the frozen threshold.",
        assumptions=("Input is numeric.",),
        component_ids=("threshold-component",),
        authority_artifact_hashes=(raw_method.sha256,),
    )
    method_state = repository.materialize(method).artifact
    implementation = StateImplementation(
        object_id="implementation-paper-canonical",
        producer=Role.IMPLEMENTER,
        status=RecordStatus.FROZEN,
        created_at=timestamp,
        code_version=state_authority.code_version,
        parents=(
            ObjectReference(
                "Method",
                method.object_id,
                method.content_hash,
                "implements",
                True,
            ),
        ),
        method_id=method.object_id,
        code_artifact_hashes=(code.sha256,),
        code_revision=state_authority.code_version,
        configuration_artifact_hashes=(method_configuration.sha256,),
        authority_artifact_hashes=(code.sha256, method_configuration.sha256),
    )
    implementation_state = repository.materialize(implementation).artifact

    metric = next(
        item
        for item in base_bundle.metrics
        if item.result_value_key == "candidate"
    )
    result_hash = metric.result_artifact_hash
    result_metrics = tuple(
        item
        for item in base_bundle.metrics
        if item.result_state_artifact_hash
        == metric.result_state_artifact_hash
        and item.result_artifact_hash == result_hash
    )
    if {item.result_value_key for item in result_metrics} != {
        "baseline",
        "candidate",
        "improvement",
    }:
        raise AssertionError("focused paper Result metric closure is incomplete")
    asset = base_candidate.assets[0]
    reference = base_candidate.references[0]
    claim_id = "claim-main"
    claim_text = "The captured offline fixture produced a candidate value of 0.75."
    provisional: list[EvidenceNode] = []
    evidence_records = []
    source_by_kind = {
        EvidenceKind.CODE: code.sha256,
        EvidenceKind.FIGURE_OR_TABLE: asset.artifact_hash,
        EvidenceKind.RESULT: result_hash,
        EvidenceKind.SOURCE_CITATION: reference.reference_artifact_hash,
    }
    for index, kind in enumerate(
        sorted(REQUIRED_EVIDENCE_KINDS, key=lambda item: item.value), 1
    ):
        source_hash = source_by_kind.get(kind)
        record = _put_json(
            registry,
            {
                "claim_text": claim_text,
                "evidence_kind": kind.value,
                "source_artifact_hash": source_hash,
                "supports": claim_text,
            }
            if source_hash is not None
            else {
                "claim_text": claim_text,
                "evidence_kind": kind.value,
                "supports": claim_text,
            },
            f"claim_evidence.{kind.value}",
            Role.EVIDENCE_CURATOR,
            ((source_hash,) if source_hash is not None else ()),
        )
        evidence_records.append(record)
        provisional.append(
            EvidenceNode(
                evidence_id=f"paper-canonical-evidence-{index:02d}-{kind.value}",
                kind=kind,
                artifact_hash=record.sha256,
                description=f"Frozen {kind.value} support for the scoped claim.",
                verified=True,
                frozen=True,
                supports_claim=True,
                contradicts_claim=False,
                locally_verifiable=True,
            )
        )
    material_claim = MaterialClaim(
        claim_id=claim_id,
        text=claim_text,
        evidence_links=tuple(
            EvidenceLink(item.evidence_id, item.kind) for item in provisional
        ),
        producer_role=Role.EXPERIMENT_RUNNER,
        confirmatory=False,
        evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
    )
    support_records = []
    nodes: list[EvidenceNode] = []
    for node in provisional:
        support = EvidenceSupportReceipt.for_claim(
            material_claim,
            node,
            verifier_id="paper-canonical-claim-verifier",
            verification_result="PASS",
            supports_claim=True,
            contradicts_claim=False,
            locally_verifiable=True,
            rationale="The exact frozen source supports this scoped claim edge.",
        )
        support_record = _put_json(
            registry,
            support.to_dict(),
            f"claim_support_receipt.{node.kind.value}",
            Role.CLAIM_VERIFIER,
            (node.artifact_hash,),
        )
        if support_record.sha256 != support.sha256:
            raise AssertionError("canonical support receipt identity mismatch")
        support_records.append(support_record)
        nodes.append(replace(node, verification_receipt_hash=support_record.sha256))
    resolver = artifact_registry_resolver(
        registry,
        resolver_id=CLAIM_GRAPH_RESOLVER_ID,
    )
    graph = ClaimEvidenceGraph(evidence_resolver=resolver)
    for node in nodes:
        graph.add_evidence(node)
    graph.add_claim(material_claim)
    decision = graph.verify_claim(
        claim_id,
        verifier_id="paper-canonical-claim-verifier",
        confirmatory_evidence_valid=False,
    )
    if decision.decision is not ClaimDecision.ELIGIBLE:
        raise AssertionError("focused canonical claim was not structurally eligible")
    verification_records = []
    for node in nodes:
        receipt = resolver(material_claim, node)
        record = registry.put_bytes(
            receipt.canonical_bytes,
            logical_type=f"claim_evidence_verification_receipt.{node.kind.value}",
            origin="focused paper canonical claim verification",
            creator_role=Role.CLAIM_VERIFIER,
            parent_artifacts=(node.artifact_hash, receipt.support_receipt_hash),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        if record.sha256 != receipt.sha256:
            raise AssertionError("canonical verification receipt identity mismatch")
        verification_records.append(record)
    graph_record = _put_json(
        registry,
        {"graph": graph.to_dict()},
        "claim_evidence_graph",
        Role.CLAIM_VERIFIER,
        tuple(
            item.sha256
            for item in (*evidence_records, *support_records, *verification_records)
        ),
    )
    state_evidence_objects = tuple(
        StateEvidence(
            object_id=node.evidence_id,
            producer=Role.CLAIM_VERIFIER,
            status=RecordStatus.VERIFIED,
            created_at=timestamp,
            code_version=state_authority.code_version,
            evidence_kind=node.kind.value,
            source_artifact_hashes=(graph_record.sha256,),
            supports_claim_ids=(claim_id,),
            verification_depth=ReferenceVerificationDepth.LEVEL_5,
            locator=f"artifact:{node.artifact_hash}",
            verification_status=VerificationStatus.VERIFIED,
            verified_at=timestamp,
            authority_artifact_hashes=(graph_record.sha256,),
        )
        for node in nodes
    )
    for state_evidence in state_evidence_objects:
        repository.materialize(state_evidence)
    semantics_record = register_claim_semantics_receipt(
        registry,
        ledger,
        receipt_id="claim-main-semantics",
        run_id=run_id,
        claim_graph_artifact_hash=graph_record.sha256,
        claim_id=claim_id,
        claim_type=ClaimType.COMPARATIVE,
        scope="Captured offline system fixture only.",
        confidence=0.9,
        expressed_strength=ClaimStrength.QUALIFIED,
        permitted_strength=ClaimStrength.QUALIFIED,
        verification_method="fresh registry-resolved claim graph",
        evidence_scope=ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE,
    )
    claim_authorities = (
        graph_record.sha256,
        *tuple(item.sha256 for item in support_records),
        *tuple(item.sha256 for item in verification_records),
        semantics_record.sha256,
    )
    state_claim = StateClaim(
        object_id=claim_id,
        producer=Role.EXPERIMENT_RUNNER,
        status=RecordStatus.VERIFIED,
        created_at=timestamp,
        code_version=state_authority.code_version,
        parents=tuple(
            ObjectReference(
                "Evidence",
                item.object_id,
                item.content_hash,
                "supported_by",
                True,
            )
            for item in state_evidence_objects
        ),
        claim_type=ClaimType.COMPARATIVE,
        claim_text=claim_text,
        scope="Captured offline system fixture only.",
        evidence_ids=tuple(item.object_id for item in state_evidence_objects),
        source_artifact_ids=(graph_record.sha256, semantics_record.sha256),
        verification_method="fresh registry-resolved claim graph",
        verification_status=VerificationStatus.VERIFIED,
        confidence=0.9,
        expressed_strength=ClaimStrength.QUALIFIED,
        permitted_strength=ClaimStrength.QUALIFIED,
        review_history=(
            ClaimReview(
                reviewer=Role.CLAIM_VERIFIER,
                timestamp=timestamp,
                verification_status=VerificationStatus.VERIFIED,
                reason="All typed evidence and receipts resolved.",
                evidence_ids=tuple(
                    item.object_id for item in state_evidence_objects
                ),
                source_artifact_ids=claim_authorities,
            ),
        ),
        confirmatory=False,
        evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
        authority_artifact_hashes=claim_authorities,
    )
    repository.materialize(state_claim)
    report = repository.validate_state(
        expected_code_version=state_authority.code_version
    )
    if not report.valid:
        raise AssertionError(f"focused canonical state invalid: {report.issues}")
    snapshot = register_research_state_snapshot(
        repository,
        snapshot_id="focused-paper-canonical",
        created_at=timestamp,
    )

    dimension_records = tuple(
        register_soundness_dimension_receipt(
            registry,
            SoundnessDimensionEvidenceReceipt(
                receipt_id=f"paper-{dimension.value.lower()}-receipt",
                dimension=dimension,
                status=DimensionStatus.UNTESTED,
                authority_kind=SoundnessAuthorityKind.NOT_EXECUTED,
                authority_artifact_hash=None,
                evidence_hashes=(result_hash,),
                governing_rule="Do not infer unexecuted scientific soundness.",
                rationale="The offline fixture leaves this dimension untested.",
                reviewer_id="paper-soundness-reviewer",
            ),
        )
        for dimension in SoundnessDimension
    )
    challenger_records = tuple(
        register_challenger_category_review(
            registry,
            ChallengerCategoryReview(
                review_id=f"paper-{category.value.lower()}-review",
                category=category,
                execution_status=ChallengerExecutionStatus.UNTESTED,
                target_claim_ids=(claim_id,),
                claim_graph_artifact_hash=graph_record.sha256,
                evidence_hashes=(result_hash,),
                finding_artifact_hashes=(),
                execution_receipt_hash=None,
                attack=f"Execute the bounded {category.value} attack.",
                conclusion="This Challenger category remains untested.",
                deterministic=False,
            ),
        )
        for category in ChallengeCategory
    )
    soundness = assess_soundness(
        registry,
        "soundness-paper-authority-claim-main",
        tuple(item.sha256 for item in dimension_records),
        tuple(item.sha256 for item in challenger_records),
        claim_graph_artifact_hash=graph_record.sha256,
        central_claim_ids=(claim_id,),
        reason="The offline fixture has incomplete scientific soundness authority.",
    )
    soundness_record = register_scientific_soundness_assessment(
        registry,
        soundness,
    )
    authoritative_evidence = tuple(
        sorted(
            {
                *tuple(item.sha256 for item in evidence_records),
                *tuple(item.sha256 for item in support_records),
                *tuple(item.sha256 for item in verification_records),
                semantics_record.sha256,
                *tuple(
                    source.artifact_hash
                    for result_metric in result_metrics
                    for source in (
                        *result_metric.result_authority_sources,
                        *result_metric.metric_authority_sources,
                    )
                ),
                raw_method.sha256,
                code.sha256,
                method_configuration.sha256,
                asset.artifact_hash,
                *asset.authoritative_parent_hashes,
                reference.reference_artifact_hash,
            }
        )
    )
    supplied_binding = MethodCodeBinding(
        raw_method.sha256,
        code.sha256,
        method_state.sha256,
        implementation_state.sha256,
    )
    bundle = build_authoritative_research_bundle(
        registry,
        ledger=ledger,
        run_id=run_id,
        research_state_hash=snapshot.sha256,
        claim_graph_hash=graph_record.sha256,
        central_claim_ids=(claim_id,),
        authoritative_evidence_hashes=authoritative_evidence,
        metrics=result_metrics,
        method_code_bindings=(supplied_binding,),
        required_baselines_complete=False,
        leakage_resolved=False,
        evaluator_exploitation_resolved=False,
        statistics_valid=False,
        novelty_supported=False,
        selection_integrity_valid=False,
        clean_reproduction_passed=False,
        soundness_assessment_hash=soundness_record.sha256,
        external_validation_complete=False,
    )
    register_authoritative_research_bundle(
        registry,
        ledger,
        bundle,
        bundle_id=bundle_fixture_id(bundle),
        created_at=timestamp,
    )
    authority_claim = bundle.claims[0]
    candidate = PaperCandidate(
        candidate_id="paper-fixture",
        title="A bounded fixture validates the vNext paper boundary",
        claims=(
            PaperClaim(
                claim_id=claim_id,
                text=authority_claim.text,
                strength=authority_claim.expressed_strength,
                evidence_hashes=authority_claim.evidence_hashes,
                citation_ids=("citation-fixture",),
                central=True,
                claim_type=authority_claim.claim_type,
                scope=authority_claim.scope,
                confidence=authority_claim.confidence,
                verification_method=authority_claim.verification_method,
                permitted_strength=authority_claim.permitted_strength,
                dependency_claim_ids=authority_claim.dependency_claim_ids,
                evidence_sources=(
                    authority_claim.requirements.evidence_sources
                    if authority_claim.requirements is not None
                    else ()
                ),
            ),
        ),
        numeric_assertions=tuple(
            PaperNumericAssertion(
                f"assertion-{result_metric.result_value_key}",
                claim_id,
                result_metric.metric_id,
                result_metric.value,
                result_metric.unit,
                result_metric.direction,
                result_metric.result_artifact_hash,
            )
            for result_metric in result_metrics
        ),
        references=(
            ReferenceUse(
                "citation-fixture",
                reference.reference_artifact_hash,
                ReferenceDepth.LEVEL_5,
                (claim_id,),
            ),
        ),
        assets=(
            GeneratedAsset(
                "table-main",
                "TABLE",
                asset.artifact_hash,
                asset.authoritative_parent_hashes,
            ),
        ),
        method_code_bindings=bundle.method_code_bindings,
        limitations=bundle.required_limitations,
        source_bundle_hashes=(
            snapshot.sha256,
            graph_record.sha256,
            soundness_record.sha256,
        ),
    )
    fixture = PaperAuthorityFixture(
        registry,
        ledger,
        bundle,
        candidate,
        result_hash,
        asset.artifact_hash,
        reference.reference_artifact_hash,
        raw_method.sha256,
        code.sha256,
        graph_record.sha256,
        snapshot.sha256,
        soundness_record.sha256,
        None,
    )
    _CACHED_AUTHORITY_TEMPORARY = temporary
    _CACHED_AUTHORITY_FIXTURE = fixture
    return fixture


def authoritative_fixture(
    root: str,
    *,
    untested_categories: tuple[ChallengeCategory, ...] = (),
    selection_integrity_valid: bool = False,
    confirmatory: bool = False,
    claim_id: str = "claim-main",
    claim_text: str = "The deterministic fixture produced a value of 0.75.",
) -> PaperAuthorityFixture:
    if not confirmatory and claim_id == "claim-main":
        source = _cached_canonical_authority_fixture()
        shutil.copytree(
            source.registry.policy.root,
            Path(root),
            dirs_exist_ok=True,
        )
        return replace(
            source,
            registry=ArtifactRegistry(root, source.registry.base_path),
            ledger=EventLedger(root, source.ledger.relative_path),
        )
    timestamp = "2026-08-29T12:00:00Z"
    planned_run_id = (
        f"paper-confirmatory-{claim_id}"
        if confirmatory
        else f"paper-authority-{claim_id}"
    )
    registry = ArtifactRegistry(root, f"runs/{planned_run_id}/registry")
    method_id = f"method-{planned_run_id}"
    implementation_id = f"implementation-{planned_run_id}"
    canonical_metric_id = f"metric-{planned_run_id}"
    result_id = f"result-{planned_run_id}"
    code = registry.put_bytes(
        b"def predict(value): return int(value >= 0.5)\n",
        logical_type="experiment_code",
        origin="paper-authority-test",
        creator_role=Role.IMPLEMENTER,
        mime_type="text/x-python",
    )
    method_configuration = _put_json(
        registry,
        {"configuration_id": "paper-method-configuration"},
        "experiment_configuration",
        Role.PROTOCOL_DESIGNER,
        (code.sha256,),
    )
    raw_method = _put_json(
        registry,
        {
            "method_id": method_id,
            "name": "Pinned threshold",
            "description": "Predict one at or above the frozen threshold.",
            "assumptions": ["Input is numeric."],
            "component_ids": ["threshold-component"],
            "tuning_trials": 0,
        },
        "method_definition",
        Role.HYPOTHESIS_DESIGNER,
        (method_configuration.sha256,),
    )
    confirmatory_artifacts = (
        register_confirmatory_artifacts(
            registry,
            root,
            code_hash=code.sha256,
            run_label=planned_run_id,
        )
        if confirmatory
        else None
    )
    raw_result = _put_json(
        registry,
        {
            "metric_id": canonical_metric_id,
            "baseline_accuracy": 0.0,
            "candidate_accuracy": 0.75,
            "effect": 0.75,
            "scientific_evidence_eligible": False,
        },
        "aggregate_experiment_result",
        Role.STATISTICIAN,
    )
    domain_support = register_domain_raw_fixture_source(
        registry,
        run_id=planned_run_id,
        domain=DomainKind.GENERIC_ML,
        object_id=result_id,
        task_id="paper-generic-ml",
        source_id="bounded-domain-input",
        payload={"fixture_observation": "non-evidentiary paper boundary input"},
        creator_role=Role.PROTOCOL_DESIGNER,
    )
    domain_source = register_domain_evidence_source(
        registry,
        run_id=planned_run_id,
        domain=DomainKind.GENERIC_ML,
        object_id=result_id,
        task_id="paper-generic-ml",
        evidence=GenericMLValidityEvidence(
            examples=(
                GenericMLExample("paper-train", SplitRole.TRAIN),
                GenericMLExample("paper-validation", SplitRole.VALIDATION),
                GenericMLExample("paper-test", SplitRole.TEST),
            ),
            preprocessing_fit_splits=(SplitRole.TRAIN,),
            benchmark_version="paper-fixture-v1",
            pretrained_contamination_checked=True,
            seed_policy_frozen=True,
            checkpoint_selection_split=SplitRole.VALIDATION,
            metric_implementation_verified=True,
            hyperparameter_budget_equivalent=True,
            compute_budget_equivalent=True,
            robustness_evaluated=True,
        ),
        supporting_artifact_hashes=(domain_support.sha256,),
    )
    domain_validity = materialize_domain_validity(
        registry,
        source_artifact_sha256=domain_source.sha256,
        expected_run_id=planned_run_id,
        expected_domain=DomainKind.GENERIC_ML,
        expected_object_id=result_id,
        expected_task_id="paper-generic-ml",
    )
    table = registry.put_bytes(
        (
            f"run_id,method,value\n{planned_run_id},pinned-threshold,0.75\n"
        ).encode(),
        logical_type="results_table",
        origin="paper-authority-test",
        creator_role=Role.STATISTICIAN,
        parent_artifacts=(raw_result.sha256,),
        mime_type="text/csv",
    )

    reference_source = _put_json(
        registry,
        {"passage": claim_text},
        "captured_reference_source",
        Role.EVIDENCE_CURATOR,
    )
    semantic = _put_json(
        registry,
        {"claim_text": claim_text, "decision": "SUPPORTS"},
        "semantic_reference_assessment",
        Role.CLAIM_VERIFIER,
        (reference_source.sha256,),
    )
    context = _put_json(
        registry,
        {"claim_text": claim_text, "decision": "NOT_CONTRADICTED"},
        "context_reference_assessment",
        Role.CLAIM_VERIFIER,
        (reference_source.sha256,),
    )
    reference_parents = (reference_source.sha256, semantic.sha256, context.sha256)
    reference_record = _put_json(
        registry,
        {
            "claim_text": claim_text,
            "reference": {"title": "Deterministic fixture source"},
            "verification": {
                "failure_reasons": [],
                "level": 5,
                "locator": {"passage_id": "fixture-passage"},
                "metadata_mismatches": [],
                "parent_artifact_hashes": list(reference_parents),
            },
        },
        "reference_verification",
        Role.CLAIM_VERIFIER,
        reference_parents,
    )
    provisional: list[EvidenceNode] = []
    evidence_records = []
    for index, kind in enumerate(sorted(REQUIRED_EVIDENCE_KINDS, key=lambda item: item.value), 1):
        source_by_kind = {
            EvidenceKind.CODE: code.sha256,
            EvidenceKind.FIGURE_OR_TABLE: table.sha256,
            EvidenceKind.RESULT: raw_result.sha256,
            EvidenceKind.SOURCE_CITATION: reference_record.sha256,
        }
        if confirmatory_artifacts is not None:
            source_by_kind.update(
                {
                    EvidenceKind.DATASET_OR_FIXTURE: (
                        confirmatory_artifacts.custody_hash
                    ),
                    EvidenceKind.PROTOCOL_VERSION: (
                        confirmatory_artifacts.protocol_hash
                    ),
                }
            )
        source_hash = source_by_kind.get(kind)
        parents = (
            (
                confirmatory_artifacts.result_hash,
                raw_result.sha256,
            )
            if kind is EvidenceKind.RESULT
            and confirmatory_artifacts is not None
            else ((source_hash,) if source_hash is not None else ())
        )
        declares_single_source = source_hash is not None and len(parents) == 1
        record = _put_json(
            registry,
            {
                "claim_text": claim_text,
                "evidence_kind": kind.value,
                "source_artifact_hash": source_hash,
                "supports": claim_text,
            }
            if declares_single_source
            else {
                "claim_text": claim_text,
                "evidence_kind": kind.value,
                "supports": claim_text,
            },
            f"claim_evidence.{kind.value}",
            Role.EVIDENCE_CURATOR,
            parents,
        )
        evidence_records.append(record)
        provisional.append(
            EvidenceNode(
                evidence_id=f"paper-evidence-{index:02d}-{kind.value}",
                kind=kind,
                artifact_hash=record.sha256,
                description=f"Frozen {kind.value} evidence for the exact scoped claim.",
                verified=True,
                frozen=True,
                supports_claim=True,
                contradicts_claim=False,
                locally_verifiable=True,
            )
        )
    material_claim = MaterialClaim(
        claim_id=claim_id,
        text=claim_text,
        evidence_links=tuple(EvidenceLink(item.evidence_id, item.kind) for item in provisional),
        producer_role=Role.EXPERIMENT_RUNNER,
        confirmatory=confirmatory,
        evidence_use=ClaimEvidenceUse.SCIENTIFIC,
    )
    support_records = []
    nodes: list[EvidenceNode] = []
    for node in provisional:
        receipt = EvidenceSupportReceipt.for_claim(
            material_claim,
            node,
            verifier_id="paper-claim-verifier",
            verification_result="PASS",
            supports_claim=True,
            contradicts_claim=False,
            locally_verifiable=True,
            rationale="The frozen artifact supports the exact scoped claim.",
        )
        receipt_record = _put_json(
            registry,
            receipt.to_dict(),
            f"claim_support_receipt.{node.kind.value}",
            Role.CLAIM_VERIFIER,
            (node.artifact_hash,),
        )
        if receipt_record.sha256 != receipt.sha256:
            raise AssertionError("support receipt fixture identity mismatch")
        support_records.append(receipt_record)
        nodes.append(replace(node, verification_receipt_hash=receipt_record.sha256))
    resolver = artifact_registry_resolver(
        registry,
        resolver_id=CLAIM_GRAPH_RESOLVER_ID,
    )
    graph = ClaimEvidenceGraph(evidence_resolver=resolver)
    for node in nodes:
        graph.add_evidence(node)
    graph.add_claim(material_claim)
    decision = graph.verify_claim(
        material_claim.claim_id,
        verifier_id="paper-claim-verifier",
        confirmatory_evidence_valid=True,
    )
    if decision.decision is not ClaimDecision.ELIGIBLE:
        raise AssertionError("paper authority fixture claim did not become eligible")
    verification_records = []
    for node in nodes:
        receipt = resolver(material_claim, node)
        record = registry.put_bytes(
            receipt.canonical_bytes,
            logical_type=f"claim_evidence_verification_receipt.{node.kind.value}",
            origin="paper-authority-test",
            creator_role=Role.CLAIM_VERIFIER,
            parent_artifacts=(node.artifact_hash, receipt.support_receipt_hash),
            mime_type="application/json",
        )
        if record.sha256 != receipt.sha256:
            raise AssertionError("verification receipt fixture identity mismatch")
        verification_records.append(record)
    graph_record = _put_json(
        registry,
        {"decision": _jsonable(decision), "graph": graph.to_dict()},
        "claim_evidence_graph",
        Role.CLAIM_VERIFIER,
        tuple(
            item.sha256
            for item in (*evidence_records, *support_records, *verification_records)
        ),
    )

    run_id = (
        confirmatory_artifacts.run_id
        if confirmatory_artifacts is not None
        else planned_run_id
    )
    ledger = (
        confirmatory_artifacts.ledger
        if confirmatory_artifacts is not None
        else EventLedger(root, f"runs/{run_id}/events.jsonl")
    )
    state_code_version = "paper-fixture-code-v1"
    state_configuration_hash = digest(f"{run_id}:state-configuration")
    repository = ResearchStateRepository(
        registry,
        ledger,
        run_id=run_id,
        code_version=state_code_version,
        configuration_hash=state_configuration_hash,
        state=MacroState.CLAIMS,
        creation_command=("scientist-one", "paper-authority-state"),
    )
    method = StateMethod(
        object_id=method_id,
        producer=Role.HYPOTHESIS_DESIGNER,
        status=RecordStatus.FROZEN,
        created_at=timestamp,
        code_version=state_code_version,
        name="Pinned threshold",
        description="Predict one at or above the frozen threshold.",
        assumptions=("Input is numeric.",),
        component_ids=("threshold-component",),
        authority_artifact_hashes=(raw_method.sha256,),
    )
    method_state = repository.materialize(method).artifact
    implementation = StateImplementation(
        object_id=implementation_id,
        producer=Role.IMPLEMENTER,
        status=RecordStatus.FROZEN,
        created_at=timestamp,
        parents=(
            ObjectReference(
                "Method",
                method.object_id,
                method.content_hash,
                "implements",
                True,
            ),
        ),
        code_version=state_code_version,
        method_id=method.object_id,
        code_artifact_hashes=(code.sha256,),
        code_revision=state_code_version,
        configuration_artifact_hashes=(method_configuration.sha256,),
        authority_artifact_hashes=(code.sha256, method_configuration.sha256),
    )
    implementation_state = repository.materialize(implementation).artifact
    metric_evaluator = _put_json(
        registry,
        {
            "metric_id": canonical_metric_id,
            "unit": "fraction",
            "description": "Exact bounded aggregate metric.",
        },
        "metric_evaluator",
        Role.PROTOCOL_DESIGNER,
    )
    evaluation_contract = _put_json(
        registry,
        {
            "evaluation_contract": {
                "primary_metric": {
                    "metric_id": canonical_metric_id,
                    "name": "Candidate accuracy",
                    "direction": "HIGHER_IS_BETTER",
                    "unit": "fraction",
                    "scope": MetricLevel.END_TO_END.value,
                },
                "secondary_metrics": [],
            }
        },
        "evaluation_contract",
        Role.PROTOCOL_DESIGNER,
        (metric_evaluator.sha256,),
    )
    state_metric = StateMetric(
        object_id=canonical_metric_id,
        producer=Role.PROTOCOL_DESIGNER,
        status=RecordStatus.FROZEN,
        created_at=timestamp,
        code_version=state_code_version,
        name="Candidate accuracy",
        direction=StateMetricDirection.HIGHER_IS_BETTER,
        unit="fraction",
        evidence_level=MetricLevel.END_TO_END,
        authority_artifact_hashes=(
            metric_evaluator.sha256,
            evaluation_contract.sha256,
        ),
    )
    metric_state = repository.materialize(state_metric).artifact
    result = StateResult(
        object_id=result_id,
        producer=Role.STATISTICIAN,
        status=RecordStatus.COMPLETE,
        created_at=timestamp,
        code_version=state_code_version,
        run_ids=(run_id,),
        metric_id=canonical_metric_id,
        value={"baseline": 0.0, "candidate": 0.75, "improvement": 0.75},
        unit="fraction",
        direction=StateMetricDirection.HIGHER_IS_BETTER,
        source_artifact_hashes=(raw_result.sha256,),
        evaluation_artifact_hashes=(domain_validity.sha256,),
        code_revision=state_code_version,
        observed_at=timestamp,
        parents=(
            ObjectReference(
                "Metric",
                state_metric.object_id,
                state_metric.content_hash,
                "measured_by",
                True,
            ),
        ),
        authority_artifact_hashes=(raw_result.sha256, domain_validity.sha256),
    )
    result_state = repository.materialize(result).artifact
    claim_authority_sources = (
        graph_record.sha256,
        *tuple(item.sha256 for item in verification_records),
        *(
            (confirmatory_artifacts.timeline_receipt_hash,)
            if confirmatory_artifacts is not None
            else ()
        ),
    )
    state_claim = StateClaim(
        object_id=material_claim.claim_id,
        producer=Role.EXPERIMENT_RUNNER,
        status=RecordStatus.VERIFIED,
        created_at=timestamp,
        code_version=state_code_version,
        claim_type=ClaimType.COMPARATIVE,
        claim_text=claim_text,
        scope="Deterministic fixture only.",
        source_artifact_ids=(graph_record.sha256,),
        verification_method="fresh registry-resolved claim graph",
        verification_status=VerificationStatus.VERIFIED,
        confidence=0.9,
        expressed_strength=ClaimStrength.QUALIFIED,
        permitted_strength=ClaimStrength.QUALIFIED,
        review_history=(
            ClaimReview(
                reviewer=Role.CLAIM_VERIFIER,
                timestamp=timestamp,
                verification_status=VerificationStatus.VERIFIED,
                reason="All typed evidence and receipts resolved.",
                source_artifact_ids=(
                    *claim_authority_sources,
                ),
            ),
        ),
        confirmatory=confirmatory,
        evidence_use=ClaimEvidenceUse.SCIENTIFIC,
        authority_artifact_hashes=claim_authority_sources,
    )
    repository.materialize(state_claim)
    state_report = repository.validate_state(expected_code_version=state_code_version)
    if not state_report.valid:
        raise AssertionError("paper authority canonical state did not validate")
    snapshot = register_research_state_snapshot(
        repository,
        snapshot_id="paper-authority",
        created_at=timestamp,
    )
    soundness_dimension_records = tuple(
        register_soundness_dimension_receipt(
            registry,
            SoundnessDimensionEvidenceReceipt(
                receipt_id=f"paper-{dimension.value.lower()}-receipt",
                dimension=dimension,
                status=DimensionStatus.UNTESTED,
                authority_kind=SoundnessAuthorityKind.NOT_EXECUTED,
                authority_artifact_hash=None,
                evidence_hashes=(graph_record.sha256,),
                governing_rule="The exact registered evidence must satisfy this dimension.",
                rationale="The bounded authority fixture supplies a content-bound PASS receipt.",
                reviewer_id="paper-soundness-reviewer",
            ),
        )
        for dimension in SoundnessDimension
    )
    challenger_records = tuple(
        register_challenger_category_review(
            registry,
            ChallengerCategoryReview(
                review_id=f"paper-{category.value.lower()}-review",
                category=category,
                execution_status=(
                    ChallengerExecutionStatus.UNTESTED
                ),
                target_claim_ids=(material_claim.claim_id,),
                claim_graph_artifact_hash=graph_record.sha256,
                evidence_hashes=(raw_result.sha256,),
                finding_artifact_hashes=(),
                execution_receipt_hash=None,
                attack=f"Execute the bounded {category.value} attack checklist.",
                conclusion=(
                    "This Challenger category remains untested."
                    if category in untested_categories
                    else "No issue was found in the synthetic authority fixture."
                ),
                deterministic=False,
            ),
        )
        for category in ChallengeCategory
    )
    soundness = assess_soundness(
        registry,
        f"soundness-paper-authority-{claim_id}",
        tuple(item.sha256 for item in soundness_dimension_records),
        tuple(item.sha256 for item in challenger_records),
        claim_graph_artifact_hash=graph_record.sha256,
        central_claim_ids=(material_claim.claim_id,),
        reason="Every locally testable soundness dimension passed in this bounded fixture.",
    )
    soundness_record = register_scientific_soundness_assessment(
        registry,
        soundness,
    )

    authority_hashes = tuple(
        sorted(
            {
                *tuple(item.sha256 for item in evidence_records),
                *tuple(item.sha256 for item in support_records),
                *tuple(item.sha256 for item in verification_records),
                raw_result.sha256,
                domain_validity.sha256,
                raw_method.sha256,
                code.sha256,
                method_configuration.sha256,
                metric_evaluator.sha256,
                evaluation_contract.sha256,
                table.sha256,
                reference_record.sha256,
                *(
                    (
                        confirmatory_artifacts.protocol_hash,
                        confirmatory_artifacts.blind_hash,
                        confirmatory_artifacts.source_inventory_hash,
                        confirmatory_artifacts.configuration_inventory_hash,
                        confirmatory_artifacts.split_manifest_hash,
                        confirmatory_artifacts.midrun_review_hash,
                        confirmatory_artifacts.resource_charge_hash,
                        confirmatory_artifacts.fresh_custody_hash,
                        confirmatory_artifacts.custody_hash,
                        confirmatory_artifacts.result_hash,
                        confirmatory_artifacts.timeline_receipt_hash,
                    )
                    if confirmatory_artifacts is not None
                    else ()
                ),
            }
        )
    )
    metric = AuthoritativeMetric(
        metric_id="metric-main",
        value=0.75,
        unit="fraction",
        direction=MetricDirection.HIGHER_IS_BETTER,
        result_artifact_hash=raw_result.sha256,
        result_state_artifact_hash=result_state.sha256,
        canonical_metric_id=canonical_metric_id,
        result_value_key="candidate",
        tolerance=1e-12,
        metric_state_artifact_hash=metric_state.sha256,
    )
    binding = MethodCodeBinding(
        method_artifact_hash=raw_method.sha256,
        code_artifact_hash=code.sha256,
        method_state_artifact_hash=method_state.sha256,
        implementation_state_artifact_hash=implementation_state.sha256,
    )
    bundle = build_authoritative_research_bundle(
        registry,
        ledger=ledger,
        run_id=run_id,
        confirmatory_timeline_receipt_hashes=(
            (confirmatory_artifacts.timeline_receipt_hash,)
            if confirmatory_artifacts is not None
            else ()
        ),
        research_state_hash=snapshot.sha256,
        claim_graph_hash=graph_record.sha256,
        central_claim_ids=(material_claim.claim_id,),
        authoritative_evidence_hashes=authority_hashes,
        metrics=(metric,),
        method_code_bindings=(binding,),
        required_baselines_complete=False,
        leakage_resolved=False,
        evaluator_exploitation_resolved=False,
        statistics_valid=False,
        novelty_supported=False,
        selection_integrity_valid=selection_integrity_valid,
        clean_reproduction_passed=False,
        soundness_assessment_hash=soundness_record.sha256,
        external_validation_complete=False,
    )
    register_authoritative_research_bundle(
        registry,
        ledger,
        bundle,
        bundle_id=bundle_fixture_id(bundle),
        created_at=timestamp,
    )
    authority_claim = bundle.claims[0]
    candidate = PaperCandidate(
        candidate_id=(
            "paper-fixture"
            if claim_id == "claim-main"
            else f"paper-fixture-{claim_id}"
        ),
        title="A bounded fixture validates the vNext paper boundary",
        claims=(
            PaperClaim(
                claim_id=authority_claim.claim_id,
                text=authority_claim.text,
                strength=authority_claim.expressed_strength,
                evidence_hashes=authority_claim.evidence_hashes,
                citation_ids=("citation-fixture",),
                central=True,
                claim_type=authority_claim.claim_type,
                scope=authority_claim.scope,
                confidence=authority_claim.confidence,
                verification_method=authority_claim.verification_method,
                permitted_strength=authority_claim.permitted_strength,
                dependency_claim_ids=authority_claim.dependency_claim_ids,
                evidence_sources=(
                    authority_claim.requirements.evidence_sources
                    if authority_claim.requirements is not None
                    else ()
                ),
            ),
        ),
        numeric_assertions=(
            PaperNumericAssertion(
                "assertion-main",
                authority_claim.claim_id,
                metric.metric_id,
                metric.value,
                metric.unit,
                metric.direction,
                metric.result_artifact_hash,
            ),
        ),
        references=(
            ReferenceUse(
                "citation-fixture",
                reference_record.sha256,
                ReferenceDepth.LEVEL_5,
                (authority_claim.claim_id,),
            ),
        ),
        assets=(
            GeneratedAsset(
                "table-main",
                "TABLE",
                table.sha256,
                table.parent_artifacts,
            ),
        ),
        method_code_bindings=bundle.method_code_bindings,
        limitations=bundle.required_limitations,
        source_bundle_hashes=(
            snapshot.sha256,
            graph_record.sha256,
            soundness_record.sha256,
        ),
    )
    return PaperAuthorityFixture(
        registry,
        ledger,
        bundle,
        candidate,
        raw_result.sha256,
        table.sha256,
        reference_record.sha256,
        raw_method.sha256,
        code.sha256,
        graph_record.sha256,
        snapshot.sha256,
        soundness_record.sha256,
        confirmatory_artifacts,
    )


def venue_authority_fixture(
    fixture: PaperAuthorityFixture,
    profile: VenueProfile,
    *,
    bundle: AuthoritativeResearchBundle | None = None,
    candidate: PaperCandidate | None = None,
) -> VenueAuthorityFixture:
    bundle = fixture.bundle if bundle is None else bundle
    candidate = fixture.candidate if candidate is None else candidate
    if bundle.run_id is None:
        raise AssertionError("venue fixture requires a run-bound paper bundle")
    bundle_artifact = register_authoritative_research_bundle(
        fixture.registry,
        fixture.ledger,
        bundle,
        bundle_id=bundle_fixture_id(bundle),
    )
    candidate_artifact = _put_json(
        fixture.registry,
        {"candidate": _jsonable(candidate)},
        "paper_candidate",
        Role.PAPER_WRITER,
        (bundle_artifact.sha256, fixture.asset_hash),
    )
    section_sources = {
        "methods": tuple(sorted((fixture.method_hash, fixture.code_hash))),
        "results": tuple(sorted((fixture.result_hash, fixture.asset_hash))),
    }
    sections = tuple(
        ManuscriptSection(
            section,
            section_sources.get(section, (fixture.claim_graph_hash,)),
        )
        for section in profile.required_sections
    )
    bindings = tuple(
        ArtifactReadinessBinding(
            requirement,
            (fixture.code_hash,)
            if requirement == "code"
            else (fixture.result_hash,),
        )
        for requirement in profile.artifact_requirements
    )
    profile_artifact = register_approved_venue_profile(fixture.registry, profile)
    manuscript = register_paper_manuscript(
        fixture.registry,
        candidate,
        bundle,
        profile,
        run_id=bundle.run_id,
        candidate_artifact_hash=candidate_artifact.sha256,
        bundle_artifact_hash=bundle_artifact.sha256,
        profile_artifact_hash=profile_artifact.sha256,
        sections=sections,
        artifact_bindings=bindings,
    )
    manifest = register_venue_readiness_manifest(
        fixture.registry,
        candidate,
        bundle,
        profile,
        run_id=bundle.run_id,
        candidate_artifact_hash=candidate_artifact.sha256,
        bundle_artifact_hash=bundle_artifact.sha256,
        profile_artifact_hash=profile_artifact.sha256,
        manuscript_artifact_hash=manuscript.sha256,
    )
    return VenueAuthorityFixture(
        bundle_artifact.sha256,
        candidate_artifact.sha256,
        profile_artifact.sha256,
        manuscript.sha256,
        manifest.sha256,
    )


def rebuild_authoritative_bundle(
    fixture: PaperAuthorityFixture,
    *,
    authoritative_evidence_hashes: tuple[str, ...] | None = None,
    claim_graph_hash: str | None = None,
    metrics: tuple[AuthoritativeMetric, ...] | None = None,
) -> AuthoritativeResearchBundle:
    bundle = fixture.bundle
    return build_authoritative_research_bundle(
        fixture.registry,
        ledger=fixture.ledger,
        run_id=bundle.run_id,
        confirmatory_timeline_receipt_hashes=(
            (fixture.confirmatory_artifacts.timeline_receipt_hash,)
            if fixture.confirmatory_artifacts is not None
            else ()
        ),
        research_state_hash=bundle.research_state_hash,
        claim_graph_hash=(
            bundle.claim_graph_hash if claim_graph_hash is None else claim_graph_hash
        ),
        central_claim_ids=bundle.central_claim_ids,
        authoritative_evidence_hashes=(
            bundle.authoritative_evidence_hashes
            if authoritative_evidence_hashes is None
            else authoritative_evidence_hashes
        ),
        metrics=bundle.metrics if metrics is None else metrics,
        method_code_bindings=bundle.method_code_bindings,
        required_baselines_complete=bundle.required_baselines_complete,
        leakage_resolved=bundle.leakage_resolved,
        evaluator_exploitation_resolved=bundle.evaluator_exploitation_resolved,
        statistics_valid=bundle.statistics_valid,
        novelty_supported=bundle.novelty_supported,
        selection_integrity_valid=bundle.selection_integrity_valid,
        clean_reproduction_passed=bundle.clean_reproduction_passed,
        soundness_assessment_hash=bundle.soundness_assessment_hash,
        external_validation_complete=bundle.external_validation_complete,
    )


def legacy_placeholder_bundle() -> AuthoritativeResearchBundle:
    return AuthoritativeResearchBundle(
        research_state_hash=digest("state"),
        claim_graph_hash=digest("claims"),
        claims=(
            AuthoritativeClaim(
                claim_id="claim-main",
                text="The deterministic fixture produced a value of 0.75.",
                expressed_strength=ClaimStrength.QUALIFIED,
                permitted_strength=ClaimStrength.QUALIFIED,
                evidence_hashes=(digest("result"),),
                claim_state_artifact_hash=digest("claim-state"),
                graph_decision_hash=digest("claim-decision"),
                claim_semantics_artifact_hash=digest("claim-semantics"),
                producer_role=Role.EXPERIMENT_RUNNER,
                claim_semantics_evidence_scope=(
                    ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE
                ),
                confidence=0.9,
                verification_method="legacy non-evidentiary placeholder",
                scientific_writer_eligible=False,
                evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
            ),
        ),
        central_claim_ids=("claim-main",),
        authoritative_evidence_hashes=(digest("result"), digest("code"), digest("table-parent")),
        metrics=(
            AuthoritativeMetric(
                metric_id="metric-main",
                value=0.75,
                unit="fraction",
                direction=MetricDirection.HIGHER_IS_BETTER,
                result_artifact_hash=digest("result"),
                result_state_artifact_hash=digest("result-state"),
                canonical_metric_id="canonical-metric-main",
                tolerance=1e-12,
            ),
        ),
        method_code_bindings=(
            MethodCodeBinding(
                digest("method"),
                digest("code"),
                digest("method-state"),
                digest("implementation-state"),
            ),
        ),
        required_limitations=("Fixture-only external validation remains untested.",),
        required_baselines_complete=True,
        leakage_resolved=True,
        evaluator_exploitation_resolved=True,
        statistics_valid=True,
        novelty_supported=True,
        selection_integrity_valid=True,
        clean_reproduction_passed=True,
        soundness_verdict=SoundnessVerdict.PASS,
        soundness_assessment_hash=digest("soundness"),
        external_validation_complete=False,
    )


class PaperClaimSchemaBoundaryTests(unittest.TestCase):
    def test_candidate_round_trip_requires_every_claim_semantics_field(self) -> None:
        evidence_hash = digest("paper-claim-schema-evidence")
        source_hash = digest("paper-claim-schema-source")
        claim = PaperClaim(
            claim_id="paper-claim-schema",
            text="A narrowly scoped typed claim.",
            strength=ClaimStrength.QUALIFIED,
            evidence_hashes=(evidence_hash,),
            claim_type=ClaimType.COMPARATIVE,
            scope="The exact bounded test population.",
            confidence=0.8,
            verification_method="fresh deterministic and semantic replay",
            permitted_strength=ClaimStrength.QUALIFIED,
            dependency_claim_ids=(),
            evidence_sources=(
                EvidenceSourceBinding(
                    EvidenceKind.RESULT,
                    evidence_hash,
                    (source_hash,),
                ),
            ),
        )
        candidate = PaperCandidate(
            candidate_id="paper-claim-schema-candidate",
            title="Typed paper claim schema",
            claims=(claim,),
            numeric_assertions=(),
            references=(),
            assets=(),
            method_code_bindings=(),
            limitations=("The exact bounded test population.",),
            source_bundle_hashes=(digest("paper-claim-schema-bundle"),),
        )
        value = _jsonable(candidate)
        self.assertEqual(_paper_candidate_from_json(value), candidate)
        for field_name in (
            "claim_type",
            "scope",
            "confidence",
            "verification_method",
            "permitted_strength",
            "dependency_claim_ids",
            "evidence_sources",
        ):
            forged = safe_json_loads(canonical_json_bytes(value))
            del forged["claims"][0][field_name]
            with self.subTest(field=field_name), self.assertRaises(ValidationError):
                _paper_candidate_from_json(forged)

    def test_numeric_comparison_does_not_alias_large_integer_tokens(self) -> None:
        self.assertTrue(
            _exact_numeric_equal(
                9_007_199_254_740_992,
                9_007_199_254_740_992.0,
            )
        )
        self.assertFalse(
            _exact_numeric_equal(
                9_007_199_254_740_992,
                9_007_199_254_740_993,
            )
        )

    def test_reference_use_requires_one_complete_claim_bound_projection(self) -> None:
        common = {
            "citation_id": "citation-bound",
            "reference_artifact_hash": digest("reference-bound"),
            "verification_depth": ReferenceDepth.LEVEL_5,
            "supported_claim_ids": ("claim-bound",),
        }
        ReferenceUse(**common)
        with self.assertRaisesRegex(ValidationError, "one exact projection"):
            ReferenceUse(
                **common,
                source_citation_evidence_artifact_hash=digest("source-bound"),
            )

    def test_citation_source_projection_is_three_parent_scientific_or_one_parent_diagnostic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            reference = _put_json(
                registry,
                {"reference": "exact-level-five-verification"},
                "reference_verification",
                Role.CLAIM_VERIFIER,
            )
            citation_graph = _put_json(
                registry,
                {"citation_graph": "exact-citation-node"},
                "citation_graph",
                Role.EVIDENCE_CURATOR,
            )
            transport = registry.put_json(
                {"transport": "structural-test-only"},
                logical_type="audited_transport_execution_authority",
                origin="paper citation projection boundary test",
                creator_role=Role.EVIDENCE_CURATOR,
                parent_artifacts=(citation_graph.sha256,),
                schema_version=AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            semantic = _put_json(
                registry,
                {"judgment": "must-not-be-an-evidence parent"},
                "semantic_judgment_receipt",
                Role.SCIENTIFIC_REVIEWER,
            )
            source = digest("paper-citation-source-projection")
            canonical_sources = (
                reference.sha256,
                citation_graph.sha256,
                transport.sha256,
            )
            canonical_binding = EvidenceSourceBinding(
                EvidenceKind.SOURCE_CITATION,
                source,
                canonical_sources,
            )
            diagnostic_binding = EvidenceSourceBinding(
                EvidenceKind.SOURCE_CITATION,
                source,
                (reference.sha256,),
            )
            with self.assertRaisesRegex(ValidationError, "one diagnostic source"):
                EvidenceSourceBinding(
                    EvidenceKind.SOURCE_CITATION,
                    source,
                    (*canonical_sources, semantic.sha256),
                )

            state_authority = ResearchStateAuthoritySnapshot(
                run_id="paper-citation-projection",
                snapshot_artifact_sha256=digest("citation-state-snapshot"),
                snapshot_artifact_record_hash=digest(
                    "citation-state-snapshot-record"
                ),
                ledger_head_hash=digest("citation-state-ledger-head"),
                ledger_event_count=1,
                code_version=f"sha256:{'a' * 64}",
                configuration_hash=digest("citation-state-configuration"),
                entries=(),
            )
            common_semantics = {
                "run_id": "paper-citation-projection",
                "claim_graph_artifact_hash": digest("citation-claim-graph"),
                "claim_graph_artifact_record_hash": digest(
                    "citation-claim-graph-record"
                ),
                "claim_id": "paper-citation-claim",
                "claim_text": "The retained passage supports this bounded claim.",
                "claim_producer_role": Role.PROBLEM_INVESTIGATOR,
                "claim_type": ClaimType.QUALITATIVE,
                "scope": "Only the exact retained passage.",
                "confidence": 0.75,
                "expressed_strength": ClaimStrength.QUALIFIED,
                "permitted_strength": ClaimStrength.QUALIFIED,
                "verification_method": "exact claim-bound semantic replay",
                "dependency_bindings": (),
            }
            scientific_semantics = ClaimSemanticsReceipt(
                **common_semantics,
                receipt_id="paper-citation-semantics",
                claim_evidence_use=ClaimEvidenceUse.SCIENTIFIC,
                evidence_scope=ClaimSemanticsEvidenceScope.SCIENTIFIC_EVIDENCE,
                semantic_proposal_artifact_hash=digest(
                    "citation-semantics-proposal"
                ),
                reference_support_semantic_judgment_artifact_hash=digest(
                    "citation-reference-support-judgment"
                ),
                semantic_authority_artifact_hash=digest(
                    "citation-main-semantic-authority"
                ),
            )
            with self.assertRaisesRegex(
                ValidationError,
                "live signed transport replay",
            ):
                _derive_claim_paper_requirements(
                    registry,
                    scientific_semantics,
                    (canonical_binding,),
                    (),
                    state_authority,
                )
            with self.assertRaisesRegex(
                ValidationError,
                "exact three-source projection",
            ):
                _derive_claim_paper_requirements(
                    registry,
                    scientific_semantics,
                    (diagnostic_binding,),
                    (),
                    state_authority,
                )
            diagnostic_semantics = ClaimSemanticsReceipt(
                **common_semantics,
                receipt_id="paper-citation-diagnostic-semantics",
                claim_evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
                evidence_scope=(
                    ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE
                ),
            )
            diagnostic_requirements = _derive_claim_paper_requirements(
                registry,
                diagnostic_semantics,
                (diagnostic_binding,),
                (),
                state_authority,
            )
            self.assertEqual(
                diagnostic_requirements.required_reference_artifact_hashes,
                (reference.sha256,),
            )
            self.assertFalse(
                diagnostic_requirements.required_reference_authorities
            )
            with self.assertRaisesRegex(
                ValidationError,
                "reordered or substituted",
            ):
                _derive_claim_paper_requirements(
                    registry,
                    scientific_semantics,
                    (
                        EvidenceSourceBinding(
                            EvidenceKind.SOURCE_CITATION,
                            source,
                            (
                                reference.sha256,
                                transport.sha256,
                                citation_graph.sha256,
                            ),
                        ),
                    ),
                    (),
                    state_authority,
                )

    def test_bundle_evidence_cannot_duplicate_primary_parent(self) -> None:
        bundle = legacy_placeholder_bundle()
        with self.assertRaisesRegex(ValidationError, "primary bundle parent"):
            replace(
                bundle,
                authoritative_evidence_hashes=(
                    *bundle.authoritative_evidence_hashes,
                    bundle.claim_graph_hash,
                ),
            )

    def test_exact_paper_inventory_excludes_unconsumed_ablation_diagnostic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            source = _put_json(
                registry,
                {"result": "bounded-fixture"},
                "aggregate_experiment_result",
                Role.STATISTICIAN,
            )
            evidence = _put_json(
                registry,
                {"evidence_kind": EvidenceKind.RESULT.value},
                f"claim_evidence.{EvidenceKind.RESULT.value}",
                Role.EVIDENCE_CURATOR,
                (source.sha256,),
            )
            support = _put_json(
                registry,
                {"support": "diagnostic-only"},
                f"claim_support_receipt.{EvidenceKind.RESULT.value}",
                Role.CLAIM_VERIFIER,
                (evidence.sha256,),
            )
            verification = _put_json(
                registry,
                {"verification": "diagnostic-only"},
                (
                    "claim_evidence_verification_receipt."
                    f"{EvidenceKind.RESULT.value}"
                ),
                Role.CLAIM_VERIFIER,
                (evidence.sha256, support.sha256),
            )
            graph = _put_json(
                registry,
                {
                    "graph": {
                        "decisions": [
                            {
                                "claim_id": "paper-inventory-claim",
                                "evidence_receipt_hashes": [
                                    verification.sha256
                                ],
                            }
                        ]
                    }
                },
                "claim_evidence_graph",
                Role.CLAIM_VERIFIER,
                (evidence.sha256, support.sha256, verification.sha256),
            )
            semantics = _put_json(
                registry,
                {"scope": "NON_EVIDENTIARY_FIXTURE"},
                "claim_semantics_receipt",
                Role.CLAIM_VERIFIER,
                (graph.sha256,),
            )
            ablation_diagnostic = _put_json(
                registry,
                {"diagnostic": "not consumed by this claim"},
                "ablation_validation",
                Role.SCIENTIFIC_REVIEWER,
            )
            requirements = ClaimPaperRequirements(
                claim_id="paper-inventory-claim",
                claim_type=ClaimType.QUALITATIVE,
                evidence_sources=(
                    EvidenceSourceBinding(
                        EvidenceKind.RESULT,
                        evidence.sha256,
                        (source.sha256,),
                    ),
                ),
                required_metric_ids=(),
                required_reference_artifact_hashes=(),
                required_method_code_bindings=(),
                required_generated_assets=(),
            )
            claim = AuthoritativeClaim(
                claim_id="paper-inventory-claim",
                text="A bounded diagnostic result was retained.",
                expressed_strength=ClaimStrength.LIMITED,
                permitted_strength=ClaimStrength.LIMITED,
                evidence_hashes=(evidence.sha256,),
                claim_state_artifact_hash=digest(
                    "paper-inventory-claim-state"
                ),
                graph_decision_hash=digest(
                    "paper-inventory-graph-decision"
                ),
                claim_semantics_artifact_hash=semantics.sha256,
                producer_role=Role.EXPERIMENT_RUNNER,
                claim_semantics_evidence_scope=(
                    ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE
                ),
                confidence=0.5,
                verification_method="diagnostic graph replay",
                scientific_writer_eligible=False,
                evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
                claim_type=ClaimType.QUALITATIVE,
                scope="Synthetic fixture only.",
                requirements=requirements,
            )
            required = _required_paper_evidence_hashes(
                registry,
                claim_graph_hash=graph.sha256,
                claims=(claim,),
                metrics=(),
                method_code_bindings=(),
            )
            self.assertEqual(
                required,
                frozenset(
                    {
                        evidence.sha256,
                        support.sha256,
                        verification.sha256,
                        semantics.sha256,
                        source.sha256,
                    }
                ),
            )
            self.assertNotIn(ablation_diagnostic.sha256, required)

    def test_shared_code_derives_every_exact_method_and_rejects_same_method_ambiguity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            code = registry.put_bytes(
                b"def candidate_or_baseline(mode, value): return mode, value\n",
                logical_type="experiment_code",
                origin="paper shared-code boundary test",
                creator_role=Role.IMPLEMENTER,
                mime_type="text/x-python",
                validation_result="PASS",
                frozen=True,
            )
            configuration = _put_json(
                registry,
                {"configuration": "shared-code-boundary"},
                "experiment_configuration",
                Role.PROTOCOL_DESIGNER,
                (code.sha256,),
            )
            candidate_definition = _put_json(
                registry,
                {"method_id": "shared-code-candidate"},
                "method_definition",
                Role.HYPOTHESIS_DESIGNER,
                (configuration.sha256,),
            )
            baseline_definition = _put_json(
                registry,
                {"method_id": "shared-code-baseline"},
                "baseline_method_definition",
                Role.PROTOCOL_DESIGNER,
                (configuration.sha256,),
            )
            timestamp = "2026-08-30T12:00:00Z"
            code_version = f"sha256:{'c' * 64}"
            candidate_method = StateMethod(
                object_id="shared-code-candidate",
                producer=Role.HYPOTHESIS_DESIGNER,
                status=RecordStatus.FROZEN,
                created_at=timestamp,
                code_version=code_version,
                name="Shared-code candidate",
                description="Candidate branch of one exact executable.",
                assumptions=("The mode is frozen.",),
                component_ids=("shared-code-candidate-component",),
                authority_artifact_hashes=(candidate_definition.sha256,),
            )
            baseline_method = StateMethod(
                object_id="shared-code-baseline",
                producer=Role.PROTOCOL_DESIGNER,
                status=RecordStatus.FROZEN,
                created_at=timestamp,
                code_version=code_version,
                name="Shared-code baseline",
                description="Baseline branch of one exact executable.",
                assumptions=("The mode is frozen.",),
                component_ids=("shared-code-baseline-component",),
                authority_artifact_hashes=(baseline_definition.sha256,),
            )

            def implementation(
                object_id: str,
                method: StateMethod,
            ) -> StateImplementation:
                return StateImplementation(
                    object_id=object_id,
                    producer=Role.IMPLEMENTER,
                    status=RecordStatus.FROZEN,
                    created_at=timestamp,
                    code_version=code_version,
                    parents=(
                        ObjectReference(
                            "Method",
                            method.object_id,
                            method.content_hash,
                            "implements",
                            True,
                        ),
                    ),
                    method_id=method.object_id,
                    code_artifact_hashes=(code.sha256,),
                    code_revision=code_version,
                    configuration_artifact_hashes=(configuration.sha256,),
                    authority_artifact_hashes=(
                        code.sha256,
                        configuration.sha256,
                    ),
                )

            candidate_implementation = implementation(
                "shared-code-candidate-implementation",
                candidate_method,
            )
            baseline_implementation = implementation(
                "shared-code-baseline-implementation",
                baseline_method,
            )

            def authority_binding(
                research_object: StateMethod | StateImplementation,
                label: str,
                authorities: tuple,
            ) -> ResearchStateAuthorityBinding:
                return ResearchStateAuthorityBinding(
                    research_object=research_object,
                    artifact_sha256=digest(f"{label}-state-artifact"),
                    artifact_record_hash=digest(f"{label}-state-record"),
                    materialization_event_id=f"{label}-materialized",
                    materialization_event_hash=digest(f"{label}-state-event"),
                    materialization_event_index=len(label),
                    authority_artifact_hashes=tuple(
                        item.sha256 for item in authorities
                    ),
                    authority_artifact_record_hashes=tuple(
                        str(item.record_hash) for item in authorities
                    ),
                    authority_logical_types=tuple(
                        item.logical_type for item in authorities
                    ),
                    authority_creator_roles=tuple(
                        item.creator_role for item in authorities
                    ),
                    scientific_evidence_eligible=False,
                    claim_semantics=None,
                )

            candidate_method_binding = authority_binding(
                candidate_method,
                "shared-code-candidate-method",
                (candidate_definition,),
            )
            baseline_method_binding = authority_binding(
                baseline_method,
                "shared-code-baseline-method",
                (baseline_definition,),
            )
            candidate_implementation_binding = authority_binding(
                candidate_implementation,
                "shared-code-candidate-implementation",
                (code, configuration),
            )
            baseline_implementation_binding = authority_binding(
                baseline_implementation,
                "shared-code-baseline-implementation",
                (code, configuration),
            )

            def snapshot(
                *entries: ResearchStateAuthorityBinding,
            ) -> ResearchStateAuthoritySnapshot:
                return ResearchStateAuthoritySnapshot(
                    run_id="paper-shared-code-boundary",
                    snapshot_artifact_sha256=digest(
                        "shared-code-state-snapshot"
                    ),
                    snapshot_artifact_record_hash=digest(
                        "shared-code-state-snapshot-record"
                    ),
                    ledger_head_hash=digest("shared-code-ledger-head"),
                    ledger_event_count=1,
                    code_version=code_version,
                    configuration_hash=digest("shared-code-configuration"),
                    entries=tuple(entries),
                )

            exact_state = snapshot(
                candidate_method_binding,
                baseline_method_binding,
                candidate_implementation_binding,
                baseline_implementation_binding,
            )
            bindings = _derive_method_bindings(
                registry,
                (code.sha256,),
                exact_state,
            )
            self.assertEqual(len(bindings), 2)
            self.assertEqual(
                {item.method_artifact_hash for item in bindings},
                {candidate_definition.sha256, baseline_definition.sha256},
            )
            self.assertEqual(
                {item.implementation_state_artifact_hash for item in bindings},
                {
                    candidate_implementation_binding.artifact_sha256,
                    baseline_implementation_binding.artifact_sha256,
                },
            )

            duplicate_candidate = implementation(
                "shared-code-candidate-implementation-duplicate",
                candidate_method,
            )
            duplicate_binding = authority_binding(
                duplicate_candidate,
                "shared-code-candidate-implementation-duplicate",
                (code, configuration),
            )
            with self.assertRaisesRegex(
                ValidationError,
                "ambiguous same-method Implementation authority",
            ):
                _derive_method_bindings(
                    registry,
                    (code.sha256,),
                    snapshot(
                        candidate_method_binding,
                        baseline_method_binding,
                        candidate_implementation_binding,
                        baseline_implementation_binding,
                        duplicate_binding,
                    ),
                )

    def test_unmocked_fixture_reference_replay_remains_non_evidentiary(
        self,
    ) -> None:
        """Exercise the real paper citation adapter without promoting a fixture."""

        with tempfile.TemporaryDirectory() as root:
            run_id = "paper-reference-boundary"
            registry = ArtifactRegistry(root, f"runs/{run_id}/registry")
            ledger = EventLedger(root, f"runs/{run_id}/events.jsonl")
            literature = _run_literature(
                registry,
                timestamp="2026-08-29T12:00:00Z",
            )
            ledger.record(
                run_id=run_id,
                actor_role=Role.EVIDENCE_CURATOR,
                state_before=MacroState.GROUND,
                requested_state_after=MacroState.GROUND,
                artifact_hashes=literature.artifact_hashes,
                code_version=f"sha256:{'a' * 64}",
                configuration_hash="b" * 64,
                dataset_identifiers=("paper-reference-boundary",),
                random_seeds=(),
                evaluator_outputs=(),
                reason="register the non-evidentiary literature boundary",
                event_type="CHECKPOINT",
                metadata={
                    "phase": "CONTROLLED_LITERATURE",
                    "research_os_materialization": (
                        "REGISTERED_BEFORE_CONSUMPTION"
                    ),
                    "scientific_evidence": False,
                },
            )
            reference_hash = literature.reference_artifact.sha256
            reference_value = safe_json_loads(
                registry.get_bytes(reference_hash)
            )
            selected_record = next(
                acquisition.record
                for acquisition in literature.acquisitions
                if acquisition.record is not None
                and acquisition.record.request_id
                == reference_value["verification"]["retrieval_request_id"]
            )
            citation_node = next(
                node
                for node in literature.citation_graph.nodes
                if node.source is selected_record.source
                and node.source_record_id == selected_record.source_record_id
            )
            claim_id = "paper-reference-boundary-claim"
            claim_text = reference_value["claim_text"]
            claim_scope = "Only the deterministic controlled-literature fixture."
            transport_placeholder = registry.put_json(
                {
                    "external_validation": "UNTESTED",
                    "scientific_authority": False,
                },
                logical_type="audited_transport_execution_authority",
                origin="paper-authority-test",
                creator_role=Role.EVIDENCE_CURATOR,
                schema_version="audited-transport-authority/v1",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            semantic_placeholder = _put_json(
                registry,
                {
                    "semantic_authority": "UNAVAILABLE",
                    "scientific_authority": False,
                },
                "unavailable_reference_support_judgment",
                Role.SCIENTIFIC_REVIEWER,
            )
            ordered_sources = (
                reference_hash,
                literature.citation_graph_artifact.sha256,
                transport_placeholder.sha256,
            )

            def source_projection(
                label: str,
                *,
                claim: str = claim_id,
                sources: tuple[str, ...] = ordered_sources,
            ):
                return register_scientific_claim_evidence_projection(
                    registry,
                    evidence_id=f"paper-reference-{label}",
                    evidence_kind=EvidenceKind.SOURCE_CITATION,
                    claim_id=claim,
                    claim_text=claim_text,
                    producer_role=Role.PROBLEM_INVESTIGATOR,
                    source_artifact_hashes=sources,
                )

            source = source_projection("exact")
            claim_graph = _put_json(
                registry,
                {"graph": {"claims": [], "decisions": [], "evidence": []}},
                "claim_evidence_graph",
                Role.CLAIM_VERIFIER,
            )
            semantics_proposal = _put_json(
                registry,
                {
                    "claim_id": claim_id,
                    "claim_text": claim_text,
                    "evidence_scope": "NON_EVIDENTIARY_FIXTURE",
                },
                "claim_semantics_proposal",
                Role.CLAIM_VERIFIER,
                (claim_graph.sha256,),
            )

            def replay(
                *,
                replay_ledger: EventLedger = ledger,
                replay_run_id: str = run_id,
                replay_claim_id: str = claim_id,
                source_hash: str = source.sha256,
            ):
                return _require_scientific_reference_source_authority(
                    registry,
                    replay_ledger,
                    run_id=replay_run_id,
                    claim_id=replay_claim_id,
                    claim_text=claim_text,
                    claim_scope=claim_scope,
                    claim_graph_artifact_hash=claim_graph.sha256,
                    claim_semantics_proposal_artifact_hash=(
                        semantics_proposal.sha256
                    ),
                    reference_support_semantic_judgment_artifact_hash=(
                        semantic_placeholder.sha256
                    ),
                    source_citation_evidence_artifact_hash=source_hash,
                    reference_artifact_hash=reference_hash,
                )

            with self.assertRaises(ValidationError):
                replay()
            wrong_ledger = EventLedger(
                root,
                "runs/paper-reference-wrong-ledger/events.jsonl",
            )
            for label, call in (
                (
                    "wrong-ledger",
                    lambda: replay(replay_ledger=wrong_ledger),
                ),
                (
                    "wrong-run",
                    lambda: replay(replay_run_id="paper-reference-other-run"),
                ),
                (
                    "wrong-claim",
                    lambda: replay(
                        replay_claim_id="paper-reference-other-claim"
                    ),
                ),
                (
                    "wrong-parent-order",
                    lambda: replay(
                        source_hash=source_projection(
                            "reordered",
                            sources=(
                                reference_hash,
                                transport_placeholder.sha256,
                                literature.citation_graph_artifact.sha256,
                            ),
                        ).sha256
                    ),
                ),
            ):
                with self.subTest(case=label), self.assertRaises(ValidationError):
                    call()
            with self.assertRaisesRegex(
                ValidationError,
                "reordered or substituted typed sources",
            ):
                require_audited_claim_bound_reference_authority(
                    registry,
                    ledger,
                    expected_run_id=run_id,
                    expected_claim_id=claim_id,
                    expected_citation_node_id=(
                        f"citation-node:{digest('wrong-reference-node')}"
                    ),
                    source_citation_evidence_artifact_sha256=source.sha256,
                    claim_semantics_proposal_artifact_sha256=(
                        semantics_proposal.sha256
                    ),
                    reference_support_semantic_judgment_artifact_sha256=(
                        semantic_placeholder.sha256
                    ),
                )

            source_record = registry.get_metadata(source.sha256)
            source_value = safe_json_loads(registry.get_bytes(source.sha256))
            self.assertEqual(source_record.parent_artifacts, ordered_sources)
            self.assertEqual(
                tuple(source_value["source_artifact_hashes"]),
                ordered_sources,
            )
            self.assertEqual(
                source_value["source_artifact_record_hashes"],
                [
                    str(registry.get_metadata(item).record_hash)
                    for item in ordered_sources
                ],
            )
            fixture_claim = AuthoritativeClaim(
                claim_id=claim_id,
                text=claim_text,
                expressed_strength=ClaimStrength.LIMITED,
                permitted_strength=ClaimStrength.LIMITED,
                evidence_hashes=(source.sha256,),
                claim_state_artifact_hash=digest("fixture-claim-state"),
                graph_decision_hash=digest("fixture-claim-decision"),
                claim_semantics_artifact_hash=digest(
                    "fixture-claim-semantics"
                ),
                producer_role=Role.PROBLEM_INVESTIGATOR,
                claim_semantics_evidence_scope=(
                    ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE
                ),
                confidence=0.5,
                verification_method="non-evidentiary fixture replay",
                scientific_writer_eligible=False,
                evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
                claim_type=ClaimType.QUALITATIVE,
                scope=claim_scope,
            )
            projected_use = ReferenceUse(
                citation_id=reference_value["citation_id"],
                reference_artifact_hash=reference_hash,
                verification_depth=ReferenceDepth.LEVEL_5,
                supported_claim_ids=(claim_id,),
                source_citation_evidence_artifact_hash=source.sha256,
                citation_node_id=citation_node.node_id,
                passage_sha256=digest("fixture-passage"),
                passage_locator_sha256=digest("fixture-locator"),
                context_sha256=digest("fixture-context"),
                semantic_judgment_artifact_hash=semantic_placeholder.sha256,
            )
            with self.assertRaisesRegex(
                ValidationError,
                "non-scientific reference cannot present",
            ):
                _verify_reference_use(
                    registry,
                    projected_use,
                    {claim_id: fixture_claim},
                    set(literature.artifact_hashes) | {source.sha256},
                    ledger=ledger,
                    run_id=run_id,
                    claim_graph_artifact_hash=claim_graph.sha256,
                )
            forbidden_types = {
                "authoritative_research_bundle",
                "paper_candidate",
                "paper_verification",
            }
            self.assertTrue(
                forbidden_types.isdisjoint(
                    {record.logical_type for record in registry.list_records()}
                )
            )

    def test_writer_view_and_spliced_reference_projection_cannot_authorize_paper(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root, "runs/reference-boundary/events.jsonl")
            claim_id = "claim-bound"
            claim_text = "The exact captured passage supports this bounded claim."
            claim_scope = "Only the retained population and method."
            graph_nodes = tuple(
                EvidenceNode(
                    evidence_id=f"writer-view-{kind.value.lower()}",
                    kind=kind,
                    artifact_hash=digest(f"writer-view-{kind.value}"),
                    description=f"Diagnostic {kind.value} projection only.",
                    verified=True,
                    frozen=True,
                    supports_claim=True,
                    contradicts_claim=False,
                    locally_verifiable=True,
                )
                for kind in sorted(
                    REQUIRED_EVIDENCE_KINDS,
                    key=lambda item: item.value,
                )
            )
            graph_claim = MaterialClaim(
                claim_id=claim_id,
                text=claim_text,
                evidence_links=tuple(
                    EvidenceLink(item.evidence_id, item.kind)
                    for item in graph_nodes
                ),
                producer_role=Role.PROBLEM_INVESTIGATOR,
                confirmatory=False,
                evidence_use=ClaimEvidenceUse.SCIENTIFIC,
            )

            def diagnostic_resolver(
                _claim: MaterialClaim,
                node: EvidenceNode,
            ) -> EvidenceVerificationReceipt:
                return EvidenceVerificationReceipt(
                    evidence_id=node.evidence_id,
                    evidence_kind=node.kind,
                    artifact_hash=node.artifact_hash,
                    content_sha256=node.artifact_hash,
                    registry_record_hash=digest(
                        f"writer-view-record-{node.evidence_id}"
                    ),
                    support_receipt_hash=digest(
                        f"writer-view-support-{node.evidence_id}"
                    ),
                    support_receipt_record_hash=digest(
                        f"writer-view-support-record-{node.evidence_id}"
                    ),
                    support_verifier_id="writer-view-verifier",
                    support_verifier_role=Role.CLAIM_VERIFIER,
                    resolver_id="writer-view-diagnostic-resolver",
                    validation_result="PASS",
                    frozen=True,
                    supports_claim=True,
                    contradicts_claim=False,
                    locally_verifiable=True,
                )

            diagnostic_graph = ClaimEvidenceGraph(
                evidence_resolver=diagnostic_resolver
            )
            for node in graph_nodes:
                diagnostic_graph.add_evidence(node)
            diagnostic_graph.add_claim(graph_claim)
            self.assertEqual(
                diagnostic_graph.verify_claim(
                    claim_id,
                    verifier_id="writer-view-verifier",
                ).decision,
                ClaimDecision.ELIGIBLE,
            )
            writer_projection = diagnostic_graph.writer_view()
            self.assertEqual(len(writer_projection), 1)
            self.assertEqual(writer_projection[0]["claim_id"], claim_id)
            self.assertEqual(writer_projection[0]["text"], claim_text)
            captured = _put_json(
                registry,
                {"passage": claim_text},
                "captured_reference_source",
                Role.EVIDENCE_CURATOR,
            )
            semantic = _put_json(
                registry,
                {"claim_text": claim_text, "decision": "SUPPORTS"},
                "semantic_reference_assessment",
                Role.CLAIM_VERIFIER,
                (captured.sha256,),
            )
            context = _put_json(
                registry,
                {"claim_text": claim_text, "decision": "NOT_CONTRADICTED"},
                "context_reference_assessment",
                Role.CLAIM_VERIFIER,
                (captured.sha256,),
            )
            parents = (captured.sha256, semantic.sha256, context.sha256)
            reference_record = _put_json(
                registry,
                {
                    "claim_text": claim_text,
                    "verification": {
                        "failure_reasons": [],
                        "level": 5,
                        "locator": {"passage_id": "passage-bound"},
                        "metadata_mismatches": [],
                        "parent_artifact_hashes": list(parents),
                    },
                },
                "reference_verification",
                Role.CLAIM_VERIFIER,
                parents,
            )
            graph_hash = digest("reference-claim-graph")
            proposal_hash = digest("reference-claim-proposal")
            source_hash = digest("reference-source-projection")
            citation_graph_hash = digest("reference-citation-graph")
            transport_hash = digest("reference-signed-transport")
            judgment_hash = digest("reference-semantic-judgment")
            judgment_evidence_hashes = tuple(
                sorted(
                    {
                        source_hash,
                        graph_hash,
                        reference_record.sha256,
                        citation_graph_hash,
                        transport_hash,
                    }
                )
            )
            judgment_context_hashes = (proposal_hash,)
            judgment_custody_hashes = tuple(
                digest(f"reference-custody-{index}") for index in range(7)
            )
            evidence_hashes = tuple(
                sorted(
                    {
                        proposal_hash,
                        source_hash,
                        judgment_hash,
                        *judgment_evidence_hashes,
                        *judgment_context_hashes,
                        *judgment_custody_hashes,
                    }
                )
            )
            authority = ReferenceAuthorityBinding(
                run_id="reference-boundary",
                claim_id=claim_id,
                claim_text=claim_text,
                claim_scope=claim_scope,
                claim_graph_artifact_hash=graph_hash,
                claim_semantics_proposal_artifact_hash=proposal_hash,
                source_citation_evidence_id="source-citation-bound",
                source_citation_evidence_artifact_hash=source_hash,
                source_citation_evidence_record_hash=digest("source-record"),
                citation_graph_artifact_hash=citation_graph_hash,
                citation_graph_record_hash=digest("citation-graph-record"),
                citation_node_id=f"citation-node:{digest('citation-node-bound')}",
                citation_node_record_sha256=digest("citation-node-record"),
                citation_id="citation-bound",
                reference_artifact_hash=reference_record.sha256,
                reference_record_hash=str(reference_record.record_hash),
                passage_sha256=digest("passage-bound"),
                passage_locator_sha256=digest("passage-locator-bound"),
                context_sha256=digest("passage-context-bound"),
                transport_execution_authority_artifact_hash=transport_hash,
                semantic_judgment_artifact_hash=judgment_hash,
                semantic_judgment_record_hash=digest("judgment-record"),
                semantic_judgment_evidence_artifact_hashes=(
                    judgment_evidence_hashes
                ),
                semantic_judgment_context_artifact_hashes=(
                    judgment_context_hashes
                ),
                semantic_judgment_custody_artifact_hashes=(
                    judgment_custody_hashes
                ),
                semantic_projection_sha256=digest("semantic-projection"),
                permitted_strength=ClaimStrength.QUALIFIED,
                evidence_artifact_hashes=evidence_hashes,
                evidence_record_hashes=tuple(
                    digest(f"record:{item}") for item in evidence_hashes
                ),
            )
            requirements = ClaimPaperRequirements(
                claim_id=claim_id,
                claim_type=ClaimType.QUALITATIVE,
                evidence_sources=(
                    EvidenceSourceBinding(
                        EvidenceKind.SOURCE_CITATION,
                        source_hash,
                        (
                            reference_record.sha256,
                            citation_graph_hash,
                            transport_hash,
                        ),
                    ),
                ),
                required_metric_ids=(),
                required_reference_artifact_hashes=(reference_record.sha256,),
                required_method_code_bindings=(),
                required_generated_assets=(),
                required_reference_authorities=(authority,),
            )
            claim = AuthoritativeClaim(
                claim_id=claim_id,
                text=claim_text,
                expressed_strength=ClaimStrength.QUALIFIED,
                permitted_strength=ClaimStrength.QUALIFIED,
                evidence_hashes=tuple(writer_projection[0]["evidence_hashes"]),
                claim_state_artifact_hash=digest("reference-claim-state"),
                graph_decision_hash=str(
                    writer_projection[0]["verifier_decision_hash"]
                ),
                claim_semantics_artifact_hash=digest("reference-semantics"),
                producer_role=Role.PROBLEM_INVESTIGATOR,
                claim_semantics_evidence_scope=(
                    ClaimSemanticsEvidenceScope.SCIENTIFIC_EVIDENCE
                ),
                confidence=0.8,
                verification_method="audited claim-bound reference replay",
                scientific_writer_eligible=True,
                evidence_use=ClaimEvidenceUse.SCIENTIFIC,
                claim_type=ClaimType.QUALITATIVE,
                scope=claim_scope,
                requirements=requirements,
            )
            with self.assertRaisesRegex(ValidationError, "incomplete or substituted"):
                replace(
                    claim,
                    requirements=replace(
                        requirements,
                        required_reference_authorities=(),
                    ),
                )
            with self.assertRaisesRegex(
                ValidationError,
                "non-scientific claim cannot retain",
            ):
                replace(claim, scientific_writer_eligible=False)
            valid_use = ReferenceUse(
                "citation-bound",
                reference_record.sha256,
                ReferenceDepth.LEVEL_5,
                (claim_id,),
                source_citation_evidence_artifact_hash=source_hash,
                citation_node_id=authority.citation_node_id,
                passage_sha256=authority.passage_sha256,
                passage_locator_sha256=authority.passage_locator_sha256,
                context_sha256=authority.context_sha256,
                semantic_judgment_artifact_hash=judgment_hash,
            )
            with patch(
                "scientist_one.paper_pipeline."
                "_require_scientific_reference_source_authority",
                return_value=authority,
            ) as mocked_reference, self.assertRaises(ValidationError):
                _verify_reference_use(
                    registry,
                    valid_use,
                    {claim_id: claim},
                    set(evidence_hashes),
                    ledger=ledger,
                    run_id="reference-boundary",
                    claim_graph_artifact_hash=graph_hash,
                )
            mocked_reference.assert_not_called()
            limited_authority = replace(
                authority,
                permitted_strength=ClaimStrength.LIMITED,
            )
            with self.assertRaisesRegex(
                ValidationError,
                "reference authorities are incomplete or substituted",
            ):
                replace(
                    claim,
                    requirements=replace(
                        requirements,
                        required_reference_authorities=(limited_authority,),
                    ),
                )


class VenuePolicyBoundaryTests(unittest.TestCase):
    def test_only_exact_source_owned_profiles_can_be_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            profile = default_venue_profiles()[0]
            record = register_approved_venue_profile(registry, profile)
            self.assertEqual(
                require_approved_venue_profile(
                    registry,
                    record.sha256,
                    expected_profile_id=profile.profile_id,
                ),
                profile,
            )
            for forged in (
                replace(profile, minimum_dimension_score=0.0),
                replace(profile, required_sections=("methods", "results")),
                replace(profile, artifact_requirements=("code",)),
            ):
                with self.subTest(profile=forged), self.assertRaises(ValidationError):
                    register_approved_venue_profile(registry, forged)

            payload = safe_json_loads(registry.get_bytes(record.sha256))
            payload["classification_policy"]["unresolved_authority"] = (
                VenueFit.UNCERTAIN.value
            )
            wrong_role = _put_json(
                registry,
                payload,
                "approved_venue_profile",
                Role.CLAIM_VERIFIER,
            )
            with self.assertRaises(ValidationError):
                require_approved_venue_profile(registry, wrong_role.sha256)

    def test_caller_scores_boolean_and_rationale_are_never_fit_authority(self) -> None:
        profile = default_venue_profiles()[0]
        verification = PaperVerification(True, (), (), ())
        result = assess_venue(
            profile,
            verification,
            {name: 1.0 for name in READINESS_DIMENSIONS},
            external_validation_complete=True,
            rationale="Guaranteed acceptance at the strongest venue.",
        )
        self.assertEqual(result.classification, VenueFit.NOT_READY)
        self.assertIn(HardBlocker.VENUE_REQUIREMENTS_UNRESOLVED, result.hard_blockers)
        self.assertNotIn("Guaranteed acceptance", result.rationale)
        self.assertIn("not acceptance authority", result.rationale)

    def test_semantic_consumer_rejects_unbound_run_and_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            wrong_ledger = EventLedger(root, "runs/wrong-ledger/events.jsonl")
            with self.assertRaises((ArtifactError, ValidationError)):
                _require_live_venue_semantic_judgment(
                    registry,
                    wrong_ledger,
                    run_id="wrong-venue-run",
                    receipt_artifact_hash=digest("missing-venue-judgment"),
                    subject_kind=JudgmentSubjectKind.VENUE_DIMENSION,
                    subject_id=READINESS_DIMENSIONS[0],
                    outcome="SCORE:1.0",
                    evidence_hashes=(digest("venue-evidence"),),
                    context_hashes=(digest("venue-context"),),
                )

    def test_conflicting_live_venue_judgments_are_rejected_contract_only(self) -> None:
        """A mocked live boundary exercises slot ambiguity, not real validation."""

        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root, "runs/venue-slot/events.jsonl")
            evidence = _put_json(
                registry,
                {"evidence": "exact venue input"},
                "venue_slot_evidence",
                Role.EVIDENCE_CURATOR,
            )
            context = _put_json(
                registry,
                {"context": "exact venue branch"},
                "venue_slot_context",
                Role.SCIENTIFIC_REVIEWER,
            )

            def register_judgment(label: str, outcome: str):
                custody = tuple(
                    _put_json(
                        registry,
                        {"custody": f"{label}-{index}"},
                        f"venue_slot_custody_{label}_{index}",
                        Role.SCIENTIFIC_REVIEWER,
                    )
                    for index in range(7)
                )
                receipt = SemanticJudgmentReceipt(
                    judgment_id=f"venue-slot-{label}",
                    subject_kind=JudgmentSubjectKind.VENUE_DIMENSION,
                    subject_id=READINESS_DIMENSIONS[0],
                    outcome=outcome,
                    evidence_hashes=(evidence.sha256,),
                    context_hashes=(context.sha256,),
                    instructions_artifact_hash=custody[0].sha256,
                    input_artifact_hash=custody[1].sha256,
                    output_schema_artifact_hash=custody[2].sha256,
                    invocation_artifact_hash=custody[3].sha256,
                    request_intent_artifact_hash=custody[4].sha256,
                    provider_response_artifact_hash=custody[5].sha256,
                    model_output_artifact_hash=custody[6].sha256,
                    invocation_id=f"venue-slot-invocation-{label}",
                    provider_id="contract-provider",
                    provider_version="1.0",
                    model="contract-model",
                    model_version="1.0",
                    prompt_template_id="venue-slot-contract",
                    prompt_template_version="1.0",
                    prompt_template_hash=digest("venue-slot-template"),
                    structured_output_sha256=digest(
                        f"venue-slot-output-{label}"
                    ),
                    reviewer_id="venue-slot-reviewer",
                    reviewer_role=Role.SCIENTIFIC_REVIEWER,
                    governing_rule="One outcome-independent judgment per venue slot.",
                    rationale="Contract-only semantic custody fixture.",
                )
                return registry.put_json(
                    receipt.to_dict(),
                    logical_type="scientific_semantic_judgment_receipt",
                    origin=(
                        "content-bound scientific review of a captured advisory "
                        "model judgment"
                    ),
                    creator_role=Role.SCIENTIFIC_REVIEWER,
                    creation_command=(
                        "scientist-one",
                        "record-semantic-judgment",
                    ),
                    parent_artifacts=(
                        *receipt.evidence_hashes,
                        *receipt.context_hashes,
                        *receipt.custody_artifact_hashes,
                    ),
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                )

            first = register_judgment("first", "SCORE:0.8")
            register_judgment("second", "SCORE:0.9")
            with patch(
                "scientist_one.paper_pipeline."
                "require_scientific_semantic_judgment_receipt"
            ), self.assertRaisesRegex(
                ValidationError,
                "conflicting live outcomes",
            ):
                _require_live_venue_semantic_judgment(
                    registry,
                    ledger,
                    run_id="venue-slot",
                    receipt_artifact_hash=first.sha256,
                    subject_kind=JudgmentSubjectKind.VENUE_DIMENSION,
                    subject_id=READINESS_DIMENSIONS[0],
                    outcome="SCORE:0.8",
                    evidence_hashes=(evidence.sha256,),
                    context_hashes=(context.sha256,),
                )


class ConfirmatoryFixtureBoundaryTests(unittest.TestCase):
    def test_simulated_fixture_cannot_mint_confirmatory_timeline_authority(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            code = registry.put_bytes(
                b"fixture",
                logical_type="experiment_code",
                origin="paper confirmatory boundary test",
                creator_role=Role.IMPLEMENTER,
                mime_type="text/plain",
                frozen=True,
            )
            artifacts = register_confirmatory_artifacts(
                registry,
                root,
                code_hash=code.sha256,
                run_label="paper-confirmatory-fixture-boundary",
            )
            custody = safe_json_loads(registry.get_bytes(artifacts.custody_hash))
            self.assertFalse(custody["confirmatory_claims_valid"])
            self.assertEqual(
                registry.get_metadata(
                    artifacts.timeline_receipt_hash
                ).logical_type,
                "non_evidentiary_confirmatory_timeline_fixture",
            )
            with self.assertRaises(ValidationError):
                require_confirmatory_timeline_receipt(
                    registry,
                    artifacts.ledger,
                    receipt_artifact_sha256=artifacts.timeline_receipt_hash,
                    run_id=artifacts.run_id,
                    study_id=f"{artifacts.run_id}-study-v1",
                    study_version=1,
                    protocol_artifact_sha256=artifacts.protocol_hash,
                    fresh_custody_receipt_sha256=(
                        artifacts.fresh_custody_hash
                    ),
                    custody_record_sha256=artifacts.custody_hash,
                    result_artifact_sha256=artifacts.result_hash,
                )


class HumanGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.fixture = authoritative_fixture(cls.temporary.name)
        bundle = cls.fixture.bundle
        candidate = cls.fixture.candidate
        cls.bundle_artifact = register_authoritative_research_bundle(
            cls.fixture.registry,
            cls.fixture.ledger,
            bundle,
            bundle_id=bundle_fixture_id(bundle),
        )
        cls.candidate_artifact = _put_json(
            cls.fixture.registry,
            {"candidate": _jsonable(candidate)},
            "paper_candidate",
            Role.PAPER_WRITER,
            (cls.bundle_artifact.sha256, cls.fixture.asset_hash),
        )
        assert bundle.run_id is not None
        cls.paper_verification = register_paper_verification(
            cls.fixture.registry,
            cls.fixture.ledger,
            candidate,
            bundle,
            run_id=bundle.run_id,
            candidate_artifact_hash=cls.candidate_artifact.sha256,
            bundle_artifact_hash=cls.bundle_artifact.sha256,
        )
        soundness_payload = safe_json_loads(
            cls.fixture.registry.get_bytes(cls.fixture.soundness_hash)
        )
        assert isinstance(soundness_payload, Mapping)
        assessment_payload = soundness_payload.get("assessment")
        assert isinstance(assessment_payload, Mapping)
        cls.soundness_assessment_id = assessment_payload["assessment_id"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_full_autonomous_never_bypasses_scientific_failure(self) -> None:
        policy = HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS)
        result = policy.evaluate(
            self.fixture.registry,
            HumanGate.NOVELTY,
            scientific_authority_hash=None,
            expected_object_id="novelty-register-fixture",
        )
        self.assertEqual(result.outcome, AuthorizationOutcome.BLOCKED_SCIENTIFICALLY)

    def test_owner_backed_paper_failure_materializes_mechanical_terminal(
        self,
    ) -> None:
        from scientist_one.terminal_outcomes import (
            PAPER_PUBLICATION_TERMINAL_MAPPING_ID,
            ResearchTerminalOutcome,
            ResearchTerminalRecord,
            TerminalAuthorityScope,
            derive_from_registered_paper_verification,
            load_terminal_outcome,
            materialize_terminal_outcome,
        )

        with tempfile.TemporaryDirectory() as root:
            shutil.copytree(
                self.fixture.registry.policy.root,
                Path(root),
                dirs_exist_ok=True,
            )
            registry = ArtifactRegistry(root, self.fixture.registry.base_path)
            ledger = EventLedger(root, self.fixture.ledger.relative_path)
            bundle = self.fixture.bundle
            assert bundle.run_id is not None
            assert bundle.research_state_code_version is not None
            last_event = ledger.events()[-1]
            repository = ResearchStateRepository(
                registry,
                ledger,
                run_id=bundle.run_id,
                code_version=bundle.research_state_code_version,
                configuration_hash=last_event.configuration_hash,
                state=last_event.state_after,
                creation_command=registry.get_metadata(
                    bundle.research_state_artifact_hashes[0]
                ).creation_command,
            )
            # The copied fixture already owns a canonical writer identity.
            # Check it before expensive paper replay; a terminal append is not
            # permission to introduce a different repository creation command.
            self.assertTrue(repository._preflight_repository_identity())
            derivation = derive_from_registered_paper_verification(
                repository,
                self.paper_verification.sha256,
                expected_candidate_id=self.fixture.candidate.candidate_id,
            )
            assert derivation is not None
            assert derivation.source_binding is not None
            self.assertIs(
                derivation.outcome,
                ResearchTerminalOutcome.NOT_PUBLISHABLE,
            )
            self.assertIs(
                derivation.authority_scope,
                TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL,
            )
            self.assertEqual(derivation.mapping_id, PAPER_PUBLICATION_TERMINAL_MAPPING_ID)
            self.assertIn(
                HardBlocker.FAILED_CLEAN_REPRODUCTION.value,
                derivation.source_statuses,
            )
            self.assertIn(
                HardBlocker.UNSUPPORTED_NOVELTY.value,
                derivation.source_statuses,
            )
            binding = derivation.source_binding
            record = ResearchTerminalRecord(
                record_id="terminal-owner-backed-paper-failure",
                run_id=bundle.run_id,
                phase=derivation.phase,
                outcome=derivation.outcome,
                reason=(
                    "Fresh paper-owner replay found a fixture-scoped publication "
                    "blocker."
                ),
                evidence_artifact_hashes=(
                    binding.required_evidence_artifact_hashes
                ),
                derivation=derivation,
                producer=Role.SCIENTIFIC_REVIEWER,
                source_object_id=binding.source_object_id,
                source_claim_ids=binding.source_claim_ids,
                uncertainty=1.0,
                created_at=self.paper_verification.created_at,
            )
            state_before = repository.state
            materialized = materialize_terminal_outcome(record, repository)
            self.assertEqual(repository.state, state_before)
            self.assertEqual(
                load_terminal_outcome(
                    registry,
                    materialized.terminal_artifact.sha256,
                    repository=repository,
                ),
                record,
            )

    def test_full_autonomous_cannot_attach_a_decision_to_failed_science(self) -> None:
        policy = HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS)
        with self.assertRaisesRegex(ValidationError, "failed scientific authority"):
            policy.evaluate(
                self.fixture.registry,
                HumanGate.SOUNDNESS_PROMOTION,
                scientific_authority_hash=self.fixture.soundness_hash,
                expected_object_id=self.soundness_assessment_id,
                autonomous_decision=autonomous_decision(
                    HumanGate.SOUNDNESS_PROMOTION,
                    self.fixture.soundness_hash,
                ),
            )

    def test_full_autonomous_cannot_mint_e4_or_release(self) -> None:
        policy = HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS)
        assert self.fixture.bundle.run_id is not None
        result = policy.evaluate(
            self.fixture.registry,
            HumanGate.FINAL_RELEASE,
            scientific_authority_hash=self.paper_verification.sha256,
            expected_object_id=self.fixture.candidate.candidate_id,
            ledger=self.fixture.ledger,
            expected_run_id=self.fixture.bundle.run_id,
        )
        self.assertEqual(result.outcome, AuthorizationOutcome.BLOCKED_SCIENTIFICALLY)
        self.assertIsNone(result.decision)

    def test_required_and_selective_profiles_remain_explicit(self) -> None:
        required = HumanGatePolicy(HumanGateProfile.HUMAN_GATES_REQUIRED)
        self.assertEqual(
            required.evaluate(
                self.fixture.registry,
                HumanGate.NOVELTY,
                scientific_authority_hash=None,
                expected_object_id="novelty-register-fixture",
            ).outcome,
            AuthorizationOutcome.BLOCKED_SCIENTIFICALLY,
        )
        selective = HumanGatePolicy(
            HumanGateProfile.HUMAN_GATES_SELECTIVE,
            (HumanGate.COMPUTE_ESCALATION,),
        )
        self.assertTrue(selective.requires_human(HumanGate.COMPUTE_ESCALATION))
        self.assertFalse(selective.requires_human(HumanGate.NOVELTY))

    def test_autonomous_progression_requires_a_structured_record(self) -> None:
        assert self.fixture.bundle.run_id is not None
        policy = HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS)
        for label, expected_candidate_id, expected_run_id, ledger in (
            (
                "candidate",
                "another-paper-candidate",
                self.fixture.bundle.run_id,
                self.fixture.ledger,
            ),
            (
                "run",
                self.fixture.candidate.candidate_id,
                "another-paper-run",
                self.fixture.ledger,
            ),
            (
                "ledger",
                self.fixture.candidate.candidate_id,
                self.fixture.bundle.run_id,
                EventLedger(
                    self.temporary.name,
                    "runs/wrong-paper-ledger/events.jsonl",
                ),
            ),
        ):
            with self.subTest(label=label), self.assertRaises(ValidationError):
                policy.evaluate(
                    self.fixture.registry,
                    HumanGate.FINAL_RELEASE,
                    scientific_authority_hash=self.paper_verification.sha256,
                    expected_object_id=expected_candidate_id,
                    ledger=ledger,
                    expected_run_id=expected_run_id,
                )


class SoundnessGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = authoritative_fixture(self.temporary.name)
        self.registry = self.fixture.registry
        self.base_evidence = self.registry.get_metadata(self.fixture.result_hash)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def dimension_receipts(
        self,
        overrides: dict[SoundnessDimension, DimensionStatus] | None = None,
    ) -> tuple[str, ...]:
        overrides = overrides or {}
        return tuple(
            register_soundness_dimension_receipt(
                self.registry,
                SoundnessDimensionEvidenceReceipt(
                    receipt_id=f"receipt-{dimension.value.lower().replace('_', '-')}",
                    dimension=dimension,
                    status=overrides.get(dimension, DimensionStatus.PASS),
                    evidence_hashes=(self.base_evidence.sha256,),
                    governing_rule="Evaluate the typed dimension from the registered fixture evidence.",
                    rationale="Focused fixture receipt for soundness-verdict derivation.",
                    reviewer_id="scientific-reviewer-fixture",
                ),
            ).sha256
            for dimension in SoundnessDimension
        )

    def challenger_reviews(
        self,
        findings: tuple[ChallengeFinding, ...] = (),
        execution_overrides: dict[
            ChallengeCategory, ChallengerExecutionStatus
        ]
        | None = None,
    ) -> tuple[str, ...]:
        execution_overrides = execution_overrides or {}
        finding_hashes: dict[ChallengeCategory, list[str]] = {
            category: [] for category in ChallengeCategory
        }
        for finding in findings:
            finding_hashes[finding.category].append(
                register_challenge_finding(self.registry, finding).sha256
            )
        return tuple(
            register_challenger_category_review(
                self.registry,
                ChallengerCategoryReview(
                    review_id=f"review-{category.value.lower().replace('_', '-')}",
                    category=category,
                    execution_status=execution_overrides.get(
                        category,
                        ChallengerExecutionStatus.EXECUTED,
                    ),
                    target_claim_ids=("claim-main",),
                    evidence_hashes=(self.base_evidence.sha256,),
                    finding_artifact_hashes=tuple(finding_hashes[category]),
                    attack=f"Execute the typed {category.value} Challenger check.",
                    conclusion="The check completed with the separately linked findings.",
                    deterministic=True,
                ),
            ).sha256
            for category in ChallengeCategory
        )

    def assessment(
        self,
        assessment_id: str,
        *,
        dimension_overrides: dict[SoundnessDimension, DimensionStatus] | None = None,
        challenge_overrides: dict[
            ChallengeCategory, ChallengerExecutionStatus
        ]
        | None = None,
        findings: tuple[ChallengeFinding, ...] = (),
        reason: str = "Registry-resolved focused soundness assessment.",
    ) -> SoundnessAssessment:
        return assess_soundness(
            self.registry,
            assessment_id,
            self.dimension_receipts(dimension_overrides),
            self.challenger_reviews(findings, challenge_overrides),
            reason=reason,
        )

    def legacy_unresolved_blocking_challenge_rejects_direction(self) -> None:
        finding = ChallengeFinding(
            "challenge-leak",
            ChallengeCategory.LEAKAGE,
            ChallengeSeverity.BLOCKING,
            ChallengeStatus.UNRESOLVED,
            ("claim-main",),
            (self.base_evidence.sha256,),
            "The test outcome is available to the solver.",
            deterministic=True,
        )
        result = self.assessment(
            "soundness-blocked",
            findings=(finding,),
            reason="Blocking leakage.",
        )
        self.assertEqual(result.verdict, SoundnessVerdict.REJECT_RESEARCH_DIRECTION)

    def legacy_fail_untested_major_and_clean_have_distinct_verdicts(self) -> None:
        self.assertEqual(
            self.assessment(
                "soundness-fail",
                dimension_overrides={
                    SoundnessDimension.STATISTICS: DimensionStatus.FAIL
                },
                reason="Invalid test.",
            ).verdict,
            SoundnessVerdict.MAJOR_REVISION,
        )
        self.assertEqual(
            self.assessment(
                "soundness-untested",
                dimension_overrides={
                    SoundnessDimension.GENERALIZATION: DimensionStatus.UNTESTED
                },
                reason="External data absent.",
            ).verdict,
            SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED,
        )
        major = ChallengeFinding(
            "challenge-seed",
            ChallengeCategory.SEED_DEPENDENCE,
            ChallengeSeverity.MAJOR,
            ChallengeStatus.UNRESOLVED,
            ("claim-main",),
            (self.base_evidence.sha256,),
            "The effect may depend on one seed.",
        )
        self.assertEqual(
            self.assessment(
                "soundness-major",
                findings=(major,),
                reason="Major caveat.",
            ).verdict,
            SoundnessVerdict.CONDITIONAL_PASS,
        )
        self.assertEqual(
            self.assessment(
                "soundness-pass",
                reason="All dimensions passed.",
            ).verdict,
            SoundnessVerdict.PASS,
        )

    def legacy_inconsistent_manual_soundness_pass_fails_closed(self) -> None:
        valid = self.assessment("soundness-valid")
        values = tuple(
            (
                item,
                DimensionStatus.FAIL
                if item is SoundnessDimension.NOVELTY
                else DimensionStatus.PASS,
            )
            for item in SoundnessDimension
        )
        with self.assertRaises(ValidationError):
            replace(
                valid,
                assessment_id="forged-pass",
                dimensions=values,
                verdict=SoundnessVerdict.PASS,
                reason="Forged pass.",
            )

    def legacy_missing_or_sha_shaped_dimension_authority_fails_closed(self) -> None:
        reviews = self.challenger_reviews()
        with self.assertRaises(ValidationError):
            assess_soundness(
                self.registry,
                "soundness-placeholder",
                tuple(digest(f"placeholder-{item.value}") for item in SoundnessDimension),
                reviews,
                reason="SHA-shaped placeholders are not evidence receipts.",
            )
        with self.assertRaises(ValidationError):
            assess_soundness(
                self.registry,
                "soundness-caller-pass-map",
                dimensions(),
                reviews,
                reason="Caller PASS mappings no longer carry authority.",
            )

    def legacy_wrong_role_dimension_receipt_is_not_authority(self) -> None:
        receipt = SoundnessDimensionEvidenceReceipt(
            receipt_id="wrong-role-question-receipt",
            dimension=SoundnessDimension.QUESTION_VALIDITY,
            status=DimensionStatus.PASS,
            evidence_hashes=(self.base_evidence.sha256,),
            governing_rule="Question validity requires registered evidence.",
            rationale="An orchestrator cannot self-assign scientific-review authority.",
            reviewer_id="wrong-role-reviewer",
        )
        wrong_role = self.registry.put_json(
            receipt.to_dict(),
            logical_type="soundness_dimension_evidence_receipt",
            origin="registry-bound per-dimension scientific soundness review",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "record-soundness-dimension"),
            parent_artifacts=receipt.evidence_hashes,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        receipts = list(self.dimension_receipts())
        receipts[0] = wrong_role.sha256
        with self.assertRaises(ValidationError):
            assess_soundness(
                self.registry,
                "soundness-wrong-review-role",
                tuple(receipts),
                self.challenger_reviews(),
                reason="Wrong-role receipts must not grant PASS authority.",
            )

    def legacy_challenger_checklist_must_cover_every_exact_category(self) -> None:
        with self.assertRaises(ValidationError):
            assess_soundness(
                self.registry,
                "soundness-missing-challenge-category",
                self.dimension_receipts(),
                self.challenger_reviews()[:-1],
                reason="An omitted attack category must fail closed.",
            )
        result = self.assessment(
            "soundness-untested-challenge",
            challenge_overrides={
                ChallengeCategory.REPRODUCTION: ChallengerExecutionStatus.UNTESTED
            },
        )
        self.assertEqual(result.verdict, SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED)

    def legacy_finding_must_be_content_bound_to_matching_category_and_evidence(self) -> None:
        finding = ChallengeFinding(
            "challenge-bound-leakage",
            ChallengeCategory.LEAKAGE,
            ChallengeSeverity.MAJOR,
            ChallengeStatus.UNRESOLVED,
            ("claim-main",),
            (self.base_evidence.sha256,),
            "Attempt to expose held-out labels.",
        )
        finding_artifact = register_challenge_finding(self.registry, finding)
        with self.assertRaises(ValidationError):
            register_challenger_category_review(
                self.registry,
                ChallengerCategoryReview(
                    review_id="review-wrong-category",
                    category=ChallengeCategory.STATISTICS,
                    execution_status=ChallengerExecutionStatus.EXECUTED,
                    target_claim_ids=("claim-main",),
                    evidence_hashes=(self.base_evidence.sha256,),
                    finding_artifact_hashes=(finding_artifact.sha256,),
                    attack="Attempt to splice a leakage finding into statistics review.",
                    conclusion="The category binding must reject this splice.",
                ),
            )
        spliced_review = ChallengerCategoryReview(
            review_id="review-manually-spliced-category",
            category=ChallengeCategory.STATISTICS,
            execution_status=ChallengerExecutionStatus.EXECUTED,
            target_claim_ids=("claim-main",),
            evidence_hashes=(self.base_evidence.sha256,),
            finding_artifact_hashes=(finding_artifact.sha256,),
            attack="Attempt to splice a leakage finding through raw registry publication.",
            conclusion="The assessment boundary must revalidate the finding category.",
        )
        spliced_artifact = self.registry.put_json(
            spliced_review.to_dict(),
            logical_type="challenger_category_review",
            origin="exact typed Challenger attack-category checklist entry",
            creator_role=Role.ADVERSARIAL_REVIEWER,
            creation_command=("scientist-one", "record-challenger-category-review"),
            parent_artifacts=(
                *spliced_review.evidence_hashes,
                *spliced_review.finding_artifact_hashes,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        reviews = list(self.challenger_reviews())
        statistics_index = tuple(ChallengeCategory).index(ChallengeCategory.STATISTICS)
        reviews[statistics_index] = spliced_artifact.sha256
        with self.assertRaises(ValidationError):
            assess_soundness(
                self.registry,
                "soundness-spliced-finding-category",
                self.dimension_receipts(),
                tuple(reviews),
                reason="Raw publication cannot bypass finding-category validation.",
            )
        placeholder = ChallengeFinding(
            "challenge-placeholder-parent",
            ChallengeCategory.LEAKAGE,
            ChallengeSeverity.MINOR,
            ChallengeStatus.UNRESOLVED,
            ("claim-main",),
            (digest("absent-evidence"),),
            "Attempt to use a SHA-shaped absent evidence parent.",
        )
        with self.assertRaises(ArtifactError):
            register_challenge_finding(self.registry, placeholder)

    # Complete receipt mechanics live in test_soundness_gates; this module
    # consumes only the public replay API at the paper boundary.
    def test_unresolved_blocking_challenge_rejects_direction(self) -> None:
        assessment = require_scientific_soundness_assessment(
            self.registry,
            assessment_artifact_hash=self.fixture.soundness_hash,
            expected_run_id=None,
        )
        self.assertIs(assessment.verdict, SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED)
        self.assertFalse(self.fixture.bundle.soundness_verdict is SoundnessVerdict.PASS)

    def test_fail_untested_major_and_clean_have_distinct_verdicts(self) -> None:
        assessment = require_scientific_soundness_assessment(
            self.registry,
            assessment_artifact_hash=self.fixture.soundness_hash,
            expected_run_id=None,
        )
        self.assertEqual(
            {status for _, status in assessment.dimensions},
            {DimensionStatus.UNTESTED},
        )
        self.assertTrue(
            all(
                review.execution_status is ChallengerExecutionStatus.UNTESTED
                for review in assessment.challenger_reviews
            )
        )

    def test_inconsistent_manual_soundness_pass_fails_closed(self) -> None:
        assessment = require_scientific_soundness_assessment(
            self.registry,
            assessment_artifact_hash=self.fixture.soundness_hash,
            expected_run_id=None,
        )
        with self.assertRaises(ValidationError):
            replace(assessment, verdict=SoundnessVerdict.PASS)

    def test_missing_or_sha_shaped_dimension_authority_fails_closed(self) -> None:
        with self.assertRaises(ValidationError):
            build_authoritative_research_bundle(
                self.registry,
                ledger=self.fixture.ledger,
                run_id=self.fixture.bundle.run_id,
                research_state_hash=self.fixture.bundle.research_state_hash,
                claim_graph_hash=self.fixture.bundle.claim_graph_hash,
                central_claim_ids=self.fixture.bundle.central_claim_ids,
                authoritative_evidence_hashes=(
                    self.fixture.bundle.authoritative_evidence_hashes
                ),
                metrics=self.fixture.bundle.metrics,
                method_code_bindings=self.fixture.bundle.method_code_bindings,
                required_baselines_complete=False,
                leakage_resolved=False,
                evaluator_exploitation_resolved=False,
                statistics_valid=False,
                novelty_supported=False,
                selection_integrity_valid=False,
                clean_reproduction_passed=False,
                soundness_assessment_hash=digest("placeholder-soundness"),
                external_validation_complete=False,
            )

    def test_wrong_role_dimension_receipt_is_not_authority(self) -> None:
        value = safe_json_loads(
            self.registry.get_bytes(self.fixture.soundness_hash)
        )
        assert isinstance(value, Mapping)
        record = self.registry.get_metadata(self.fixture.soundness_hash)
        with self.assertRaises(FrozenArtifactError):
            self.registry.put_json(
                dict(value),
                logical_type=record.logical_type,
                origin=record.origin,
                creator_role=Role.ORCHESTRATOR,
                creation_command=record.creation_command,
                parent_artifacts=record.parent_artifacts,
                schema_version=record.schema_version,
                mime_type=record.mime_type,
                validation_result="PASS",
                frozen=True,
            )

    def test_challenger_checklist_must_cover_every_exact_category(self) -> None:
        with self.assertRaises(ValidationError):
            require_scientific_soundness_assessment(
                self.registry,
                assessment_artifact_hash=self.fixture.soundness_hash,
                expected_assessment_id="another-soundness-assessment",
                expected_run_id=None,
            )

    def test_finding_must_be_content_bound_to_matching_category_and_evidence(self) -> None:
        bundle = replace(
            self.fixture.bundle,
            claim_graph_hash=digest("substituted-claim-graph"),
        )
        result = verify_paper(
            self.fixture.candidate,
            bundle,
            self.registry,
            self.fixture.ledger,
        )
        self.assertEqual(result.blockers, (HardBlocker.UNRESOLVED_AUTHORITY,))


class PaperBoundStateReplayTests(unittest.TestCase):
    def test_paper_replay_uses_frozen_state_projection_after_unrelated_append(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root:
            run_id = "paper-bound-state-replay"
            registry = ArtifactRegistry(root, f"runs/{run_id}/registry")
            ledger = EventLedger(root, f"runs/{run_id}/events.jsonl")
            repository = ResearchStateRepository(
                registry,
                ledger,
                run_id=run_id,
                code_version="paper-bound-code-v1",
                configuration_hash=digest("paper-bound-configuration"),
                state=MacroState.GROUND,
            )
            code = registry.put_bytes(
                b"def predict(value): return value\n",
                logical_type="experiment_code",
                origin="paper bound-state replay fixture",
                creator_role=Role.IMPLEMENTER,
                creation_command=("scientist-one", "paper-bound-state-test"),
                mime_type="text/x-python",
                frozen=True,
            )
            configuration = registry.put_json(
                {"configuration_id": "paper-bound-configuration"},
                logical_type="experiment_configuration",
                origin="paper bound-state replay fixture",
                creator_role=Role.PROTOCOL_DESIGNER,
                creation_command=("scientist-one", "paper-bound-state-test"),
                parent_artifacts=(code.sha256,),
                mime_type="application/json",
                frozen=True,
            )
            method_source = registry.put_json(
                {
                    "method_id": "method-paper-bound",
                    "name": "Bound replay method",
                    "description": "A method retained only for replay coverage.",
                    "assumptions": ["The test seam is non-evidentiary."],
                    "component_ids": ["bound-replay-component"],
                },
                logical_type="method_definition",
                origin="paper bound-state replay fixture",
                creator_role=Role.HYPOTHESIS_DESIGNER,
                creation_command=("scientist-one", "paper-bound-state-test"),
                parent_artifacts=(configuration.sha256,),
                mime_type="application/json",
                frozen=True,
            )
            question = ResearchQuestion(
                object_id="rq-paper-bound",
                producer=Role.PROBLEM_INVESTIGATOR,
                created_at="2026-08-29T12:00:00Z",
                status=RecordStatus.ACTIVE,
                code_version=repository.code_version,
                research_goal="Exercise immutable paper-state replay.",
                question="Does a later unrelated append alter paper authority?",
                falsification_condition="The bound replay changes.",
            )
            materialized = repository.materialize(question)
            state_method = StateMethod(
                object_id="method-paper-bound",
                producer=Role.HYPOTHESIS_DESIGNER,
                created_at="2026-08-29T12:00:01Z",
                status=RecordStatus.FROZEN,
                code_version=repository.code_version,
                name="Bound replay method",
                description="A method retained only for replay coverage.",
                assumptions=("The test seam is non-evidentiary.",),
                component_ids=("bound-replay-component",),
                authority_artifact_hashes=(method_source.sha256,),
            )
            method_state = repository.materialize(state_method)
            state_implementation = StateImplementation(
                object_id="implementation-paper-bound",
                producer=Role.IMPLEMENTER,
                created_at="2026-08-29T12:00:02Z",
                status=RecordStatus.ACTIVE,
                parents=(
                    ObjectReference(
                        "Method",
                        state_method.object_id,
                        state_method.content_hash,
                        "implements",
                        True,
                    ),
                ),
                code_version=repository.code_version,
                method_id=state_method.object_id,
                code_artifact_hashes=(code.sha256,),
                code_revision=repository.code_version,
                authority_artifact_hashes=(code.sha256,),
            )
            implementation_state = repository.materialize(state_implementation)
            current_state = tuple(
                sorted(
                    (
                        materialized.artifact.sha256,
                        method_state.artifact.sha256,
                        implementation_state.artifact.sha256,
                    )
                )
            )
            snapshot = register_research_state_snapshot(
                repository,
                snapshot_id="paper-bound-state-replay",
                created_at="2026-08-29T12:00:03Z",
            )
            issued = resolve_research_state_authority(
                registry,
                ledger,
                run_id=run_id,
                snapshot_artifact_hash=snapshot.sha256,
            )
            evidence = registry.put_json(
                {"fixture": "paper-bound-evidence"},
                logical_type="paper_bound_evidence",
                origin="paper bound-state replay fixture",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "paper-bound-state-test"),
                mime_type="application/json",
                frozen=True,
            )
            result_source = registry.put_json(
                {"fixture": "paper-bound-result"},
                logical_type="paper_bound_result",
                origin="paper bound-state replay fixture",
                creator_role=Role.STATISTICIAN,
                creation_command=("scientist-one", "paper-bound-state-test"),
                mime_type="application/json",
                frozen=True,
            )
            asset = registry.put_json(
                {"fixture": "paper-bound-table"},
                logical_type="paper_bound_table",
                origin="paper bound-state replay fixture",
                creator_role=Role.PAPER_WRITER,
                creation_command=("scientist-one", "paper-bound-state-test"),
                parent_artifacts=(result_source.sha256,),
                mime_type="application/json",
                frozen=True,
            )
            graph = registry.put_json(
                {"fixture": "paper-bound-graph"},
                logical_type="paper_bound_graph",
                origin="paper bound-state replay fixture",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "paper-bound-state-test"),
                mime_type="application/json",
                frozen=True,
            )
            soundness = registry.put_json(
                {"fixture": "paper-bound-soundness"},
                logical_type="paper_bound_soundness",
                origin="paper bound-state replay fixture",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "paper-bound-state-test"),
                mime_type="application/json",
                frozen=True,
            )
            evidence_hash = evidence.sha256
            graph_hash = graph.sha256
            soundness_hash = soundness.sha256
            authority = AuthoritativeClaim(
                claim_id="claim-paper-bound",
                text="The bounded paper fixture remains historical.",
                expressed_strength=ClaimStrength.QUALIFIED,
                permitted_strength=ClaimStrength.QUALIFIED,
                evidence_hashes=(evidence_hash,),
                claim_state_artifact_hash=materialized.artifact.sha256,
                graph_decision_hash=digest("paper-bound-graph-decision"),
                claim_semantics_artifact_hash=digest("paper-bound-semantics"),
                producer_role=Role.EXPERIMENT_RUNNER,
                claim_semantics_evidence_scope=(
                    ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE
                ),
                confidence=0.5,
                verification_method="Bound replay test seam.",
                scientific_writer_eligible=False,
                evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
                claim_type=ClaimType.QUALITATIVE,
                scope="Bound test only.",
            )
            metric = AuthoritativeMetric(
                metric_id="paper-bound-metric",
                value=0.0,
                unit="fixture",
                direction=MetricDirection.HIGHER_IS_BETTER,
                result_artifact_hash=result_source.sha256,
                result_state_artifact_hash=materialized.artifact.sha256,
                canonical_metric_id="paper-bound-canonical-metric",
            )
            method_binding = MethodCodeBinding(
                method_artifact_hash=method_source.sha256,
                code_artifact_hash=code.sha256,
                method_state_artifact_hash=method_state.artifact.sha256,
                implementation_state_artifact_hash=(
                    implementation_state.artifact.sha256
                ),
            )
            authoritative_evidence = tuple(
                sorted(
                    {
                        evidence.sha256,
                        result_source.sha256,
                        asset.sha256,
                        code.sha256,
                        configuration.sha256,
                        method_source.sha256,
                    }
                )
            )
            bundle = AuthoritativeResearchBundle(
                research_state_hash=snapshot.sha256,
                claim_graph_hash=graph_hash,
                claims=(authority,),
                central_claim_ids=(authority.claim_id,),
                authoritative_evidence_hashes=authoritative_evidence,
                metrics=(metric,),
                method_code_bindings=(method_binding,),
                required_limitations=("Bound test only.",),
                required_baselines_complete=False,
                leakage_resolved=False,
                evaluator_exploitation_resolved=False,
                statistics_valid=False,
                novelty_supported=False,
                selection_integrity_valid=False,
                clean_reproduction_passed=False,
                soundness_verdict=SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED,
                soundness_assessment_hash=soundness_hash,
                external_validation_complete=False,
                run_id=run_id,
                research_state_artifact_hashes=current_state,
                research_state_ledger_head_hash=issued.ledger_head_hash,
                research_state_ledger_event_count=issued.ledger_event_count,
                research_state_code_version=issued.code_version,
                research_state_configuration_hash=issued.configuration_hash,
            )
            with patch(
                "scientist_one.paper_pipeline._build_authoritative_research_bundle",
                return_value=bundle,
            ):
                bundle_artifact = register_authoritative_research_bundle(
                    registry,
                    ledger,
                    bundle,
                    bundle_id=bundle_fixture_id(bundle),
                    created_at="2026-08-29T12:00:03Z",
                )
                self.assertEqual(
                    register_authoritative_research_bundle(
                        registry,
                        ledger,
                        bundle,
                        bundle_id=bundle_fixture_id(bundle),
                        created_at="2026-08-29T12:00:03Z",
                    ),
                    bundle_artifact,
                )
            resumable_bundle = replace(
                bundle,
                required_baselines_complete=True,
            )
            resumable_id = bundle_fixture_id(resumable_bundle)
            pre_interrupt_records = len(registry.list_records())
            pre_interrupt_events = ledger.assert_valid().event_count
            with (
                patch(
                    "scientist_one.paper_pipeline._build_authoritative_research_bundle",
                    return_value=resumable_bundle,
                ),
                patch.object(
                    ledger,
                    "_append_locked",
                    side_effect=RuntimeError("bundle issuance interrupted"),
                ),
                self.assertRaisesRegex(RuntimeError, "interrupted"),
            ):
                register_authoritative_research_bundle(
                    registry,
                    ledger,
                    resumable_bundle,
                    bundle_id=resumable_id,
                    created_at="2026-08-29T12:00:03Z",
                )
            self.assertEqual(
                len(registry.list_records()),
                pre_interrupt_records + 1,
            )
            self.assertEqual(
                ledger.assert_valid().event_count,
                pre_interrupt_events,
            )
            with patch(
                "scientist_one.paper_pipeline._build_authoritative_research_bundle",
                return_value=resumable_bundle,
            ):
                resumed_bundle_artifact = (
                    register_authoritative_research_bundle(
                        registry,
                        ledger,
                        resumable_bundle,
                        bundle_id=resumable_id,
                        created_at="2026-08-29T12:00:03Z",
                    )
                )
            ledger.append_correction(
                f"arb-{resumed_bundle_artifact.sha256[:48]}",
                actor_role=Role.ORCHESTRATOR,
                reason="withdraw the interrupted bundle issuance test authority",
                corrected_fields={"authority": "WITHDRAWN"},
                event_id="withdraw-resumed-paper-bundle",
                timestamp="2026-08-29T12:00:03Z",
            )
            with (
                patch(
                    "scientist_one.paper_pipeline._build_authoritative_research_bundle",
                    return_value=resumable_bundle,
                ),
                self.assertRaisesRegex(
                    ValidationError,
                    "issuance was later corrected",
                ),
            ):
                register_authoritative_research_bundle(
                    registry,
                    ledger,
                    resumable_bundle,
                    bundle_id=resumable_id,
                    created_at="2026-08-29T12:00:03Z",
                )

            # Freeze a clone before any later canonical materialization.  A
            # correction that lands after fresh bundle replay but before the
            # issuer's commit snapshot must invalidate the operation without
            # publishing either the new bundle artifact or its ARB event.
            with tempfile.TemporaryDirectory() as race_root:
                shutil.copytree(
                    Path(root),
                    Path(race_root),
                    dirs_exist_ok=True,
                )
                race_registry = ArtifactRegistry(
                    race_root,
                    f"runs/{run_id}/registry",
                )
                race_ledger = EventLedger(
                    race_root,
                    f"runs/{run_id}/events.jsonl",
                )
                race_bundle = replace(bundle, leakage_resolved=True)
                bundle_count = sum(
                    item.logical_type == "authoritative_research_bundle"
                    for item in race_registry.list_records()
                )
                event_count = race_ledger.assert_valid().event_count
                arb_event_ids = {
                    event.event_id
                    for event in race_ledger.assert_valid().events
                    if event.event_id.startswith("arb-")
                }

                def correct_snapshot_after_replay(*_args, **_kwargs):
                    race_ledger.append_correction(
                        f"rss-{snapshot.sha256[:48]}",
                        actor_role=Role.ORCHESTRATOR,
                        reason=(
                            "withdraw snapshot authority at the bundle "
                            "fresh-replay boundary"
                        ),
                        corrected_fields={"authority": "WITHDRAWN"},
                        event_id="withdraw-snapshot-during-bundle-replay",
                        timestamp="2026-08-29T12:00:04Z",
                    )
                    return race_bundle

                with (
                    patch(
                        "scientist_one.paper_pipeline."
                        "_build_authoritative_research_bundle",
                        side_effect=correct_snapshot_after_replay,
                    ),
                    self.assertRaisesRegex(
                        ValidationError,
                        "source changed during fresh replay",
                    ),
                ):
                    register_authoritative_research_bundle(
                        race_registry,
                        race_ledger,
                        race_bundle,
                        bundle_id=bundle_fixture_id(race_bundle),
                        created_at="2026-08-29T12:00:04Z",
                    )
                self.assertEqual(
                    sum(
                        item.logical_type == "authoritative_research_bundle"
                        for item in race_registry.list_records()
                    ),
                    bundle_count,
                )
                self.assertEqual(
                    race_ledger.assert_valid().event_count,
                    event_count + 1,
                )
                self.assertEqual(
                    {
                        event.event_id
                        for event in race_ledger.assert_valid().events
                        if event.event_id.startswith("arb-")
                    },
                    arb_event_ids,
                )
            candidate = PaperCandidate(
                candidate_id="paper-bound-candidate",
                title="Bound state replay fixture",
                claims=(
                    PaperClaim(
                        claim_id=authority.claim_id,
                        text=authority.text,
                        strength=authority.expressed_strength,
                        evidence_hashes=authority.evidence_hashes,
                        central=True,
                        claim_type=authority.claim_type,
                        scope=authority.scope,
                        confidence=authority.confidence,
                        verification_method=authority.verification_method,
                        permitted_strength=authority.permitted_strength,
                    ),
                ),
                numeric_assertions=(),
                references=(),
                assets=(
                    GeneratedAsset(
                        asset_id="paper-bound-table",
                        kind="TABLE",
                        artifact_hash=asset.sha256,
                        authoritative_parent_hashes=(result_source.sha256,),
                    ),
                ),
                method_code_bindings=(method_binding,),
                limitations=bundle.required_limitations,
                source_bundle_hashes=(
                    snapshot.sha256,
                    graph_hash,
                    soundness_hash,
                ),
            )

            with patch(
                "scientist_one.paper_pipeline._build_authoritative_research_bundle",
                return_value=bundle,
            ):
                before = verify_paper(candidate, bundle, registry, ledger)
                repository.materialize(
                    replace(
                        question,
                        object_id="rq-paper-unrelated",
                        created_at="2026-08-29T12:00:04Z",
                        content_hash=None,
                    )
                )
                post_append_record_count = len(registry.list_records())
                post_append_event_count = ledger.assert_valid().event_count
                self.assertEqual(
                    register_authoritative_research_bundle(
                        registry,
                        ledger,
                        bundle,
                        bundle_id=bundle_fixture_id(bundle),
                        created_at="2026-08-29T12:00:03Z",
                    ),
                    bundle_artifact,
                )
                with self.assertRaisesRegex(
                    ValidationError,
                    "state changed before bundle issuance",
                ):
                    register_authoritative_research_bundle(
                        registry,
                        ledger,
                        bundle,
                        bundle_id="paper-bundle-late-reissuance",
                        created_at="2026-08-29T12:00:04Z",
                    )
                self.assertEqual(
                    len(registry.list_records()),
                    post_append_record_count,
                )
                self.assertEqual(
                    ledger.assert_valid().event_count,
                    post_append_event_count,
                )
                after = verify_paper(candidate, bundle, registry, ledger)
                self.assertEqual(after, before)

                repository.materialize(
                    replace(
                        question,
                        revision=2,
                        created_at="2099-01-01T00:00:00Z",
                        question="Does a revised bound input alter paper authority?",
                        supersedes_content_hash=question.content_hash,
                        content_hash=None,
                    )
                )
                rejected = verify_paper(candidate, bundle, registry, ledger)
                self.assertEqual(
                    rejected,
                    PaperVerification(
                        passed=False,
                        blockers=(HardBlocker.UNRESOLVED_AUTHORITY,),
                        discrepancies=("authoritative_bundle_does_not_resolve",),
                        verified_claim_ids=(),
                    ),
                )

    def test_real_paper_and_v1_venue_inventory_remain_not_ready_after_state_appends(
        self,
    ) -> None:
        """A structural v1 inventory cannot mint semantic venue authority."""

        with tempfile.TemporaryDirectory() as root:
            source_fixture = _cached_canonical_authority_fixture()
            shutil.copytree(
                source_fixture.registry.policy.root,
                Path(root),
                dirs_exist_ok=True,
            )
            registry = ArtifactRegistry(root, source_fixture.registry.base_path)
            ledger = EventLedger(root, source_fixture.ledger.relative_path)
            fixture = replace(
                source_fixture,
                registry=registry,
                ledger=ledger,
            )
            bundle = source_fixture.bundle
            candidate = source_fixture.candidate
            assert bundle.run_id is not None

            issued = resolve_research_state_authority(
                registry,
                ledger,
                run_id=bundle.run_id,
                snapshot_artifact_hash=bundle.research_state_hash,
            )
            seed = issued.entries[0]
            seed_event = ledger.events()[seed.materialization_event_index]
            repository = ResearchStateRepository(
                registry,
                ledger,
                run_id=bundle.run_id,
                code_version=issued.code_version,
                configuration_hash=issued.configuration_hash,
                state=seed_event.state_before,
                creation_command=registry.get_metadata(
                    seed.artifact_sha256
                ).creation_command,
            )
            initial_verification = verify_paper(
                candidate,
                bundle,
                registry,
                ledger,
            )
            profile = default_venue_profiles()[0]
            authority = venue_authority_fixture(fixture, profile)
            scores = {name: 0.95 for name in READINESS_DIMENSIONS}
            result = assess_venue(
                profile,
                initial_verification,
                scores,
                external_validation_complete=True,
                rationale="An inventory is not a live semantic review.",
                registry=registry,
                ledger=ledger,
                candidate=candidate,
                bundle=bundle,
                run_id=bundle.run_id,
                candidate_artifact_hash=authority.candidate_artifact_hash,
                bundle_artifact_hash=authority.bundle_artifact_hash,
                profile_artifact_hash=authority.profile_artifact_hash,
                readiness_manifest_hash=authority.readiness_manifest_hash,
            )
            self.assertEqual(result.classification, VenueFit.NOT_READY)
            self.assertIn(
                HardBlocker.VENUE_REQUIREMENTS_UNRESOLVED,
                result.hard_blockers,
            )
            self.assertEqual(
                result.dimension_scores,
                tuple((name, 0.0) for name in READINESS_DIMENSIONS),
            )
            with self.assertRaisesRegex(
                ValidationError,
                "structural venue inventory cannot authorize requirement satisfaction",
            ):
                register_venue_requirement_receipt(
                    registry,
                    ledger,
                    candidate,
                    bundle,
                    profile,
                    receipt_id="bound-venue-requirement-code",
                    run_id=bundle.run_id,
                    candidate_artifact_hash=authority.candidate_artifact_hash,
                    bundle_artifact_hash=authority.bundle_artifact_hash,
                    profile_artifact_hash=authority.profile_artifact_hash,
                    readiness_manifest_hash=authority.readiness_manifest_hash,
                    requirement="code",
                    semantic_judgment_hash=None,
                )

            unrelated = ResearchQuestion(
                object_id="rq-paper-bound-downstream",
                producer=Role.PROBLEM_INVESTIGATOR,
                created_at="2026-08-29T12:00:04Z",
                status=RecordStatus.ACTIVE,
                code_version=issued.code_version,
                research_goal="Exercise downstream append monotonicity.",
                question="Can an unrelated later state object invalidate paper authority?",
                falsification_condition="The frozen paper projection changes.",
            )
            repository.materialize(unrelated)
            with self.assertRaisesRegex(ValidationError, "snapshot is stale"):
                resolve_research_state_authority(
                    registry,
                    ledger,
                    run_id=bundle.run_id,
                    snapshot_artifact_hash=bundle.research_state_hash,
                )
            self.assertEqual(
                verify_paper(candidate, bundle, registry, ledger),
                initial_verification,
            )
            self.assertEqual(
                assess_venue(
                    profile,
                    initial_verification,
                    scores,
                    external_validation_complete=True,
                    rationale="An inventory is not a live semantic review.",
                    registry=registry,
                    ledger=ledger,
                    candidate=candidate,
                    bundle=bundle,
                    run_id=bundle.run_id,
                    candidate_artifact_hash=authority.candidate_artifact_hash,
                    bundle_artifact_hash=authority.bundle_artifact_hash,
                    profile_artifact_hash=authority.profile_artifact_hash,
                    readiness_manifest_hash=authority.readiness_manifest_hash,
                ),
                result,
            )
            report = repository.validate_state(expected_code_version=issued.code_version)
            self.assertTrue(report.valid, report.issues)


class PaperPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        if (
            self._testMethodName
            == "test_canonical_run_replays_exact_execution_input_binding"
        ):
            root = Path(self.temporary.name)
            shutil.copytree(
                PROJECT_ROOT / "src" / "scientist_one",
                root / "src" / "scientist_one",
            )
            (root / "scripts").mkdir(parents=True)
            shutil.copy2(
                PROJECT_ROOT / "scripts" / "vnext_fixture_experiment.py",
                root / "scripts" / "vnext_fixture_experiment.py",
            )
            shutil.copytree(PROJECT_ROOT / "fixtures", root / "fixtures")
            shutil.copytree(PROJECT_ROOT / "configs", root / "configs")
            run_id = "paper-run-binding-canonical"

            def stop_at_paper_boundary(*_args, **_kwargs):
                raise RuntimeError("canonical-run-boundary-reached")

            with (
                patch(
                    "scientist_one.research_os._run_paper_pipeline",
                    side_effect=stop_at_paper_boundary,
                ),
                self.assertRaisesRegex(
                    RuntimeError, "canonical-run-boundary-reached"
                ),
            ):
                run_research_os_fixture(root, run_id=run_id)
            registry = ArtifactRegistry(root, f"runs/{run_id}/registry")
            snapshot = _one_registry_record(
                registry, "canonical_research_state_snapshot"
            )
            self.fixture = SimpleNamespace(
                registry=registry,
                ledger=EventLedger(root, f"runs/{run_id}/events.jsonl"),
                bundle=SimpleNamespace(
                    run_id=run_id,
                    research_state_hash=snapshot.sha256,
                ),
            )
            return
        self.fixture = authoritative_fixture(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_clean_candidate_is_a_faithful_structured_view(self) -> None:
        result = verify_paper(
            self.fixture.candidate,
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.verified_claim_ids, ())
        self.assertIn(HardBlocker.UNRESOLVED_AUTHORITY, result.blockers)
        self.assertIn(HardBlocker.UNSUPPORTED_CENTRAL_CLAIM, result.blockers)
        self.assertIn(HardBlocker.UNRESOLVED_BLOCKING_CHALLENGE, result.blockers)
        self.assertIn(HardBlocker.IRREPRODUCIBLE_HEADLINE_RESULT, result.blockers)
        self.assertIs(
            self.fixture.bundle.metrics[0].scientific_evidence_status,
            MetricEvidenceStatus.NON_EVIDENTIARY,
        )

    def test_canonical_run_replays_exact_execution_input_binding(self) -> None:
        snapshot_value = safe_json_loads(
            self.fixture.registry.get_bytes(self.fixture.bundle.research_state_hash)
        )
        self.assertIsInstance(snapshot_value, Mapping)
        repository = ResearchStateRepository(
            self.fixture.registry,
            self.fixture.ledger,
            run_id=self.fixture.bundle.run_id,
            code_version=snapshot_value["repository_code_version"],
            configuration_hash=snapshot_value["repository_configuration_hash"],
            state=MacroState(snapshot_value["repository_state"]),
            creation_command=tuple(
                snapshot_value["materialization_creation_command"]
            ),
        )
        stored = repository._stored_objects()
        by_content, _by_identity = repository._indexes(stored)
        run = next(
            item.research_object
            for item in stored
            if isinstance(item.research_object, StateRun)
            and item.research_object.producer is Role.EXPERIMENT_RUNNER
        )
        records = tuple(
            self.fixture.registry.get_metadata(digest)
            for digest in run.authority_artifact_hashes
        )

        def one(logical_type: str):
            matches = tuple(
                item for item in records if item.logical_type == logical_type
            )
            self.assertEqual(len(matches), 1)
            return matches[0]

        input_record = one("execution_input_binding")
        plan_record = one("adaptive_execution_plan")
        binding_record = one("adaptive_execution_plan_binding")
        spec_record = self.fixture.registry.get_metadata(
            input_record.parent_artifacts[0]
        )
        input_value = safe_json_loads(
            self.fixture.registry.get_bytes(input_record.sha256)
        )
        binding_value = safe_json_loads(
            self.fixture.registry.get_bytes(binding_record.sha256)
        )
        self.assertIsInstance(input_value, Mapping)
        self.assertIsInstance(binding_value, Mapping)

        resolved = repository._resolve_object_authority(run, by_content)
        self.assertIn(input_record.sha256, tuple(item.sha256 for item in resolved.records))

        def replace_run_hashes(replacements: Mapping[str, str]) -> StateRun:
            def replaced(values: tuple[str, ...]) -> tuple[str, ...]:
                return tuple(replacements.get(value, value) for value in values)

            return replace(
                run,
                authority_artifact_hashes=replaced(run.authority_artifact_hashes),
                output_artifact_hashes=replaced(run.output_artifact_hashes),
                content_hash=None,
            )

        missing_input = replace(
            run,
            authority_artifact_hashes=tuple(
                digest
                for digest in run.authority_artifact_hashes
                if digest != input_record.sha256
            ),
            output_artifact_hashes=tuple(
                digest
                for digest in run.output_artifact_hashes
                if digest != input_record.sha256
            ),
            content_hash=None,
        )
        with self.assertRaisesRegex(
            ValidationError, "execution[_ ]input[_ ]binding"
        ):
            repository._resolve_object_authority(missing_input, by_content)

        def register_input_binding(value: Mapping[str, Any]):
            return self.fixture.registry.put_bytes(
                canonical_json_bytes(value) + b"\n",
                logical_type=input_record.logical_type,
                origin=input_record.origin,
                creator_role=input_record.creator_role,
                creation_command=input_record.creation_command,
                parent_artifacts=input_record.parent_artifacts,
                schema_version=input_record.schema_version,
                mime_type=input_record.mime_type,
                validation_result=input_record.validation_result,
                frozen=input_record.frozen,
                created_at=input_record.created_at,
            )

        def register_plan_binding(
            value: Mapping[str, Any],
            input_binding_sha256: str,
            *,
            encoded: bytes | None = None,
        ):
            return self.fixture.registry.put_bytes(
                (
                    canonical_json_bytes(value) + b"\n"
                    if encoded is None
                    else encoded
                ),
                logical_type=binding_record.logical_type,
                origin=binding_record.origin,
                creator_role=binding_record.creator_role,
                creation_command=binding_record.creation_command,
                parent_artifacts=(
                    plan_record.sha256,
                    input_binding_sha256,
                    spec_record.sha256,
                ),
                schema_version=binding_record.schema_version,
                mime_type=binding_record.mime_type,
                validation_result=binding_record.validation_result,
                frozen=binding_record.frozen,
                created_at=binding_record.created_at,
            )

        swapped_input = dict(input_value)
        swapped_entries = [dict(item) for item in input_value["inputs"]]
        swapped_entries[0], swapped_entries[1] = (
            swapped_entries[1],
            swapped_entries[0],
        )
        swapped_input["inputs"] = swapped_entries
        swapped_input_record = register_input_binding(swapped_input)
        swapped_binding = dict(binding_value)
        for field in (
            "collected_execution_input_binding_sha256",
            "execution_input_binding_artifact_sha256",
            "execution_input_binding_sha256",
            "submission_execution_input_binding_sha256",
        ):
            swapped_binding[field] = swapped_input_record.sha256
        swapped_binding_record = register_plan_binding(
            swapped_binding, swapped_input_record.sha256
        )
        swapped_run = replace_run_hashes(
            {
                input_record.sha256: swapped_input_record.sha256,
                binding_record.sha256: swapped_binding_record.sha256,
            }
        )
        with self.assertRaisesRegex(
            ValidationError, "execution input binding differs"
        ):
            repository._resolve_object_authority(swapped_run, by_content)

        for field in (
            "collected_execution_input_binding_sha256",
            "execution_input_binding_artifact_sha256",
            "execution_input_binding_sha256",
            "submission_execution_input_binding_sha256",
        ):
            with self.subTest(substituted_field=field):
                substituted_binding = dict(binding_value)
                substituted_binding[field] = digest(f"substituted:{field}")
                substituted_binding_record = register_plan_binding(
                    substituted_binding, input_record.sha256
                )
                substituted_run = replace_run_hashes(
                    {binding_record.sha256: substituted_binding_record.sha256}
                )
                with self.assertRaisesRegex(
                    ValidationError, "plan custody binding is not exact"
                ):
                    repository._resolve_object_authority(
                        substituted_run, by_content
                    )

        malformed_bindings: list[tuple[str, Mapping[str, Any]]] = []
        missing_field = dict(binding_value)
        missing_field.pop("agreement")
        malformed_bindings.append(("missing field", missing_field))
        unknown_field = dict(binding_value)
        unknown_field["caller_asserted_authority"] = True
        malformed_bindings.append(("unknown field", unknown_field))
        reordered_outputs = dict(binding_value)
        reordered_outputs["collected_returned_artifact_sha256s"] = list(
            reversed(binding_value["collected_returned_artifact_sha256s"])
        )
        malformed_bindings.append(("reordered outputs", reordered_outputs))
        for name, malformed in malformed_bindings:
            with self.subTest(plan_binding=name):
                malformed_record = register_plan_binding(
                    malformed, input_record.sha256
                )
                malformed_run = replace_run_hashes(
                    {binding_record.sha256: malformed_record.sha256}
                )
                with self.assertRaisesRegex(
                    ValidationError, "plan custody binding is not exact"
                ):
                    repository._resolve_object_authority(
                        malformed_run, by_content
                    )

        replay_arguments = {
            "run_id": run.object_id,
            "spec_artifact_sha256": spec_record.sha256,
            "spec_sha256": binding_value["spec_sha256"],
            "execution_plan_artifact_sha256": plan_record.sha256,
            "execution_plan_sha256": binding_value["execution_plan_sha256"],
            "execution_input_binding_sha256": input_record.sha256,
            "manifest_artifact_sha256": binding_value[
                "collected_manifest_sha256"
            ],
            "returned_artifact_sha256s": tuple(
                binding_value["collected_returned_artifact_sha256s"]
            ),
        }
        with self.assertRaisesRegex(
            ValidationError, "plan custody binding is not exact"
        ):
            repository._replay_adaptive_execution_plan_binding(
                replace(
                    binding_record,
                    parent_artifacts=(
                        input_record.sha256,
                        plan_record.sha256,
                        spec_record.sha256,
                    ),
                    record_hash=None,
                ),
                binding_value,
                **replay_arguments,
            )

        noncanonical_record = register_plan_binding(
            binding_value,
            input_record.sha256,
            encoded=b" " + canonical_json_bytes(binding_value) + b"\n",
        )
        noncanonical_run = replace_run_hashes(
            {binding_record.sha256: noncanonical_record.sha256}
        )
        with self.assertRaisesRegex(ValidationError, "not canonical JSON"):
            repository._resolve_object_authority(noncanonical_run, by_content)

        with self.assertRaisesRegex(
            ValidationError, "plan custody binding is not exact"
        ):
            repository._replay_adaptive_execution_plan_binding(
                replace(
                    binding_record,
                    origin="caller-supplied adaptive execution custody",
                    record_hash=None,
                ),
                binding_value,
                **replay_arguments,
            )

        spec_value = safe_json_loads(
            self.fixture.registry.get_bytes(spec_record.sha256)
        )
        self.assertIsInstance(spec_value, Mapping)
        with self.assertRaisesRegex(
            ValidationError, "execution input binding custody is not exact"
        ):
            repository._replay_execution_input_binding(
                replace(
                    input_record,
                    creation_command=("caller", "assert-input-custody"),
                    record_hash=None,
                ),
                spec_artifact_sha256=spec_record.sha256,
                spec_sha256=input_value["spec_sha256"],
                spec_value=spec_value,
            )

    def test_claim_semantics_are_source_owned_and_fixture_only(self) -> None:
        authority = self.fixture.bundle.claims[0]
        paper_claim = self.fixture.candidate.claims[0]
        self.assertIs(authority.claim_type, ClaimType.COMPARATIVE)
        self.assertEqual(authority.scope, "Captured offline system fixture only.")
        self.assertIs(
            authority.claim_semantics_evidence_scope,
            ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE,
        )
        self.assertFalse(authority.scientific_writer_eligible)
        self.assertIn(
            authority.claim_semantics_artifact_hash,
            self.fixture.bundle.authoritative_evidence_hashes,
        )
        self.assertIs(paper_claim.claim_type, authority.claim_type)
        self.assertEqual(paper_claim.scope, authority.scope)
        self.assertEqual(paper_claim.confidence, authority.confidence)
        self.assertEqual(
            paper_claim.verification_method,
            authority.verification_method,
        )
        self.assertIs(
            paper_claim.permitted_strength,
            authority.permitted_strength,
        )
        self.assertEqual(
            paper_claim.dependency_claim_ids,
            authority.dependency_claim_ids,
        )
        assert authority.requirements is not None
        self.assertEqual(
            paper_claim.evidence_sources,
            authority.requirements.evidence_sources,
        )

    def test_paper_claim_cannot_omit_or_relabel_canonical_semantics(self) -> None:
        claim = self.fixture.candidate.claims[0]
        substitutions = (
            (
                replace(claim, claim_type=ClaimType.QUALITATIVE),
                "claim_type_mismatch:claim-main",
            ),
            (
                replace(claim, scope="An unattested broad population."),
                "claim_scope_mismatch:claim-main",
            ),
            (
                replace(claim, confidence=1.0),
                "claim_confidence_mismatch:claim-main",
            ),
            (
                replace(claim, verification_method="caller-selected method"),
                "claim_verification_method_mismatch:claim-main",
            ),
            (
                replace(claim, permitted_strength=ClaimStrength.STRONG),
                "claim_permitted_strength_mismatch:claim-main",
            ),
            (
                replace(claim, dependency_claim_ids=("missing-dependency",)),
                "claim_dependencies_mismatch:claim-main",
            ),
            (
                replace(claim, evidence_sources=()),
                "claim_evidence_sources_mismatch:claim-main",
            ),
        )
        for forged_claim, expected_discrepancy in substitutions:
            with self.subTest(discrepancy=expected_discrepancy):
                result = verify_paper(
                    replace(
                        self.fixture.candidate,
                        claims=(forged_claim,),
                    ),
                    self.fixture.bundle,
                    self.fixture.registry,
                    self.fixture.ledger,
                )
                self.assertIn(
                    expected_discrepancy,
                    result.discrepancies,
                )

    def test_claim_type_relabel_cannot_suppress_typed_requirements(self) -> None:
        authority = self.fixture.bundle.claims[0]
        assert authority.requirements is not None
        forged_requirements = replace(
            authority.requirements,
            claim_type=ClaimType.QUALITATIVE,
            required_metric_ids=(),
            required_method_code_bindings=(),
            required_generated_assets=(),
        )
        forged_claim = replace(
            authority,
            claim_type=ClaimType.QUALITATIVE,
            requirements=forged_requirements,
        )
        result = verify_paper(
            self.fixture.candidate,
            replace(
                self.fixture.bundle,
                claims=(forged_claim,),
                method_code_bindings=(),
            ),
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertEqual(result.blockers, (HardBlocker.UNRESOLVED_AUTHORITY,))

    def test_claim_semantics_receipt_cannot_be_omitted_from_authority(self) -> None:
        semantics_hash = self.fixture.bundle.claims[0].claim_semantics_artifact_hash
        with self.assertRaisesRegex(
            ValidationError,
            "omits the resolved claim-semantics receipt",
        ):
            rebuild_authoritative_bundle(
                self.fixture,
                authoritative_evidence_hashes=tuple(
                    item
                    for item in self.fixture.bundle.authoritative_evidence_hashes
                    if item != semantics_hash
                ),
            )

    def test_authoritative_claim_preserves_canonical_type_sources_and_requirements(self) -> None:
        authority = self.fixture.bundle.claims[0]
        self.assertIs(authority.claim_type, ClaimType.COMPARATIVE)
        self.assertEqual(authority.scope, "Captured offline system fixture only.")
        self.assertEqual(authority.dependency_claim_ids, ())
        self.assertEqual(
            authority.source_artifact_ids,
            (
                self.fixture.claim_graph_hash,
                authority.claim_semantics_artifact_hash,
            ),
        )
        self.assertIsNotNone(authority.requirements)
        assert authority.requirements is not None
        self.assertEqual(
            authority.requirements.required_metric_ids,
            tuple(sorted(item.metric_id for item in self.fixture.bundle.metrics)),
        )
        self.assertEqual(
            authority.requirements.required_reference_artifact_hashes,
            (self.fixture.reference_hash,),
        )
        self.assertEqual(
            authority.requirements.required_method_code_bindings,
            self.fixture.bundle.method_code_bindings,
        )
        self.assertEqual(
            tuple(item.artifact_hash for item in authority.requirements.required_generated_assets),
            (self.fixture.asset_hash,),
        )

    def test_synthetic_confirmatory_scope_cannot_be_promoted(self) -> None:
        authority = ConfirmatoryClaimAuthority(
            claim_id="claim-confirmatory-fixture",
            run_id="run-confirmatory-fixture",
            timeline_receipt_hash=digest("timeline"),
            protocol_artifact_hash=digest("protocol-artifact"),
            fresh_custody_receipt_hash=digest("fresh-custody"),
            custody_record_hash=digest("custody-record"),
            result_artifact_hash=digest("confirmatory-result"),
            protocol_hash=digest("protocol-payload"),
            study_id="study-confirmatory-fixture",
            study_version=1,
            holdout_identity_hash=digest("holdout-identity"),
            seal_hash=digest("seal"),
            release_id=digest("release"),
            scope=ConfirmatoryAuthorityScope.NON_EVIDENTIARY_FIXTURE,
            scientific_gate_passed=False,
        )
        self.assertFalse(authority.scientific_gate_passed)
        with self.assertRaises(ValidationError):
            replace(authority, scientific_gate_passed=True)
        with self.assertRaises(ValidationError):
            replace(
                authority,
                scope=ConfirmatoryAuthorityScope.SCIENTIFIC_EVIDENCE,
            )
        with self.assertRaises(ValidationError):
            register_confirmatory_claim_authority(
                self.fixture.registry,
                self.fixture.ledger,
                authority_id="non-confirmatory-substitution",
                run_id=self.fixture.bundle.run_id or "missing-run",
                claim_id="claim-main",
                claim_graph_artifact_hash=self.fixture.claim_graph_hash,
                timeline_receipt_artifact_hash=digest("absent-timeline"),
            )

    def test_confirmatory_authority_rejects_missing_forged_or_wrong_role_receipt(self) -> None:
        with self.assertRaises((ArtifactError, ValidationError)):
            require_confirmatory_claim_authority(
                self.fixture.registry,
                self.fixture.ledger,
                authority_artifact_hash=digest("missing-confirmatory-authority"),
                expected_run_id=self.fixture.bundle.run_id or "missing-run",
                expected_claim_id="claim-main",
                expected_claim_graph_artifact_hash=self.fixture.claim_graph_hash,
            )
        wrong_role = _put_json(
            self.fixture.registry,
            {"schema_version": "confirmatory-claim-authority/v1"},
            "confirmatory_claim_authority",
            Role.ORCHESTRATOR,
            (self.fixture.claim_graph_hash,),
        )
        with self.assertRaises(ValidationError):
            require_confirmatory_claim_authority(
                self.fixture.registry,
                self.fixture.ledger,
                authority_artifact_hash=wrong_role.sha256,
                expected_run_id=self.fixture.bundle.run_id or "missing-run",
                expected_claim_id="claim-main",
                expected_claim_graph_artifact_hash=self.fixture.claim_graph_hash,
            )

    def test_confirmatory_authority_rejects_wrong_run_stale_and_wrong_claim_substitution(self) -> None:
        run_id = self.fixture.bundle.run_id or "missing-run"
        forged = self.fixture.registry.put_json(
            {
                "schema_version": "confirmatory-claim-authority/v1",
                "authority_id": "forged-confirmatory-authority",
                "run_id": run_id,
                "claim_id": "claim-main",
                "claim_graph_artifact_hash": self.fixture.claim_graph_hash,
                "timeline_receipt_artifact_hash": digest("forged-timeline"),
                "evidence_sources": [],
                "claim_evidence_closure_hashes": [],
                "authority": {},
            },
            logical_type="confirmatory_claim_authority",
            origin=(
                "claim-scoped live replay of confirmatory timeline and custody authority"
            ),
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=(
                "scientist-one",
                "record-confirmatory-claim-authority",
            ),
            parent_artifacts=(self.fixture.claim_graph_hash,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        substitutions = (
            ("another-run", "claim-main", self.fixture.claim_graph_hash),
            (run_id, "claim-other", self.fixture.claim_graph_hash),
            (run_id, "claim-main", digest("other-claim-graph")),
        )
        for expected_run, expected_claim, expected_graph in substitutions:
            with self.subTest(
                run=expected_run,
                claim=expected_claim,
                graph=expected_graph,
            ), self.assertRaises(ValidationError):
                require_confirmatory_claim_authority(
                    self.fixture.registry,
                    self.fixture.ledger,
                    authority_artifact_hash=forged.sha256,
                    expected_run_id=expected_run,
                    expected_claim_id=expected_claim,
                    expected_claim_graph_artifact_hash=expected_graph,
                )

    def test_required_numeric_assertion_cannot_be_omitted(self) -> None:
        result = verify_paper(
            replace(self.fixture.candidate, numeric_assertions=()),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(HardBlocker.TABLE_PROSE_CONTRADICTION, result.blockers)
        self.assertIn(
            f"missing_required_metric:claim-main:{self.fixture.bundle.metrics[0].metric_id}",
            result.discrepancies,
        )

    def test_caller_metric_alias_cannot_widen_paper_authority(self) -> None:
        extra_metric = replace(
            self.fixture.bundle.metrics[0],
            metric_id="unused-canonical-metric",
        )
        with self.assertRaisesRegex(
            ValidationError,
            "metric identity, units, direction, or raw source conflicts",
        ):
            rebuild_authoritative_bundle(
                self.fixture,
                metrics=(*self.fixture.bundle.metrics, extra_metric),
            )
        with self.assertRaisesRegex(
            ValidationError,
            "canonical Result value bindings",
        ):
            rebuild_authoritative_bundle(
                self.fixture,
                metrics=self.fixture.bundle.metrics[:-1],
            )
        laundered_tolerance = replace(
            self.fixture.bundle.metrics[0],
            tolerance=1_000_000.0,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "metric identity, units, direction, or raw source conflicts",
        ):
            rebuild_authoritative_bundle(
                self.fixture,
                metrics=(laundered_tolerance, *self.fixture.bundle.metrics[1:]),
            )

    def test_required_reference_cannot_be_omitted_from_claim_and_inventory(self) -> None:
        claim = replace(self.fixture.candidate.claims[0], citation_ids=())
        result = verify_paper(
            replace(self.fixture.candidate, claims=(claim,), references=()),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(HardBlocker.FABRICATED_OR_UNSUPPORTED_REFERENCE, result.blockers)
        self.assertTrue(
            any(item.startswith("missing_required_reference:claim-main:") for item in result.discrepancies)
        )

    def test_required_method_code_binding_cannot_be_omitted(self) -> None:
        result = verify_paper(
            replace(self.fixture.candidate, method_code_bindings=()),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(HardBlocker.METHOD_CODE_CONTRADICTION, result.blockers)
        self.assertIn("missing_required_method_code:claim-main", result.discrepancies)

    def test_required_generated_asset_cannot_be_omitted(self) -> None:
        result = verify_paper(
            replace(self.fixture.candidate, assets=()),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(HardBlocker.TABLE_PROSE_CONTRADICTION, result.blockers)
        self.assertIn(
            f"missing_required_asset:claim-main:{self.fixture.asset_hash}",
            result.discrepancies,
        )

    def test_caller_cannot_omit_canonical_method_binding_from_bundle(self) -> None:
        with self.assertRaisesRegex(
            ValidationError,
            "method/code bindings differ from canonical claim requirements",
        ):
            build_authoritative_research_bundle(
                self.fixture.registry,
                ledger=self.fixture.ledger,
                run_id=self.fixture.bundle.run_id,
                research_state_hash=self.fixture.bundle.research_state_hash,
                claim_graph_hash=self.fixture.bundle.claim_graph_hash,
                central_claim_ids=self.fixture.bundle.central_claim_ids,
                authoritative_evidence_hashes=(
                    self.fixture.bundle.authoritative_evidence_hashes
                ),
                metrics=self.fixture.bundle.metrics,
                method_code_bindings=(),
                required_baselines_complete=True,
                leakage_resolved=True,
                evaluator_exploitation_resolved=True,
                statistics_valid=True,
                novelty_supported=True,
                selection_integrity_valid=True,
                clean_reproduction_passed=True,
                soundness_assessment_hash=self.fixture.bundle.soundness_assessment_hash,
                external_validation_complete=True,
            )

    def test_legacy_self_asserted_bundle_without_registry_fails_closed(self) -> None:
        result = verify_paper(self.fixture.candidate, legacy_placeholder_bundle())
        self.assertFalse(result.passed)
        self.assertEqual(result.blockers, (HardBlocker.UNRESOLVED_AUTHORITY,))
        self.assertEqual(result.discrepancies, ("authoritative_registry_required",))

    def test_self_asserted_eligibility_or_strength_cannot_override_registry(self) -> None:
        authority = self.fixture.bundle.claims[0]
        with self.assertRaises(ValidationError):
            replace(authority, scientific_writer_eligible=True)

        forged_claim = replace(
            self.fixture.candidate.claims[0],
            text="A stronger rewritten claim not present in canonical state.",
            strength=ClaimStrength.STRONG,
            evidence_hashes=(self.fixture.result_hash,),
            evidence_sources=(
                EvidenceSourceBinding(
                    EvidenceKind.RESULT,
                    self.fixture.result_hash,
                    (self.fixture.result_hash,),
                ),
            ),
        )
        result = verify_paper(
            replace(self.fixture.candidate, claims=(forged_claim,)),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(HardBlocker.UNSUPPORTED_CENTRAL_CLAIM, result.blockers)
        self.assertIn("claim_text_mismatch:claim-main", result.discrepancies)
        self.assertIn("claim_strength_mismatch:claim-main", result.discrepancies)
        self.assertIn("claim_evidence_mismatch:claim-main", result.discrepancies)

    def test_positive_selection_integrity_requires_executed_challenger_reviews(self) -> None:
        bundle = self.fixture.bundle
        with self.assertRaises(ValidationError):
            build_authoritative_research_bundle(
                self.fixture.registry,
                ledger=self.fixture.ledger,
                run_id=bundle.run_id,
                research_state_hash=bundle.research_state_hash,
                claim_graph_hash=bundle.claim_graph_hash,
                central_claim_ids=bundle.central_claim_ids,
                authoritative_evidence_hashes=bundle.authoritative_evidence_hashes,
                metrics=bundle.metrics,
                method_code_bindings=bundle.method_code_bindings,
                required_baselines_complete=bundle.required_baselines_complete,
                leakage_resolved=bundle.leakage_resolved,
                evaluator_exploitation_resolved=(
                    bundle.evaluator_exploitation_resolved
                ),
                statistics_valid=bundle.statistics_valid,
                novelty_supported=bundle.novelty_supported,
                selection_integrity_valid=True,
                clean_reproduction_passed=bundle.clean_reproduction_passed,
                soundness_assessment_hash=bundle.soundness_assessment_hash,
                external_validation_complete=bundle.external_validation_complete,
            )

    def test_required_limitations_are_derived_from_review_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            fixture = authoritative_fixture(
                root,
                untested_categories=(ChallengeCategory.EXPERIMENTAL_DESIGN,),
                selection_integrity_valid=False,
            )
            self.assertIn(
                "This Challenger category remains untested.",
                fixture.bundle.required_limitations,
            )
            self.assertTrue(
                set(fixture.bundle.required_limitations).issubset(
                    fixture.candidate.limitations
                )
            )

    def test_wrong_metric_value_unit_and_direction_fail_closed(self) -> None:
        candidate = self.fixture.candidate
        assertion = replace(
            candidate.numeric_assertions[0],
            value=75.0,
            unit="percent",
            direction=MetricDirection.LOWER_IS_BETTER,
        )
        result = verify_paper(
            replace(candidate, numeric_assertions=(assertion,)),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(HardBlocker.TABLE_PROSE_CONTRADICTION, result.blockers)
        self.assertTrue(any("metric_unit_mismatch" in item for item in result.discrepancies))

    def test_metadata_only_reference_cannot_support_a_claim(self) -> None:
        candidate = self.fixture.candidate
        weak = replace(candidate.references[0], verification_depth=ReferenceDepth.LEVEL_2)
        result = verify_paper(
            replace(candidate, references=(weak,)),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(HardBlocker.FABRICATED_OR_UNSUPPORTED_REFERENCE, result.blockers)

    def test_surrounding_context_contradiction_blocks_reference(self) -> None:
        candidate = self.fixture.candidate
        contradiction = replace(candidate.references[0], contradictory_context=True)
        result = verify_paper(
            replace(candidate, references=(contradiction,)),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(HardBlocker.FABRICATED_OR_UNSUPPORTED_REFERENCE, result.blockers)

    def test_method_code_and_asset_parent_mismatch_fail_closed(self) -> None:
        candidate = self.fixture.candidate
        bad_asset = replace(candidate.assets[0], authoritative_parent_hashes=(digest("invented"),))
        bad_binding = replace(
            candidate.method_code_bindings[0],
            code_artifact_hash=digest("other-code"),
        )
        result = verify_paper(
            replace(candidate, method_code_bindings=(bad_binding,), assets=(bad_asset,)),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(HardBlocker.METHOD_CODE_CONTRADICTION, result.blockers)
        self.assertIn(HardBlocker.TABLE_PROSE_CONTRADICTION, result.blockers)

    def test_caller_cannot_widen_asset_authority_with_unrelated_frozen_artifacts(self) -> None:
        unrelated = _put_json(
            self.fixture.registry,
            {"unrelated": True},
            "unrelated_frozen_input",
            Role.STATISTICIAN,
        )
        unrelated_table = self.fixture.registry.put_bytes(
            b"unrelated,value\nfixture,1\n",
            logical_type="results_table",
            origin="paper-authority-test",
            creator_role=Role.STATISTICIAN,
            parent_artifacts=(unrelated.sha256,),
            mime_type="text/csv",
        )
        widened_bundle = replace(
            self.fixture.bundle,
            authoritative_evidence_hashes=(
                *self.fixture.bundle.authoritative_evidence_hashes,
                unrelated.sha256,
                unrelated_table.sha256,
            ),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "exact consumed authority",
        ):
            rebuild_authoritative_bundle(
                self.fixture,
                authoritative_evidence_hashes=(
                    *self.fixture.bundle.authoritative_evidence_hashes,
                    unrelated.sha256,
                    unrelated_table.sha256,
                ),
            )
        widened_asset = GeneratedAsset(
            "table-unrelated",
            "TABLE",
            unrelated_table.sha256,
            (unrelated.sha256,),
        )
        result = verify_paper(
            replace(self.fixture.candidate, assets=(widened_asset,)),
            widened_bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertEqual(result.blockers, (HardBlocker.UNRESOLVED_AUTHORITY,))

    def test_related_but_unused_authority_and_extra_inventory_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "exact consumed authority"):
            rebuild_authoritative_bundle(
                self.fixture,
                authoritative_evidence_hashes=tuple(
                    reversed(self.fixture.bundle.authoritative_evidence_hashes)
                ),
            )
        with self.assertRaisesRegex(ValidationError, "exact consumed authority"):
            rebuild_authoritative_bundle(
                self.fixture,
                authoritative_evidence_hashes=(
                    *self.fixture.bundle.authoritative_evidence_hashes,
                    self.fixture.bundle.research_state_hash,
                ),
            )

        extra_reference = replace(
            self.fixture.candidate.references[0],
            citation_id="unused-background-reference",
            supported_claim_ids=(),
        )
        reference_result = verify_paper(
            replace(
                self.fixture.candidate,
                references=(*self.fixture.candidate.references, extra_reference),
            ),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(
            HardBlocker.FABRICATED_OR_UNSUPPORTED_REFERENCE,
            reference_result.blockers,
        )
        self.assertIn(
            "paper_reference_inventory_does_not_match",
            reference_result.discrepancies,
        )

        extra_asset = replace(
            self.fixture.candidate.assets[0],
            asset_id="duplicate-result-table",
        )
        asset_result = verify_paper(
            replace(
                self.fixture.candidate,
                assets=(*self.fixture.candidate.assets, extra_asset),
            ),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(HardBlocker.TABLE_PROSE_CONTRADICTION, asset_result.blockers)
        self.assertIn(
            "paper_asset_inventory_does_not_match",
            asset_result.discrepancies,
        )

    def test_missing_limitations_or_bundle_binding_blocks_promotion(self) -> None:
        candidate = self.fixture.candidate
        result = verify_paper(
            replace(candidate, limitations=(), source_bundle_hashes=(digest("state"),)),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(HardBlocker.UNSUPPORTED_CENTRAL_CLAIM, result.blockers)
        widened_sources = verify_paper(
            replace(
                candidate,
                source_bundle_hashes=(
                    *candidate.source_bundle_hashes,
                    digest("unused-paper-source-bundle"),
                ),
            ),
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertIn(
            "paper_is_not_bound_to_complete_authoritative_bundle",
            widened_sources.discrepancies,
        )

    def test_every_policy_hard_blocker_overrides_presentation(self) -> None:
        toggles = {
            "required_baselines_complete": HardBlocker.OMITTED_REQUIRED_BASELINE,
            "leakage_resolved": HardBlocker.UNRESOLVED_LEAKAGE,
            "evaluator_exploitation_resolved": HardBlocker.EVALUATOR_EXPLOITATION,
            "statistics_valid": HardBlocker.INVALID_STATISTICS,
            "novelty_supported": HardBlocker.UNSUPPORTED_NOVELTY,
            "selection_integrity_valid": HardBlocker.SELECTION_BIAS,
            "clean_reproduction_passed": HardBlocker.FAILED_CLEAN_REPRODUCTION,
        }
        for field, blocker in toggles.items():
            with self.subTest(field=field):
                bundle = replace(self.fixture.bundle, **{field: False})
                self.assertIn(
                    blocker,
                    verify_paper(
                        self.fixture.candidate,
                        bundle,
                        self.fixture.registry,
                        self.fixture.ledger,
                    ).blockers,
                )

    def test_self_asserted_soundness_verdict_cannot_override_receipts(self) -> None:
        bundle = replace(
            self.fixture.bundle,
            soundness_verdict=SoundnessVerdict.MAJOR_REVISION,
        )
        result = verify_paper(
            self.fixture.candidate,
            bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        self.assertEqual(result.blockers, (HardBlocker.UNRESOLVED_AUTHORITY,))

    def test_venue_hard_blocker_overrides_perfect_scores(self) -> None:
        bundle = replace(self.fixture.bundle, clean_reproduction_passed=False)
        verification = verify_paper(
            self.fixture.candidate,
            bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        profile = default_venue_profiles()[0]
        scores = {name: 1.0 for name in READINESS_DIMENSIONS}
        result = assess_venue(profile, verification, scores, external_validation_complete=True, rationale="Perfect prose cannot waive evidence failures.")
        self.assertEqual(result.classification, VenueFit.NOT_READY)

    def test_external_validation_gap_remains_not_ready_without_live_receipts(self) -> None:
        bundle = self.fixture.bundle
        verification = verify_paper(
            self.fixture.candidate,
            bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        scores = {name: 0.95 for name in READINESS_DIMENSIONS}
        profile = default_venue_profiles()[0]
        authority = venue_authority_fixture(self.fixture, profile, bundle=bundle)
        result = assess_venue(
            profile,
            verification,
            scores,
            external_validation_complete=True,
            rationale="Live validation is unavailable.",
            registry=self.fixture.registry,
            ledger=self.fixture.ledger,
            candidate=self.fixture.candidate,
            bundle=bundle,
            run_id=bundle.run_id,
            candidate_artifact_hash=authority.candidate_artifact_hash,
            bundle_artifact_hash=authority.bundle_artifact_hash,
            profile_artifact_hash=authority.profile_artifact_hash,
            readiness_manifest_hash=authority.readiness_manifest_hash,
        )
        self.assertEqual(result.classification, VenueFit.NOT_READY)
        self.assertIn(HardBlocker.VENUE_REQUIREMENTS_UNRESOLVED, result.hard_blockers)
        self.assertEqual(
            result.dimension_scores,
            tuple((name, 0.0) for name in READINESS_DIMENSIONS),
        )

    def test_venue_profiles_cover_the_four_required_families(self) -> None:
        profiles = default_venue_profiles()
        self.assertEqual({item.family for item in profiles}, set(VenueFamily))

    def test_high_caller_scores_cannot_promote_an_offline_candidate(self) -> None:
        verification = verify_paper(
            self.fixture.candidate,
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        scores = {name: 0.95 for name in READINESS_DIMENSIONS}
        profile = default_venue_profiles()[0]
        authority = venue_authority_fixture(self.fixture, profile)
        self.assertEqual(
            self.fixture.registry.get_metadata(
                authority.manuscript_artifact_hash
            ).parent_artifacts[:3],
            (
                authority.candidate_artifact_hash,
                authority.bundle_artifact_hash,
                authority.profile_artifact_hash,
            ),
        )
        self.assertEqual(
            self.fixture.registry.get_metadata(
                authority.readiness_manifest_hash
            ).parent_artifacts[:4],
            (
                authority.candidate_artifact_hash,
                authority.bundle_artifact_hash,
                authority.profile_artifact_hash,
                authority.manuscript_artifact_hash,
            ),
        )
        result = assess_venue(
            profile,
            verification,
            scores,
            external_validation_complete=True,
            rationale="This is a candidacy classification, never an acceptance guarantee.",
            registry=self.fixture.registry,
            ledger=self.fixture.ledger,
            candidate=self.fixture.candidate,
            bundle=self.fixture.bundle,
            run_id=self.fixture.bundle.run_id,
            candidate_artifact_hash=authority.candidate_artifact_hash,
            bundle_artifact_hash=authority.bundle_artifact_hash,
            profile_artifact_hash=authority.profile_artifact_hash,
            readiness_manifest_hash=authority.readiness_manifest_hash,
        )
        self.assertEqual(result.classification, VenueFit.NOT_READY)
        self.assertIn(HardBlocker.VENUE_REQUIREMENTS_UNRESOLVED, result.hard_blockers)
        self.assertEqual(
            result.dimension_scores,
            tuple((name, 0.0) for name in READINESS_DIMENSIONS),
        )

    def test_v1_venue_inventory_is_rejected_before_final_authority(self) -> None:
        """Inventory-only readiness remains a direct NOT_READY diagnostic."""

        profile = default_venue_profiles()[0]
        # Venue-review custody cannot manufacture external scientific validation.
        bundle = self.fixture.bundle
        candidate = replace(
            self.fixture.candidate,
            candidate_id="paper-fixture-final-venue",
        )
        authority = venue_authority_fixture(
            self.fixture,
            profile,
            bundle=bundle,
            candidate=candidate,
        )
        registry = self.fixture.registry
        ledger = self.fixture.ledger
        assert bundle.run_id is not None
        verification = verify_paper(candidate, bundle, registry, ledger)
        result = assess_venue(
            profile,
            verification,
            {name: 1.0 for name in READINESS_DIMENSIONS},
            external_validation_complete=True,
            rationale="A structural inventory is not external validation.",
            registry=registry,
            ledger=ledger,
            candidate=candidate,
            bundle=bundle,
            run_id=bundle.run_id,
            candidate_artifact_hash=authority.candidate_artifact_hash,
            bundle_artifact_hash=authority.bundle_artifact_hash,
            profile_artifact_hash=authority.profile_artifact_hash,
            readiness_manifest_hash=authority.readiness_manifest_hash,
        )
        self.assertEqual(result.classification, VenueFit.NOT_READY)
        self.assertIn(HardBlocker.VENUE_REQUIREMENTS_UNRESOLVED, result.hard_blockers)
        self.assertEqual(
            result.dimension_scores,
            tuple((name, 0.0) for name in READINESS_DIMENSIONS),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "structural venue inventory cannot authorize requirement satisfaction",
        ):
            register_venue_requirement_receipt(
                registry,
                ledger,
                candidate,
                bundle,
                profile,
                receipt_id="venue-requirement-code",
                run_id=bundle.run_id,
                candidate_artifact_hash=authority.candidate_artifact_hash,
                bundle_artifact_hash=authority.bundle_artifact_hash,
                profile_artifact_hash=authority.profile_artifact_hash,
                readiness_manifest_hash=authority.readiness_manifest_hash,
                requirement="code",
                semantic_judgment_hash=None,
            )

    def test_perfect_caller_scores_and_boolean_cannot_replace_venue_authority(self) -> None:
        verification = verify_paper(
            self.fixture.candidate,
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        scores = {name: 1.0 for name in READINESS_DIMENSIONS}
        profile = VenueProfile(
            "caller-only-ml",
            VenueFamily.ML_AI,
            ("methods", "results"),
            ("code",),
        )
        result = assess_venue(
            profile,
            verification,
            scores,
            external_validation_complete=True,
            rationale="Caller-only readiness is not scientific authority.",
        )
        self.assertEqual(result.classification, VenueFit.NOT_READY)
        self.assertIn(HardBlocker.VENUE_REQUIREMENTS_UNRESOLVED, result.hard_blockers)

    def test_wrong_profile_or_candidate_artifact_forces_not_ready(self) -> None:
        verification = verify_paper(
            self.fixture.candidate,
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        scores = {name: 1.0 for name in READINESS_DIMENSIONS}
        profile = default_venue_profiles()[0]
        authority = venue_authority_fixture(self.fixture, profile)
        substituted_profile = replace(profile, profile_id="substituted-ml")
        wrong_profile = assess_venue(
            substituted_profile,
            verification,
            scores,
            external_validation_complete=True,
            rationale="A manifest for another profile cannot be substituted.",
            registry=self.fixture.registry,
            ledger=self.fixture.ledger,
            candidate=self.fixture.candidate,
            bundle=self.fixture.bundle,
            run_id=self.fixture.bundle.run_id,
            candidate_artifact_hash=authority.candidate_artifact_hash,
            bundle_artifact_hash=authority.bundle_artifact_hash,
            profile_artifact_hash=authority.profile_artifact_hash,
            readiness_manifest_hash=authority.readiness_manifest_hash,
        )
        self.assertEqual(wrong_profile.classification, VenueFit.NOT_READY)

        profile_payload = safe_json_loads(
            self.fixture.registry.get_bytes(authority.profile_artifact_hash)
        )
        with self.assertRaises(FrozenArtifactError):
            _put_json(
                self.fixture.registry,
                profile_payload,
                "approved_venue_profile",
                Role.PROTOCOL_DESIGNER,
            )

        other_candidate = replace(
            self.fixture.candidate,
            candidate_id="other-paper-fixture",
        )
        other_record = _put_json(
            self.fixture.registry,
            {"candidate": _jsonable(other_candidate)},
            "paper_candidate",
            Role.PAPER_WRITER,
            (authority.bundle_artifact_hash, self.fixture.asset_hash),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "registered paper candidate differs from the typed candidate",
        ):
            _resolve_candidate_bundle_artifacts(
                self.fixture.registry,
                self.fixture.candidate,
                self.fixture.bundle,
                other_record.sha256,
                authority.bundle_artifact_hash,
            )
        wrong_candidate = assess_venue(
            profile,
            verification,
            scores,
            external_validation_complete=True,
            rationale="A candidate artifact for another candidate cannot be substituted.",
            registry=self.fixture.registry,
            ledger=self.fixture.ledger,
            candidate=self.fixture.candidate,
            bundle=self.fixture.bundle,
            run_id=self.fixture.bundle.run_id,
            candidate_artifact_hash=other_record.sha256,
            bundle_artifact_hash=authority.bundle_artifact_hash,
            profile_artifact_hash=authority.profile_artifact_hash,
            readiness_manifest_hash=authority.readiness_manifest_hash,
        )
        self.assertEqual(wrong_candidate.classification, VenueFit.NOT_READY)

        extra_parent = _put_json(
            self.fixture.registry,
            {"extra": "candidate-parent"},
            "paper_test_extra_parent",
            Role.ORCHESTRATOR,
        )
        widened_candidate_input = replace(
            self.fixture.candidate,
            candidate_id="widened-paper-fixture",
        )
        widened_candidate_record = _put_json(
            self.fixture.registry,
            {"candidate": _jsonable(widened_candidate_input)},
            "paper_candidate",
            Role.PAPER_WRITER,
            (
                authority.bundle_artifact_hash,
                self.fixture.asset_hash,
                extra_parent.sha256,
            ),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "registered paper candidate has substituted authority parents",
        ):
            _resolve_candidate_bundle_artifacts(
                self.fixture.registry,
                widened_candidate_input,
                self.fixture.bundle,
                widened_candidate_record.sha256,
                authority.bundle_artifact_hash,
            )
        widened_candidate = assess_venue(
            profile,
            verification,
            scores,
            external_validation_complete=True,
            rationale="An extra candidate parent cannot widen venue authority.",
            registry=self.fixture.registry,
            ledger=self.fixture.ledger,
            candidate=widened_candidate_input,
            bundle=self.fixture.bundle,
            run_id=self.fixture.bundle.run_id,
            candidate_artifact_hash=widened_candidate_record.sha256,
            bundle_artifact_hash=authority.bundle_artifact_hash,
            profile_artifact_hash=authority.profile_artifact_hash,
            readiness_manifest_hash=authority.readiness_manifest_hash,
        )
        self.assertEqual(widened_candidate.classification, VenueFit.NOT_READY)

        other_bundle = replace(
            self.fixture.bundle,
            external_validation_complete=False,
        )
        other_bundle_record = _put_json(
            self.fixture.registry,
            {"bundle": _jsonable(other_bundle)},
            "authoritative_research_bundle",
            Role.ORCHESTRATOR,
            (
                other_bundle.research_state_hash,
                other_bundle.claim_graph_hash,
                other_bundle.soundness_assessment_hash,
                *other_bundle.confirmatory_claim_authority_hashes,
                *other_bundle.authoritative_evidence_hashes,
            ),
        )
        candidate_for_other_bundle_input = replace(
            self.fixture.candidate,
            candidate_id="paper-fixture-other-bundle",
        )
        candidate_for_other_bundle = _put_json(
            self.fixture.registry,
            {"candidate": _jsonable(candidate_for_other_bundle_input)},
            "paper_candidate",
            Role.PAPER_WRITER,
            (other_bundle_record.sha256, self.fixture.asset_hash),
        )
        wrong_run = assess_venue(
            profile,
            verification,
            scores,
            external_validation_complete=True,
            rationale="A bundle artifact from another authority run cannot be substituted.",
            registry=self.fixture.registry,
            ledger=self.fixture.ledger,
            candidate=self.fixture.candidate,
            bundle=self.fixture.bundle,
            run_id=self.fixture.bundle.run_id,
            candidate_artifact_hash=candidate_for_other_bundle.sha256,
            bundle_artifact_hash=other_bundle_record.sha256,
            profile_artifact_hash=authority.profile_artifact_hash,
            readiness_manifest_hash=authority.readiness_manifest_hash,
        )
        self.assertEqual(wrong_run.classification, VenueFit.NOT_READY)

    def test_forged_or_malformed_venue_manifest_forces_not_ready(self) -> None:
        verification = verify_paper(
            self.fixture.candidate,
            self.fixture.bundle,
            self.fixture.registry,
            self.fixture.ledger,
        )
        scores = {name: 1.0 for name in READINESS_DIMENSIONS}
        profile = default_venue_profiles()[0]
        authority = venue_authority_fixture(self.fixture, profile)
        manifest_value = safe_json_loads(
            self.fixture.registry.get_bytes(authority.readiness_manifest_hash)
        )
        assert isinstance(manifest_value, dict)
        manifest_value["profile_sha256"] = digest("forged-profile")
        forged = _put_json(
            self.fixture.registry,
            manifest_value,
            "venue_readiness_manifest",
            Role.SCIENTIFIC_REVIEWER,
            self.fixture.registry.get_metadata(
                authority.readiness_manifest_hash
            ).parent_artifacts,
        )
        result = assess_venue(
            profile,
            verification,
            scores,
            external_validation_complete=True,
            rationale="A structurally valid semantic manifest forgery is not authority.",
            registry=self.fixture.registry,
            ledger=self.fixture.ledger,
            candidate=self.fixture.candidate,
            bundle=self.fixture.bundle,
            run_id=self.fixture.bundle.run_id,
            candidate_artifact_hash=authority.candidate_artifact_hash,
            bundle_artifact_hash=authority.bundle_artifact_hash,
            profile_artifact_hash=authority.profile_artifact_hash,
            readiness_manifest_hash=forged.sha256,
        )
        self.assertEqual(result.classification, VenueFit.NOT_READY)
        self.assertIn(HardBlocker.VENUE_REQUIREMENTS_UNRESOLVED, result.hard_blockers)

    def test_missing_methods_or_code_cannot_be_registered_as_ready(self) -> None:
        profile = default_venue_profiles()[0]
        authority = venue_authority_fixture(self.fixture, profile)
        with self.assertRaisesRegex(ValidationError, "methods section omits"):
            register_paper_manuscript(
                self.fixture.registry,
                self.fixture.candidate,
                self.fixture.bundle,
                profile,
                run_id=self.fixture.bundle.run_id,
                candidate_artifact_hash=authority.candidate_artifact_hash,
                bundle_artifact_hash=authority.bundle_artifact_hash,
                profile_artifact_hash=authority.profile_artifact_hash,
                sections=tuple(
                    ManuscriptSection(
                        section,
                        (self.fixture.method_hash,)
                        if section == "methods"
                        else (
                            tuple(sorted((self.fixture.result_hash, self.fixture.asset_hash)))
                            if section == "results"
                            else (self.fixture.claim_graph_hash,)
                        ),
                    )
                    for section in profile.required_sections
                ),
                artifact_bindings=tuple(
                    ArtifactReadinessBinding(
                        requirement,
                        (self.fixture.code_hash,)
                        if requirement == "code"
                        else (self.fixture.result_hash,),
                    )
                    for requirement in profile.artifact_requirements
                ),
            )
        with self.assertRaisesRegex(ValidationError, "code inventory differs"):
            register_paper_manuscript(
                self.fixture.registry,
                self.fixture.candidate,
                self.fixture.bundle,
                profile,
                run_id=self.fixture.bundle.run_id,
                candidate_artifact_hash=authority.candidate_artifact_hash,
                bundle_artifact_hash=authority.bundle_artifact_hash,
                profile_artifact_hash=authority.profile_artifact_hash,
                sections=tuple(
                    ManuscriptSection(
                        section,
                        tuple(sorted((self.fixture.method_hash, self.fixture.code_hash)))
                        if section == "methods"
                        else (
                            tuple(sorted((self.fixture.result_hash, self.fixture.asset_hash)))
                            if section == "results"
                            else (self.fixture.claim_graph_hash,)
                        ),
                    )
                    for section in profile.required_sections
                ),
                artifact_bindings=tuple(
                    ArtifactReadinessBinding(
                        requirement,
                        (self.fixture.result_hash,),
                    )
                    for requirement in profile.artifact_requirements
                ),
            )


if __name__ == "__main__":
    unittest.main()
