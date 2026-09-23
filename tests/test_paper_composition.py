from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.claims import ClaimEvidenceUse
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.gates import SoundnessVerdict
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import MacroState, utc_now
from scientist_one.paper_composition import (
    LEGACY_RENDERER_VERSION,
    PaperCompositionInput,
    PaperManuscriptRevision,
    RENDERER_VERSION,
    _derive_composition_input,
    _event_admitted_revision_identity_hashes,
    _replay_immutable_revision,
    _require_historical_predecessor_lineage,
    _require_revision_event,
    _revision_event_metadata,
    _validate_revision_timestamp,
    _validate_source_map,
    register_paper_manuscript_revision,
    render_paper_composition,
    require_paper_manuscript_revision,
)
from scientist_one.paper_pipeline import (
    ArtifactReadinessBinding,
    AuthoritativeClaim,
    AuthoritativeResearchBundle,
    ClaimPaperRequirements,
    HardBlocker,
    ManuscriptSection,
    PaperCandidate,
    PaperClaim,
    PaperVerification,
    READINESS_DIMENSIONS,
    VenueFamily,
    VenueFit,
    VenueProfile,
    VenueReadinessManifest,
    _read_paper_manuscript,
    _resolve_venue_dimension_assessment,
    _resolve_venue_requirement_receipt,
    _revision_sections_for_profile,
    _validate_revision_section_coverage,
    assess_venue,
    default_venue_profiles,
    register_venue_readiness_manifest,
)
from scientist_one.paper_composition import _validate_composition_authority
from scientist_one.research_state import ClaimSemanticsEvidenceScope, ClaimStrength, ClaimType
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes, safe_json_loads


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def fixture_input() -> PaperCompositionInput:
    claim_source = digest("claim-state")
    semantics = digest("claim-semantics")
    evidence = digest("claim-evidence")
    result = digest("result")
    reference = digest("reference")
    judgment = digest("judgment")
    asset = digest("asset")
    asset_parent = digest("asset-parent")
    method = digest("method")
    code = digest("code")
    method_state = digest("method-state")
    implementation_state = digest("implementation-state")
    soundness = digest("soundness")
    finding = digest("finding")
    review = digest("review")
    return PaperCompositionInput(
        run_id="fixture-run",
        manuscript_id="fixture-manuscript",
        revision=1,
        predecessor_revision_artifact_hash=None,
        candidate_id="fixture-candidate",
        candidate_artifact_hash=digest("candidate"),
        bundle_artifact_hash=digest("bundle"),
        verification_artifact_hash=digest("paper-verification"),
        bundle_issuance_event_id="arb-fixture",
        bundle_issuance_event_hash=digest("bundle-event"),
        bundle_issuance_event_index=3,
        historical_ledger_head_hash=digest("historical-head"),
        historical_ledger_event_count=4,
        research_state_binding={
            "snapshot_artifact_hash": digest("snapshot"),
            "state_artifact_hashes": [digest("state")],
            "ledger_head_hash": digest("state-head"),
            "ledger_event_count": 2,
            "code_version": "fixture-code-v1",
            "configuration_hash": digest("configuration"),
        },
        authority_scope="SYSTEM_FIXTURE",
        claims=(
            {
                "claim_id": "claim-1",
                "text": "The exact canonical claim text is copied without paraphrase.",
                "scope": "Pure renderer contract evidence only.",
                "claim_type": "QUALITATIVE",
                "expressed_strength": "QUALIFIED",
                "permitted_strength": "QUALIFIED",
                "claim_state_artifact_hash": claim_source,
                "claim_semantics_artifact_hash": semantics,
                "evidence_hashes": [evidence],
                "dependency_claim_ids": [],
                "source_artifact_ids": [evidence],
                "central": True,
            },
        ),
        numeric_assertions=(
            {
                "assertion_id": "assertion-1",
                "claim_id": "claim-1",
                "metric_id": "metric-1",
                "value": 0.75,
                "unit": "fraction",
                "direction": "HIGHER_IS_BETTER",
                "source_artifact_hash": result,
            },
        ),
        references=(
            {
                "citation_id": "citation-1",
                "reference_artifact_hash": reference,
                "verification_depth": "LEVEL_5",
                "supported_claim_ids": ["claim-1"],
                "contradictory_context": False,
                "source_citation_evidence_artifact_hash": digest("citation-evidence"),
                "citation_node_id": "citation-node-1",
                "passage_sha256": digest("passage"),
                "passage_locator_sha256": digest("locator"),
                "context_sha256": digest("context"),
                "semantic_judgment_artifact_hash": judgment,
            },
        ),
        assets=(
            {
                "asset_id": "table-1",
                "kind": "TABLE",
                "artifact_hash": asset,
                "authoritative_parent_hashes": [asset_parent],
            },
        ),
        method_code_bindings=(
            {
                "method_artifact_hash": method,
                "code_artifact_hash": code,
                "method_state_artifact_hash": method_state,
                "implementation_state_artifact_hash": implementation_state,
                "authority_sources": [],
            },
        ),
        required_limitations=("This is a required limitation copied exactly.",),
        soundness={
            "assessment_artifact_hash": soundness,
            "assessment_id": "soundness-1",
            "verdict": "CONDITIONAL_PASS",
            "reason": "The stated condition remains.",
            "dimension_statuses": [],
        },
        findings=(
            {
                "finding_artifact_hash": finding,
                "challenge_id": "challenge-1",
                "category": "EXTERNAL_VALIDITY",
                "severity": "MAJOR",
                "status": "UNRESOLVED",
                "target_claim_ids": ["claim-1"],
                "attack": "External validity remains bounded.",
                "resolution": None,
                "resolution_receipt_hash": None,
            },
        ),
        challenger_reviews=(
            {
                "review_artifact_hash": review,
                "review_id": "review-1",
                "category": "EXTERNAL_VALIDITY",
                "execution_status": "EXECUTED",
                "finding_artifact_hashes": [finding],
                "attack": "Test transfer beyond the measured scope.",
                "conclusion": "Transfer remains unresolved.",
            },
        ),
    )


class DeterministicRendererTests(unittest.TestCase):
    def test_golden_bytes_exact_claim_and_complete_source_map(self) -> None:
        value = fixture_input()
        first = render_paper_composition(value)
        second = render_paper_composition(value)
        self.assertEqual(first, second)
        self.assertEqual(RENDERER_VERSION, "deterministic-markdown/v2")
        self.assertEqual(
            hashlib.sha256(first.content_bytes).hexdigest(),
            "b8c87e8c1aa092f5bed1d35ee2c896836604ac401fa1e80bdd4e455a7eb85c6a",
        )
        text = first.content_bytes.decode()
        self.assertIn(value.claims[0]["text"], text)
        self.assertIn('"value":0.75', text)
        self.assertIn(value.required_limitations[0], text)
        self.assertIn(value.findings[0]["attack"], text)
        self.assertEqual(first.source_map[0].start_byte, 0)
        self.assertEqual(first.source_map[-1].end_byte, len(first.content_bytes))
        for left, right in zip(first.source_map, first.source_map[1:]):
            self.assertEqual(left.end_byte, right.start_byte)

        legacy = render_paper_composition(
            value,
            renderer_version=LEGACY_RENDERER_VERSION,
        )
        self.assertEqual(
            hashlib.sha256(legacy.content_bytes).hexdigest(),
            "3ea630116222386967c62e0e016edb138c27748056318484040da23d5354ec36",
        )
        self.assertEqual(
            legacy,
            render_paper_composition(
                value,
                renderer_version=LEGACY_RENDERER_VERSION,
            ),
        )
        with self.assertRaisesRegex(ValidationError, "version is unsupported"):
            render_paper_composition(
                value,
                renderer_version="deterministic-markdown/unknown",
            )

    def test_numeric_reference_asset_and_method_bindings_are_source_mapped(self) -> None:
        value = fixture_input()
        rendered = render_paper_composition(value)
        by_id = {item.block_id: item for item in rendered.source_map}
        self.assertEqual(by_id["result-numeric-1"].source_artifact_hashes, (value.numeric_assertions[0]["source_artifact_hash"],))
        self.assertIn(value.references[0]["reference_artifact_hash"], by_id["reference-1"].source_artifact_hashes)
        self.assertEqual(by_id["result-asset-1"].source_artifact_hashes, (value.assets[0]["artifact_hash"], value.assets[0]["authoritative_parent_hashes"][0]))
        self.assertEqual(len(by_id["method-1"].source_artifact_hashes), 4)
        self.assertEqual(
            by_id["reproducibility-body"].source_artifact_hashes,
            (
                value.bundle_artifact_hash,
                value.research_state_binding["snapshot_artifact_hash"],
                *value.research_state_binding["state_artifact_hashes"],
                *by_id["method-1"].source_artifact_hashes,
            ),
        )

    def test_tampered_content_or_source_map_is_rejected(self) -> None:
        rendered = render_paper_composition(fixture_input())
        with self.assertRaisesRegex(ValidationError, "cover every content byte"):
            _validate_source_map(rendered.content_bytes + b"x", rendered.source_map)
        broken = replace(rendered.source_map[1], start_byte=rendered.source_map[1].start_byte + 1)
        with self.assertRaisesRegex(ValidationError, "incomplete"):
            _validate_source_map(rendered.content_bytes, (rendered.source_map[0], broken, *rendered.source_map[2:]))

    def test_unknown_input_field_is_rejected(self) -> None:
        value = fixture_input().to_dict()
        value["caller_authored_scientific_field"] = "forbidden"
        with self.assertRaisesRegex(ValidationError, "unknown or missing"):
            PaperCompositionInput.from_dict(value)

    def test_fixture_label_is_honest_and_candidate_title_is_never_rendered(self) -> None:
        value = fixture_input()
        self.assertNotIn("title", value.to_dict())
        rendered = render_paper_composition(value).content_bytes.decode()
        self.assertTrue(rendered.startswith("# Evidence dossier\n\n"))
        self.assertIn(
            "Status: SYSTEM_FIXTURE / NOT_SCIENTIFIC_MANUSCRIPT / "
            "NOT_RELEASED / NOT_SUBMITTED",
            rendered,
        )
        self.assertNotIn("MANUSCRIPT_CANDIDATE", rendered)
        self.assertNotIn("Fixture candidate", rendered)
        with self.assertRaisesRegex(ValidationError, "unknown or missing"):
            PaperCompositionInput.from_dict(
                {**value.to_dict(), "title": "RELEASED: universal breakthrough"}
            )

    def test_markdown_control_text_is_rendered_as_inert_literals(self) -> None:
        attack = (
            "line one\n# Forged heading\nStatus: RELEASED\n"
            "``` break ```\n<script>alert(1)</script>\n"
            "![image](https://invalid.example/x) [link](https://invalid.example)"
        )
        base = fixture_input()
        claim = {**base.claims[0], "text": attack, "scope": attack}
        rendered = render_paper_composition(
            replace(base, claims=(claim,), required_limitations=(attack,))
        )
        text = rendered.content_bytes.decode()
        self.assertEqual(
            [line for line in text.splitlines() if line.startswith("#")],
            [
                "# Evidence dossier",
                "## Abstract",
                "## Introduction",
                "## Methods",
                "## Results",
                "## Registered references",
                "## Limitations",
                "## Reproducibility",
                "## Soundness and Challenger record",
            ],
        )
        self.assertEqual(
            [line for line in text.splitlines() if line.startswith("Status:")],
            [
                "Status: SYSTEM_FIXTURE / NOT_SCIENTIFIC_MANUSCRIPT / "
                "NOT_RELEASED / NOT_SUBMITTED"
            ],
        )
        self.assertNotIn("\n<script>", text)
        self.assertNotIn("\n![image]", text)
        self.assertNotIn("\n[link]", text)
        self.assertEqual(
            rendered,
            render_paper_composition(
                replace(base, claims=(claim,), required_limitations=(attack,))
            ),
        )

    def test_arbitrary_review_artifact_field_is_rejected(self) -> None:
        value = fixture_input().to_dict()
        value["review_input_artifact_hashes"] = [digest("caller-review")]
        with self.assertRaisesRegex(ValidationError, "unknown or missing"):
            PaperCompositionInput.from_dict(value)


class ProductionBoundaryTests(unittest.TestCase):
    def _inert_revision_case(
        self,
        root: str,
        *,
        revision_created_at: str | None = None,
    ):
        registry = ArtifactRegistry(root)
        ledger = EventLedger(root)
        configuration = digest("orphan-configuration")
        initial = ledger.record(
            run_id="fixture-run", actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.WRITE, requested_state_after=MacroState.WRITE,
            artifact_hashes=(), code_version="fixture-code-v1",
            configuration_hash=configuration, reason="establish inert test history",
            event_id="orphan-history", event_type="CHECKPOINT",
        )

        def put(label: str, logical_type: str, role: Role):
            return registry.put_bytes(
                label.encode(), logical_type=logical_type,
                origin="inert revision test", creator_role=role,
                mime_type="application/octet-stream",
            )

        candidate = put("candidate", "paper_candidate", Role.PAPER_WRITER)
        bundle = put("bundle", "authoritative_research_bundle", Role.ORCHESTRATOR)
        paper_verification = put(
            "paper-verification", "paper_verification", Role.SCIENTIFIC_REVIEWER
        )
        base = fixture_input()
        composition = replace(
            base, candidate_artifact_hash=candidate.sha256,
            bundle_artifact_hash=bundle.sha256,
            verification_artifact_hash=paper_verification.sha256,
            bundle_issuance_event_index=0,
            historical_ledger_head_hash=str(initial.event_hash),
            historical_ledger_event_count=1,
            research_state_binding={
                **base.research_state_binding,
                "configuration_hash": configuration,
            },
        )
        input_record = registry.put_bytes(
            canonical_json_bytes(composition.to_dict()) + b"\n",
            logical_type="paper_composition_input", origin="inert revision test",
            creator_role=Role.PAPER_WRITER, mime_type="application/json",
        )
        content_record = put(
            "content", "paper_manuscript_content", Role.PAPER_WRITER
        )
        composition_verification = put(
            "composition-verification", "paper_composition_verification",
            Role.SCIENTIFIC_REVIEWER,
        )
        revision = PaperManuscriptRevision(
            "fixture-run", "fixture-manuscript", 1, None,
            input_record.sha256, content_record.sha256,
            composition_verification.sha256, candidate.sha256, bundle.sha256,
            paper_verification.sha256, (), (),
        )
        parents = (
            input_record.sha256, content_record.sha256,
            composition_verification.sha256, candidate.sha256, bundle.sha256,
            paper_verification.sha256,
        )
        revision_record = registry.put_bytes(
            canonical_json_bytes(revision.to_dict()) + b"\n",
            logical_type="paper_manuscript_revision",
            origin="issued deterministic evidence-only manuscript revision",
            creator_role=Role.PAPER_WRITER,
            creation_command=(
                "scientist-one", "paper", "issue-manuscript-revision"
            ),
            parent_artifacts=parents, schema_version="1.0",
            mime_type="application/json",
            created_at=revision_created_at,
        )
        records = (
            input_record, content_record, composition_verification, revision_record
        )
        return registry, ledger, composition, revision, revision_record, records

    def _mechanical_historical_revision(
        self,
        registry: ArtifactRegistry,
        ledger: EventLedger,
        *,
        tag: str,
        revision_number: int,
        predecessor_hash: str | None,
        candidate_id: str = "lineage-candidate",
        renderer_version: str = RENDERER_VERSION,
        tamper_content: bool = False,
    ) -> SimpleNamespace:
        """Materialize an inert, exact revision contract without science claims."""

        for label in (
            "claim-state",
            "claim-semantics",
            "claim-evidence",
            "result",
            "reference",
            "citation-evidence",
            "judgment",
            "asset",
            "asset-parent",
            "method",
            "code",
            "method-state",
            "implementation-state",
            "soundness",
            "finding",
            "review",
            "state",
        ):
            registry.put_bytes(
                label.encode(),
                logical_type="mechanical_historical_source",
                origin="inert historical lineage fixture",
                creator_role=Role.ORCHESTRATOR,
            )
        candidate_record = registry.put_json(
            {"candidate": {"mechanical_fixture": tag}},
            logical_type="paper_candidate",
            origin="inert historical lineage fixture",
            creator_role=Role.PAPER_WRITER,
            mime_type="application/json",
        )
        bundle_record = registry.put_bytes(
            f"bundle-{tag}".encode(),
            logical_type="authoritative_research_bundle",
            origin="inert historical lineage fixture",
            creator_role=Role.ORCHESTRATOR,
        )
        paper_verification_record = registry.put_bytes(
            f"paper-verification-{tag}".encode(),
            logical_type="paper_verification",
            origin="inert historical lineage fixture",
            creator_role=Role.SCIENTIFIC_REVIEWER,
        )
        snapshot_record = registry.put_bytes(
            f"snapshot-{tag}".encode(),
            logical_type="research_state_snapshot",
            origin="inert historical lineage fixture",
            creator_role=Role.ORCHESTRATOR,
        )
        prior = ledger.last_event()
        state = prior.requested_state_after if prior is not None else MacroState.WRITE
        configuration_hash = digest("lineage-configuration")
        bundle_event = ledger.record(
            run_id="fixture-run",
            actor_role=Role.ORCHESTRATOR,
            state_before=state,
            requested_state_after=state,
            artifact_hashes=(bundle_record.sha256,),
            code_version="mechanical-fixture-code-v1",
            configuration_hash=configuration_hash,
            reason="bind an inert historical bundle fixture",
            event_id=f"arb-{bundle_record.sha256[:48]}",
            event_type="CHECKPOINT",
            metadata={"mechanical_fixture": True},
        )
        history = ledger.validate(raise_on_error=True)
        base = fixture_input()
        composition = replace(
            base,
            run_id="fixture-run",
            manuscript_id="lineage-manuscript",
            revision=revision_number,
            predecessor_revision_artifact_hash=predecessor_hash,
            candidate_id=candidate_id,
            candidate_artifact_hash=candidate_record.sha256,
            bundle_artifact_hash=bundle_record.sha256,
            verification_artifact_hash=paper_verification_record.sha256,
            bundle_issuance_event_id=bundle_event.event_id,
            bundle_issuance_event_hash=str(bundle_event.event_hash),
            bundle_issuance_event_index=history.event_count - 1,
            historical_ledger_head_hash=str(history.head_hash),
            historical_ledger_event_count=history.event_count,
            research_state_binding={
                **base.research_state_binding,
                "snapshot_artifact_hash": snapshot_record.sha256,
                "configuration_hash": configuration_hash,
                "code_version": "mechanical-fixture-code-v1",
            },
            authority_scope="SCIENTIFIC_EVIDENCE",
        )
        rendered = render_paper_composition(
            composition,
            renderer_version=renderer_version,
        )
        content = (
            rendered.content_bytes + b"hash-consistent splice\n"
            if tamper_content
            else rendered.content_bytes
        )
        created_at = utc_now()
        input_parents = tuple(
            dict.fromkeys(
                (
                    candidate_record.sha256,
                    bundle_record.sha256,
                    paper_verification_record.sha256,
                    str(composition.soundness["assessment_artifact_hash"]),
                    *((predecessor_hash,) if predecessor_hash else ()),
                )
            )
        )
        input_record = registry.put_bytes(
            canonical_json_bytes(composition.to_dict()) + b"\n",
            logical_type="paper_composition_input",
            origin="canonical source-owned paper composition input",
            creator_role=Role.PAPER_WRITER,
            creation_command=(
                "scientist-one",
                "paper",
                "derive-composition-input",
            ),
            parent_artifacts=input_parents,
            schema_version="1.0",
            mime_type="application/json",
            created_at=created_at,
        )
        content_record = registry.put_bytes(
            content,
            logical_type="paper_manuscript_content",
            origin="deterministic evidence-only manuscript content",
            creator_role=Role.PAPER_WRITER,
            creation_command=("scientist-one", "paper", "render-manuscript"),
            parent_artifacts=(candidate_record.sha256, bundle_record.sha256),
            schema_version="1.0",
            mime_type="text/markdown",
            created_at=created_at,
        )
        composition_verification_value = {
            "schema_version": "paper-composition-verification/v1",
            "renderer_version": renderer_version,
            "composition_input_artifact_hash": input_record.sha256,
            "content_artifact_hash": content_record.sha256,
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "source_map": [item.to_dict() for item in rendered.source_map],
            "passed": True,
        }
        composition_verification_record = registry.put_bytes(
            canonical_json_bytes(composition_verification_value) + b"\n",
            logical_type="paper_composition_verification",
            origin="byte-exact deterministic manuscript replay verification",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            creation_command=("scientist-one", "paper", "verify-composition"),
            parent_artifacts=(input_record.sha256, content_record.sha256),
            schema_version="1.0",
            mime_type="application/json",
            created_at=created_at,
        )
        resolved = tuple(
            item["finding_artifact_hash"]
            for item in composition.findings
            if item["status"] == "RESOLVED"
        )
        unresolved = tuple(
            item["finding_artifact_hash"]
            for item in composition.findings
            if item["status"] == "UNRESOLVED"
        )
        revision = PaperManuscriptRevision(
            "fixture-run",
            "lineage-manuscript",
            revision_number,
            predecessor_hash,
            input_record.sha256,
            content_record.sha256,
            composition_verification_record.sha256,
            candidate_record.sha256,
            bundle_record.sha256,
            paper_verification_record.sha256,
            resolved,
            unresolved,
        )
        revision_parents = tuple(
            dict.fromkeys(
                (
                    input_record.sha256,
                    content_record.sha256,
                    composition_verification_record.sha256,
                    candidate_record.sha256,
                    bundle_record.sha256,
                    paper_verification_record.sha256,
                    *((predecessor_hash,) if predecessor_hash else ()),
                )
            )
        )
        revision_record = registry.put_bytes(
            canonical_json_bytes(revision.to_dict()) + b"\n",
            logical_type="paper_manuscript_revision",
            origin="issued deterministic evidence-only manuscript revision",
            creator_role=Role.PAPER_WRITER,
            creation_command=(
                "scientist-one",
                "paper",
                "issue-manuscript-revision",
            ),
            parent_artifacts=revision_parents,
            schema_version="1.0",
            mime_type="application/json",
            created_at=created_at,
        )
        records = (
            input_record,
            content_record,
            composition_verification_record,
            revision_record,
        )
        prior = ledger.last_event()
        assert prior is not None
        issuance_event = LedgerEvent.create(
            run_id="fixture-run",
            actor_role=Role.PAPER_WRITER,
            state_before=prior.requested_state_after,
            requested_state_after=prior.requested_state_after,
            artifact_hashes=(revision_record.sha256,),
            code_version="mechanical-fixture-code-v1",
            configuration_hash=configuration_hash,
            reason="issued deterministic evidence-only manuscript revision",
            prior_event_hash=prior.event_hash,
            event_id=f"pmr-{revision_record.sha256[:48]}",
            timestamp=revision_record.created_at,
            event_type="CHECKPOINT",
            metadata=_revision_event_metadata(records, revision, composition),
        )
        ledger.append(issuance_event)
        return SimpleNamespace(
            composition=composition,
            revision=revision,
            revision_record=revision_record,
            issuance_event=issuance_event,
            records=records,
            candidate_record=candidate_record,
            bundle_record=bundle_record,
            bundle_event=bundle_event,
        )

    def _eligible_policy_bundle(self) -> AuthoritativeResearchBundle:
        evidence = digest("policy-evidence")
        requirements = ClaimPaperRequirements(
            "claim-central", ClaimType.QUALITATIVE, (), (), (), (), ()
        )
        claim = AuthoritativeClaim(
            claim_id="claim-central", text="A source-owned scoped claim.",
            expressed_strength=ClaimStrength.QUALIFIED,
            permitted_strength=ClaimStrength.QUALIFIED,
            evidence_hashes=(evidence,), claim_state_artifact_hash=digest("policy-state"),
            graph_decision_hash=digest("policy-decision"),
            claim_semantics_artifact_hash=digest("policy-semantics"),
            producer_role=Role.EXPERIMENT_RUNNER,
            claim_semantics_evidence_scope=ClaimSemanticsEvidenceScope.SCIENTIFIC_EVIDENCE,
            confidence=0.8, verification_method="source-owned replay",
            scientific_writer_eligible=True, evidence_use=ClaimEvidenceUse.SCIENTIFIC,
            claim_type=ClaimType.QUALITATIVE, scope="Measured scope only.",
            requirements=requirements,
        )
        return AuthoritativeResearchBundle(
            research_state_hash=digest("policy-snapshot"), claim_graph_hash=digest("policy-graph"),
            claims=(claim,), central_claim_ids=(claim.claim_id,), authoritative_evidence_hashes=(evidence,),
            metrics=(), method_code_bindings=(), required_limitations=(),
            required_baselines_complete=True, leakage_resolved=True,
            evaluator_exploitation_resolved=True, statistics_valid=True,
            novelty_supported=True, selection_integrity_valid=True,
            clean_reproduction_passed=True, soundness_verdict=SoundnessVerdict.PASS,
            soundness_assessment_hash=digest("policy-soundness"), external_validation_complete=True,
        )

    def test_policy_rejects_failed_verification_noneligible_fixture_and_nonpassing_soundness(self) -> None:
        bundle = self._eligible_policy_bundle()
        passed = PaperVerification(True, (), (), ("claim-central",))
        _validate_composition_authority(bundle, passed)
        with self.assertRaisesRegex(ValidationError, "freshly passed"):
            _validate_composition_authority(
                bundle, PaperVerification(False, (), ("failed",), ())
            )
        with self.assertRaisesRegex(ValidationError, "central claim"):
            _validate_composition_authority(
                replace(bundle, claims=(replace(bundle.claims[0], requirements=None, scientific_writer_eligible=False),)),
                passed,
            )
        fixture_claim = AuthoritativeClaim(
            claim_id="fixture-claim", text="Fixture-only claim.",
            expressed_strength=ClaimStrength.LIMITED, permitted_strength=ClaimStrength.LIMITED,
            evidence_hashes=(digest("fixture-evidence"),), claim_state_artifact_hash=digest("fixture-state"),
            graph_decision_hash=digest("fixture-decision"), claim_semantics_artifact_hash=digest("fixture-semantics"),
            producer_role=Role.EXPERIMENT_RUNNER,
            claim_semantics_evidence_scope=ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE,
            confidence=0.2, verification_method="fixture", scientific_writer_eligible=False,
            evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE, claim_type=ClaimType.QUALITATIVE,
            scope="SYSTEM_FIXTURE",
        )
        with self.assertRaisesRegex(ValidationError, "SYSTEM_FIXTURE/NON_EVIDENTIARY"):
            _validate_composition_authority(
                replace(bundle, claims=(bundle.claims[0], fixture_claim)), passed
            )
        with self.assertRaisesRegex(ValidationError, "PASS or CONDITIONAL_PASS"):
            _validate_composition_authority(
                replace(bundle, soundness_verdict=SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED),
                passed,
            )

    def test_public_registration_rejects_fixture_scope_before_any_write(self) -> None:
        eligible = self._eligible_policy_bundle()
        fixture_evidence = digest("public-fixture-evidence")
        fixture_claim = AuthoritativeClaim(
            claim_id="fixture-claim",
            text="Fixture-only claim.",
            expressed_strength=ClaimStrength.LIMITED,
            permitted_strength=ClaimStrength.LIMITED,
            evidence_hashes=(fixture_evidence,),
            claim_state_artifact_hash=digest("public-fixture-state"),
            graph_decision_hash=digest("public-fixture-decision"),
            claim_semantics_artifact_hash=digest("public-fixture-semantics"),
            producer_role=Role.EXPERIMENT_RUNNER,
            claim_semantics_evidence_scope=(
                ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE
            ),
            confidence=0.2,
            verification_method="fixture",
            scientific_writer_eligible=False,
            evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
            claim_type=ClaimType.QUALITATIVE,
            scope="SYSTEM_FIXTURE",
        )
        bundle = replace(
            eligible,
            claims=(*eligible.claims, fixture_claim),
            authoritative_evidence_hashes=(
                *eligible.authoritative_evidence_hashes,
                fixture_evidence,
            ),
        )
        candidate = PaperCandidate(
            candidate_id="fixture-scope-candidate",
            title="Untrusted fixture title",
            claims=tuple(
                PaperClaim(
                    claim.claim_id,
                    claim.text,
                    claim.expressed_strength,
                    claim.evidence_hashes,
                    central=claim.claim_id in bundle.central_claim_ids,
                    claim_type=claim.claim_type,
                    scope=claim.scope,
                    confidence=claim.confidence,
                    verification_method=claim.verification_method,
                    permitted_strength=claim.permitted_strength,
                )
                for claim in bundle.claims
            ),
            numeric_assertions=(),
            references=(),
            assets=(),
            method_code_bindings=(),
            limitations=(),
            source_bundle_hashes=(
                bundle.research_state_hash,
                bundle.claim_graph_hash,
                bundle.soundness_assessment_hash,
            ),
        )
        candidate_hash = digest("fixture-scope-candidate-artifact")
        bundle_hash = digest("fixture-scope-bundle-artifact")
        verification_hash = digest("fixture-scope-verification")
        verification = PaperVerification(
            True,
            (),
            (),
            tuple(item.claim_id for item in bundle.claims),
        )
        verification_record = SimpleNamespace(
            parent_artifacts=(candidate_hash, bundle_hash),
            schema_version="1.0",
            mime_type="application/json",
            origin="fresh registry-and-ledger replay of exact paper authority",
            creation_command=("scientist-one", "verify-paper-authority"),
        )
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root)
            before = registry.verify_all(raise_on_error=True)
            with (
                patch(
                    "scientist_one.paper_composition."
                    "_resolve_candidate_bundle_artifacts"
                ),
                patch(
                    "scientist_one.paper_composition._require_frozen_artifact",
                    return_value=verification_record,
                ),
                patch(
                    "scientist_one.paper_composition.require_paper_verification",
                    return_value=verification,
                ),
                self.assertRaisesRegex(
                    ValidationError,
                    "SYSTEM_FIXTURE/NON_EVIDENTIARY",
                ),
            ):
                register_paper_manuscript_revision(
                    registry,
                    ledger,
                    candidate,
                    bundle,
                    run_id="fixture-run",
                    manuscript_id="fixture-scope-manuscript",
                    revision=1,
                    candidate_artifact_hash=candidate_hash,
                    bundle_artifact_hash=bundle_hash,
                    verification_artifact_hash=verification_hash,
                )
            self.assertEqual(registry.verify_all(raise_on_error=True), before)
            self.assertEqual(ledger.validate(raise_on_error=True).event_count, 0)

    def test_superseded_legacy_predecessor_reaches_r2_fresh_gate_without_write(
        self,
    ) -> None:
        """Historical continuity passes; current scientific authority is not mocked."""

        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root)
            first = self._mechanical_historical_revision(
                registry,
                ledger,
                tag="legacy-r1",
                revision_number=1,
                predecessor_hash=None,
                renderer_version=LEGACY_RENDERER_VERSION,
            )
            prior = ledger.last_event()
            assert prior is not None
            ledger.record(
                run_id="fixture-run",
                actor_role=Role.ORCHESTRATOR,
                state_before=prior.requested_state_after,
                requested_state_after=prior.requested_state_after,
                artifact_hashes=(),
                code_version="mechanical-fixture-code-v2",
                configuration_hash=digest("lineage-configuration"),
                reason="supersede the old research-state source fixture",
                event_id="mechanical-source-supersession",
                event_type="CHECKPOINT",
                metadata={"research_state_operation": "SUPERSEDED"},
            )
            events = ledger.validate(raise_on_error=True).events
            historical = _require_historical_predecessor_lineage(
                registry,
                events,
                predecessor_revision_artifact_hash=first.revision_record.sha256,
                expected_run_id="fixture-run",
                expected_manuscript_id="lineage-manuscript",
                expected_revision=1,
                expected_candidate_id="lineage-candidate",
                before_event_index=len(events),
            )
            self.assertEqual(
                historical.revision_record.sha256,
                first.revision_record.sha256,
            )
            verification_value = safe_json_loads(
                registry.get_bytes(
                    historical.composition_verification_record.sha256
                )
            )
            self.assertEqual(
                verification_value["renderer_version"],
                LEGACY_RENDERER_VERSION,
            )

            bundle = self._eligible_policy_bundle()
            claim = bundle.claims[0]
            candidate = PaperCandidate(
                candidate_id="lineage-candidate",
                title="Never rendered current-boundary fixture",
                claims=(
                    PaperClaim(
                        claim.claim_id,
                        claim.text,
                        claim.expressed_strength,
                        claim.evidence_hashes,
                        central=True,
                        claim_type=claim.claim_type,
                        scope=claim.scope,
                        confidence=claim.confidence,
                        verification_method=claim.verification_method,
                        permitted_strength=claim.permitted_strength,
                    ),
                ),
                numeric_assertions=(),
                references=(),
                assets=(),
                method_code_bindings=(),
                limitations=(),
                source_bundle_hashes=(
                    bundle.research_state_hash,
                    bundle.claim_graph_hash,
                    bundle.soundness_assessment_hash,
                ),
            )
            before_registry = registry.verify_all(raise_on_error=True)
            before_ledger = ledger.validate(raise_on_error=True)
            with (
                patch(
                    "scientist_one.paper_composition."
                    "_resolve_candidate_bundle_artifacts"
                ),
                patch(
                    "scientist_one.paper_composition._derive_composition_input",
                    side_effect=ValidationError(
                        "fresh current scientific authority required"
                    ),
                ) as fresh_gate,
                self.assertRaisesRegex(
                    ValidationError,
                    "fresh current scientific authority required",
                ),
            ):
                register_paper_manuscript_revision(
                    registry,
                    ledger,
                    candidate,
                    bundle,
                    run_id="fixture-run",
                    manuscript_id="lineage-manuscript",
                    revision=2,
                    candidate_artifact_hash=digest("prospective-r2-candidate"),
                    bundle_artifact_hash=digest("prospective-r2-bundle"),
                    verification_artifact_hash=digest(
                        "prospective-r2-verification"
                    ),
                    predecessor_revision_artifact_hash=(
                        first.revision_record.sha256
                    ),
                )
            fresh_gate.assert_called_once()
            self.assertEqual(
                registry.verify_all(raise_on_error=True),
                before_registry,
            )
            self.assertEqual(
                ledger.validate(raise_on_error=True),
                before_ledger,
            )

            second = self._mechanical_historical_revision(
                registry,
                ledger,
                tag="current-r2-boundary",
                revision_number=2,
                predecessor_hash=first.revision_record.sha256,
            )
            with (
                patch(
                    "scientist_one.paper_composition."
                    "_read_authoritative_bundle_artifact",
                    return_value=(second.bundle_record, {}, bundle),
                ),
                patch(
                    "scientist_one.paper_composition._paper_candidate_from_json",
                    return_value=candidate,
                ),
                patch(
                    "scientist_one.paper_composition._derive_composition_input",
                    side_effect=ValidationError(
                        "newest r2 still requires fresh scientific authority"
                    ),
                ),
                self.assertRaisesRegex(
                    ValidationError,
                    "newest r2 still requires fresh scientific authority",
                ),
            ):
                require_paper_manuscript_revision(
                    registry,
                    ledger,
                    revision_artifact_hash=second.revision_record.sha256,
                )

            with (
                patch(
                    "scientist_one.paper_composition."
                    "_read_authoritative_bundle_artifact",
                    return_value=(first.bundle_record, {}, bundle),
                ),
                patch(
                    "scientist_one.paper_composition._paper_candidate_from_json",
                    return_value=candidate,
                ),
                patch(
                    "scientist_one.paper_composition._derive_composition_input",
                    side_effect=ValidationError(
                        "stale r1 cannot satisfy current scientific authority"
                    ),
                ),
                self.assertRaisesRegex(
                    ValidationError,
                    "stale r1 cannot satisfy current scientific authority",
                ),
            ):
                require_paper_manuscript_revision(
                    registry,
                    ledger,
                    revision_artifact_hash=first.revision_record.sha256,
                )

    def test_historical_lineage_rejects_tamper_correction_and_ambiguity(
        self,
    ) -> None:
        with self.subTest(case="hash-consistent-content-splice"):
            with tempfile.TemporaryDirectory() as root:
                registry = ArtifactRegistry(root)
                ledger = EventLedger(root)
                first = self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="tampered-r1",
                    revision_number=1,
                    predecessor_hash=None,
                    tamper_content=True,
                )
                events = ledger.validate(raise_on_error=True).events
                with self.assertRaisesRegex(ValidationError, "cover every content byte"):
                    _require_historical_predecessor_lineage(
                        registry,
                        events,
                        predecessor_revision_artifact_hash=(
                            first.revision_record.sha256
                        ),
                        expected_run_id="fixture-run",
                        expected_manuscript_id="lineage-manuscript",
                        expected_revision=1,
                        expected_candidate_id="lineage-candidate",
                        before_event_index=len(events),
                    )

        with self.subTest(case="corrected-revision-issuance"):
            with tempfile.TemporaryDirectory() as root:
                registry = ArtifactRegistry(root)
                ledger = EventLedger(root)
                first = self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="corrected-r1",
                    revision_number=1,
                    predecessor_hash=None,
                )
                prior = ledger.last_event()
                assert prior is not None
                ledger.record(
                    run_id="fixture-run",
                    actor_role=Role.ORCHESTRATOR,
                    state_before=prior.requested_state_after,
                    requested_state_after=prior.requested_state_after,
                    artifact_hashes=(),
                    code_version="mechanical-fixture-code-v1",
                    configuration_hash=digest("lineage-configuration"),
                    reason="withdraw the inert revision issuance",
                    event_id="correct-mechanical-r1",
                    event_type="CORRECTION",
                    supersedes_event_id=first.issuance_event.event_id,
                )
                events = ledger.validate(raise_on_error=True).events
                with self.assertRaisesRegex(ValidationError, "was corrected"):
                    _require_historical_predecessor_lineage(
                        registry,
                        events,
                        predecessor_revision_artifact_hash=(
                            first.revision_record.sha256
                        ),
                        expected_run_id="fixture-run",
                        expected_manuscript_id="lineage-manuscript",
                        expected_revision=1,
                        expected_candidate_id="lineage-candidate",
                        before_event_index=len(events),
                    )

        with self.subTest(case="two-admitted-roots"):
            with tempfile.TemporaryDirectory() as root:
                registry = ArtifactRegistry(root)
                ledger = EventLedger(root)
                first = self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="ambiguous-r1-a",
                    revision_number=1,
                    predecessor_hash=None,
                )
                self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="ambiguous-r1-b",
                    revision_number=1,
                    predecessor_hash=None,
                )
                events = ledger.validate(raise_on_error=True).events
                with self.assertRaisesRegex(ValidationError, "unique admitted root"):
                    _require_historical_predecessor_lineage(
                        registry,
                        events,
                        predecessor_revision_artifact_hash=(
                            first.revision_record.sha256
                        ),
                        expected_run_id="fixture-run",
                        expected_manuscript_id="lineage-manuscript",
                        expected_revision=1,
                        expected_candidate_id="lineage-candidate",
                        before_event_index=len(events),
                    )

    def test_historical_lineage_rejects_gap_switch_and_depth(self) -> None:
        with self.subTest(case="revision-gap"):
            with tempfile.TemporaryDirectory() as root:
                registry = ArtifactRegistry(root)
                ledger = EventLedger(root)
                first = self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="gap-r1",
                    revision_number=1,
                    predecessor_hash=None,
                )
                third = self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="gap-r3",
                    revision_number=3,
                    predecessor_hash=first.revision_record.sha256,
                )
                events = ledger.validate(raise_on_error=True).events
                third_index = next(
                    index
                    for index, event in enumerate(events)
                    if event.event_id == third.issuance_event.event_id
                )
                with self.assertRaisesRegex(ValidationError, "revision n-1"):
                    _require_historical_predecessor_lineage(
                        registry,
                        events,
                        predecessor_revision_artifact_hash=(
                            first.revision_record.sha256
                        ),
                        expected_run_id="fixture-run",
                        expected_manuscript_id="lineage-manuscript",
                        expected_revision=2,
                        expected_candidate_id="lineage-candidate",
                        before_event_index=third_index,
                    )

        with self.subTest(case="candidate-switch"):
            with tempfile.TemporaryDirectory() as root:
                registry = ArtifactRegistry(root)
                ledger = EventLedger(root)
                first = self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="switch-r1",
                    revision_number=1,
                    predecessor_hash=None,
                    candidate_id="original-candidate",
                )
                second = self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="switch-r2",
                    revision_number=2,
                    predecessor_hash=first.revision_record.sha256,
                    candidate_id="switched-candidate",
                )
                events = ledger.validate(raise_on_error=True).events
                with self.assertRaisesRegex(ValidationError, "switch candidate"):
                    _require_historical_predecessor_lineage(
                        registry,
                        events,
                        predecessor_revision_artifact_hash=(
                            second.revision_record.sha256
                        ),
                        expected_run_id="fixture-run",
                        expected_manuscript_id="lineage-manuscript",
                        expected_revision=2,
                        expected_candidate_id="original-candidate",
                        before_event_index=len(events),
                    )

        with self.subTest(case="depth-bound"):
            with tempfile.TemporaryDirectory() as root:
                registry = ArtifactRegistry(root)
                ledger = EventLedger(root)
                first = self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="depth-r1",
                    revision_number=1,
                    predecessor_hash=None,
                )
                second = self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="depth-r2",
                    revision_number=2,
                    predecessor_hash=first.revision_record.sha256,
                )
                third = self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="depth-r3",
                    revision_number=3,
                    predecessor_hash=second.revision_record.sha256,
                )
                events = ledger.validate(raise_on_error=True).events
                with (
                    patch(
                        "scientist_one.paper_composition."
                        "MAX_REVISION_LINEAGE_DEPTH",
                        2,
                    ),
                    self.assertRaisesRegex(ValidationError, "depth bound"),
                ):
                    _require_historical_predecessor_lineage(
                        registry,
                        events,
                        predecessor_revision_artifact_hash=(
                            third.revision_record.sha256
                        ),
                        expected_run_id="fixture-run",
                        expected_manuscript_id="lineage-manuscript",
                        expected_revision=3,
                        expected_candidate_id="lineage-candidate",
                        before_event_index=len(events),
                    )

    def test_stable_fresh_replay_rejects_midstream_corrections(self) -> None:
        """A resolver-era correction cannot be absorbed into a mixed snapshot."""

        bundle = self._eligible_policy_bundle()
        claim = bundle.claims[0]
        candidate = PaperCandidate(
            candidate_id="lineage-candidate",
            title="Never rendered correction-race fixture",
            claims=(
                PaperClaim(
                    claim.claim_id,
                    claim.text,
                    claim.expressed_strength,
                    claim.evidence_hashes,
                    central=True,
                    claim_type=claim.claim_type,
                    scope=claim.scope,
                    confidence=claim.confidence,
                    verification_method=claim.verification_method,
                    permitted_strength=claim.permitted_strength,
                ),
            ),
            numeric_assertions=(),
            references=(),
            assets=(),
            method_code_bindings=(),
            limitations=(),
            source_bundle_hashes=(
                bundle.research_state_hash,
                bundle.claim_graph_hash,
                bundle.soundness_assessment_hash,
            ),
        )

        with self.subTest(path="registration"):
            with tempfile.TemporaryDirectory() as root:
                registry = ArtifactRegistry(root)
                ledger = EventLedger(root)
                initial = ledger.record(
                    run_id="fixture-run",
                    actor_role=Role.ORCHESTRATOR,
                    state_before=MacroState.WRITE,
                    requested_state_after=MacroState.WRITE,
                    artifact_hashes=(),
                    code_version="mechanical-fixture-code-v1",
                    configuration_hash=digest("lineage-configuration"),
                    reason="establish the current-source race fixture",
                    event_id="current-source-race-base",
                    event_type="CHECKPOINT",
                )
                base = fixture_input()
                mixed = replace(
                    base,
                    run_id="fixture-run",
                    manuscript_id="lineage-manuscript",
                    candidate_id=candidate.candidate_id,
                    candidate_artifact_hash=digest("race-current-candidate"),
                    bundle_artifact_hash=digest("race-current-bundle"),
                    verification_artifact_hash=digest("race-current-verification"),
                    bundle_issuance_event_id=initial.event_id,
                    bundle_issuance_event_hash=str(initial.event_hash),
                    bundle_issuance_event_index=0,
                    historical_ledger_head_hash=str(initial.event_hash),
                    historical_ledger_event_count=1,
                    authority_scope="SCIENTIFIC_EVIDENCE",
                )

                def correct_after_source_replay(*args, **kwargs):
                    ledger.append_correction(
                        initial.event_id,
                        actor_role=Role.ORCHESTRATOR,
                        reason="withdraw a source during composition replay",
                        corrected_fields={"authority": "WITHDRAWN"},
                        event_id="correct-current-source-during-registration",
                    )
                    return mixed

                before_registry = registry.verify_all(raise_on_error=True)
                before_ledger_count = ledger.validate(
                    raise_on_error=True
                ).event_count
                with (
                    patch(
                        "scientist_one.paper_composition."
                        "_resolve_candidate_bundle_artifacts"
                    ),
                    patch(
                        "scientist_one.paper_composition."
                        "_derive_composition_input",
                        side_effect=correct_after_source_replay,
                    ),
                    self.assertRaisesRegex(
                        ValidationError,
                        "changed during fresh composition replay",
                    ),
                ):
                    register_paper_manuscript_revision(
                        registry,
                        ledger,
                        candidate,
                        bundle,
                        run_id="fixture-run",
                        manuscript_id="lineage-manuscript",
                        revision=1,
                        candidate_artifact_hash=digest(
                            "race-current-candidate"
                        ),
                        bundle_artifact_hash=digest("race-current-bundle"),
                        verification_artifact_hash=digest(
                            "race-current-verification"
                        ),
                    )
                self.assertEqual(
                    registry.verify_all(raise_on_error=True),
                    before_registry,
                )
                self.assertEqual(
                    ledger.validate(raise_on_error=True).event_count,
                    before_ledger_count + 1,
                )

        with self.subTest(path="public-replay"):
            with tempfile.TemporaryDirectory() as root:
                registry = ArtifactRegistry(root)
                ledger = EventLedger(root)
                first = self._mechanical_historical_revision(
                    registry,
                    ledger,
                    tag="replay-source-race-r1",
                    revision_number=1,
                    predecessor_hash=None,
                )

                def correct_bundle_after_source_replay(*args, **kwargs):
                    ledger.append_correction(
                        first.bundle_event.event_id,
                        actor_role=Role.ORCHESTRATOR,
                        reason="withdraw bundle during current revision replay",
                        corrected_fields={"authority": "WITHDRAWN"},
                        event_id="correct-bundle-during-replay",
                    )
                    return first.composition

                with (
                    patch(
                        "scientist_one.paper_composition."
                        "_read_authoritative_bundle_artifact",
                        return_value=(first.bundle_record, {}, bundle),
                    ),
                    patch(
                        "scientist_one.paper_composition."
                        "_paper_candidate_from_json",
                        return_value=candidate,
                    ),
                    patch(
                        "scientist_one.paper_composition."
                        "_derive_composition_input",
                        side_effect=correct_bundle_after_source_replay,
                    ),
                    self.assertRaisesRegex(
                        ValidationError,
                        "changed during fresh composition replay",
                    ),
                ):
                    require_paper_manuscript_revision(
                        registry,
                        ledger,
                        revision_artifact_hash=first.revision_record.sha256,
                    )

    def test_public_replay_rejects_correction_during_immutable_replay(
        self,
    ) -> None:
        """The final co-locked read rejects a post-fresh correction."""

        bundle = self._eligible_policy_bundle()
        claim = bundle.claims[0]
        candidate = PaperCandidate(
            candidate_id="lineage-candidate",
            title="Never rendered immutable-replay race fixture",
            claims=(
                PaperClaim(
                    claim.claim_id,
                    claim.text,
                    claim.expressed_strength,
                    claim.evidence_hashes,
                    central=True,
                    claim_type=claim.claim_type,
                    scope=claim.scope,
                    confidence=claim.confidence,
                    verification_method=claim.verification_method,
                    permitted_strength=claim.permitted_strength,
                ),
            ),
            numeric_assertions=(),
            references=(),
            assets=(),
            method_code_bindings=(),
            limitations=(),
            source_bundle_hashes=(
                bundle.research_state_hash,
                bundle.claim_graph_hash,
                bundle.soundness_assessment_hash,
            ),
        )
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root)
            first = self._mechanical_historical_revision(
                registry,
                ledger,
                tag="immutable-replay-source-race-r1",
                revision_number=1,
                predecessor_hash=None,
            )
            stable_registry = registry.verify_all(raise_on_error=True)
            stable_ledger = ledger.validate(raise_on_error=True)
            stable_replay = SimpleNamespace(
                composition=first.composition,
                registry_snapshot=stable_registry,
                ledger_snapshot=stable_ledger,
            )
            replay_calls = 0

            def correct_during_immutable_replay(*args, **kwargs):
                nonlocal replay_calls
                replay_calls += 1
                if replay_calls == 2:
                    ledger.append_correction(
                        first.issuance_event.event_id,
                        actor_role=Role.ORCHESTRATOR,
                        reason="withdraw revision during immutable replay",
                        corrected_fields={"authority": "WITHDRAWN"},
                        event_id="correct-during-immutable-replay",
                    )
                return _replay_immutable_revision(*args, **kwargs)

            before_registry = registry.verify_all(raise_on_error=True)
            before_ledger_count = stable_ledger.event_count
            with (
                patch(
                    "scientist_one.paper_composition."
                    "_read_authoritative_bundle_artifact",
                    return_value=(first.bundle_record, {}, bundle),
                ),
                patch(
                    "scientist_one.paper_composition."
                    "_paper_candidate_from_json",
                    return_value=candidate,
                ),
                patch(
                    "scientist_one.paper_composition."
                    "_derive_composition_input_stably",
                    return_value=stable_replay,
                ),
                patch(
                    "scientist_one.paper_composition."
                    "_replay_immutable_revision",
                    side_effect=correct_during_immutable_replay,
                ),
                self.assertRaisesRegex(
                    ValidationError,
                    "changed after fresh composition replay",
                ),
            ):
                require_paper_manuscript_revision(
                    registry,
                    ledger,
                    revision_artifact_hash=first.revision_record.sha256,
                )
            self.assertEqual(replay_calls, 2)
            self.assertEqual(
                registry.verify_all(raise_on_error=True),
                before_registry,
            )
            self.assertEqual(
                ledger.validate(raise_on_error=True).event_count,
                before_ledger_count + 1,
            )

    def test_missing_fresh_verification_rejects_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root)
            evidence = digest("evidence")
            claim = AuthoritativeClaim(
                claim_id="claim-1",
                text="A noneligible fixture claim.",
                expressed_strength=ClaimStrength.QUALIFIED,
                permitted_strength=ClaimStrength.QUALIFIED,
                evidence_hashes=(evidence,),
                claim_state_artifact_hash=digest("claim-state"),
                graph_decision_hash=digest("decision"),
                claim_semantics_artifact_hash=digest("semantics"),
                producer_role=Role.EXPERIMENT_RUNNER,
                claim_semantics_evidence_scope=ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE,
                confidence=0.5,
                verification_method="fixture-only",
                scientific_writer_eligible=False,
                evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
                claim_type=ClaimType.QUALITATIVE,
                scope="SYSTEM_FIXTURE",
            )
            bundle = AuthoritativeResearchBundle(
                research_state_hash=digest("snapshot"), claim_graph_hash=digest("graph"),
                claims=(claim,), central_claim_ids=(claim.claim_id,),
                authoritative_evidence_hashes=(evidence,), metrics=(), method_code_bindings=(),
                required_limitations=("Fixture evidence is non-evidentiary.",),
                required_baselines_complete=True, leakage_resolved=True,
                evaluator_exploitation_resolved=True, statistics_valid=True,
                novelty_supported=True, selection_integrity_valid=True,
                clean_reproduction_passed=True, soundness_verdict=SoundnessVerdict.PASS,
                soundness_assessment_hash=digest("soundness"), external_validation_complete=True,
                run_id="fixture-run", research_state_artifact_hashes=(digest("state"),),
                research_state_ledger_head_hash=digest("state-head"), research_state_ledger_event_count=1,
                research_state_code_version="fixture-code", research_state_configuration_hash=digest("configuration"),
            )
            candidate = PaperCandidate(
                candidate_id="candidate-1", title="Fixture candidate",
                claims=(PaperClaim(claim.claim_id, claim.text, claim.expressed_strength, claim.evidence_hashes, central=True, claim_type=claim.claim_type, scope=claim.scope, confidence=claim.confidence, verification_method=claim.verification_method, permitted_strength=claim.permitted_strength),),
                numeric_assertions=(), references=(), assets=(), method_code_bindings=(),
                limitations=bundle.required_limitations,
                source_bundle_hashes=(bundle.research_state_hash, bundle.claim_graph_hash, bundle.soundness_assessment_hash),
            )
            before = registry.verify_all(raise_on_error=True)
            with self.assertRaises(ValidationError):
                register_paper_manuscript_revision(
                    registry, ledger, candidate, bundle, run_id="fixture-run",
                    manuscript_id="manuscript-1", revision=1,
                    candidate_artifact_hash=digest("candidate-artifact"),
                    bundle_artifact_hash=digest("bundle-artifact"),
                    verification_artifact_hash=digest("verification-artifact"),
                )
            self.assertEqual(registry.verify_all(raise_on_error=True), before)
            self.assertEqual(ledger.validate(raise_on_error=True).event_count, 0)
            self.assertFalse(any(item.logical_type.startswith("paper_composition") or item.logical_type == "paper_manuscript_content" for item in registry.list_records()))

    def test_verification_parent_splices_reject_before_composition_writes(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root)

            def parent(label: str):
                return registry.put_bytes(
                    label.encode(), logical_type="fixture_parent",
                    origin="parent-splice contract fixture",
                    creator_role=Role.ORCHESTRATOR,
                )

            candidate_a = parent("candidate-a")
            candidate_b = parent("candidate-b")
            bundle_a = parent("bundle-a")
            bundle_b = parent("bundle-b")
            verification = registry.put_json(
                {"fixture": True}, logical_type="paper_verification",
                origin="parent-splice contract fixture",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                parent_artifacts=(candidate_a.sha256, bundle_a.sha256),
            )
            bundle = self._eligible_policy_bundle()
            claim = bundle.claims[0]
            candidate = PaperCandidate(
                candidate_id="same-candidate-id",
                title="Untrusted overclaiming title",
                claims=(
                    PaperClaim(
                        claim.claim_id, claim.text, claim.expressed_strength,
                        claim.evidence_hashes, central=True,
                        claim_type=claim.claim_type, scope=claim.scope,
                        confidence=claim.confidence,
                        verification_method=claim.verification_method,
                        permitted_strength=claim.permitted_strength,
                    ),
                ),
                numeric_assertions=(), references=(), assets=(),
                method_code_bindings=(), limitations=(),
                source_bundle_hashes=(
                    bundle.research_state_hash, bundle.claim_graph_hash,
                    bundle.soundness_assessment_hash,
                ),
            )
            before = registry.verify_all(raise_on_error=True)
            for supplied_candidate, supplied_bundle in (
                (candidate_b.sha256, bundle_a.sha256),
                (candidate_a.sha256, bundle_b.sha256),
            ):
                with self.assertRaisesRegex(ValidationError, "not bound"):
                    _derive_composition_input(
                        registry, ledger, candidate, bundle,
                        run_id="fixture-run", manuscript_id="manuscript-1",
                        revision=1, predecessor_revision_artifact_hash=None,
                        candidate_artifact_hash=supplied_candidate,
                        bundle_artifact_hash=supplied_bundle,
                        verification_artifact_hash=verification.sha256,
                    )
                self.assertEqual(registry.verify_all(raise_on_error=True), before)

    def test_revision_contract_cannot_claim_release_submission_or_skip_predecessor(self) -> None:
        hashes = [digest(str(index)) for index in range(8)]
        revision = PaperManuscriptRevision("run-1", "manuscript-1", 1, None, *hashes[:6], (), ())
        self.assertEqual((revision.manuscript_status, revision.release_status, revision.submission_status), ("MANUSCRIPT_CANDIDATE", "NOT_RELEASED", "NOT_SUBMITTED"))
        with self.assertRaisesRegex(ValidationError, "predecessor"):
            replace(revision, revision=2)
        with self.assertRaisesRegex(ValidationError, "release or submission"):
            replace(revision, release_status="RELEASED")

    def test_venue_v2_requires_exact_revision_triple_and_inventory_is_not_ready(self) -> None:
        section = ManuscriptSection("methods", (digest("method"),))
        binding = ArtifactReadinessBinding("code", (digest("code"),))
        common = dict(
            run_id="run-1", candidate_id="candidate-1",
            candidate_artifact_hash=digest("candidate"),
            bundle_artifact_hash=digest("bundle"),
            manuscript_artifact_hash=digest("inventory"),
            profile_id="fixture-profile", profile_sha256=digest("profile-json"),
            profile_artifact_hash=digest("profile-artifact"),
            sections=(section,), artifact_bindings=(binding,),
            source_artifact_hashes=(digest("method"), digest("code")),
        )
        legacy = VenueReadinessManifest(
            **common, schema_version="venue-readiness/v1"
        )
        self.assertIsNone(legacy.manuscript_revision_artifact_hash)
        with self.assertRaisesRegex(ValidationError, "requires issued manuscript"):
            VenueReadinessManifest(**common)
        with self.assertRaisesRegex(ValidationError, "incomplete"):
            VenueReadinessManifest(
                **common,
                manuscript_revision_artifact_hash=digest("revision"),
            )

        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root)
            with self.assertRaisesRegex(ValidationError, "structural venue inventory"):
                _resolve_venue_requirement_receipt(
                    registry, ledger, digest("receipt"), None, None, None,
                    legacy, run_id="run-1",
                    candidate_artifact_hash=digest("candidate"),
                    bundle_artifact_hash=digest("bundle"),
                    profile_artifact_hash=digest("profile-artifact"),
                    readiness_manifest_hash=digest("manifest"),
                )
            with self.assertRaisesRegex(ValidationError, "structural venue inventory"):
                _resolve_venue_dimension_assessment(
                    registry, ledger, digest("dimension"), None, None, None,
                    legacy, (), run_id="run-1",
                    candidate_artifact_hash=digest("candidate"),
                    bundle_artifact_hash=digest("bundle"),
                    profile_artifact_hash=digest("profile-artifact"),
                    readiness_manifest_hash=digest("manifest"),
                )

        profile = VenueProfile(
            "fixture-profile", VenueFamily.ML_AI, ("methods",), ("code",)
        )
        result = assess_venue(
            profile,
            PaperVerification(True, (), (), ("claim-1",)),
            {name: 1.0 for name in READINESS_DIMENSIONS},
            external_validation_complete=True,
            rationale="Inventory cannot substitute for prose.",
        )
        self.assertEqual(result.classification, VenueFit.NOT_READY)
        self.assertIn(
            HardBlocker.VENUE_REQUIREMENTS_UNRESOLVED,
            result.hard_blockers,
        )

    def test_v2_default_ml_sections_use_full_source_map_closure(self) -> None:
        base = fixture_input()
        extra_authority = digest("method-extra-authority")
        binding = {
            **base.method_code_bindings[0],
            "authority_sources": [extra_authority],
        }
        value = replace(base, method_code_bindings=(binding,))
        rendered = render_paper_composition(value)
        profile = default_venue_profiles()[0]
        sections = _revision_sections_for_profile(
            SimpleNamespace(source_map=rendered.source_map), profile
        )
        by_id = {item.section_id: item for item in sections}
        self.assertEqual(tuple(by_id), profile.required_sections)
        claim_sources = (
            value.claims[0]["claim_state_artifact_hash"],
            value.claims[0]["claim_semantics_artifact_hash"],
            value.claims[0]["evidence_hashes"][0],
        )
        self.assertEqual(by_id["abstract"].source_artifact_hashes, claim_sources)
        self.assertEqual(
            by_id["introduction"].source_artifact_hashes,
            claim_sources,
        )
        self.assertEqual(
            by_id["methods"].source_artifact_hashes,
            (
                binding["method_artifact_hash"], binding["code_artifact_hash"],
                binding["method_state_artifact_hash"],
                binding["implementation_state_artifact_hash"], extra_authority,
            ),
        )
        self.assertEqual(
            by_id["results"].source_artifact_hashes,
            (
                *claim_sources,
                value.numeric_assertions[0]["source_artifact_hash"],
                value.assets[0]["artifact_hash"],
                value.assets[0]["authoritative_parent_hashes"][0],
            ),
        )
        self.assertEqual(
            by_id["limitations"].source_artifact_hashes,
            (
                value.bundle_artifact_hash,
                value.soundness["assessment_artifact_hash"],
            ),
        )
        self.assertEqual(
            by_id["reproducibility"].source_artifact_hashes,
            (
                value.bundle_artifact_hash,
                value.research_state_binding["snapshot_artifact_hash"],
                *value.research_state_binding["state_artifact_hashes"],
                binding["method_artifact_hash"],
                binding["code_artifact_hash"],
                binding["method_state_artifact_hash"],
                binding["implementation_state_artifact_hash"],
                extra_authority,
            ),
        )

        legacy = render_paper_composition(
            value,
            renderer_version=LEGACY_RENDERER_VERSION,
        )
        legacy_sections = _revision_sections_for_profile(
            SimpleNamespace(source_map=legacy.source_map), profile
        )
        self.assertNotEqual(
            {item.section_id for item in legacy_sections},
            set(profile.required_sections),
        )
        with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(
            ValidationError,
            "lacks required venue sections",
        ):
            _validate_revision_section_coverage(
                ArtifactRegistry(root),
                SimpleNamespace(source_map=legacy.source_map),
                profile,
                None,
                None,
                candidate_artifact_hash=digest("candidate"),
                bundle_artifact_hash=digest("bundle"),
            )
        for domain_profile in default_venue_profiles()[1:]:
            derived = _revision_sections_for_profile(
                SimpleNamespace(source_map=rendered.source_map),
                domain_profile,
            )
            self.assertEqual(
                tuple(item.section_id for item in derived),
                profile.required_sections,
            )

    def test_v2_common_section_body_omission_and_source_splice_fail_closed(self) -> None:
        """Mechanical coverage test only; it creates no manuscript authority."""

        rendered = render_paper_composition(fixture_input())
        profile = default_venue_profiles()[0]
        selectors = {
            "abstract": lambda block_id: block_id.startswith("abstract-claim-"),
            "introduction": lambda block_id: block_id.startswith(
                "introduction-scope-"
            ),
            "methods": lambda block_id: block_id.startswith("method-"),
            "results": lambda block_id: block_id.startswith("result-"),
            "limitations": lambda block_id: block_id == "limitations-body",
            "reproducibility": lambda block_id: (
                block_id == "reproducibility-body"
            ),
        }
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            for section_id, selected in selectors.items():
                source_map = tuple(
                    entry
                    for entry in rendered.source_map
                    if not selected(entry.block_id)
                )
                with self.subTest(section=section_id), self.assertRaisesRegex(
                    ValidationError,
                    "lacks required venue sections",
                ):
                    _validate_revision_section_coverage(
                        registry,
                        SimpleNamespace(source_map=source_map),
                        profile,
                        None,
                        None,
                        candidate_artifact_hash=digest("candidate"),
                        bundle_artifact_hash=digest("bundle"),
                    )

        allowed = {
            digest_value
            for section in _revision_sections_for_profile(
                SimpleNamespace(source_map=rendered.source_map),
                profile,
            )
            for digest_value in section.source_artifact_hashes
        }
        result_claim_index = next(
            index
            for index, entry in enumerate(rendered.source_map)
            if entry.block_id == "result-claim-1"
        )
        source_map = list(rendered.source_map)
        source_map[result_claim_index] = replace(
            source_map[result_claim_index],
            source_artifact_hashes=(
                *source_map[result_claim_index].source_artifact_hashes,
                digest("unauthorized-section-source"),
            ),
        )
        with (
            tempfile.TemporaryDirectory() as root,
            patch(
                "scientist_one.paper_pipeline._paper_source_authority",
                return_value=allowed,
            ),
            patch("scientist_one.paper_pipeline._require_frozen_artifact"),
        ):
            registry = ArtifactRegistry(root)
            exact = _validate_revision_section_coverage(
                registry,
                SimpleNamespace(source_map=rendered.source_map),
                profile,
                None,
                None,
                candidate_artifact_hash=digest("candidate"),
                bundle_artifact_hash=digest("bundle"),
            )
            self.assertEqual(
                tuple(section.section_id for section in exact),
                profile.required_sections,
            )
            with self.assertRaisesRegex(
                ValidationError,
                "source map exceeds paper authority",
            ):
                _validate_revision_section_coverage(
                    registry,
                    SimpleNamespace(source_map=tuple(source_map)),
                    profile,
                    None,
                    None,
                    candidate_artifact_hash=digest("candidate"),
                    bundle_artifact_hash=digest("bundle"),
                )

    def test_venue_manifest_registration_v1_and_bogus_v2_paths_are_typed(self) -> None:
        """Wiring-only fixture: it cannot mint scientific revision authority."""

        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root)

            def source(label: str):
                return registry.put_bytes(
                    label.encode(), logical_type="fixture_parent",
                    origin="venue registration wiring fixture",
                    creator_role=Role.ORCHESTRATOR,
                )

            candidate_record = source("candidate")
            bundle_record = source("bundle")
            profile_record = source("profile")
            manuscript_record = source("structural-inventory")
            section_source = source("method")
            requirement_source = source("code")
            bogus_revision = source("not-an-issued-revision")
            bundle = self._eligible_policy_bundle()
            claim = bundle.claims[0]
            candidate = PaperCandidate(
                candidate_id="candidate-1", title="Untrusted title",
                claims=(
                    PaperClaim(
                        claim.claim_id, claim.text, claim.expressed_strength,
                        claim.evidence_hashes, central=True,
                        claim_type=claim.claim_type, scope=claim.scope,
                        confidence=claim.confidence,
                        verification_method=claim.verification_method,
                        permitted_strength=claim.permitted_strength,
                    ),
                ),
                numeric_assertions=(), references=(), assets=(),
                method_code_bindings=(), limitations=(),
                source_bundle_hashes=(
                    bundle.research_state_hash, bundle.claim_graph_hash,
                    bundle.soundness_assessment_hash,
                ),
            )
            profile = VenueProfile(
                "fixture-profile", VenueFamily.ML_AI, ("methods",), ("code",)
            )
            structural = (
                (ManuscriptSection("methods", (section_source.sha256,)),),
                (ArtifactReadinessBinding("code", (requirement_source.sha256,)),),
                (section_source.sha256, requirement_source.sha256),
            )
            with (
                patch(
                    "scientist_one.paper_pipeline._resolve_candidate_bundle_artifacts"
                ),
                patch(
                    "scientist_one.paper_pipeline._read_paper_manuscript",
                    return_value=structural,
                ),
            ):
                record = register_venue_readiness_manifest(
                    registry, candidate, bundle, profile, run_id="run-1",
                    candidate_artifact_hash=candidate_record.sha256,
                    bundle_artifact_hash=bundle_record.sha256,
                    profile_artifact_hash=profile_record.sha256,
                    manuscript_artifact_hash=manuscript_record.sha256,
                )
                payload = safe_json_loads(registry.get_bytes(record.sha256))
                self.assertEqual(payload["schema_version"], "venue-readiness/v1")
                self.assertNotIn("manuscript_revision_artifact_hash", payload)
                metadata = registry.get_metadata(record.sha256)
                self.assertEqual(
                    metadata.origin,
                    "structural venue inventory; no manuscript prose authority",
                )
                self.assertEqual(
                    metadata.creation_command,
                    ("scientist-one", "register-venue-readiness"),
                )
                with self.assertRaises(ArtifactError):
                    registry.put_bytes(
                        registry.get_bytes(record.sha256),
                        logical_type=metadata.logical_type,
                        origin="forged venue-readiness provenance",
                        creator_role=metadata.creator_role,
                        creation_command=metadata.creation_command,
                        parent_artifacts=metadata.parent_artifacts,
                        schema_version=metadata.schema_version,
                        mime_type=metadata.mime_type,
                    )
                with self.assertRaises(ValidationError):
                    register_venue_readiness_manifest(
                        registry, candidate, bundle, profile, run_id="run-1",
                        candidate_artifact_hash=candidate_record.sha256,
                        bundle_artifact_hash=bundle_record.sha256,
                        profile_artifact_hash=profile_record.sha256,
                        manuscript_artifact_hash=manuscript_record.sha256,
                        ledger=ledger,
                        manuscript_revision_artifact_hash=bogus_revision.sha256,
                    )

    def test_legacy_manuscript_inventory_requires_exact_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)

            def source(label: str):
                return registry.put_bytes(
                    label.encode(), logical_type="fixture_parent",
                    origin="manuscript envelope fixture",
                    creator_role=Role.ORCHESTRATOR,
                )

            candidate_record = source("candidate")
            bundle_record = source("bundle")
            profile_record = source("profile")
            evidence = source("section-source")
            bundle = replace(
                self._eligible_policy_bundle(),
                run_id="run-1",
                research_state_artifact_hashes=(digest("state-artifact"),),
                research_state_ledger_head_hash=digest("state-head"),
                research_state_ledger_event_count=1,
                research_state_code_version="fixture-code",
                research_state_configuration_hash=digest("state-configuration"),
            )
            claim = bundle.claims[0]
            candidate = PaperCandidate(
                candidate_id="candidate-1", title="Inventory title",
                claims=(
                    PaperClaim(
                        claim.claim_id, claim.text, claim.expressed_strength,
                        claim.evidence_hashes, central=True,
                        claim_type=claim.claim_type, scope=claim.scope,
                        confidence=claim.confidence,
                        verification_method=claim.verification_method,
                        permitted_strength=claim.permitted_strength,
                    ),
                ),
                numeric_assertions=(), references=(), assets=(),
                method_code_bindings=(), limitations=(),
                source_bundle_hashes=(
                    bundle.research_state_hash, bundle.claim_graph_hash,
                    bundle.soundness_assessment_hash,
                ),
            )
            profile = VenueProfile(
                "fixture-profile", VenueFamily.ML_AI,
                ("limitations",), ("data_identity",),
            )
            inventory = {
                "schema_version": "paper-manuscript/v1",
                "run_id": "run-1", "candidate_id": candidate.candidate_id,
                "candidate_artifact_hash": candidate_record.sha256,
                "bundle_artifact_hash": bundle_record.sha256,
                "profile_id": profile.profile_id,
                "profile_sha256": profile.sha256,
                "profile_artifact_hash": profile_record.sha256,
                "sections": [{
                    "section_id": "limitations",
                    "source_artifact_hashes": [evidence.sha256],
                }],
                "artifact_bindings": [{
                    "requirement": "data_identity",
                    "artifact_hashes": [evidence.sha256],
                }],
            }
            record = registry.put_json(
                inventory, logical_type="paper_manuscript",
                origin="deterministic paper section and authoritative-source inventory",
                creator_role=Role.PAPER_WRITER,
                creation_command=("scientist-one", "register-paper-manuscript"),
                parent_artifacts=(
                    candidate_record.sha256, bundle_record.sha256,
                    profile_record.sha256, evidence.sha256,
                ),
                schema_version="1.0", mime_type="application/json",
            )
            with (
                patch(
                    "scientist_one.paper_pipeline.require_approved_venue_profile",
                    return_value=profile,
                ),
                patch("scientist_one.paper_pipeline._validate_manuscript_coverage"),
            ):
                sections, bindings, sources = _read_paper_manuscript(
                    registry, record.sha256, candidate, bundle, profile,
                    run_id="run-1",
                    candidate_artifact_hash=candidate_record.sha256,
                    bundle_artifact_hash=bundle_record.sha256,
                    profile_artifact_hash=profile_record.sha256,
                )
            self.assertEqual(sections[0].section_id, "limitations")
            self.assertEqual(bindings[0].requirement, "data_identity")
            self.assertEqual(sources, (evidence.sha256,))
            with self.assertRaises(ArtifactError):
                registry.put_json(
                    inventory, logical_type="paper_manuscript",
                    origin="forged manuscript provenance",
                    creator_role=Role.PAPER_WRITER,
                    creation_command=("scientist-one", "register-paper-manuscript"),
                    parent_artifacts=record.parent_artifacts,
                    schema_version="1.0", mime_type="application/json",
                )

    def test_inert_revision_artifact_is_not_a_manuscript_without_event(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry, ledger, composition, revision, record, records = (
                self._inert_revision_case(root)
            )
            with self.assertRaisesRegex(
                ValidationError, "lacks one exact issuance event"
            ):
                _require_revision_event(
                    registry, ledger, record, revision, composition, records
                )
            self.assertEqual(ledger.validate(raise_on_error=True).event_count, 1)

    def test_predated_exact_orphan_cannot_be_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry, ledger, _, _, record, _ = self._inert_revision_case(root)
            historical = ledger.validate(raise_on_error=True).events
            old_record = replace(
                record, created_at="2000-01-01T00:00:00Z", record_hash=None
            )
            with self.assertRaisesRegex(ValidationError, "cannot predate"):
                _validate_revision_timestamp(old_record, historical)

    def test_predated_revision_with_exact_event_fails_full_readback(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry, ledger, composition, revision, record, records = (
                self._inert_revision_case(
                    root, revision_created_at="2000-01-01T00:00:00Z"
                )
            )
            prior = ledger.last_event()
            assert prior is not None
            issuance = LedgerEvent.create(
                run_id=revision.run_id, actor_role=Role.PAPER_WRITER,
                state_before=prior.requested_state_after,
                requested_state_after=prior.requested_state_after,
                artifact_hashes=(record.sha256,), code_version="fixture-code-v1",
                configuration_hash=composition.research_state_binding[
                    "configuration_hash"
                ],
                reason="issued deterministic evidence-only manuscript revision",
                prior_event_hash=prior.event_hash,
                event_id=f"pmr-{record.sha256[:48]}",
                timestamp=record.created_at, event_type="CHECKPOINT",
                metadata=_revision_event_metadata(records, revision, composition),
            )
            ledger.append(issuance)
            with self.assertRaisesRegex(ValidationError, "cannot predate"):
                _require_revision_event(
                    registry, ledger, record, revision, composition, records
                )

    def test_unrelated_append_is_accepted_but_correction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry, ledger, composition, revision, record, records = (
                self._inert_revision_case(root)
            )
            prior = ledger.last_event()
            assert prior is not None
            issuance = LedgerEvent.create(
                run_id=revision.run_id, actor_role=Role.PAPER_WRITER,
                state_before=prior.requested_state_after,
                requested_state_after=prior.requested_state_after,
                artifact_hashes=(record.sha256,), code_version="fixture-code-v1",
                configuration_hash=composition.research_state_binding[
                    "configuration_hash"
                ],
                reason="issued deterministic evidence-only manuscript revision",
                prior_event_hash=prior.event_hash,
                event_id=f"pmr-{record.sha256[:48]}",
                timestamp=record.created_at, event_type="CHECKPOINT",
                metadata=_revision_event_metadata(
                    records, revision, composition
                ),
            )
            ledger.append(issuance)
            ledger.record(
                run_id=revision.run_id, actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.WRITE,
                requested_state_after=MacroState.WRITE,
                artifact_hashes=(), code_version="fixture-code-v1",
                configuration_hash=composition.research_state_binding[
                    "configuration_hash"
                ],
                reason="unrelated later append", event_id="unrelated-append",
                event_type="CHECKPOINT",
            )
            self.assertEqual(
                _require_revision_event(
                    registry, ledger, record, revision, composition, records
                ),
                issuance,
            )
            ledger.record(
                run_id=revision.run_id, actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.WRITE,
                requested_state_after=MacroState.WRITE,
                artifact_hashes=(), code_version="fixture-code-v1",
                configuration_hash=composition.research_state_binding[
                    "configuration_hash"
                ],
                reason="correct the manuscript issuance",
                event_id="corrected-issuance", event_type="CORRECTION",
                supersedes_event_id=issuance.event_id,
            )
            with self.assertRaisesRegex(ValidationError, "was corrected"):
                _require_revision_event(
                    registry, ledger, record, revision, composition, records
                )

    def test_post_scan_revision_appearance_is_detected_before_loser_writes(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry, ledger, base_composition, base_revision, _, records = (
                self._inert_revision_case(root)
            )
            bundle = self._eligible_policy_bundle()
            claim = bundle.claims[0]
            candidate = PaperCandidate(
                candidate_id="race-candidate", title="Untrusted race title",
                claims=(
                    PaperClaim(
                        claim.claim_id, claim.text, claim.expressed_strength,
                        claim.evidence_hashes, central=True,
                        claim_type=claim.claim_type, scope=claim.scope,
                        confidence=claim.confidence,
                        verification_method=claim.verification_method,
                        permitted_strength=claim.permitted_strength,
                    ),
                ),
                numeric_assertions=(), references=(), assets=(),
                method_code_bindings=(), limitations=(),
                source_bundle_hashes=(
                    bundle.research_state_hash, bundle.claim_graph_hash,
                    bundle.soundness_assessment_hash,
                ),
            )
            race_composition = replace(
                base_composition,
                manuscript_id="race-manuscript",
                candidate_id=candidate.candidate_id,
                authority_scope="SCIENTIFIC_EVIDENCE",
            )
            race_revision = replace(
                base_revision,
                manuscript_id="race-manuscript",
            )
            race_bytes = canonical_json_bytes(race_revision.to_dict()) + b"\n"
            race_parents = (
                race_revision.composition_input_artifact_hash,
                race_revision.content_artifact_hash,
                race_revision.composition_verification_artifact_hash,
                race_revision.candidate_artifact_hash,
                race_revision.bundle_artifact_hash,
                race_revision.paper_verification_artifact_hash,
            )
            derivation_entered = threading.Event()
            published = threading.Event()
            observed: dict[str, object] = {}

            def winner() -> None:
                derivation_entered.wait(timeout=5)
                record = registry.put_bytes(
                    race_bytes, logical_type="paper_manuscript_revision",
                    origin="issued deterministic evidence-only manuscript revision",
                    creator_role=Role.PAPER_WRITER,
                    creation_command=(
                        "scientist-one", "paper", "issue-manuscript-revision"
                    ),
                    parent_artifacts=race_parents, schema_version="1.0",
                    mime_type="application/json",
                )
                prior = ledger.last_event()
                assert prior is not None
                event = LedgerEvent.create(
                    run_id="fixture-run", actor_role=Role.PAPER_WRITER,
                    state_before=prior.requested_state_after,
                    requested_state_after=prior.requested_state_after,
                    artifact_hashes=(record.sha256,), code_version="fixture-code-v1",
                    configuration_hash=digest("orphan-configuration"),
                    reason="issued deterministic evidence-only manuscript revision",
                    prior_event_hash=prior.event_hash,
                    event_id=f"pmr-{record.sha256[:48]}",
                    timestamp=record.created_at, event_type="CHECKPOINT",
                    metadata=_revision_event_metadata(
                        (*records[:3], record), race_revision, race_composition
                    ),
                )
                ledger.append(event)
                observed["winner"] = record.sha256
                observed["winner_registry_count"] = registry.verify_all(
                    raise_on_error=True
                ).count
                observed["winner_ledger_count"] = ledger.validate(
                    raise_on_error=True
                ).event_count
                published.set()

            def paused_derivation(*args, **kwargs):
                derivation_entered.set()
                if not published.wait(timeout=5):
                    raise AssertionError("race winner did not publish")
                return race_composition

            def loser() -> None:
                try:
                    register_paper_manuscript_revision(
                        registry, ledger, candidate, bundle,
                        run_id="fixture-run", manuscript_id="race-manuscript",
                        revision=1,
                        candidate_artifact_hash=(
                            base_revision.candidate_artifact_hash
                        ),
                        bundle_artifact_hash=base_revision.bundle_artifact_hash,
                        verification_artifact_hash=(
                            base_revision.paper_verification_artifact_hash
                        ),
                    )
                except ValidationError as exc:
                    observed["loser_error"] = str(exc)
                else:
                    observed["loser_error"] = None

            with (
                patch(
                    "scientist_one.paper_composition._resolve_candidate_bundle_artifacts"
                ),
                patch(
                    "scientist_one.paper_composition._derive_composition_input",
                    side_effect=paused_derivation,
                ),
            ):
                threads = (
                    threading.Thread(target=winner),
                    threading.Thread(target=loser),
                )
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=10)
                    self.assertFalse(thread.is_alive())
            self.assertIn(
                "paper authority changed during fresh composition replay",
                observed["loser_error"],
            )
            self.assertEqual(
                registry.verify_all(raise_on_error=True).count,
                observed["winner_registry_count"],
            )
            self.assertEqual(
                ledger.validate(raise_on_error=True).event_count,
                observed["winner_ledger_count"],
            )
            admitted = {
                digest_value
                for event in ledger.validate(raise_on_error=True).events
                for digest_value in event.artifact_hashes
                if digest_value == observed["winner"]
            }
            self.assertEqual(len(admitted), 1)

    def test_public_replay_rejects_two_event_admitted_revision_roots(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry, ledger, _, revision, first, _ = self._inert_revision_case(root)
            alternate_content = registry.put_bytes(
                b"alternate content", logical_type="paper_manuscript_content",
                origin="inert revision test", creator_role=Role.PAPER_WRITER,
            )
            second_revision = replace(
                revision, content_artifact_hash=alternate_content.sha256
            )
            second_parents = (
                second_revision.composition_input_artifact_hash,
                second_revision.content_artifact_hash,
                second_revision.composition_verification_artifact_hash,
                second_revision.candidate_artifact_hash,
                second_revision.bundle_artifact_hash,
                second_revision.paper_verification_artifact_hash,
            )
            second = registry.put_bytes(
                canonical_json_bytes(second_revision.to_dict()) + b"\n",
                logical_type="paper_manuscript_revision",
                origin="issued deterministic evidence-only manuscript revision",
                creator_role=Role.PAPER_WRITER,
                creation_command=(
                    "scientist-one", "paper", "issue-manuscript-revision"
                ),
                parent_artifacts=second_parents, schema_version="1.0",
                mime_type="application/json",
            )
            for index, record in enumerate((first, second), start=1):
                ledger.record(
                    run_id="fixture-run", actor_role=Role.PAPER_WRITER,
                    state_before=MacroState.WRITE,
                    requested_state_after=MacroState.WRITE,
                    artifact_hashes=(record.sha256,),
                    code_version="fixture-code-v1",
                    configuration_hash=digest("orphan-configuration"),
                    reason="ambiguous imported revision root",
                    event_id=f"ambiguous-root-{index}", event_type="CHECKPOINT",
                )
            with self.assertRaisesRegex(ValidationError, "unique admitted root"):
                require_paper_manuscript_revision(
                    registry, ledger, revision_artifact_hash=first.sha256
                )

    def test_current_event_replay_rechecks_roots_after_entry_scan(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            registry, ledger, composition, revision, first, records = (
                self._inert_revision_case(root)
            )
            prior = ledger.last_event()
            assert prior is not None
            first_event = LedgerEvent.create(
                run_id=revision.run_id, actor_role=Role.PAPER_WRITER,
                state_before=prior.requested_state_after,
                requested_state_after=prior.requested_state_after,
                artifact_hashes=(first.sha256,), code_version="fixture-code-v1",
                configuration_hash=composition.research_state_binding[
                    "configuration_hash"
                ],
                reason="issued deterministic evidence-only manuscript revision",
                prior_event_hash=prior.event_hash,
                event_id=f"pmr-{first.sha256[:48]}",
                timestamp=first.created_at, event_type="CHECKPOINT",
                metadata=_revision_event_metadata(
                    records, revision, composition
                ),
            )
            ledger.append(first_event)
            entry_roots = _event_admitted_revision_identity_hashes(
                registry,
                ledger.validate(raise_on_error=True).events,
                manuscript_id=revision.manuscript_id,
                revision=revision.revision,
            )
            self.assertEqual(entry_roots, frozenset((first.sha256,)))

            alternate_content = registry.put_bytes(
                b"second imported content",
                logical_type="paper_manuscript_content",
                origin="inert revision test", creator_role=Role.PAPER_WRITER,
            )
            second_revision = replace(
                revision, content_artifact_hash=alternate_content.sha256
            )
            second = registry.put_bytes(
                canonical_json_bytes(second_revision.to_dict()) + b"\n",
                logical_type="paper_manuscript_revision",
                origin="issued deterministic evidence-only manuscript revision",
                creator_role=Role.PAPER_WRITER,
                creation_command=(
                    "scientist-one", "paper", "issue-manuscript-revision"
                ),
                parent_artifacts=(
                    second_revision.composition_input_artifact_hash,
                    second_revision.content_artifact_hash,
                    second_revision.composition_verification_artifact_hash,
                    second_revision.candidate_artifact_hash,
                    second_revision.bundle_artifact_hash,
                    second_revision.paper_verification_artifact_hash,
                ),
                schema_version="1.0", mime_type="application/json",
            )
            barrier = threading.Barrier(2)
            published = threading.Event()
            observed: dict[str, object] = {}

            def importer() -> None:
                barrier.wait()
                current = ledger.last_event()
                assert current is not None
                ledger.record(
                    run_id=revision.run_id, actor_role=Role.PAPER_WRITER,
                    state_before=current.requested_state_after,
                    requested_state_after=current.requested_state_after,
                    artifact_hashes=(second.sha256,),
                    code_version="fixture-code-v1",
                    configuration_hash=composition.research_state_binding[
                        "configuration_hash"
                    ],
                    reason="second imported revision root",
                    event_id=f"pmr-{second.sha256[:48]}",
                    event_type="CHECKPOINT",
                )
                published.set()

            def reader() -> None:
                barrier.wait()
                if not published.wait(timeout=5):
                    observed["error"] = "import timeout"
                    return
                try:
                    _require_revision_event(
                        registry, ledger, first, revision, composition, records
                    )
                except ValidationError as exc:
                    observed["error"] = str(exc)

            threads = (threading.Thread(target=importer), threading.Thread(target=reader))
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())
            self.assertIn("unique admitted root", observed["error"])

    def test_research_os_fixture_has_no_composition_callsite(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src"
            / "scientist_one"
            / "research_os.py"
        ).read_text()
        for forbidden in (
            "register_paper_manuscript_revision",
            'logical_type="paper_composition_input"',
            'logical_type="paper_manuscript_content"',
            'logical_type="paper_manuscript_revision"',
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
