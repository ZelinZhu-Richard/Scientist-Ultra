"""Non-evidentiary regression probes for private same-round replay seams.

Peer stand-ins below are NOT issued semantic authority. They isolate the
aggregate/cache boundary; no provider, signer, or positive issuer is replaced.
"""

from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scientist_one import evaluators, gates
from scientist_one.errors import ValidationError
from scientist_one.roles import Role
from tests import test_challenger_audit_authority as audit_fixtures
from tests import test_terminal_outcomes as terminal_fixtures


class SoundnessRoundReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = terminal_fixtures.TerminalOutcomeIntegrationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.registry = self.fixture.registry
        self.ledger = self.fixture.ledger
        self.assessment = self.fixture.assessment(run_id=self.fixture.repository.run_id)

    def _peer_stubs_for_rejection(self):
        """Round-shaped stand-ins, without any publication/issuance claim."""

        assessment = self.assessment
        digest = audit_fixtures._digest
        fields = dict(
            assessment_id=assessment.assessment_id,
            run_id=assessment.run_id,
            research_state_snapshot_artifact_hash=digest("unissued-snapshot"),
            research_state_snapshot_artifact_record_hash=digest("unissued-snapshot-record"),
            claim_graph_artifact_hash=assessment.claim_graph_artifact_hash,
            claim_graph_artifact_record_hash=self.registry.get_metadata(
                assessment.claim_graph_artifact_hash
            ).record_hash,
            central_claim_ids=assessment.central_claim_ids,
            result_artifact_hashes=(digest("unissued-result"),),
            result_artifact_record_hashes=(digest("unissued-result-record"),),
        )
        peers = tuple(
            gates._SemanticChallengerAuditPublishedPeer(
                authority=SimpleNamespace(**fields, category=category),
                record=None, slot=None, findings=(), publication_event_index=1,
                review=next(item for item in assessment.challenger_reviews if item.category is category),
            )
            for category in gates._SEMANTIC_CHALLENGER_CATEGORIES
        )
        return SimpleNamespace(**fields), peers

    def _aggregate(self, value):
        return self.registry.put_json(
            {"schema_version": "scientific-soundness-assessment/v2", "assessment": value},
            logical_type=gates.SOUNDNESS_ASSESSMENT_LOGICAL_TYPE,
            schema_version=gates.SOUNDNESS_ASSESSMENT_SCHEMA_VERSION,
            creator_role=Role.SCIENTIFIC_REVIEWER,
            origin="registry-rederived complete scientific soundness assessment",
            creation_command=("scientist-one", "record-scientific-soundness-assessment"),
            parent_artifacts=tuple(value["evidence_hashes"]),
            mime_type="application/json", validation_result="PASS", frozen=True,
        )

    def _review(self, review, *, parents=None):
        return self.registry.put_json(
            review.to_dict(),
            logical_type=gates.CHALLENGER_CATEGORY_REVIEW_LOGICAL_TYPE,
            schema_version=gates.CHALLENGER_CATEGORY_REVIEW_SCHEMA_VERSION,
            creator_role=Role.ADVERSARIAL_REVIEWER,
            origin="exact typed Challenger attack-category checklist entry",
            creation_command=("scientist-one", "record-challenger-category-review"),
            parent_artifacts=parents if parents is not None else (
                review.claim_graph_artifact_hash, *review.evidence_hashes,
                *review.finding_artifact_hashes, review.execution_receipt_hash,
            ),
            mime_type="application/json", validation_result="PASS", frozen=True,
        )

    def test_shared_derivation_preserves_real_incomplete_mechanical_control(self) -> None:
        assessment = self.assessment
        fresh = gates._derive_soundness_assessment(
            self.registry, assessment.assessment_id,
            assessment.dimension_receipt_hashes, assessment.challenger_review_hashes,
            claim_graph_artifact_hash=assessment.claim_graph_artifact_hash,
            central_claim_ids=assessment.central_claim_ids, reason=assessment.reason,
            ledger=self.ledger, run_id=assessment.run_id,
        )
        self.assertEqual(fresh.to_dict(), assessment.to_dict())
        self.assertIsNot(fresh.verdict, gates.SoundnessVerdict.PASS)

    def test_round_rejects_canonical_aggregate_with_dummy_dimension_owner(self) -> None:
        value = self.assessment.to_dict()
        dummy = self.fixture.evidence("not a soundness dimension receipt")
        old = value["dimension_receipt_hashes"][0]
        value["dimension_receipt_hashes"][0] = dummy.sha256
        value["evidence_hashes"] = [dummy.sha256 if item == old else item for item in value["evidence_hashes"]]
        forged = self._aggregate(value)
        # The old wrapper/DTO parser accepts these canonical bytes. Acceptance
        # is not authority: the repaired full derivation must reopen the owner.
        parsed = gates._semantic_challenger_audit_parse_soundness(self.registry, forged)
        self.assertEqual(parsed.to_dict(), value)
        slot, peers = self._peer_stubs_for_rejection()
        with self.assertRaises(ValidationError):
            gates._semantic_challenger_audit_round_soundness(
                self.registry, self.ledger, audit_slot=slot, peers=peers,
                soundness_artifact_hashes=frozenset({forged.sha256}),
            )

    def test_deterministic_review_cannot_use_semantic_peer_cache(self) -> None:
        _, peers = self._peer_stubs_for_rejection()
        dummy = self.fixture.evidence("not an executed deterministic attack")
        for category in (gates.ChallengeCategory.ALTERNATIVE_EXPLANATION,
                         gates.ChallengeCategory.EXTERNAL_VALIDITY):
            review = replace(
                next(item for item in self.assessment.challenger_reviews if item.category is category),
                execution_status=gates.ChallengerExecutionStatus.EXECUTED,
                execution_receipt_hash=dummy.sha256, deterministic=True,
            )
            record = self._review(review)
            with self.subTest(category=category), self.assertRaises(ValidationError):
                gates._soundness_category_review_with_round_peers(
                    self.registry, record.sha256, ledger=self.ledger, replay_peers=peers,
                )

    def test_round_requires_exact_unique_peer_round_before_source_body_reads(self) -> None:
        slot, peers = self._peer_stubs_for_rejection()
        poisoned = self.fixture.evidence("not a soundness aggregate")
        changed = replace(peers[0], authority=SimpleNamespace(
            **{**vars(peers[0].authority), "research_state_snapshot_artifact_hash": audit_fixtures._digest("other")}
        ))
        for supplied in ((*peers, peers[0]), (changed, *peers[1:])):
            with self.subTest(peers=supplied), self.assertRaisesRegex(ValidationError, "exact audited round"):
                gates._semantic_challenger_audit_round_soundness(
                    self.registry, self.ledger, audit_slot=slot, peers=supplied,
                    soundness_artifact_hashes=frozenset({poisoned.sha256}),
                )

    def test_unselected_malformed_aggregate_is_not_parsed(self) -> None:
        self.fixture.evidence("unrelated malformed aggregate body")
        slot, peers = self._peer_stubs_for_rejection()
        self.assertIsNone(gates._semantic_challenger_audit_round_soundness(
            self.registry, self.ledger, audit_slot=slot, peers=peers,
            soundness_artifact_hashes=frozenset(),
        ))

    def test_semantic_cache_checks_current_bytes_descriptor_and_parent_closure(self) -> None:
        base = next(item for item in self.assessment.challenger_reviews
                    if item.category is gates.ChallengeCategory.STATISTICS)
        dummy = self.fixture.evidence("unissued semantic execution DTO")
        for variant in ("exact", "record", "bytes", "parents", "source"):
            with self.subTest(variant=variant):
                review = replace(base, review_id=f"cache-{variant}",
                                 execution_status=gates.ChallengerExecutionStatus.EXECUTED,
                                 execution_receipt_hash=dummy.sha256)
                record = self._review(review, parents=() if variant == "parents" else None)
                peer = gates._SemanticChallengerAuditPublishedPeer(
                    authority=SimpleNamespace(
                        category=review.category,
                        challenger_review_artifact_hash=(audit_fixtures._digest("other-review")
                                                        if variant == "source" else record.sha256),
                        challenger_execution_artifact_hash=dummy.sha256,
                        input_artifact_hashes=(record.sha256,),
                        input_artifact_record_hashes=(audit_fixtures._digest("other-record")
                                                      if variant == "record" else record.record_hash,),
                    ),
                    record=None, slot=None, findings=(), publication_event_index=1,
                    review=replace(review, conclusion="Substituted conclusion.") if variant == "bytes" else review,
                )
                def replay():
                    return gates._soundness_category_review_with_round_peers(
                        self.registry, record.sha256, ledger=self.ledger, replay_peers=(peer,),
                    )
                if variant == "exact":
                    # Cache equality only, not a published or qualified audit.
                    self.assertEqual(replay(), review)
                else:
                    with self.assertRaisesRegex(ValidationError, "replayed semantic peer"):
                        replay()

    def test_shared_projection_slot_rejects_unpublished_malformed_aliases(self) -> None:
        for logical_type in (
            gates.SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_LOGICAL_TYPE,
            gates.CHALLENGER_ATTACK_EXECUTION_LOGICAL_TYPE,
            gates.CHALLENGER_CATEGORY_REVIEW_LOGICAL_TYPE,
        ):
            with self.subTest(logical_type=logical_type):
                parent = self.fixture.evidence(f"selected-parent-{logical_type}")
                def write(label, parents):
                    return self.registry.put_bytes(
                        label.encode(), logical_type=logical_type,
                        origin="unissued descriptor-only collision probe", creator_role=Role.ORCHESTRATOR,
                        creation_command=("scientist-one", "test-round-collision"),
                        parent_artifacts=parents, schema_version="1.0", mime_type="application/json",
                        validation_result="PASS", frozen=True,
                    )
                selected = write(f"unissued-selected-{logical_type}", (parent.sha256,))
                write(f"malformed-unrelated-{logical_type}", ())
                options = dict(logical_type=logical_type, parent_artifact_hash=parent.sha256, reason="ambiguous slot")
                with patch.object(self.registry, "get_bytes", side_effect=AssertionError("descriptor guard parsed body")):
                    gates._require_semantic_audit_unique_projection(self.registry, selected, **options)
                write(f"malformed-related-{logical_type}", (parent.sha256,))
                with patch.object(self.registry, "get_bytes", side_effect=AssertionError("descriptor guard parsed body")), self.assertRaisesRegex(ValidationError, "ambiguous slot"):
                    gates._require_semantic_audit_unique_projection(self.registry, selected, **options)

    def test_shared_finding_identity_check_ignores_other_graph_but_rejects_alias(self) -> None:
        evidence = self.fixture.evidence("non-evidentiary finding evidence")
        finding = gates.ChallengeFinding(
            challenge_id="finding-identity", category=gates.ChallengeCategory.STATISTICS,
            severity=gates.ChallengeSeverity.MAJOR, status=gates.ChallengeStatus.UNRESOLVED,
            target_claim_ids=self.assessment.central_claim_ids,
            claim_graph_artifact_hash=self.assessment.claim_graph_artifact_hash,
            evidence_hashes=(evidence.sha256,), attack="Original non-evidentiary finding.",
        )
        selected = gates.register_challenge_finding(self.registry, finding, ledger=self.ledger)
        self.registry.put_bytes(
            b"malformed unrelated finding", logical_type=gates.CHALLENGE_FINDING_LOGICAL_TYPE,
            origin="unrelated graph probe", creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "test-round-collision"), parent_artifacts=(),
            schema_version="1.0", mime_type="application/json", validation_result="PASS", frozen=True,
        )
        options = dict(slot=SimpleNamespace(category=finding.category, claim_graph_artifact_hash=finding.claim_graph_artifact_hash),
                       findings=(finding,), finding_artifact_hashes=(selected.sha256,))
        gates._require_semantic_audit_unique_findings(self.registry, self.ledger, **options)
        gates.register_challenge_finding(self.registry, replace(finding, attack="Substituted same-ID finding."), ledger=self.ledger)
        with self.assertRaisesRegex(ValidationError, "finding identity is ambiguous"):
            gates._require_semantic_audit_unique_findings(self.registry, self.ledger, **options)

    def test_shared_judgment_identity_guard_retains_subject_or_invocation_aliases(self) -> None:
        # Boolean ID reconciliation only; semantic source replay is not replaced
        # with a positive issuer and these are not valid receipt payloads.
        slot, _ = _incomplete_authority_dto()
        selected = SimpleNamespace(sha256="a" * 64, logical_type=gates.SEMANTIC_JUDGMENT_RECEIPT_LOGICAL_TYPE)
        other = SimpleNamespace(sha256="b" * 64, logical_type=gates.SEMANTIC_JUDGMENT_RECEIPT_LOGICAL_TYPE)
        for mode in ("unrelated", "subject", "invocation"):
            def load(_registry, digest):
                if digest == selected.sha256:
                    return SimpleNamespace(subject_id=slot.slot_id, invocation_id=slot.provider_invocation_id)
                return SimpleNamespace(subject_id=slot.slot_id if mode == "subject" else "other-slot",
                                       invocation_id=slot.provider_invocation_id if mode == "invocation" else "other-invocation")
            registry = SimpleNamespace(list_records=lambda: (selected, other))
            with self.subTest(mode=mode), patch.object(gates, "_load_semantic_judgment_receipt", side_effect=load):
                if mode == "unrelated":
                    gates._require_semantic_audit_unique_judgment(registry, slot=slot, judgment_artifact_hash=selected.sha256)
                else:
                    with self.assertRaisesRegex(ValidationError, "multiple completed judgments"):
                        gates._require_semantic_audit_unique_judgment(registry, slot=slot, judgment_artifact_hash=selected.sha256)


def _incomplete_authority_dto():
    """Typed UNTESTED value only; intentionally has no custody/publication."""

    slot = audit_fixtures.SemanticChallengerAuditAuthorityTests()._slot(
        category=gates.ChallengeCategory.REPRODUCTION, scientific_source_qualified=False,
    )
    digest = audit_fixtures._digest
    sources = tuple(digest(label) for label in ("judgment", "execution", "review"))
    records = tuple(digest(label) for label in ("judgment-record", "execution-record", "review-record"))
    copied = {name: getattr(slot, name) for name in (
        "assessment_id", "run_id", "category", "research_state_snapshot_artifact_hash",
        "research_state_snapshot_artifact_record_hash", "claim_graph_artifact_hash",
        "claim_graph_artifact_record_hash", "central_claim_ids", "evidence_artifact_hashes",
        "evidence_artifact_record_hashes", "result_artifact_hashes", "result_artifact_record_hashes",
        "reproducibility_package_artifact_hash", "slot_id", "provider_invocation_id",
        "procedure_id", "procedure_version", "prompt_template_hash", "ledger_path",
    )}
    authority = gates.SemanticChallengeAuditAuthority(
        **copied, authority_id="unissued-incomplete-authority",
        slot_subject_sha256=slot.subject_sha256, slot_event_id=slot.event_id,
        slot_event_hash=slot.event_hash, slot_event_index=slot.event_index,
        semantic_judgment_artifact_hash=sources[0], semantic_judgment_artifact_record_hash=records[0],
        challenger_execution_artifact_hash=sources[1], challenger_execution_artifact_record_hash=records[1],
        challenger_review_artifact_hash=sources[2], challenger_review_artifact_record_hash=records[2],
        finding_artifact_hashes=(), finding_artifact_record_hashes=(),
        status=gates.SemanticChallengeAuditStatus.UNTESTED, scientific_source_qualified=False,
        residual_risk_summary="Incomplete mechanical DTO; no review execution or authority is claimed.",
        input_artifact_hashes=(*slot.scoped_artifact_hashes, *sources),
        input_artifact_record_hashes=(*slot.scoped_artifact_record_hashes, *records),
        verification_event_id="unissued-event", verification_event_hash=digest("unissued-event"),
        verification_event_index=slot.event_index + 1,
    )
    return slot, authority


class R7RoundCacheTests(unittest.TestCase):
    def test_private_peer_acquisition_avoids_public_cycle_but_is_exact(self) -> None:
        slot, authority = _incomplete_authority_dto()
        record = SimpleNamespace(sha256=audit_fixtures._digest("unissued-authority"),
                                 record_hash=audit_fixtures._digest("unissued-authority-record"),
                                 logical_type="semantic_challenge_audit_authority",
                                 schema_version="1.0")
        peer = gates._SemanticChallengerAuditPublishedPeer(
            authority=authority, record=record, slot=slot, findings=(),
            publication_event_index=5, review=None,
        )
        options = dict(expected_category=gates.ChallengeCategory.REPRODUCTION, _replayed_peer=peer)
        with patch.object(gates, "require_semantic_challenge_audit_authority",
                          side_effect=AssertionError("private cache must not reenter current audit")):
            self.assertEqual(evaluators._replay_semantic_audit_source(
                None, None, authority.run_id, record, authority.to_dict(), **options,
            ), authority)
            for variant in ("run", "category", "record", "payload", "peer-type"):
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    changed = dict(options)
                    payload = authority.to_dict()
                    if variant == "category":
                        changed["expected_category"] = gates.ChallengeCategory.STATISTICS
                    if variant == "payload":
                        payload["residual_risk_summary"] = "Substituted content."
                    if variant == "peer-type":
                        changed["_replayed_peer"] = SimpleNamespace(authority=authority, record=record)
                    evaluators._replay_semantic_audit_source(
                        None, None, "another-run" if variant == "run" else authority.run_id,
                        SimpleNamespace(sha256=record.sha256, record_hash="0" * 64,
                                        logical_type=record.logical_type,
                                        schema_version=record.schema_version) if variant == "record" else record,
                        payload, **changed,
                    )
