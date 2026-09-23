"""Independent canonical terminal Decision checks using non-evidentiary sources."""

from __future__ import annotations

from dataclasses import replace
import unittest

from scientist_one.errors import ValidationError
from scientist_one.models import MacroState
from scientist_one.research_state import thaw_json
from scientist_one.terminal_outcomes import (
    LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
    LEGACY_TERMINAL_OUTCOME_SCHEMA_VERSION,
    TERMINAL_OUTCOME_LOGICAL_TYPE,
    TerminalAuthorityScope,
    _terminal_decision,
    load_terminal_outcome,
)
from tests import test_terminal_outcomes as terminal_fixtures


class TerminalDecisionReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        # Import the fixture module, not its TestCase into this module's namespace;
        # unittest discovery must not silently count its original tests twice.
        self.fixture = terminal_fixtures.TerminalOutcomeIntegrationTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        _assessment, _source, derivation = self.fixture.authority()
        self.record = self.fixture.record(derivation)

    def publish_source(self, record, **metadata_changes):
        metadata = {
            "logical_type": TERMINAL_OUTCOME_LOGICAL_TYPE,
            "origin": f"research-terminal:{record.run_id}:{record.record_id}",
            "creator_role": record.producer,
            "creation_command": self.fixture.repository.creation_command,
            "parent_artifacts": record.evidence_artifact_hashes,
            "schema_version": record.schema_version,
            "mime_type": "application/json",
            "validation_result": "PASS",
            "frozen": True,
            "created_at": record.created_at,
        }
        metadata.update(metadata_changes)
        return self.fixture.registry.put_bytes(record.canonical_bytes(), **metadata)

    def test_direct_canonical_materialization_requires_the_complete_owner_decision(self) -> None:
        source = self.publish_source(self.record)
        expected = _terminal_decision(
            self.record, self.fixture.repository, source.sha256
        )
        metadata = thaw_json(expected.metadata)
        without_scope = dict(metadata)
        del without_scope["terminal_authority_scope"]
        variants = (
            replace(expected, decision_type="ANOTHER_DECISION_TYPE", content_hash=None),
            replace(expected, governing_rule="unreviewed-terminal-rule", content_hash=None),
            replace(expected, uncertainty=0.5, content_hash=None),
            replace(expected, alternatives=("another possible outcome",), content_hash=None),
            replace(expected, consequences=("Different operational consequence.",), content_hash=None),
            replace(expected, metadata=without_scope, content_hash=None),
            replace(
                expected,
                metadata={
                    **metadata,
                    "terminal_authority_scope": (
                        TerminalAuthorityScope.SCIENTIFIC_EVIDENCE.value
                    ),
                },
                content_hash=None,
            ),
            replace(expected, metadata={**metadata, "unowned_annotation": True}, content_hash=None),
        )
        artifacts_before = self.fixture.registry.list_records()
        events_before = self.fixture.ledger.events()
        for variant in variants:
            with self.subTest(content_hash=variant.content_hash):
                with self.assertRaisesRegex(
                    ValidationError, "canonical terminal Decision differs"
                ):
                    self.fixture.repository.materialize(variant)
                self.assertEqual(
                    self.fixture.registry.list_records(), artifacts_before
                )
                self.assertEqual(self.fixture.ledger.events(), events_before)
        materialized = self.fixture.repository.materialize(expected)
        self.assertEqual(materialized.research_object, expected)
        self.assertEqual(
            load_terminal_outcome(
                self.fixture.registry,
                source.sha256,
                repository=self.fixture.repository,
            ),
            self.record,
        )
        self.assertIs(self.fixture.repository.state, MacroState.CONFIRM)

    def test_direct_canonical_materialization_checks_same_run_source_metadata(self) -> None:
        source = self.publish_source(
            self.record,
            origin="terminal source outside its repository run binding",
        )
        decision = _terminal_decision(
            self.record, self.fixture.repository, source.sha256
        )
        with self.assertRaisesRegex(
            ValidationError, "canonical terminal Decision differs"
        ):
            self.fixture.repository.materialize(decision)

    def test_direct_canonical_materialization_checks_exact_source_schema(self) -> None:
        source = self.publish_source(self.record, schema_version="99.0")
        decision = _terminal_decision(
            self.record, self.fixture.repository, source.sha256
        )
        with self.assertRaisesRegex(
            ValidationError, "terminal Decision derivation failed"
        ):
            self.fixture.repository.materialize(decision)

    def test_legacy_v2_canonical_decision_keeps_its_historical_shape(self) -> None:
        derivation = replace(
            self.record.derivation,
            mapping_id=LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
            source_binding=replace(
                self.record.derivation.source_binding, source_record_hash=None
            ),
            authority_scope=None,
        )
        legacy = replace(
            self.record,
            schema_version=LEGACY_TERMINAL_OUTCOME_SCHEMA_VERSION,
            derivation=derivation,
            authority_scope=None,
        )
        source = self.publish_source(legacy)
        decision = _terminal_decision(
            legacy, self.fixture.repository, source.sha256
        )
        self.assertNotIn("terminal_authority_scope", decision.metadata)
        self.assertEqual(
            self.fixture.repository.materialize(decision).research_object, decision
        )
        self.assertEqual(
            load_terminal_outcome(
                self.fixture.registry,
                source.sha256,
                repository=self.fixture.repository,
            ),
            legacy,
        )


if __name__ == "__main__":
    unittest.main()
