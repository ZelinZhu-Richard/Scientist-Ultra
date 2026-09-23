"""Caller-mutation control over real, non-authorizing revision publication."""

import unittest
from unittest import mock

import scientist_one.scientific_protocol_revision as revision
from tests import test_scientific_protocol_revision as fixtures


class ProtocolRevisionDetachedInputTests(unittest.TestCase):
    def test_caller_mutation_after_reparse_cannot_change_owned_protocol(self):
        case = fixtures.ScientificProtocolRevisionTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        before = case.snapshot()
        intended_hash = case.child_protocol.sha256
        intended_reserve = case.child_protocol.validity_reserve_fraction
        original_snapshot = revision._locked_checked_result_authority_snapshot
        mutated = False

        def snapshot_after_caller_mutation(*args, **kwargs):
            nonlocal mutated
            if not mutated:
                # This seam changes only the external caller's object after
                # reparse. It still executes the real snapshot and all owners.
                object.__setattr__(case.child_protocol, "validity_reserve_fraction", 0.1)
                mutated = True
            return original_snapshot(*args, **kwargs)

        with mock.patch.object(
            revision,
            "_locked_checked_result_authority_snapshot",
            side_effect=snapshot_after_caller_mutation,
        ):
            publication = case.publish()

        after = case.snapshot()
        self.assertTrue(mutated)
        self.assertEqual(case.child_protocol.validity_reserve_fraction, 0.1)
        self.assertEqual(publication.protocol.validity_reserve_fraction, intended_reserve)
        self.assertEqual(publication.protocol.sha256, intended_hash)
        self.assertIsNot(publication.protocol, case.child_protocol)
        self.assertFalse(publication.authority.confirmation_authorized)
        self.assertEqual(after[0].count, before[0].count + 1)
        self.assertEqual(after[1].event_count, before[1].event_count + 1)
        self.assertEqual(
            revision.require_scientific_protocol_revision(
                case.registry,
                case.ledger,
                expected_run_id=publication.authority.ledger_run_id,
                protocol_artifact_sha256=publication.protocol_record.sha256,
            ),
            publication,
        )
        self.assertEqual(case.snapshot(), after)


if __name__ == "__main__":
    unittest.main()
