"""Frozen-source disclosure checks, not a public-release audit approval."""

from pathlib import Path
import unittest

from scientist_one.orchestrator import _source_inventory
from scientist_one.packaging import _contains_forbidden_boundary_text


class PackagingSourceBoundaryTests(unittest.TestCase):
    def test_fixed_git_tools_and_pmc_route_are_source_only_references(self):
        for reference in (
            b"/usr/bin/git",
            b"/Library/Developer/CommandLineTools/usr/bin/git",
            b"/api/oai/v1/mh/",
        ):
            with self.subTest(reference=reference):
                self.assertFalse(
                    _contains_forbidden_boundary_text(reference, source_member=True)
                )
                self.assertTrue(_contains_forbidden_boundary_text(reference))

    def test_approved_reference_is_not_a_directory_or_suffix_allowance(self):
        for reference in (
            b"/usr/bin/git-secret",
            b"/usr/bin/git/private-data",
            b"/Library/Developer/CommandLineTools/usr/bin/git/credentials",
            b"/api/oai/v1/mh/private-data",
            b"/private/customer/data",
        ):
            with self.subTest(reference=reference):
                self.assertTrue(
                    _contains_forbidden_boundary_text(reference, source_member=True)
                )

    def test_repeated_path_separators_cannot_truncate_an_approved_reference(self):
        for reference in (
            b"/usr/bin/git//private-data",
            b"/Library/Developer/CommandLineTools/usr/bin/git//credentials",
            b"/api/oai/v1/mh//private-data",
            b"//usr/bin/git/private-data",
            b"/usr//bin/git",
        ):
            with self.subTest(reference=reference):
                self.assertTrue(
                    _contains_forbidden_boundary_text(reference, source_member=True)
                )

    def test_actual_frozen_source_inventory_satisfies_existing_disclosure_guard(self):
        root = Path(__file__).resolve().parents[1]
        inventory = _source_inventory(root)
        self.assertGreater(len(inventory["entries"]), 1)
        for entry in inventory["entries"]:
            with self.subTest(path=entry["path"]):
                content = (root / entry["path"]).read_bytes()
                self.assertFalse(
                    _contains_forbidden_boundary_text(content, source_member=True),
                    entry["path"],
                )
