"""Synthetic supplied-data joins; never live, native, signed or scientific evidence."""
from dataclasses import replace
import unittest

from tests import test_pmc_wire_replay as fixtures


class PmcWireRootJoins(unittest.TestCase):
    def fixture(self):
        return fixtures.PmcWireReplayEdges.fixture(self)

    def replay(self, case):
        return fixtures._replay_pmc_wire_attempts(*case)

    def test_complete_chunked_control_without_length_is_a_valid_supplied_shape(self):
        case = self.fixture()
        row = case[3]["attempts"][0]
        row["control_headers"] = [p for p in row["control_headers"] if p[0] != "content-length"]
        case[3]["headers"].pop("content-length")
        row["control_headers"].append(["transfer-encoding", "chunked"])
        # No claim of reconstructing transfer framing from representation bytes.
        self.assertIsNone(self.replay(case))

    def test_simultaneous_content_length_and_transfer_encoding_refuses(self):
        case = self.fixture()
        row = case[3]["attempts"][0]
        self.assertEqual([p for p in row["control_headers"] if p[0] == "content-length"],
                         [["content-length", str(row["body_size"])]])
        row["control_headers"].append(["transfer-encoding", "chunked"])
        with self.assertRaises(fixtures.EgressPolicyError):
            self.replay(case)

    def test_unsupported_transfer_encoding_grammar_refuses(self):
        for value in ("gzip", "gzip, chunked", "chunked, chunked", "chunked; mode=test"):
            with self.subTest(value=value):
                case = self.fixture()
                row = case[3]["attempts"][0]
                row["control_headers"] = [p for p in row["control_headers"] if p[0] != "content-length"]
                case[3]["headers"].pop("content-length")
                row["control_headers"].append(["transfer-encoding", value])
                with self.assertRaises(fixtures.EgressPolicyError):
                    self.replay(case)

    def set_times(self, case, pending):
        coordination = case[3]["attempts"][0]["coordination"]
        coordination["pending_observed_ns"] = pending
        coordination["schedule"]["observation_start_ns"] = pending + 5
        coordination["schedule"]["observation_end_ns"] = pending + 10
        coordination["cleanup_ns"] = pending + 20
        coordination["terminal_observed_ns"] = pending + 30

    def test_internally_ordered_observations_before_attempt_start_refuse(self):
        case = self.fixture()
        self.set_times(case, 10_000_000)
        # Valid within the absolute 10-second deadline, but before offset 0.1.
        with self.assertRaises(fixtures.EgressPolicyError):
            self.replay(case)

    def test_internally_ordered_observations_after_attempt_completion_refuse(self):
        case = self.fixture()
        self.set_times(case, 2_000_000_000)
        # Still before the deadline, but inconsistent with completion offset 0.2.
        with self.assertRaises(fixtures.EgressPolicyError):
            self.replay(case)

    def translated_case(self, start_seconds):
        case = self.fixture()
        policy, row = case[1], case[3]["attempts"][0]
        coordination = row["coordination"]
        shift = start_seconds * 1_000_000_000
        for key in ("pending_observed_ns", "cleanup_ns", "terminal_observed_ns"):
            coordination[key] += shift
        for key in ("observation_start_ns", "observation_end_ns"):
            coordination["schedule"][key] += shift
        coordination["deadline_seconds_hex"] = (float(start_seconds) + policy.timeout_seconds).hex()
        return case

    def test_nonzero_original_clock_origin_preserves_supplied_timing(self):
        self.assertIsNone(self.replay(self.translated_case(100)))

    def test_large_representable_clock_origin_preserves_supplied_timing(self):
        # Tests float/NS join arithmetic, not hardware clock or boot validity.
        self.assertIsNone(self.replay(self.translated_case(1 << 30)))

    def test_nonintegral_timeout_preserves_exact_source_float_arithmetic(self):
        registry, policy, request, receipt = self.fixture()
        policy = replace(policy, timeout_seconds=0.1)
        request["egress_budget"] = fixtures._egress_budget_policy_claim(policy)
        request["policy_claim_sha256"] = fixtures._safe_hash(
            fixtures.canonical_json_bytes(fixtures._egress_policy_claim(policy)))
        origin = float(1 << 24)
        deadline = origin + policy.timeout_seconds
        started, completed = origin + 0.01, origin + 0.02
        row = receipt["attempts"][0]
        row["started_offset_seconds"] = started - origin
        row["completed_offset_seconds"] = completed - origin
        row["prepared_request"].update(
            timeout_seconds=deadline - started,
            deadline_elapsed_seconds=started - origin,
        )
        row["prepared_request_binding"] = fixtures._safe_hash(
            fixtures.canonical_json_bytes(row["prepared_request"]))
        self.assertGreater(abs((deadline - started) - (policy.timeout_seconds - (started - origin))), 1e-9)
        case = registry, policy, request, receipt
        self.set_times(case, (1 << 24) * 1_000_000_000 + 16_000_000)
        row["coordination"]["deadline_seconds_hex"] = deadline.hex()
        self.assertIsNone(self.replay(case))
