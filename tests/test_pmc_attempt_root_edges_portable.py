"""Portable synthetic root PMC-attempt edge controls."""

from dataclasses import replace
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from scientist_one import external as subject
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.scholarly_gateway import pmc_content_scholarly_egress_policy
from tests import pmc_wire_fixtures as _fixtures

FixtureEnvironment = _fixtures.FixtureEnvironment
ComposedTransport = _fixtures.ComposedTransport
observed_counts = _fixtures.observed_counts
request = _fixtures.request

class PmcAttemptRootEdges(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="pmc-composition-fixture-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "artifacts").mkdir()
        self.registry = ArtifactRegistry(root / "artifacts")
        self.env = FixtureEnvironment(root / "store")
        self.addCleanup(self.env.cleanup)

    def gateway(self, *, before=None):
        transport = ComposedTransport(self.env, before)
        return subject.EgressGateway(pmc_content_scholarly_egress_policy(maximum_attempts=2), transport,
                                     registry=self.registry), transport

    def denied(self, *, count=0):
        gateway, transport = self.gateway()
        with self.env.active(), observed_counts() as counts:
            with self.assertRaises(subject.EgressDeniedError) as caught:
                gateway.execute(request())
        self.assertEqual(counts[-1], count)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(gateway._request_count, 1)
        return caught.exception

    def test_system_exit_from_completed_parser_keeps_count_and_aborted_disposition(self):
        primary = SystemExit(73)
        original = subject._PmcFramedResponseReader.read

        def cancelled(reader):
            original(reader)
            raise primary

        gateway, transport = self.gateway()
        with self.env.active(), patch.object(subject._PmcFramedResponseReader, "read", cancelled), \
                observed_counts() as counts:
            with self.assertRaises(SystemExit) as caught:
                gateway.execute(request())
        self.assertIs(caught.exception, primary)
        self.assertEqual(counts[-1], 4)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_ABORTED")
        self.assertEqual(self.env.connections[0].closes, 1)

    def test_normal_result_finalizer_cancellation_is_not_hidden_by_ambient_exception(self):
        primary = SystemExit(74)
        self.env.native_close_error = primary
        gateway, transport = self.gateway()
        try:
            raise ValueError("ambient root fixture")
        except ValueError:
            with self.env.active(), observed_counts() as counts:
                with self.assertRaises(SystemExit) as caught:
                    gateway.execute(request())
        self.assertIs(caught.exception, primary)
        self.assertEqual(counts[-1], 4)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_COMPLETE")
        self.assertTrue(all(context.closed for context in self.env.contexts))

    def test_later_not_sent_preserves_actual_prior_cleanup_and_cumulative_bytes(self):
        self.env.wires = [
            b"HTTP/1.1 500 Error\r\nContent-Type: application/xml\r\nContent-Length: 4\r\n\r\nfail"
        ]
        # Four context observations in attempt1, then attempt2 acquisition5;
        # observation6 is the explicit inert schedule gate before construction.
        self.env.blocked.add(6)
        gateway, transport = self.gateway()
        with self.env.active(), observed_counts() as counts:
            with self.assertRaises(subject.EgressDeniedError):
                gateway.execute(request())
        self.assertEqual(len(transport.prepared), 2)
        self.assertEqual(len(self.env.connections), 1)
        self.assertEqual(counts[-1], 4)
        state = self.env.state()
        self.assertEqual(state["sequence"], 2)
        self.assertEqual(state["terminal"]["kind"], "NOT_SENT")
        self.assertIsNotNone(state["last_cleanup_ns"])
        self.assertEqual(state["last_cleanup_ns"], state["predecessor"]["cleanup_ns"])
        self.assertEqual(self.env.deadlines[0], self.env.deadlines[1])

    def test_zero_body_count_does_not_turn_incomplete_head_into_not_sent(self):
        self.env.wires = [b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"]
        self.denied(count=0)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_ABORTED")
        self.assertEqual(len(self.env.connections[0].requests), 1)
        self.assertIsNotNone(self.env.state()["last_cleanup_ns"])

    def test_partial_chunk_budget_denial_keeps_only_proved_bytes_and_aborted_terminal(self):
        self.env.wires = [
            b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n"
        ]
        baseline, _ = self.gateway()
        policy = replace(baseline.policy, maximum_response_bytes=2)
        transport = ComposedTransport(self.env)
        gateway = subject.EgressGateway(policy, transport, registry=self.registry)
        with self.env.active(), observed_counts() as counts:
            with self.assertRaises(subject.EgressDeniedError):
                gateway.execute(request())
        self.assertEqual(counts[-1], 2)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_ABORTED")

    def test_pre_request_schedule_primary_survives_observation_close_cancellation(self):
        self.env.blocked.add(4)
        self.env.close_errors[4] = SystemExit(75)
        self.denied(count=0)  # An ordinary refusal remains primary, not the later SystemExit.
        self.assertEqual(self.env.state()["phase"], "PENDING")
        self.assertEqual(self.env.connections[0].requests, [])
        self.assertEqual(self.env.connections[0].closes, 1)
        self.assertTrue(all(context.closed for context in self.env.contexts))

    def test_terminal_cancellation_preserves_count_through_secondary_owner_failure(self):
        primary = SystemExit(76)
        self.env.terminal_error = primary
        self.env.native_close_error = KeyboardInterrupt("secondary root fixture")
        gateway, transport = self.gateway()
        with self.env.active(), observed_counts() as counts:
            with self.assertRaises(SystemExit) as caught:
                gateway.execute(request())
        self.assertIs(caught.exception, primary)
        self.assertEqual(counts[-1], 4)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(self.env.state()["phase"], "PENDING")
        self.assertTrue(all(context.closed for context in self.env.contexts))
