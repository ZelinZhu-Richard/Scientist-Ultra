"""Portable synthetic root PMC-outcome edge controls."""

from types import FunctionType
import tempfile
from pathlib import Path
import unittest

from scientist_one import external as subject
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.scholarly_gateway import pmc_content_scholarly_egress_policy
from tests import pmc_wire_fixtures as _fixtures

fixtures = _fixtures
FixtureEnvironment = _fixtures.FixtureEnvironment
ComposedTransport = _fixtures.ComposedTransport
observed_counts = _fixtures.observed_counts
request = _fixtures.request

def execute_with_hooks(gateway, request, *, outcome_hook=None, count_hook=None):
    """TEST ONLY: wrap hidden callbacks, preserving real wrapper/row/raw execute.

    This is deliberate source/closure reconstruction, not production admission.
    No module binding, function or gateway instance is changed.
    """
    wrapper = subject.EgressGateway.execute
    original = fixtures.captured_cell(wrapper, "method")
    def method(self, request, **kwargs):
        for name, hook in (("_settle_pmc_outcome", outcome_hook), ("_settle_pmc_progress", count_hook)):
            if hook is not None:
                callback = kwargs[name]
                def intercepted(capability, callback=callback, hook=hook):
                    return hook(callback, capability)
                kwargs[name] = intercepted
        return original(self, request, **kwargs)
    def cell(value):
        return (lambda: value).__closure__[0]
    closure = tuple(cell(method) if name == "method" else old
                    for name, old in zip(wrapper.__code__.co_freevars, wrapper.__closure__))
    reconstructed = FunctionType(wrapper.__code__, wrapper.__globals__, wrapper.__name__, wrapper.__defaults__, closure)
    reconstructed.__kwdefaults__ = wrapper.__kwdefaults__
    return reconstructed(gateway, request)

def live_row(capability):
    admission = fixtures.captured_cell(subject._execute_pmc_coordinated_attempt, "admission")
    return fixtures.captured_cell(admission, "issued")[id(capability)]

class PmcOutcomeRootEdges(unittest.TestCase):
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

    def test_constructor_primary_precedes_outcome_settlement_cancellation(self):
        self.env.constructor_error = OSError("root earlier construction failure")
        callbacks = []

        def later(original, capability):
            callbacks.append(original(capability))
            raise SystemExit(81)

        gateway, transport = self.gateway()
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(subject.EgressDeniedError):
                execute_with_hooks(gateway, fixtures.request(), outcome_hook=later)
        self.assertEqual(callbacks, [False])
        self.assertEqual(counts[-1], 0)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(self.env.state()["phase"], "PENDING")
        self.assertIsNone(self.env.state()["terminal"])
        self.assertEqual(self.env.connections, [])

    def test_constructor_cancellation_identity_precedes_later_outcome_cancellation(self):
        primary = KeyboardInterrupt("root earlier construction cancellation")
        self.env.constructor_error = primary
        callbacks = []

        def later(original, capability):
            callbacks.append(original(capability))
            raise SystemExit(82)

        gateway, transport = self.gateway()
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(KeyboardInterrupt) as caught:
                execute_with_hooks(gateway, fixtures.request(), outcome_hook=later)
        self.assertIs(caught.exception, primary)
        self.assertEqual(callbacks, [False])
        self.assertEqual(counts[-1], 0)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(self.env.state()["phase"], "PENDING")
        self.assertIsNone(self.env.state()["terminal"])
        self.assertEqual([record.logical_type for record in self.registry.list_records()], ["external_request"])

    def test_normal_response_settlement_cancellation_keeps_known_bytes_without_publication(self):
        cancellation = SystemExit(83)
        callbacks = []

        def later(original, capability):
            callbacks.append(original(capability))
            self.assertEqual(live_row(capability)[11], 4)
            raise cancellation

        gateway, transport = self.gateway()
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(SystemExit) as caught:
                execute_with_hooks(gateway, fixtures.request(), outcome_hook=later)
        self.assertIs(caught.exception, cancellation)
        self.assertEqual(callbacks, [True])
        self.assertEqual(counts[-1], 4)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_COMPLETE")
        self.assertEqual([record.logical_type for record in self.registry.list_records()], ["external_request"])

    def test_missing_terminal_witness_rejects_actual_normal_driver_response(self):
        self.env.writer_hooks["terminal"] = lambda original, record: None
        driver = self.env.driver
        returned = []

        def record_return(prepared, transport):
            result = driver(prepared, transport)
            returned.append(result)
            return result

        self.env.driver = record_return
        gateway, transport = self.gateway()
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(subject.EgressDeniedError):
                gateway.execute(fixtures.request())
        self.assertEqual(len(returned), 1)
        self.assertIsInstance(returned[0], subject.TransportResponse)
        self.assertEqual(returned[0].body, b"<x/>")
        self.assertEqual(counts[-1], 4)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_COMPLETE")
        self.assertEqual(self.env.connections[0].closes, 1)
        self.assertEqual([name for name, _ in self.env.writer_calls],
                         ["pending", "terminal", "finalized"])
        self.assertIsNone(self.env.outcome_snapshots[-1][2])
        self.assertTrue(self.env.outcome_snapshots[-1][3])
        # Denial metadata may be published. Raw content may not be published.
        records = self.registry.list_records()
        self.assertEqual(sorted(record.logical_type for record in records),
                         ["external_request", "external_transport_denial_receipt"])

    def test_acquisition_failure_records_only_actual_independent_finalization(self):
        self.env.acquire_error = OSError("root acquisition fixture")
        settled = []

        def observe(original, capability):
            result = original(capability)
            settled.append(live_row(capability)[15])
            return result

        gateway, transport = self.gateway()
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(subject.EgressDeniedError):
                execute_with_hooks(gateway, fixtures.request(), outcome_hook=observe)
        self.assertEqual(counts[-1], 0)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual([name for name, _ in self.env.writer_calls], ["finalized"])
        self.assertEqual(settled, [("REQUIRED", None, None, True, True)])
        self.assertEqual(self.env.events.count(("owner-close",)), 1)
        self.assertEqual(self.env.connections, [])
        self.assertEqual(self.env.state()["phase"], "QUIESCENT")

    def test_unknown_count_is_terminal_before_outcome_callback_or_publication(self):
        failure = subject._PmcProgressAccountingError("PMC_PROGRESS_UNKNOWN")
        callbacks = []

        def unknown(original, capability):
            self.assertEqual(original(capability), 4)
            raise failure

        def forbidden(original, capability):
            callbacks.append(capability)
            raise SystemExit(84)

        gateway, transport = self.gateway()
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(subject._PmcProgressAccountingError):
                execute_with_hooks(gateway, fixtures.request(), count_hook=unknown, outcome_hook=forbidden)
        self.assertEqual(callbacks, [])
        self.assertEqual(counts[-1], 0)  # The intercepted count was not available to this consumer.
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_COMPLETE")
        self.assertEqual([record.logical_type for record in self.registry.list_records()], ["external_request"])
