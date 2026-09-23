"""Synthetic end-to-end wire custody; never native/TLS/provider evidence."""
import ast
from dataclasses import replace
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import struct
import tempfile
import time
from types import FunctionType, MethodType, SimpleNamespace
import unittest
import zlib

from scientist_one import external as subject
from scientist_one import scholarly_gateway as scholarly
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.roles import Role
from tests import pmc_wire_fixtures as fixtures
from tests.test_scholarly_gateway import pmc_xml

SOURCE = Path(subject.__file__)


def clone(function, **overrides):
    """TEST ONLY namespace reconstruction; not a production injection seam."""
    namespace = dict(function.__globals__)
    namespace.update(overrides)
    result = FunctionType(function.__code__, namespace, function.__name__, function.__defaults__, function.__closure__)
    result.__kwdefaults__ = function.__kwdefaults__
    return result


def source_function(name):
    node = next(n for n in ast.parse(SOURCE.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == name)
    namespace = dict(vars(subject))
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), "exec"), namespace)
    return namespace[name]


def rules():
    header = b"TZif2" + b"\0" * 15 + struct.pack(">6I", 0, 0, 0, 0, 2, 8)
    block = struct.pack(">iBBiBB", -18000, 0, 0, -14400, 1, 4) + b"EST\0EDT\0"
    return header + block + header + block + b"\nEST5EDT,M3.2.0,M11.1.0\n"


def request():
    return scholarly.ScholarlyRequest(scholarly.ScholarlySource.PMC, "resolve_work",
        scholarly.ScholarlyIdentifier(scholarly.IdentifierKind.PMCID, "PMC1234567"))


def xml(*, license_uri="https://creativecommons.org/licenses/by/4.0/"):
    return pmc_xml(license_uri=license_uri)


def frame(body, *, status=200, coding="identity", chunked=False):
    payload = gzip.compress(body, mtime=0) if coding == "gzip" else zlib.compress(body) if coding == "deflate" else body
    headers = f"HTTP/1.1 {status} Fixture\r\nContent-Type: application/xml\r\nContent-Encoding: {coding}\r\n"
    if chunked:
        return headers.encode() + b"Transfer-Encoding: chunked\r\n\r\n" + f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n"
    return headers.encode() + f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload


class WireEnvironment:
    """Disposable files + socketpair + real owner bodies; synthetic origin only.

    Only test factories/classification/activation and fetch dispatch are reconstructed.
    Actual admission rows, driver, state store, framing, count/outcome, registry,
    existing local key/HMAC/ledger and native parser/replay algorithms execute.
    """
    def __init__(self, directory, *, wires=None, maximum_attempts=2, clock_origin=None, timeout_seconds=30.0):
        directory.mkdir(exist_ok=True)
        (directory / "research").mkdir()
        self.registry, self.ledger = ArtifactRegistry(directory / "research"), EventLedger(directory / "research")
        self.run_id = "private-pmc-wire-fixture"
        self.ledger.record(run_id=self.run_id, actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.GROUND, requested_state_after=MacroState.GROUND,
            artifact_hashes=(), code_version="synthetic-wire-fixture", configuration_hash="0" * 64,
            reason="private synthetic wire custody test prefix", event_type="CHECKPOINT")
        def permitted():
            return None
        def classification(transport):
            return subject.AUDITED_LIVE_TRANSPORT_AUTHORITY
        self.clock_shift = 0.0
        self.clock_ticks = 0
        self.rules_hook = None
        def clock():
            if clock_origin is not None:
                self.clock_ticks += 10
                return float(clock_origin) + self.clock_ticks / 1_000_000 + self.clock_shift
            return time.monotonic() + self.clock_shift
        def capture_rules(*args):
            record = subject._capture_pmc_wire_rules(*args)
            if self.rules_hook is not None:
                self.rules_hook(record)
            return record
        self.owners = fixtures.rebuild_factory(subject, SOURCE, "_build_prepared_request_authority",
            {"_require_pmc_wire_activation": permitted, "time": SimpleNamespace(monotonic=clock, sleep=time.sleep),
             "_capture_pmc_wire_rules": capture_rules})
        self.owners[4](subject._PmcExchangeLifecycle, subject._PmcFramedResponseReader)
        issuer, self.verify = fixtures.rebuild_factory(subject, SOURCE, "_build_audited_transport_execution_authority", {
            "_classify_transport_authority": classification,
            "_build_gateway_authority_key_access": source_function("_build_gateway_authority_key_access"),
            "_prepare_audited_transport_execution_claim": clone(source_function("_prepare_audited_transport_execution_claim"),
                _require_pmc_wire_activation=permitted, _classify_transport_authority=classification),
            "_require_audited_live_transport_execution_with_key": clone(source_function("_require_audited_live_transport_execution_with_key"),
                _require_pmc_wire_activation=permitted),
        })
        self.owners[2](issuer)
        wall = int(datetime(2026, 9, 19, 12, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
        self.native = fixtures.FixtureEnvironment(directory / "store", owners=self.owners, rules=rules(), wall=wall,
                                                  clock=clock if clock_origin is not None else None)
        self.native.wires = wires if wires is not None else [frame(xml())]
        self.transport = fixtures.ComposedTransport(self.native)
        self.transport.network_used = True
        self.transport.external_validation = "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
        self.gateway = subject.EgressGateway(scholarly.pmc_wire_scholarly_egress_policy(maximum_attempts=maximum_attempts, timeout_seconds=timeout_seconds),
            self.transport, registry=self.registry, authority_ledger=self.ledger, authority_run_id=self.run_id)
        self.issue_hook = self.projection_hook = None
        raw = clone(fixtures.captured_cell(subject.EgressGateway.execute, "method"), _classify_transport_authority=classification)
        env = self
        def method(gateway, request, **kwargs):
            for name, hook in (("_issue_execution_authority", env.issue_hook), ("_project_pmc_wire_attempt", env.projection_hook)):
                if hook is not None:
                    original = kwargs[name]
                    kwargs[name] = lambda *a, original=original, hook=hook, **k: hook(original, *a, **k)
            return raw(gateway, request, **kwargs)
        self.execute = self.owners[1](method)
        capture = clone(scholarly.SourceOwnedScholarlyGateway._capture_parsed,
                        require_audited_live_transport_execution=self.verify)
        # One explicit TEST-ONLY call substitution, retaining the entire fetch body.
        path = Path(scholarly.__file__)
        cls = next(n for n in ast.parse(path.read_text()).body if isinstance(n, ast.ClassDef) and n.name == "SourceOwnedScholarlyGateway")
        fetch = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "fetch")
        class Dispatch(ast.NodeTransformer):
            def visit_Call(self, node):
                self.generic_visit(node)
                if isinstance(node.func, ast.Attribute) and ast.unparse(node.func) == "binding.gateway.execute":
                    node.func = ast.Name(id="_fixture_execute", ctx=ast.Load())
                return node
        fetch = ast.fix_missing_locations(Dispatch().visit(fetch))
        namespace = dict(vars(scholarly), _require_pmc_wire_activation=permitted,
                         _fixture_execute=lambda req, **kw: env.execute(env.gateway, req, **kw))
        exec(compile(ast.Module(body=[fetch], type_ignores=[]), str(path), "exec"), namespace)
        class FixtureScholarly(scholarly.SourceOwnedScholarlyGateway):
            _capture_parsed = capture
            fetch = namespace["fetch"]
        self.scholarly = FixtureScholarly(pmc_gateway=self.gateway)
        route_replay = clone(scholarly._require_native_route_authority, _require_pmc_wire_activation=permitted)
        self.replay = clone(scholarly.require_captured_pmc_wire_response, _require_pmc_wire_activation=permitted,
                            require_audited_live_transport_execution=self.verify,
                            _require_native_route_authority=route_replay)

    def fetch(self):
        with self.native.active():
            return self.scholarly.fetch(request())

    def replay_capture(self, captured):
        return self.replay(self.registry, self.ledger, run_id=self.run_id, request=request(),
                           raw_artifact_sha256=captured.raw_artifact_hash,
                           response_artifact_sha256=captured.response_artifact_hash)

    def cleanup(self):
        self.native.cleanup()


class PmcWireCandidateTests(unittest.TestCase):
    def environment(self, **kwargs):
        temporary = tempfile.TemporaryDirectory(prefix="pmc-wire-private-")
        self.addCleanup(temporary.cleanup)
        env = WireEnvironment(Path(temporary.name), **kwargs)
        self.addCleanup(env.cleanup)
        return env

    def authority(self, env, captured):
        return json.loads(env.registry.get_bytes(captured.transport_execution_authority_artifact_sha256))

    def test_complete_actual_gateway_driver_signature_native_replay_identity_gzip_deflate(self):
        for coding in ("identity", "gzip", "deflate"):
            with self.subTest(coding=coding):
                env = self.environment(wires=[frame(xml(), coding=coding)])
                captured = env.fetch()
                self.assertEqual(captured.status, scholarly.RetrievalStatus.AVAILABLE)
                self.assertEqual(captured.capture_authority, "SIGNED_HTTP_CAPTURE")
                self.assertFalse(captured.scientific_evidence)
                replayed = env.replay_capture(captured)
                self.assertEqual(replayed.envelope.payload, captured.payload)
                value = self.authority(env, captured)
                self.assertEqual(value["schema_version"], subject.PMC_WIRE_AUTHORITY_SCHEMA)
                self.assertEqual(value["content_coding"], coding)
                self.assertEqual(value["attempts"][0]["coordination"]["terminal_kind"], "LOCAL_CLOSED_COMPLETE")
                self.assertEqual(env.native.connections[0].requests[0][3]["Accept-Encoding"], "gzip, deflate")
                self.assertIsNone(env.native.connections[0].requests[0][2])

    def test_status_retry_retains_each_row_raw_rules_and_independent_prepared_cap(self):
        env = self.environment(wires=[frame(b"<busy/>", status=503), frame(xml(), coding="gzip", chunked=True)])
        captured = env.fetch()
        value = self.authority(env, captured)
        self.assertEqual(len(value["attempts"]), 2)
        self.assertNotEqual(value["attempts"][0]["prepared_request_binding"], value["attempts"][1]["prepared_request_binding"])
        self.assertEqual(value["prepared_request"], value["attempts"][-1]["prepared_request"])
        receipt_record = env.registry.get_metadata(value["response_receipt_artifact_sha256"])
        expected = (value["request_artifact_sha256"],
                    *(a["raw_response_record_sha256"] for a in value["attempts"]),
                    value["attempts"][0]["coordination"]["schedule"]["rules_artifact_sha256"], value["decoding_artifact_sha256"])
        self.assertEqual(receipt_record.parent_artifacts, expected)
        env.replay_capture(captured)

    def test_equal_content_invocations_are_distinct_issuance_and_sequences(self):
        env = self.environment(wires=[frame(xml()), frame(xml())])
        one, two = env.fetch(), env.fetch()
        a, b = self.authority(env, one), self.authority(env, two)
        self.assertEqual(a["request_id"], b["request_id"])
        self.assertNotEqual(one.transport_execution_authority_artifact_sha256, two.transport_execution_authority_artifact_sha256)
        self.assertGreater(b["attempts"][0]["coordination"]["sequence"], a["attempts"][0]["coordination"]["sequence"])
        env.replay_capture(one)
        env.replay_capture(two)

    def test_complete_non2xx_is_signed_transport_without_decode_or_content(self):
        env = self.environment(wires=[frame(b"<missing/>", status=404)])
        captured = env.fetch()
        self.assertEqual(captured.capture_authority, "SIGNED_HTTP_CAPTURE")
        self.assertIsNone(captured.payload)
        self.assertIsNone(self.authority(env, captured)["decoding_artifact_sha256"])
        self.assertNotEqual(env.replay_capture(captured).envelope.status, scholarly.RetrievalStatus.AVAILABLE)

    def test_malformed_and_rights_restricted_complete_captures_replay_their_negative_outcomes(self):
        for body, expected in ((b"<broken", scholarly.RetrievalStatus.MALFORMED),
                               (xml(license_uri="https://creativecommons.org/licenses/by-nc/4.0/"), scholarly.RetrievalStatus.LICENSE_RESTRICTED)):
            with self.subTest(expected=expected):
                env = self.environment(wires=[frame(body)])
                captured = env.fetch()
                self.assertEqual(captured.status, expected)
                self.assertEqual(captured.capture_authority, "SIGNED_HTTP_CAPTURE")
                self.assertEqual(env.replay_capture(captured).envelope.status, expected)

    def test_actual_production_entry_stays_closed_before_io(self):
        env = self.environment()
        with self.assertRaises(subject.EgressPolicyError):
            env.gateway.execute(replace(fixtures.request(), adapter_id=subject.PMC_WIRE_ADAPTER_ID))
        self.assertEqual(env.native.connections, [])
        result = scholarly.SourceOwnedScholarlyGateway(pmc_gateway=env.gateway).fetch(request())
        self.assertEqual(result.capture_authority, "UNVERIFIED_TERMINAL_DIAGNOSTIC")
        self.assertIsNone(result.transport_execution_authority_artifact_sha256)

    def test_incomplete_framing_and_failed_decoding_only_produce_diagnostics(self):
        for wire in (b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 9\r\n\r\nabc",
                     frame(b"not gzip").replace(b"identity", b"gzip")):
            with self.subTest(wire=wire):
                env = self.environment(wires=[wire])
                result = env.fetch()
                self.assertEqual(result.capture_authority, "UNVERIFIED_TERMINAL_DIAGNOSTIC")
                self.assertIsNone(result.payload)
                self.assertIsNone(result.transport_execution_authority_artifact_sha256)
                self.assertEqual(len(env.native.connections), 1)
                with self.assertRaises((scholarly.ScholarlyGatewayError, subject.EgressPolicyError)):
                    env.replay_capture(result)

    def test_early_attempt_mutation_cannot_sign_despite_valid_final_row(self):
        env = self.environment(wires=[frame(b"<busy/>", status=503), frame(xml())])
        reached = []
        def mutate(original, *args, **kwargs):
            reached.append(True)
            kwargs["attempts"][0]["status_code"] = 500
            return original(*args, **kwargs)
        env.issue_hook = mutate
        result = env.fetch()
        self.assertEqual(reached, [True])
        self.assertEqual(result.capture_authority, "UNVERIFIED_TERMINAL_DIAGNOSTIC")
        self.assertIsNone(result.transport_execution_authority_artifact_sha256)
        self.assertFalse(any(r.logical_type == "audited_transport_execution_authority" for r in env.registry.list_records()))

    def test_missing_schedule_or_response_writer_cannot_promote_complete_equal_body(self):
        for writer in ("schedule", "response"):
            with self.subTest(writer=writer):
                env = self.environment()
                env.native.writer_hooks[writer] = lambda original, *args: None
                result = env.fetch()
                self.assertTrue(any(name == writer for name, _ in env.native.writer_calls))
                self.assertEqual(result.capture_authority, "UNVERIFIED_TERMINAL_DIAGNOSTIC")
                self.assertIsNone(result.payload)

    def test_publication_failure_does_not_retry_or_refund(self):
        env = self.environment()
        reached = []
        def fail(original, *args, **kwargs):
            reached.append(True)
            raise subject.EgressPolicyError("fixture immutable publication failure")
        env.issue_hook = fail
        result = env.fetch()
        self.assertEqual(reached, [True])
        self.assertEqual(result.capture_authority, "UNVERIFIED_TERMINAL_DIAGNOSTIC")
        self.assertEqual(len(env.native.connections), 1)
        self.assertEqual(env.gateway._request_count, 1)
        self.assertTrue(any(r.logical_type == "external_response_raw" for r in env.registry.list_records()))

    def test_actual_sender_factory_one_time_binding_and_generated_header_path(self):
        env = self.environment()
        send, bind = fixtures.rebuild_factory(subject, SOURCE, "_build_stdlib_https_send", {
            "_consume_prepared_request": env.owners[0], "_pmc_wire_prepared_selected": env.owners[6],
            "_require_pmc_wire_activation": lambda: None,
            "_execute_pmc_coordinated_attempt": env.native.driver,
        })
        with self.assertRaises(RuntimeError):
            bind(lambda *args: None)
        bind(env.native.driver)
        with self.assertRaises(RuntimeError):
            bind(env.native.driver)
        env.transport.send = MethodType(send, env.transport)
        captured = env.fetch()
        self.assertEqual(captured.capture_authority, "SIGNED_HTTP_CAPTURE")
        sent = env.native.connections[0].requests[0]
        self.assertEqual(sent[0], "GET")
        self.assertIsNone(sent[2])
        self.assertEqual(sent[3]["Accept-Encoding"], "gzip, deflate")
        env.replay_capture(captured)

    def test_actual_sender_non_pmc_admission_row_refuses_without_policy_dereference(self):
        env = self.environment()
        send, bind = fixtures.rebuild_factory(subject, SOURCE, "_build_stdlib_https_send", {
            "_consume_prepared_request": env.owners[0], "_pmc_wire_prepared_selected": env.owners[6],
            "_require_pmc_wire_activation": lambda: None,
            "_execute_pmc_coordinated_attempt": env.native.driver,
        })
        bind(env.native.driver)
        policy = replace(env.gateway.policy, adapter_id="private-generic-pmc-host")
        gateway = subject.EgressGateway(policy, env.transport, registry=env.registry)
        wire = replace(fixtures.request(), adapter_id=policy.adapter_id)
        reached = []
        def method(owner, request, *, _issue_prepared, **kwargs):
            prepared = subject.PreparedEgressRequest(request_id=request.request_id, method="GET", url=request.url,
                host="pmc.ncbi.nlm.nih.gov", target="/api/oai/v1/mh/", headers=request.headers, body=b"",
                content_type=request.content_type)
            capability = _issue_prepared(prepared)
            object.__setattr__(prepared, "_capability", capability)
            reached.append(True)
            return send(env.transport, prepared, credential=None)
        with self.assertRaises(subject.EgressDeniedError):
            env.owners[1](method)(gateway, wire)
        self.assertEqual(reached, [True])
        self.assertEqual(env.native.connections, [])

    def test_rules_registration_readback_must_finish_before_original_deadline(self):
        env = self.environment()
        registered = []
        def late(record):
            registered.append(record)
            env.clock_shift += 1000.0
        env.rules_hook = late
        captured = env.fetch()
        self.assertEqual(captured.capture_authority, "UNVERIFIED_TERMINAL_DIAGNOSTIC")
        self.assertEqual(len(registered), 1)
        env.registry.verify(registered[0].sha256, raise_on_error=True)
        self.assertEqual(len(env.native.connections), 1)
        self.assertEqual(env.native.state()["terminal"]["kind"], "LOCAL_CLOSED_COMPLETE")
        self.assertFalse(any(r.logical_type == "external_response_receipt" for r in env.registry.list_records()))

    def test_post_endpoint_publication_is_not_claimed_inside_transport_deadline(self):
        env = self.environment()
        def late(original, *args, **kwargs):
            env.clock_shift += 1000.0
            return original(*args, **kwargs)
        env.issue_hook = late
        captured = env.fetch()
        self.assertEqual(captured.capture_authority, "SIGNED_HTTP_CAPTURE")
        value = self.authority(env, captured)
        self.assertEqual(value["egress_budget"]["deadline_scope"], subject.PMC_WIRE_DEADLINE_SCOPE)
        self.assertLess(value["egress_budget"]["deadline_elapsed_seconds"], env.gateway.policy.timeout_seconds)
        self.assertEqual(len(env.native.connections), 1)
        env.replay_capture(captured)

    def test_diagnostic_dto_cannot_claim_available_or_signed_without_authority(self):
        env = self.environment()
        diagnostic = scholarly.SourceOwnedScholarlyGateway(pmc_gateway=env.gateway).fetch(request())
        with self.assertRaises(scholarly.ScholarlyGatewayError):
            replace(diagnostic, capture_authority="SIGNED_HTTP_CAPTURE")
        with self.assertRaises(scholarly.ScholarlyGatewayError):
            replace(diagnostic, status=scholarly.RetrievalStatus.AVAILABLE)

    def test_partial_failure_retains_exact_count_with_new_attempt_null_coordination(self):
        env = self.environment(wires=[b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 9\r\n\r\nabc"])
        wire = replace(scholarly._encode_pmc_request(request()), adapter_id=subject.PMC_WIRE_ADAPTER_ID)
        with env.native.active(), self.assertRaises(subject.EgressDeniedError) as caught:
            env.execute(env.gateway, wire)
        self.assertEqual(len(caught.exception.attempts), 1)
        attempt = caught.exception.attempts[0]
        self.assertEqual(attempt["schema_version"], subject.PMC_WIRE_ATTEMPT_SCHEMA)
        self.assertEqual(attempt["response_body_bytes"], 3)
        self.assertIsNone(attempt["coordination"])
        self.assertIsNone(attempt["raw_response_record_hash"])
        self.assertEqual(attempt["control_headers"], [])
        self.assertEqual(attempt["prepared_request"]["request_id"], wire.request_id)

    def test_large_original_clock_fractional_timeout_issuance_and_outer_replay(self):
        env = self.environment(clock_origin=2**24, timeout_seconds=0.1)
        captured = env.fetch()
        self.assertEqual(captured.capture_authority, "SIGNED_HTTP_CAPTURE")
        value = self.authority(env, captured)
        prepared = value["prepared_request"]
        self.assertGreater(abs(prepared["timeout_seconds"] - (0.1 - prepared["deadline_elapsed_seconds"])), 1e-9)
        env.replay_capture(captured)
        receipt = json.loads(env.registry.get_bytes(value["response_receipt_artifact_sha256"]))
        request_value = json.loads(env.registry.get_bytes(value["request_artifact_sha256"]))
        changed = receipt["attempts"][0]["prepared_request"]
        changed["timeout_seconds"] += 1e-5
        receipt["attempts"][0]["prepared_request_binding"] = subject._safe_hash(subject.canonical_json_bytes(changed))
        with self.assertRaises(subject.EgressPolicyError):
            subject._replay_pmc_wire_attempts(env.registry, env.gateway.policy, request_value, receipt)

    def test_replay_nil_identity_and_recorded_control_substitution_refuse(self):
        env = self.environment(wires=[frame(b"<missing/>", status=404)])
        captured = env.fetch()
        value = self.authority(env, captured)
        request_value = json.loads(env.registry.get_bytes(value["request_artifact_sha256"]))
        for change in ("nil", "length", "type"):
            with self.subTest(change=change):
                receipt = json.loads(env.registry.get_bytes(value["response_receipt_artifact_sha256"]))
                if change == "nil":
                    receipt["attempts"][0]["coordination"]["boot_uuid"] = "00000000-0000-0000-0000-000000000000"
                elif change == "length":
                    receipt["headers"]["content-length"] = "0"
                else:
                    receipt["content_type"] = "text/xml"
                with self.assertRaises(subject.EgressPolicyError):
                    subject._replay_pmc_wire_attempts(env.registry, env.gateway.policy, request_value, receipt)

