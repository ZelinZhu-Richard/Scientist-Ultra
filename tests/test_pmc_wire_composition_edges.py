"""Private reconstructed-factory integration controls; no native/live evidence."""
from dataclasses import replace
import unittest

from tests import test_pmc_wire_custody as fixtures


class PmcWireRootComposition(unittest.TestCase):
    environment = fixtures.PmcWireCandidateTests.environment

    def test_omitted_or_extra_attempt_cannot_issue_after_two_real_fixture_responses(self):
        for mode in ("omit", "extra"):
            with self.subTest(mode=mode):
                env = self.environment(wires=[fixtures.frame(b"<busy/>", status=503), fixtures.frame(fixtures.xml())])
                reached = []

                def alter(original, *args, **kwargs):
                    reached.append(len(kwargs["attempts"]))
                    if mode == "omit":
                        kwargs["attempts"].pop(0)
                    else:
                        kwargs["attempts"].append(dict(kwargs["attempts"][-1]))
                    return original(*args, **kwargs)

                env.issue_hook = alter
                captured = env.fetch()
                self.assertEqual(reached, [2])
                self.assertEqual(len(env.native.connections), 2)
                self.assertEqual(captured.capture_authority, "UNVERIFIED_TERMINAL_DIAGNOSTIC")
                self.assertIsNone(captured.transport_execution_authority_artifact_sha256)
                self.assertFalse(any(r.logical_type == "audited_transport_execution_authority"
                                     for r in env.registry.list_records()))

    def available(self, env, captured):
        replay = fixtures.clone(fixtures.scholarly.require_available_scholarly_native_capture,
                                require_captured_pmc_wire_response=env.replay)
        return replay(env.registry, ledger=env.ledger, run_id=env.run_id,
                      request=fixtures.request(), raw_artifact_sha256=captured.raw_artifact_hash,
                      response_artifact_sha256=captured.response_artifact_hash)

    def test_available_wrapper_accepts_replayed_available_capture(self):
        env = self.environment()
        captured = env.fetch()
        self.assertEqual(captured.capture_authority, "SIGNED_HTTP_CAPTURE")
        self.assertEqual(self.available(env, captured).envelope.status, fixtures.scholarly.RetrievalStatus.AVAILABLE)

    def test_available_wrapper_refuses_valid_signed_negative_capture(self):
        env = self.environment(wires=[fixtures.frame(b"<missing/>", status=404)])
        captured = env.fetch()
        self.assertEqual(captured.capture_authority, "SIGNED_HTTP_CAPTURE")
        self.assertNotEqual(env.replay_capture(captured).envelope.status, fixtures.scholarly.RetrievalStatus.AVAILABLE)
        with self.assertRaisesRegex(fixtures.scholarly.ScholarlyGatewayError, "not available full text"):
            self.available(env, captured)

    def test_caller_cannot_select_generated_accept_encoding_header(self):
        env = self.environment()
        before = tuple(env.registry.list_records())
        with self.assertRaises(fixtures.subject.EgressPolicyError):
            wire = fixtures.scholarly._encode_pmc_request(fixtures.request())
            supplied = replace(wire, adapter_id=fixtures.subject.PMC_WIRE_ADAPTER_ID,
                               headers=(*wire.headers, ("Accept-Encoding", "identity")))
            with env.native.active():
                env.execute(env.gateway, supplied)
        self.assertEqual(env.native.connections, [])
        self.assertEqual(tuple(env.registry.list_records()), before)
        self.assertEqual(env.fetch().capture_authority, "SIGNED_HTTP_CAPTURE")

    def test_complete_non2xx_html_stays_policy_denied_not_signed_transport(self):
        wire = fixtures.frame(b"<html>forbidden</html>", status=403).replace(b"application/xml", b"text/html")
        env = self.environment(wires=[wire])
        captured = env.fetch()
        self.assertEqual(len(env.native.connections), 1)
        self.assertEqual(captured.capture_authority, "UNVERIFIED_TERMINAL_DIAGNOSTIC")
        self.assertIsNone(captured.transport_execution_authority_artifact_sha256)
        self.assertIsNone(captured.payload)
        self.assertFalse(any(r.logical_type == "audited_transport_execution_authority"
                             for r in env.registry.list_records()))
