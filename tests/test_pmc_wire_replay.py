"""Unrun supplied-data edges for the private PMC wire replay helper.

Every fixture here is synthetic, NON_EVIDENTIARY, non-native, unsigned, and
never a production activation or authority.  It exercises only the direct
replay join against a temporary ArtifactRegistry.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import struct
import tempfile
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.external import (
    EGRESS_REQUEST_SCHEMA,
    PMC_CONTENT_PROFILE,
    PMC_COORDINATION_PROFILE,
    PMC_REQUEST_WIRE_PROFILE,
    PMC_WIRE_ADAPTER_ID,
    PMC_WIRE_ATTEMPT_SCHEMA,
    PMC_WIRE_RESPONSE_SCHEMA,
    EgressPolicy,
    EgressPolicyError,
    EgressRequest,
    _DEFAULT_RECORDED_RESPONSE_HEADERS,
    _capture_pmc_wire_rules,
    _egress_budget_policy_claim,
    _egress_policy_claim,
    _replay_pmc_wire_attempts,
    _safe_hash,
    canonical_json_bytes,
)
from scientist_one.roles import Role


_URL = (
    "https://pmc.ncbi.nlm.nih.gov/api/oai/v1/mh/?verb=GetRecord"
    "&identifier=oai%3Apubmedcentral.nih.gov%3A12345&metadataPrefix=pmc"
)
_TARGET = (
    "/api/oai/v1/mh/?verb=GetRecord"
    "&identifier=oai%3Apubmedcentral.nih.gov%3A12345&metadataPrefix=pmc"
)
_HEADERS = [
    ["Accept", "application/xml, text/xml;q=0.9"],
    ["User-Agent", "Scientist-One-vNext-Scholarly/2"],
]
_BOOT_UUID = "12345678-1234-4234-9234-1234567890ab"
_COORDINATOR_UUID = "87654321-4321-4234-9234-ba0987654321"
_OFFPEAK_UTC_NS = 3 * 86_400 * 1_000_000_000


def _synthetic_tzif() -> bytes:
    """Return fixture-created TZif2 bytes; they are never host rules."""

    header = b"TZif2" + b"\x00" * 15 + struct.pack(">6I", 0, 0, 0, 0, 2, 8)
    block = (
        struct.pack(">iBBiBB", -18_000, 0, 0, -14_400, 1, 4)
        + b"EST\x00EDT\x00"
    )
    return header + block + header + block + b"\nEST5EDT,M3.2.0,M11.1.0\n"


class PmcWireReplayEdges(unittest.TestCase):
    """A reusable supplied-data fixture plus narrow direct-helper edges."""

    def fixture(self, *, attempts: int = 1) -> tuple[ArtifactRegistry, EgressPolicy, dict, dict]:
        """Build a valid synthetic 404 history with one or two complete rows.

        This intentionally remains a small, reusable supplied-data factory for
        root's disjoint header/absolute-time join controls.  It does not invoke
        native context, signing, gateway dispatch, decoding, or production
        activation; its temporary registry is test-only.
        """

        if attempts not in (1, 2):
            raise ValueError("fixture supports one or two rows")
        temporary = tempfile.TemporaryDirectory(prefix="pmc-wire-replay-")
        self.addCleanup(temporary.cleanup)
        registry = ArtifactRegistry(temporary.name)
        policy = EgressPolicy(
            policy_id="synthetic-pmc-wire-replay",
            adapter_id=PMC_WIRE_ADAPTER_ID,
            allowed_hosts=("pmc.ncbi.nlm.nih.gov",),
            allowed_path_prefixes=("/api/oai/v1/mh/",),
            allowed_methods=("GET",),
            allowed_query_keys=("identifier", "metadataPrefix", "verb"),
            allowed_request_headers=("accept", "user-agent"),
            allowed_request_content_types=("application/xml",),
            allowed_response_content_types=("application/xml", "text/xml"),
            recorded_response_headers=(*_DEFAULT_RECORDED_RESPONSE_HEADERS, "content-encoding"),
            maximum_request_bytes=0,
            maximum_response_bytes=64,
            maximum_total_bytes=128,
            timeout_seconds=10.0,
            minimum_interval_seconds=1.0,
            maximum_attempts=3,
            retry_statuses=(429, 500, 502, 503, 504),
            backoff_initial_seconds=0.25,
            backoff_maximum_seconds=8.0,
            credential_env_name=None,
            credential_required=False,
        )
        request = EgressRequest(
            adapter_id=policy.adapter_id,
            method="GET",
            url=_URL,
            headers=tuple(tuple(pair) for pair in _HEADERS),
            body=b"",
            content_type="application/xml",
        )
        request_payload = {
            "schema_version": EGRESS_REQUEST_SCHEMA,
            "kind": "REDACTED_EXTERNAL_REQUEST",
            "policy_id": policy.policy_id,
            "policy_claim_sha256": _safe_hash(
                canonical_json_bytes(_egress_policy_claim(policy))
            ),
            "egress_budget": _egress_budget_policy_claim(policy),
            "adapter_id": policy.adapter_id,
            "method": "GET",
            "url": _URL,
            "headers": deepcopy(_HEADERS),
            "body_sha256": _safe_hash(b""),
            "body_size": 0,
            "content_type": "application/xml",
            "credential_present": False,
            "credential_env_name": None,
            "scientific_evidence": False,
            "request_id": request.request_id,
        }
        rules = _capture_pmc_wire_rules(registry, _synthetic_tzif(), _OFFPEAK_UTC_NS)
        rows: list[dict] = []
        cumulative = 0
        for ordinal in range(1, attempts + 1):
            status = 503 if ordinal == 1 and attempts == 2 else 404
            body = f"<synthetic-attempt-{ordinal}/>".encode("ascii")
            raw = registry.put_bytes(
                body,
                logical_type="external_response_raw",
                origin="controlled external egress raw response",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "controlled-egress"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/octet-stream",
                validation_result="PASS",
                frozen=True,
            )
            if ordinal == 1:
                started, completed = 0.1, (0.99 if attempts == 2 else 0.2)
                pending, cleanup, terminal = 160_000_000, (980_000_000 if attempts == 2 else 190_000_000), (985_000_000 if attempts == 2 else 195_000_000)
            else:
                started, completed = 1.3, 1.5
                pending, cleanup, terminal = 1_313_333_334, 1_313_333_354, 1_313_333_364
            elapsed = started
            controls = [
                ["content-type", "application/xml"],
                ["content-length", str(len(body))],
            ]
            retry_delay = None
            if ordinal < attempts:
                controls.append(["retry-after", "0.25"])
                retry_delay = 0.25
            prepared = {
                "request_id": request.request_id,
                "method": "GET",
                "url": _URL,
                "host": "pmc.ncbi.nlm.nih.gov",
                "target": _TARGET,
                "headers": deepcopy(_HEADERS),
                "body_sha256": _safe_hash(b""),
                "body_size": 0,
                "content_type": "application/xml",
                "timeout_seconds": policy.timeout_seconds - elapsed,
                "maximum_response_bytes": min(
                    policy.maximum_response_bytes,
                    policy.maximum_total_bytes - cumulative,
                ),
                "attempt_number": ordinal,
                "cumulative_bytes_before_attempt": cumulative,
                "deadline_elapsed_seconds": elapsed,
                "credential_header": None,
                "credential_prefix": policy.credential_prefix,
            }
            schedule_start = pending + 5
            schedule_end = pending + 10
            coordination = {
                "profile": PMC_COORDINATION_PROFILE,
                "coordinator_uuid": _COORDINATOR_UUID,
                "boot_uuid": _BOOT_UUID,
                "sequence": 7 if ordinal == 1 else 100,
                "pending_observed_ns": pending,
                "deadline_seconds_hex": (10.0).hex(),
                "terminal_kind": "LOCAL_CLOSED_COMPLETE",
                "terminal_observed_ns": terminal,
                "cleanup_ns": cleanup,
                "finalized": True,
                "schedule": {
                    "utc_unix_ns": _OFFPEAK_UTC_NS,
                    "observation_start_ns": schedule_start,
                    "observation_end_ns": schedule_end,
                    "rules_artifact_sha256": rules.sha256,
                    "rules_artifact_record_hash": rules.record_hash,
                },
            }
            cumulative += len(body)
            rows.append(
                {
                    "schema_version": PMC_WIRE_ATTEMPT_SCHEMA,
                    "attempt": ordinal,
                    "status": "RESPONSE",
                    "status_code": status,
                    "body_sha256": _safe_hash(body),
                    "body_size": len(body),
                    "raw_response_record_sha256": raw.sha256,
                    "request_body_bytes": 0,
                    "response_body_bytes": len(body),
                    "cumulative_bytes": cumulative,
                    "started_offset_seconds": started,
                    "completed_offset_seconds": completed,
                    "retry_delay_seconds": retry_delay,
                    "prepared_request": prepared,
                    "prepared_request_binding": _safe_hash(
                        canonical_json_bytes(prepared)
                    ),
                    "raw_response_record_hash": raw.record_hash,
                    "control_headers": controls,
                    "coordination": coordination,
                }
            )
        final = rows[-1]
        receipt = {
            "schema_version": PMC_WIRE_RESPONSE_SCHEMA,
            "request_wire_profile": PMC_REQUEST_WIRE_PROFILE,
            "content_profile": PMC_CONTENT_PROFILE,
            "attempts": rows,
            "request_id": request.request_id,
            "raw_response_record_sha256": final["raw_response_record_sha256"],
            "raw_response_sha256": final["body_sha256"],
            "body_size": final["body_size"],
            "status_code": final["status_code"],
            "headers": {key: value for key, value in final["control_headers"]
                        if key in policy.recorded_response_headers},
            "content_type": "application/xml",
            "content_coding": "identity",
            "decoding_artifact_sha256": None,
            "decoding_artifact_record_hash": None,
            "scientific_evidence": False,
        }
        return registry, policy, request_payload, receipt

    def assert_refused(
        self,
        registry,
        policy,
        request_payload,
        receipt,
        *,
        reason: str = "PMC wire custody replay differs",
    ) -> None:
        with self.assertRaises(EgressPolicyError) as caught:
            _replay_pmc_wire_attempts(registry, policy, request_payload, receipt)
        self.assertEqual(str(caught.exception), reason)

    def test_valid_synthetic_supplied_data_is_non_evidentiary(self) -> None:
        registry, policy, request_payload, receipt = self.fixture()
        self.assertFalse(request_payload["scientific_evidence"])
        self.assertFalse(receipt["scientific_evidence"])
        self.assertIsNone(_replay_pmc_wire_attempts(registry, policy, request_payload, receipt))

    def test_temporal_chain_requires_pending_schedule_cleanup_terminal_order(self) -> None:
        for label, mutate in (
            ("pending", lambda row: row["coordination"].update(pending_observed_ns=160_000_006)),
            ("schedule", lambda row: row["coordination"]["schedule"].update(observation_end_ns=160_000_004)),
            ("cleanup", lambda row: row["coordination"].update(cleanup_ns=160_000_009)),
            ("terminal", lambda row: row["coordination"].update(terminal_observed_ns=189_999_999)),
        ):
            with self.subTest(label=label):
                registry, policy, request_payload, receipt = self.fixture()
                mutate(receipt["attempts"][0])
                self.assert_refused(registry, policy, request_payload, receipt)

    def test_sequence_gaps_are_allowed_but_nonincrease_and_prior_cleanup_spacing_refuse(self) -> None:
        registry, policy, request_payload, receipt = self.fixture(attempts=2)
        self.assertIsNone(_replay_pmc_wire_attempts(registry, policy, request_payload, receipt))

        for label, mutate in (
            ("nonincreasing", lambda row: row["coordination"].update(sequence=7)),
            (
                "prior-cleanup-spacing",
                lambda row: row["coordination"].update(pending_observed_ns=1_313_333_333),
            ),
        ):
            with self.subTest(label=label):
                registry, policy, request_payload, receipt = self.fixture(attempts=2)
                mutate(receipt["attempts"][1])
                self.assert_refused(registry, policy, request_payload, receipt)

    def test_deadline_hex_and_uuid_must_be_canonical(self) -> None:
        for label, mutate in (
            (
                "noncanonical-deadline",
                lambda row: row["coordination"].update(deadline_seconds_hex="0x1.4p+3"),
            ),
            (
                "uppercase-uuid",
                lambda row: row["coordination"].update(boot_uuid=_BOOT_UUID.upper()),
            ),
        ):
            with self.subTest(label=label):
                registry, policy, request_payload, receipt = self.fixture()
                mutate(receipt["attempts"][0])
                self.assert_refused(registry, policy, request_payload, receipt)

    def test_rules_artifact_requires_the_exact_registry_record_identity(self) -> None:
        registry, policy, request_payload, receipt = self.fixture()
        receipt["attempts"][0]["coordination"]["schedule"][
            "rules_artifact_record_hash"
        ] = hashlib.sha256(b"not-the-captured-rule-record").hexdigest()
        self.assert_refused(
            registry,
            policy,
            request_payload,
            receipt,
            reason="PMC schedule rule custody differs",
        )

    def test_each_prepared_cap_and_retry_after_are_replayed_per_attempt(self) -> None:
        for label, mutate in (
            (
                "second-prepared-cap",
                lambda row: (
                    row["prepared_request"].update(maximum_response_bytes=63),
                    row.update(
                        prepared_request_binding=_safe_hash(
                            canonical_json_bytes(row["prepared_request"])
                        )
                    ),
                ),
            ),
            ("retry-after", lambda row: row.update(retry_delay_seconds=0.30)),
        ):
            with self.subTest(label=label):
                registry, policy, request_payload, receipt = self.fixture(attempts=2)
                mutate(receipt["attempts"][1 if label == "second-prepared-cap" else 0])
                self.assert_refused(registry, policy, request_payload, receipt)
