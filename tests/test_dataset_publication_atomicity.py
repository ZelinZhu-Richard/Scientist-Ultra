from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.roles import Role
import scientist_one.research_state as research_state
import scientist_one.scientific_design as scientific_design
from scientist_one.security import canonical_json_bytes
from tests.test_scientific_design import make_contract


STAMP = "2026-08-30T12:00:00Z"
SEMANTIC_STAMP = "2026-08-30T12:00:01Z"
CONFIGURATION_HASH = "c" * 64
RUN_ID = "dataset-run"


class DatasetPublicationAtomicityTests(unittest.TestCase):
    def _put_json(
        self,
        registry: ArtifactRegistry,
        value: object,
        *,
        logical_type: str,
        role: Role,
        parents: tuple[str, ...] = (),
        origin: str | None = None,
        command: tuple[str, ...] = ("scientist-one", "dataset-test"),
        schema_version: str = "1.0",
        created_at: str = STAMP,
    ):
        if logical_type == "evaluation_contract":
            # NON_EVIDENTIARY fixture: use the actual contract/lineage owner;
            # only external acquisition and usage-review sources are mocked.
            evidence = registry.put_json(
                {"fixture": "NON_EVIDENTIARY Dataset contract evidence"},
                logical_type="dataset_publication_fixture_evidence",
                origin="Dataset publication fixture evidence",
                creator_role=Role.EVIDENCE_CURATOR,
                validation_result="PASS", frozen=True,
            )
            base = make_contract()
            contract = replace(base, dataset=replace(
                base.dataset, dataset_id="dataset-public",
                train_split_id="train-public",
                development_split_id="development-public",
                validation_split_id="validation-public",
                confirmatory_split_id="confirmatory-public",
                exclusions=("unit_id:unit-7",),
            ))
            return scientific_design.register_frozen_evaluation_contract(
                registry, contract=contract,
                parent_artifact_sha256s=(evidence.sha256,),
            )
        return registry.put_json(
            value,
            logical_type=logical_type,
            origin=origin or f"Dataset publication fixture {logical_type}",
            creator_role=role,
            creation_command=command,
            parent_artifacts=parents,
            schema_version=schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=created_at,
        )

    def _fixture(self) -> dict[str, object]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        registry = ArtifactRegistry(root, f"runs/{RUN_ID}/registry")
        ledger = EventLedger(root, f"runs/{RUN_ID}/events.jsonl")

        document = {
            "schema_version": "scientific-dataset-source/v1",
            "dataset_id": "dataset-public",
            "name": "Audited public Dataset",
            "version": "2026-08-30",
            "license": {
                "spdx_id": "CC-BY-4.0",
                "canonical_url": (
                    "https://creativecommons.org/licenses/by/4.0/"
                ),
            },
            "data": [
                {"unit_id": f"unit-{index}", "value": index}
                for index in range(8)
            ],
        }
        source_bytes = canonical_json_bytes(document) + b"\n"
        source = research_state._scientific_dataset_source_projection(
            source_bytes
        )
        raw = registry.put_bytes(
            source_bytes,
            logical_type="external_response_body",
            origin="audited Dataset response body",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "dataset-test"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        acquisition_record = self._put_json(
            registry,
            {"dataset_id": source["dataset_id"], "kind": "acquisition-plan"},
            logical_type="scientific_dataset_acquisition_plan",
            role=Role.EVIDENCE_CURATOR,
        )
        acquisition_plan = SimpleNamespace(
            artifact_hash=acquisition_record.sha256,
            record_hash=str(acquisition_record.record_hash),
            intended_use="Evaluate the frozen method.",
            processing_scope=("parse numeric values",),
            derivative_output_scope=("aggregate statistics",),
            redistribution_plan="DERIVED_AGGREGATES_ONLY",
            attribution_notice="Attribute the Dataset publisher.",
            license_obligations=(
                "attribute-source",
                "link-license",
                "mark-changes",
            ),
            source_url="https://datasets.example.org/public.json",
            source_host="datasets.example.org",
            policy_id="scientific-dataset-pinned-json/v1",
            adapter_id="scientist-one-scientific-dataset-json-v1",
        )
        contract_record = self._put_json(
            registry,
            {"contract_id": "dataset-contract"},
            logical_type="evaluation_contract",
            role=Role.PROTOCOL_DESIGNER,
        )
        contract = scientific_design.require_frozen_evaluation_contract(
            registry, contract_artifact_sha256=contract_record.sha256,
        )
        request = self._put_json(
            registry,
            {"kind": "transport-request"},
            logical_type="external_request",
            role=Role.EVIDENCE_CURATOR,
        )
        response = self._put_json(
            registry,
            {"kind": "transport-response"},
            logical_type="external_response_receipt",
            role=Role.EVIDENCE_CURATOR,
        )
        transport_authority = self._put_json(
            registry,
            {"kind": "transport-authority"},
            logical_type="audited_transport_execution_authority",
            role=Role.EVIDENCE_CURATOR,
        )
        transport = SimpleNamespace(
            authority_artifact=transport_authority,
            request_artifact=request,
            response_receipt_artifact=response,
            raw_response_artifact=raw,
            body_sha256=raw.sha256,
            body_size=raw.size,
        )
        proposal = self._put_json(
            registry,
            {"dataset_id": source["dataset_id"], "kind": "usage-proposal"},
            logical_type="scientific_dataset_usage_proposal",
            role=Role.EVIDENCE_CURATOR,
        )
        semantic = self._put_json(
            registry,
            {"dataset_id": source["dataset_id"], "accepted": True},
            logical_type="scientific_semantic_judgment_receipt",
            role=Role.CLAIM_VERIFIER,
        )
        semantic_transport = self._put_json(
            registry,
            {"dataset_id": source["dataset_id"], "provider": "fixture"},
            logical_type="audited_provider_transport_authority",
            role=Role.CLAIM_VERIFIER,
        )
        manifest_payload = research_state._scientific_dataset_manifest_payload(
            source,
            acquisition_plan=acquisition_plan,
            evaluation_contract_record=contract_record,
            raw_record=raw,
            transport_authority_record=transport_authority,
            response_receipt_record=response,
        )
        manifest = self._put_json(
            registry,
            manifest_payload,
            logical_type=research_state.SCIENTIFIC_DATASET_MANIFEST_LOGICAL_TYPE,
            role=Role.EVIDENCE_CURATOR,
            origin=(
                "audited external scientific dataset manifest "
                f"{source['dataset_id']}"
            ),
            command=(
                "scientist-one",
                "manifest-audited-scientific-dataset",
            ),
            parents=(
                acquisition_record.sha256,
                contract_record.sha256,
                transport_authority.sha256,
                response.sha256,
                raw.sha256,
            ),
            schema_version=(
                research_state.SCIENTIFIC_DATASET_AUTHORITY_SCHEMA_VERSION
            ),
        )
        ledger.record(
            run_id=RUN_ID,
            actor_role=Role.CLAIM_VERIFIER,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=(semantic_transport.sha256,),
            code_version="dataset-test-code",
            configuration_hash=CONFIGURATION_HASH,
            reason="accepted audited-live Dataset usage review",
            event_id="dataset-semantic-transport",
            timestamp=SEMANTIC_STAMP,
            event_type="CHECKPOINT",
            metadata={"fixture": "Dataset semantic transport"},
        )
        semantic_resolution = (
            None,
            proposal,
            {},
            transport,
            source,
            manifest,
            semantic,
            semantic_transport.sha256,
            acquisition_plan,
            contract_record,
        )
        return {
            "registry": registry,
            "ledger": ledger,
            "source": source,
            "contract": contract,
            "contract_record": contract_record,
            "proposal": proposal,
            "semantic": semantic,
            "semantic_resolution": semantic_resolution,
        }

    @contextmanager
    def _patched_fixture(self):
        fixture = self._fixture()
        with patch.object(
            research_state,
            "_require_scientific_dataset_usage_semantic_authority",
            return_value=fixture["semantic_resolution"],
        ):
            yield fixture

    @staticmethod
    def _register_authority(fixture: dict[str, object]):
        return research_state.register_scientific_dataset_authority(
            fixture["registry"],
            fixture["ledger"],
            run_id=RUN_ID,
            usage_proposal_artifact_hash=fixture["proposal"].sha256,
            semantic_authority_artifact_hash=fixture["semantic"].sha256,
        )

    @staticmethod
    def _register_projection(fixture: dict[str, object], authority):
        return research_state.register_scientific_experiment_dataset_projection(
            fixture["registry"],
            fixture["ledger"],
            run_id=RUN_ID,
            dataset_authority_artifact_hash=authority.sha256,
            evaluation_contract_artifact_hash=(
                fixture["contract_record"].sha256
            ),
        )

    @staticmethod
    def _register_splits(fixture: dict[str, object], authority):
        return research_state.register_scientific_dataset_split_authorities(
            fixture["registry"],
            fixture["ledger"],
            run_id=RUN_ID,
            dataset_authority_artifact_hash=authority.sha256,
            evaluation_contract_artifact_hash=(
                fixture["contract_record"].sha256
            ),
        )

    def test_publication_family_is_idempotent_and_timestamp_bound(self) -> None:
        with self._patched_fixture() as fixture:
            registry = fixture["registry"]
            ledger = fixture["ledger"]
            authority = self._register_authority(fixture)
            resolved = research_state.require_scientific_dataset_authority(
                registry,
                ledger,
                run_id=RUN_ID,
                authority_artifact_hash=authority.sha256,
            )
            count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            self.assertEqual(self._register_authority(fixture), authority)
            self.assertEqual(len(registry.list_records()), count)
            self.assertEqual(ledger.assert_valid().event_count, event_count)

            projection = self._register_projection(fixture, authority)
            projection_count = len(registry.list_records())
            projection_event_count = ledger.assert_valid().event_count
            self.assertEqual(
                self._register_projection(fixture, authority),
                projection,
            )
            self.assertEqual(len(registry.list_records()), projection_count)
            self.assertEqual(
                ledger.assert_valid().event_count,
                projection_event_count,
            )

            splits = self._register_splits(fixture, authority)
            split_count = len(registry.list_records())
            split_event_count = ledger.assert_valid().event_count
            self.assertEqual(self._register_splits(fixture, authority), splits)
            self.assertEqual(len(registry.list_records()), split_count)
            self.assertEqual(ledger.assert_valid().event_count, split_event_count)

            authority_time = registry.get_metadata(authority.sha256).created_at
            usage_time = registry.get_metadata(
                resolved.usage_artifact_hash
            ).created_at
            self.assertEqual(authority_time, SEMANTIC_STAMP)
            self.assertEqual(usage_time, authority_time)
            self.assertEqual(projection.created_at, authority_time)
            self.assertEqual(
                {record.created_at for record in splits},
                {authority_time},
            )
            split_event = next(
                event
                for event in ledger.events()
                if event.event_id.startswith("scientific-dataset-splits-")
            )
            self.assertEqual(split_event.timestamp, authority_time)

    def test_artifact_without_event_resumes_for_all_publications(self) -> None:
        with self._patched_fixture() as fixture:
            registry = fixture["registry"]
            ledger = fixture["ledger"]

            with patch.object(
                ledger,
                "_append_locked",
                side_effect=RuntimeError("injected Dataset event interruption"),
            ):
                with self.assertRaisesRegex(RuntimeError, "injected Dataset"):
                    self._register_authority(fixture)
            base_count = len(registry.list_records())
            base_events = ledger.assert_valid().event_count
            authority = self._register_authority(fixture)
            self.assertEqual(len(registry.list_records()), base_count)
            self.assertEqual(ledger.assert_valid().event_count, base_events + 1)

            with patch.object(
                ledger,
                "_append_locked",
                side_effect=RuntimeError("injected projection event interruption"),
            ):
                with self.assertRaisesRegex(RuntimeError, "injected projection"):
                    self._register_projection(fixture, authority)
            projection_count = len(registry.list_records())
            projection_events = ledger.assert_valid().event_count
            self._register_projection(fixture, authority)
            self.assertEqual(len(registry.list_records()), projection_count)
            self.assertEqual(
                ledger.assert_valid().event_count,
                projection_events + 1,
            )

            with patch.object(
                ledger,
                "_append_locked",
                side_effect=RuntimeError("injected split event interruption"),
            ):
                with self.assertRaisesRegex(RuntimeError, "injected split"):
                    self._register_splits(fixture, authority)
            split_count = len(registry.list_records())
            split_events = ledger.assert_valid().event_count
            records = self._register_splits(fixture, authority)
            self.assertEqual(len(records), 4)
            self.assertEqual(len(registry.list_records()), split_count)
            self.assertEqual(ledger.assert_valid().event_count, split_events + 1)

    def test_capacity_failures_are_zero_write_for_all_publications(self) -> None:
        with self._patched_fixture() as fixture:
            registry = fixture["registry"]
            ledger = fixture["ledger"]
            registry_count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            with patch.object(
                research_state,
                "MAX_REGISTRY_RECORDS",
                registry_count + 1,
            ):
                with self.assertRaisesRegex(ValidationError, "registry capacity"):
                    self._register_authority(fixture)
            self.assertEqual(len(registry.list_records()), registry_count)
            self.assertEqual(ledger.assert_valid().event_count, event_count)

            authority = self._register_authority(fixture)
            ledger_result = ledger.assert_valid()
            projection_registry_count = len(registry.list_records())
            with patch.object(
                research_state,
                "MAX_LEDGER_BYTES",
                ledger_result.valid_prefix_bytes + 1,
            ):
                with self.assertRaisesRegex(
                    ValidationError,
                    "ledger byte capacity",
                ):
                    self._register_projection(fixture, authority)
            self.assertEqual(
                len(registry.list_records()),
                projection_registry_count,
            )
            self.assertEqual(
                ledger.assert_valid().event_count,
                ledger_result.event_count,
            )

            self._register_projection(fixture, authority)
            split_registry_count = len(registry.list_records())
            split_event_count = ledger.assert_valid().event_count
            with patch.object(
                research_state,
                "MAX_REGISTRY_RECORDS",
                split_registry_count + 3,
            ):
                with self.assertRaisesRegex(ValidationError, "registry capacity"):
                    self._register_splits(fixture, authority)
            self.assertEqual(len(registry.list_records()), split_registry_count)
            self.assertEqual(ledger.assert_valid().event_count, split_event_count)

    def test_artifact_and_event_collisions_are_zero_write(self) -> None:
        with self._patched_fixture() as fixture:
            registry = fixture["registry"]
            ledger = fixture["ledger"]
            source = fixture["source"]
            self._put_json(
                registry,
                {
                    "dataset_id": source["dataset_id"],
                    "version": source["version"],
                    "caller_collision": True,
                },
                logical_type=(
                    research_state.SCIENTIFIC_DATASET_USAGE_LOGICAL_TYPE
                ),
                role=Role.EVIDENCE_CURATOR,
            )
            registry_count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            with self.assertRaisesRegex(ValidationError, "identity collides"):
                self._register_authority(fixture)
            self.assertEqual(len(registry.list_records()), registry_count)
            self.assertEqual(ledger.assert_valid().event_count, event_count)

        with self._patched_fixture() as fixture:
            registry = fixture["registry"]
            ledger = fixture["ledger"]
            authority_record = self._register_authority(fixture)
            authority = research_state.require_scientific_dataset_authority(
                registry,
                ledger,
                run_id=RUN_ID,
                authority_artifact_hash=authority_record.sha256,
            )
            payload = (
                research_state._scientific_experiment_dataset_projection_payload(
                    authority,
                    evaluation_contract_record=fixture["contract_record"],
                )
            )
            projection_plan = research_state._scientific_dataset_artifact_plan(
                registry,
                payload,
                logical_type="experiment_dataset",
                origin=(
                    "audited scientific experiment Dataset projection "
                    f"{authority.dataset_id}:{authority.version}"
                ),
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=(
                    "scientist-one",
                    "project-scientific-experiment-dataset",
                ),
                parent_artifacts=(
                    authority.authority_artifact_hash,
                    fixture["contract_record"].sha256,
                    authority.raw_data_artifact_hash,
                ),
                schema_version=(
                    research_state
                    .SCIENTIFIC_EXPERIMENT_DATASET_PROJECTION_SCHEMA_VERSION
                ),
                created_at=registry.get_metadata(
                    authority_record.sha256
                ).created_at,
            )[1]
            current = ledger.assert_valid().events[-1]
            ledger.record(
                run_id=RUN_ID,
                actor_role=Role.EVIDENCE_CURATOR,
                state_before=current.requested_state_after,
                requested_state_after=current.requested_state_after,
                artifact_hashes=(authority_record.sha256,),
                code_version=current.code_version,
                configuration_hash=current.configuration_hash,
                reason="injected projection event collision",
                event_id=(
                    "scientific-experiment-dataset-"
                    f"{projection_plan.sha256[:32]}"
                ),
                timestamp=current.timestamp,
                event_type="CHECKPOINT",
                metadata={"collision": True},
            )
            registry_count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            with self.assertRaisesRegex(
                ValidationError,
                "event precedes|event collides",
            ):
                self._register_projection(fixture, authority_record)
            self.assertEqual(len(registry.list_records()), registry_count)
            self.assertEqual(ledger.assert_valid().event_count, event_count)

        with self._patched_fixture() as fixture:
            registry = fixture["registry"]
            ledger = fixture["ledger"]
            authority_record = self._register_authority(fixture)
            authority = research_state.require_scientific_dataset_authority(
                registry,
                ledger,
                run_id=RUN_ID,
                authority_artifact_hash=authority_record.sha256,
            )
            partition, memberships, excluded, unit_type = (
                research_state._scientific_dataset_partition_projection(
                    registry,
                    dataset_authority=authority,
                    evaluation_contract_artifact_hash=(
                        fixture["contract_record"].sha256
                    ),
                )
            )
            role, split_id, members, member_hashes = memberships[0]
            payload = research_state._scientific_dataset_split_payload(
                run_id=RUN_ID,
                dataset_authority=authority,
                evaluation_contract_record=fixture["contract_record"],
                partition_sha256=partition,
                split_role=role,
                split_id=split_id,
                member_unit_ids=members,
                member_unit_hashes=member_hashes,
                excluded_unit_ids=excluded,
                unit_type=unit_type,
            )
            payload["caller_collision"] = True
            self._put_json(
                registry,
                payload,
                logical_type=(
                    research_state
                    .SCIENTIFIC_DATASET_SPLIT_AUTHORITY_LOGICAL_TYPE
                ),
                role=Role.PROTOCOL_DESIGNER,
            )
            registry_count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            with self.assertRaisesRegex(ValidationError, "identity collides"):
                self._register_splits(fixture, authority_record)
            self.assertEqual(len(registry.list_records()), registry_count)
            self.assertEqual(ledger.assert_valid().event_count, event_count)

    def test_corrected_projection_and_split_timestamp_mismatch_are_rejected(
        self,
    ) -> None:
        with self._patched_fixture() as fixture:
            registry = fixture["registry"]
            ledger = fixture["ledger"]
            authority = self._register_authority(fixture)
            projection = self._register_projection(fixture, authority)
            projection_event = next(
                event
                for event in ledger.events()
                if event.event_id.startswith("scientific-experiment-dataset-")
            )
            ledger.append_correction(
                projection_event.event_id,
                actor_role=Role.CLAIM_VERIFIER,
                reason="correct the Dataset projection checkpoint",
                corrected_fields={"projection": "caller-corrected"},
            )
            with self.assertRaisesRegex(ValidationError, "differs or is late"):
                research_state.require_scientific_experiment_dataset_projection(
                    registry,
                    ledger,
                    run_id=RUN_ID,
                    projection_artifact_hash=projection.sha256,
                )
            registry_count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            with self.assertRaisesRegex(ValidationError, "stale"):
                self._register_projection(fixture, authority)
            self.assertEqual(len(registry.list_records()), registry_count)
            self.assertEqual(ledger.assert_valid().event_count, event_count)

        with self._patched_fixture() as fixture:
            registry = fixture["registry"]
            ledger = fixture["ledger"]
            authority_record = self._register_authority(fixture)
            authority = research_state.require_scientific_dataset_authority(
                registry,
                ledger,
                run_id=RUN_ID,
                authority_artifact_hash=authority_record.sha256,
            )
            partition, memberships, excluded, unit_type = (
                research_state._scientific_dataset_partition_projection(
                    registry,
                    dataset_authority=authority,
                    evaluation_contract_artifact_hash=(
                        fixture["contract_record"].sha256
                    ),
                )
            )
            created_at = registry.get_metadata(authority_record.sha256).created_at
            records = []
            for index, (role, split_id, members, member_hashes) in enumerate(
                memberships
            ):
                payload = research_state._scientific_dataset_split_payload(
                    run_id=RUN_ID,
                    dataset_authority=authority,
                    evaluation_contract_record=fixture["contract_record"],
                    partition_sha256=partition,
                    split_role=role,
                    split_id=split_id,
                    member_unit_ids=members,
                    member_unit_hashes=member_hashes,
                    excluded_unit_ids=excluded,
                    unit_type=unit_type,
                )
                records.append(
                    registry.put_json(
                        payload,
                        logical_type=(
                            research_state
                            .SCIENTIFIC_DATASET_SPLIT_AUTHORITY_LOGICAL_TYPE
                        ),
                        origin=(
                            f"deterministic scientific Dataset split {split_id}:"
                            f"{role.value}"
                        ),
                        creator_role=Role.PROTOCOL_DESIGNER,
                        creation_command=(
                            "scientist-one",
                            "freeze-scientific-dataset-splits",
                        ),
                        parent_artifacts=(
                            authority.authority_artifact_hash,
                            fixture["contract_record"].sha256,
                        ),
                        schema_version=(
                            research_state
                            .SCIENTIFIC_DATASET_SPLIT_AUTHORITY_SCHEMA_VERSION
                        ),
                        mime_type="application/json",
                        validation_result="PASS",
                        frozen=True,
                        created_at=(
                            STAMP if index == 0 else created_at
                        ),
                    )
                )
            current = ledger.assert_valid().events[-1]
            artifact_hashes = tuple(record.sha256 for record in records)
            ledger.record(
                run_id=RUN_ID,
                actor_role=Role.PROTOCOL_DESIGNER,
                state_before=current.requested_state_after,
                requested_state_after=current.requested_state_after,
                artifact_hashes=artifact_hashes,
                code_version=current.code_version,
                configuration_hash=current.configuration_hash,
                reason=(
                    "froze one exhaustive disjoint Dataset partition before execution"
                ),
                event_id=f"scientific-dataset-splits-{partition[:24]}",
                timestamp=created_at,
                event_type="CHECKPOINT",
                metadata={
                    "schema_version": (
                        research_state.SCIENTIFIC_DATASET_SPLIT_EVENT_SCHEMA
                    ),
                    "dataset_id": authority.dataset_id,
                    "dataset_version": authority.version,
                    "dataset_authority_artifact_hash": (
                        authority.authority_artifact_hash
                    ),
                    "evaluation_contract_artifact_hash": (
                        fixture["contract_record"].sha256
                    ),
                    "algorithm_id": (
                        research_state.SCIENTIFIC_DATASET_SPLIT_ALGORITHM_ID
                    ),
                    "partition_sha256": partition,
                    "split_artifact_hashes": list(artifact_hashes),
                    "split_record_hashes": [
                        record.record_hash for record in records
                    ],
                },
            )
            with self.assertRaisesRegex(
                ValidationError,
                "artifact differs|ledger authority",
            ):
                research_state.require_scientific_dataset_split_authority(
                    registry,
                    ledger,
                    run_id=RUN_ID,
                    split_authority_artifact_hash=records[0].sha256,
                )


if __name__ == "__main__":
    unittest.main()
