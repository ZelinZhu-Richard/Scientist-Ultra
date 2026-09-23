"""Inert GPU-compute terminal codecs and real-negative boundaries only.

Constructed DTOs carry no source authority. These tests do not manufacture a
completed GPU requirement, scientific owner, execution, observation, approval
or spending permission. No issuer, registry-positive owner mock, GPU or live
external call is used. Legacy codec goldens are from the saved pre-integration
source, not refreshed from the GPU candidate.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import unittest

from scientist_one import compute_terminal as compute
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.resources import ResourceConfig, resource_config_sha256
from scientist_one.security import canonical_json_bytes
from tests.test_paper_verification_shared_replay import _portable_ast_dump


def _sha(value):
    return f"{value:064x}"


def _function(value):
    return ast.parse(inspect.getsource(value)).body[0]


def _calls(node, name):
    return sorted((item for item in ast.walk(node) if isinstance(item, ast.Call)
                   and ((isinstance(item.func, ast.Name) and item.func.id == name)
                        or (isinstance(item.func, ast.Attribute) and item.func.attr == name))),
                  key=lambda item: item.lineno)


def _expression_line(node, source):
    """Locate an actual expression subtree, not prose claiming a guard exists."""
    wanted = ast.dump(ast.parse(source, mode="eval").body, include_attributes=False)
    matches = [item.lineno for item in ast.walk(node) if isinstance(item, ast.expr)
               and ast.dump(item, include_attributes=False) == wanted]
    if not matches:
        raise AssertionError(f"missing actual expression: {source}")
    return min(matches)


def _assessment(**changes):
    """Native unissued value only: no full requirement or source companion."""
    values = dict(
        assessment_id="inert-gpu-requirement", ledger_run_id="inert-ledger-run",
        execution_run_id="inert-execution-run", hypothesis_id="inert-hypothesis",
        experiment_id="inert-experiment", scientific_binding_sha256=_sha(10),
        project_definition_sha256=_sha(11), contract_value_sha256=_sha(12),
        evaluation_contract_freeze_receipt_artifact_sha256=_sha(1),
        evaluation_contract_freeze_receipt_record_hash=_sha(101),
        contract_artifact_sha256=_sha(2), contract_record_hash=_sha(102),
        frozen_run_spec_artifact_sha256=_sha(3), frozen_run_spec_record_hash=_sha(103),
        compute_escalation_plan_authority_artifact_sha256=_sha(4),
        compute_escalation_plan_authority_record_hash=_sha(104),
        cloud_run_spec_sha256=_sha(13), local_compute_profile_sha256=_sha(14),
        cloud_compute_profile_sha256=_sha(15), freeze_event_id="inert-freeze",
        freeze_event_hash=_sha(20), freeze_event_index=1,
        escalation_event_id="inert-escalation", escalation_event_hash=_sha(21),
        escalation_event_index=2, source_artifact_sha256s=tuple(_sha(i) for i in range(1, 5)),
        source_artifact_record_hashes=tuple(_sha(i) for i in range(101, 105)),
        ledger_event_id="inert-gpu-admission", ledger_event_hash=_sha(22),
        ledger_event_index=3, ledger_prefix_head_hash=_sha(22),
    )
    values.update(changes)
    return compute.GpuRequirementComputeTerminalAssessment(**values)


def _legacy_assessment():
    """Unissued v1 wall-budget value; not a source-owned exhaustion finding."""
    config = ResourceConfig(maximum_wall_clock_seconds=10.0, cpu_worker_limit=1)
    return compute.ComputeTerminalAssessment(
        assessment_id="inert-wall-assessment", ledger_run_id="inert-ledger-run",
        execution_run_id="inert-execution-run", scientific_binding_sha256=_sha(10),
        evaluation_contract_freeze_receipt_artifact_sha256=_sha(1),
        evaluation_contract_freeze_receipt_record_hash=_sha(101),
        contract_artifact_sha256=_sha(2), contract_record_hash=_sha(102),
        frozen_run_spec_artifact_sha256=_sha(3), frozen_run_spec_record_hash=_sha(103),
        frozen_configuration_inventory_artifact_sha256=_sha(4),
        frozen_configuration_inventory_record_hash=_sha(104),
        wall_budget_observation_artifact_sha256=_sha(5), wall_budget_observation_record_hash=_sha(105),
        resource_config=config, resource_config_sha256=resource_config_sha256(config),
        external_resource_authority_sequence=1, external_resource_authority_sha256=_sha(6),
        maximum_wall_clock_seconds=10.0, wall_started_at_epoch_seconds=100.0,
        wall_observed_at_epoch_seconds=110.0, wall_elapsed_seconds=10.0,
        mandatory_work_status=compute.MANDATORY_WORK_STATUS,
        external_effect_status=compute.EXTERNAL_EFFECT_STATUS,
        factual_status=compute.WALL_BUDGET_EXHAUSTED_STATUS,
        source_artifact_sha256s=tuple(_sha(i) for i in range(1, 6)),
        source_artifact_record_hashes=tuple(_sha(i) for i in range(101, 106)),
        ledger_event_id="inert-wall-admission", ledger_event_hash=_sha(22),
        ledger_event_index=3, ledger_prefix_head_hash=_sha(22),
    )


class GpuComputeTerminalValueTests(unittest.TestCase):
    def test_exact_closed_codec_roundtrip_and_detached_native_arrays(self):
        value = _assessment()
        wire = value.to_dict()
        self.assertEqual(wire["schema_version"], "compute-terminal-gpu-requirement/v1")
        self.assertEqual(set(wire), {item.name for item in fields(value)} | {"schema_version"})
        self.assertIs(type(wire["source_artifact_sha256s"]), list)
        self.assertIs(type(wire["source_artifact_record_hashes"]), list)
        raw = canonical_json_bytes(wire) + b"\n"
        replayed = compute.GpuRequirementComputeTerminalAssessment.from_mapping(json.loads(raw))
        self.assertIs(type(replayed), compute.GpuRequirementComputeTerminalAssessment)
        self.assertEqual(replayed, value)
        self.assertEqual(canonical_json_bytes(replayed.to_dict()) + b"\n", raw)
        wire["source_artifact_sha256s"].clear()
        self.assertEqual(len(value.source_artifact_sha256s), 4)
        with self.assertRaises(FrozenInstanceError):
            value.spending_authorized = True

    def test_exact_status_and_scope_never_claim_science_spend_or_observation(self):
        value = _assessment()
        self.assertEqual(value.factual_status,
                         "UNPERFORMED_MANDATORY_CUDA_DEVICE_PROTOCOL_REQUIRES_GPU_CLOUD")
        self.assertEqual(value.requirement_profile_id, "cuda-u32-vector-add-events/v1")
        self.assertEqual(value.requirement_scope, "ONE_MANDATORY_CUDA_DEVICE_TIMING_OBLIGATION")
        self.assertEqual(value.mandatory_work_status, "NOT_STARTED_INCOMPLETE")
        self.assertEqual(value.external_effect_status, "NONE_OBSERVED")
        self.assertEqual(value.external_validation_status, "UNTESTED")
        self.assertEqual(value.authority_scope, "OPERATIONAL_BLOCKER")
        self.assertIs(value.scientific_evidence, False)
        self.assertIs(value.spending_authorized, False)
        for name, alternative in (
            ("factual_status", compute.WALL_BUDGET_EXHAUSTED_STATUS),
            ("requirement_profile_id", "cuda-same-name-unreviewed"),
            ("requirement_scope", "ALL_SCIENTIFIC_WORK"),
            ("mandatory_work_status", "COMPLETED"), ("external_effect_status", "OBSERVED"),
            ("external_validation_status", "PASS"), ("authority_scope", "SCIENTIFIC_EVIDENCE"),
        ):
            with self.subTest(name=name), self.assertRaises(compute.ComputeTerminalError):
                replace(value, **{name: alternative})
        for name in ("scientific_evidence", "spending_authorized"):
            for alternative in (True, 0, 1, None, "False"):
                with self.subTest(name=name, alternative=alternative), self.assertRaises(compute.ComputeTerminalError):
                    replace(value, **{name: alternative})

    def test_no_wall_budget_or_legacy_alias_fields_are_available(self):
        value = _assessment()
        self.assertNotIsInstance(value, compute.ComputeTerminalAssessment)
        self.assertFalse(any("wall" in name for name in value.to_dict()))
        forbidden = (
            "resource_config", "resource_config_sha256", "external_resource_authority_sequence",
            "external_resource_authority_sha256", "maximum_wall_clock_seconds",
            "wall_budget_observation_artifact_sha256", "wall_elapsed_seconds",
            "frozen_configuration_inventory_artifact_sha256",
        )
        for name in forbidden:
            self.assertFalse(hasattr(value, name))
            with self.subTest(name=name), self.assertRaises(compute.ComputeTerminalError):
                compute.GpuRequirementComputeTerminalAssessment.from_mapping({**value.to_dict(), name: None})

    def test_unknown_missing_cross_schema_and_nonnative_wire_arrays_refuse(self):
        wire = _assessment().to_dict()
        for missing in wire:
            changed = dict(wire)
            del changed[missing]
            with self.subTest(missing=missing), self.assertRaises(compute.ComputeTerminalError):
                compute.GpuRequirementComputeTerminalAssessment.from_mapping(changed)
        for changes in ({"schema_version": compute.COMPUTE_TERMINAL_ASSESSMENT_SCHEMA},
                        {"schema_version": True}, {"unknown": True},
                        {"source_artifact_sha256s": tuple(wire["source_artifact_sha256s"])},
                        {"source_artifact_record_hashes": tuple(wire["source_artifact_record_hashes"])}):
            with self.subTest(keys=tuple(changes)), self.assertRaises(compute.ComputeTerminalError):
                compute.GpuRequirementComputeTerminalAssessment.from_mapping({**wire, **changes})

    def test_chronology_requires_both_exact_prior_admissions_and_ledger_hash(self):
        value = _assessment()
        for name in ("freeze_event_index", "escalation_event_index"):
            for index in (value.ledger_event_index, value.ledger_event_index + 1, -1, True, 1.0):
                with self.subTest(name=name, index=index), self.assertRaises(compute.ComputeTerminalError):
                    replace(value, **{name: index})
        for index in (-1, 0, 2, True, 3.0, compute.MAX_LEDGER_EVENTS):
            with self.subTest(index=index), self.assertRaises(compute.ComputeTerminalError):
                replace(value, ledger_event_index=index)
        self.assertEqual(replace(value, ledger_event_index=compute.MAX_LEDGER_EVENTS - 1).ledger_event_index, 9999)
        with self.assertRaises(compute.ComputeTerminalError):
            replace(value, ledger_prefix_head_hash=_sha(900))
        # The codec asserts only both-before-terminal, not an invented relative
        # order between the two independently source-owned admissions.
        self.assertEqual(replace(value, freeze_event_index=2, escalation_event_index=1).freeze_event_index, 2)

    def test_named_source_map_requires_every_exact_artifact_record_pair(self):
        value = _assessment()
        pairs = (
            ("evaluation_contract_freeze_receipt_artifact_sha256", "evaluation_contract_freeze_receipt_record_hash"),
            ("contract_artifact_sha256", "contract_record_hash"),
            ("frozen_run_spec_artifact_sha256", "frozen_run_spec_record_hash"),
            ("compute_escalation_plan_authority_artifact_sha256", "compute_escalation_plan_authority_record_hash"),
        )
        for digest_name, record_name in pairs:
            for name in (digest_name, record_name):
                with self.subTest(name=name), self.assertRaisesRegex(compute.ComputeTerminalError, "outside its closure"):
                    replace(value, **{name: _sha(900)})
            index = value.source_artifact_sha256s.index(getattr(value, digest_name))
            with self.subTest(omission=digest_name), self.assertRaises(compute.ComputeTerminalError):
                replace(value, source_artifact_sha256s=value.source_artifact_sha256s[:index] + value.source_artifact_sha256s[index + 1:],
                        source_artifact_record_hashes=value.source_artifact_record_hashes[:index] + value.source_artifact_record_hashes[index + 1:])
        with self.assertRaises(compute.ComputeTerminalError):
            replace(value, source_artifact_record_hashes=tuple(reversed(value.source_artifact_record_hashes)))
        # Mapping equality is exact, but canonical closure order belongs to the
        # full source owner; the value codec does not invent its own ordering.
        reordered = replace(value, source_artifact_sha256s=tuple(reversed(value.source_artifact_sha256s)),
                            source_artifact_record_hashes=tuple(reversed(value.source_artifact_record_hashes)))
        self.assertEqual(dict(zip(reordered.source_artifact_sha256s, reordered.source_artifact_record_hashes)),
                         dict(zip(value.source_artifact_sha256s, value.source_artifact_record_hashes)))

    def test_source_capacity_preserves_one_parent_for_downstream_terminal(self):
        value = _assessment()
        extra = tuple(_sha(i) for i in range(1000, 1251))
        maximum = replace(value, source_artifact_sha256s=value.source_artifact_sha256s + extra,
                          source_artifact_record_hashes=value.source_artifact_record_hashes + extra)
        self.assertEqual(len(maximum.source_artifact_sha256s), 255)
        self.assertLess(len(canonical_json_bytes(maximum.to_dict())) + 1, compute._MAX_COMPUTE_TERMINAL_BYTES)
        for digests, records in (((), ()), (maximum.source_artifact_sha256s + (_sha(2000),),
                                          maximum.source_artifact_record_hashes + (_sha(2001),)),
                                 (value.source_artifact_sha256s, value.source_artifact_record_hashes[:-1]),
                                 (value.source_artifact_sha256s + (value.source_artifact_sha256s[0],),
                                  value.source_artifact_record_hashes + (value.source_artifact_record_hashes[0],)),
                                 (list(value.source_artifact_sha256s), value.source_artifact_record_hashes)):
            with self.subTest(count=len(digests)), self.assertRaises(compute.ComputeTerminalError):
                replace(value, source_artifact_sha256s=digests, source_artifact_record_hashes=records)

    def test_native_leaf_subclasses_bool_and_mutation_refuse_before_value_hooks(self):
        calls = []
        class ForeignText(str):
            def __eq__(self, other):
                calls.append("equal")
                return True

        class ForeignInt(int):
            def __lt__(self, other):
                calls.append("less")
                return False

        value = _assessment()
        for changes in ({"assessment_id": ForeignText("id")}, {"contract_record_hash": ForeignText(_sha(102))},
                        {"requirement_scope": ForeignText(compute.GPU_REQUIREMENT_SCOPE)},
                        {"ledger_event_index": ForeignInt(3)},
                        {"source_artifact_record_hashes": (ForeignText(_sha(101)), *value.source_artifact_record_hashes[1:])}):
            with self.subTest(keys=tuple(changes)), self.assertRaises(compute.ComputeTerminalError):
                replace(value, **changes)
        object.__setattr__(value, "spending_authorized", 0)
        with self.assertRaises(compute.ComputeTerminalError):
            value.to_dict()
        self.assertEqual(calls, [])
        class ForeignAssessment(compute.GpuRequirementComputeTerminalAssessment):
            pass
        with self.assertRaises(compute.ComputeTerminalError):
            ForeignAssessment.from_mapping(_assessment().to_dict())

    def test_foreign_mapping_keys_and_arrays_refuse_before_container_hooks(self):
        calls = []

        class ForeignMapping(Mapping):
            def __iter__(self):
                calls.append("mapping iteration")
                raise AssertionError("foreign Mapping must not be traversed")

            def __len__(self):
                calls.append("mapping length")
                raise AssertionError("foreign Mapping must not be measured")

            def __getitem__(self, key):
                calls.append("mapping lookup")
                raise AssertionError("foreign Mapping must not be read")

        class ForeignDict(dict):
            __iter__ = ForeignMapping.__iter__
            __len__ = ForeignMapping.__len__
            __getitem__ = ForeignMapping.__getitem__

        class ForeignList(list):
            __iter__ = ForeignMapping.__iter__
            __len__ = ForeignMapping.__len__
            __getitem__ = ForeignMapping.__getitem__

        class ForeignKey(str):
            __hash__ = str.__hash__

            def __eq__(self, other):
                calls.append("key comparison")
                return str.__eq__(self, other)

        wire = _assessment().to_dict()
        foreign_key_wire = {ForeignKey(key) if key == "assessment_id" else key: value
                            for key, value in wire.items()}
        for value in (ForeignMapping(), ForeignDict(wire), foreign_key_wire):
            with self.subTest(kind=type(value)), self.assertRaises(compute.ComputeTerminalError):
                compute.GpuRequirementComputeTerminalAssessment.from_mapping(value)
        for name in ("source_artifact_sha256s", "source_artifact_record_hashes"):
            with self.subTest(name=name), self.assertRaises(compute.ComputeTerminalError):
                compute.GpuRequirementComputeTerminalAssessment.from_mapping(
                    {**wire, name: ForeignList(wire[name])})
        self.assertEqual(calls, [])

    def test_wire_array_capacity_and_native_hash_identifier_syntax(self):
        wire = _assessment().to_dict()
        for name in ("source_artifact_sha256s", "source_artifact_record_hashes"):
            for values in ([], [_sha(1)] * 256):
                with self.subTest(name=name, count=len(values)), self.assertRaisesRegex(
                    compute.ComputeTerminalError, "native arrays"
                ):
                    compute.GpuRequirementComputeTerminalAssessment.from_mapping({**wire, name: values})
        for name, value in (("assessment_id", ""), ("execution_run_id", "has space"),
                            ("contract_value_sha256", "g" * 64), ("ledger_event_hash", "a" * 63),
                            ("scientific_binding_sha256", "A" * 64)):
            with self.subTest(name=name, value=value), self.assertRaises(ValidationError):
                compute.GpuRequirementComputeTerminalAssessment.from_mapping({**wire, name: value})

    def test_legacy_v1_full_codec_ast_and_roundtrip_remain_unchanged(self):
        # Saved pre-integration compute_terminal.py SHA4d55aa3f..., not a GPU
        # candidate hash. Entire class bodies/decorators/signatures are checked.
        for value, expected in (
            (compute.ComputeTerminalAssessment, "c86b92c09043b146f8838ef89b26bb82f895986ad3dfd7909c1cfc32b2b6e00c"),
            (compute.ComputeTerminalAssessmentResolution, "291383150c5de9a664b1a8b237d58ee02b5443c93f9760c53e94b3988a397660"),
            (compute.ComputeTerminalAssessmentResolutionStatus, "a21ec053924a6110972fa56a44983a7d4f17999bac7c143ce59fddf2398ef215"),
        ):
            node = ast.parse(inspect.getsource(value)).body[0]
            self.assertEqual(hashlib.sha256(_portable_ast_dump(node).encode()).hexdigest(), expected)
        legacy = _legacy_assessment()
        wire = legacy.to_dict()
        self.assertEqual(wire["schema_version"], "compute-terminal-assessment/v1")
        self.assertEqual(compute.ComputeTerminalAssessment.from_mapping(json.loads(canonical_json_bytes(wire))), legacy)
        self.assertIn("wall_elapsed_seconds", wire)
        self.assertNotIn("requirement_profile_id", wire)
        with self.assertRaises(compute.ComputeTerminalError):
            compute.GpuRequirementComputeTerminalAssessment.from_mapping(wire)
        with self.assertRaises(compute.ComputeTerminalError):
            compute.ComputeTerminalAssessment.from_mapping(_assessment().to_dict())


class GpuComputeTerminalBoundaryTests(unittest.TestCase):
    def test_real_absent_sources_refuse_both_public_paths_with_zero_admission_delta(self):
        # No source artifact, event or private completed-source value is made.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "run/registry")
            ledger = EventLedger(root, "run/events.jsonl")
            before = registry.verify_all(), ledger.assert_valid()
            self.assertEqual((before[0].count, before[1].event_count), (0, 0))
            with self.assertRaisesRegex(compute.ComputeTerminalError, "SOURCE_REQUIREMENT_UNAVAILABLE"):
                compute.register_gpu_requirement_compute_terminal_assessment(
                    registry, ledger, assessment_id="absent-gpu-assessment",
                    expected_ledger_run_id="absent-ledger-run",
                    expected_execution_run_id="absent-execution-run",
                    evaluation_contract_freeze_receipt_artifact_sha256=_sha(1),
                    compute_escalation_plan_authority_artifact_sha256=_sha(2),
                )
            self.assertEqual((registry.verify_all(), ledger.assert_valid()), before)
            with self.assertRaisesRegex(compute.ComputeTerminalError, "cannot be reopened"):
                compute.require_compute_terminal_assessment(
                    registry, ledger, assessment_artifact_sha256=_sha(3),
                    expected_ledger_run_id="absent-ledger-run",
                    expected_execution_run_id="absent-execution-run",
                )
            self.assertEqual((registry.verify_all(), ledger.assert_valid()), before)

    def test_public_api_has_no_source_injection_and_full_owner_precedes_publication(self):
        self.assertEqual(tuple(inspect.signature(
            compute.register_gpu_requirement_compute_terminal_assessment).parameters), (
                "registry", "ledger", "assessment_id", "expected_ledger_run_id",
                "expected_execution_run_id", "evaluation_contract_freeze_receipt_artifact_sha256",
                "compute_escalation_plan_authority_artifact_sha256"))
        self.assertEqual(tuple(inspect.signature(compute.require_compute_terminal_assessment).parameters), (
            "registry", "ledger", "assessment_artifact_sha256", "expected_ledger_run_id",
            "expected_execution_run_id"))
        register = _function(compute.register_gpu_requirement_compute_terminal_assessment)
        with_blocks = [item for item in register.body if isinstance(item, ast.With)]
        self.assertEqual(len(with_blocks), 1)
        owner, publish, readback = (_calls(with_blocks[0], name)[0] for name in (
            "_derive_gpu_compute_sources", "_publish_verified_compute_assessment",
            "_require_compute_terminal_assessment"))
        self.assertLess(owner.lineno, publish.lineno)
        self.assertLess(publish.lineno, readback.lineno)
        self.assertEqual(ast.unparse(with_blocks[0].items[0].context_expr),
                         "_project_resource_execution_lock(registry.policy.root)")
        self.assertEqual({item.arg: ast.unparse(item.value) for item in readback.keywords}["project_lock_held"], "True")
        derive = _function(compute._derive_gpu_compute_sources)
        full_owner = _calls(derive, "_resolve_gpu_validation_requirement")[0]
        self.assertEqual({item.arg: ast.unparse(item.value) for item in full_owner.keywords}["project_lock_held"], "True")
        required_status = _expression_line(
            derive, "resolution.status is not GpuValidationRequirementStatus.REQUIREMENT_ESTABLISHED")
        self.assertLess(full_owner.lineno, required_status)
        self.assertLess(required_status, _calls(derive, "_GpuComputeSources")[0].lineno)
        _expression_line(derive, "resolution.requirement is None")
        _expression_line(derive, "len(sources.records) > 255")

    def test_shared_publisher_structurally_preflights_cas_capacity_and_exact_delta(self):
        # Static control placement only; not a publication or race proof.
        node = _function(compute._publish_verified_compute_assessment)
        type_guard = _expression_line(node, "type(sources) not in {_ComputeSources, _GpuComputeSources}")
        self.assertLess(type_guard, _calls(node, "_assessment_event_binding")[0].lineno)
        self.assertLess(_calls(node, "_open_mutation_lock")[0].lineno,
                        _calls(node, "_open_lock")[0].lineno)
        append, put = _calls(node, "_append_locked")[0], _calls(node, "_put_bytes_locked")[0]
        self.assertLess(append.lineno, put.lineno)
        for expression in (
            "locked_registry != sources.registry_snapshot", "locked_ledger != sources.ledger_snapshot",
            "len(data) > _MAX_COMPUTE_TERMINAL_BYTES",
            "locked_registry.count + records_needed > MAX_REGISTRY_RECORDS",
            "locked_ledger.event_count + events_needed > MAX_LEDGER_EVENTS",
            "locked_ledger.valid_prefix_bytes + len(line) > MAX_LEDGER_BYTES",
        ):
            self.assertLess(_expression_line(node, expression), append.lineno)
        _expression_line(node, "'2.0' if gpu else '1.0'")
        _expression_line(node, "event.timestamp if gpu else None")
        for expression in (
            "{item.sha256: item for item in final_registry.records} != expected_records",
            "final_registry.count != locked_registry.count + records_needed",
            "final_ledger != committed_ledger", "record.sha256 != prospective_sha256",
        ):
            self.assertGreater(_expression_line(node, expression), put.lineno)

    def test_native_readback_full_source_and_event_rebuild_precede_final_snapshot(self):
        # No fake requirement is supplied: these are actual owner-call and
        # exact-comparison AST checks in addition to the real refusal above.
        selector = _function(compute._require_compute_terminal_assessment)
        native = _calls(selector, "_require_gpu_compute_terminal_assessment")[0]
        schema = _expression_line(selector, "value.get('schema_version') == GPU_COMPUTE_TERMINAL_ASSESSMENT_SCHEMA")
        self.assertLess(schema, native.lineno)
        self.assertGreater(_expression_line(selector,
            "_locked_resource_registry_ledger_snapshot(registry, ledger, expected_ledger_run_id) != (entry_registry, entry_ledger)"),
            native.lineno)
        node = _function(compute._require_gpu_compute_terminal_assessment)
        owner = _calls(node, "_derive_gpu_compute_sources")[0]
        parse = _calls(node, "from_mapping")[0]
        event = _calls(node, "_validate_compute_assessment_event")[0]
        rebuilt = _calls(node, "_assessment_from_event")[0]
        final = _calls(node, "_locked_resource_registry_ledger_snapshot")[-1]
        self.assertLess(parse.lineno, owner.lineno)
        self.assertLess(owner.lineno, event.lineno)
        self.assertLess(event.lineno, rebuilt.lineno)
        self.assertLess(rebuilt.lineno, final.lineno)
        self.assertLess(final.lineno, node.body[-1].lineno)
        for expression in (
            "record.schema_version != '2.0'", "record.mime_type != 'application/json'",
            "record.parent_artifacts != assessment.source_artifact_sha256s",
            "(sources.registry_snapshot, sources.ledger_snapshot) != entry",
            "len(matches) != 1", "thaw_json(binding) != expected_binding",
            "assessment != _assessment_from_event(assessment.assessment_id, sources, event, index)",
            "record.created_at != event.timestamp", "publications != (record,)",
            "_locked_resource_registry_ledger_snapshot(registry, ledger, expected_ledger_run_id) != entry",
        ):
            _expression_line(node, expression)


if __name__ == "__main__":
    unittest.main()
