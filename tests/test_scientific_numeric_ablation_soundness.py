"""Inert publication arithmetic and actual negative source boundaries only.

No scientific owner is replaced and no scientific receipt is issued. The
in-memory path/byte fixture is used only by the pure publication preflight;
its exact-match controls do not establish registrar idempotency or science.
"""

from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import inspect
from pathlib import PurePosixPath
from tempfile import TemporaryDirectory
import traceback
from types import SimpleNamespace
import unittest

from scientist_one import gates
from scientist_one.artifacts import (
    MAX_ARTIFACT_PARENTS, MAX_REGISTRY_RECORDS, ArtifactRegistry,
    RegistryValidationResult,
)
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from scientist_one import scientific_numeric_ablation_soundness as soundness
from scientist_one.scientific_numeric_ablation_cohort import (
    NATIVE_ABLATION_COVERAGE_RATIONALE, NATIVE_ABLATION_COVERAGE_RULE,
    ScientificNumericAblationCohort,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads
from tests.test_scientific_numeric_ablation_authority_value import _authority
from tests.test_scientific_numeric_ablation_cohort import _record, _state


def _receipt(**changes):
    values = dict(
        receipt_id="inert-native-ablation-dimension",
        dimension=gates.SoundnessDimension.ABLATIONS,
        status=gates.DimensionStatus.UNTESTED,
        authority_kind=gates.SoundnessAuthorityKind.DETERMINISTIC,
        authority_artifact_hash=f"{1:064x}",
        evidence_hashes=tuple(f"{index:064x}" for index in range(2, 5)),
        governing_rule=NATIVE_ABLATION_COVERAGE_RULE,
        rationale=NATIVE_ABLATION_COVERAGE_RATIONALE,
        reviewer_id="inert-reviewer",
    )
    return gates.SoundnessDimensionEvidenceReceipt(**{**values, **changes})


def _case(evidence_count=3):
    """Unregistered PENDING records and unissued DTOs for preflight only."""

    source = _record(1, "canonical_research_state_snapshot")
    evidence = tuple(_record(index, "inert_canonical_evidence")
                     for index in range(2, evidence_count + 2))
    receipt = _receipt(evidence_hashes=tuple(item.sha256 for item in evidence))
    cohort = ScientificNumericAblationCohort(
        state=_state(()), snapshot_record=source, members=(), ablation_authorities=(),
        evidence_hashes=receipt.evidence_hashes,
        evidence_record_hashes=tuple(item.record_hash for item in evidence),
        entry_snapshot=None,
    )
    return receipt, cohort, RegistryValidationResult(True, (source, *evidence))


class _InertPathsAndBytes:
    """No registry, persistence, verification, source admission, or authority."""

    def __init__(self, payloads=None):
        self.payloads = {} if payloads is None else dict(payloads)
        self.reads = []

    def _object_relative(self, digest):
        return PurePosixPath("inert/objects") / digest

    def _metadata_relative(self, digest):
        return PurePosixPath("inert/metadata") / (digest + ".json")

    def get_bytes(self, digest):
        self.reads.append(digest)
        return self.payloads[digest]


def _preflight(receipt, cohort, snapshot, *, paths=None, created_at="2026-09-06T00:00:01Z"):
    return soundness._preflight_dimension_publication(
        _InertPathsAndBytes() if paths is None else paths,
        snapshot, receipt, cohort, created_at=created_at,
    )


def _function(value):
    return ast.parse(inspect.getsource(value)).body[0]


def _calls(value, name):
    return tuple(node for node in ast.walk(_function(value))
                 if isinstance(node, ast.Call)
                 and ((isinstance(node.func, ast.Name) and node.func.id == name)
                      or (isinstance(node.func, ast.Attribute) and node.func.attr == name)))


class NumericAblationSoundnessTests(unittest.TestCase):
    def test_existing_wire_retains_exact_untested_operational_profile(self):
        receipt = _receipt()
        soundness.require_native_numeric_ablation_dimension_shape(receipt)
        wire = receipt.to_dict()
        self.assertEqual(set(wire), {
            "schema_version", "receipt_id", "dimension", "status", "authority_kind",
            "authority_artifact_hash", "evidence_hashes", "governing_rule", "rationale", "reviewer_id",
        })
        self.assertEqual(wire["schema_version"], "soundness-dimension-evidence-receipt/v2")
        self.assertEqual((wire["dimension"], wire["authority_kind"], wire["status"]),
                         ("ABLATIONS", "DETERMINISTIC", "UNTESTED"))
        self.assertEqual(gates.SoundnessDimensionEvidenceReceipt.from_dict(wire), receipt)
        self.assertEqual(wire["governing_rule"], NATIVE_ABLATION_COVERAGE_RULE)
        self.assertEqual(wire["rationale"], NATIVE_ABLATION_COVERAGE_RATIONALE)
        for key in wire:
            with self.subTest(missing=key), self.assertRaises(ValidationError):
                gates.SoundnessDimensionEvidenceReceipt.from_dict({k: v for k, v in wire.items() if k != key})
        with self.assertRaises(ValidationError):
            gates.SoundnessDimensionEvidenceReceipt.from_dict({**wire, "scientific_evidence_eligible": True})

    def test_shape_rejects_positive_failed_mixed_and_foreign_profiles(self):
        cases = (
            {"status": gates.DimensionStatus.PASS},
            {"status": gates.DimensionStatus.FAIL},
            {"dimension": gates.SoundnessDimension.STATISTICS},
            {"authority_kind": gates.SoundnessAuthorityKind.NOT_EXECUTED, "authority_artifact_hash": None},
            {"authority_kind": gates.SoundnessAuthorityKind.SEMANTIC, "status": gates.DimensionStatus.PASS},
            {"governing_rule": "Treat operational coverage as mechanistic adequacy."},
            {"rationale": "All scientific ablation questions are answered."},
        )
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValidationError):
                soundness.require_native_numeric_ablation_dimension_shape(_receipt(**change))
        class ForeignReceipt(gates.SoundnessDimensionEvidenceReceipt):
            pass
        for value in (SimpleNamespace(), ForeignReceipt(**{
            key: getattr(_receipt(), key) for key in _receipt().__dataclass_fields__
        })):
            with self.subTest(kind=type(value)), self.assertRaisesRegex(ValidationError, "exact existing receipt"):
                soundness.require_native_numeric_ablation_dimension_shape(value)

    def test_exact_evidence_order_parent_capacity_and_no_self_parent(self):
        receipt, cohort, snapshot = _case(255)
        raw, existing, planned = _preflight(receipt, cohort, snapshot)
        self.assertIsNone(existing)
        self.assertEqual(MAX_ARTIFACT_PARENTS, 256)
        self.assertEqual(len(planned.parent_artifacts), MAX_ARTIFACT_PARENTS)
        self.assertEqual(planned.parent_artifacts, (receipt.authority_artifact_hash, *receipt.evidence_hashes))
        self.assertLess(len(raw), 4 * 1024 * 1024)
        self.assertEqual(safe_json_loads(raw, max_bytes=4 * 1024 * 1024, max_items=50_000), receipt.to_dict())
        for hashes in (receipt.evidence_hashes[::-1], receipt.evidence_hashes + (f"{257:064x}",),
                       receipt.evidence_hashes + receipt.evidence_hashes[:1], (),
                       (receipt.authority_artifact_hash,), list(receipt.evidence_hashes)):
            with self.subTest(length=len(hashes)), self.assertRaises(ValidationError):
                soundness.require_native_numeric_ablation_dimension_shape(_receipt(evidence_hashes=hashes))

    def test_preflight_exact_wire_short_metadata_and_sources_without_publication(self):
        receipt, cohort, snapshot = _case()
        paths = _InertPathsAndBytes()
        raw, existing, planned = _preflight(receipt, cohort, snapshot, paths=paths)
        self.assertEqual(raw, canonical_json_bytes(receipt.to_dict()) + b"\n")
        self.assertEqual(planned.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(planned.size, len(raw))
        self.assertIsNone(existing)
        self.assertEqual(paths.reads, [])
        self.assertEqual(planned.logical_type, gates.SOUNDNESS_DIMENSION_RECEIPT_LOGICAL_TYPE)
        self.assertEqual(planned.schema_version, "2.0")
        self.assertEqual(planned.mime_type, "application/json")
        self.assertEqual(planned.creator_role, Role.SCIENTIFIC_REVIEWER)
        self.assertEqual(planned.origin, "registry-bound per-dimension scientific soundness review")
        self.assertEqual(planned.creation_command, ("scientist-one", "record-soundness-dimension"))
        self.assertEqual(planned.parent_artifacts, tuple(item.sha256 for item in snapshot.records))
        self.assertTrue(all(item.validation_result == "PENDING" and not item.frozen for item in snapshot.records))

    def test_preflight_retains_zero_negative_and_reversed_descriptive_values(self):
        receipt, cohort, snapshot = _case()
        baseline = _preflight(receipt, cohort, snapshot)
        for total in (0, 4, 6):
            observation = _authority(ablated_correct_total=total)
            self.assertFalse(observation.scientific_evidence_eligible)
            changed = replace(cohort, ablation_authorities=(observation,))
            self.assertEqual(_preflight(receipt, changed, snapshot), baseline)
        # This is outcome-neutral preflight arithmetic, not completeness replay.
        self.assertEqual(safe_json_loads(baseline[0])["status"], "UNTESTED")

    def test_preflight_requires_exact_cohort_snapshot_evidence_and_record_mapping(self):
        receipt, cohort, snapshot = _case()
        for changed in (
            SimpleNamespace(), replace(cohort, snapshot_record=_record(50, "canonical_research_state_snapshot")),
            replace(cohort, evidence_hashes=cohort.evidence_hashes[:-1]),
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValidationError, "complete owned cohort"):
                _preflight(receipt, changed, snapshot)
        for index in range(len(snapshot.records)):
            missing = replace(snapshot, records=snapshot.records[:index] + snapshot.records[index + 1:])
            changed_record = replace(snapshot.records[index], origin="another inert source", record_hash=None)
            changed = replace(snapshot, records=tuple(
                changed_record if i == index else item for i, item in enumerate(snapshot.records)))
            for malformed in (missing, changed):
                with self.subTest(index=index), self.assertRaisesRegex(ValidationError, "sources changed or postdate"):
                    _preflight(receipt, cohort, malformed)
        with self.assertRaises(ValueError):
            _preflight(receipt, replace(cohort, evidence_record_hashes=cohort.evidence_record_hashes[:-1]), snapshot)

    def test_preflight_exact_utc_chronology_including_equal_and_recovered_time(self):
        receipt, cohort, snapshot = _case()
        for timestamp in ("2026-09-06T00:00:00Z", "2026-09-06T00:00:00.000000Z", "2026-09-06T00:00:01Z"):
            raw, _, record = _preflight(receipt, cohort, snapshot, created_at=timestamp)
            paths = _InertPathsAndBytes({record.sha256: raw})
            recovered = replace(snapshot, records=(*snapshot.records, record))
            self.assertEqual(_preflight(receipt, cohort, recovered, paths=paths,
                                        created_at="2099-01-01T00:00:00Z"), (raw, record, record))
        for timestamp in ("2026-09-05T23:59:59.999999Z", "2026-09-06T00:00:00+00:00",
                          "2026-09-06T00:00:00", "not-a-timeZ"):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValidationError):
                _preflight(receipt, cohort, snapshot, created_at=timestamp)
        raw, _, record = _preflight(receipt, cohort, snapshot)
        backdated = replace(record, created_at="2026-09-05T23:59:59Z", record_hash=None)
        with self.assertRaisesRegex(ValidationError, "sources changed or postdate"):
            _preflight(receipt, cohort, replace(snapshot, records=(*snapshot.records, backdated)),
                       paths=_InertPathsAndBytes({record.sha256: raw}), created_at="2099-01-01T00:00:00Z")

    def test_preflight_exact_existing_bytes_and_each_immutable_metadata_field(self):
        receipt, cohort, snapshot = _case()
        raw, _, record = _preflight(receipt, cohort, snapshot)
        exact = replace(snapshot, records=(*snapshot.records, record))
        paths = _InertPathsAndBytes({record.sha256: raw})
        self.assertEqual(_preflight(receipt, cohort, exact, paths=paths), (raw, record, record))
        self.assertEqual(paths.reads, [record.sha256])
        for changes in (
            {"logical_type": "inert_other"}, {"schema_version": "1.0"}, {"mime_type": "text/plain"},
            {"size": record.size + 1}, {"origin": "inert changed origin"},
            {"creator_role": Role.ORCHESTRATOR}, {"creation_command": ("inert", "another")},
            {"parent_artifacts": record.parent_artifacts[:-1]},
            {"parent_artifacts": record.parent_artifacts[::-1]},
            {"parent_artifacts": (*record.parent_artifacts, f"{99:064x}")},
            {"validation_result": "PENDING", "frozen": False}, {"frozen": False},
            {"path": "other/object", "relative_path": "other/object"}, {"metadata_path": "other/metadata"},
        ):
            conflicting = replace(record, **changes, record_hash=None)
            with self.subTest(changes=changes), self.assertRaisesRegex(ValidationError, "different bytes or metadata"):
                _preflight(receipt, cohort, replace(snapshot, records=(*snapshot.records, conflicting)), paths=paths)
        for changed in (raw[:-1], raw + b"\n", raw + b" ", b"{}\n"):
            with self.subTest(raw=changed[:40]), self.assertRaisesRegex(ValidationError, "different bytes or metadata"):
                _preflight(receipt, cohort, exact, paths=_InertPathsAndBytes({record.sha256: changed}))

    def test_registry_count_preflight_preserves_full_capacity_only_for_exact_existing(self):
        receipt, cohort, snapshot = _case()
        raw, _, record = _preflight(receipt, cohort, snapshot)
        fillers = tuple(_record(index, "inert_count_only")
                        for index in range(100, 100 + MAX_REGISTRY_RECORDS - len(snapshot.records)))
        one_free = replace(snapshot, records=(*snapshot.records, *fillers[:-1]))
        self.assertEqual(_preflight(receipt, cohort, one_free)[2], record)
        full = replace(snapshot, records=(*snapshot.records, *fillers))
        self.assertEqual(full.count, MAX_REGISTRY_RECORDS)
        with self.assertRaisesRegex(ValidationError, "registry capacity"):
            _preflight(receipt, cohort, full)
        existing_full = replace(one_free, records=(*one_free.records, record))
        self.assertEqual(existing_full.count, MAX_REGISTRY_RECORDS)
        self.assertEqual(_preflight(receipt, cohort, existing_full,
                                   paths=_InertPathsAndBytes({record.sha256: raw})), (raw, record, record))

    def test_discriminator_is_only_family_routing_and_grants_no_authority(self):
        with TemporaryDirectory(prefix="numeric-dimension-routing-") as directory:
            registry = ArtifactRegistry(directory, "runs/inert-run/registry")
            ledger = EventLedger(directory, "runs/inert-run/events.jsonl")
            with self.assertRaisesRegex(ValidationError, "authority is absent"):
                soundness.is_native_numeric_ablation_dimension(registry, _receipt())
            for logical_type in ("canonical_research_state_snapshot", "canonical_research_state_final_snapshot", "inert_other"):
                record = registry.put_json(
                    {"inert": logical_type}, logical_type=logical_type,
                    origin="non-evidentiary routing fixture", creator_role=Role.ORCHESTRATOR,
                    creation_command=("test", "inert-routing"), parent_artifacts=(), schema_version="1.0",
                    mime_type="application/json", validation_result="PENDING", frozen=False,
                )
                receipt = _receipt(authority_artifact_hash=record.sha256)
                selected = logical_type != "inert_other"
                self.assertEqual(soundness.is_native_numeric_ablation_dimension(registry, receipt), selected)
                self.assertFalse(soundness.is_native_numeric_ablation_dimension(
                    registry, replace(receipt, dimension=gates.SoundnessDimension.STATISTICS)))
                if selected:
                    before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
                    with self.assertRaises((ArtifactError, ValidationError)):
                        gates.register_soundness_dimension_receipt(registry, receipt, ledger=ledger, run_id="inert-run")
                    self.assertEqual((registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)), before)

    def test_real_missing_source_registrar_and_record_reader_refuse_without_delta(self):
        with TemporaryDirectory(prefix="numeric-dimension-refusal-") as directory:
            registry = ArtifactRegistry(directory, "runs/inert-run/registry")
            ledger = EventLedger(directory, "runs/inert-run/events.jsonl")
            receipt = _receipt()
            before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
            operations = (
                lambda: soundness.register_native_numeric_ablation_dimension(registry, ledger, receipt, run_id="inert-run"),
                lambda: soundness.require_native_numeric_ablation_dimension_record(
                    registry, ledger, receipt, _record(99, "inert_unissued_dimension"), run_id="inert-run"),
                lambda: gates.register_soundness_dimension_receipt(registry, receipt, ledger=ledger, run_id="inert-run"),
                lambda: gates._load_soundness_dimension_receipt(registry, "f" * 64, ledger=ledger, run_id="inert-run"),
            )
            for index, operation in enumerate(operations):
                try:
                    operation()
                except (ArtifactError, ValidationError) as exc:
                    if index < 2:
                        frames = {item.name for item in traceback.extract_tb(exc.__traceback__)}
                        self.assertIn("require_scientific_numeric_ablation_cohort", frames)
                        self.assertIn("_read_canonical_research_state_snapshot", frames)
                else:
                    self.fail("unissued source was accepted")
                self.assertEqual((registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)), before)

    def test_registrar_full_owner_preflight_registry_first_cas_and_readback_order(self):
        owner = soundness.register_native_numeric_ablation_dimension
        source = inspect.getsource(owner)

        def line(name):
            return _calls(owner, name)[0].lineno

        self.assertLess(line("require_native_numeric_ablation_dimension_shape"), line("require_scientific_numeric_ablation_cohort"))
        self.assertLess(line("require_scientific_numeric_ablation_cohort"), line("_preflight_dimension_publication"))
        self.assertLess(line("_preflight_dimension_publication"), line("_open_mutation_lock"))
        self.assertLess(line("_open_mutation_lock"), line("_open_lock"))
        self.assertLess(line("_verify_all_locked"), line("_put_bytes_locked"))
        self.assertLess(line("_put_bytes_locked"), line("_load_soundness_dimension_receipt"))
        owner_call = _calls(owner, "require_scientific_numeric_ablation_cohort")[0]
        self.assertIs(next(item.value.value for item in owner_call.keywords if item.arg == "require_whole_current"), True)
        self.assertEqual(len(_calls(owner, "_put_bytes_locked")), 1)
        self.assertEqual(len(_calls(owner, "_locked_checked_result_authority_snapshot")), 2)
        for expression in (
            "cohort.entry_snapshot != before", "(locked_registry, locked_ledger) != before",
            "not locked_ledger.valid", "record != planned", "after_ledger != before[1]",
            "after_registry.count != before[0].count + int(existing is None)",
            "{item.sha256: item for item in after_registry.records} != expected_records",
        ):
            self.assertIn(expression, source)
        self.assertGreater(_calls(owner, "_locked_checked_result_authority_snapshot")[-1].lineno,
                           line("_load_soundness_dimension_receipt"))
        self.assertIn("if record is None:", source)
        self.assertNotIn("ledger.append", source)
        self.assertEqual(tuple(inspect.signature(owner).parameters), ("registry", "ledger", "receipt", "run_id"))

    def test_record_reader_replays_full_bound_sources_and_exact_publication_before_return(self):
        owner = soundness.require_native_numeric_ablation_dimension_record
        calls = _calls(owner, "require_scientific_numeric_ablation_cohort")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("require_whole_current", {item.arg for item in calls[0].keywords})
        self.assertLess(calls[0].lineno, _calls(owner, "_preflight_dimension_publication")[0].lineno)
        self.assertEqual(len(_calls(owner, "_locked_checked_result_authority_snapshot")), 2)
        source = inspect.getsource(owner)
        for expression in ("cohort.entry_snapshot != before", "existing != record", "planned != record"):
            self.assertIn(expression, source)
        for forbidden in ("_put_bytes_locked", "put_json", "ledger.append", "replay_peers"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(tuple(inspect.signature(owner).parameters), ("registry", "ledger", "receipt", "record", "run_id"))

    def test_pure_preflight_bounds_and_existing_public_routes_keep_full_native_owner(self):
        parser = _calls(soundness._preflight_dimension_publication, "safe_json_loads")
        self.assertEqual(len(parser), 1)
        self.assertEqual(ast.unparse(next(item.value for item in parser[0].keywords if item.arg == "max_bytes")), "_MAX_BYTES")
        self.assertEqual(next(item.value.value for item in parser[0].keywords if item.arg == "max_items"), 50_000)
        self.assertEqual(soundness._MAX_BYTES, 4 * 1024 * 1024)
        for owner, native in (
            (gates.register_soundness_dimension_receipt, "register_native_numeric_ablation_dimension"),
            (gates._load_soundness_dimension_receipt, "require_native_numeric_ablation_dimension_record"),
        ):
            self.assertEqual(len(_calls(owner, native)), 1)
            self.assertLess(_calls(owner, "is_native_numeric_ablation_dimension")[0].lineno,
                            _calls(owner, native)[0].lineno)
            self.assertLess(_calls(owner, native)[0].lineno,
                            _calls(owner, "_resolve_soundness_dimension_authority")[0].lineno)


if __name__ == "__main__":
    unittest.main()
