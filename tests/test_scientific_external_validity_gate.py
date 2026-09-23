"""Inert external-inventory shapes/preflight and real source refusals only.

No source owner is replaced, no execution/review is positively published, and
no scientific external validity is asserted. The in-memory path/byte fixture
exercises pure preflight equality, not successful owner/registrar recovery.
"""

from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import inspect
from tempfile import TemporaryDirectory
import traceback
from types import SimpleNamespace
import unittest

from scientist_one import gates
from scientist_one.artifacts import (
    MAX_ARTIFACT_PARENTS, MAX_REGISTRY_RECORDS, ArtifactRecord, ArtifactRegistry,
    RegistryValidationResult,
)
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from scientist_one import scientific_external_validity as boundary_source
from scientist_one import scientific_external_validity_gate as gate
from scientist_one.security import canonical_json_bytes, safe_json_loads
from tests.test_scientific_numeric_ablation_soundness import _InertPathsAndBytes


def _h(number):
    return f"{number:064x}"


def _execution(**changes):
    values = dict(
        receipt_id="inert-external-execution", review_id="inert-external-review", run_id="inert-run",
        category=gates.ChallengeCategory.EXTERNAL_VALIDITY,
        claim_graph_artifact_hash=_h(1), target_claim_ids=("claim-a", "claim-b"),
        # S has its own fixed first position; only the domain suffix is sorted.
        evidence_hashes=(_h(1000), _h(10), _h(11)),
        executor_kind=gates.ChallengerExecutorKind.DETERMINISTIC,
        executor_id="inert-executor", executor_role=Role.ADVERSARIAL_REVIEWER,
        procedure_id=boundary_source.SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_ID,
        procedure_version=boundary_source.SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_VERSION,
        result_artifact_hashes=(_h(20), _h(21)), finding_artifact_hashes=(),
        completed=True, semantic_judgment_hash=None,
    )
    return gates.ChallengerAttackExecutionReceipt(**{**values, **changes})


def _wire(value):
    return canonical_json_bytes(value.to_dict()) + b"\n"


def _review(execution=None, **changes):
    execution = _execution() if execution is None else execution
    values = dict(
        review_id=execution.review_id, category=execution.category,
        execution_status=gates.ChallengerExecutionStatus.EXECUTED,
        target_claim_ids=execution.target_claim_ids,
        claim_graph_artifact_hash=execution.claim_graph_artifact_hash,
        evidence_hashes=execution.evidence_hashes, finding_artifact_hashes=(),
        execution_receipt_hash=hashlib.sha256(_wire(execution)).hexdigest(),
        attack=boundary_source.SCIENTIFIC_EXTERNAL_VALIDITY_ATTACK,
        conclusion=boundary_source.SCIENTIFIC_EXTERNAL_VALIDITY_CONCLUSION,
        deterministic=True,
    )
    return gates.ChallengerCategoryReview(**{**values, **changes})


def _source_record(digest, *, created_at="2026-09-06T00:00:00Z"):
    """Actual native, unregistered PENDING metadata; not scientific authority."""
    return ArtifactRecord(
        sha256=digest, path=f"inert/source/{digest}", relative_path=f"inert/source/{digest}",
        metadata_path=f"inert/source-metadata/{digest}.json",
        logical_type="external_inventory_inert_source", schema_version="1.0", mime_type="application/json",
        size=1, origin="non-evidentiary external inventory preflight fixture",
        creator_role=Role.ORCHESTRATOR, creation_command=("test", "inert-external-inventory"),
        parent_artifacts=(), validation_result="PENDING", frozen=False, created_at=created_at,
    )


def _snapshot(receipt, *, review):
    parents = (receipt.claim_graph_artifact_hash, *receipt.evidence_hashes,
               *((receipt.execution_receipt_hash,) if review else receipt.result_artifact_hashes))
    return RegistryValidationResult(True, tuple(_source_record(digest) for digest in parents))


def _preflight(receipt, snapshot, *, review=False, paths=None, created_at="2026-09-06T00:00:01Z"):
    return gate._preflight_publication(
        _InertPathsAndBytes() if paths is None else paths, snapshot, receipt,
        review=review, created_at=created_at,
    )


def _function(value):
    return ast.parse(inspect.getsource(value)).body[0]


def _calls(value, name):
    return tuple(node for node in ast.walk(_function(value)) if isinstance(node, ast.Call)
                 and ((isinstance(node.func, ast.Name) and node.func.id == name)
                      or (isinstance(node.func, ast.Attribute) and node.func.attr == name)))


class ScientificExternalValidityGateTests(unittest.TestCase):
    def test_fixed_execution_review_shapes_keep_old_wires_and_untested_conclusion(self):
        execution = _execution()
        review = _review(execution)
        gate._require_execution_shape(execution)
        gate._require_review_shape(review, execution)
        self.assertTrue(gate.is_scientific_external_validity_execution(execution))
        self.assertEqual((execution.procedure_id, execution.procedure_version),
                         ("external-validity-boundary-audit", "2.0"))
        self.assertEqual(review.attack,
                         "Replay the complete canonical Result and StatisticalTest cohort against "
                         "source-owned domain evidence and frozen generalization scope.")
        self.assertEqual(review.conclusion,
                         "Deterministic source and scope inventory completed. External scientific "
                         "validity and generalization adequacy remain UNTESTED.")
        self.assertEqual(execution.finding_artifact_hashes, ())
        self.assertEqual(review.finding_artifact_hashes, ())
        self.assertEqual(execution.to_dict()["schema_version"], "challenger-attack-execution-receipt/v2")
        self.assertEqual(review.to_dict()["schema_version"], "challenger-category-review/v3")
        self.assertEqual(gates.ChallengerAttackExecutionReceipt.from_dict(safe_json_loads(_wire(execution))), execution)
        self.assertEqual(gates.ChallengerCategoryReview.from_dict(safe_json_loads(_wire(review))), review)
        self.assertNotIn("scientific_evidence_eligible", review.to_dict())

    def test_exact_execution_profile_rejects_old_wrong_semantic_and_incomplete_shapes(self):
        for change in (
            {"procedure_version": "1.0"}, {"procedure_id": "another-procedure"},
            {"category": gates.ChallengeCategory.STATISTICS},
            {"executor_kind": gates.ChallengerExecutorKind.SEMANTIC, "semantic_judgment_hash": _h(80)},
            {"finding_artifact_hashes": (_h(81),)}, {"completed": False}, {"completed": 1},
            {"executor_role": Role.SCIENTIFIC_REVIEWER},
        ):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                gate._require_execution_shape(_execution(**change))
        class ForeignExecution(gates.ChallengerAttackExecutionReceipt):
            pass
        original = _execution()
        foreign = ForeignExecution(**{key: getattr(original, key) for key in original.__dataclass_fields__})
        for value in (SimpleNamespace(), foreign):
            with self.subTest(kind=type(value)), self.assertRaisesRegex(ValidationError, "exact execution receipt"):
                gate._require_execution_shape(value)

    def test_evidence_suffix_results_and_claims_are_sorted_nonempty_and_disjoint(self):
        execution = _execution()
        self.assertNotEqual(execution.evidence_hashes, tuple(sorted(execution.evidence_hashes)))
        gate._require_execution_shape(execution)
        for change in (
            {"evidence_hashes": ()}, {"evidence_hashes": (_h(1000),)},
            {"evidence_hashes": (_h(1000), _h(11), _h(10))},
            {"evidence_hashes": (_h(1000), _h(10), _h(10))},
            {"evidence_hashes": (_h(1000), execution.claim_graph_artifact_hash)},
            {"evidence_hashes": list(execution.evidence_hashes)},
            {"result_artifact_hashes": ()}, {"result_artifact_hashes": (_h(21), _h(20))},
            {"result_artifact_hashes": (_h(20), _h(20))},
            {"result_artifact_hashes": (_h(10), _h(20))},
            {"result_artifact_hashes": list(execution.result_artifact_hashes)},
            {"target_claim_ids": ()}, {"target_claim_ids": ("claim-b", "claim-a")},
            {"target_claim_ids": ("claim-a", "claim-a")},
        ):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                gate._require_execution_shape(_execution(**change))

    def test_review_requires_exact_execution_identity_hash_sources_and_fixed_prose(self):
        execution = _execution()
        for change in (
            {"review_id": "another-review"}, {"category": gates.ChallengeCategory.STATISTICS},
            {"target_claim_ids": ("claim-a",)}, {"claim_graph_artifact_hash": _h(90)},
            {"evidence_hashes": execution.evidence_hashes[:-1]}, {"finding_artifact_hashes": (_h(91),)},
            {"execution_receipt_hash": _h(92)},
            {"execution_receipt_hash": hashlib.sha256(_wire(execution)[:-1]).hexdigest()},
            {"attack": "External accuracy was measured."}, {"conclusion": "Scientific adequacy PASS."},
            {"deterministic": False},
            {"execution_status": gates.ChallengerExecutionStatus.UNTESTED,
             "execution_receipt_hash": None, "deterministic": False},
        ):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                gate._require_review_shape(_review(execution, **change), execution)
        with self.assertRaisesRegex(ValidationError, "exact category review"):
            gate._require_review_shape(SimpleNamespace(), execution)
        # A changed execution ID changes its body hash even when scientific
        # selectors are unchanged; no old review can silently point at it.
        with self.assertRaises(ValidationError):
            gate._require_review_shape(_review(execution), replace(execution, receipt_id="another-execution"))

    def test_full_execution_parent_capacity_and_review_capacity_are_not_truncated(self):
        self.assertEqual(MAX_ARTIFACT_PARENTS, 256)
        execution = _execution(evidence_hashes=(_h(1000), *tuple(_h(i) for i in range(10, 262))),
                               result_artifact_hashes=(_h(2000), _h(2001)))
        gate._require_execution_shape(execution)
        self.assertEqual(len(gate._execution_parents(execution)), 256)
        raw, _, planned = _preflight(execution, _snapshot(execution, review=False))
        self.assertEqual(len(planned.parent_artifacts), 256)
        self.assertEqual(planned.size, len(raw))
        with self.assertRaisesRegex(ValidationError, "parent capacity"):
            gate._require_execution_shape(replace(execution, result_artifact_hashes=(*execution.result_artifact_hashes, _h(2002))))
        review_execution = _execution(
            evidence_hashes=(*execution.evidence_hashes, _h(2003)),
            result_artifact_hashes=(_h(2000),),
        )
        review = _review(review_execution)
        gate._require_review_shape(review, review_execution)
        snapshot = _snapshot(review, review=True)
        self.assertEqual(len(_preflight(review, snapshot, review=True)[2].parent_artifacts), 256)
        too_many = replace(review, evidence_hashes=(*review.evidence_hashes, _h(2004)))
        with self.assertRaisesRegex(ValidationError, "parent capacity"):
            _preflight(too_many, snapshot, review=True)

    def test_both_publication_formats_have_exact_canonical_bytes_and_native_metadata(self):
        for is_review in (False, True):
            receipt = _review() if is_review else _execution()
            snapshot = _snapshot(receipt, review=is_review)
            paths = _InertPathsAndBytes()
            raw, existing, record = _preflight(receipt, snapshot, review=is_review, paths=paths)
            self.assertEqual(raw, _wire(receipt))
            self.assertEqual(record.sha256, hashlib.sha256(raw).hexdigest())
            self.assertIs(type(record), ArtifactRecord)
            self.assertIsNone(existing)
            self.assertEqual(paths.reads, [])
            self.assertEqual(record.size, len(raw))
            self.assertEqual(record.mime_type, "application/json")
            self.assertIs(record.creator_role, Role.ADVERSARIAL_REVIEWER)
            self.assertEqual(record.parent_artifacts, tuple(item.sha256 for item in snapshot.records))
            self.assertEqual((record.logical_type, record.schema_version),
                             (gates.CHALLENGER_CATEGORY_REVIEW_LOGICAL_TYPE, "3.0") if is_review else
                             (gates.CHALLENGER_ATTACK_EXECUTION_LOGICAL_TYPE, "2.0"))
            self.assertEqual(record.origin, "exact typed Challenger attack-category checklist entry" if is_review else
                             "registry-replayed exact Challenger attack execution")
            self.assertEqual(record.creation_command, ("scientist-one", "record-challenger-category-review") if is_review else
                             ("scientist-one", "record-challenger-execution"))
            self.assertTrue(all(item.validation_result == "PENDING" and not item.frozen for item in snapshot.records))
            self.assertEqual(safe_json_loads(raw, max_bytes=gates.MAX_GATE_RECEIPT_BYTES, max_items=50_000), receipt.to_dict())

    def test_preflight_rejects_every_missing_parent_and_future_parent(self):
        for is_review in (False, True):
            receipt = _review() if is_review else _execution()
            snapshot = _snapshot(receipt, review=is_review)
            for index in range(snapshot.count):
                missing = replace(snapshot, records=snapshot.records[:index] + snapshot.records[index + 1:])
                future = replace(snapshot.records[index], created_at="2099-01-01T00:00:00Z", record_hash=None)
                changed = replace(snapshot, records=tuple(future if i == index else item
                                                        for i, item in enumerate(snapshot.records)))
                for candidate in (missing, changed):
                    with self.subTest(review=is_review, index=index), self.assertRaisesRegex(ValidationError, "absent or postdate"):
                        _preflight(receipt, candidate, review=is_review)

    def test_preflight_exact_time_and_existing_timestamp_cannot_launder_backdating(self):
        for is_review in (False, True):
            receipt = _review() if is_review else _execution()
            snapshot = _snapshot(receipt, review=is_review)
            for timestamp in ("2026-09-06T00:00:00Z", "2026-09-06T00:00:00.000000Z", "2026-09-06T00:00:01Z"):
                raw, _, record = _preflight(receipt, snapshot, review=is_review, created_at=timestamp)
                existing = replace(snapshot, records=(*snapshot.records, record))
                paths = _InertPathsAndBytes({record.sha256: raw})
                self.assertEqual(_preflight(receipt, existing, review=is_review, paths=paths,
                                            created_at="2099-01-01T00:00:00Z"), (raw, record, record))
            for timestamp in ("2026-09-05T23:59:59.999999Z", "2026-09-06T00:00:00+00:00", "2026-09-06T00:00:00", "invalidZ"):
                with self.subTest(review=is_review, timestamp=timestamp), self.assertRaises(ValidationError):
                    _preflight(receipt, snapshot, review=is_review, created_at=timestamp)
            raw, _, record = _preflight(receipt, snapshot, review=is_review)
            backdated = replace(record, created_at="2026-09-05T23:59:59Z", record_hash=None)
            with self.assertRaisesRegex(ValidationError, "absent or postdate"):
                _preflight(receipt, replace(snapshot, records=(*snapshot.records, backdated)), review=is_review,
                           paths=_InertPathsAndBytes({record.sha256: raw}), created_at="2099-01-01T00:00:00Z")

    def test_preflight_existing_record_requires_all_immutable_metadata_and_exact_bytes(self):
        for is_review in (False, True):
            receipt = _review() if is_review else _execution()
            snapshot = _snapshot(receipt, review=is_review)
            raw, _, record = _preflight(receipt, snapshot, review=is_review)
            paths = _InertPathsAndBytes({record.sha256: raw})
            for changes in (
                {"logical_type": "inert_other"}, {"schema_version": "1.0"}, {"mime_type": "text/plain"},
                {"size": record.size + 1}, {"origin": "inert another origin"},
                {"creator_role": Role.ORCHESTRATOR}, {"creation_command": ("test", "another")},
                {"parent_artifacts": record.parent_artifacts[:-1]}, {"parent_artifacts": record.parent_artifacts[::-1]},
                {"validation_result": "PENDING", "frozen": False}, {"frozen": False},
                {"path": "inert/other", "relative_path": "inert/other"}, {"metadata_path": "inert/other-meta"},
            ):
                changed = replace(record, **changes, record_hash=None)
                with self.subTest(review=is_review, changes=changes), self.assertRaisesRegex(ValidationError, "different bytes or metadata"):
                    _preflight(receipt, replace(snapshot, records=(*snapshot.records, changed)), review=is_review, paths=paths)
            existing = replace(snapshot, records=(*snapshot.records, record))
            self.assertEqual(_preflight(receipt, existing, review=is_review, paths=paths), (raw, record, record))
            for body in (raw[:-1], raw + b"\n", raw + b" ", b"{}\n"):
                with self.subTest(review=is_review, body=body[:30]), self.assertRaisesRegex(ValidationError, "different bytes or metadata"):
                    _preflight(receipt, existing, review=is_review, paths=_InertPathsAndBytes({record.sha256: body}))

    def test_registry_capacity_distinguishes_new_from_exact_existing_content(self):
        fillers = tuple(_source_record(_h(index)) for index in range(10_000, 10_000 + MAX_REGISTRY_RECORDS))
        for is_review in (False, True):
            receipt = _review() if is_review else _execution()
            snapshot = _snapshot(receipt, review=is_review)
            raw, _, record = _preflight(receipt, snapshot, review=is_review)
            one_free = replace(snapshot, records=(*snapshot.records, *fillers[:MAX_REGISTRY_RECORDS - snapshot.count - 1]))
            self.assertEqual(one_free.count, MAX_REGISTRY_RECORDS - 1)
            self.assertEqual(_preflight(receipt, one_free, review=is_review)[2], record)
            full = replace(one_free, records=(*one_free.records, fillers[-1]))
            with self.assertRaisesRegex(ValidationError, "registry capacity"):
                _preflight(receipt, full, review=is_review)
            existing = replace(one_free, records=(*one_free.records, record))
            self.assertEqual(_preflight(receipt, existing, review=is_review,
                                       paths=_InertPathsAndBytes({record.sha256: raw})), (raw, record, record))

    def test_real_missing_snapshot_execution_owners_refuse_with_zero_delta(self):
        with TemporaryDirectory(prefix="external-inventory-refusal-") as directory:
            registry = ArtifactRegistry(directory, "runs/inert-run/registry")
            ledger = EventLedger(directory, "runs/inert-run/events.jsonl")
            execution = _execution()
            before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
            for operation in (
                lambda: gate.require_scientific_external_validity_execution(registry, ledger, execution),
                lambda: gate.register_scientific_external_validity_execution(registry, ledger, execution),
                lambda: gate.require_scientific_external_validity_execution_record(
                    registry, ledger, execution, _source_record(_h(90))),
                lambda: gates.register_challenger_attack_execution_receipt(registry, execution, ledger=ledger),
            ):
                try:
                    operation()
                except (ArtifactError, ValidationError) as exc:
                    frames = {item.name for item in traceback.extract_tb(exc.__traceback__)}
                    self.assertIn("require_scientific_external_validity_boundary", frames)
                    self.assertIn("_read_canonical_research_state_snapshot", frames)
                else:
                    self.fail("missing scientific snapshot was accepted")
                self.assertEqual((registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)), before)

    def test_real_missing_execution_review_owners_refuse_with_zero_delta(self):
        with TemporaryDirectory(prefix="external-review-refusal-") as directory:
            registry = ArtifactRegistry(directory, "runs/inert-run/registry")
            ledger = EventLedger(directory, "runs/inert-run/events.jsonl")
            review = _review()
            before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
            for operation in (
                lambda: gate.register_scientific_external_validity_review(registry, ledger, review),
                lambda: gate.require_scientific_external_validity_review_record(
                    registry, ledger, review, _source_record(_h(91))),
            ):
                try:
                    operation()
                except (ArtifactError, ValidationError) as exc:
                    frames = {item.name for item in traceback.extract_tb(exc.__traceback__)}
                    self.assertIn("_load_challenger_attack_execution_receipt", frames)
                else:
                    self.fail("missing execution authority was accepted")
                self.assertEqual((registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)), before)

    def test_execution_full_owner_precedes_inventory_comparison_and_selected_S_is_exact(self):
        owner = gate.require_scientific_external_validity_execution
        source = inspect.getsource(owner)
        full = _calls(owner, "require_scientific_external_validity_boundary")
        self.assertEqual(len(full), 1)
        self.assertLess(_calls(owner, "_require_execution_shape")[0].lineno, full[0].lineno)
        keywords = {item.arg: ast.unparse(item.value) for item in full[0].keywords}
        self.assertEqual(keywords, {
            "expected_ledger_run_id": "receipt.run_id",
            "snapshot_artifact_sha256": "receipt.evidence_hashes[0]",
            "claim_graph_artifact_sha256": "receipt.claim_graph_artifact_hash",
            "central_claim_ids": "receipt.target_claim_ids", "require_whole_current": "require_whole_current",
        })
        self.assertIn("receipt.evidence_hashes != boundary.evidence_hashes", source)
        self.assertIn("receipt.result_artifact_hashes != tuple(sha for sha, _ in boundary.result_test_bindings)", source)
        self.assertLess(source.index("boundary = require_scientific_external_validity_boundary("),
                        source.index("receipt.evidence_hashes != boundary.evidence_hashes"))

    def test_registrars_require_whole_owner_before_private_publication_and_exact_readback(self):
        for owner, is_review, reader in (
            (gate.register_scientific_external_validity_execution, False, "_load_challenger_attack_execution_receipt"),
            (gate.register_scientific_external_validity_review, True, "_load_challenger_category_review"),
        ):
            full = _calls(owner, "require_scientific_external_validity_execution")[0]
            publish = _calls(owner, "_publish")[0]
            self.assertIs(next(item.value.value for item in full.keywords if item.arg == "require_whole_current"), True)
            self.assertLess(full.lineno, publish.lineno)
            self.assertIs(next(item.value.value for item in publish.keywords if item.arg == "review"), is_review)
            self.assertIn("boundary.entry_snapshot != before", inspect.getsource(owner))
            self.assertEqual(len(_calls(owner, reader)), 1)
            if is_review:
                self.assertLess(_calls(owner, "_load_challenger_attack_execution_receipt")[0].lineno,
                                _calls(owner, "_require_review_shape")[0].lineno)
                self.assertLess(_calls(owner, "_require_review_shape")[0].lineno, full.lineno)

    def test_private_publication_preflights_capacity_then_paired_cas_exact_delta_readback(self):
        owner = gate._publish
        source = inspect.getsource(owner)

        def line(name):
            return _calls(owner, name)[0].lineno

        self.assertLess(line("_preflight_publication"), line("_open_mutation_lock"))
        self.assertLess(line("_open_mutation_lock"), line("_open_lock"))
        self.assertLess(line("_verify_all_locked"), line("_put_bytes_locked"))
        self.assertLess(line("_put_bytes_locked"), line("readback"))
        self.assertLess(line("readback"), line("_locked_checked_result_authority_snapshot"))
        self.assertEqual(len(_calls(owner, "_put_bytes_locked")), 1)
        for expression in (
            "(locked_registry, locked_ledger) != before", "not locked_ledger.valid", "if record is None:",
            "record != planned", "after_registry.count != before[0].count + int(existing is None)",
            "{item.sha256: item for item in after_registry.records} != expected", "after_ledger != before[1]",
        ):
            self.assertIn(expression, source)
        self.assertNotIn("ledger.append", source)
        parser = _calls(gate._preflight_publication, "safe_json_loads")[0]
        keywords = {item.arg: ast.unparse(item.value) for item in parser.keywords}
        self.assertEqual(keywords, {"max_bytes": "MAX_GATE_RECEIPT_BYTES", "max_items": "50000"})
        self.assertEqual(gates.MAX_GATE_RECEIPT_BYTES, 256 * 1024)

    def test_record_readers_replay_full_bound_owner_and_same_preflight_with_final_snapshot(self):
        for owner, is_review in (
            (gate.require_scientific_external_validity_execution_record, False),
            (gate.require_scientific_external_validity_review_record, True),
        ):
            full = _calls(owner, "require_scientific_external_validity_execution")[0]
            self.assertNotIn("require_whole_current", {item.arg for item in full.keywords})
            preflight = _calls(owner, "_preflight_publication")[0]
            self.assertLess(full.lineno, preflight.lineno)
            self.assertIs(next(item.value.value for item in preflight.keywords if item.arg == "review"), is_review)
            snapshots = _calls(owner, "_locked_checked_result_authority_snapshot")
            self.assertEqual(len(snapshots), 2)
            self.assertGreater(snapshots[-1].lineno, preflight.lineno)
            source = inspect.getsource(owner)
            for expression in ("boundary.entry_snapshot != before", "existing != record", "planned != record"):
                self.assertIn(expression, source)
            for forbidden in ("_publish(", "put_json", "_put_bytes_locked", "replay_peers"):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
