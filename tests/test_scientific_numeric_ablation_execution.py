"""Bounded controls for the downstream native numeric-ablation replay.

The DTOs and records in this module are inert test values.  They do not stand
in for a scientific source owner, an execution authority, a signature, or a
positive scientific lifecycle.  The one integration boundary deliberately
uses the ordinary unpatched owner against a fixture with no execution
authority and requires refusal without a registry or ledger admission.
"""

from __future__ import annotations

import ast
import copy
import inspect
from dataclasses import replace
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from scientist_one.artifacts import ArtifactRecord
from scientist_one import execution_admissibility
from scientist_one.experiments import (
    COMPLETE_GENERIC_ML_ACTIVITY_PROFILE,
    AblationResult,
    ExperimentPhase,
    ExperimentError,
    FrozenRunSpec,
    OutputArtifact,
    OutputManifest,
    ScientificDatasetAccessPurpose,
    ScientificExecutionActivity,
    ScientificExecutionActivityKind,
    ScientificExecutionActivityRow,
    ScientificExecutionActivityTerminal,
    ScientificExecutionArtifactBinding,
    ScientificExecutionTerminalKind,
)
from scientist_one.generic_ml_ablation import GenericMLFeatureIntervention
from scientist_one.generic_ml_projection import GenericMLPairedMetricProjectionAuthority
from scientist_one.models import Role
from scientist_one.scientific_numeric_ablation import (
    GenericMLAblationPolicy,
    ScientificNumericAblationError,
)
from scientist_one.scientific_numeric_ablation_execution import (
    _records_once,
    _require_ablation_activity,
    _require_complete_inventory,
    _require_grid_projection_join,
    require_scientific_numeric_ablation_execution,
)
from tests.test_generic_ml_ablation_output import _grid, _row
from tests.test_scientific_method_alignment import _prepared_canonical_timeline


def _digest(index: int) -> str:
    return f"{index:064x}"


def _record(index: int) -> ArtifactRecord:
    path = f"numeric-execution/record-{index}.json"
    return ArtifactRecord(
        sha256=_digest(index),
        path=path,
        relative_path=path,
        metadata_path=f"{path}.metadata.json",
        logical_type="test_fixture",
        schema_version="1.0",
        mime_type="application/json",
        size=1,
        origin="non-evidentiary numeric execution fixture",
        creator_role=Role.EXPERIMENT_RUNNER,
        creation_command=("test", "numeric-execution"),
        parent_artifacts=(),
        validation_result="PASS",
        frozen=True,
        created_at="2024-01-01T00:00:00Z",
    )


def _records(count: int = 16) -> tuple[ArtifactRecord, ...]:
    return tuple(_record(index) for index in range(1, count + 1))


def _intervention(index: int) -> GenericMLFeatureIntervention:
    return GenericMLFeatureIntervention(
        ablation_id=f"ablation-{index}",
        hypothesis_id="hypothesis-primary",
        component_id=f"component-{index}",
        candidate_condition_id="experiment-primary",
        baseline_condition_id="baseline-strong",
        intervention_condition_id=f"experiment-primary-ablation-{index}",
        feature_indices=(0,),
    )


def _policy(count: int = 1) -> GenericMLAblationPolicy:
    return GenericMLAblationPolicy(
        method_id="method-primary",
        metric_id="accuracy",
        interventions=tuple(_intervention(index) for index in range(count)),
    )


def _spec(policy: GenericMLAblationPolicy, seeds: tuple[int, ...] = (7, 11)) -> FrozenRunSpec:
    return FrozenRunSpec(
        run_id="numeric-execution-run",
        experiment_id="experiment-primary",
        hypothesis_id="hypothesis-primary",
        phase=ExperimentPhase.EXPLORATORY,
        argv=("fixture.py",),
        working_directory=".",
        code_sha256=_digest(101),
        data_sha256=_digest(102),
        configuration_sha256=_digest(103),
        evaluator_sha256=_digest(104),
        seeds=seeds,
        required_ablations=tuple(item.ablation_id for item in policy.interventions),
    )


def _bare_projection(**values: object) -> GenericMLPairedMetricProjectionAuthority:
    projection = object.__new__(GenericMLPairedMetricProjectionAuthority)
    for name, value in values.items():
        object.__setattr__(projection, name, value)
    return projection


def _inventory_fixture() -> tuple[
    GenericMLAblationPolicy,
    FrozenRunSpec,
    OutputManifest,
    GenericMLPairedMetricProjectionAuthority,
]:
    policy = _policy(2)
    spec = _spec(policy)
    domain = tuple(_digest(200 + index) for index in range(4 * len(spec.seeds)))
    ablations = tuple(_digest(300 + index) for index in range(len(policy.interventions)))
    record_hashes = tuple(_digest(400 + index) for index in range(len(ablations)))
    artifacts = tuple(
        OutputArtifact(
            path=f"outputs/{index}.json",
            sha256=digest,
            size=1,
            logical_type="output",
        )
        for index, digest in enumerate((*domain, *ablations))
    )
    manifest = OutputManifest(
        run_id=spec.run_id,
        spec_sha256=_digest(401),
        code_sha256=_digest(402),
        data_sha256=_digest(403),
        configuration_sha256=_digest(404),
        evaluator_sha256=_digest(405),
        planned_seeds=spec.seeds,
        seed_results=(),
        artifacts=artifacts,
        ablations=tuple(
            AblationResult(item.ablation_id, digest)
            for item, digest in zip(policy.interventions, ablations, strict=True)
        ),
    )
    projection = _bare_projection(
        domain_consumed_output_artifact_sha256s=domain,
        ablation_output_artifact_sha256s=ablations,
        ablation_output_record_hashes=record_hashes,
    )
    return policy, spec, manifest, projection


def _binding(record: ArtifactRecord) -> ScientificExecutionArtifactBinding:
    return ScientificExecutionArtifactBinding(record.sha256, record.record_hash)


def _feature_row(
    sequence: int,
    dataset_record: ArtifactRecord,
    split_record: ArtifactRecord,
    *,
    purpose: ScientificDatasetAccessPurpose = ScientificDatasetAccessPurpose.CONFIRMATORY_FEATURES,
    seed: int | None = None,
    condition_id: str | None = None,
    ablation_id: str | None = None,
) -> ScientificExecutionActivityRow:
    return ScientificExecutionActivityRow(
        sequence=sequence,
        kind=ScientificExecutionActivityKind.DATASET_READ,
        seed=seed,
        condition_id=condition_id,
        ablation_id=ablation_id,
        input_artifact_bindings=(),
        output_artifact_bindings=(),
        dataset_artifact_binding=_binding(dataset_record),
        split_artifact_binding=_binding(split_record),
        dataset_access_purpose=purpose,
    )


def _producer_row(
    sequence: int,
    policy: GenericMLAblationPolicy,
    input_records: tuple[ArtifactRecord, ...],
    output_record: ArtifactRecord,
) -> ScientificExecutionActivityRow:
    intervention = policy.interventions[0]
    return ScientificExecutionActivityRow(
        sequence=sequence,
        kind=ScientificExecutionActivityKind.ABLATION_EXECUTION,
        seed=None,
        condition_id=intervention.intervention_condition_id,
        ablation_id=intervention.ablation_id,
        input_artifact_bindings=tuple(_binding(record) for record in input_records),
        output_artifact_bindings=(_binding(output_record),),
        dataset_artifact_binding=None,
        split_artifact_binding=None,
        dataset_access_purpose=None,
    )


def _activity_fixture(
    records: tuple[ArtifactRecord, ...],
    policy: GenericMLAblationPolicy,
    *,
    rows: tuple[ScientificExecutionActivityRow, ...] | None = None,
) -> ScientificExecutionActivity:
    dataset_record, split_record = records[:2]
    input_records = records[2:4]
    output_record = records[4]
    if rows is None:
        rows = (
            _feature_row(0, dataset_record, split_record),
            _feature_row(1, dataset_record, split_record),
            _producer_row(2, policy, input_records, output_record),
        )
    return ScientificExecutionActivity(
        activity_id="numeric-activity",
        ledger_run_id="numeric-ledger-run",
        execution_run_id="numeric-execution-run",
        preparation_artifact_sha256=records[5].sha256,
        preparation_record_hash=records[5].record_hash,
        frozen_run_spec_artifact_sha256=records[6].sha256,
        frozen_run_spec_record_hash=records[6].record_hash,
        output_manifest_artifact_sha256=records[7].sha256,
        output_manifest_record_hash=records[7].record_hash,
        capture_profile=COMPLETE_GENERIC_ML_ACTIVITY_PROFILE,
        activity_rows=rows,
        terminal=ScientificExecutionActivityTerminal(
            sequence=len(rows),
            kind=ScientificExecutionTerminalKind.ALL_PLANNED_WORK_COMPLETED,
            occurred_at="2024-01-01T00:00:00Z",
        ),
    )


def _grid_projection(grid):
    seed_projections = []
    for seed in grid.seed_results:
        seed_projections.append(
            SimpleNamespace(
                seed=seed.seed,
                paired_unit_ids=grid.unit_ids,
                paired_unit_hashes=grid.unit_hashes,
                reference_labels=grid.reference_labels,
                candidate_condition_id=grid.intervention.candidate_condition_id,
                baseline_condition_id=grid.intervention.baseline_condition_id,
                candidate_values=tuple(
                    float(value == label)
                    for value, label in zip(seed.candidate_predictions, grid.reference_labels, strict=True)
                ),
                baseline_values=tuple(
                    float(value == label)
                    for value, label in zip(seed.baseline_predictions, grid.reference_labels, strict=True)
                ),
            )
        )
    return _bare_projection(
        seed_order=grid.seed_order,
        paired_unit_ids=grid.unit_ids,
        paired_unit_hashes=grid.unit_hashes,
        reference_labels=grid.reference_labels,
        seed_projections=tuple(seed_projections),
    )


class NumericExecutionPureHelperTests(unittest.TestCase):
    def test_records_once_deduplicates_only_exact_native_records(self):
        records = _records(3)
        self.assertEqual(_records_once((records[0], records[1], records[0])), records[:2])
        self.assertEqual(_records_once(()), ())
        conflict = copy.copy(records[0])
        object.__setattr__(conflict, "record_hash", _digest(999))
        with self.assertRaisesRegex(ScientificNumericAblationError, "conflicting record identities"):
            _records_once((records[0], conflict))
        with self.assertRaises(ScientificNumericAblationError):
            _records_once([records[0]])

        class TupleSubclass(tuple):
            pass

        with self.assertRaises(ScientificNumericAblationError):
            _records_once(TupleSubclass((records[0],)))
        with self.assertRaises(ScientificNumericAblationError):
            _records_once((SimpleNamespace(sha256=records[0].sha256, record_hash=records[0].record_hash),))

    def test_complete_inventory_requires_exact_obligation_and_four_s_domain_partition(self):
        policy, spec, manifest, projection = _inventory_fixture()
        self.assertIsNone(_require_complete_inventory(policy, spec, manifest, projection))
        cases = (
            (
                "spec-order",
                replace(spec, required_ablations=("ablation-1", "ablation-0")),
            ),
            ("manifest-order", replace(manifest, ablations=manifest.ablations[::-1])),
            (
                "manifest-status",
                replace(
                    manifest,
                    ablations=(
                        replace(manifest.ablations[0], status="FAIL"),
                        manifest.ablations[1],
                    ),
                ),
            ),
            ("manifest-count", replace(manifest, artifacts=manifest.artifacts[:-1])),
            (
                "domain-count",
                _bare_projection(
                    domain_consumed_output_artifact_sha256s=(
                        projection.domain_consumed_output_artifact_sha256s[:-1]
                    ),
                    ablation_output_artifact_sha256s=projection.ablation_output_artifact_sha256s,
                    ablation_output_record_hashes=projection.ablation_output_record_hashes,
                ),
            ),
            (
                "duplicate-output",
                _bare_projection(
                    domain_consumed_output_artifact_sha256s=projection.domain_consumed_output_artifact_sha256s,
                    ablation_output_artifact_sha256s=(
                        projection.ablation_output_artifact_sha256s[0],
                        projection.domain_consumed_output_artifact_sha256s[0],
                    ),
                    ablation_output_record_hashes=projection.ablation_output_record_hashes,
                ),
            ),
            (
                "record-count",
                _bare_projection(
                    domain_consumed_output_artifact_sha256s=projection.domain_consumed_output_artifact_sha256s,
                    ablation_output_artifact_sha256s=projection.ablation_output_artifact_sha256s,
                    ablation_output_record_hashes=projection.ablation_output_record_hashes[:1],
                ),
            ),
        )
        for name, wrong in cases:
            candidate_spec = wrong if name == "spec-order" else spec
            candidate_manifest = wrong if name in {"manifest-order", "manifest-status", "manifest-count"} else manifest
            candidate_projection = wrong if name in {"domain-count", "duplicate-output", "record-count"} else projection
            with self.subTest(name=name), self.assertRaises(ScientificNumericAblationError):
                _require_complete_inventory(policy, candidate_spec, candidate_manifest, candidate_projection)

    def test_activity_requires_ordered_inputs_one_grid_producer_feature_reads_and_nulls(self):
        records = _records()
        policy = _policy()
        activity = _activity_fixture(records, policy)
        self.assertIsNone(activity.activity_rows[0].seed)
        self.assertIsNone(activity.activity_rows[0].condition_id)
        self.assertIsNone(activity.activity_rows[0].ablation_id)
        self.assertIsNone(activity.activity_rows[2].seed)
        self.assertIsNone(activity.activity_rows[2].dataset_artifact_binding)
        self.assertIsNone(activity.activity_rows[2].split_artifact_binding)
        self.assertIsNone(activity.activity_rows[2].dataset_access_purpose)
        self.assertEqual(
            _require_ablation_activity(
                activity,
                policy,
                input_records=records[2:4],
                output_records=(records[4],),
                dataset_record=records[0],
                confirmatory_split_record=records[1],
            ),
            (2,),
        )
        reversed_inputs = _producer_row(2, policy, records[3:1:-1], records[4])
        with self.assertRaises(ScientificNumericAblationError):
            _require_ablation_activity(
                _activity_fixture(records, policy, rows=(activity.activity_rows[0], activity.activity_rows[1], reversed_inputs)),
                policy,
                input_records=records[2:4], output_records=(records[4],),
                dataset_record=records[0], confirmatory_split_record=records[1],
            )
        wrong_split = _feature_row(0, records[0], records[2])
        with self.assertRaises(ScientificNumericAblationError):
            _require_ablation_activity(
                _activity_fixture(
                    records,
                    policy,
                    rows=(wrong_split, activity.activity_rows[1], activity.activity_rows[2]),
                ),
                policy,
                input_records=records[2:4],
                output_records=(records[4],),
                dataset_record=records[0],
                confirmatory_split_record=records[1],
            )
        wrong_output = _producer_row(2, policy, records[2:4], records[5])
        with self.assertRaises(ScientificNumericAblationError):
            _require_ablation_activity(
                _activity_fixture(
                    records,
                    policy,
                    rows=(activity.activity_rows[0], activity.activity_rows[1], wrong_output),
                ),
                policy,
                input_records=records[2:4],
                output_records=(records[4],),
                dataset_record=records[0],
                confirmatory_split_record=records[1],
            )
        labels = _feature_row(
            0, records[0], records[1], purpose=ScientificDatasetAccessPurpose.CONFIRMATORY_LABELS,
        )
        with self.assertRaisesRegex(ScientificNumericAblationError, "confirmatory labels"):
            _require_ablation_activity(
                _activity_fixture(records, policy, rows=(labels, activity.activity_rows[1], activity.activity_rows[2])),
                policy,
                input_records=records[2:4], output_records=(records[4],),
                dataset_record=records[0], confirmatory_split_record=records[1],
            )
        no_feature = _activity_fixture(
            records,
            policy,
            rows=(_producer_row(0, policy, records[2:4], records[4]),),
        )
        with self.assertRaises(ScientificNumericAblationError):
            _require_ablation_activity(
                no_feature,
                policy,
                input_records=records[2:4], output_records=(records[4],),
                dataset_record=records[0], confirmatory_split_record=records[1],
            )
        duplicate = _producer_row(3, policy, records[2:4], records[5])
        with self.assertRaises(ScientificNumericAblationError):
            _require_ablation_activity(
                _activity_fixture(records, policy, rows=(activity.activity_rows[0], activity.activity_rows[1], activity.activity_rows[2], duplicate)),
                policy,
                input_records=records[2:4], output_records=(records[4],),
                dataset_record=records[0], confirmatory_split_record=records[1],
            )
        mutated = copy.copy(activity.activity_rows[2])
        object.__setattr__(mutated, "seed", 7)
        with self.assertRaises(ScientificNumericAblationError):
            _require_ablation_activity(
                _activity_fixture(records, policy, rows=(activity.activity_rows[0], activity.activity_rows[1], mutated)),
                policy,
                input_records=records[2:4], output_records=(records[4],),
                dataset_record=records[0], confirmatory_split_record=records[1],
            )

    def test_grid_projection_join_accepts_zero_and_reversed_effects_but_exact_coordinates(self):
        for grid in (
            _grid(seeds=(7,), rows=(_row("unit-a", (0,), 0),)),
            _grid(seeds=(7,), rows=(_row("unit-a", (1,), 0),)),
        ):
            self.assertIsNone(
                _require_grid_projection_join(
                    grid,
                    _grid_projection(grid),
                    tuple(item.changed_coefficient_count for item in grid.seed_results),
                )
            )
        grid = _grid(seeds=(7,), rows=(_row("unit-a", (0,), 0),))
        expected_counts = tuple(item.changed_coefficient_count for item in grid.seed_results)
        mutations = (
            {"seed_order": (99,)},
            {"paired_unit_ids": ("other",)},
            {"paired_unit_hashes": (_digest(998),)},
            {"reference_labels": (1,)},
            {"seed_projections": ()},
        )
        for change in mutations:
            projection = _grid_projection(grid)
            for name, value in change.items():
                object.__setattr__(projection, name, value)
            with self.subTest(change=change), self.assertRaises(ScientificNumericAblationError):
                _require_grid_projection_join(grid, projection, expected_counts)
        for wrong_counts in ((0,), (expected_counts[0] + 1,)):
            with self.assertRaises(ScientificNumericAblationError):
                _require_grid_projection_join(grid, _grid_projection(grid), wrong_counts)
        for name in ("seed", "candidate_condition_id", "baseline_condition_id", "candidate_values", "baseline_values"):
            projection = _grid_projection(grid)
            row = copy.copy(projection.seed_projections[0])
            value = {
                "seed": 99,
                "candidate_condition_id": "other-candidate",
                "baseline_condition_id": "other-baseline",
                "candidate_values": (0.0,),
                "baseline_values": (0.0,),
            }[name]
            object.__setattr__(row, name, value)
            object.__setattr__(projection, "seed_projections", (row,))
            with self.subTest(name=name), self.assertRaises(ScientificNumericAblationError):
                _require_grid_projection_join(grid, projection, expected_counts)

    def test_multiple_obligations_need_their_own_producers_and_prior_typed_feature_access(self):
        records, policy = _records(), _policy(2)
        arguments = dict(input_records=records[2:4], output_records=records[4:6],
                         dataset_record=records[0], confirmatory_split_record=records[1])
        first = _producer_row(1, policy, records[2:4], records[4])
        second = replace(first, sequence=3, ablation_id=policy.interventions[1].ablation_id,
                         condition_id=policy.interventions[1].intervention_condition_id,
                         output_artifact_bindings=(_binding(records[5]),))
        features = _feature_row(0, records[0], records[1])
        reread = replace(features, sequence=2)
        activity = _activity_fixture(records, policy, rows=(features, first, reread, second))
        self.assertEqual(_require_ablation_activity(activity, policy, **arguments), (1, 3))
        # Reordering execution of independent obligations is truthful; the
        # returned tuple still follows the complete frozen policy order.
        reordered = _activity_fixture(records, policy, rows=(features, replace(second, sequence=1),
                                                             reread, replace(first, sequence=3)))
        self.assertEqual(_require_ablation_activity(reordered, policy, **arguments), (3, 1))
        late = _activity_fixture(records, policy, rows=(replace(first, sequence=0), replace(features, sequence=1),
                                                       replace(second, sequence=2)))
        with self.assertRaisesRegex(ScientificNumericAblationError, "feature chronology"):
            _require_ablation_activity(late, policy, **arguments)
        for changed_first in (
            replace(first, condition_id="foreign-intervention"),
            replace(first, ablation_id="foreign-obligation"),
            replace(first, input_artifact_bindings=first.input_artifact_bindings[:1]),
            replace(first, input_artifact_bindings=(*first.input_artifact_bindings, _binding(records[0]))),
            replace(first, output_artifact_bindings=()),
        ):
            with self.subTest(changed=changed_first), self.assertRaises(ScientificNumericAblationError):
                _require_ablation_activity(_activity_fixture(records, policy, rows=(features, changed_first, reread, second)),
                                          policy, **arguments)
        for changed_feature in (
            replace(features, dataset_artifact_binding=_binding(records[8])),
            replace(features, seed=7), replace(features, condition_id="foreign-condition"),
            replace(features, ablation_id=policy.interventions[0].ablation_id),
            replace(features, input_artifact_bindings=(_binding(records[8]),)),
            replace(features, output_artifact_bindings=(_binding(records[8]),)),
        ):
            with self.subTest(changed=changed_feature), self.assertRaises(ScientificNumericAblationError):
                _require_ablation_activity(_activity_fixture(records, policy, rows=(changed_feature, first, reread, second)),
                                          policy, **arguments)
class NumericExecutionOwnerBoundaryTests(unittest.TestCase):
    def test_real_missing_execution_authority_refuses_without_registry_or_ledger_delta(self):
        with TemporaryDirectory(prefix="numeric-execution-owner-") as directory:
            values = _prepared_canonical_timeline(directory)
            registry = values["registry"]
            ledger = values["ledger"]
            before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
            with self.assertRaises(ExperimentError) as raised:
                require_scientific_numeric_ablation_execution(
                    registry,
                    ledger,
                    expected_ledger_run_id="global-run-1",
                    expected_execution_run_id="confirmatory-run-1",
                    generic_ml_projection_artifact_sha256=_digest(701),
                    scientific_execution_authority_artifact_sha256=_digest(702),
                    scientific_domain_evidence_source_artifact_sha256=_digest(703),
                    expected_contract_artifact_sha256=values["contract_record"].sha256,
                    expected_output_manifest_artifact_sha256=_digest(704),
                )
            self.assertIn("scientific_execution_authority", str(raised.exception))
            self.assertEqual(
                (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)),
                before,
            )

    def test_public_owner_rejects_non_native_runtime_and_selector_hooks_before_replay(self):
        with TemporaryDirectory(prefix="numeric-execution-types-") as directory:
            values = _prepared_canonical_timeline(directory)
            registry = values["registry"]
            ledger = values["ledger"]

            class HostileText(str):
                def __str__(self):
                    raise AssertionError("selector coercion hook ran")

                def __hash__(self):
                    raise AssertionError("selector hash hook ran")

            valid = dict(
                expected_ledger_run_id="global-run-1",
                expected_execution_run_id="confirmatory-run-1",
                generic_ml_projection_artifact_sha256=_digest(701),
                scientific_execution_authority_artifact_sha256=_digest(702),
                scientific_domain_evidence_source_artifact_sha256=_digest(703),
                expected_contract_artifact_sha256=values["contract_record"].sha256,
                expected_output_manifest_artifact_sha256=_digest(704),
            )
            calls = [
                lambda: require_scientific_numeric_ablation_execution(SimpleNamespace(), ledger, **valid),
                lambda: require_scientific_numeric_ablation_execution(registry, SimpleNamespace(), **valid),
                lambda: require_scientific_numeric_ablation_execution(
                    registry, ledger, **{**valid, "expected_ledger_run_id": HostileText(valid["expected_ledger_run_id"])},
                ),
                lambda: require_scientific_numeric_ablation_execution(
                    registry, ledger, **{**valid, "generic_ml_projection_artifact_sha256": HostileText(_digest(701))},
                ),
            ]
            for call in calls:
                with self.subTest(call=call), self.assertRaises(ScientificNumericAblationError):
                    call()


class NumericExecutionStructureTests(unittest.TestCase):
    @staticmethod
    def _call_lines(function):
        tree = ast.parse(inspect.getsource(function))
        calls = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            else:
                continue
            calls.setdefault(name, []).append(node.lineno)
        return {name: min(lines) for name, lines in calls.items()}

    def test_full_owner_replays_fresh_sources_before_grid_output_and_final_snapshot(self):
        calls = self._call_lines(require_scientific_numeric_ablation_execution)
        ordered = (
            "_locked_scientific_execution_snapshot",
            "require_scientific_execution_authority",
            "require_scientific_execution_run_spec",
            "resolve_scientific_numeric_ablation_binding",
            "require_generic_ml_paired_metric_projection_authority",
            "require_scientific_execution_activity",
            "_require_complete_inventory",
            "_require_ablation_activity",
            "derive_generic_ml_ablation_grid",
            "_require_grid_projection_join",
            "require_generic_ml_ablation_output",
            "_require_scientific_execution_snapshot_unchanged",
        )
        for name in ordered:
            self.assertIn(name, calls)
        for before, after in zip(ordered, ordered[1:]):
            self.assertLess(calls[before], calls[after])
        source = inspect.getsource(require_scientific_numeric_ablation_execution)
        self.assertNotIn("put_json", source)
        self.assertNotIn("put_bytes", source)
        self.assertNotIn("append_event", source)
        self.assertNotIn("register_", source)
        self.assertEqual(source.count("_require_scientific_execution_snapshot_unchanged"), 1)

    def test_admissibility_mandates_fresh_numeric_replay_after_projection_and_exact_handoff(self):
        function = execution_admissibility._derive_sources_at_snapshot
        calls = self._call_lines(function)
        self.assertLess(calls["require_generic_ml_paired_metric_projection_authority"],
                        calls["require_scientific_numeric_ablation_execution"])
        tree = ast.parse(inspect.getsource(function))
        branch, = [node for node in ast.walk(tree) if isinstance(node, ast.If)
                   and ast.unparse(node.test) == "SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY in thaw_json(spec.metadata)"]
        self.assertEqual(branch.orelse, [])
        self.assertEqual(sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id == "require_scientific_numeric_ablation_execution"
                             for node in ast.walk(branch)), 1)
        join, = [node for node in branch.body if isinstance(node, ast.If)]
        names = ("execution", "projection", "spec", "execution_record", "projection_record",
                 "spec_record", "manifest_record", "activity_record")
        # Evaluate only the actual equality predicate over inert local values;
        # no source owner is replaced and no admission path returns success.
        values = {name: f"inert-{name}" for name in names}
        expression = compile(ast.Expression(join.test), "<inert-numeric-source-handoff>", "eval")
        context = {**values, "numeric_ablations": SimpleNamespace(**values)}
        self.assertFalse(eval(expression, {"__builtins__": {}}, context))
        for name in names:
            changed = {**values, name: f"other-{name}"}
            with self.subTest(name=name):
                self.assertTrue(eval(expression, {"__builtins__": {}},
                                     {**context, "numeric_ablations": SimpleNamespace(**changed)}))


if __name__ == "__main__":
    unittest.main()
