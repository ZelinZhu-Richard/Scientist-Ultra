"""Non-evidentiary clean-rerun consumption-time and prefix topology checks.

These private-validator probes use unregistered FAIL/unfrozen records and
in-memory hash-linked ledger vectors. No source owner is replaced, no registry
or ledger is written, and no scientific authority is admitted. The inert
publication indices exercise ordering only, not proof of owned publication.
"""

from dataclasses import replace
import hashlib
from types import SimpleNamespace
import unittest

from scientist_one.artifacts import ArtifactRecord
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import MacroState
import scientist_one.reproduction as reproduction
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
from tests.test_bounded_mean_clean_rerun_profile import _authority as bounded_authority
from tests.test_experiments import spec as inert_spec
from tests import test_scientific_clean_rerun as legacy_fixtures


_EARLIER = "2026-09-03T12:00:00Z"
_CONSUMED = "2026-09-04T12:00:00Z"
_LATER = "2026-09-05T12:00:00Z"
_PLAN_RECORD_FIELDS = (
    "result_promotion_record",
    "assessment_record",
    "original_execution_record",
    "rerun_spec_record",
)
_AUTHORITY_RECORD_FIELDS = (
    "plan_record",
    "result_promotion_record",
    "rerun_domain_record",
    "original_assessment_record",
    "rerun_assessment_record",
    "original_execution_record",
    "rerun_execution_record",
    "original_environment_record",
    "rerun_environment_record",
    "original_isolation_record",
    "rerun_isolation_record",
)


class _HostileIndex(int):
    def _unexpected(self, other):
        raise AssertionError("non-native publication index reached comparison")

    __lt__ = __le__ = __gt__ = __ge__ = _unexpected


class CleanRerunSourceChronologyTests(unittest.TestCase):
    def setUp(self):
        self.spec = inert_spec("inert-rerun-execution")

    def _record(self, name, *, created_at=_EARLIER):
        raw = canonical_json_bytes({"inert_source": name, "scientific_evidence": False}) + b"\n"
        return ArtifactRecord(
            sha256=hashlib.sha256(raw).hexdigest(),
            path=f"inert/{name}.json",
            relative_path=f"inert/{name}.json",
            metadata_path=f"inert/{name}.metadata.json",
            logical_type="non_evidentiary_clean_chronology",
            schema_version="0.0",
            mime_type="application/json",
            size=len(raw),
            origin="NON_EVIDENTIARY_CHRONOLOGY_PROBE",
            creator_role=Role.IMPLEMENTER,
            creation_command=("inert-only",),
            parent_artifacts=(),
            validation_result="FAIL",
            frozen=False,
            created_at=created_at,
        )

    def _records(self, names, *, bounded, created_at=_EARLIER):
        if bounded:
            names = (*names, "statistical_use_record")
        return {name: self._record(name, created_at=created_at) for name in names}

    def _plan_sources(self, *, bounded, created_at=_EARLIER):
        return reproduction._CleanRerunPlanSources(
            **self._records(_PLAN_RECORD_FIELDS, bounded=bounded, created_at=created_at),
            result_resolution=None,
            # This is intentionally not an execution authority or a PASS verdict.
            original_execution=SimpleNamespace(
                execution_run_id="inert-original-execution", ledger_event_index=0,
            ),
            rerun_spec=self.spec,
            original_promotion_event_index=0,
            original_domain_event_index=0,
        )

    def _authority_sources(self, *, bounded, created_at=_EARLIER):
        return reproduction._CleanRerunAuthoritySources(
            **self._records(_AUTHORITY_RECORD_FIELDS, bounded=bounded, created_at=created_at),
            plan=SimpleNamespace(ledger_event_index=0),
            rerun_domain=None,
            original_assessment=None,
            rerun_assessment=None,
            original_execution=SimpleNamespace(ledger_event_index=0),
            rerun_execution=SimpleNamespace(ledger_event_index=0),
            original_environment={},
            original_isolation={},
            rerun_environment={},
            rerun_isolation={},
            rerun_spec=self.spec,
            comparison=None,
            rerun_domain_event_index=0,
        )

    def _event(self, *, event_id, prior=None, role=Role.IMPLEMENTER,
               records=(), reason="non-evidentiary chronology anchor", metadata=None):
        return LedgerEvent.create(
            run_id="inert-chronology-ledger",
            actor_role=role,
            state_before=MacroState.PREFLIGHT,
            requested_state_after=MacroState.PREFLIGHT,
            artifact_hashes=tuple(record.sha256 for record in records),
            code_version=f"sha256:{self.spec.code_sha256}",
            configuration_hash=self.spec.configuration_sha256,
            dataset_identifiers=(self.spec.data_sha256,),
            random_seeds=self.spec.seeds,
            evaluator_outputs=(),
            reason=reason,
            prior_event_hash=prior,
            event_id=event_id,
            timestamp=_CONSUMED,
            event_type="CHECKPOINT",
            metadata=metadata if metadata is not None else {"scientific_evidence": False},
        )

    def _vectors(self, event, anchor):
        retained = self._event(event_id="inert-later-prefix", prior=event.event_hash)
        vectors = ((anchor, event), (anchor, event, retained))
        for vector in vectors:
            raw = b"".join(canonical_json_bytes(item.to_dict()) + b"\n" for item in vector)
            self.assertTrue(EventLedger._validate_bytes(raw).valid)
        return vectors

    def _validate_plan(self, sources, *, error=None):
        binding = reproduction._scientific_clean_rerun_plan_binding(
            plan_id="inert-plan",
            ledger_run_id="inert-chronology-ledger",
            original_result_id="inert-original-result",
            rerun_result_id="inert-rerun-result",
            rerun_assessment_id="inert-rerun-assessment",
            rerun_domain="GENERIC_ML",
            rerun_domain_task_id="inert-task",
            sources=sources,
        )
        anchor = self._event(event_id="inert-anchor")
        event = self._event(
            event_id="inert-plan-event", prior=anchor.event_hash,
            role=Role.PROTOCOL_DESIGNER, records=sources.source_records,
            reason="froze a distinct scientific clean-rerun comparison before preparation",
            metadata={"scientific_clean_rerun_plan": binding},
        )
        for vector in self._vectors(event, anchor):
            if error is None:
                reproduction._validate_scientific_clean_rerun_plan_event(
                    event, 1, vector, binding=binding, sources=sources,
                )
            else:
                with self.assertRaisesRegex(reproduction.ReproductionError, error):
                    reproduction._validate_scientific_clean_rerun_plan_event(
                        event, 1, vector, binding=binding, sources=sources,
                    )

    def _validate_verification(self, sources, *, error=None):
        # The event validator expects an already-derived binding. This deliberately
        # non-scientific map isolates chronology; it does not exercise that derivation.
        binding = {
            "kind": "NON_EVIDENTIARY_CHRONOLOGY_PROBE",
            "scientific_evidence": False,
            "source_artifact_sha256s": [record.sha256 for record in sources.source_records],
            "source_artifact_record_hashes": [record.record_hash for record in sources.source_records],
        }
        anchor = self._event(event_id="inert-anchor")
        event = self._event(
            event_id="inert-verification-event", prior=anchor.event_hash,
            role=Role.REPRODUCTION_VERIFIER, records=sources.source_records,
            reason="verified two prospectively bound isolated scientific executions",
            metadata={"scientific_clean_rerun_authority": binding},
        )
        for vector in self._vectors(event, anchor):
            if error is None:
                reproduction._validate_scientific_clean_rerun_authority_event(
                    event, 1, vector, sources=sources, binding=binding,
                )
            else:
                with self.assertRaisesRegex(reproduction.ReproductionError, error):
                    reproduction._validate_scientific_clean_rerun_authority_event(
                        event, 1, vector, sources=sources, binding=binding,
                    )

    def _validate_publication(self, record, *, bounded, error=None):
        # Existing closed codec fixtures remain inert: this record is FAIL and
        # unfrozen, and neither fixture nor event is registered with any owner.
        authority = bounded_authority() if bounded else legacy_fixtures.ScientificCleanRerunTests()._authority()
        authority = replace(authority, verification_event_index=0)
        anchor = self._event(event_id="inert-anchor")
        event = self._event(
            event_id="inert-publication-event", prior=anchor.event_hash,
            role=Role.REPRODUCTION_VERIFIER, records=(record,),
            reason="admitted source-owned scientific clean-rerun authority",
            metadata=reproduction._scientific_clean_rerun_publication_metadata(record, authority),
        )
        for vector in self._vectors(event, anchor):
            if error is None:
                reproduction._validate_scientific_clean_rerun_publication_event(
                    event, 1, vector, record=record, authority=authority, rerun_spec=self.spec,
                )
            else:
                with self.assertRaisesRegex(reproduction.ReproductionError, error):
                    reproduction._validate_scientific_clean_rerun_publication_event(
                        event, 1, vector, record=record, authority=authority, rerun_spec=self.spec,
                    )

    def test_plan_accepts_earlier_or_simultaneous_inert_sources_in_both_prefix_shapes(self):
        for bounded in (False, True):
            for created_at in (_EARLIER, _CONSUMED):
                with self.subTest(bounded=bounded, created_at=created_at):
                    sources = self._plan_sources(bounded=bounded, created_at=created_at)
                    self.assertEqual(len(sources.source_records), 5 if bounded else 4)
                    self._validate_plan(sources)

    def test_plan_rejects_each_late_direct_source_including_optional_statistical_use(self):
        for bounded in (False, True):
            sources = self._plan_sources(bounded=bounded)
            for name in (*_PLAN_RECORD_FIELDS, *(("statistical_use_record",) if bounded else ())):
                with self.subTest(bounded=bounded, source=name):
                    late = replace(getattr(sources, name), created_at=_LATER, record_hash=None)
                    self._validate_plan(replace(sources, **{name: late}), error="predates a consumed source")

    def test_plan_requires_native_nonnegative_strictly_earlier_owned_publication_indices(self):
        for bounded in (False, True):
            for name in ("original_promotion_event_index", "original_domain_event_index"):
                for index in (None, -1, True, 0.0, 1, 2, _HostileIndex(0)):
                    with self.subTest(bounded=bounded, source=name, index=index, index_type=type(index).__name__):
                        sources = replace(self._plan_sources(bounded=bounded), **{name: index})
                        self._validate_plan(sources, error="stale, post hoc, or substituted")

    def test_verification_accepts_earlier_or_simultaneous_inert_sources_in_both_prefix_shapes(self):
        for bounded in (False, True):
            for created_at in (_EARLIER, _CONSUMED):
                with self.subTest(bounded=bounded, created_at=created_at):
                    sources = self._authority_sources(bounded=bounded, created_at=created_at)
                    self.assertEqual(len(sources.source_records), 12 if bounded else 11)
                    self._validate_verification(sources)

    def test_verification_rejects_each_late_direct_source_with_exact_record_hashes(self):
        for bounded in (False, True):
            sources = self._authority_sources(bounded=bounded)
            for name in (*_AUTHORITY_RECORD_FIELDS, *(("statistical_use_record",) if bounded else ())):
                with self.subTest(bounded=bounded, source=name):
                    late = replace(getattr(sources, name), created_at=_LATER, record_hash=None)
                    self._validate_verification(replace(sources, **{name: late}), error="predates a consumed source")

    def test_verification_requires_native_nonnegative_strictly_earlier_domain_index(self):
        for bounded in (False, True):
            for index in (None, -1, True, 0.0, 1, 2, _HostileIndex(0)):
                with self.subTest(bounded=bounded, index=index, index_type=type(index).__name__):
                    sources = replace(self._authority_sources(bounded=bounded), rerun_domain_event_index=index)
                    self._validate_verification(sources, error="stale or substituted")

    def test_publication_accepts_earlier_or_simultaneous_inert_record_for_both_codecs(self):
        for bounded in (False, True):
            for created_at in (_EARLIER, _CONSUMED):
                with self.subTest(bounded=bounded, created_at=created_at):
                    self._validate_publication(self._record("authority", created_at=created_at), bounded=bounded)

    def test_publication_rejects_late_record_for_both_codecs_and_prefix_shapes(self):
        for bounded in (False, True):
            with self.subTest(bounded=bounded):
                self._validate_publication(
                    self._record("authority", created_at=_LATER), bounded=bounded,
                    error="predates a consumed source",
                )


if __name__ == "__main__":
    unittest.main()
