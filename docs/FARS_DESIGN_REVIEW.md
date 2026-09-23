# Bounded FARS design review

Status: source assessment complete; A01 integrated with scoped verification.
Final whole-Goal verification and release remain unfinished.
This review does not complete the original vNext Goal.

## Authority and source

The [meta-spec](../RESEARCH_OS_VNEXT_META_SPEC.md) remains authoritative.
The [FARS addendum](../FARS_REFERENCE_ADDENDUM.md) is a bounded reference, not a
replacement specification. On 2026-09-20 the owner explicitly authorized this
assessment at the installed, writer-free PMC checkpoint while preserving every
unresolved data, custodian, deployment, live-access, platform and safety boundary.

Examined: Qiong Tang et al., *FARS: A Fully Automated Research System Deployed at
Scale*, [arXiv:2606.31651v2](https://arxiv.org/abs/2606.31651v2), revised
2026-07-13, retrieved 2026-09-20. The [versioned PDF](https://arxiv.org/pdf/2606.31651v2)
has 20 pages; references below use its one-based printed/PDF page numbers.
SHA-256: `a05a021aada5ade821a96cd6d3fed3638651b9c035fd6d9a8ab7c3bcf51a8925`;
3,720,742 bytes. Root read the paper directly and visually checked Figure 1,
Table 6 and Appendix B. No FARS repository was cloned or executed. The paper's
arXiv non-exclusive distribution license is not project redistribution clearance;
the PDF and renderings are not public project artifacts.

### PAPER_DESCRIPTION: stage interface capsule

| Order | Input to output; owner, tools, validation and termination | Source |
| --- | --- | --- |
| Ideation | Directions to proposals; lead/summary/discussion/evaluation agents, search, shared knowledge, iterative review and best-draft circuit breaker. | §3.2, p.5 |
| Planning | Proposal to ordered item/step JSON; planner, related-work setup, format/category/order validation and regeneration. | §3.3, pp.5-6 |
| Experiment | Items to results; harness/agent/reviewer, managed tools, completeness checks, checkpoints and interruption cleanup. | §3.4, pp.6-7 |
| Writing | Trajectory to blueprint to manuscript; analysis/writing agents, plotting/compilation, evidence-linked checks and refinement. | §3.5, p.7 |

### AUTHOR_REPORTED_RESULT

166 papers; 282 reviews covering 140, excluding 26 unreviewed papers. Six reviews
were withheld. Fourteen of 16 papers with mean rating at least six had one
reviewer. Automated comparison covers 165 FARS papers and heterogeneous released
subsets, not controlled experiments (§§4-6, pp.7-16).

### OUR_INFERENCE

Those denominators, voluntary self-selection and non-comparable release/task
policies prevent treating reviewer scores as acceptance rates or as causal
evidence that a particular architectural mechanism improves research. No
mechanism-level ablation was established by this assessment. Figure 1 is an
architecture description, not proof of enforcement. Neither our coverage table
nor internal tests establish superiority over FARS or upstream ScientistOne.

## Actual local separation

These are current source observations, not conclusions from matching names:

1. `scientific_design.EvaluationContract` owns scientific commitments, contract
   identity/version, hypotheses, metrics, Dataset/splits, baseline fairness,
   seed/reporting rules, budgets, statistics, ablations and stopping policies.
   `ExperimentPlan` stores one seed/purpose/split/evaluator projection bound to
   the exact contract hash. `_validate_experiment_plan_structure` refuses a
   substituted hypothesis experiment, seed, evaluator, split or ablation purpose.
   Protected confirmation is not authorized by its caller-supplied observation
   boolean; `admit_experiment` requires the separate authoritative timeline path.
2. `register_frozen_experiment_plan`, `_require_frozen_experiment_plans` and
   `register_frozen_run_spec` preserve exact contract parents, ordered per-seed
   plans, required ablations and immutable code/data/configuration/evaluator
   inputs. `FrozenRunSpec` supplies the executable argv, seeds, minimum outputs,
   resources, timeout and explicit retry identity. `AdaptiveExecutionPlan` is
   only a memory/concurrency/batch/cache projection, not another scientific plan.
3. Execution and interpretation remain separate. The local collector checks
   exact manifest/spec identities, seed population, required ablations and
   actual artifact bytes. GPU bundle acceptance uses the shared validator.
   `AutonomousImplementationController.execute_prepared_local_run` revalidates
   its admitted implementation, frozen spec and bound inputs rather than
   accepting a provider completion claim. Scientific execution/outcome and result
   promotion add independent authorities; operational success is not positive
   science, scientific eligibility, human E4 or publication permission.

The model already exists across these owners. Replacing it with a second generic
"experiment contract" or task ledger would introduce competing authority. An
arbitrary study-wide DAG is not currently represented by the per-seed plan, and
that limitation is stated rather than credited as implemented. Additional
hierarchy must be justified by an actual workload dependency, not the diagram.

## Adoption matrix

`ALREADY_COVERED` means the stated bounded local mechanism exists in inspected
implementation and test cases, not that every real scientific trajectory passes.
Named tests are source evidence unless a recorded execution below explicitly
covers them. `DEFER` applies only to additional reference-inspired scope, never
to an original vNext requirement. Source locations refer to the versioned PDF
above; decisions, gaps and acceptance criteria are our architectural judgments.

| ID / reference mechanism | Source | Local owner and test evidence | Demonstrated gap / decision | Rationale, dependency and observable acceptance |
| --- | --- | --- | --- | --- |
| F01: artifact-centred handoffs | §3.1, p.5; Fig.1, p.4 | Existing `ArtifactRegistry`, `EventLedger`; contract/plan/spec parent checks and `ScientificTimelineAuthorityTests` in `test_scientific_design.py` | `ALREADY_COVERED` at the immutable handoff boundary | Reuse these owners. Acceptance: substitution or missing parent is refused; historical source identities survive later descendants. This is not proof of independent custody or complete recovery. |
| F02: item/step hierarchy | §3.3, pp.5-6 | `ExperimentPlan`, `FrozenRunSpec`, `AdaptiveExecutionPlan`; `EvaluationContractTests`, `SelectionStatisticsAndPromotionTests`, `ComputeProfileTests` | `DEFER` only an additional generic multi-stage DAG | Existing purpose/seed execution needs no parallel task registry. Reconsider when an admitted workload has necessary cross-item dependencies that existing owners cannot express. Acceptance then requires exact contract binding, dependency completion and interruption replay; original real-workload requirements remain open. |
| F03: controller completion | §3.4, p.6 | `LocalMacBackend._capture_and_validate_manifest`, `_validate_manifest_bindings`, `derive_scientific_execution_outcome`; new `test_expected_output_completion.py` | `ADAPT_NOW` A01: missing declared output type could still yield operational success | Enforce the existing frozen minimum-output predicate at existing acceptance points. Complete evidence, tests and limits are below. No semantic/scientific authority is added. |
| F04: layered environments | §3.4, p.6 | `ComputeProfile`, `FrozenRunSpec`, bound worker/input staging; `LocalMacControlTests` | `DEFER` additional reusable workload recipes; `UNKNOWN` equivalence of actual containment | A dependency environment is not a sandbox. Reconsider versioned recipes only for a concrete authorized workload with proven repeated setup failure. Original isolation/read-restriction work remains `SAFETY_STOPPED`; this review neither repairs nor certifies it. |
| F05: managed resources | §3.4, p.7 | `plan_adaptive_execution`, `ScheduledGPUCloudBackend`, escalation authority; `ComputeProfileTests`, `GPUCloudBoundaryTests`, `ScheduledGPUBackendTests` | `ALREADY_COVERED` for local policy/fixture boundaries, not live infrastructure | Exact profile/cost/concurrency and submission identities are already owned. Acceptance: altered plans/requeue attempts refuse and uncertain external windows do not cause duplicate submission. Real GPU allocation, cleanup, hardware parity and cost remain externally unverified. |
| F06: unified model access | §3.4, p.7 | `ModelProvider`, `OpenAIResponsesProvider`, provider wire/schema verification; `test_external_providers.py`, `test_openai_schema_admission.py` | `REJECT` adding a multi-provider proxy merely for resemblance | Keep one OpenAI adapter plus capability-neutral interfaces. Acceptance remains exact request/provenance/failure contracts and genuine permitted deployment validation, not provider count. Confidential deployment is unfinished; no D032 gate is opened. |
| F07: checkpoints | §3.4, p.7 | local persisted spec/plan/manifest and scheduled GPU recovery; `test_scheduled_gpu_recovery.py`, local recovery tests | `ALREADY_COVERED` at bounded replay/reconciliation; `REJECT` automatic public per-task commits | Private scientific checkpoints and release Git are separate. Recovered valid outputs must match frozen bytes, incomplete/uncertain attempts must not be repeated silently. Public commits/pushes still require the original audit, licensing, confidentiality and history gates. |
| F08: research-practice guides | §3.4, p.6 | Existing reviewed implementation catalog and attested source/runtime; no new guide owner selected | `DEFER` a new workload-guide catalog | No repeated current workload error has been demonstrated that a guide closes. Reconsider with a concrete repeated failure, versioned advice and a non-authorizing consumer. Acceptance: advice cannot alter contract commitments, authorize egress or execute downloaded instructions. |
| F09: best-draft fallback | §3.2, p.5 | novelty/research gates and `DiscoveryEngine`; `NoveltyAndHypothesisTests` | `REJECT` fallback as scientific admission | Budget exhaustion may terminate with insufficient evidence. Acceptance: an unqualified candidate remains rejected even if it is the highest-scoring remaining draft. No retry budget overrides a scientific gate. |
| F10: effectiveness gate | §3.4, p.6 | outcome-neutral scientific result derivation, required ablation and soundness gates; `test_manifest_outcome_derivation_is_closed_and_outcome_neutral` | `REJECT` adopting a positive-result prerequisite for mandatory analysis | Preserve negative/null/inconclusive distinctions and predeclared checks. Acceptance: null/negative operational completion is retained, but neither proves falsification nor permits skipping required validity work. |
| F11: reporting/replay discipline | §3.1, p.5; Appendix B, pp.18-20 | `SeedReportingPlan`, `validate_seed_report`, `seed_reporting._report_projection`; `test_seed_reporting_edge_cases.py`, operational reporting/readback tests, amendment tests | `ALREADY_COVERED` for tested reporting/amendment components; `UNKNOWN` equivalent FARS guarantees | Our complete population, selected result, adverse outcomes, retry history and amendment lineage remain authoritative. Acceptance: omission, rename/restart concealment, stale readback or post-observation replacement refuses. Fresh real confirmatory reserve/custodian authority remains unsatisfied. |
| F12: portfolio scale | Fig.1, p.4; §4, pp.7-8 | Existing single-run/project identities and resource boundaries | `DEFER` portfolio infrastructure | First establish an authorized real trajectory. Reconsider only with concrete multi-project workload demand and tested isolation/budget ownership; do not add a shared private-data memory or new service layer now. |
| F13: literature knowledge | §3.2, p.5 | `scientific_design.py` investigation/novelty replay; `literature.py:FullTextPassage`; `research_state.py` PriorWork projection; `test_registry_novelty_gate_binds_all_comparison_dimensions`, `test_registry_gate_rejects_coherent_round_and_receipt_narrative_rebinding`, `test_registry_novelty_gate_rejects_structural_level_three_support` in `test_research_os_literature_integration.py` | `ALREADY_COVERED` for exact source/claim provenance; `DEFER` additional individual advisory-note passage indexing | Notes remain whole-record/source-bound, not individually passage-indexed. Canonical notes are DRAFT/LEVEL_3/non-evidentiary; round findings are replayed operational narratives. Actual novelty comparisons independently require canonical claim-target and captured-passage semantic support. Reconsider finer note representation only for a concrete material consumer; acceptance must reject substituted note inputs/support without inventing another evidence authority. Real summary quality, exhaustive coverage and live workflows remain unverified. |
| F14: evidence-first manuscript planning | §3.5, p.7 | `paper_composition.py:PaperCompositionInput`, `_derive_composition_input`, `require_paper_manuscript_revision`; `paper_pipeline.py:_verify_reference_use`; `test_golden_bytes_exact_claim_and_complete_source_map`, `test_tampered_content_or_source_map_is_rejected` in `test_paper_composition.py`, claim/passage/context-forgery tests in `test_research_os_literature_integration.py` | `ALREADY_COVERED` for the authority-derived deterministic composition path | The composition input is a derived blueprint, not claim approval. It resolves fresh bundle/claim/metric/reference/review authority before rendering and maps every content byte to its sources. Scientific references separately require exact claim, passage, locator, context and judgment identities. Acceptance: changed sources or content/source-map substitution refuses; historical revision replay uses exact prior evidence. Arbitrary generative prose and real-paper quality are not established. No second blueprint subsystem is justified. |

For F13, the initial advisory identified the absent per-note field but did not
demonstrate a scientific-admission failure. A separate consumer trace and root
inspection confirmed that novelty constructs its exact support target from all
comparison dimensions, then resolves the matching captured passage and semantic
assessment. Important claims are not admitted merely from a note. The deferral
therefore concerns additional advisory indexing only; any demonstrated original
claim-support defect remains mandatory current-milestone work.

Owner paths above are relative to `src/scientist_one/`; test paths are relative
to `tests/`. F01/F02/F09 contract/design tests are in
`test_scientific_design.py`; F04/F05 compute tests are in `test_experiments.py`.
No general FARS schema, exact retry schedule, OS enforcement, independent custody
or mechanism-level causal benefit is inferred where the primary paper does not
establish it (`UNKNOWN`).

## A01: failure, patch and verification

The unchanged-source diagnostic reproducer executed four checks on each of
Python 3.14.6 and 3.11.15: two passed and two failed. A custom `analysis_report`
was required by `FrozenRunSpec.expected_outputs` but absent from the manifest;
the local backend returned `SUCCEEDED`, and shared manifest validation did not
raise. The already-existing scientific outcome validator correctly refused it.
The failing status assertion preceded collection, so the original reproduction
does not claim its later collection assertion executed.

The patch extracts the existing minimum-type rule into
`experiments._missing_expected_output_types` and uses it before local acceptance
and shared GPU manifest acceptance. The scientific outcome path uses the same
predicate without changing its ordering or outcome semantics. The manifest and
structured seed collection remain intrinsic outputs, both historical singular
and plural seed aliases are preserved, custom artifact types satisfy the minimum,
and additional outputs remain legal.

No new type authority, contract, ledger, state machine, schema, source of truth
or provider was added. Artifact type presence is not semantic correctness; exact
bytes, identities, evaluator checks and scientific authorities remain independent.
Historical complete outputs remain compatible. An incomplete historical success
cache must now refuse fresh collection/recovery without rewriting its bytes or
rerunning the workload. This is an explicit correction of operational acceptance,
not a retroactive scientific amendment.

### VERIFIED_REPOSITORY_BEHAVIOR

The original four-check reproducer now passes on each Python 3.14.6 and 3.11.15.
Permanent captured-worker verification establishes:

- 14 corrected completion tests pass on each runtime, with no failures, errors,
  skips, expected failures or unexpected successes. They cover missing/present
  custom types, both seed aliases, permitted extras, wrong logical types,
  missing/altered files, negative/null records, local/FakeGPU/scheduled fixture
  completion, incomplete-cache refusal with unchanged bytes/no replacement run,
  and valid-cache recovery. Local runs use supplied diagnostic output; scheduled
  transport is a fixture. Neither is scientific or live execution.
- 17 scientific-execution-authority and 22 scheduled-recovery methods pass on
  each runtime against the same production bytes. Their loaded test closures
  remain unchanged after the two-line correction below. This is 53 distinct
  selected method IDs across the retained checks, **not** one green 53-method
  rerun, the whole suite, or 106 distinct methods.
- The first 53-method run had 51 passes and two test-only errors: tests attempted
  to read `SubmissionReceipt.reason` instead of `JobStatus.reason`. Both failed
  result sets remain preserved. Only the affected 14-method module was rerun
  after correcting those reads. Earlier unrun drafts with stale-spec fixtures
  are also retained; none is falsely reported as executed.
- Root rehashed all 281 selected-run input files, compared both runtime
  inventories, and verified identical production attestations (74 files), test
  inventories (203 files) and loaded closures as applicable. Ruff passes for the
  production patch and permanent test module. No source schema or serialized
  contract identity changed. Full `test_experiments.py` execution was excluded
  because its native mutation control overlaps a stopped boundary; importing
  its fixture helpers is not execution of those tests.

Production `experiments.py`: `1bbeac688b62c810b1f9f2c5ba3217ba1caa7d7c94ba0eb28e72ca80f8c30d38`.
Permanent test module: `7b61c7f4c314492e4f7345e5f8c1055527b19c09015f8d56551f2436f8b5a223`.
Corrected captured-14 result hashes are
`c23772a757533bdf6f65a72ad448e706ebd2fbc5c0692977ab59f808d9079bfc`
(3.14.6) and
`d9117032ca1097ae62c250cf56c6b901c742a31c6524473043eff705d69187bd`
(3.11.15). Original captured-53 results are
`a6692a694191d4761840c44490b32547f5757382613c0a819b0d84ac3a573001`
and `cd5200a898ce4c1e5e7b7178232a5354966429aef64d9ed93a59b0ec7157a1c3`.

An independent nonauthor examined the entire production delta, full permanent
test file, caller/recovery implications and actual result/attestation evidence.
No material A01 correctness issue remains identified. Requested reviewer routing
predated the updated policy; actual runtime model/effort is `UNVERIFIED`.
This bounded architecture/correctness review is not a security scan or the
unavailable/stopped platform assessment. Original failures and source preimage
remain preserved privately; no test result authorizes protected data, provider
credentials, cloud spending, containment or scientific promotion.

## Unresolved requirements and continuation

Protected real data, real/independent custodians, fresh confirmation authority,
confidential deployment, live provider/scholarly access, stopped safety work and
exact unavailable platform reviews retain their prior unresolved statuses. The
bounded correctness review here is not the stopped `assess-patch-risk` mechanism
or a workaround for it. The system is not newly classified as research-grade.

After A01 and the assessment close, continue the original nonblocked roadmap,
revisit prerequisites safely, and perform the permitted full regression,
adversarial/end-to-end, recovery/reproduction, packaging and architecture checks.
Explicit safety exclusions remain exclusions, not skipped tests relabeled PASS.
Git reconstruction and public synchronization require the separate release gates;
this report does not authorize publication or make an unfinished branch complete.
