# Scientific Validity Model

## Authority and scope

### Permutation comparison semantics (v2)

`statistics.permutation_test_mean_difference` counts assignments whose mean
difference is at least as extreme as the observed difference. `greater` and
`less` are signed tails; `two-sided` uses the absolute statistic, not twice a
one-sided tail. Ties are included. Comparison v2 converts the validated floats
to exact integers over a common binary denominator, then compares exact
mean-difference numerators. It does not merge unequal statistics using a fixed
absolute tolerance. For `[1,2,3,4]` versus four zeros, both unscaled and scaled
by `1e-16`, exact enumeration returns `1/35`, not the old scaled result `1.0`.

Positive rescaling that preserves represented values exactly preserves these
comparisons. Floating multiplication may round, overflow or underflow and
change the observations; arbitrary rescaling is not guaranteed invariant.
This correction does not change the range or semantics of other effect-size,
bootstrap or variance routines. Exact enumeration, indexed multiplicities,
seeded Monte Carlo shuffling and its `(extreme + 1)/(resamples + 1)` correction
remain. Exact comparison arithmetic does not imply exhaustive Monte Carlo
sampling, domain exchangeability or scientific eligibility.

The only in-repository direct caller is `analyze_two_group`; its new
`test_method` is `exchangeable-unit label permutation; binary64-exact-comparison/v2`.
Historical result bytes, method descriptions, evaluator receipts and study
interpretations are not rewritten. External callers must retain their source
revision and distinguish this interpretation from the earlier `1e-15` rule.
The independently reviewed `tests/test_permutation_precision.py` uses rational
group means as an oracle, separately from production integer-score arithmetic.
Its 18 distinct numerical tests pass on Python 3.14.6 and 3.11.15; this is
cross-runtime component evidence, not 36 distinct tests or full regression.

### Structured-state authority

Scientist-One vNext treats the typed, canonical research state as the scientific source of truth. `ArtifactRegistry` and `EventLedger` remain the persistence and provenance authorities for that state. Markdown reports, paper candidates, tables, figures, and summaries are derived views; they cannot add evidence, approvals, eligibility, or conclusions that are absent from the structured state.

The integrated Research OS fixture exercises the vNext control path with captured provider and literature responses, a checked research brief, a frozen evaluation contract, real local subprocesses, discovery branches, a claim graph, challenger review, soundness assessment, and paper-readiness verification. Its study is nevertheless synthetic and every result-bearing fixture artifact is marked `scientific_evidence_eligible=false`. A system-fixture integrity pass establishes that the bounded plumbing and validators worked. It does not establish real-world novelty, empirical importance, external validity, independent review, or publication readiness.

The two judgments must never be collapsed:

- **System integrity** asks whether the declared workflow ran, its artifacts resolve, its state is reproducible, and its deterministic controls behaved as specified.
- **Scientific eligibility** asks whether the evidence is real, appropriately designed, externally grounded where required, independently challenged, and eligible for the proposed claim.

The integrated fixture can pass the first while correctly failing the second.

## Research-question and design authority

The Problem Investigator is a checked builder, not a form that accepts a naked `gap_reality` assertion. It consumes the bound `LiteratureRecord` set, requires a sufficient reviewed and elite pool, checks that selected records resolve into that pool, and requires an explicit disconfirming search. If selected or disconfirming evidence is marked `destroys_gap=true`, the builder must stop with `INSUFFICIENT_NOVELTY` or require `REFORMULATE`; a caller cannot override that evidence with an optimistic Boolean.

The integrated fixture uses synthetic literature records to exercise this gate. A captured Level-5 passage and a successful checked brief prove only that passage binding, contradiction handling, and gate derivation work. They are not an external bibliography and do not establish real novelty. Its novelty status is deliberately narrow (`INCREMENTAL_NOVELTY` for the repository fixture), with real-world novelty unsupported.

The `NoveltyRegister` binds each contribution to the closest prior work, comparison dimensions, conflicts, and adjudication history. The `HypothesisRegister` distinguishes falsifiable primary and secondary hypotheses and records promotions rather than rewriting history. A hypothesis created or promoted after results are visible cannot silently become confirmatory.

Before result-bearing work, the `EvaluationContract` freezes:

- metric identity, direction, unit, scope, estimand, and whether each metric is a proxy or end-to-end measure;
- datasets, split roles, analysis and resampling units, exclusions, leakage controls, and protected resources;
- `MUST_RUN`, `SHOULD_RUN`, and `MAY_RUN` baselines, reasoned exclusions, and equivalent data, preprocessing, features, tuning, compute, and stopping access;
- every seed, the reporting regime, selection policy, multiplicity treatment, statistical tests, intervals, and effect-size requirements;
- required ablations, negative controls, compute budget, retry/stopping rules, and the interpretation ladder for positive, null, reversed, unstable, or invalid outcomes; and
- explicit exploratory-versus-confirmatory roles and the conditions for promotion from proxy evidence to end-to-end evidence.

The contract is deeply immutable. Amendments are new, reasoned records with lineage and result-visibility status; they do not edit the frozen contract. Proxy results cannot be promoted to end-to-end evidence unless the predeclared promotion criteria and end-to-end validation are present.

New contract-bound Dataset authority, experiment projection and split-family
publications additionally require the existing current-contract lineage owner.
After complete preflight, any missing artifact or missing publication event
requires the exact contract record and original registry/ledger snapshot pair;
the existing paired commit check rejects a later amendment or other source
change before a Dataset write. A fully completed, exact historical retry remains
a no-op, and historical readers remain available. An incomplete old-contract
publication cannot finish merely because its artifact bytes already exist.
These rules do not rebind old Dataset authority to a successor contract or prove
fresh independent units, non-exposure or a new confirmatory reserve. The
conditional regression tests use real contract/ledger/publication owners with
explicitly synthetic external semantic sources, not real Dataset admission.

Scientific superiority has a separate fail-closed promotion boundary. The compatibility validator accepts value objects only to produce a `DIAGNOSTIC_ONLY` consistency result with `authoritative=false`; it cannot mint promotion authority. The checked path instead resolves exact frozen `ArtifactRegistry` records for the evaluation contract, an independent scientific-evidence eligibility receipt, aggregate result, statistical analysis, and evaluator assessment. The eligibility receipt must itself bind the aggregate to its frozen run specification and output manifest and attest confirmatory scientific evidence, verified execution isolation and protocol separation, and an attested network-use state. The checker validates canonical bytes, roles, schemas, hashes, ordered parents, and registry closure and deterministically recomputes the baseline identity, paired observations, metric semantics, effect, confidence interval, exact test, sample size, scope, and evaluator verdict. A caller-supplied eligibility Boolean, evaluator pass, statistic, baseline ID, or SHA-shaped string is not authority. Only a checked receipt that survives independent re-resolution may carry `SCIENTIFIC_PROMOTION_AUTHORIZED`.

All declared seed runs must be retained and reported, including failures and technically invalid runs. `BEST_OF_N` is not an informal best-seed report: `N`, the complete run set, metric direction, selection policy, and multiplicity/statistical treatment must be predeclared, and all runs remain visible. Selective seed replacement, metric switching, undeclared reruns, and outcome-dependent exclusions are scientific failures.

Exploration uses development resources only. Confirmation uses separately protected resources and a frozen interpretation map. The validity reserve may not be used for architecture, model, prompt, feature, metric, baseline, seed, or story selection. A material post-reveal design change creates a new study or requires new confirmatory reserve.

## Normative R0–R7 checks

| Check | Required evidence | Blocking examples |
|---|---|---|
| R0 — integrity | Valid schemas, content hashes, event chain, state contracts, provenance, frozen artifacts | Missing origin, broken hash, unauthorized transition, mutated frozen artifact |
| R1 — question/protocol | Falsifiable hypothesis, estimand, unit, protocol, decision ladder, claim-scope contract | Outcome-switched hypothesis, undefined estimand, post-result protocol change |
| R2 — implementation | Core/metric correctness and equivalent baseline access, preprocessing, budget, stopping, features | Candidate benefits from extra data, tuning, compute, or broken baseline |
| R3 — data/splits | Data quality, split integrity, leakage/contamination checks, correct analysis unit | Train/holdout overlap, duplicated dependent observations counted independently |
| R4 — statistics | Assumptions, effect size, uncertainty, valid resampling unit, multiplicity, calibration | Seeds treated as samples, invalid exchangeability, uncorrected search |
| R5 — robustness | Ablations, negative controls, domain-adaptive nulls, shift/reversal tests | Generic permutation used where invalid, conclusion collapses under required control |
| R6 — claims/writing | Claim-evidence links, verified citations, limitations, contradiction scan | Numeric prose lacks result artifact, omitted material failure, invented citation |
| R7 — reproduction/release | Frozen replay, output comparison/tolerance, package audit, residual risks | Reproduction mismatch, original evidence mutated, E4 implied or forged |

For a real workflow, all mandatory R0–R7 meanings must be evidenced before `READY_FOR_HUMAN_REVIEW`. Authority is check-specific: R0 requires E0; R1/R2/R4 require E0+E2; R3 requires E0+E3; R5/R6 require E2+E3; and R7 requires E3. E1 self-review cannot satisfy a mandatory check. A numerical readiness score cannot override a failed mandatory check.

The dependency-free statistical layer validates explicit analysis, resampling, and dependency-group identities; rejects pseudo-replication without design justification; and requires domain nulls to preserve declared structure and use the protocol's resampling unit. Seeds, folds, time points, repeated measures, checkpoints, and correlated tasks are not independent observations merely because several values exist.

## Native descriptive numerical interventions

The fixed-model Generic ML profile has a distinct native descriptive ablation path. A prospectively frozen feature-weight intervention is replayed against the full declared unit/seed grid and joined to the outcome-neutral primary Result, its actual Method/Experiment/Run, output records, execution activity, and custody closure. The new `scientific-ablation-authority/v2` payload retains the existing artifact family, while canonical metadata uses `scientific-numeric-ablation-canonical/v1`. Its signed integer effect summaries are descriptive, not significance tests. Zero and reversed effects are retained. Every native canonical Ablation remains `scientific_evidence_eligible=false`; legacy scientific robustness routes explicitly refuse this profile.

Complete numerical coverage requires one ordinary issued canonical snapshot, every Result and its exact StatisticalTest, and a bijection between every required intervention and native observation. It cannot be reconstructed from selected favorable leaves. The native Soundness publisher replays the whole current cohort, checks capacity and exact bytes/metadata/chronology before writing, and commits through the existing registry/ledger paired mutation checks. Readback reopens the complete bound cohort and exact publication. It reuses the existing v2 dimension receipt with fixed rule/rationale, `DETERMINISTIC` authority and `UNTESTED` scientific adequacy. Even complete replay does not prove that these interventions adequately answer the frozen research question or support a mechanistic claim; it cannot issue a prose-qualified scientific `PASS`.

Soundness first determines applicability independently of the caller's selected ablation receipt. It combines snapshot selectors from the fully replayed REPRODUCTION review and the separately resolved R7 audit, rejects competing snapshots, and fully replays the issued bound state and audit-free scientific-core drift checks. Thus an older ablation receipt or an older review without a snapshot cannot hide native intent in the audited experiment policies. Native work requires the fixed native receipt and joins that same snapshot and complete Result/StatisticalTest identities to exactly one plural REPRODUCTION audit, including the exact graph, assessment, central claims, review and execution records. Static round replay uses its existing fully replayed REPRODUCTION peer; the numerical cohort itself never enters an audit or Soundness owner. R5/E2 remains downstream and replays the full audit, same numerical cohort and all clean-package outcomes. Authenticated adverse outcomes remain failures; successful operational coverage still leaves scientific adequacy `UNTESTED`.

The plural audit family also supports older non-native experiments. For the exact singleton R5/E2 route, applicability is read only after full audit ownership, from every Result-bound Run's retained frozen specification. Numeric-policy key presence, or required fixed-model interventions, selects the complete native cohort even when all observations are missing. No failure in that native replay can fall back to legacy behavior. Complete absence retains the old non-native result; mixed/multiple source combinations retain their old nonauthoritative handling. Existing Result-to-Run relations such as `reproduced_by` remain valid for applicability; native coverage keeps its stricter own ancestry checks.

Current integration verification is scoped source review plus focused/affected tests, not positive scientific publication or end-to-end scientific adequacy. The final full frozen suite, security scan and system fixture remain separate pending authorities.

The initial cohort scope caps retained canonical history at 32 Results, 32 StatisticalTests, 64 Ablations and 32 reproduction packages before expensive snapshot-owner replay. These are admission-cardinality limits, not measured runtime, global primitive-work or memory guarantees. Oversized or unsupported cohorts are refused without truncation and are not classified as scientific failures. Focused source, pure/inert and real-negative tests do not establish a genuine positive scientific lifecycle.

## Calibration and honest outcomes

Real research cannot begin until validators distinguish the known-answer cases in `fixtures/calibration/calibration_cases.json`:

| Case | Required decision |
|---|---|
| planted positive | `PLANTED_SIGNAL_RECOVERED` |
| true null | `TRUE_NULL_RETAINED` |
| leakage trap | `LEAKAGE_DETECTED` |
| regime reversal/shift | `REGIME_REVERSAL_DETECTED` |
| invalid resampling unit | `INVALID_RESAMPLING_UNIT_DETECTED` |
| multiple comparisons | `MULTIPLE_COMPARISONS_DETECTED` |
| baseline implementation mismatch | `BASELINE_MISMATCH_DETECTED` |
| corrupted provenance | `CORRUPTED_PROVENANCE_DETECTED` |
| unsupported claim | `UNSUPPORTED_CLAIM_REJECTED` |
| holdout access violation | `HOLDOUT_ACCESS_VIOLATION_DETECTED` |
| prompt injection in research artifact | `PROMPT_INJECTION_QUARANTINED` |
| domain-invalid permutation | `DOMAIN_INVALID_PERMUTATION_REJECTED` |

These are deterministic regression fixtures, not external scientific results. Expected behavior includes stopping or rejecting invalid cases, not merely producing a score. Text from a provider, paper, benchmark, or other network-derived artifact is untrusted evidence and never control authority.

Negative, null, inconclusive, falsified, failed, and scientifically invalid outcomes are retained in canonical state. The integrated discovery fixture deliberately preserves negative and null branches even though its selected development branch is positive. A disappointing result is evidence, not a retry condition or a reason to delete a run.

## Claims, verifier receipts, and generated views

Each material claim links the required typed evidence kinds: hypothesis, estimand, dataset or fixture, protocol version, code, result, statistical analysis, robustness, figure/table, verified source citation, scope qualifier, and limitation. A SHA-shaped string or a serialized `ELIGIBLE` decision is not authority.

Evidence production and claim verification are distinct roles. Evidence artifacts are created by their declared producers. A `Role.CLAIM_VERIFIER` then creates content-bound `EvidenceSupportReceipt` artifacts for the exact claim text, evidence node, semantic payload, and support decision. Claim-graph resolution independently validates the live registry objects and derives `EvidenceVerificationReceipt` identities used by the eligibility decision. Deserialization does not preserve derived eligibility, and writing must re-resolve the graph and its generated-asset parents.

This distinction prevents evidence producers from self-authorizing their claims and prevents a copied receipt digest from standing in for a resolvable verifier artifact. Graph-local `ELIGIBLE` means that the narrowly scoped claim has the required support under the graph contract. It does not override `scientific_evidence_eligible=false` on the integrated system fixture or make that fixture publishable science.

Tables, figures, prose, and paper candidates are deterministic views over the registry-derived `AuthoritativeResearchBundle`. Bundle construction and paper verification independently re-resolve the frozen research state, claim graph and verifier receipts, evidence set, metric values, method-code bindings, soundness assessment, and limitations. They must agree with frozen metric direction/unit, result values, method-code identities, limitations, and claim scope. Regenerated bytes and parent bindings are verified before a writing or packaging transition.

## Challenger, soundness, paper, and release gates

Scientific gates remain mandatory in every human-gate policy, including `FULL_AUTONOMOUS`. Automation may waive an optional human checkpoint; it cannot waive novelty, validity, evidence, challenge, soundness, reproduction, or release requirements and cannot synthesize E4.

The Challenger records falsification attempts and unresolved findings across exactly 14 categories: prior art, experimental design, implementation, leakage, statistics, baselines, compute fairness, evaluator gaming, confounding, alternative explanation, seed dependence, external validity, reproduction, and overclaiming. The soundness assessment requires registry-resolved evidence receipts for exactly 15 dimensions: question validity, novelty, technical correctness, dataset validity, baseline completeness, evaluator validity, statistics, robustness, ablations, generalization, compute fairness, end-to-end evidence, alternative explanations, limitations, and reproducibility. It binds every category review and finding and can return `PASS`, `CONDITIONAL_PASS`, `MORE_EXPERIMENTS_REQUIRED`, `MAJOR_REVISION`, or `REJECT_RESEARCH_DIRECTION`. Missing, duplicate, noncanonical, role-invalid, or provenance-incomplete authority fails closed; unresolved blocking or major findings constrain the verdict. In the integrated fixture, generalization and external validity remain untested, so the conservative result is `MORE_EXPERIMENTS_REQUIRED`, not a scientific pass.

The evidence-first paper pipeline consumes the registry-derived `AuthoritativeResearchBundle`; it does not invent a result or citation while drafting. The integrated non-evidentiary run registers its comparison only as a strict `superiority_promotion_diagnostic`: `DIAGNOSTIC_ONLY`, non-authoritative, scientifically ineligible, and unable to authorize promotion. That artifact is excluded from the paper bundle's authoritative evidence, and the fixture's scientific baseline-completeness and statistics policy flags remain false. Unsupported/fabricated references, irreproducible headline results, unresolved leakage, evaluator exploitation, omitted required baselines, method-code or table-prose contradictions, invalid statistics, unsupported novelty, selection bias, failed clean reproduction, unsupported central claims, and unresolved blocking challenges are hard blockers. Any hard blocker forces venue status `NOT_READY` regardless of a numeric rubric score. E4 remains a later, human-only release authority even after scientific and venue checks pass.

## Current external boundary

Every currently admitted scientific Generic-ML source profile is restricted to `WITHIN_DATASET_ONLY` and derives no external-validation evidence. Consequently, the GENERALIZATION dimension remains `UNTESTED` after full source replay even when the scoped domain checks pass, including older training/projection profiles. A future external-validation profile needs explicit source-owned generalization checks; changing an adapter version or omitting a generalization claim cannot grant PASS.

The `external-validity-boundary-audit/2.0` procedure extends deterministic inspection beyond the historical fixture-only procedure. It reopens one ordinary issued snapshot, the exact complete Claim graph, every Result and StatisticalTest, and their outcome-neutral promotion, checked assessment, execution/spec and domain owners. Current and historical registration/readback use the same scientific sources with paired currentness and publication checks. Existing execution/review receipts retain `(snapshot, domain receipts)` as evidence and the whole Result/Test population as results. Fixed review prose reports scope inventory only, no fabricated severe finding and no claim that external validation or overclaiming review succeeded. Executed semantic reviews in Soundness must bind the same snapshot; UNTESTED reviews retain the ordinary incomplete verdict without claiming snapshot coverage. R5/E3 requires exact complete audit/cohort agreement; external adequacy remains `UNTESTED`. Independent scoped review closed and root651 affected tests passed; control/refusal tests are not positive scientific lifecycle evidence.

The integrated fixture uses captured, auditable provider and literature transports rather than live services. Live scholarly sources, a real OpenAI provider call, proprietary data, physical GPU-cloud execution, and independent external validation remain `UNTESTED` or `BLOCKED_EXTERNAL` as applicable. The fake GPU backend validates only the provider-neutral boundary. `LOCAL_MAC` uses the same scientific contract as `GPU_CLOUD`, but the current local executor does not provide an OS-enforced network, filesystem, or process sandbox; enclosing application and OS controls remain part of the trusted computing base.

Local custody and role receipts provide deterministic misuse and provenance checks, not genuine institutional independence. A same-user authority capable of coherently replacing all local witnesses can recompute unsigned history. Strong irreversible custody requires an external human or service authority, a different UID, WORM or signed/witnessed storage, a TPM-backed record, or an equivalent trust anchor.

No current artifact demonstrates empirical superiority over upstream ScientistOne. Architectural coverage and deterministic fixture behavior are not a comparable upstream benchmark, and documentation must keep `UPSTREAM_SCIENTISTONE` distinct from `THIS_REPOSITORY`.
