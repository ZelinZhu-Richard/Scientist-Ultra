# THIS_REPOSITORY Compared with UPSTREAM_SCIENTISTONE

**INFERENCE — comparison status.** This is a source-backed architectural comparison at an earlier implementation checkpoint, not acceptance of the current DEVELOPMENT / REVIEW tree. Final frozen verification and unresolved defects remain in the [current handoff](../OVERNIGHT_REPORT.md#development--review-checkpoint-september-23-2026); empirical superiority remains unestablished.

**FACT_FROM_ARTIFACT — compared local state.** The local side includes the historical reported pre-vNext foundation in [`baseline_before_vnext.md`](baseline_before_vnext.md), separately labeled [reconstructed verification](BASELINE_TEST_RECONSTRUCTION.md), implemented vNext modules and the synthetic research-OS fixture in [`research_os.py`](../src/scientist_one/research_os.py). The fixture is deliberately non-evidentiary scientifically and is not a surrogate for a real research result.

**FACT_FROM_SOURCE + FACT_FROM_ARTIFACT — compared upstream state.** The upstream side is `UPSTREAM_SCIENTISTONE` as described by the [project site](https://scientist-one.github.io/), [arXiv:2605.26340v1](https://arxiv.org/html/2605.26340), and generated artifacts pinned at commit [`721f1fbe3b39a558dff13386c50621a357e6f9a7`](https://github.com/scientist-one/generated-artifacts/commit/721f1fbe3b39a558dff13386c50621a357e6f9a7).

**INFERENCE — comparison rule.** Architectural capability and empirical performance are independent axes. A safeguard, interface, test, or larger claim taxonomy can support an architectural verdict; it cannot establish an empirical performance verdict.

## Evidence labels and verdict vocabulary

**FACT_FROM_SOURCE — upstream evidence rule.** Upstream paper and site claims are source-reported unless the public artifact tree itself establishes the fact. No upstream evaluator or GPU result was rerun for this comparison.

**FACT_FROM_ARTIFACT — local evidence rule.** Local claims distinguish historical reported baseline measurements, reconstructed executable checks and inspectable, exercised vNext artifacts. Passing a synthetic system fixture establishes bounded architectural behavior, not scientific validity, real-world novelty, external-provider validation, or research-performance superiority.

**INFERENCE — relative classifications.** `STRONGER`, `PARITY`, `PARTIAL`, `WEAKER`, `MISSING`, `UNKNOWN`, and `NOT_COMPARABLE` are evidence-bounded judgments about the stated scope, not global system rankings.

**INFERENCE — architectural verdicts.** Architectural rows use only `ARCHITECTURALLY_STRONGER`, `ARCHITECTURALLY_PARITY`, `ARCHITECTURALLY_WEAKER`, or `UNKNOWN`.

**INFERENCE — empirical verdicts.** Empirical rows use only `EMPIRICALLY_STRONGER`, `EMPIRICALLY_PARITY`, `EMPIRICALLY_WEAKER`, `NOT_YET_ESTABLISHED`, or `NOT_COMPARABLE`.

## Evidence base

### THIS_REPOSITORY evidence

#### Independently reproduced pre-vNext foundation

| Evidence class | Verified local fact | Evidence |
|---|---|---|
| `FACT_FROM_ARTIFACT` | The isolated test suite passed 364/364 with no failure, error, skip, expected failure, or unexpected success. | [`baseline_before_vnext.md` — Test baseline](baseline_before_vnext.md#test-baseline) |
| `FACT_FROM_ARTIFACT` | Fifteen of fifteen architecture controls passed after stale report bindings were explicitly repaired; the targeted validator passed 4/4. | [`baseline_before_vnext.md` — Architecture-control baseline](baseline_before_vnext.md#architecture-control-baseline) |
| `FACT_FROM_ARTIFACT` | The final pre-documentation project audit passed for 899 files with zero findings and zero lockfiles after a root `.DS_Store` was quarantined without deletion. | [`baseline_before_vnext.md` — Audit, security, and dependency baseline](baseline_before_vnext.md#audit-security-and-dependency-baseline) |
| `FACT_FROM_ARTIFACT` | A fresh deterministic demonstration reached `READY_FOR_HUMAN_REVIEW` / `COMPLETE_DEMO_ONLY`, with 21 ledger events and 58 artifacts; it remained `DEMO_RESEARCH_PACKAGE` and `NOVELTY_UNVERIFIED`. | [`baseline_before_vnext.md` — CLI and deterministic demonstration](baseline_before_vnext.md#cli-and-deterministic-demonstration) |
| `FACT_FROM_ARTIFACT` | Reproduction compared expected 1.0 with observed 1.0 at frozen tolerance `1e-12`; verify, recovery, packaging, and post-package verify passed. | [`baseline_before_vnext.md` — Recovery, reproduction, packaging, and custody](baseline_before_vnext.md#recovery-reproduction-packaging-and-custody) |
| `FACT_FROM_ARTIFACT` | Exploration and confirmation are separated; reveal is one-time; confirmatory rerun is prohibited; E4 remains human-only and absent. | [`baseline_before_vnext.md` — Guarantees B-05 through B-07](baseline_before_vnext.md#guarantees-that-vnext-must-preserve) |
| `FACT_FROM_ARTIFACT` | The baseline has content-addressed frozen artifacts, a hash-linked ledger, typed transitions, claim/evidence nodes, verifier receipts, deterministic calibration, resource authority, recovery, and bounded packaging. | [`baseline_before_vnext.md` — Guarantees B-01 through B-15](baseline_before_vnext.md#guarantees-that-vnext-must-preserve) |
| `FACT_FROM_ARTIFACT` | The baseline has no working model provider, controlled scholarly gateway, real Problem Investigator, external novelty determination, autonomous discovery, real workload orchestration, GPU-cloud backend, four domain adapters, or venue pipeline. | [`baseline_before_vnext.md` — Verified pre-vNext gaps](baseline_before_vnext.md#verified-pre-vnext-gaps) |

#### Implemented vNext checkpoint

| Evidence class | Exercised local fact | Evidence and boundary |
|---|---|---|
| `FACT_FROM_ARTIFACT` | Canonical, append-only research state covers the required scientific objects; materialization resolves through the existing Artifact Registry and Event Ledger before downstream use. | [`research_state.py`](../src/scientist_one/research_state.py), [`research_os.py`](../src/scientist_one/research_os.py), and authority-bypass tests in [`test_vnext_state.py`](../tests/test_vnext_state.py). This is local architectural evidence, not an upstream-style experiment. |
| `FACT_FROM_ARTIFACT` | Controlled scholarly acquisition records request/response provenance and can verify an exact supporting passage through `LEVEL_5`, including surrounding-context non-contradiction. | [`literature.py`](../src/scientist_one/literature.py) and [`test_literature.py`](../tests/test_literature.py). The integrated records are synthetic; live scholarly access remains `BLOCKED_EXTERNAL`, so they cannot establish real-world novelty. |
| `FACT_FROM_ARTIFACT` | A provider-neutral interface and OpenAI Responses implementation run behind an audited egress gateway with captured artifacts, strict structured output, credential-state reporting, and non-evidentiary failure provenance. | [`external.py`](../src/scientist_one/external.py), [`providers.py`](../src/scientist_one/providers.py), and [`test_external_providers.py`](../tests/test_external_providers.py). The integrated provider call is an offline fixture; live availability is external and unvalidated. |
| `FACT_FROM_ARTIFACT` | The integrated flow builds an evidence-checked research brief, scoped novelty and hypothesis records, a frozen evaluation contract, retained discovery branches, an all-seed analysis, an ablation, an independent claim decision, and preserved positive, negative, and null outcomes. | [`scientific_design.py`](../src/scientist_one/scientific_design.py), [`discovery.py`](../src/scientist_one/discovery.py), [`claims.py`](../src/scientist_one/claims.py), and [`research_os.py`](../src/scientist_one/research_os.py). All outcomes are scoped to the synthetic development fixture. |
| `FACT_FROM_ARTIFACT` | A real local subprocess executes the frozen fixture twice and materializes outputs, logs, manifests, statistics, and comparison receipts. Scientific evidence defaults to `NON_EVIDENTIARY`. | [`experiments.py`](../src/scientist_one/experiments.py), [`vnext_fixture_experiment.py`](../scripts/vnext_fixture_experiment.py), and [`test_research_os_e2e.py`](../tests/test_research_os_e2e.py). `LOCAL_MAC` still lacks an OS-enforced filesystem/process/network sandbox. |
| `FACT_FROM_ARTIFACT` | Typed domain-validity adapters cover Generic ML, medical imaging, time series, recommender systems, operations research, and systems; Generic ML is exercised in the end-to-end fixture. | [`domains.py`](../src/scientist_one/domains.py) and [`test_domains.py`](../tests/test_domains.py). Real domain tasks and external validity remain untested. |
| `FACT_FROM_ARTIFACT` | Independent Challenger, soundness, human-policy, paper-readiness, and venue gates fail closed. The current fixture ends `MORE_EXPERIMENTS_REQUIRED`, `BLOCKED_SCIENTIFICALLY`, paper `BLOCKED`, and venue `NOT_READY`; E4 is never synthesized. | [`gates.py`](../src/scientist_one/gates.py), [`paper_pipeline.py`](../src/scientist_one/paper_pipeline.py), and [`research_os.py`](../src/scientist_one/research_os.py). The pipeline materializes a machine-verifiable paper candidate, not a generated scientific paper. |
| `FACT_FROM_ARTIFACT` | `GPU_CLOUD` is represented only by a deterministic boundary fixture and remains `UNTESTED` and non-evidentiary. | [`experiments.py`](../src/scientist_one/experiments.py) and the integrated fixture summary in [`research_os.py`](../src/scientist_one/research_os.py). No real GPU-cloud run is claimed. |

### UPSTREAM_SCIENTISTONE source floor

| Evidence class | Upstream fact or reported result | Evidence |
|---|---|---|
| `FACT_FROM_SOURCE` | UPSTREAM_SCIENTISTONE links literature grounding, PEE discovery, and claim-grounded paper writing into an end-to-end pipeline. | [Paper §4 and Figure 1, pp. 4–6](https://arxiv.org/html/2605.26340#S4) |
| `FACT_FROM_SOURCE` | PI builds a two-hop Semantic Scholar graph, filters it, reads full text in multiple rounds, audits directions, and writes an experiment brief. | [Appendix B.1, pp. 20–21](https://arxiv.org/html/2605.26340#A2.SS1) |
| `FACT_FROM_SOURCE` | PEE retains top branches, refills slots with fresh ideation, filters audited solutions, selects the best score, and runs ablations. | [§4.2, p. 5](https://arxiv.org/html/2605.26340#S4.SS2) |
| `FACT_FROM_SOURCE` | The Paper Writer uses Conceive, Ground, Critic, Resolve, and Compose before a Claim Verifier/refiner. | [Appendix B.4–B.5, pp. 21–22](https://arxiv.org/html/2605.26340#A2.SS4) |
| `FACT_FROM_SOURCE` | Table 1 reports I1 12/12, I2 0/15, I3 0/337, and I4 14/15 for UPSTREAM_SCIENTISTONE. | [§6.1 and Table 1, pp. 8–10](https://arxiv.org/html/2605.26340#S6.SS1) |
| `FACT_FROM_SOURCE` | Raw numerical CPR is reported as 627/639, or 98.1%; the authors estimate about 99% after manual correction. | [§6.2, pp. 10–11](https://arxiv.org/html/2605.26340#S6.SS2) |
| `FACT_FROM_SOURCE` | The system has a reported I4 failure and a real LLM-SQL specification exploit that escaped the 5-judge majority rule. | [§6.1, p. 10](https://arxiv.org/html/2605.26340#S6.SS1), [Appendix A.1 Case 3, pp. 19–20](https://arxiv.org/html/2605.26340#A1.SS1) |
| `FACT_FROM_SOURCE` | The paper identifies citation-support depth, audit false negatives, proxy review, missing strong baselines, proxy-only metrics, domain coverage, and benchmark depth as limitations. | [§6.3, pp. 11–12](https://arxiv.org/html/2605.26340#S6.SS3), [§9, pp. 15–16](https://arxiv.org/html/2605.26340#S9) |
| `FACT_FROM_ARTIFACT` | The pinned output release contains 21 PDFs, 15 ADRS solver files, and six fuller MLE/Parameter Golf workspaces, but not the complete framework/auditor/evaluator/provenance bundle. | [Pinned release commit](https://github.com/scientist-one/generated-artifacts/commit/721f1fbe3b39a558dff13386c50621a357e6f9a7) |

## Capability matrix

**INFERENCE — matrix scope.** The verdict column compares the exercised vNext architecture of `THIS_REPOSITORY` with disclosed UPSTREAM_SCIENTISTONE architecture. `UNKNOWN` means that different scope or missing evidence prevents a directional result; it does not mean feature absence.

| Dimension | Current vNext architectural verdict | Evidence class | Evidence and rationale |
|---|---|---|---|
| Security | `UNKNOWN` | `FACT_FROM_ARTIFACT` + `INFERENCE` | `THIS_REPOSITORY` retains verified kernel controls and adds bounded egress/provider parsing, but `LOCAL_MAC` does not yet provide an OS-enforced experiment sandbox. The upstream sources do not disclose a comparable security model or full framework source. |
| Provenance | `ARCHITECTURALLY_STRONGER` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` + `INFERENCE` | The local vNext fixture materializes typed research objects, exact source/result artifacts, claim evidence, independent receipts, and phase checkpoints through the sole registry and ledger authorities. Upstream has real cross-stage annotations and reported CPR, but its pinned release has no inspectable equivalent canonical graph. This verdict concerns durable traceability, not real-workload performance. |
| Protocol discipline | `ARCHITECTURALLY_STRONGER` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` + `INFERENCE` | Local protocol freeze, exploration/confirmation separation, protected-resource controls, and rerun rules are enforced. Upstream MLE explicitly selected models using up to 16 test-server queries. |
| Reproducibility | `UNKNOWN` | `FACT_FROM_ARTIFACT` + `INFERENCE` | Local execution now includes a second clean system-fixture run with frozen inputs and registry-resolved expected/observed artifacts. Upstream reports real evaluator reruns, but the pinned bundle is incomplete and the workloads are not comparable. |
| Literature reasoning | `UNKNOWN` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` + `INFERENCE` | Local architecture reaches exact passage/context verification through controlled captured synthetic records; upstream reports broad live graph traversal and full-text reading. Local depth and upstream breadth/liveness are different, and live local retrieval is blocked. |
| Problem investigation | `UNKNOWN` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` + `INFERENCE` | Local checked briefs, explicit gap-destroying evidence, baseline and ablation requirements, and freezeable directions are exercised synthetically. Upstream reports a broader live PI process. No like-for-like architectural dominance follows. |
| Novelty | `UNKNOWN` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` + `INFERENCE` | Local novelty state and disconfirming checks fail closed, but synthetic literature cannot establish real-world novelty. Upstream scores novelty and reports a Parameter Golf novelty claim without independently establishing global novelty in the pinned release. |
| Discovery | `UNKNOWN` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` + `INFERENCE` | Local discovery retains promoted, negative, and null branches under typed policy; upstream reports real multi-branch PEE search. The local fixture establishes branch semantics, not comparable discovery capability. |
| Experimentation | `UNKNOWN` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` + `INFERENCE` | Local vNext runs a real subprocess with frozen manifests, all seeds, a required baseline, an ablation, statistics, and a clean rerun, but only on a synthetic non-evidentiary fixture without OS isolation. Upstream reports real ADRS/MLE/Parameter Golf runs. |
| Scientific soundness | `ARCHITECTURALLY_STRONGER` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` + `INFERENCE` | Local vNext has an independent typed Challenger and complete soundness gate that preserves an unresolved external-validity challenge and blocks promotion. Upstream has Critic/audit/review stages but reports missing baselines, proxy-only evaluation, qualitative overclaims, and unbounded audit false negatives. This is a gate-architecture verdict only. |
| Claim verification | `UNKNOWN` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` + `INFERENCE` | Local verification resolves a complete bounded evidence graph, independent receipts, expanded claim types, and exact synthetic passage support. Upstream verifies real generated papers but its I3 is shallower and I2/I4 have documented misses. Scope prevents an overall direction. |
| Writing | `ARCHITECTURALLY_WEAKER` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` | Local vNext verifies an evidence-only paper candidate and correctly blocks it; it deliberately does not generate a scientific paper. Upstream generates full papers through Conceive, Ground, Critic, Resolve, Compose, and refinement. |
| Compute | `ARCHITECTURALLY_WEAKER` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` | Local `LOCAL_MAC` is exercised without an OS sandbox and `GPU_CLOUD` is boundary-tested only and `UNTESTED`. Upstream reports real 8×H100 workloads. |
| Domain extensibility | `ARCHITECTURALLY_STRONGER` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` + `INFERENCE` | Local vNext implements typed validity adapters and adversarial checks for six domain families, with Generic ML integrated end to end. Upstream demonstrates task portability but explicitly did not build open-ended domain-specific verification. This does not establish real-domain performance. |
| Autonomy | `UNKNOWN` | `FACT_FROM_ARTIFACT` + `FACT_FROM_SOURCE` + `INFERENCE` | Local vNext autonomously traverses the complete synthetic exploration fixture while preserving independent scientific gates; upstream reports broader live literature, discovery, experiment, and paper autonomy. Local live external and paper endpoints remain blocked. |
| Human authority and custody | `ARCHITECTURALLY_STRONGER` | `FACT_FROM_ARTIFACT` + `INFERENCE` | Local modes vary human approvals without weakening scientific gates, E4 remains human-only, and failed soundness blocks release. No equivalent upstream release-authority or custody protocol is disclosed. |

## Architectural verdicts

**INFERENCE — verdict scope.** These are bounded target-level conclusions from the current implementation checkpoint. They do not imply empirical superiority or erase the stated live-external, compute, sandbox, and paper-generation gaps.

| Dimension | Verdict for current THIS_REPOSITORY vs UPSTREAM_SCIENTISTONE | Evidence class | Basis |
|---|---|---|---|
| Security | `UNKNOWN` | `INFERENCE` | Comparable upstream evidence is absent and the local subprocess lacks OS-enforced isolation. |
| Provenance | `ARCHITECTURALLY_STRONGER` | `INFERENCE` | Local canonical objects and registry/ledger-resolved claim evidence remain inspectable after composition boundaries; the pinned upstream release does not expose an equivalent graph. |
| Protocol discipline | `ARCHITECTURALLY_STRONGER` | `INFERENCE` | Verified local confirmation/reveal controls versus disclosed upstream test-result selection. |
| Reproducibility | `UNKNOWN` | `INFERENCE` | Local synthetic clean rerun and upstream real-task reporting are not like-for-like; the public upstream bundle remains incomplete. |
| Literature reasoning | `UNKNOWN` | `INFERENCE` | Local exact captured-passage depth versus upstream live breadth are different capabilities. |
| Problem investigation | `UNKNOWN` | `INFERENCE` | Local checked synthetic brief versus upstream live multi-round PI are not comparable. |
| Novelty | `UNKNOWN` | `INFERENCE` | Neither side supplies independently established global novelty under a common protocol. |
| Discovery | `UNKNOWN` | `INFERENCE` | Local typed branch retention is exercised synthetically; upstream real search is broader. |
| Experimentation | `UNKNOWN` | `INFERENCE` | Local real subprocess controls and upstream real workload scale cover different scopes. |
| Scientific soundness | `ARCHITECTURALLY_STRONGER` | `INFERENCE` | Local independent typed gates deterministically block the exercised fixture when external validity is unresolved. |
| Claim verification | `UNKNOWN` | `INFERENCE` | Local depth/authority and upstream real-paper breadth do not yield a scalar direction. |
| Writing | `ARCHITECTURALLY_WEAKER` | `INFERENCE` | The local pipeline stops at an evidence-only paper candidate; upstream generates complete papers. |
| Compute | `ARCHITECTURALLY_WEAKER` | `INFERENCE` | Real GPU cloud is untested locally; upstream reports H100 workloads. |
| Domain extensibility | `ARCHITECTURALLY_STRONGER` | `INFERENCE` | Local typed domain-validity interfaces cover six families; upstream explicitly lacks open-ended domain verification. |
| Autonomy | `UNKNOWN` | `INFERENCE` | Local autonomous synthetic exploration and upstream broader live autonomy are not equivalent. |
| Human authority and custody | `ARCHITECTURALLY_STRONGER` | `INFERENCE` | Local E4 and custody semantics are verified; no upstream equivalent is disclosed. |

**INFERENCE — no aggregate architectural winner.** The evidence supports narrow local advantages in durable provenance, protocol discipline, fail-closed soundness, explicit domain-validity architecture, and release authority. UPSTREAM_SCIENTISTONE remains broader in live literature, real workload execution, GPU scale, and paper generation. These facts cannot be collapsed into a single “stronger system” verdict.

## Empirical comparison

**FACT_FROM_ARTIFACT — local empirical boundary.** The vNext checkpoint still has not run ADRS, MLE-Bench, Parameter Golf, ScholarPeer, the upstream CoE Audit, real scholarly retrieval, a live external model workload, or a real GPU-cloud workload. Its synthetic threshold fixture is explicitly `NON_EVIDENTIARY`, uses no protected confirmatory result for promotion, and cannot be compared with upstream research results.

| Evaluation | UPSTREAM_SCIENTISTONE result | THIS_REPOSITORY comparable result | Verdict | Evidence class and caveat |
|---|---|---|---|---|
| I1 Score Verification | 12/12 reported | Not run on the same papers/evaluators | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE` upstream; `FACT_FROM_ARTIFACT` local absence. |
| I2 Specification Violation | 0/15 reported under majority vote; one upstream exploit escaped 4/5 judges | Not run under the same tasks/auditor | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`; table value cannot be treated as a measured zero-failure rate. |
| I3 Reference Verification | 0/337 hallucinated entries reported at existence/metadata depth | Not run on a comparable bibliography | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`; semantic passage support is not included. |
| I4 Method–Code Alignment | 14/15 aligned papers reported | Not run on comparable generated papers | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`. |
| Numerical CPR | 627/639 raw, 98.1%; approximately 99% manually corrected | No comparable real-paper CPR | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`; local synthetic claim tests use different semantics. |
| ScholarPeer average | Overall 4.5/10, 6/15 accepts | Not run | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`; automated review is not human review. |
| ADRS Prism | 26.26, best of three | Not run | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`; no local comparable task. |
| ADRS Cloudcast | 618.08, best of three, lower is better | Not run | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`; no local comparable task. |
| ADRS EPLB | 0.1459, best of three | Not run | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`; runtime component complicates hardware comparison. |
| ADRS LLM-SQL | 0.7222, best of three | Not run | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`; upstream search produced a documented exploit in another seed. |
| ADRS TXN | 3906, best of three | Not run | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`; no local comparable task. |
| Five MLE tasks | Two Gold, two Silver, one Above Median reported | Not run | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`; upstream used up to 16 test-server queries and 8×H100. |
| Parameter Golf | 1.0600 reported at cutoff | Not run | `NOT_YET_ESTABLISHED` | `FACT_FROM_SOURCE`; leaderboard cutoff, hardware, full artifact, and ablation completeness must be matched. |
| Clean reproduction | Real-task full public rerun not available from pinned bundle | A second clean local system-fixture execution agrees under frozen inputs; scientific comparison remains `NON_EVIDENTIARY` | `NOT_COMPARABLE` | `FACT_FROM_ARTIFACT`; system-integrity reproduction and real scientific reproduction are different claims. |

**INFERENCE — empirical verdict.** There is no comparable experiment on which to call `THIS_REPOSITORY` empirically stronger, equal, or weaker than UPSTREAM_SCIENTISTONE. The only valid overall empirical verdict is `NOT_YET_ESTABLISHED`.

## Comparison limitations

| Evidence class | Limitation | Effect on comparison |
|---|---|---|
| `FACT_FROM_ARTIFACT` | The pinned upstream repository lacks the full system, audit implementation, golden evaluators, TeX/Bib inputs, and complete provenance bundle. | Upstream architecture and reported metrics cannot be independently reconstructed from the specified release alone. |
| `FACT_FROM_SOURCE` | Baselines in the paper required unequal adaptations: Sakana 16 files, ARC two, DeepScientist prompt-only, and AI-Researcher 19. | Cross-system upstream rankings are not definitive reference measurements. |
| `FACT_FROM_SOURCE` | ADRS scores use best-of-three selection; Table 6 uses single-seed search ceilings; MLE permits test-server selection. | Reported discovery performance is not a clean confirmatory distribution. |
| `FACT_FROM_SOURCE` | UPSTREAM_SCIENTISTONE used Gemini 3.1 Pro and, for generalization, 8×H100 infrastructure. | A local comparison must match or account for model, compute, wall-clock, memory, and tuning budgets. |
| `FACT_FROM_ARTIFACT` | The current local fixture uses a real CPU subprocess, synthetic captured literature, and an offline provider transport; MPS/CUDA/real GPU cloud and live provider/literature access remain unvalidated. | Current local results are architecture and system-integrity evidence, not research-performance evidence. |
| `FACT_FROM_SOURCE` | ScholarPeer is an automated proxy; I2 and I4 are model-majority judgments; audit false negatives are not bounded. | Audit/reviewer scores require independent calibration before use as superiority targets. |
| `FACT_FROM_SOURCE` | I3 establishes reference existence/metadata, not passage-level support. | A deeper local check is architecturally different and cannot be compared as the same metric without stratification. |
| `FACT_FROM_ARTIFACT` | `LOCAL_MAC` does not yet enforce an operating-system filesystem/process/network sandbox, and `GPU_CLOUD` is only boundary-tested. | A solver-resistant real experiment pipeline and backend-equivalence claim remain unestablished. |
| `FACT_FROM_ARTIFACT` | The local paper stage emits a machine-verifiable candidate and blocker assessment, not a scientific manuscript. | Upstream paper-generation breadth has not been matched locally. |

## Final conservative summary

**FACT_FROM_ARTIFACT + INFERENCE — current local capability.** The conservative vNext implementation classification is `AUTONOMOUS_EXPLORATION_READY`. The system autonomously exercises a complete synthetic literature-to-design-to-discovery-to-experiment-to-claim-to-gate path while keeping scientific evidence, release authority, and paper readiness fail closed. This classification is below `REAL_EXPERIMENT_PIPELINE_READY`, `RESEARCH_GRADE`, and `SUBMISSION_PIPELINE_READY` because OS isolation, real external evidence, real GPU validation, external novelty/generalization, and scientific paper generation remain incomplete.

**FACT_FROM_SOURCE — upstream capability.** UPSTREAM_SCIENTISTONE demonstrates a broader research-intelligence pipeline: real literature investigation, branch discovery, task execution, ablation, paper composition, and several forms of claim checking.

**INFERENCE — architectural conclusion.** Current `THIS_REPOSITORY` has evidence-bounded architectural advantages in durable canonical provenance, enforced confirmation/reveal, fail-closed soundness, explicit domain-validity adapters, and human release authority. It remains architecturally weaker in complete paper generation and validated GPU compute, and mixed or `UNKNOWN` where local synthetic depth and upstream real-workflow breadth are not comparable.

**INFERENCE — empirical conclusion.** `NOT_YET_ESTABLISHED`. No “beats UPSTREAM_SCIENTISTONE,” empirical parity, or empirical inferiority statement is permitted from the available local evidence.

**INFERENCE — update rule.** Do not promote any empirical verdict until a comparable upstream-style evaluation uses matched tasks, data, evaluators, model and compute budgets, selection rules, uncertainty reporting, and clean reproduction. Do not promote the capability classification beyond `AUTONOMOUS_EXPLORATION_READY` until the named local blockers are actually removed and verified.
