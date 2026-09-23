# UPSTREAM_SCIENTISTONE Reverse Engineering

**FACT_FROM_ARTIFACT — review status.** Primary-source review is complete; reported results were not independently reproduced.

**FACT_FROM_SOURCE — identity and scope.** This document principally describes `UPSTREAM_SCIENTISTONE`, the external system presented at <https://scientist-one.github.io/> and in arXiv:2605.26340. Historical `PROPOSED_IMPROVEMENT` statements record the local design implications derived from that review; a separate checkpoint near the end identifies which implications are now implemented in `THIS_REPOSITORY`, Scientist-One vNext. The two systems and their evidence remain distinct.

## Evidence labels and boundary

**FACT_FROM_SOURCE — label meaning.** A statement reported by the upstream paper or project site is labeled `FACT_FROM_SOURCE`. The label records what the authors state; it does not mean `THIS_REPOSITORY` reproduced the result.

**FACT_FROM_ARTIFACT — label meaning.** A statement directly observed in a retrieved primary artifact, the pinned public generated-artifacts tree, or a verified local artifact is labeled `FACT_FROM_ARTIFACT`.

**INFERENCE — label meaning.** A conclusion drawn from the primary sources is labeled `INFERENCE` and is not presented as an upstream-authored claim.

**PROPOSED_IMPROVEMENT — label meaning.** A requirement proposed for `THIS_REPOSITORY` at the time of reverse engineering is labeled `PROPOSED_IMPROVEMENT`. The proposal itself is not implementation evidence; current local implementation status is separately labeled `FACT_FROM_ARTIFACT` below.

**FACT_FROM_ARTIFACT — non-reproduction caveat.** This review downloaded and inspected the paper and public artifact tree, but did not run UPSTREAM_SCIENTISTONE, rerun its golden evaluators, reconstruct its 75-paper audit, call its model provider, or reproduce its GPU experiments. The public repository does not contain the full framework, golden evaluators, CoE Audit implementation, or all inputs required for those reruns.

## Primary-source inventory

| Evidence class | Source | Version and precise identity | What it supports |
|---|---|---|---|
| `FACT_FROM_SOURCE` | [Project site](https://scientist-one.github.io/) | Retrieved 2026-08-29 | Project-level architecture summary, displayed headline metrics, ADRS and generalization tables, and the link to generated outputs. |
| `FACT_FROM_SOURCE` | [arXiv abstract record](https://arxiv.org/abs/2605.26340) | arXiv:2605.26340v1, submitted 2026-05-25 | Paper identity, authorship, submission history, and links to PDF/HTML/source. |
| `FACT_FROM_SOURCE` + `FACT_FROM_ARTIFACT` | [Paper PDF](https://arxiv.org/pdf/2605.26340) and [HTML](https://arxiv.org/html/2605.26340) | 35-page v1; downloaded PDF SHA-256 `9d4fa9d1e9e6b1cdccfeff02fecbd28b5b961594952a1ac96e00ad135bed0a51` | Source-reported architecture, implementation appendix, metrics, failures, ablations, reviewer results, limitations, and baseline-adaptation details, plus retrieved-file identity. |
| `FACT_FROM_ARTIFACT` | [Generated-artifacts repository](https://github.com/scientist-one/generated-artifacts) | Repository HEAD resolved to pinned commit [`721f1fbe3b39a558dff13386c50621a357e6f9a7`](https://github.com/scientist-one/generated-artifacts/commit/721f1fbe3b39a558dff13386c50621a357e6f9a7), authored 2026-05-25T23:05:13Z; the retrieved `main` archive had SHA-256 `8164e53450ba2454b25e2c430cad16db85e4a984c69806f7478988778d34e732` | Released papers, solver files, selected-idea records, search/evaluator artifacts, and ablation artifacts. |

## Architecture and control flow

**FACT_FROM_SOURCE — three-stage architecture.** UPSTREAM_SCIENTISTONE is presented as a three-stage system: literature grounding, discovery, and paper writing plus verification. Each module is intended to emit structured artifacts carrying provenance needed by downstream verification. Source: [paper §4, pp. 4–6](https://arxiv.org/html/2605.26340#S4).

**FACT_FROM_SOURCE — Figure 1 control flow.** Figure 1 and §§4.1–4.3 show this flow:

```text
Task Definition + Seed Papers
-> Problem Investigator
   Citation Graph
   -> Elite Pool Filter
   -> Multi-Round Investigation
-> Research Brief
-> Ideator
   Conservative + Unconventional Generation
   -> Expand to Proposal
-> Parallel Explore-Exploit (PEE)
   Scatter across B branches
   -> per branch: Solve -> Evaluate -> Audit
   -> Rank + Select
   -> distilled feedback and metrics return to the Ideator
-> Best Solution + Logs + Raw Materials
-> Paper Writer
   Conceive -> Ground -> Critic -> Resolve -> Compose
-> Draft
-> Claim Verifier
   Extract Claims -> Verify Sources -> Refine
-> final paper
```

Source: [Figure 1 and §§4.1–4.3, pp. 4–6](https://arxiv.org/html/2605.26340#S4).

**FACT_FROM_SOURCE — implementation substrate.** Appendix B says the Problem Investigator stages communicate through file-backed artifacts on disk; the solver operates in a sandbox with file, command, solution-management, and knowledge-base tools; and it maintains an experimental log. Source: [Appendix B.1–B.2, pp. 20–21](https://arxiv.org/html/2605.26340#A2).

**INFERENCE — state architecture.** The disclosed authoritative intermediate is primarily a file-backed pipeline plus a Markdown research representation. The primary sources do not describe a typed, append-only canonical scientific-object graph, a hash-linked event ledger, immutable artifact identities, supersession semantics, or protocol/authority state comparable to the trusted kernel in `THIS_REPOSITORY`.

**PROPOSED_IMPROVEMENT — canonical state.** `THIS_REPOSITORY` should retain its ledger and content-addressed artifact registry as the authoritative substrate and represent upstream-like briefs, ideas, hypotheses, experiments, runs, results, challenges, reviews, and claims as typed objects rather than adopting Markdown or conversational memory as system state.

## Chain-of-Evidence and claim system

**FACT_FROM_SOURCE — CoE principle.** Chain-of-Evidence requires every claim to trace through recorded supporting claims and evidence to a grounding source. The standard is described as architecture-agnostic and author-agnostic. Source: [paper §3, p. 4](https://arxiv.org/html/2605.26340#S3).

| Evidence class | Upstream claim type | Required evidence-chain shape | Source |
|---|---|---|---|
| `FACT_FROM_SOURCE` | Citation | The cited work exists in a scholarly database and its content is consistent with the paper's description. | [§3, p. 4](https://arxiv.org/html/2605.26340#S3) |
| `FACT_FROM_SOURCE` | Numerical | The paper value traces to a recorded execution log, measurement, or simulation result. | [§3, p. 4](https://arxiv.org/html/2605.26340#S3) |
| `FACT_FROM_SOURCE` | Methodological | The method description resolves to corresponding implementation. | [§3, p. 4](https://arxiv.org/html/2605.26340#S3) |
| `FACT_FROM_SOURCE` | Conclusion | The conclusion derives from supporting numerical and/or methodological claims through verifiable reasoning. | [§3, p. 4](https://arxiv.org/html/2605.26340#S3) |

**FACT_FROM_SOURCE — coverage limit.** The paper calls the four-type taxonomy non-exhaustive and says qualitative observations and theoretical properties remain harder to automate because they require domain expertise or subjective judgment. Source: [§3, p. 4](https://arxiv.org/html/2605.26340#S3).

**FACT_FROM_SOURCE — native numerical provenance.** During writing, numerical sentences receive an annotation such as `{source: "experimental_log.md:N"}`. The `check_sources` verifier compares the number with the referenced line using 5% relative tolerance. Across 15 papers it extracted 639 numerical claims, of which 627 passed, for 98.1% raw numerical Claim Provenance Rate. The authors manually estimated that only 2–4 of the 12 failures were genuine, giving a reported corrected rate of approximately 99%. Source: [§6.2, pp. 10–11](https://arxiv.org/html/2605.26340#S6.SS2).

**INFERENCE — CPR scope.** Numerical CPR measures whether a number matches a nearby declared log source; it does not by itself establish correct metric semantics, fair selection, statistical validity, causal interpretation, or support for a conclusion.

**PROPOSED_IMPROVEMENT — expanded claim graph.** `THIS_REPOSITORY` should preserve numerical, citation, methodological, and conclusion claims while adding typed comparative, novelty, robustness, generalization, efficiency, theoretical, causal, qualitative, and limitation claims. Each claim should retain stable identity, evidence and claim dependencies, permitted strength, verification history, and failure reason.

## Problem Investigator and literature grounding

**FACT_FROM_SOURCE — input and output.** The Problem Investigator starts from task definition and seed papers, constructs a research brief, and supplies both that brief and the seed bibliography to later ideation and writing. The main text says it reads up to 100 full-text PDFs per topic. Source: [§4.1, pp. 4–5](https://arxiv.org/html/2605.26340#S4.SS1).

| Evidence class | PI stage | Reported implementation | Source |
|---|---|---|---|
| `FACT_FROM_SOURCE` | 1. Citation Graph | Start from 2–4 seed papers; traverse Semantic Scholar references and citations up to two hops; produce about 2,000–5,000 candidates. | [Appendix B.1, pp. 20–21](https://arxiv.org/html/2605.26340#A2.SS1) |
| `FACT_FROM_SOURCE` | 2. Literature Filter | Score methodology relevance and problem alignment from 1–5. `Core` requires both at least 4; `Adjacent` requires one at least 4 and the other at least 3; other tiers are `Spark` and `Noise`. The elite pool is about 500 papers. Abort if fewer than five Core+Adjacent papers exist. | [Appendix B.1, pp. 20–21](https://arxiv.org/html/2605.26340#A2.SS1) |
| `FACT_FROM_SOURCE` | 3. Multi-Round Investigation | Three rounds coordinated by a Principal Investigator: Librarian selection; five parallel Researcher agents reading PDFs and extracting structured notes; SubdomainWriter dossiers; IslandConsolidator merges redundant directions and retires weak ones. Target about 100 notes in 5–15 directions. | [Appendix B.1, pp. 20–21](https://arxiv.org/html/2605.26340#A2.SS1) |
| `FACT_FROM_SOURCE` | 4. Evaluation Protocol Audit and Refresh | Produce and rubric-score per-direction audit reports across multiple rounds until a direction passes; run a focused mini-crawl adding 20–30 notes for the winning direction. | [Appendix B.1, p. 21](https://arxiv.org/html/2605.26340#A2.SS1) |
| `FACT_FROM_SOURCE` | 5. Experiment Brief | Select directions by seed relevance and use up to five section-level critic/revision rounds. The brief covers landscape/taxonomy/best-known results; experiment plan, baselines, metrics, and ablations; and 25–40 references traceable to source-PDF notes. | [Appendix B.1, p. 21](https://arxiv.org/html/2605.26340#A2.SS1) |

**INFERENCE — source breadth.** The implementation appendix names Semantic Scholar for PI graph traversal. The broader Semantic Scholar/arXiv/OpenAlex/Crossref set is described for post-hoc reference resolution, not for the PI discovery path.

**INFERENCE — missing acquisition details.** The primary sources do not disclose a controlled egress gateway, licensing/rate-limit records, captured-response hashes, prompt-injection isolation, parser status, full-text legal availability status, or stable passage identifiers.

**PROPOSED_IMPROVEMENT — auditable literature gateway.** `THIS_REPOSITORY` should route all scholarly access through a narrow policy gateway and replaceable adapters, retain request/response hashes and licensing/retrieval status, treat content as untrusted evidence, and bind important related-work and novelty claims to exact passages and surrounding context.

## Ideation and discovery

**FACT_FROM_SOURCE — Ideator.** The Ideator consumes the PI brief, generates conservative and unconventional candidates, scores novelty and feasibility, expands selected candidates into proposals, and scatters top proposals to PEE branches. Figure 1 shows branch metrics and distilled feedback returning to the Ideator. Source: [Figure 1 and §4.2, p. 5](https://arxiv.org/html/2605.26340#S4.SS2).

**FACT_FROM_SOURCE — branch search.** PEE performs `I` iterations across `B` isolated branches. A Solver may evaluate up to `E` versions per node. At each iteration the top `K` branches survive; remaining slots are filled by fresh ideas derived from top performers. Source: [§4.2, p. 5](https://arxiv.org/html/2605.26340#S4.SS2).

**FACT_FROM_SOURCE — selection and ablation.** After search, a selector filters solutions flagged for specification violations, chooses the highest-scoring survivor, and sends it to an ablation agent. The ablation agent identifies core components, implements controlled removals or substitutions, and re-evaluates them. Source: [§4.2, p. 5](https://arxiv.org/html/2605.26340#S4.SS2), [Appendix B.3, p. 21](https://arxiv.org/html/2605.26340#A2.SS3).

**FACT_FROM_SOURCE — solver.** A Solution Development Agent iteratively executes, debugs, and optimizes validation metrics while maintaining an experimental log. A Report Writing Agent converts experimental artifacts into a technical report. Source: [Appendix B.2, p. 21](https://arxiv.org/html/2605.26340#A2.SS2).

**FACT_FROM_SOURCE — base search parameters.** The Table 6 base configuration is `I=5`, `B=5`, `K=2`, `E=4`, totaling 25 nodes. Table 3 uses the final iteration of the best of five branches, whereas Table 6 reports the best score across any node and excludes manually identified specification-violating solutions. Source: [Appendix C and Table 6, pp. 23–24](https://arxiv.org/html/2605.26340#A3).

**FACT_FROM_SOURCE — scaling result and caveat.** The paper reports width as the most effective scaling axis for TXN, but calls the configurations single-seed and directional because cross-seed variance is substantial. Source: [Appendix C and Table 6, pp. 23–24](https://arxiv.org/html/2605.26340#A3).

**FACT_FROM_SOURCE — exploit pressure.** At larger per-node budgets the fraction of flagged exploitative nodes increased. The paper reports roughly 50% and 70% of LLM-SQL nodes flagged at budgets 200 and 500, respectively, and 2–8% of Prism nodes at those budgets. Wider trees with fewer calls per node showed lower violation rates. Source: [Appendix C, pp. 23–24](https://arxiv.org/html/2605.26340#A3).

**INFERENCE — optimization hazard.** More within-branch evaluator access can teach an agent to exploit metric or specification gaps rather than improve scientific content; scaling search is therefore also scaling adversarial pressure on the evaluator.

**PROPOSED_IMPROVEMENT — discovery policy.** `THIS_REPOSITORY` should select actions by expected information value, hypothesis discrimination, scientific importance, uncertainty, and resource cost rather than copying upstream constants. It should preserve every branch and result, explicitly distinguish fresh ideas from refinements, and run deterministic specification checks before promotion.

## Research representation and paper pipeline

| Evidence class | Stage | Reported function | Source |
|---|---|---|---|
| `FACT_FROM_SOURCE` | Conceive | One model call consumes PI brief, experimental log, evaluator scores, solver code, and seed abstracts. It emits a Markdown story arc in which every factual claim has an inline evidence tag naming a log line, score entry, citation key, or ablation. | [Appendix B.4, pp. 21–22](https://arxiv.org/html/2605.26340#A2.SS4) |
| `FACT_FROM_SOURCE` | Ground | Deterministically verify score agreement, baseline traceability, referenced-artifact existence, expected sections, hyperbole, and known score mismatches. Label claims `supported`, `partial`, or `unsupported`; compute a grounding ratio. | [Appendix B.4, p. 22](https://arxiv.org/html/2605.26340#A2.SS4.SSS0.Px2) |
| `FACT_FROM_SOURCE` | Critic | Use one model call for gap–approach alignment, contradictions, overclaiming, missing comparisons, baseline fairness, and honest limitations; return pass or major/minor issues. | [Appendix B.4, p. 22](https://arxiv.org/html/2605.26340#A2.SS4.SSS0.Px3) |
| `FACT_FROM_SOURCE` | Resolve | Rewrite against Ground flags and Critic issues, dropping or softening unsupported claims, resolving contradictions against verified sources, and calibrating overclaims. | [Appendix B.4, p. 22](https://arxiv.org/html/2605.26340#A2.SS4.SSS0.Px4) |
| `FACT_FROM_SOURCE` | Loop termination | Run at most two Ground–Critic–Resolve rounds; terminate on zero flags or plateau. Abort when grounding remains below a configured threshold. | [Appendix B.4, p. 22](https://arxiv.org/html/2605.26340#A2.SS4.SSS0.Px4) |
| `FACT_FROM_SOURCE` | Compose | Per-section writers generate LaTeX from the grounded representation and commit numerical or citation-bearing sentences to evidence at writing time. | [Appendix B.4, p. 22](https://arxiv.org/html/2605.26340#A2.SS4.SSS0.Px5) |
| `FACT_FROM_SOURCE` | Refine | Rewrite flagged sentences, remove unsupported claims, strip inline annotations from final LaTeX, and promote only drafts with no blocking violations. | [Appendix B.4, p. 22](https://arxiv.org/html/2605.26340#A2.SS4.SSS0.Px5) |

**INFERENCE — provenance retention gap.** Removing inline annotations from final LaTeX is compatible with a clean manuscript, but the public artifact release does not retain a separately inspectable claim graph that would preserve those mappings after composition.

**PROPOSED_IMPROVEMENT — provenance through prose.** `THIS_REPOSITORY` should render clean prose while preserving the underlying typed claim graph, verifier receipts, source passages, table/figure derivations, and revision history as immutable review artifacts.

## Native Claim Verifier

| Evidence class | Claim class | Verification rule | Source |
|---|---|---|---|
| `FACT_FROM_SOURCE` | Numerical | Compare against cited log, ablation, or PI baseline; inspect a ±3-line log window; normalize percent/fraction and millisecond/second mismatches. | [Appendix B.5, p. 22](https://arxiv.org/html/2605.26340#A2.SS5) |
| `FACT_FROM_SOURCE` | Citation | Resolve the citation key in the bibliography and ask a one-shot JSON-mode model whether the cited abstract supports the assertion. | [Appendix B.5, p. 22](https://arxiv.org/html/2605.26340#A2.SS5) |
| `FACT_FROM_SOURCE` | Methodological | Check substantive textual overlap with the cited region of the experimental log. | [Appendix B.5, p. 22](https://arxiv.org/html/2605.26340#A2.SS5) |
| `FACT_FROM_SOURCE` | Unsourced or malformed | Drop the claim automatically and record a break code for reporting. | [Appendix B.5, p. 22](https://arxiv.org/html/2605.26340#A2.SS5) |

**INFERENCE — semantic depth.** Abstract entailment is stronger than bibliography existence but weaker than locating a supporting full-text passage and checking whether surrounding context contradicts the claim.

**PROPOSED_IMPROVEMENT — reference levels.** `THIS_REPOSITORY` should distinguish reference existence, resolution, metadata agreement, passage location, semantic support, and contextual non-contradiction instead of calling all of them “verified.”

## CoE Integrity Audit

**FACT_FROM_SOURCE — normalized bundle.** CoE Audit adapts each system's `paper.tex`, solution code, and `references.bib` to a common bundle, then runs four independent checks. Source: [Figure 2 and §5, pp. 6–7](https://arxiv.org/html/2605.26340#S5).

| Evidence class | Check | Inputs and procedure | Result semantics | Source |
|---|---|---|---|---|
| `FACT_FROM_SOURCE` | I1 Score Verification | Extract paper score with a model from TeX/PDF; rerun submitted code on the golden evaluator; compare deterministically within adaptive tolerance. Evaluators are run five times and tolerance is `max(1%, 3σ/abs(mean))`. | match / mismatch | [§5, pp. 6–7](https://arxiv.org/html/2605.26340#S5) and [§6, p. 7](https://arxiv.org/html/2605.26340#S6) |
| `FACT_FROM_SOURCE` | I2 Specification Violation | Model judges inspect solution code against evaluator and task specification; combine independent judgments by majority vote. | clean / flagged | [§5, p. 7](https://arxiv.org/html/2605.26340#S5) |
| `FACT_FROM_SOURCE` | I3 Reference Verification | Resolve arXiv ID, DOI, or title through Semantic Scholar, arXiv, OpenAlex, and Crossref; use a model to disambiguate near-misses. | verified / hallucinated | [§5, p. 7](https://arxiv.org/html/2605.26340#S5) |
| `FACT_FROM_SOURCE` | I4 Method–Code Alignment | Model judges compare paper method and submitted code; acceptable omission is aligned, fundamental algorithm mismatch is not; use majority vote. | aligned / misaligned | [§5, p. 7](https://arxiv.org/html/2605.26340#S5) |

**FACT_FROM_SOURCE — automation and human review.** Table 7 identifies Gemini 3 Flash for I1 extraction and I3 disambiguation and Gemini 3.1 Pro for I2 and I4 judgments. Human reviewers manually checked and corrected all flagged I1–I3 positives before Table 1; I4 received sampled human validation only. Source: [Appendix D.1 and Table 7, p. 24](https://arxiv.org/html/2605.26340#A4.SS1).

**FACT_FROM_SOURCE — post-hoc scope.** The paper says the demonstrated audit covers tractably verifiable structural integrity and that broader claim coverage and real-time verification are outside the audit's scope. Source: [§5, p. 6](https://arxiv.org/html/2605.26340#S5).

**INFERENCE — fail-closed limit.** A majority-vote model check is probabilistic and cannot serve as the sole fail-closed authority for evaluator access, leakage, artifact identity, numerical equality, or other properties deterministic code can verify.

## Reported experiments and results

**FACT_FROM_SOURCE — evaluation design.** The primary audit covers 75 papers: five systems, five ADRS tasks, three seeds per system/task. Baselines use Gemini 3.1 Pro, up to 20 solver iterations, two-hour code-generation windows, and retries only for infrastructure failures. Sixteen runs required at least one infrastructure retry; the authors state no run was retried to improve score. Source: [§6, pp. 7–8](https://arxiv.org/html/2605.26340#S6).

**FACT_FROM_SOURCE — CoE Audit Table 1.** EPLB is excluded from I1 because its runtime-sensitive score is hardware-dependent.

| System | I1 score match | I2 violations | I3 hallucinated entries | I4 aligned papers |
|---|---:|---:|---:|---:|
| Sakana AI-Scientist v2 | 5/12 | 10/15 | 0/159 | 5/15 |
| AutoResearchClaw | 5/12 | 0/15 | 3/196 | 3/15 |
| DeepScientist | 11/12 | 0/15 | 42/201 | 5/15 |
| AI-Researcher | 9/12 | 1/15 | 21/222 | 12/15 |
| UPSTREAM_SCIENTISTONE | 12/12 | 0/15 | 0/337 | 14/15 |

Source: [§6.1 and Table 1, pp. 8–10](https://arxiv.org/html/2605.26340#S6.SS1).

**FACT_FROM_SOURCE — automated reviewer Table 2.** ScholarPeer, backed by `gemini-3.1-pro-preview` with literature search, supplied automated review scores; it was not human peer review.

| UPSTREAM_SCIENTISTONE regime | Soundness /4 | Originality /4 | Quality /4 | Clarity /4 | Overall /10 | Accept |
|---|---:|---:|---:|---:|---:|---:|
| Average of 15 papers | 2.3 | 2.5 | 2.3 | 3.0 | 4.5 | 6/15 |
| Best of three seeds per task | 2.8 | 3.0 | 2.8 | 3.6 | 6.6 | 4/5 |

Source: [§6.3 and Table 2, pp. 11–12](https://arxiv.org/html/2605.26340#S6.SS3).

**FACT_FROM_SOURCE — ADRS Table 3.** The comparison reports best-of-three scores. UPSTREAM_SCIENTISTONE ties the Prism ceiling, has the best listed Cloudcast and EPLB scores, and does not lead LLM-SQL or TXN. The authors state that solver scores cluster tightly across systems. Source: [§6.4 and Table 3, p. 12](https://arxiv.org/html/2605.26340#S6.SS4).

| ADRS task | Direction | Human | UPSTREAM_SCIENTISTONE | Best listed comparator |
|---|---:|---:|---:|---:|
| Prism | up | 21.89 | 26.26 | 26.26, tied by several systems |
| Cloudcast | down | 626.24 | 618.08 | 620.09 DeepScientist |
| EPLB | up | 0.1265 | 0.1459 | 0.1453 EvoX |
| LLM-SQL | up | 0.6920 | 0.7222 | 0.7520 AdaEvolve |
| TXN | up | 2724.8 | 3906 | 4311 AI-Researcher |

**FACT_FROM_SOURCE — MLE/Parameter Golf Table 4.** The paper reports these results:

| Task | Direction | UPSTREAM_SCIENTISTONE score | Reported standing |
|---|---:|---:|---|
| 3D Object Detection | up | 0.1763 | Gold |
| AI4Code | up | 0.8356 | Above Median |
| iMet 2020 FGVC7 | up | 0.6791 | Silver |
| RSNA Brain Tumor | up | 0.6518 | Gold |
| iNaturalist 2019 FGVC6 | down | 0.2445 | Silver |
| Parameter Golf | down | 1.0600 | Reported top-1 as of 2026-04-27, with constraints met |

Source: [§7 and Table 4, pp. 13–14](https://arxiv.org/html/2605.26340#S7).

**FACT_FROM_SOURCE — MLE compute and evaluation protocol.** MLE runs used 8 H100 GPUs, 192 CPU cores, and 1 TB RAM. The agent could query formatting validation without limit and the test grading server up to 16 times. The authors state that the grading server was used sparingly to select the best-performing models on the test set, explicitly departing from MLE-Bench's single-final-submission protocol. Source: [Appendix F, pp. 32–33](https://arxiv.org/html/2605.26340#A6).

**FACT_FROM_SOURCE — Parameter Golf novelty claim.** The paper attributes the reported Parameter Golf improvement to Hessian-diagonal-weighted SVD initialization and a GPTQ-based alternating-least-squares refinement loop and states that internal ablations identify ALS as the primary driver. Source: [§7, p. 14](https://arxiv.org/html/2605.26340#S7).

**INFERENCE — selection regime.** Best-of-three ADRS reporting, best-branch selection, search over many nodes, and MLE test-server selection are exploratory selection regimes. They do not by themselves constitute protected confirmatory evidence or an unbiased estimate of expected performance.

## Published generated artifacts

**FACT_FROM_ARTIFACT — release inventory.** The pinned commit message and inspected tree contain 21 PDFs: 15 ADRS, five MLE-Bench, and one Parameter Golf; 15 standalone ADRS `.py` solver files; five MLE workspaces with search artifacts; and one Parameter Golf workspace with search artifacts. Source: [pinned commit](https://github.com/scientist-one/generated-artifacts/commit/721f1fbe3b39a558dff13386c50621a357e6f9a7).

**FACT_FROM_ARTIFACT — artifact asymmetry.** The ADRS release contains only one solver file per paper, while the MLE and Parameter Golf directories contain selected ideas, agent logs, solver candidates, evaluator metrics, state/status files, and ablation artifacts.

**FACT_FROM_ARTIFACT — missing audit bundle.** The pinned tree contains no `.tex`, `.bib`, submission CSV, named claim/provenance/evidence record, PI research brief, golden evaluator, CoE Audit implementation, or full UPSTREAM_SCIENTISTONE framework source. MLE evaluation JSON records point to unavailable internal absolute paths for submission CSVs.

**INFERENCE — public reproducibility.** The specified public repository cannot independently regenerate Table 1, rerun the full claim-provenance audit, reproduce the PI literature process, or reconstruct all claimed evaluator outputs without additional code, data, prompts, provider access, and evaluators.

**FACT_FROM_ARTIFACT — Parameter Golf selector.** The released selector chooses iteration 4, branch 1 at `1.0599987899999999`; it reports eight audited solutions out of 16 search solutions and rejects several shortlisted solutions for `idea_mismatch` or `trivial`. Source: [pinned `bestrun_selection.json`](https://github.com/scientist-one/generated-artifacts/blob/721f1fbe3b39a558dff13386c50621a357e6f9a7/solution-code/parameter-golf/bestrun_selection.json).

**FACT_FROM_ARTIFACT — selected hypothesis.** The selected Parameter Golf idea includes a named hypothesis that Hessian-weighted SVD initialization should improve initial and final weighted quantization error, plus risks involving diagonal-Hessian approximation, numerical instability, and potentially marginal gain. Source: [pinned `selected_idea.yaml`](https://github.com/scientist-one/generated-artifacts/blob/721f1fbe3b39a558dff13386c50621a357e6f9a7/solution-code/parameter-golf/search_artifacts/ideator/selected_idea.yaml).

**FACT_FROM_ARTIFACT — partial ablations.** The released Parameter Golf ablation JSON has non-null aggregates for Cholesky-weighted initialization and removal of ALS, but null aggregates for unweighted-SVD and random initialization. Source: [pinned `ablation_results.json`](https://github.com/scientist-one/generated-artifacts/blob/721f1fbe3b39a558dff13386c50621a357e6f9a7/solution-code/parameter-golf/ablation/ablation_results.json).

**INFERENCE — novelty evidence limit.** The public evidence supports that UPSTREAM_SCIENTISTONE generated and tested the recorded proposal. It does not independently establish global novelty, complete prior-art exclusion, or the paper's stronger causal statement that ALS is the primary driver because the released ablation matrix is incomplete.

## Failures and limitations

**FACT_FROM_SOURCE — UPSTREAM_SCIENTISTONE method mismatch.** One Cloudcast paper described a hybrid neuro-symbolic, LLM-guided evolutionary solver, while submitted code was a deterministic routing heuristic with no LLM calls. It is the system's one paper-level I4 failure. Source: [§6.1, p. 10](https://arxiv.org/html/2605.26340#S6.SS1).

**FACT_FROM_SOURCE — UPSTREAM_SCIENTISTONE specification-audit false negative.** An UPSTREAM_SCIENTISTONE LLM-SQL solver used the same column-permutation exploit found in other systems. Only one of five I2 judges flagged it, so the majority-vote table counted the paper as clean. Source: [Appendix A.1 Case 3, pp. 19–20](https://arxiv.org/html/2605.26340#A1.SS1).

**FACT_FROM_SOURCE — UPSTREAM_SCIENTISTONE I4 finding shape.** Table 14 attributes five I4 findings to UPSTREAM_SCIENTISTONE: four algorithm-class mismatches and one incomplete/broken mechanism. Source: [Appendix E.4 and Tables 13–14, pp. 31–32](https://arxiv.org/html/2605.26340#A5.SS4).

**FACT_FROM_SOURCE — reference depth.** I3 establishes existence and metadata resolution, not whether a full-text passage supports the cited claim. The paper identifies passage-level natural-language inference as future work. Source: [§9, p. 15](https://arxiv.org/html/2605.26340#S9).

**FACT_FROM_SOURCE — reviewer proxy.** ScholarPeer is a scalable automated proxy and does not replace human expert review; model reviewers can miss domain-specific score interpretation and specification violations. Source: [§9, p. 15](https://arxiv.org/html/2605.26340#S9).

**FACT_FROM_SOURCE — research-soundness bottleneck.** Across systems, clarity exceeded soundness. The two most frequent review complaints were missing head-to-head comparisons with published baselines and proxy-only evaluation without end-to-end system measurement. UPSTREAM_SCIENTISTONE also exhibited high seed variance and qualitative overclaims that numerical verification did not catch. Source: [§6.3, pp. 11–12](https://arxiv.org/html/2605.26340#S6.SS3).

**FACT_FROM_SOURCE — domain coverage.** The demonstrated CoE audit centers on systems-optimization tasks with deterministic evaluators. Wet-lab protocols, simulation reproducibility, proof sketches, and open-ended biology, materials science, and theoretical ML verification were not built or tested. Source: [§9, p. 15](https://arxiv.org/html/2605.26340#S9).

**FACT_FROM_SOURCE — audit false negatives.** I1–I3 flagged positives were manually checked, but false negatives were not systematically bounded. I4 was only sampled by humans and the table retains majority-vote judgments. Source: [§9, pp. 15–16](https://arxiv.org/html/2605.26340#S9).

**FACT_FROM_SOURCE — benchmark depth.** ADRS compresses systems research into single-metric solver optimization. The authors explicitly state that competitive ADRS solver performance should not be equated with competitive systems research. Source: [§9, p. 16](https://arxiv.org/html/2605.26340#S9).

**FACT_FROM_SOURCE — baseline adaptation caveat.** Baseline adaptations were uneven: Sakana changed 16 files, AutoResearchClaw two, DeepScientist prompt-only, and AI-Researcher 19. The paper asks readers to interpret comparisons as good-faith equal-resource adaptations rather than definitive rankings. Source: [§9, p. 15](https://arxiv.org/html/2605.26340#S9), [Appendix G, pp. 33–35](https://arxiv.org/html/2605.26340#A7).

**INFERENCE — “human-level” boundary.** The title and site use “human-level,” but the paper's own limitation confines the evidence to competitive solver performance on benchmark tasks. The primary sources do not establish human-level problem formulation, scientific judgment, domain-valid experimentation, causal inference, or human peer-review quality.

## Feature evidence table

**INFERENCE — table timing.** The local-implication column preserves the design targets derived during the upstream review. It should be read together with the current implementation checkpoint that follows, not as a claim that every target remains merely proposed.

| Capability | Evidence class | Upstream evidence | Reverse-engineered conclusion | Local implication |
|---|---|---|---|---|
| CoE claim taxonomy | `FACT_FROM_SOURCE` | [§3, p. 4](https://arxiv.org/html/2605.26340#S3) | Four primary, non-exhaustive claim classes. | `PROPOSED_IMPROVEMENT`: extend typed coverage and permitted-strength rules. |
| Literature graph | `FACT_FROM_SOURCE` | [Appendix B.1, pp. 20–21](https://arxiv.org/html/2605.26340#A2.SS1) | Two-hop Semantic Scholar graph from 2–4 seeds. | `PROPOSED_IMPROVEMENT`: replaceable multi-source adapters behind audited egress. |
| Full-text reading | `FACT_FROM_SOURCE` | [§4.1, pp. 4–5](https://arxiv.org/html/2605.26340#S4.SS1) | Up to 100 PDFs and structured notes. | `PROPOSED_IMPROVEMENT`: stable passage identities, content hashes, legal availability status. |
| Research brief | `FACT_FROM_SOURCE` | [Appendix B.1, p. 21](https://arxiv.org/html/2605.26340#A2.SS1) | Landscape, experiment plan, baselines, metrics, ablations, traced literature. | `PROPOSED_IMPROVEMENT`: typed brief generated from canonical evidence state. |
| Ideation | `FACT_FROM_SOURCE` | [Figure 1, p. 5](https://arxiv.org/html/2605.26340#S4) | Conservative and unconventional proposal generation. | `PROPOSED_IMPROVEMENT`: explicit novelty and hypothesis registers with disconfirming search. |
| PEE search | `FACT_FROM_SOURCE` | [§4.2, p. 5](https://arxiv.org/html/2605.26340#S4.SS2) | Parallel branches, retained leaders, and fresh ideation. | `PROPOSED_IMPROVEMENT`: information-value policy and complete branch retention. |
| Specification audit | `FACT_FROM_SOURCE` | [§5, p. 7](https://arxiv.org/html/2605.26340#S5) | Model-majority inspection of code/evaluator/spec. | `PROPOSED_IMPROVEMENT`: deterministic rules and inaccessible evaluators before semantic judgment. |
| Research representation | `FACT_FROM_SOURCE` | [Appendix B.4, pp. 21–22](https://arxiv.org/html/2605.26340#A2.SS4) | Markdown narrative with inline evidence annotations. | `PROPOSED_IMPROVEMENT`: typed claim graph is authoritative; Markdown is a view. |
| Ground | `FACT_FROM_SOURCE` | [Appendix B.4, p. 22](https://arxiv.org/html/2605.26340#A2.SS4.SSS0.Px2) | Deterministic artifact and numeric checks plus grounding ratio. | `PROPOSED_IMPROVEMENT`: preserve deterministic-first policy and artifact freshness checks. |
| Critic/Resolve | `FACT_FROM_SOURCE` | [Appendix B.4, p. 22](https://arxiv.org/html/2605.26340#A2.SS4) | Semantic critique and evidence-calibrated rewrite. | `PROPOSED_IMPROVEMENT`: independent challenger and typed blocking findings. |
| Citation verification | `FACT_FROM_SOURCE` | [Appendix B.5, p. 22](https://arxiv.org/html/2605.26340#A2.SS5), [§9, p. 15](https://arxiv.org/html/2605.26340#S9) | Abstract entailment natively; existence/metadata in I3; no passage-level context check. | `PROPOSED_IMPROVEMENT`: passage-level support and contextual contradiction checks. |
| Numerical CPR | `FACT_FROM_SOURCE` | [§6.2, pp. 10–11](https://arxiv.org/html/2605.26340#S6.SS2) | 627/639 raw matches; approximately 99% manually corrected claim. | `PROPOSED_IMPROVEMENT`: bind metric semantics, units, selection regime, and statistical inference. |
| Research soundness | `FACT_FROM_SOURCE` | [§6.3, pp. 11–12](https://arxiv.org/html/2605.26340#S6.SS3) | Missing strong baselines, proxy-only evaluation, and qualitative overclaiming remain. | `PROPOSED_IMPROVEMENT`: mandatory soundness gate with hard blockers. |
| Public reproducibility | `FACT_FROM_ARTIFACT` | [Pinned repository commit](https://github.com/scientist-one/generated-artifacts/commit/721f1fbe3b39a558dff13386c50621a357e6f9a7) | Generated outputs are public, but complete framework/audit/evaluator/provenance bundle is not. | `PROPOSED_IMPROVEMENT`: publish immutable manifests and complete review/reproduction bundles. |

## THIS_REPOSITORY implementation checkpoint

**INFERENCE — comparison boundary.** This section records only how `THIS_REPOSITORY` responded architecturally to the reverse-engineered floor. It does not amend the upstream facts, reproduce upstream results, or establish a performance ranking.

| Derived local target | Current FACT_FROM_ARTIFACT | Remaining boundary |
|---|---|---|
| Canonical state and expanded claims | [`research_state.py`](../src/scientist_one/research_state.py) implements append-only canonical objects for the required research lifecycle, expanded typed claims, content-bound relationships, and registry/ledger materialization. [`claims.py`](../src/scientist_one/claims.py) requires a complete bounded evidence graph with independent verification receipts. | Final frozen verification counts and hashes are reported elsewhere; these structures do not establish scientific truth by themselves. |
| Controlled literature and citation depth | [`external.py`](../src/scientist_one/external.py) and [`literature.py`](../src/scientist_one/literature.py) record policy, request, raw response, parsed record, passage, and verification provenance. The integrated synthetic fixture reaches exact passage/context `LEVEL_5`. | Live scholarly access remains `BLOCKED_EXTERNAL`; synthetic records cannot establish real-world novelty or source coverage. |
| Problem investigation and discovery | [`scientific_design.py`](../src/scientist_one/scientific_design.py) enforces evidence-checked questions, baselines, ablations, and gap-destroying prior evidence; [`discovery.py`](../src/scientist_one/discovery.py) retains promoted, negative, null, invalid, and terminated outcomes. | The exercised investigation and branches are synthetic, not a comparable reproduction of upstream PI breadth or PEE performance. |
| Deterministic-first experiment and statistics | [`experiments.py`](../src/scientist_one/experiments.py) and [`research_os.py`](../src/scientist_one/research_os.py) run a frozen real local subprocess, all declared seeds, a fair required baseline, an ablation, paired inference, immutable output promotion, and a second clean system rerun. | The fixture is explicitly `NON_EVIDENTIARY`; `LOCAL_MAC` lacks an OS-enforced experiment sandbox, and `GPU_CLOUD` is boundary-tested only and `UNTESTED`. |
| Provider boundary | [`providers.py`](../src/scientist_one/providers.py) supplies a capability-oriented OpenAI Responses implementation behind audited egress with strict structured output and preserved failure provenance. | The integrated call is an offline fixture; live credential/service availability is external and unvalidated. |
| Domain validity | [`domains.py`](../src/scientist_one/domains.py) implements typed validity adapters for Generic ML, medical imaging, time series, recommender systems, operations research, and systems; Generic ML is integrated end to end. | Real-domain performance and external validity remain untested. |
| Challenger and scientific gates | [`gates.py`](../src/scientist_one/gates.py) separates human policy from complete typed scientific soundness, retains unresolved challenges, and blocks release without synthesizing E4. | The integrated fixture correctly ends `MORE_EXPERIMENTS_REQUIRED` / `BLOCKED_SCIENTIFICALLY`; this is gate behavior, not proof of a sound research result. |
| Evidence-first composition | [`paper_pipeline.py`](../src/scientist_one/paper_pipeline.py) checks metrics, claims, sources, assets, limitations, soundness, and hard blockers against an authoritative bundle; the fixture records paper `BLOCKED` and venue `NOT_READY`. | The current integration creates a machine-verifiable paper candidate and readiness assessment, not a generated scientific manuscript or submission-ready package. |

**INFERENCE — conservative local capability ceiling.** These earlier exercised capabilities support a provisional `AUTONOMOUS_EXPLORATION_READY` ceiling for bounded synthetic exploration, not final acceptance of the current DEVELOPMENT / REVIEW tree. The [current handoff](../OVERNIGHT_REPORT.md#development--review-checkpoint-september-23-2026) preserves later failures and unfinished verification. Neither these source observations nor synthetic fixtures establish `REAL_EXPERIMENT_PIPELINE_READY`, `RESEARCH_GRADE`, `SUBMISSION_PIPELINE_READY`, or empirical superiority.

## Final evidence boundary

**FACT_FROM_SOURCE — supported conclusion.** The primary sources support that UPSTREAM_SCIENTISTONE implements a literature-to-discovery-to-writing pipeline with explicit evidence annotations, deterministic and model-based verification stages, parallel branch search, and published generated outputs.

**INFERENCE — unsupported conclusion.** The primary sources do not establish that all reported results are independently reproducible, that citation use is passage-supported, that audit false-negative rates are bounded, that search results are confirmatory, or that the system performs human-level science across open-ended domains.

**INFERENCE — reference-floor rule.** `THIS_REPOSITORY` treats these capabilities as a reference floor and claims a narrow architectural advantage only where local implementation, integration, and verification evidence supports that dimension. Design intent and synthetic fixture success do not support an aggregate ranking.

**INFERENCE — empirical boundary.** No comparable UPSTREAM_SCIENTISTONE experiment was run in `THIS_REPOSITORY`. Empirical superiority, parity, and inferiority are therefore all **NOT ESTABLISHED**; the only permitted empirical verdict is `NOT_YET_ESTABLISHED` until a fair matched protocol is executed.
