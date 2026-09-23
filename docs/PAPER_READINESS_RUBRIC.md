# Paper-Readiness Authority and Rubric

The authoritative machine-readable scoring rubric is `configs/paper_readiness_rubric.json`. It was frozen before the bundled demonstration result. Changing it after observing results creates a new evaluation version with explicit lineage.

The rubric totals 100 points and requires at least 85, with per-category floors. It measures question precision (8), novelty evidence (8), falsifiability (7), methodological validity (12), baseline fairness (8), experimental design (10), statistical validity (10), ablations and robustness (8), negative controls (5), reproducibility (8), claim-evidence alignment (8), writing clarity (4), limitations (2), and artifact quality (2).

This score is only one input. The vNext evidence-first paper pipeline is the controlling authority for paper and venue readiness, and no score can override a mandatory scientific gate or hard blocker.

## Evidence-first candidate boundary

A `PaperCandidate` is a machine-verifiable candidate boundary, not proof that a paper was generated or is publishable. It must be derived from an `AuthoritativeResearchBundle` that binds:

- the canonical research-state artifact and claim graph;
- eligible, scoped claims and their distinct verifier receipts;
- evidence, metric semantics, results, method-code mappings, generated tables/figures, and limitations;
- baseline completeness and fairness, leakage and evaluator-exploitation findings, statistical validity, novelty, selection integrity, and clean reproduction; and
- challenger findings, the soundness verdict, external-validity status, and venue-family assessment.

The bundle is registry-derived rather than caller-authoritative. Construction and paper verification re-resolve the exact frozen research-state, claim-graph, evidence, metric, method-code, and soundness artifacts; recompute claim eligibility and metric values; and reject substituted, stale, malformed, or provenance-incomplete inputs. Markdown, prose, tables, and figures are views over that bundle. They may not add a citation, result, comparison, or conclusion that the structured state does not support.

## Superiority-promotion boundary

Value-only superiority validation is diagnostic. `validate_superiority_claim` can check arithmetic consistency, declared baselines, metric direction/scope, supplied statistics, and evaluator shape, but it returns `DIAGNOSTIC_ONLY` with `authoritative=false`; caller-supplied values and hashes cannot authorize scientific promotion.

The only implemented promotion path is the checked registry path. It resolves exact frozen artifacts for the evaluation contract, an independently produced scientific-evidence eligibility receipt, the aggregate result, statistical analysis, and evaluator assessment. The eligibility receipt must bind the contract, aggregate, frozen run specification, and output manifest and must attest confirmatory scientific evidence, verified execution isolation and protocol separation, and attested network status. The checker validates roles, schemas, canonical bytes, hashes, ordered parents, and registry closure, then deterministically recomputes the material observations, baseline identity, effect, confidence interval, exact test, sample size, metric unit/direction/scope, and evaluator result. Only the resulting checked promotion receipt, re-resolved at use time, can carry `SCIENTIFIC_PROMOTION_AUTHORIZED`.

An aggregate field such as `scientific_evidence_eligible=true`, a SHA-shaped value, or a serialized evaluator pass is never sufficient authority by itself. Unsupported tests, multiplicity families, execution chains, or evidence classes fail closed rather than being generalized from the currently implemented checked protocol.

## Challenger and soundness authority

A soundness decision must bind one registry-verified receipt for each of 15 dimensions: question validity, novelty, technical correctness, dataset validity, baseline completeness, evaluator validity, statistics, robustness, ablations, generalization, compute fairness, end-to-end evidence, alternative explanations, limitations, and reproducibility. It must also bind one Challenger review for each of 14 categories: prior art, experimental design, implementation, leakage, statistics, baselines, compute fairness, evaluator gaming, confounding, alternative explanation, seed dependence, external validity, reproduction, and overclaiming, plus every referenced finding.

Completeness is exact, not a narrative checklist. Inputs are normalized into the declared dimension/category order; missing, duplicate, substituted, noncanonical, role-invalid, or parent-incomplete receipts fail closed. A local dimension marked `PASS` for a bounded fixture control does not convert non-evidentiary execution into scientific authority, and unresolved major or blocking findings constrain the overall verdict.

## Mandatory blockers

The verifier fails closed for these hard-blocker classes:

- fabricated or unsupported references;
- irreproducible headline results;
- unresolved leakage or evaluator exploitation;
- omitted `MUST_RUN` baselines;
- method-code or table-prose contradictions;
- invalid statistics or selection bias;
- unsupported novelty or central claims;
- failed clean reproduction; and
- unresolved blocking challenger findings or a non-passing soundness verdict.

Security failure, failed mandatory R0–R7 checks, contaminated confirmation resources, unsupported material claims, and unverifiable citations likewise block candidacy. E1 self-review is advisory. E4 is human-only and cannot be issued by the program.

## Venue assessment

Venue scoring is family-specific and covers question/importance, novelty, technical correctness, evidence quality, statistics, robustness/ablations, reproducibility, clarity, limitations, and venue fit. The supported assessment families are ML/AI, medical imaging, operations research, and systems; each profile adds its own required sections and artifacts. Per-dimension scores and thresholds remain subordinate to hard blockers:

- any hard blocker yields `NOT_READY`;
- an otherwise adequate record with required external validation still incomplete may be `UNCERTAIN`; and
- only a blocker-free, evidence-backed record can advance to a positive venue-readiness status.

A venue assessment is not acceptance prediction and never replaces E4 release judgment.

### Same-round paper and Venue readback

Native final Venue ownership shares the complete paper, current manuscript,
readiness and canonical projection validators. A private chronological replay
context prevents the later review from recursively reopening its own audit; it
does not replace source ownership. Exact audited-to-final state bindings,
completed Soundness, current sources, semantic corrections/conflicts and paired
registry/ledger freshness remain mandatory. Only an earlier, fully verified
canonical review may be reused. Current, later, unrelated and scientific-core
objects cannot enter that context, and review reuse grants no scientific
evidence eligibility. Historical manuscript predecessors retain immutable-only
replay; the current manuscript still requires fresh scientific writing gates.

Actual gateway admissions, bundle issuance and manuscript issuance must precede
the canonical Venue event in the verified ledger. Venue `assessed_at` retains
its existing meaning: the last dimension in canonical dimension order, not the
maximum timestamp or a publication clock. The paper-terminal timestamp ceiling
therefore applies to terminal Decisions, not to a Venue event after a backward
clock adjustment. Internal paper source chronology and full event ownership
are unchanged.

Final Venue publication preflights exact bytes, complete metadata and registry
capacity; compares a locked registry/ledger snapshot before writing; verifies
exactly zero or one new artifact and no ledger change; and performs complete
public readback after releasing the locks. Identical retries must match all
metadata, including the stored timestamp. Ordinary historical/bound fixture
Venue ownership is preserved separately; a newly related fixture Venue lacks
the complete native projection and is not a same-round exemption.

These source boundaries passed scoped regression verification (root788 distinct
affected tests) and independent source review. This is not evidence of a genuine
positive scientific Venue lifecycle or final full-suite acceptance. The exact
checkpoint and verification limits are recorded in `.run/STATE.json` (D069).

## Integrated fixture classification

The integrated vNext fixture exercises paper-candidate construction and deterministic rejection; it records `paper_generated=false`. Its provider/literature records are captured synthetic fixtures, its experiment artifacts are explicitly non-evidentiary, real-world novelty is unsupported, generalization/external validity is untested, and soundness requires more experiments. Its comparison is registered only as a `superiority_promotion_diagnostic` with `DIAGNOSTIC_ONLY`, `authoritative=false`, `scientific_evidence_eligible=false`, and `scientific_promotion_authorized=false`. That diagnostic is excluded from the paper bundle's authoritative evidence, while `required_baselines_complete` and `statistics_valid` remain false for scientific-paper authority. It is therefore scientifically blocked and venue `NOT_READY`, even if its bounded system-integrity controls and internal score pass.

This conservative classification is intentional. It demonstrates that the paper pipeline does not convert a complete software fixture into a scientific claim, and it provides no empirical evidence of superiority over upstream ScientistOne.
