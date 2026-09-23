# Research OS vNext Preparation Report

Date: 2026-08-29

Status: **PREPARATION COMPLETE; BUILD EXECUTION NOT STARTED**

## Outcome

The repository-aware design from the shared ChatGPT conversation has been converted into a durable specification and execution-control structure. The initial greenfield framing was intentionally discarded because the current repository already contains a substantial trusted research-control kernel.

No project tests, audits, demos, provider calls, network acquisition, experiments, reproduction, packaging, baseline commands, or vNext implementation were run in this preparation pass.

## Structure added

```text
ScientistOne/
├── RESEARCH_OS_VNEXT_META_SPEC.md
├── AGENTS.md
├── .run/
│   ├── GOAL.md
│   ├── STATE.json
│   ├── DECISIONS.md
│   └── ISSUES.md
└── docs/
    ├── VNEXT_PREPARATION_REPORT.md
    ├── baseline_before_vnext.md
    ├── upstream_scientistone_reverse_engineering.md
    ├── upstream_scientistone_comparison.md
    └── benchmarks/
        └── SCIENTISTONE_BEYOND_TARGET.md
```

## File-by-file changes

### `RESEARCH_OS_VNEXT_META_SPEC.md`

Created the authoritative vNext constitution. It merges the shared chat's repository-aware correction with its detailed scientific-control requirements, including:

- preservation and independent verification of the current kernel;
- before/after zero-regression requirements;
- upstream ScientistOne reverse engineering and evidence-based comparison;
- typed research state, claim-evidence, citation-depth, hypothesis, Evaluation Contract, baseline, fair-comparison, statistical, and best-run controls;
- a controlled network/literature boundary;
- one OpenAI reference provider plus replaceable provider interfaces;
- Problem Investigator, novelty, discovery, experiment, compute, and domain systems;
- configurable human gates without weakening mandatory scientific gates;
- strict preservation of human-only E4 semantics;
- challenger, falsification, research-soundness, paper, venue, reproducibility, and adversarial-testing requirements;
- a clear long-run stopping condition and final report contract.

### `AGENTS.md`

Created concise repository-wide operating rules. It defines the reading order, preservation invariants, naming separation between upstream ScientistOne and this repository, evidence-claim rules, external-boundary behavior, and the preparation/execution boundary.

### `.run/GOAL.md`

Created the ready-to-paste `/goal` prompt. It points to the meta-spec, defines the required initial baseline freeze, orders the upgrade, names non-negotiable constraints, requires compact checkpoints, handles optional external blockers, and includes a verifiable completion condition.

### `.run/STATE.json`

Initialized resumable orchestration state as `PREPARED_NOT_STARTED`. Historical `364/364` and `15/15` results are explicitly labeled reported and not newly reverified. The next action is to start the prompt in `.run/GOAL.md`.

### `.run/DECISIONS.md`

Recorded preparatory decisions: existing-kernel treatment, three-layer authority model, upstream/local naming, OpenAI as the first reference provider, initial scholarly-source set, separation of human and scientific gates, E4 preservation, no-execution boundary, and the non-scientific role of the `.run` ledger.

### `.run/ISSUES.md`

Recorded no current preparation blocker and listed expected external boundaries for credentials, scholarly APIs, full text, GPU/cloud access, sensitive datasets, and independent human authority. It also identifies implementation choices that should be resolved from evidence during the goal rather than blocking preparation.

### `docs/baseline_before_vnext.md`

Created a deliberately unverified baseline template. It requires exact commands, identities, digests, results, custody/release status, and preserved guarantees before consequential vNext edits.

### `docs/upstream_scientistone_reverse_engineering.md`

Created a primary-source analysis template that forces separation of sourced fact, inference, and proposed local improvement.

### `docs/upstream_scientistone_comparison.md`

Created a comparison template separating architectural from empirical verdicts across security, provenance, protocol, research intelligence, experimentation, writing, compute, domains, and autonomy.

### `docs/benchmarks/SCIENTISTONE_BEYOND_TARGET.md`

Created the target-definition template that prohibits unsupported “beats ScientistOne” claims and requires comparable evidence for empirical superiority.

## Preparatory defaults locked in

- First working provider: OpenAI, behind provider-neutral capability interfaces.
- Initial scholarly source set: OpenAlex, Semantic Scholar, Crossref, arXiv, and PubMed/PMC, with controlled general web search only when needed.
- External content: untrusted evidence only, never executable control instructions.
- Human approval: configurable independently from mandatory scientific gates.
- E4: remains human-only and may never be synthesized.
- Current historical results: reported until the future goal reproduces them.

## Structural verification performed

- Confirmed every planned file exists.
- Parsed `.run/STATE.json` successfully as JSON.
- Checked cross-file names for the final `RESEARCH_OS_VNEXT_META_SPEC.md` convention.
- Checked that historical baseline numbers are labeled reported/not reverified.
- Checked that the upstream/local naming and E4 constraints appear consistently.

This structural verification is not project execution and does not establish any vNext scientific, software, provider, network, or compute capability.

## Start command

Use the command block in `.run/GOAL.md`. The first line begins with `/goal`, and the prompt's first real work is to reproduce and freeze the current baseline before consequential changes.
