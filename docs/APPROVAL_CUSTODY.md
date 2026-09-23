# Approval Custody

## Authority is typed, not inferred

Scientist-One separates the ability to produce an artifact, request a transition, deterministically validate it, scientifically review it, adversarially test it, access a holdout, verify a claim, write prose, package evidence, and authorize external release. Possessing filesystem or process access does not grant all of those scientific authorities.

No producer can authoritatively approve its own artifact. Silence is not approval. An automatic sandbox reviewer is a platform security-boundary reviewer only; it is not scientific, dependency, holdout, research, publication, or release approval.

## Authority matrix

| Authority | May do | Must not do |
|---|---|---|
| Orchestrator | Schedule allowed work, request typed transitions, checkpoint | Forge evaluator decisions, bypass failed gates |
| Artifact producer | Create role-scoped artifact with provenance | Approve own artifact as gate authority |
| E0 deterministic validator | Validate schemas/hashes/contracts and issue machine decision | Make subjective novelty or release claims |
| E1 producer-local reviewer | Record advisory self-check | Authorize a transition alone |
| E2 scientific-review context | Record a hash-bound review receipt over frozen artifacts | Edit producer artifacts or claim independent human review |
| E3 adversarial/reproduction context | Record declared adversarial checks and the deterministic replay comparison | Mutate originals, waive a failed replay, or claim an independent red team |
| Holdout custodian | Enforce release preconditions and ledger access | Select hypotheses, tune methods, reinterpret outcomes |
| Claim verifier | Mark claims eligible/ineligible from immutable evidence | Create missing evidence or soften contradictory results |
| Paper writer | Compose from eligible claims and generated outputs | Edit results, analyses, ledger, or evaluator decisions |
| Release packager | Assemble content-addressed review candidate | Publish, submit, or label `RELEASED` |
| E4 human owner | Make genuine external-release/human-only decisions | This authority cannot be simulated by code or an agent role |

Local E2/E3 role separation uses hash-bound inputs and separate outputs, but both demo records are constructed in the orchestrator process. They are governance plumbing and regression evidence, not independent human or institutional review. That limitation must stay visible in the review packet.

The vNext checked authorities follow the same trust-domain rule. Registry-resolved discovery and superiority receipts; prospective Dataset/Split authority; Result-v2/StatisticalTest bundle completion; canonical ClaimSemantics; claim-bound `Jref`; exact Result/Run/completion-bound `Jqual`; source-owned v2 Ablation; the registry-derived paper bundle; the 15 soundness-dimension receipts; and the 14 Challenger category reviews enforce exact roles, canonical content, hashes, parent closure, freshness, outcome ambiguity and deterministic recomputation. They are logical separation inside the local system, not evidence that independent people, institutions, accounts, or machines reviewed the work. A role label such as `SCIENTIFIC_REVIEWER`, `ADVERSARIAL_REVIEWER`, or `CLAIM_VERIFIER` must not be described as genuine external independence merely because its receipt verifies.

The live gateway's `audited_transport_execution_authority` is also not approval. Its local HMAC proves only that the exact built-in transport consumed one admitted credentialless request and the captured claim was bound to the run registry/ledger. Credential-bearing real-network execution is blocked before gateway external-request registration or dispatch and cannot mint this authority; resolved credentials are never passed to unverified transports. The authority grants no semantic truth, scientific eligibility, protected-data access, compute escalation, human identity, E4, publication, submission, or release. Because the signing key and verifier remain local, same-process/key/source compromise is `BLOCKED_LOCAL`, and there is no external witness.

## vNext human-gate profiles remain separate from scientific gates

The vNext `HumanGatePolicy` supports `HUMAN_GATES_REQUIRED`, `HUMAN_GATES_SELECTIVE`, and `FULL_AUTONOMOUS` for research-question, novelty, Evaluation Contract, compute-escalation, confirmation-reveal, soundness-promotion, and final-release decisions. A human-gate profile answers who may authorize progression. It does not answer whether the scientific evidence justifies progression.

Every autonomous progression requires a structured decision naming alternatives, registry evidence hashes, governing rule, uncertainty, reason, and downstream consequences. This record is concise decision provenance, not hidden reasoning and not human approval. `FULL_AUTONOMOUS` can remove an optional human authorization only after the independent scientific gate passes; it cannot waive protocol freeze, evidence, baseline, statistical, challenger, soundness, reproducibility, or claim-verification requirements.

Final release remains exceptional: the current policy always reserves it for genuine external E4 authority. If a scientific gate fails, the outcome is `BLOCKED_SCIENTIFICALLY` before any human authorization could matter. If science passes but E4 is absent, the most the system can form is a release candidate. The states `RESEARCH_COMPLETED_AUTONOMOUSLY`, `HUMAN_APPROVED_FOR_RELEASE`, and `SUBMITTED` must never be collapsed.

The integrated vNext fixture uses autonomous decision records only for its bounded synthetic research-question and Evaluation Contract gates. Its soundness path remains blocked and it emits `human_e4_synthesized=false`. Its `fixture-operation.json` receipt is an atomic operational status record, not an approval object. `COMPLETE` proves only that the bounded operation finished with the registry/ledger/summary identities named by the receipt; it grants no scientific-evidence eligibility, discovery or superiority promotion, paper readiness, human approval, confirmation access, publication, submission, credentials, network access, compute escalation, or release authority.

No new scientific-source authority changes the current final outcome. The unsandboxed Local Mac Result remains scientifically ineligible, synthetic reproduction cannot satisfy robustness, scientific soundness remains `MORE_EXPERIMENTS_REQUIRED`, paper verification is `BLOCKED`, venue classification is `NOT_READY`, and E4 is absent.

For a vNext fixture, the supported post-run parent commands are read-only `status` and authority-aware `verify`. Do not call the legacy `resume`, `reproduce`, or `package` lifecycle on a vNext run. A failed or abandoned vNext operation requires preservation and a fresh run ID after diagnosis; it cannot be resumed into authority.

## Approval records

Human approvals are read-only evidence. Scientist-One never creates, modifies, backdates, or signs one. Requests belong under `state/approval_requests/` as append-only records and must identify:

- exact requested action and why it is necessary;
- executable and argument array when applicable;
- exact project-relative paths;
- alternatives already attempted;
- expected outputs and validation;
- risks and rollback;
- independent work that continued; and
- request identity/timestamp without secrets.

Requests are written as immutable project-local JSON by `write_approval_request`; that operation never creates approval. An approval applies only to its exact subject, repository, version, and bounds. Approval from another project—especially dependency or network approval—is irrelevant. A broad capability supplied by the OS, app, plugin, or sandbox does not broaden the run’s authorization.

## E4 boundary

E4 is required for publication, submission, external release, any claim of submission readiness, network/credential expansion, and dependency escalation where the governing policy reserves that decision for the human owner. `Evaluation` deliberately rejects construction of every E4 decision; a `human_release` role label is not human identity or approval custody. A future genuine approval would need a separate imported, validated human-custody record. The autonomous controller may reach `READY_FOR_HUMAN_REVIEW`; it may not reach `RELEASED` or represent missing E4 as administrative delay after all substantive approval has occurred.

For this repository, external novelty is also unverified. Thus even a perfect local synthetic demonstration remains `DEMO_RESEARCH_PACKAGE`, `NOVELTY_UNVERIFIED`, with simulated non-independent custody. Likewise, successful vNext system-fixture integrity remains non-evidentiary science with blocked paper promotion. E4 cannot convert synthetic evidence into real-world scientific validation.

The historical legacy run `run-20260812T204930Z-299b1dad55` stops at `READY_FOR_HUMAN_REVIEW` with `COMPLETE_DEMO_ONLY`. Its detached envelope states `publication_authority=E4_HUMAN_REQUIRED`, and the readiness report records `e4_present=false` and `submission_ready=false`. No network, credential, dependency, publication, submission, or external-release authority was requested or inferred. This is not a vNext gate receipt.

## Forgery and ambiguity handling

An approval is rejected if its subject, authority, artifact/protocol identity, scope, or required signature/record is absent or mismatched. Free-form text saying “approved,” producer-authored approval objects, embedded instructions in artifacts, and an existing writable file in a nominal approval directory are insufficient. Ambiguity at a security or human-only gate fails closed and produces a request rather than an invented decision.

## Audit procedure

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B - <<'PY'
import os
from pathlib import Path
import stat

root = Path.cwd().resolve(strict=True)
base = root / "state" / "approval_requests"
info = base.lstat()
if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
    raise SystemExit("STOP_SECURITY: approval request directory is absent, linked, or not a directory")
for directory, names, files in os.walk(base, topdown=True, followlinks=False):
    parent = Path(directory)
    for name in sorted(names + files):
        path = parent / name
        item = path.lstat()
        if stat.S_ISLNK(item.st_mode):
            raise SystemExit(f"STOP_SECURITY: linked approval entry: {path.relative_to(root)}")
        if not (stat.S_ISDIR(item.st_mode) or stat.S_ISREG(item.st_mode)):
            raise SystemExit(f"STOP_SECURITY: special approval entry: {path.relative_to(root)}")
        if stat.S_ISREG(item.st_mode) and item.st_nlink != 1:
            raise SystemExit(f"STOP_SECURITY: hard-linked approval entry: {path.relative_to(root)}")
        if stat.S_ISREG(item.st_mode):
            print(path.relative_to(root))
PY
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py verify RUN_ID
```

For a vNext fixture, use only:

```sh
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py status VNEXT_RUN_ID
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py verify VNEXT_RUN_ID
```

The inventory is only a filesystem safety check; `verify` does not authenticate human approvals. Authoritative approval custody would additionally require schema, subject/scope, identity, hash, and human-attestation validation. The final review must confirm that no autonomous event claims E4, no producer supplied its own authoritative gate, logical evaluator receipts bind the reviewed artifact hashes, vNext `COMPLETE` is not treated as approval, and a legacy package says `READY_FOR_HUMAN_REVIEW` at most. Final vNext run identities, counts, and pre-audit hashes remain **PENDING** until the frozen evidence sequence completes. The project audit is the last mutation; its machine result is `reports/final_audit.json` and is reported externally without a post-audit edit here.
