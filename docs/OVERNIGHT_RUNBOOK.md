# Overnight Runbook

## Scope and non-negotiable labels

This runbook operates Scientist-One inside the app-selected project root with no uncontrolled command network, no dependency acquisition, and no write outside the repository. The legacy demonstration is synthetic: every resulting package remains `DEMO_RESEARCH_PACKAGE`, `NOVELTY_UNVERIFIED`, with simulated non-independent custody. The vNext integrated fixture is also synthetic and nonpublishable; it exercises audited egress with deterministic fixture transports, not live network access, and its local experiment output is explicitly `NON_EVIDENTIARY`. E4 is human-only; overnight automation cannot publish, submit, or declare `RELEASED`.

The repository also contains source-owned scientific Dataset/Split, Result/StatisticalTest, ClaimSemantics/`Jref`/`Jqual`, and v2 Ablation authority paths. They are not activated by this synthetic fixture. A credentialless live gateway crossing may mint a narrow run-bound HMAC execution authority, but no overnight step may treat that local signature as response truth, scientific approval, protected custody, E4, or an external witness; same-process/key/source compromise remains `BLOCKED_LOCAL`. Credential-bearing real-network egress is disabled before gateway external-request registration or dispatch pending a separately reviewed sensitive-response store, and the unverified fixture transport receives no resolved credential.

Final vNext run identities, artifact/event/object counts, test totals, and hashes remain **PENDING** until the source, tests, configuration, and documentation are frozen and the final evidence sequence completes.

The two paths share the trusted registry and ledger implementations but have distinct control semantics:

- the legacy `demo` traverses the macro state machine and supports the legacy `status`/`resume`/`verify`/`reproduce`/`package` lifecycle; and
- `research-os-fixture` materializes vNext phase checkpoints and canonical research state without pretending to traverse legacy macro states. It has an atomic operation receipt and is not resumed or packaged through the legacy commands.

## 1. Establish the root and bootstrap evidence

The bootstrap receipt records the original workspace admission. The owner later
initialized the canonical Git repository; do not overwrite the historical
receipt or treat its former `git_top_level: null` as a claim that Git is still
absent. Verify current Git identity separately at a stable boundary. The
read-only September20 check found `main` tracking `origin/main` at the owner's
README-only `bba9ec5` commit and the exact Scientist-Ultra remote; this is not
release clearance or permission to overwrite different future state.

Start in the app-selected ScientistOne workspace:

```sh
set -eu
pwd -P
/opt/homebrew/bin/python3 -I -S -B - <<'PY'
import json
from pathlib import Path
import stat

root = Path.cwd().resolve(strict=True)
def require(condition, message):
    if not condition:
        raise SystemExit(f"STOP_SECURITY_WORKSPACE_IDENTITY: {message}")

require(root.name == "ScientistOne", "unexpected workspace basename")
require(
    root not in {Path("/"), Path.home(), Path("/Users"), Path.home() / "dev"},
    "workspace is a prohibited broad root",
)
state = root / "state"
receipt_path = state / "APP_SESSION_BOOTSTRAP.json"
for candidate in (state, receipt_path):
    info = candidate.lstat()
    require(not stat.S_ISLNK(info.st_mode), f"symlink rejected: {candidate.name}")
require(state.is_dir(), "state is not a directory")
require(receipt_path.is_file(), "bootstrap receipt is not a regular file")
require(receipt_path.stat().st_nlink == 1, "hard-linked bootstrap receipt rejected")
receipt = json.loads(receipt_path.read_text())
require(receipt["app_session_bootstrap"] == "PASS", "bootstrap receipt is not PASS")
require(
    receipt["canonical_project_root"] == str(root),
    "receipt root differs from current canonical root",
)
identity = receipt["repository_identity_evidence"]
require(
    identity["app_selected_workspace"] == str(root),
    "receipt app workspace differs from current root",
)
require(identity["canonical_pwd_matches_workspace"] is True, "receipt identity failed")
require(
    all(item["result"] == "PASS" for item in receipt["bootstrap_checks"]),
    "one or more bootstrap checks are not PASS",
)
receipt_git = receipt["git_top_level"]
require(
    receipt_git is None or receipt_git == str(root),
    "historical bootstrap names a different Git root",
)
print(root)
print("APP_SESSION_BOOTSTRAP=PASS")
PY
```

The app’s visible workspace selection remains authoritative outer evidence; the script cross-checks it against the receipt and current canonical directory. Do not search parent directories if any assertion fails. Stop with `STOP_SECURITY_WORKSPACE_IDENTITY`. Do not use a stored absolute path to navigate to a different workspace.

Separately inspect current `git rev-parse --show-toplevel`, branch/tracking,
remotes and history without changing them. The Git root must be this exact
workspace and origin must be the canonical remote in
[Git history reconstruction](GIT_HISTORY_RECONSTRUCTION.md). Unexpected state
requires reconciliation, not initialization, reset, force-push or a new receipt.
The existing launcher/runtime admission checks remain unchanged.

Confirm local-only policy and review existing status:

```sh
set -eu
/opt/homebrew/bin/python3 --version
/opt/homebrew/bin/python3 -I -S -B -c 'import tomllib, pathlib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["dependencies"])'
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py status
```

Expected dependencies are `[]`. Never repair missing functionality with a package install.

## 2. Preflight and calibration

Inspect the exact implemented syntax, then execute the gates:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py --help
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py preflight
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py calibrate
```

Do not proceed if canonical-path, ledger, approval forgery, holdout violation, or prompt-injection calibration fails. Do not suppress a failing case or weaken its expected result.

## 3. Start one bounded synthetic path

### 3.1 Legacy trusted-kernel demonstration

Before starting, verify the configured limits, then run the bounded synthetic workflow:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B -m json.tool configs/resource_limits.json
/opt/homebrew/bin/python3 -I -S -B -m json.tool configs/paper_readiness_rubric.json
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py demo
```

The JSON result supplies the run ID; substitute that exact value for `RUN_ID` below. The start record must identify a synthetic target and preserve the required labels. Do not invent a real research question because no local target/corpus exists. Do not use reserve data during development. Before confirmatory reveal, verify frozen protocol, code/configuration identity, midrun review, reserve integrity, and blind interpretation.

Checkpoint before each expensive stage and at least every 300 seconds during long work where supported. Default ceilings are eight hours, 2 GiB artifacts, two experiments, seven CPU workers, one GPU job, 60%/70% memory soft/hard fractions, and the greater of 25 GiB or 10% free disk.

### 3.2 Integrated Research OS vNext fixture

Use this path when the objective is to exercise the vNext research-intelligence integration. Run it with the captured-source launcher:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py research-os-fixture --run-id VNEXT_RUN_ID
```

Omit `--run-id` to request a generated identity, or choose a new project-safe identifier. A run directory is reserved atomically before execution. Reusing an existing ID—including one from a failed attempt—must fail rather than merge or overwrite history.

The fixture must retain all of these interpretations:

- `PASS` means integrated system-fixture integrity only;
- controlled literature and model calls use deterministic non-network fixture transports, while live paths remain `BLOCKED_EXTERNAL` or `UNTESTED` as recorded;
- `LOCAL_MAC` executes the reviewed child as `/usr/bin/python3 -I -S -B scripts/vnext_fixture_experiment.py` using a frozen `SMOKE` profile, admitted arguments, a scrubbed environment, bounded resources, and validated outputs;
- the local child has no OS-enforced filesystem, process, or network sandbox, so `VALIDATED_LOCAL` is not an isolation claim;
- the clean local rerun checks system reproducibility but remains scientifically `NON_EVIDENTIARY`;
- the `GPU_CLOUD` backend is boundary-tested only and remains externally `UNTESTED`; and
- the confirmatory split is represented but not consumed; no vNext holdout reveal or E4 approval occurs.

The fixture also exercises logical same-trust-domain authorities: checked discovery derives promotion from exact registry/ledger evidence; value-only superiority remains `DIAGNOSTIC_ONLY` while scientific promotion requires a separately checked receipt; paper verification re-resolves its registry-derived bundle; and soundness binds all 15 dimension receipts, all 14 Challenger category reviews, and every finding. These controls prevent caller-supplied values or missing receipts from authorizing a claim, but they are not independent human, institutional, custody, or external scientific review.

`fixture-operation.json: COMPLETE` means only that the operation finished and binds its recorded registry, ledger, and summary identities. It grants no scientific-evidence eligibility, discovery or superiority promotion, paper readiness, holdout access, human approval, E4, publication, submission, or release authority.

Do not substitute an arbitrary experiment program for the reviewed fixture child. The missing OS sandbox is a material boundary, not a warning that can be waived by an overnight run.

## 4. Monitor without busy-waiting

Use bounded, human-paced checks:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py status RUN_ID
df -k .
for path in .scientist-one-build artifacts runs reports; do
    if [ -L "$path" ]; then
        echo "STOP_SECURITY: symlinked monitor path: $path" >&2
        exit 1
    fi
    if [ -e "$path" ]; then
        if [ ! -d "$path" ]; then
            echo "STOP_SECURITY: monitor path is not a directory: $path" >&2
            exit 1
        fi
        if ! du -sk -- "$path"; then
            echo "STOP_SECURITY: cannot measure monitor path: $path" >&2
            exit 1
        fi
    fi
done
```

Pause new work and checkpoint on hard memory/disk/budget thresholds, abnormal artifact growth, repeated worker failure, or serious/critical thermal state where observable. One failed optional MPS parity check selects CPU; it does not block the standard-library demo.

For a running vNext fixture, `runs/VNEXT_RUN_ID/fixture-operation.json` is an operational liveness receipt only. `IN_PROGRESS` explicitly carries `IN_PROGRESS_NO_DOWNSTREAM_AUTHORITY`. Do not treat the presence of registry files, ledger events, canonical objects, or experiment outputs as completion until the operation is `COMPLETE` and the command has returned successfully. Even then, completion is operational integrity only and does not grant any scientific, human, confirmation, paper, or release authority.

## 5. Interruption and recovery

### 5.1 Legacy macro-state run

After app termination, sleep, or uncertain interruption, do not assume the last command completed. First rerun the complete identity/bootstrap validation block from section 1 verbatim; a parse-only check is insufficient. Then run:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py status RUN_ID
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py verify RUN_ID
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py resume RUN_ID
```

Resume validates the existing manifest against the EventLedger, run-scoped registry, live source/configuration inventory, external custody journal, ordered external resource authority, checkpoint/recovery evidence, and confirmatory-rerun guard; eligible descriptor-verified unregistered regular partials are quarantined. It may correct state/head/count fields from the ledger and continue materialized stages without repeating confirmation. It does **not** reconstruct a missing or corrupt manifest's artifact/evaluator/transition projections from a checkpoint. A newer surviving checkpoint with a rolled-back ledger produces a nonpersisted out-of-band `STOP_SECURITY`, because appending to the stale fork would invent history. Preserve the run and stop for repair if the manifest cannot be safely loaded. A partial experiment is not evidence, and scientific failure never qualifies as a retry.

If the controller ends at `STOP_BUDGET`, preserve the checkpoint and report the last valid state; the current implementation treats that outcome as terminal rather than an automatic resume point. If security evidence fails, use `STOP_SECURITY`. If scientific validity is compromised, use `STOP_SCIENTIFIC_INVALIDITY`.

### 5.2 vNext integrated fixture

Do not call legacy `resume`, `reproduce`, or `package` for a vNext fixture. After interruption, re-run the workspace identity checks, then use the authority-aware read-only commands:

```sh
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py status VNEXT_RUN_ID
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py verify VNEXT_RUN_ID
```

`status` validates and reports the operation state. `verify` returns a fail-closed result for `IN_PROGRESS` or `FAILED`; for `COMPLETE` it revalidates the receipt, registry/ledger closure and bindings, final summary, canonical research state, checked discovery, the non-authoritative superiority diagnostic, 15/14 gate authority, and registry-derived paper blockers. The underlying `runs/VNEXT_RUN_ID/fixture-operation.json` remains an inspectable receipt and must not be edited:

- `COMPLETE` means only that the operation finished and the receipt binds its registry, ledger, and summary identities; it grants no scientific, human, holdout, paper, publication, or release authority;
- `FAILED` means the operation failed closed and its recovery policy requires a new run ID; and
- a surviving `IN_PROGRESS` after process loss has no downstream authority and is not an event-sourced resume point.

Preserve the abandoned directory for diagnosis. Start the whole fixture under a fresh ID only after the cause is understood; never copy partial artifacts into the new registry, overwrite the receipt, or reinterpret a failed scientific/integrity check as a mechanical retry.

## 6. Verify, reproduce, and package the legacy demonstration

Use the exact run ID returned by `demo`. `demo` performs its own replay during `AUDIT` and freezes a `reproduction_report`. The standalone `reproduce` command is an idempotent replay check over the same frozen artifacts. The surrounding `verify` commands validate the EventLedger, run-scoped registry/recursive artifact projection, manifest agreement, transition/receipt sequences, evaluator hashes, live source/configuration, external custody/resource authorities, recovery safety, and final package binding. They do not independently recompute R0–R7 or redo replay arithmetic.

The special handling around `reproduce` is required. A successful synthetic architecture-control replay returns JSON `status=ARCHITECTURE_CONTROL_REPLAY_PASS`, not generic `PASS`, so the generic CLI intentionally exits `1`. Under `set -e`, accepting that command without inspecting its JSON would abort a valid sequence; ignoring every nonzero code would hide a real error. Use this exact semantic check and finish packaging before documentation finalization:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py verify RUN_ID
set +e
REPRODUCE_JSON=$(/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py reproduce RUN_ID)
REPRODUCE_RC=$?
set -e
printf '%s\n' "$REPRODUCE_JSON"
if [ "$REPRODUCE_RC" -ne 1 ]; then
    echo "STOP_VERIFICATION: expected semantic reproduce exit 1, got $REPRODUCE_RC" >&2
    exit 1
fi
REPRODUCE_JSON="$REPRODUCE_JSON" /opt/homebrew/bin/python3 -I -S -B - <<'PY'
import json
import os

value = json.loads(os.environ["REPRODUCE_JSON"])
if value.get("status") != "ARCHITECTURE_CONTROL_REPLAY_PASS":
    raise SystemExit("STOP_VERIFICATION: semantic reproduction did not pass")
print("SEMANTIC_REPRODUCTION=ARCHITECTURE_CONTROL_REPLAY_PASS")
PY
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py verify RUN_ID
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py package RUN_ID
/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py verify RUN_ID
```

`test-suite` and `audit-project` are exact single-argument evidence modes in the captured launcher. Both capture project and test sources before any project import, use only the in-memory source loader, re-attest live trees/modules/loaders around work, stage the destination through held descriptors, and publish the machine report only after final attestation. The compatibility scripts `scripts/run_test_suite.py` and `scripts/audit_project.py` import no project module and only exec these modes; final evidence should cite the direct launcher commands in section 7. Direct `PYTHONPATH`, `python -m scientist_one`, direct project imports, or altered arguments are not substitutes.

Treat the commands as separate evidence layers:

- `verify`: structural run integrity and receipt consistency described above;
- `reproduce`: frozen-artifact replay through a newly written immutable replay manifest, with numeric/hash comparison;
- full tests: implementation regressions, including calibration, custody, claims, resources, recovery, and failure cases;
- `audit-project`: descriptor-pinned no-follow directory inventory plus confinement, directory/leaf-swap, special-entry/hard-link/symlink, shared secret-pattern, outside-root JSON path, lockfile, 100,000-entry, 64 MiB-per-file, 2 GiB-total, and 8 MiB-report checks; and
- `package`: exact-pre-admitted demo-only ZIP plus detached final envelope after the run's bounded audit/readiness gates.

The run's `audit_report`, `readiness_report`, `e2_review`, and `e3_review` record bounded same-process demo predicates. They are not independent human review, external citation/novelty verification, or exhaustive proof of the normative R0–R7 definitions. The vNext checked discovery/superiority/paper authorities and 15/14 gate receipts have the same logical-role, same-trust-domain limitation. Separately validate `.scientist-one-build/custody/RUN_ID.jsonl` against the frozen custody artifact using the procedure in `docs/HOLDOUT_CUSTODY.md`. Packaging copies/references frozen evidence; it does not authorize release.

The vNext fixture performs deterministic validation, registry/ledger closure checks, canonical-state validation, and a clean local system rerun inside its command. The standalone authority-aware `verify` command independently rehydrates and checks those completed authorities. Neither check makes the local result scientific evidence, validates the live provider/literature or GPU paths, exercises a confirmatory reveal, or creates a publishable package. There is currently no vNext resume/reproduce/package operation to add to the legacy command sequence above.

## 7. Final evidence-freeze ordering

The final evidence sequence is stricter than an ordinary overnight run because `audit-project` must describe the completed repository and must itself be the final mutation.

1. Freeze source, tests, and configuration and record the functional-source inventory, interpreter identity, file set, per-file hashes, and aggregate hash.
2. Complete the Standard security scan and all targeted compile, provider, literature, state, design, discovery, experiment, domain, gate, paper, CLI, failure-injection, and recovery checks. Resolve any source defect before continuing and restart the freeze if source changes.
3. Run the captured suite exactly once on the candidate frozen source:

   ```sh
   set -eu
   /opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py test-suite
   ```

   Parse `reports/test_results.json`; require its captured success flag and zero failures, errors, and unexpected successes. Record the measured count and digest. Do not copy a historical `364/364` value into the vNext result.

4. Run one fresh guarded vNext fixture, followed by its authority-aware `status` and `verify`. Then run the complete legacy demo path from sections 3.1 and 6, including semantic reproduction, the post-reproduction verify, package, and post-package verify. Packaging and every legacy/vNext command that can write must finish before narrative finalization.
5. Refresh the architecture report only from the captured test and fresh run evidence. Finalize `README.md`, `STATUS.md`, `PLAN.md`, `OVERNIGHT_REPORT.md`, `CHECKLIST.md`, the required `docs/` files, and the compact `.run` ledger. All final run IDs/counts/digests that already exist may be recorded now. For the not-yet-run project audit, write only that its authority will be `reports/final_audit.json`; do not invent or reserve its digest.
6. Recompute the functional-source inventory and require exact equality with step 1. Quarantine generated caches using the bounded, no-follow procedure; do not broadly delete repository trees. Run the independent architecture validator one last time.
7. Run the project audit as the **last repository mutation**:

   ```sh
   set -eu
   /opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py audit-project
   ```

8. After `audit-project`, do not run `status`, `verify`, `package`, tests, formatters, cache cleanup, documentation edits, `.run` updates, or any other command that might write. Only read-only `-B` parsing and hashing are permitted. For example:

   ```sh
   /opt/homebrew/bin/python3 -I -S -B - <<'PY'
   import hashlib
   import json
   from pathlib import Path

   path = Path("reports/final_audit.json")
   raw = path.read_bytes()
   value = json.loads(raw)
   print(json.dumps(value, indent=2, sort_keys=True))
   print("final_audit_report_sha256=" + hashlib.sha256(raw).hexdigest())
   PY
   ```

   Report that measured result and digest in the external handoff. The repository documentation points to the machine report and intentionally does not contain a self-referential post-audit digest.

## 8. Handoff

The final report must state an exact truthful terminal outcome, commands and verified identities from the completed run, safe recovery point, changed files, residual risks, and human decisions. For the legacy synthetic run, the successful package outcome is `COMPLETE_DEMO_ONLY`, never an external paper claim. Confirm all of these remain explicit:

- `DEMO_RESEARCH_PACKAGE`;
- `NOVELTY_UNVERIFIED`;
- local custody is simulated and non-independent;
- E4 is human-only and absent; and
- no network, dependency acquisition, publication, or submission occurred.

For a vNext fixture handoff, additionally report the operation-receipt status and keep separate the system-fixture result, checked discovery status, non-authoritative superiority diagnostic, 15/14 gate receipt coverage, scientific-soundness verdict, registry-derived paper/venue status, `LOCAL_MAC` technical validation versus scientific ineligibility, missing OS sandbox, live provider/literature status, and `GPU_CLOUD` external-validation status. State that `COMPLETE` grants no downstream authority, the confirmatory resource was not used, the local comparison is non-evidentiary, negative/null branches were retained, the checked receipts are same-trust-domain logical roles, and E4 was not synthesized. Do not reuse the legacy `READY_FOR_HUMAN_REVIEW` label unless a legacy macro run actually reached it. Final vNext evidence fields remain **PENDING** until the frozen verification sequence completes.

The historical selected legacy checkpoint is `run-20260812T204930Z-299b1dad55`: `READY_FOR_HUMAN_REVIEW`/`COMPLETE_DEMO_ONLY`, CPU path, no MPS adapter, one simulated/non-independent reveal, replay manifest/result SHA-256 `5f6624739072982bbd68b9704d880d0b26e1dbd2d21b5637c0ef6ecc548baaa0`/`bd3ec781660cd928af29e41be8e664bec38f643f95eaaa75612602684c7a2c17`, ZIP/envelope SHA-256 `58512e88ee05266df7517cd0837ac57db777976cfa90eacff7c931b4af7bca2c`/`66a19b93e99447a04fe3f44863f59c821b6c0b1ac8361f99a62d2a098a61ec81`, and captured full suite 364/364. The checkpoint aggregate-admission repair is bound to recovery/test source SHA-256 `c2586c8bb5bfeee1a1133c0c53483e5e3c726ebbaf11cf89125d4dc49944e723`/`730b7961fc3d77eb7cd268f4af22cc84e93f05172b003572823a8380a3529ea1`; known-security review closed `PASS` with no `BLOCKED_SECURITY_REVIEW`. These are historical legacy identities, not vNext evidence. The self-excluded final audit must be cited from its own freshly generated `reports/final_audit.json` rather than inferred from these facts.
