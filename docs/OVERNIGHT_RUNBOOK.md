# Overnight Runbook

## Fresh-checkout onboarding and exit contract

The supported entry is the source-checkout launcher, not a pip-installed
`scientist-one` command or direct import of `scientist_one.cli`. The former
console declaration was removed because ordinary startup cannot supply the
captured import authority. Neither CLI nor launcher guards were weakened.

In an app-selected checkout named `ScientistOne`, use an already trusted
CPython >=3.11 installation; `python3` below denotes that selected interpreter,
not permission to download one or substitute an unreviewed runtime. Record its
version. The tested versions are 3.11.15 and 3.14.6:

```sh
python3 --version
python3 -I -S -B scripts/scientist_one_cli.py --help
python3 -I -S -B scripts/scientist_one_cli.py status
```

Fresh source-only smoke: help exits0; status exits2 with
`OrchestrationError: app-session bootstrap receipt is invalid`. No receipt,
run, artifact store or resource authority is created. A caller-supplied brief
does not bypass that prerequisite. This is a verified refusal, NOT successful
onboarding. The existing section1 only validates a receipt already issued for
the admitted workspace. It is not a recipe for manufacturing one. A supported
fresh app-bound issuer is not supplied here. That assessment is complete; the
owner instead selected a non-host LOCAL_DEVELOPMENT design, reviewed below and
not implemented. Do not copy the development receipt or edit its path.

The legacy exit contract is unchanged:

| Exit | Meaning | Not implied |
| --- | --- | --- |
| 0 | Help succeeded, or a command result has top-level `status: PASS` | Scientific support, publication readiness, human/E4 approval |
| 1 | A command returned another status; inspect its JSON | Necessarily a crash or invalid negative/null scientific result |
| 2 | Usage/startup/admission error or caught command exception | A completed research evaluation |

For example, `ARCHITECTURE_CONTROL_REPLAY_PASS` remains a non-PASS top-level
label and therefore retains exit1. No blanket success adapter or breaking
exit-code migration was introduced. Six focused fresh-source tests cover
metadata, help, missing admission, supplied-question refusal, usage and the
unchanged source-level status mapping. They do not fabricate a runtime PASS
to test approval authority or claim that a scientific workflow executed.

### Requested question-driven workflow: first blocked stage

The smoke question is “Does a fixed linear classifier exceed a majority
baseline on permitted local data?” It is authored synthetic test text, not a
scientific result, literature source or dataset. An input file can be named by:

```sh
python3 -I -S -B scripts/scientist_one_cli.py start --brief question.md
```

Fresh-workspace admission currently blocks this command BEFORE brief ingestion,
source/data registration, prospective planning or worker dispatch. No data was
consumed, baseline/candidate run, uncertainty calculated or research report
generated. The public tests record that failure instead of returning canned
results. The selected next proposal is truthful local-development admission,
not a replacement host receipt; implementation requires separate approval.
After admission, the existing `start --brief` only registers supplied text and
initializes a run; it does not itself translate arbitrary questions/configuration
into executable research. The requested full configurable workflow remains
unfinished and must reuse the existing prospective plan/worker/artifact owners.
Current `research-os-fixture` is a reviewed fixed synthetic demonstration, not
general autonomous coding or a fallback presented as the user's research.

The remaining sections apply to ALREADY ADMITTED workspaces. Their retained
historical interpreter examples are not prerequisites for a new user; use the
selected trusted interpreter consistently. Original admission, external-access,
custody, scientific and human-only E4 requirements continue to govern execution.

## Scope and non-negotiable labels

### Standalone local-development decision packet — D-082, DESIGN ONLY

This supersedes D081's proposed host-issuer next action, not its source findings.
The host assessment is complete; no issuer search or conditional host adapter
will proceed. Owner authorized this design and independent review, not code or
admission experiments. Source basis remains `1090bdd` / functional freeze
`8f5b3669`; none of the following new commands exists yet.

**Recommended minimum.** Add an explicit `local-development` command namespace
through the existing captured launcher. Initially allow only initialization,
admission inspection and validation of the existing local resource configuration.
This deliberately does NOT enable research execution. It establishes a truthful
standalone entry point without changing E0 or inventing host authority. The
question/configuration-driven research workflow remains a separate incomplete
requirement, not satisfied by these technical operations.

**Local contract.** A create-once private `state/LOCAL_DEVELOPMENT.json` has ONLY
these proposed fields: `schema_version: LOCAL_DEVELOPMENT_V1`,
`mode: LOCAL_DEVELOPMENT`, `host_app_attestation: NOT_PROVIDED`,
`canonical_project_root` (string), `root_device`/`root_inode` (nonnegative integers,
not booleans), `source_inventory_sha256` (64 lowercase hex),
`local_checks` (exact map of `selected_narrow_root`, `captured_source_match`,
`no_authority_conflict`, each `PASS` after its actual check), and
`allowed_operations: [init, status, check-config]`. Unknown keys/versions or
changed allowlists refuse; stored permissions cannot extend source-defined
permissions. The source digest is the existing `_source_inventory` aggregate:
sorted path/size/hash entries for package Python files plus the guarded launcher,
validated against the actual capture. No timestamp, nonce or configuration hash
enters the equality-critical record. These are local observations, not an
authenticated user/host identity or protection against a
user controlling the interpreter/filesystem. A hash is not an issuer signature.
Never include `app_session_bootstrap`, `bootstrap_checks`, historical receipt
hashes or approval claims. The record grants no platform permission, network,
spending, protected data, custody, scientific promotion, publication or E4.
Paths/identities stay private; displayed status uses relative root and scope.

**Proposed fresh-checkout sequence** (already trusted Python >=3.11; explicitly
selected narrow checkout named `ScientistOne`, cwd equals that checkout):

```sh
python3 -I -S -B scripts/scientist_one_cli.py --root . local-development init
python3 -I -S -B scripts/scientist_one_cli.py --root . local-development status
python3 -I -S -B scripts/scientist_one_cli.py --root . local-development check-config
```

The user selects the directory; captured repository code checks current identity
and records only those facts. No host actor is asserted. `check-config` reads
only confined `configs/resource_limits.json` with existing byte/JSON bounds,
calls existing `ResourceConfig.from_mapping`, and returns the input digest,
defaults-expanded `to_dict()` settings and validation outcome from the SAME read
buffer. Existing `resources.py` import observes CPU count; omitted worker count
inherits that default, which the output discloses. No additional hardware
profiling, subprocess/process probes, `ResourceController`, resource acquisition,
worker dispatch, research calibration, run creation or provider call is allowed.
Existing parser semantics remain: unknown keys refuse; `schema_version` need
only be a nonempty string, not a known version. This is distinct from the new
record's exact-version check. Users may edit config and recheck it; input identity
is captured for each invocation, not declared permanently approved by init.
Outputs use the existing CLI JSON/exit convention: PASS0, other result1,
usage/admission/exception2. No result is a scientific finding.

**Command / authority matrix for the proposed new version:**

| Command | Fresh local-development workspace | Required authority / common limits |
| --- | --- | --- |
| `--help` | Allowed without a record | Existing captured startup; no initialization |
| `local-development init` | Explicit selection; absent record or exact valid repeat only | Current confined root/source identity; create-once publication |
| `local-development status` | Valid local record required; missing/invalid returns error without creation | Revalidate binding and exact schema; no legacy run traversal |
| `local-development check-config` | Allowed with valid local record | Same checks plus bounded existing configuration parser; no resource lease |
| Existing `preflight`, `calibrate`, `start`, `demo`, `research-os-fixture` (including restart) | NOT authorized by local mode | Existing broader operations are not implicitly inherited |
| Existing `status [run]`, `resume`, `verify`, `reproduce`, `package` | NOT authorized by local mode | May traverse/mutate legacy or vNext run authorities; no alias to local status |
| Host-admitted execution | Unavailable in this proposed version until a separate genuine authority contract is approved | Local record cannot satisfy it; no failed-host fallback |
| Launcher `test-suite`, `audit-project`, internal captured-test selector | Not authorized by this product record | Existing independently controlled verification paths unchanged; local mode grants no new test/audit or stopped-scope permission |
| Network, paid/cloud work, protected data, custody, promotion, submission/E4 | Never granted | Their independent platform/scientific/human gates remain |

Common checks retain real `-I -S -B` captured startup and loaded/live-source
attestation, narrow canonical root/cwd identity, confined regular single-link
records, bounded strict JSON, and existing confined atomic publication helpers.
No manually injected capability flags, alternate launcher or platform bypass.
The allowlist must be enforced before constructing the existing broad
orchestrator; parser selection alone must not grant its methods.

**Precise E0 treatment.** No existing E0 field or predicate changes. Today
`orchestrator._safe_root` requires `app_session_bootstrap == PASS` plus matching
`canonical_project_root`. `_handler_calibrate` creates logical artifact
`bootstrap_receipt` with kind `CONFINED_BOOTSTRAP_RECEIPT_REFERENCE`, schema1.0,
`app_session_bootstrap`, `bootstrap_checks`, redacted root `.`,
`source_receipt_sha256` and `external_absolute_paths_recorded: false`; together
with `calibration_report` it requests `E0:CALIBRATE` / R0. The frozen
`CALIBRATE → CHARTER` transition requires both artifacts and E0.
`StateController._validate_semantic_artifact` requires bootstrap PASS and a
nonempty all-PASS check list; calibration must equal fresh deterministic replay.
None of those checks authenticates a host issuer. Local initialization produces
NEITHER artifact, evaluator receipt nor state transition. Its status explicitly
says host E0 evidence NOT_PROVIDED / NOT_EVALUATED, never PASS. Other E0 usages
(e.g. SYSTEM_FIXTURE technical checks) are not all host attestations and are
unchanged. Enabling a legacy research workflow would require a separately
approved versioned authority/transition design; renaming this record is invalid.

**Compatibility decision requiring explicit approval.** The current reader
cannot distinguish an old authentic context from newly written legacy-shaped
PASS/path JSON. No filename, timestamp, command flag or copied digest fixes
that. Recommended fail-closed tradeoff: in the *proposed upgraded public CLI*,
reject the existing broad command route regardless of a legacy-shaped receipt;
do not offer a `--trust-legacy` escape. Local init also refuses any existing
`APP_SESSION_BOOTSTRAP.json` or legacy run authority instead of migrating it.
This is an explicit CLI compatibility restriction, NOT implemented or already
approved. Existing frozen-source verification continues unchanged before any
future integration. Preserve all historical bytes, results and historical
readers; do not retroactively authenticate them or alter E0. Users retaining
historical workspaces cannot migrate/execute them through this minimum new
local path. If preserving broad historical execution in the upgraded CLI is
required, this minimum cannot honestly promise authenticated historical/fresh
routing; that compatibility requirement needs a separate owner decision. No new
trust service or hidden grandfathered hash is proposed.

**Record lifecycle.** Every local command checks the finite conflicting paths:
`state/APP_SESSION_BOOTSTRAP.json`, `runs`, `artifacts`, `reports`, and
`.scientist-one-build/{checkpoints,custody,resource-authority}`. ANY entry at
these names (even empty, malformed or linked) refuses; unreadable/unsafe parents
refuse. This is conservative namespace isolation, not historical authentication.
Absence permits only explicit init; all other local
commands refuse. Exact valid repeat rechecks current root/source/schema and
returns without replacing bytes or changing run state. A copied root binding,
directory replacement, changed captured source, malformed/unknown schema,
partial final record, symlink/hardlink, unexpected authority-bearing fields,
or simultaneous local/legacy records refuses without repair or downgrade.
Initialization may create only its missing confined `state` parent and the
record through existing `atomic_write_json(overwrite=False, immutable=True)`;
no research/runtime directories. Validate before publication and revalidate
root/source/conflicts and final record afterward. A post-publication refusal
may leave a complete record, not admission success. Pre-publication failure
grants nothing. Existing helper-owned temporary cleanup remains unchanged.
Any pre-existing name matching `.LOCAL_DEVELOPMENT.json.*.partial` in `state`
refuses, with or without a final record; unrelated temporary names are not
scanned as admission evidence. The helper's transient two-link interval or
concurrent initialization may safely refuse; no liveness inference/automatic
retry. Adapter never removes leftovers or repairs final records. A later exact
repeat succeeds only when all checks are clean; record bytes/mtime stay intact.
Ambiguity requires a reported recovery decision, not lock removal. No
automatic migration/rebinding/update command is part of the minimum. Changed
configuration can be checked afresh; changed captured source requires a fresh
explicitly selected workspace until an upgrade policy is separately approved.

**Smallest implementation envelope for the next approval:** `cli.py` routing;
small common-root/local-record functions in `orchestrator.py` without granting
the broad constructor local authority; reuse unchanged `security.py` publication
and `resources.py` parsing; one focused captured-startup test module, existing
onboarding test expectations explicitly versioned for the CLI restriction,
runbook/README/ignore-policy updates. No launcher/capability protocol, E0,
state-machine, scientific ledger/registry, worker/provider or custody changes.
Record handling is product configuration, not a second approval service.

**Acceptance after approval, NOT executed now:** genuine fresh source checkout
with no private receipts; all three proposed commands; same-input repeat with
unchanged record bytes/mtime and no run creation; copied/stale/unknown/partial/
conflicting records detected in pre-publication checks fail before writes;
post-publication revalidation refusal may leave a complete record, never success;
deterministic publication-failure cases
using existing supported helpers (no stopped native probes); historical bytes
unchanged; newly legacy-shaped JSON cannot enable the upgraded broad route;
all out-of-allowlist commands refuse; no bootstrap/E0/ledger/claim authority is
created; configuration parser accepts/rejects its existing schema and binds
each input digest; source tamper/cwd mismatch and existing guarded-startup
controls remain fail-closed. Run focused new/affected CLI controls on both
supported runtimes, not unchanged numerical or broad suites merely for design.
An approved CLI restriction invalidates previous broad CLI/lifecycle acceptance
for that future version and must be explicitly reported, not inherited as PASS.

**Next decision:** approve this three-command technical-only implementation
INCLUDING the stated legacy CLI restriction, or require historical execution
compatibility first. No external issuer/credentials are needed for this local
minimum. Actual configurable research remains unfinished and requires its own
scientifically valid command/authority path, not a bootstrap alias.

**Non-author review:** reused admission reviewer supports this technical scope
and E0 separation; actual runtime/configuration UNVERIFIED. Root incorporated
the CPU-default/parser semantics, exact record/conflict namespace and existing
publication cleanup/concurrency qualifications. No production bug or exploit was
reproduced. The smaller alternative is additive local isolation with the old
route explicitly UNAUTHENTICATED and blocked whenever local records exist; it
does NOT prevent new legacy-only JSON enabling old commands. Reviewer and root
agree it cannot claim equivalent protection. Root recommends the stronger
restriction above; the compatibility choice remains the sole owner decision.
No admission experiments or production edits occurred. Implementation UNAPPROVED.

Source anchors: `cli.py:164`; `orchestrator.py:1503,1610,1706,2222,9546`;
`state_machine.py:215,648`; `resources.py:33,74,90,132`;
`security.py:331,385,571`. These refer to the source basis above. Private review
retains both draft identities; final wording adds the reviewer's distinction
between pre-publication refusal and refusal after a completed publication.

### Historical host-admission assessment — D-081, completed; adapter not selected

The owner selected the separate D082 local-development proposal above. This
preceding assessment is retained as evidence, not an instruction to search for
an issuer or implement its conditional adapter. Its former next actions are
superseded; historical receipt bytes and scientific semantics remain unchanged.

Source basis: published `84f045c`, functional freeze `8f5b3669`; no admission
code has changed. This is a bounded proposal, not a second specification or
permission to execute it. The host-issuer question below must be resolved before
implementation. Independent non-author review found the legacy-routing and E0
compatibility questions below still unresolved; it did not approve implementation.

**Existing authority, separated.** `scripts/scientist_one_cli.py:main` captures
source and binds dispatch to its canonical directory. The orchestrator's
`_captured_project_root`, `_safe_root` and constructor require that identity,
the current directory, a narrow `ScientistOne` basename and a confined regular
`state/APP_SESSION_BOOTSTRAP.json` with PASS and matching canonical path.
`_handler_calibrate` subsequently registers a hash-bound, path-redacted reference
to that receipt as existing E0 input. The runbook additionally checks the claimed
app-selected workspace and historical bootstrap checks. These readers do not
themselves issue a receipt or authenticate a host-app signature. The source
loader establishes captured local source identity, not host selection or
platform permission. Filesystem/platform permission remains imposed externally.

No supported issuer is present in the public scripts or CLI, and no approved
host receipt-issuance interface was identified in the available tool metadata.
This does not prove no such host facility exists elsewhere. The provenance of
the historical receipt is not reconstructed or upgraded into a host attestation.
Its bytes and all historical references must remain unchanged. Repository-owned
code cannot truthfully fill an app-attested field solely from cwd or user text.

**Recommended route: keep the existing authority boundary.**

1. User explicitly selects the new narrow workspace in the host app and confirms
   the intended project. This selection is not itself a repository receipt.
2. Host/platform owner identifies an approved admission mechanism and its trust
   contract: actor, selected-directory binding, authenticity/freshness, permitted
   operations and safe handoff to the repository. This is an external prerequisite,
   not an interface this project may invent and call host-approved.
3. Only that approved issuer records freshly observed facts for this workspace.
   Any repository adapter may validate/import the approved evidence, but may not
   mint host claims. A potential `initialize workspace` host action is PROPOSED,
   NOT AVAILABLE here. Its wire/command cannot be specified honestly before the
   issuer contract is supplied.
4. After an approved legacy/new dispatch rule, captured startup revalidates
   current root identity, issuer context and receipt binding, then permits
   ordinary commands through their unchanged scientific,
   resource and approval gates. Record source/runtime identity through existing
   run manifests and artifact/ledger owners; no parallel provenance store.

The receipt could prove only the facts actually supplied by the approved issuer
and the local checks actually performed. It would not prove data rights,
protected-data access, network/spending permission, sandbox containment,
exchangeability, successful experiments, custody independence, scientific
promotion, release readiness or E4. A recorded initialization is not a research
result. Exact command permissions cannot exceed the issuer/platform contract.

**Required state behavior for any approved adapter:**

| Input state | Proposed behavior; all remain UNIMPLEMENTED |
| --- | --- |
| No record | Validate host evidence and current root before an atomic create-once publication; absence/failure grants no admission. |
| Exact valid record for same workspace/issuer context | Revalidate issuer authenticity/freshness and current identity; no-op without changing bytes, timestamps, run state or historical authority. |
| Copied/mismatched record, changed directory identity, symlink/hardlink or unknown schema | Refuse; never repair paths, overwrite or silently downgrade to local admission. |
| Partial publication | Incomplete evidence grants no authority; retry may complete only an exact validated pending publication under the approved protocol. No automatic cleanup, lock removal or invented success. |
| Existing historical receipt | Preserve original bytes and established historical-context semantics; no inference that any legacy-shaped file has historical authority. Legacy/new routing remains unresolved below. |

Canonical path alone cannot identify a replaced directory. Proposed new evidence
must bind the live selected directory identity and approved issuer context and
be rechecked at admission; stale identity fails closed. Machine-local details
remain private. The exact persistence/atomicity implementation must reuse the
existing confined publication helpers and be reviewed, not assumed solved here.

**Unresolved legacy/new routing (non-author review finding):** current
`_safe_root` does not authenticate issuer/schema, so preserving its permissive
legacy shape for arbitrary fresh workspaces would contradict a new claim that
local assertions cannot admit them. This is a source-level compatibility
finding, not an executed exploit. A filename, timestamp, caller-selected mode
or merely old-looking JSON cannot establish historical authority. The approved
host contract must provide a trusted distinction between an already admitted
historical context and fresh admission, with no unknown-version/legacy-shaped
fallback on the fresh path. No such distinction is implemented or assumed here.
If providing it requires migration or a new trust service, that exceeds this
adapter proposal and returns to owner triage. Preserving historical bytes does
not authorize falsely granting historical status to newly written files.

**Separate option if no host issuer is available:** owner may instead approve
a distinctly labelled `LOCAL_DEVELOPMENT` mode. A proposed command could be
`python3 -I -S -B scripts/scientist_one_cli.py init --mode local-development --root .`.
It is NOT implemented or currently accepted. A locally issued record would
prove only explicit user selection and current local checks; it must state
`host_app_attestation: NOT_PROVIDED` and confer no platform authority. It must
not write `app_session_bootstrap: PASS`, reuse historical bootstrap hashes or
enter the old E0 bootstrap-evidence slot by alias. Whether that mode may admit
any research commands and how E0 records its distinct technical scope require
a separate owner-approved design. It is not an automatic fallback, and would
not overcome a platform denial. This option is not the recommendation for
implementation while the original host-authority contract is unresolved.

**Minimal implementation envelope after approval:** existing launcher/CLI
admission and orchestrator `_safe_root` are the integration seam; add only a
small adapter to the *identified* issuer contract, focused startup tests and
this runbook. Preserve existing source capture, root confinement, legacy exit
codes and historical receipt readers. Inspect `_handler_calibrate` only for
version-correct reference compatibility; no E0 predicate/authority migration
is authorized. If host evidence cannot fit without changing those semantics,
return that expansion to owner triage. No provider, worker, custody, scientific
state-machine, claim registry or ledger changes are part of this proposal.

**Acceptance before enabling fresh admission:** authentic fresh issuer evidence
in a fresh selected workspace; no private development state; exact same-context
repeat no-op; mismatched/copied/stale/partial/unknown evidence refuses; no writes
before complete admission except explicitly approved initialization publication;
interrupted-publication tests use permitted deterministic failure injection,
not stopped native/process probes; historical bytes/readback stay unchanged;
captured startup remains mandatory; no host, scientific, custody or E4 authority
can be obtained from a local assertion on the proposed fresh path. Test a fresh
locally asserted legacy-shaped record, unknown-version fallback, directory
replacement, expired/replayed issuer context and conflicting concurrent
publication explicitly, without executing stopped investigations. These are
acceptance requirements, not demonstrated properties of the current reader.
Run the existing six onboarding controls (including help, metadata and static
exit mapping) and focused new initializer tests on both supported test runtimes.
Synthetic issuer fixtures establish adapter behavior only; enabling real
admission additionally requires authentic approved-issuer evidence. Only then
test a permitted question-driven workflow; initializer success is not its PASS.

**Decision needed:** identify an approved host issuer and authorize its precise
adapter, or explicitly choose the separate non-host local-development design.
Neither exists by assumption. Production implementation remains unapproved.

Review disposition: preserve the host boundary; obtain an approved issuer
contract and legacy/new routing before any adapter. E0's existing bootstrap
field meanings also need compatibility review, not a name-only substitution.
Root accepts these qualifications; there is no remaining reviewer and root
disagreement, but the issuer, routing and E0 compatibility are unresolved
dependencies. The implementation envelope above is conditional, not clearance.

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
