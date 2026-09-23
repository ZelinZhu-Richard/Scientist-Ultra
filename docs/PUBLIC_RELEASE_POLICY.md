# Public-release policy

Status: **development-checkpoint disclosure review in progress; not final-release clearance**. The owner
published a README-only bootstrap (`bba9ec5`) before agent release work; it is not
a verified kernel import or completed vNext release. No agent implementation
commit or push has occurred. The canonical destination is the existing
[Scientist-Ultra repository](https://github.com/ZelinZhu-Richard/Scientist-Ultra).
Treat it as public unless its actual visibility is independently verified
otherwise. Do not change its visibility or create a substitute repository.

September23 owner amendment permits a safe **DEVELOPMENT / REVIEW** branch before
final scientific validation or qualified historical import. Known disclosed
software/test failures are not alone disclosure blockers. All outgoing-file and
reachable-history checks below still apply; unknown/confidential content stays
excluded. This changes checkpoint sequencing, not the final definition of done.

## Candidate contents

Publish only explicitly selected, reviewed source, tests, configuration,
documentation, and necessary redistributable synthetic fixtures. A filename,
an ignore rule, a successful test, or a synthetic-data label is not clearance.
Do not stage the entire working directory. Scan exact staged bytes before each
commit and inspect the resulting commit; before publication review all reachable
history, not merely the current checkout.

The root ignore policy excludes local run and custody stores, orchestration
state, generated reports, caches, virtual environments, local app configuration,
common credential files, logs, crash dumps, archives, and unreviewed binary
literature/data/model files. This is intentionally conservative. Runtime files
remain on disk and remain available to the existing research kernel; ignoring
them neither deletes them nor changes scientific provenance or audit rules.

The entire `state/` tree is excluded because it contains machine and run state.
Any useful handoff guidance should be rewritten as portable documentation, not
published by broadly unignoring that tree. Generated verification evidence must
be reviewed and minimized separately; raw runs, holdouts, custody material, and
provider exchanges must not be made public as proof of testing.

Only a sanitized `.env.example` is eligible for review among `.env` files.
No such file is approved merely by that exception. Required public assets that
match a conservative binary rule need an explicit, narrowly scoped ignore-rule
exception and a documented content, size, licensing, and redistribution review.
Do not use force-add to bypass the policy. Unknown private files and alternate
encodings can evade name-based ignores; semantic review is still required.

## Mandatory checks

Every proposed public file and every reachable committed version must pass:

1. Secret and credential review, without printing sensitive matches in logs.
2. Confidential provider input/output review, including raw, parsed, derived,
   error, and metadata surfaces. Pattern matching alone cannot establish this.
3. Private literature and dataset review, including inline test/document data.
4. Machine-specific absolute-path review of content and metadata.
5. Generated-artifact review, including renamed or embedded artifacts.
6. Large-file review: flag every file larger than 1 MiB (1,048,576 bytes), record
   its exact path, size, hash, necessity, and disposition. Smaller files still
   undergo every other check; this is a review threshold, not a safety limit.
7. Dependency-license review of actual runtime, test, build, and bundled code.
8. Copyright and redistribution review, including third-party code, figures,
   papers, data, and fixtures. Do not infer rights from public accessibility or
   invent a project license on the owner's behalf. The owner selected MIT for
   this project; that decision does not license third-party papers, code or data.
9. Effective `.gitignore` verification using Git at a stable integration
   boundary, including representative forbidden paths and required source/test
   paths. Also inspect actual untracked, ignored, staged, and tracked populations.
10. README capability-claim review against current scoped evidence, retaining
    external `UNTESTED` paths and all scientific and human-approval limitations.

Record the exact scope, tools, source inventory, findings, dispositions,
exceptions, and limitations. Uncertain or confidential files fail closed and
are not published. Never claim that adding an ignore rule repairs an earlier
commit containing prohibited material. If that occurs, stop publication and
address the history and any required credential containment first.

## Timing and completion

Git initialization, reconstruction, staging, commits, and remote operations wait
for stable integration boundaries. No commit may race a subagent writer.
Per-commit targeted tests must exercise the exact candidate, not a different
unstaged version. Fetch and inspect remote refs before each push; no force-push.

The history method and baseline-test limitation are recorded in
[Git history reconstruction](GIT_HISTORY_RECONSTRUCTION.md). The public audit,
truthful baseline and feature history, verified synchronization, final combined
validation, and the project's last-mutation audit rule remain incomplete gates.
This policy does not change the scientific audit inventory or authorize any
publication by itself.
