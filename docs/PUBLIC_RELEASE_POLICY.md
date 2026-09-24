# Public-release policy for the recovered baseline

Status: proposed policy; public-readiness audit pending. The qualified tag name
`v0.1.0-recovered-baseline` is owner-authorized. As of 2026-09-23, development
review checkpoint `review/vnext-checkpoint` at
`f6b3d92e1884caebea1e715272f527ca7588e5e4` is published over and preserves the
README-only bootstrap; it is not the recovered-baseline import or qualified tag.
Owner authorization for the qualified-baseline publication and tag is recorded;
implementation and public-readiness gates remain pending. No routine
reauthorization is needed for that scope. This policy does not grant scientific,
human E4, security/platform or stopped-review clearance.

## Explicit content selection

Select only reviewed source, tests, configurations, necessary redistributable
synthetic fixtures, license and portable documentation. The tested manifest's
39 input rows remain unchanged. Maintain a separate exact release inventory
for all selected support files; the unchanged private-predecessor manifest is
not an inventory of later documentation. Never stage the entire workspace or
copy private evidence trees as proof of testing.

Keep run/state/custody/holdout stores, provider exchanges, local orchestration
and app configuration, caches, virtual environments, preservation archives,
generated reports/packages, logs, crash dumps and private literature/data out
of public content. Generated verification evidence needs separate minimization
and content review before any publication. A synthetic label or successful test
does not establish confidentiality, redistribution rights or public safety.

The conservative [ignore rules](../.gitignore) are defense in depth, not a
clearance mechanism. They do not delete local files or change the scientific
inventory, provenance or audit rules. Effective ignores remain unverified
until checked against the actual final repository. Do not use force-add to
bypass them. A necessary redistributable asset requires a narrow documented
exception and full review. `.env.example` is merely eligible for review, not
automatically sanitized or approved.

## Mandatory review of exact bytes and history

Before publication, review the exact proposed public files and every reachable
committed version, including the existing README bootstrap:

1. Secrets and credentials, without exposing sensitive matches in reports.
2. Confidential provider input/output, including parsed, derived, error and
   metadata content. Pattern scanning alone is insufficient.
3. Private literature and datasets, including inline test/document content.
4. Machine-specific absolute paths in source, tests, documentation and metadata.
5. Generated artifacts, including renamed or embedded material.
6. Every file larger than 1 MiB (1,048,576 bytes): record path, size, hash,
   necessity and disposition. Smaller files still require every other check.
7. Licenses of actual runtime, test, build and bundled dependencies.
8. Copyright and redistribution rights for code, figures, papers, data and
   fixtures. Owner-authorized MIT licensing does not license third-party work.
9. Effective ignores and the actual tracked, staged, untracked and ignored
   populations, with required source/test paths and prohibited-path examples.
10. README and documentation claims against scoped evidence, retaining all
    reconstructed/historical distinctions and partial/stopped/external limits.

Record scope, exact inventory, methods, findings, exceptions, dispositions and
limitations. Uncertain/confidential content is excluded while the repository
is public. Adding an ignore rule after content entered history is not
remediation; halt publication and resolve contaminated history and any required
credential containment before continuing. No publication-risk assessment is
performed merely by writing this policy.

## Stable boundary and audit freshness

Git mutations wait for a stable writer/test-free integration boundary and a
fresh verified complete private preservation. Inspect exact staged filenames,
full diff/statistics and resulting commits. Relevant checks must apply to the
actual selected bytes; do not substitute tests of a different unstaged version.
Documentation-only changes require their exact content/link/provenance checks,
not an automatic repeat of every unchanged kernel test. Executable or consumed
input changes require an explicitly assessed affected verification scope.

Preserve [README-bootstrap ancestry](GIT_HISTORY_RECONSTRUCTION.md), legitimate
authorship and actual reconstruction time. Fetch and inspect exact refs before
each authorized push, never force-push, and verify publication afterward.
Do not change remote visibility or substitute another repository implicitly.

Reconcile Git/commit operations with the actual final project's scientific
audit inventory and last-mutation rule. Synthetic adapter tests are not an
audit of this repository's real history. Do not edit audited content afterward
to backfill an audit digest or silently exclude Git metadata. Public-content
checks do not resume or replace safety-stopped investigations. Publication and
whole-project completion remain separate from this metadata preparation.
