# History of the qualified recovered-baseline import

This document describes the transparent reconstruction method. The owner
authorized `v0.1.0-recovered-baseline` on 2026-09-21 in place of
`v0.1.0-trusted-kernel`, retaining the recovered source's partial and unverified
guarantees. As of 2026-09-23, development review checkpoint
`review/vnext-checkpoint` at `f6b3d92e1884caebea1e715272f527ca7588e5e4` is
published over and preserves the README-only bootstrap. It is not the
recovered-baseline import or qualified tag. Owner authorization for the
qualified-baseline publication and tag is recorded; implementation and public
release gates remain pending. This methodological description does not grant
scientific or public-content clearance.

## Preserve the existing bootstrap

The designated canonical remote is the existing
[Scientist-Ultra repository](https://github.com/ZelinZhu-Richard/Scientist-Ultra).
Recorded inspection identifies commit
`bba9ec5b652e78b5f4bfda6a101d640f0e07869e` as the owner's README-only bootstrap,
not a verified implementation baseline or completed vNext release. Preserve
that commit, its actual authorship and timestamp as an ancestor of the import.
Do not erase it, force-push over it or invent an initially empty history.
Remote refs and visibility require a fresh check at the publication boundary;
these historical observations do not establish their current state.

## What is reconstructed

The project predates its implementation Git history. The recovered snapshot
establishes one joint source/configuration state, not a sequence of independently
verified development milestones. The 31 recovered source/launcher,
configuration and synthetic fixture inputs remain byte-identical; the eight
test modules are newly authored semantic reconstructions. The complete original
test suite and original architecture packet were not recovered. See the
[reconstruction summary](../RECONSTRUCTION_SUMMARY.md) for exact classifications,
retained report identities and the limits of each evidence category.

Prefer one coherent descendant import:

```text
chore(import): preserve recovered pre-vnext baseline
```

Use its actual creation time and legitimate configured authorship. Explicitly
review replacement of the bootstrap README with baseline-specific documentation;
the original README remains in ancestry. Do not backdate, invent authors,
split the joint snapshot into fictitious historical milestones or imply that
Git recorded the original development process. Preserve all private and
uncommitted work before any reconstruction or checkout operation.

The README, reconstruction summary, history/policy documents and ignore rules
are new support metadata. The unchanged `manifest.json` describes the tested
private predecessor and its 39 inputs, not an exhaustive final public inventory.
Any public selection or sanitization must be recorded separately with exact
new bytes; sanitized bytes must never be labeled original recovered bytes.
No such source sanitization is performed by these documents.

Only a reviewed recovered import is eligible for the qualified tag. It must
retain the partial resource/recovery/reserve guarantees and excluded/stopped
review, not claim historical 364/15 or blanket trust. The published development
review checkpoint does not establish a recovered-baseline import or qualified
tag, and this baseline metadata makes no vNext implementation or completion
claims.

## Before import and publication

Reach a stable writer/test-free boundary, preserve the complete current tree
privately, and verify the exact selected public contents, staged changes and
reachable history under the [public-release policy](PUBLIC_RELEASE_POLICY.md).
Existing private backup/report identities alone are not current protection or
public clearance. No broad staging, force-add or confidential-data publication
is authorized by the qualified-label decision.

After the required implementation and public-content gates pass, proceed under
the recorded owner authorization while preserving bootstrap ancestry in any
transparent import and creating the qualified tag. No routine reauthorization
is needed for that already-authorized scope. Escalate material scope changes,
uncertain or potentially confidential content, remote-visibility changes, and
destructive or history-rewriting actions before proceeding. Before authorized
synchronization, fetch and inspect exact remote refs and unchanged release
evidence. Never force-push or imply that the published development checkpoint is
the recovered-baseline import. Record actual commit/tag/ref identities and any
remaining limitations when those operations occur; do not fill them with
proposed or fabricated values.
