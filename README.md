# Scientist-One: recovered pre-vNext baseline

This snapshot contains recovered pre-vNext source and explicitly reconstructed
tests. Its owner-authorized qualified label is `v0.1.0-recovered-baseline`, not
`v0.1.0-trusted-kernel`. As of 2026-09-23, the development review checkpoint
`review/vnext-checkpoint` at `f6b3d92e1884caebea1e715272f527ca7588e5e4` is
published over and preserves the README-only bootstrap. That checkpoint is not
the recovered-baseline import or qualified tag. Owner authorization for the
qualified-baseline publication and tag is recorded; implementation and public
release gates remain pending. This source description is not a public-readiness
approval or proof of synchronization.

The qualification matters: recovered bytes and scoped executable checks do not
establish every historical scientific, recovery, resource or security guarantee.
This is not a vNext release, a research result, independent custody or human E4
approval. The local project is **THIS_REPOSITORY**; the external project remains
**UPSTREAM_SCIENTISTONE**, not an interchangeable identity or a verified comparison.

## What is preserved

- 31 recovered inputs: 26 source/launcher files, three configurations and two
  synthetic calibration fixtures.
- Eight newly authored `SEMANTIC_RECONSTRUCTION` test modules, containing 146
  methods. They are not the missing historical test sources.
- The unchanged portable staging runner, tested predecessor manifest and
  owner-authorized MIT license, plus newly authored import documentation and
  conservative ignore policy. These support files are not recovered source.

Retained execution reports record the reconstructed 146 passing on Python 3.14.6
and 3.11.14, and the same 146 through portable staging on Python 3.14.6 and 3.11.15.
Repeated runtimes and staging runs do not add distinct methods. Historical
364/364 tests and 15/15 architecture controls remain historical reports, not
reproduced totals. See the [reconstruction summary](RECONSTRUCTION_SUMMARY.md)
for evidence identities, separate check counts and substantive limitations.

## Run the reconstructed suite locally

From this directory, choose a new output directory beneath the ignored `tmp/`
directory. The final destination must not already exist:

```text
python3 -I -S -B run_portable_candidate.py --output-dir tmp/baseline-check-1
```

The POSIX-oriented runner requires regular files and non-symlink path components.
It creates a fresh physical project named `ScientistOne`, prepares local runtime
directories and an honest `NEW_TEST_FIXTURE` bootstrap with no historical
authority, then invokes the unchanged captured launcher with `test-suite`.
It checks the 39 pinned inputs, exact 146 test IDs, runtime, source/test
attestations and zero bad outcomes. Generated roots and logs remain local and
must not be published. This procedure does not reproduce the original 364 tests
or close the partial/stopped guarantees.

[`manifest.json`](manifest.json) is intentionally the byte-identical manifest of
the tested **private staging predecessor**. Its PRIVATE status and excluded tag
claim describe that evidence scope; it is not a public approval or a complete
inventory of subsequently authored documentation. The qualified import purpose
is described here without rewriting those tested metadata bytes.

See [history reconstruction](docs/GIT_HISTORY_RECONSTRUCTION.md) for the retained
README-bootstrap ancestry and [public-release policy](docs/PUBLIC_RELEASE_POLICY.md)
for publication controls. The [MIT license](LICENSE) does not grant rights
to third-party material or waive those checks.
