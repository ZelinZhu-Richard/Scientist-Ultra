# Recovered baseline: reconstruction and evidence limits

Authored 2026-09-21 as new support metadata for the recovered snapshot. As of
2026-09-23, development review checkpoint `review/vnext-checkpoint` at
`f6b3d92e1884caebea1e715272f527ca7588e5e4` is published over and preserves the
README-only bootstrap. It is not the recovered-baseline import or qualified tag.
Owner authorization for the qualified-baseline publication and tag is recorded;
implementation, public-content and other release gates remain pending. No
public-content audit or new execution is established by authoring this document.
The owner-authorized qualified label is `v0.1.0-recovered-baseline`, not
`v0.1.0-trusted-kernel`.

## Identity and classification

The frozen input set comprises 26 recovered source/launcher files, three
recovered configurations and two recovered synthetic calibration fixtures.
Eight newly authored reconstructed test modules add scoped regression support;
they are not original historical tests. Their per-path classifications, sizes
and SHA-256 hashes remain in the unchanged [tested manifest](manifest.json).

| Preserved identity | SHA-256 |
|---|---|
| Tested private candidate manifest | `38bb80a25711b3e2267374f9639b2de70fd8e98246bffc1ad0e16832fcd4d187` |
| Portable staging runner | `a4d61461ddd5c5fce956c22540cad4d3571d30a13bcea2c3808bc822353b6113` |
| Recovered source inventory | `a4bc87d557696c761b0df05bf0ff3eb8dedd1a5f5d4d7fb0cf8413bff8aee786` |
| Recovered configuration inventory | `95fba6687d56bd503a4689bb0c4d0ef030499af5fffe3d509e8f7d14a219a52e` |
| Retained source-recovery report | `9549daa2ef8ff654a26d6e0936d13bc7251382132523f5beb5f30c9dc337484b` |

The source/configuration inventories and recovery report identify retained
private evidence; they are not included public attachments. A reported hash
alone does not let a reader inspect the underlying evidence or prove a claim.
The manifest and runner are directly included support files. No raw run,
holdout, custody, bootstrap, provider exchange or verification log is included
as a public proof artifact.

The manifest's `PRIVATE_LOCAL_PORTABLE_BASELINE_CANDIDATE` and
`PRIVATE_LOCAL_PORTABLE_STAGING` fields intentionally describe the tested
predecessor, not a later publication state. Its 39 input rows and 31/8 partition
are unchanged. Its support list describes the predecessor, not a complete
release inventory: this README, summary, history/policy documents and ignore
rules are newly authored support, excluded from recovered identity. No public
approval is inferred from preserving or passing that manifest.

## Distinct evidence scopes

These are retained observations, not tests rerun during metadata preparation.
The report identities below identify private records, not downloadable public
reports. Keep their dates and runtimes distinct.

| Evidence | Recorded result and exact scope |
|---|---|
| Historical baseline | Reported 364/364 tests and 15/15 architecture controls. Complete original test sources and original architecture evidence packet remain unrecovered. These totals are not independently reproduced by the reconstruction. |
| September 19 reconstructed suite | 146 methods in eight new modules passed on actual Python 3.14.6 and 3.11.14 against recovered source. This is `SEMANTIC_RECONSTRUCTION`, not recovery of 364 methods. |
| September 20 portable candidate | The same 146 methods passed through new staging support on actual Python 3.14.6 and 3.11.15, in fresh physical roots using the unchanged captured launcher. This verifies the portable support path, not 146 additional methods. |
| Separate lifecycle/refusal evidence | Seven-command synthetic lifecycle, exact primary-output reproduction within frozen tolerance, completed-run resume without confirmatory replay, and two corrupt-output refusals. These are bounded synthetic scenarios, not comprehensive lifecycle or release assurance. |
| Separate checkpoint controls | Two new controls, each on Python 3.14.6 and 3.11.15: continuation from a completed checkpoint without duplicate pilot work, and a typed durable stop after inert configuration drift before pilot. Not four distinct tests, a historical 148, or part of the portable 146. |
| Separate runner support controls | Six support controls on Python 3.14.6 and 3.11.15: report/ID/runtime rejection, output-path handling and timeout retention. Mocked reports are support rejection fixtures, not evidence that the kernel passed. |
| Separate architecture validator | Four original structural consistency checks passed against a newly reconstructed private packet. The packet records 11 scoped PASS / 3 PARTIAL / 1 BLOCKED. Four validator checks do not establish 15/15 substantive acceptance. |

Retained reconstructed report SHA-256 identities:

- September 19 Python 3.14.6: `75d4ccfb019f51c5d18073749112ad2c9931784d70d78fa2c81d838c6f021487`.
- September 19 Python 3.11.14: `9826a368184a0bca3ba37e325734d2cacb173ac0e338b0c00df023edcae7b8cc`.
- Portable Python 3.14.6: `059203dd284e403aaf5c7a74fd124dce588f980e9ae94f52730732ca4d0b1aa1`.
- Portable Python 3.11.15: `74d02c495ab732142aeac20dd3c8e1b5ac2eb4a9a69e828fa26ba9a997239389`.

The portable reports bind manifest `38bb80a2…` and runner `a4d61461…` above. Later
documentation is not retroactively covered by those execution hashes. The
checkpoint/support/architecture test sources and private packet are not
included in the portable 146, so the provided runner does not rerun those
separate checks. Do not sum overlapping runs or add unlike evidence categories
into a purported complete baseline test total.

## Substantive limitations retained by the qualified tag

- The packet's PARTIAL rows are `review_packet_usability`, `validity_reserve`
  and `drift_and_stall_detection`. `prompt_injection_resistance` remains
  excluded/BLOCKED. The scoped PASS labels do not assert every possible
  scientific, security, resource or recovery guarantee.
- Recovery checks include actual ledger/artifact validation, quarantine,
  checkpoint selection and the bounded completed-checkpoint continuation above.
  They do not establish all mid-write crash or arbitrary interruption cases.
- Resource component tests use deterministic injected observations and exercise
  admission, budgeting, pause/checkpoint decisions and bounded backoff. The
  recovered orchestration does not establish durable integration of all
  no-progress, failed-work and worker-crash observations. A raised operation
  exception is not proof of an observed OS crash. Physical containment and GPU
  capacity are not certified by these tests.
- The recovered integer validity budget and protocol role labels do not prove
  a protected population denominator, membership/access history, or that 40%
  of actual data remains untouched by pilot, tuning and story selection.
  Repeating integer-partition tests would not establish that missing property.
- Frozen synthetic interpretation/reveal and logical role checks do not provide
  independent external custody or genuine independent scientific review.
  No human-only E4 authority is synthesized or conferred by this import.
- The safety-stopped review and native/J lifetime, execution/read-restriction,
  and scholarly event-key/capture-alias investigations remain stopped. Neither
  these documents nor public-content checks resume, replace or clear them.
  No comprehensive security/platform acceptance is claimed.
- Results are bounded synthetic software evidence, not real-data validation,
  external-provider validation, publication readiness, external novelty or
  superiority over UPSTREAM_SCIENTISTONE. Broader external validation remains
  UNTESTED or blocked where its prerequisites are unavailable.

A retained source-gap follow-up documents these resource/reserve limits under
SHA-256 `70329c986cc5ec251f4e96999b71aeefc59f6762a7a0c8c0f881af848131da8f`.
The private support closure is identified by
`9f6f657fb8965a6a5d96a8817043c0b2e404fcec1000e65a9d47c1403af056d4`;
the separate checkpoint closure by
`cda809beb9ff592fa4c41f5f875717e464f2650749def6667890508b0335954b`.
These identities provide provenance references, not public access or proof on
their own. This portable metadata selection does not promote private packet
usability or any partial/stopped criterion to complete acceptance.

## Reproduction support and release boundary

The [README](README.md) describes the unchanged POSIX-oriented runner. It creates
an honest fresh local test fixture and canonical `ScientistOne` project root;
it does not create app, historical, provider, custody or human authority.
Original warnings and failed support-development attempts remain in private
evidence, rather than being rewritten as successful original executions.

This metadata changes no source, configuration, fixture, test, runner or tested
manifest bytes. It does not repair historical implementation limitations.
[History reconstruction](docs/GIT_HISTORY_RECONSTRUCTION.md) explains the
qualified import and preserved bootstrap; [public-release policy](docs/PUBLIC_RELEASE_POLICY.md)
defines the separate checks required before publication.
