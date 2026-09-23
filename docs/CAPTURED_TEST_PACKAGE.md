# Captured test-package execution

The isolated launcher captures the real `tests` package, rather than inventing
a private namespace that is incompatible with the repository's test imports.
Invoke it with the required `-I -S -B` startup flags from the project root.

The inventory has three roles:

| Captured source | Execution role |
| --- | --- |
| `tests/__init__.py` | Required package initializer; executed in workers, not the parent/audit dispatcher |
| `tests/provider_fixtures.py` | Explicitly approved support module; imported when needed, never selected as a worker |
| `tests/pmc_wire_fixtures.py` | Explicitly approved synthetic PMC support; imported when needed, never selected as a worker |
| Identifier-valid `tests/test_*.py` | Runnable modules; one isolated worker per selected module |

Other helper filenames are refused. An existing directory-only `__pycache__`
entry is ignored; cached bytecode is not used to execute captured sources.
The existing V1 test-source attestation covers the **complete captured package
inventory**, including the initializer and both approved support files. This differs
from a worker's loaded closure and from its runnable test IDs. Support imports
must not inflate test counts or disappear from the source attestation.

The exclusive captured finder handles `tests` and its children, uses an empty
package search path, and refuses uncaptured names. Selected modules use normal
import machinery through that finder, preserving parent-child attributes and
one execution per worker. Pre-existing public-package modules are refused.
The finder remains active through methods, class/module teardown and final
attestation, then is removed. Parent report validation compares full source
attestations and the loaded package/selected-module hashes. Changed unused
support files also invalidate final publication.

Static test-ID derivation, strict discovered/static equality and observed test
outcome accounting are unchanged. Re-exporting a foreign `TestCase` is not
silently filtered into an apparently passing suite. This package repair does
not relax bootstrap, source identity or report-publication requirements.

## Verification scope

The first private implementation had a real selected-module parent-binding
defect. The expanded 17-control run reproduced it on Python 3.14.6 and 3.11.15;
the failed source and results were retained. The correction uses captured-only
`importlib.import_module` and passes 21 focused controls on both runtimes,
followed by independent complete-patch review.

The installed repair passed three actual captured workers on both runtimes:
18 Dataset-currentness tests, 5 Dataset-publication tests, and 12 permanent
package regression tests. Each run preserved 259 inventoried Python inputs.
The Dataset controls still use explicitly non-evidentiary external/semantic
fixtures. The package audit-dispatch control uses a disposable stub, not a real
repository audit. These overlapping checks are not a full-regression total,
scientific validation, security-platform assessment or public-release clearance.

The later PMC integration adds only the second exact support filename, not a
generic helper rule. Its direct-worker refusal is covered by the existing package
regression. After installation, 23 selected captured workers passed 342 methods
on each runtime, with 74 project files and all 202 test-package files attested;
two additional offline provider workers passed 81 methods. Each pair preserved
280 inventoried inputs, including its driver. Full inventories remain separate
from loaded closures and selected method counts. See [PMC wire custody](PMC_WIRE_CUSTODY.md)
for fixture limitations and overlapping compatibility evidence.

Owners: `scripts/scientist_one_cli.py`, `tests/test_isolated_launchers.py`, and
`tests/test_captured_test_package.py`. Local run evidence is indexed in `.run`;
private generated reports are not release contents.
