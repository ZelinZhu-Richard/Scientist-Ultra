# Dependency Review

## Decision

Scientist-One vNext's required Python core uses Python 3.11+ and the standard library. `pyproject.toml` declares `dependencies = []`. At the final-verification checkpoint, `/opt/homebrew/bin/python3` reported Python 3.14.6 and satisfied the required `-I -S -B` startup flags. No dependency acquisition was authorized or performed; provider and experiment validation remains offline at this checkpoint.

September20 release-content inspection found no bundled third-party distribution
in the explicit prospective source/test/configuration/fixture population. This is
not a claim that optional integrations have no dependencies: `device.py` can adapt
an already-preloaded, separately trusted PyTorch module and observes installed
distribution metadata; it explicitly refuses automatic framework import.
Hardware profiling can observe installed numerical-framework versions. Python,
Git, operating-system tools and optional frameworks belong to the deployment
environment and are not redistributed in the reviewed candidate. Any future
bundled dependency needs its own exact license/source review. Full candidate
copyright and public-readiness clearance remains pending.

The core may use standard-library facilities including `argparse`, `dataclasses`, `pathlib`, `hashlib`, `json`, `sqlite3`, `statistics`, `subprocess` with explicit argument arrays, `tempfile` directed inside the project where controlled, and `unittest`. Optional accelerator detection must not turn an installed third-party library into a required dependency.

## Commands that are not authorized

Do not run `pip install`, `uv add`, `poetry add`, `conda install`, `npm install`, `pnpm install`, `yarn install`, `npx`, `cargo add`, `cargo install`, `brew install`, remote scripts, Git dependencies, or downloads. A package manager being installed or an automatic sandbox reviewer being available is not dependency approval.

If optional functionality cannot run with the existing local environment, record it as unavailable, use the CPU/standard-library path, and continue independent work. Do not silently acquire a library to make a test pass.

## Review evidence

Run from the project root:

```sh
set -eu
/opt/homebrew/bin/python3 -I -S -B -c 'import tomllib, pathlib; p=tomllib.loads(pathlib.Path("pyproject.toml").read_text()); d=p["project"]["dependencies"]; print(d); raise SystemExit(0 if d == [] else 1)'
/opt/homebrew/bin/python3 -I -S -B - <<'PY'
import os
from pathlib import Path
import stat

root = Path.cwd().resolve(strict=True)
names = {"Pipfile.lock", "poetry.lock", "uv.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "conda-lock.yml"}
found = []
for directory, subdirs, files in os.walk(root, topdown=True, followlinks=False):
    parent = Path(directory)
    for name in sorted(subdirs + files):
        item = parent / name
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise SystemExit(f"unsafe linked entry prevents complete scan: {item.relative_to(root)}")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise SystemExit(f"unsafe special entry prevents complete scan: {item.relative_to(root)}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise SystemExit(f"unsafe hard-linked file prevents complete scan: {item.relative_to(root)}")
    for name in sorted(files):
        if name in names or (name.startswith("requirements") and name.endswith(".txt")):
            found.append((parent / name).relative_to(root).as_posix())
if found:
    raise SystemExit("unexpected dependency/lock files: " + ", ".join(sorted(found)))
print("NO_DEPENDENCY_LOCKFILES")
PY
```

Expected dependency declaration is `[]` and the scan must print `NO_DEPENDENCY_LOCKFILES`. Any discovered lock/dependency file fails this recorded no-dependency review until a separate decision updates the policy. The authoritative test and audit entry points are the exact captured commands `/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py test-suite` and `/opt/homebrew/bin/python3 -I -S -B scripts/scientist_one_cli.py audit-project`; both preserve the captured import boundary and the audit repeats the dependency/lockfile policy. Direct `PYTHONPATH` imports are not accepted evidence. The historical pre-vNext 364/364 suite required no dependency acquisition; current post-vNext counts remain pending until the final captured run. The whole-project audit is emitted only after the documentation/state snapshot is frozen; its self-excluded `reports/final_audit.json` is the status authority.

## Optional local toolchains

Hardware profiling may observe already-installed tools and numerical libraries without importing them into the trusted core or installing anything. `cpu` must remain available. The device API may select `mps` only through an explicitly supplied adapter or a framework already imported by a separately trusted startup, when the operation is supported and a frozen CPU-versus-MPS parity test passes within tolerance. The captured-source CLI runs with `-S`, preloads no third-party framework, and currently supplies no such adapter, so it takes and records the CPU path. Failure or absence is not a reason to download PyTorch, MLX, JAX, TensorFlow, or another framework.

## Future dependency decision

A future addition requires a project-specific review that identifies exact package/version/source/hash, license, transitive dependencies, native-code and serialization risk, network/install commands, artifact/cache locations, update policy, deterministic/offline effect, rollback, and independent human authority where required. Approval from any unrelated repository is invalid here.

No future review may weaken path confinement, introduce executable untrusted serialization, enable hidden telemetry, or convert external service availability into a prerequisite for validating existing local evidence.

The current registry's bounded byte API accepts at most 64 MiB per object and 10,000 records even though the resource controller permits up to 2 GiB total project artifacts. A future large-object/registry streaming provider is an architectural and dependency decision: it must preserve hashing, size limits, no-follow confinement, atomic publication, offline determinism, and reviewable provenance.
