#!/usr/bin/env python3
"""Captured-source, isolated launcher for the Scientist-One CLI.

The project package is never placed on ``sys.path``.  Instead, this launcher
opens every package source file without following links, captures its exact
bytes, and installs a dedicated importer which can execute only those bytes.
The on-disk tree is checked again immediately before command dispatch.
"""

from __future__ import annotations

import sys


if not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.safe_path
    and sys.flags.ignore_environment
    and sys.flags.no_user_site
    and sys.flags.dont_write_bytecode
    and sys.flags.optimize == 0
    and sys.dont_write_bytecode
):
    raise SystemExit(
        "refusing unsafe startup; invoke the pinned interpreter with -I -S -B"
    )


import hashlib
import importlib.abc
import importlib.machinery
import os
from pathlib import Path
import secrets
import stat


if not hasattr(os, "O_NOFOLLOW"):
    raise SystemExit("refusing startup without no-follow filesystem support")


_PACKAGE_NAME = "scientist_one"
_MAX_SOURCE_FILE_BYTES = 4 * 1024 * 1024
_MAX_SOURCE_TREE_BYTES = 64 * 1024 * 1024
_MAX_SOURCE_ENTRIES = 2_048
_MAX_TEST_ENTRIES = 2_048
_NOFOLLOW = os.O_NOFOLLOW
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | _NOFOLLOW


def _fail(message: str) -> "None":
    raise SystemExit(message)


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
    )


def _same_source_state(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        _same_identity(left, right)
        and left.st_nlink == right.st_nlink
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _canonical_regular_file(
    path: Path,
) -> tuple[Path, bytes, os.stat_result]:
    candidate = path if path.is_absolute() else Path.cwd() / path
    try:
        descriptor = os.open(candidate, _FILE_FLAGS)
    except OSError as exc:
        _fail(f"launcher is unavailable or unsafe: {exc}")
    try:
        source, opened = _read_source(descriptor, "scripts/scientist_one_cli.py")
        named = os.stat(candidate, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not _same_identity(opened, named)
        ):
            _fail("launcher must be a single-link regular file")
        canonical = candidate.resolve(strict=True)
        resolved = os.stat(canonical, follow_symlinks=False)
        if not _same_identity(opened, resolved):
            _fail("launcher identity changed during verification")
        return canonical, source, opened
    finally:
        os.close(descriptor)


def _read_source(descriptor: int, label: str) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        _fail(f"unsafe Scientist-One source file: {label}")
    if before.st_size < 0 or before.st_size > _MAX_SOURCE_FILE_BYTES:
        _fail(f"oversized Scientist-One source file: {label}")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65536, _MAX_SOURCE_FILE_BYTES + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_SOURCE_FILE_BYTES:
            _fail(f"oversized Scientist-One source file: {label}")
        chunks.append(chunk)
    after = os.fstat(descriptor)
    if (
        not _same_identity(before, after)
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
        or total != after.st_size
    ):
        _fail(f"Scientist-One source changed while being captured: {label}")
    return b"".join(chunks), after


def _bounded_directory_names(
    descriptor: int,
    *,
    maximum: int,
    overflow_message: str,
) -> tuple[str, ...]:
    names: list[str] = []
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if len(names) >= maximum:
                _fail(overflow_message)
            names.append(entry.name)
    return tuple(sorted(names))


class _CapturedSource:
    __slots__ = (
        "module_name",
        "path",
        "source",
        "sha256",
        "identity",
        "is_package",
    )

    def __init__(
        self,
        module_name: str,
        path: Path,
        source: bytes,
        identity: os.stat_result,
        *,
        is_package: bool,
    ) -> None:
        self.module_name = module_name
        self.path = path
        self.source = source
        self.sha256 = hashlib.sha256(source).hexdigest()
        self.identity = identity
        self.is_package = is_package


class _CapturedTree:
    __slots__ = (
        "root",
        "source_root",
        "package_root",
        "root_identity",
        "scripts_identity",
        "source_identity",
        "package_identity",
        "source_names",
        "package_names",
        "tests_root",
        "tests_identity",
        "test_names",
        "test_records",
        "launcher",
        "records",
    )

    def __init__(
        self,
        root: Path,
        launcher: Path,
        initial_launcher_source: bytes,
        initial_launcher_identity: os.stat_result,
        *,
        capture_tests: bool = False,
    ) -> None:
        self.root = root
        self.source_root = root / "src"
        self.package_root = self.source_root / _PACKAGE_NAME
        self.tests_root = root / "tests"
        self.tests_identity: os.stat_result | None = None
        self.test_names: tuple[str, ...] = ()
        self.test_records: dict[str, _CapturedSource] = {}
        self.records: dict[str, _CapturedSource] = {}

        root_fd = scripts_fd = source_fd = package_fd = tests_fd = -1
        try:
            root_fd = os.open(root, _DIRECTORY_FLAGS)
            self.root_identity = os.fstat(root_fd)
            scripts_fd = os.open("scripts", _DIRECTORY_FLAGS, dir_fd=root_fd)
            self.scripts_identity = os.fstat(scripts_fd)
            if launcher != root / "scripts" / "scientist_one_cli.py":
                _fail("launcher is outside the canonical project scripts directory")
            launcher_fd = os.open(
                "scientist_one_cli.py", _FILE_FLAGS, dir_fd=scripts_fd
            )
            try:
                launcher_source, launcher_identity = _read_source(
                    launcher_fd, "scripts/scientist_one_cli.py"
                )
            finally:
                os.close(launcher_fd)
            if (
                not _same_source_state(
                    launcher_identity, initial_launcher_identity
                )
                or launcher_source != initial_launcher_source
            ):
                _fail("launcher changed after initial verification")
            self.launcher = _CapturedSource(
                "__launcher__",
                launcher,
                initial_launcher_source,
                initial_launcher_identity,
                is_package=False,
            )
            source_fd = os.open("src", _DIRECTORY_FLAGS, dir_fd=root_fd)
            self.source_identity = os.fstat(source_fd)
            self.source_names = _bounded_directory_names(
                source_fd,
                maximum=1,
                overflow_message=(
                    "unexpected top-level entry in the Scientist-One source root"
                ),
            )
            if self.source_names != (_PACKAGE_NAME,):
                _fail("unexpected top-level entry in the Scientist-One source root")

            package_fd = os.open(_PACKAGE_NAME, _DIRECTORY_FLAGS, dir_fd=source_fd)
            self.package_identity = os.fstat(package_fd)
            self.package_names = _bounded_directory_names(
                package_fd,
                maximum=_MAX_SOURCE_ENTRIES,
                overflow_message="Scientist-One captured source inventory is invalid",
            )
            self._capture_package(package_fd)
            if capture_tests:
                tests_fd = os.open("tests", _DIRECTORY_FLAGS, dir_fd=root_fd)
                self.tests_identity = os.fstat(tests_fd)
                self.test_names = _bounded_directory_names(
                    tests_fd,
                    maximum=_MAX_TEST_ENTRIES + 1,
                    overflow_message="Scientist-One captured test inventory is invalid",
                )
                self._capture_tests(tests_fd)
        except OSError as exc:
            _fail(f"Scientist-One source tree is unavailable or unsafe: {exc}")
        finally:
            for descriptor in (tests_fd, package_fd, source_fd, scripts_fd, root_fd):
                if descriptor >= 0:
                    os.close(descriptor)

    def _capture_package(self, package_fd: int) -> None:
        total = len(self.launcher.source)
        for name in self.package_names:
            if name == "__pycache__":
                cache_info = os.stat(name, dir_fd=package_fd, follow_symlinks=False)
                if not stat.S_ISDIR(cache_info.st_mode):
                    _fail("unsafe Scientist-One bytecode-cache entry")
                continue
            if not name.endswith(".py"):
                _fail(f"unexpected Scientist-One package entry: {name}")
            stem = name[:-3]
            if not stem.isidentifier():
                _fail(f"invalid Scientist-One module name: {name}")
            module_name = (
                _PACKAGE_NAME if stem == "__init__" else f"{_PACKAGE_NAME}.{stem}"
            )
            try:
                descriptor = os.open(name, _FILE_FLAGS, dir_fd=package_fd)
            except OSError as exc:
                _fail(f"unsafe Scientist-One source file {name}: {exc}")
            try:
                source, identity = _read_source(descriptor, name)
            finally:
                os.close(descriptor)
            total += len(source)
            if total > _MAX_SOURCE_TREE_BYTES:
                _fail("Scientist-One captured source tree is oversized")
            if (
                module_name in self.records
                or len(self.records) >= _MAX_SOURCE_ENTRIES - 1
            ):
                _fail("Scientist-One captured source inventory is invalid")
            self.records[module_name] = _CapturedSource(
                module_name,
                self.package_root / name,
                source,
                identity,
                is_package=stem == "__init__",
            )
        if _PACKAGE_NAME not in self.records or f"{_PACKAGE_NAME}.cli" not in self.records:
            _fail("Scientist-One package must contain __init__.py and cli.py")

    def _capture_tests(self, tests_fd: int) -> None:
        total = len(self.launcher.source) + sum(
            len(record.source) for record in self.records.values()
        )
        for name in self.test_names:
            if name == "__pycache__":
                cache_info = os.stat(name, dir_fd=tests_fd, follow_symlinks=False)
                if not stat.S_ISDIR(cache_info.st_mode):
                    _fail("unsafe Scientist-One test bytecode-cache entry")
                continue
            if not name.startswith("test_") or not name.endswith(".py"):
                _fail(f"unexpected Scientist-One test entry: {name}")
            stem = name[:-3]
            if not stem.isidentifier():
                _fail(f"invalid Scientist-One test module name: {name}")
            module_name = f"_scientist_one_tests.{stem}"
            try:
                descriptor = os.open(name, _FILE_FLAGS, dir_fd=tests_fd)
            except OSError as exc:
                _fail(f"unsafe Scientist-One test source file {name}: {exc}")
            try:
                source, identity = _read_source(descriptor, f"tests/{name}")
            finally:
                os.close(descriptor)
            total += len(source)
            if total > _MAX_SOURCE_TREE_BYTES:
                _fail("Scientist-One captured executable tree is oversized")
            if (
                module_name in self.test_records
                or len(self.test_records) >= _MAX_TEST_ENTRIES
            ):
                _fail("Scientist-One captured test inventory is invalid")
            self.test_records[module_name] = _CapturedSource(
                module_name,
                self.tests_root / name,
                source,
                identity,
                is_package=False,
            )
        if not self.test_records:
            _fail("Scientist-One test suite contains no captured tests")

    def _open_live_tree(self) -> tuple[int, int, int, int, int]:
        root_fd = scripts_fd = source_fd = package_fd = tests_fd = -1
        try:
            root_fd = os.open(self.root, _DIRECTORY_FLAGS)
            root_info = os.fstat(root_fd)
            if not _same_identity(root_info, self.root_identity):
                _fail("Scientist-One project root identity changed after capture")
            scripts_fd = os.open("scripts", _DIRECTORY_FLAGS, dir_fd=root_fd)
            scripts_info = os.fstat(scripts_fd)
            if not _same_identity(scripts_info, self.scripts_identity):
                _fail("Scientist-One scripts directory identity changed after capture")
            source_fd = os.open("src", _DIRECTORY_FLAGS, dir_fd=root_fd)
            source_info = os.fstat(source_fd)
            if not _same_identity(source_info, self.source_identity):
                _fail("Scientist-One source directory identity changed after capture")
            if _bounded_directory_names(
                source_fd,
                maximum=1,
                overflow_message=(
                    "Scientist-One source directory names changed after capture"
                ),
            ) != self.source_names:
                _fail("Scientist-One source directory names changed after capture")
            package_fd = os.open(_PACKAGE_NAME, _DIRECTORY_FLAGS, dir_fd=source_fd)
            package_info = os.fstat(package_fd)
            if not _same_identity(package_info, self.package_identity):
                _fail("Scientist-One package directory identity changed after capture")
            if _bounded_directory_names(
                package_fd,
                maximum=_MAX_SOURCE_ENTRIES,
                overflow_message="Scientist-One package names changed after capture",
            ) != self.package_names:
                _fail("Scientist-One package names changed after capture")
            if self.tests_identity is not None:
                tests_fd = os.open("tests", _DIRECTORY_FLAGS, dir_fd=root_fd)
                tests_info = os.fstat(tests_fd)
                if not _same_identity(tests_info, self.tests_identity):
                    _fail("Scientist-One tests directory identity changed after capture")
                if _bounded_directory_names(
                    tests_fd,
                    maximum=_MAX_TEST_ENTRIES + 1,
                    overflow_message="Scientist-One test names changed after capture",
                ) != self.test_names:
                    _fail("Scientist-One test names changed after capture")
            return root_fd, scripts_fd, source_fd, package_fd, tests_fd
        except BaseException:
            for descriptor in (tests_fd, package_fd, source_fd, scripts_fd, root_fd):
                if descriptor >= 0:
                    os.close(descriptor)
            raise

    def attest_live_tree(self) -> None:
        root_fd, scripts_fd, source_fd, package_fd, tests_fd = self._open_live_tree()
        try:
            try:
                launcher_fd = os.open(
                    "scientist_one_cli.py", _FILE_FLAGS, dir_fd=scripts_fd
                )
            except OSError as exc:
                _fail(f"Scientist-One launcher disappeared after capture: {exc}")
            try:
                launcher_source, launcher_identity = _read_source(
                    launcher_fd, "scripts/scientist_one_cli.py"
                )
            finally:
                os.close(launcher_fd)
            if not _same_source_state(launcher_identity, self.launcher.identity):
                _fail("Scientist-One launcher identity changed after capture")
            if (
                len(launcher_source) != len(self.launcher.source)
                or hashlib.sha256(launcher_source).digest()
                != hashlib.sha256(self.launcher.source).digest()
            ):
                _fail("Scientist-One launcher digest changed after capture")
            for record in self.records.values():
                name = record.path.name
                try:
                    descriptor = os.open(name, _FILE_FLAGS, dir_fd=package_fd)
                except OSError as exc:
                    _fail(f"Scientist-One source disappeared after capture: {name}: {exc}")
                try:
                    source, identity = _read_source(descriptor, name)
                finally:
                    os.close(descriptor)
                if not _same_source_state(identity, record.identity):
                    _fail(f"Scientist-One source identity changed after capture: {name}")
                if (
                    len(source) != len(record.source)
                    or hashlib.sha256(source).digest()
                    != hashlib.sha256(record.source).digest()
                ):
                    _fail(f"Scientist-One source digest changed after capture: {name}")
            for record in self.test_records.values():
                name = record.path.name
                try:
                    descriptor = os.open(name, _FILE_FLAGS, dir_fd=tests_fd)
                except OSError as exc:
                    _fail(
                        f"Scientist-One test source disappeared after capture: {name}: {exc}"
                    )
                try:
                    source, identity = _read_source(descriptor, f"tests/{name}")
                finally:
                    os.close(descriptor)
                if not _same_source_state(identity, record.identity):
                    _fail(
                        f"Scientist-One test source identity changed after capture: {name}"
                    )
                if (
                    len(source) != len(record.source)
                    or hashlib.sha256(source).digest()
                    != hashlib.sha256(record.source).digest()
                ):
                    _fail(
                        f"Scientist-One test source digest changed after capture: {name}"
                    )
        finally:
            if tests_fd >= 0:
                os.close(tests_fd)
            os.close(package_fd)
            os.close(source_fd)
            os.close(scripts_fd)
            os.close(root_fd)

    def attestation(self) -> tuple[str, tuple[tuple[object, ...], ...]]:
        entries: list[tuple[object, ...]] = []
        for relative, record in (
            ("scripts/scientist_one_cli.py", self.launcher),
            *(
                (f"src/scientist_one/{item.path.name}", item)
                for item in self.records.values()
            ),
        ):
            identity = record.identity
            entries.append(
                (
                    relative,
                    record.sha256,
                    len(record.source),
                    identity.st_dev,
                    identity.st_ino,
                    identity.st_mtime_ns,
                    identity.st_ctime_ns,
                )
            )
        entries.sort(key=lambda entry: str(entry[0]))
        return ("SCIENTIST_ONE_CAPTURED_SOURCE_V1", tuple(entries))

    def test_attestation(self) -> tuple[str, tuple[tuple[object, ...], ...]]:
        entries = tuple(
            (
                f"tests/{record.path.name}",
                record.sha256,
                len(record.source),
                record.identity.st_dev,
                record.identity.st_ino,
                record.identity.st_mtime_ns,
                record.identity.st_ctime_ns,
            )
            for record in sorted(
                self.test_records.values(), key=lambda item: item.path.name
            )
        )
        return ("SCIENTIST_ONE_CAPTURED_TESTS_V1", entries)


class _CapturedSourceLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Exclusive loader for the captured ``scientist_one`` namespace."""

    def __init__(self, tree: _CapturedTree) -> None:
        self.tree = tree
        self.executed: dict[str, str] = {}

    def find_spec(self, fullname: str, path: object = None, target: object = None):
        if fullname != _PACKAGE_NAME and not fullname.startswith(f"{_PACKAGE_NAME}."):
            return None
        record = self.tree.records.get(fullname)
        if record is None:
            raise ImportError(f"Scientist-One module was not captured: {fullname}")
        spec = importlib.machinery.ModuleSpec(
            fullname,
            self,
            origin=str(record.path),
            is_package=record.is_package,
        )
        spec.has_location = True
        spec.cached = None
        if record.is_package:
            # An empty package path keeps PathFinder away from the filesystem;
            # relative imports are resolved by this meta-path finder instead.
            spec.submodule_search_locations = []
        return spec

    def create_module(self, spec):
        return None

    def exec_module(self, module) -> None:
        name = module.__spec__.name
        record = self.tree.records.get(name)
        if record is None or module.__spec__.loader is not self:
            raise ImportError(f"foreign Scientist-One loader substitution: {name}")
        if name in self.executed:
            raise ImportError(f"Scientist-One module executed more than once: {name}")
        module.__cached__ = None
        code = compile(record.source, str(record.path), "exec", dont_inherit=True)
        self.executed[name] = record.sha256
        exec(code, module.__dict__)

    def is_package(self, fullname: str) -> bool:
        record = self.tree.records.get(fullname)
        if record is None:
            raise ImportError(f"Scientist-One module was not captured: {fullname}")
        return record.is_package


class _CapturedTestLoader(importlib.abc.Loader):
    """Execute only the already captured test bytes; never consult path finders."""

    def __init__(self, tree: _CapturedTree) -> None:
        self.tree = tree
        self.executed: dict[str, str] = {}

    def create_module(self, spec):
        return None

    def exec_module(self, module) -> None:
        name = module.__spec__.name
        record = self.tree.test_records.get(name)
        if record is None or module.__spec__.loader is not self:
            raise ImportError(f"uncaptured Scientist-One test module: {name}")
        if name in self.executed:
            raise ImportError(f"Scientist-One test module executed more than once: {name}")
        module.__cached__ = None
        code = compile(record.source, str(record.path), "exec", dont_inherit=True)
        self.executed[name] = record.sha256
        exec(code, module.__dict__)


def _attest_loaded_modules(loader: _CapturedSourceLoader) -> None:
    if not sys.meta_path or sys.meta_path[0] is not loader:
        _fail("Scientist-One captured-source loader was replaced")
    if sum(finder is loader for finder in sys.meta_path) != 1:
        _fail("Scientist-One captured-source loader registration is ambiguous")

    loaded = 0
    for name, module in tuple(sys.modules.items()):
        if name != _PACKAGE_NAME and not name.startswith(f"{_PACKAGE_NAME}."):
            continue
        record = loader.tree.records.get(name)
        if record is None or module is None:
            _fail(f"uncaptured Scientist-One module was loaded: {name}")
        spec = getattr(module, "__spec__", None)
        if (
            getattr(module, "__loader__", None) is not loader
            or spec is None
            or spec.loader is not loader
            or spec.origin != str(record.path)
            or getattr(module, "__file__", None) != str(record.path)
            or getattr(module, "__cached__", None) is not None
            or loader.executed.get(name) != record.sha256
        ):
            _fail(f"Scientist-One loaded-module attestation failed: {name}")
        loaded += 1
    if (
        loaded < 2
        or _PACKAGE_NAME not in loader.executed
        or f"{_PACKAGE_NAME}.cli" not in loader.executed
    ):
        _fail("Scientist-One CLI was not fully loaded from captured source")


def _load_captured_test_suite(tree: _CapturedTree):
    import types
    import unittest

    package_name = "_scientist_one_tests"
    if package_name in sys.modules:
        _fail("Scientist-One captured test namespace already existed")
    package = types.ModuleType(package_name)
    package_spec = importlib.machinery.ModuleSpec(
        package_name, loader=None, is_package=True
    )
    package_spec.submodule_search_locations = []
    package.__spec__ = package_spec
    package.__package__ = package_name
    package.__path__ = []
    sys.modules[package_name] = package

    test_loader = _CapturedTestLoader(tree)
    suite = unittest.TestSuite()
    for record in sorted(tree.test_records.values(), key=lambda item: item.module_name):
        name = record.module_name
        if name in sys.modules:
            _fail(f"Scientist-One captured test module already existed: {name}")
        spec = importlib.machinery.ModuleSpec(
            name,
            test_loader,
            origin=str(record.path),
            is_package=False,
        )
        spec.has_location = True
        spec.cached = None
        module = types.ModuleType(name)
        module.__spec__ = spec
        module.__loader__ = test_loader
        module.__file__ = str(record.path)
        module.__cached__ = None
        module.__package__ = package_name
        sys.modules[name] = module
        test_loader.exec_module(module)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    return suite, test_loader


def _attest_loaded_tests(tree: _CapturedTree, loader: _CapturedTestLoader) -> None:
    expected = set(tree.test_records)
    if set(loader.executed) != expected:
        _fail("Scientist-One captured test execution set is incomplete")
    loaded = {
        name
        for name in sys.modules
        if name == "_scientist_one_tests" or name.startswith("_scientist_one_tests.")
    }
    if loaded != expected | {"_scientist_one_tests"}:
        _fail("Scientist-One captured test module set changed during execution")
    for name, record in tree.test_records.items():
        module = sys.modules.get(name)
        spec = getattr(module, "__spec__", None)
        if (
            module is None
            or getattr(module, "__loader__", None) is not loader
            or spec is None
            or spec.loader is not loader
            or spec.origin != str(record.path)
            or getattr(module, "__file__", None) != str(record.path)
            or getattr(module, "__cached__", None) is not None
            or loader.executed.get(name) != record.sha256
        ):
            _fail(f"Scientist-One loaded-test attestation failed: {name}")


def _attest_evidence_dispatch(
    tree: _CapturedTree,
    source_loader: _CapturedSourceLoader,
    test_loader: _CapturedTestLoader | None = None,
) -> None:
    tree.attest_live_tree()
    _attest_loaded_modules(source_loader)
    if (
        getattr(sys, "_scientist_one_captured_evidence_capability", None)
        is not source_loader
    ):
        _fail("Scientist-One evidence capability changed during dispatch")
    if getattr(sys, "_scientist_one_captured_source_attestation", None) != (
        tree.attestation()
    ):
        _fail("Scientist-One source attestation changed during evidence dispatch")
    if "_scientist_one_isolated_launcher" in sys.__dict__:
        _fail("production CLI authority appeared during evidence dispatch")
    if test_loader is None:
        if "_scientist_one_test_runner" in sys.__dict__:
            _fail("test authority appeared during audit evidence dispatch")
    else:
        if getattr(sys, "_scientist_one_test_runner", None) is not True:
            _fail("Scientist-One test authority changed during evidence dispatch")
        _attest_loaded_tests(tree, test_loader)


class _StagedEvidence:
    """A held, unpublished report which can be committed after final attestation."""

    __slots__ = (
        "root_fd",
        "reports_fd",
        "descriptor",
        "temporary_name",
        "target_name",
        "data",
        "committed",
    )

    def __init__(self, root: Path, target_name: str, data: bytes) -> None:
        if not target_name or "/" in target_name or target_name in {".", ".."}:
            _fail("invalid evidence report filename")
        self.root_fd = self.reports_fd = self.descriptor = -1
        self.temporary_name = f".{target_name}.{secrets.token_hex(16)}.partial"
        self.target_name = target_name
        self.data = data
        self.committed = False
        try:
            self.root_fd = os.open(root, _DIRECTORY_FLAGS)
            self.reports_fd = os.open(
                "reports", _DIRECTORY_FLAGS, dir_fd=self.root_fd
            )
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW
            self.descriptor = os.open(
                self.temporary_name, flags, 0o600, dir_fd=self.reports_fd
            )
            view = memoryview(data)
            total = 0
            while total < len(view):
                written = os.write(self.descriptor, view[total:])
                if written <= 0:
                    _fail("short write while staging evidence report")
                total += written
            os.fsync(self.descriptor)
            self._attest_staged()
        except BaseException:
            self.close()
            raise

    def _attest_staged(self) -> None:
        held = os.fstat(self.descriptor)
        named = os.stat(
            self.temporary_name,
            dir_fd=self.reports_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(held.st_mode)
            or held.st_nlink != 1
            or not _same_identity(held, named)
            or held.st_size != len(self.data)
        ):
            _fail("staged evidence report identity changed")
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(self.descriptor, min(65536, len(self.data) + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > len(self.data):
                _fail("staged evidence report changed size")
            chunks.append(chunk)
        if b"".join(chunks) != self.data:
            _fail("staged evidence report changed bytes")

    def commit(self, root: Path) -> Path:
        # These are the last checks before one atomic rename.  Nothing which
        # imports project/test code or calls a mutable callback follows them.
        named_root = os.stat(root, follow_symlinks=False)
        held_root = os.fstat(self.root_fd)
        named_reports = os.stat("reports", dir_fd=self.root_fd, follow_symlinks=False)
        held_reports = os.fstat(self.reports_fd)
        if (
            not stat.S_ISDIR(held_root.st_mode)
            or not stat.S_ISDIR(held_reports.st_mode)
            or not _same_identity(held_root, named_root)
            or not _same_identity(held_reports, named_reports)
        ):
            _fail("evidence report destination identity changed")
        self._attest_staged()
        os.replace(
            self.temporary_name,
            self.target_name,
            src_dir_fd=self.reports_fd,
            dst_dir_fd=self.reports_fd,
        )
        self.committed = True
        return root / "reports" / self.target_name

    def close(self) -> None:
        if self.reports_fd >= 0 and not self.committed:
            try:
                os.unlink(self.temporary_name, dir_fd=self.reports_fd)
            except FileNotFoundError:
                pass
        for descriptor in (self.descriptor, self.reports_fd, self.root_fd):
            if descriptor >= 0:
                os.close(descriptor)
        self.descriptor = self.reports_fd = self.root_fd = -1


def _run_test_suite(
    root: Path, tree: _CapturedTree, source_loader: _CapturedSourceLoader
) -> int:
    from datetime import datetime, timezone
    import io
    import platform
    import time
    import unittest

    if not tree.test_records:
        _fail("Scientist-One test evidence mode lacks a captured test inventory")
    if "_scientist_one_test_runner" in sys.__dict__:
        _fail("Scientist-One test capability existed before evidence dispatch")
    sys._scientist_one_test_runner = True
    try:
        started = datetime.now(timezone.utc)
        monotonic_start = time.monotonic()
        suite, test_loader = _load_captured_test_suite(tree)
        _attest_evidence_dispatch(tree, source_loader, test_loader)
        buffer = io.StringIO()
        result = unittest.TextTestRunner(stream=buffer, verbosity=2).run(suite)
        elapsed = time.monotonic() - monotonic_start
        output = buffer.getvalue()

        # Never publish a machine result after source, test, directory, loader,
        # or module replacement.  The final launcher guard repeats this check.
        _attest_evidence_dispatch(tree, source_loader, test_loader)
        from scientist_one.security import canonical_json_bytes

        source_attestation_version, source_attestation_entries = tree.attestation()
        test_attestation_version, test_attestation_entries = tree.test_attestation()
        payload = {
            "schema_version": "1.0",
            "started_at_utc": started.isoformat().replace("+00:00", "Z"),
            "elapsed_seconds": round(elapsed, 6),
            "command": (
                "python3 -I -S -B scripts/scientist_one_cli.py test-suite"
            ),
            "executable": Path(sys.executable).name,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "tests_run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "skipped": len(result.skipped),
            "expected_failures": len(result.expectedFailures),
            "unexpected_successes": len(result.unexpectedSuccesses),
            "successful": result.wasSuccessful(),
            "failure_details": [
                {"test": str(test), "traceback": traceback}
                for test, traceback in result.failures
            ],
            "error_details": [
                {"test": str(test), "traceback": traceback}
                for test, traceback in result.errors
            ],
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "output": output,
            "project_source_attestation": {
                "schema_version": source_attestation_version,
                "entries": [
                    {"path": entry[0], "sha256": entry[1], "size": entry[2]}
                    for entry in source_attestation_entries
                ],
            },
            "test_source_attestation": {
                "schema_version": test_attestation_version,
                "entries": [
                    {"path": entry[0], "sha256": entry[1], "size": entry[2]}
                    for entry in test_attestation_entries
                ],
            },
        }
        report = root / "reports" / "test_results.json"
        staged = _StagedEvidence(
            root, report.name, canonical_json_bytes(payload) + b"\n"
        )
        try:
            _attest_evidence_dispatch(tree, source_loader, test_loader)
            report = staged.commit(root)
        finally:
            staged.close()
        print(output, end="")
        print(f"machine_report={report.relative_to(root)}")
        return 0 if result.wasSuccessful() else 1
    finally:
        sys.__dict__.pop("_scientist_one_test_runner", None)


def _run_project_audit(
    root: Path, tree: _CapturedTree, source_loader: _CapturedSourceLoader
) -> int:
    from scientist_one.audit import audit_project

    if not tree.test_records:
        _fail("Scientist-One audit evidence mode lacks a captured test inventory")
    _attest_evidence_dispatch(tree, source_loader)
    audit = audit_project(root)
    _attest_evidence_dispatch(tree, source_loader)
    target = root / "reports" / "final_audit.json"
    staged = _StagedEvidence(root, target.name, audit.as_json().encode("utf-8"))
    try:
        _attest_evidence_dispatch(tree, source_loader)
        target = staged.commit(root)
    finally:
        staged.close()
    print(f"passed={str(audit.passed).lower()}")
    print(f"snapshot_digest={audit.snapshot_digest}")
    print(f"file_count={audit.file_count}")
    print(f"total_bytes={audit.total_bytes}")
    print(f"findings={len(audit.findings)}")
    print(f"lockfiles={len(audit.lockfiles)}")
    print(f"report={target.relative_to(root)}")
    return 0 if audit.passed else 1


def _verify_startup() -> None:
    if not (
        sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.safe_path
        and sys.flags.ignore_environment
        and sys.flags.no_user_site
        and sys.flags.dont_write_bytecode
        and sys.flags.optimize == 0
        and sys.dont_write_bytecode
    ):
        _fail("refusing unsafe startup; invoke the pinned interpreter with -I -S -B")
    if "site" in sys.modules or "sitecustomize" in sys.modules:
        _fail("site initialization occurred before the security boundary")
    if "_scientist_one_isolated_launcher" in sys.__dict__:
        _fail("Scientist-One isolated-launcher marker existed before attestation")
    if "_scientist_one_captured_source_attestation" in sys.__dict__:
        _fail("Scientist-One source attestation existed before capture")
    if "_scientist_one_captured_import_capability" in sys.__dict__:
        _fail("Scientist-One import capability existed before capture")
    if "_scientist_one_captured_evidence_capability" in sys.__dict__:
        _fail("Scientist-One evidence capability existed before capture")
    if "_scientist_one_test_runner" in sys.__dict__:
        _fail("Scientist-One test capability existed before capture")
    if any(
        name == _PACKAGE_NAME or name.startswith(f"{_PACKAGE_NAME}.")
        for name in sys.modules
    ):
        _fail("Scientist-One was imported before captured-source activation")


def main() -> int:
    _verify_startup()
    launcher, launcher_source, launcher_identity = _canonical_regular_file(
        Path(__file__)
    )
    root = launcher.parents[1].resolve(strict=True)
    if Path.cwd().resolve(strict=True) != root:
        _fail("run from the canonical ScientistOne project root")

    for entry in sys.path:
        if not entry:
            _fail("unsafe empty import path before project activation")
        candidate = Path(os.path.abspath(entry))
        try:
            candidate.relative_to(root)
        except ValueError:
            pass
        else:
            _fail(f"project path was active before verification: {entry}")
        try:
            canonical_guess = candidate.resolve(strict=False)
            canonical_guess.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            pass
        else:
            _fail(f"project path was active before verification: {entry}")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        _fail(f"project path was active before verification: {entry}")

    arguments = tuple(sys.argv[1:])
    evidence_mode = arguments[0] if len(arguments) == 1 and arguments[0] in {
        "test-suite",
        "audit-project",
    } else None
    tree = _CapturedTree(
        root,
        launcher,
        launcher_source,
        launcher_identity,
        capture_tests=evidence_mode is not None,
    )
    loader = _CapturedSourceLoader(tree)
    sys.meta_path.insert(0, loader)
    try:
        sys._scientist_one_captured_import_capability = loader
        try:
            cli = __import__(f"{_PACKAGE_NAME}.cli", fromlist=("cli",))
        finally:
            sys.__dict__.pop("_scientist_one_captured_import_capability", None)
        _attest_loaded_modules(loader)
        tree.attest_live_tree()
        attestation = tree.attestation()
        sys._scientist_one_captured_source_attestation = attestation
        try:
            if evidence_mode is not None:
                sys._scientist_one_captured_evidence_capability = loader
                try:
                    if evidence_mode == "test-suite":
                        return _run_test_suite(root, tree, loader)
                    return _run_project_audit(root, tree, loader)
                finally:
                    capability_intact = (
                        getattr(
                            sys,
                            "_scientist_one_captured_evidence_capability",
                            None,
                        )
                        is loader
                    )
                    sys.__dict__.pop(
                        "_scientist_one_captured_evidence_capability", None
                    )
                    if not capability_intact:
                        _fail(
                            "Scientist-One evidence capability changed during dispatch"
                        )
            # This marker assignment is intentionally the final operation
            # before production CLI dispatch. cli.main independently fails
            # closed when it is absent.
            sys._scientist_one_isolated_launcher = True
            return cli.main()
        finally:
            try:
                tree.attest_live_tree()
                _attest_loaded_modules(loader)
                if (
                    (
                        evidence_mode is None
                        and getattr(sys, "_scientist_one_isolated_launcher", None)
                        is not True
                    )
                    or (
                        evidence_mode is not None
                        and "_scientist_one_isolated_launcher" in sys.__dict__
                    )
                    or getattr(
                        sys, "_scientist_one_captured_source_attestation", None
                    )
                    != attestation
                ):
                    _fail("Scientist-One launch attestation changed during dispatch")
            finally:
                sys.__dict__.pop("_scientist_one_isolated_launcher", None)
                sys.__dict__.pop("_scientist_one_captured_source_attestation", None)
    finally:
        if loader in sys.meta_path:
            sys.meta_path.remove(loader)


if __name__ == "__main__":
    raise SystemExit(main())
