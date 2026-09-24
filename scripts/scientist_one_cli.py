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
import importlib
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
_MAX_TEST_WORKER_OUTPUT_BYTES = 32 * 1024 * 1024
_TEST_WORKER_MODE = "__captured-test-module__"
_TEST_WORKER_PROTOCOL = "SCIENTIST_ONE_CAPTURED_TEST_MODULE_V1="
_TEST_WORKER_FAILED = 32
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
        "test_module_names",
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
        self.test_module_names: tuple[str, ...] = ()
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
        runnable: list[str] = []
        for name in self.test_names:
            if name == "__pycache__":
                cache_info = os.stat(name, dir_fd=tests_fd, follow_symlinks=False)
                if not stat.S_ISDIR(cache_info.st_mode):
                    _fail("unsafe Scientist-One test bytecode-cache entry")
                continue
            if name == "__init__.py":
                module_name = "tests"
                is_package = True
            elif name in {"provider_fixtures.py", "pmc_wire_fixtures.py"}:
                module_name = f"tests.{name[:-3]}"
                is_package = False
            elif name.startswith("test_") and name.endswith(".py"):
                stem = name[:-3]
                if not stem.isidentifier():
                    _fail(f"invalid Scientist-One test module name: {name}")
                module_name = f"tests.{stem}"
                is_package = False
                runnable.append(module_name)
            else:
                _fail(f"unexpected Scientist-One test entry: {name}")
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
                is_package=is_package,
            )
        if "tests" not in self.test_records:
            _fail("Scientist-One test package must contain __init__.py")
        if not runnable:
            _fail("Scientist-One test suite contains no runnable captured tests")
        self.test_module_names = tuple(runnable)

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
        """Inventory all captured test-package sources, not just runnable tests."""
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


class _CapturedTestLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Execute only the already captured test bytes; never consult path finders."""

    def __init__(self, tree: _CapturedTree) -> None:
        self.tree = tree
        self.executed: dict[str, str] = {}

    def create_module(self, spec):
        return None

    def find_spec(self, fullname: str, path: object = None, target: object = None):
        package_name = "tests"
        if fullname != package_name and not fullname.startswith(f"{package_name}."):
            return None
        record = self.tree.test_records.get(fullname)
        if record is None:
            raise ImportError(f"uncaptured Scientist-One test module: {fullname}")
        spec = importlib.machinery.ModuleSpec(
            fullname,
            self,
            origin=str(record.path),
            is_package=record.is_package,
        )
        spec.has_location = True
        spec.cached = None
        if record.is_package:
            spec.submodule_search_locations = []
        return spec

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


def _load_captured_test_suite(
    tree: _CapturedTree,
    module_names: tuple[str, ...] | None = None,
):
    import unittest

    package_name = "tests"
    if any(
        name == package_name or name.startswith(f"{package_name}.")
        for name in sys.modules
    ):
        _fail("Scientist-One captured test namespace already existed")

    test_loader = _CapturedTestLoader(tree)
    test_case_type = unittest.TestCase
    case_loader = unittest.TestLoader()
    load_from_module = case_loader.loadTestsFromModule
    suite = unittest.TestSuite()
    add_test = suite.addTest

    def flattened(loaded_suite):
        pending = [loaded_suite]
        count = 0
        while pending:
            item = pending.pop()
            if isinstance(item, test_case_type):
                count += 1
                if count > 100_000:
                    _fail("captured unittest case inventory exceeds its bound")
                yield item
                continue
            try:
                children = tuple(item)
            except (TypeError, ValueError) as exc:
                _fail(f"captured unittest suite is malformed: {exc}")
            pending.extend(reversed(children))

    # Keep the captured source loader first, and retain the test finder through
    # method execution and final loaded-module attestation in the worker.
    sys.meta_path.insert(1, test_loader)
    handoff = False
    try:
        package = __import__(package_name)
        if package is None:
            _fail("Scientist-One captured test package did not load")
        selected = (
            tree.test_module_names
            if module_names is None
            else module_names
        )
        if (
            len(set(selected)) != len(selected)
            or any(name not in tree.test_module_names for name in selected)
        ):
            _fail("Scientist-One captured test module selection is invalid")
        for name in selected:
            record = tree.test_records[name]
            # Import through the captured finder, rather than creating the
            # selected module by hand.  This preserves ordinary package
            # semantics, including binding tests.test_name on its real parent.
            module = importlib.import_module(name)
            spec = getattr(module, "__spec__", None)
            if (
                getattr(module, "__loader__", None) is not test_loader
                or spec is None
                or spec.loader is not test_loader
                or spec.origin != str(record.path)
                or getattr(module, "__file__", None) != str(record.path)
                or getattr(module, "__cached__", None) is not None
                or test_loader.executed.get(name) != record.sha256
            ):
                _fail(f"Scientist-One captured test module was substituted: {name}")
            for test in flattened(load_from_module(module)):
                add_test(test)
        handoff = True
        return suite, test_loader
    finally:
        if not handoff and test_loader in sys.meta_path:
            sys.meta_path.remove(test_loader)


def _attest_loaded_tests(
    tree: _CapturedTree,
    loader: _CapturedTestLoader,
    *,
    require_complete: bool,
) -> None:
    if (
        len(sys.meta_path) < 2
        or sys.meta_path[1] is not loader
        or sum(finder is loader for finder in sys.meta_path) != 1
    ):
        _fail("Scientist-One captured-test loader was replaced")
    executed = set(loader.executed)
    if require_complete and not ({"tests", *tree.test_module_names} <= executed):
        _fail("Scientist-One captured test execution set is incomplete")
    loaded = {
        name
        for name in sys.modules
        if name == "tests" or name.startswith("tests.")
    }
    if loaded != executed:
        _fail("Scientist-One captured test module set changed during execution")
    for name in executed:
        record = tree.test_records[name]
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
    *,
    require_complete_tests: bool = True,
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
        _attest_loaded_tests(
            tree,
            test_loader,
            require_complete=require_complete_tests,
        )


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
        "identity",
    )

    def __init__(self, root: Path, target_name: str, data: bytes) -> None:
        if not target_name or "/" in target_name or target_name in {".", ".."}:
            _fail("invalid evidence report filename")
        self.root_fd = self.reports_fd = self.descriptor = -1
        self.temporary_name = f".{target_name}.{secrets.token_hex(16)}.partial"
        self.target_name = target_name
        self.data = data
        self.committed = False
        self.identity = None
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
            self.identity = os.fstat(self.descriptor)
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
            or (held.st_mode & 0o777) != 0o600
            or self.identity is None
            or not _same_source_state(self.identity, held)
            or not _same_source_state(held, named)
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
        after = os.fstat(self.descriptor)
        named_after = os.stat(
            self.temporary_name, dir_fd=self.reports_fd, follow_symlinks=False
        )
        if (
            (after.st_mode & 0o777) != 0o600
            or not _same_source_state(held, after)
            or not _same_source_state(after, named_after)
        ):
            _fail("staged evidence report changed during final read")

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
        if self.reports_fd >= 0 and self.descriptor >= 0 and not self.committed:
            try:
                named = os.stat(
                    self.temporary_name, dir_fd=self.reports_fd, follow_symlinks=False
                )
                held = os.fstat(self.descriptor)
                if _same_identity(held, named):
                    os.unlink(self.temporary_name, dir_fd=self.reports_fd)
            except FileNotFoundError:
                pass
        for descriptor in (self.descriptor, self.reports_fd, self.root_fd):
            if descriptor >= 0:
                os.close(descriptor)
        self.descriptor = self.reports_fd = self.root_fd = -1


def _attestation_payload(
    attestation: tuple[str, tuple[tuple[object, ...], ...]],
) -> dict[str, object]:
    version, entries = attestation
    return {
        "schema_version": version,
        "entries": [
            {"path": entry[0], "sha256": entry[1], "size": entry[2]}
            for entry in entries
        ],
    }


def _static_test_ids(record: _CapturedSource) -> tuple[str, ...]:
    """Derive the supported static unittest inventory without executing it."""

    import ast

    try:
        parsed = ast.parse(record.source, filename=str(record.path))
    except (SyntaxError, ValueError) as exc:
        _fail(f"captured test syntax is invalid: {record.module_name}: {exc}")
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "load_tests"
        for node in parsed.body
    ):
        _fail("dynamic unittest load_tests hooks are not evidence-admissible")
    classes = {
        node.name: node
        for node in parsed.body
        if isinstance(node, ast.ClassDef)
    }

    def base_names(node: ast.ClassDef) -> tuple[str, ...]:
        names: list[str] = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                names.append(base.id)
            elif isinstance(base, ast.Attribute):
                names.append(base.attr)
        return tuple(names)

    memo: dict[str, bool] = {}
    visiting: set[str] = set()

    def is_test_case(name: str) -> bool:
        if name in memo:
            return memo[name]
        if name in visiting:
            _fail("captured test class inheritance contains a cycle")
        visiting.add(name)
        node = classes[name]
        bases = base_names(node)
        result = "TestCase" in bases or any(
            base in classes and is_test_case(base) for base in bases
        )
        visiting.remove(name)
        memo[name] = result
        return result

    def test_methods(name: str) -> set[str]:
        node = classes[name]
        methods = {
            child.name
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name.startswith("test")
        }
        for base in base_names(node):
            if base in classes and is_test_case(base):
                methods.update(test_methods(base))
        return methods

    result = [
        f"{record.module_name}.{class_name}.{method_name}"
        for class_name in sorted(classes)
        if is_test_case(class_name)
        for method_name in sorted(test_methods(class_name))
    ]
    return tuple(result)


def _suite_test_ids(suite: object) -> tuple[str, ...]:
    pending = [suite]
    result: list[str] = []
    while pending:
        item = pending.pop()
        identifier = getattr(item, "id", None)
        if callable(identifier):
            value = identifier()
            if not isinstance(value, str) or not value:
                _fail("captured unittest produced an invalid test identifier")
            result.append(value)
            continue
        try:
            children = tuple(item)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            _fail(f"captured unittest suite is malformed: {exc}")
        if len(result) + len(pending) + len(children) > 100_000:
            _fail("captured unittest case inventory exceeds its bound")
        pending.extend(reversed(children))
    return tuple(result)


def _run_test_module(
    root: Path,
    tree: _CapturedTree,
    source_loader: _CapturedSourceLoader,
    module_name: str,
) -> int:
    """Run one captured module with a pre-import, append-only outcome sink."""

    import traceback as traceback_module
    import time
    import unittest

    record = tree.test_records.get(module_name)
    if record is None or module_name not in tree.test_module_names:
        _fail("Scientist-One test worker selected a non-runnable module")
    if "_scientist_one_test_runner" in sys.__dict__:
        _fail("Scientist-One test capability existed before worker dispatch")
    expected_ids = _static_test_ids(record)
    monotonic = time.monotonic
    builtin_id = id
    format_exception = traceback_module.format_exception
    test_result_init = unittest.TestResult.__init__
    test_case_run = unittest.TestCase.run
    tear_down_previous_class = unittest.TestSuite._tearDownPreviousClass
    handle_module_fixture = unittest.TestSuite._handleModuleFixture
    handle_class_setup = unittest.TestSuite._handleClassSetUp
    handle_module_teardown = unittest.TestSuite._handleModuleTearDown
    attest_dispatch = _attest_evidence_dispatch
    attestation_payload = _attestation_payload
    protocol = _TEST_WORKER_PROTOCOL.encode("ascii")
    worker_failed = _TEST_WORKER_FAILED
    write_fd = os.write
    close_fd = os.close
    protocol_fd = os.dup(sys.stdout.fileno())
    from scientist_one.security import canonical_json_bytes

    started: dict[int, int] = {}
    stopped: dict[int, int] = {}
    outcomes: dict[int, tuple[str, str]] = {}
    outcome_integrity_errors: list[str] = []
    infrastructure_errors: list[str] = []
    case_ids: dict[int, str] = {}
    test_loader: _CapturedTestLoader | None = None

    def error_text(error: tuple[object, object, object] | None) -> str:
        if error is None:
            return ""
        try:
            return "".join(format_exception(*error))  # type: ignore[arg-type]
        except BaseException:
            return "captured test raised an unrenderable exception"

    def record_outcome(
        test: object,
        status: str,
        error: tuple[object, object, object] | None = None,
        *,
        merge_subtest: bool = False,
    ) -> None:
        key = builtin_id(test)
        test_id = case_ids.get(key)
        detail = error_text(error)
        if test_id is None:
            infrastructure_errors.append(
                f"{status}: {test!s}: {detail}"
            )
            return
        previous = outcomes.get(key)
        if previous is not None:
            if merge_subtest and previous[0] in {"failure", "error"}:
                if previous[0] == "failure" and status == "error":
                    outcomes[key] = (status, detail)
                return
            outcome_integrity_errors.append(
                f"captured test emitted multiple terminal outcomes: {test_id}"
            )
            return
        outcomes[key] = (status, detail)

    class ObservedResult(unittest.TestResult):
        def __init__(self) -> None:
            test_result_init(self)

        def startTest(self, test) -> None:  # noqa: N802
            key = builtin_id(test)
            started[key] = started.get(key, 0) + 1
            self.testsRun += 1

        def stopTest(self, test) -> None:  # noqa: N802
            key = builtin_id(test)
            stopped[key] = stopped.get(key, 0) + 1

        def addSuccess(self, test) -> None:  # noqa: N802
            record_outcome(test, "success")

        def addFailure(self, test, error) -> None:  # noqa: N802
            record_outcome(test, "failure", error)

        def addError(self, test, error) -> None:  # noqa: N802
            record_outcome(test, "error", error)

        def addSkip(self, test, reason) -> None:  # noqa: N802
            record_outcome(test, "skipped", (type(reason), reason, None))

        def addExpectedFailure(self, test, error) -> None:  # noqa: N802
            record_outcome(test, "expected_failure", error)

        def addUnexpectedSuccess(self, test) -> None:  # noqa: N802
            record_outcome(test, "unexpected_success")

        def addSubTest(self, test, subtest, error) -> None:  # noqa: N802
            if error is None:
                return
            try:
                is_failure = issubclass(error[0], test.failureException)
            except (AttributeError, TypeError):
                is_failure = False
            record_outcome(
                test,
                "failure" if is_failure else "error",
                error,
                merge_subtest=True,
            )

    sys._scientist_one_test_runner = True
    try:
        monotonic_start = monotonic()
        result = ObservedResult()
        suite, test_loader = _load_captured_test_suite(tree, (module_name,))
        observed_ids = _suite_test_ids(suite)
        if observed_ids != expected_ids:
            _fail(
                "captured unittest discovery differs from its static inventory"
            )
        cases = tuple(suite)
        if len(cases) != len(expected_ids):
            _fail("captured unittest suite was not flattened exactly")
        case_ids.update(
            (builtin_id(test), test_id)
            for test, test_id in zip(cases, expected_ids)
        )
        if len(case_ids) != len(expected_ids):
            _fail("captured unittest case identities are ambiguous")
        attest_dispatch(
            tree,
            source_loader,
            test_loader,
            require_complete_tests=False,
        )
        result._testRunEntered = True
        try:
            for test in cases:
                if result.shouldStop:
                    break
                tear_down_previous_class(suite, test, result)
                handle_module_fixture(suite, test, result)
                handle_class_setup(suite, test, result)
                result._previousTestClass = test.__class__
                if (
                    getattr(test.__class__, "_classSetupFailed", False)
                    or getattr(result, "_moduleSetUpFailed", False)
                ):
                    continue
                test_case_run(test, result)
        finally:
            tear_down_previous_class(suite, None, result)
            handle_module_teardown(suite, result)
            result._testRunEntered = False
        elapsed = monotonic() - monotonic_start
        attest_dispatch(
            tree,
            source_loader,
            test_loader,
            require_complete_tests=False,
        )
        if infrastructure_errors:
            _fail(
                "captured unittest fixture outcome is not attributable to its "
                "static test inventory"
            )
        if outcome_integrity_errors:
            _fail(outcome_integrity_errors[0])
        for key, test_id in case_ids.items():
            if (
                started.get(key) != 1
                or stopped.get(key) != 1
                or key not in outcomes
            ):
                _fail(
                    "captured unittest did not emit one observed lifecycle and "
                    f"terminal outcome: {test_id}"
                )
        status_by_id = {
            test_id: outcomes[key]
            for key, test_id in case_ids.items()
        }
        counts = {
            "tests_run": len(expected_ids),
            "failures": sum(
                status == "failure" for status, _detail in status_by_id.values()
            ),
            "errors": sum(
                status == "error" for status, _detail in status_by_id.values()
            ),
            "skipped": sum(
                status == "skipped" for status, _detail in status_by_id.values()
            ),
            "expected_failures": sum(
                status == "expected_failure"
                for status, _detail in status_by_id.values()
            ),
            "unexpected_successes": sum(
                status == "unexpected_success"
                for status, _detail in status_by_id.values()
            ),
        }
        successful = not any(
            counts[name]
            for name in ("failures", "errors", "unexpected_successes")
        )
        output = "".join(
            f"{test_id} ... {status.replace('_', ' ')}\n"
            for test_id, (status, _detail) in status_by_id.items()
        )
        payload = {
            "schema_version": "captured-test-module/v1",
            "module_name": module_name,
            "module_sha256": record.sha256,
            "test_ids": list(expected_ids),
            **counts,
            "successful": successful,
            "failure_details": [
                {"test": test_id, "traceback": detail}
                for test_id, (status, detail) in status_by_id.items()
                if status == "failure"
            ],
            "error_details": [
                {"test": test_id, "traceback": detail}
                for test_id, (status, detail) in status_by_id.items()
                if status == "error"
            ],
            "output": output,
            "elapsed_seconds": round(elapsed, 6),
            "loaded_test_modules": [
                {"module_name": name, "sha256": digest}
                for name, digest in sorted(test_loader.executed.items())
            ],
            "project_source_attestation": attestation_payload(
                tree.attestation()
            ),
            "test_source_attestation": attestation_payload(
                tree.test_attestation()
            ),
        }
        encoded = canonical_json_bytes(payload)
        attest_dispatch(
            tree,
            source_loader,
            test_loader,
            require_complete_tests=False,
        )
        protocol_bytes = protocol + encoded + b"\n"
        written = 0
        while written < len(protocol_bytes):
            count = write_fd(protocol_fd, protocol_bytes[written:])
            if count <= 0:
                _fail("captured test worker protocol write was short")
            written += count
        return 0 if successful else worker_failed
    finally:
        if test_loader is not None and test_loader in sys.meta_path:
            sys.meta_path.remove(test_loader)
        sys.__dict__.pop("_scientist_one_test_runner", None)
        close_fd(protocol_fd)


def _run_test_suite(
    root: Path, tree: _CapturedTree, source_loader: _CapturedSourceLoader
) -> int:
    """Publish aggregate evidence from a parent that never imports test code."""

    from datetime import datetime, timezone
    import json
    import platform
    import subprocess
    import time

    if not tree.test_module_names:
        _fail("Scientist-One test evidence mode lacks a captured test inventory")
    if "_scientist_one_test_runner" in sys.__dict__:
        _fail("Scientist-One test capability existed before evidence dispatch")
    started = datetime.now(timezone.utc)
    monotonic_start = time.monotonic()
    project_attestation = _attestation_payload(tree.attestation())
    test_attestation = _attestation_payload(tree.test_attestation())
    module_results: list[dict[str, object]] = []
    failure_details: list[dict[str, str]] = []
    error_details: list[dict[str, str]] = []
    outputs: list[str] = []
    totals = {
        "tests_run": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
    }
    successful = True
    expected_worker_keys = {
        "schema_version",
        "module_name",
        "module_sha256",
        "test_ids",
        "tests_run",
        "failures",
        "errors",
        "skipped",
        "expected_failures",
        "unexpected_successes",
        "successful",
        "failure_details",
        "error_details",
        "output",
        "elapsed_seconds",
        "loaded_test_modules",
        "project_source_attestation",
        "test_source_attestation",
    }
    for module_name in tree.test_module_names:
        record = tree.test_records[module_name]
        expected_ids = _static_test_ids(record)
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(tree.launcher.path),
                _TEST_WORKER_MODE,
                module_name,
            ],
            cwd=root,
            check=False,
            capture_output=True,
        )
        if (
            len(completed.stdout) > _MAX_TEST_WORKER_OUTPUT_BYTES
            or len(completed.stderr) > _MAX_TEST_WORKER_OUTPUT_BYTES
        ):
            _fail(f"captured test worker output is oversized: {module_name}")
        lines = completed.stdout.splitlines(keepends=True)
        protocol_lines = [
            line
            for line in lines
            if line.startswith(_TEST_WORKER_PROTOCOL.encode("ascii"))
        ]
        if len(protocol_lines) != 1:
            detail = completed.stderr.decode("utf-8", errors="backslashreplace")
            _fail(
                f"captured test worker protocol is absent or ambiguous: "
                f"{module_name}: {detail}"
            )
        protocol_line = protocol_lines[0].rstrip(b"\r\n")
        try:
            worker = json.loads(
                protocol_line[len(_TEST_WORKER_PROTOCOL) :].decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            _fail(f"captured test worker protocol is malformed: {exc}")
        if not isinstance(worker, dict) or set(worker) != expected_worker_keys:
            _fail("captured test worker result schema is invalid")
        loaded = worker["loaded_test_modules"]
        if not isinstance(loaded, list) or not loaded:
            _fail("captured test worker loaded-module proof is invalid")
        loaded_map: dict[str, str] = {}
        for item in loaded:
            if (
                not isinstance(item, dict)
                or set(item) != {"module_name", "sha256"}
                or not isinstance(item["module_name"], str)
                or not isinstance(item["sha256"], str)
                or item["module_name"] in loaded_map
                or item["module_name"] not in tree.test_records
                or tree.test_records[item["module_name"]].sha256
                != item["sha256"]
            ):
                _fail("captured test worker loaded-module proof differs")
            loaded_map[item["module_name"]] = item["sha256"]
        numeric_fields = tuple(totals)
        if (
            worker["schema_version"] != "captured-test-module/v1"
            or worker["module_name"] != module_name
            or worker["module_sha256"] != record.sha256
            or worker["test_ids"] != list(expected_ids)
            or worker["project_source_attestation"] != project_attestation
            or worker["test_source_attestation"] != test_attestation
            or loaded_map.get("tests") != tree.test_records["tests"].sha256
            or loaded_map.get(module_name) != record.sha256
            or not isinstance(worker["successful"], bool)
            or not isinstance(worker["output"], str)
            or isinstance(worker["elapsed_seconds"], bool)
            or not isinstance(worker["elapsed_seconds"], (int, float))
            or worker["elapsed_seconds"] < 0
            or any(
                isinstance(worker[field], bool)
                or not isinstance(worker[field], int)
                or worker[field] < 0
                for field in numeric_fields
            )
            or worker["tests_run"] != len(expected_ids)
            or completed.returncode
            != (0 if worker["successful"] else _TEST_WORKER_FAILED)
        ):
            _fail("captured test worker result differs from parent authority")
        for detail_key, count_key in (
            ("failure_details", "failures"),
            ("error_details", "errors"),
        ):
            details = worker[detail_key]
            if not isinstance(details, list) or len(details) != worker[count_key]:
                _fail("captured test worker detail count is inconsistent")
            for detail in details:
                if (
                    not isinstance(detail, dict)
                    or set(detail) != {"test", "traceback"}
                    or not isinstance(detail["test"], str)
                    or not isinstance(detail["traceback"], str)
                ):
                    _fail("captured test worker detail is malformed")
        derived_success = not any(
            worker[field]
            for field in ("failures", "errors", "unexpected_successes")
        )
        if worker["successful"] is not derived_success:
            _fail("captured test worker success flag is inconsistent")
        for field in numeric_fields:
            totals[field] += worker[field]
        successful = successful and worker["successful"]
        for detail in worker["failure_details"]:
            failure_details.append(
                {"test": detail["test"], "traceback": detail["traceback"]}
            )
        for detail in worker["error_details"]:
            error_details.append(
                {"test": detail["test"], "traceback": detail["traceback"]}
            )
        unstructured = b"".join(
            line for line in lines if line is not protocol_lines[0]
        ).decode("utf-8", errors="backslashreplace")
        stderr = completed.stderr.decode("utf-8", errors="backslashreplace")
        outputs.extend((unstructured, worker["output"], stderr))
        module_results.append(
            {
                "module_name": module_name,
                "module_sha256": record.sha256,
                "test_ids": list(expected_ids),
                **{field: worker[field] for field in numeric_fields},
                "successful": worker["successful"],
                "elapsed_seconds": worker["elapsed_seconds"],
                "loaded_test_modules": loaded,
            }
        )
        _attest_evidence_dispatch(tree, source_loader)

    elapsed = time.monotonic() - monotonic_start
    output = "".join(outputs)
    _attest_evidence_dispatch(tree, source_loader)
    from scientist_one.security import canonical_json_bytes

    payload = {
        "schema_version": "1.0",
        "started_at_utc": started.isoformat().replace("+00:00", "Z"),
        "elapsed_seconds": round(elapsed, 6),
        "command": "python3 -I -S -B scripts/scientist_one_cli.py test-suite",
        "executable": Path(sys.executable).name,
        "python": platform.python_version(),
        "platform": platform.platform(),
        **totals,
        "successful": successful,
        "failure_details": failure_details,
        "error_details": error_details,
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "output": output,
        "worker_isolation": {
            "schema_version": "captured-test-workers/v1",
            "module_count": len(module_results),
            "modules": module_results,
        },
        "project_source_attestation": project_attestation,
        "test_source_attestation": test_attestation,
    }
    report = root / "reports" / "test_results.json"
    staged = _StagedEvidence(
        root, report.name, canonical_json_bytes(payload) + b"\n"
    )
    try:
        _attest_evidence_dispatch(tree, source_loader)
        report = staged.commit(root)
    finally:
        staged.close()
    print(output, end="")
    print(f"machine_report={report.relative_to(root)}")
    return 0 if successful else 1


def _run_project_audit(
    root: Path, tree: _CapturedTree, source_loader: _CapturedSourceLoader
) -> int:
    from scientist_one.audit import audit_project, require_current_audit

    if not tree.test_module_names:
        _fail("Scientist-One audit evidence mode lacks a captured test inventory")
    _attest_evidence_dispatch(tree, source_loader)
    audit = audit_project(root)
    _attest_evidence_dispatch(tree, source_loader)
    target = root / "reports" / "final_audit.json"
    staged = _StagedEvidence(root, target.name, audit.as_json().encode("utf-8"))
    try:
        _attest_evidence_dispatch(tree, source_loader)
        require_current_audit(
            audit, root,
            staged_report_path="reports/" + staged.temporary_name,
        )
        target = staged.commit(root)
    finally:
        staged.close()
    print(f"passed={str(audit.passed).lower()}")
    print(f"snapshot_digest={audit.snapshot_digest}")
    print(f"file_count={audit.file_count}")
    print(f"total_bytes={audit.total_bytes}")
    print(f"findings={len(audit.findings)}")
    print(f"unresolved_findings={audit.unresolved_finding_count}")
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
    test_worker_module = (
        arguments[1]
        if len(arguments) == 2 and arguments[0] == _TEST_WORKER_MODE
        else None
    )
    evidence_mode = (
        arguments[0]
        if len(arguments) == 1
        and arguments[0] in {"test-suite", "audit-project"}
        else (_TEST_WORKER_MODE if test_worker_module is not None else None)
    )
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
                    if test_worker_module is not None:
                        return _run_test_module(
                            root,
                            tree,
                            loader,
                            test_worker_module,
                        )
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
