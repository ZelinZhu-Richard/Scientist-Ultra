"""Project confinement, safe serialization, and no-shell command policy."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum
import hashlib
import json
import math
import os
from pathlib import Path, PurePath
import re
import secrets
import stat
from typing import Any, Iterable, Mapping, Sequence

from .errors import (
    CommandSecurityError,
    PathSecurityError,
    UnsafeSerializationError,
)


DEFAULT_MAX_JSON_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_JSON_DEPTH = 64
DEFAULT_MAX_JSON_ITEMS = 250_000
MAX_SECRET_SCAN_BYTES = 64 * 1024 * 1024
INVALID_UTF8_SECRET_SCAN_LABEL = "invalid_utf8"
NETWORK_EXECUTABLES = frozenset(
    {"curl", "wget", "nc", "netcat", "ssh", "scp", "sftp", "ftp", "telnet"}
)
DEPENDENCY_EXECUTABLES = frozenset(
    {"pip", "pip3", "uv", "poetry", "conda", "npm", "pnpm", "yarn", "npx", "cargo", "brew"}
)
SHELL_EXECUTABLES = frozenset(
    {"sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh", "osascript"}
)
SHELL_TOKENS = frozenset({";", "&&", "||", "|", "`", ">", ">>", "<", "<<", "$(", "${"})
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "secret_assignment": re.compile(
        r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)"
        r"\s*[:=]\s*['\"]?([A-Za-z0-9_./+\-=]{16,})"
    ),
}


def sha256_bytes(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError("sha256_bytes requires bytes")
    return hashlib.sha256(data).hexdigest()


def _home_without_environment() -> Path | None:
    try:
        import pwd

        return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    except (ImportError, KeyError, OSError, RuntimeError):
        return None


def canonical_root(root: str | os.PathLike[str]) -> Path:
    raw = Path(root)
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    try:
        if raw.is_symlink():
            raise PathSecurityError("project root cannot be a symbolic link")
        resolved = raw.resolve(strict=True)
        metadata = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise PathSecurityError("project root is not a resolvable directory") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise PathSecurityError("project root is not a directory")
    anchor = Path(resolved.anchor)
    home = _home_without_environment()
    if resolved == anchor or (home is not None and resolved == home):
        raise PathSecurityError("project root is too broad")
    return resolved


def _raw_parts(path: Path) -> tuple[str, ...]:
    # PurePath.parts preserves lexical '..' components before resolve().
    return tuple(PurePath(os.fspath(path)).parts)


def _reject_lexical_path(path: str | os.PathLike[str]) -> Path:
    if not isinstance(path, (str, os.PathLike)):
        raise PathSecurityError("path must be text or PathLike")
    raw_text = os.fspath(path)
    if not isinstance(raw_text, str) or not raw_text or "\x00" in raw_text:
        raise PathSecurityError("path is empty or malformed")
    candidate = Path(raw_text)
    if ".." in _raw_parts(candidate):
        raise PathSecurityError("path traversal is forbidden")
    return candidate


def _relative_candidate(root: Path, path: str | os.PathLike[str]) -> Path:
    raw = _reject_lexical_path(path)
    if raw.is_absolute():
        try:
            return raw.relative_to(root)
        except ValueError as exc:
            raise PathSecurityError("absolute path is outside the project root") from exc
    return raw


def _check_components(
    root: Path,
    relative: Path,
    *,
    must_exist: bool,
    expected_kind: str | None,
    reject_hardlinks: bool,
) -> Path:
    current = root
    parts = relative.parts
    if not parts or parts == (".",):
        if expected_kind not in (None, "directory"):
            raise PathSecurityError("project root has the wrong entry type")
        return root
    for index, component in enumerate(parts):
        if component in {"", ".", ".."}:
            raise PathSecurityError("unsafe path component")
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if must_exist or index < len(parts) - 1:
                raise PathSecurityError("path or parent does not exist")
            break
        except OSError as exc:
            raise PathSecurityError("path metadata cannot be verified") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise PathSecurityError("symbolic links are forbidden")
        is_leaf = index == len(parts) - 1
        if not is_leaf and not stat.S_ISDIR(metadata.st_mode):
            raise PathSecurityError("path parent is not a directory")
        if is_leaf:
            if expected_kind == "file" and not stat.S_ISREG(metadata.st_mode):
                raise PathSecurityError("path is not a regular file")
            if expected_kind == "directory" and not stat.S_ISDIR(metadata.st_mode):
                raise PathSecurityError("path is not a directory")
            if expected_kind is None and not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
                raise PathSecurityError("special filesystem entries are forbidden")
            if reject_hardlinks and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise PathSecurityError("hard-linked files are forbidden for protected evidence")
    try:
        resolved_parent = current.parent.resolve(strict=True) if not current.exists() else current.resolve(strict=True)
        resolved_parent.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PathSecurityError("path does not resolve inside project root") from exc
    return root / relative


def resolve_confined(
    root: str | os.PathLike[str],
    path: str | os.PathLike[str],
    *,
    must_exist: bool = True,
    expected_kind: str | None = None,
    allow_root: bool = False,
    reject_hardlinks: bool = False,
) -> Path:
    """Return a confined path after lexical and component-wise no-link checks.

    ``expected_kind`` may be ``"file"`` or ``"directory"``.  For a missing
    write target, only the leaf may be absent; every parent must already exist.
    """

    canonical = canonical_root(root)
    relative = _relative_candidate(canonical, path)
    if relative.parts in ((), (".",)) and not allow_root:
        raise PathSecurityError("the project root itself is not an allowed target")
    if expected_kind not in {None, "file", "directory"}:
        raise ValueError("expected_kind must be file, directory, or None")
    return _check_components(
        canonical,
        relative,
        must_exist=must_exist,
        expected_kind=expected_kind,
        reject_hardlinks=reject_hardlinks,
    )


def project_relative(root: str | os.PathLike[str], path: str | os.PathLike[str]) -> str:
    canonical = canonical_root(root)
    confined = resolve_confined(canonical, path, must_exist=True)
    return confined.relative_to(canonical).as_posix()


def secure_directory(
    root: str | os.PathLike[str],
    path: str | os.PathLike[str],
    *,
    create: bool = False,
    mode: int = 0o700,
) -> Path:
    """Traverse/create a directory without accepting symlink components."""

    canonical = canonical_root(root)
    relative = _relative_candidate(canonical, path)
    descriptor = open_confined_directory_fd(canonical, relative, create=create, mode=mode)
    os.close(descriptor)
    return canonical / relative


def open_confined_directory_fd(
    root: str | os.PathLike[str],
    path: str | os.PathLike[str],
    *,
    create: bool = False,
    mode: int = 0o700,
) -> int:
    """Open a directory by walking every component relative to a pinned fd.

    The returned descriptor is owned by the caller.  Component swaps cannot
    redirect this traversal because every subsequent lookup is relative to the
    already opened parent and uses ``O_NOFOLLOW``.
    """

    canonical = canonical_root(root)
    relative = _relative_candidate(canonical, path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        current_fd = os.open(canonical, flags)
    except OSError as exc:
        raise PathSecurityError("cannot pin the project root directory") from exc
    try:
        for component in relative.parts:
            if component in {"", ".", ".."}:
                raise PathSecurityError("unsafe directory component")
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise PathSecurityError("required directory is absent")
                try:
                    os.mkdir(component, mode=mode, dir_fd=current_fd)
                except FileExistsError:
                    # A concurrent creator is acceptable only if the no-follow
                    # open and fstat below prove it created a real directory.
                    pass
                except OSError as exc:
                    raise PathSecurityError("confined directory creation failed") from exc
                try:
                    next_fd = os.open(component, flags, dir_fd=current_fd)
                except OSError as exc:
                    raise PathSecurityError("created directory cannot be opened safely") from exc
            except OSError as exc:
                raise PathSecurityError("directory path contains a link or non-directory") from exc
            metadata = os.fstat(next_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_fd)
                raise PathSecurityError("directory component is not a directory")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _directory_fd(directory: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(directory, flags)
    except OSError as exc:
        raise PathSecurityError("cannot safely open destination directory") from exc


def _read_regular_at(
    directory_fd: int,
    name: str,
    *,
    reject_hardlinks: bool = False,
    max_bytes: int | None = None,
    read_content: bool = True,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError:
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PathSecurityError("destination is not a regular file")
        if reject_hardlinks and metadata.st_nlink != 1:
            raise PathSecurityError("hard-linked destination is forbidden")
        if max_bytes is not None and metadata.st_size > max_bytes:
            raise PathSecurityError("destination exceeds size limit")
        if not read_content:
            return b""
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise PathSecurityError("destination exceeds size limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_confined_before_final_fstat(descriptor: int) -> None:
    """Deterministic test seam before a confined read is revalidated."""


def _stable_file_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_confined_bytes(
    root: str | os.PathLike[str],
    path: str | os.PathLike[str],
    *,
    reject_hardlinks: bool = False,
    max_bytes: int | None = None,
    missing_ok: bool = False,
) -> bytes | None:
    """Read a regular file relative to pinned no-follow directory descriptors."""

    canonical = canonical_root(root)
    relative = _relative_candidate(canonical, path)
    if not relative.parts or relative.name in {"", ".", ".."}:
        raise PathSecurityError("invalid input filename")
    directory_fd = open_confined_directory_fd(canonical, relative.parent, create=False)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(relative.name, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            if missing_ok:
                return None
            raise PathSecurityError("input file is absent")
        except OSError as exc:
            raise PathSecurityError("input file cannot be opened safely") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise PathSecurityError("input is not a regular file")
            if reject_hardlinks and metadata.st_nlink != 1:
                raise PathSecurityError("hard-linked input is forbidden")
            if max_bytes is not None and metadata.st_size > max_bytes:
                raise PathSecurityError("input file exceeds size limit")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    raise PathSecurityError("input file exceeds size limit")
                chunks.append(chunk)
            _read_confined_before_final_fstat(descriptor)
            final_metadata = os.fstat(descriptor)
            if _stable_file_metadata(final_metadata) != _stable_file_metadata(metadata):
                raise PathSecurityError("input file changed while it was being read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)


def atomic_write_bytes(
    root: str | os.PathLike[str],
    target: str | os.PathLike[str],
    data: bytes,
    *,
    overwrite: bool = False,
    immutable: bool = False,
    create_parents: bool = False,
    mode: int = 0o600,
) -> Path:
    """Durably publish bytes through a directory fd and no-follow temp file.

    With ``immutable=True``, an identical existing file is idempotent and any
    differing content is a collision.  Publication uses a same-directory hard
    link, so an attacker cannot make a create-only write replace another entry.
    """

    if not isinstance(data, bytes):
        raise TypeError("atomic_write_bytes requires bytes")
    canonical = canonical_root(root)
    raw_target = _reject_lexical_path(target)
    relative = _relative_candidate(canonical, raw_target)
    if not relative.parts or relative.name in {"", ".", ".."}:
        raise PathSecurityError("invalid destination filename")
    parent_relative = relative.parent
    target_name = relative.name
    directory_fd = open_confined_directory_fd(
        canonical,
        parent_relative,
        create=create_parents,
    )
    temporary_name = f".{target_name}.{secrets.token_hex(16)}.partial"
    descriptor: int | None = None
    temporary_created = False
    published = False
    try:
        try:
            existing = _read_regular_at(
                directory_fd,
                target_name,
                reject_hardlinks=immutable,
                max_bytes=len(data) if (immutable or not overwrite) else None,
                read_content=immutable or not overwrite,
            )
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise PathSecurityError("existing destination cannot be safely read") from exc
        if existing is not None:
            if immutable and existing == data:
                return canonical / relative
            if immutable or not overwrite:
                raise PathSecurityError("destination already exists with different or mutable content")

        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(temporary_name, flags, mode, dir_fd=directory_fd)
            temporary_created = True
            view = memoryview(data)
            total = 0
            while total < len(view):
                written = os.write(descriptor, view[total:])
                if written <= 0:
                    raise OSError("short write")
                total += written
            os.fsync(descriptor)
        except OSError as exc:
            raise PathSecurityError("atomic temporary write failed") from exc

        def require_name_matches_held(
            name: str,
            *,
            expected_links: int | None = None,
        ) -> None:
            if descriptor is None:  # pragma: no cover - internal invariant
                raise PathSecurityError("atomic publication descriptor was lost")
            try:
                held = os.fstat(descriptor)
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise PathSecurityError(
                    "atomic publication entry cannot be revalidated"
                ) from exc
            if (
                not stat.S_ISREG(held.st_mode)
                or not stat.S_ISREG(named.st_mode)
                or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
                or (expected_links is not None and held.st_nlink != expected_links)
            ):
                raise PathSecurityError(
                    "atomic publication entry changed before commit"
                )

        # Closing the temporary descriptor before publication would allow a
        # same-user rename/replace race to substitute different bytes at the
        # deterministic temporary name.  Keep it held, and prove the name still
        # identifies that exact inode immediately before and after publication.
        require_name_matches_held(temporary_name, expected_links=1)

        if immutable or not overwrite:
            try:
                os.link(
                    temporary_name,
                    target_name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                published = True
                require_name_matches_held(target_name, expected_links=2)
            except FileExistsError:
                try:
                    raced = _read_regular_at(
                        directory_fd,
                        target_name,
                        reject_hardlinks=immutable,
                        max_bytes=len(data),
                    )
                except OSError as exc:
                    raise PathSecurityError("destination changed during publication") from exc
                if immutable and raced == data:
                    published = True
                else:
                    raise PathSecurityError("destination changed during publication")
        else:
            # Replacing a symlink replaces the directory entry; it never follows
            # the link.  Parent confinement is pinned by directory_fd.
            os.replace(
                temporary_name,
                target_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            published = True
            require_name_matches_held(target_name, expected_links=1)
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                # os.replace consumed the temporary name on overwrite.
                pass
            temporary_created = False
        if descriptor is not None:
            os.lseek(descriptor, 0, os.SEEK_SET)
            held_bytes = bytearray()
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, len(data) + 1))
                if not chunk:
                    break
                held_bytes.extend(chunk)
                if len(held_bytes) > len(data):
                    raise PathSecurityError("published destination changed size")
            if bytes(held_bytes) != data:
                raise PathSecurityError("published destination bytes changed")
            os.close(descriptor)
            descriptor = None
        try:
            final_bytes = _read_regular_at(
                directory_fd,
                target_name,
                reject_hardlinks=immutable,
                max_bytes=len(data),
            )
        except OSError as exc:
            raise PathSecurityError(
                "published destination cannot be safely verified"
            ) from exc
        if final_bytes != data:
            raise PathSecurityError("published destination differs from source bytes")
        os.fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            if temporary_created:
                os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError:
            if not published:
                raise
        finally:
            os.close(directory_fd)
    return canonical / relative


def atomic_write_json(
    root: str | os.PathLike[str],
    target: str | os.PathLike[str],
    value: Any,
    **kwargs: Any,
) -> Path:
    return atomic_write_bytes(root, target, canonical_json_bytes(value) + b"\n", **kwargs)


def _normalize_json_value(
    value: Any,
    *,
    depth: int = 0,
    budget: list[int] | None = None,
    ancestors: frozenset[int] = frozenset(),
) -> Any:
    if budget is None:
        budget = [DEFAULT_MAX_JSON_ITEMS]
    budget[0] -= 1
    if budget[0] < 0:
        raise UnsafeSerializationError("JSON item limit exceeded")
    if depth > DEFAULT_MAX_JSON_DEPTH:
        raise UnsafeSerializationError("JSON nesting limit exceeded")
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if value.bit_length() > 4096:
            raise UnsafeSerializationError("JSON integer exceeds safety limit")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise UnsafeSerializationError("non-finite JSON number is forbidden")
        return value
    if isinstance(value, Enum) and isinstance(value.value, str):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    identity = id(value)
    if identity in ancestors:
        raise UnsafeSerializationError("cyclic JSON values are forbidden")
    nested_ancestors = ancestors | {identity}
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise UnsafeSerializationError("JSON object keys must be strings")
        return {
            key: _normalize_json_value(
                child,
                depth=depth + 1,
                budget=budget,
                ancestors=nested_ancestors,
            )
            for key, child in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            _normalize_json_value(
                child,
                depth=depth + 1,
                budget=budget,
                ancestors=nested_ancestors,
            )
            for child in value
        ]
    raise UnsafeSerializationError(f"unsupported JSON type: {type(value).__name__}")


def _validate_json_value(value: Any, *, max_depth: int, max_items: int) -> None:
    count = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        count += 1
        if count > max_items:
            raise UnsafeSerializationError("JSON item limit exceeded")
        if depth > max_depth:
            raise UnsafeSerializationError("JSON nesting limit exceeded")
        if current is None or isinstance(current, (str, bool)):
            continue
        if isinstance(current, int):
            if current.bit_length() > 4096:
                raise UnsafeSerializationError("JSON integer exceeds safety limit")
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise UnsafeSerializationError("non-finite JSON number is forbidden")
            continue
        if isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
            continue
        if isinstance(current, dict):
            if any(not isinstance(key, str) for key in current):
                raise UnsafeSerializationError("JSON object keys must be strings")
            stack.extend((item, depth + 1) for item in current.values())
            continue
        raise UnsafeSerializationError(f"unsupported JSON type: {type(current).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    try:
        converted = _normalize_json_value(value)
    except UnsafeSerializationError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise UnsafeSerializationError("value is not safely JSON serializable") from exc
    encoded = json.dumps(
        converted,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > DEFAULT_MAX_JSON_BYTES:
        raise UnsafeSerializationError("canonical JSON exceeds size limit")
    return encoded


def canonical_json_dumps(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UnsafeSerializationError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise UnsafeSerializationError("non-finite JSON number is forbidden")


def _reject_json_item_overflow_before_parse(text: str, *, max_items: int) -> None:
    """Reject JSON that lexically contains more than the allowed values.

    Containers and scalar values each consume one item in
    ``_validate_json_value``; object keys do not.  This bounded scanner counts
    the same items for syntactically valid JSON without constructing the
    decoded object graph.  Syntax remains the responsibility of ``json.loads``.
    """

    count = 0
    index = 0
    length = len(text)

    def consume_item() -> None:
        nonlocal count
        count += 1
        if count > max_items:
            raise UnsafeSerializationError("JSON item limit exceeded")

    while index < length:
        character = text[index]
        if character == '"':
            index += 1
            while index < length:
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    index += 1
                    break
                index += 1
            following = index
            while following < length and text[following] in " \t\r\n":
                following += 1
            if following >= length or text[following] != ":":
                consume_item()
            continue
        if character in "[{":
            consume_item()
            index += 1
            continue
        if character == "-" or character.isdigit():
            consume_item()
            index += 1
            while index < length and text[index] in "0123456789+-.eE":
                index += 1
            continue
        matched_literal = False
        for literal in ("true", "false", "null"):
            if text.startswith(literal, index):
                consume_item()
                index += len(literal)
                matched_literal = True
                break
        if not matched_literal:
            index += 1


def safe_json_loads(
    payload: str | bytes,
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
    max_items: int = DEFAULT_MAX_JSON_ITEMS,
) -> Any:
    if not isinstance(payload, (str, bytes)):
        raise UnsafeSerializationError("JSON payload must be text or bytes")
    encoded = payload.encode("utf-8") if isinstance(payload, str) else payload
    if len(encoded) > max_bytes:
        raise UnsafeSerializationError("JSON payload exceeds size limit")
    try:
        text = encoded.decode("utf-8")
        _reject_json_item_overflow_before_parse(text, max_items=max_items)
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except UnsafeSerializationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError, OverflowError) as exc:
        raise UnsafeSerializationError("malformed JSON payload") from exc
    _validate_json_value(value, max_depth=max_depth, max_items=max_items)
    return value


def safe_json_load(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> Any:
    try:
        data = read_confined_bytes(
            root,
            path,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
    except PathSecurityError as exc:
        raise PathSecurityError("JSON file cannot be safely read") from exc
    if data is None:  # missing_ok is false; retained as a defensive invariant.
        raise PathSecurityError("JSON file cannot be safely read")
    return safe_json_loads(data)


def validate_command(
    command: Sequence[str],
    *,
    allowed_executables: Iterable[str],
    root: str | os.PathLike[str] | None = None,
    allowed_python_modules: Iterable[str] = ("scientist_one",),
) -> tuple[str, ...]:
    """Validate an explicit argv vector; shell strings and networking fail closed."""

    if isinstance(command, (str, bytes)) or not isinstance(command, Sequence) or not command:
        raise CommandSecurityError("command must be a non-empty argument vector")
    argv = tuple(command)
    if any(not isinstance(arg, str) or not arg or "\x00" in arg or "\n" in arg or "\r" in arg for arg in argv):
        raise CommandSecurityError("command arguments must be non-empty single-line strings")
    allowed = frozenset(allowed_executables)
    if not allowed or any(not isinstance(item, str) or not item for item in allowed):
        raise CommandSecurityError("an explicit executable allowlist is required")
    executable_path = Path(argv[0])
    basename = executable_path.name
    if basename in NETWORK_EXECUTABLES or basename in SHELL_EXECUTABLES or basename in DEPENDENCY_EXECUTABLES:
        raise CommandSecurityError("network, shell, and dependency executables are forbidden")
    if argv[0] not in allowed and basename not in allowed:
        raise CommandSecurityError("executable is not allowlisted")
    if executable_path.is_absolute() or len(executable_path.parts) > 1:
        # A path-qualified executable must either be exactly allowlisted or be
        # a confined project executable whose basename is allowlisted.
        if argv[0] not in allowed:
            if root is None:
                raise CommandSecurityError("path-qualified executable requires root confinement")
            try:
                resolve_confined(
                    root,
                    executable_path,
                    must_exist=True,
                    expected_kind="file",
                    reject_hardlinks=True,
                )
            except PathSecurityError as exc:
                raise CommandSecurityError("path-qualified executable is not confined") from exc
    for argument in argv[1:]:
        if any(token in argument for token in SHELL_TOKENS):
            raise CommandSecurityError("shell control syntax is forbidden")
    if basename.startswith("python") or basename in {"pypy", "pypy3"}:
        if "-c" in argv or "-" in argv[1:]:
            raise CommandSecurityError("inline or stdin Python execution is forbidden")
        if "-m" in argv:
            index = argv.index("-m")
            if index + 1 >= len(argv):
                raise CommandSecurityError("Python module argument is missing")
            modules = frozenset(allowed_python_modules)
            if argv[index + 1] not in modules:
                raise CommandSecurityError("Python module is not explicitly allowlisted")
        else:
            scripts = [argument for argument in argv[1:] if argument.endswith((".py", ".pyw", ".pyc"))]
            if len(scripts) != 1 or root is None:
                raise CommandSecurityError("Python must run one confined script or an allowlisted module")
            resolve_confined(root, scripts[0], must_exist=True, expected_kind="file", reject_hardlinks=True)
    if basename == "git" and len(argv) > 1 and argv[1] in {
        "clone", "fetch", "pull", "push", "ls-remote", "submodule"
    }:
        raise CommandSecurityError("network-capable Git subcommands are forbidden")
    return argv


def detect_secret_patterns(text: str) -> tuple[str, ...]:
    """Return pattern labels only; never echo or persist the matched secret."""

    if not isinstance(text, str):
        raise UnsafeSerializationError("secret scanning input must be text")
    return tuple(name for name, pattern in SECRET_PATTERNS.items() if pattern.search(text))


def detect_secret_patterns_in_bytes(payload: bytes) -> tuple[str, ...]:
    """Scan bytes without allowing malformed UTF-8 to suppress ASCII matches.

    The malformed-input condition is returned as a label, alongside any
    pattern labels found after replacement decoding.  No matched value is ever
    returned or persisted.
    """

    if not isinstance(payload, bytes):
        raise UnsafeSerializationError("secret scanning input must be bytes")
    try:
        content = payload.decode("utf-8")
    except UnicodeDecodeError:
        content = payload.decode("utf-8", errors="replace")
        return (INVALID_UTF8_SECRET_SCAN_LABEL, *detect_secret_patterns(content))
    return detect_secret_patterns(content)


def scan_file_for_secrets(
    root: str | os.PathLike[str], path: str | os.PathLike[str]
) -> tuple[str, ...]:
    data = read_confined_bytes(
        root,
        path,
        reject_hardlinks=True,
        max_bytes=MAX_SECRET_SCAN_BYTES,
    )
    if data is None:
        raise PathSecurityError("file cannot be safely scanned")
    return detect_secret_patterns_in_bytes(data)


def write_approval_request(root: str | os.PathLike[str], request: Any) -> Path:
    """Persist a request as immutable evidence; this never creates approval."""

    if not hasattr(request, "request_id") or not hasattr(request, "to_dict"):
        raise UnsafeSerializationError("approval request must be a typed record")
    filename = f"{request.request_id}.json"
    return atomic_write_json(
        root,
        Path("state") / "approval_requests" / filename,
        request.to_dict(),
        immutable=True,
        create_parents=True,
    )


class PathPolicy:
    """Bound root convenience wrapper used by controller components."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = canonical_root(root)

    def resolve(
        self,
        path: str | os.PathLike[str],
        *,
        must_exist: bool = True,
        expected_kind: str | None = None,
        allow_root: bool = False,
        reject_hardlinks: bool = False,
    ) -> Path:
        return resolve_confined(
            self.root,
            path,
            must_exist=must_exist,
            expected_kind=expected_kind,
            allow_root=allow_root,
            reject_hardlinks=reject_hardlinks,
        )

    def relative(self, path: str | os.PathLike[str]) -> str:
        return project_relative(self.root, path)

    def directory(self, path: str | os.PathLike[str], *, create: bool = False) -> Path:
        return secure_directory(self.root, path, create=create)

    def atomic_write(self, path: str | os.PathLike[str], data: bytes, **kwargs: Any) -> Path:
        return atomic_write_bytes(self.root, path, data, **kwargs)

    def atomic_json(self, path: str | os.PathLike[str], value: Any, **kwargs: Any) -> Path:
        return atomic_write_json(self.root, path, value, **kwargs)

    def read_json(self, path: str | os.PathLike[str]) -> Any:
        return safe_json_load(path, self.root)


SecurityPolicy = PathPolicy
