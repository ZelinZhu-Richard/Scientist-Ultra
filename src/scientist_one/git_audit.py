"""Bounded Git-format inspection of an already pinned project inventory.

This is a parser companion to the project audit, not a public-release gate.
The caller owns live directory/file identity checks, raw secret scanning and
final snapshot freshness. Only bytes supplied to ``observe`` enter a disposable
private parser image; this module never opens the live repository. Git commands
are fixed, local, read-only operations. Scientific authority is never issued.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import tempfile
import time
from typing import Callable
from urllib.parse import urlsplit

from .security import (
    INVALID_UTF8_SECRET_SCAN_LABEL,
    SECRET_PATTERNS,
    canonical_json_bytes,
    detect_secret_patterns_in_bytes,
)


GIT_AUDIT_SCHEMA = "git-audit-coverage/v1"
GIT_AUDIT_PROFILE = "COMPLETE_SHA1_GIT_INDEX_V2_AUDIT001_V1"
MAX_RAW_FILES = 100_000
MAX_RAW_FILE_BYTES = 64 * 1024 * 1024
MAX_RAW_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_OBJECTS = 100_000
MAX_OBJECT_BYTES = 64 * 1024 * 1024
MAX_DECODED_BYTES = 2 * 1024 * 1024 * 1024
MAX_INDEX_ENTRIES = 100_000
MAX_COMMAND_SECONDS = 30.0
MAX_SESSION_SECONDS = 120.0
MAX_DIAGNOSTIC_BYTES = 32 * 1024
MAX_PATH_BYTES = 4096
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_LOOSE = re.compile(r"objects/[0-9a-f]{2}/[0-9a-f]{38}\Z")
_PACK = re.compile(r"objects/pack/pack-([0-9a-f]{40})\.(pack|idx)\Z")
_SIDECAR = re.compile(r"objects/pack/pack-([0-9a-f]{40})\.(rev|mtimes)\Z")
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_APP_REF = re.compile(
    r"refs/codex/turn-diffs/(?:captures/[0-9]{13}/" + _UUID + r"/base|"
    r"checkpoints/[0-9a-f]{32}/[0-9a-f]{32}/[0-9]{13}/" + _UUID + r")\Z"
)
_MIDX_PATH = "objects/pack/multi-pack-index"
_TEXT_PATHS = frozenset({
    "HEAD", "config", "description", "COMMIT_EDITMSG", "FETCH_HEAD",
    "ORIG_HEAD", "packed-refs", "info/exclude", "info/refs", "objects/info/packs",
})
_LIMITATIONS = (
    "FORMAT_INTEGRITY_ONLY_NOT_PUBLIC_READINESS_OR_SCIENTIFIC_AUTHORITY",
    "CALLER_MUST_BIND_LIVE_RAW_INVENTORY_AND_REATTEST_BEFORE_PUBLICATION",
    "ONLY_COMPLETE_SHA1_REPOSITORIES_INDEX_V2_AND_TREE_EXTENSION_SUPPORTED",
    "UNBORN_EMPTY_REPOSITORIES_UNSUPPORTED_INDEX_AND_OBJECTS_REQUIRED",
    "ONLY_MIDX_V1_PNAM_OIDF_OIDL_OOFF_RIDX_V1_MTME_V1_SHA1_SUPPORTED",
    "MTME_FORMAT_PAIR_CONSISTENCY_NOT_TIMESTAMP_TRUTH_OR_RETENTION_AUTHORITY",
    "NON_UTF8_BLOBS_UNSUPPORTED_INCLUDING_ARCHIVES",
    "SYSTEM_GIT_RUNTIME_TRUSTED_NO_INDEPENDENT_PROCESS_ISOLATION_ATTESTATION",
    "NATIVE_HEADER_DISCOVERY_MAY_ALLOCATE_OR_DECOMPRESS_NO_OS_RSS_BOUND",
)


class GitAuditError(ValueError):
    """Invalid session use; messages never contain supplied content."""


class _Refusal(Exception):
    def __init__(self, code: str, path: str = ".git") -> None:
        self.code = code
        self.path = path
        super().__init__(code)


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _component(value: str) -> bool:
    return bool(
        0 < len(value.encode("utf-8")) <= 255
        and re.fullmatch(r"[A-Za-z0-9_. -]+", value)
        and value not in {".", ".."}
        and value == value.strip()
        and not value.endswith(".")
        and value.casefold() != ".git"
    )


def _path(value: str) -> bool:
    return bool(
        type(value) is str
        and 0 < len(value.encode("utf-8")) <= MAX_PATH_BYTES
        and len(value.split("/")) <= 64
        and all(_component(item) for item in value.split("/"))
    )


@dataclass(frozen=True, slots=True)
class GitAuditFile:
    path: str
    size: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str
            or not self.path.startswith(".git/")
            or not _path(self.path[5:])
            or type(self.size) is not int
            or not 0 <= self.size <= MAX_RAW_FILE_BYTES
            or type(self.sha256) is not str
            or not _HEX64.fullmatch(self.sha256)
        ):
            raise GitAuditError("invalid Git inventory identity")


@dataclass(frozen=True, slots=True)
class GitAuditFinding:
    code: str
    path: str = ".git"


@dataclass(frozen=True, slots=True)
class GitAuditCoverage:
    schema_version: str
    profile: str
    raw_inventory_sha256: str
    raw_file_count: int
    raw_total_bytes: int
    tool_path: str | None
    tool_sha256: str | None
    tool_version: str | None
    decoded_inventory_sha256: str | None
    decoded_object_count: int
    decoded_total_bytes: int
    index_inventory_sha256: str | None
    index_entry_count: int
    binary_waiver_paths: tuple[str, ...]
    findings: tuple[GitAuditFinding, ...]
    limitations: tuple[str, ...] = _LIMITATIONS
    reviewed_findings: tuple[GitAuditFinding, ...] = ()

    @property
    def passed(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "passed": self.passed}


def _classify(relative: str) -> str:
    if relative == "index":
        return "index"
    if _LOOSE.fullmatch(relative):
        return "object"
    if _PACK.fullmatch(relative):
        return "pack"
    if _SIDECAR.fullmatch(relative) or relative == _MIDX_PATH:
        return "sidecar"
    if _APP_REF.fullmatch(relative):
        return "app_reference"
    if relative in _TEXT_PATHS:
        return "text"
    if relative.startswith(("refs/heads/", "refs/tags/", "refs/remotes/")):
        return "reference"
    if relative == "logs/HEAD" or relative.startswith(
        ("logs/refs/heads/", "logs/refs/tags/", "logs/refs/remotes/")
    ):
        return "text"
    if re.fullmatch(r"hooks/[A-Za-z0-9-]+\.sample", relative):
        return "sample"
    raise _Refusal("unsupported_git_metadata")


def _scan(payload: bytes, path: str, *, binary: bool = False) -> None:
    for label in detect_secret_patterns_in_bytes(payload):
        if label == INVALID_UTF8_SECRET_SCAN_LABEL and binary:
            continue
        raise _Refusal(
            "unsupported_decoded_encoding" if label == INVALID_UTF8_SECRET_SCAN_LABEL
            else "secret_pattern_" + label,
            path,
        )


_REVIEWED_SYNTHETIC_BLOBS = (
    ("bce2eed606bb7eed19f902167a60a9e9248fe5a1", 139_137,
     "d0e59a5f285498633b98c7c152e62b0ae1e0ed856b9d3f910af997e6ffdfceab"),
    ("eed1d57e7b1645f7498dbab679859d95e37a54e9", 135_099,
     "de1d966155aec9441bf3c0c4bd3a0227ff433c927aaa333571932ff5350f0b7e"),
)


def reviewed_synthetic_fixture_sha256(blob_oid: str) -> str | None:
    """Describe an already classified blob; this lookup grants no disposition."""
    if type(blob_oid) is str:
        for oid, _size, digest in _REVIEWED_SYNTHETIC_BLOBS:
            if blob_oid == oid:
                return digest
    return None


def _has_reviewed_rejection_match(payload: bytes) -> bool:
    """Check the exact match and context, not object identity or audit authority."""
    if detect_secret_patterns_in_bytes(payload) != ("secret_assignment",):
        return False
    text = payload.decode("utf-8")
    matches = list(SECRET_PATTERNS["secret_assignment"].finditer(text))
    if len(matches) != 1:
        return False
    match = matches[0]
    start = len(text[:match.start()].encode("utf-8"))
    end = len(text[:match.end()].encode("utf-8"))
    return (
        (start, end) == (21865, 21889)
        and payload[:start].count(b"\n") + 1 == 584
        and hashlib.sha256(payload[start:end]).hexdigest()
        == "2c66730fbffaa076361f7c3d291251c8243143bbd4c2e462e0386a026cc295df"
        and hashlib.sha256(payload[20808:22229]).hexdigest()
        == "cc3084799e4e6efbb0589a1f836c70983a387edbed187aa3ac62454914227967"
    )


def is_reviewed_synthetic_fixture(
    path: str, payload: bytes, *, blob_oid: str | None = None,
) -> bool:
    """Recognize only the indivisible owner-reviewed AUDIT-001 observations.

    Decoded callers first verify blob type, object hash and framing. The second
    identity is decoded-only: it grants no new working-tree path classification.
    An observation is pending, never a waiver; complete successful Git coverage
    and the existing live report/publication seal are still required.
    """
    if blob_oid is None:
        _oid, size, digest = _REVIEWED_SYNTHETIC_BLOBS[0]
        expected_path = "tests/test_external_providers.py"
    elif type(blob_oid) is str:
        identity = next((item for item in _REVIEWED_SYNTHETIC_BLOBS if item[0] == blob_oid), None)
        if identity is None:
            return False
        _oid, size, digest = identity
        expected_path = ".git/decoded-objects/" + blob_oid
    else:
        return False
    return (
        type(path) is str and path == expected_path
        and type(payload) is bytes and len(payload) == size
        and hashlib.sha256(payload).hexdigest() == digest
        and _has_reviewed_rejection_match(payload)
    )


def _config(payload: bytes) -> None:
    """Accept a deliberately small subset of Git's textual config grammar."""
    if len(payload) > 64 * 1024:
        raise _Refusal("config_size_limit")
    _scan(payload, ".git/config")
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise _Refusal("invalid_config_encoding") from None
    section: tuple[str, str | None] | None = None
    values: dict[tuple[str, str | None, str], str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        match = re.fullmatch(r'\[([A-Za-z][A-Za-z0-9-]*)(?: "([^"\\]+)")?\]', line)
        if match:
            section = (match[1].lower(), match[2])
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*)", line)
        if section is None or match is None:
            raise _Refusal("unsupported_config_grammar")
        key = (*section, match[1].lower())
        value = match[2].strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if key in values or any(char in value for char in '\\"#;\x00') or not value:
            raise _Refusal("unsupported_config_value")
        values[key] = value
    allowed_core = {
        "repositoryformatversion": {"0"}, "bare": {"false"},
        "filemode": {"true", "false"}, "logallrefupdates": {"true"},
        "ignorecase": {"true", "false"}, "precomposeunicode": {"true", "false"},
        "fsmonitor": {"false"}, "untrackedcache": {"false"},
        "hookspath": {"/dev/null"},
    }
    for (group, subsection, name), value in values.items():
        good = False
        if group == "core" and subsection is None:
            good = name in allowed_core and value.lower() in allowed_core[name]
        elif group == "user" and subsection is None and name in {"name", "email"}:
            good = len(value) <= 256 and all(ord(char) >= 32 for char in value)
        elif group == "remote" and subsection == "origin":
            if name == "url":
                try:
                    url = urlsplit(value)
                    good = bool(
                        url.scheme == "https" and url.hostname and url.path
                        and not url.username and not url.password
                        and not url.query and not url.fragment
                    )
                except ValueError:
                    good = False
            elif name == "fetch":
                good = value == "+refs/heads/*:refs/remotes/origin/*"
        elif group == "branch" and subsection is not None and _path(subsection):
            good = (name == "remote" and value == "origin") or (
                name == "merge" and value.startswith("refs/heads/") and _path(value)
            )
        elif subsection is None:
            good = (group, name, value.lower()) in {
                ("gc", "auto", "0"), ("maintenance", "auto", "false"),
                ("index", "version", "2"), ("pack", "writereverseindex", "false"),
            }
        if not good:
            raise _Refusal("unsafe_or_unsupported_config")
    if values.get(("core", None, "repositoryformatversion")) != "0" or values.get(
        ("core", None, "bare")
    ) != "false":
        raise _Refusal("unsupported_repository_format")


def _reference(payload: bytes, path: str) -> None:
    _scan(payload, path)
    try:
        value = payload.decode("ascii")
    except UnicodeDecodeError:
        raise _Refusal("invalid_reference") from None
    if re.fullmatch(r"[0-9a-f]{40}\n", value):
        return
    if value.startswith("ref: ") and value.endswith("\n"):
        target = value[5:-1]
        if target.startswith(("refs/heads/", "refs/tags/", "refs/remotes/")) and _path(target):
            return
    raise _Refusal("invalid_reference")


def _object_hash(kind: str, payload: bytes) -> str:
    return hashlib.sha1(kind.encode("ascii") + b" " + str(len(payload)).encode("ascii") + b"\0" + payload).hexdigest()


def _sidecar(payload: bytes, kind: str, count: int, pack_hash: bytes) -> None:
    """Validate the closed sidecar envelope; native fsck owns RIDX tables."""
    magic = b"RIDX" if kind == "rev" else b"MTME"
    if (
        payload[:12] != magic + struct.pack("!II", 1, 1)
        or len(payload) != 12 + 4 * count + 40
        or payload[-40:-20] != pack_hash
        or hashlib.sha1(payload[:-20]).digest() != payload[-20:]
    ):
        raise _Refusal("invalid_git_sidecar_envelope")


def _midx(payload: bytes, pairs: dict[str, tuple[int, bytes, int]]) -> None:
    """Closed observed-format coverage checks, not a MIDX integrity engine.

    Native fsck remains responsible for OID ordering and the actual pack-offset
    lookup. Neither enumeration nor secret scanning trusts this accelerator.
    """
    if (
        len(payload) < 92 or payload[:8] != b"MIDX\x01\x01\x04\x00"
        or hashlib.sha1(payload[:-20]).digest() != payload[-20:]
    ):
        raise _Refusal("invalid_midx_header_or_checksum")
    pack_count = struct.unpack_from("!I", payload, 8)[0]
    if not 1 <= pack_count <= MAX_RAW_FILES or pack_count > len(pairs):
        raise _Refusal("invalid_midx_pack_count")
    table = [struct.unpack_from("!4sQ", payload, 12 + 12 * index) for index in range(5)]
    ids = [entry[0] for entry in table[:-1]]
    offsets = [entry[1] for entry in table]
    if (
        set(ids) != {b"PNAM", b"OIDF", b"OIDL", b"OOFF"}
        or table[-1][0] != bytes(4) or offsets[0] != 72
        or offsets[-1] != len(payload) - 20
        or any(left >= right for left, right in zip(offsets, offsets[1:]))
    ):
        raise _Refusal("unsupported_midx_chunk_table")
    chunks = {name: payload[offsets[i]:offsets[i + 1]] for i, name in enumerate(ids)}
    names_chunk = chunks[b"PNAM"]
    names: list[str] = []
    position = 0
    for _ in range(pack_count):
        end = names_chunk.find(b"\0", position)
        if end < 0:
            raise _Refusal("invalid_midx_pack_names")
        name = names_chunk[position:end]
        if re.fullmatch(rb"pack-[0-9a-f]{40}\.idx", name) is None:
            raise _Refusal("invalid_midx_pack_names")
        names.append(name.decode("ascii"))
        position = end + 1
    if (
        names != sorted(set(names)) or any(name not in pairs for name in names)
        or len(names_chunk) % 4 or len(names_chunk) - position > 3
        or any(names_chunk[position:])
    ):
        raise _Refusal("invalid_midx_pack_names")
    if len(chunks[b"OIDF"]) != 1024:
        raise _Refusal("invalid_midx_object_tables")
    fanout = struct.unpack("!256I", chunks[b"OIDF"])
    count = fanout[-1]
    if (
        count > MAX_OBJECTS or count > sum(pairs[name][0] for name in names)
        or any(left > right for left, right in zip(fanout, fanout[1:]))
        or len(chunks[b"OIDL"]) != 20 * count
        or len(chunks[b"OOFF"]) != 8 * count
    ):
        raise _Refusal("invalid_midx_object_tables")
    for pack_id, offset in struct.iter_unpack("!II", chunks[b"OOFF"]):
        if pack_id >= pack_count or not 12 <= offset < pairs[names[pack_id]][2] - 20:
            raise _Refusal("invalid_midx_pack_offset")


def _index_trees(entries: tuple[tuple[str, int, str], ...]) -> dict[str, tuple[int, str]]:
    nodes: dict[str, dict[str, tuple[int, str]]] = {"": {}}
    counts: dict[str, int] = {"": 0}
    aliases: dict[str, dict[str, str]] = {"": {}}
    for path, mode, oid in entries:
        parts = path.split("/")
        prefix = ""
        counts[prefix] += 1
        for name in parts[:-1]:
            previous = aliases[prefix].setdefault(name.casefold(), name)
            if previous != name:
                raise _Refusal("index_path_collision")
            child = prefix + "/" + name if prefix else name
            if name in nodes[prefix] and nodes[prefix][name][0] != 0o40000:
                raise _Refusal("index_path_collision")
            nodes[prefix][name] = (0o40000, child)
            nodes.setdefault(child, {})
            aliases.setdefault(child, {})
            counts[child] = counts.get(child, 0) + 1
            prefix = child
            if len(nodes) > MAX_INDEX_ENTRIES:
                raise _Refusal("index_tree_count_limit")
        previous = aliases[prefix].setdefault(parts[-1].casefold(), parts[-1])
        if previous != parts[-1] or parts[-1] in nodes[prefix]:
            raise _Refusal("index_path_collision")
        nodes[prefix][parts[-1]] = (mode, oid)
    results: dict[str, tuple[int, str]] = {}
    for prefix in sorted(nodes, key=lambda item: item.count("/") + bool(item), reverse=True):
        body = bytearray()
        for name, (mode, oid) in sorted(
            nodes[prefix].items(),
            key=lambda item: item[0].encode("utf-8") + (b"/" if item[1][0] == 0o40000 else b""),
        ):
            if mode == 0o40000:
                oid = results[oid][1]
            body.extend(f"{mode:o} {name}".encode("utf-8") + b"\0" + bytes.fromhex(oid))
        results[prefix] = (counts[prefix], _object_hash("tree", bytes(body)))
    return results


def _tree_cache(payload: bytes, expected: dict[str, tuple[int, str]]) -> None:
    position = 0
    seen: set[str] = set()

    def entry(parent: str | None, depth: int) -> None:
        nonlocal position
        if depth > 64 or len(seen) >= MAX_INDEX_ENTRIES:
            raise _Refusal("index_tree_cache_limit")
        end = payload.find(b"\0", position)
        line_end = payload.find(b"\n", end + 1) if end >= 0 else -1
        if end < 0 or line_end < 0:
            raise _Refusal("malformed_index_tree_cache")
        try:
            name = payload[position:end].decode("utf-8")
            header = payload[end + 1:line_end].decode("ascii")
        except UnicodeDecodeError:
            raise _Refusal("malformed_index_tree_cache") from None
        match = re.fullmatch(r"(-1|0|[1-9][0-9]*) (0|[1-9][0-9]*)", header)
        if match is None or (parent is None and name != "") or (parent is not None and not _component(name)):
            raise _Refusal("malformed_index_tree_cache")
        prefix = name if not parent else parent + "/" + name
        if prefix not in expected or prefix in seen:
            raise _Refusal("index_tree_cache_path_mismatch")
        seen.add(prefix)
        count, children = int(match[1]), int(match[2])
        if children > MAX_INDEX_ENTRIES:
            raise _Refusal("index_tree_cache_limit")
        position = line_end + 1
        if count >= 0:
            if position + 20 > len(payload) or (count, payload[position:position + 20].hex()) != expected[prefix]:
                raise _Refusal("index_tree_cache_identity_mismatch")
            position += 20
        for _ in range(children):
            entry(prefix, depth + 1)

    entry(None, 0)
    if position != len(payload):
        raise _Refusal("index_tree_cache_trailing_bytes")


def _index(payload: bytes) -> tuple[tuple[str, int, str], ...]:
    if len(payload) < 32 or payload[:4] != b"DIRC" or hashlib.sha1(payload[:-20]).digest() != payload[-20:]:
        raise _Refusal("invalid_index_checksum_or_header")
    version, count = struct.unpack("!II", payload[4:12])
    if version != 2 or count > MAX_INDEX_ENTRIES:
        raise _Refusal("unsupported_index_version_or_count")
    entries: list[tuple[str, int, str]] = []
    position = 12
    limit = len(payload) - 20
    for _ in range(count):
        start = position
        if position + 62 > limit:
            raise _Refusal("truncated_index")
        mode = struct.unpack("!I", payload[position + 24:position + 28])[0]
        oid = payload[position + 40:position + 60].hex()
        flags = struct.unpack("!H", payload[position + 60:position + 62])[0]
        end = payload.find(b"\0", position + 62, min(limit, position + 62 + MAX_PATH_BYTES + 1))
        if end < 0 or flags & 0xF000 or mode not in {0o100644, 0o100755}:
            raise _Refusal("unsupported_index_path_mode_or_stage")
        name_bytes = payload[position + 62:end]
        try:
            name = name_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise _Refusal("invalid_index_path") from None
        if not _path(name) or flags != min(len(name_bytes), 0xFFF):
            raise _Refusal("invalid_index_path")
        position = start + ((end - start + 1 + 7) // 8) * 8
        if position > limit or any(payload[end:position]):
            raise _Refusal("invalid_index_padding")
        entries.append((name, mode, oid))
    frozen = tuple(entries)
    if frozen != tuple(sorted(frozen)) or len({item[0].casefold() for item in frozen}) != len(frozen):
        raise _Refusal("index_path_order_or_alias")
    expected_trees = _index_trees(frozen)
    extensions: set[bytes] = set()
    while position < limit:
        if position + 8 > limit:
            raise _Refusal("truncated_index_extension")
        signature = payload[position:position + 4]
        length = struct.unpack("!I", payload[position + 4:position + 8])[0]
        position += 8
        if signature != b"TREE" or signature in extensions or position + length > limit:
            raise _Refusal("unsupported_index_extension")
        extensions.add(signature)
        _tree_cache(payload[position:position + length], expected_trees)
        position += length
    return frozen


def _object_header(payload: bytes) -> tuple[str, str, int]:
    match = re.fullmatch(
        rb"([0-9a-f]{40}) (blob|tree|commit|tag) (0|[1-9][0-9]{0,19})",
        payload,
    )
    if match is None:
        raise _Refusal("malformed_object_frame")
    return match[1].decode("ascii"), match[2].decode("ascii"), int(match[3])


class _ObjectHeaders:
    """Bound declared decoded sizes before asking fsck to inspect contents."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.objects: dict[str, tuple[str, int]] = {}
        self.total = 0

    def feed(self, chunk: bytes) -> None:
        self.buffer.extend(chunk)
        while True:
            newline = self.buffer.find(b"\n")
            if newline < 0:
                if len(self.buffer) > 160:
                    raise _Refusal("malformed_object_frame")
                return
            oid, kind, size = _object_header(bytes(self.buffer[:newline]))
            del self.buffer[:newline + 1]
            if oid in self.objects:
                raise _Refusal("duplicate_object_header")
            if size > MAX_OBJECT_BYTES or self.total + size > MAX_DECODED_BYTES or len(self.objects) >= MAX_OBJECTS:
                raise _Refusal("decoded_object_limit")
            self.objects[oid] = (kind, size)
            self.total += size

    def finish(self) -> None:
        if self.buffer or not self.objects:
            raise _Refusal("incomplete_object_headers")


class _ObjectStream:
    def __init__(self, expected: dict[str, tuple[str, int]]) -> None:
        self.buffer = bytearray()
        self.header: tuple[str, str, int] | None = None
        self.expected = expected
        self.objects: dict[str, tuple[str, int, str]] = {}
        self.references: list[tuple[str, str]] = []
        self.reviewed_findings: list[GitAuditFinding] = []
        self.total = 0

    def feed(self, chunk: bytes) -> None:
        self.buffer.extend(chunk)
        while True:
            if self.header is None:
                newline = self.buffer.find(b"\n")
                if newline < 0:
                    if len(self.buffer) > 160:
                        raise _Refusal("malformed_object_frame")
                    return
                header = bytes(self.buffer[:newline])
                del self.buffer[:newline + 1]
                oid, kind, size = _object_header(header)
                if size > MAX_OBJECT_BYTES or self.total + size > MAX_DECODED_BYTES or len(self.objects) >= MAX_OBJECTS:
                    raise _Refusal("decoded_object_limit")
                if self.expected.get(oid) != (kind, size):
                    raise _Refusal("object_header_content_mismatch")
                self.header = (oid, kind, size)
            oid, kind, size = self.header
            if len(self.buffer) < size + 1:
                return
            payload = bytes(self.buffer[:size])
            if self.buffer[size] != 10 or oid in self.objects or _object_hash(kind, payload) != oid:
                raise _Refusal("decoded_object_identity_mismatch")
            del self.buffer[:size + 1]
            self.header = None
            path = ".git/decoded-objects/" + oid
            if kind == "blob" and is_reviewed_synthetic_fixture(path, payload, blob_oid=oid):
                self.reviewed_findings.append(GitAuditFinding("secret_pattern_secret_assignment", path))
            else:
                _scan(payload, path, binary=kind == "tree")
            self.objects[oid] = (kind, size, hashlib.sha256(payload).hexdigest())
            self.total += size
            if kind == "tree":
                self._tree(payload)

    def _tree(self, payload: bytes) -> None:
        position = 0
        seen: set[str] = set()
        while position < len(payload):
            nul = payload.find(b"\0", position)
            if nul < 0 or nul + 21 > len(payload):
                raise _Refusal("malformed_tree")
            try:
                mode, name = payload[position:nul].decode("utf-8").split(" ", 1)
            except (UnicodeDecodeError, ValueError):
                raise _Refusal("malformed_tree") from None
            if mode not in {"40000", "100644", "100755"} or not _component(name) or name.casefold() in seen:
                raise _Refusal("unsupported_tree_path_or_mode")
            seen.add(name.casefold())
            self.references.append((payload[nul + 1:nul + 21].hex(), "tree" if mode == "40000" else "blob"))
            if len(self.references) > MAX_OBJECTS:
                raise _Refusal("tree_reference_count_limit")
            position = nul + 21

    def finish(self) -> None:
        if self.header is not None or self.buffer or not self.objects:
            raise _Refusal("incomplete_object_stream")
        if self.objects.keys() != self.expected.keys():
            raise _Refusal("object_header_content_mismatch")
        if any(self.objects.get(oid, (None,))[0] != kind for oid, kind in self.references):
            raise _Refusal("tree_object_source_mismatch")


class GitAuditSession:
    """One-shot context consuming only caller-verified ``.git`` bytes.

    Construct from the full planned file inventory, call observe exactly once
    per file, then finalize. Always use a context manager (or close in finally).
    A failed coverage result has an empty binary waiver set. This session cannot
    attest live path modes, missing directories, freshness or public content.
    """

    def __init__(self, files: tuple[GitAuditFile, ...]) -> None:
        if type(files) is not tuple or not 1 <= len(files) <= MAX_RAW_FILES or any(type(item) is not GitAuditFile for item in files):
            raise GitAuditError("invalid Git inventory population")
        # Frozen caller DTOs are not a trust boundary: reconstruct them so
        # low-level mutation cannot change the planned identity after entry.
        files = tuple(sorted(
            (GitAuditFile(item.path, item.size, item.sha256) for item in files),
            key=lambda item: item.path,
        ))
        if len({item.path for item in files}) != len(files) or sum(item.size for item in files) > MAX_RAW_TOTAL_BYTES:
            raise GitAuditError("Git inventory duplicate or capacity violation")
        self._files = files
        self._planned = {item.path: item for item in files}
        self._seen: set[str] = set()
        self._classes: dict[str, str] = {}
        self._failure: _Refusal | None = None
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._image: Path | None = None
        self._finalized = False
        self._closed = False
        self._tool: Path | None = None
        self._tool_identity: tuple[int, ...] | None = None
        self._tool_sha256: str | None = None
        self._tool_version: str | None = None
        self._deadline = time.monotonic() + MAX_SESSION_SECONDS
        self._index_entries: tuple[tuple[str, int, str], ...] = ()
        self._pack_envelopes: dict[str, tuple[bytes, bytes, int]] = {}
        self._app_references: dict[str, str] = {}
        try:
            for item in files:
                relative = item.path[5:]
                if any(part.endswith(".lock") for part in relative.split("/")):
                    raise _Refusal("active_git_lock")
                self._classes[item.path] = _classify(relative)
            names = set(self._planned)
            if not {".git/HEAD", ".git/config", ".git/index"}.issubset(names):
                raise _Refusal("incomplete_git_inventory")
            for name in names:
                match = _PACK.fullmatch(name[5:])
                if match and ".git/objects/pack/pack-" + match[1] + (".idx" if match[2] == "pack" else ".pack") not in names:
                    raise _Refusal("incomplete_pack_pair")
                sidecar = _SIDECAR.fullmatch(name[5:])
                if sidecar and any(
                    ".git/objects/pack/pack-" + sidecar[1] + suffix not in names
                    for suffix in (".pack", ".idx")
                ):
                    raise _Refusal("incomplete_sidecar_pack_pair", name)
            self._temporary = tempfile.TemporaryDirectory(prefix="scientist-git-audit-")
            self._image = Path(self._temporary.name) / "image"
            self._image.mkdir(mode=0o700)
        except _Refusal as exc:
            self._failure = exc
            self.close()
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> GitAuditSession:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None
        self._closed = True

    def _put(self, relative: str, payload: bytes) -> None:
        assert self._image is not None
        target = self._image / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            os.chmod(target, 0o600)
            stream.write(payload)

    def observe(self, path: str, payload: bytes) -> None:
        if self._finalized:
            raise GitAuditError("Git audit session is finalized")
        if self._failure is not None:
            return
        if self._closed:
            raise GitAuditError("Git audit session is closed")
        try:
            if time.monotonic() >= self._deadline:
                raise _Refusal("git_session_timeout")
            item = self._planned.get(path) if type(path) is str else None
            if item is None or path in self._seen or type(payload) is not bytes or len(payload) != item.size or hashlib.sha256(payload).hexdigest() != item.sha256:
                raise _Refusal("observed_inventory_identity_mismatch")
            kind = self._classes[path]
            _scan(payload, path, binary=kind in {"object", "pack", "index", "sidecar"})
            relative = path[5:]
            if relative == "config":
                _config(payload)
            elif relative == "index":
                self._index_entries = _index(payload)
                self._put(relative, payload)
            elif kind == "reference" or relative == "HEAD":
                _reference(payload, path)
                self._put(relative, payload)
            elif kind == "app_reference":
                if re.fullmatch(rb"[0-9a-f]{40}\n", payload) is None:
                    raise _Refusal("invalid_app_reference", path)
                self._app_references[path] = payload[:40].decode("ascii")
                self._put(relative, payload)
            elif kind in {"object", "pack", "sidecar"} or relative == "packed-refs" or relative.startswith("logs/"):
                self._put(relative, payload)
                if kind == "pack":
                    self._pack_envelopes[relative] = (payload[:1032], payload[-40:], len(payload))
                if relative == "packed-refs" and b"refs/codex/" in payload:
                    raise _Refusal("unsupported_packed_app_reference", path)
            self._seen.add(path)
        except _Refusal as exc:
            self._failure = exc
            self.close()
        except BaseException:
            self.close()
            raise

    def _validate_sidecars(self) -> None:
        assert self._image is not None
        sidecars = [path[5:] for path, kind in self._classes.items() if kind == "sidecar"]
        if not sidecars:
            return
        pairs: dict[str, tuple[int, bytes, int]] = {}
        for path, (header, trailer, size) in self._pack_envelopes.items():
            if not path.endswith(".pack"):
                continue
            index_header, index_trailer, index_size = self._pack_envelopes[path[:-5] + ".idx"]
            if (
                size < 32 or header[:4] != b"PACK"
                or struct.unpack_from("!I", header, 4)[0] not in {2, 3}
                or index_size < 1064
            ):
                raise _Refusal("invalid_sidecar_pack_envelope")
            count = struct.unpack_from("!I", header, 8)[0]
            index_offset = 0
            if index_header[:4] == b"\xfftOc":
                if struct.unpack_from("!I", index_header, 4)[0] != 2:
                    raise _Refusal("unsupported_sidecar_pack_index")
                index_offset = 8
            index_count = struct.unpack_from("!I", index_header, index_offset + 1020)[0]
            if (
                count > MAX_OBJECTS or count != index_count
                or trailer[-20:] != index_trailer[:20]
                or trailer[-20:].hex() != Path(path).stem[5:]
            ):
                raise _Refusal("invalid_sidecar_pack_count_or_pair")
            pairs[Path(path).stem + ".idx"] = (count, trailer[-20:], size)
        for path in sidecars:
            if time.monotonic() >= self._deadline:
                raise _Refusal("git_session_timeout")
            payload = (self._image / path).read_bytes()
            if path == _MIDX_PATH:
                _midx(payload, pairs)
            else:
                match = _SIDECAR.fullmatch(path)
                assert match is not None
                count, pack_hash, _size = pairs["pack-" + match[1] + ".idx"]
                _sidecar(payload, match[2], count, pack_hash)

    @staticmethod
    def _identity(info: os.stat_result) -> tuple[int, ...]:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def _pin_tool(self) -> None:
        # Prefer the real macOS binary over /usr/bin/git's developer-tool shim.
        for name in ("/Library/Developer/CommandLineTools/usr/bin/git", "/usr/bin/git"):
            try:
                path = Path(name).resolve(strict=True)
                info = path.stat()
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and 0 < info.st_size <= MAX_RAW_FILE_BYTES:
                self._tool = path
                self._tool_identity = self._identity(info)
                self._tool_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
                self._check_tool()
                return
        raise _Refusal("supported_system_git_unavailable")

    def _check_tool(self) -> None:
        assert self._tool is not None
        if self._identity(self._tool.stat()) != self._tool_identity or hashlib.sha256(self._tool.read_bytes()).hexdigest() != self._tool_sha256:
            raise _Refusal("git_executable_changed")

    def _run(self, arguments: tuple[str, ...], *, output_limit: int, consume: Callable[[bytes], None] | None = None, repository: bool = True) -> bytes:
        assert self._tool is not None and self._image is not None
        self._check_tool()
        argv = [str(self._tool), "--no-pager", "--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks"]
        if repository:
            argv.extend(["--git-dir=" + str(self._image), "-c", "protocol.allow=never", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "gc.auto=0"])
        argv.extend(arguments)
        environment = {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "",
        }
        output = bytearray()
        errors = bytearray()
        received = 0
        deadline = min(self._deadline, time.monotonic() + MAX_COMMAND_SECONDS)
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(argv, cwd=self._image, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            assert process.stdout is not None and process.stderr is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise _Refusal("git_command_timeout")
                    for key, _mask in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        if key.data == "stderr":
                            errors.extend(chunk)
                            if len(errors) > MAX_DIAGNOSTIC_BYTES:
                                raise _Refusal("git_diagnostic_limit")
                        else:
                            received += len(chunk)
                            if received > output_limit:
                                raise _Refusal("git_output_limit")
                            if consume is None:
                                output.extend(chunk)
                            else:
                                consume(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _Refusal("git_command_timeout")
            try:
                status = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise _Refusal("git_command_timeout") from None
            if status != 0 or errors:
                raise _Refusal("native_git_validation_failed")
        finally:
            if process is not None:
                try:
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            # Managed hosts may deny even our group signals.
                            # Fixed builtins have no hook/filter child workload.
                            if process.poll() is None:
                                process.kill()
                    try:
                        process.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        raise _Refusal("git_process_cleanup_failure") from None
                finally:
                    if process.stdout is not None:
                        process.stdout.close()
                    if process.stderr is not None:
                        process.stderr.close()
        self._check_tool()
        return bytes(output)

    def finalize(self) -> GitAuditCoverage:
        if self._finalized:
            raise GitAuditError("Git audit session is finalized")
        self._finalized = True
        objects: _ObjectStream | None = None
        object_digest = index_digest = None
        try:
            if self._failure is not None:
                raise self._failure
            if self._closed or self._seen != set(self._planned):
                raise _Refusal("incomplete_observed_inventory")
            assert self._image is not None
            # The original configuration is never installed in the image.
            self._put("config", b"[core]\nrepositoryformatversion = 0\nbare = true\nfsmonitor = false\n[gc]\nauto = 0\n")
            for directory in ("objects", "refs"):
                (self._image / directory).mkdir(mode=0o700, exist_ok=True)
            if time.monotonic() >= self._deadline:
                raise _Refusal("git_session_timeout")
            self._validate_sidecars()
            self._pin_tool()
            version = self._run(("--version",), output_limit=256, repository=False)
            if re.fullmatch(rb"git version 2\.(?:[5-9][0-9]|[1-9][0-9]{2,})\.[0-9]+(?: \(Apple Git-[0-9]+\))?\n", version) is None:
                raise _Refusal("unsupported_git_version")
            self._tool_version = version.decode("ascii").strip()
            headers = _ObjectHeaders()
            self._run(
                ("-c", "core.multiPackIndex=false", "cat-file", "--batch-all-objects", "--batch-check"),
                output_limit=MAX_OBJECTS * 162 + 65536,
                consume=headers.feed,
            )
            headers.finish()
            result = self._run(("-c", "core.multiPackIndex=true", "-c", "pack.readReverseIndex=true", "fsck", "--full", "--strict", "--no-dangling", "--no-progress"), output_limit=MAX_DIAGNOSTIC_BYTES)
            if result:
                raise _Refusal("unexpected_git_validation_output")
            objects = _ObjectStream(headers.objects)
            self._run(("-c", "core.multiPackIndex=false", "cat-file", "--batch-all-objects", "--batch"), output_limit=MAX_DECODED_BYTES + MAX_OBJECTS * 162, consume=objects.feed)
            objects.finish()
            for path, oid in self._app_references.items():
                if objects.objects.get(oid, (None,))[0] != "commit":
                    raise _Refusal("app_reference_requires_commit", path)
            for path, mode, oid in self._index_entries:
                if objects.objects.get(oid, (None,))[0] != "blob":
                    raise _Refusal("index_object_source_mismatch")
            stages = self._run(("ls-files", "--stage", "-z"), output_limit=MAX_INDEX_ENTRIES * (MAX_PATH_BYTES + 64))
            expected = b"".join(f"{mode:o} {oid} 0\t{path}".encode("utf-8") + b"\0" for path, mode, oid in self._index_entries)
            if stages != expected:
                raise _Refusal("native_index_projection_mismatch")
            object_digest = _digest([[oid, *value] for oid, value in sorted(objects.objects.items())])
            index_digest = _digest([list(entry) for entry in self._index_entries])
        except _Refusal as exc:
            self._failure = exc
        except (OSError, ValueError, OverflowError, struct.error):
            self._failure = _Refusal("git_parser_io_or_format_failure")
        finally:
            self.close()
        failure = self._failure
        return GitAuditCoverage(
            GIT_AUDIT_SCHEMA, GIT_AUDIT_PROFILE,
            _digest([asdict(item) for item in self._files]), len(self._files),
            sum(item.size for item in self._files),
            str(self._tool) if self._tool is not None else None,
            self._tool_sha256, self._tool_version,
            object_digest if failure is None else None,
            len(objects.objects) if objects is not None else 0,
            objects.total if objects is not None else 0,
            index_digest if failure is None else None, len(self._index_entries),
            tuple(sorted(path for path, kind in self._classes.items() if kind in {"object", "pack", "index", "sidecar"})) if failure is None else (),
            (GitAuditFinding(failure.code, failure.path),) if failure is not None else (),
            reviewed_findings=tuple(objects.reviewed_findings) if objects is not None else (),
        )


__all__ = ["GitAuditCoverage", "GitAuditError", "GitAuditFile", "GitAuditFinding", "GitAuditSession", "is_reviewed_synthetic_fixture", "reviewed_synthetic_fixture_sha256"]
