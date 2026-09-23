"""Composed private fixtures: synthetic native observations, never TLS/PMC proof."""

import ast
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

from scientist_one import external as subject
from scientist_one import pmc_coordination as coordination


# These paths are the captured subject modules, never a draft-relative copy.
EXTERNAL = Path(subject.__file__)
COORDINATION = Path(coordination.__file__)
BOOT = b"12345678-1234-4234-8234-123456789abc"
URL = "https://pmc.ncbi.nlm.nih.gov/api/oai/v1/mh/?verb=GetRecord&identifier=oai%3Apubmedcentral.nih.gov%3A123&metadataPrefix=pmc"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def identity(path):
    value = os.stat(path)
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid]


def envelope(path, payload):
    path.write_bytes(canonical({"payload": payload, "sha256": hashlib.sha256(canonical(payload)).hexdigest()}))
    path.chmod(0o600)


def provision(directory):
    directory.mkdir(mode=0o700)
    (directory / "coordinator.lock").touch(mode=0o600)
    anchor = {"schema": "pmc-operational-anchor/v1", "trace_anchor": {
        "schema": "pmc-supplied-coordination-trace/v1", "coordinator_uuid": "23456789-2345-4345-8345-23456789abcd",
        "boot_uuid": BOOT.decode(), "initialized_ns": 0, "initial_sequence": 0},
        "directory_identity": identity(directory), "lock_identity": identity(directory / "coordinator.lock")}
    envelope(directory / "anchor.json", anchor)
    envelope(directory / "state.json", {"schema": "pmc-operational-state/v1",
        "anchor_sha256": hashlib.sha256(canonical(anchor)).hexdigest(), "generation": 0, "sequence": 0,
        "phase": "QUIESCENT", "predecessor": None, "pending": None, "terminal": None,
        "last_cleanup_ns": None, "last_observed_ns": 0})


def rebuild_factory(module, path, name, overrides):
    """Explicit TEST-ONLY source reconstruction. Production capture is untouched."""
    node = next(node for node in ast.parse(path.read_text()).body
                if isinstance(node, ast.FunctionDef) and node.name == name)
    namespace = dict(vars(module))
    namespace.update(overrides)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
    return namespace[name]()


def captured_cell(function, name):
    """TEST ONLY: inspect captured bindings to reconstruct unverified fixtures."""
    return dict(zip(function.__code__.co_freevars, function.__closure__))[name].cell_contents


def request():
    return subject.EgressRequest(adapter_id=subject.PMC_CONTENT_ADAPTER_ID, method="GET", url=URL,
        headers=(("Accept", "application/xml, text/xml;q=0.9"),
                 ("User-Agent", "Scientist-One-vNext-Scholarly/2")), body=b"", content_type="application/xml")


class FixtureEnvironment:
    """Not a native context: explicit inert observations plus disposable files."""
    def __init__(self, directory, *, owners=None, rules=None, wall=0, clock=None):
        self.directory = directory
        provision(directory)
        self.events, self.contexts, self.connections, self.registered, self.deadlines = [], [], [], [], []
        self.acquire_error = self.constructor_error = self.native_close_error = None
        self.close_errors = {}
        self.blocked, self.changed = set(), {}
        self.confirm_error = self.terminal_error = None
        self.after_constructor = self.before_request = None
        self.offset_ns = 0
        self.expired = False
        self.writer_hooks, self.writer_calls, self.writer_bundles = {}, [], []
        self.outcome_snapshots = []
        self.wires = [b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 4\r\n\r\n<x/>"]
        env = self
        self.owners = owners
        self._clock_override = clock

        class FixtureContext:
            __slots__ = ("_fds", "_namespace_chain", "_principal", "_native_home", "_boot_session_uuid",
                         "_tzif_bytes", "_wall_unix_ns", "_monotonic_interval_ns", "index", "closed")
            def __init__(self, index):
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                self._fds = [fd]
                self._namespace_chain = ((-1, "fixture-coordinator", fd, tuple(identity(directory))),)
                self._principal, self._native_home, self._boot_session_uuid = os.geteuid(), "/fixture-home", BOOT
                self._tzif_bytes, self._wall_unix_ns = (rules, wall) if rules is not None else (b"INERT_RULES", index)
                self._monotonic_interval_ns = (env.clock_ns(), env.clock_ns())
                self.index, self.closed = index, False
                for key, value in env.changed.get(index, {}).items():
                    setattr(self, key, value)
            def __enter__(self):
                if self.closed:
                    raise RuntimeError("closed fixture context")
                os.fstat(self._fds[-1])
                return self
            def close(self):
                if not self.closed:
                    self.closed = True
                    os.close(self._fds[-1])
                    env.events.append(("context-close", self.index))
                if self.index in env.close_errors:
                    raise env.close_errors[self.index]

        def acquire():
            env.events.append(("acquire", len(env.contexts) + 1))
            if not env.registered:
                raise AssertionError("acquisition preceded registration")
            if env.acquire_error is not None:
                raise env.acquire_error
            context = FixtureContext(len(env.contexts) + 1)
            env.contexts.append(context)
            return context

        native_class = rebuild_factory(coordination, COORDINATION, "_build_pmc_attempt_native_owner", {
            "acquire_native_pmc_context": acquire, "_NativePmcContext": FixtureContext,
            "project_pmc_schedule": (coordination.project_pmc_schedule if rules is not None else
                lambda rules, utc_unix_ns: SimpleNamespace(weekday_0500_2100_window=utc_unix_ns in env.blocked)),
            "_pmc_store_clock": self.clock_ns,
        })

        def native_factory(deadline):
            env.deadlines.append(deadline)
            native = native_class(deadline)
            original_confirm, original_terminal, original_close = native.confirm, native.terminal, native.close
            def confirm(record):
                env.events.append(("confirm", record["kind"]))
                if env.confirm_error == record["kind"]:
                    raise OSError("inert confirmation failure")
                return original_confirm(record)
            def terminal(kind):
                env.events.append(("terminal", kind))
                if env.terminal_error is not None:
                    raise env.terminal_error
                return original_terminal(kind)
            def close():
                original_close()
                env.events.append(("owner-close",))
                if env.native_close_error is not None:
                    raise env.native_close_error
            native.confirm, native.terminal, native.close = confirm, terminal, close
            return native

        class FixtureConnection:
            def __init__(self, host, port, *, timeout, context):
                env.events.append(("construct",))
                if env.state()["phase"] != "PENDING":
                    raise AssertionError("construction before confirmed pending")
                if env.constructor_error is not None:
                    raise env.constructor_error
                self.sock = None
                self.timeout, self.closes, self.requests = timeout, 0, []
                self.sender, self.receiver = socket.socketpair()
                env.connections.append(self)
                if env.after_constructor is not None:
                    env.after_constructor()
            def request(self, method, target, *, body, headers):
                env.events.append(("request",))
                if env.before_request is not None:
                    env.before_request()
                self.requests.append((method, target, body, headers))
                self.sock = self.receiver
                self.sock.settimeout(self.timeout)
                self.sender.sendall(env.wires.pop(0))
                self.sender.shutdown(socket.SHUT_WR)
            def close(self):
                self.closes += 1
                if self.closes > 1:
                    raise AssertionError("duplicate fixture connection close")
                self.sock = None
                self.receiver.close()
                self.sender.close()
                env.events.append(("connection-close",))

        real_register = owners[3] if owners is not None else subject._register_pmc_exchange_progress
        def register(prepared, transport, lifecycle):
            real_register(prepared, transport, lifecycle)
            env.registered.append(lifecycle)
            env.events.append(("register",))
        def tls():
            env.events.append(("tls",))
            if env.state()["phase"] != "PENDING":
                raise AssertionError("TLS construction before pending")
            return object()
        captured_admission = owners[5] if owners is not None else captured_cell(subject._execute_pmc_coordinated_attempt, "admission")
        def fixture_admission(prepared, transport):
            result = captured_admission(prepared, transport)
            writers = result[4]
            env.writer_bundles.append(writers)
            def intercept(index, name):
                def write(*args):
                    env.writer_calls.append((name, args))
                    try:
                        hook = env.writer_hooks.get(name)
                        if hook is None:
                            return writers[index](*args)
                        return hook(writers[index], *args)
                    finally:
                        issued = captured_cell(captured_admission, "issued")
                        row = issued.get(id(prepared._capability))
                        if row is not None:
                            env.outcome_snapshots.append(row[15])
                return write
            return (*result[:4], tuple(intercept(index, name) for index, name in
                                      enumerate(("pending", "terminal", "finalized", "schedule", "response")[:len(writers)])))
        with patch.object(coordination, "_PmcAttemptNativeOwner", native_factory):
            self.driver = rebuild_factory(subject, EXTERNAL, "_build_pmc_attempt_driver", {
                "http": SimpleNamespace(client=SimpleNamespace(HTTPSConnection=FixtureConnection)),
                "ssl": SimpleNamespace(create_default_context=tls),
                "_stdlib_tls_context_is_audited": lambda context: True,
                "_register_pmc_exchange_progress": register,
                "_pmc_attempt_admission": fixture_admission,
                # Explicit unverified reconstruction only; the actual entry
                # retains its original exact native classifier and class.
                "StdlibHttpsTransport": ComposedTransport,
                "_classify_transport_authority": lambda transport: subject.AUDITED_LIVE_TRANSPORT_AUTHORITY,
                "_require_pmc_wire_activation": lambda: None,
            })

    def clock_ns(self):
        if self.expired and self.deadlines:
            return coordination._pmc_floor_deadline_ns(self.deadlines[-1]) + 1
        if self._clock_override is not None:
            return coordination._pmc_floor_deadline_ns(self._clock_override())
        return time.monotonic_ns() + self.offset_ns

    def sleep(self, delay):
        time.sleep(delay)

    def state(self):
        return json.loads((self.directory / "state.json").read_bytes())["payload"]

    @contextmanager
    def active(self):
        with patch.object(coordination, "_pmc_store_clock", self.clock_ns), \
                patch.object(coordination, "_pmc_store_sleep", self.sleep):
            yield

    def cleanup(self):
        for connection in self.connections:
            connection.sender.close()
            connection.receiver.close()
        for context in self.contexts:
            if not context.closed:
                context.closed = True
                os.close(context._fds[-1])


class ComposedTransport:
    network_used = False
    inherits_proxy_environment = False
    scientific_evidence = False
    external_validation = "UNTESTED"
    def __init__(self, environment, before=None):
        self.environment, self.before, self.prepared = environment, before, []
    def send(self, prepared, *, credential):
        (self.environment.owners[0] if self.environment.owners is not None else subject._consume_prepared_request)(prepared, self)
        self.prepared.append(prepared)
        if self.before is not None:
            self.before(prepared)
        return self.environment.driver(prepared, self)


@contextmanager
def observed_counts():
    values, old = [], sys.gettrace()
    def trace(frame, event, arg):
        if frame.f_code.co_name == "execute" and frame.f_code.co_filename == str(EXTERNAL):
            if "response_bytes_used" in frame.f_locals:
                values.append(frame.f_locals["response_bytes_used"])
        return trace
    sys.settrace(trace)
    try:
        yield values
    finally:
        sys.settrace(old)
