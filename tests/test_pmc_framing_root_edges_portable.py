"""Portable supplied-stream PMC framing root edges."""

import http.client
import io
import unittest

import scientist_one.external as subject

def fixed(body=b"abc", *, status=b"200 OK", extra=b"", declared=None):
    length = len(body) if declared is None else declared
    return (b"HTTP/1.1 " + status + b"\r\nContent-Length: " + str(length).encode()
            + b"\r\n" + extra + b"\r\n" + body)

def chunked(body, *, extra=b""):
    return b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n" + extra + b"\r\n" + body

class SuppliedSocket:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)

class ObservedStream(io.BytesIO):
    def __init__(self, raw):
        super().__init__(raw)
        self.calls = []

    def read(self, size=-1):
        self.calls.append(("read", size))
        return super().read(size)

    def readline(self, size=-1):
        self.calls.append(("readline", size))
        return super().readline(size)

def reader(raw=None, *, stream=None, limit=64, deadline=None, method="GET"):
    source = ObservedStream(raw) if stream is None else stream
    sock = SuppliedSocket()
    prepared = subject.PreparedEgressRequest(
        request_id="a" * 64, method=method,
        url="https://pmc.ncbi.nlm.nih.gov/api/oai/v1/mh/?verb=GetRecord",
        host="pmc.ncbi.nlm.nih.gov", target="/api/oai/v1/mh/?verb=GetRecord",
        headers=(("Accept", "application/xml"),), body=b"",
        maximum_response_bytes=limit, _deadline_monotonic=100.0,
    )
    result = subject._PmcFramedResponseReader(
        stream=source, retained_socket=sock, prepared=prepared,
        deadline_remaining=deadline or (lambda supplied: 1.0),
    )
    return result, source, sock

class FramingRootEdges(unittest.TestCase):
    def denied(self, instance, expected_count):
        with self.assertRaises(subject._PartialResponseTransportFailure) as caught:
            instance.read()
        self.assertTrue(caught.exception.policy_denial)
        self.assertEqual(caught.exception.response_body_bytes, expected_count)
        self.assertEqual(instance.response_body_bytes, expected_count)
        return caught.exception

    def test_rejects_observed_incomplete_and_discarded_head_lines(self):
        for raw in (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nMALFORMED\r\nX-Later: hidden\r\n\r\n",
        ):
            with self.subTest(raw=raw):
                instance, _, _ = reader(raw)
                self.denied(instance, 0)

    def test_rejects_observed_chunk_number_spellings_and_delimiter(self):
        for spelling in (b"+3", b"0x3", b"0_3"):
            with self.subTest(spelling=spelling):
                instance, _, _ = reader(chunked(spelling + b"\r\nabc\r\n0\r\n\r\n"))
                self.denied(instance, 0)
        instance, _, _ = reader(chunked(b"3\r\nabcXX0\r\n\r\n"))
        self.denied(instance, 3)

    def test_empty_reason_requires_both_literal_sp_separators(self):
        instance, _, _ = reader(fixed(b"", status=b"200 "))
        self.assertEqual(instance.read(), (200, (("Content-Length", "0"),), b""))
        for status in (b"200", b"\t200 ", b"200\tOK"):
            with self.subTest(status=status):
                instance, _, _ = reader(fixed(b"", status=status))
                self.denied(instance, 0)

    def test_304_metadata_int64_is_not_body_budget_or_body_read(self):
        raw = fixed(b"", status=b"304 Not Modified", declared=(1 << 63) - 1)
        instance, stream, _ = reader(raw + b"DO_NOT_READ", limit=0)
        result = instance.read()
        self.assertEqual(result[0], 304)
        self.assertEqual(result[2], b"")
        self.assertEqual(instance.response_body_bytes, 0)
        self.assertEqual(stream.tell(), len(raw))
        self.assertFalse(any(kind == "read" for kind, _ in stream.calls))
        instance, _, _ = reader(fixed(b"", status=b"304 Not Modified", declared=1 << 63), limit=0)
        self.denied(instance, 0)

    def test_informational_heads_do_not_replace_final_headers(self):
        raw = (b"HTTP/1.1 103 Early Hints\r\nLink: ignored\r\n\r\n"
               b"HTTP/1.1 100 Continue\r\nX-Info: ignored\r\n\r\n" + fixed())
        instance, _, _ = reader(raw)
        self.assertEqual(instance.read(), (200, (("Content-Length", "3"),), b"abc"))
        for count, accepted in ((8, True), (9, False)):
            instance, _, _ = reader(b"HTTP/1.1 103 Hint\r\n\r\n" * count + fixed())
            if accepted:
                self.assertEqual(instance.read()[2], b"abc")
            else:
                self.denied(instance, 0)

    def test_informational_head_byte_budget_never_resets(self):
        info = b"HTTP/1.1 103 Hint\r\nX-Padding: " + b"x" * 8170 + b"\r\n\r\n"
        # Every individual line/head is valid, but eight heads exceed64KiB.
        self.assertLessEqual(len(b"X-Padding: " + b"x" * 8170 + b"\r\n"), 8192)
        instance, _, _ = reader(info * 7 + fixed())
        self.assertEqual(instance.read()[2], b"abc")
        self.assertGreater(len(info) * 8, 65536)
        instance, _, _ = reader(info * 8 + fixed())
        self.denied(instance, 0)

    def test_post_body_deadline_denial_preserves_count_and_burned_use(self):
        stream = ObservedStream(fixed())
        reads_finished = False
        original = stream.read

        def read_body(size):
            nonlocal reads_finished
            value = original(size)
            reads_finished = True
            return value

        stream.read = read_body
        calls = []

        def deadline(prepared):
            calls.append(prepared._deadline_monotonic)
            if reads_finished:
                raise subject.EgressDeniedError("supplied deadline ended")
            return 0.75

        instance, _, sock = reader(stream=stream, deadline=deadline)
        self.denied(instance, 3)
        call_count = len(calls)
        self.denied(instance, 3)
        self.assertEqual(len(calls), call_count)
        self.assertEqual(set(calls), {100.0})
        self.assertTrue(sock.timeouts)
        self.assertEqual(set(sock.timeouts), {0.75})

    def test_cancellation_identity_and_count_survive_post_body_check(self):
        stream = ObservedStream(fixed())
        primary = KeyboardInterrupt()

        def deadline(_prepared):
            if any(kind == "read" for kind, _ in stream.calls):
                raise primary
            return 1.0

        instance, _, _ = reader(stream=stream, deadline=deadline)
        with self.assertRaises(KeyboardInterrupt) as caught:
            instance.read()
        self.assertIs(caught.exception, primary)
        self.assertEqual(instance.response_body_bytes, 3)
        self.denied(instance, 3)

    def test_body_partial_counts_only_direct_bounded_bytes_not_nested_cause(self):
        class PartialStream(ObservedStream):
            def __init__(self, raw):
                super().__init__(raw)
                self.body_calls = 0

            def read(self, size=-1):
                self.body_calls += 1
                if self.body_calls == 1:
                    return super().read(min(size, 3))
                failure = http.client.IncompleteRead(b"de", 3)
                failure.__cause__ = http.client.IncompleteRead(b"NOT_BODY", 1)
                raise failure

        instance, _, _ = reader(stream=PartialStream(fixed(b"abcdefgh")))
        error = self.denied(instance, 5)
        self.assertFalse(hasattr(error, "partial"))
        self.assertNotIn("NOT_BODY", repr(vars(error)))

    def test_oversized_body_return_keeps_only_previously_proved_count(self):
        class OverReturn(ObservedStream):
            def __init__(self, raw):
                super().__init__(raw)
                self.body_calls = 0

            def read(self, size=-1):
                self.body_calls += 1
                if self.body_calls == 1:
                    return super().read(1)
                return b"x" * (size + 1)

        instance, _, _ = reader(stream=OverReturn(fixed(b"abc")))
        self.denied(instance, 1)

    def test_extensions_and_discarded_trailers_have_no_header_authority(self):
        body = b'1 \t; name = "x\\\"y"; flag\r\nz\r\n00\r\nDigest: unverified\r\n\r\n'
        raw = chunked(body)
        instance, stream, _ = reader(raw + b"EXTRA_MESSAGE")
        self.assertEqual(instance.read(), (200, (("Transfer-Encoding", "chunked"),), b"z"))
        self.assertEqual(stream.tell(), len(raw))
        for size in (b'1; flag ', b'1; name="unterminated', b'1; name="\x80"'):
            with self.subTest(size=size):
                instance, _, _ = reader(chunked(size + b"\r\nz\r\n0\r\n\r\n"))
                self.denied(instance, 0)

    def test_reentry_refusal_preserves_outer_progress_and_poisoned_state(self):
        holder, nested = [], []
        attempted = False
        stream = ObservedStream(fixed())

        def deadline(_prepared):
            nonlocal attempted
            if not attempted and any(kind == "read" for kind, _ in stream.calls):
                attempted = True
                try:
                    holder[0].read()
                except subject._PartialResponseTransportFailure as error:
                    nested.append(error.response_body_bytes)
                else:
                    self.fail("reentrant parser read succeeded")
            return 1.0

        instance, _, _ = reader(stream=stream, deadline=deadline)
        holder.append(instance)
        self.denied(instance, 3)
        self.assertEqual(nested, [3])
        self.assertEqual(instance.response_body_bytes, 3)
