"""Portable supplied-stream PMC framing controls."""

import gzip
import http.client
import io
import socket
import unittest
import zlib
from unittest.mock import patch

from scientist_one import external as subject
from scientist_one.bounded_http_decoder import decode_http_content

def prepared(cap=1024, method="GET"):
    return subject.PreparedEgressRequest(
        request_id="a" * 64, method=method, url="https://pmc.ncbi.nlm.nih.gov/fixture",
        host="pmc.ncbi.nlm.nih.gov", target="/fixture", headers=(), body=b"",
        maximum_response_bytes=cap,
    )

def wire(body=b"abc", headers=None, status=200, version=b"HTTP/1.1", reason=b"OK"):
    if headers is None:
        headers = [(b"Content-Length", str(len(body)).encode())]
    head = version + b" " + str(status).encode() + b" " + reason + b"\r\n"
    return head + b"".join(name + b": " + value + b"\r\n" for name, value in headers) + b"\r\n" + body

def chunked(body=b"abc", suffix=b"0\r\n\r\n", size=None):
    size = format(len(body), "x").encode() if size is None else size
    return wire(size + b"\r\n" + body + b"\r\n" + suffix,
                headers=[(b"Transfer-Encoding", b"chunked")])

class FakeSocket:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

class FragmentedStream(io.BytesIO):
    def __init__(self, raw, fragment=1):
        super().__init__(raw)
        self.fragment = fragment
        self.operations = []

    def read(self, amount=-1):
        self.operations.append(("body", amount))
        return super().read(min(amount, self.fragment))

    def readline(self, amount=-1):
        self.operations.append(("line", amount))
        return super().readline(min(amount, self.fragment))

class PmcFramingCandidateTests(unittest.TestCase):
    def reader(self, raw, *, cap=1024, stream=None, remaining=None, method="GET"):
        stream = io.BytesIO(raw) if stream is None else stream
        sock = FakeSocket()
        reader = subject._PmcFramedResponseReader(
            stream=stream, retained_socket=sock, prepared=prepared(cap, method),
            deadline_remaining=(lambda request: 1.0) if remaining is None else remaining,
        )
        return reader, stream, sock

    def accept(self, raw, expected=b"abc", *, cap=1024, **kwargs):
        reader, stream, sock = self.reader(raw, cap=cap, **kwargs)
        status, headers, body = reader.read()
        self.assertEqual(body, expected)
        self.assertEqual(reader.response_body_bytes, len(expected))
        self.assertIs(type(status), int)
        self.assertIs(type(headers), tuple)
        self.assertIs(type(body), bytes)
        self.assertFalse(stream.closed)
        self.assertTrue(sock.timeouts)
        return reader, stream

    def reject(self, raw, *, count=0, **kwargs):
        reader, _, _ = self.reader(raw, **kwargs)
        with self.assertRaises(subject._PartialResponseTransportFailure) as caught:
            reader.read()
        self.assertEqual(reader.response_body_bytes, count)
        self.assertEqual(caught.exception.response_body_bytes, count)
        self.assertTrue(caught.exception.policy_denial)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertFalse(hasattr(caught.exception, "partial"))
        return reader

    def test_fixed_length_and_http10_positive_no_endpoint_overread(self):
        for version in (b"HTTP/1.0", b"HTTP/1.1"):
            with self.subTest(version=version):
                raw = wire(version=version)
                _, stream = self.accept(raw + b"NEXT")
                self.assertEqual(stream.read(), b"NEXT")

    def test_fragmented_head_body_and_chunk_metadata(self):
        for raw in (wire(), chunked()):
            for fragment in (1, 2, 7):
                with self.subTest(fragment=fragment):
                    stream = FragmentedStream(raw, fragment)
                    self.accept(raw, stream=stream)
                    self.assertTrue(all(0 < size <= 65536 for _, size in stream.operations))

    def test_every_fixed_message_cutoff_preserves_actual_exposed_count(self):
        raw = wire(b"abcde")
        start = raw.index(b"\r\n\r\n") + 4
        for end in range(len(raw)):
            with self.subTest(end=end):
                self.reject(raw[:end], count=max(0, end - start))
        self.accept(raw, b"abcde")

    def test_every_chunk_message_cutoff_preserves_only_data_bytes(self):
        head = wire(b"", headers=[(b"Transfer-Encoding", b"chunked")])
        body = b"2\r\nab\r\n1\r\nc\r\n0\r\nX-Final: yes\r\n\r\n"
        raw = head + body
        positions = [len(head) + 3, len(head) + 4, len(head) + 10]
        for end in range(len(raw)):
            with self.subTest(end=end):
                self.reject(raw[:end], count=sum(position < end for position in positions))
        self.accept(raw)

    def test_strict_status_grammar_and_allowed_reason_bytes(self):
        for line in (b"HTTP/1.1 200\r\n", b"HTTP/1.1\t200 OK\r\n", b"HTTP/1.1 20 OK\r\n",
                     b"HTTP/1.1 +20 OK\r\n", b"HTTP/1.1 600 OK\r\n", b"HTTP/2.0 200 OK\r\n",
                     b"HTTP/1.1 200 OK\n", b"HTTP/1.1 200 A\x7fB\r\n"):
            with self.subTest(line=line):
                self.reject(line + b"Content-Length: 0\r\n\r\n")
        for reason in (b"", b"\t Latin \xff"):
            self.accept(wire(b"", reason=reason), b"")

    def test_strict_headers_folding_duplicates_controls_and_obs_text(self):
        prefix = b"HTTP/1.1 200 OK\r\n"
        for field in (b" Content-Length: 0\r\n", b"Content-Length : 0\r\n", b"MissingColon\r\n",
                      b"X: \r\n", b"X: a\x00b\r\n", b"X: a\x7fb\r\n", b"X: y\n",
                      b"X: a\r\nX: b\r\n", b"X: a\r\n\tfold\r\n"):
            with self.subTest(field=field):
                self.reject(prefix + field + b"Content-Length: 0\r\n\r\n")
        self.accept(wire(b"", headers=[(b"X", b"\t\xff visible\t"), (b"Content-Length", b"0")]), b"")

    def test_informational_head_chain_limits_and_no_header_promotion(self):
        interim = wire(b"", headers=[(b"X-Info", b"discard")], status=103)
        reader, _, _ = self.reader(interim * 8 + wire())
        status, headers, body = reader.read()
        self.assertEqual((status, body), (200, b"abc"))
        self.assertNotIn("X-Info", dict(headers))
        self.reject(interim * 9 + wire())
        for status in (100, 103):
            self.reject(wire(b"", headers=[(b"Content-Length", b"0")], status=status) + wire())
        self.reject(wire(b"", headers=[], status=101))
        self.reject(wire(headers=[(b"Content-Length", b"3"), (b"Upgrade", b"h2c")]))
        self.reject(wire(headers=[(b"Content-Length", b"3"), (b"Connection", b"keep-alive, Upgrade")]))

    def test_head_line_and_field_count_exact_bounds(self):
        self.accept(wire(b"", reason=b"x" * (8192 - 15)), b"")
        self.reject(wire(b"", reason=b"x" * (8192 - 14)))
        fields = [(b"Content-Length", b"0")] + [(f"X-{index}".encode(), b"v") for index in range(63)]
        self.accept(wire(b"", headers=fields), b"")
        self.reject(wire(b"", headers=fields + [(b"X-extra", b"v")]))
        self.accept(wire(b"", headers=[(b"Content-Length", b"0"), (b"X", b"v" * 8187)]), b"")
        self.reject(wire(b"", headers=[(b"Content-Length", b"0"), (b"X", b"v" * 8188)]))

    def test_aggregate_head_bytes_exact_limit_and_no_interim_reset(self):
        def sized(total):
            start = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
            lines, remaining, index = [], total - len(start) - 2, 0
            while remaining:
                length = min(8192, remaining)
                prefix = f"X-{index}: ".encode()
                lines.append(prefix + b"v" * (length - len(prefix) - 2) + b"\r\n")
                remaining -= length
                index += 1
            return start + b"".join(lines) + b"\r\n"

        self.accept(sized(65536), b"")
        self.reject(sized(65537))
        self.reject(wire(b"", status=100, headers=[]) + sized(65536))

    def test_length_syntax_leading_zeros_and_significant_numeric_bounds(self):
        for value in (b"+3", b"-3", b"0x3", b"0_3", b"3,3", b"\xff", b"999999999999999999999"):
            self.reject(wire(headers=[(b"Content-Length", value)]))
        self.accept(wire(headers=[(b"Content-Length", b"0" * 5000 + b"3")]))
        self.accept(wire(b"", headers=[(b"Content-Length", b"0" * 5000)]), b"", cap=0)
        self.reject(wire(headers=[(b"Content-Length", b"4")]), cap=3)

    def test_ambiguous_transfer_missing_framing_and_http10_chunked_refuse(self):
        for headers in ([], [(b"Transfer-Encoding", b"gzip")], [(b"Transfer-Encoding", b"gzip, chunked")],
                        [(b"Content-Length", b"3"), (b"Transfer-Encoding", b"chunked")],
                        [(b"Content-Length", b"3"), (b"content-length", b"3")]):
            self.reject(wire(headers=headers))
        self.reject(wire(b"0\r\n\r\n", headers=[(b"Transfer-Encoding", b"chunked")], version=b"HTTP/1.0"))
        self.accept(wire(b"3\r\nabc\r\n0\r\n\r\n", headers=[(b"Transfer-Encoding", b"ChUnKeD")]))

    def test_bodyless204_304_metadata_and205_zero_data(self):
        for status in (204, 304):
            raw = wire(b"", headers=[], status=status)
            _, stream = self.accept(raw + b"NEXT", b"", cap=0)
            self.assertEqual(stream.read(), b"NEXT")
        for value in (b"999999", b"0" * 5000 + str((1 << 63) - 1).encode()):
            self.accept(wire(b"", headers=[(b"Content-Length", value)], status=304), b"", cap=0)
        self.reject(wire(b"", headers=[(b"Content-Length", str(1 << 63).encode())], status=304), cap=0)
        raw = wire(b"", headers=[(b"Transfer-Encoding", b"chunked")], status=304)
        _, stream = self.accept(raw + b"NO_CHUNKS", b"", cap=0)
        self.assertEqual(stream.read(), b"NO_CHUNKS")
        self.reject(wire(b"", headers=[(b"Content-Length", b"0")], status=204))
        self.accept(wire(b"", status=205), b"", cap=0)
        self.accept(wire(b"0\r\n\r\n", headers=[(b"Transfer-Encoding", b"chunked")], status=205), b"", cap=0)
        self.reject(wire(b"x", status=205))
        self.reject(wire(b"1\r\nx\r\n0\r\n\r\n", headers=[(b"Transfer-Encoding", b"chunked")], status=205))

    def test_strict_chunk_size_spellings_and_data_delimiters(self):
        for size in (b"+3", b"-3", b"0x3", b"0_3", b" 3", b"3 ", b"", b"g", b"999999999999999999"):
            self.reject(chunked(size=size))
        for delimiter in (b"XX", b"\n\r", b"\n", b"\rX"):
            self.reject(wire(b"3\r\nabc" + delimiter + b"0\r\n\r\n",
                             headers=[(b"Transfer-Encoding", b"chunked")]), count=3)
        self.accept(chunked(size=b"0" * 5000 + b"3"))

    def test_chunk_extensions_exact_tokens_bws_quotes_and_escapes(self):
        for size in (b"3;a", b"3 \t; a = token ;b=\"quoted \\\"text\"", b"3;a=\"\"", b"3;a=\"\\\t\""):
            with self.subTest(size=size):
                self.accept(chunked(size=size))
        for size in (b"3;", b"3;a=", b"3;a ", b"3;a=t ", b"3;a=\"unterminated", b"3;a=\"bad\x01\"",
                     b"3;a=\"bad\xff\"", b"3;a=\"bad\\\xff\"", b"3;a==x", b"3;a=\"x\"tail"):
            with self.subTest(size=size):
                self.reject(chunked(size=size))

    def test_trailers_strict_termination_syntax_controls_and_duplicates(self):
        self.accept(chunked(suffix=b"0\r\nX-Trailer: \xff\tvalue\r\n\r\n"))
        for tail in (b"0\r\n", b"0\r\n\n", b"0\n\r\n", b"0\r\n folded\r\n\r\n",
                     b"0\r\nX: one\r\nx: two\r\n\r\n", b"0\r\nX: \r\n\r\n"):
            self.reject(chunked(suffix=tail), count=3)
        for name in (b"Content-Length", b"Transfer-Encoding", b"Content-Type", b"Content-Encoding", b"Trailer",
                     b"Host", b"Connection", b"Proxy-Connection", b"Retry-After", b"Location"):
            self.reject(chunked(suffix=b"0\r\n" + name + b": value\r\n\r\n"), count=3)
        self.reject(wire(b"3\r\nabc\r\n0\r\nX-Initial: again\r\n\r\n",
                         headers=[(b"Transfer-Encoding", b"chunked"), (b"X-Initial", b"first")]), count=3)

    def test_trailer_line_count_and_aggregate_exact_limits(self):
        lines = b"".join(f"X-{index}: v\r\n".encode() for index in range(64))
        self.accept(chunked(suffix=b"0\r\n" + lines + b"\r\n"))
        self.reject(chunked(suffix=b"0\r\n" + lines + b"X-extra: v\r\n\r\n"), count=3)
        self.accept(chunked(suffix=b"0\r\nX: " + b"v" * 8187 + b"\r\n\r\n"))
        self.reject(chunked(suffix=b"0\r\nX: " + b"v" * 8188 + b"\r\n\r\n"), count=3)
        def trailer(total):
            values = []
            for index, length in enumerate([8192] * 7 + [total - 2 - 8192 * 7]):
                prefix = f"X-{index}: ".encode()
                values.append(prefix + b"v" * (length - len(prefix) - 2) + b"\r\n")
            return b"".join(values) + b"\r\n"
        self.accept(chunked(suffix=b"0\r\n" + trailer(65536)))
        self.reject(chunked(suffix=b"0\r\n" + trailer(65537)), count=3)

    def test_chunk_syntax_aggregate_exact_limit(self):
        def payload(total):
            syntax = total - 5
            lengths = [8194] * (syntax // 8194)
            if syntax % 8194:
                lengths.append(syntax % 8194)
            data = b"".join(b"1;a=" + b"v" * (length - 8) + b"\r\nx\r\n" for length in lengths)
            return wire(data + b"0\r\n\r\n", headers=[(b"Transfer-Encoding", b"chunked")]), len(lengths)
        raw, count = payload(1048576)
        self.accept(raw, b"x" * count)
        raw, count = payload(1048577)
        self.reject(raw, count=count)

    def test_chunk_overbudget_refuses_before_advertised_data(self):
        self.reject(chunked(size=b"4"), cap=3)
        raw = wire(b"2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n", headers=[(b"Transfer-Encoding", b"chunked")])
        self.reject(raw, cap=3, count=2)
        self.accept(wire(b"000\r\n\r\n", headers=[(b"Transfer-Encoding", b"chunked")]), b"", cap=0)

    def test_readonly_count_single_use_and_cancellation_before_io(self):
        marker = KeyboardInterrupt()
        reader, stream, _ = self.reader(wire(), remaining=lambda request: (_ for _ in ()).throw(marker))
        with self.assertRaises(KeyboardInterrupt) as caught:
            reader.read()
        self.assertIs(caught.exception, marker)
        self.assertEqual(stream.tell(), 0)
        with self.assertRaises(subject._PartialResponseTransportFailure):
            reader.read()
        self.assertEqual(reader.response_body_bytes, 0)
        with self.assertRaises(AttributeError):
            reader.response_body_bytes = 99

    def test_late_return_and_cancellation_preserve_count_before_postcheck(self):
        for failure in (ValueError("PRIVATE_DEADLINE"), KeyboardInterrupt()):
            stream = io.BytesIO(wire())
            body_start = len(wire()) - 3
            def remaining(request):
                if stream.tell() > body_start:
                    raise failure
                return 1.0
            reader, _, _ = self.reader(b"", stream=stream, remaining=remaining)
            expected = KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else subject._PartialResponseTransportFailure
            with self.assertRaises(expected) as caught:
                reader.read()
            self.assertEqual(reader.response_body_bytes, 3)
            if isinstance(failure, KeyboardInterrupt):
                self.assertIs(caught.exception, failure)
            with self.assertRaises(subject._PartialResponseTransportFailure):
                reader.read()
            self.assertEqual(reader.response_body_bytes, 3)

    def test_reentrant_read_poisoning_retains_proved_count(self):
        stream = io.BytesIO(wire())
        inner_counts = []
        reader = None
        def remaining(request):
            if reader.response_body_bytes and not inner_counts:
                try:
                    reader.read()
                except subject._PartialResponseTransportFailure as error:
                    inner_counts.append(error.response_body_bytes)
            return 1.0
        reader, _, _ = self.reader(b"", stream=stream, remaining=remaining)
        with self.assertRaises(subject._PartialResponseTransportFailure):
            reader.read()
        self.assertEqual(inner_counts, [3])
        self.assertEqual(reader.response_body_bytes, 3)

    def test_malformed_stream_values_do_not_invent_progress(self):
        for returned in (None, bytearray(b"x"), "x", b"toolong"):
            class Bad(io.BytesIO):
                def read(self, amount):
                    return returned
            self.reject(wire(), stream=Bad(wire()), count=0)
        class BadLine(io.BytesIO):
            def readline(self, amount):
                return b"x" * (amount + 1)
        self.reject(wire(), stream=BadLine(wire()))

    def test_direct_incomplete_body_partial_only_with_exact_bounded_bytes(self):
        for partial, count in ((b"xy", 2), (b"toolong", 0), (bytearray(b"x"), 0)):
            error = http.client.IncompleteRead(partial, 1)
            error.__cause__ = http.client.IncompleteRead(b"nested", 1)
            class Incomplete(io.BytesIO):
                def read(self, amount):
                    raise error
            self.reject(wire(), stream=Incomplete(wire()), count=count)
        class IncompleteLine(io.BytesIO):
            def readline(self, amount):
                raise http.client.IncompleteRead(b"framing", 1)
        self.reject(wire(), stream=IncompleteLine(wire()), count=0)

    def test_framing_partial_is_not_added_to_body_count(self):
        class DelimiterFailure(io.BytesIO):
            def read(self, amount):
                if amount == 2:
                    raise http.client.IncompleteRead(b"\r", 1)
                return super().read(amount)
        self.reject(chunked(), stream=DelimiterFailure(chunked()), count=3)

    def test_retained_socket_timeout_refresh_and_terminal_timeout_failure(self):
        reader, _, sock = self.reader(wire(), remaining=lambda request: 0.75)
        reader.read()
        self.assertGreaterEqual(len(sock.timeouts), 4)
        self.assertEqual(set(sock.timeouts), {0.75})
        for remaining in (0.0, -1.0, float("nan"), float("inf"), True, None):
            self.reject(wire(), remaining=lambda request, value=remaining: value)
        class TimedOut(io.BytesIO):
            def read(self, amount):
                raise TimeoutError("PRIVATE_TIMEOUT")
        self.reject(wire(), stream=TimedOut(wire()))

    def test_final_assembly_failure_retains_exact_count(self):
        reader, _, _ = self.reader(wire())
        with patch.object(subject._PmcFramedResponseReader, "_assemble", side_effect=MemoryError("fixture")):
            with self.assertRaises(subject._PartialResponseTransportFailure) as caught:
                reader.read()
        self.assertEqual(caught.exception.response_body_bytes, 3)
        self.assertEqual(reader.response_body_bytes, 3)

    def test_prepared_exact_get_and_nonnegative_cap(self):
        for method in ("HEAD", "CONNECT", "POST", b"GET"):
            self.reject(wire(), method=method)
        for cap in (-1, True, 1.0):
            self.reject(wire(), cap=cap)
        self.accept(wire(b""), b"", cap=0)
        reader = subject._PmcFramedResponseReader(stream=io.BytesIO(wire()), retained_socket=FakeSocket(),
                                                  prepared=object(), deadline_remaining=lambda request: 1.0)
        with self.assertRaises(subject._PartialResponseTransportFailure):
            reader.read()

    def test_fixed_and_chunked_gzip_deflate_existing_decoder(self):
        original = b"<article>fixture content</article>" * 8
        for coding, encoded in (("gzip", gzip.compress(original)), ("deflate", zlib.compress(original))):
            for mode in ("fixed", "chunked"):
                with self.subTest(coding=coding, mode=mode):
                    if mode == "fixed":
                        raw = wire(encoded, headers=[(b"Content-Length", str(len(encoded)).encode()),
                                                     (b"Content-Encoding", coding.encode())])
                    else:
                        raw = wire(format(len(encoded), "x").encode() + b"\r\n" + encoded + b"\r\n0\r\n\r\n",
                                   headers=[(b"Transfer-Encoding", b"chunked"), (b"Content-Encoding", coding.encode())])
                    reader, _, _ = self.reader(raw)
                    _, _, body = reader.read()
                    self.assertEqual(body, encoded)
                    decoded = decode_http_content(body, coding, maximum_input_bytes=1024,
                                                  maximum_output_bytes=4096, maximum_expansion_ratio=200,
                                                  check_deadline=lambda: None)
                    self.assertEqual(decoded, original)
                    self.assertEqual(reader.response_body_bytes, len(encoded))

    def test_actual_disposable_socketpair_fixed_and_chunked_no_reader_closure(self):
        for raw in (wire(), chunked()):
            with self.subTest(mode=raw[:30]):
                sender, receiver = socket.socketpair()
                stream = receiver.makefile("rb")
                try:
                    sender.sendall(raw + b"NEXT")
                    sender.shutdown(socket.SHUT_WR)
                    reader = subject._PmcFramedResponseReader(stream=stream, retained_socket=receiver,
                                                              prepared=prepared(), deadline_remaining=lambda request: 1.0)
                    self.assertEqual(reader.read()[2], b"abc")
                    self.assertEqual(stream.read(4), b"NEXT")
                    self.assertFalse(stream.closed)
                    self.assertGreaterEqual(receiver.fileno(), 0)
                finally:
                    stream.close()
                    receiver.close()
                    sender.close()

    def test_existing_generic_nested_incomplete_read_count_is_unchanged(self):
        inner = http.client.IncompleteRead(b"fg", 1)
        outer = http.client.IncompleteRead(b"de", 1)
        outer.__cause__ = inner
        class ExistingResponse:
            calls = 0
            def read(self, amount):
                self.calls += 1
                if self.calls == 1:
                    return b"abc"
                raise outer
        connection = type("Connection", (), {"sock": FakeSocket()})()
        with self.assertRaises(subject._PartialResponseTransportFailure) as caught:
            subject._read_bounded_response_body(ExistingResponse(), connection, prepared(),
                                                deadline_remaining=lambda request: 1.0)
        self.assertEqual(caught.exception.response_body_bytes, 7)
        self.assertFalse(caught.exception.policy_denial)
