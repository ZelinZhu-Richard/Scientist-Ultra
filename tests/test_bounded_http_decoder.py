"""Portable synthetic-only decoder controls; no network or scientific evidence."""

import ast
import builtins
import hashlib
import inspect
import unittest
import zlib
from scientist_one import bounded_http_decoder as subject


def encode(data, coding, level=6):
    return zlib.compress(data, level=level, wbits=31 if coding == "gzip" else 15)


def decode(raw, coding="identity", **kwargs):
    options = dict(maximum_input_bytes=subject.MAX_RAW_BYTES,
                   maximum_output_bytes=subject.MAX_DECODED_BYTES,
                   maximum_expansion_ratio=200, check_deadline=lambda: None)
    options.update(kwargs)
    return subject.decode_http_content(raw, coding, **options)


_REAL_BUILTINS = {
    name: getattr(builtins, name)
    for name in (
        "Exception", "any", "bytearray", "bytes", "int", "len", "min",
        "range", "str", "type",
    )
}
_REAL_INT = _REAL_BUILTINS["int"]
_MUTATION_SENTINEL = object()


class _MutationTrapError(Exception):
    pass


def mutating_deadline():
    """Return a checker that transiently poisons module and builtin seams."""

    module_names = (
        "MAX_RAW_BYTES", "MAX_DECODED_BYTES", "MAX_EXPANSION_RATIO",
        "CHUNK_BYTES", "BoundedDecodeError", "_deadline", "any", "bytearray",
        "bytes", "int", "len", "min", "range", "str", "type",
    )
    saved_module = {
        name: getattr(subject, name, _MUTATION_SENTINEL)
        for name in module_names
    }
    zlib_module = subject.zlib
    saved_decompressobj = zlib_module.decompressobj
    saved_zlib_error = zlib_module.error
    count = 0
    builtins_mutated = False

    def trap(*args, **kwargs):
        raise _MutationTrapError("deadline mutation reached an uncaptured dependency")

    def mutate_module():
        for name in module_names:
            setattr(subject, name, trap)
        for name in (
            "MAX_RAW_BYTES", "MAX_DECODED_BYTES", "MAX_EXPANSION_RATIO",
            "CHUNK_BYTES",
        ):
            setattr(subject, name, 1)
        subject.BoundedDecodeError = _MutationTrapError
        zlib_module.decompressobj = trap
        zlib_module.error = _MutationTrapError

    def mutate_builtins():
        nonlocal builtins_mutated
        if not builtins_mutated:
            for name in _REAL_BUILTINS:
                setattr(builtins, name, trap if name != "Exception" else _MutationTrapError)
            builtins_mutated = True

    def restore_builtins():
        nonlocal builtins_mutated
        if builtins_mutated:
            builtins.__dict__.update(_REAL_BUILTINS)
            builtins_mutated = False

    def restore_all():
        restore_builtins()
        for name, value in saved_module.items():
            if value is _MUTATION_SENTINEL:
                try:
                    delattr(subject, name)
                except AttributeError:
                    pass
            else:
                setattr(subject, name, value)
        zlib_module.decompressobj = saved_decompressobj
        zlib_module.error = saved_zlib_error

    def checker():
        nonlocal count
        count = _REAL_INT(count) + 1
        if count == 1:
            mutate_module()
            mutate_builtins()
        elif count == 2:
            restore_builtins()
        elif count == 4:
            mutate_builtins()
        elif count == 5:
            restore_builtins()

    return checker, restore_all, lambda: count


class DecoderTests(unittest.TestCase):
    def test_identity_preserves_object_and_empty(self):
        for data in (b"", b"synthetic\x00\xff"):
            self.assertIs(decode(data), data)

    def test_valid_empty_compressed_stream(self):
        for coding in ("gzip", "deflate"):
            self.assertEqual(decode(encode(b"", coding), coding), b"")
            with self.assertRaises(subject.BoundedDecodeError):
                decode(b"", coding)

    def test_both_real_compression_formats(self):
        data = b"<article>synthetic payload</article>" * 31
        for coding in ("gzip", "deflate"):
            raw = encode(data, coding)
            before = hashlib.sha256(raw).digest()
            self.assertEqual(decode(raw, coding), data)
            self.assertEqual(hashlib.sha256(raw).digest(), before)

    def test_wrong_wrappers_and_raw_deflate(self):
        data = b"synthetic"
        for raw, coding in ((encode(data, "gzip"), "deflate"),
                            (encode(data, "deflate"), "gzip"),
                            (zlib.compress(data, wbits=-15), "deflate")):
            with self.assertRaises(subject.BoundedDecodeError):
                decode(raw, coding)

    def test_truncated_at_every_byte(self):
        for coding in ("gzip", "deflate"):
            raw = encode(b"synthetic", coding)
            for size in range(len(raw)):
                with self.subTest(coding=coding, size=size):
                    with self.assertRaises(subject.BoundedDecodeError):
                        decode(raw[:size], coding)

    def test_corrupt_checksum(self):
        for coding in ("gzip", "deflate"):
            raw = bytearray(encode(b"synthetic", coding))
            raw[-1] ^= 1
            with self.assertRaises(subject.BoundedDecodeError):
                decode(bytes(raw), coding)

    def test_preset_dictionary_rejected(self):
        compressor = zlib.compressobj(zdict=b"synthetic dictionary")
        raw = compressor.compress(b"synthetic dictionary payload") + compressor.flush()
        with self.assertRaises(subject.BoundedDecodeError):
            decode(raw, "deflate")

    def test_trailing_bytes_and_concatenated_members(self):
        for coding in ("gzip", "deflate"):
            raw = encode(b"synthetic", coding)
            for suffix in (b"\x00", b"trailing", raw):
                with self.subTest(coding=coding, suffix_size=len(suffix)):
                    with self.assertRaises(subject.BoundedDecodeError):
                        decode(raw + suffix, coding)

    def test_exact_input_limit(self):
        for coding in ("identity", "gzip", "deflate"):
            data = b"synthetic"
            raw = data if coding == "identity" else encode(data, coding)
            self.assertEqual(decode(raw, coding, maximum_input_bytes=len(raw)), data)
            with self.assertRaises(subject.BoundedDecodeError):
                decode(raw, coding, maximum_input_bytes=len(raw) - 1)

    def test_exact_output_limit(self):
        data = b"abcd" * 300
        for coding in ("identity", "gzip", "deflate"):
            raw = data if coding == "identity" else encode(data, coding)
            self.assertEqual(decode(raw, coding, maximum_output_bytes=len(data)), data)
            with self.assertRaises(subject.BoundedDecodeError):
                decode(raw, coding, maximum_output_bytes=len(data) - 1)

    def test_exact_ratio_boundary(self):
        # Find a genuine stream whose decoded length is exactly 2x encoded.
        for coding in ("gzip", "deflate"):
            pair = next((b"x" * n, encode(b"x" * n, coding))
                        for n in range(1, 2000)
                        if n == 2 * len(encode(b"x" * n, coding)))
            data, raw = pair
            self.assertEqual(decode(raw, coding, maximum_expansion_ratio=2), data)
            with self.assertRaises(subject.BoundedDecodeError):
                decode(raw, coding, maximum_expansion_ratio=1)

    def test_ratio_and_decoded_hard_ceiling_clamp(self):
        raw = encode(b"a" * 1_000_000, "gzip")
        with self.assertRaises(subject.BoundedDecodeError):
            decode(raw, "gzip", maximum_expansion_ratio=10**9)
        with self.assertRaises(subject.BoundedDecodeError):
            decode(b"x" * (subject.MAX_DECODED_BYTES + 1), maximum_output_bytes=10**9)

    def test_raw_hard_ceiling_clamp(self):
        with self.assertRaisesRegex(subject.BoundedDecodeError, "encoded content"):
            decode(b"x" * (subject.MAX_RAW_BYTES + 1), maximum_input_bytes=10**9)

    def test_real_compressed_output_hard_ceiling(self):
        data = b"x" * subject.MAX_DECODED_BYTES
        for coding in ("gzip", "deflate"):
            # Stored blocks isolate the output ceiling from expansion policy.
            raw = encode(data, coding, level=0)
            self.assertEqual(decode(raw, coding, maximum_output_bytes=10**9), data)
            with self.assertRaisesRegex(subject.BoundedDecodeError, "decoded content"):
                decode(encode(data + b"x", coding, level=0), coding,
                       maximum_output_bytes=10**9)

    def test_deadline_brackets_actual_native_decode(self):
        events = []
        raw = encode(b"synthetic" * 100, "gzip")
        self.assertEqual(
            subject.decode_http_content(
                raw,
                "gzip",
                maximum_input_bytes=subject.MAX_RAW_BYTES,
                maximum_output_bytes=subject.MAX_DECODED_BYTES,
                maximum_expansion_ratio=200,
                check_deadline=lambda: events.append("check"),
            ),
            b"synthetic" * 100,
        )
        self.assertGreaterEqual(len(events), 5)
        self.assertEqual(events[0], "check")
        self.assertEqual(events[-1], "check")

    def test_import_time_capture_survives_callback_mutations(self):
        data = b"captured native decoder payload" * 100
        raw = encode(data, "gzip")
        checker, restore, count = mutating_deadline()
        original_error = subject.BoundedDecodeError
        first_restore = None
        second_restore = None
        try:
            first_restore = restore
            self.assertEqual(
                decode(raw, "gzip", check_deadline=checker),
                data,
            )
            self.assertGreaterEqual(count(), 5)
            first_restore()
            first_restore = None
            corrupted = bytearray(raw)
            corrupted[-1] ^= 1
            checker, restore, count = mutating_deadline()
            second_restore = restore
            with self.assertRaises(original_error):
                decode(bytes(corrupted), "gzip", check_deadline=checker)
            self.assertGreaterEqual(count(), 3)
        finally:
            if first_restore is not None:
                first_restore()
            if second_restore is not None:
                second_restore()
        self.assertIs(subject.BoundedDecodeError, original_error)
        self.assertEqual(subject.zlib.decompressobj, zlib.decompressobj)
        self.assertIs(subject.zlib.error, zlib.error)
        self.assertEqual(subject.MAX_RAW_BYTES, 64 * 1024 * 1024)
        self.assertEqual(subject.MAX_DECODED_BYTES, 16 * 1024 * 1024)
        self.assertEqual(subject.MAX_EXPANSION_RATIO, 200)
        self.assertEqual(subject.CHUNK_BYTES, 64 * 1024)
        for name in (
            "_deadline", "any", "bytearray", "bytes", "int", "len", "min",
            "range", "str", "type",
        ):
            self.assertFalse(hasattr(subject, name))
        self.assertEqual(decode(raw, "gzip"), data)

    def test_public_signature_has_fixed_parameters_and_kinds(self):
        signature = inspect.signature(subject.decode_http_content)
        expected_names = (
            "raw",
            "coding",
            "maximum_input_bytes",
            "maximum_output_bytes",
            "maximum_expansion_ratio",
            "check_deadline",
        )
        self.assertEqual(tuple(signature.parameters), expected_names)
        expected_kinds = (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertEqual(
            tuple(parameter.kind for parameter in signature.parameters.values()),
            expected_kinds,
        )
        self.assertTrue(
            all(
                parameter.default is inspect.Parameter.empty
                for parameter in signature.parameters.values()
            )
        )
        self.assertFalse(hasattr(subject, "_build_decoder"))
        self.assertFalse(hasattr(subject, "_builtins"))
        freevars = set(subject.decode_http_content.__code__.co_freevars)
        self.assertTrue({
            "deadline", "exact_decompressobj", "exact_zlib_error",
            "exact_max_raw_bytes", "exact_max_decoded_bytes",
            "exact_max_expansion_ratio", "exact_chunk_bytes",
            "exact_decode_error", "exact_type", "exact_int", "exact_str",
            "exact_bytes", "exact_bytearray", "exact_len", "exact_min",
            "exact_range", "exact_any",
        } <= freevars)

    def test_bounded_decode_call_shape_remains_native_and_capped(self):
        tree = ast.parse(inspect.getsource(subject))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "decompress"
        ]
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            [keyword.arg for keyword in calls[0].keywords], ["max_length"]
        )
        self.assertIsInstance(calls[0].keywords[0].value, ast.Name)
        self.assertEqual(calls[0].keywords[0].value.id, "cap")

    def test_invalid_types_and_limits(self):
        class BytesSubclass(bytes):
            pass
        class StrSubclass(str):
            pass
        class IntSubclass(int):
            pass
        for raw in ("secret", bytearray(b"secret"), memoryview(b"secret"),
                    BytesSubclass(b"secret"), None):
            with self.assertRaises(subject.BoundedDecodeError):
                decode(raw)
        for coding in (None, b"gzip", StrSubclass("gzip"), "GZIP", " gzip",
                       "gzip ", "gzip, deflate", "br", ""):
            with self.assertRaises(subject.BoundedDecodeError):
                decode(b"secret", coding)
        for name in ("maximum_input_bytes", "maximum_output_bytes", "maximum_expansion_ratio"):
            for value in (0, -1, True, False, 1.0, None, "10", IntSubclass(10)):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(subject.BoundedDecodeError):
                        decode(b"secret", **{name: value})

    def test_deadline_every_checkpoint_sanitized(self):
        raw = encode(b"synthetic" * 100, "gzip")
        calls = []
        decode(raw, "gzip", check_deadline=lambda: calls.append(None))
        self.assertGreaterEqual(len(calls), 5)
        for refusal in range(1, len(calls) + 1):
            count = 0
            def checker():
                nonlocal count
                count += 1
                if count == refusal:
                    raise RuntimeError("PRIVATE_RAW_CONTENT")
            with self.assertRaises(subject.BoundedDecodeError) as caught:
                decode(raw, "gzip", check_deadline=checker)
            self.assertNotIn("PRIVATE_RAW_CONTENT", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(count, refusal)

    def test_cancel_baseexception_propagates(self):
        def cancel():
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            decode(b"", check_deadline=cancel)

    def test_checker_is_mandatory_zero_argument(self):
        for checker in (None, lambda argument: None):
            with self.assertRaises(subject.BoundedDecodeError):
                decode(b"", check_deadline=checker)
        with self.assertRaises(TypeError):
            subject.decode_http_content(b"", "identity", maximum_input_bytes=1,
                                        maximum_output_bytes=1, maximum_expansion_ratio=1)

    def test_legitimate_multichunk_and_tail_drains(self):
        # Deterministic, partly repeated data keeps ratio under200 while forcing
        # both >64KiB wire input and >64KiB decoded output; genuine zlib is used.
        seed = b"".join(hashlib.sha256(str(n).encode()).digest() for n in range(5000))
        data = b"".join(seed[n:n+1000] * 50 for n in range(0, len(seed), 1000))
        for coding in ("gzip", "deflate"):
            raw = encode(data, coding)
            self.assertGreater(len(raw), subject.CHUNK_BYTES)
            self.assertLess(len(data), 200 * len(raw))
            self.assertEqual(decode(raw, coding), data)
            self.assertGreater(len(raw), subject.CHUNK_BYTES)
            self.assertGreater(len(data), subject.CHUNK_BYTES)



if __name__ == "__main__":
    unittest.main(verbosity=2)
