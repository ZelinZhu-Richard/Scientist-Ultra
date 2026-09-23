"""Private pure selected-profile decoder; no I/O, provenance or live authority.

The caller canonicalizes HTTP coding names and rejects duplicate/stacked headers.
Only canonical identity/gzip/deflate are accepted here. HTTP deflate requires the
zlib wrapper. A single complete compressed stream is required: concatenated gzip
members and all trailing bytes are deliberately unsupported. Positive integer
limits are clamped to raw64MiB, decoded16MiB and expansion200. Ratio uses complete
encoded length, not an intermediate input prefix. Empty identity is permitted.
The mandatory deadline hook supplies cancellation only, never issuing authority.
An import-time deleted factory captures the native decoder, hard ceilings,
deadline sanitizer, and bounded builtins before the hook can run.
"""

import zlib
from collections.abc import Callable


MAX_RAW_BYTES = 64 * 1024 * 1024  # external.MAX_ABSOLUTE_RESPONSE_BYTES
MAX_DECODED_BYTES = 16 * 1024 * 1024  # selected PMC decoding profile
MAX_EXPANSION_RATIO = 200
CHUNK_BYTES = 64 * 1024


class BoundedDecodeError(ValueError):
    """Static safe failure, without response bytes or underlying error text."""


def _build_decoder():
    """Capture the pure decoder's dependencies before any caller hook runs."""

    import builtins as _builtins

    exact_decompressobj = zlib.decompressobj
    exact_zlib_error = zlib.error
    exact_max_raw_bytes = MAX_RAW_BYTES
    exact_max_decoded_bytes = MAX_DECODED_BYTES
    exact_max_expansion_ratio = MAX_EXPANSION_RATIO
    exact_chunk_bytes = CHUNK_BYTES
    exact_decode_error = BoundedDecodeError
    exact_exception = _builtins.Exception
    exact_type = _builtins.type
    exact_int = _builtins.int
    exact_str = _builtins.str
    exact_bytes = _builtins.bytes
    exact_bytearray = _builtins.bytearray
    exact_len = _builtins.len
    exact_min = _builtins.min
    exact_range = _builtins.range
    exact_any = _builtins.any

    def deadline(check: Callable[[], None]) -> None:
        failed = False
        try:
            check()
        except exact_exception:
            failed = True
        # Raise outside the handler so even __context__ does not retain its message.
        # BaseException cancellations intentionally propagate.
        if failed:
            raise exact_decode_error("content decoding deadline refused") from None

    def decode_http_content(
        raw: bytes,
        coding: str,
        *,
        maximum_input_bytes: int,
        maximum_output_bytes: int,
        maximum_expansion_ratio: int,
        check_deadline: Callable[[], None],
    ) -> bytes:
        """Decode within hard ceilings; limits may tighten but never enlarge them."""
        deadline(check_deadline)
        if exact_type(raw) is not exact_bytes:
            raise exact_decode_error("content decoding requires exact bytes")
        if exact_type(coding) is not exact_str or coding not in (
            "identity", "gzip", "deflate"
        ):
            raise exact_decode_error("content coding is unsupported")
        if exact_any(
            exact_type(value) is not exact_int or value <= 0
            for value in (
                maximum_input_bytes, maximum_output_bytes, maximum_expansion_ratio
            )
        ):
            raise exact_decode_error("content decoding limits are invalid")
        input_limit = exact_min(maximum_input_bytes, exact_max_raw_bytes)
        output_limit = exact_min(maximum_output_bytes, exact_max_decoded_bytes)
        ratio_limit = exact_min(maximum_expansion_ratio, exact_max_expansion_ratio)
        if exact_len(raw) > input_limit:
            raise exact_decode_error("encoded content exceeds limit")
        budget = exact_min(output_limit, exact_len(raw) * ratio_limit)
        if coding == "identity":
            if exact_len(raw) > budget:
                raise exact_decode_error("decoded content exceeds limit")
            deadline(check_deadline)
            return raw

        deadline(check_deadline)
        decoder = exact_decompressobj(31 if coding == "gzip" else 15)
        output = exact_bytearray()
        offset = 0
        pending = b""
        # Each nonterminal successful call consumes >=1 encoded byte or emits >=1
        # decoded byte. This explicit bound also prevents any accidental zero-work
        # loop. Calls themselves have <=64KiB input and <=64KiB output.
        for _ in exact_range(exact_len(raw) + budget + 2):
            if pending:
                part = pending
            elif offset < exact_len(raw):
                part = raw[offset:offset + exact_chunk_bytes]
                offset += exact_len(part)
            else:
                # Bounded empty-input drain, never flush(): flush(length) is not a cap.
                part = b""
            cap = exact_min(
                exact_chunk_bytes, budget - exact_len(output) + 1
            )
            deadline(check_deadline)
            invalid = False
            try:
                block = decoder.decompress(part, max_length=cap)
            except exact_zlib_error:
                invalid = True
            deadline(check_deadline)
            if invalid:
                raise exact_decode_error("compressed content is invalid") from None
            if exact_len(output) + exact_len(block) > budget:
                raise exact_decode_error("decoded content exceeds limit")
            output.extend(block)
            pending = decoder.unconsumed_tail
            if decoder.eof:
                if decoder.unused_data or pending or offset != exact_len(raw):
                    raise exact_decode_error("compressed content has trailing data")
                result = exact_bytes(output)
                deadline(check_deadline)
                return result
            if not block and exact_len(pending) == exact_len(part):
                raise exact_decode_error("compressed content is incomplete or stalled")
        raise exact_decode_error("compressed content progress bound exceeded")

    decode_http_content.__name__ = "decode_http_content"
    decode_http_content.__qualname__ = "decode_http_content"
    return decode_http_content


decode_http_content = _build_decoder()
del _build_decoder
