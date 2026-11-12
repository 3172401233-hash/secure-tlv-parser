from __future__ import annotations

import unittest

from tlm_parser import (
    CONTAINER_TYPE,
    ErrorCode,
    FinishStatus,
    FrameParser,
    ParserLimits,
    ParseStatus,
)

from tests.fixtures import (
    drive,
    encode_container,
    encode_frame,
    encode_node,
    nested_chain,
    simple_frame,
)


def _generous_limits(**overrides: int) -> ParserLimits:
    values = {
        "max_frame_body": 1 << 16,
        "max_value_bytes": 1 << 12,
        "max_nodes": 256,
        "max_depth": 32,
        "max_pending_bytes": 1 << 12,
    }
    values.update(overrides)
    return ParserLimits(**values)


class ErrorSemanticsTests(unittest.TestCase):
    def _assert_failed(
        self,
        raw: bytes,
        code: ErrorCode,
        offset: int,
        limits: ParserLimits | None = None,
        consumed: int | None = None,
    ) -> FrameParser:
        parser = FrameParser(limits)
        result = parser.feed(raw)
        self.assertEqual(result.status, ParseStatus.FAILED)
        self.assertIsNone(result.frame)
        self.assertIsNotNone(result.error)
        assert result.error is not None
        self.assertEqual(result.error.code, code)
        self.assertEqual(result.error.offset, offset)
        if consumed is not None:
            self.assertEqual(result.consumed, consumed)
        return parser

    def test_header_field_rejections_have_field_offsets(self) -> None:
        raw = encode_frame(b"")
        cases = (
            (b"BAD!" + raw[4:], ErrorCode.BAD_MAGIC, 0),
            (raw[:4] + b"\x02" + raw[5:], ErrorCode.UNSUPPORTED_VERSION, 4),
            (raw[:5] + b"\x01" + raw[6:], ErrorCode.NONZERO_FLAGS, 5),
            (raw[:6] + b"\x00\x01" + raw[8:], ErrorCode.NONZERO_RESERVED, 6),
        )
        for mutated, code, offset in cases:
            with self.subTest(code=code):
                self._assert_failed(mutated, code, offset, consumed=12)

    def test_terminal_failure_requires_reset(self) -> None:
        raw = b"BAD!" + encode_frame(b"")[4:]
        parser = self._assert_failed(raw, ErrorCode.BAD_MAGIC, 0)
        failed_again = parser.feed(encode_frame(b""))
        self.assertEqual(failed_again.status, ParseStatus.FAILED)
        self.assertEqual(failed_again.consumed, 0)
        self.assertEqual(failed_again.error, parser.finish().error)
        self.assertEqual(parser.finish().status, FinishStatus.FAILED)

        parser.reset()
        ready = parser.feed(encode_frame(b""))
        self.assertEqual(ready.status, ParseStatus.FRAME_READY)
        self.assertEqual(ready.consumed, 12)

    def test_frame_length_over_limit_rejected_from_header_only(self) -> None:
        body = encode_node(0x01, b"1234567890")
        raw = encode_frame(body)
        limits = _generous_limits(max_frame_body=len(body) - 1)
        parser = self._assert_failed(
            raw[:12],
            ErrorCode.FRAME_TOO_LARGE,
            8,
            limits=limits,
            consumed=12,
        )
        self.assertEqual(parser.stats.payload_bytes_copied, 0)

    def test_huge_node_length_rejected_before_value_arrives(self) -> None:
        body = encode_node(0x01, b"x")
        raw = encode_frame(body)
        limits = _generous_limits(max_value_bytes=4)
        parser = FrameParser(limits)
        malformed = raw[:13] + (0xFFFFFFFF).to_bytes(4, "big")
        result = parser.feed(malformed[:17])
        self.assertEqual(result.status, ParseStatus.FAILED)
        self.assertEqual(result.consumed, 17)
        assert result.error is not None
        self.assertEqual(result.error.code, ErrorCode.VALUE_TOO_LARGE)
        self.assertEqual(result.error.offset, 12)
        self.assertEqual(parser.stats.payload_bytes_copied, 0)

    def test_impossible_short_frame_body_rejected_without_body_bytes(self) -> None:
        raw = encode_frame(b"abc")
        self._assert_failed(
            raw[:12],
            ErrorCode.MALFORMED_TLV,
            12,
            limits=_generous_limits(),
            consumed=12,
        )

    def test_node_value_crossing_container_boundary_is_malformed(self) -> None:
        body = b"\x01" + (6).to_bytes(4, "big")
        raw = encode_frame(body)
        self._assert_failed(
            raw,
            ErrorCode.MALFORMED_TLV,
            12,
            limits=_generous_limits(),
            consumed=len(raw),
        )

    def test_container_trailing_bytes_are_malformed(self) -> None:
        child = encode_node(0x01, b"ok")
        bad_container = encode_node(CONTAINER_TYPE, child + b"x")
        raw = encode_frame(bad_container)
        self._assert_failed(
            raw,
            ErrorCode.MALFORMED_TLV,
            12 + 5 + len(child),
            limits=_generous_limits(),
        )

    def test_nonempty_container_too_short_for_child_header_is_malformed(self) -> None:
        for length in (1, 2, 3, 4):
            with self.subTest(length=length):
                payload = b"x" * length
                raw = encode_frame(encode_node(CONTAINER_TYPE, payload))
                self._assert_failed(
                    raw,
                    ErrorCode.MALFORMED_TLV,
                    12,
                    limits=_generous_limits(),
                )

    def test_truncated_header_and_body_are_distinguished(self) -> None:
        raw = simple_frame(encode_node(0x01, b"abcdef"))

        header_parser = FrameParser()
        result = header_parser.feed(raw[:7])
        self.assertEqual(result.status, ParseStatus.NEED_MORE)
        self.assertEqual(result.consumed, 7)
        finish = header_parser.finish()
        self.assertEqual(finish.status, FinishStatus.FAILED)
        assert finish.error is not None
        self.assertEqual(finish.error.code, ErrorCode.TRUNCATED_HEADER)
        self.assertEqual(finish.error.offset, 7)

        body_parser = FrameParser()
        result = body_parser.feed(raw[:12])
        self.assertEqual(result.status, ParseStatus.NEED_MORE)
        finish = body_parser.finish()
        assert finish.error is not None
        self.assertEqual(finish.error.code, ErrorCode.TRUNCATED_BODY)
        self.assertEqual(finish.error.offset, 12)

        body_parser.reset()
        result = body_parser.feed(raw[:13])
        self.assertEqual(result.status, ParseStatus.NEED_MORE)
        finish = body_parser.finish()
        assert finish.error is not None
        self.assertEqual(finish.error.code, ErrorCode.TRUNCATED_BODY)
        self.assertEqual(finish.error.offset, 13)

    def test_clean_boundary_is_not_reported_as_truncation(self) -> None:
        parser = FrameParser()
        raw = encode_frame(b"")
        result = parser.feed(raw)
        self.assertEqual(result.status, ParseStatus.FRAME_READY)
        self.assertEqual(parser.finish().status, FinishStatus.CLEAN_END)

        parser2 = FrameParser()
        self.assertEqual(parser2.feed(b"").status, ParseStatus.NEED_MORE)
        self.assertEqual(parser2.finish().status, FinishStatus.CLEAN_END)

    def test_reset_clears_partial_state_and_offsets(self) -> None:
        raw = encode_frame(encode_node(0x01, b"reuse"))
        parser = FrameParser()
        first = parser.feed(raw[:5])
        self.assertEqual(first.status, ParseStatus.NEED_MORE)
        self.assertEqual(parser.stats.bytes_consumed, 5)

        parser.reset()
        self.assertEqual(
            parser.stats,
            parser.stats.__class__(
                bytes_consumed=0,
                frame_headers_decoded=0,
                node_headers_decoded=0,
                payload_bytes_copied=0,
                staging_appends=0,
                staging_bytes_high_water=0,
                max_container_stack_depth=0,
            ),
        )
        result = parser.feed(raw)
        self.assertEqual(result.status, ParseStatus.FRAME_READY)
        self.assertEqual(result.consumed, len(raw))
        self.assertEqual(parser.finish().status, FinishStatus.CLEAN_END)


class LimitBoundaryTests(unittest.TestCase):
    def _parse(self, raw: bytes, limits: ParserLimits):
        return drive(FrameParser(limits), [raw])

    def test_frame_body_limit_below_exact_and_over(self) -> None:
        body = encode_node(0x11, b"12345")
        raw = encode_frame(body)

        at_limit = self._parse(raw, _generous_limits(max_frame_body=len(body)))
        self.assertIsNone(at_limit.error)
        self.assertEqual(len(at_limit.frames), 1)

        below = self._parse(raw, _generous_limits(max_frame_body=len(body) + 1))
        self.assertIsNone(below.error)

        over = self._parse(raw, _generous_limits(max_frame_body=len(body) - 1))
        self.assertIsNotNone(over.error)
        assert over.error is not None
        self.assertEqual(over.error.code, ErrorCode.FRAME_TOO_LARGE)

    def test_opaque_value_limit_below_exact_and_over(self) -> None:
        value = b"abcd"
        raw = encode_frame(encode_node(0x22, value))

        at_limit = self._parse(
            raw,
            _generous_limits(max_value_bytes=len(value), max_pending_bytes=len(value)),
        )
        self.assertIsNone(at_limit.error)

        below = self._parse(
            raw,
            _generous_limits(
                max_value_bytes=len(value) + 1,
                max_pending_bytes=len(value) + 1,
            ),
        )
        self.assertIsNone(below.error)

        over = self._parse(
            raw,
            _generous_limits(
                max_value_bytes=len(value) - 1,
                max_pending_bytes=len(value) + 1,
            ),
        )
        self.assertIsNotNone(over.error)
        assert over.error is not None
        self.assertEqual(over.error.code, ErrorCode.VALUE_TOO_LARGE)
        self.assertEqual(over.error.offset, 12)

    def test_container_value_uses_max_value_limit(self) -> None:
        child = encode_node(0x01, b"ab")
        raw = encode_frame(encode_node(CONTAINER_TYPE, child))
        limits = _generous_limits(
            max_value_bytes=len(child) - 1,
            max_pending_bytes=len(child) + 1,
        )
        result = self._parse(raw, limits)
        self.assertIsNotNone(result.error)
        assert result.error is not None
        self.assertEqual(result.error.code, ErrorCode.VALUE_TOO_LARGE)

    def test_pending_staging_limit_below_exact_and_over(self) -> None:
        value = b"abcd"
        raw = encode_frame(encode_node(0x33, value))

        at_limit = self._parse(
            raw,
            _generous_limits(max_value_bytes=len(value), max_pending_bytes=len(value)),
        )
        self.assertIsNone(at_limit.error)

        below = self._parse(
            raw,
            _generous_limits(
                max_value_bytes=len(value) + 1,
                max_pending_bytes=len(value) + 1,
            ),
        )
        self.assertIsNone(below.error)

        over = self._parse(
            raw,
            _generous_limits(
                max_value_bytes=len(value) + 1,
                max_pending_bytes=len(value) - 1,
            ),
        )
        self.assertIsNotNone(over.error)
        assert over.error is not None
        self.assertEqual(over.error.code, ErrorCode.STAGING_LIMIT)
        self.assertEqual(over.error.offset, 12)

        zero_limit = self._parse(
            encode_frame(encode_node(0x33, b"")),
            _generous_limits(max_pending_bytes=0),
        )
        self.assertIsNone(zero_limit.error)

    def test_pending_limit_does_not_buffer_container_bodies(self) -> None:
        child = encode_node(0x01, b"")
        raw = encode_frame(encode_node(CONTAINER_TYPE, child))
        limits = _generous_limits(
            max_value_bytes=1 << 10,
            max_pending_bytes=0,
        )
        result = self._parse(raw, limits)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.frames), 1)

    def test_node_count_limit_below_exact_and_over(self) -> None:
        nodes = [encode_node(0x40 + index, b"") for index in range(3)]
        raw = encode_frame(b"".join(nodes))

        at_limit = self._parse(raw, _generous_limits(max_nodes=3))
        self.assertIsNone(at_limit.error)
        self.assertEqual(len(at_limit.frames[0].nodes), 3)

        below = self._parse(raw, _generous_limits(max_nodes=4))
        self.assertIsNone(below.error)

        over = self._parse(raw, _generous_limits(max_nodes=2))
        self.assertIsNotNone(over.error)
        assert over.error is not None
        self.assertEqual(over.error.code, ErrorCode.TOO_MANY_NODES)
        self.assertEqual(over.error.offset, 12 + 10)

        empty_frame = self._parse(encode_frame(b""), _generous_limits(max_nodes=0))
        self.assertIsNone(empty_frame.error)

    def test_empty_containers_count_as_nodes(self) -> None:
        raw = encode_frame(
            b"".join(encode_container([]) for _ in range(3))
        )
        result = self._parse(raw, _generous_limits(max_nodes=2))
        self.assertIsNotNone(result.error)
        assert result.error is not None
        self.assertEqual(result.error.code, ErrorCode.TOO_MANY_NODES)

    def test_depth_limit_below_exact_and_over(self) -> None:
        depth = 4
        raw = nested_chain(depth)
        needed_value_bytes = 5 * (depth - 1)

        at_limit = self._parse(
            raw,
            _generous_limits(
                max_depth=depth,
                max_nodes=depth,
                max_value_bytes=needed_value_bytes,
            ),
        )
        self.assertIsNone(at_limit.error)

        below = self._parse(
            raw,
            _generous_limits(
                max_depth=depth + 1,
                max_nodes=depth,
                max_value_bytes=needed_value_bytes,
            ),
        )
        self.assertIsNone(below.error)

        over = self._parse(
            raw,
            _generous_limits(
                max_depth=depth - 1,
                max_nodes=depth,
                max_value_bytes=needed_value_bytes,
            ),
        )
        self.assertIsNotNone(over.error)
        assert over.error is not None
        self.assertEqual(over.error.code, ErrorCode.DEPTH_EXCEEDED)

    def test_empty_container_counts_toward_depth(self) -> None:
        raw = nested_chain(3)
        result = self._parse(
            raw,
            _generous_limits(
                max_depth=2,
                max_nodes=3,
                max_value_bytes=10,
            ),
        )
        self.assertIsNotNone(result.error)
        assert result.error is not None
        self.assertEqual(result.error.code, ErrorCode.DEPTH_EXCEEDED)

    def test_nonempty_container_at_depth_limit_rejected_immediately(self) -> None:
        child = encode_node(0x01, b"x")
        raw = encode_frame(encode_node(CONTAINER_TYPE, child))
        parser = FrameParser(_generous_limits(max_depth=1))
        result = parser.feed(raw[:17])
        self.assertEqual(result.status, ParseStatus.FAILED)
        self.assertEqual(result.consumed, 17)
        assert result.error is not None
        self.assertEqual(result.error.code, ErrorCode.DEPTH_EXCEEDED)
        self.assertEqual(result.error.offset, 12)

    def test_invalid_limit_values_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ParserLimits(max_depth=-1)
        with self.assertRaises(TypeError):
            ParserLimits(max_nodes=True)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            FrameParser(limits="bad")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
