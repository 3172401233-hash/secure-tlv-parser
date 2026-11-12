from __future__ import annotations

import random
import sys
import unittest
from array import array

from tlm_parser import (
    CONTAINER_TYPE,
    ErrorCode,
    FinishStatus,
    FrameParser,
    ParsedFrame,
    ParserLimits,
    ParseStatus,
    TlvNode,
)

from tests.fixtures import (
    drive,
    encode_container,
    encode_frame,
    encode_node,
    make_chunks,
    nested_chain,
    simple_frame,
)


def _nested_example() -> tuple[bytes, ParsedFrame]:
    body = (
        encode_container(
            [
                encode_node(0x01, b"alpha"),
                encode_container(
                    [
                        encode_node(0x02, b"beta"),
                        encode_container([]),
                    ]
                ),
                encode_node(0x00, b""),
            ]
        )
        + encode_node(0x20, b"tail")
    )
    nodes = (
        TlvNode(
            node_type=CONTAINER_TYPE,
            is_container=True,
            value=(
                TlvNode(node_type=0x01, is_container=False, value=b"alpha"),
                TlvNode(
                    node_type=CONTAINER_TYPE,
                    is_container=True,
                    value=(
                        TlvNode(node_type=0x02, is_container=False, value=b"beta"),
                        TlvNode(
                            node_type=CONTAINER_TYPE,
                            is_container=True,
                            value=(),
                        ),
                    ),
                ),
                TlvNode(node_type=0x00, is_container=False, value=b""),
            ),
        ),
        TlvNode(node_type=0x20, is_container=False, value=b"tail"),
    )
    return encode_frame(body), ParsedFrame(body_length=len(body), nodes=nodes)


class ProtocolTests(unittest.TestCase):
    def test_empty_body_and_clean_end(self) -> None:
        raw = encode_frame(b"")
        parser = FrameParser()
        result = parser.feed(raw)
        self.assertEqual(result.status, ParseStatus.FRAME_READY)
        self.assertEqual(result.consumed, 12)
        self.assertEqual(result.frame, ParsedFrame(body_length=0, nodes=()))
        self.assertEqual(parser.finish().status, FinishStatus.CLEAN_END)
        self.assertEqual(parser.feed(b"").status, ParseStatus.NEED_MORE)

    def test_normal_nesting_empty_container_and_empty_opaque(self) -> None:
        raw, expected = _nested_example()
        result = drive(FrameParser(), [raw])
        self.assertIsNone(result.error)
        self.assertEqual(result.frames, (expected,))
        self.assertEqual(result.finish_status, FinishStatus.CLEAN_END)

    def test_multi_frame_input_delivers_one_frame_per_call(self) -> None:
        raw1, expected1 = _nested_example()
        raw2 = encode_frame(encode_node(0x30, b"second"))
        raw3 = encode_frame(b"")
        combined = raw1 + raw2 + raw3
        parser = FrameParser()

        first = parser.feed(combined)
        self.assertEqual(first.status, ParseStatus.FRAME_READY)
        self.assertEqual(first.consumed, len(raw1))
        self.assertEqual(first.frame, expected1)

        second = parser.feed(combined[first.consumed :])
        self.assertEqual(second.status, ParseStatus.FRAME_READY)
        self.assertEqual(second.consumed, len(raw2))
        self.assertEqual(
            second.frame,
            ParsedFrame(
                body_length=11,
                nodes=(TlvNode(node_type=0x30, is_container=False, value=b"second"),),
            ),
        )

        third = parser.feed(combined[first.consumed + second.consumed :])
        self.assertEqual(third.status, ParseStatus.FRAME_READY)
        self.assertEqual(third.consumed, len(raw3))
        self.assertEqual(third.frame, ParsedFrame(body_length=0, nodes=()))
        self.assertEqual(parser.feed(b"").status, ParseStatus.NEED_MORE)
        self.assertEqual(parser.finish().status, FinishStatus.CLEAN_END)

    def test_byte_by_byte_and_random_fragmentation(self) -> None:
        raw, expected = _nested_example()
        expected_frames = (expected,)
        observed: list[tuple[ParsedFrame, ...]] = []

        for mode in ("bytes", "random"):
            rng = random.Random(93)
            chunks = make_chunks(raw, mode, rng)
            result = drive(FrameParser(), chunks)
            self.assertIsNone(result.error)
            self.assertEqual(result.frames, expected_frames)
            self.assertEqual(result.finish_status, FinishStatus.CLEAN_END)
            observed.append(result.frames)

        self.assertEqual(observed[0], observed[1])

    def test_empty_feeds_are_harmless_between_fragments(self) -> None:
        raw = simple_frame(encode_node(0x7A, b"payload"))
        chunks = [b"", raw[:4], b"", raw[4:12], b"", raw[12:], b""]
        parser = FrameParser()
        result = drive(parser, chunks)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.frames), 1)
        self.assertEqual(
            result.frames[0],
            ParsedFrame(
                body_length=12,
                nodes=(TlvNode(node_type=0x7A, is_container=False, value=b"payload"),),
            ),
        )

    def test_fragment_containing_two_frames_returns_remainder_for_repass(self) -> None:
        raw1 = simple_frame(encode_node(0x01, b"one"))
        raw2 = simple_frame(encode_node(0x02, b"two"))
        result = drive(FrameParser(), [raw1 + raw2])
        self.assertIsNone(result.error)
        self.assertEqual(len(result.frames), 2)
        self.assertEqual(result.frames[0].nodes[0].value, b"one")
        self.assertEqual(result.frames[1].nodes[0].value, b"two")

    def test_accepts_all_documented_input_types(self) -> None:
        raw = simple_frame(encode_node(0x44, b"types"))
        expected = ParsedFrame(
            body_length=10,
            nodes=(TlvNode(node_type=0x44, is_container=False, value=b"types"),),
        )

        for data in (
            raw,
            bytearray(raw),
            memoryview(raw),
            memoryview(bytearray(raw)),
            memoryview(array("B", raw)),
            memoryview(array("b", raw)),
        ):
            with self.subTest(type=type(data), format=getattr(data, "format", None)):
                parser = FrameParser()
                result = parser.feed(data)
                self.assertEqual(result.status, ParseStatus.FRAME_READY)
                self.assertEqual(result.frame, expected)
                self.assertEqual(parser.finish().status, FinishStatus.CLEAN_END)

    def test_rejects_non_byte_or_non_contiguous_memoryviews(self) -> None:
        raw = simple_frame(encode_node(0x01, b"x"))

        with self.assertRaises(ValueError):
            FrameParser().feed(memoryview(bytearray(raw * 2))[::2])
        with self.assertRaises(ValueError):
            FrameParser().feed(memoryview(bytearray(16)).cast("B", shape=(2, 8)))
        with self.assertRaises(TypeError):
            FrameParser().feed(memoryview(bytearray(16)).cast("I"))
        with self.assertRaises(TypeError):
            FrameParser().feed("not bytes")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            FrameParser().feed(None)  # type: ignore[arg-type]

    def test_mutable_input_is_copied_and_never_retained(self) -> None:
        payload = b"abcdefghijklmnopqrstuvwxyz"
        raw = simple_frame(encode_node(0x31, payload))
        expected = ParsedFrame(
            body_length=5 + len(payload),
            nodes=(TlvNode(node_type=0x31, is_container=False, value=payload),),
        )

        mutable_prefix = bytearray(raw[:18])
        view = memoryview(mutable_prefix)
        parser = FrameParser()
        first = parser.feed(view)
        self.assertEqual(first.status, ParseStatus.NEED_MORE)
        self.assertEqual(first.consumed, 18)

        mutable_prefix[:] = b"\xFF" * len(mutable_prefix)
        second = parser.feed(raw[18:])
        self.assertEqual(second.status, ParseStatus.FRAME_READY)
        self.assertEqual(second.frame, expected)

        full_buffer = bytearray(raw)
        parser2 = FrameParser()
        ready = parser2.feed(full_buffer)
        self.assertEqual(ready.status, ParseStatus.FRAME_READY)
        full_buffer[:] = b"Z" * len(full_buffer)
        self.assertEqual(ready.frame, expected)
        self.assertEqual(parser2.finish().status, FinishStatus.CLEAN_END)

    def test_delivered_result_survives_reset_and_input_reuse(self) -> None:
        payload = b"stable"
        raw = simple_frame(encode_node(0x05, payload))
        buffer = bytearray(raw)
        parser = FrameParser()
        result = parser.feed(buffer)
        delivered = result.frame
        parser.reset()
        buffer[:] = simple_frame(encode_node(0x06, b"other"))
        self.assertEqual(
            delivered,
            ParsedFrame(
                body_length=11,
                nodes=(TlvNode(node_type=0x05, is_container=False, value=payload),),
            ),
        )

    def test_deep_nesting_uses_explicit_stack(self) -> None:
        depth = 300
        raw = nested_chain(depth)
        limits = ParserLimits(
            max_frame_body=4096,
            max_value_bytes=2048,
            max_nodes=400,
            max_depth=depth,
            max_pending_bytes=2048,
        )
        old_limit = sys.getrecursionlimit()
        try:
            sys.setrecursionlimit(80)
            parser = FrameParser(limits)
            result = parser.feed(raw)
            self.assertEqual(result.status, ParseStatus.FRAME_READY)
            self.assertIsNotNone(result.frame)
        finally:
            sys.setrecursionlimit(old_limit)

        node = result.frame.nodes[0]
        for level in range(depth - 1):
            self.assertTrue(node.is_container)
            self.assertEqual(len(node.value), 1)
            node = node.value[0]
            self.assertEqual(node.node_type, CONTAINER_TYPE, level)
        self.assertTrue(node.is_container)
        self.assertEqual(node.value, ())
        self.assertEqual(parser.stats.max_container_stack_depth, depth - 1)

    def test_work_counters_are_linear_and_fragmentation_invariant(self) -> None:
        payloads = [bytes([0x41 + (index % 26)]) * 31 for index in range(24)]
        body = b"".join(encode_node(0x80 + index, value) for index, value in enumerate(payloads))
        raw = encode_frame(body)
        expected_payload = sum(len(value) for value in payloads)
        expected_nodes = len(payloads)
        stats_by_mode = []

        for mode in ("whole", "random", "bytes"):
            rng = random.Random(701)
            parser = FrameParser(
                ParserLimits(
                    max_frame_body=4096,
                    max_value_bytes=64,
                    max_nodes=64,
                    max_depth=8,
                    max_pending_bytes=64,
                )
            )
            result = drive(parser, make_chunks(raw, mode, rng))
            self.assertIsNone(result.error)
            stats = parser.stats
            self.assertEqual(stats.bytes_consumed, len(raw))
            self.assertEqual(stats.frame_headers_decoded, 1)
            self.assertEqual(stats.node_headers_decoded, expected_nodes)
            self.assertEqual(stats.payload_bytes_copied, expected_payload)
            self.assertLessEqual(stats.payload_bytes_copied, stats.bytes_consumed)
            if mode == "bytes":
                self.assertEqual(stats.staging_bytes_high_water, 31)
            stats_by_mode.append(
                (
                    stats.bytes_consumed,
                    stats.frame_headers_decoded,
                    stats.node_headers_decoded,
                    stats.payload_bytes_copied,
                )
            )

        self.assertEqual(len(set(stats_by_mode)), 1)

    def test_failure_error_category_and_offset_are_fragmentation_invariant(self) -> None:
        raw = encode_frame(encode_node(0x10, encode_node(0x01, b"ok")))
        malformed = raw[:13] + (10).to_bytes(4, "big") + raw[17:]
        observations = []

        for mode in ("whole", "random", "bytes"):
            rng = random.Random(55)
            result = drive(
                FrameParser(
                    ParserLimits(
                        max_frame_body=1024,
                        max_value_bytes=1024,
                        max_nodes=32,
                        max_depth=8,
                        max_pending_bytes=1024,
                    )
                ),
                make_chunks(malformed, mode, rng),
            )
            self.assertIsNotNone(result.error)
            self.assertEqual(result.error.code, ErrorCode.MALFORMED_TLV)
            observations.append((result.error.code, result.error.offset))

        self.assertEqual(len(set(observations)), 1)


if __name__ == "__main__":
    unittest.main()
