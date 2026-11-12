"""Independent TLM1 encoders, generators, and test drivers."""

from __future__ import annotations

import random
from dataclasses import dataclass

from tlm_parser import (
    CONTAINER_TYPE,
    ParsedFrame,
    ParserError,
    ParserLimits,
    ParseStatus,
    TlvNode,
    FinishStatus,
    FrameParser,
)


def encode_node(node_type: int, value: bytes) -> bytes:
    return bytes((node_type,)) + len(value).to_bytes(4, "big") + value


def encode_container(child_nodes: list[bytes]) -> bytes:
    return encode_node(CONTAINER_TYPE, b"".join(child_nodes))


def encode_frame(body: bytes) -> bytes:
    return (
        b"TLM1"
        + b"\x01\x00\x00\x00"
        + len(body).to_bytes(4, "big")
        + body
    )


def simple_frame(*nodes: bytes) -> bytes:
    return encode_frame(b"".join(nodes))


def nested_chain(depth: int) -> bytes:
    """Build a depth-``depth`` chain whose deepest container is empty."""

    raw = encode_node(CONTAINER_TYPE, b"")
    for _ in range(depth - 1):
        raw = encode_node(CONTAINER_TYPE, raw)
    return encode_frame(raw)


@dataclass(frozen=True, slots=True)
class DriveResult:
    frames: tuple[ParsedFrame, ...]
    feed_error: ParserError | None
    finish_error: ParserError | None
    finish_status: FinishStatus
    feed_calls: int

    @property
    def error(self) -> ParserError | None:
        return self.feed_error or self.finish_error


def drive(parser: FrameParser, chunks: list[bytes]) -> DriveResult:
    """Feed chunks while re-passing unconsumed bytes, then check end input."""

    frames: list[ParsedFrame] = []
    feed_error: ParserError | None = None
    calls = 0

    for chunk in chunks:
        left = chunk
        while True:
            result = parser.feed(left)
            calls += 1
            if not 0 <= result.consumed <= len(left):
                raise AssertionError("parser returned an invalid consumed count")

            if result.status == ParseStatus.FRAME_READY:
                if result.frame is None or result.error is not None:
                    raise AssertionError("FRAME_READY must contain only a frame")
                if result.consumed == 0:
                    raise AssertionError("FRAME_READY must consume at least one byte")
                frames.append(result.frame)
                left = left[result.consumed :]
                if not left:
                    break
                continue

            if result.status == ParseStatus.NEED_MORE:
                if result.frame is not None or result.error is not None:
                    raise AssertionError("NEED_MORE must not contain a result payload")
                if result.consumed != len(left):
                    raise AssertionError(
                        "NEED_MORE must consume all supplied bytes; re-passing "
                        "unconsumed bytes as well would cause repeated work"
                    )
                break

            if result.status == ParseStatus.FAILED:
                if result.error is None or result.frame is not None:
                    raise AssertionError("FAILED must contain an error and no frame")
                feed_error = result.error
                break

            raise AssertionError(f"unknown parse status {result.status!r}")

        if feed_error is not None:
            break

    finish = parser.finish()
    finish_error = finish.error
    if finish.status == FinishStatus.CLEAN_END and finish_error is not None:
        raise AssertionError("CLEAN_END must not contain an error")
    if finish.status == FinishStatus.FAILED and finish_error is None:
        raise AssertionError("finish FAILED must contain an error")

    return DriveResult(
        frames=tuple(frames),
        feed_error=feed_error,
        finish_error=finish_error,
        finish_status=finish.status,
        feed_calls=calls,
    )


def make_chunks(raw: bytes, mode: str, rng: random.Random | None = None) -> list[bytes]:
    if mode == "whole":
        return [raw]
    if mode == "bytes":
        return [raw[index : index + 1] for index in range(len(raw))] or [b""]
    if mode == "random":
        if rng is None:
            raise ValueError("random fragmentation requires an rng")
        chunks: list[bytes] = []
        index = 0
        while index < len(raw):
            take = rng.randint(1, 7)
            chunks.append(raw[index : index + take])
            index += take
            if rng.random() < 0.25:
                chunks.append(b"")
        if not chunks:
            chunks.append(b"")
        return chunks
    raise ValueError(f"unknown fragmentation mode {mode!r}")


@dataclass(frozen=True, slots=True)
class FuzzCase:
    label: str
    raw: bytes
    expected_frames: tuple[ParsedFrame, ...] | None
    expect_reject: bool
    limits: ParserLimits


@dataclass(slots=True)
class _Budget:
    nodes: int


def _generate_nodes(
    rng: random.Random,
    budget: _Budget,
    depth: int,
    max_depth: int,
) -> tuple[list[bytes], tuple[TlvNode, ...]]:
    count = rng.randint(1, 4)
    raw_nodes: list[bytes] = []
    expected_nodes: list[TlvNode] = []

    for _ in range(count):
        if budget.nodes <= 0:
            break
        budget.nodes -= 1

        make_container = (
            depth < max_depth
            and budget.nodes > 1
            and rng.random() < 0.36
        )
        if make_container:
            child_count = rng.randint(0, 3)
            if child_count > budget.nodes:
                child_count = budget.nodes
            child_raw: list[bytes] = []
            child_expected: list[TlvNode] = []
            for _ in range(child_count):
                children_raw, children_nodes = _generate_nodes(
                    rng, budget, depth + 1, max_depth
                )
                child_raw.extend(children_raw)
                child_expected.extend(children_nodes)
            child_body = b"".join(child_raw)
            raw_nodes.append(encode_node(CONTAINER_TYPE, child_body))
            expected_nodes.append(
                TlvNode(
                    node_type=CONTAINER_TYPE,
                    is_container=True,
                    value=tuple(child_expected),
                )
            )
            continue

        node_type = rng.randrange(0x100)
        if node_type == CONTAINER_TYPE:
            node_type = 0x11
        value_length = rng.choice((0, 0, 1, 1, 2, 3, 5, 9, 17, 33))
        value = bytes(rng.randrange(0x100) for _ in range(value_length))
        raw_nodes.append(encode_node(node_type, value))
        expected_nodes.append(
            TlvNode(node_type=node_type, is_container=False, value=value)
        )

    return raw_nodes, tuple(expected_nodes)


def _default_fuzz_limits() -> ParserLimits:
    return ParserLimits(
        max_frame_body=1 << 16,
        max_value_bytes=1 << 11,
        max_nodes=256,
        max_depth=24,
        max_pending_bytes=1 << 11,
    )


def generate_valid_case(rng: random.Random, limits: ParserLimits) -> FuzzCase:
    budget = _Budget(nodes=rng.randint(1, 28))
    raw_frames: list[bytes] = []
    expected_frames: list[ParsedFrame] = []
    frame_count = rng.randint(1, 4)

    for _ in range(frame_count):
        if rng.random() < 0.12:
            body = b""
            expected_nodes: tuple[TlvNode, ...] = ()
        else:
            raw_nodes, expected_nodes = _generate_nodes(
                rng, budget, depth=1, max_depth=7
            )
            body = b"".join(raw_nodes)
        raw_frames.append(encode_frame(body))
        expected_frames.append(
            ParsedFrame(body_length=len(body), nodes=expected_nodes)
        )

    return FuzzCase(
        label="valid-structured",
        raw=b"".join(raw_frames),
        expected_frames=tuple(expected_frames),
        expect_reject=False,
        limits=limits,
    )


def _single_valid_frame(rng: random.Random, limits: ParserLimits) -> tuple[bytes, ParsedFrame]:
    budget = _Budget(nodes=rng.randint(3, 16))
    raw_nodes, expected_nodes = _generate_nodes(rng, budget, 1, 6)
    while not raw_nodes:
        budget.nodes = 3
        raw_nodes, expected_nodes = _generate_nodes(rng, budget, 1, 6)
    body = b"".join(raw_nodes)
    return encode_frame(body), ParsedFrame(body_length=len(body), nodes=expected_nodes)


def generate_mutations(
    rng: random.Random, count: int, limits: ParserLimits
) -> list[FuzzCase]:
    cases: list[FuzzCase] = []

    while len(cases) < count:
        raw, expected = _single_valid_frame(rng, limits)
        mutation_kind = len(cases) % 8

        if mutation_kind == 0:
            cut = rng.randint(1, len(raw) - 1)
            cases.append(
                FuzzCase(
                    label=f"truncate@{cut}",
                    raw=raw[:cut],
                    expected_frames=None,
                    expect_reject=True,
                    limits=limits,
                )
            )
        elif mutation_kind == 1:
            field_offset, replacement = rng.choice(
                (
                    (0, b"BAD!"),
                    (4, b"\x02"),
                    (5, b"\x01"),
                    (7, b"\x01"),
                )
            )
            width = len(replacement)
            mutated = raw[:field_offset] + replacement + raw[field_offset + width :]
            cases.append(
                FuzzCase(
                    label="bad-frame-field",
                    raw=mutated,
                    expected_frames=None,
                    expect_reject=True,
                    limits=limits,
                )
            )
        elif mutation_kind == 2:
            declared = limits.max_frame_body + rng.randint(1, 4096)
            mutated = raw[:8] + declared.to_bytes(4, "big") + raw[12:]
            cases.append(
                FuzzCase(
                    label="oversized-frame-length",
                    raw=mutated,
                    expected_frames=None,
                    expect_reject=True,
                    limits=limits,
                )
            )
        elif mutation_kind == 3:
            body_length = int.from_bytes(raw[8:12], "big")
            mutated = raw[:8] + (body_length + 1).to_bytes(4, "big") + raw[12:]
            cases.append(
                FuzzCase(
                    label="frame-length-plus-one",
                    raw=mutated,
                    expected_frames=None,
                    expect_reject=True,
                    limits=limits,
                )
            )
        elif mutation_kind == 4:
            if len(raw) <= 17:
                continue
            huge = rng.choice((0xFFFFFFFF, limits.max_value_bytes + 1))
            mutated = raw[:13] + huge.to_bytes(4, "big") + raw[17:]
            cases.append(
                FuzzCase(
                    label="huge-node-length",
                    raw=mutated,
                    expected_frames=None,
                    expect_reject=True,
                    limits=limits,
                )
            )
        elif mutation_kind == 5:
            body = encode_node(rng.choice((1, 2)), b"x")
            trailing = bytes(rng.randrange(0x100) for _ in range(rng.randint(1, 4)))
            bad_container = encode_node(
                CONTAINER_TYPE, body + trailing
            )
            cases.append(
                FuzzCase(
                    label="container-trailing-bytes",
                    raw=encode_frame(bad_container),
                    expected_frames=None,
                    expect_reject=True,
                    limits=limits,
                )
            )
        elif mutation_kind == 6:
            short_length = rng.randint(1, 4)
            payload = bytes(rng.randrange(0x100) for _ in range(short_length))
            cases.append(
                FuzzCase(
                    label="container-value-too-short",
                    raw=encode_frame(encode_node(CONTAINER_TYPE, payload)),
                    expected_frames=None,
                    expect_reject=True,
                    limits=limits,
                )
            )
        else:
            value = bytes(rng.randrange(0x100) for _ in range(rng.randint(0, 8)))
            old_type = rng.choice((0x00, 0x01, 0x20, 0x7F, 0xFF))
            new_type = rng.choice(
                tuple(t for t in (0x00, 0x01, 0x20, 0x7F, 0xFF) if t != old_type)
            )
            body = encode_node(old_type, value)
            mutated = encode_frame(encode_node(new_type, value))
            expected_new = ParsedFrame(
                body_length=len(body),
                nodes=(
                    TlvNode(node_type=new_type, is_container=False, value=value),
                ),
            )
            cases.append(
                FuzzCase(
                    label="valid-type-change",
                    raw=mutated,
                    expected_frames=(expected_new,),
                    expect_reject=False,
                    limits=limits,
                )
            )

    return cases
