"""Public data model and status types for the TLM1 parser."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias


MAGIC = b"TLM1"
FRAME_HEADER_SIZE = 12
NODE_HEADER_SIZE = 5
CONTAINER_TYPE = 0x10


class ParseStatus(StrEnum):
    """Result of :meth:`tlm_parser.FrameParser.feed`.

    ``NEED_MORE`` means every supplied byte was consumed and another call is
    required. ``FRAME_READY`` means one validated frame is available.
    ``FAILED`` is terminal until :meth:`reset` is called.
    """

    NEED_MORE = "need_more"
    FRAME_READY = "frame_ready"
    FAILED = "failed"


class FinishStatus(StrEnum):
    """Result of :meth:`tlm_parser.FrameParser.finish`.

    ``CLEAN_END`` is returned only at a frame boundary. ``FAILED`` means the
    pending input was truncated or the parser was already failed.
    """

    CLEAN_END = "clean_end"
    FAILED = "failed"


class ErrorCode(StrEnum):
    """Stable protocol-rejection categories."""

    BAD_MAGIC = "bad_magic"
    UNSUPPORTED_VERSION = "unsupported_version"
    NONZERO_FLAGS = "nonzero_flags"
    NONZERO_RESERVED = "nonzero_reserved"
    FRAME_TOO_LARGE = "frame_too_large"
    VALUE_TOO_LARGE = "value_too_large"
    STAGING_LIMIT = "staging_limit"
    TOO_MANY_NODES = "too_many_nodes"
    DEPTH_EXCEEDED = "depth_exceeded"
    MALFORMED_TLV = "malformed_tlv"
    TRUNCATED_HEADER = "truncated_header"
    TRUNCATED_BODY = "truncated_body"


@dataclass(frozen=True, slots=True)
class ParserError:
    """A protocol rejection.

    ``offset`` is a zero-based absolute byte offset in the logical stream since
    the last reset. It is independent of how the input was fragmented.
    """

    code: ErrorCode
    offset: int
    message: str


TlvValue: TypeAlias = bytes | tuple["TlvNode", ...]


@dataclass(frozen=True, slots=True)
class TlvNode:
    """A fully parsed TLV node.

    Opaque nodes contain an independent ``bytes`` value. Container nodes
    contain a tuple of child nodes. ``node_type`` is always preserved.
    """

    node_type: int
    is_container: bool
    value: TlvValue

    def __post_init__(self) -> None:
        if not 0 <= self.node_type <= 0xFF:
            raise ValueError("node_type must fit in one byte")
        if self.is_container != (self.node_type == CONTAINER_TYPE):
            raise ValueError("is_container must match node_type 0x10")
        if self.is_container:
            if not isinstance(self.value, tuple):
                raise ValueError("container value must be a tuple of nodes")
            if any(not isinstance(child, TlvNode) for child in self.value):
                raise ValueError("container children must be TlvNode instances")
        elif not isinstance(self.value, bytes):
            raise ValueError("opaque value must be bytes")


@dataclass(frozen=True, slots=True)
class ParsedFrame:
    """One completely validated frame."""

    body_length: int
    nodes: tuple[TlvNode, ...]


@dataclass(frozen=True, slots=True)
class FeedResult:
    """Result of one incremental feed call.

    The caller must continue with ``data[result.consumed:]`` when it is
    non-empty. At most one frame is returned per call.
    """

    status: ParseStatus
    consumed: int
    frame: ParsedFrame | None = None
    error: ParserError | None = None


@dataclass(frozen=True, slots=True)
class FinishResult:
    """Result of the explicit end-of-input check."""

    status: FinishStatus
    error: ParserError | None = None


@dataclass(frozen=True, slots=True)
class ParserLimits:
    """Resource limits checked against protocol/decoded-data quantities.

    ``max_frame_body`` and ``max_value_bytes`` are protocol byte limits.
    ``max_nodes`` and ``max_depth`` bound result objects and structure.
    ``max_pending_bytes`` is checked as soon as an opaque node header is read;
    it bounds staging for one incomplete opaque value. Container bodies are
    parsed streaming and are not staged as one buffer. These are logical caps,
    not a precise bound on process RSS or Python interpreter overhead.
    """

    max_frame_body: int = 1 << 20
    max_value_bytes: int = 1 << 18
    max_nodes: int = 4096
    max_depth: int = 32
    max_pending_bytes: int = 1 << 18

    def __post_init__(self) -> None:
        for name in (
            "max_frame_body",
            "max_value_bytes",
            "max_nodes",
            "max_depth",
            "max_pending_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if value < 0:
                raise ValueError(f"{name} must be non-negative")


@dataclass(frozen=True, slots=True)
class ParserStats:
    """Deterministic work counters accumulated since the last reset.

    ``payload_bytes_copied`` counts opaque payload bytes retained in results,
    once per byte independent of fragmentation. The implementation may make
    one additional temporary copy when converting an incomplete value buffer
    to immutable ``bytes``. Fixed frame-header scratch is at most 12 bytes and
    node-header scratch at most 5 bytes. The high-water mark records bytes
    retained across feed calls for an incomplete opaque value.
    """

    bytes_consumed: int = 0
    frame_headers_decoded: int = 0
    node_headers_decoded: int = 0
    payload_bytes_copied: int = 0
    staging_appends: int = 0
    staging_bytes_high_water: int = 0
    max_container_stack_depth: int = 0

