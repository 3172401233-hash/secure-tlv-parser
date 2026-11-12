"""Incremental, non-recursive TLM1 parser."""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import (
    CONTAINER_TYPE,
    FRAME_HEADER_SIZE,
    MAGIC,
    NODE_HEADER_SIZE,
    ErrorCode,
    FeedResult,
    FinishResult,
    FinishStatus,
    ParsedFrame,
    ParserError,
    ParserLimits,
    ParserStats,
    ParseStatus,
    TlvNode,
)


class _Phase:
    HEADER = 0
    BODY = 1
    FAILED = 2


class _Rejected(Exception):
    __slots__ = ("code", "offset", "message")

    def __init__(self, code: ErrorCode, offset: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.offset = offset
        self.message = message


@dataclass(slots=True)
class _ContainerContext:
    node_type: int | None
    end: int
    depth: int
    parent_children: list[TlvNode] | None
    children: list[TlvNode] = field(default_factory=list)


@dataclass(slots=True)
class _OpaqueContext:
    node_type: int
    remaining: int
    buffer: bytearray
    parent_children: list[TlvNode]


class FrameParser:
    """Parse TLM1 frames incrementally.

    A parser instance holds state for at most one incomplete frame. It never
    retains a reference to a caller's bytes, bytearray, or memoryview.
    """

    __slots__ = (
        "_limits",
        "_phase",
        "_abs_pos",
        "_frame_start",
        "_body_length",
        "_body_start",
        "_frame_end",
        "_header",
        "_stack",
        "_root_nodes",
        "_node_count",
        "_node_header",
        "_node_header_have",
        "_node_header_start",
        "_opaque",
        "_last_error",
        "_bytes_consumed",
        "_frame_headers_decoded",
        "_node_headers_decoded",
        "_payload_bytes_copied",
        "_staging_appends",
        "_max_staging_bytes",
        "_max_stack_depth",
    )

    def __init__(self, limits: ParserLimits | None = None) -> None:
        self._limits = ParserLimits() if limits is None else limits
        if not isinstance(self._limits, ParserLimits):
            raise TypeError("limits must be a ParserLimits instance")
        self.reset()

    @property
    def limits(self) -> ParserLimits:
        return self._limits

    @property
    def stats(self) -> ParserStats:
        return ParserStats(
            bytes_consumed=self._bytes_consumed,
            frame_headers_decoded=self._frame_headers_decoded,
            node_headers_decoded=self._node_headers_decoded,
            payload_bytes_copied=self._payload_bytes_copied,
            staging_appends=self._staging_appends,
            staging_bytes_high_water=self._max_staging_bytes,
            max_container_stack_depth=self._max_stack_depth,
        )

    def reset(self) -> None:
        """Clear incomplete state, terminal failures, and work counters."""

        self._phase = _Phase.HEADER
        self._abs_pos = 0
        self._frame_start = 0
        self._body_length = 0
        self._body_start = 0
        self._frame_end = 0
        self._header = bytearray()
        self._stack: list[_ContainerContext] = []
        self._root_nodes: list[TlvNode] = []
        self._node_count = 0
        self._node_header = bytearray()
        self._node_header_have = 0
        self._node_header_start = 0
        self._opaque: _OpaqueContext | None = None
        self._last_error: ParserError | None = None
        self._bytes_consumed = 0
        self._frame_headers_decoded = 0
        self._node_headers_decoded = 0
        self._payload_bytes_copied = 0
        self._staging_appends = 0
        self._max_staging_bytes = 0
        self._max_stack_depth = 0

    def feed(self, data: bytes | bytearray | memoryview) -> FeedResult:
        """Consume as much of ``data`` as needed for at most one frame.

        ``consumed`` is always in ``[0, len(data)]``. If unread bytes remain,
        the caller passes them again. Invalid API input raises ``TypeError`` or
        ``ValueError``; protocol rejection is reported as ``FAILED``.
        """

        if self._phase == _Phase.FAILED:
            return FeedResult(
                status=ParseStatus.FAILED,
                consumed=0,
                error=self._last_error,
            )

        view, owned = _as_byte_view(data)
        consumed = 0
        call_start_abs = self._abs_pos
        size = view.nbytes
        try:
            while True:
                try:
                    if self._phase == _Phase.HEADER:
                        consumed = self._feed_header(view, consumed, size)
                        if self._phase == _Phase.HEADER:
                            return FeedResult(
                                status=ParseStatus.NEED_MORE,
                                consumed=consumed,
                            )
                        continue
                    elif self._phase == _Phase.BODY:
                        consumed, frame = self._feed_body(view, consumed, size)
                        if frame is not None:
                            return FeedResult(
                                status=ParseStatus.FRAME_READY,
                                consumed=consumed,
                                frame=frame,
                            )
                        return FeedResult(
                            status=ParseStatus.NEED_MORE,
                            consumed=consumed,
                        )
                    else:
                        raise AssertionError(f"unexpected parser phase {self._phase}")
                except _Rejected as exc:
                    consumed = self._abs_pos - call_start_abs
                    return self._reject(consumed, exc)
        finally:
            if owned:
                view.release()

    def finish(self) -> FinishResult:
        """Check end of input.

        A pending partial frame becomes a terminal truncation failure. After
        a clean result the parser remains usable.
        """

        if self._phase == _Phase.FAILED:
            return FinishResult(status=FinishStatus.FAILED, error=self._last_error)

        if self._phase == _Phase.HEADER:
            if self._header:
                exc = _error(
                    ErrorCode.TRUNCATED_HEADER,
                    self._abs_pos,
                    "end of input in frame header",
                )
                self._enter_failed(exc)
                return FinishResult(status=FinishStatus.FAILED, error=self._last_error)
            return FinishResult(status=FinishStatus.CLEAN_END)

        if self._phase == _Phase.BODY:
            exc = _error(
                ErrorCode.TRUNCATED_BODY,
                self._abs_pos,
                "end of input in frame body",
            )
            self._enter_failed(exc)
            return FinishResult(status=FinishStatus.FAILED, error=self._last_error)

        raise AssertionError(f"unexpected parser phase {self._phase}")

    def _feed_header(
        self, view: memoryview, consumed: int, size: int
    ) -> int:
        take = min(FRAME_HEADER_SIZE - len(self._header), size - consumed)
        if take:
            self._header.extend(view[consumed : consumed + take])
            consumed += take
            self._advance(take)

        if len(self._header) != FRAME_HEADER_SIZE:
            return consumed

        self._frame_headers_decoded += 1
        self._frame_start = self._abs_pos - FRAME_HEADER_SIZE
        raw = bytes(self._header)
        if raw[0:4] != MAGIC:
            raise _error(
                ErrorCode.BAD_MAGIC,
                self._frame_start,
                "frame magic is not TLM1",
            )
        if raw[4] != 1:
            raise _error(
                ErrorCode.UNSUPPORTED_VERSION,
                self._frame_start + 4,
                "frame version must be 1",
            )
        if raw[5] != 0:
            raise _error(
                ErrorCode.NONZERO_FLAGS,
                self._frame_start + 5,
                "frame flags must be zero",
            )
        if raw[6:8] != b"\x00\x00":
            raise _error(
                ErrorCode.NONZERO_RESERVED,
                self._frame_start + 6,
                "frame reserved field must be zero",
            )

        body_length = int.from_bytes(raw[8:12], "big")
        if body_length > self._limits.max_frame_body:
            raise _error(
                ErrorCode.FRAME_TOO_LARGE,
                self._frame_start + 8,
                "declared frame body exceeds max_frame_body",
            )

        self._body_length = body_length
        self._body_start = self._frame_start + FRAME_HEADER_SIZE
        self._frame_end = self._body_start + body_length
        self._header.clear()

        self._phase = _Phase.BODY
        self._root_nodes = []
        self._stack = [
            _ContainerContext(
                node_type=None,
                end=self._frame_end,
                depth=0,
                parent_children=None,
                children=self._root_nodes,
            )
        ]
        return consumed

    def _feed_body(
        self, view: memoryview, consumed: int, size: int
    ) -> tuple[int, ParsedFrame | None]:
        while True:
            if self._opaque is not None:
                consumed = self._consume_opaque(view, consumed, size)
                if self._opaque is not None:
                    return consumed, None
                continue

            self._close_finished_containers()

            if not self._stack:
                frame = ParsedFrame(
                    body_length=self._body_length,
                    nodes=tuple(self._root_nodes),
                )
                self._phase = _Phase.HEADER
                self._clear_frame_state()
                return consumed, frame

            top = self._stack[-1]
            remaining = top.end - self._abs_pos
            header_needed = NODE_HEADER_SIZE - self._node_header_have
            if remaining < header_needed:
                raise _error(
                    ErrorCode.MALFORMED_TLV,
                    self._abs_pos,
                    "container has trailing bytes that cannot form a TLV header",
                )

            if consumed >= size:
                return consumed, None

            consumed = self._consume_node_header(view, consumed, size)
            if self._node_header_have:
                return consumed, None

        # Unreachable; kept for static analyzers.
        raise AssertionError("body parser did not make progress")

    def _consume_opaque(
        self, view: memoryview, consumed: int, size: int
    ) -> int:
        opaque = self._opaque
        if opaque is None:
            raise AssertionError("opaque context is absent")

        take = min(opaque.remaining, size - consumed)
        if take == 0:
            return consumed

        piece = view[consumed : consumed + take]
        if take == opaque.remaining:
            if opaque.buffer:
                opaque.buffer.extend(piece)
                self._staging_appends += 1
                self._record_staging_size(len(opaque.buffer))
            value = bytes(piece if not opaque.buffer else opaque.buffer)
            opaque.parent_children.append(
                TlvNode(node_type=opaque.node_type, is_container=False, value=value)
            )
            self._opaque = None
        else:
            opaque.buffer.extend(piece)
            self._staging_appends += 1
            self._record_staging_size(len(opaque.buffer))
            opaque.remaining -= take

        self._payload_bytes_copied += take
        consumed += take
        self._advance(take)
        return consumed

    def _consume_node_header(
        self, view: memoryview, consumed: int, size: int
    ) -> int:
        top = self._stack[-1]
        available_in_container = top.end - self._abs_pos

        if self._node_header_have == 0:
            self._node_header_start = self._abs_pos

        if self._node_header_have == 0 and size - consumed >= NODE_HEADER_SIZE:
            raw = bytes(view[consumed : consumed + NODE_HEADER_SIZE])
            consumed += NODE_HEADER_SIZE
            self._advance(NODE_HEADER_SIZE)
        else:
            take = min(
                NODE_HEADER_SIZE - self._node_header_have,
                size - consumed,
                available_in_container,
            )
            if take == 0:
                return consumed
            self._node_header.extend(view[consumed : consumed + take])
            self._node_header_have += take
            consumed += take
            self._advance(take)
            if self._node_header_have < NODE_HEADER_SIZE:
                return consumed
            raw = bytes(self._node_header)

        self._node_headers_decoded += 1
        self._node_header.clear()
        self._node_header_have = 0
        self._accept_node_header(raw, self._node_header_start)
        return consumed

    def _accept_node_header(self, raw: bytes, node_start: int) -> None:
        top = self._stack[-1]
        node_type = raw[0]
        value_length = int.from_bytes(raw[1:5], "big")
        value_start = self._abs_pos
        available_in_parent = top.end - value_start

        if value_length > self._limits.max_value_bytes:
            raise _error(
                ErrorCode.VALUE_TOO_LARGE,
                node_start,
                "node value exceeds max_value_bytes",
            )
        if node_type != CONTAINER_TYPE and value_length > self._limits.max_pending_bytes:
            raise _error(
                ErrorCode.STAGING_LIMIT,
                node_start,
                "opaque value exceeds max_pending_bytes",
            )
        if value_length > available_in_parent:
            raise _error(
                ErrorCode.MALFORMED_TLV,
                node_start,
                "node value extends beyond its enclosing container",
            )

        next_node_count = self._node_count + 1
        if next_node_count > self._limits.max_nodes:
            raise _error(
                ErrorCode.TOO_MANY_NODES,
                node_start,
                "node count exceeds max_nodes",
            )
        depth = top.depth + 1
        if depth > self._limits.max_depth:
            raise _error(
                ErrorCode.DEPTH_EXCEEDED,
                node_start,
                "node depth exceeds max_depth",
            )
        self._node_count = next_node_count

        if node_type == CONTAINER_TYPE:
            if value_length == 0:
                top.children.append(
                    TlvNode(node_type=node_type, is_container=True, value=())
                )
                return
            if depth + 1 > self._limits.max_depth:
                raise _error(
                    ErrorCode.DEPTH_EXCEEDED,
                    node_start,
                    "non-empty container requires a child beyond max_depth",
                )
            if value_length < NODE_HEADER_SIZE:
                raise _error(
                    ErrorCode.MALFORMED_TLV,
                    node_start,
                    "non-empty container is too short to hold a TLV header",
                )

            previous_children = top.children
            child_context = _ContainerContext(
                node_type=node_type,
                end=value_start + value_length,
                depth=depth,
                parent_children=previous_children,
            )
            self._stack.append(child_context)
            stack_depth = len(self._stack) - 1
            if stack_depth > self._max_stack_depth:
                self._max_stack_depth = stack_depth
            return

        if value_length == 0:
            top.children.append(
                TlvNode(node_type=node_type, is_container=False, value=b"")
            )
            return

        self._opaque = _OpaqueContext(
            node_type=node_type,
            remaining=value_length,
            buffer=bytearray(),
            parent_children=top.children,
        )

    def _close_finished_containers(self) -> None:
        while self._stack and self._stack[-1].end == self._abs_pos:
            context = self._stack.pop()
            if context.node_type is None:
                if context.parent_children is not None:
                    raise AssertionError("root context has a parent")
                return
            node = TlvNode(
                node_type=context.node_type,
                is_container=True,
                value=tuple(context.children),
            )
            if context.parent_children is None:
                raise AssertionError("container context has no parent")
            context.parent_children.append(node)

    def _advance(self, count: int) -> None:
        self._abs_pos += count
        self._bytes_consumed += count

    def _record_staging_size(self, size: int) -> None:
        if size > self._max_staging_bytes:
            self._max_staging_bytes = size

    def _reject(self, consumed: int, rejected: _Rejected) -> FeedResult:
        self._enter_failed(rejected)
        return FeedResult(
            status=ParseStatus.FAILED,
            consumed=consumed,
            error=self._last_error,
        )

    def _enter_failed(self, rejected: _Rejected) -> None:
        self._phase = _Phase.FAILED
        self._last_error = ParserError(
            code=rejected.code,
            offset=rejected.offset,
            message=rejected.message,
        )
        self._clear_unfinished()

    def _clear_unfinished(self) -> None:
        self._header.clear()
        self._stack.clear()
        self._root_nodes = []
        self._node_count = 0
        self._node_header.clear()
        self._node_header_have = 0
        self._opaque = None

    def _clear_frame_state(self) -> None:
        self._stack.clear()
        self._root_nodes = []
        self._node_count = 0
        self._node_header.clear()
        self._node_header_have = 0
        self._opaque = None


def _error(code: ErrorCode, offset: int, message: str) -> _Rejected:
    return _Rejected(code=code, offset=offset, message=message)


def _as_byte_view(
    data: bytes | bytearray | memoryview,
) -> tuple[memoryview, bool]:
    if isinstance(data, memoryview):
        if data.ndim != 1:
            raise ValueError("memoryview must be one-dimensional")
        if not data.contiguous:
            raise ValueError("memoryview must be C-contiguous")
        if data.itemsize != 1:
            raise TypeError("memoryview itemsize must be one byte")
        if data.format == "B":
            return data, False
        try:
            return data.cast("B"), True
        except TypeError as exc:
            raise TypeError("memoryview must expose byte-oriented data") from exc

    if isinstance(data, (bytes, bytearray)):
        return memoryview(data), True

    raise TypeError(
        "data must be bytes, bytearray, or a contiguous 1-D byte memoryview"
    )
