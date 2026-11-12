"""Fixed-seed structured fuzzing with reproducible failure records."""

from __future__ import annotations

import hashlib
import json
import os
import random
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tlm_parser import (
    FinishStatus,
    FrameParser,
    ParserError,
    ParserLimits,
    ParsedFrame,
    TlvNode,
)

from tests.fixtures import (
    DriveResult,
    FuzzCase,
    drive,
    generate_mutations,
    generate_valid_case,
    make_chunks,
)


FUZZ_SEED = 0x5EED1234
VALID_CASES = 500
MUTATION_CASES = 2500
FRAGMENTATION_MODES = ("whole", "bytes", "random")


@dataclass(slots=True)
class FuzzFailure:
    case: FuzzCase
    mode: str
    chunks: list[bytes]
    seed: int
    reason: str
    expected: Any
    actual: Any
    exception: str | None = None


@dataclass(slots=True)
class FuzzReport:
    seed: int
    cases: int
    feed_calls: int
    failures: list[tuple[FuzzFailure, Path | None]]

    @property
    def ok(self) -> bool:
        return not self.failures


def _node_summary(node: TlvNode) -> dict[str, Any]:
    if node.is_container:
        return {
            "type": node.node_type,
            "container": True,
            "children": [_node_summary(child) for child in node.value],
        }
    return {
        "type": node.node_type,
        "container": False,
        "value_hex": node.value.hex(),
    }


def _frame_summary(frame: ParsedFrame) -> dict[str, Any]:
    return {
        "body_length": frame.body_length,
        "nodes": [_node_summary(node) for node in frame.nodes],
    }


def _error_summary(error: ParserError | None) -> dict[str, Any] | None:
    if error is None:
        return None
    return {
        "code": str(error.code),
        "offset": error.offset,
        "message": error.message,
    }


def _fragmentation_summary(failure: FuzzFailure) -> dict[str, Any]:
    return {
        "mode": failure.mode,
        "chunks_hex": [chunk.hex() for chunk in failure.chunks],
        "chunk_lengths": [len(chunk) for chunk in failure.chunks],
    }


def failure_record(failure: FuzzFailure) -> dict[str, Any]:
    return {
        "format": "tlm1-fuzz-failure-v1",
        "seed": failure.seed,
        "case_label": failure.case.label,
        "expect_reject": failure.case.expect_reject,
        "limits": {
            "max_frame_body": failure.case.limits.max_frame_body,
            "max_value_bytes": failure.case.limits.max_value_bytes,
            "max_nodes": failure.case.limits.max_nodes,
            "max_depth": failure.case.limits.max_depth,
            "max_pending_bytes": failure.case.limits.max_pending_bytes,
        },
        "input_hex": failure.case.raw.hex(),
        "fragmentation": _fragmentation_summary(failure),
        "reason": failure.reason,
        "expected": failure.expected,
        "actual": failure.actual,
        "exception": failure.exception,
    }


def archive_failure(failure_dir: Path, failure: FuzzFailure) -> Path:
    record = failure_record(failure)
    encoded = json.dumps(
        record, ensure_ascii=True, indent=2, sort_keys=True
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:24]
    failure_dir.mkdir(parents=True, exist_ok=True)
    path = failure_dir / f"failure-{digest}.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(encoded)
    os.replace(temporary, path)
    return path


def load_failure(path: Path) -> dict[str, Any]:
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("format") != "tlm1-fuzz-failure-v1":
        raise ValueError("not a TLM1 fuzz failure record")
    return record


def replay_record(record: dict[str, Any]) -> DriveResult:
    """Replay a saved failure with its exact limits and fragmentation."""

    limits = ParserLimits(**record["limits"])
    chunks = [bytes.fromhex(item) for item in record["fragmentation"]["chunks_hex"]]
    return drive(FrameParser(limits), chunks)


def _record_failure(
    failures: list[tuple[FuzzFailure, Path | None]],
    failure: FuzzFailure,
    failure_dir: Path,
) -> None:
    path = archive_failure(failure_dir, failure)
    failures.append((failure, path))


def run_fuzz(
    seed: int = FUZZ_SEED,
    valid_cases: int = VALID_CASES,
    mutation_cases: int = MUTATION_CASES,
    failure_dir: Path = Path("artifacts/fuzz_failures"),
) -> FuzzReport:
    """Run deterministic structured and mutation fuzzing.

    Raw bytes, seed, limits, and the exact fragmentation sequence are archived
    for every mismatch or unexpected exception.
    """

    rng = random.Random(seed)
    limits = ParserLimits(
        max_frame_body=1 << 16,
        max_value_bytes=1 << 11,
        max_nodes=256,
        max_depth=24,
        max_pending_bytes=1 << 11,
    )
    cases = [generate_valid_case(rng, limits) for _ in range(valid_cases)]
    cases.extend(generate_mutations(rng, mutation_cases, limits))

    failures: list[tuple[FuzzFailure, Path | None]] = []
    feed_calls = 0

    for case_index, case in enumerate(cases):
        mode_results: list[tuple[str, list[bytes], Any, Exception | None]] = []

        for mode_index, mode in enumerate(FRAGMENTATION_MODES):
            case_rng = random.Random((seed << 32) ^ (case_index << 8) ^ mode_index)
            chunks = make_chunks(case.raw, mode, case_rng)
            try:
                result = drive(FrameParser(case.limits), chunks)
                feed_calls += result.feed_calls
            except Exception as exc:
                failure = FuzzFailure(
                    case=case,
                    mode=mode,
                    chunks=chunks,
                    seed=seed,
                    reason="unhandled Python exception",
                    expected=(
                        "protocol rejection" if case.expect_reject else "valid frames"
                    ),
                    actual=f"{type(exc).__name__}: {exc}",
                    exception=traceback.format_exc(),
                )
                _record_failure(failures, failure, failure_dir)
                mode_results.append((mode, chunks, None, exc))
                continue

            mode_results.append((mode, chunks, result, None))
            if case.expect_reject:
                if result.error is None:
                    failure = FuzzFailure(
                        case=case,
                        mode=mode,
                        chunks=chunks,
                        seed=seed,
                        reason="mutated input was not rejected",
                        expected="protocol rejection",
                        actual={
                            "frames": [_frame_summary(f) for f in result.frames],
                            "finish": str(result.finish_status),
                            "error": _error_summary(result.error),
                        },
                    )
                    _record_failure(failures, failure, failure_dir)
            else:
                if result.error is not None:
                    failure = FuzzFailure(
                        case=case,
                        mode=mode,
                        chunks=chunks,
                        seed=seed,
                        reason="valid input was rejected",
                        expected=[
                            _frame_summary(frame)
                            for frame in (case.expected_frames or ())
                        ],
                        actual=_error_summary(result.error),
                    )
                    _record_failure(failures, failure, failure_dir)
                elif result.frames != case.expected_frames:
                    failure = FuzzFailure(
                        case=case,
                        mode=mode,
                        chunks=chunks,
                        seed=seed,
                        reason="valid input produced a different result",
                        expected=[
                            _frame_summary(frame)
                            for frame in (case.expected_frames or ())
                        ],
                        actual=[_frame_summary(frame) for frame in result.frames],
                    )
                    _record_failure(failures, failure, failure_dir)
                elif result.finish_status != FinishStatus.CLEAN_END:
                    failure = FuzzFailure(
                        case=case,
                        mode=mode,
                        chunks=chunks,
                        seed=seed,
                        reason="valid input did not end cleanly",
                        expected=str(FinishStatus.CLEAN_END),
                        actual=str(result.finish_status),
                    )
                    _record_failure(failures, failure, failure_dir)

        if len(mode_results) != len(FRAGMENTATION_MODES):
            continue

        if any(item[3] is not None for item in mode_results):
            continue

        observed = [item[2] for item in mode_results]
        if any(item.frames != observed[0].frames for item in observed[1:]):
            mode, chunks, result, _ = mode_results[0]
            failure = FuzzFailure(
                case=case,
                mode=mode,
                chunks=chunks,
                seed=seed,
                reason="frame output differs across fragmentation modes",
                expected=[_frame_summary(f) for f in observed[0].frames],
                actual=[
                    [_frame_summary(f) for f in item.frames] for item in observed
                ],
            )
            _record_failure(failures, failure, failure_dir)

        errors = [item[2].error for item in mode_results]
        error_keys = [
            None if error is None else (str(error.code), error.offset)
            for error in errors
        ]
        if len(set(error_keys)) != 1:
            mode, chunks, result, _ = mode_results[0]
            failure = FuzzFailure(
                case=case,
                mode=mode,
                chunks=chunks,
                seed=seed,
                reason="failure category or global offset differs by fragmentation",
                expected=error_keys[0],
                actual=error_keys,
            )
            _record_failure(failures, failure, failure_dir)

    return FuzzReport(
        seed=seed,
        cases=len(cases),
        feed_calls=feed_calls,
        failures=failures,
    )
