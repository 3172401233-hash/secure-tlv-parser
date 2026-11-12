from __future__ import annotations

import contextlib
import json
import random
import signal
import tempfile
import unittest
from pathlib import Path

from tlm_parser import ErrorCode, ParserLimits

from tests.fixtures import (
    FuzzCase,
    encode_frame,
    encode_node,
    make_chunks,
)
from tests.fuzz_harness import (
    FUZZ_SEED,
    MUTATION_CASES,
    VALID_CASES,
    FuzzFailure,
    archive_failure,
    load_failure,
    replay_record,
    run_fuzz,
)


class _FuzzTimeout(BaseException):
    pass


@contextlib.contextmanager
def _deadline(seconds: float):
    if not hasattr(signal, "setitimer"):
        yield
        return

    def handler(_signum, _frame):
        raise _FuzzTimeout(f"fuzz run exceeded the {seconds:g}s watchdog")

    previous = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class FuzzTests(unittest.TestCase):
    def test_fixed_seed_structured_and_mutation_fuzz(self) -> None:
        failure_dir = Path("artifacts/fuzz_failures")
        with _deadline(50):
            report = run_fuzz(
                seed=FUZZ_SEED,
                valid_cases=VALID_CASES,
                mutation_cases=MUTATION_CASES,
                failure_dir=failure_dir,
            )

        print(
            f"\nfuzz: seed=0x{report.seed:X} cases={report.cases} "
            f"feed_calls={report.feed_calls} failures={len(report.failures)}",
        )
        if not report.ok:
            details = []
            for failure, path in report.failures[:10]:
                details.append(
                    f"{failure.case.label}/{failure.mode}: {failure.reason} "
                    f"(record={path})"
                )
            self.fail("fuzz failures:\n" + "\n".join(details))

    def test_failure_record_round_trip_and_offline_replay(self) -> None:
        limits = ParserLimits(
            max_frame_body=256,
            max_value_bytes=64,
            max_nodes=16,
            max_depth=8,
            max_pending_bytes=64,
        )
        valid_raw = encode_frame(encode_node(0x27, b"round-trip"))
        valid_case = FuzzCase(
            label="archive-valid",
            raw=valid_raw,
            expected_frames=(),
            expect_reject=False,
            limits=limits,
        )
        failure = FuzzFailure(
            case=valid_case,
            mode="random",
            chunks=make_chunks(valid_raw, "random", random.Random(9)),
            seed=1234,
            reason="archive round-trip exercise",
            expected="valid frame",
            actual="valid frame",
        )

        with tempfile.TemporaryDirectory() as temporary:
            archive_dir = Path(temporary)
            path = archive_failure(archive_dir, failure)
            record = load_failure(path)
            self.assertEqual(record["seed"], 1234)
            self.assertEqual(record["input_hex"], valid_raw.hex())
            self.assertEqual(record["fragmentation"]["mode"], "random")
            self.assertEqual(record["limits"], {
                "max_frame_body": 256,
                "max_value_bytes": 64,
                "max_nodes": 16,
                "max_depth": 8,
                "max_pending_bytes": 64,
            })
            replayed = replay_record(record)
            self.assertIsNone(replayed.error)
            self.assertEqual(replayed.frames[0].nodes[0].value, b"round-trip")

            invalid_raw = b"BAD!" + valid_raw[4:]
            invalid_case = FuzzCase(
                label="archive-invalid",
                raw=invalid_raw,
                expected_frames=None,
                expect_reject=True,
                limits=limits,
            )
            invalid_failure = FuzzFailure(
                case=invalid_case,
                mode="whole",
                chunks=[invalid_raw],
                seed=4321,
                reason="expected rejection",
                expected="protocol rejection",
                actual="bad_magic",
            )
            invalid_path = archive_failure(archive_dir, invalid_failure)
            invalid_record = load_failure(invalid_path)
            replayed_invalid = replay_record(invalid_record)
            self.assertIsNotNone(replayed_invalid.error)
            assert replayed_invalid.error is not None
            self.assertEqual(replayed_invalid.error.code, ErrorCode.BAD_MAGIC)

    def test_archive_record_contains_required_context(self) -> None:
        limits = ParserLimits()
        raw = encode_frame(encode_node(0x01, b"x"))
        case = FuzzCase(
            label="required-context",
            raw=raw,
            expected_frames=None,
            expect_reject=True,
            limits=limits,
        )
        failure = FuzzFailure(
            case=case,
            mode="bytes",
            chunks=make_chunks(raw, "bytes"),
            seed=77,
            reason="test",
            expected="unused",
            actual="unused",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = archive_failure(Path(temporary), failure)
            record = json.loads(path.read_text(encoding="utf-8"))
            for key in (
                "seed",
                "limits",
                "input_hex",
                "fragmentation",
                "expected",
                "actual",
            ):
                self.assertIn(key, record)


if __name__ == "__main__":
    unittest.main()
