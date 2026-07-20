# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from array import array
from pathlib import Path
import tempfile
import threading
import unittest

import wordlist_merger_gpu as merger


class FormattingTests(unittest.TestCase):
    def test_human_size_and_rate_use_binary_units(self) -> None:
        self.assertEqual(merger.human_size(0), "0 B")
        self.assertEqual(merger.human_size(1536), "1.5 KiB")
        self.assertEqual(merger.human_rate(2048, 2), "1.0 KiB/s")
        self.assertEqual(merger.human_rate(2048, 0), "0 B/s")

    def test_cpu_hasher_is_deterministic_for_equal_lines(self) -> None:
        hasher = merger.CpuTestHasher()
        first, second = hasher.hash_lines(
            bytearray(b"alphabetalpha"),
            array("Q", [0, 5, 8]),
            array("I", [5, 3, 5]),
        )
        self.assertEqual((first[0], second[0]), (first[2], second[2]))
        self.assertNotEqual((first[0], second[0]), (first[1], second[1]))


class MergeTests(unittest.TestCase):
    @staticmethod
    def no_progress(_done: int, _total: int, _detail: str) -> None:
        return

    def test_exact_merge_inserts_only_the_needed_file_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            first = directory / "first.txt"
            second = directory / "second.txt"
            destination = directory / "combined.txt"
            first.write_bytes(b"alpha\nbeta")
            second.write_bytes(b"gamma\n")

            result = merger.merge_exact(
                [first, second], destination, threading.Event(), self.no_progress
            )

            self.assertEqual(destination.read_bytes(), b"alpha\nbeta\ngamma\n")
            self.assertEqual(result.input_files, 2)
            self.assertEqual(result.output_bytes, len(b"alpha\nbeta\ngamma\n"))

    def test_exact_merge_cancellation_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            source = directory / "source.txt"
            destination = directory / "combined.txt"
            source.write_bytes(b"new content\n")
            destination.write_bytes(b"keep me\n")
            cancelled = threading.Event()
            cancelled.set()

            with self.assertRaises(merger.MergeCancelled):
                merger.merge_exact(
                    [source], destination, cancelled, self.no_progress
                )

            self.assertEqual(destination.read_bytes(), b"keep me\n")
            self.assertEqual(list(directory.glob(".*.partial")), [])

    def test_deduplicated_merge_normalizes_lines_and_counts_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            first = directory / "first.txt"
            second = directory / "second.txt"
            destination = directory / "unique.txt"
            first.write_bytes(b"alpha\r\nbeta\nbeta")
            second.write_bytes(b"beta\ngamma\n\n")

            result = merger.merge_deduplicated(
                [first, second],
                destination,
                merger.CpuTestHasher(),
                True,
                threading.Event(),
                self.no_progress,
            )

            self.assertEqual(destination.read_bytes(), b"alpha\nbeta\ngamma\n")
            self.assertEqual(result.input_lines, 6)
            self.assertEqual(result.output_lines, 3)
            self.assertEqual(result.duplicate_lines, 2)
            self.assertEqual(result.blank_lines_skipped, 1)

    def test_hasher_failure_preserves_existing_output_and_closes_backend(self) -> None:
        class FailingHasher:
            name = "failing test backend"

            def __init__(self) -> None:
                self.closed = False

            def hash_lines(self, *_arguments: object) -> tuple[array, array]:
                raise RuntimeError("expected failure")

            def close(self) -> None:
                self.closed = True

        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            source = directory / "source.txt"
            destination = directory / "unique.txt"
            source.write_bytes(b"alpha\n")
            destination.write_bytes(b"keep me\n")
            hasher = FailingHasher()

            with self.assertRaisesRegex(RuntimeError, "expected failure"):
                merger.merge_deduplicated(
                    [source],
                    destination,
                    hasher,
                    False,
                    threading.Event(),
                    self.no_progress,
                )

            self.assertTrue(hasher.closed)
            self.assertEqual(destination.read_bytes(), b"keep me\n")
            self.assertEqual(list(directory.glob(".*.partial")), [])

    def test_progress_report_reaches_the_total(self) -> None:
        events: list[tuple[int, int, str]] = []
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            source = directory / "source.txt"
            destination = directory / "combined.txt"
            source.write_bytes(b"content\n")
            merger.merge_exact(
                [source],
                destination,
                threading.Event(),
                lambda done, total, detail: events.append((done, total, detail)),
            )

        self.assertTrue(events)
        self.assertEqual(events[-1], (8, 8, "Complete"))


if __name__ == "__main__":
    unittest.main()
