# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

import pkzip_overdrive as overdrive


class SessionInfoTests(unittest.TestCase):
    def test_load_session_info_accepts_only_json_objects(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            information = directory / "session-info.json"

            information.write_text('{"session": "sample"}\n', encoding="utf-8")
            self.assertEqual(
                overdrive.load_session_info(directory), {"session": "sample"}
            )

            information.write_text('["not", "an", "object"]\n', encoding="utf-8")
            self.assertEqual(overdrive.load_session_info(directory), {})

            information.write_text("not json\n", encoding="utf-8")
            self.assertEqual(overdrive.load_session_info(directory), {})

class DiscoveryTests(unittest.TestCase):
    def test_detect_gpu_selects_the_only_supported_card(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="0, NVIDIA GeForce RTX 2080 Ti, 11264\n1, Other GPU, 8192\n",
            stderr="",
        )
        with mock.patch.object(overdrive.subprocess, "run", return_value=completed):
            detected = overdrive.detect_gpu("nvidia-smi")

        self.assertEqual(
            detected, overdrive.Gpu(0, "NVIDIA GeForce RTX 2080 Ti", 11264)
        )

    def test_detect_gpu_rejects_ambiguous_or_under_size_cards(self) -> None:
        outputs = (
            "0, NVIDIA GeForce RTX 2080 Ti, 11264\n1, RTX 2080 Ti, 11264\n",
            "0, NVIDIA GeForce RTX 2080 Ti, 8192\n",
        )
        for output in outputs:
            with self.subTest(output=output):
                completed = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=output, stderr=""
                )
                with mock.patch.object(
                    overdrive.subprocess, "run", return_value=completed
                ):
                    with self.assertRaises(SystemExit):
                        overdrive.detect_gpu("nvidia-smi")

    def test_resumable_checkpoints_are_sorted_newest_first(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            older = root / "older"
            newer = root / "newer"
            older.mkdir()
            newer.mkdir()
            older_restore = older / "older.restore"
            newer_restore = newer / "newer.restore"
            older_restore.write_bytes(b"old")
            newer_restore.write_bytes(b"new")
            os.utime(older_restore, (100, 100))
            os.utime(newer_restore, (200, 200))

            checkpoints = overdrive.resumable_checkpoints(root)

        self.assertEqual([checkpoint[0] for checkpoint in checkpoints], ["newer", "older"])


class RestoreParsingTests(unittest.TestCase):
    def test_restore_snapshot_reads_hashcat_header_fields(self) -> None:
        arguments = ["hashcat", "--attack-mode=3", "?d?d?d"]
        raw = bytearray(296)
        struct.pack_into("<i", raw, 0, 7)
        struct.pack_into("<II", raw, 260, 2, 1)
        struct.pack_into("<Q", raw, 272, 250)
        struct.pack_into("<I", raw, 280, len(arguments))
        raw.extend(("\n".join(arguments) + "\n").encode())

        with tempfile.TemporaryDirectory() as directory_name:
            restore_file = Path(directory_name) / "sample.restore"
            restore_file.write_bytes(raw)
            snapshot = overdrive.restore_snapshot(restore_file)

        self.assertEqual(snapshot["version"], 7)
        self.assertEqual(snapshot["dicts_pos"], 2)
        self.assertEqual(snapshot["masks_pos"], 1)
        self.assertEqual(snapshot["words_cur"], 250)
        self.assertEqual(snapshot["argv"], arguments)

    def test_restore_snapshot_rejects_truncated_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            restore_file = Path(directory_name) / "sample.restore"
            restore_file.write_bytes(b"too short")
            self.assertEqual(overdrive.restore_snapshot(restore_file), {})

    def test_argument_and_mask_parsers_handle_hashcat_forms(self) -> None:
        arguments = ["--hash-type", "17220", "--attack-mode=3"]
        self.assertEqual(overdrive.argument_value(arguments, "hash-type"), "17220")
        self.assertEqual(overdrive.argument_value(arguments, "attack-mode"), "3")
        self.assertIsNone(overdrive.argument_value(arguments, "session"))
        self.assertEqual(overdrive.mask_tokens("?1?d-x"), ["?1", "?d", "-", "x"])

    def test_restore_progress_calculates_current_increment_mask(self) -> None:
        snapshot = {
            "argv": ["hashcat", "--attack-mode=3", "--increment", "?d?d?d"],
            "words_cur": 250,
            "masks_pos": 1,
        }
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="1000\n", stderr=""
        )
        with mock.patch.object(overdrive.subprocess, "run", return_value=completed):
            progress, mask = overdrive.restore_progress(snapshot, "/opt/hashcat/hashcat")

        self.assertEqual(mask, "?d?d")
        self.assertIn("25.00%", progress or "")
        self.assertIn("250/1,000", progress or "")


class InputTests(unittest.TestCase):
    def test_extract_pkzip_hash_writes_only_the_record(self) -> None:
        record = "$pkzip$1*2*3*$/pkzip$"
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            source = directory / "john.txt"
            destination = directory / "pkzip.hash"
            source.write_text(f"archive.zip:{record}:metadata\n", encoding="utf-8")

            overdrive.extract_pkzip_hash(source, destination)

            self.assertEqual(destination.read_text(encoding="ascii"), record + "\n")
            if os.name != "nt":
                mode = stat.S_IMODE(destination.stat().st_mode)
                self.assertEqual(mode, 0o600)

    def test_choose_source_path_uses_a_directorys_only_zip_case_insensitively(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            expected = directory / "archive.ZIP"
            expected.write_bytes(b"not needed for path selection")
            with mock.patch("builtins.print"):
                selected = overdrive.choose_source_path(str(directory))
            self.assertEqual(selected, expected.resolve())

    def test_multiple_archives_fail_cleanly_when_interactive_input_ends(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            (directory / "first.zip").write_bytes(b"first")
            (directory / "second.zip").write_bytes(b"second")
            with mock.patch("builtins.print"), mock.patch(
                "builtins.input", side_effect=EOFError
            ):
                with self.assertRaisesRegex(SystemExit, "explicit ZIP file path"):
                    overdrive.choose_source_path(str(directory))

    def test_choose_wordlist_prefers_known_wordlist_suffixes(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            expected = directory / "passwords.txt"
            expected.write_text("secret\n", encoding="utf-8")
            (directory / "notes.bin").write_bytes(b"other")
            with mock.patch("builtins.print"):
                selected = overdrive.choose_wordlist_path(str(directory))
            self.assertEqual(selected, expected.resolve())

    def test_multiple_wordlists_fail_cleanly_when_interactive_input_ends(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            (directory / "first.txt").write_text("first\n", encoding="utf-8")
            (directory / "second.txt").write_text("second\n", encoding="utf-8")
            with mock.patch("builtins.print"), mock.patch(
                "builtins.input", side_effect=EOFError
            ):
                with self.assertRaisesRegex(SystemExit, "explicit wordlist file path"):
                    overdrive.choose_wordlist_path(str(directory))

    def test_empty_paths_are_rejected(self) -> None:
        for chooser in (
            overdrive.choose_source_path,
            overdrive.choose_wordlist_path,
        ):
            for value in ("", '""', "''"):
                with self.subTest(chooser=chooser.__name__, value=value):
                    with self.assertRaisesRegex(SystemExit, "path cannot be empty"):
                        chooser(value)

    def test_identify_mode_requires_one_supported_match(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="  17220 | PKZIP (Compressed Multi-File)\n",
            stderr="",
        )
        with mock.patch.object(overdrive.subprocess, "run", return_value=completed):
            mode = overdrive.identify_mode("/opt/hashcat/hashcat", Path("hash"), {})
        self.assertEqual(mode, 17220)


class ValidationTests(unittest.TestCase):
    def test_session_and_numeric_validators(self) -> None:
        self.assertEqual(overdrive.validate_session("job-2026.07_20"), "job-2026.07_20")
        with self.assertRaises(argparse.ArgumentTypeError):
            overdrive.validate_session("unsafe/session")
        self.assertEqual(overdrive.length("10"), 10)
        self.assertEqual(overdrive.status_interval("15"), 15)
        for invalid in ("0", "11", "not-a-number"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(argparse.ArgumentTypeError):
                    overdrive.length(invalid)
        with self.assertRaises(argparse.ArgumentTypeError):
            overdrive.status_interval("9")

    def test_mask_arguments_cover_every_character_set(self) -> None:
        self.assertEqual(overdrive.mask_arguments("ascii", 2), ([], "?a?a"))
        self.assertEqual(overdrive.mask_arguments("lower", 2), ([], "?l?l"))
        self.assertEqual(overdrive.mask_arguments("digits", 2), ([], "?d?d"))
        self.assertEqual(
            overdrive.mask_arguments("alnum", 2),
            (["--custom-charset1=?l?u?d"], "?1?1"),
        )

    def test_parser_accepts_an_automated_brute_force_start(self) -> None:
        arguments = overdrive.build_parser().parse_args(
            ["start", "archive.zip", "--attack", "brute", "--max-length", "4"]
        )
        self.assertEqual(arguments.source, "archive.zip")
        self.assertEqual(arguments.attack, "brute")
        self.assertEqual(arguments.max_length, 4)
        self.assertIs(arguments.handler, overdrive.start_command)

    def test_show_checkpoint_writes_a_reusable_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            restore_file = directory / "sample.restore"
            restore_file.write_bytes(b"checkpoint")
            with mock.patch("builtins.print"):
                overdrive.show_checkpoint("sample", restore_file)
            information = (directory / "checkpoint-info.txt").read_text(
                encoding="utf-8"
            )
        self.assertIn("status=ready", information)
        self.assertIn("restore sample", information)


if __name__ == "__main__":
    unittest.main()
