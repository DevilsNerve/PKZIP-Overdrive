# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import pkzip_overdrive as overdrive


class StatusTrackingTests(unittest.TestCase):
    def test_combined_hashcat_speed_is_saved_with_attempt_rate(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            tracker = overdrive.SessionTracker(directory, {"session": "sample"})

            tracker.consume("Speed.#*.........: 1.5 GH/s (10.00ms) @ Accel:64")
            tracker.consume("Progress.........: 1,500/2,000 (75.00%)")
            tracker.finish(0)

            saved = json.loads(
                (directory / "session-info.json").read_text(encoding="utf-8")
            )

        self.assertEqual(saved["progress"]["speed"], "1.5 GH/s (10.00ms) @ Accel:64")
        self.assertEqual(saved["progress"]["attempts_per_minute"], 90_000_000_000)
        self.assertEqual(saved["progress"]["attempted"], 1500)
        self.assertEqual(saved["progress"]["percent"], 75.0)


if __name__ == "__main__":
    unittest.main()
