#!/usr/bin/env python3
"""Dedicated PKZIP launcher for one NVIDIA GeForce RTX 2080 Ti.

Hashcat performs the attack directly. This wrapper only validates the GPU and
input, extracts a Hashcat-compatible PKZIP record, selects the mode, and then
launches Hashcat. There is no monitoring process competing with the cracking
workload; Hashcat's live status includes aggregate speed and total progress.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
from typing import Callable, Sequence
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile


GPU_NAME_FRAGMENT = "RTX 2080 Ti"
MIN_VRAM_MIB = 10_000
MAX_PASSWORD_LENGTH = 10
PKZIP_MODES = {17200, 17210, 17220, 17225, 17230}
DEFAULT_STATE_ROOT = (
    Path(os.environ.get("LOCALAPPDATA", Path.home())) / "hashcat-rtx2080ti"
    if os.name == "nt"
    else Path("/var/tmp/hashcat-rtx2080ti")
)
PKZIP_PATTERN = re.compile(r"(\$pkzip(?:2)?\$.*?\$/pkzip(?:2)?\$)")


@dataclass(frozen=True)
class Gpu:
    index: int
    name: str
    memory_mib: int


def local_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_session_info(session_directory: Path) -> dict[str, object]:
    information_file = session_directory / "session-info.json"
    try:
        loaded = json.loads(information_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


class SessionTracker:
    """Persist source details and the latest Hashcat status block."""

    def __init__(
        self, session_directory: Path, initial: dict[str, object] | None = None
    ) -> None:
        self.path = session_directory / "session-info.json"
        self.data = load_session_info(session_directory)
        if initial:
            self.data.update(
                {key: value for key, value in initial.items() if value is not None}
            )
        self.data.setdefault("schema_version", 1)
        self.data.setdefault("created_at", local_timestamp())
        self.progress = self.data.setdefault("progress", {})
        if not isinstance(self.progress, dict):
            self.progress = {}
            self.data["progress"] = self.progress
        self._dirty = True
        self.save()

    def save(self) -> None:
        if not self._dirty:
            return
        self.data["updated_at"] = local_timestamp()
        temporary = self.path.with_suffix(".json.tmp")
        try:
            temporary.write_text(
                json.dumps(self.data, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, self.path)
            self._dirty = False
        except OSError as error:
            print(f"warning: could not save session progress: {error}", file=sys.stderr)

    def consume(self, raw_line: str) -> None:
        line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw_line).strip()
        field = re.match(r"^([A-Za-z][A-Za-z0-9.#]*?)\.*:\s*(.*)$", line)
        if field:
            label, value = field.groups()
            key: str | None = None
            if label == "Status":
                key = "status"
            elif label == "Time.Started":
                key = "started"
            elif label == "Time.Estimated":
                key = "estimated_completion"
            elif label == "Guess.Mask":
                key = "mask"
            elif label == "Guess.Queue":
                key = "queue"
            elif label.startswith("Speed.#"):
                key = "speed"
                speed = re.search(r"([0-9.]+)\s*([kMGT]?H)/s", value)
                if speed:
                    scales = {"H": 1, "kH": 1_000, "MH": 1_000_000, "GH": 1_000_000_000, "TH": 1_000_000_000_000}
                    attempts_per_second = float(speed.group(1)) * scales[speed.group(2)]
                    self.progress["attempts_per_minute"] = round(
                        attempts_per_second * 60
                    )
            elif label == "Recovered":
                key = "recovered"
            elif label == "Progress":
                key = "display"
                progress = re.search(
                    r"([0-9,]+)/([0-9,]+)\s*\(([0-9.]+)%\)", value
                )
                if progress:
                    self.progress["attempted"] = int(
                        progress.group(1).replace(",", "")
                    )
                    self.progress["total"] = int(
                        progress.group(2).replace(",", "")
                    )
                    self.progress["percent"] = float(progress.group(3))
            elif label == "Restore.Point":
                key = "restore_point"
            elif label.startswith("Candidates.#"):
                key = "candidates"
            elif label.startswith("Hardware.Mon.#"):
                key = "hardware"
            if key:
                self.progress[key] = value
                self.progress["reported_at"] = local_timestamp()
                self._dirty = True
                if label in ("Progress",) or label.startswith("Hardware.Mon.#"):
                    self.save()
        elif line.startswith("[s]tatus"):
            self.save()

    def finish(self, return_code: int | None) -> None:
        if return_code is not None:
            self.data["last_exit_code"] = return_code
        self.data["last_exit_at"] = local_timestamp()
        self._dirty = True
        self.save()


def executable(value: str) -> str:
    if "/" in value or "\\" in value:
        path = os.path.abspath(os.path.expanduser(value))
        if os.path.isfile(path) and (os.name == "nt" or os.access(path, os.X_OK)):
            return path
    else:
        found = shutil.which(value)
        if found:
            return found
    raise SystemExit(f"error: executable not found: {value}")


def detect_gpu(nvidia_smi: str) -> Gpu:
    command = [
        nvidia_smi,
        "--query-gpu=index,name,memory.total",
        "--format=csv,noheader,nounits",
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SystemExit(f"error: nvidia-smi failed: {detail}")

    detected: list[Gpu] = []
    for line in result.stdout.splitlines():
        fields = [field.strip() for field in line.split(",", 2)]
        if len(fields) != 3:
            continue
        try:
            detected.append(Gpu(int(fields[0]), fields[1], int(fields[2])))
        except ValueError:
            continue

    matches = [gpu for gpu in detected if GPU_NAME_FRAGMENT.casefold() in gpu.name.casefold()]
    if len(matches) != 1:
        names = ", ".join(gpu.name for gpu in detected) or "none"
        raise SystemExit(
            f"error: expected exactly one {GPU_NAME_FRAGMENT}; detected: {names}"
        )

    gpu = matches[0]
    if gpu.memory_mib < MIN_VRAM_MIB:
        raise SystemExit(
            f"error: {gpu.name} reports only {gpu.memory_mib} MiB VRAM; expected the 11 GB model"
        )
    return gpu


def windows_cuda_root(override: str | None) -> Path | None:
    if os.name != "nt":
        return None
    if override:
        return Path(override).expanduser().resolve()

    configured = os.environ.get("CUDA_PATH")
    if configured:
        return Path(configured).resolve()

    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ) as key:
            configured, _ = winreg.QueryValueEx(key, "CUDA_PATH")
            return Path(configured).resolve()
    except (ImportError, OSError):
        pass

    toolkit_parent = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / (
        "NVIDIA GPU Computing Toolkit/CUDA"
    )
    versions = sorted(toolkit_parent.glob("v*"), reverse=True)
    return versions[0].resolve() if versions else None


def gpu_environment(
    gpu: Gpu, cache_path: Path, cuda_root_override: str | None
) -> dict[str, str]:
    cache_path.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["CUDA_DEVICE_ORDER"] = "PCI_BUS_ID"
    environment["CUDA_VISIBLE_DEVICES"] = str(gpu.index)
    environment["CUDA_CACHE_PATH"] = str(cache_path)
    cuda_root = windows_cuda_root(cuda_root_override)
    if cuda_root:
        runtime_paths = [cuda_root / "bin" / "x64", cuda_root / "bin"]
        environment["CUDA_PATH"] = str(cuda_root)
        environment["PATH"] = os.pathsep.join(
            [str(path) for path in runtime_paths] + [environment.get("PATH", "")]
        )
    return environment


def active_hashcat_pids() -> list[int]:
    pids: list[int] = []
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq hashcat.exe", "/FO", "CSV", "/NH"],
            text=True,
            capture_output=True,
            check=False,
        )
        for match in re.finditer(
            r'(?im)^"hashcat(?:\.exe)?","(\d+)"', result.stdout
        ):
            pids.append(int(match.group(1)))
        return sorted(pids)

    try:
        entries = os.scandir("/proc")
    except OSError:
        return pids

    with entries:
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            try:
                command = Path(f"/proc/{entry.name}/cmdline").read_bytes().split(b"\0", 1)[0]
            except OSError:
                continue
            if Path(os.fsdecode(command)).name.lower().startswith("hashcat"):
                pids.append(int(entry.name))
    return sorted(pids)


def resumable_checkpoints(state_root: Path) -> list[tuple[str, Path, float]]:
    checkpoints: list[tuple[str, Path, float]] = []
    if not state_root.is_dir():
        return checkpoints
    try:
        session_directories = list(state_root.iterdir())
    except OSError:
        return checkpoints
    for session_directory in session_directories:
        if not session_directory.is_dir():
            continue
        session = session_directory.name
        restore_file = session_directory / f"{session}.restore"
        try:
            file_status = restore_file.stat()
        except OSError:
            continue
        if file_status.st_size > 0:
            checkpoints.append((session, restore_file.resolve(), file_status.st_mtime))
    checkpoints.sort(key=lambda item: item[2], reverse=True)
    return checkpoints


def restore_snapshot(restore_file: Path) -> dict[str, object]:
    """Read the portable fields from Hashcat's 64-bit v7 restore header."""
    try:
        raw = restore_file.read_bytes()
    except OSError:
        return {}
    header_size = 296
    if len(raw) < header_size:
        return {}
    try:
        version = struct.unpack_from("<i", raw, 0)[0]
        dicts_pos, masks_pos = struct.unpack_from("<II", raw, 260)
        words_cur = struct.unpack_from("<Q", raw, 272)[0]
        argc = struct.unpack_from("<I", raw, 280)[0]
    except struct.error:
        return {}
    if not 1 <= argc <= 512:
        return {}
    arguments = raw[header_size:].decode("utf-8", errors="replace").splitlines()[:argc]
    if len(arguments) != argc:
        return {}
    return {
        "version": version,
        "dicts_pos": dicts_pos,
        "masks_pos": masks_pos,
        "words_cur": words_cur,
        "argv": arguments,
    }


def argument_value(arguments: list[str], name: str) -> str | None:
    prefix = f"--{name}="
    for index, argument in enumerate(arguments):
        if argument.startswith(prefix):
            return argument[len(prefix) :]
        if argument == f"--{name}" and index + 1 < len(arguments):
            return arguments[index + 1]
    return None


def mask_tokens(mask: str) -> list[str]:
    tokens: list[str] = []
    index = 0
    while index < len(mask):
        if mask[index] == "?" and index + 1 < len(mask):
            tokens.append(mask[index : index + 2])
            index += 2
        else:
            tokens.append(mask[index])
            index += 1
    return tokens


def restore_progress(
    snapshot: dict[str, object], hashcat: str | None = None
) -> tuple[str | None, str | None]:
    arguments = snapshot.get("argv")
    if not isinstance(arguments, list) or not all(
        isinstance(argument, str) for argument in arguments
    ):
        return None, None
    attack_mode = argument_value(arguments, "attack-mode")
    words_cur = snapshot.get("words_cur")
    masks_pos = snapshot.get("masks_pos")
    dicts_pos = snapshot.get("dicts_pos")
    if not isinstance(words_cur, int):
        return None, None

    if attack_mode == "3" and arguments:
        maximum_mask = arguments[-1]
        tokens = mask_tokens(maximum_mask)
        minimum = argument_value(arguments, "increment-min")
        if "--increment" in arguments and isinstance(masks_pos, int):
            try:
                current_length = int(minimum or "1") + masks_pos
            except ValueError:
                current_length = len(tokens)
            current_mask = "".join(tokens[: max(1, min(current_length, len(tokens)))])
        else:
            current_mask = maximum_mask

        executable_path = Path(hashcat) if hashcat else None
        keyspace_command = [str(executable_path), "--keyspace", "--attack-mode=3"]
        keyspace_command.extend(
            argument
            for argument in arguments
            if argument.startswith("--custom-charset")
        )
        keyspace_command.append(current_mask)
        try:
            if executable_path is None:
                raise OSError("trusted Hashcat executable unavailable")
            result = subprocess.run(
                keyspace_command,
                cwd=executable_path.parent,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
            keyspace = int(result.stdout.strip()) if result.returncode == 0 else 0
        except (OSError, subprocess.TimeoutExpired, ValueError):
            keyspace = 0
        if keyspace > 0:
            percent = min(100.0, words_cur * 100.0 / keyspace)
            return (
                f"{percent:.2f}% of current mask "
                f"(restore point {words_cur:,}/{keyspace:,})",
                current_mask,
            )
        return f"restore point {words_cur:,}", current_mask

    if attack_mode == "0":
        dictionary_number = dicts_pos + 1 if isinstance(dicts_pos, int) else 1
        return (
            f"restore position {words_cur:,} in dictionary {dictionary_number}",
            None,
        )
    return f"restore point {words_cur:,}", None


def preview_checkpoint(
    checkpoint: tuple[str, Path, float], hashcat: str | None = None
) -> None:
    session, restore_file, modified = checkpoint
    session_directory = restore_file.parent
    information = load_session_info(session_directory)
    snapshot = restore_snapshot(restore_file)
    arguments = snapshot.get("argv")
    argument_list = arguments if isinstance(arguments, list) else []
    attack_mode = argument_value(argument_list, "attack-mode")
    inferred_attack = {"0": "dictionary", "3": "brute force"}.get(
        attack_mode or "", "not recorded"
    )
    source = information.get("source")
    source_display = (
        str(source)
        if isinstance(source, str) and source
        else "Not recorded (checkpoint predates ZIP metadata tracking)"
    )
    progress = information.get("progress")
    progress_data = progress if isinstance(progress, dict) else {}
    attempted = progress_data.get("attempted")
    total = progress_data.get("total")
    percent = progress_data.get("percent")
    if isinstance(attempted, int) and isinstance(total, int):
        progress_display = f"{attempted:,}/{total:,}"
        if isinstance(percent, (int, float)):
            progress_display += f" ({float(percent):.2f}%)"
        current_mask = progress_data.get("mask")
    else:
        progress_display, current_mask = restore_progress(snapshot, hashcat)
        progress_display = progress_display or "Not recorded"

    saved = datetime.fromtimestamp(modified).astimezone().strftime(
        "%Y-%m-%d %I:%M:%S %p %Z"
    )
    print("\n" + "=" * 72)
    print("CHECKPOINT PREVIEW")
    print(f"Name.............: {session}")
    print(f"ZIP/source.......: {source_display}")
    print(f"Attack...........: {information.get('attack', inferred_attack)}")
    print(
        f"Hash mode........: {information.get('mode', argument_value(argument_list, 'hash-type') or 'not recorded')}"
    )
    print(f"Progress.........: {progress_display}")
    if current_mask:
        print(f"Current mask.....: {current_mask}")
    for label, key in (
        ("Queue", "queue"),
        ("Last speed", "speed"),
        ("ETA", "estimated_completion"),
        ("Status", "status"),
        ("Recovered", "recovered"),
    ):
        value = progress_data.get(key)
        if value:
            print(f"{label + '':17}: {value}")
    attempts_per_minute = progress_data.get("attempts_per_minute")
    if isinstance(attempts_per_minute, int):
        print(f"Attempts/minute..: {attempts_per_minute:,}")
    wordlist = information.get("wordlist")
    if wordlist:
        print(f"Wordlist.........: {wordlist}")
    print(f"Saved............: {saved}")
    print(f"Checkpoint file..: {restore_file}")
    print(f"Session folder...: {session_directory}")
    print("=" * 72, flush=True)


def choose_checkpoint_number(
    checkpoints: list[tuple[str, Path, float]], action: str
) -> int | None:
    try:
        selected = input(f"Checkpoint number to {action}: ").strip()
    except EOFError:
        return None
    try:
        selected_index = int(selected)
    except ValueError:
        selected_index = 0
    if 1 <= selected_index <= len(checkpoints):
        return selected_index - 1
    print("error: enter one of the displayed checkpoint numbers", file=sys.stderr)
    return None


def delete_checkpoint(
    state_root: Path,
    checkpoint: tuple[str, Path, float],
    hashcat: str | None = None,
) -> bool:
    session, restore_file, _ = checkpoint
    root = state_root.resolve()
    session_directory = restore_file.parent.resolve()
    expected = session_directory / f"{session}.restore"
    if session_directory.parent != root or restore_file.resolve() != expected:
        print("error: refusing to delete a checkpoint outside the state folder", file=sys.stderr)
        return False
    running = active_hashcat_pids()
    if running:
        print(
            "error: stop active Hashcat process(es) before deleting a checkpoint: "
            + ", ".join(str(pid) for pid in running),
            file=sys.stderr,
        )
        return False
    preview_checkpoint(checkpoint, hashcat)
    print(
        "This removes resume capability for this checkpoint. Other session files are kept.",
        flush=True,
    )
    try:
        confirmation = input(f"Type DELETE to remove '{session}': ").strip()
    except EOFError:
        confirmation = ""
    if confirmation != "DELETE":
        print("Deletion cancelled.", flush=True)
        return False
    try:
        restore_file.unlink()
        Path(str(restore_file) + ".new").unlink(missing_ok=True)
        (session_directory / "checkpoint-info.txt").unlink(missing_ok=True)
    except OSError as error:
        print(f"error: could not delete checkpoint: {error}", file=sys.stderr)
        return False
    print(f"Deleted checkpoint: {restore_file}", flush=True)
    return True


def choose_checkpoint(state_root: Path, hashcat: str | None = None) -> str | None:
    while True:
        checkpoints = resumable_checkpoints(state_root)
        if not checkpoints:
            print("No resumable checkpoints found; starting a new attack.", flush=True)
            return None
        print("Resumable checkpoints (newest first):", flush=True)
        for index, (session, restore_file, modified) in enumerate(checkpoints, 1):
            saved = datetime.fromtimestamp(modified).astimezone().strftime(
                "%Y-%m-%d %I:%M:%S %p %Z"
            )
            print(f"  {index}. {session} | saved {saved}", flush=True)
            print(f"     {restore_file}", flush=True)
        print("  0. Start a new attack", flush=True)
        print("Actions: number=resume  P=preview  D=delete  0=new", flush=True)
        try:
            selected = input("Select action [0]: ").strip()
        except EOFError as error:
            raise SystemExit(
                "error: interactive input is unavailable; use restore SESSION_NAME"
            ) from error
        if selected in ("", "0") or selected.casefold() in ("n", "new"):
            return None
        if selected.casefold() in ("p", "preview"):
            selected_index = choose_checkpoint_number(checkpoints, "preview")
            if selected_index is not None:
                preview_checkpoint(checkpoints[selected_index], hashcat)
            continue
        if selected.casefold() in ("d", "delete"):
            selected_index = choose_checkpoint_number(checkpoints, "delete")
            if selected_index is not None:
                delete_checkpoint(state_root, checkpoints[selected_index], hashcat)
            continue
        try:
            selected_index = int(selected)
        except ValueError:
            selected_index = 0
        if 1 <= selected_index <= len(checkpoints):
            return checkpoints[selected_index - 1][0]
        print("error: enter a checkpoint number, P, D, or 0", file=sys.stderr)


def default_session_name(state_root: Path) -> str:
    base = datetime.now().strftime("pkzip_%Y-%m-%d_%H-%M-%S")
    candidate = base
    suffix = 2
    while (state_root / candidate).exists():
        candidate = f"{base}_{suffix}"
        suffix += 1
    return candidate


def choose_session_name(state_root: Path) -> str:
    default = default_session_name(state_root)
    while True:
        try:
            entered = input(f"Checkpoint name [{default}]: ").strip()
        except EOFError as error:
            raise SystemExit(
                "error: interactive input is unavailable; provide --session SESSION_NAME"
            ) from error
        candidate = entered or default
        try:
            candidate = validate_session(candidate)
        except argparse.ArgumentTypeError as error:
            print(f"error: {error}", file=sys.stderr)
            continue
        if (state_root / candidate).exists():
            print(
                f"error: that checkpoint/session name already exists: {candidate}",
                file=sys.stderr,
            )
            continue
        return candidate


def extract_pkzip_hash(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise SystemExit(f"error: hash input does not exist: {source}")

    try:
        with source.open("r", encoding="utf-8", errors="replace") as input_file:
            for line in input_file:
                match = PKZIP_PATTERN.search(line)
                if match:
                    destination.write_text(match.group(1) + "\n", encoding="ascii")
                    os.chmod(destination, 0o600)
                    return
    except OSError as error:
        raise SystemExit(f"error: cannot read {source}: {error}") from error

    raise SystemExit(f"error: no $pkzip$ or $pkzip2$ record found in {source}")


def choose_source_path(provided: str | None) -> Path:
    if provided is None:
        try:
            provided = input("ZIP archive or PKZIP hash-file path: ").strip()
        except EOFError as error:
            raise SystemExit(
                "error: interactive input is unavailable; provide a ZIP/hash path"
            ) from error

    provided = provided.strip()
    if len(provided) >= 2 and provided[0] == provided[-1] and provided[0] in "\"'":
        provided = provided[1:-1]
    source = Path(os.path.expandvars(provided)).expanduser().resolve()

    if source.is_dir():
        archives = sorted(
            (path for path in source.glob("*.zip") if path.is_file()),
            key=lambda path: path.name.casefold(),
        )
        if not archives:
            raise SystemExit(f"error: no ZIP files found directly in directory: {source}")
        if len(archives) == 1:
            source = archives[0]
            print(f"Using the only ZIP in that directory: {source}", flush=True)
        else:
            print("ZIP files found:", flush=True)
            for index, archive in enumerate(archives, 1):
                print(f"  {index}. {archive.name}", flush=True)
            while True:
                try:
                    selected = input(f"Select ZIP (1-{len(archives)}): ").strip()
                    selected_index = int(selected)
                    if 1 <= selected_index <= len(archives):
                        source = archives[selected_index - 1]
                        break
                except (EOFError, ValueError):
                    pass
                print("error: enter one of the displayed numbers", file=sys.stderr)

    if not source.is_file():
        raise SystemExit(f"error: input file does not exist: {source}")
    return source


def choose_attack(provided: str | None) -> str:
    if provided is not None:
        return provided
    print("Attack method:", flush=True)
    print("  1. Dictionary", flush=True)
    print("  2. Brute force", flush=True)
    choices = {
        "1": "dictionary",
        "d": "dictionary",
        "dictionary": "dictionary",
        "2": "brute",
        "b": "brute",
        "brute": "brute",
        "bruteforce": "brute",
        "brute-force": "brute",
    }
    while True:
        try:
            selected = input("Select attack (1-2): ").strip().casefold()
        except EOFError as error:
            raise SystemExit(
                "error: interactive input is unavailable; provide --attack"
            ) from error
        attack = choices.get(selected)
        if attack:
            return attack
        print("error: enter 1 for dictionary or 2 for brute force", file=sys.stderr)


def choose_wordlist_path(provided: str | None) -> Path:
    if provided is None:
        try:
            provided = input("Wordlist file or directory path: ").strip()
        except EOFError as error:
            raise SystemExit(
                "error: interactive input is unavailable; provide --wordlist"
            ) from error

    provided = provided.strip()
    if len(provided) >= 2 and provided[0] == provided[-1] and provided[0] in "\"'":
        provided = provided[1:-1]
    wordlist = Path(os.path.expandvars(provided)).expanduser().resolve()

    if wordlist.is_dir():
        preferred_suffixes = {".txt", ".dict", ".dic", ".lst", ".wordlist", ".gz"}
        all_files = sorted(
            (path for path in wordlist.iterdir() if path.is_file()),
            key=lambda path: path.name.casefold(),
        )
        preferred = [path for path in all_files if path.suffix.casefold() in preferred_suffixes]
        files = preferred or all_files
        if not files:
            raise SystemExit(f"error: no wordlist files found in directory: {wordlist}")
        if len(files) == 1:
            wordlist = files[0]
            print(f"Using the only wordlist in that directory: {wordlist}", flush=True)
        else:
            print("Wordlist files found:", flush=True)
            for index, path in enumerate(files, 1):
                print(f"  {index}. {path.name}", flush=True)
            while True:
                try:
                    selected = input(f"Select wordlist (1-{len(files)}): ").strip()
                    selected_index = int(selected)
                    if 1 <= selected_index <= len(files):
                        wordlist = files[selected_index - 1]
                        break
                except (EOFError, ValueError):
                    pass
                print("error: enter one of the displayed numbers", file=sys.stderr)

    if not wordlist.is_file():
        raise SystemExit(f"error: wordlist file does not exist: {wordlist}")
    if wordlist.stat().st_size == 0:
        raise SystemExit(f"error: wordlist file is empty: {wordlist}")
    return wordlist


def extract_pkzip_from_archive(
    archive: Path, destination: Path, zip2john: str, log_file: Path
) -> int:
    try:
        with ZipFile(archive) as zip_file:
            candidates = [
                member
                for member in zip_file.infolist()
                if member.flag_bits & 1
                and not member.is_dir()
                and member.file_size > 0
                and member.compress_type in (ZIP_DEFLATED, ZIP_STORED)
            ]
    except (BadZipFile, OSError) as error:
        raise SystemExit(f"error: cannot read ZIP metadata from {archive}: {error}") from error

    if not candidates:
        raise SystemExit(
            "error: no traditionally encrypted stored/deflated members were found; "
            "AES-encrypted ZIPs are not supported by PKZIP modes 17200/17210"
        )

    def member_priority(member: object) -> tuple[int, int, str]:
        is_deflated = member.compress_type == ZIP_DEFLATED
        large_enough = member.compress_size >= 32
        if is_deflated and large_enough:
            group = 0
        elif not is_deflated and large_enough:
            group = 1
        elif is_deflated:
            group = 2
        else:
            group = 3
        return group, member.compress_size, member.filename.casefold()

    diagnostics: list[str] = []
    for member in sorted(candidates, key=member_priority)[:25]:
        result = subprocess.run(
            [zip2john, "-o", member.filename, str(archive)],
            cwd=Path(zip2john).parent,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        output = result.stdout + "\n" + result.stderr
        match = PKZIP_PATTERN.search(output)
        diagnostics.append(
            f"member={member.filename!r} returncode={result.returncode}\n{result.stderr}"
        )
        if not match:
            continue

        destination.write_text(match.group(1) + "\n", encoding="ascii")
        os.chmod(destination, 0o600)
        log_file.write_text("\n\n".join(diagnostics), encoding="utf-8")
        mode = 17200 if member.compress_type == ZIP_DEFLATED else 17210
        print(
            f"Selected encrypted member={member.filename!r} "
            f"compressed_bytes={member.compress_size} mode={mode}",
            flush=True,
        )
        return mode

    log_file.write_text("\n\n".join(diagnostics), encoding="utf-8")
    raise SystemExit(
        f"error: zip2john could not create a usable PKZIP record; see {log_file}"
    )


def identify_mode(hashcat: str, hash_file: Path, environment: dict[str, str]) -> int:
    result = subprocess.run(
        [hashcat, "--identify", str(hash_file)],
        cwd=Path(hashcat).parent if os.name == "nt" else hash_file.parent,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    output = result.stdout + "\n" + result.stderr
    modes = {
        int(match.group(1))
        for match in re.finditer(r"(?m)^\s*(172(?:00|10|20|25|30))\s+\|", output)
    }
    modes &= PKZIP_MODES
    if len(modes) == 1:
        return modes.pop()
    if not modes:
        detail = "\n".join(line for line in output.strip().splitlines()[-12:])
        raise SystemExit(
            "error: Hashcat could not identify a supported PKZIP mode. "
            "Use --mode only after confirming the archive variant.\n" + detail
        )
    choices = ", ".join(str(mode) for mode in sorted(modes))
    raise SystemExit(f"error: multiple PKZIP modes matched ({choices}); select one with --mode")


def validate_session(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise argparse.ArgumentTypeError(
            "session may contain only letters, digits, dot, underscore, and dash"
        )
    return value


def length(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("length must be an integer") from error
    if not 1 <= parsed <= MAX_PASSWORD_LENGTH:
        raise argparse.ArgumentTypeError(
            f"maximum length must be between 1 and {MAX_PASSWORD_LENGTH}"
        )
    return parsed


def choose_max_length(provided: int | None) -> int:
    if provided is not None:
        return provided
    while True:
        try:
            entered = input(
                f"Maximum password length to try (1-{MAX_PASSWORD_LENGTH}): "
            ).strip()
        except EOFError as error:
            raise SystemExit(
                "error: interactive input is unavailable; provide --max-length 1-10"
            ) from error
        try:
            return length(entered)
        except argparse.ArgumentTypeError as error:
            print(f"error: {error}", file=sys.stderr, flush=True)


def status_interval(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("status interval must be an integer") from error
    if parsed < 10:
        raise argparse.ArgumentTypeError("status interval must be at least 10 seconds")
    return parsed


def mask_arguments(charset: str, maximum_length: int) -> tuple[list[str], str]:
    if charset == "ascii":
        token = "?a"
        options: list[str] = []
    elif charset == "lower":
        token = "?l"
        options = []
    elif charset == "digits":
        token = "?d"
        options = []
    else:
        token = "?1"
        options = ["--custom-charset1=?l?u?d"]
    return options, token * maximum_length


def common_preflight(arguments: argparse.Namespace) -> tuple[str, Gpu, dict[str, str]]:
    hashcat = executable(arguments.hashcat)
    nvidia_smi = executable(arguments.nvidia_smi)
    gpu = detect_gpu(nvidia_smi)
    state_root = Path(arguments.state_root).expanduser().resolve()
    environment = gpu_environment(gpu, state_root / "cuda-cache", arguments.cuda_root)
    return hashcat, gpu, environment


def launch(
    command: list[str],
    environment: dict[str, str],
    windows_workdir: Path,
    monitor_escape: bool = False,
    line_handler: Callable[[str], None] | None = None,
) -> int:
    """Replace this process on POSIX; use a normal child process on Windows."""
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if monitor_escape else 0
        process = subprocess.Popen(
            command,
            cwd=windows_workdir,
            env=environment,
            stdin=None,
            stdout=subprocess.PIPE if line_handler else None,
            stderr=subprocess.STDOUT if line_handler else None,
            text=bool(line_handler),
            encoding="utf-8" if line_handler else None,
            errors="replace" if line_handler else None,
            bufsize=1 if line_handler else -1,
            creationflags=creationflags,
        )
        output_thread: threading.Thread | None = None
        if line_handler and process.stdout:
            def forward_output() -> None:
                for line in process.stdout:
                    print(line, end="", flush=True)
                    line_handler(line.rstrip("\r\n"))

            output_thread = threading.Thread(target=forward_output, daemon=True)
            output_thread.start()

        def wait_for_process(timeout: float | None = None) -> int:
            return_code = process.wait(timeout=timeout)
            if output_thread:
                output_thread.join(timeout=5)
            return return_code

        if not monitor_escape or not sys.stdin.isatty():
            return wait_for_process()

        import ctypes

        get_key_state = ctypes.windll.user32.GetAsyncKeyState
        escape_vk = 0x1B
        hashcat_control_vks = tuple(ord(key) for key in "SPBCFQR") + (0x0D,)
        escape_was_down = bool(get_key_state(escape_vk) & 0x8000)
        controls_were_down = {
            key: bool(get_key_state(key) & 0x8000) for key in hashcat_control_vks
        }

        escape_armed = False
        while process.poll() is None:
            escape_down = bool(get_key_state(escape_vk) & 0x8000)
            escape_pressed = escape_down and not escape_was_down
            controls_down = {
                key: bool(get_key_state(key) & 0x8000)
                for key in hashcat_control_vks
            }
            control_pressed = any(
                controls_down[key] and not controls_were_down[key]
                for key in hashcat_control_vks
            )

            if escape_pressed:
                if not escape_armed:
                    escape_armed = True
                    print(
                        "\nSTOP ARMED: press Esc once more to terminate Hashcat. "
                        "Native s/p/r/b/c/f/q controls remain active.",
                        flush=True,
                    )
                else:
                    print(
                        "\nStopping Hashcat and preserving its restore checkpoint...",
                        flush=True,
                    )
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                    try:
                        return wait_for_process(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        return wait_for_process()
            elif escape_armed and control_pressed:
                    escape_armed = False
                    print(
                        "\nDouble-Esc stop cancelled; Hashcat command forwarded.",
                        flush=True,
                    )

            escape_was_down = escape_down
            controls_were_down = controls_down
            time.sleep(0.05)
        return wait_for_process()
    os.execvpe(command[0], command, environment)
    return 127


def show_recovered(result_file: Path) -> None:
    if not result_file.is_file() or result_file.stat().st_size == 0:
        return
    recovered = result_file.read_bytes().splitlines()
    print("\n" + "=" * 72)
    print("PASSWORD FOUND")
    for password in recovered:
        print(password.decode("utf-8", errors="backslashreplace"))
    print("=" * 72, flush=True)
    if sys.stdin.isatty():
        try:
            input("Press Enter to close...")
        except EOFError:
            pass


def show_checkpoint(session: str, restore_file: Path) -> None:
    """Print and persist everything needed to resume a stopped session."""
    checkpoint = restore_file.resolve()
    resume_command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "restore",
        session,
    ]
    formatted_command = (
        subprocess.list2cmdline(resume_command)
        if os.name == "nt"
        else shlex.join(resume_command)
    )
    ready = checkpoint.is_file() and checkpoint.stat().st_size > 0
    status = "ready" if ready else "not present"
    information_file = checkpoint.parent / "checkpoint-info.txt"
    information = (
        f"session={session}\n"
        f"status={status}\n"
        f"checkpoint={checkpoint}\n"
        f"resume_command={formatted_command}\n"
    )
    try:
        information_file.write_text(information, encoding="utf-8")
    except OSError as error:
        print(f"warning: could not write checkpoint details: {error}", file=sys.stderr)

    print("\n" + "=" * 72)
    print("CHECKPOINT READY" if ready else "NO RESUMABLE CHECKPOINT")
    print(f"Checkpoint file: {checkpoint}")
    print(f"Checkpoint details: {information_file}")
    if ready:
        print(f"Resume command: {formatted_command}")
    else:
        print("The attack completed, recovered the password, or exited before Hashcat saved a checkpoint.")
    print("=" * 72, flush=True)


def start_command(arguments: argparse.Namespace) -> int:
    state_root = Path(arguments.state_root).expanduser().resolve()
    if arguments.source is None and arguments.session is None and sys.stdin.isatty():
        try:
            preview_hashcat = executable(arguments.hashcat)
        except SystemExit:
            preview_hashcat = None
        checkpoint = choose_checkpoint(state_root, preview_hashcat)
        if checkpoint is not None:
            arguments.session = checkpoint
            return restore_command(arguments)
        arguments.session = choose_session_name(state_root)

    source = choose_source_path(arguments.source)
    attack = choose_attack(arguments.attack)
    maximum_length: int | None = None
    wordlist: Path | None = None
    if attack == "brute":
        if arguments.wordlist:
            raise SystemExit("error: --wordlist is only valid with --attack dictionary")
        maximum_length = choose_max_length(arguments.max_length)
    else:
        if arguments.max_length is not None:
            raise SystemExit("error: --max-length is only valid with --attack brute")
        wordlist = choose_wordlist_path(arguments.wordlist)
    hashcat, gpu, environment = common_preflight(arguments)
    running = active_hashcat_pids()
    if running:
        raise SystemExit(
            "error: refusing to contend with active Hashcat process(es): "
            + ", ".join(str(pid) for pid in running)
        )
    session = arguments.session or default_session_name(state_root)
    session_directory = state_root / session
    try:
        session_directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    except FileExistsError as error:
        raise SystemExit(
            f"error: session already exists: {session}; use restore or choose another name"
        ) from error

    extracted_hash = session_directory / "pkzip.hash"
    inferred_mode: int | None = None
    if source.suffix.casefold() == ".zip":
        zip2john = executable(arguments.zip2john)
        inferred_mode = extract_pkzip_from_archive(
            source, extracted_hash, zip2john, session_directory / "zip2john.log"
        )
    else:
        extract_pkzip_hash(source, extracted_hash)

    if arguments.mode and inferred_mode and arguments.mode != inferred_mode:
        raise SystemExit(
            f"error: --mode {arguments.mode} conflicts with archive member mode {inferred_mode}"
        )
    mode = arguments.mode or inferred_mode or identify_mode(hashcat, extracted_hash, environment)
    if mode not in PKZIP_MODES:
        raise SystemExit(f"error: unsupported PKZIP mode: {mode}")

    result_file = session_directory / "recovered.txt"
    pot_file = state_root / "pkzip.potfile"
    restore_file = session_directory / f"{session}.restore"

    if attack == "brute":
        assert maximum_length is not None
        custom_charset, mask = mask_arguments(arguments.charset, maximum_length)
        attack_arguments = [
            "--attack-mode=3",
            "--increment",
            "--increment-min=1",
            f"--increment-max={maximum_length}",
            *custom_charset,
            str(extracted_hash),
            mask,
        ]
        attack_description = (
            f"attack=brute charset={arguments.charset} lengths=1-{maximum_length}"
        )
    else:
        assert wordlist is not None
        attack_arguments = ["--attack-mode=0", str(extracted_hash), str(wordlist)]
        attack_description = f"attack=dictionary wordlist={wordlist}"

    command = [
        hashcat,
        f"--hash-type={mode}",
        "--optimized-kernel-enable",
        "--workload-profile=4",
        "--backend-ignore-opencl",
        "--backend-devices=1",
        "--status",
        f"--status-timer={arguments.status_interval}",
        f"--session={session}",
        f"--restore-file-path={restore_file}",
        f"--potfile-path={pot_file}",
        f"--outfile={result_file}",
        "--outfile-format=2",
        "--hwmon-temp-abort=88",
        *attack_arguments,
    ]
    tracker = SessionTracker(
        session_directory,
        {
            "session": session,
            "source": str(source),
            "attack": attack,
            "mode": mode,
            "charset": arguments.charset if attack == "brute" else None,
            "maximum_length": maximum_length,
            "wordlist": str(wordlist) if wordlist else None,
            "checkpoint_file": str(restore_file),
        },
    )

    if os.name != "nt":
        os.chdir(session_directory)
    print(
        f"GPU={gpu.name} index={gpu.index} VRAM={gpu.memory_mib}MiB mode={mode} "
        f"{attack_description}",
        flush=True,
    )
    print(f"session={session} state={session_directory}", flush=True)
    print(f"source={source}", flush=True)
    print(f"command={shlex.join(command)}", flush=True)
    print(
        f"Hashcat will print exact progress, speed, GPU utilization, and temperature every "
        f"{arguments.status_interval} seconds.",
        flush=True,
    )
    return_code: int | None = None
    try:
        return_code = launch(
            command,
            environment,
            Path(hashcat).parent,
            monitor_escape=True,
            line_handler=tracker.consume,
        )
    finally:
        tracker.finish(return_code)
        show_checkpoint(session, restore_file)
    show_recovered(result_file)
    return return_code


def restore_command(arguments: argparse.Namespace) -> int:
    hashcat, gpu, environment = common_preflight(arguments)
    running = active_hashcat_pids()
    if running:
        raise SystemExit(
            "error: refusing to contend with active Hashcat process(es): "
            + ", ".join(str(pid) for pid in running)
        )

    session_directory = Path(arguments.state_root).expanduser().resolve() / arguments.session
    restore_file = session_directory / f"{arguments.session}.restore"
    if not restore_file.is_file():
        raise SystemExit(f"error: restore file does not exist: {restore_file}")

    command = [
        hashcat,
        f"--session={arguments.session}",
        f"--restore-file-path={restore_file}",
        "--restore",
    ]
    tracker = SessionTracker(
        session_directory,
        {
            "session": arguments.session,
            "checkpoint_file": str(restore_file),
            "last_resumed_at": local_timestamp(),
        },
    )
    if os.name != "nt":
        os.chdir(session_directory)
    print(f"GPU={gpu.name} restoring={arguments.session}", flush=True)
    return_code: int | None = None
    try:
        return_code = launch(
            command,
            environment,
            Path(hashcat).parent,
            monitor_escape=True,
            line_handler=tracker.consume,
        )
    finally:
        tracker.finish(return_code)
        show_checkpoint(arguments.session, restore_file)
    show_recovered(session_directory / "recovered.txt")
    return return_code


def benchmark_command(arguments: argparse.Namespace) -> int:
    hashcat, gpu, environment = common_preflight(arguments)
    running = active_hashcat_pids()
    if running:
        raise SystemExit(
            "error: refusing to benchmark beside active Hashcat process(es): "
            + ", ".join(str(pid) for pid in running)
        )

    command = [
        hashcat,
        "--benchmark",
        f"--hash-type={arguments.mode}",
        "--optimized-kernel-enable",
        "--workload-profile=4",
        "--backend-ignore-opencl",
        "--backend-devices=1",
    ]
    print(f"GPU={gpu.name} benchmark_mode={arguments.mode}", flush=True)
    return launch(command, environment, Path(hashcat).parent)


def add_runtime_options(parser: argparse.ArgumentParser) -> None:
    bundled_hashcat = Path.home() / "Tools/hashcat-7.1.2/hashcat.exe"
    system_nvidia_smi = Path(
        os.environ.get("SystemRoot", r"C:\Windows")
    ) / "System32/nvidia-smi.exe"
    parser.add_argument(
        "--hashcat",
        default=os.environ.get(
            "HASHCAT_BIN",
            str(bundled_hashcat) if bundled_hashcat.is_file() else "hashcat",
        ),
    )
    parser.add_argument(
        "--nvidia-smi",
        default=os.environ.get(
            "NVIDIA_SMI",
            str(system_nvidia_smi) if system_nvidia_smi.is_file() else "nvidia-smi",
        ),
    )
    parser.add_argument("--state-root", default=str(DEFAULT_STATE_ROOT))
    parser.add_argument(
        "--cuda-root",
        help="CUDA Toolkit root (auto-detected from Windows system configuration)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Drive one 11 GB RTX 2080 Ti at maximum Hashcat PKZIP throughput."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    start = commands.add_parser("start", help="start a dictionary or brute-force attack")
    start.add_argument(
        "source",
        nargs="?",
        help="ZIP archive, directory containing ZIPs, or PKZIP hash file (prompted when omitted)",
    )
    start.add_argument("--charset", choices=("ascii", "alnum", "lower", "digits"), default="ascii")
    start.add_argument(
        "--attack",
        choices=("dictionary", "brute"),
        help="attack method (prompted when omitted)",
    )
    start.add_argument(
        "--wordlist",
        help="wordlist file/directory for a dictionary attack (prompted when omitted)",
    )
    start.add_argument(
        "--max-length",
        type=length,
        help="maximum length to try, 1-10 (prompted when omitted; always starts at 1)",
    )
    start.add_argument("--mode", type=int, choices=sorted(PKZIP_MODES))
    bundled_zip2john = Path.home() / "Tools/john-1.9.0-jumbo-1-win64/run/zip2john.exe"
    start.add_argument(
        "--zip2john",
        default=os.environ.get(
            "ZIP2JOHN_BIN",
            str(bundled_zip2john) if bundled_zip2john.is_file() else "zip2john",
        ),
        help="zip2john executable used when source is a ZIP archive",
    )
    start.add_argument("--session", type=validate_session)
    start.add_argument(
        "--status-interval",
        type=status_interval,
        default=10,
        help="seconds between live aggregate speed/progress updates (default: 10)",
    )
    add_runtime_options(start)
    start.set_defaults(handler=start_command)

    restore = commands.add_parser("restore", help="resume an existing Hashcat session")
    restore.add_argument("session", type=validate_session)
    add_runtime_options(restore)
    restore.set_defaults(handler=restore_command)

    benchmark = commands.add_parser("benchmark", help="benchmark one PKZIP mode")
    benchmark.add_argument("--mode", type=int, choices=sorted(PKZIP_MODES), default=17220)
    add_runtime_options(benchmark)
    benchmark.set_defaults(handler=benchmark_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    command_line = list(sys.argv[1:] if argv is None else argv)
    if not command_line:
        command_line = ["start"]
    arguments = parser.parse_args(command_line)
    return arguments.handler(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
