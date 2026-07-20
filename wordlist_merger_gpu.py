#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Interactive TXT wordlist merger with optional CUDA deduplication.

The exact-combine path is intentionally disk/CPU buffered because a GPU cannot
accelerate filesystem reads or writes.  The dedupe path sends line batches to a
small native CUDA helper for 128-bit hashing on the selected NVIDIA GPU.
"""

from __future__ import annotations

from array import array
import ctypes
from dataclasses import dataclass
from datetime import datetime
import faulthandler
import hashlib
import os
from pathlib import Path
import platform
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from typing import Callable, Protocol, Sequence
import uuid


DEFAULT_DIRECTORY = Path.home() / "Downloads" / "lists"
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
CUDA_HELPER = SCRIPT_DIRECTORY / "wordlist_gpu_hash.dll"
CRASH_LOG = SCRIPT_DIRECTORY / "wordlist_merger_crash.log"
GPU_NAME_FRAGMENT = "RTX 2080 Ti"
MIN_GPU_MEMORY_MIB = 10_000
COPY_BUFFER_BYTES = 16 * 1024 * 1024
GPU_BATCH_BYTES = 32 * 1024 * 1024
GPU_BATCH_LINES = 1_000_000
PROGRESS_GRANULARITY = 1024 * 1024


_FAULT_STREAM: object | None = None


def install_crash_logging() -> None:
    """Enable a persistent traceback for Python and native-level failures."""
    global _FAULT_STREAM
    try:
        _FAULT_STREAM = CRASH_LOG.open("a", encoding="utf-8", buffering=1)
        _FAULT_STREAM.write(
            f"\n[{datetime.now().astimezone().isoformat(timespec='seconds')}] "
            f"Starting wordlist merger with {sys.executable}\n"
        )
        faulthandler.enable(file=_FAULT_STREAM, all_threads=True)
    except OSError:
        _FAULT_STREAM = None


def record_exception(
    exception_type: type[BaseException],
    exception: BaseException,
    trace: object,
    context: str,
) -> None:
    """Append enough context to diagnose an otherwise hidden GUI failure."""
    lines = [
        "",
        "=" * 78,
        f"Time: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"Context: {context}",
        f"Python: {sys.version}",
        f"Executable: {sys.executable}",
        f"Platform: {platform.platform()}",
        f"Arguments: {sys.argv!r}",
        "Traceback:",
        "".join(traceback.format_exception(exception_type, exception, trace)).rstrip(),
        "=" * 78,
        "",
    ]
    report = "\n".join(lines)
    try:
        with CRASH_LOG.open("a", encoding="utf-8") as log_file:
            log_file.write(report)
    except OSError:
        pass
    try:
        if sys.stderr is not None:
            sys.stderr.write(report)
            sys.stderr.flush()
    except OSError:
        pass


def show_fatal_error(message: str) -> None:
    """Show a useful error even when launched with pythonw and no console."""
    if os.name != "nt":
        return
    try:
        ctypes.windll.user32.MessageBoxW(
            0,
            f"{message}\n\nCrash log:\n{CRASH_LOG}",
            "Wordlist Merger failed",
            0x10,
        )
    except Exception:
        pass


class MergeCancelled(Exception):
    """Raised internally after the user requests cancellation."""


@dataclass(frozen=True)
class ListedFile:
    path: Path
    size: int
    modified: float


@dataclass(frozen=True)
class GpuStatus:
    index: int
    name: str
    memory_mib: int
    utilization: int | None = None
    memory_used_mib: int | None = None


@dataclass(frozen=True)
class MergeResult:
    output: Path
    input_files: int
    input_bytes: int
    output_bytes: int
    elapsed_seconds: float
    backend: str
    input_lines: int | None = None
    output_lines: int | None = None
    duplicate_lines: int | None = None
    blank_lines_skipped: int | None = None


ProgressCallback = Callable[[int, int, str], None]


def human_size(value: int) -> str:
    size = float(value)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0 or suffix == "TiB":
            return f"{size:.0f} {suffix}" if suffix == "B" else f"{size:.1f} {suffix}"
        size /= 1024.0
    return f"{value} B"


def human_rate(byte_count: int, seconds: float) -> str:
    if seconds <= 0:
        return "0 B/s"
    return f"{human_size(int(byte_count / seconds))}/s"


def nvidia_smi_path() -> str:
    system_path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/nvidia-smi.exe"
    return str(system_path) if system_path.is_file() else "nvidia-smi"


def detect_rtx_2080_ti() -> GpuStatus:
    command = [
        nvidia_smi_path(),
        "--query-gpu=index,name,memory.total,utilization.gpu,memory.used",
        "--format=csv,noheader,nounits",
    ]
    result = subprocess.run(
        command,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "nvidia-smi failed"
        raise RuntimeError(detail)

    detected: list[GpuStatus] = []
    for line in result.stdout.splitlines():
        fields = [field.strip() for field in line.split(",")]
        if len(fields) != 5:
            continue
        try:
            detected.append(
                GpuStatus(
                    index=int(fields[0]),
                    name=fields[1],
                    memory_mib=int(fields[2]),
                    utilization=int(fields[3]),
                    memory_used_mib=int(fields[4]),
                )
            )
        except ValueError:
            continue

    matches = [gpu for gpu in detected if GPU_NAME_FRAGMENT.casefold() in gpu.name.casefold()]
    if len(matches) != 1:
        names = ", ".join(gpu.name for gpu in detected) or "none"
        raise RuntimeError(f"Expected one {GPU_NAME_FRAGMENT}; detected: {names}")
    gpu = matches[0]
    if gpu.memory_mib < MIN_GPU_MEMORY_MIB:
        raise RuntimeError(
            f"{gpu.name} reports {gpu.memory_mib} MiB VRAM; the 11 GB card was expected"
        )
    return gpu


def active_hashcat_pids() -> list[int]:
    if os.name != "nt":
        return []
    result = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq hashcat.exe", "/FO", "CSV", "/NH"],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    pids: list[int] = []
    for line in result.stdout.splitlines():
        fields = [field.strip().strip('"') for field in line.split(",")]
        if len(fields) >= 2 and fields[0].casefold() == "hashcat.exe":
            try:
                pids.append(int(fields[1]))
            except ValueError:
                pass
    return sorted(pids)


class BatchHasher(Protocol):
    name: str

    def hash_lines(
        self, payload: bytearray, offsets: array, lengths: array
    ) -> tuple[array, array]: ...

    def close(self) -> None: ...


class CudaLineHasher:
    """ctypes wrapper around the native CUDA batch-hashing helper."""

    def __init__(self, helper: Path, device_index: int) -> None:
        if os.name != "nt":
            raise RuntimeError("The bundled CUDA helper was built for Windows")
        if not helper.is_file():
            raise RuntimeError(f"CUDA helper is missing: {helper}")

        os.environ.setdefault("CUDA_DEVICE_ORDER", "PCI_BUS_ID")
        self._library = ctypes.CDLL(str(helper))
        self._device_index = device_index
        self._closed = False

        self._library.gpu_info.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        self._library.gpu_info.restype = ctypes.c_int
        self._library.gpu_hash_lines.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        self._library.gpu_hash_lines.restype = ctypes.c_int
        self._library.gpu_release.argtypes = []
        self._library.gpu_release.restype = None

        gpu_name = ctypes.create_string_buffer(256)
        error = ctypes.create_string_buffer(1024)
        memory = ctypes.c_uint64()
        result = self._library.gpu_info(
            device_index,
            gpu_name,
            len(gpu_name),
            ctypes.byref(memory),
            error,
            len(error),
        )
        if result != 0:
            raise RuntimeError(self._error_text(error, result))
        decoded_name = gpu_name.value.decode("utf-8", errors="replace")
        if GPU_NAME_FRAGMENT.casefold() not in decoded_name.casefold():
            raise RuntimeError(f"CUDA device {device_index} is {decoded_name}, not {GPU_NAME_FRAGMENT}")
        if memory.value < MIN_GPU_MEMORY_MIB * 1024 * 1024:
            raise RuntimeError(f"CUDA reports insufficient VRAM for {decoded_name}")
        self.name = f"CUDA 128-bit dedupe on {decoded_name}"

    @staticmethod
    def _error_text(error: ctypes.Array[ctypes.c_char], code: int) -> str:
        detail = error.value.decode("utf-8", errors="replace").strip()
        return f"CUDA helper error {code}: {detail or 'unknown error'}"

    def hash_lines(
        self, payload: bytearray, offsets: array, lengths: array
    ) -> tuple[array, array]:
        count = len(offsets)
        if count != len(lengths):
            raise ValueError("offset and length counts do not match")
        if count == 0:
            return array("Q"), array("Q")
        if offsets.itemsize != 8 or lengths.itemsize != 4:
            raise RuntimeError("This Python build uses unexpected native array widths")

        data_buffer = payload if payload else bytearray(1)
        hash_a = array("Q", [0]) * count
        hash_b = array("Q", [0]) * count
        data_view = (ctypes.c_ubyte * len(data_buffer)).from_buffer(data_buffer)
        offset_view = (ctypes.c_uint64 * count).from_buffer(offsets)
        length_view = (ctypes.c_uint32 * count).from_buffer(lengths)
        hash_a_view = (ctypes.c_uint64 * count).from_buffer(hash_a)
        hash_b_view = (ctypes.c_uint64 * count).from_buffer(hash_b)
        error = ctypes.create_string_buffer(1024)

        result = self._library.gpu_hash_lines(
            self._device_index,
            data_view,
            len(payload),
            offset_view,
            length_view,
            count,
            hash_a_view,
            hash_b_view,
            error,
            len(error),
        )
        if result != 0:
            raise RuntimeError(self._error_text(error, result))
        return hash_a, hash_b

    def close(self) -> None:
        if not self._closed:
            self._library.gpu_release()
            self._closed = True


class CpuTestHasher:
    """Deterministic test backend; the GUI's GPU mode never silently uses it."""

    name = "CPU BLAKE2 self-test"

    def hash_lines(
        self, payload: bytearray, offsets: array, lengths: array
    ) -> tuple[array, array]:
        first = array("Q")
        second = array("Q")
        view = memoryview(payload)
        try:
            for offset, length in zip(offsets, lengths):
                digest = hashlib.blake2b(view[offset : offset + length], digest_size=16).digest()
                first.append(int.from_bytes(digest[:8], "little"))
                second.append(int.from_bytes(digest[8:], "little"))
        finally:
            view.release()
        return first, second

    def close(self) -> None:
        return


class ProgressReporter:
    def __init__(self, total: int, callback: ProgressCallback) -> None:
        self.total = total
        self.callback = callback
        self.completed = 0
        self.started = time.perf_counter()
        self.last_report = 0.0

    def add(self, amount: int, detail: str, force: bool = False) -> None:
        self.completed += amount
        now = time.perf_counter()
        if force or now - self.last_report >= 0.10 or self.completed >= self.total:
            self.callback(min(self.completed, self.total), self.total, detail)
            self.last_report = now


def check_cancel(cancel_event: threading.Event) -> None:
    if cancel_event.is_set():
        raise MergeCancelled("Merge cancelled")


def temporary_output_path(destination: Path) -> Path:
    return destination.with_name(f".{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.partial")


def merge_exact(
    sources: Sequence[Path],
    destination: Path,
    cancel_event: threading.Event,
    progress: ProgressCallback,
) -> MergeResult:
    total_bytes = sum(path.stat().st_size for path in sources)
    reporter = ProgressReporter(total_bytes, progress)
    temporary = temporary_output_path(destination)
    started = time.perf_counter()
    buffer = bytearray(COPY_BUFFER_BYTES)
    wrote_anything = False
    last_byte = b""

    try:
        with temporary.open("xb", buffering=COPY_BUFFER_BYTES) as output:
            for source in sources:
                check_cancel(cancel_event)
                first_chunk = True
                with source.open("rb", buffering=0) as input_file:
                    while True:
                        check_cancel(cancel_event)
                        count = input_file.readinto(buffer)
                        if not count:
                            break
                        if first_chunk and wrote_anything and last_byte not in (b"\n", b"\r"):
                            output.write(b"\n")
                        first_chunk = False
                        chunk = memoryview(buffer)[:count]
                        try:
                            output.write(chunk)
                            last_byte = bytes(chunk[-1:])
                        finally:
                            chunk.release()
                        wrote_anything = True
                        reporter.add(count, f"Copying {source.name}")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    elapsed = time.perf_counter() - started
    reporter.add(0, "Complete", force=True)
    return MergeResult(
        output=destination,
        input_files=len(sources),
        input_bytes=total_bytes,
        output_bytes=destination.stat().st_size,
        elapsed_seconds=elapsed,
        backend="Direct buffered disk I/O",
    )


def merge_deduplicated(
    sources: Sequence[Path],
    destination: Path,
    hasher: BatchHasher,
    skip_blank_lines: bool,
    cancel_event: threading.Event,
    progress: ProgressCallback,
) -> MergeResult:
    total_bytes = sum(path.stat().st_size for path in sources)
    reporter = ProgressReporter(total_bytes, progress)
    temporary = temporary_output_path(destination)
    started = time.perf_counter()
    seen: set[int] = set()
    payload = bytearray()
    offsets = array("Q")
    lengths = array("I")
    input_lines = 0
    output_lines = 0
    duplicates = 0
    blanks_skipped = 0

    def flush_batch(output: object, source_name: str) -> None:
        nonlocal payload, offsets, lengths, output_lines, duplicates
        if not offsets:
            return
        check_cancel(cancel_event)
        reporter.add(0, f"GPU hashing {len(offsets):,} lines from {source_name}", force=True)
        hash_a, hash_b = hasher.hash_lines(payload, offsets, lengths)
        view = memoryview(payload)
        unique_output = bytearray()
        try:
            for index, (first, second) in enumerate(zip(hash_a, hash_b)):
                if index % 65_536 == 0:
                    check_cancel(cancel_event)
                fingerprint = (int(first) << 64) | int(second)
                if fingerprint in seen:
                    duplicates += 1
                    continue
                seen.add(fingerprint)
                start = offsets[index]
                end = start + lengths[index]
                unique_output.extend(view[start:end])
                unique_output.append(0x0A)
                output_lines += 1
            output.write(unique_output)
        finally:
            view.release()
        payload = bytearray()
        offsets = array("Q")
        lengths = array("I")

    unreported_bytes = 0
    try:
        with temporary.open("xb", buffering=COPY_BUFFER_BYTES) as output:
            for source in sources:
                check_cancel(cancel_event)
                with source.open("rb", buffering=COPY_BUFFER_BYTES) as input_file:
                    for raw_line in input_file:
                        input_lines += 1
                        unreported_bytes += len(raw_line)
                        if unreported_bytes >= PROGRESS_GRANULARITY:
                            reporter.add(unreported_bytes, f"Reading {source.name}")
                            unreported_bytes = 0
                        if input_lines % 65_536 == 0:
                            check_cancel(cancel_event)

                        line = raw_line
                        if line.endswith(b"\n"):
                            line = line[:-1]
                            if line.endswith(b"\r"):
                                line = line[:-1]
                        if skip_blank_lines and not line:
                            blanks_skipped += 1
                            continue

                        if len(line) > 0xFFFFFFFF:
                            raise RuntimeError(
                                f"A line in {source} exceeds the CUDA helper's 4 GiB line limit"
                            )
                        offsets.append(len(payload))
                        lengths.append(len(line))
                        payload.extend(line)
                        if len(payload) >= GPU_BATCH_BYTES or len(offsets) >= GPU_BATCH_LINES:
                            flush_batch(output, source.name)

                if unreported_bytes:
                    reporter.add(unreported_bytes, f"Reading {source.name}")
                    unreported_bytes = 0
            flush_batch(output, sources[-1].name)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        hasher.close()

    elapsed = time.perf_counter() - started
    reporter.add(0, "Complete", force=True)
    return MergeResult(
        output=destination,
        input_files=len(sources),
        input_bytes=total_bytes,
        output_bytes=destination.stat().st_size,
        elapsed_seconds=elapsed,
        backend=hasher.name,
        input_lines=input_lines,
        output_lines=output_lines,
        duplicate_lines=duplicates,
        blank_lines_skipped=blanks_skipped,
    )


def run_self_test() -> int:
    cancel = threading.Event()
    progress = lambda _done, _total, _detail: None
    with tempfile.TemporaryDirectory(prefix="wordlist-merger-test-") as directory_name:
        directory = Path(directory_name)
        first = directory / "first.txt"
        second = directory / "second.txt"
        first.write_bytes(b"alpha\r\nbeta\nbeta")
        second.write_bytes(b"beta\ngamma\n\n")

        exact = directory / "exact.txt"
        merge_exact([first, second], exact, cancel, progress)
        expected_exact = b"alpha\r\nbeta\nbeta\nbeta\ngamma\n\n"
        if exact.read_bytes() != expected_exact:
            raise AssertionError("exact merge output did not preserve expected bytes")

        unique = directory / "unique.txt"
        result = merge_deduplicated(
            [first, second], unique, CpuTestHasher(), True, cancel, progress
        )
        if unique.read_bytes() != b"alpha\nbeta\ngamma\n":
            raise AssertionError("deduplicated output is incorrect")
        if result.duplicate_lines != 2 or result.blank_lines_skipped != 1:
            raise AssertionError("dedupe counters are incorrect")
    print("Self-test passed: exact merge, line normalization, dedupe, and counters")
    return 0


def run_gpu_probe() -> int:
    pids = active_hashcat_pids()
    if pids:
        raise SystemExit(
            "GPU probe refused while Hashcat is active (PID%s %s)"
            % ("s" if len(pids) != 1 else "", ", ".join(map(str, pids)))
        )
    gpu = detect_rtx_2080_ti()
    hasher = CudaLineHasher(CUDA_HELPER, gpu.index)
    try:
        payload = bytearray(b"alphabetagamma")
        offsets = array("Q", [0, 5, 9, 0])
        lengths = array("I", [5, 4, 5, 5])
        first, second = hasher.hash_lines(payload, offsets, lengths)
        if (first[0], second[0]) != (first[3], second[3]):
            raise AssertionError("GPU hashes for equal lines did not match")
        if len(set(zip(first, second))) != 3:
            raise AssertionError("GPU probe produced unexpected hashes")
    finally:
        hasher.close()
    print(f"GPU probe passed: {hasher.name}")
    return 0


def launch_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError as error:
        raise SystemExit(f"Tkinter is required for the interactive interface: {error}") from error

    class MergerApp:
        def __init__(self, root: tk.Tk) -> None:
            self.root = root
            self.root.title("GPU Wordlist Merger — RTX 2080 Ti")
            self.root.geometry("980x700")
            self.root.minsize(800, 560)
            self.root.protocol("WM_DELETE_WINDOW", self.close_window)

            self.events: queue.Queue[tuple[str, object]] = queue.Queue()
            self.records: dict[str, ListedFile] = {}
            self.checked: set[Path] = set()
            self.worker: threading.Thread | None = None
            self.cancel_event = threading.Event()
            self.closing = False
            self.started_at = 0.0

            self.directory_var = tk.StringVar(value=str(DEFAULT_DIRECTORY))
            self.output_var = tk.StringVar(value=str(DEFAULT_DIRECTORY / "combined_wordlist.txt"))
            self.mode_var = tk.StringVar(value="gpu")
            self.skip_blank_var = tk.BooleanVar(value=True)
            self.selection_var = tk.StringVar(value="No files checked")
            self.gpu_var = tk.StringVar(value="Checking NVIDIA GPU...")
            self.status_var = tk.StringVar(value="Ready")
            self.progress_var = tk.DoubleVar(value=0.0)

            self.build_interface(ttk, tk)
            self.refresh_files()
            self.root.after(75, self.drain_events)
            threading.Thread(target=self.probe_status, daemon=True).start()

        def build_interface(self, ttk: object, tk_module: object) -> None:
            outer = ttk.Frame(self.root, padding=14)
            outer.pack(fill="both", expand=True)
            outer.columnconfigure(0, weight=1)
            outer.rowconfigure(3, weight=1)

            title = ttk.Label(outer, text="GPU Wordlist Merger", font=("Segoe UI", 17, "bold"))
            title.grid(row=0, column=0, sticky="w", pady=(0, 10))

            directory_frame = ttk.LabelFrame(outer, text="Wordlist folder", padding=8)
            directory_frame.grid(row=1, column=0, sticky="ew")
            directory_frame.columnconfigure(0, weight=1)
            ttk.Entry(directory_frame, textvariable=self.directory_var).grid(
                row=0, column=0, sticky="ew", padx=(0, 6)
            )
            ttk.Button(directory_frame, text="Browse...", command=self.browse_directory).grid(
                row=0, column=1, padx=(0, 6)
            )
            ttk.Button(directory_frame, text="Refresh", command=self.refresh_files).grid(
                row=0, column=2
            )

            status_frame = ttk.Frame(outer)
            status_frame.grid(row=2, column=0, sticky="ew", pady=(8, 5))
            status_frame.columnconfigure(0, weight=1)
            ttk.Label(status_frame, textvariable=self.gpu_var).grid(row=0, column=0, sticky="w")
            ttk.Label(status_frame, textvariable=self.selection_var).grid(row=0, column=1, sticky="e")

            list_frame = ttk.LabelFrame(outer, text="Click the box beside each file to merge", padding=6)
            list_frame.grid(row=3, column=0, sticky="nsew")
            list_frame.columnconfigure(0, weight=1)
            list_frame.rowconfigure(1, weight=1)
            controls = ttk.Frame(list_frame)
            controls.grid(row=0, column=0, sticky="ew", pady=(0, 5))
            ttk.Button(controls, text="Check all", command=self.check_all).pack(side="left")
            ttk.Button(controls, text="Check none", command=self.check_none).pack(
                side="left", padx=5
            )
            ttk.Button(controls, text="Invert", command=self.invert_checks).pack(side="left")

            columns = ("checked", "name", "size", "modified")
            self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="extended")
            self.tree.heading("checked", text="Merge")
            self.tree.heading("name", text="File")
            self.tree.heading("size", text="Size")
            self.tree.heading("modified", text="Modified")
            self.tree.column("checked", width=62, minwidth=55, anchor="center", stretch=False)
            self.tree.column("name", width=520, minwidth=240)
            self.tree.column("size", width=105, anchor="e", stretch=False)
            self.tree.column("modified", width=155, anchor="center", stretch=False)
            scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=scroll.set)
            self.tree.grid(row=1, column=0, sticky="nsew")
            scroll.grid(row=1, column=1, sticky="ns")
            self.tree.bind("<Button-1>", self.tree_click)
            self.tree.bind("<space>", self.toggle_highlighted)
            self.tree.bind("<Double-1>", self.toggle_highlighted)

            options = ttk.LabelFrame(outer, text="Merge mode", padding=8)
            options.grid(row=4, column=0, sticky="ew", pady=(8, 0))
            options.columnconfigure(2, weight=1)
            ttk.Radiobutton(
                options,
                text="GPU dedupe (CUDA; removes repeated lines)",
                variable=self.mode_var,
                value="gpu",
                command=self.mode_changed,
            ).grid(row=0, column=0, sticky="w", padx=(0, 18))
            ttk.Radiobutton(
                options,
                text="Exact combine (preserves every line)",
                variable=self.mode_var,
                value="exact",
                command=self.mode_changed,
            ).grid(row=0, column=1, sticky="w")
            self.blank_check = ttk.Checkbutton(
                options, text="Skip blank lines", variable=self.skip_blank_var
            )
            self.blank_check.grid(row=1, column=0, sticky="w", pady=(5, 0))
            ttk.Label(
                options,
                text="CUDA hashes line batches; disk reads/writes remain the limiting step.",
                foreground="#666666",
            ).grid(row=1, column=1, columnspan=2, sticky="w", pady=(5, 0))

            output_frame = ttk.LabelFrame(outer, text="Output", padding=8)
            output_frame.grid(row=5, column=0, sticky="ew", pady=(8, 0))
            output_frame.columnconfigure(0, weight=1)
            ttk.Entry(output_frame, textvariable=self.output_var).grid(
                row=0, column=0, sticky="ew", padx=(0, 6)
            )
            ttk.Button(output_frame, text="Save as...", command=self.browse_output).grid(
                row=0, column=1
            )

            bottom = ttk.Frame(outer)
            bottom.grid(row=6, column=0, sticky="ew", pady=(10, 0))
            bottom.columnconfigure(0, weight=1)
            self.progress = ttk.Progressbar(
                bottom, variable=self.progress_var, maximum=100.0, mode="determinate"
            )
            self.progress.grid(row=0, column=0, sticky="ew", padx=(0, 8))
            self.merge_button = ttk.Button(bottom, text="Merge checked files", command=self.start_merge)
            self.merge_button.grid(row=0, column=1, padx=(0, 5))
            self.cancel_button = ttk.Button(
                bottom, text="Cancel", command=self.cancel_merge, state="disabled"
            )
            self.cancel_button.grid(row=0, column=2)
            ttk.Label(outer, textvariable=self.status_var).grid(
                row=7, column=0, sticky="w", pady=(6, 0)
            )

        def probe_status(self) -> None:
            try:
                gpu = detect_rtx_2080_ti()
                pids = active_hashcat_pids()
                busy = (
                    f" | Hashcat active (PID{'s' if len(pids) != 1 else ''} "
                    + ", ".join(map(str, pids))
                    + ")"
                    if pids
                    else ""
                )
                helper = "CUDA helper ready" if CUDA_HELPER.is_file() else "CUDA helper missing"
                text = (
                    f"GPU {gpu.index}: {gpu.name} | {gpu.memory_mib / 1024:.1f} GiB | "
                    f"{gpu.utilization}% load | {helper}{busy}"
                )
            except Exception as error:
                text = f"GPU unavailable: {error}"
            self.events.put(("gpu_status", text))

        def current_directory(self) -> Path:
            return Path(os.path.expandvars(self.directory_var.get().strip().strip('"'))).expanduser().resolve()

        def browse_directory(self) -> None:
            initial = self.current_directory()
            selected = filedialog.askdirectory(
                title="Choose the folder containing TXT wordlists",
                initialdir=str(initial if initial.is_dir() else DEFAULT_DIRECTORY),
            )
            if selected:
                self.directory_var.set(selected)
                self.output_var.set(str(Path(selected) / "combined_wordlist.txt"))
                self.refresh_files()

        def browse_output(self) -> None:
            selected = filedialog.asksaveasfilename(
                title="Choose the combined wordlist output",
                initialdir=str(self.current_directory()),
                initialfile=Path(self.output_var.get()).name or "combined_wordlist.txt",
                defaultextension=".txt",
                filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
            )
            if selected:
                self.output_var.set(selected)

        def refresh_files(self) -> None:
            try:
                directory = self.current_directory()
                if not directory.is_dir():
                    raise RuntimeError(f"Folder does not exist: {directory}")
                files = sorted(
                    (path for path in directory.iterdir() if path.is_file() and path.suffix.casefold() == ".txt"),
                    key=lambda path: path.name.casefold(),
                )
            except Exception as error:
                messagebox.showerror("Cannot load folder", str(error), parent=self.root)
                return

            previous = set(self.checked)
            self.tree.delete(*self.tree.get_children())
            self.records.clear()
            self.checked.clear()
            for index, path in enumerate(files):
                try:
                    status = path.stat()
                except OSError:
                    continue
                record = ListedFile(path.resolve(), status.st_size, status.st_mtime)
                item = f"file-{index}"
                self.records[item] = record
                if record.path in previous:
                    self.checked.add(record.path)
                self.tree.insert(
                    "",
                    "end",
                    iid=item,
                    values=(
                        "☑" if record.path in self.checked else "☐",
                        record.path.name,
                        human_size(record.size),
                        datetime.fromtimestamp(record.modified).strftime("%Y-%m-%d %I:%M %p"),
                    ),
                )
            self.update_selection_text()
            self.status_var.set(f"Loaded {len(self.records)} TXT file{'s' if len(self.records) != 1 else ''}")

        def set_checked(self, item: str, checked: bool) -> None:
            record = self.records[item]
            if checked:
                self.checked.add(record.path)
            else:
                self.checked.discard(record.path)
            values = list(self.tree.item(item, "values"))
            values[0] = "☑" if checked else "☐"
            self.tree.item(item, values=values)

        def tree_click(self, event: object) -> str | None:
            if self.worker and self.worker.is_alive():
                return None
            region = self.tree.identify_region(event.x, event.y)
            item = self.tree.identify_row(event.y)
            column = self.tree.identify_column(event.x)
            if region == "cell" and item and column == "#1":
                record = self.records[item]
                self.set_checked(item, record.path not in self.checked)
                self.update_selection_text()
                return "break"
            return None

        def toggle_highlighted(self, _event: object | None = None) -> str:
            if self.worker and self.worker.is_alive():
                return "break"
            items = self.tree.selection()
            if not items:
                focused = self.tree.focus()
                items = (focused,) if focused else ()
            for item in items:
                record = self.records[item]
                self.set_checked(item, record.path not in self.checked)
            self.update_selection_text()
            return "break"

        def check_all(self) -> None:
            for item in self.records:
                self.set_checked(item, True)
            self.update_selection_text()

        def check_none(self) -> None:
            for item in self.records:
                self.set_checked(item, False)
            self.update_selection_text()

        def invert_checks(self) -> None:
            for item, record in self.records.items():
                self.set_checked(item, record.path not in self.checked)
            self.update_selection_text()

        def update_selection_text(self) -> None:
            selected = [record for record in self.records.values() if record.path in self.checked]
            total = sum(record.size for record in selected)
            self.selection_var.set(f"Checked: {len(selected)} file(s), {human_size(total)}")

        def mode_changed(self) -> None:
            self.blank_check.configure(state="normal" if self.mode_var.get() == "gpu" else "disabled")

        def selected_paths(self) -> list[Path]:
            return [record.path for record in self.records.values() if record.path in self.checked]

        def start_merge(self) -> None:
            sources = self.selected_paths()
            if len(sources) < 2:
                messagebox.showwarning(
                    "Choose files", "Check at least two TXT files to merge.", parent=self.root
                )
                return
            try:
                raw_output = self.output_var.get().strip().strip('"')
                if not raw_output:
                    raise RuntimeError("Choose an output file")
                destination = Path(os.path.expandvars(raw_output)).expanduser().resolve()
                if not destination.suffix:
                    destination = destination.with_suffix(".txt")
                    self.output_var.set(str(destination))
                if destination in sources:
                    raise RuntimeError("The output file cannot also be one of the selected inputs")
                destination.parent.mkdir(parents=True, exist_ok=True)
                total = sum(path.stat().st_size for path in sources)
                free = shutil.disk_usage(destination.parent).free
                if free < total + 64 * 1024 * 1024:
                    raise RuntimeError(
                        f"Not enough free space. Need about {human_size(total)}, have {human_size(free)}."
                    )
            except Exception as error:
                messagebox.showerror("Cannot start merge", str(error), parent=self.root)
                return

            if destination.exists() and not messagebox.askyesno(
                "Replace output?",
                f"This file already exists:\n\n{destination}\n\nReplace it after the merge succeeds?",
                parent=self.root,
            ):
                return

            mode = self.mode_var.get()
            if mode == "gpu":
                if not CUDA_HELPER.is_file():
                    messagebox.showerror(
                        "CUDA helper missing",
                        f"GPU mode needs this compiled helper:\n{CUDA_HELPER}",
                        parent=self.root,
                    )
                    return
                pids = active_hashcat_pids()
                if pids:
                    messagebox.showwarning(
                        "GPU is in use by Hashcat",
                        "GPU dedupe will not compete with your active Hashcat job.\n\n"
                        f"Active PID(s): {', '.join(map(str, pids))}\n\n"
                        "Wait for Hashcat to finish, or choose Exact combine (which uses disk I/O).",
                        parent=self.root,
                    )
                    return
                try:
                    gpu = detect_rtx_2080_ti()
                except Exception as error:
                    messagebox.showerror("GPU validation failed", str(error), parent=self.root)
                    return
                device_index = gpu.index
            else:
                device_index = 0

            self.cancel_event.clear()
            self.progress_var.set(0.0)
            self.status_var.set("Starting merge...")
            self.merge_button.configure(state="disabled")
            self.cancel_button.configure(state="normal")
            self.started_at = time.perf_counter()
            skip_blank_lines = self.skip_blank_var.get()
            self.worker = threading.Thread(
                target=self.worker_main,
                args=(sources, destination, mode, device_index, skip_blank_lines),
                daemon=False,
                name="wordlist-merge-worker",
            )
            self.worker.start()

        def worker_main(
            self,
            sources: list[Path],
            destination: Path,
            mode: str,
            device_index: int,
            skip_blank_lines: bool,
        ) -> None:
            def report(done: int, total: int, detail: str) -> None:
                self.events.put(("progress", (done, total, detail)))

            try:
                if mode == "gpu":
                    hasher = CudaLineHasher(CUDA_HELPER, device_index)
                    result = merge_deduplicated(
                        sources,
                        destination,
                        hasher,
                        skip_blank_lines,
                        self.cancel_event,
                        report,
                    )
                else:
                    result = merge_exact(sources, destination, self.cancel_event, report)
            except MergeCancelled:
                self.events.put(("cancelled", None))
            except BaseException as error:
                self.events.put(("error", (str(error), traceback.format_exc())))
            else:
                self.events.put(("complete", result))

        def cancel_merge(self) -> None:
            if self.worker and self.worker.is_alive():
                self.cancel_event.set()
                self.cancel_button.configure(state="disabled")
                self.status_var.set("Cancelling safely; partial output will be removed...")

        def finish_worker(self) -> None:
            self.merge_button.configure(state="normal")
            self.cancel_button.configure(state="disabled")
            self.worker = None
            if self.closing:
                self.root.destroy()

        def drain_events(self) -> None:
            try:
                while True:
                    event, payload = self.events.get_nowait()
                    if event == "gpu_status":
                        self.gpu_var.set(str(payload))
                    elif event == "progress":
                        done, total, detail = payload
                        percent = (done / total * 100.0) if total else 100.0
                        elapsed = max(time.perf_counter() - self.started_at, 0.001)
                        self.progress_var.set(percent)
                        self.status_var.set(
                            f"{detail} — {percent:.1f}% — {human_rate(done, elapsed)}"
                        )
                    elif event == "cancelled":
                        self.status_var.set("Merge cancelled; no output was replaced")
                        self.finish_worker()
                    elif event == "error":
                        detail, trace = payload
                        self.status_var.set("Merge failed")
                        self.finish_worker()
                        messagebox.showerror(
                            "Merge failed", f"{detail}\n\nTechnical details:\n{trace}", parent=self.root
                        )
                    elif event == "complete":
                        result = payload
                        self.progress_var.set(100.0)
                        self.status_var.set(
                            f"Complete: {human_size(result.output_bytes)} written in "
                            f"{result.elapsed_seconds:.2f} seconds"
                        )
                        self.finish_worker()
                        lines = [
                            "Merge complete.",
                            "",
                            f"Output: {result.output}",
                            f"Backend: {result.backend}",
                            f"Input: {result.input_files} files, {human_size(result.input_bytes)}",
                            f"Output size: {human_size(result.output_bytes)}",
                            f"Time: {result.elapsed_seconds:.2f} seconds",
                            f"Average input rate: {human_rate(result.input_bytes, result.elapsed_seconds)}",
                        ]
                        if result.output_lines is not None:
                            lines.extend(
                                [
                                    f"Lines read: {result.input_lines:,}",
                                    f"Unique lines written: {result.output_lines:,}",
                                    f"Duplicates removed: {result.duplicate_lines:,}",
                                    f"Blank lines skipped: {result.blank_lines_skipped:,}",
                                ]
                            )
                        messagebox.showinfo("Merge complete", "\n".join(lines), parent=self.root)
                        self.refresh_files()
            except queue.Empty:
                pass
            if self.root.winfo_exists():
                self.root.after(75, self.drain_events)

        def close_window(self) -> None:
            if self.worker and self.worker.is_alive():
                if not messagebox.askyesno(
                    "Cancel merge?",
                    "A merge is running. Cancel it and close after cleanup?",
                    parent=self.root,
                ):
                    return
                self.closing = True
                self.cancel_merge()
                return
            self.root.destroy()

    root = tk.Tk()
    def report_tk_exception(
        exception_type: type[BaseException], exception: BaseException, trace: object
    ) -> None:
        record_exception(exception_type, exception, trace, "Tkinter callback")
        try:
            messagebox.showerror(
                "Unexpected error",
                f"The operation failed: {exception}\n\nA crash log was written to:\n{CRASH_LOG}",
                parent=root,
            )
        except Exception:
            show_fatal_error(str(exception))

    root.report_callback_exception = report_tk_exception
    try:
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except tk.TclError:
        pass
    MergerApp(root)
    root.mainloop()
    return 0


def main(arguments: Sequence[str] | None = None) -> int:
    command_line = list(sys.argv[1:] if arguments is None else arguments)
    if command_line == ["--self-test"]:
        return run_self_test()
    if command_line == ["--probe-gpu"]:
        return run_gpu_probe()
    if command_line:
        raise SystemExit("usage: wordlist_merger_gpu.py [--self-test | --probe-gpu]")
    return launch_gui()


if __name__ == "__main__":
    install_crash_logging()
    try:
        exit_code = main()
    except KeyboardInterrupt:
        exit_code = 130
    except BaseException as error:
        record_exception(type(error), error, error.__traceback__, "Unhandled top-level exception")
        show_fatal_error(str(error))
        exit_code = 1
    raise SystemExit(exit_code)
