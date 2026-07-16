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
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from typing import Sequence


GPU_NAME_FRAGMENT = "RTX 2080 Ti"
MIN_VRAM_MIB = 10_000
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
    if not 1 <= parsed <= 31:
        raise argparse.ArgumentTypeError("optimized PKZIP masks are limited here to 1-31 characters")
    return parsed


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
) -> int:
    """Replace this process on POSIX; use a normal child process on Windows."""
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if monitor_escape else 0
        process = subprocess.Popen(
            command,
            cwd=windows_workdir,
            env=environment,
            stdin=subprocess.DEVNULL if monitor_escape else None,
            creationflags=creationflags,
        )
        if not monitor_escape or not sys.stdin.isatty():
            return process.wait()

        import msvcrt

        escape_armed = False
        while process.poll() is None:
            if msvcrt.kbhit():
                key = msvcrt.getwch()
                if key == "\x1b":
                    if not escape_armed:
                        escape_armed = True
                        print(
                            "\nSTOP ARMED: press Esc once more to terminate Hashcat; "
                            "press any other key to cancel.",
                            flush=True,
                        )
                    else:
                        print(
                            "\nStopping Hashcat and preserving its restore checkpoint...",
                            flush=True,
                        )
                        process.send_signal(signal.CTRL_BREAK_EVENT)
                        try:
                            return process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            return process.wait()
                elif escape_armed:
                    escape_armed = False
                    print("\nStop cancelled; Hashcat is still running.", flush=True)
            time.sleep(0.05)
        return process.returncode
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


def start_command(arguments: argparse.Namespace) -> int:
    hashcat, gpu, environment = common_preflight(arguments)
    running = active_hashcat_pids()
    if running:
        raise SystemExit(
            "error: refusing to contend with active Hashcat process(es): "
            + ", ".join(str(pid) for pid in running)
        )
    if arguments.min_length > arguments.max_length:
        raise SystemExit("error: --min-length cannot exceed --max-length")

    session = arguments.session or datetime.now().strftime("pkzip_2080ti_%Y%m%d_%H%M%S")
    state_root = Path(arguments.state_root).expanduser().resolve()
    session_directory = state_root / session
    try:
        session_directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    except FileExistsError as error:
        raise SystemExit(
            f"error: session already exists: {session}; use restore or choose another name"
        ) from error

    extracted_hash = session_directory / "pkzip.hash"
    extract_pkzip_hash(Path(arguments.hash_file).expanduser().resolve(), extracted_hash)
    mode = arguments.mode or identify_mode(hashcat, extracted_hash, environment)
    if mode not in PKZIP_MODES:
        raise SystemExit(f"error: unsupported PKZIP mode: {mode}")

    custom_charset, mask = mask_arguments(arguments.charset, arguments.max_length)
    result_file = session_directory / "recovered.txt"
    pot_file = state_root / "pkzip.potfile"

    command = [
        hashcat,
        f"--hash-type={mode}",
        "--attack-mode=3",
        "--optimized-kernel-enable",
        "--workload-profile=4",
        "--backend-ignore-opencl",
        "--backend-devices=1",
        "--increment",
        f"--increment-min={arguments.min_length}",
        f"--increment-max={arguments.max_length}",
        "--status",
        f"--status-timer={arguments.status_interval}",
        f"--session={session}",
        f"--restore-file-path={session_directory / (session + '.restore')}",
        f"--potfile-path={pot_file}",
        f"--outfile={result_file}",
        "--outfile-format=2",
        "--hwmon-temp-abort=88",
        *custom_charset,
        str(extracted_hash),
        mask,
    ]

    if os.name != "nt":
        os.chdir(session_directory)
    print(
        f"GPU={gpu.name} index={gpu.index} VRAM={gpu.memory_mib}MiB mode={mode} "
        f"charset={arguments.charset} lengths={arguments.min_length}-{arguments.max_length}",
        flush=True,
    )
    print(f"session={session} state={session_directory}", flush=True)
    print(f"command={shlex.join(command)}", flush=True)
    print(
        f"Hashcat will print exact progress, speed, GPU utilization, and temperature every "
        f"{arguments.status_interval} seconds.",
        flush=True,
    )
    return_code = launch(
        command, environment, Path(hashcat).parent, monitor_escape=True
    )
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
    if os.name != "nt":
        os.chdir(session_directory)
    print(f"GPU={gpu.name} restoring={arguments.session}", flush=True)
    return_code = launch(
        command, environment, Path(hashcat).parent, monitor_escape=True
    )
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

    start = commands.add_parser("start", help="start a new GPU mask attack")
    start.add_argument("hash_file", help="zip2john output or a bare $pkzip$ record")
    start.add_argument("--charset", choices=("ascii", "alnum", "lower", "digits"), default="ascii")
    start.add_argument("--min-length", type=length, default=6)
    start.add_argument("--max-length", type=length, default=12)
    start.add_argument("--mode", type=int, choices=sorted(PKZIP_MODES))
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
    arguments = parser.parse_args(sys.argv[1:] if argv is None else argv)
    return arguments.handler(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
