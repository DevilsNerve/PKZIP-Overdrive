# PKZIP Overdrive

[![Python tests](https://github.com/DevilsNerve/PKZIP-Overdrive/actions/workflows/tests.yml/badge.svg)](https://github.com/DevilsNerve/PKZIP-Overdrive/actions/workflows/tests.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

Maximum-throughput PKZIP password recovery for a dedicated NVIDIA GeForce RTX 2080 Ti.

PKZIP Overdrive is a focused Python launcher for Hashcat. It validates the GPU, isolates CUDA to one RTX 2080 Ti, selects a supported PKZIP mode, applies maximum-performance workload settings, maintains resumable sessions, and shows Hashcat's aggregate speed and progress counter every 10 seconds.

> Use this software only with archives you own or are explicitly authorized to recover.

## Highlights

- CUDA-only execution on one 11 GB RTX 2080 Ti
- Hashcat workload profile 4 with automatic kernel tuning
- No CPU/OpenCL hashing, leaving Windows responsive
- Aggregate speed, progress, temperature, utilization, and ETA updates
- Interactive maximum-length prompt capped at 10; every run starts at length 1
- Interactive ZIP path/directory prompt with automatic `zip2john` hash extraction and mode selection
- Resumable sessions and a shared potfile
- 88°C emergency temperature cutoff
- Two-stage keyboard stop: press `Esc` twice to stop cleanly
- Prominent recovered-password display with an Enter prompt before closing
- PKZIP modes 17200, 17210, 17220, 17225, and 17230

## Measured performance

Test system:

- NVIDIA GeForce RTX 2080 Ti, 11,264 MiB
- NVIDIA driver 591.86
- CUDA Toolkit 13.1
- Hashcat 7.1.2

| Hashcat mode | Workload | Measured speed | Candidates/minute |
| --- | --- | ---: | ---: |
| 17220, PKZIP compressed multi-file | Synthetic benchmark | 11.1402 GH/s | 668.412 billion |

Actual speed varies with PKZIP mode, member size, compression method, thermals, and attack shape. Benchmark results are not a guarantee for every archive.

## Quick start

Ensure Hashcat and `zip2john` are on `PATH`, then run from PowerShell:

```powershell
python .\pkzip_overdrive.py
```

Running without arguments starts the complete guided flow. The launcher first finds valid saved checkpoints and lets you resume one or start a new attack. New attacks prompt for a checkpoint name; pressing Enter uses a Windows-safe timestamp such as `pkzip_2026-07-16_14-30-00`. It then asks for the ZIP path, attack method, and wordlist or maximum length. You can also paste a directory: its only ZIP is selected automatically, or the launcher displays a numbered choice when several ZIPs are present. Surrounding quotes and paths containing spaces or parentheses are accepted.

The startup checkpoint manager supports:

- Enter a checkpoint number to resume it.
- Enter `P`, then its number, to preview the ZIP/source path, attack type, latest attempted/total count and percentage, speed, attempts per minute, ETA, queue, mask, and checkpoint location.
- Enter `D`, then its number, to delete its `.restore` checkpoint after typing `DELETE`. Other session logs and results are retained, and deletion is blocked while Hashcat is running.
- Enter `0` or press Enter to start a new attack.

New sessions save their source and latest status in `session-info.json` after every Hashcat status update. Checkpoints created by older launcher versions can still expose their attack mode, current mask, and restore-position percentage, but their original ZIP path displays as not recorded.

The launcher reads ZIP metadata, selects a compact encrypted member, creates the PKZIP hash with `zip2john`, infers mode 17200 or 17210, and asks you to choose a dictionary or brute-force attack.

| Attack | Interactive flow |
| --- | --- |
| Dictionary | Paste a wordlist file/directory; a directory with multiple wordlists displays a numbered choice |
| Brute force | Select a maximum length from 1 through 10; every length from 1 through that selection is tested |

For automation, provide both values explicitly:

```powershell
python .\pkzip_overdrive.py start "C:\path with spaces\archive.zip" --attack brute --max-length 7
```

```powershell
python .\pkzip_overdrive.py start "C:\path with spaces\archive.zip" --attack dictionary --wordlist "C:\wordlists\rockyou.txt"
```

Use `--hashcat C:\path\to\hashcat.exe` when Hashcat is not on `PATH`. Session data defaults to `%LOCALAPPDATA%\hashcat-rtx2080ti` on Windows.

The launcher prints the generated session name at startup. Do not run multiple Hashcat processes against the same GPU; they contend for compute and VRAM and normally reduce total throughput.

## Live controls

- Press `Esc` once to arm termination.
- Press `Esc` again to stop Hashcat and preserve its restore checkpoint.
- Pressing a native Hashcat command after the first `Esc` cancels double-Esc termination and forwards the command.
- When a password is recovered, Hashcat stops, PKZIP Overdrive displays it, and the console waits for Enter before closing.
- Whenever Hashcat exits, the launcher prints the absolute `.restore` checkpoint path and an exact resume command. It also writes those details to `checkpoint-info.txt` in the session directory.
- The latest ZIP path and aggregate progress are persisted to `session-info.json` for the next startup preview.

| Key | Action |
| --- | --- |
| `s` or Enter | Show status immediately |
| `p` / `r` | Pause / resume |
| `b` | Bypass the current wordlist/mask and advance to the next queued attack |
| `c` | Toggle stopping at the next restore checkpoint |
| `f` | Toggle finishing the current wordlist/mask before stopping |
| `q` | Quit Hashcat cleanly |

Hashcat's `Progress` value is the total number of candidates attempted across all active device workers. `Speed.#01`, `Speed.#02`, and so on are per-device rates; `Speed.#*` is the combined rate.

## Resume a stopped session

Replace `SESSION_NAME` with the session printed at startup:

```powershell
python .\pkzip_overdrive.py restore SESSION_NAME
```

## Benchmark

```powershell
python .\pkzip_overdrive.py benchmark --mode 17220
```

## Development checks

The regression suite uses only the Python standard library and exercises the
launcher parsers, checkpoint metadata, protected hash extraction, exact merge,
deduplication, cancellation, and failure cleanup:

```powershell
python -m unittest discover -s tests -v
python .\wordlist_merger_gpu.py --self-test
```

## Character sets

| Value | Hashcat mask | Contents |
| --- | --- | --- |
| `ascii` | `?a` | Printable ASCII |
| `alnum` | custom `?1` | Lowercase, uppercase, digits |
| `lower` | `?l` | Lowercase letters |
| `digits` | `?d` | Decimal digits |

Large masks grow exponentially. Narrow the character set and length range whenever you know anything about the password format.

## GPU wordlist merger

The repository also includes an interactive Windows wordlist merger. It opens `%USERPROFILE%\Downloads\lists`, lists the `.txt` files with checkboxes, and writes the selected files to a user-chosen output.

Launch it by double-clicking `Launch Wordlist Merger.cmd`, or from Command Prompt:

```bat
"Launch Wordlist Merger.cmd"
```

Two merge modes are available:

| Mode | Behavior |
| --- | --- |
| GPU dedupe | Uses the RTX 2080 Ti CUDA helper to generate 128-bit line fingerprints, preserves first-seen order, removes duplicate lines, and optionally skips blank lines |
| Exact combine | Uses large buffered disk I/O and preserves every input line; this is the fastest path when deduplication is not needed |

Raw file copying is limited by storage throughput, so the GPU is used only for the line-hashing work it can accelerate. GPU dedupe refuses to compete with an active Hashcat process; Exact combine remains available while Hashcat is running.

The prebuilt `wordlist_gpu_hash.dll` targets the RTX 2080 Ti's `sm_75` architecture. To rebuild it locally, install the CUDA Toolkit and Visual Studio C++ tools, then run `Build Wordlist GPU Helper.cmd`.

The launcher records startup and error details in `wordlist_merger_crash.log`. If startup fails, its console remains open and displays the same traceback. Source wordlists are never modified, and an output file is replaced only after a successful merge.

## Requirements

- Windows 10 or 11
- Exactly one NVIDIA GeForce RTX 2080 Ti with 11 GB VRAM
- A compatible NVIDIA driver and CUDA Toolkit
- Python 3.10 or newer
- Hashcat 7.1.2
- John the Ripper's `zip2john` executable for direct ZIP input (or an existing `$pkzip$`/`$pkzip2$` hash file)

## Licensing and contact

The source and compiled project files in this repository are licensed under
**GNU Affero General Public License v3.0 only**
([`AGPL-3.0-only`](https://spdx.org/licenses/AGPL-3.0-only.html)). See
[`LICENSE`](LICENSE) for the complete terms.

For alternative licensing, custom builds, and support, visit
**[austenjgreen.com](https://austenjgreen.com/)**.

Hashcat, NVIDIA CUDA, and John the Ripper/`zip2john` are third-party projects
governed by their respective licenses. They are not distributed as part of
this repository.
