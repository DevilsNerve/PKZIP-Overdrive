# PKZIP Overdrive

Maximum-throughput PKZIP password recovery for a dedicated NVIDIA GeForce RTX 2080 Ti.

PKZIP Overdrive is a focused Python launcher for Hashcat. It validates the GPU, isolates CUDA to one RTX 2080 Ti, selects a supported PKZIP mode, applies maximum-performance workload settings, maintains resumable sessions, and shows Hashcat's aggregate speed and progress counter every 10 seconds.

> Use this software only with archives you own or are explicitly authorized to recover.

## Highlights

- CUDA-only execution on one 11 GB RTX 2080 Ti
- Hashcat workload profile 4 with automatic kernel tuning
- No CPU/OpenCL hashing, leaving Windows responsive
- Aggregate speed, progress, temperature, utilization, and ETA updates
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

Place a Hashcat-compatible PKZIP record in `pkzip.hash`, ensure Hashcat is on `PATH`, and run from PowerShell:

```powershell
python .\pkzip_overdrive.py start .\pkzip.hash --mode 17200 --charset ascii --min-length 6 --max-length 12
```

Use `--hashcat C:\path\to\hashcat.exe` when Hashcat is not on `PATH`. Session data defaults to `%LOCALAPPDATA%\hashcat-rtx2080ti` on Windows.

The launcher prints the generated session name at startup. Do not run multiple Hashcat processes against the same GPU; they contend for compute and VRAM and normally reduce total throughput.

## Live controls

- Press `Esc` once to arm termination.
- Press `Esc` again to stop Hashcat and preserve its restore checkpoint.
- Press any other key after the first `Esc` to cancel termination.
- When a password is recovered, Hashcat stops, PKZIP Overdrive displays it, and the console waits for Enter before closing.

Hashcat's `Progress` value is the total number of candidates attempted across all active device workers. `Speed.#*` is per-device throughput and `Speed.#*`/aggregate status is the combined rate.

## Resume a stopped session

Replace `SESSION_NAME` with the session printed at startup:

```powershell
python .\pkzip_overdrive.py restore SESSION_NAME
```

## Benchmark

```powershell
python .\pkzip_overdrive.py benchmark --mode 17220
```

## Character sets

| Value | Hashcat mask | Contents |
| --- | --- | --- |
| `ascii` | `?a` | Printable ASCII |
| `alnum` | custom `?1` | Lowercase, uppercase, digits |
| `lower` | `?l` | Lowercase letters |
| `digits` | `?d` | Decimal digits |

Large masks grow exponentially. Narrow the character set and length range whenever you know anything about the password format.

## Requirements

- Windows 10 or 11
- Exactly one NVIDIA GeForce RTX 2080 Ti with 11 GB VRAM
- A compatible NVIDIA driver and CUDA Toolkit
- Python 3.10 or newer
- Hashcat 7.1.2
- A Hashcat-compatible `$pkzip$` or `$pkzip2$` record extracted from an authorized archive

## Licensing and contact

The public edition of PKZIP Overdrive is licensed under the **GNU Affero General Public License v3.0**, as provided in this repository's `LICENSE` file.

For an alternative private/commercial license, custom builds, and support, visit **[austenjgreen.com](https://austenjgreen.com/)**.

Hashcat, NVIDIA CUDA, and John the Ripper/`zip2john` are third-party projects governed by their respective licenses and are not included under the PKZIP Overdrive private license.
