# Contributing to PKZIP Overdrive

Thanks for helping improve PKZIP Overdrive. Keep each change focused, testable,
and safe for people recovering archives they own or are explicitly authorized
to access.

## Protect recovery data

- Never commit or attach real archives, extracted hashes, wordlists, potfiles,
  recovered passwords, checkpoint folders, or unredacted crash logs.
- Build test fixtures from synthetic data that can be published safely.
- Remove usernames and local paths from logs before sharing them.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Development setup

The launcher supports Python 3.10 or newer. Most parser, persistence, and merge
work can be developed without Hashcat or a GPU:

```powershell
git clone https://github.com/DevilsNerve/PKZIP-Overdrive.git
cd PKZIP-Overdrive
python -m unittest discover -s tests -v
python .\wordlist_merger_gpu.py --self-test
python -m compileall -q pkzip_overdrive.py wordlist_merger_gpu.py tests
```

The repository workflow repeats these checks on Linux and native Windows at
the supported Python boundaries.

## Hardware-specific changes

Changes to GPU discovery, Hashcat command construction, keyboard control, CUDA
runtime selection, or the native helper need Windows evidence in addition to
the standard tests. Record the relevant Windows, Python, NVIDIA driver, CUDA,
Hashcat, and GPU versions in the pull request.

If `wordlist_gpu_hash.dll` changes:

1. Update `wordlist_gpu_hash.cu` in the same pull request.
2. Rebuild with `Build Wordlist GPU Helper.cmd`.
3. Run `python .\wordlist_merger_gpu.py --probe-gpu` on an RTX 2080 Ti while
   Hashcat is stopped.
4. Record the DLL SHA-256 and exported functions in the pull request.

Do not commit CUDA build intermediates, local checkpoints, output wordlists, or
crash logs.

## Pull requests

- Keep one coherent purpose per pull request.
- Add or update regression coverage for behavior changes.
- Update the README when commands, requirements, safety behavior, or user flow
  changes.
- Explain what changed, why it matters, and exactly what was verified.
- Wait for every Linux and Windows workflow job to pass before merging.
- Confirm the source is offered under `AGPL-3.0-only` and that third-party work
  is compatible and clearly identified.
