# Security policy

## Supported code

Security fixes are applied to the current `main` branch. Before reporting a
problem, reproduce it against the latest commit when that can be done safely.

## Report a vulnerability privately

Use a
[private repository security advisory](https://github.com/DevilsNerve/PKZIP-Overdrive/security/advisories/new)
for vulnerabilities involving command execution, unsafe file handling,
checkpoint isolation, credential or password exposure, DLL loading, or another
security boundary. Do not open a public issue for an undisclosed vulnerability.

Include:

- the affected commit or version;
- Windows, Python, Hashcat, CUDA, driver, and GPU versions when relevant;
- a minimal reproduction using synthetic, non-sensitive data;
- the impact and any conditions required to trigger it; and
- a suggested fix, if one is available.

Please allow time to reproduce and prepare a fix before public disclosure.

## Keep sensitive data out of reports

Do not upload real ZIP archives, extracted PKZIP hashes, wordlists, potfiles,
recovered passwords, session folders, or unredacted logs. Replace usernames,
paths, archive names, and secrets with safe placeholders. If a minimal sample
is necessary, create a new synthetic archive and disclose its password in the
private report only.

This process is for security defects in PKZIP Overdrive. Questions about
recovering an archive, Hashcat behavior, CUDA installation, or account support
belong in a normal issue and must still use only authorized, sanitized data.
