# Security Policy

## Scope

carvX is a forensic file carver that parses **untrusted, potentially
adversarial input**: disk images, block devices, and filesystem metadata that
may be corrupted or deliberately malformed. The most relevant security concerns
for this project are therefore:

- Crashes, hangs, or unbounded memory/CPU use triggered by crafted input.
- Path-traversal or writes outside the chosen `--output` directory when
  reconstructing recovered filenames.
- Handling of decryption credentials (BitLocker keys/passwords).

carvX is **read-only** with respect to the source it analyses and never
modifies the evidence image or device.

## Handling credentials

BitLocker credentials passed on the command line (`--bitlocker-password`,
`--bitlocker-recovery-key`, `--bitlocker-fvek`) may be visible in your shell
history and process list. Prefer key files (`--bitlocker-bek`) or run in an
environment where the process list is not exposed. carvX passes credentials to
worker processes through an environment variable that is not written to disk.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** rather than opening a
public issue:

- Open a [GitHub security advisory](https://github.com/sltcnb/BreadCrumb/security/advisories/new), or
- Contact the maintainers through the repository's contact channels.

Include a description, the affected version/commit, and — where possible — a
minimal input sample or reproduction steps. Please do not share real evidence
data; a synthetic reproducer is preferred.

We aim to acknowledge reports within a reasonable time and will coordinate a
fix and disclosure timeline with you.

## Supported versions

This project is pre-1.0; only the latest `main` branch receives security fixes.
