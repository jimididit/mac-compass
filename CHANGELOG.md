# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- `--html` writes a self-contained HTML report (no scripts, no network requests) and `--sarif` writes SARIF 2.1.0;
  `collect` now stores `report.html` in the evidence bundle.

## [0.3.0] - 2026-10-09

### Added
- `collect` writes a hashed evidence bundle (report, snapshot, findings and the raw output of every check, with a
  SHA-256 manifest) and `verify` checks one later, optionally against a hash recorded off the machine.
- Code-signing analysis of running programs: each distinct program currently running, with its signature and
  notarization state. Flags programs started from temporary or hidden locations, root processes run from a
  user's home folder, programs deleted while still running, and unsigned programs.
- Code-signing analysis of launch items: the program each LaunchDaemon and LaunchAgent runs, with its signature
  and notarization state. Flags programs in temporary or hidden locations, unsigned or ad-hoc signed programs,
  missing programs and inline scripts; `compare` reports new items and changes of signing team.

### Changed
- The catalog now has 48 read-only checks. Release archives contain the binary, README and LICENSE.

## [0.2.0] - 2026-10-09

First public release.

### Added
- Findings engine: pass / fail (with severity and a fix) / info / error, with a typed JSON report
  (`schema_version` 1), `--fail-on <severity>` and `--redact`.
- `snapshot` and `compare` for baselining persistence items, listeners, extensions, accounts and settings.
  A setting that moves to its secure value is reported as an improvement, not a failure.
- `--suppress <file>`: accept reviewed findings with a recorded reason, optional per-item `match` and
  `expires`; accepted findings stay visible in the report.
- 46 read-only checks, including background items, TCC privacy grants, configuration profiles and MDM,
  local accounts and admins, SSH keys, shell startup files, login hooks, `/etc/hosts`, `sudoers.d`,
  proxies and connections.
- MITRE ATT&CK technique ids on persistence, tampering and access checks, carried into the JSON report.
- macOS version, CPU architecture and optional-binary gating in the catalog; stable check ids.
- CI on real macOS 15 and 26 (Apple Silicon and Intel), `staticcheck`, `govulncheck`; GoReleaser pipeline
  producing a universal binary, checksums and a build provenance attestation.
- Documentation: usage, baselines, check reference, `SECURITY.md`, `CONTRIBUTING.md`.

### Changed
- Checks run by absolute path with a scrubbed environment; timeouts kill the whole process group.
- Exit status reflects failed checks (1) and findings at or above `--fail-on` (2).
- Interactive menu loops until quit.
- Go 1.24 is required.

### Fixed
- Removed mutating `kextcache` checks and the deprecated `kextstat`, `eficheck` (where unavailable) and
  `repair_packages` checks; "nothing found" exit codes no longer show as errors.
- Removed the unused `vm_safe` catalog field.
