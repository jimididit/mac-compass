# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- `--suppress <file>`: accept reviewed findings with a recorded reason, optional per-item `match` and
  `expires`; accepted findings stay visible in the report.
- MITRE ATT&CK technique ids on persistence, tampering and access checks,
  carried through to findings in the JSON report.
- `CONTRIBUTING.md`, this changelog, and a `staticcheck` job in CI.

### Changed
- Removed the unused `vm_safe` catalog field (`--vm` is driven by `requires_hardware`).
- Updated cobra to 1.10.2.

## [0.1.0] - 2026-10-09

First tagged release.

### Added
- Findings engine: pass / fail (with severity and a fix) / info / error, with a typed JSON report
  (`schema_version` 1), `--fail-on <severity>` and `--redact`.
- `snapshot` and `compare` for baselining persistence items, listeners, extensions, accounts and settings.
- Coverage for background items, TCC privacy grants, configuration profiles and MDM, local accounts and
  admins, SSH keys, shell startup files, login hooks, `/etc/hosts`, `sudoers.d`, proxies and connections.
- macOS version, CPU architecture and optional-binary gating in the catalog; stable check ids.
- CI on real macOS 15 and 26 (Apple Silicon and Intel); GoReleaser release pipeline with universal binary.

### Changed
- Checks run by absolute path with a scrubbed environment; timeouts kill the whole process group.
- Exit status reflects failed checks (1) and findings at or above `--fail-on` (2).
- Interactive menu loops until quit.

### Fixed
- Removed mutating `kextcache` checks and the deprecated `kextstat`, `eficheck` (where unavailable) and
  `repair_packages` checks; "nothing found" exit codes no longer show as errors.
