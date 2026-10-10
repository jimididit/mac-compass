# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- `mac-compass posture` scores the Mac against 16 hardening controls that follow the macOS Security Compliance
  Project, with each control's mSCP rule id. The score is also in the JSON report and on the last line of other runs.

## [0.4.1] - 2026-10-09

### Added
- Each release also publishes the universal archive without a version in its name
  (`mac-compass_macos_universal.tar.gz`), so `releases/latest/download/` gives a one-line install.

### Changed
- The Homebrew formula installs the release archive (no Go toolchain needed).
- Install instructions lead with a `curl` install, which macOS does not quarantine, and explain the one-time prompt
  for browser downloads (the binary is signed but not yet notarized).

## [0.4.0] - 2026-10-09

### Fixed
- `compare` against a baseline taken with `--redact` no longer reports every item that mentions the user or host
  as both new and removed: the live snapshot is masked the same way before the comparison.
- `softwareupdate` reporting "No new software available" on stderr (macOS 15) is now recognised as up to date.
- Files written under `sudo` (`--html`, `--sarif`, `--report`, `snapshot -o`, `collect`) are handed back to the user
  who ran `sudo`; runtime errors no longer print the full usage text.
- Findings: hidden folders under a home directory (developer tool caches) are medium instead of high, the monitor's
  own launch item is not flagged, and TCC and timeout errors explain what to do.
- Monitor status says `alert-active` when findings were already announced instead of repeating `alerted`.
- Release binaries are now ad-hoc code signed. An unsigned x86_64 binary was killed by macOS (`zsh: killed`) when
  it carried the quarantine flag of a browser download. The release build runs on macOS to sign them, and the
  pipeline can be dry-run without publishing.

### Added
- `--progress` prints one line per check to stderr, and a check can have its own shorter time limit; login items
  and the update check now do, so one slow check cannot hold up a whole run.
- `monitor` runs the baseline comparison on a schedule through launchd (`install`, `status`, `run`, `uninstall`),
  alerting once when the set of serious new findings changes. A root daemon is refused unless the binary and its
  folders are root-owned and not writable by others.
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
