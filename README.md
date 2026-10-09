<div align="center">

# mac-compass

**Triage, baseline and audit a Mac from the command line.**
Read-only checks for signs of compromise and weak security settings, explained in plain language.

[![CI](https://github.com/jimididit/mac-compass/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jimididit/mac-compass/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/jimididit/mac-compass)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/jimididit/mac-compass)](go.mod)
[![macOS 15 | 26](https://img.shields.io/badge/macOS-15%20%7C%2026%20tested-blue?logo=apple&logoColor=white)](#supported-macos-versions)

</div>

---

mac-compass runs a catalog of 46 read-only checks and turns their raw output into **findings**: what is wrong,
how serious it is, and how to fix it. Save a **baseline** on a Mac you trust, then see exactly what changed
later.

- **Triage** – SIP, Gatekeeper, kernel and system extensions, boot arguments.
- **Persistence** – LaunchDaemons and Agents, background items, login items, cron, shell startup files, login hooks.
- **Access** – local accounts and admins, SSH keys, guest and auto login, privacy (TCC) grants, profiles and MDM.
- **Network** – listeners, connections, firewall, DNS and proxies.
- **Baseline and compare** – a normalized inventory you can diff, with `--fail-on` for scripts and CI.
- **Safe by design** – checks only *read*; absolute paths and a scrubbed environment; reports are `0600`; `--redact` before sharing.

## Quick start

Download the latest build from [**Releases**](https://github.com/jimididit/mac-compass/releases) (one universal
binary for Apple Silicon and Intel), then:

```bash
tar -xzf mac-compass_*_macos_universal.tar.gz && cd mac-compass_*_macos_universal
xattr -dr com.apple.quarantine .        # the binary is not notarized yet
./mac-compass triage --no-sudo          # quick look, no password needed
sudo ./mac-compass run-all -y           # the full check
```

Or build it yourself (Go 1.24+): `go install github.com/jimididit/mac-compass@latest`

<details>
<summary>Verify the download first (recommended before running anything as root)</summary>

```bash
shasum -a 256 -c checksums.txt --ignore-missing
gh attestation verify mac-compass_*_macos_universal.tar.gz --repo jimididit/mac-compass   # build provenance
```

If macOS reports `zsh: killed`, sign it locally: `codesign --force --sign - ./mac-compass`.
A step-by-step guide for someone you are sending it to is in [SHARING.md](SHARING.md).

</details>

## Example output

Real, abridged output from a deliberately weak test machine (a GitHub-hosted macOS 26 runner; `...` marks omitted lines):

```text
========== Findings ==========
[HIGH] System Integrity Protection is disabled
    SIP protects system files and processes from modification, even by root. Malware commonly disables it.
    fix: Boot to Recovery, open Terminal and run: csrutil enable
[MEDIUM] Application firewall is off
    Incoming connections to apps are not filtered.
    fix: Enable in System Settings > Network > Firewall
[MEDIUM] FileVault disk encryption is off
    Anyone with physical access can read the disk.
    fix: Enable in System Settings > Privacy & Security > FileVault
[MEDIUM] 16 binary(ies) granted sensitive privacy access by path (system-wide)
    Accessibility (control the computer): /bin/bash
    ...
[MEDIUM] Automatic login is on for runner
[LOW] Remote Login (SSH) is reachable on the network
[LOW] 4 software update(s) available
...
[INFO] 12 enabled background item(s) of 12 registered

11 failed (1 high, 5 medium, 5 low), 13 passed, 8 info, 0 errors; checks: 45 ok, 1 skipped, 0 failed
```

## Catch changes with a baseline

```bash
sudo mac-compass snapshot -o baseline.json     # on a Mac you trust
sudo mac-compass compare baseline.json         # later: what is new, removed or changed?
```

A new LaunchDaemon, listener, admin account, SSH key or modified `.zshrc` shows up as a finding; an untouched
machine compares clean. Accept things you have reviewed with `--suppress`. See [Baselines](docs/baseline.md).

## Documentation

| | |
|---|---|
| [Usage reference](docs/usage.md) | Commands, flags, reading results, JSON report, exit codes |
| [Baselines and suppressions](docs/baseline.md) | `snapshot`, `compare`, accepting reviewed findings |
| [Check reference](docs/checks.md) | All 46 checks, what they flag, and their MITRE ATT&CK mapping |
| [Sharing it with someone](SHARING.md) | Plain instructions to hand to a non-expert |
| [Contributing](CONTRIBUTING.md) · [Releasing](RELEASING.md) · [Changelog](CHANGELOG.md) | For maintainers |

## Supported macOS versions

| macOS | Status |
|---|---|
| 26 (Tahoe), 15 (Sequoia) | Tested in CI on real runners, Apple Silicon and Intel |
| 27 | Expected to work; not in CI until GitHub offers a macOS 27 runner |
| 12 – 14 | Best effort |
| 11 and older | Unsupported |

Checks adapt to the host and are *skipped*, not failed, when they do not apply to your macOS version or CPU.

## Know the limits

- **A compromised Mac can lie.** Every check relies on the system it inspects, so a clean result is evidence,
  not proof. For a machine you strongly suspect, also collect evidence from outside it.
- **Findings are heuristics.** Third-party launch items, privacy grants and proxies are often legitimate.
- Builds are not yet signed or notarized with an Apple Developer ID.

Details and how to report a vulnerability: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
