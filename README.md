<div align="center">

# mac-compass

**Triage, baseline and audit a Mac from the command line.**
Read-only checks for signs of compromise and weak security settings, explained in plain language.

[![Release](https://img.shields.io/github/v/release/jimididit/mac-compass)](https://github.com/jimididit/mac-compass/releases/latest)
[![CI](https://github.com/jimididit/mac-compass/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jimididit/mac-compass/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/jimididit/mac-compass)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/jimididit/mac-compass)](go.mod)
[![macOS 15 | 26](https://img.shields.io/badge/macOS-15%20%7C%2026%20tested-blue?logo=apple&logoColor=white)](#supported-macos-versions)

</div>

---

mac-compass runs a catalog of 48 read-only checks and turns their raw output into **findings**: what is wrong,
how serious it is, and how to fix it. Save a **baseline** on a Mac you trust, then see exactly what changed
later.

- **Triage** – SIP, Gatekeeper, kernel and system extensions, boot arguments.
- **Persistence** – LaunchDaemons and Agents, background items, login items, cron, shell startup files, login hooks.
- **Access** – local accounts and admins, SSH keys, guest and auto login, privacy (TCC) grants, profiles and MDM.
- **Network** – listeners, connections, firewall, DNS and proxies.
- **Reports** – terminal, JSON, a self-contained HTML page, SARIF, and hashed evidence bundles.
- **Monitor mode** – a scheduled comparison that alerts you when something new and serious appears, once.
- **Baseline and compare** – a normalized inventory you can diff, with `--fail-on` for scripts and CI.
- **Safe by design** – checks only *read*; absolute paths and a scrubbed environment; reports are `0600`; `--redact` before sharing.

## Quick start

Install the latest release from Terminal. Downloads made with `curl` are not flagged by macOS, so there is no
"Apple could not verify" prompt:

```bash
mkdir mac-compass && cd mac-compass
VER=$(curl -fsSL https://api.github.com/repos/jimididit/mac-compass/releases/latest | grep -m1 '"tag_name"' | cut -d'"' -f4)
curl -fsSL "https://github.com/jimididit/mac-compass/releases/download/${VER}/mac-compass_${VER#v}_macos_universal.tar.gz" | tar -xz
./mac-compass triage --no-sudo          # quick look, no password needed
sudo ./mac-compass run-all -y           # the full check
```

Or build it yourself (Go 1.24+), which also avoids the prompt: `go install github.com/jimididit/mac-compass@latest`

**Downloaded with a browser instead?** The binary is signed but not yet notarized by Apple, so macOS shows
"Apple could not verify..." the first time. Clear it with `xattr -dr com.apple.quarantine .` in the extracted
folder, or open System Settings > Privacy & Security, find the "mac-compass was blocked" notice and click
**Open Anyway**.

<details>
<summary>Verify the download first (recommended before running anything as root)</summary>

```bash
# download the archive and checksums.txt from the release page into one folder, then:
shasum -a 256 -c checksums.txt --ignore-missing
gh attestation verify mac-compass_*_macos_universal.tar.gz --repo jimididit/mac-compass   # build provenance
codesign -dv ./mac-compass 2>&1 | grep -E "Identifier|Signature"                          # ad-hoc signed
```

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
| [Check reference](docs/checks.md) | All 48 checks, what they flag, and their MITRE ATT&CK mapping |
| [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) | For contributors |

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
