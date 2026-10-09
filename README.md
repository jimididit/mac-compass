# mac-compass

**mac-compass** is an interactive CLI that helps you check a macOS system for signs of compromise. It runs a catalog of security and triage checks - SIP, Gatekeeper, kernel extensions, persistence locations, network state, and more - so you can quickly see what’s on the system without memorizing commands.

- **Repository:** [github.com/jimididit/mac-compass](https://github.com/jimididit/mac-compass)
- **Platform:** macOS only. See [Supported macOS versions](#supported-macos-versions).
- **Requirements:** Many checks need `sudo`; run with an admin account when you want full results.

---

## Supported macOS versions

| macOS | Status |
|-------|--------|
| 26 (Tahoe), 15 (Sequoia) | Tested in CI on real runners, Apple Silicon and Intel |
| 27 (Golden Gate) | Expected to work; not in CI until GitHub ships a macOS 27 runner image |
| 12-14 | Best effort, not in CI (GitHub's macOS 14 runners are deprecated) |
| 11 and older | Unsupported (minimum for the Go toolchain is macOS 11; older lacks `kmutil`) |

Checks adapt to the host: each catalog entry can declare `macos_min` / `macos_max`, `arch`, and `optional`, and is *skipped* (not failed) when it does not apply. If the macOS version cannot be detected, nothing is hidden.

---

## Install

### From source (Go 1.24+)

```bash
git clone https://github.com/jimididit/mac-compass.git
cd mac-compass
go build -o mac-compass .
# Binary is ./mac-compass
```

Or with Make:

```bash
make build
```

### Homebrew

Once a Homebrew tap is published for this repo:

```bash
brew tap jimididit/tap
brew install mac-compass
```

*(Tap and formula will be added when releases are available.)*

---

## Usage

### Interactive menu

Run **mac-compass** with no arguments to get a numbered menu. Enter a number or subcommand name to run that section; the menu returns after each one, and `q` quits.

```bash
mac-compass
```

### Subcommands

You can also run a section directly:

| Command | Description |
|--------|-------------|
| `mac-compass triage` | Quick triage (SIP, Gatekeeper, KEXTs, persistence). Run this first. |
| `mac-compass processes` | Process and memory analysis |
| `mac-compass kernel` | Kernel extensions and rootkit-related checks |
| `mac-compass persistence` | File system and persistence (launchd, cron, login items, etc.) |
| `mac-compass network` | Network listeners, firewall, DNS |
| `mac-compass security-tools` | Built-in security tools (FileVault, repair_packages, etc.) |
| `mac-compass advanced` | Advanced detection (e.g. system extensions, launchctl security) |
| `mac-compass harden` | Hardening / preventive checks |
| `mac-compass run-all` | Run all sections (asks for confirmation unless `-y`) |
| `mac-compass checklist` | Show incident response checklist (no commands run) |
| `mac-compass refs` | Show references and resource links (no commands run) |
| `mac-compass version` | Print version |

### Global flags

These work on the root command and on section subcommands:

| Flag | Description |
|------|-------------|
| `--no-sudo` | Skip checks that require sudo |
| `--vm` | VM mode: skip checks that need real hardware (e.g. T2 / Secure Enclave) |
| `--timeout <duration>` | Time limit per check (default: 90s). Example: `--timeout 30s` |
| `--json` | Output results as JSON instead of plain text |
| `--report <path>` | Append human-readable output to a file (ignored when using `--json`) |
| `--fail-on <severity>` | Exit `2` if any finding is at or above `info`, `low`, `medium`, `high` or `critical` |
| `--redact` | Mask the host name and your user name in output, JSON reports and snapshots (not serial numbers, UUIDs or IP addresses). Redact both sides of a `compare` or neither. |

### Findings

After the checks run, mac-compass interprets the output and lists findings, most severe first. Each is `pass`, `fail` (with a severity and a fix), `info`, or `error` (the check could not run). Checks without an evaluator still show raw output but produce no finding.

`--json` emits one report object (`schema_version` 1): tool and host metadata (macOS version/build, arch), `sections` with every check's raw result, `findings`, and a `summary`. Every check has a stable `id` such as `triage.sip`.

### Baseline and compare

```bash
# On a known-good Mac (use the same sudo setting both times):
sudo mac-compass snapshot -o baseline.json

# Later: what changed?
sudo mac-compass compare baseline.json            # snapshot now, then diff
mac-compass compare baseline.json today.json      # or diff two snapshots
sudo mac-compass compare baseline.json --fail-on medium
```

A snapshot is a normalized inventory: LaunchDaemons/Agents, login items, crontab, kernel and system extensions, TCP/UDP listeners, DNS servers, and security settings (SIP, Gatekeeper, firewall, FileVault, boot-args, update switches). Volatile details (pids, timestamps, sizes) are stripped. Additions are findings, removals are informational, and a changed setting is a finding. A setting that moves to its secure value (for example SIP turned back on) is reported as an improvement, not a failure. A different macOS version, host name or sudo setting between snapshots is reported so Apple's own post-update changes are not mistaken for tampering. Snapshot files are written with mode `0600`.

### Exit status and safety

- Exit `0`: every check ran (skipped checks do not count as failures) and no `--fail-on` threshold was met. Exit `1`: at least one check failed or timed out. Exit `2`: a finding met `--fail-on`.
- Checks are read-only. Each runs by absolute path with a fixed `PATH` and no `DYLD_*`/`LD_*` variables, so a poisoned environment cannot shadow system tools.
- Some commands treat a non-zero exit as normal (for example `grep` with no match); the catalog marks these with `ok_exit`.
- `--report` files are created with mode `0600`.
- Checks refuse to run off macOS. Set `MAC_COMPASS_ALLOW_NON_DARWIN=1` only for development.

### Examples

```bash
# Quick triage without sudo (fewer checks, but no root needed)
mac-compass triage --no-sudo

# Running in a VM? Skip hardware-dependent checks
mac-compass triage --vm

# Run every section without being prompted
mac-compass run-all -y

# Get triage results as JSON
mac-compass triage --json

# Save a human-readable report to a file
mac-compass triage --report ./my-report.txt
```

---

## Development

- **Check catalog:** `internal/catalog/checks.yaml`  -  all runnable checks; this file is embedded in the binary via `//go:embed`.
- **Runner:** `internal/runner/`  -  runs shell commands from the catalog (with optional sudo, timeouts, capture).
- **Commands:** `cmd/`  -  Cobra root and subcommands.

**Build:**

```bash
go build .
# or
make build
```

**Test:**

```bash
go test ./...
# or
make test
```

Tests cover: catalog loading and filtering by section, runner (ExpandUserHome, SkipSudo/VMMode behavior, simple command and script execution), JSON output encoding, the interactive menu choice mapping, and CLI integration (e.g. `--help`, `version`, `checklist`, `refs`). Runner tests that execute real commands are skipped on non-Unix environments.

The catalog is maintained from an external reference (not stored in this repo). When that reference changes, update `checks.yaml` and add or adjust checks as needed.

---

## License

See the [LICENSE](LICENSE) file in this repository.
