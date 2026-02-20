# mac-compass

**mac-compass** is an interactive CLI that helps you check a macOS system for signs of compromise. It runs a catalog of security and triage checks - SIP, Gatekeeper, kernel extensions, persistence locations, network state, and more - so you can quickly see what’s on the system without memorizing commands.

- **Repository:** [github.com/jimididit/mac-compass](https://github.com/jimididit/mac-compass)
- **Platform:** macOS only (tested on Sequoia)
- **Requirements:** Many checks need `sudo`; run with an admin account when you want full results.

---

## Install

### From source (Go 1.21+)

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

Run **mac-compass** with no arguments to get a numbered menu. Enter a number or subcommand name to run that section.

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

**Build and test:**

```bash
go build .
go test ./...
# or
make build
make test
```

The catalog is maintained from an external reference (not stored in this repo). When that reference changes, update `checks.yaml` and add or adjust checks as needed.

---

## License

See the [LICENSE](LICENSE) file in this repository.
