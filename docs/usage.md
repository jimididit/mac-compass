# Usage reference

## Commands

| Command | What it does |
|---|---|
| `mac-compass` | Interactive menu (loops until you press `q`) |
| `mac-compass triage` | Quick triage: SIP, Gatekeeper, kernel extensions, launch items. Run this first |
| `mac-compass run-all` | Every section; asks for confirmation unless `-y` |
| `mac-compass processes` · `kernel` · `persistence` · `network` · `security-tools` · `advanced` · `harden` · `accounts` | One section at a time |
| `mac-compass snapshot` | Record a baseline ([details](baseline.md)) |
| `mac-compass compare BASELINE [CURRENT]` | Show what changed since a baseline ([details](baseline.md)) |
| `mac-compass checklist` | Incident-response checklist (runs nothing) |
| `mac-compass refs` | Links to further reading (runs nothing) |
| `mac-compass version` | Print the version |
| `mac-compass completion <shell>` | Shell completions (bash, zsh, fish, powershell) |

## Flags

These work on every command that runs checks.

| Flag | Description |
|---|---|
| `--no-sudo` | Skip checks that need administrator rights (they are reported as skipped, not failed) |
| `--vm` | Skip checks that need real hardware (Secure Enclave, EFI integrity) |
| `--timeout <duration>` | Per-check time limit (default `90s`) |
| `--json` | One JSON report instead of text |
| `--report <path>` | Also append the text output to a file (mode `0600`) |
| `--fail-on <severity>` | Exit `2` if any finding is at or above `info`, `low`, `medium`, `high` or `critical` |
| `--suppress <file>` | Accept reviewed findings ([details](baseline.md#accepting-reviewed-findings)) |
| `--redact` | Mask the host name and your user name in output, reports and snapshots |

## Reading the results

After the raw output of each check, mac-compass prints a **Findings** list, most severe first. Each is one of:

| Status | Meaning |
|---|---|
| `fail` | Something worth attention, with a **severity** (`low` to `critical`) and a suggested fix |
| `info` | Worth knowing, no judgement (for example the list of third-party launch items) |
| `pass` | Checked and as expected (hidden in text output, present in JSON) |
| `error` | The check could not run, so nothing can be concluded |

Many `fail` findings are normal on a machine you set up yourself. mac-compass tells you what is there and why it
matters, not that it is malicious. Use [suppressions](baseline.md#accepting-reviewed-findings) to record the ones
you have reviewed.

## JSON report

`--json` prints one object (`schema_version` 1):

```jsonc
{
  "tool":     { "name": "mac-compass", "version": "0.2.0" },
  "host":     { "hostname": "…", "macos_version": "26.6.2", "macos_build": "25G83", "arch": "arm64" },
  "sections": [ { "section": "triage", "checks": [ { "id": "triage.sip", "ok": true, "stdout": "…" } ] } ],
  "findings": [ { "id": "triage.sip", "status": "fail", "severity": "high", "title": "…",
                  "remediation": "…", "attack": ["T1562.001"] } ],
  "suppressed": [ /* findings you accepted, with your reason */ ],
  "summary":  { "pass": 12, "fail": 6, "info": 2, "error": 0, "highest_severity": "high" }
}
```

## Exit status

| Code | Meaning |
|---|---|
| `0` | Every check ran, and no `--fail-on` threshold was met |
| `1` | At least one check failed to run or timed out |
| `2` | A finding met the `--fail-on` severity |

## Safety

- Checks only **read** system state. A test fails if a mutating command is added.
- Each check runs by absolute path with a fixed `PATH` and without `DYLD_*` / `LD_*` variables.
- Privileged checks run through `sudo`; `--no-sudo` skips them.
- Reports and snapshots are written with mode `0600`.
- Checks refuse to run off macOS (set `MAC_COMPASS_ALLOW_NON_DARWIN=1` for development only).
