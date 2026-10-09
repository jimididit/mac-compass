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
| `mac-compass monitor install` / `status` / `run` / `uninstall` | Watch for changes on a schedule ([details](#monitor-mode)) |
| `mac-compass collect` | Run everything and save a hashed evidence bundle ([details](#evidence-bundles)) |
| `mac-compass verify FOLDER` | Check an evidence bundle against its manifest |
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
| `--html <file>` | Also write a self-contained HTML report ([details](#report-formats)) |
| `--sarif <file>` | Also write a SARIF 2.1.0 report ([details](#report-formats)) |
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

## Report formats

Besides the terminal output and `--json`, any run can also write:

- **`--html report.html`**: one self-contained page you can open in a browser, print, or send. Findings are
  grouped by severity with the fix and ATT&CK links, followed by accepted findings and a table of every
  check. It contains no scripts and makes no network requests, and a content-security policy enforces that,
  so text from the examined Mac (file names, process names) cannot do anything when the page is opened.
- **`--sarif report.sarif`**: [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) for tools that
  ingest it (viewers, DefectDojo and similar). Each finding is a result with a stable fingerprint, a level
  (`error` for high and critical, `warning` for medium, `note` otherwise) and its ATT&CK ids as tags. Findings
  describe a machine rather than source files, so they carry the host as a logical location; GitHub code
  scanning, which needs file locations, will not display them. Passing findings are left out.

Both files are written with mode `0600`, honour `--redact` and `--suppress`, and also work with `compare`.
`collect` stores `report.html` in the evidence bundle automatically.

```bash
sudo mac-compass run-all -y --html report.html --sarif report.sarif
```

## Monitor mode

`mac-compass monitor` runs the comparison on a schedule through launchd and alerts you when something new and
serious appears.

```bash
mac-compass monitor install            # a LaunchAgent for you; runs every hour
mac-compass monitor status             # installed? loaded? what did it last see?
mac-compass monitor uninstall [--purge]
```

The first run records a **baseline** of this Mac. Every later run takes a fresh snapshot, compares it with that
baseline, and raises an alert only when the set of findings at or above `--notify-on` (default `medium`)
**changes**. The same unresolved problem is not announced every hour, and a problem that goes away and comes
back alerts again. Each run's comparison is kept in `history/` (the newest 50) and the latest in `latest.json`,
in the state folder with the baseline, `state.json` and `monitor.log` (emptied once it passes 1 MB).

| | `--scope user` (default) | `--scope system` (needs `sudo`) |
|---|---|---|
| Installs | a LaunchAgent in `~/Library/LaunchAgents` | a root LaunchDaemon in `/Library/LaunchDaemons` |
| Checks that run | unprivileged ones | all of them, as root |
| Alerts | desktop notifications, plus the log | the log and `state.json` only |
| State folder | `~/Library/Application Support/mac-compass` | `/Library/Application Support/mac-compass` |

Options: `--every 30m` (minimum 5 minutes), `--notify-on high`, `--suppress file.yaml` to accept reviewed
findings, `--no-load` to write the plist without loading it, and `monitor run --rebaseline` to accept the current
state as the new baseline after a legitimate change (an update, new software).

**Security notes.** A root daemon runs the mac-compass binary as root on a schedule, so `install --scope system`
refuses unless the binary and every folder above it are owned by root and not writable by anyone else (for
example `sudo cp mac-compass /usr/local/bin/`); otherwise whoever can replace the file could get root. The
monitor does not repair a damaged baseline silently, because that would hide changes: it reports the error and
asks for `--rebaseline`. The job's own plist appears as a launch item on the next comparison, so install it
before you take the baseline you care about.

## Evidence bundles

`mac-compass collect` runs every check once and writes a folder you can keep or hand to someone else:

```text
mac-compass-evidence-20261009T151500Z/
  report.json       the full report: every check's raw result, findings, summary
  report.html       the same findings as a page you can open and share
  snapshot.json     the baseline snapshot, ready for `compare`
  findings.txt      the findings as printed in the terminal
  raw/<check-id>.txt  stdout, stderr, exit code and timing of each check
  MANIFEST.json     SHA-256 and size of every file above
  MANIFEST.sha256   the SHA-256 of MANIFEST.json (the "bundle hash")
```

The folder is created with mode `0700` and refuses to write into a folder that already has files.
It prints the **bundle hash**. Record it somewhere other than the Mac you examined, then check the bundle any
time:

```bash
sudo mac-compass collect -o /Volumes/Evidence/laptop-2026-10-09      # an external drive is best
mac-compass verify /Volumes/Evidence/laptop-2026-10-09 --expect <the hash you recorded>
```

`verify` re-hashes every file and reports changed, missing and unlisted files. Without `--expect` it only
proves the files match the manifest; someone able to edit a file could also have rewritten the manifest. The
hash you recorded elsewhere is what closes that gap. Use `--redact` to mask the host and user name inside the
bundle, and `--suppress` to move reviewed findings out of the active list.

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
