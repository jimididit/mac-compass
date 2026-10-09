# Check reference

Every check is read-only and runs by absolute path.

- **Judged**: the output is interpreted into a pass/fail finding with a severity and a fix. Otherwise the raw output is shown.
- **Baseline**: the check feeds `snapshot` / `compare`.
- **sudo**: the check is skipped with `--no-sudo`.

A test keeps this page in step with `internal/catalog/checks.yaml`: every check id must appear here.


## Triage

Run first. Core protections and the quickest signs of tampering.

| Check id | What it looks at | sudo | Judged | Baseline | ATT&CK |
|---|---|:-:|:-:|:-:|---|
| `triage.sip` | Check System Integrity Protection status; expected "enabled" |  | ✓ | ✓ | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |
| `triage.sip-authenticated-root` | Sealed system volume status; expected "enabled" |  | ✓ | ✓ |  |
| `triage.gatekeeper` | Verify Gatekeeper (assessments) is enabled |  | ✓ | ✓ | [T1553.001](https://attack.mitre.org/techniques/T1553/001/) |
| `triage.kext-non-apple` | Loaded kernel extensions not signed by Apple (kmutil; kextstat is deprecated) |  | ✓ | ✓ | [T1547.006](https://attack.mitre.org/techniques/T1547/006/) |
| `triage.launchdaemons` | Quick check /Library/LaunchDaemons/ |  | ✓ | ✓ | [T1543.004](https://attack.mitre.org/techniques/T1543/004/) |
| `triage.launchagents-system` | Quick check /Library/LaunchAgents/ |  | ✓ | ✓ | [T1543.001](https://attack.mitre.org/techniques/T1543/001/) |

## Processes

What is running and what could be injecting into it.

| Check id | What it looks at | sudo | Judged | Baseline | ATT&CK |
|---|---|:-:|:-:|:-:|---|
| `processes.signatures` | Each distinct program currently running, with its code-signing and notarization state |  | ✓ |  | [T1036](https://attack.mitre.org/techniques/T1036/) |
| `processes.ps-all` | List all running processes with full details |  |  |  |  |
| `processes.high-cpu` | Processes using >50% CPU |  |  |  |  |
| `processes.high-memory` | Processes using >50% memory |  |  |  |  |
| `processes.launchctl-dyld` | Check for dyld env vars (dylib injection) in system domain | yes | ✓ | ✓ | [T1574.006](https://attack.mitre.org/techniques/T1574/006/) |

## Kernel and extensions

Kernel and system extensions, boot arguments, firmware.

| Check id | What it looks at | sudo | Judged | Baseline | ATT&CK |
|---|---|:-:|:-:|:-:|---|
| `kernel.kext-loaded` | All loaded kernel extensions (kmutil; kextstat is deprecated) |  |  | ✓ | [T1547.006](https://attack.mitre.org/techniques/T1547/006/) |
| `kernel.system-extensions` | Modern system extensions (replacement for KEXTs) |  | ✓ | ✓ | [T1547.006](https://attack.mitre.org/techniques/T1547/006/) |
| `kernel.nvram-boot-args` | Check boot-args for suspicious modifications |  | ✓ | ✓ |  |
| `kernel.efi-integrity` | Firmware integrity check (Intel Macs only; removed on newer macOS) | yes |  |  |  |

## Persistence

Ways code survives a reboot or login: launchd, login items, cron, shell startup, hooks.

| Check id | What it looks at | sudo | Judged | Baseline | ATT&CK |
|---|---|:-:|:-:|:-:|---|
| `persistence.system-launchdaemons` | /System/Library/LaunchDaemons/ |  |  | ✓ | [T1543.004](https://attack.mitre.org/techniques/T1543/004/) |
| `persistence.launchagents-user` | User LaunchAgents |  |  | ✓ | [T1543.001](https://attack.mitre.org/techniques/T1543/001/) |
| `persistence.launchctl-list` | Loaded system services | yes |  |  |  |
| `persistence.login-items` | Per-user login items |  |  | ✓ | [T1547.015](https://attack.mitre.org/techniques/T1547/015/) |
| `persistence.crontab` | Current user crontab |  | ✓ | ✓ | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) |
| `persistence.periodic-daily` | /etc/periodic/daily/ (absent on newer macOS, e.g. 26; absence is normal) |  |  |  |  |
| `persistence.btm` | Login items and background items registered with the system (raw dump) | yes | ✓ | ✓ | [T1547.015](https://attack.mitre.org/techniques/T1547/015/), [T1543.001](https://attack.mitre.org/techniques/T1543/001/), [T1543.004](https://attack.mitre.org/techniques/T1543/004/) |
| `persistence.launchd-targets` | Program each launch item runs, with its code-signing and notarization state |  | ✓ | ✓ | [T1543.001](https://attack.mitre.org/techniques/T1543/001/), [T1543.004](https://attack.mitre.org/techniques/T1543/004/) |
| `persistence.shell-rc` | SHA-256 of shell startup files (changes here run code at every shell) |  |  | ✓ | [T1546.004](https://attack.mitre.org/techniques/T1546/004/) |
| `persistence.login-hooks` | Deprecated loginwindow hooks that run a script as root at login or logout |  | ✓ | ✓ | [T1037.002](https://attack.mitre.org/techniques/T1037/002/) |
| `persistence.hosts` | Non-comment lines in /etc/hosts (used to redirect domains) |  | ✓ | ✓ |  |
| `persistence.sudoers-d` | Files in /etc/sudoers.d (a NOPASSWD file here is a classic privilege backdoor) |  | ✓ | ✓ | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) |

## Network

Listeners, connections, firewall, DNS and proxies.

| Check id | What it looks at | sudo | Judged | Baseline | ATT&CK |
|---|---|:-:|:-:|:-:|---|
| `network.listening-tcp` | All listening TCP ports | yes | ✓ | ✓ |  |
| `network.listening-udp` | UDP listeners | yes |  | ✓ |  |
| `network.firewall` | Application firewall global state | yes | ✓ | ✓ | [T1562.004](https://attack.mitre.org/techniques/T1562/004/) |
| `network.dns` | Current DNS configuration |  |  | ✓ |  |
| `network.resolv-conf` | /etc/resolv.conf |  |  |  |  |
| `network.proxy` | Configured HTTP/HTTPS/SOCKS/PAC proxies (a proxy can intercept traffic) |  | ✓ | ✓ |  |
| `network.established` | Current outbound TCP connections with the owning process | yes |  |  |  |

## Security tools and privacy

Disk encryption, malware signatures, profiles, MDM and privacy (TCC) grants.

| Check id | What it looks at | sudo | Judged | Baseline | ATT&CK |
|---|---|:-:|:-:|:-:|---|
| `security-tools.filevault` | Disk encryption status | yes | ✓ | ✓ |  |
| `security-tools.xprotect-version` | Version of Apple's built-in malware signatures |  | ✓ | ✓ |  |
| `security-tools.profiles` | Installed configuration profiles (MDM, VPN, certificates, restrictions) | yes | ✓ | ✓ |  |
| `security-tools.mdm-enrollment` | Whether this Mac is enrolled in device management | yes | ✓ | ✓ |  |
| `security-tools.tcc-system` | Apps allowed Full Disk Access, Accessibility, Screen Recording or input monitoring (system-wide) | yes | ✓ | ✓ | [T1548.006](https://attack.mitre.org/techniques/T1548/006/) |
| `security-tools.tcc-user` | Apps allowed Accessibility, Screen Recording or input monitoring for this user |  | ✓ | ✓ | [T1548.006](https://attack.mitre.org/techniques/T1548/006/) |

## Advanced

Extra launchd inspection.

| Check id | What it looks at | sudo | Judged | Baseline | ATT&CK |
|---|---|:-:|:-:|:-:|---|
| `advanced.endpoint-security` | Security-related launchd services | yes |  |  |  |

## Hardening

Preventive settings: updates and update policy.

| Check id | What it looks at | sudo | Judged | Baseline | ATT&CK |
|---|---|:-:|:-:|:-:|---|
| `harden.softwareupdate-list` | Available updates (contacts Apple) |  | ✓ |  |  |
| `harden.auto-update-settings` | Software Update preferences (auto-check, auto-download, critical updates) |  | ✓ | ✓ |  |

## Accounts and access

Local accounts, admins, remote-access keys, guest and auto login.

| Check id | What it looks at | sudo | Judged | Baseline | ATT&CK |
|---|---|:-:|:-:|:-:|---|
| `accounts.local-users` | Local accounts and their UIDs (an extra uid 0 account is a red flag) |  | ✓ | ✓ | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) |
| `accounts.admin-group` | Accounts with administrator rights |  | ✓ | ✓ | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) |
| `accounts.guest` | Whether the guest user is enabled at the login window |  | ✓ | ✓ |  |
| `accounts.autologin` | User that logs in automatically at boot, if any |  | ✓ | ✓ |  |
| `accounts.ssh-authorized-keys` | Fingerprints of keys that can log in over SSH as this user |  | ✓ | ✓ | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) |
