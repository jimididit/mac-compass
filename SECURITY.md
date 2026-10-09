# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: **Security > Report a vulnerability** on
[jimididit/mac-compass](https://github.com/jimididit/mac-compass/security/advisories/new). Do not open a
public issue for a vulnerability. Expect an acknowledgement within a few days.

Supported version: the latest release and `main`.

## What mac-compass does and does not do

- It only runs **read-only** system commands from its embedded catalog (`internal/catalog/checks.yaml`),
  by absolute path, with a fixed `PATH` and without `DYLD_*`/`LD_*` variables. A test fails if a mutating
  command (for example `kextcache`) is added.
- Privileged checks run through `sudo`. Use `--no-sudo` to skip them.
- It makes no network connections of its own. One check (`softwareupdate -l`) contacts Apple.
- Reports and snapshots contain host details and are written with mode `0600`. Use `--redact` before
  sharing them; it masks the host name and your user name, not serial numbers, UUIDs or IP addresses.

## Limits you should know about

- **A compromised Mac can lie.** Every check relies on the operating system and its tools. Malware with
  kernel or root access can falsify their output. A clean result is evidence, not proof. For a machine you
  strongly suspect, collect evidence from outside it (network logs, a forensic image) as well.
- Findings are heuristics. Third-party LaunchDaemons, TCC grants by path, a proxy and so on are often
  legitimate; the tool tells you what is there and why it matters, not that it is malicious.
- Release binaries are not yet signed or notarized with an Apple Developer ID. Verify the checksum and the
  build provenance attestation (see the README) before running a downloaded binary as root.
