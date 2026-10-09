# Baselines and accepting reviewed findings

## Baseline: snapshot and compare

A baseline answers "what changed since this Mac was known to be good?"

```bash
# On a Mac you trust (use the same sudo setting both times):
sudo mac-compass snapshot -o baseline.json

# Later:
sudo mac-compass compare baseline.json            # takes a fresh snapshot, then diffs
mac-compass compare baseline.json today.json      # or diff two snapshots
sudo mac-compass compare baseline.json --fail-on medium
```

A snapshot is a normalized inventory: LaunchDaemons and LaunchAgents, background items, login items, crontab,
shell startup file hashes, kernel and system extensions, TCP/UDP listeners, DNS servers, proxies, local
accounts and admins, SSH keys, privacy grants, and security settings (SIP, Gatekeeper, firewall, FileVault,
`boot-args`, update switches). Volatile details such as process ids, timestamps and file sizes are stripped,
so an untouched machine compares clean. Snapshot files are written with mode `0600`.

**How differences are reported**

| Change | Result |
|---|---|
| New item (daemon, listener, extension, admin, key, grant…) | `fail`, severity by kind |
| Item removed | `info` |
| Setting changed for the worse | `fail` |
| Setting moved to its secure value (for example SIP turned back on) | `info`, "improved" |
| Different macOS version, host name, or sudo setting | `info`, so Apple's own post-update changes are not mistaken for tampering |
| Check present in only one snapshot | counted as "not comparable", never a change |

Use `--redact` on both snapshots or neither; a masked and an unmasked snapshot differ.

## Accepting reviewed findings

Once you have investigated a finding and decided it is fine, record that instead of seeing it on every run.
Copy [`suppressions.example.yaml`](../suppressions.example.yaml), edit it, and pass it with `--suppress`
(works with `run-all`, the section commands and `compare`):

```bash
sudo mac-compass run-all -y --suppress suppressions.yaml
```

```yaml
suppressions:
  - id: network.firewall                 # the check id shown in the JSON report
    reason: Managed by our MDM profile   # required
    expires: 2027-01-01                  # optional: re-review after this day

  - id: security-tools.tcc-system
    match: /usr/bin/osascript            # optional: accept only detail lines containing this text
    reason: Our automation tooling needs Accessibility; reviewed
```

- With only `id`, every finding from that check is accepted.
- With `match`, only the detail lines containing that text are accepted (case-insensitive). Anything new in
  the same finding still shows, so a reviewed item cannot hide a new one.
- Accepted findings are removed from the results, the summary and `--fail-on`, but they are **listed in the
  output and in the JSON `suppressed` array with your reason**. Nothing is silently hidden.
- An expired rule is ignored and reported, prompting a re-review.
