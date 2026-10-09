# Running mac-compass on your Mac

mac-compass checks a Mac for signs of compromise and weak security settings. It only **reads** system
state: it does not change settings, install anything, or send data anywhere. Everything it prints stays in
your Terminal unless you save it. (One check, `softwareupdate -l`, asks Apple which updates exist.)

## 1. Unpack

Double-click the `.tar.gz` file you were sent. You get a folder with `mac-compass`, `README.md`,
`LICENSE` and this file. Open **Terminal** and go to that folder, for example:

```bash
cd ~/Downloads/mac-compass_*_macos_universal
```

## 2. Allow it to run

The program is not signed with an Apple Developer ID yet, so macOS may block a file that arrived by
download, AirDrop or email. Only do this if you trust whoever sent it:

```bash
xattr -dr com.apple.quarantine .
chmod +x mac-compass
./mac-compass version
```

If that prints `zsh: killed` instead of a version, sign it locally and try again:

```bash
codesign --force --sign - ./mac-compass
./mac-compass version
```

## 3. Run it

A quick look, no password needed:

```bash
./mac-compass triage --no-sudo
```

The full check. It asks for your password because some checks need administrator rights:

```bash
sudo ./mac-compass run-all -y
```

You get the raw output of every check, then a **Findings** list sorted by severity with a suggested fix
for each. Many findings are normal (for example a third-party launch item you installed on purpose). The
tool tells you what is there and why it matters, not that it is malicious.

## 4. Share the result (optional)

To save a report you can send back, mask your computer name and user name first:

```bash
sudo ./mac-compass run-all -y --json --redact > ~/Desktop/mac-compass-report.json
```

`--redact` hides the host name and your account name. It does **not** hide serial numbers, IP addresses or
other accounts' names, so look through the file before you send it.

## 5. Keep a baseline (optional)

On a Mac you trust, save a snapshot. Later, compare against it to see exactly what was added or changed:

```bash
sudo ./mac-compass snapshot -o ~/baseline.json
sudo ./mac-compass compare ~/baseline.json
```

## Troubleshooting

- **A check says "permission denied" or the Privacy checks are empty:** give Terminal *Full Disk Access*
  (System Settings > Privacy & Security > Full Disk Access), quit and reopen Terminal, run again.
- **"Operation not permitted" on a file the program reads:** same fix as above.
- **Which Mac am I on?** `uname -m` prints `arm64` (Apple Silicon) or `x86_64` (Intel). The universal
  binary runs on both.
- **Exit codes:** `0` all checks ran; `1` at least one check failed to run; `2` a finding met `--fail-on`.
- Supported: macOS 15 and 26 are tested; 12 to 14 and 27 should work.
