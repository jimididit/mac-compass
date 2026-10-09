# Releasing mac-compass

Releases are built by GitHub Actions from a `v*` tag using GoReleaser (`.goreleaser.yaml`,
`.github/workflows/release.yml`). The release is created as a **draft**; nothing is public until you
publish it.

## Cut a release

1. Make sure `main` is green (CI includes real macOS 15 and 26 runs).
2. Pick the version (semver) and tag it:

   ```bash
   git checkout main && git pull
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

3. The `release` workflow runs the tests, builds darwin arm64 + amd64 and a universal binary, writes
   `checksums.txt`, creates a draft GitHub release and attaches a build provenance attestation.
4. Review the draft (notes, assets, checksums), then publish it.
5. Verify what you published:

   ```bash
   gh release download v0.2.0 --repo jimididit/mac-compass
   shasum -a 256 -c checksums.txt --ignore-missing
   gh attestation verify mac-compass_0.2.0_macos_universal.tar.gz --repo jimididit/mac-compass
   ```

To try the pipeline without publishing anything: `goreleaser release --snapshot --clean` (output in `dist/`).

## Homebrew

`Formula/mac-compass.rb` builds from the tagged source. After publishing a release, update its `url`
and `sha256` (`shasum -a 256` of the tag's source tarball), then copy it into a tap repository
(`jimididit/homebrew-tap`, `Formula/mac-compass.rb`) so that `brew install jimididit/tap/mac-compass` works.
Create the tap repository by hand; the release workflow does not push to it.

## Signing and notarization (not set up yet)

Needs an Apple Developer ID Application certificate. When you have one, add the certificate and the
App Store Connect API key as repository secrets and enable GoReleaser's `notarize` section, then update
the README and SECURITY.md wording. Until then the binaries are unsigned and verified by checksum and
provenance attestation only.
