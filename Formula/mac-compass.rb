# Homebrew formula for mac-compass. It installs the signed universal release archive, so no Go toolchain
# is needed and macOS does not show a first-run prompt (Homebrew downloads are not quarantined).
#
#   brew tap jimididit/mac-compass https://github.com/jimididit/mac-compass
#   brew install mac-compass
#
# For each release, point url at the new archive and set sha256 from the release's checksums.txt.

class MacCompass < Formula
  desc "Triage, baseline and audit a Mac from the command line"
  homepage "https://github.com/jimididit/mac-compass"
  url "https://github.com/jimididit/mac-compass/releases/download/v0.4.0/mac-compass_0.4.0_macos_universal.tar.gz"
  sha256 "9b810d6715d802ab56f5b6ac3af4c2a16aa7eb1433736b8c8928af3523cf58b1"
  license "MIT"

  depends_on :macos

  def install
    bin.install "mac-compass"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/mac-compass version")
    assert_match "triage", shell_output("#{bin}/mac-compass --help")
  end
end
