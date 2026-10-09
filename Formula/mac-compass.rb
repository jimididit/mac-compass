# Homebrew formula for mac-compass. It installs the signed universal release archive, so no Go toolchain
# is needed and macOS does not show a first-run prompt (Homebrew downloads are not quarantined).
#
#   brew tap jimididit/mac-compass https://github.com/jimididit/mac-compass
#   brew trust --formula jimididit/mac-compass/mac-compass   # Homebrew 6 requires trusting third-party taps
#   brew install mac-compass
#
# For each release, point url at the new archive and set sha256 from the release's checksums.txt.

class MacCompass < Formula
  desc "Triage, baseline and audit a Mac from the command line"
  homepage "https://github.com/jimididit/mac-compass"
  url "https://github.com/jimididit/mac-compass/releases/download/v0.4.1/mac-compass_0.4.1_macos_universal.tar.gz"
  sha256 "0565fc8d3440ddcf395f36c0a2f46658b137209d5f6d3ea59b626c191c73278c"
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
