# Homebrew formula for mac-compass
# Install: brew tap jimididit/tap && brew install mac-compass
# Update url and sha256 for each release.

class MacCompass < Formula
  desc "Interactive CLI for macOS compromise detection"
  homepage "https://github.com/jimididit/mac-compass"
  url "https://github.com/jimididit/mac-compass/archive/refs/tags/v0.4.0.tar.gz"
  sha256 "" # run: shasum -a 256 <(curl -sL <tarball_url>)
  license "MIT"
  head "https://github.com/jimididit/mac-compass.git", branch: "main"

  depends_on :macos
  depends_on "go" => :build

  def install
    ldflags = %W[
      -s -w
      -X github.com/jimididit/mac-compass/cmd.version=#{version}
    ]
    system "go", "build", *std_go_args(ldflags: ldflags)
  end

  test do
    assert_match "mac-compass", shell_output("#{bin}/mac-compass version")
    assert_match "triage", shell_output("#{bin}/mac-compass --help")
  end
end
