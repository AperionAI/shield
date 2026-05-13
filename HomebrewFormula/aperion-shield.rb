# typed: false
# frozen_string_literal: true
#
# Homebrew formula for aperion-shield. Lives in this repo so the
# release pipeline can mirror it into `AperionAI/homebrew-tap` on
# every tag bump.
#
# Once published:
#   brew tap AperionAI/tap
#   brew install aperion-shield
class AperionShield < Formula
  desc     "Local MCP guardrail for AI coding agents"
  homepage "https://shield.aperion.ai"
  license  "Apache-2.0"
  version  "0.2.1"

  on_macos do
    on_arm do
      url "https://github.com/AperionAI/shield/releases/download/shield-v#{version}/aperion-shield-shield-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
    on_intel do
      url "https://github.com/AperionAI/shield/releases/download/shield-v#{version}/aperion-shield-shield-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/AperionAI/shield/releases/download/shield-v#{version}/aperion-shield-shield-v#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
    on_intel do
      url "https://github.com/AperionAI/shield/releases/download/shield-v#{version}/aperion-shield-shield-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
  end

  def install
    bin.install "aperion-shield"
    pkgshare.install "shield.example.yaml" if File.exist?("shield.example.yaml")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/aperion-shield --version")
    # Smoke test the bundled-rule load path; should print help and exit
    # cleanly (no upstream MCP given is a usage error returning 1).
    assert_match "no upstream MCP server command",
      shell_output("#{bin}/aperion-shield 2>&1", 1)
  end
end
