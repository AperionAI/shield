#!/bin/sh
# Aperion Shield installer.
#
#   curl -fsSL https://shield-get.aperion.ai | sh
#
# Detects OS/arch, downloads the matching GitHub Release tarball, verifies
# its SHA-256 sidecar, and drops `aperion-shield` onto PATH. POSIX sh; needs
# curl + tar + (shasum or sha256sum).
#
# Override:
#   SHIELD_VERSION=shield-v1.5.0     pin a tag (default: latest)
#   SHIELD_INSTALL_DIR=~/.local/bin  destination
#   SHIELD_DIST_REPO=AperionAI/shield
set -eu

REPO="${SHIELD_DIST_REPO:-AperionAI/shield}"
BIN="aperion-shield"
INSTALL_DIR="${SHIELD_INSTALL_DIR:-}"
VERSION="${SHIELD_VERSION:-latest}"

err() { echo "shield-install: $*" >&2; exit 1; }

path_hint() {
  dir="$1"
  echo "shield-install: NOTE: $dir is not on your PATH."
  echo "  This shell:"
  echo "    export PATH=\"$dir:\$PATH\""
  shellname="$(basename "${SHELL:-sh}")"
  case "$shellname" in
    zsh) rc="$HOME/.zshrc" ;;
    bash)
      if [ "$(uname -s)" = Darwin ]; then rc="$HOME/.bash_profile"
      else rc="$HOME/.bashrc"
      fi
      ;;
    fish) rc="$HOME/.config/fish/config.fish" ;;
    *) rc="$HOME/.profile" ;;
  esac
  echo "  Permanent:"
  if [ "$shellname" = fish ]; then
    echo "    echo 'fish_add_path $dir' >> $rc"
  else
    echo "    echo 'export PATH=\"$dir:\$PATH\"' >> $rc"
  fi
}

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Linux)  os_part="unknown-linux-gnu" ;;
    Darwin) os_part="apple-darwin" ;;
    *) err "unsupported OS '$os'. Windows: download the .zip from https://github.com/$REPO/releases" ;;
  esac
  case "$arch" in
    x86_64|amd64) arch_part="x86_64" ;;
    arm64|aarch64) arch_part="aarch64" ;;
    *) err "unsupported architecture '$arch'" ;;
  esac
  echo "${arch_part}-${os_part}"
}

# Prefer a directory already on PATH so the next line of
#   curl | sh && aperion-shield --scan-ide
# actually runs this binary. Homebrew leftovers (1.0.x) sit earlier on
# PATH than ~/.local/bin and make --scan-ide look like an unknown flag.
pick_install_dir() {
  if [ -n "$INSTALL_DIR" ]; then echo "$INSTALL_DIR"; return; fi

  existing="$(command -v aperion-shield 2>/dev/null || true)"
  if [ -n "$existing" ]; then
    ed="$(dirname "$existing")"
    if [ -w "$ed" ]; then echo "$ed"; return; fi
  fi

  for d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin" "$HOME/.cargo/bin"; do
    case ":$PATH:" in
      *":$d:"*)
        if [ -d "$d" ] && [ -w "$d" ]; then echo "$d"; return; fi
        ;;
    esac
  done

  if [ -w /usr/local/bin ] 2>/dev/null; then echo /usr/local/bin; return; fi
  echo "$HOME/.local/bin"
}

warn_if_shadowed() {
  dir="$1"
  installed="$dir/$BIN"
  resolved="$(command -v aperion-shield 2>/dev/null || true)"
  [ -n "$resolved" ] || return 0
  inst_real="$(cd "$dir" && pwd)/$BIN"
  if [ "$resolved" = "$installed" ] || [ "$resolved" = "$inst_real" ]; then
    return 0
  fi
  old_ver="$("$resolved" --version 2>/dev/null || echo unknown)"
  new_ver="$("$installed" --version 2>/dev/null || echo unknown)"
  echo "shield-install: WARNING: PATH still prefers an older binary."
  echo "  PATH hits:    $resolved  ($old_ver)"
  echo "  this install: $installed  ($new_ver)"
  echo "  Homebrew leftover:  brew unlink aperion-shield"
  echo "  This shell:         export PATH=\"$dir:\$PATH\""
  echo "  Then:               aperion-shield --version   # must read 1.6+"
}

resolve_tag() {
  if [ "$VERSION" = "latest" ]; then
    json="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest")" || err "couldn't resolve latest release"
    tag="$(printf '%s\n' "$json" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$tag" ] || err "latest release has no tag_name"
    echo "$tag"
    return
  fi
  case "$VERSION" in
    shield-v*) echo "$VERSION" ;;
    v*) echo "shield-$VERSION" ;;
    *) echo "shield-v$VERSION" ;;
  esac
}

main() {
  command -v curl >/dev/null 2>&1 || err "curl is required"
  command -v tar  >/dev/null 2>&1 || err "tar is required"

  target="$(detect_target)"
  tag="$(resolve_tag)"
  asset="aperion-shield-${tag}-${target}.tar.gz"
  url="https://github.com/$REPO/releases/download/$tag/$asset"

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  echo "shield-install: downloading $asset ..."
  curl -fSL "$url" -o "$tmp/$asset" || err "download failed: $url"

  if curl -fSL "$url.sha256" -o "$tmp/$asset.sha256" 2>/dev/null; then
    echo "shield-install: verifying checksum ..."
    (
      cd "$tmp"
      expected="$(cut -d' ' -f1 < "$asset.sha256")"
      if command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$asset" | cut -d' ' -f1)"
      else
        actual="$(sha256sum "$asset" | cut -d' ' -f1)"
      fi
      [ "$expected" = "$actual" ] || err "checksum mismatch (expected $expected, got $actual)"
    )
  else
    echo "shield-install: NOTE: no .sha256 sidecar; skipping checksum"
  fi

  tar -xzf "$tmp/$asset" -C "$tmp"
  bin_src=""
  if [ -f "$tmp/$BIN" ]; then
    bin_src="$tmp/$BIN"
  else
    bin_src="$(find "$tmp" -type f -name "$BIN" | head -1)"
  fi
  [ -n "$bin_src" ] && [ -f "$bin_src" ] || err "archive did not contain $BIN"

  dir="$(pick_install_dir)"
  mkdir -p "$dir"
  install -m 0755 "$bin_src" "$dir/$BIN"

  echo "shield-install: installed to $dir/$BIN"
  if [ -z "$INSTALL_DIR" ] && [ "$dir" = "$HOME/.local/bin" ]; then
    echo "shield-install: NOTE: personal $HOME/.local/bin -- only visible to $(whoami)."
    echo "  Shared box: SHIELD_INSTALL_DIR=/usr/local/bin sudo -E sh -c 'curl -fsSL https://shield-get.aperion.ai | sh'"
  fi
  case ":$PATH:" in
    *":$dir:"*) : ;;
    *) path_hint "$dir" ;;
  esac
  warn_if_shadowed "$dir"
  "$dir/$BIN" --version || true
  echo "shield-install: done. Next: 'aperion-shield --version' (must be 1.6+), then"
  echo "  aperion-shield --install-agent-hooks && aperion-shield --scan-ide"
}

main "$@"
