#!/usr/bin/env bash
# Render the Aperion Shield developer one-pager to PDF using headless Chrome.
#
# Default: dark theme — looks exactly like https://docs.aperion.ai (good for screen / Slack).
# Pass --light to get the white-background handout (good for print).
#
# Usage:
#   ./scripts/render-onepager-pdf.sh                       # → ./aperion-shield-onepager-dark.pdf
#   ./scripts/render-onepager-pdf.sh --light               # → ./aperion-shield-onepager-light.pdf
#   ./scripts/render-onepager-pdf.sh --out ~/Desktop/x.pdf
#   ./scripts/render-onepager-pdf.sh --url file:///tmp/onepager.html
#
# Requires: Google Chrome, Chromium, Brave, or Microsoft Edge installed.
# No npm / pip dependencies — pure shell + your browser binary.

set -euo pipefail

THEME="dark"
URL="https://docs.aperion.ai/aperion-shield-developer-onepager.html"
OUT=""

print_usage() {
  cat <<USAGE
render-onepager-pdf.sh — Aperion Shield one-pager → PDF

  --dark            Preserve the website's dark theme (default).
  --light           Render the white-background print handout.
  --url <URL>       Source URL (default: live docs site).
                    Use file://$PWD/docs/aperion-shield-developer-onepager.html for local.
  --out <PATH>      Output PDF path (default: aperion-shield-onepager-<theme>.pdf).
  -h, --help        Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dark)   THEME="dark";  shift ;;
    --light)  THEME="light"; shift ;;
    --url)    URL="$2";      shift 2 ;;
    --out)    OUT="$2";      shift 2 ;;
    -h|--help) print_usage; exit 0 ;;
    *) echo "[render-onepager-pdf] unknown arg: $1" >&2; print_usage; exit 2 ;;
  esac
done

if [[ -z "$OUT" ]]; then
  OUT="aperion-shield-onepager-${THEME}.pdf"
fi

# Append ?theme=dark for the dark export so the page's JS flips the print stylesheet.
if [[ "$THEME" == "dark" ]]; then
  if [[ "$URL" == *"?"* ]]; then FULL_URL="${URL}&theme=dark"
  else                            FULL_URL="${URL}?theme=dark"
  fi
else
  FULL_URL="$URL"
fi

# Locate a Chromium-family browser binary.
CANDIDATES=(
  "${CHROME_BIN:-}"
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
  "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"
  "/Applications/Chromium.app/Contents/MacOS/Chromium"
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
  "/usr/bin/google-chrome"
  "/usr/bin/google-chrome-stable"
  "/usr/bin/chromium"
  "/usr/bin/chromium-browser"
  "/snap/bin/chromium"
  "/snap/bin/google-chrome"
)

CHROME=""
for c in "${CANDIDATES[@]}"; do
  if [[ -n "$c" && -x "$c" ]]; then CHROME="$c"; break; fi
done

if [[ -z "$CHROME" ]]; then
  if command -v google-chrome >/dev/null 2>&1; then CHROME="$(command -v google-chrome)"
  elif command -v chromium >/dev/null 2>&1; then CHROME="$(command -v chromium)"
  elif command -v brave-browser >/dev/null 2>&1; then CHROME="$(command -v brave-browser)"
  fi
fi

if [[ -z "$CHROME" ]]; then
  cat >&2 <<'ERR'
[render-onepager-pdf] No Chromium-family browser found.

Install one of:
  - Google Chrome      https://www.google.com/chrome/
  - Chromium           brew install chromium       (macOS)
                       apt install chromium        (Debian/Ubuntu)
  - Brave              brew install --cask brave-browser

Or set CHROME_BIN=/path/to/chrome and re-run.
ERR
  exit 1
fi

echo "[render-onepager-pdf] browser : $CHROME"
echo "[render-onepager-pdf] url     : $FULL_URL"
echo "[render-onepager-pdf] theme   : $THEME"
echo "[render-onepager-pdf] output  : $OUT"

# headless=new is the modern headless mode. virtual-time-budget gives the JS
# a moment to swap the print stylesheets before the snapshot is taken.
"$CHROME" \
  --headless=new \
  --disable-gpu \
  --no-pdf-header-footer \
  --hide-scrollbars \
  --virtual-time-budget=10000 \
  --run-all-compositor-stages-before-draw \
  --print-to-pdf="$OUT" \
  "$FULL_URL"

if [[ -f "$OUT" ]]; then
  BYTES=$(wc -c <"$OUT" | tr -d ' ')
  printf '[render-onepager-pdf] done. %s (%s bytes)\n' "$OUT" "$BYTES"
else
  echo "[render-onepager-pdf] failed — no output file produced" >&2
  exit 1
fi
