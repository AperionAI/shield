#!/usr/bin/env bash
# Run the golden corpus through `aperion-shield --check` and report
# pass/fail per case. Designed for wide-scale rule validation, CI gates,
# and ad-hoc red-team exploration -- no MCP / IDE required.
#
# Usage:
#     scripts/check-corpus.sh                   # uses bundled corpus
#     scripts/check-corpus.sh path/to/my.jsonl  # uses your corpus
#     RULES=my.yaml scripts/check-corpus.sh     # custom ruleset
#     WORKSPACE=/tmp/prod-fixture scripts/check-corpus.sh
#                                               # fake a prod workspace
#     SHIELD_BIN=./target/release/aperion-shield \
#         scripts/check-corpus.sh               # custom binary path
#
# Exit code: 0 if every case met its `expect`, non-zero otherwise.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CORPUS="${1:-$ROOT/tests/corpus/golden.jsonl}"
SHIELD_BIN="${SHIELD_BIN:-aperion-shield}"
RULES="${RULES:-}"
WORKSPACE="${WORKSPACE:-}"

if [[ ! -f "$CORPUS" ]]; then
    echo "error: corpus file not found: $CORPUS" >&2
    exit 2
fi

if ! command -v "$SHIELD_BIN" >/dev/null 2>&1 && [[ ! -x "$SHIELD_BIN" ]]; then
    echo "error: SHIELD_BIN '$SHIELD_BIN' not found on PATH and not executable." >&2
    echo "  Build first:  cargo build --release   (binary lands in target/release/aperion-shield)" >&2
    echo "  Or set:       SHIELD_BIN=./target/release/aperion-shield $0" >&2
    exit 2
fi

cmd=("$SHIELD_BIN" --check)
[[ -n "$RULES"     ]] && cmd+=(--rules "$RULES")
[[ -n "$WORKSPACE" ]] && cmd+=(--workspace "$WORKSPACE")
# Decision memory + burst across a corpus run would skew expectations.
# Disable both for stable, deterministic batch runs.
cmd+=(--no-memory --no-burst)

echo "[corpus] binary  = $SHIELD_BIN"
echo "[corpus] corpus  = $CORPUS"
[[ -n "$RULES"     ]] && echo "[corpus] rules   = $RULES"
[[ -n "$WORKSPACE" ]] && echo "[corpus] workspace = $WORKSPACE"
echo "[corpus] running ..."
echo

tmp_out="$(mktemp)"
tmp_err="$(mktemp)"
trap 'rm -f "$tmp_out" "$tmp_err"' EXIT

set +e
"${cmd[@]}" <"$CORPUS" >"$tmp_out" 2>"$tmp_err"
rc=$?
set -e

# Print one human line per case.
fail=0
pass=0
nocheck=0
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if command -v jq >/dev/null 2>&1; then
        # Note: cannot use jq's `//` here -- it fires on both `null` and
        # `false`, which would conflate "no expectation" with "expectation
        # failed". `if . == null` distinguishes them correctly.
        passed=$(echo "$line"   | jq -r 'if .passed == null then "null" else (.passed|tostring) end')
        decision=$(echo "$line" | jq -r '.decision')
        expected=$(echo "$line" | jq -r '.expected // "(none)"')
        rule=$(echo "$line"     | jq -r '.primary_rule_id // "-"')
        if   [[ "$passed" == "true"  ]]; then pass=$((pass+1)); marker="PASS"
        elif [[ "$passed" == "false" ]]; then fail=$((fail+1)); marker="FAIL"
        else                                   nocheck=$((nocheck+1)); marker="----"
        fi
        printf "  %s  decision=%-9s expected=%-9s rule=%s\n" \
            "$marker" "$decision" "$expected" "$rule"
    else
        # Fallback: dump raw JSON.
        echo "  $line"
    fi
done <"$tmp_out"

echo
echo "[corpus] summary from shield --------"
sed 's/^/  /' "$tmp_err"
echo
echo "[corpus] tally: $pass pass / $fail fail / $nocheck unchecked"

if [[ $fail -gt 0 || $rc -ne 0 ]]; then
    exit 1
fi
exit 0
