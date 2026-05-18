#!/usr/bin/env python3
"""Backward-compat wrapper around `aperion-shield --diff`.

The behavior-diff explainer is now native Rust as of v0.6.0
(2026-05-18). This script remains in the tree so that CI workflows
or developer aliases originally wired against the Python prototype
keep working unchanged -- it just `exec`'s `aperion-shield --diff`
with the same arguments.

The `--format json` output schema is source-compatible with the
prototype, so callers consuming that JSON do not need to be updated.

Two prototype-only flags are silently dropped because they have no
equivalent in the native mode:

  --shield-bin PATH   -- the native mode IS the binary; if you need
                         to pick a non-PATH binary, invoke it
                         directly: `/path/to/aperion-shield --diff ...`

No other behaviour change. See `aperion-shield --diff --help` for
the full flag set, and `docs/shieldset-as-code.md` Layer 4 for the
PR-review pattern this enables.
"""

from __future__ import annotations

import os
import shutil
import sys


def main() -> int:
    args = sys.argv[1:]
    # Strip the prototype-only flag that the native mode does not
    # accept. `--shield-bin PATH` was used to pick which binary to
    # shell out to; the native mode IS the binary, so this is moot.
    out_args: list[str] = []
    i = 0
    explicit_bin: str | None = None
    while i < len(args):
        a = args[i]
        if a == "--shield-bin" and i + 1 < len(args):
            explicit_bin = args[i + 1]
            i += 2
            continue
        if a.startswith("--shield-bin="):
            explicit_bin = a.split("=", 1)[1]
            i += 1
            continue
        out_args.append(a)
        i += 1

    # Resolve which `aperion-shield` to invoke.
    bin_path = explicit_bin or shutil.which("aperion-shield")
    if not bin_path:
        sys.stderr.write(
            "error: `aperion-shield` not found on PATH.\n"
            "       install it via `brew install AperionAI/tap/aperion-shield`\n"
            "       or `cargo install aperion-shield`, then re-run.\n"
        )
        return 2

    # Hand off the entire diff invocation to the native mode.
    cmd = [bin_path, "--diff", *out_args]
    os.execvp(cmd[0], cmd)
    # execvp never returns on success; if we get here, raise.
    return 2


if __name__ == "__main__":
    sys.exit(main())
