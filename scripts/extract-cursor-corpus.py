#!/usr/bin/env python3
"""Extract a Shield --check corpus from Cursor agent transcripts.

Cursor stores every agent conversation as JSON-Lines on disk under
~/.cursor/projects/<project>/agent-transcripts/<uuid>/<uuid>.jsonl
(plus subagents/<uuid>.jsonl). Each event is `{role, message}` where
message.content is a list whose items are either `{type:"text",text}`
or `{type:"tool_use",name,input,...}`.

This script walks every transcript, pulls out
  * Shell / run_terminal_cmd commands  -> tool_call scope
  * Assistant text turns               -> llm_response scope
deduplicates, redacts obvious secrets, and emits JSON-Lines in the
exact schema `aperion-shield --check` expects.

Usage:
    python3 scripts/extract-cursor-corpus.py \
        > tests/corpus/my-cursor-history.jsonl

    # Then:
    aperion-shield --check < tests/corpus/my-cursor-history.jsonl

Or pipe straight through:

    python3 scripts/extract-cursor-corpus.py \
        | aperion-shield --check \
        | jq -c 'select(.decision != "allow")'

Flags:
    --root DIR        override ~/.cursor/projects (default: $HOME/.cursor/projects)
    --project NAME    only this project folder (substring match)
    --shell-only      omit assistant text (llm_response scope) -- tool_calls only
    --text-only       only assistant text
    --max-text LEN    truncate each assistant text turn (default: 4000 chars)
    --keep-dup        do NOT deduplicate (default: dedupe by command/text)
    --raw             skip the secret redaction pass
    --limit N         stop after N output lines

No network. No data leaves your machine. Reads transcripts only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
from typing import Iterable


# Tool names Cursor uses for shell execution. The MCP-equivalent target
# (Shield's `run_terminal`) is what we emit.
SHELL_TOOL_NAMES = {"Shell", "run_terminal_cmd", "run_terminal", "Bash"}

# Argument keys Cursor uses for the command string.
COMMAND_KEYS = ("command", "cmd", "bash", "shell_command")

# Best-effort redactions for credentials that occasionally show up in
# prompts / outputs. Pattern -> replacement. These are intentionally
# conservative; review the output before sharing it.
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"AKIA[A-Z0-9]{16}"),                       "AKIA<REDACTED>"),
    (re.compile(r"ASIA[A-Z0-9]{16}"),                       "ASIA<REDACTED>"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"),                    "sk-<REDACTED>"),
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),              "sk-ant-<REDACTED>"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"),                   "ghp_<REDACTED>"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),           "github_pat_<REDACTED>"),
    (re.compile(r"xoxb-[A-Za-z0-9-]{20,}"),                 "xoxb-<REDACTED>"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
                                                            "eyJ<REDACTED.JWT>"),
    # AWS secret keys are 40 chars; match common shell-assignment shapes.
    (re.compile(r"(AWS_SECRET_ACCESS_KEY\s*[:=]\s*['\"]?)[A-Za-z0-9/+=]{40}",
                re.IGNORECASE),                             r"\1<REDACTED>"),
]


def redact(text: str) -> str:
    if not text:
        return text
    out = text
    for pat, sub in SECRET_PATTERNS:
        out = pat.sub(sub, out)
    return out


def iter_transcripts(root: pathlib.Path, project: str | None) -> Iterable[pathlib.Path]:
    """Yield every `*.jsonl` transcript under the Cursor projects tree."""
    if not root.exists():
        print(f"[extract] root not found: {root}", file=sys.stderr)
        return
    for p in root.rglob("*.jsonl"):
        if project and project not in str(p):
            continue
        yield p


def iter_events(path: pathlib.Path) -> Iterable[dict]:
    """Yield parsed events from a transcript file, skipping garbage."""
    try:
        f = path.open("r", encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"[extract] open failed {path}: {e}", file=sys.stderr)
        return
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def extract_shell_command(tool_use: dict) -> str | None:
    """Pull the command text out of a shell tool_use event."""
    inp = tool_use.get("input") or {}
    if not isinstance(inp, dict):
        return None
    for key in COMMAND_KEYS:
        v = inp.get(key)
        if isinstance(v, str) and v.strip():
            return v
    return None


def emit(out, record: dict) -> None:
    out.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    out.write("\n")


def fp_key(s: str) -> str:
    """Stable dedupe key (collapses trivial whitespace differences)."""
    return hashlib.sha1(re.sub(r"\s+", " ", s.strip()).encode("utf-8", "ignore")).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root",       default=os.path.expanduser("~/.cursor/projects"))
    ap.add_argument("--project",    default=None,
                    help="Only transcripts whose path contains this substring.")
    ap.add_argument("--shell-only", action="store_true")
    ap.add_argument("--text-only",  action="store_true")
    ap.add_argument("--max-text",   type=int, default=4000)
    ap.add_argument("--keep-dup",   action="store_true",
                    help="Disable de-duplication.")
    ap.add_argument("--raw",        action="store_true",
                    help="Skip the secret-redaction pass.")
    ap.add_argument("--limit",      type=int, default=0)
    ap.add_argument("--out",        default="-",
                    help="Output path. `-` for stdout.")
    args = ap.parse_args()

    if args.shell_only and args.text_only:
        print("[extract] --shell-only and --text-only are mutually exclusive.", file=sys.stderr)
        return 2

    do_shell = not args.text_only
    do_text  = not args.shell_only
    root     = pathlib.Path(args.root).expanduser()
    seen: set[str] = set()
    out_path = args.out
    out      = sys.stdout if out_path == "-" else open(out_path, "w", encoding="utf-8")

    transcripts = 0
    events      = 0
    shell_n     = 0
    text_n      = 0
    dedup_skip  = 0
    redacted    = 0
    emitted     = 0

    for tpath in iter_transcripts(root, args.project):
        transcripts += 1
        for ev in iter_events(tpath):
            events += 1
            msg = ev.get("message", {})
            content = msg.get("content") if isinstance(msg, dict) else None
            if not isinstance(content, list):
                continue

            role = ev.get("role")
            for item in content:
                if not isinstance(item, dict):
                    continue
                itype = item.get("type")

                if do_shell and itype == "tool_use" and item.get("name") in SHELL_TOOL_NAMES:
                    cmd = extract_shell_command(item)
                    if not cmd:
                        continue
                    if not args.raw:
                        new = redact(cmd)
                        if new != cmd:
                            redacted += 1
                            cmd = new
                    key = "S:" + fp_key(cmd)
                    if not args.keep_dup and key in seen:
                        dedup_skip += 1
                        continue
                    seen.add(key)
                    emit(out, {
                        "tool": "run_terminal",
                        "params": {"command": cmd},
                        "source": {
                            "transcript": tpath.name,
                            "cursor_tool": item.get("name"),
                        },
                    })
                    shell_n += 1
                    emitted += 1

                elif do_text and role == "assistant" and itype == "text":
                    text = (item.get("text") or "").strip()
                    if not text:
                        continue
                    if len(text) > args.max_text:
                        text = text[: args.max_text]
                    if not args.raw:
                        new = redact(text)
                        if new != text:
                            redacted += 1
                            text = new
                    key = "T:" + fp_key(text)
                    if not args.keep_dup and key in seen:
                        dedup_skip += 1
                        continue
                    seen.add(key)
                    emit(out, {
                        "text": text,
                        "source": {"transcript": tpath.name},
                    })
                    text_n += 1
                    emitted += 1

                if args.limit and emitted >= args.limit:
                    break
            if args.limit and emitted >= args.limit:
                break
        if args.limit and emitted >= args.limit:
            break

    if out is not sys.stdout:
        out.close()

    print(
        f"[extract] transcripts={transcripts} events={events} "
        f"shell={shell_n} text={text_n} dedup_skip={dedup_skip} "
        f"redacted={redacted} emitted={emitted}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
