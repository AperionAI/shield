#!/usr/bin/env python3
"""Behavior-diff explainer for aperion-shield shieldset.yaml changes.

Runs `aperion-shield --check` twice over the same corpus -- once with
the current shieldset, once with the proposed shieldset -- and produces
a human-readable report:

  - decision-distribution table (allow / warn / approval / block deltas)
  - per-rule analysis (added / removed / modified / unchanged rules)
  - sample of flipped lines (allow->approval, allow->block, etc.)
  - inline YAML diff for any rule whose body actually changed

This is the v0.6/v0.7 candidate roadmap item that fills the "still
manual" gap called out in docs/shieldset-as-code.md. The output is
deterministic: stdin -> stdout, no network, no telemetry.

Usage:
    python3 scripts/shield-diff.py \
        --rules-before shieldset.yaml \
        --rules-after  shieldset.pr.yaml \
        --corpus       tests/corpus/team-cursor-history.jsonl

    # corpus also works on stdin
    cat corpus.jsonl | python3 scripts/shield-diff.py \
        --rules-before before.yaml \
        --rules-after  after.yaml

    # markdown output for posting as a PR comment
    python3 scripts/shield-diff.py --format markdown \
        --rules-before before.yaml --rules-after after.yaml \
        --corpus corpus.jsonl > pr-comment.md

Flags:
    --rules-before PATH    current (main-branch) shieldset YAML  [required]
    --rules-after  PATH    proposed (PR-branch) shieldset YAML   [required]
    --corpus PATH          JSON-Lines corpus file (default: stdin)
    --shield-bin PATH      aperion-shield binary (default: PATH lookup)
    --workspace PATH       --workspace passthrough (prod-probe root)
    --format {text,markdown,json}    output format (default: text)
    --max-samples N        max flipped-line samples per direction (default: 3)
    --fail-if-flipped      exit 1 if any line's decision flipped
    --fail-if-loosened     exit 1 if any line went toward a more permissive decision
    --fail-if-allows-loosened N    exit 1 if >N lines flipped to `allow`

Privacy:
    Calls `aperion-shield` locally. No network, no telemetry. The two
    shieldset files and the corpus are read; nothing is written.

Requirements:
    python3.10+ and PyYAML. Install PyYAML against the SAME python
    you'll run this script with -- on conda / pyenv / system-vs-brew
    setups `pip3 install pyyaml` often lands in a different python:

        python3 -m pip install pyyaml
        python3 -c "import yaml; print(yaml.__version__)"   # verify
"""

from __future__ import annotations

import argparse
import dataclasses
import difflib
import io
import json
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:
    sys.stderr.write(
        "error: PyYAML is required. Install with: pip install pyyaml\n"
    )
    sys.exit(2)


DECISIONS = ("allow", "warn", "approval", "block")
SEVERITY_ORDER = {"allow": 0, "warn": 1, "approval": 2, "block": 3}


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class DecisionLine:
    """One line of `aperion-shield --check` JSON output."""
    decision: str
    primary_rule_id: str | None
    matched_rules: list[str]
    composite_severity: str
    composite_points: int
    raw_severity: str
    reason: str
    input_obj: dict[str, Any]  # echoed input

    @classmethod
    def parse(cls, raw: str) -> DecisionLine:
        obj = json.loads(raw)
        return cls(
            decision=obj.get("decision", "allow"),
            primary_rule_id=obj.get("primary_rule_id"),
            matched_rules=list(obj.get("matched_rules", [])),
            composite_severity=obj.get("composite_severity", ""),
            composite_points=int(obj.get("composite_points", 0)),
            raw_severity=obj.get("raw_severity", ""),
            reason=obj.get("reason", ""),
            input_obj=obj.get("input", {}),
        )


@dataclasses.dataclass
class RuleDelta:
    """Per-rule change: YAML-level (textual) + behavioral (corpus-level)."""
    rule_id: str
    status: str                       # "added" | "removed" | "modified" | "unchanged"
    yaml_diff: str                    # unified diff of the rule's serialized YAML
    fires_before: int                 # how many corpus lines matched this rule under before
    fires_after: int                  # ... under after
    flipped_lines_caused: list[tuple[str, str, dict]] = dataclasses.field(default_factory=list)
    # (decision_before, decision_after, input_obj)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def resolve_shield_bin(explicit: str | None) -> str:
    """Find the aperion-shield binary on disk or fall back to PATH."""
    if explicit:
        if not Path(explicit).is_file():
            sys.stderr.write(f"error: --shield-bin not found at {explicit}\n")
            sys.exit(2)
        return explicit
    found = shutil.which("aperion-shield")
    if not found:
        sys.stderr.write(
            "error: aperion-shield not found on PATH. "
            "Install it (brew install AperionAI/tap/aperion-shield) "
            "or pass --shield-bin PATH.\n"
        )
        sys.exit(2)
    return found


def read_corpus(path: str | None) -> bytes:
    """Read JSON-Lines corpus from stdin or a file path."""
    if path:
        return Path(path).read_bytes()
    if sys.stdin.isatty():
        sys.stderr.write(
            "error: no corpus on stdin and no --corpus PATH given.\n"
            "       hint: python3 shield-diff.py --corpus tests/corpus/golden.jsonl ...\n"
        )
        sys.exit(2)
    return sys.stdin.buffer.read()


def load_ruleset(path: str) -> dict[str, dict[str, Any]]:
    """Parse a shieldset YAML and return {rule_id: rule_body} (excluding id)."""
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        sys.stderr.write(f"error: {path} did not parse as a YAML mapping\n")
        sys.exit(2)
    shieldset = raw.get("shieldset") or raw  # tolerate wrapped or bare
    rules = shieldset.get("rules", []) if isinstance(shieldset, dict) else []
    out: dict[str, dict[str, Any]] = {}
    for r in rules:
        if not isinstance(r, dict) or "id" not in r:
            continue
        rid = str(r["id"])
        body = {k: v for k, v in r.items() if k != "id"}
        out[rid] = body
    return out


def yaml_dump_rule(rid: str, body: dict[str, Any]) -> str:
    """Render one rule (id + body) as canonical YAML for diffing."""
    full = {"id": rid, **body}
    return yaml.safe_dump([full], sort_keys=False, default_flow_style=False)


def run_shield_check(
    shield_bin: str,
    rules_path: str,
    corpus_bytes: bytes,
    workspace: str | None,
) -> list[DecisionLine]:
    """Run `aperion-shield --check` against a corpus and parse stdout."""
    cmd = [shield_bin, "--check", "--no-memory", "--no-burst",
           "--rules", rules_path]
    if workspace:
        cmd.extend(["--workspace", workspace])
    try:
        proc = subprocess.run(
            cmd, input=corpus_bytes, capture_output=True, timeout=300, check=False
        )
    except FileNotFoundError:
        sys.stderr.write(f"error: cannot execute {shield_bin}\n")
        sys.exit(2)
    if proc.returncode != 0 and proc.returncode != 1:
        # exit 1 in --check mode means "an expect: line failed", which we
        # tolerate here. Anything else is a real engine error.
        sys.stderr.write(
            f"error: aperion-shield --check exited {proc.returncode}\n"
            f"stderr:\n{proc.stderr.decode('utf-8', errors='replace')}\n"
        )
        sys.exit(2)
    out: list[DecisionLine] = []
    for raw in proc.stdout.decode("utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("[shield-check]"):
            continue
        try:
            out.append(DecisionLine.parse(raw))
        except json.JSONDecodeError:
            # ignore non-JSON lines (engine info chatter)
            continue
    return out


# ---------------------------------------------------------------------------
# Diff logic
# ---------------------------------------------------------------------------

def diff_rulesets(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
) -> dict[str, RuleDelta]:
    """Classify every rule in either ruleset."""
    all_ids = set(before) | set(after)
    deltas: dict[str, RuleDelta] = {}
    for rid in sorted(all_ids):
        in_before, in_after = rid in before, rid in after
        if in_before and not in_after:
            status = "removed"
            yaml_diff = "\n".join(f"- {line}" for line in
                yaml_dump_rule(rid, before[rid]).splitlines())
        elif in_after and not in_before:
            status = "added"
            yaml_diff = "\n".join(f"+ {line}" for line in
                yaml_dump_rule(rid, after[rid]).splitlines())
        elif before[rid] == after[rid]:
            status = "unchanged"
            yaml_diff = ""
        else:
            status = "modified"
            yaml_diff = "".join(difflib.unified_diff(
                yaml_dump_rule(rid, before[rid]).splitlines(keepends=True),
                yaml_dump_rule(rid, after[rid]).splitlines(keepends=True),
                fromfile=f"{rid}.before", tofile=f"{rid}.after",
                n=2,
            ))
        deltas[rid] = RuleDelta(
            rule_id=rid, status=status, yaml_diff=yaml_diff,
            fires_before=0, fires_after=0,
        )
    return deltas


def populate_behavior(
    deltas: dict[str, RuleDelta],
    before: list[DecisionLine],
    after: list[DecisionLine],
) -> tuple[Counter, list[tuple[str, str, dict, DecisionLine, DecisionLine]]]:
    """Fill in fires_before / fires_after counts and collect flipped lines.

    Returns:
        flip_counter: Counter of (decision_before, decision_after) tuples
        flipped: list of (decision_before, decision_after, input_obj, before_line, after_line)
    """
    if len(before) != len(after):
        sys.stderr.write(
            f"warn: decision counts differ "
            f"({len(before)} vs {len(after)}); pairing by index\n"
        )
    n = min(len(before), len(after))
    flip_counter: Counter = Counter()
    flipped: list[tuple[str, str, dict, DecisionLine, DecisionLine]] = []
    for i in range(n):
        b, a = before[i], after[i]
        for rid in b.matched_rules:
            if rid in deltas:
                deltas[rid].fires_before += 1
        for rid in a.matched_rules:
            if rid in deltas:
                deltas[rid].fires_after += 1
        if b.decision != a.decision:
            flip_counter[(b.decision, a.decision)] += 1
            flipped.append((b.decision, a.decision, b.input_obj, b, a))
            # attribute the flip to whichever rule(s) changed under `after`
            for rid in a.matched_rules:
                if rid in deltas and deltas[rid].status in ("added", "modified"):
                    deltas[rid].flipped_lines_caused.append(
                        (b.decision, a.decision, b.input_obj)
                    )
            for rid in b.matched_rules:
                if rid in deltas and deltas[rid].status == "removed":
                    deltas[rid].flipped_lines_caused.append(
                        (b.decision, a.decision, b.input_obj)
                    )
    return flip_counter, flipped


def loosening_count(flip_counter: Counter) -> int:
    """Number of flips that moved to a more permissive decision."""
    n = 0
    for (b, a), c in flip_counter.items():
        if SEVERITY_ORDER.get(a, 99) < SEVERITY_ORDER.get(b, 99):
            n += c
    return n


def flips_to_allow(flip_counter: Counter) -> int:
    return sum(c for (_, a), c in flip_counter.items() if a == "allow")


# ---------------------------------------------------------------------------
# Render: text format (default)
# ---------------------------------------------------------------------------

def short_input(input_obj: dict[str, Any], maxlen: int = 110) -> str:
    """Compact one-line summary of an input record."""
    if "tool" in input_obj:
        params = input_obj.get("params", {})
        keys = ("query", "command", "cmd", "sql", "path", "url")
        for k in keys:
            if k in params:
                s = f"{input_obj['tool']}: {params[k]}"
                break
        else:
            s = f"{input_obj['tool']}: {json.dumps(params)[:80]}"
    elif "text" in input_obj:
        s = f"text: {input_obj['text']}"
    else:
        s = json.dumps(input_obj)
    s = s.replace("\n", " ").replace("\t", " ")
    return s if len(s) <= maxlen else s[: maxlen - 1] + "..."


def render_text(
    before_path: str,
    after_path: str,
    corpus_lines: int,
    decision_before: Counter,
    decision_after: Counter,
    deltas: dict[str, RuleDelta],
    flip_counter: Counter,
    flipped: list[tuple[str, str, dict, DecisionLine, DecisionLine]],
    max_samples: int,
) -> str:
    buf = io.StringIO()
    w = buf.write
    w(f"shield-diff: {before_path} -> {after_path}\n")
    w(f"corpus:      {corpus_lines:,} commands\n\n")

    w("DECISION DISTRIBUTION\n")
    w(f"{'':<12}{'before':>10}{'after':>10}{'delta':>14}\n")
    for d in DECISIONS:
        b, a = decision_before[d], decision_after[d]
        delta = a - b
        pct = f"({delta:+d}, {(delta / b * 100):+.1f}%)" if b else f"({delta:+d})"
        w(f"  {d:<10}{b:>10,}{a:>10,}  {pct:<14}\n")
    w("\n")

    # ----- ruleset changes (YAML-level)
    added    = [d for d in deltas.values() if d.status == "added"]
    removed  = [d for d in deltas.values() if d.status == "removed"]
    modified = [d for d in deltas.values() if d.status == "modified"]
    unchanged_n = sum(1 for d in deltas.values() if d.status == "unchanged")

    w("RULESET CHANGES\n")
    if added:
        w(f"  added    ({len(added)}): " + ", ".join(d.rule_id for d in added) + "\n")
    if removed:
        w(f"  removed  ({len(removed)}): " + ", ".join(d.rule_id for d in removed) + "\n")
    if modified:
        w(f"  modified ({len(modified)}): " + ", ".join(d.rule_id for d in modified) + "\n")
    w(f"  unchanged: {unchanged_n} rules\n\n")

    # YAML diffs for added / removed / modified
    for d in [*added, *removed, *modified]:
        w(f"  --- {d.rule_id} ({d.status}) ---\n")
        for line in d.yaml_diff.splitlines():
            w(f"    {line}\n")
        w("\n")

    # ----- behavioral impact
    w("BEHAVIORAL IMPACT BY RULE\n")
    behavioral = [d for d in deltas.values()
                  if d.fires_before != d.fires_after or d.flipped_lines_caused]
    behavioral.sort(key=lambda d: -abs(d.fires_after - d.fires_before))
    if not behavioral:
        w("  (no rules changed their fire counts in this corpus)\n\n")
    else:
        for d in behavioral:
            delta = d.fires_after - d.fires_before
            w(f"  {d.rule_id}:\n")
            w(f"    fired before:  {d.fires_before} lines\n")
            w(f"    fired after:   {d.fires_after} lines  ({delta:+d})\n")
            if d.flipped_lines_caused:
                samples = d.flipped_lines_caused[:max_samples]
                w(f"    sample of {len(samples)} of {len(d.flipped_lines_caused)} flipped lines:\n")
                for db, da, inp in samples:
                    w(f"      [{db} -> {da}]  {short_input(inp)}\n")
            w("\n")

    # ----- flip summary
    flipped_total = sum(flip_counter.values())
    w("SUMMARY\n")
    w(f"  flipped lines:    {flipped_total:,} of {corpus_lines:,} "
      f"({(flipped_total / corpus_lines * 100):.2f}% of corpus)\n"
      if corpus_lines else "  flipped lines:    0\n")
    if flip_counter:
        for (b, a), c in sorted(flip_counter.items(), key=lambda kv: -kv[1]):
            arrow = f"{b} -> {a}"
            w(f"    {arrow:<24}{c:>6}\n")
        loosened = loosening_count(flip_counter)
        if loosened:
            w(f"\n  loosened decisions: {loosened}  "
              f"(this proposed change makes the engine MORE permissive on "
              f"{loosened} previously-flagged calls -- review each by hand)\n")
        else:
            w("\n  no loosening detected (no line moved toward a more permissive decision)\n")
    else:
        w("  no behavioral change in this corpus.\n")
    w("\n")

    # ----- guidance line
    if flipped_total == 0:
        w("GUIDANCE: this ruleset change has no observable effect on the supplied\n"
          "corpus. Either it only affects patterns your team hasn't seen yet, or\n"
          "it's a no-op. Add more representative cases to the corpus before merging.\n")
    else:
        n_appr = sum(c for (_, a), c in flip_counter.items() if a == "approval")
        n_block = sum(c for (_, a), c in flip_counter.items() if a == "block")
        parts = []
        if n_appr:
            parts.append(f"~{n_appr} more daily approval prompts")
        if n_block:
            parts.append(f"~{n_block} more daily hard blocks")
        if parts:
            w("GUIDANCE: based on this corpus, expect " + " and ".join(parts) + ".\n"
              "Review the flipped-line samples above to confirm these are the\n"
              "prompts/blocks the change intends to add.\n")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Render: markdown (for PR comments)
# ---------------------------------------------------------------------------

def render_markdown(
    before_path: str, after_path: str, corpus_lines: int,
    decision_before: Counter, decision_after: Counter,
    deltas: dict[str, RuleDelta],
    flip_counter: Counter,
    flipped: list[tuple[str, str, dict, DecisionLine, DecisionLine]],
    max_samples: int,
) -> str:
    buf = io.StringIO()
    w = buf.write
    w(f"### shieldset behavior diff — `{before_path}` → `{after_path}`\n")
    w(f"_corpus: {corpus_lines:,} commands_\n\n")
    w("| decision | before | after | delta |\n")
    w("|---|---:|---:|---:|\n")
    for d in DECISIONS:
        b, a = decision_before[d], decision_after[d]
        delta = a - b
        delta_s = f"{delta:+d}"
        if b:
            delta_s += f" ({(delta / b * 100):+.1f}%)"
        w(f"| `{d}` | {b:,} | {a:,} | {delta_s} |\n")

    added    = [d for d in deltas.values() if d.status == "added"]
    removed  = [d for d in deltas.values() if d.status == "removed"]
    modified = [d for d in deltas.values() if d.status == "modified"]
    w("\n**Ruleset changes:** ")
    parts = []
    if added:    parts.append(f"{len(added)} added")
    if removed:  parts.append(f"{len(removed)} removed")
    if modified: parts.append(f"{len(modified)} modified")
    if not parts: parts.append("none")
    w(", ".join(parts) + "\n\n")

    behavioral = [d for d in deltas.values()
                  if d.fires_before != d.fires_after or d.flipped_lines_caused]
    if behavioral:
        w("<details><summary>Rules with changed behavior on this corpus</summary>\n\n")
        for d in behavioral:
            delta = d.fires_after - d.fires_before
            w(f"**`{d.rule_id}`** ({d.status}) — fires `{d.fires_before}` → `{d.fires_after}` ({delta:+d})\n\n")
            if d.flipped_lines_caused:
                w(f"_Sample of {min(len(d.flipped_lines_caused), max_samples)} of {len(d.flipped_lines_caused)} flipped lines:_\n\n")
                for db, da, inp in d.flipped_lines_caused[:max_samples]:
                    w(f"- `{db} → {da}`: `{short_input(inp)}`\n")
                w("\n")
        w("</details>\n\n")

    flipped_total = sum(flip_counter.values())
    if flipped_total == 0:
        w("**Behavioral impact:** no flipped decisions on this corpus.\n")
    else:
        pct = (flipped_total / corpus_lines * 100) if corpus_lines else 0
        w(f"**Behavioral impact:** {flipped_total:,} of {corpus_lines:,} lines flipped ({pct:.2f}%).\n\n")
        w("| direction | count |\n|---|---:|\n")
        for (b, a), c in sorted(flip_counter.items(), key=lambda kv: -kv[1]):
            w(f"| `{b} → {a}` | {c} |\n")
        loosened = loosening_count(flip_counter)
        if loosened:
            w(f"\n> ⚠ **{loosened} lines loosened** (moved toward a more "
              f"permissive decision). Review each by hand.\n")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Render: json
# ---------------------------------------------------------------------------

def render_json(
    before_path: str, after_path: str, corpus_lines: int,
    decision_before: Counter, decision_after: Counter,
    deltas: dict[str, RuleDelta],
    flip_counter: Counter,
) -> str:
    payload = {
        "before": before_path,
        "after":  after_path,
        "corpus_lines": corpus_lines,
        "decision_before": {d: decision_before[d] for d in DECISIONS},
        "decision_after":  {d: decision_after[d]  for d in DECISIONS},
        "rules": [
            {
                "id":             d.rule_id,
                "status":         d.status,
                "fires_before":   d.fires_before,
                "fires_after":    d.fires_after,
                "flipped_caused": len(d.flipped_lines_caused),
            }
            for d in deltas.values()
        ],
        "flips": [
            {"from": b, "to": a, "count": c}
            for (b, a), c in flip_counter.items()
        ],
        "loosened_count": loosening_count(flip_counter),
    }
    return json.dumps(payload, indent=2, sort_keys=False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Behavior diff of two aperion-shield shieldsets over a corpus.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See docs/shieldset-as-code.md for the full review pattern.",
    )
    ap.add_argument("--rules-before", required=True, help="current (main) shieldset YAML")
    ap.add_argument("--rules-after",  required=True, help="proposed (PR) shieldset YAML")
    ap.add_argument("--corpus",       help="JSON-Lines corpus path (default: stdin)")
    ap.add_argument("--shield-bin",   help="aperion-shield binary (default: PATH)")
    ap.add_argument("--workspace",    help="--workspace passthrough for the prod-probe")
    ap.add_argument("--format", choices=("text", "markdown", "json"),
                    default="text")
    ap.add_argument("--max-samples", type=int, default=3,
                    help="max flipped-line samples per rule (default: 3)")
    ap.add_argument("--fail-if-flipped", action="store_true",
                    help="exit 1 if any line's decision flipped")
    ap.add_argument("--fail-if-loosened", action="store_true",
                    help="exit 1 if any line moved to a more permissive decision")
    ap.add_argument("--fail-if-allows-loosened", type=int, metavar="N",
                    help="exit 1 if more than N lines flipped TO allow")
    args = ap.parse_args()

    shield_bin = resolve_shield_bin(args.shield_bin)
    corpus_bytes = read_corpus(args.corpus)
    if not corpus_bytes.strip():
        sys.stderr.write("error: corpus is empty\n")
        return 2
    corpus_lines = sum(1 for line in corpus_bytes.splitlines()
                       if line.strip() and not line.startswith(b"#"))

    rules_before = load_ruleset(args.rules_before)
    rules_after  = load_ruleset(args.rules_after)

    before_decisions = run_shield_check(
        shield_bin, args.rules_before, corpus_bytes, args.workspace,
    )
    after_decisions = run_shield_check(
        shield_bin, args.rules_after, corpus_bytes, args.workspace,
    )

    decision_before = Counter(d.decision for d in before_decisions)
    decision_after  = Counter(d.decision for d in after_decisions)

    deltas = diff_rulesets(rules_before, rules_after)
    flip_counter, flipped = populate_behavior(deltas, before_decisions, after_decisions)

    if args.format == "text":
        out = render_text(args.rules_before, args.rules_after, corpus_lines,
                          decision_before, decision_after, deltas,
                          flip_counter, flipped, args.max_samples)
    elif args.format == "markdown":
        out = render_markdown(args.rules_before, args.rules_after, corpus_lines,
                              decision_before, decision_after, deltas,
                              flip_counter, flipped, args.max_samples)
    else:
        out = render_json(args.rules_before, args.rules_after, corpus_lines,
                          decision_before, decision_after, deltas, flip_counter)
    sys.stdout.write(out)
    if out and not out.endswith("\n"):
        sys.stdout.write("\n")

    # ----- exit-code policy
    total_flipped = sum(flip_counter.values())
    if args.fail_if_allows_loosened is not None and \
       flips_to_allow(flip_counter) > args.fail_if_allows_loosened:
        return 1
    if args.fail_if_loosened and loosening_count(flip_counter) > 0:
        return 1
    if args.fail_if_flipped and total_flipped > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
