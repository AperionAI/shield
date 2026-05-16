# Methodology — how the 98.4% pass-through number was measured

This document exists for one reason: so any reader can reproduce the
number in our README, exactly, on their own machine, against their own
data — or, equivalently, against our published corpus.

False-positive rate is **the** product KPI for a guardrail. A
guardrail with a high false-positive rate gets disabled within a week,
which means it's worse than nothing — it created a false sense of
security and then got turned off. We measure ours publicly so the
people running Shield on their machines can verify it.

If you find we got it wrong, [open an issue](https://github.com/AperionAI/shield/issues/new)
and we will rerun the methodology and correct the README. The number
we cite has to be the number anyone can reproduce.

---

## The headline

Against a corpus of **12,912 real Cursor agent commands** drawn from
the lead author's own Cursor transcript history (Apr 2025 → May 2026),
run from a vanilla project root with no production signals present,
Shield v0.5.0 produced:

```
 12,708 (98.42%)   allow      <-- legitimate operations pass through
      3 (0.02%)   warn        <-- annotated, agent continues
    191 (1.48%)   approval    <-- pause for human signoff (writes to
                                   /etc, ~/.ssh, /usr/local/bin, etc.)
     10 (0.08%)   block       <-- hard stop (curl|bash, env->curl
                                   exfiltration, reverse-shell patterns)
```

The headline number — **98.4% pass-through** — is the sum of the
`allow` and `warn` columns, which is the operational definition of "did
not interrupt the developer's workflow."

The 0.08% block rate represents calls Shield correctly stopped (verified
by manual inspection of all 10). There is no published evidence of any
of the 12,708 allowed calls being something a security-aware developer
would have wanted Shield to block, but the corpus is public, and we
welcome counterexamples.

---

## The corpus

### Source

Every JSON-Lines transcript Cursor writes under
`~/.cursor/projects/*/cursor-transcripts/` is parsed by
[`scripts/extract-cursor-corpus.py`](../scripts/extract-cursor-corpus.py),
which:

1. Walks every project directory
2. Extracts shell commands (from `run_terminal_cmd` and similar tool
   calls) and assistant text turns
3. Applies regex-based redaction for credentials before any output
   leaves your machine (AKIA-prefixed AWS keys, `sk-`-prefixed OpenAI
   keys, `ghp_`-prefixed GitHub tokens, JWT-shaped triple-segment
   base64 strings)
4. Deduplicates by command/text hash
5. Emits the exact JSON-Lines schema `aperion-shield --check` expects

For the headline number, the lead author ran:

```bash
python3 scripts/extract-cursor-corpus.py \
    --shell-only \
    --out tests/corpus/real-cursor-2026-may.jsonl
```

This produced **12,912 deduplicated lines** from approximately
**73 projects** spanning a 13-month window of active Cursor use.

`--shell-only` excludes assistant text turns (which exercise the
`where: llm_response` rules — those are validated separately, see
**LLM-plan rules** below). The headline 98.4% number is a `tool_call`-
scope-only measurement.

### Why a real-history corpus instead of a synthetic one

A guardrail's false-positive rate is a function of the **distribution
of legitimate commands developers actually run**. Synthesizing a
corpus, even carefully, encodes the rule author's assumptions about
"what legitimate commands look like," which is exactly the bias the
test is supposed to catch.

The Cursor transcript corpus is the closest publicly-reproducible
proxy we have for the population of "commands AI coding agents
actually emit in 2026." It includes:

- Build-tool invocations (`cargo`, `npm`, `pnpm`, `yarn`, `pip`, `uv`)
- Git operations (clones, branches, checkouts, status, log, diff,
  commit, push, rebase, merge, cherry-pick, stash)
- Test invocations (jest, vitest, pytest, cargo test, go test)
- File reads and writes via the IDE's filesystem MCP
- Network fetches (curl, wget, fetch from inside scripts)
- Docker invocations (build, run, exec, compose)
- SQL queries via the postgres MCP server
- Shell pipelines, conditional execution, here-docs
- Sudo invocations
- Many, many `ls`, `cat`, `grep`, `pwd`, `cd`, `find` calls

### Reproducing on your own data

Every Cursor user has their own corpus on disk. **You can run the
methodology against your own transcripts in under 60 seconds:**

```bash
git clone https://github.com/AperionAI/shield.git
cd shield
cargo build --release

python3 scripts/extract-cursor-corpus.py \
    --shell-only \
    | ./target/release/aperion-shield --check --no-memory --no-burst \
    | jq -c '{decision: .decision}' \
    | sort | uniq -c | sort -rn
```

That single pipeline prints your decision distribution. If your number
materially diverges from our 98.4%, we want to hear about it —
that's a signal of either a rule the corpus exposed differently in
your project mix or a redaction bug, and either way it's a fix.

### The bundled golden corpus

Independent of the wide-scale Cursor mining, the repository ships
[`tests/corpus/golden.jsonl`](../tests/corpus/golden.jsonl) — a
hand-curated corpus of **positive and negative cases for every
shipping rule** with `expect:` annotations. It runs in CI on every
commit; a regression in any rule fails the build. This is the
"correctness" half of the validation; the Cursor-history corpus is
the "noise floor" half.

```bash
# Run the golden corpus -- should be exit 0 with all expectations met
./target/release/aperion-shield --check < tests/corpus/golden.jsonl
```

---

## The configuration

The headline number was measured with the **default**, **bundled**,
**unmodified** `shieldset.yaml` shipping with `aperion-shield v0.5.0`:

- File: [`config/shieldset.yaml`](../config/shieldset.yaml)
- Schema version: 2
- 45 rules across 9 destructive surfaces:
  SQL, Git, Filesystem, Secrets exfiltration, Supply chain / RCE,
  Reverse shells, Privilege escalation, Cloud (AWS/GCP/Azure), Kubernetes,
  Docker, plus LLM-plan inspection and the burst anomaly detector
- Adaptive features: composite scoring enabled, decision memory
  enabled but disabled for the test run (`--no-memory`), burst
  detector enabled but disabled for the test run (`--no-burst`),
  workspace probe enabled but run from a vanilla repo root with no
  production signals (so the probe does not fire and severity is
  not bumped)

The `--no-memory --no-burst` flags exist precisely to make corpus
runs deterministic: memory and burst introduce path-dependent state
(prior approvals demote future severity; bursts inside a 5-minute
window escalate every match in the window). For a noise-floor
measurement that any reader can reproduce identically, those state
machines must be disabled.

---

## The command

```bash
aperion-shield --check --no-memory --no-burst \
    < tests/corpus/real-cursor-2026-may.jsonl \
    > tests/corpus/real-cursor-2026-may.decisions.jsonl

jq -c '{decision: .decision}' \
    < tests/corpus/real-cursor-2026-may.decisions.jsonl \
    | sort | uniq -c | sort -rn
```

The first command runs the full engine (load shieldset, parse JSON
input, fire rules, composite-score, decide) on every line and emits
the decision on stdout, one line per input line. The second command
counts the decisions by category.

Both commands are deterministic. Identical inputs produce identical
outputs.

---

## What's measured and what isn't

### Measured

- **Rule-level correctness**: does Shield correctly fire on the
  patterns it claims to fire on? (Golden corpus, 100% pass)
- **Pass-through rate**: across 12,912 real agent-emitted commands,
  what fraction does Shield interrupt? (1.56% — 1.48% approval +
  0.08% block; the remaining 98.44% are allow + warn)
- **No-false-block correctness**: of the 10 blocks, are any of them
  things a security-aware developer would have wanted to allow?
  (Manually inspected: 0)
- **Adaptive scoring effects**: composite, workspace probe, decision
  memory, and burst detector are all exercised by the golden corpus
  with `expect:` annotations, but disabled in the noise-floor run
  for determinism

### Not measured by this number

- **Workspace-probe-on behaviour**: running from a project root with
  `.env.production` / `kubeconfig` / `prod/` present escalates every
  match by one tier; this is by design and tested separately. The
  noise-floor number is the **vanilla project root** baseline.
- **Coverage of attack patterns Shield does NOT have rules for**:
  this is a measure of false-positive rate, not coverage. Coverage
  is measured by the test suite (`cargo test --release`, 133
  passing) and by community-contributed corpus additions.
- **Adversarial input**: the corpus is real developer-issued commands,
  not red-team probes. A red-team corpus measures something different
  (and is on the v0.7 roadmap).
- **End-to-end latency**: the engine evaluates a tool-call in <2ms on
  a 2024 M3 MacBook; that number is separately benchmarked in
  `cargo bench`. The 98.4% is correctness, not performance.

---

## LLM-plan rules

The five `where: llm_response` rules (`llm.suggests_drop_database`,
`llm.suggests_force_push`, `llm.suggests_rm_rf`,
`llm.suggests_curl_pipe_sh`, `llm.suggests_secret_exfil`) are
validated against **assistant text turns** rather than tool calls.
Run separately:

```bash
python3 scripts/extract-cursor-corpus.py \
    --out tests/corpus/real-cursor-2026-may-with-text.jsonl
aperion-shield --check --no-memory --no-burst \
    < tests/corpus/real-cursor-2026-may-with-text.jsonl \
    | jq -c 'select(.scope == "llm_response")'
```

On the same time-window corpus this produced **4 `llm.suggests_*`
warnings out of 23,847 assistant text turns** (0.017%) — useful as
early signal, not interruptive.

---

## Pre-publication review

Before any pass-through number ships in a public claim:

1. The corpus is regenerated from the latest `~/.cursor/projects/`
   state with the redactor enabled
2. The full `cargo test --release` suite must pass (133 tests)
3. The golden corpus must pass with zero expectation mismatches
4. The wide-scale run is repeated three times on three different
   developer laptops; results must agree within ±0.5%
5. Any rule change between the last published number and the new
   number is run through `scripts/shield-diff.py` (the behavior-diff
   explainer); reviewers must approve the diff before publication

This document gets updated when the published number changes. The
changelog at the bottom records every revision.

---

## Honest limitations of the number

The 98.4% figure is a **noise floor**, not a guarantee. Specifically:

- **It's specific to the corpus.** A team using Shield on a primarily-
  Postgres-MCP workflow will see a different (likely higher) pass-
  through rate, because the SQL rules dominate the matched set.
  A team doing infrastructure-as-code work with heavy `terraform`
  and `kubectl` use will likely see a slightly lower rate.
- **It's specific to v0.5.0's shieldset.** Tightening any rule will
  reduce pass-through; loosening any rule will increase it. The
  number is a baseline, not a promise.
- **It is workspace-probe-off.** Running Shield from a workspace
  with production signals raises the approval rate intentionally,
  by design. You will not get 98.4% in a `kubeconfig`-containing
  directory, and you should not expect to.
- **It is single-author.** The corpus is the lead author's own
  Cursor history. We are actively soliciting independent measurements
  from contributors; if you run the methodology and your number
  diverges materially, please [open an issue](https://github.com/AperionAI/shield/issues/new).
  We'll publish multi-author measurements once we have at least
  three independent corpora.

---

## Changelog

| Date | Shield version | Corpus size | Allow + Warn | Notes |
|---|---|---|---|---|
| 2026-05-15 | v0.5.0 | 12,912 | 98.42% | First publication; vanilla project root, workspace probe off |

When this number is updated, the previous values stay in the table.
A number that moves silently isn't a measurement; it's marketing.
