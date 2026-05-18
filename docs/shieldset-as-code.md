# Treating `shieldset.yaml` as code

A practical guide to putting your Shield ruleset under the same
review process as the rest of your codebase — and the tooling that
ships in this repo to make that review meaningful.

## Why this matters

The point of a guardrail is to catch the small number of calls that
would actually hurt you without getting in the way of the 98% that
won't. Get the ratio wrong and you don't have a guardrail — you have
a CAPTCHA. Engineers learn to click through, the demo stops mattering,
and the agent goes back to having root.

So **every rule change is a behaviour change against thousands of
real commands.** Tightening one regex can add 50 approval prompts to
your team's day. Loosening one can silently let a destructive call
through. Neither outcome should land without someone reading the diff
and someone else verifying the impact.

The good news is that this is a well-understood problem in any other
configuration-as-code domain (Terraform, OPA, ESLint, GitHub branch
protection, ...) and the same pattern applies here.

---

## The four-layer test stack

Shield ships with everything you need to run four progressively
stricter checks on a `shieldset.yaml` change before it merges:

| Layer | What it asserts | Speed | When it runs |
|---|---|---|---|
| **1. Load** | The YAML parses; every rule compiles; no unsupported regex constructs | <100ms | On `aperion-shield` startup, in `--check` mode, in CI |
| **2. Golden corpus** | Every documented positive/negative case for every rule still produces the expected decision | <1s | In CI on every PR that touches the shieldset |
| **3. Workflow corpus** | The proposed shieldset doesn't change the decision distribution on your team's actual recent Cursor history in surprising ways | 1-5s per 1k commands | In CI on every PR; optionally daily against fresh history |
| **4. Behavior diff** | A human-readable explanation of *which rule* caused *which lines to flip* — generated from layers 1-3 | 5-15s per 1k commands | In CI on every PR; output posted as a PR comment |

Layers 1 and 2 are the same for every team. Layers 3 and 4 are per-team
and are the ones most people skip — they're also what catches the
"this will spam my team with prompts" footgun before merge.

---

## Layer 1 — Load (the YAML compiles)

```bash
aperion-shield --rules path/to/your.yaml --check < /dev/null
```

If the YAML is well-formed, the engine boots and prints a one-line
summary:

```
[shield-check] engine: 45 rules | workspace_prod=false signals=[] composite=true memory=true burst=true
```

If a rule's regex uses lookbehind (`(?<!...)`) or arbitrary lookahead
(`(?=...)`), or a `sql_predicate:` references a name the engine
doesn't know, Shield rejects it at load with the exact rule ID. Wire
this into CI as your fastest possible feedback loop:

```bash
# Fails the job if any rule fails to compile
aperion-shield --rules .aperion-shield/shieldset.yaml --check < /dev/null
```

---

## Layer 2 — Golden corpus (every documented case still passes)

Each line of a corpus file is one of:

```jsonc
// tool_call scope
{"tool":"execute_sql","params":{"query":"DROP DATABASE x"},"expect":"block"}

// llm_response scope (assistant text)
{"text":"I will rm -rf /","expect":"warn"}
```

The `expect:` field is optional. If present, `--check` grades the
output and exits **non-zero** if any line's actual decision doesn't
match the expectation. Wire it into CI to fail the job:

```bash
aperion-shield --rules .aperion-shield/shieldset.yaml \
               --check \
               < tests/corpus/golden.jsonl
echo "exit code: $?   # 0 if all expectations met, 1 otherwise"
```

This repo's [`tests/corpus/golden.jsonl`](../tests/corpus/golden.jsonl)
is a covered example: every shipping rule has at least one positive
case and one negative case. Your own rules should ship with their own
corpus — one file per rule is a clean pattern, but a single
`team-corpus.jsonl` works too.

**Reviewer hint:** if a PR adds a rule but doesn't add corpus lines
covering both branches (the case that should fire AND a case that
shouldn't), reject it. You're going to need those cases the day the
rule starts mis-firing.

---

## Layer 3 — Workflow corpus (what changes in *your* world)

This is the layer that catches false-positive regressions. The flow:

```
1. Periodically run scripts/extract-cursor-corpus.py on your team's
   shared Cursor history. Save the result somewhere you can check
   into git (or a CI artifact / S3 bucket / artifact registry).

2. In CI, run aperion-shield --check twice:
     (a) once with main's shieldset.yaml
     (b) once with the PR's proposed shieldset.yaml
   over the SAME workflow corpus.

3. Diff the two decision streams. The diff IS the behaviour change.
```

### Extracting the corpus

```bash
# Mine every transcript under ~/.cursor/projects, shell commands only,
# redact obvious secrets, dedupe, emit ~/.aperion-shield/corpus.jsonl
python3 scripts/extract-cursor-corpus.py \
    --shell-only \
    > tests/corpus/team-cursor-history.jsonl
```

The extractor reads only local Cursor JSONL transcripts, scrubs
AKIA / `sk-` / `ghp_` / JWT-shaped tokens before output, and
deduplicates by command. It never opens a network socket. See
`extract-cursor-corpus.py --help` for the flag inventory
(`--project`, `--text-only`, `--keep-dup`, `--raw`, `--limit`, etc.).

> **One-time vs. periodic:** the simplest pattern is to commit a
> snapshot of `team-cursor-history.jsonl` to the repo and refresh it
> weekly. Teams that want more rigor extract fresh in a cron job and
> stash the artifact in S3 keyed by date.

### Running both shieldsets and diffing

```bash
# current
aperion-shield --rules main-shieldset.yaml \
               --check --no-memory --no-burst \
               < tests/corpus/team-cursor-history.jsonl \
               > /tmp/current.decisions.jsonl

# proposed (the PR branch's shieldset)
aperion-shield --rules pr-shieldset.yaml \
               --check --no-memory --no-burst \
               < tests/corpus/team-cursor-history.jsonl \
               > /tmp/proposed.decisions.jsonl

# decision counts: side by side
echo "=== current shieldset ==="
jq -r '.decision' /tmp/current.decisions.jsonl | sort | uniq -c | sort -rn

echo "=== proposed shieldset ==="
jq -r '.decision' /tmp/proposed.decisions.jsonl | sort | uniq -c | sort -rn

# inputs where the proposed shieldset changed the decision
diff <(jq -c '{i: .input, d: .decision}' /tmp/current.decisions.jsonl) \
     <(jq -c '{i: .input, d: .decision}' /tmp/proposed.decisions.jsonl) \
  | head -50
```

> `--no-memory --no-burst` is important here: in batch you want
> **deterministic** per-line decisions, not state-machine output that
> depends on the line order. Memory and burst are for production.

### What the diff tells you

| Pattern in the diff | What it means | What to do |
|---|---|---|
| Net **+approvals** on proposed | The tighten is doing what it should — more calls now require a human signature | Confirm the increase is bounded; sanity-check 3-5 specific lines |
| Net **+blocks** on proposed | The tighten escalated some Approvals to Blocks | Almost always intentional; document why in the PR |
| Net **+allows** on proposed | The loosen passed through some previously-flagged calls | This is the dangerous one — read every flipped line by hand |
| Decision distribution **unchanged** | The rule change is dead code or only fires on patterns not in your corpus | Add a test case to the golden corpus, or accept that this change has no effect today |

---

## Layer 4 — Behavior-diff explainer

The decision-distribution diff above answers *what changed*. It does
not answer *why*, or *which rule is responsible*. Reading the raw
JSON-Lines decision output to figure that out is the chore that most
teams will skip.

`aperion-shield --diff` closes that gap: it runs the engine over the
same corpus twice (once with the current shieldset, once with the
proposed one), attributes every flipped line to the specific rule
whose YAML changed, and prints a single readable report.

```bash
aperion-shield --diff \
    --rules-before main-shieldset.yaml \
    --rules-after  pr-shieldset.yaml \
    --corpus       tests/corpus/team-cursor-history.jsonl
```

Sample output:

```
shield-diff: main-shieldset.yaml -> pr-shieldset.yaml
corpus:      12,706 commands

DECISION DISTRIBUTION
                before     after         delta
  allow        12,540    12,485    (-55, -0.4%)
  warn              3         3         (+0)
  approval        191       218   (+27, +14.1%)
  block            10        10         (+0)

RULESET CHANGES
  modified (1): supply.curl_pipe_sh
  unchanged: 44 rules

  --- supply.curl_pipe_sh (modified) ---
    --- supply.curl_pipe_sh.before
    +++ supply.curl_pipe_sh.after
    @@ ... @@
     match:
       any_param_matches:
    -    - '(?i)\bcurl\s+.*(npmjs\.org|pypi\.org)' # allowlist
    +    - '(?i)\bcurl\s+.*--checksum\b'           # require inline checksum

BEHAVIORAL IMPACT BY RULE
  supply.curl_pipe_sh:
    fired before:  0 lines
    fired after:   27 lines  (+27)
    sample of 3 of 27 flipped lines:
      [allow -> approval]  run_terminal: npm install --registry https://npm.internal.corp/ axios
      [allow -> approval]  run_terminal: pip install --index-url https://pypi.corp/internal/ requests
      [allow -> approval]  run_terminal: curl https://artifacts.corp/install.sh | sh

SUMMARY
  flipped lines:    27 of 12,706  (0.21% of corpus)
    allow -> approval         27
  no loosening detected.

GUIDANCE: based on this corpus, expect ~27 more daily approval prompts.
Review the flipped-line samples above to confirm these are the prompts
the change intends to add.
```

**That's the artifact you want a reviewer reading**, not raw jq output.
Other useful flags:

```bash
# markdown output (paste into a PR comment, or pipe straight to gh)
aperion-shield --diff --format markdown ... | gh pr comment --body-file -

# json output (for programmatic consumption in your own tooling)
aperion-shield --diff --format json ...

# CI gate: fail the PR if any line moved toward MORE permissive
aperion-shield --diff --fail-if-loosened ...

# CI gate: fail if more than N lines flipped to `allow`
aperion-shield --diff --fail-if-allows-loosened 0 ...
```

**Implementation:** native Rust (in-process, no subprocess) since
v0.6.0 (2026-05-18). Reuses the same engine the proxy uses, so the
decisions in the diff are *exactly* the decisions a live wrapped
agent would receive against either shieldset. No Python runtime
dependency, no external binary, no PATH lookup.

> **Legacy:** if you have CI workflows wired against the previous
> Python prototype (`scripts/shield-diff.py`), they continue to work
> unchanged — the script is now a thin wrapper that delegates to
> `aperion-shield --diff` and the `--format json` output schema is
> source-compatible.

---

## A CI workflow that runs all four

GitHub Actions example. Drop into `.github/workflows/shieldset.yml`
in any repo that hosts a `shieldset.yaml`:

```yaml
name: shieldset-validate
on:
  pull_request:
    paths:
      - 'shieldset.yaml'
      - 'tests/corpus/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2   # need main + PR head

      - name: Install aperion-shield
        run: |
          curl -sL https://github.com/AperionAI/shield/releases/download/shield-v0.5.0/aperion-shield-shield-v0.5.0-x86_64-unknown-linux-gnu.tar.gz \
            | tar -xz
          ./aperion-shield --version

      # Layer 1 — load
      - name: Validate ruleset loads
        run: ./aperion-shield --rules shieldset.yaml --check < /dev/null

      # Layer 2 — golden corpus
      - name: Golden corpus regression
        run: ./aperion-shield --rules shieldset.yaml --check < tests/corpus/golden.jsonl
        # --check returns non-zero if any `expect:` line fails

      # Layer 3 + 4 — workflow corpus diff + behavior-diff explainer
      - name: Behavior diff vs. main
        if: hashFiles('tests/corpus/team-cursor-history.jsonl') != ''
        run: |
          git show origin/main:shieldset.yaml > /tmp/main-shieldset.yaml

          # render text version inline on the checks tab
          ./aperion-shield --diff \
              --rules-before /tmp/main-shieldset.yaml \
              --rules-after  shieldset.yaml \
              --corpus       tests/corpus/team-cursor-history.jsonl \
              | tee /tmp/shield-diff.txt
          echo '```'                   >> $GITHUB_STEP_SUMMARY
          cat /tmp/shield-diff.txt     >> $GITHUB_STEP_SUMMARY
          echo '```'                   >> $GITHUB_STEP_SUMMARY

          # render markdown version and post as a PR comment
          ./aperion-shield --diff \
              --rules-before /tmp/main-shieldset.yaml \
              --rules-after  shieldset.yaml \
              --corpus       tests/corpus/team-cursor-history.jsonl \
              --format       markdown \
              > /tmp/shield-diff.md
          gh pr comment "${{ github.event.pull_request.number }}" \
              --body-file /tmp/shield-diff.md
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      # Optional CI gate: fail the PR if any line moves toward `allow`
      - name: Block loosening without explicit reviewer signoff
        if: hashFiles('tests/corpus/team-cursor-history.jsonl') != ''
        run: |
          ./aperion-shield --diff \
              --rules-before /tmp/main-shieldset.yaml \
              --rules-after  shieldset.yaml \
              --corpus       tests/corpus/team-cursor-history.jsonl \
              --fail-if-allows-loosened 0 \
              --format json > /dev/null
```

The workflow's `$GITHUB_STEP_SUMMARY` output renders inline on the PR
checks tab, **and** the markdown version is posted as a comment on
the PR. Reviewers see the rule-attributed behavior diff at the top of
the PR conversation without opening logs.

---

## PR review checklist

### For the author

- [ ] If you added a rule, you added at least two corpus lines: one
      that should fire (`expect:` is `warn`/`approval`/`block`), one
      that shouldn't (`expect:"allow"`).
- [ ] You ran the workflow corpus diff locally — Net `+allow`s should
      be zero unless this PR is explicitly about loosening.
- [ ] If you touched a rule that already had corpus coverage, the
      old test cases still pass (or you updated them with a
      one-line PR comment explaining why).
- [ ] The PR description includes the decision-distribution table.

### For the reviewer

- [ ] CI is green (all three layers pass).
- [ ] The decision delta in the PR description matches what CI
      reports.
- [ ] If the diff shows new `allow`s, you read each flipped line by
      hand. Loosens get the same scrutiny as security policy
      changes — because they are.
- [ ] The rule's `reason` field is something an engineer will
      actually understand when it fires at 11pm on a Friday.
- [ ] The rule has a `safer_alternative` field on `approval`/`block`
      severity. Block messages without an alternative train people
      to disable the rule.

---

## Common gotchas

- **Regex backslashes in YAML.** YAML's string rules eat one
  backslash. Use single-quoted YAML strings for any regex
  containing `\b`, `\s`, `\d`, etc. — single quotes preserve
  literal backslashes; double quotes don't.

- **`tool` allowlist too narrow.** If your rule says
  `tool: [execute_sql]` but your team uses
  `mcp_postgres_query`, the rule never fires. Audit the tool
  names in your workflow corpus.

- **Rules that "fire on everything" in batch but not in IDE.** The
  workspace probe is what changes behaviour between batch and
  IDE. `--check` defaults to `workspace_prod=false`; if your IDE
  invocations are run from a prod-shaped repo, the bump pushes
  severity up one tier. Test both with `--workspace
  /path/to/prod-shaped-fixture` and without.

- **Memory + burst skew batch results.** These two adaptive signals
  carry state across calls. Always pass `--no-memory --no-burst`
  in batch contexts — otherwise the order of lines in your corpus
  affects the output and your CI is non-deterministic.

- **Tautological-WHERE detection is new in v0.5.0.** If your CI
  pins an older Shield binary, the rule won't catch the
  `WHERE col = FALSE` / `SET col = TRUE` pattern. Update the
  download URL.

---

## Roadmap

The behavior-diff explainer is **native Rust as of v0.6.0**
(2026-05-18) — built directly into the binary as
`aperion-shield --diff --rules-before X --rules-after Y --corpus Z`.
Both runs reuse the same engine the proxy uses, so the decisions in
the diff are exactly what a live wrapped agent would see against
either shieldset.

A thin `scripts/shield-diff.py` wrapper is still shipped so CI
workflows wired against the previous Python prototype keep working
unchanged. The `--format json` output schema is source-compatible
between the two.

If your team has a use case that the current explainer doesn't cover
(streaming diffs for 1M+ corpora, regex-level explanations, etc.),
open an issue at <https://github.com/AperionAI/shield/issues> and
describe the workflow. That's the signal to prioritise.

---

## Related

- [README — Mining your own Cursor history as a test corpus](../README.md#mining-your-own-cursor-history-as-a-test-corpus)
- [README — Wide-scale testing without an IDE](../README.md#wide-scale-testing-without-an-ide)
- [`tests/corpus/golden.jsonl`](../tests/corpus/golden.jsonl) — the shipped positive/negative cases
- [`scripts/extract-cursor-corpus.py`](../scripts/extract-cursor-corpus.py) — the corpus extractor
- [`aperion-shield --diff`](../src/diff/) — the native behavior-diff explainer (v0.6.0+)
- [`scripts/shield-diff.py`](../scripts/shield-diff.py) — backward-compat wrapper around `--diff`
- [`docs/aperion-shield-developer-onepager.html`](aperion-shield-developer-onepager.html) — printable one-pager
