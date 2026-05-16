# Contributing to Aperion Shield

Thanks for considering a contribution. Shield is built to be modified
by the people running it — adding a rule, tightening a regex, filing
a false positive, all of these are first-class community workflows.

This guide covers the four common contributor paths:

1. **[Reporting a bug](#1-reporting-a-bug)** — Shield does something
   wrong; you can describe the wrong behaviour.
2. **[Filing a false positive](#2-filing-a-false-positive)** — Shield
   stopped a legitimate operation. The single most important kind
   of feedback we receive; treated as a P0.
3. **[Adding a new rule](#3-adding-a-new-rule)** — there is a
   destructive pattern Shield doesn't catch and you want to fix that.
4. **[Improving an existing rule or component](#4-improving-an-existing-rule-or-component)**
   — tightening a regex, adding a `safer_alternative`, refactoring
   internals.

Plus the universal pre-flight checklist at the bottom. Read that
before opening a PR.

---

## 1. Reporting a bug

[Open an issue](https://github.com/AperionAI/shield/issues/new) and
include:

- **Shield version**: `aperion-shield --version` output
- **OS + architecture**: macOS arm64, Linux x86_64, Windows, etc.
- **The exact command you ran** that produced the bug
- **What you expected** to happen
- **What actually happened** (stdout, stderr, exit code, panic
  backtrace if applicable — `RUST_BACKTRACE=1` helps)
- **A minimal reproducer** if you can isolate one

If the bug is a panic or memory-unsafe behaviour, please use the
private channel in [`SECURITY.md`](SECURITY.md) instead of a public
issue.

---

## 2. Filing a false positive

**This is the most important feedback a Shield user can give us.**
A guardrail with a high false-positive rate gets disabled within a
week, so we treat false positives as P0 bugs and we publish our
[methodology](docs/methodology.md) so the false-positive rate is
verifiable.

To file a false positive, open an issue with the **"False positive"**
template, and include:

```text
**The line that fired** (in JSON-Lines form — the same format
`aperion-shield --check` accepts):

```json
{"tool":"run_terminal","params":{"command":"<your command here>"}}
```

**What Shield decided:** allow / warn / approval / block

**What you expected:** allow / warn / approval / block

**Which rule fired:** (from `aperion-shield --check`'s output —
the `matched_rules` field)

**Shieldset version:** (from `aperion-shield --version` — the
shieldset.yaml schema and any `--rules path/to/custom.yaml`
overrides you're using)

**Why this is legitimate:** one or two sentences of context. The
command, the workflow it's part of, why it's safe in this case.
```

Optional but extremely helpful: a minimal `expect:` line you'd want
to see merged into [`tests/corpus/golden.jsonl`](tests/corpus/golden.jsonl)
so the case is regression-protected once we fix it:

```json
{"tool":"run_terminal","params":{"command":"<your command>"},"expect":"allow"}
```

The fix usually lands as one of:
- A new positive case in `tests/corpus/golden.jsonl` plus a tightening
  of the matching rule's regex (we shipped six such fixes between
  v0.2 and v0.3 — search the changelog for "v0.3 baseline").
- A new entry in the `command_predicates` allow-list (e.g. an
  interpreter-with-stdin pattern that should not count as exfiltration).
- A new `safer_alternative` text if the rule is correct but the
  diagnostic is unhelpful.

We will tell you which class of fix yours is, and either ship it
ourselves or merge a PR from you.

---

## 3. Adding a new rule

Adding a rule is a four-step process. The first two are mandatory;
the third is mandatory for PRs we intend to merge; the fourth is
optional but appreciated.

### Step 1: write the rule in `shieldset.yaml`

Open [`config/shieldset.yaml`](config/shieldset.yaml). The schema
preamble at the top of the file is the authoritative reference; the
abbreviated version is:

```yaml
- id: surface.short_name              # e.g. `sql.drop_database` or `cloud.aws_rds_skip_snapshot`
  severity: Critical|High|Medium|Low  # mapped to Block / Approval / Warn / Allow
  points: 6                           # composite-score contribution; default = severity rank
  where: tool_call|llm_response       # what stream this rule watches
  match:
    tool: [execute_sql, postgres.query]    # tool names that trigger this rule (regex-free)
    sql_matches: ['(?i)\bDROP\s+DATABASE\b']  # full-line regex against the SQL string
    # OR
    any_param_matches:
      - '\bsome-regex\b'              # full-line regex against any param value
    # OR
    command_predicates: [curl_pipe_sh]   # named code-level predicates from src/predicates.rs
    # OR
    sql_predicates: [unscoped_update]    # named SQL-level predicates
    # OR
    sensitive_paths:
      - "/etc/**"
      - "~/.ssh/**"
  reason: "User-facing diagnostic. Two sentences max."
  safer_alternative: "What the user should do instead. Concrete."
```

Pick the **lowest** severity tier consistent with the threat. A `Critical`
rule blocks unconditionally; `High` prompts for approval; `Medium` warns
and proceeds; `Low` is audit-only. Composite scoring means several
`Medium`s can stack into a `High`, so you don't need to over-rate a
rule to make it count.

Always provide a `safer_alternative` for rules with severity ≥ Medium.
That's the developer-friendliness contract: Shield is supposed to
teach, not just refuse.

### Step 2: add positive AND negative cases to the golden corpus

Open [`tests/corpus/golden.jsonl`](tests/corpus/golden.jsonl). For
each new rule add at minimum:

- **One positive case** — input that should fire the rule (`expect`
  field set to the decision the rule produces: `block`, `approval`,
  `warn`)
- **One negative case** — input that **looks like** the positive case
  but is legitimate and should pass (`expect: allow`)

For a SQL rule:

```json
{"tool":"execute_sql","params":{"query":"DROP TABLE customers"},"expect":"approval"}
{"tool":"execute_sql","params":{"query":"DROP TABLE IF EXISTS tmp_customers_20260516"},"expect":"approval"}
{"tool":"execute_sql","params":{"query":"SELECT * FROM customers"},"expect":"allow"}
```

For a shell rule:

```json
{"tool":"run_terminal","params":{"command":"git push --force origin main"},"expect":"block"}
{"tool":"run_terminal","params":{"command":"git push origin feature/foo"},"expect":"allow"}
```

The negative cases are what keep your rule from becoming a false-
positive factory. **PRs that add a rule without a negative case will
be sent back for one.**

### Step 3: verify the corpus passes

```bash
cargo build --release
./target/release/aperion-shield --check < tests/corpus/golden.jsonl
echo "Exit code: $?"   # must be 0
cargo test --release   # all 133+ tests must pass
```

If the exit code is non-zero, the corpus output (one line per case)
will show which `expect:` annotations failed. Iterate until both
`--check` returns 0 and `cargo test --release` passes.

### Step 4 (optional but recommended): run the behavior-diff

If your change touches a regex pattern in an existing rule, or adds
a `command_predicates` / `sql_predicates` clause that overlaps with
existing rules, run [`scripts/shield-diff.py`](scripts/shield-diff.py)
against a real-world corpus (mine yours via
`scripts/extract-cursor-corpus.py`) to see which lines flip decision
under the new ruleset.

```bash
# Get a baseline ruleset
git show main:config/shieldset.yaml > /tmp/shieldset-before.yaml

# Mine your corpus
python3 scripts/extract-cursor-corpus.py --shell-only --out /tmp/cursor.jsonl

# Diff old vs new shieldsets across the corpus
python3 scripts/shield-diff.py \
    --before /tmp/shieldset-before.yaml \
    --after config/shieldset.yaml \
    --corpus /tmp/cursor.jsonl \
    --format markdown
```

The output gets attached to the PR description. It is the most
useful single artifact a Shield-change reviewer can have. See
[`docs/shieldset-as-code.md`](docs/shieldset-as-code.md) for the full
explanation of why and how.

---

## 4. Improving an existing rule or component

For changes to existing rules:

- Open an issue first describing the change and its motivation. We
  almost never reject these, but rule changes have non-obvious
  blast radius (one regex tightening can add 50 prompts/day to a
  team) and we want to think it through before you spend the time.
- Run `scripts/shield-diff.py` against a real corpus as part of the
  PR. Paste the output into the PR body. This is mandatory for
  rule changes.

For changes to internal components (`src/engine.rs`, `src/predicates.rs`,
`src/identity/*`, `src/orgmode/*`, etc.):

- Open an issue first if the change is substantial (>100 lines or
  touches the public API).
- Smaller, surgical fixes can go straight to PR.

---

## Universal pre-flight checklist

Before opening any PR:

```bash
# 1. Format
cargo fmt --all

# 2. Lint (we treat clippy warnings as errors in CI)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Tests
cargo test --release

# 4. Corpus (mandatory if you touched shieldset.yaml or any rule code)
cargo build --release
./target/release/aperion-shield --check < tests/corpus/golden.jsonl
```

If all four exit 0, you're cleared to push.

---

## Commit-message conventions

We use plain descriptive commit messages, no enforcement of
Conventional Commits. The bar is:

- Imperative mood ("Add tautological-WHERE detection" not "Added
  tautological-WHERE detection")
- One-sentence subject line, ≤72 chars
- Optional body explaining **why** the change is correct, not what
  the change does (the diff says what)

Example:

```
Add tautological-WHERE detection to sql.unscoped_update

Catches agents' favourite work-around: appending a WHERE clause
that is functionally equivalent to no WHERE clause (e.g. `WHERE
col = FALSE` paired with `SET col = TRUE`). Six tautology patterns
are detected; genuine scope-narrowing (e.g. `WHERE created_at >
NOW() - INTERVAL '7 days'`) still passes through. Adds 12 new
golden-corpus cases (6 positive, 6 negative) and updates the rule
reason / safer_alternative text.
```

---

## License and contributor agreement

By contributing, you agree that your contributions will be licensed
under the project's [Apache License 2.0](LICENSE). No separate CLA
required; the Apache 2.0 license already contains the necessary
patent and copyright grant language.

We do not require [DCO sign-off](https://developercertificate.org/)
on commits, though you are welcome to use it if your employer
requires it.

---

## Code of conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
Be kind, be technically precise, assume good faith, and report
behaviour that violates the code to `community@aperion.ai`.

---

## Where to ask questions

- **Bugs / feature requests**: [GitHub Issues](https://github.com/AperionAI/shield/issues)
- **Security issues**: see [`SECURITY.md`](SECURITY.md)
- **General Q&A or design discussion**: [GitHub Discussions](https://github.com/AperionAI/shield/discussions)
  (enable if not enabled in repo settings)
- **Commercial / Smartflow questions**: hello@aperion.ai

Thanks for making Shield better.
