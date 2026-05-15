# aperion-shield — local MCP guardrail for AI coding agents

`aperion-shield` is a tiny, local MCP server that sits between your AI
coding agent (Cursor, Claude Code, …) and the **real** MCP servers your
agent talks to (postgres, github, shell, filesystem, …). On every
`tools/call` it evaluates **45+ adaptive safety rules** across eight
destructive surfaces — SQL, git, filesystem, secrets exfiltration,
supply-chain RCE, reverse shells, sudo / privilege escalation, cloud
(AWS/GCP/Azure), Kubernetes, and Docker — and either blocks the call,
prompts you for approval, or lets it through with a warning banner.

Plus, when you need to prove **who** approved a destructive call —
not just that *someone* did — Shield can gate selected rules behind
**biometric identity verification** (ID.me, or a pluggable OIDC provider).
And when you outgrow the single-machine model, the **same binary**
enrolls into a Smartflow control plane with one command to pull
org-wide policy, ship audit upstream, and use your existing IdP as
the relying party — no rewrite, no re-install.

---

## What's new in v0.5

- **Identity gates** (new): selected high-blast-radius rules can now require a
  cryptographically-fresh proof of human identity *before* the call is forwarded.
  Pluggable providers ship with a mock-friendly default; ID.me OIDC + an
  optional local callback server lands behind a feature flag. Ed25519
  signatures on every proof; cache lives under `~/.aperion-shield/proofs/`
  (mode 0600). See [Identity gates](#identity-gates-new-in-v05).
- **Org mode** (new, opt-in): `aperion-shield --enroll --smartflow-url <URL>
  --token <ENROLL_TOKEN>` enrolls this Shield against a Smartflow control
  plane. On enrollment the client persists an Ed25519 vkey, then every run
  pulls policy, streams audit, and lets your existing Smartflow IdP serve as
  the relying party for identity gates. The control-plane code path is **inert
  until you enroll** — out-of-the-box `aperion-shield` is standalone and
  offline. See [Org mode](#org-mode-new-in-v05).
- **Tautological-WHERE detection** in `sql.unscoped_update` (new): the rule now
  catches the agent's favourite work-around — *"sure, I'll add a `WHERE`
  clause: `WHERE email_verified = FALSE` when I'm `SET email_verified = TRUE`"*
  — which selects exactly the rows the `SET` would change. Six tautology
  patterns are detected (boolean opposites, `IS NULL`-vs-`SET <value>`,
  inequality-vs-equality, etc.). Genuine scope-narrowing (`WHERE created_at >
  NOW() - INTERVAL '7 days'`) passes through.
- **0.5 is a strict superset of 0.3**: every rule, decision, and corpus
  result below still holds; identity gates and org mode are *additions*, not
  replacements, and the v0.3 noise-floor work (below) carries forward.

---

## v0.3 baseline (still in force in v0.5)

Wide-scale validation against ~13,000 real Cursor agent commands -- run
from a typical project root with no prod-signal files -- shows:

```
 12,708 (98.42%)   allow      <-- legitimate operations pass through
      3 (0.02%)   warn        <-- annotated, agent continues
    191 (1.48%)   approval    <-- pause for human signoff (writes to
                                    /etc, ~/.ssh, /usr/local/bin, etc.)
     10 (0.08%)   block       <-- hard stop (curl|bash, env->curl
                                    exfiltration, reverse-shell patterns)
```

That's a **94% reduction in approval-prompt noise vs v0.2** (which
fired on 73% of commands). The fixes:

- Recognising `ssh -i FILE`, `kubectl --kubeconfig FILE`, `KUBECONFIG=FILE`,
  and 20+ similar tool-flag patterns as identity / config args -- not
  write targets.
- Gating the `fs.sensitive_path_write_or_delete` rule on an actual
  write verb being present in the same command (`rm`, `mv`, `cp`, `dd`,
  `tee`, `chmod`, `chown`, `sed -i`, `tar -x`, `kubectl apply`, `>`/`>>`,
  here-docs, ...). Pure reads (`grep`, `cat`, `head`, `tail`, `ls`,
  `find -print`, ...) no longer trigger.
- Narrowing `/usr/**` to the genuinely-sensitive subdirs
  (`/usr/local/bin`, `/usr/local/sbin`, `/usr/local/lib`,
  `/usr/share/keyrings`, `/usr/lib/systemd`).
- Treating `2>/dev/null`, `1>/dev/null`, `&>/dev/null` as discard
  idioms, not filesystem writes.
- Allowing `curl URL | python -c CODE` / `python -m json.tool` /
  `perl -e CODE` / `node -e CODE` -- when the interpreter takes its
  code from args, stdin is DATA, not code.

**v0.2 added adaptive scoring** — Shield doesn't just match regexes. It
sums points across every rule that fires, bumps severity in
prod-looking workspaces, remembers which decisions you've already
approved or denied, and detects destructive bursts in real time. The
result: fewer false-positive prompts on benign repeats, harder gates
on the operations that matter, and a teach-as-you-go safer-alternative
hint on every block.

It is **free**, **open source** (Apache 2.0), and **standalone**. No
cloud account required. The binary is the same size as `git` and runs
on macOS, Linux, and Windows.

The paid product, [Aperion Smartflow](https://aperion.ai), bundles
Shield with a hosted approval queue, tamper-evident audit chain (RFC
3161 timestamps), AI-BOM, EU-AI-Act conformity console, and SOC 2 /
HIPAA / GDPR connectors. The two products share the same rule language
— a `shieldset.yaml` you write for one works in the other.

---

## Install

### Homebrew (macOS / Linux)

```bash
brew install AperionAI/tap/aperion-shield
```

### Docker

```bash
docker run --rm -i ghcr.io/aperionai/shield:latest --help
```

### Cargo (any platform)

```bash
cargo install aperion-shield
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/AperionAI/shield/releases).

---

## Quickstart

Add `aperion-shield` to your IDE's MCP config. Shield then transparently
wraps your real MCP server.

### Cursor (`~/.cursor/mcp.json`)

Before:

```json
{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgres://..."]
    }
  }
}
```

After:

```json
{
  "mcpServers": {
    "postgres": {
      "command": "aperion-shield",
      "args": [
        "--",
        "npx", "-y", "@modelcontextprotocol/server-postgres", "postgres://..."
      ]
    }
  }
}
```

That's it. Restart Cursor. Every `execute_sql` your agent issues now
goes through Shield first.

### Claude Code (`~/.claude/config.json`)

```json
{
  "mcpServers": {
    "shell": {
      "command": "aperion-shield",
      "args": ["--", "claude-mcp-shell"]
    }
  }
}
```

For the longer walk-through (combining multiple MCP servers under a
single Shield, IDE-specific tips, troubleshooting), see
[docs.aperion.ai/aperion-shield.html](https://docs.aperion.ai/aperion-shield.html).

---

## What does Shield catch out-of-the-box?

The bundled ruleset covers eight destructive surfaces with 45+ rules:

| Category          | Examples                                                                                       |
|-------------------|------------------------------------------------------------------------------------------------|
| SQL               | `DROP DATABASE`, `DROP TABLE`, `TRUNCATE`, unscoped `UPDATE`/`DELETE` (incl. **tautological-WHERE** detection — `WHERE col = FALSE` paired with `SET col = TRUE`), `COPY FROM PROGRAM`, `LOAD DATA INFILE`, `GRANT ALL`, `REVOKE FROM PUBLIC` |
| Git               | `git push --force` to protected branches, `filter-branch` / `filter-repo`, `reset --hard HEAD~`, `branch -D`, `clean -fxd`, `checkout .`         |
| Filesystem        | `rm -rf /`, `dd` to `/dev/sd*`, deletes/writes under `/etc`, `/var/lib`, `~/.ssh`, `~/.aws`; world-writable `chmod 777`; recursive `chown root`  |
| Secrets exfil     | compound *(read `.env` / `~/.aws/credentials` / `~/.ssh/id_*`) + (curl / wget / nc post)* in the same command — near-certain exfiltration         |
| Supply chain      | `curl ... \| sh`, `bash <(curl ...)`, `npm/pip/yarn/gem install --registry <untrusted-host>` (allowlist of npmjs / pypi / yarnpkg / rubygems)     |
| Reverse shells    | `bash -i >& /dev/tcp/...`, `nc -e /bin/sh`, mkfifo back-channels, python/perl/ruby one-liners, openssl s_client, socat, PowerShell `TCPClient`   |
| Privilege         | `sudo`-prefixed destructive verbs, setuid grants (`chmod u+s`, `setcap`)                                                                          |
| Cloud / k8s / Docker | `aws s3 rm --recursive`, `aws rds delete-db-instance --skip-final-snapshot`, `terraform destroy -auto-approve`, `gcloud sql instances delete`, `az group delete --yes`, `kubectl delete namespace`, `kubectl delete --all`, `helm uninstall`, `docker system prune -a --volumes -f` |
| LLM plans         | Assistant-text mentions of the same destructive patterns above (second-pair-of-eyes)                                                              |
| Anomaly           | Burst of destructive verbs by the same actor inside a 5-minute window                                                                             |

### Adaptive scoring (new in v0.2)

Shield combines five signals when deciding whether to allow, warn,
prompt, or block a call:

| Signal                      | Effect                                                          |
|-----------------------------|------------------------------------------------------------------|
| **Raw severity**            | The highest single rule's tier (Low / Medium / High / Critical) |
| **Composite points**        | Sum of points across every rule that fired — turns multiple Mediums into a High |
| **Workspace context**       | One-tier bump in prod-looking repos (`.env.production`, `kubeconfig`, `prod/`, etc.) |
| **Decision memory**         | Three approvals of the same fingerprint demotes one tier; a denial in the last 7 days escalates one tier |
| **Burst detector**          | While 5+ destructive matches in a 5-minute window are in flight, every match bumps one tier |

Memory lives at `.aperion-shield/decisions.jsonl` in your project root.
It never leaves your machine; the standalone is offline-only.

You can layer your own rules on top via `--rules my.yaml`.

---

## Identity gates (new in v0.5)

For the highest-blast-radius calls -- `DROP DATABASE`, force-push to a
protected branch, `aws rds delete-db-instance`, an unscoped `UPDATE` on
prod, or whatever you decide is *"a human signature should be on this"*
-- a `block` or `approval` isn't always enough. You want a fresh proof
that the *person* on the other end of the keyboard is who they claim to
be, *right now*, before the call is forwarded.

Identity gates do that. Any rule can carry an `identity:` block:

```yaml
shieldset:
  version: 1
  rules:
    - id: sql.drop_database
      severity: Critical
      where: tool_call
      match:
        tool: [execute_sql]
        sql_predicate: drop_database
      identity:
        require: true            # gate this rule on a fresh identity proof
        ial: 2                   # NIST IAL2 minimum (in-person or remote biometric)
        aal: 2                   # NIST AAL2 minimum (MFA bound to a hardware token)
        max_age_seconds: 300     # proof must be < 5 min old
        scopes: ["destructive_db"]
      reason: "DROP DATABASE is never auto-allowed."
```

When that rule fires, Shield emits a `Decision::IdentityVerification`
to the caller (the agent, surfaced in the IDE), opens a local callback
server, and waits for the user to complete an OIDC flow with the
configured provider. On success it caches an **Ed25519-signed proof**
in `~/.aperion-shield/proofs/` (mode 0600). Subsequent calls within
`max_age_seconds` re-use the cached proof; older proofs force a fresh
verification.

### Providers

| Provider           | Status        | Use it for                                    |
|--------------------|---------------|-----------------------------------------------|
| `mock`             | default       | Local dev / CI; instantly issues a proof      |
| `idme`             | feature-gated | ID.me OIDC, IAL/AAL-graded biometric          |
| `smartflow`        | org mode only | Uses your Smartflow tenant's IdP (Okta / Auth0 / Azure AD / Google) as the relying party |
| custom (trait impl)| any           | Implement `IdentityProvider` and link it in    |

Config lives at `~/.aperion-shield/identity.yaml` (or pass
`--identity-config path.yaml`). An annotated example is at
[`examples/identity.yaml`](examples/identity.yaml).

### CLI

```bash
# Disable identity gating entirely (rules' identity blocks become plain Approval/Block).
aperion-shield --no-identity -- npx ...

# Inspect the cached-proof store.
aperion-shield --identity-list

# Drop every cached proof; forces re-verification on the next gated call.
aperion-shield --identity-flush
```

ID.me sandbox access is pending; until then the `mock` provider is the
recommended default and the YAML schema is stable.

---

## Org mode (new in v0.5)

Standalone Shield is single-machine, offline, and never phones home.
That's the right default for individual developers and tight
engineering teams. But once you have ten or a hundred Shields running
across a workforce, you'll want:

- one shieldset for the whole org, versioned centrally
- audit centralised in one place, tamper-evident
- identity gates that lean on your existing IdP, not on per-laptop config
- a kill-switch that disables a compromised laptop in <60s

Org mode is the upgrade path. The **same `aperion-shield` binary** in
this repo, when enrolled into a Smartflow control plane, becomes a
tenant-aware client. Out of the box it is dormant. You opt in:

```bash
# 1. From a Smartflow admin console: mint an enrollment token (one-shot, scoped).

# 2. On the user's laptop, once:
aperion-shield --enroll \
    --smartflow-url https://shield.your-tenant.smartflow.ai \
    --token sf_enroll_eyJhb...

# Persists an Ed25519 vkey at ~/.aperion-shield/orgmode.json (mode 0600).
# Subsequent `aperion-shield` runs:
#   - pull policy from the control plane on startup
#   - watch a long-poll endpoint for shieldset / killswitch updates
#   - stream every decision as a signed audit record upstream
#   - use the tenant's IdP as the identity-gate relying party
```

Status:

```bash
aperion-shield --status
# Standalone:  prints "standalone (not enrolled)" and exits 0.
# Enrolled:    prints tenant ID, last policy sync, last heartbeat, etc.
```

The control-plane code path **only activates once you enroll**. Without
an enrollment token + Smartflow URL the org-mode subsystem stays
inert -- Shield runs identically to the standalone configuration.

Why ship the client code in the OSS binary? Because:

1. It's the bridge to the paid product. Engineers exploring the OSS
   today should be able to read exactly how the upgrade works -- no
   binary swap, no re-install, no surprise dependencies. When their
   shop buys Smartflow, the laptops they already have keep running.
2. Auditability. The wire protocol, the signing scheme, the policy-pull
   semantics, and the audit-record format are all in
   [`src/orgmode/`](src/orgmode/). You can review them before adopting.
3. Inert until enrolled. The code does not initiate any outbound
   traffic, look at any env vars, or open any sockets until `--enroll`
   has been run and a vkey is persisted on disk.

Smartflow itself (the control plane, the dashboards, the EU-AI-Act
conformity console, the WORM audit chain) is a separate, commercial
product at [aperion.ai](https://aperion.ai). The wire format the
OSS client speaks is documented in
[`src/orgmode/mod.rs`](src/orgmode/mod.rs).

---

## Operating modes

Default mode is **enforce**: Critical-severity decisions hard-block, and
High-severity decisions require human approval before the call is
forwarded.

| Mode      | Block      | Approval                                 |
|-----------|------------|------------------------------------------|
| `enforce` | Yes (403)  | Wait on local inbox file (60s timeout)   |
| `shadow`  | Warn only  | Warn only                                |
| auto-deny | Yes (403)  | Auto-deny (`--auto-deny-high`)           |

```bash
# Pure observability — never blocks; ideal for the first week
aperion-shield --shadow -- npx @modelcontextprotocol/server-postgres ...

# CI / unattended use — never prompt, deny anything High
aperion-shield --auto-deny-high -- npx @modelcontextprotocol/server-postgres ...
```

---

## Workspace probe (prod-shaped repos run stricter)

Shield boots a tiny "is this a production-shaped workspace?" probe at
startup. If the CWD contains any of these signals, every match in this
session gets a **+1 severity bump** -- a warn becomes an approval, an
approval becomes a block, a block stays a block:

```
.env.production    .env.prod              kubeconfig
prod/              production/            .kube/config
Procfile           production.yml         production.yaml
k8s/prod/          deploy/prod/           .terraform/terraform.tfstate
```

This is by design: when you're operating an agent in a workspace that
already touches live infrastructure, you want a harder gate. In a
vanilla project root the probe doesn't fire and you see the raw rule
output. The probe also runs at the cwd Shield started in, NOT at
`$HOME` -- so dropping a kubeconfig in your home directory doesn't
affect Shield invocations launched from a clean repo.

Three ways to inspect / control:

```bash
# Confirm what the probe sees right now (printed in startup banner).
aperion-shield --check --no-memory < /dev/null
# [shield-check] ... workspace_prod=false signals=[]

# Override the probe root -- useful for batch testing.
aperion-shield --check --workspace /tmp/empty < cases.jsonl

# Disable the probe entirely (raw rule output, no bumps).
aperion-shield --check --no-workspace-probe < cases.jsonl
```

For interpreting wide-scale runs: anchor on the **realistic-project-
root** number (probe off OR run from a vanilla repo). The probe-on
number is the "strictest-mode preview" for prod-shaped workspaces.

---

## Mining your own Cursor history as a test corpus

If you use Cursor (or Claude Code), every agent conversation is stored
on disk as JSON-Lines. `scripts/extract-cursor-corpus.py` walks all of
your transcripts, pulls out shell commands and assistant text, redacts
obvious secrets, deduplicates, and emits the exact JSON-Lines schema
`aperion-shield --check` expects -- so you can run Shield against your
actual workflow before ever wiring it into the IDE.

```bash
# Mine all transcripts under ~/.cursor/projects, then evaluate them all.
python3 scripts/extract-cursor-corpus.py --shell-only \
  | aperion-shield --check --no-memory --no-burst \
  | jq -c 'select(.decision != "allow")'

# Mine just one project, save the corpus for re-use.
python3 scripts/extract-cursor-corpus.py \
    --project Smartflow --shell-only \
    --out my-corpus.jsonl
aperion-shield --check < my-corpus.jsonl > decisions.jsonl

# Include assistant text turns (llm_response scope rules) too.
python3 scripts/extract-cursor-corpus.py > my-corpus.jsonl

# Disable redaction (default-on) only if you've reviewed the patterns.
python3 scripts/extract-cursor-corpus.py --raw ...
```

The extractor is read-only, reads only your local Cursor transcript
files, redacts AKIA/sk-/ghp_/JWT-shaped tokens before output, and
de-duplicates by command/text. The corpus this produces is exactly
what was used to validate Shield against ~13k real-world commands and
drove the v0.3 rule-quality improvements (false-positive rate dropped
from 73% to 1.5%).

---

## Wide-scale testing without an IDE

Want to throw hundreds of synthetic tool-calls at the engine before
wiring it into Cursor? Shield ships a one-shot `--check` mode that
reads JSON-Lines from stdin, runs each one through the full engine
(rules + composite scoring + workspace probe + memory + burst), and
emits one decision per line to stdout.

```bash
# One-off
echo '{"tool":"execute_sql","params":{"query":"DROP DATABASE x"}}' \
  | aperion-shield --check

# Batch — JSON-Lines in, JSON-Lines out
aperion-shield --check < tests/corpus/golden.jsonl
```

Input schema per line (the `expect` field is optional and enables
pass/fail grading + a non-zero exit on any mismatch):

```json
{"tool":"execute_sql","params":{"query":"DROP DATABASE x"},"expect":"block"}
{"text":"I will rm -rf /","expect":"warn"}
```

The bundled corpus at
[`tests/corpus/golden.jsonl`](tests/corpus/golden.jsonl)
covers every shipping rule (positive + negative cases). The
[`scripts/check-corpus.sh`](scripts/check-corpus.sh) wrapper formats
the output for humans:

```bash
# Build once, run the corpus
cargo build --release
SHIELD_BIN=./target/release/aperion-shield scripts/check-corpus.sh

# Against your own corpus
SHIELD_BIN=./target/release/aperion-shield scripts/check-corpus.sh ./my-cases.jsonl

# With a custom ruleset and a fixtured prod workspace
RULES=my.yaml WORKSPACE=/tmp/fake-prod \
  SHIELD_BIN=./target/release/aperion-shield scripts/check-corpus.sh
```

`--check` honours the same `--rules`, `--no-workspace-probe`,
`--no-memory`, and `--no-burst` flags as the MCP-proxy mode. There's
also a `--workspace <PATH>` flag (check-mode only) that overrides the
prod-probe root so you can simulate "what would happen in a prod repo"
without `cd`-ing anywhere. Decision memory and burst are auto-disabled
inside `check-corpus.sh` for deterministic batch runs.

---

## Approving a request

When a `High`-severity rule fires, Shield logs a line like:

```text
[shield] APPROVAL REQUIRED rule=sql.unscoped_update ticket=shld_<uuid> tool=execute_sql
[shield] To approve, write 'approve shld_<uuid>' to ./.aperion-shield/inbox  (waiting 60s)
```

To approve, in a second terminal:

```bash
echo "approve shld_<uuid>" >> .aperion-shield/inbox
```

To deny:

```bash
echo "deny shld_<uuid>" >> .aperion-shield/inbox
```

If 60 seconds pass with no decision, the call is denied.

---

## Custom rules

The full schema lives in
[`config/shieldset.yaml`](config/shieldset.yaml). A minimal custom
rule:

```yaml
shieldset:
  version: 1
  rules:
    - id: company.no_prod_writes
      severity: Critical
      where: tool_call
      match:
        tool: [execute_sql, postgres.query, mysql.query]
        any_param_matches:
          - '(?i)\bUPDATE\s+.*\bprod_'
      reason: "Direct writes to prod_* tables are forbidden."
```

Drop it in `~/.aperion-shield/shield.yaml` (or pass `--rules path.yaml`)
and restart your IDE.

---

## Free vs paid

| Feature                                                                | Free standalone | Smartflow (paid) |
|------------------------------------------------------------------------|:---------------:|:----------------:|
| Local rule engine + default ruleset (45+ rules)                        | ✅              | ✅               |
| Cursor / Claude Code MCP adapter                                       | ✅              | ✅               |
| Custom rules via local YAML                                            | ✅              | ✅               |
| Shadow / enforce / auto-deny modes                                     | ✅              | ✅               |
| Composite scoring + workspace probe + decision memory + burst detector | ✅              | ✅               |
| Local stderr audit log + `.aperion-shield/decisions.jsonl`             | ✅              | ✅               |
| `--check` mode (CI / corpus testing)                                   | ✅              | ✅               |
| Identity gates -- mock provider + ID.me provider (feature-gated)       | ✅              | ✅               |
| Org-mode **client** (`--enroll`, policy pull, audit stream, vkey)      | ✅              | ✅               |
| Hosted approval queue + dashboard                                      | —               | ✅               |
| Org-wide shieldset distribution + versioning                           | —               | ✅               |
| Killswitch + remote-disable a compromised laptop in <60s               | —               | ✅               |
| Tamper-evident audit chain (RFC 3161)                                  | —               | ✅               |
| WORM compliance connectors (S3 Object Lock)                            | —               | ✅               |
| EU AI Act conformity console + AI-BOM                                  | —               | ✅               |
| Shared team rules + role-based approval                                | —               | ✅               |
| Tenant IdP as identity-gate relying party (Okta/Auth0/Azure AD/Google) | —               | ✅               |
| MCP trust registry (signed servers)                                    | —               | ✅               |
| Sigstore-signed binaries + admission policies                          | —               | ✅               |

The free product is governed by Apache 2.0 — including the `src/orgmode/`
client. The paid product is the Smartflow **control plane** that the
client talks to: a hosted service, separately licensed. Both halves
share the same `shieldset.yaml` schema and the same audit-record format,
so policy you author for standalone Shield works unchanged once you
enroll into Smartflow.

---

## Privacy

The free standalone product does **not** phone home. There is no
telemetry, no usage counters sent anywhere, and no cloud account ever
created. All logs go to your local stderr.

A future optional "public block ticker" (a counter of how many
destructive ops Shield blocked across the entire user base, never
including the actual SQL / prompt / payload) is being designed; if /
when it ships, it will be **explicitly opt-in** at install time and
gated on legal / DPO review.

---

## Build from source

```bash
git clone https://github.com/AperionAI/shield.git
cd shield
cargo build --release
./target/release/aperion-shield --help
```

The binary is self-contained: ship just the file. Builds on macOS,
Linux, and Windows with stable Rust (1.75+).

---

## Developer one-pager (PDF)

A self-contained HTML one-pager lives at
[`docs/aperion-shield-developer-onepager.html`](docs/aperion-shield-developer-onepager.html)
(also published at <https://docs.aperion.ai/aperion-shield-developer-onepager.html>).

Open the page and use the **Save as PDF** toolbar at the top — two one-click
options:

| Button                  | Result                                                                   |
| ----------------------- | ------------------------------------------------------------------------ |
| **Dark (matches site)** | PDF preserves the website's dark navy / emerald theme exactly.           |
| **Light (handout)**     | White-background, ink-friendly handout for printing & internal hand-out. |
| **Copy CLI command**    | Copies a headless-Chrome command for CI / batch generation.              |

When you click "Save as PDF" in the browser dialog, make sure **Background
graphics** is enabled (Chrome: *More settings → Options → Background graphics*).
Without it the browser strips colors and you get a faded version.

### CLI export (headless Chrome)

For CI, automation, or "just give me the file" use:

```bash
# Dark theme (default) — looks identical to the site
./scripts/render-onepager-pdf.sh

# White-background handout
./scripts/render-onepager-pdf.sh --light

# Custom URL / output path
./scripts/render-onepager-pdf.sh --url file://$PWD/docs/aperion-shield-developer-onepager.html \
                                  --out ~/Desktop/shield.pdf
```

The script auto-detects Chrome, Chromium, Brave, or Edge. Set `CHROME_BIN` to
override. Append `?theme=dark` to the URL manually if you're feeding it to
another PDF renderer — the page's JS picks that up and swaps the print
stylesheet at load time.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
