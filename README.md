# aperion-shield — local MCP guardrail for AI coding agents

`aperion-shield` is a tiny, local MCP server that sits between your AI
coding agent (Cursor, Claude Code, …) and the **real** MCP servers your
agent talks to (postgres, github, shell, filesystem, …). On every
`tools/call` it evaluates **45+ adaptive safety rules** across eight
destructive surfaces — SQL, git, filesystem, secrets exfiltration,
supply-chain RCE, reverse shells, sudo / privilege escalation, cloud
(AWS/GCP/Azure), Kubernetes, and Docker — and either blocks the call,
prompts you for approval, or lets it through with a warning banner.

**v0.2 adds adaptive scoring** — Shield doesn't just match regexes. It
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

See [`docs/shield-public/cursor-quickstart.md`](../../docs/shield-public/cursor-quickstart.md)
and [`docs/shield-public/claude-code-quickstart.md`](../../docs/shield-public/claude-code-quickstart.md)
for the full walk-through (including how to combine multiple MCP
servers under a single Shield).

---

## What does Shield catch out-of-the-box?

The bundled ruleset covers eight destructive surfaces with 45+ rules:

| Category          | Examples                                                                                       |
|-------------------|------------------------------------------------------------------------------------------------|
| SQL               | `DROP DATABASE`, `DROP TABLE`, `TRUNCATE`, unscoped `UPDATE`/`DELETE`, `COPY FROM PROGRAM`, `LOAD DATA INFILE`, `GRANT ALL`, `REVOKE FROM PUBLIC` |
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

| Feature                                        | Free standalone | Smartflow (paid) |
|------------------------------------------------|:---------------:|:----------------:|
| Local rule engine + default ruleset            | ✅              | ✅               |
| Cursor / Claude Code MCP adapter               | ✅              | ✅               |
| Custom rules via local YAML                    | ✅              | ✅               |
| Shadow / enforce / audit modes                 | ✅              | ✅               |
| Local stderr audit log                         | ✅              | ✅               |
| Hosted approval queue + dashboard              | —               | ✅               |
| Tamper-evident audit chain (RFC 3161)          | —               | ✅               |
| WORM compliance connectors (S3 Object Lock)    | —               | ✅               |
| EU AI Act conformity console + AI-BOM          | —               | ✅               |
| Shared team rules + role-based approval        | —               | ✅               |
| MCP trust registry (signed servers)            | —               | ✅               |
| Sigstore-signed binaries + admission policies  | —               | ✅               |

The free product is governed by Apache 2.0; the paid product is a
commercial Aperion subscription. Both products live in this monorepo so
rules and tests stay in sync.

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
cd tools/shield-standalone
cargo build --release
./target/release/aperion-shield --help
```

The binary is self-contained: ship just the file.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
