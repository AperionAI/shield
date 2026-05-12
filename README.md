# aperion-shield — local MCP guardrail for AI coding agents

`aperion-shield` is a tiny, local MCP server that sits between your AI
coding agent (Cursor, Claude Code, …) and the **real** MCP servers your
agent talks to (postgres, github, shell, filesystem, …). On every
`tools/call` it evaluates a set of safety rules — `DROP DATABASE`,
unscoped `UPDATE`, `git push --force` to a protected branch, `rm -rf /`,
and so on — and either blocks the call, prompts you for approval, or
lets it through with a warning banner.

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

The bundled ruleset (the same YAML that ships with the enterprise
Smartflow build) covers:

| Category   | Examples                                                                              |
|------------|---------------------------------------------------------------------------------------|
| SQL        | `DROP DATABASE`, `DROP TABLE`, `TRUNCATE`, unscoped `UPDATE` / `DELETE`, `GRANT ALL`  |
| Git        | `git push --force` to `main` / `master`, `git filter-repo`, `git reset --hard HEAD~`  |
| Filesystem | `rm -rf /`, `rm -rf $HOME`, `dd if=… of=/dev/sda`, delete under `/etc`, `/var`, etc.  |
| LLM plans  | Assistant-text mentions of the same destructive patterns above (second-pair-of-eyes) |
| Anomaly    | Burst of destructive verbs by the same actor inside a 5-minute window                |

13 rules out of the box. You can layer on your own via `--rules my.yaml`.

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
[`config/shieldset.yaml`](../../config/shieldset.yaml). A minimal custom
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
