# Security policy

Aperion Shield is a security product. We take vulnerabilities in it,
and in its dependencies, seriously — and we document our analysis in
public so the people running it on their machines can make their own
informed decision.

This file covers four things:

1. **Supported versions** — which releases get fixes.
2. **Reporting a vulnerability** — how to tell us about a new one.
3. **Threat model** — what Shield is designed to protect against, and
   the trust boundaries that come with that.
4. **Open advisories** — the public alerts that exist right now,
   our analysis of whether they affect Shield's actual usage, and
   the release that closes them.

If you only read one section, read **§4 — Open advisories** below.

---

## 1. Supported versions

| Version | Status | Receives fixes |
|---|---|---|
| `1.6.x` | current stable | yes |
| `1.5.x` | previous       | security-only — superseded by v1.6.0 on 2026-08-25 |
| `1.4.x` | previous       | security-only — superseded by v1.5.0 on 2026-08-25 |
| `1.3.x` | superseded     | no |
| `0.8.x` | superseded     | no |
| `< 0.8` | superseded     | no |

We do **not** backport fixes to pre-1.0 minor lines. Stay on the
latest tagged release. Homebrew users get this automatically; pinned
Docker users should bump to `:latest` or the newest version tag on
each release.

---

## 2. Reporting a vulnerability

**Preferred channel:** [GitHub Security Advisories](https://github.com/AperionAI/shield/security/advisories/new) — private,
end-to-end, auditable.

**Alternate:** email `security@aperion.ai` (PGP key on request).

**Response targets:**

- Acknowledgement: within **48 hours**
- Initial triage / severity assessment: within **5 business days**
- Patch released: **30 days** for High/Critical, **90 days** for
  Medium/Low, faster when a public exploit exists

**Coordinated disclosure.** We will not publicly disclose a reported
issue until either a fix is released or the timelines above expire,
whichever comes first. We will credit reporters who request it.

**Safe harbour.** Good-faith security research that:

- Does not access data belonging to other Shield users,
- Does not degrade service for anyone other than the researcher's
  own infrastructure, and
- Does not violate any laws,

will not be pursued legally by Aperion. We are operationally
sympathetic to fuzzing, dependency analysis, and protocol
inspection of every binary we ship.

---

## 3. Threat model

### What Shield is designed to defend against

- **An AI coding agent issuing a destructive tool call** (e.g. `DROP
  DATABASE`, `rm -rf /`, `git push --force` to a protected branch,
  `curl ... | sh`, `aws rds delete-db-instance --skip-final-snapshot`).
- **A compromised assistant turn** that emits an LLM-response-scope
  matched pattern (e.g. assistant text containing a destructive
  plan that would be acted on by a downstream agent).
- **A burst of low-individual-severity calls** that collectively
  represent an attack (caught by the anomaly burst detector).
- **An agent doing the right thing in the wrong context** — e.g.
  running a normally-fine call against a production-shaped workspace
  (caught by the workspace probe's severity bump).

### What Shield is **not** designed to defend against

- **A malicious or compromised user with shell access on the same
  machine.** Shield runs as the local user; anyone who can already
  run arbitrary commands on the host can disable Shield, edit its
  rules, or replace the binary. Shield is a guardrail for *agents*,
  not for *adversaries with root*.
- **An attacker who can replace the upstream MCP server** that
  Shield wraps. Shield evaluates `tools/call` payloads on the way
  in; if the upstream itself is malicious, Shield's allow decisions
  send traffic to a malicious tool.
- **Side-channel attacks against the local rule engine** (timing,
  memory inspection). Shield's threat model assumes the host is
  trusted.
- **Vulnerabilities in your operating system, IDE, or upstream MCP
  servers.** Shield does not patch what it does not own.

### Trust boundaries

| Boundary | Trusted? | Notes |
|---|---|---|
| The local user account running Shield | yes | Shield runs in-process |
| The shieldset YAML on disk | yes | Editable by the user; load-time validated |
| The upstream MCP server Shield spawns | partially | Process boundary; child process inherits the parent's environment |
| The IDE / agent on the other side of the MCP socket | partially | JSON-RPC frames are validated, oversized payloads rejected |
| Identity providers (ID.me, OIDC) over the network | partially | TLS-validated; we trust the chain to the OS's CA bundle |
| Smartflow control plane (org-mode only, when enrolled) | partially | TLS + HMAC vkey on every request |

### Known limitation: drift-check probes are not unspoofable (v1.2+)

Continuous MCP catalog drift monitoring (`--drift-check-interval-secs`,
shipped in v1.2) proactively re-sends `tools/list` to the upstream on a
timer to catch a rug pull mid-session, instead of waiting for the
client's next real catalog refresh. This raises the cost of a rug pull
but does **not** make it cryptographically impossible to evade:

- The probe travels over the *same* stdio/HTTP channel as real client
  traffic. The only thing distinguishing it from a client-initiated
  `tools/list` is the request `id` -- there is no other metadata
  boundary between "Shield asked" and "the IDE asked." A malicious
  upstream that specifically targets Shield could, in principle, try
  to tell them apart and answer differently (lie to the probe, attack
  the client).
- We mitigate the cheapest version of this: the probe id is a bare
  random UUID with no `shield`/`drift`-style prefix (any static,
  greppable marker in observed network traffic would hand an adversary
  a free tell), and the polling interval is jittered +/-20% so the
  cadence itself isn't a clean, easily-fingerprinted periodic signal.
- We do **not** claim this defeats a well-resourced, targeted
  adversary running statistical traffic analysis over a long session
  (e.g., correlating `tools/list` calls against observable user
  activity to infer which ones are unattended). Closing that
  completely would require either making the probe indistinguishable
  in *timing* as well as content (out of scope for v1.2), or a
  channel-independent verification mechanism (e.g. signed tool
  manifests from a registry Shield trusts independently of the
  upstream server itself) -- an ecosystem-level primitive that does
  not exist yet for MCP.
- The complementary control for "I don't trust this upstream server's
  process at all" is `--sandbox` (OS-level process confinement), which
  constrains what a malicious server can *do* even if it evades
  catalog-level detection entirely.

### Known limitation: cross-tool taint tracking is heuristic (v1.3+)

Cross-tool secret taint tracking (`--taint-ttl-secs`, shipped in v1.3)
tags a hash of any credential-shaped value a tool *returns*, and escalates
a later call on any surface that relays the same value. It closes the
confused-deputy / cross-tool-relay gap (OWASP MCP09) that per-call checks
miss, but it is **heuristic correlation, not a cryptographic taint-
tracking guarantee**:

- **Hash-equality only.** The correlation works by matching a SHA-256 of
  the *exact substring* our regex extracts. A secret that is re-encoded or
  transformed before reuse -- base64/hex re-encoding, URL-encoding,
  splitting across fields, partial retyping, or wrapping in a different
  serialization -- will not hash-match and will evade detection. Detecting
  transformed secrets would require dataflow-level taint propagation
  inside the agent/runtime, which a protocol-level proxy cannot see.
- **Regex coverage is finite.** Only the enumerated high-signal shapes
  (AWS/GitHub/Slack/OpenAI/Anthropic/Google/Stripe tokens, JWTs, PEM
  private-key blocks, DB connection strings) are tracked. A bespoke or
  vendor-specific credential format outside that corpus is not tagged. The
  scope is deliberately tight to keep false positives near zero; it is not
  a claim of completeness.
- **No file locking.** The ledger (`.aperion-shield/taint.jsonl`) is
  append-only and lock-free, the same best-effort contract as decision
  memory. A read/write race between two Shield processes in the same
  project can, in a narrow window, miss a just-written entry (fail open,
  never fail closed with a false block on unrelated data).
- **CWD-scoped.** The ledger lives under the current working directory's
  `.aperion-shield/` (falling back to `~/.aperion-shield/` when the
  project dir is read-only) -- the same inherited scoping caveat that
  already applies to decision memory. Two IDE windows rooted at different
  directories do not share a ledger.
- **We never store the raw secret** -- only its hash, plus the entity kind
  and the source tool/surface for the human-readable reason. `--taint-list`
  and the audit log surface those metadata, never the credential itself.

The signal is intended to *raise the cost and visibility* of a cross-tool
credential relay and force a human decision on it, not to be an
unbypassable exfiltration control. For "I don't trust this server's
process at all," `--sandbox` remains the complementary control.

### Known limitation: native agent hooks are user-level (v1.5+)

`--install-agent-hooks` writes fail-closed wrappers under
`~/.aperion-shield/hooks/` and merges **user-level** host config
(Claude, Cursor, Codex, Gemini CLI, Copilot CLI). That is the
TrustFall-shaped threat: project-local hook files can be dropped in by
a malicious repo. Install prints those files and does not modify them;
`--scan-ide` flags them as `scan.ide.project_hooks`.

Honest limits:

- **Project hooks can still exist.** We do not delete or override
  `.cursor/hooks.json` / `.claude/settings.json` (or Codex / Gemini /
  Copilot equivalents) inside a repo. A project can add its own hooks;
  user-level hooks still fire if the host loads both, but that is
  host-defined.
- **`SHIELD_HOOKS_DISABLE=1` and git `--no-verify` still bypass.** Same
  contract as the git hooks. The native wrappers fail closed if the
  binary is missing; git hooks historically fail open so teammates
  without Shield can still commit.
- **Claude and Cursor deny JSON are not interchangeable.** The wrong
  dialect is a silent allow on one host. Wrappers are separate on
  purpose.
- **`--scan-ide` does not execute servers.** It reads JSON and SKILL.md.
  A command-type MCP that is not yet written to disk will not show up.

### Cryptographic primitives

- **Ed25519** for identity proofs (the `--identity-*` family) and
  for org-mode device vkeys (when `--enroll`ed). Keys are generated
  per machine, stored in `~/.aperion-shield/` at mode `0600`, never
  transmitted off the device.
- **Rustls** (with the OS trust store) for all outbound TLS. We do
  not implement custom TLS or roll our own X.509 path validation.
- **SHA-256** for content hashes (audit chain, proof cache fingerprints).

We use well-reviewed Rust crates for all of the above (`ed25519-dalek`,
`rustls`, `sha2`). Where those crates have advisories, see §4 below.

---

## 4. Open advisories

This section is the truthful, technical answer to the question
"are there any known vulnerabilities affecting aperion-shield?"
It is updated when alerts open and when they close.

### As of 2026-05-18 — none

`cargo audit` against the v0.6.0 `Cargo.lock` returns clean.
GitHub Dependabot has zero open advisories against the
`AperionAI/shield` repository on `main`.

The three `rustls-webpki 0.101.7` advisories that were open between
2026-05-15 and 2026-05-18 are now **closed in v0.6.0** by the
dependency upgrade described in §4.5 below. Their detailed analysis
is retained in §4.1 – §4.3 for the historical record so anyone
auditing the pre-v0.6.0 line can see the reasoning we applied.

#### 4.1 [RUSTSEC-2026-0104](https://rustsec.org/advisories/RUSTSEC-2026-0104.html) — `rustls-webpki`: reachable panic on malformed CRL BIT STRING

- **Status:** **CLOSED in v0.6.0** by upgrading `rustls-webpki`
  `0.101.7` → `0.103.13`. `Cargo.lock` no longer references the
  vulnerable crate.
- **Severity (GitHub):** High
- **Triggering condition (from the advisory):** *"Applications that
  do not use CRLs are not affected."*
- **Was Shield exploitable?** **No.** Shield does not use
  Certificate Revocation Lists. The default rustls configuration
  used by `reqwest` does not perform CRL checking, and we do not
  call either `BorrowedCertRevocationList::from_der` or
  `OwnedCertRevocationList::from_der`. There is no code path in
  Shield that parses a CRL.

#### 4.2 [RUSTSEC-2026-0098](https://rustsec.org/advisories/RUSTSEC-2026-0098.html) — `rustls-webpki`: URI name constraints incorrectly accepted

- **Status:** **CLOSED in v0.6.0** (same upgrade as §4.1).
- **Severity (GitHub):** Low
- **Triggering condition (from the advisory):** *"This bug is
  reachable only after signature verification and requires
  misissuance to exploit."*
- **Was Shield exploitable?** **In practice, no.** The exploit
  required a certificate authority in the OS trust store to
  misissue a certificate with malformed URI name constraints.
  If that condition were true, every TLS-using application on the
  machine would be at risk — not just Shield. We rely on the
  system trust store and rustls' standard chain validation; we do
  not add or remove CAs. The advisory itself notes the library
  does not currently expose an API for asserting URI names, which
  made the practical exploit surface narrow.

#### 4.3 [RUSTSEC-2026-0099](https://rustsec.org/advisories/RUSTSEC-2026-0099.html) — `rustls-webpki`: wildcard names accepted under name constraints

- **Status:** **CLOSED in v0.6.0** (same upgrade as §4.1).
- **Severity (GitHub):** Low
- **Triggering condition (from the advisory):** *"requires
  misissuance to exploit."*
- **Was Shield exploitable?** **In practice, no.** Same reasoning
  as §4.2. The exploit required a misissued certificate in the
  chain to a CA the host already trusted.

### 4.4 Historical: why we did not yank v0.5.0

The three advisories are real, but **not exploitable in Shield's
actual usage**:

- Shield does not parse CRLs.
- Shield does not assert URI or wildcard name constraints during
  TLS validation; it uses rustls' default validator with the OS
  trust store. The two name-constraint advisories require a
  misissued certificate in a trusted CA chain — a scenario that
  compromises every TLS-using application on the host, not just
  Shield.

Yanking v0.5.0 over advisories that have no practical effect on
the binary would signal something incorrect about the actual
security posture. We choose to leave the release in place,
document the analysis here, and ship the dependency upgrade as
part of the **next planned release**.

### 4.5 Fix shipped in v0.6.0 (2026-05-18)

All three advisories were fixed by upgrading the connected
`reqwest` / `rustls` / `hyper` dependency cluster:

| Dependency | v0.5.x | v0.6.0 |
|---|---|---|
| `reqwest`       | `0.11.27` | `0.12.28` |
| `rustls`        | `0.21.12` | `0.23.40` |
| `rustls-webpki` | `0.101.7` | `0.103.13` (closes all three advisories) |
| `hyper-rustls`  | `0.24.2`  | `0.27.9`  |
| `hyper`         | `0.14.32` | `1.9.0`   |
| `tokio-rustls`  | `0.24.1`  | `0.26.4`  |
| `webpki-roots`  | `0.25.4`  | `1.0.7`   |

The hyper 0.14 → 1.x bump required a refactor of the OIDC callback
server in `src/identity/server.rs` to the new
`http1::Builder` / per-connection `serve_connection` model and the
`http_body_util::Full<Bytes>` body type. The refactor is contained
to that one file; the rest of the binary saw no API surface change.

**Verification on the v0.6.0 release commit:**

1. `cargo audit` returns clean against an empty
   `.cargo/audit.toml` ignore list (the file is in the repo at the
   tagged commit if you want to confirm).
2. `cargo build --release --locked` succeeds.
3. `cargo test --release` passes all 148 tests (133 from v0.5.0 +
   15 new diff-mode tests in v0.6.0).
4. End-to-end identity flow against the mock OIDC provider in
   `tests/identity_e2e.rs` still completes successfully on the
   refactored hyper 1.x callback server.

---

## 5. Supply-chain provenance

Every release on GitHub ships:

- A `sha256` digest file alongside each binary archive (computed at
  build time on GitHub-hosted runners).
- A multi-arch Docker image at `ghcr.io/aperionai/shield` with
  build-attestation provenance (`linux/amd64` + `linux/arm64`).
- Source available at the tag (`shield-v0.5.0`, `shield-v0.6.0`, ...)
  with the full build history.
- A CI gate that runs `cargo audit` against every push to `main`.

The Homebrew formula at `AperionAI/homebrew-tap` references the
GitHub-Release binaries by their published `sha256` hashes.

We do not currently sign binaries with Sigstore / cosign. That's
on the v0.7 roadmap. Until then, the chain of integrity is
GitHub's HTTPS to the release CDN plus the per-binary `sha256`.

---

## 6. Hardening recommendations for operators

If you operate Shield as part of an enterprise deployment:

- **Run from a vanilla repo root**, not from `$HOME`. The workspace
  probe escalates severity in prod-shaped directories; running from
  `$HOME` either over-fires (false positives) or under-fires
  (your home directory isn't prod). The IDE / agent should `cd`
  into the project root before launching Shield.
- **Pin the binary by `sha256`**, not by `latest`. Each
  GitHub Release publishes hashes; verify before installing in CI.
- **Use `--auto-deny-high`** in unattended / batch environments
  where there's no human to approve.
- **Enable org-mode (`--enroll`)** if you want central policy
  versioning, audit shipping, and a fleet killswitch. See
  [`README.md`](README.md#org-mode-new-in-v05).
- **Audit `~/.aperion-shield/`** periodically. The proof cache,
  decision memory, and orgmode vkey are all there at mode `0600`.
- **Treat shieldset.yaml changes like code**. See
  [`docs/shieldset-as-code.md`](docs/shieldset-as-code.md) for the
  four-layer PR review pattern.

---

## 7. Changelog

| Date | Change |
|---|---|
| 2026-08-25 | v1.6.0. Linux Landlock backend for `--sandbox secrets` / `--sandbox strict` (helper `--internal-sandbox-exec`, then exec into the upstream; `strict` without `--sandbox-allow-network` is a hard fail if the kernel cannot deny TCP). Windows PATH shims (`aws.cmd` via PATHEXT). `--install-agent-hooks` covers Codex / Gemini CLI / Copilot CLI. TrustFall follow-through: install reports project-level hook files without modifying them; `--scan-ide` finding `scan.ide.project_hooks`. Supported-versions table: 1.6.x current, 1.5.x security-only. No new network endpoints. |
| 2026-08-25 | v1.5.0 shipped. Native Claude/Cursor PreToolUse hooks (`--check-hook`, `--install-agent-hooks`, fail-closed wrappers), `--scan-ide` (TrustFall project MCP + Skills ATR pass), `install.sh` for `shield-get.aperion.ai`. New §3 subsection "native agent hooks are user-level". Supported-versions table: 1.5.x current, 1.4.x security-only. No new network endpoints in the binary; the installer still only talks to GitHub Releases. |
| 2026-05-15 | Initial policy. Documents the three open Dependabot advisories surfaced by Shield's first public release and the v0.6.0 fix plan. |
| 2026-05-18 | v0.6.0 shipped. RUSTSEC-2026-0098 / -0099 / -0104 closed by `rustls-webpki 0.103.13` (transitively via the `reqwest 0.12` / `rustls 0.23` / `hyper 1.x` upgrade). `.cargo/audit.toml` ignore list trimmed back to `[]`. Supported-versions table updated. |
| 2026-05-20 | v0.7.0 shipped. No new advisories or fix-required changes; this is a feature-only release. `cargo audit` clean against `Cargo.lock` at the v0.7.0 commit. New surfaces (`--install-hooks`, `--check-staged`, `--check-pushed-refs`, `--suggest-rules`) all stay within the standalone process model — no new network endpoints, no new on-disk persistence beyond `.git/hooks/` (Shield itself) and the operator-redirected audit log. Supported-versions table updated; v0.6.x dropped to security-only. |
| 2026-07-03 | v1.2.1 shipped. Hardening for the v1.2 continuous drift-check probe, prompted by external feedback: dropped the `__shield_drift_`-prefixed request id (a static, greppable marker, given this project is open source) in favor of a bare random UUID, and added +/-20% jitter to the polling interval so the cadence isn't a clean periodic signal. New §3 subsection "Known limitation: drift-check probes are not unspoofable" documents what this does and does not close — a targeted adversary running statistical traffic analysis could still attempt evasion; that residual risk is inherent to any protocol-level monitor sharing a channel with the thing it doesn't trust, and `--sandbox` is the complementary control for that threat model. No CVE; not a regression, a hardening of a feature shipped hours earlier. |
| 2026-05-27 | v0.8.0 shipped. No new advisories or fix-required changes; this is a feature-only release. `cargo audit` clean against `Cargo.lock` at the v0.8.0 commit. New surfaces (`--install-shims`, `--uninstall-shims`, `--list-shims`, `--check-cmd`, `--explain`) all stay within the standalone process model. The shim path writes per-command `/bin/sh` wrappers into `~/.aperion-shield/bin/` (or `--shim-dir PATH`) at mode `0755` inside a directory at mode `0700`; **Shield will NOT overwrite any file it didn't write itself** (foreign-file collisions exit non-zero, file untouched). `--explain` is pure-input/pure-output — no on-disk persistence, no side-effects on decision memory or audit. Supported-versions table updated; v0.7.x dropped to security-only. |
| 2026-07-03 | v1.3.0 shipped. New feature: cross-tool secret taint tracking (`--taint-ttl-secs`, `--no-taint-tracking`, `--taint-list`, `--taint-flush`). Closes the OWASP MCP09 confused-deputy / cross-tool-relay gap that per-call, single-server guardrails structurally miss — a credential leaked by one tool being relayed into a different tool/server/surface. New on-disk persistence: `.aperion-shield/taint.jsonl`, a per-project append-only ledger storing **only a SHA-256 hash** of each observed credential-shaped value (never the raw secret) plus its entity kind and source tool/surface. No new network endpoints. New §3 subsection "Known limitation: cross-tool taint tracking is heuristic" documents the honest limits: hash-equality correlation only (transformed/re-encoded secrets evade), finite regex corpus, lock-free (fail-open) ledger, CWD-scoped — it raises the cost and visibility of a relay and forces a human decision, it is not an unbypassable exfiltration control; `--sandbox` remains the complementary process-level control. `cargo audit` clean against `Cargo.lock` at the v1.3.0 commit. |
