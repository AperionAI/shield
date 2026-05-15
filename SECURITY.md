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
| `0.5.x` | current stable | yes |
| `< 0.5` | superseded   | no |

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

### As of 2026-05-15

GitHub Dependabot has surfaced **three open advisories** against a
single transitive dependency, `rustls-webpki 0.101.7`. All three were
published 2026-04-14 → 2026-04-22 by the rustls maintainers. They
showed up against Shield's repository within hours of our first
public release because Dependabot scans every public repo's
`Cargo.lock` on push.

We have analyzed each advisory against Shield's actual usage of
the affected crate and concluded that **none of the three is
practically exploitable in Shield's default configuration**. The fix
is nonetheless scheduled for **v0.6.0 on Monday 2026-05-18** — see
§4.4 below for the upgrade plan.

#### 4.1 [RUSTSEC-2026-0104](https://rustsec.org/advisories/RUSTSEC-2026-0104.html) — `rustls-webpki`: reachable panic on malformed CRL BIT STRING

- **Severity (GitHub):** High
- **Triggering condition (from the advisory):** *"Applications that
  do not use CRLs are not affected."*
- **Does this affect aperion-shield?** **No.** Shield does not use
  Certificate Revocation Lists. The default rustls configuration
  used by `reqwest` does not perform CRL checking, and we do not
  call either `BorrowedCertRevocationList::from_der` or
  `OwnedCertRevocationList::from_der`. There is no code path in
  Shield that parses a CRL.

#### 4.2 [RUSTSEC-2026-0098](https://rustsec.org/advisories/RUSTSEC-2026-0098.html) — `rustls-webpki`: URI name constraints incorrectly accepted

- **Severity (GitHub):** Low
- **Triggering condition (from the advisory):** *"This bug is
  reachable only after signature verification and requires
  misissuance to exploit."*
- **Does this affect aperion-shield?** **In practice, no.** The
  exploit requires a certificate authority in the OS trust store
  to misissue a certificate with malformed URI name constraints.
  If that condition is true, every TLS-using application on your
  machine is at risk — not just Shield. We rely on the system
  trust store and rustls' standard chain validation; we do not
  add or remove CAs. The advisory itself notes the library does
  not currently expose an API for asserting URI names, which makes
  the practical exploit surface narrow.

#### 4.3 [RUSTSEC-2026-0099](https://rustsec.org/advisories/RUSTSEC-2026-0099.html) — `rustls-webpki`: wildcard names accepted under name constraints

- **Severity (GitHub):** Low
- **Triggering condition (from the advisory):** *"requires
  misissuance to exploit."*
- **Does this affect aperion-shield?** **In practice, no.** Same
  reasoning as §4.2. The exploit requires a misissued certificate
  in the chain to a CA your machine already trusts.

### 4.4 Why we are not yanking v0.5.0

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

### 4.5 Fix plan: v0.6.0 on Monday 2026-05-18

All three advisories are fixed by `rustls-webpki >= 0.103.13`. That
version requires `rustls 0.23.x`, which in turn requires
`reqwest 0.12.x`, which in turn aligns naturally with `hyper 1.x`.
The dependency-graph upgrade is therefore a connected change of:

- `reqwest`        `0.11.27` → `0.12.x`
- `rustls`         `0.21.12` → `0.23.x`
- `rustls-webpki`  `0.101.7` → `0.103.13+` (closes all three advisories)
- `hyper-rustls`   `0.24.2`  → newer compatible release
- `hyper`          `0.14.x`  → `1.x` (modest API refactor in
  `src/identity/server.rs`, our OIDC callback server)

This upgrade is scheduled for **`shield-v0.6.0`, releasing Monday
2026-05-18**, alongside the v0.6 native `aperion-shield --diff` mode
(see [`docs/shieldset-as-code.md`](docs/shieldset-as-code.md)).

When v0.6.0 lands:

1. `Cargo.lock` no longer references `rustls-webpki 0.101.7`.
2. GitHub Dependabot auto-closes all three advisories within minutes.
3. `cargo audit` against the v0.6.0 `Cargo.lock` returns clean.
4. The updated `.cargo/audit.toml` (in this repo) drops the three
   ignored advisory IDs once the underlying advisory text no longer
   applies to our `Cargo.lock`.

If a verified exploit path is discovered against Shield's actual
configuration before 2026-05-18, we will accelerate the release.

---

## 5. Supply-chain provenance

Every release on GitHub ships:

- A `sha256` digest file alongside each binary archive (computed at
  build time on GitHub-hosted runners).
- A multi-arch Docker image at `ghcr.io/aperionai/shield` with
  build-attestation provenance (`linux/amd64` + `linux/arm64`).
- Source available at the tag (`shield-v0.5.0`, `shield-v0.6.0`, ...)
  with the full build history.

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
| 2026-05-15 | Initial policy. Documents the three open Dependabot advisories surfaced by Shield's first public release and the v0.6.0 fix plan. |
