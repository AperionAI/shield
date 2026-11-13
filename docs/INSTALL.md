# Installing Shield

Artifacts are public. Three channels; pick one.

```bash
curl -fsSL https://shield-get.aperion.ai | sh
```

Downloads the matching GitHub Release tarball, verifies SHA-256, and drops
`aperion-shield` onto PATH. Pin a version or relocate:

```bash
SHIELD_VERSION=shield-v1.27.1 SHIELD_INSTALL_DIR=~/.local/bin \
  curl -fsSL https://shield-get.aperion.ai | sh
```

Fallback if the hostname is down:

```bash
curl -fsSL https://raw.githubusercontent.com/AperionAI/shield/main/install.sh | sh
```

Then wire native agent hooks (the v1.5 table-stakes path — Cursor Bash/Write
do not go through `$PATH` shims):

```bash
aperion-shield --install-agent-hooks
aperion-shield --scan-ide
```

Enroll writes the Claude Desktop gateway file for that user. Quit Claude Desktop and open it again after enroll. The terminal `claude` command still uses the managed settings below.

Org laptops, after enroll, as root:

```bash
sudo aperion-shield --claude-managed-settings --managed-settings-out default
sudo aperion-shield --cursor-managed-hooks --managed-settings-out default
sudo aperion-shield --codex-managed-requirements --managed-settings-out default
```

Someone who pays for their own Claude plan (Pro, Max, Team) can keep using it through the gateway. This writes the same managed settings without the Smartflow key, so Claude Code keeps their own login. The gateway knows the laptop from its device certificate, logs every call and runs policy on it, but doesn't charge it to a spend cap.

```bash
sudo aperion-shield --claude-own-subscription
claude /login   # once, with the person's own Claude account
```

Run `--claude-managed-settings` again to switch back to the org key.

Other channels: `brew install AperionAI/tap/aperion-shield`, Docker
`ghcr.io/aperionai/shield:latest`, or `cargo install aperion-shield`.

Windows: grab the `.zip` from [Releases](https://github.com/AperionAI/shield/releases).

---

## Operator setup (one-time) — `shield-get.aperion.ai`

Copy the Halo pattern. `halo-get.aperion.ai` is a Cloudflare hostname that 302s
to `raw.githubusercontent.com/AperionAI/halo-dist/main/install.sh`.

1. In Cloudflare DNS for `aperion.ai`, add **CNAME** `shield-get` → the same
   proxied target as `halo-get` (or `aperion.ai` with a dedicated redirect).
2. Bulk Redirect / Redirect Rule:
   - hostname `shield-get.aperion.ai`
   - destination `https://raw.githubusercontent.com/AperionAI/shield/main/install.sh`
   - 302, preserve query string off
3. After the first `shield-v1.5.0` GitHub Release exists, smoke:

```bash
curl -fsSL https://shield-get.aperion.ai | sh
aperion-shield --version
```
