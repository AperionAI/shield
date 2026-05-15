//! `aperion-shield enroll` / `status` / `disenroll` subcommand handlers.
//!
//! Each is a small CLI helper. The actual long-lived org-mode tasks
//! (heartbeat, policy pull, audit sink) are started elsewhere from
//! `main.rs` when an enrollment record is present.

use anyhow::{anyhow, Context};

use super::client::{OrgApi, TokenEnrollResponse};
use super::state::OrgState;

/// Run `aperion-shield enroll`.
///
/// Args mirror the dashboard's "issue enrollment token" form:
///   * `smartflow_url` -- base URL of the smartflow control plane
///   * `token` -- the one-time enrollment token (printed in the
///     dashboard)
///   * `device_name` -- optional friendly name; defaults to hostname
///   * `user_email` -- optional; appears in audit rows + fleet view
pub async fn run_enroll(
    smartflow_url: &str,
    token: &str,
    device_name: Option<&str>,
    user_email: Option<&str>,
) -> anyhow::Result<()> {
    if smartflow_url.is_empty() {
        return Err(anyhow!(
            "--smartflow-url is required (e.g. https://smartflow.example.com)"
        ));
    }
    if token.is_empty() {
        return Err(anyhow!(
            "enrollment token is empty; ask your admin to issue one from the dashboard"
        ));
    }

    let fingerprint = OrgState::fingerprint();
    let name = device_name
        .map(|s| s.to_string())
        .unwrap_or_else(default_device_name);
    let platform = current_platform();

    eprintln!(
        "[shield] enrolling against {} (platform={}, device_name={})",
        smartflow_url, platform, name
    );

    let resp: TokenEnrollResponse = OrgApi::token_enroll(
        smartflow_url,
        token,
        &fingerprint,
        &name,
        &platform,
        user_email,
    )
    .await
    .context("token-enroll request failed")?;

    let state = OrgState {
        smartflow_url: smartflow_url.trim_end_matches('/').to_string(),
        vkey: resp.vkey.clone(),
        device_id: resp.device_id.clone(),
        policy_group: resp.policy_group.clone(),
        owner_email: user_email.map(|s| s.to_string()),
        enrolled_at: chrono::Utc::now().to_rfc3339(),
        platform,
        device_name: name,
        device_fingerprint: fingerprint,
    };
    state.save().context("save orgmode.json")?;

    eprintln!("[shield] enrolled successfully");
    eprintln!("[shield]   device_id    = {}", resp.device_id);
    eprintln!("[shield]   policy_group = {}", resp.policy_group);
    eprintln!("[shield]   vkey         = {}*** (stored at ~/.aperion-shield/orgmode.json)",
        &resp.vkey[..resp.vkey.len().min(12)]);
    eprintln!("[shield]");
    eprintln!("[shield] next run of `aperion-shield -- <mcp-server>` will pull policy from {}",
        smartflow_url);
    Ok(())
}

/// Run `aperion-shield status`. Prints the current enrollment record
/// and probes the smartflow control plane for liveness + current
/// policy version.
pub async fn run_status() -> anyhow::Result<()> {
    let state = match OrgState::load()? {
        Some(s) => s,
        None => {
            println!("aperion-shield is NOT enrolled (running standalone).");
            println!();
            println!("To enroll, ask your Smartflow admin for a one-time token, then:");
            println!("  aperion-shield --enroll --smartflow-url <url> --token <token>");
            return Ok(());
        }
    };

    println!("aperion-shield enrollment");
    println!("  smartflow_url    = {}", state.smartflow_url);
    println!("  device_id        = {}", state.device_id);
    println!("  device_name      = {}", state.device_name);
    println!("  policy_group     = {}", state.policy_group);
    println!("  owner_email      = {}",
        state.owner_email.clone().unwrap_or_else(|| "<none>".into()));
    println!("  enrolled_at      = {}", state.enrolled_at);
    println!("  platform         = {}", state.platform);
    println!("  device_fingerprint = {}", state.device_fingerprint);
    println!();

    let api = OrgApi::from_state(&state);
    match api.info().await {
        Ok(info) => {
            println!("smartflow control plane is reachable.");
            println!("  policy_version   = {}", info.policy_version);
            println!("  killswitch.on    = {}", info.killswitch.on);
            if let Some(r) = &info.killswitch.reason {
                println!("  killswitch.reason= {}", r);
            }
            println!("  server_time      = {}", info.server_time);
            println!("  identity_providers ({}):", info.identity_providers.len());
            for p in &info.identity_providers {
                println!(
                    "    - {:<8} {:<10} ready={} ({})",
                    p.id, p.kind, p.ready, p.display_name
                );
            }
        }
        Err(e) => {
            println!("smartflow control plane: UNREACHABLE ({})", e);
        }
    }
    Ok(())
}

/// Run `aperion-shield disenroll`. Just deletes the local record;
/// the dashboard `DELETE /api/enterprise/devices/{id}` revokes the
/// vkey server-side. Optionally calls that endpoint if the caller
/// passes `--revoke`.
pub async fn run_disenroll(revoke: bool) -> anyhow::Result<()> {
    let state = match OrgState::load()? {
        Some(s) => s,
        None => {
            println!("aperion-shield is not enrolled. Nothing to do.");
            return Ok(());
        }
    };

    if revoke {
        let api = OrgApi::from_state(&state);
        // Use reqwest directly here since there's no DELETE wrapper
        // for the convenience method.
        let client = reqwest::Client::new();
        let url = format!(
            "{}/api/enterprise/devices/{}",
            state.smartflow_url.trim_end_matches('/'),
            state.device_id
        );
        let resp = client
            .delete(&url)
            .bearer_auth(&state.vkey)
            .send()
            .await
            .context("revoke request failed")?;
        if !resp.status().is_success() {
            eprintln!(
                "[shield] revoke returned HTTP {}; the local record will still be removed",
                resp.status()
            );
        } else {
            eprintln!("[shield] device revoked server-side");
        }
        // Keep `api` alive across the await -- silence unused warning.
        let _ = api;
    }
    OrgState::remove()?;
    println!("aperion-shield disenrolled (local record removed).");
    Ok(())
}

fn current_platform() -> String {
    match std::env::consts::OS {
        "macos" => "macos".to_string(),
        "linux" => "linux".to_string(),
        "windows" => "windows".to_string(),
        other => other.to_string(),
    }
}

fn default_device_name() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "shield-host".to_string());
    format!("{}-shield", host)
}
