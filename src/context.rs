//! Workspace context probe — runs once at startup and reports whether
//! the current working directory looks like a production-managed repo.
//! When it does, the engine bumps every matched rule's severity by one
//! tier. The signals are deliberately conservative: only files that
//! strongly imply "this codebase manages production".
//!
//! Cheap by design — does not recurse, does not stat outside the cwd
//! root, returns in a millisecond. Designed to run on every Shield
//! launch with zero perceptible cost.

use std::path::{Path, PathBuf};

use crate::engine::Policy;

#[derive(Debug, Clone)]
pub struct WorkspaceContext {
    pub root: PathBuf,
    pub is_prod: bool,
    pub matched_signals: Vec<String>,
}

impl WorkspaceContext {
    /// Probe the cwd against the policy's prod_signals.
    pub fn probe(policy: &Policy) -> Self {
        let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::probe_at(policy, &root)
    }

    /// Probe an arbitrary root directory. Exists primarily for tests —
    /// the production code path goes through `probe()`, which is the
    /// single-arg convenience wrapper.
    pub fn probe_at(policy: &Policy, root: &Path) -> Self {
        let root = root.to_path_buf();
        if !policy.workspace_probe.enabled {
            return Self { root, is_prod: false, matched_signals: vec![] };
        }
        let mut matched = Vec::new();
        for sig in &policy.workspace_probe.prod_signals {
            if signal_present(&root, sig) {
                matched.push(sig.clone());
            }
        }
        let is_prod = !matched.is_empty();
        Self { root, is_prod, matched_signals: matched }
    }
}

fn signal_present(root: &Path, signal: &str) -> bool {
    if let Some(dir) = signal.strip_suffix('/') {
        let p = root.join(dir);
        return p.is_dir();
    }
    // Bare filename — checked at cwd and one level under common
    // configuration dirs (config/, deploy/, ops/). One level is enough
    // to catch nested production manifests without unbounded recursion.
    if root.join(signal).exists() {
        return true;
    }
    for sub in ["config", "deploy", "ops", "infra"] {
        if root.join(sub).join(signal).exists() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::WorkspaceProbeCfg;
    use std::fs;
    use tempfile::TempDir;

    fn policy_with_signals(signals: &[&str]) -> Policy {
        let mut p = Policy::default();
        p.workspace_probe = WorkspaceProbeCfg {
            enabled: true,
            prod_signals: signals.iter().map(|s| s.to_string()).collect(),
            severity_bump: 1,
        };
        p
    }

    #[test]
    fn no_signals_means_not_prod() {
        let tmp = TempDir::new().unwrap();
        let ctx = WorkspaceContext::probe_at(
            &policy_with_signals(&[".env.production", "prod/"]),
            tmp.path(),
        );
        assert!(!ctx.is_prod);
        assert!(ctx.matched_signals.is_empty());
    }

    #[test]
    fn file_signal_at_cwd_root() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join(".env.production"), "DB=prod").unwrap();
        let ctx = WorkspaceContext::probe_at(
            &policy_with_signals(&[".env.production"]),
            tmp.path(),
        );
        assert!(ctx.is_prod);
        assert_eq!(ctx.matched_signals, vec![".env.production".to_string()]);
    }

    #[test]
    fn dir_signal() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("prod")).unwrap();
        let ctx = WorkspaceContext::probe_at(&policy_with_signals(&["prod/"]), tmp.path());
        assert!(ctx.is_prod);
    }

    #[test]
    fn nested_config_dir() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("config")).unwrap();
        fs::write(tmp.path().join("config").join("production.yml"), "x: 1").unwrap();
        let ctx = WorkspaceContext::probe_at(&policy_with_signals(&["production.yml"]), tmp.path());
        assert!(ctx.is_prod);
    }

    #[test]
    fn disabled_probe_short_circuits() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join(".env.production"), "x").unwrap();
        let mut p = policy_with_signals(&[".env.production"]);
        p.workspace_probe.enabled = false;
        let ctx = WorkspaceContext::probe_at(&p, tmp.path());
        assert!(!ctx.is_prod);
    }
}
