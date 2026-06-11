//! Aperion Shield -- library surface.
//!
//! This crate exposes the rule engine and its adaptive layers so that:
//!
//!   * the `aperion-shield` binary in `src/main.rs` can wire them into
//!     an MCP stdio guardrail, and
//!   * integration tests in `tests/` can exercise the engine end-to-end
//!     without spawning a process, and
//!   * embedders who want to drop Shield into a non-MCP context (custom
//!     proxies, lint tools, etc.) can do so without re-implementing the
//!     decision pipeline.
//!
//! The public API is intentionally small. The main types you'll touch:
//!
//!   * [`Engine`] -- load a `shieldset.yaml` and evaluate calls.
//!   * [`Adjustments`] -- adaptive inputs (prod workspace, memory, burst).
//!   * [`Evaluation`] -- what fired, what scored, what tier we landed on.
//!   * [`decide`] -- turn an [`Evaluation`] into a concrete [`Decision`].
//!   * [`WorkspaceContext`], [`DecisionMemory`], [`BurstDetector`] --
//!     the three adaptive helpers, each independently constructable.

pub mod burst;
pub mod context;
pub mod diff;
pub mod engine;
pub mod explain;
pub mod hooks;
pub mod identity;
pub mod memory;
pub mod orgmode;
pub mod predicates;
pub mod sandbox;
pub mod shims;
pub mod suggest;
pub mod supply;
pub mod transport;

pub use burst::BurstDetector;
pub use context::WorkspaceContext;
pub use engine::{
    decide, fingerprint, Adjustments, Decision, Engine, Evaluation, MatchInfo, Policy, Severity,
};
pub use identity::{
    IdentityConfig, IdentityGate, IdentityProvider, IdMeProvider, MockProvider, Proof,
    ProviderConfig, ProviderKind, Requirement as IdentityRequirement,
};
pub use memory::{DecisionMemory, MemoryEntry, MemoryVerdict, Outcome};
pub use predicates::{CommandPredicate, SensitivePath};
