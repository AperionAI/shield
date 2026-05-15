//! Concrete `IdentityProvider` implementations.
//!
//! Today:
//!   * [`mock::MockProvider`] -- always verifies. Used by tests, demos,
//!     and any environment where ID.me credentials aren't available.
//!   * [`idme::IdMeProvider`] -- ID.me OAuth 2.0 + PKCE flow. Wired and
//!     ready; activates the moment we receive sandbox credentials.

pub mod idme;
pub mod mock;
