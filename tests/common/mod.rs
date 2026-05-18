//! Shared test infrastructure for ContextCrawler integration suites.
//!
//! Tracked by issue #48: prior to this module each `secure_*_tests`-style
//! suite spawned the real binary with mutated env vars (via either
//! `Command::env(...)` or, in some unit tests under `src/`,
//! `std::env::set_var`). When the suites ran in parallel — the cargo
//! default — there was no coordination, so a future test that touched
//! parent-process env would race with the others.
//!
//! Rather than re-add a private `static LOCK` per suite (the pre-#48
//! pattern, duplicated across `src/`), every env-mutating integration
//! test takes a guard from [`env_lock`]. The lock serializes ONLY the
//! tests that opt in; the rest of the suite still runs in parallel.
//!
//! Usage:
//!
//! ```ignore
//! mod common;
//!
//! #[test]
//! fn my_env_sensitive_test() {
//!     let _g = common::env_lock();
//!     // ... spawn child with mutated env, assert, drop guard at end of scope.
//! }
//! ```
//!
//! The guard MUST be bound to a named local (`let _g = ...`, NOT
//! `let _ = ...`) so it is held for the entire test body. `let _ = ...`
//! drops the guard immediately and defeats the lock.

use std::sync::{Mutex, MutexGuard};

/// Process-wide lock acquired by any integration test that mutates env
/// (parent-process env directly, or via `Command::env*` where multiple
/// tests share filesystem state the child reads). Held across the spawn
/// + assertion phase of each test.
///
/// `Mutex::new` is const since Rust 1.63, so no `lazy_static` /
/// `OnceLock` ceremony is required.
pub static GLOBAL_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Acquire [`GLOBAL_ENV_LOCK`], recovering from poisoning so that a
/// panicking test in one suite does not cascade-fail every subsequent
/// test that also takes the lock. We don't read the protected value
/// (it's `()`), so a previously-poisoned guard is safe to reuse.
#[allow(dead_code)] // not every suite imports this helper; that's fine.
pub fn env_lock() -> MutexGuard<'static, ()> {
    match GLOBAL_ENV_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}
