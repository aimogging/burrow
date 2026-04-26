//! Build/deploy orchestration. Wraps the existing low-level pieces
//! (`config_gen`, `cargo` itself) behind a single TOML-spec-driven CLI
//! (`burrowctl`) so the operator picks every setting exactly once.
//!
//! Phase 1: `gen` (configs + cert + token) and `build` (cargo, with the
//! `BURROW_*_EMBED_*` env vars set internally). `ship` / `up` / `down`
//! land later — see `~/.claude/plans/zzz-i-hate-the-enchanted-cerf.md`.

pub mod build;
pub mod exec;
pub mod gen;
pub mod init;
pub mod ship;
