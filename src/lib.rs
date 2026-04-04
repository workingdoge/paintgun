//! Paintgun: DTCG 2025.10 resolver compiler + composability certificate.
//!
//! Design goals:
//! - Spec-compliant resolution semantics (Resolver Module): LWW + resolutionOrder
//! - Typed IR (Res) with structured DTCG values (no CSS strings in core)
//! - Target-agnostic analysis: Kan completion + Beck–Chevalley witnesses
//! - Target-specific emission via `Emitter` trait

pub mod allowlist;
pub mod analysis;
pub mod annotations;
pub mod artifact;
pub mod backend;
pub mod cert;
pub mod compose;
pub mod contexts;
pub use premath_dsl as dsl;
pub mod diagnostics;
pub mod dtcg;
pub mod emit;
pub mod explain;
pub(crate) mod finding_presentation;
pub mod gate;
pub mod ids;
pub use premath_kcir::kcir_v2;
pub mod pack_identity;
pub mod path_safety;
pub mod pipeline;
pub mod policy;
pub mod provenance;
pub mod resolver;
pub(crate) mod resolver_io;
pub(crate) mod resolver_runtime;
pub mod signing;
pub mod util;
pub mod verify;
pub(crate) mod web_css;
