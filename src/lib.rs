// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Isopod — compliance nervous system.
//!
//! Isopod transforms compliance from a periodic audit into a continuously
//! observable engineering property. It collects tamper-evident evidence,
//! evaluates declarative controls, detects drift, and produces remediation
//! guidance with confidence scores.
//!
//! # Principles
//! - **Evidence over assertions** — every claim maps to a control, artifact,
//!   timestamp, hash, confidence, and remediation.
//! - **Continuous** — daemon, not scanner. Posture updates as system state changes.
//! - **Inherit, don't rediscover** — governance layer above Traci, Dreamseq,
//!   Jeenome, Kaptaind, Hellhound, and Deliver.
//!
//! # Quick start
//! ```bash
//! isopod init
//! isopod status              # stylised dashboard
//! isopod status --json       # machine-readable
//! isopod evidence --limit 20
//! isopod export ./audit
//! ```
//!
//! # Architecture
//! Observer → Evidence Engine → Control Engine → Drift Detection → Remediation
//! See `docs/architecture.md` for the full pipeline.
//!
//! # Storage
//! `~/.isopod/` holds `evidence/{hashes,artifacts}`, `controls/*.yaml`,
//! `state.db` (SQLite), and `reports/`. All evidence is SHA-256 hashed with
//! sidecar files for tamper detection.

pub mod api;
pub mod config;
pub mod control;
pub mod daemon;
pub mod discover;
pub mod drift;
pub mod evidence;
pub mod isopod_d;
pub mod maintain;
pub mod observer;
pub mod project;
pub mod provision;
pub mod prune;
pub mod remediation;
pub mod runtime;
pub mod store;
pub mod style;
pub mod web_assurance;
pub mod webhook;

pub use config::Config;
pub use control::{Control, ControlResult, ControlSet, ControlStatus};
pub use evidence::{ArtifactType, Evidence, EvidenceStore};
pub use store::Store;

/// Crate version from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
