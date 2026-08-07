//! Observer Layer — trait, composite, and ecosystem inheritance.
//! Inherit evidence from Traci, Dreamseq, Jeenome, Kaptaind, Hellhound, Deliver.
//! See `docs/architecture.md`.

pub mod git;
pub mod system;

use crate::evidence::{ArtifactType, Observation};
use async_trait::async_trait;
use serde_json::json;

/// All observers implement this — collect returns Observations that will be
/// normalized into Evidence.
#[async_trait]
pub trait Observer: Send + Sync {
    fn name(&self) -> &str;
    async fn collect(&self) -> anyhow::Result<Vec<Observation>>;
}

/// Ecosystem observers — inherit evidence graph from existing tools.
pub mod ecosystem {
    use super::*;
    use std::path::Path;

    /// Traci: traceability evidence (observability enforcement)
    pub fn traci_observations(base: &Path) -> Vec<Observation> {
        let mut out = Vec::new();
        // Look for .traci/state.json or traci reports
        for candidate in [base.join(".traci"), base.join("target/traci")] {
            if candidate.exists() {
                out.push(Observation::new(
                    "traci",
                    ArtifactType::TraciTrace,
                    json!({"path": candidate.to_string_lossy(), "kind": "traceability"}),
                ));
            }
        }
        // Also check if traci binary output directory exists as evidence
        out
    }

    /// Dreamseq: semantic operational histories
    pub fn dreamseq_observations(base: &Path) -> Vec<Observation> {
        let mut out = Vec::new();
        for candidate in [
            base.join(".dreamseq"),
            base.join("dreamseq.toml"),
            dirs::home_dir()
                .unwrap_or_else(|| Path::new(".").to_path_buf())
                .join(".dreamseq"),
        ] {
            if candidate.exists() {
                out.push(Observation::new(
                    "dreamseq",
                    ArtifactType::DreamseqHistory,
                    json!({"path": candidate.to_string_lossy(), "kind": "semantic_history"}),
                ));
            }
        }
        out
    }

    /// Jeenome: system-level behavioural evidence (strace)
    pub fn jeenome_observations(base: &Path) -> Vec<Observation> {
        let mut out = Vec::new();
        let candidate = base.join(".jeenome");
        if candidate.exists() {
            out.push(Observation::new(
                "jeenome",
                ArtifactType::JeenomeBehaviour,
                json!({"path": candidate.to_string_lossy(), "kind": "behaviour"}),
            ));
        }
        out
    }

    /// Kaptaind: version and release governance
    pub fn kaptaind_observations(base: &Path) -> Vec<Observation> {
        let mut out = Vec::new();
        for candidate in [
            base.join("kaptaind.toml"),
            base.join(".kaptaind"),
            base.join("VERSION"),
        ] {
            if candidate.exists() {
                let content = std::fs::read_to_string(&candidate).unwrap_or_default();
                out.push(Observation::new(
                    "kaptaind",
                    ArtifactType::KaptaindRelease,
                    json!({"path": candidate.to_string_lossy(), "content_preview": content.chars().take(200).collect::<String>()}),
                ));
            }
        }
        out
    }

    /// Hellhound: daemon and service health
    pub fn hellhound_observations(base: &Path) -> Vec<Observation> {
        let mut out = Vec::new();
        for candidate in [base.join(".hellhound"), base.join("hellhound.toml")] {
            if candidate.exists() {
                out.push(Observation::new(
                    "hellhound",
                    ArtifactType::HellhoundHealth,
                    json!({"path": candidate.to_string_lossy(), "kind": "daemon_health"}),
                ));
            }
        }
        out
    }

    /// Deliver: milestone evidence verification
    pub fn deliver_observations(base: &Path) -> Vec<Observation> {
        let mut out = Vec::new();
        for candidate in [base.join("deliver.toml"), base.join("deliver.json")] {
            if candidate.exists() {
                out.push(Observation::new(
                    "deliver",
                    ArtifactType::DeliverMilestone,
                    json!({"path": candidate.to_string_lossy(), "kind": "milestone"}),
                ));
            }
        }
        out
    }

    pub fn all(base: &Path) -> Vec<Observation> {
        let mut v = Vec::new();
        v.extend(traci_observations(base));
        v.extend(dreamseq_observations(base));
        v.extend(jeenome_observations(base));
        v.extend(kaptaind_observations(base));
        v.extend(hellhound_observations(base));
        v.extend(deliver_observations(base));
        v
    }
}

/// Combined observer that fans out to all configured sources.
pub struct CompositeObserver {
    pub base_path: std::path::PathBuf,
    pub observers: Vec<Box<dyn Observer>>,
}

impl CompositeObserver {
    pub fn new(base_path: std::path::PathBuf) -> Self {
        Self {
            base_path,
            observers: Vec::new(),
        }
    }

    pub fn with_defaults(mut self) -> Self {
        self.observers.push(Box::new(git::GitObserver {
            path: self.base_path.clone(),
        }));
        self.observers.push(Box::new(system::SystemObserver));
        self
    }
}

#[async_trait]
impl Observer for CompositeObserver {
    fn name(&self) -> &str {
        "composite"
    }

    async fn collect(&self) -> anyhow::Result<Vec<Observation>> {
        let mut all = Vec::new();
        // Ecosystem (sync)
        all.extend(ecosystem::all(&self.base_path));
        // Async observers
        for o in &self.observers {
            match o.collect().await {
                Ok(mut v) => all.append(&mut v),
                Err(e) => tracing::warn!(observer = o.name(), error = %e, "observer failed"),
            }
        }
        Ok(all)
    }
}
