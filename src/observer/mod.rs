// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
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

/// Factory function for creating an observer rooted at a base path.
pub type ObserverFactory = Box<dyn Fn(&std::path::Path) -> Box<dyn Observer> + Send + Sync>;

/// Registry of named observer factories. Allows runtime extension of the
/// observation layer without modifying the daemon.
#[derive(Default)]
pub struct ObserverRegistry {
    factories: Vec<(String, ObserverFactory)>,
}

impl ObserverRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a factory under a human-readable name.
    pub fn register<F>(&mut self, name: impl Into<String>, factory: F)
    where
        F: Fn(&std::path::Path) -> Box<dyn Observer> + Send + Sync + 'static,
    {
        self.factories.push((name.into(), Box::new(factory)));
    }

    /// List registered observer names.
    pub fn list(&self) -> Vec<&str> {
        self.factories.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// Build a composite observer from all registered factories.
    pub fn build(&self, base_path: &std::path::Path) -> CompositeObserver {
        let mut composite = CompositeObserver::new(base_path.to_path_buf());
        for (name, factory) in &self.factories {
            let observer = factory(base_path);
            tracing::debug!(observer = %name, "registered observer from registry");
            composite.observers.push(observer);
        }
        composite
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

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyObserver;

    #[async_trait]
    impl Observer for DummyObserver {
        fn name(&self) -> &str {
            "dummy"
        }
        async fn collect(&self) -> anyhow::Result<Vec<Observation>> {
            Ok(vec![])
        }
    }

    #[test]
    fn registry_lists_registered_observers() {
        let mut registry = ObserverRegistry::new();
        registry.register("dummy", |_path| Box::new(DummyObserver));
        assert_eq!(registry.list(), vec!["dummy"]);
    }

    struct FailingObserver;

    #[async_trait]
    impl Observer for FailingObserver {
        fn name(&self) -> &str {
            "failing"
        }
        async fn collect(&self) -> anyhow::Result<Vec<Observation>> {
            anyhow::bail!("expected")
        }
    }

    #[test]
    fn ecosystem_discovers_every_supported_local_signal() {
        let dir = tempfile::tempdir().unwrap();
        for path in [".traci", ".dreamseq", ".jeenome", ".kaptaind", ".hellhound"] {
            std::fs::create_dir_all(dir.path().join(path)).unwrap();
        }
        for file in ["kaptaind.toml", "VERSION", "hellhound.toml", "deliver.toml"] {
            std::fs::write(dir.path().join(file), "evidence").unwrap();
        }
        let observations = ecosystem::all(dir.path());
        let sources = observations
            .iter()
            .map(|o| o.source.as_str())
            .collect::<Vec<_>>();
        for expected in [
            "traci",
            "dreamseq",
            "jeenome",
            "kaptaind",
            "hellhound",
            "deliver",
        ] {
            assert!(sources.contains(&expected), "missing {expected}");
        }
    }

    #[tokio::test]
    async fn registry_build_and_composite_tolerate_failed_observers() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = ObserverRegistry::new();
        registry.register("dummy", |_| Box::new(DummyObserver));
        registry.register("failing", |_| Box::new(FailingObserver));
        let composite = registry.build(dir.path());
        assert_eq!(composite.name(), "composite");
        assert!(composite.collect().await.unwrap().is_empty());
    }

    #[test]
    fn defaults_register_git_and_system_observers() {
        let composite = CompositeObserver::new(std::path::PathBuf::from(".")).with_defaults();
        assert_eq!(composite.observers.len(), 2);
    }
}
