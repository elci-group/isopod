// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Daemon — single `tick` evaluation and `run_forever` loop.
//! See `docs/architecture.md` and `docs/operations.md`.

use crate::config::Config;
use crate::control::ControlSet;
use crate::evidence::Evidence;
use crate::observer::{CompositeObserver, Observer};
use crate::store::Store;
use anyhow::Context;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

pub struct Daemon {
    pub config: Config,
    pub store: Arc<Store>,
    pub controls: ControlSet,
}

impl Daemon {
    pub fn new(config: Config, store: Arc<Store>) -> Self {
        let controls = ControlSet::load_dir_self_healing(&config.controls_dir);
        Self {
            config,
            store,
            controls,
        }
    }

    /// Single evaluation cycle: collect -> normalize -> evaluate -> drift -> persist
    pub async fn tick(
        &self,
        base_path: &std::path::Path,
    ) -> anyhow::Result<Vec<crate::control::ControlResult>> {
        info!(base_path = %base_path.display(), "collecting compliance observations");
        let observer = CompositeObserver::new(base_path.to_path_buf()).with_defaults();
        let observations = observer
            .collect()
            .await
            .context("collect compliance observations")?;
        info!(
            observation_count = observations.len(),
            "collected compliance observations"
        );

        // Normalize to Evidence
        let mut evidence_by_control: std::collections::HashMap<String, Vec<Evidence>> =
            std::collections::HashMap::new();
        let mut all_evidence = Vec::new();

        for obs in observations {
            // Data-driven control mapping
            let control_ids = map_observation_to_controls(&obs, &self.controls);
            let confidence = obs
                .confidence_hint
                .unwrap_or_else(|| obs.score_confidence());
            let mut ev = obs.into_evidence(confidence);
            // Deduplicate by content hash
            match self.store.has_evidence_with_hash(&ev.content_hash) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => warn!(error = %e, "failed to check evidence hash"),
            }
            // Attach the first control for provenance linking; all mapped controls share the evidence
            let primary_control = control_ids.first().cloned();
            match self
                .store
                .latest_evidence_for_control_source(primary_control.as_deref(), &ev.source)
            {
                Ok(Some(prev)) => ev.previous_id = Some(prev.id),
                Ok(None) => {}
                Err(e) => warn!(error = %e, "failed to find previous evidence"),
            }
            for cid in &control_ids {
                let mapped = ev.clone().with_control(cid.clone());
                evidence_by_control
                    .entry(cid.clone())
                    .or_default()
                    .push(mapped);
            }
            // Tag the persisted record with the primary mapped control, if any.
            if let Some(ref cid) = primary_control {
                ev.control_id = Some(cid.clone());
            }
            // write artifact file for offline verification
            let artifact_rel = format!("artifacts/{}.json", ev.id);
            let artifact_path = self.config.evidence_dir.join(&artifact_rel);
            std::fs::write(&artifact_path, ev.metadata.to_string())
                .with_context(|| format!("write evidence artifact {}", artifact_path.display()))?;
            ev.artifact_path = Some(artifact_rel.clone());
            // persist
            self.store
                .insert_evidence(&ev)
                .with_context(|| format!("persist evidence {}", ev.id))?;
            let hash_path = self
                .config
                .evidence_dir
                .join("hashes")
                .join(format!("{}.sha256", ev.id));
            let sidecar = format!("{}  {}", ev.content_hash, artifact_rel);
            std::fs::write(&hash_path, sidecar)
                .with_context(|| format!("write evidence hash sidecar {}", hash_path.display()))?;
            all_evidence.push(ev);
        }

        // Also persist evidence that had no control mapping (still valuable)
        // Already done above

        // Evaluate controls
        let grouped: Vec<(String, Vec<Evidence>)> = evidence_by_control.into_iter().collect();
        // For controls with no evidence, evaluate will mark UNKNOWN
        let results = self.controls.evaluate(&grouped);

        // Drift detection
        let previous = self.store.list_control_results().unwrap_or_default();
        let drifts = crate::drift::detect(&previous, &results);
        for d in &drifts {
            info!(
                control = %d.control_id,
                previous = %d.previous,
                current = %d.current,
                severity = %d.severity,
                "COMPLIANCE_DRIFT"
            );
            self.store
                .insert_drift(d)
                .with_context(|| format!("persist drift event {}", d.id))?;
        }

        // Persist results and append to history
        for r in &results {
            self.store
                .upsert_control_result(r)
                .with_context(|| format!("persist control result {}", r.id))?;
            self.store
                .insert_control_result_history(r)
                .with_context(|| format!("persist control history {}", r.id))?;
        }

        Ok(results)
    }

    pub async fn run_forever(&self, base_path: std::path::PathBuf) {
        let interval = Duration::from_secs(self.config.interval_secs);
        loop {
            if let Err(e) = self.tick(&base_path).await {
                warn!(error = %e, "tick failed");
            }
            sleep(interval).await;
        }
    }
}

fn map_observation_to_controls(
    obs: &crate::evidence::Observation,
    controls: &crate::control::ControlSet,
) -> Vec<String> {
    let artifact_type_str = obs.artifact_type.to_string();
    controls
        .controls
        .iter()
        .filter(|c| c.evidence_types.iter().any(|t| t == &artifact_type_str))
        .map(|c| c.id.clone())
        .collect()
}
