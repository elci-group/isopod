use crate::config::Config;
use crate::control::ControlSet;
use crate::evidence::{ArtifactType, Evidence};
use crate::observer::{CompositeObserver, Observer};
use crate::store::Store;
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
        let controls = ControlSet::load_dir(&config.controls_dir);
        Self {
            config,
            store,
            controls,
        }
    }

    /// Single evaluation cycle: collect -> normalize -> evaluate -> drift -> persist
    pub async fn tick(&self, base_path: &std::path::Path) -> anyhow::Result<Vec<crate::control::ControlResult>> {
        info!("tick: collecting observations from {}", base_path.display());
        let observer = CompositeObserver::new(base_path.to_path_buf()).with_defaults();
        let observations = observer.collect().await.unwrap_or_default();
        info!("collected {} observations", observations.len());

        // Normalize to Evidence
        let mut evidence_by_control: std::collections::HashMap<String, Vec<Evidence>> =
            std::collections::HashMap::new();
        let mut all_evidence = Vec::new();

        for obs in observations {
            // Heuristic control mapping
            let control_id = map_observation_to_control(&obs);
            let confidence = obs.confidence_hint.unwrap_or(0.85);
            let mut ev = obs.into_evidence(confidence);
            // hash file persistence attempt (tamper detection)
            if let Some(cid) = control_id.clone() {
                ev = ev.with_control(cid.clone());
                evidence_by_control.entry(cid).or_default().push(ev.clone());
            }
            // persist
            if let Err(e) = self.store.insert_evidence(&ev) {
                warn!(error = %e, "failed to persist evidence");
            } else {
                // write hash sidecar
                let hash_path = self
                    .config
                    .evidence_dir
                    .join("hashes")
                    .join(format!("{}.sha256", ev.id));
                let _ = std::fs::write(hash_path, &ev.content_hash);
            }
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
            let _ = self.store.insert_drift(d);
        }

        // Persist results
        for r in &results {
            let _ = self.store.upsert_control_result(r);
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

fn map_observation_to_control(obs: &crate::evidence::Observation) -> Option<String> {
    // Framework-agnostic mapping; extend as needed
    match obs.artifact_type {
        ArtifactType::AuditLog | ArtifactType::ServiceState => Some("ISO27001-A.8.15".to_string()),
        ArtifactType::GitBranchProtection | ArtifactType::GitCommit => Some("ISO27001-A.8.9".to_string()),
        ArtifactType::FilePermission | ArtifactType::AccessReview => Some("ISO27001-A.9.2".to_string()),
        ArtifactType::EncryptionState | ArtifactType::NetworkExposure => Some("ISO27001-A.8.26".to_string()),
        ArtifactType::BackupRecord => Some("ISO27001-A.8.13".to_string()),
        ArtifactType::Certificate => Some("ISO27001-A.8.26".to_string()),
        ArtifactType::TraciTrace => Some("ISO27001-A.8.15".to_string()),
        ArtifactType::KaptaindRelease => Some("ISO27001-A.8.29".to_string()),
        ArtifactType::DeliverMilestone => Some("ISO27001-A.8.30".to_string()),
        _ => None,
    }
}

/// Derive confidence from observation content (example: audit logs present => 0.92)
#[allow(dead_code)]
fn confidence_for(obs: &crate::evidence::Observation) -> f32 {
    match obs.artifact_type {
        ArtifactType::AuditLog => {
            if obs.raw.get("audit_logs_present").and_then(|v| v.as_bool()) == Some(true) {
                0.92
            } else {
                0.3
            }
        }
        _ => 0.85,
    }
}
