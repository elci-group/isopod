// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Evidence retention and pruning.
//!
//! Removes evidence older than a configured retention window, along with the
//! associated artifact files and hash sidecars.

use crate::config::Config;
use crate::store::Store;
use chrono::Utc;
use std::sync::Arc;

/// Result of a prune operation.
#[derive(Debug, Clone)]
pub struct PruneResult {
    pub deleted_evidence: usize,
    pub deleted_artifacts: usize,
    pub deleted_sidecars: usize,
}

impl PruneResult {
    pub fn empty() -> Self {
        Self {
            deleted_evidence: 0,
            deleted_artifacts: 0,
            deleted_sidecars: 0,
        }
    }
}

/// Prune evidence older than `retention_days`.
/// Pass `None` to use `config.retention_days`; pass `Some(0)` to delete nothing.
pub fn prune_evidence(
    store: &Store,
    config: &Config,
    retention_days: Option<u64>,
) -> anyhow::Result<PruneResult> {
    let days = retention_days.unwrap_or(config.retention_days);
    if days == 0 {
        return Ok(PruneResult::empty());
    }
    let cutoff = Utc::now() - chrono::Duration::days(days as i64);
    let old = store.list_evidence_before(cutoff)?;
    let mut result = PruneResult::empty();
    for ev in old {
        // Attempt to remove artifact file
        let artifact_rel = ev
            .artifact_path
            .clone()
            .unwrap_or_else(|| format!("artifacts/{}.json", ev.id));
        let artifact_path = config.evidence_dir.join(&artifact_rel);
        if artifact_path.exists() && std::fs::remove_file(&artifact_path).is_ok() {
            result.deleted_artifacts += 1;
        }
        // Attempt to remove hash sidecar
        let sidecar_path = config
            .evidence_dir
            .join("hashes")
            .join(format!("{}.sha256", ev.id));
        if sidecar_path.exists() && std::fs::remove_file(&sidecar_path).is_ok() {
            result.deleted_sidecars += 1;
        }
        // Remove from store
        store.delete_evidence(&ev.id)?;
        result.deleted_evidence += 1;
    }
    Ok(result)
}

/// Convenience: prune with an `Arc<Store>`.
pub fn prune_evidence_arc(
    store: &Arc<Store>,
    config: &Config,
    retention_days: Option<u64>,
) -> anyhow::Result<PruneResult> {
    prune_evidence(store, config, retention_days)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{ArtifactType, Evidence};
    use crate::store::Store;

    #[test]
    fn prune_keeps_recent_and_removes_old() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = dir.path().join("state.db");
        let evidence_dir = dir.path().join("evidence");
        let artifacts_dir = evidence_dir.join("artifacts");
        let hashes_dir = evidence_dir.join("hashes");
        std::fs::create_dir_all(&artifacts_dir).unwrap();
        std::fs::create_dir_all(&hashes_dir).unwrap();
        let store = Store::open(&db).unwrap();

        // Recent evidence
        let recent = Evidence::new("test", ArtifactType::AuditLog, b"recent", 0.9);
        store.insert_evidence(&recent).unwrap();

        // Old evidence
        let mut old = Evidence::new("test", ArtifactType::AuditLog, b"old", 0.9);
        old.timestamp = Utc::now() - chrono::Duration::days(365);
        store.insert_evidence(&old).unwrap();
        let artifact = artifacts_dir.join(format!("{}.json", old.id));
        std::fs::write(&artifact, old.metadata.to_string()).unwrap();
        let sidecar = hashes_dir.join(format!("{}.sha256", old.id));
        std::fs::write(&sidecar, "hash  artifacts/x.json").unwrap();

        let cfg = Config {
            state_dir: dir.path().to_path_buf(),
            evidence_dir: evidence_dir.clone(),
            controls_dir: dir.path().to_path_buf(),
            reports_dir: dir.path().to_path_buf(),
            interval_secs: 60,
            api_addr: None,
            api_token: None,
            api_rate_limit: 0,
            frameworks: vec!["iso27001".to_string()],
            retention_days: 90,
        };

        let result = prune_evidence(&store, &cfg, None).unwrap();
        assert_eq!(result.deleted_evidence, 1);
        assert_eq!(result.deleted_artifacts, 1);
        assert_eq!(result.deleted_sidecars, 1);
        assert_eq!(store.count_evidence().unwrap(), 1);
        assert!(!artifact.exists());
        assert!(!sidecar.exists());
    }
}
