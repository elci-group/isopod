// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Provision — generate .isopod for untracked projects.
//!
//! Creates the local-first directory layout, seeds default controls, and
//! initialises the SQLite state.db. Idempotent; safe to re-run on existing
//! projects (maintenance will call ensure).

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::project::{config_for_project, seed_controls};
use crate::store::Store;

/// Result of provisioning a single project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionResult {
    pub path: std::path::PathBuf,
    pub created: bool,
    pub controls_seeded: usize,
    pub error: Option<String>,
}

/// Ensure a single project's .isopod layout exists.
/// Returns ProvisionResult with created flag.
pub fn provision_project(project_path: &Path) -> ProvisionResult {
    let isopod_dir = project_path.join(".isopod");
    let was_created = !isopod_dir.exists();

    // Build config pointing at this project's .isopod
    let cfg = config_for_project(project_path);

    if let Err(e) = cfg.ensure_dirs() {
        tracing::error!(path = %project_path.display(), error = %e, "project provisioning directory setup failed");
        return ProvisionResult {
            path: project_path.to_path_buf(),
            created: false,
            controls_seeded: 0,
            error: Some(format!("ensure_dirs failed: {e}")),
        };
    }

    // Seed controls if empty
    let seeded = match seed_controls(&cfg) {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(path = %project_path.display(), error = %e, "project control seeding failed");
            return ProvisionResult {
                path: project_path.to_path_buf(),
                created: was_created,
                controls_seeded: 0,
                error: Some(format!("seed_controls failed: {e}")),
            };
        }
    };

    // Initialise state.db (creates tables)
    if let Err(e) = Store::open(&cfg.db_path()).map(|_| ()) {
        tracing::error!(path = %cfg.db_path().display(), error = %e, "project store initialization failed");
        return ProvisionResult {
            path: project_path.to_path_buf(),
            created: was_created,
            controls_seeded: seeded,
            error: Some(format!("store init failed: {e}")),
        };
    }

    ProvisionResult {
        path: project_path.to_path_buf(),
        created: was_created,
        controls_seeded: seeded,
        error: None,
    }
}

/// Provision many projects, returning per-project results.
pub fn provision_projects(paths: &[std::path::PathBuf]) -> Vec<ProvisionResult> {
    paths.iter().map(|p| provision_project(p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn provisions_new_project() {
        let dir = TempDir::new().unwrap();
        let proj = dir.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("Cargo.toml"), b"").unwrap();
        let res = provision_project(&proj);
        assert!(res.error.is_none(), "error: {:?}", res.error);
        assert!(res.created);
        assert!(proj.join(".isopod").exists());
        assert!(proj.join(".isopod/state.db").exists());
        assert!(proj.join(".isopod/controls/iso27001.yaml").exists());
    }

    #[test]
    fn idempotent_on_existing() {
        let dir = TempDir::new().unwrap();
        let proj = dir.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let r1 = provision_project(&proj);
        assert!(r1.created);
        let r2 = provision_project(&proj);
        assert!(!r2.created);
        assert!(r2.error.is_none());
    }
}
