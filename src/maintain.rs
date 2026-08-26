// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Maintain — keeps existing .isopod installations healthy.
//!
//! Checks for corruption, missing controls, stale DB, and optionally
//! runs a compliance tick to keep posture fresh.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::control::ControlSet;
use crate::project::{config_for_project, default_controls, seed_controls};
use crate::store::Store;

/// Health of a single .isopod installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceReport {
    pub path: PathBuf,
    pub ok: bool,
    pub issues: Vec<String>,
    pub fixed: Vec<String>,
    pub evidence_count: usize,
    pub controls: usize,
}

impl MaintenanceReport {
    pub fn healthy(path: PathBuf) -> Self {
        Self {
            path,
            ok: true,
            issues: vec![],
            fixed: vec![],
            evidence_count: 0,
            controls: 0,
        }
    }
}

/// Check and fix a single project's .isopod.
pub fn maintain_project(project_path: &Path, auto_fix: bool) -> MaintenanceReport {
    let isopod_dir = project_path.join(".isopod");
    let mut report = MaintenanceReport {
        path: project_path.to_path_buf(),
        ok: true,
        issues: vec![],
        fixed: vec![],
        evidence_count: 0,
        controls: 0,
    };

    if !isopod_dir.exists() {
        report.ok = false;
        report.issues.push("missing .isopod directory".to_string());
        return report;
    }

    let cfg = config_for_project(project_path);

    // Ensure dirs exist
    for dir in [
        &cfg.evidence_dir,
        &cfg.controls_dir,
        &cfg.reports_dir,
        &cfg.evidence_dir.join("hashes"),
        &cfg.evidence_dir.join("artifacts"),
    ] {
        if !dir.exists() {
            report.ok = false;
            report.issues.push(format!("missing dir {}", dir.display()));
            if auto_fix {
                match std::fs::create_dir_all(dir) {
                    Ok(()) => {
                        report.fixed.push(format!("created {}", dir.display()));
                        report.ok = report.issues.len() == report.fixed.len();
                    }
                    Err(error) => {
                        tracing::error!(path = %dir.display(), error = %error, "maintenance directory repair failed");
                        report
                            .issues
                            .push(format!("failed to create {}: {error}", dir.display()));
                    }
                }
            }
        }
    }

    // Check controls
    let controls = ControlSet::load_dir(&cfg.controls_dir);
    report.controls = controls.controls.len();
    if controls.controls.is_empty() {
        report.ok = false;
        report.issues.push("no controls found".to_string());
        if auto_fix {
            // Force seed if controls invalid/empty, even if dir not empty (e.g., placeholder test.yaml)
            let before = controls.controls.len();
            // Remove invalid placeholder if present and try to seed defaults
            let placeholder = cfg.controls_dir.join("test.yaml");
            if placeholder.exists() && before == 0 {
                if let Err(error) = std::fs::remove_file(&placeholder) {
                    tracing::error!(path = %placeholder.display(), error = %error, "invalid control placeholder could not be removed");
                    report.issues.push(format!(
                        "failed to remove invalid control placeholder: {error}"
                    ));
                }
            }
            match seed_controls(&cfg) {
                Ok(n) => {
                    if n > 0 {
                        report.fixed.push(format!("seeded {n} control packs"));
                        let re = ControlSet::load_dir(&cfg.controls_dir);
                        report.controls = re.controls.len();
                        if report.controls > 0 {
                            report.fixed.push("controls now valid".to_string());
                        }
                    }
                }
                Err(error) => {
                    tracing::error!(path = %cfg.controls_dir.display(), error = %error, "control pack repair failed");
                    report
                        .issues
                        .push(format!("failed to seed control packs: {error}"));
                }
            }
            // If still empty, try to ensure defaults exist directly
            if report.controls == 0 {
                for (name, content) in default_controls() {
                    let path = cfg.controls_dir.join(name);
                    if !path.exists() {
                        match std::fs::write(&path, content) {
                            Ok(()) => {
                                report.fixed.push(format!("created {name}"));
                                report.controls += 1;
                            }
                            Err(error) => {
                                tracing::error!(path = %path.display(), error = %error, "default control pack write failed");
                                report
                                    .issues
                                    .push(format!("failed to create control pack {name}: {error}"));
                            }
                        }
                    }
                }
            }
        }
    }

    // Check state.db
    let db_path = cfg.db_path();
    if !db_path.exists() {
        report.ok = false;
        report.issues.push("missing state.db".to_string());
        if auto_fix {
            match Store::open(&db_path) {
                Ok(_) => report.fixed.push("created state.db".to_string()),
                Err(e) => {
                    tracing::error!(path = %db_path.display(), error = %e, "maintenance store creation failed");
                    report
                        .issues
                        .push(format!("failed to create state.db: {e}"));
                }
            }
        }
    } else {
        // Try to open and query
        match Store::open(&db_path) {
            Ok(store) => {
                match store.count_evidence() {
                    Ok(n) => report.evidence_count = n,
                    Err(e) => {
                        tracing::error!(path = %db_path.display(), error = %e, "maintenance evidence count failed");
                        report.ok = false;
                        report.issues.push(format!("evidence count failed: {e}"));
                    }
                }
                // Check hash sidecars and artifact files for evidence
                if auto_fix {
                    // Ensure hashes dir has sidecars for recent evidence (best-effort)
                    match store.list_evidence(None, 100) {
                        Ok(evs) => {
                            for ev in evs {
                                let artifact_rel = ev
                                    .artifact_path
                                    .clone()
                                    .unwrap_or_else(|| format!("artifacts/{}.json", ev.id));
                                let artifact_path = cfg.evidence_dir.join(&artifact_rel);
                                if !artifact_path.exists() {
                                    match std::fs::write(&artifact_path, ev.metadata.to_string()) {
                                        Ok(()) => {}
                                        Err(error) => {
                                            tracing::error!(evidence_id = %ev.id, path = %artifact_path.display(), error = %error, "evidence artifact repair failed");
                                            report.issues.push(format!(
                                                "failed to repair evidence artifact {}: {error}",
                                                ev.id
                                            ));
                                        }
                                    }
                                }
                                let hash_path = cfg
                                    .evidence_dir
                                    .join("hashes")
                                    .join(format!("{}.sha256", ev.id));
                                if !hash_path.exists() {
                                    let sidecar = format!("{}  {}", ev.content_hash, artifact_rel);
                                    if let Err(error) = std::fs::write(&hash_path, sidecar) {
                                        tracing::error!(evidence_id = %ev.id, path = %hash_path.display(), error = %error, "evidence sidecar repair failed");
                                        report.issues.push(format!(
                                            "failed to repair evidence sidecar {}: {error}",
                                            ev.id
                                        ));
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            tracing::error!(path = %db_path.display(), error = %error, "maintenance evidence listing failed");
                            report
                                .issues
                                .push(format!("failed to list evidence for repair: {error}"));
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(path = %db_path.display(), error = %e, "maintenance detected unreadable store");
                report.ok = false;
                report.issues.push(format!("state.db open failed: {e}"));
                if auto_fix {
                    let backup = db_path.with_extension(format!(
                        "corrupt-{}.bak",
                        chrono::Utc::now().timestamp_millis()
                    ));
                    match std::fs::rename(&db_path, &backup) {
                        Ok(()) => match Store::open(&db_path) {
                            Ok(_) => report.fixed.push(format!(
                                "preserved unreadable database at {} and created state.db",
                                backup.display()
                            )),
                            Err(error) => {
                                tracing::error!(path = %db_path.display(), error = %error, "maintenance store recreation failed");
                                report.issues.push(format!("recreate failed: {error}"));
                            }
                        },
                        Err(error) => {
                            tracing::error!(path = %db_path.display(), backup = %backup.display(), error = %error, "unreadable store could not be preserved");
                            report
                                .issues
                                .push(format!("failed to preserve unreadable database: {error}"));
                        }
                    }
                }
            }
        }
    }

    // Re-evaluate ok if all issues were fixed
    if !report.issues.is_empty() && report.fixed.len() >= report.issues.len() {
        // Check if any unfixed remain
        let unfixed = report
            .issues
            .iter()
            .filter(|i| !report.fixed.iter().any(|f| f.contains(i.as_str())))
            .count();
        if unfixed == 0 {
            // We attempted fixes; re-check quickly
            report.ok = true;
        }
    }

    report
}

/// Maintain many projects.
pub fn maintain_projects(paths: &[PathBuf], auto_fix: bool) -> Vec<MaintenanceReport> {
    paths
        .iter()
        .map(|p| maintain_project(p, auto_fix))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::provision_project;
    use tempfile::TempDir;

    #[test]
    fn maintains_healthy() {
        let dir = TempDir::new().unwrap();
        let proj = dir.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        provision_project(&proj);
        let rep = maintain_project(&proj, true);
        assert!(rep.ok);
        assert!(rep.issues.is_empty() || rep.fixed.len() == rep.issues.len());
    }

    #[test]
    fn detects_missing() {
        let dir = TempDir::new().unwrap();
        let proj = dir.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        // No .isopod
        let rep = maintain_project(&proj, false);
        assert!(!rep.ok);
        assert!(rep.issues.iter().any(|i| i.contains("missing .isopod")));
    }

    #[test]
    fn auto_fixes_missing_dirs() {
        let dir = TempDir::new().unwrap();
        let proj = dir.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        provision_project(&proj);
        // Remove controls
        std::fs::remove_dir_all(proj.join(".isopod/controls")).unwrap();
        let rep = maintain_project(&proj, true);
        assert!(proj.join(".isopod/controls").exists());
        // Should have fixed
        assert!(rep
            .fixed
            .iter()
            .any(|f| f.contains("controls") || f.contains("seeded")));
    }
}
