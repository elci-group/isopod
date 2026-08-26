// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! isopod.d — fleet daemon that discovers, provisions, and maintains .isopod.
//!
//! Watches configured roots for project directories, ensures every project has
//! a valid `.isopod` installation, and keeps existing installations healthy.
//! Designed to run as a long-lived daemon (isopod-d) or as a one-shot
//! provisioner (`isopod provision`).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::discover::{discover_projects, DiscoverConfig, DiscoveredProject};
use crate::maintain::{maintain_projects, MaintenanceReport};
use crate::project::config_for_project;
use crate::provision::{provision_projects, ProvisionResult};
use crate::store::Store;

/// Configuration for isopod.d.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsopodDConfig {
    /// Roots to scan for projects.
    pub roots: Vec<PathBuf>,
    /// How often to scan (seconds).
    pub scan_interval_secs: u64,
    /// Whether to run a compliance tick for each project after provision/maintain.
    pub run_tick: bool,
    /// Auto-fix maintenance issues.
    pub auto_fix: bool,
    /// Maximum walk depth.
    pub max_depth: usize,
    /// Project markers.
    pub markers: Vec<String>,
    /// Ignore dir names.
    pub ignore: Vec<String>,
    /// Dry-run (log but don't create).
    pub dry_run: bool,
}

impl Default for IsopodDConfig {
    fn default() -> Self {
        Self {
            roots: vec![PathBuf::from(".")],
            scan_interval_secs: 300,
            run_tick: false,
            auto_fix: true,
            max_depth: 4,
            markers: crate::discover::DEFAULT_MARKERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ignore: crate::discover::DEFAULT_IGNORE
                .iter()
                .map(|s| s.to_string())
                .collect(),
            dry_run: false,
        }
    }
}

impl IsopodDConfig {
    pub fn from_discover_config(
        dc: &DiscoverConfig,
        auto_fix: bool,
        run_tick: bool,
        dry_run: bool,
        interval: u64,
    ) -> Self {
        Self {
            roots: dc.roots.clone(),
            scan_interval_secs: interval,
            run_tick,
            auto_fix,
            max_depth: dc.max_depth,
            markers: dc.markers.clone(),
            ignore: dc.ignore.clone(),
            dry_run,
        }
    }

    pub fn discover_config(&self) -> DiscoverConfig {
        DiscoverConfig {
            roots: self.roots.clone(),
            markers: self.markers.clone(),
            max_depth: self.max_depth,
            ignore: self.ignore.clone(),
            require_marker: true,
        }
    }
}

/// Summary of a single isopod.d cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleReport {
    pub discovered: usize,
    pub untracked: usize,
    pub tracked: usize,
    pub provisioned: Vec<ProvisionResult>,
    pub maintained: Vec<MaintenanceReport>,
    pub ticks: Vec<TickResult>,
}

/// Result of a per-project tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickResult {
    pub path: PathBuf,
    pub controls: Option<usize>,
    pub error: Option<String>,
}

impl CycleReport {
    pub fn new(discovered: Vec<DiscoveredProject>) -> Self {
        let untracked = discovered.iter().filter(|p| p.is_untracked()).count();
        let tracked = discovered.len() - untracked;
        Self {
            discovered: discovered.len(),
            untracked,
            tracked,
            provisioned: vec![],
            maintained: vec![],
            ticks: vec![],
        }
    }
}

/// Run a single discovery → provision → maintain cycle.
/// Returns CycleReport for stylised rendering.
pub async fn run_cycle(cfg: &IsopodDConfig) -> CycleReport {
    let dc = cfg.discover_config();
    let discovered = discover_projects(&dc);
    info!(
        discovered = discovered.len(),
        untracked = discovered.iter().filter(|p| p.is_untracked()).count(),
        tracked = discovered.iter().filter(|p| p.is_tracked()).count(),
        "discovery complete"
    );

    let mut report = CycleReport::new(discovered.clone());

    // Partition
    let untracked_paths: Vec<PathBuf> = discovered
        .iter()
        .filter(|p| p.is_untracked())
        .map(|p| p.path.clone())
        .collect();
    let tracked_paths: Vec<PathBuf> = discovered
        .iter()
        .filter(|p| p.is_tracked())
        .map(|p| p.path.clone())
        .collect();

    // Provision untracked
    if !untracked_paths.is_empty() {
        if cfg.dry_run {
            info!(count = untracked_paths.len(), "dry-run: would provision");
            // Create fake results for display
            report.provisioned = untracked_paths
                .iter()
                .map(|p| ProvisionResult {
                    path: p.clone(),
                    created: true,
                    controls_seeded: 2,
                    error: None,
                })
                .collect();
        } else {
            let results = provision_projects(&untracked_paths);
            for r in &results {
                if let Some(e) = &r.error {
                    warn!(path = %r.path.display(), error = %e, "provision failed");
                } else {
                    info!(path = %r.path.display(), created = r.created, controls = r.controls_seeded, "provisioned");
                }
            }
            report.provisioned = results;
        }
    }

    // Maintain tracked (and newly provisioned if not dry-run)
    let maintain_paths = if cfg.dry_run {
        tracked_paths.clone()
    } else {
        // After provisioning, those untracked are now tracked; maintain all
        discovered.iter().map(|p| p.path.clone()).collect()
    };

    if !maintain_paths.is_empty() {
        let results = maintain_projects(&maintain_paths, cfg.auto_fix);
        for r in &results {
            if !r.ok {
                warn!(path = %r.path.display(), issues = ?r.issues, "maintenance issues");
            } else {
                debug!(path = %r.path.display(), "maintenance ok");
            }
        }
        report.maintained = results;
    }

    // Optionally run a tick for each project to keep posture fresh
    if cfg.run_tick && !cfg.dry_run {
        for path in &maintain_paths {
            let tick_res = run_tick_for_project(path).await;
            match tick_res {
                Ok(n) => report.ticks.push(TickResult {
                    path: path.clone(),
                    controls: Some(n),
                    error: None,
                }),
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "fleet compliance tick failed");
                    report.ticks.push(TickResult {
                        path: path.clone(),
                        controls: None,
                        error: Some(e),
                    });
                }
            }
        }
    }

    report
}

async fn run_tick_for_project(project_path: &Path) -> Result<usize, String> {
    // Build per-project config and store
    let cfg = config_for_project(project_path);
    let store = match Store::open(&cfg.db_path()) {
        Ok(s) => std::sync::Arc::new(s),
        Err(e) => {
            warn!(path = %project_path.display(), error = %e, "fleet project store open failed");
            return Err(format!("store open failed: {e}"));
        }
    };
    let daemon = crate::daemon::Daemon::new(cfg, store);
    match daemon.tick(project_path).await {
        Ok(results) => Ok(results.len()),
        Err(e) => {
            warn!(path = %project_path.display(), error = %e, "fleet project evaluation failed");
            Err(e.to_string())
        }
    }
}

/// Long-running daemon loop.
pub async fn run_forever(cfg: IsopodDConfig) {
    let interval = Duration::from_secs(cfg.scan_interval_secs);
    info!(roots = ?cfg.roots, interval = cfg.scan_interval_secs, "isopod.d starting");

    loop {
        let report = run_cycle(&cfg).await;
        // Stylised summary via tracing
        info!(
            discovered = report.discovered,
            untracked = report.untracked,
            provisioned = report
                .provisioned
                .iter()
                .filter(|r| r.error.is_none())
                .count(),
            maintained = report.maintained.iter().filter(|r| r.ok).count(),
            "cycle complete"
        );
        sleep(interval).await;
    }
}
