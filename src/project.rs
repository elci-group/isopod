// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Shared project-level helpers for provisioning and maintenance.
//!
//! Centralizes the per-project `.isopod` layout, default control packs, and
//! seeding logic so `provision`, `maintain`, and the main CLI do not duplicate
//! it.

use crate::config::Config;
use std::path::Path;

/// Build a `Config` that stores all Isopod state under `<project>/.isopod`.
pub fn config_for_project(project_path: &Path) -> Config {
    let isopod_dir = project_path.join(".isopod");
    Config {
        state_dir: isopod_dir.clone(),
        evidence_dir: isopod_dir.join("evidence"),
        controls_dir: isopod_dir.join("controls"),
        reports_dir: isopod_dir.join("reports"),
        interval_secs: 60,
        api_addr: None,
        api_token: None,
        api_rate_limit: 0,
        frameworks: vec!["iso27001".to_string()],
        retention_days: 0,
    }
}

/// Embedded default control packs shipped with Isopod.
pub fn default_controls() -> Vec<(&'static str, &'static str)> {
    vec![
        ("iso27001.yaml", include_str!("../controls/iso27001.yaml")),
        ("iso27002.yaml", include_str!("../controls/iso27002.yaml")),
    ]
}

/// Seed default control packs into `cfg.controls_dir` if the directory is empty.
/// Returns the number of packs written.
pub fn seed_controls(cfg: &Config) -> anyhow::Result<usize> {
    let is_empty = std::fs::read_dir(&cfg.controls_dir)
        .map(|mut i| i.next().is_none())
        .unwrap_or(true);
    if !is_empty {
        return Ok(0);
    }
    let mut count = 0;
    for (name, content) in default_controls() {
        let path = cfg.controls_dir.join(name);
        if !path.exists() {
            std::fs::write(&path, content)?;
            count += 1;
        }
    }
    Ok(count)
}
