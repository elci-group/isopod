// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Config — local-first, file-based, sandbox-aware.
//! See `docs/configuration.md`.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub state_dir: PathBuf,
    pub evidence_dir: PathBuf,
    pub controls_dir: PathBuf,
    pub reports_dir: PathBuf,
    pub interval_secs: u64,
    pub api_addr: Option<String>,
    /// Optional bearer token required to access protected API endpoints.
    #[serde(default)]
    pub api_token: Option<String>,
    /// Maximum API requests per minute. 0 disables rate limiting.
    #[serde(default)]
    pub api_rate_limit: u32,
    pub frameworks: Vec<String>,
    /// Evidence retention window in days. 0 disables pruning.
    pub retention_days: u64,
}

impl Default for Config {
    fn default() -> Self {
        let base = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".isopod");
        Self {
            evidence_dir: base.join("evidence"),
            controls_dir: base.join("controls"),
            reports_dir: base.join("reports"),
            state_dir: base.clone(),
            interval_secs: 60,
            api_addr: Some("127.0.0.1:8787".to_string()),
            api_token: None,
            api_rate_limit: 0,
            frameworks: vec!["iso27001".to_string()],
            retention_days: 0,
        }
    }
}

impl Config {
    pub fn db_path(&self) -> PathBuf {
        self.state_dir.join("state.db")
    }

    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        for d in [
            &self.state_dir,
            &self.evidence_dir,
            &self.evidence_dir.join("hashes"),
            &self.evidence_dir.join("artifacts"),
            &self.controls_dir,
            &self.reports_dir,
        ] {
            // In sandboxed env home may be read-only; best-effort with fallback
            if let Err(e) = std::fs::create_dir_all(d) {
                tracing::warn!(path = %d.display(), error = %e, "ensure_dir failed, trying fallback");
                // Fallback to local ./ .isopod if home is read-only
                if d.starts_with(dirs::home_dir().unwrap_or_default()) {
                    let fallback = std::path::Path::new(".isopod").join(
                        d.strip_prefix(dirs::home_dir().unwrap_or_default())
                            .unwrap_or(d),
                    );
                    std::fs::create_dir_all(&fallback).with_context(|| {
                        format!("create fallback state directory {}", fallback.display())
                    })?;
                }
            }
        }
        Ok(())
    }

    pub fn load_or_default(path: Option<PathBuf>) -> Self {
        if let Some(p) = path {
            if let Ok(text) = std::fs::read_to_string(&p) {
                if let Ok(cfg) = serde_yaml::from_str::<Config>(&text) {
                    return cfg;
                }
            }
        }
        // Try default locations
        let default_path = Self::default().state_dir.join("config.yaml");
        if let Ok(text) = std::fs::read_to_string(&default_path) {
            if let Ok(cfg) = serde_yaml::from_str::<Config>(&text) {
                return cfg;
            }
        }
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_yaml_configuration_roundtrips_and_creates_layout() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let config = Config {
            state_dir: state.clone(),
            evidence_dir: state.join("evidence"),
            controls_dir: state.join("controls"),
            reports_dir: state.join("reports"),
            interval_secs: 15,
            api_addr: None,
            api_token: Some("token".into()),
            api_rate_limit: 12,
            frameworks: vec!["custom".into()],
            retention_days: 30,
        };
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let loaded = Config::load_or_default(Some(path));
        assert_eq!(loaded.interval_secs, 15);
        assert_eq!(loaded.db_path(), state.join("state.db"));
        loaded.ensure_dirs().unwrap();
        assert!(loaded.evidence_dir.join("artifacts").is_dir());
        assert!(loaded.evidence_dir.join("hashes").is_dir());
    }

    #[test]
    fn invalid_or_missing_configuration_uses_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let invalid = dir.path().join("invalid.yaml");
        std::fs::write(&invalid, "not: [valid").unwrap();
        assert_eq!(
            Config::load_or_default(Some(invalid)).interval_secs,
            Config::default().interval_secs
        );
        assert_eq!(
            Config::load_or_default(Some(dir.path().join("missing"))).retention_days,
            0
        );
    }
}
