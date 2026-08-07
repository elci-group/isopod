//! Config — local-first, file-based, sandbox-aware.
//! See `docs/configuration.md`.

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
    pub frameworks: Vec<String>,
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
            frameworks: vec!["iso27001".to_string()],
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
                    let fallback = std::path::Path::new(".isopod").join(d.strip_prefix(dirs::home_dir().unwrap_or_default()).unwrap_or(d));
                    let _ = std::fs::create_dir_all(&fallback);
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
