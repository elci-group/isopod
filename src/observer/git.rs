use crate::evidence::{ArtifactType, Observation};
use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;
use std::process::Command;

pub struct GitObserver {
    pub path: PathBuf,
}

#[async_trait]
impl super::Observer for GitObserver {
    fn name(&self) -> &str {
        "git"
    }

    async fn collect(&self) -> anyhow::Result<Vec<Observation>> {
        let path = self.path.clone();
        // Offload blocking git calls
        let obs = tokio::task::spawn_blocking(move || collect_git_sync(&path))
            .await
            .unwrap_or_default();
        Ok(obs)
    }
}

fn collect_git_sync(base: &std::path::Path) -> Vec<Observation> {
    let mut out = Vec::new();
    if !base.join(".git").exists() {
        return out;
    }

    // branch protection: check if .git/config has protected branches or if GitHub API not needed
    // Heuristic: existence of branch protection file or config
    let head = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(base)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default()
        .trim()
        .to_string();

    out.push(Observation::new(
        "git",
        ArtifactType::GitBranchProtection,
        json!({"branch": head, "protected_hint": base.join(".github/branch-protection.json").exists()}),
    ));

    // commit history depth
    let log = Command::new("git")
        .args(["log", "--oneline", "-n", "20", "--pretty=format:%H %ai %s"])
        .current_dir(base)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let count = log.lines().count();
    out.push(Observation::new(
        "git",
        ArtifactType::GitCommit,
        json!({"recent_commits": count, "preview": log.chars().take(500).collect::<String>()}),
    ));

    // review evidence: check last commits have merges or PR refs
    let merges = Command::new("git")
        .args(["log", "--merges", "--oneline", "-n", "10"])
        .current_dir(base)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    out.push(Observation::new(
        "git",
        ArtifactType::DeploymentHistory,
        json!({"merges": merges.lines().count(), "preview": merges.chars().take(300).collect::<String>()}),
    ));

    out
}
