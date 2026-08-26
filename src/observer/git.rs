// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! GitObserver — branch protection, commits, merges, review evidence.
//! Read-only `git` CLI, no network.

use crate::evidence::{ArtifactType, Observation};
use anyhow::Context;
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
            .context("join Git observer task")??;
        Ok(obs)
    }
}

fn collect_git_sync(base: &std::path::Path) -> anyhow::Result<Vec<Observation>> {
    let mut out = Vec::new();
    if !base.join(".git").exists() {
        return Ok(out);
    }

    // branch protection: check if .git/config has protected branches or if GitHub API not needed
    // Heuristic: existence of branch protection file or config
    let head = git_output(base, &["rev-parse", "--abbrev-ref", "HEAD"])?
        .trim()
        .to_string();

    out.push(Observation::new(
        "git",
        ArtifactType::GitBranchProtection,
        json!({"branch": head, "protected_hint": base.join(".github/branch-protection.json").exists()}),
    ));

    // commit history depth
    let log = git_output(
        base,
        &["log", "--oneline", "-n", "20", "--pretty=format:%H %ai %s"],
    )?;

    let count = log.lines().count();
    out.push(Observation::new(
        "git",
        ArtifactType::GitCommit,
        json!({"recent_commits": count, "preview": log.chars().take(500).collect::<String>()}),
    ));

    // review evidence: check last commits have merges or PR refs
    let merges = git_output(base, &["log", "--merges", "--oneline", "-n", "10"])?;

    out.push(Observation::new(
        "git",
        ArtifactType::DeploymentHistory,
        json!({"merges": merges.lines().count(), "preview": merges.chars().take(300).collect::<String>()}),
    ));

    Ok(out)
}

fn git_output(base: &std::path::Path, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(base)
        .output()
        .with_context(|| format!("execute git {}", args.join(" ")))?;
    if !output.status.success() {
        tracing::warn!(
            status = %output.status,
            arguments = %args.join(" "),
            "Git observer command did not succeed"
        );
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
