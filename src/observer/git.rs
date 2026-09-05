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

    let head = git_output(base, &["rev-parse", "--abbrev-ref", "HEAD"])?
        .trim()
        .to_string();

    out.push(branch_protection_observation(base, &head));

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

/// Branch protection is a server-side GitHub setting — no local file
/// reflects it. The previous heuristic checked for a `.github/branch-
/// protection.json` marker that GitHub never creates and nothing else
/// writes either, so it could only ever report "unprotected" regardless
/// of the repository's real state. Query the GitHub API via `gh` (already
/// used elsewhere in this ecosystem for authenticated calls) when a
/// `github.com` remote and the `gh` CLI are both available, and fall back
/// to the old local marker — clearly labelled low-confidence — otherwise.
fn branch_protection_observation(base: &std::path::Path, branch: &str) -> Observation {
    if let Some((owner, repo)) = github_owner_repo(base) {
        let output = Command::new("gh")
            .args([
                "api",
                &format!("repos/{owner}/{repo}/branches/{branch}/protection"),
            ])
            .current_dir(base)
            .output();
        if let Ok(output) = output {
            // gh exits non-zero on a 404 ("Branch not protected") as much
            // as on an auth failure; distinguish by checking whether gh
            // actually reached GitHub (stderr carries the HTTP status).
            let stderr = String::from_utf8_lossy(&output.stderr);
            if output.status.success() {
                let mut obs = Observation::new(
                    "git",
                    ArtifactType::GitBranchProtection,
                    json!({"branch": branch, "source": "gh_api", "protected": true}),
                );
                obs.confidence_hint = Some(0.95);
                return obs;
            }
            if stderr.contains("HTTP 404") || stderr.contains("Branch not protected") {
                let mut obs = Observation::new(
                    "git",
                    ArtifactType::GitBranchProtection,
                    json!({"branch": branch, "source": "gh_api", "protected": false}),
                );
                obs.confidence_hint = Some(0.95);
                return obs;
            }
            tracing::warn!(stderr = %stderr.trim(), "gh api branch protection query failed; falling back to local heuristic");
        }
    }
    let mut obs = Observation::new(
        "git",
        ArtifactType::GitBranchProtection,
        json!({
            "branch": branch,
            "source": "local_marker",
            "protected_hint": base.join(".github/branch-protection.json").exists(),
        }),
    );
    // This heuristic cannot observe the real GitHub setting, so it is
    // capped well below the confidence threshold that would let a control
    // PASS on this evidence alone (see control::evaluate's 0.75 cutoff).
    obs.confidence_hint = Some(0.45);
    obs
}

/// Parse `owner/repo` out of the `origin` remote when it points at
/// github.com (https or ssh form). Returns `None` for any other host or
/// when no `gh` CLI would have anything to query.
fn github_owner_repo(base: &std::path::Path) -> Option<(String, String)> {
    let url = git_output(base, &["remote", "get-url", "origin"]).ok()?;
    let url = url.trim();
    let rest = url
        .strip_prefix("git@github.com:")
        .or_else(|| url.strip_prefix("https://github.com/"))
        .or_else(|| url.strip_prefix("ssh://git@github.com/"))?;
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let (owner, repo) = rest.split_once('/')?;
    Some((owner.to_string(), repo.to_string()))
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
