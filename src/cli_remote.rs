// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Remote hardening — fork a target project, add the missing evidence
//! baseline for ISO27001-A.8.15 (Logging) / A.8.16 (Monitoring), and open
//! a PR with the change.
//!
//! Unlike `cli_web::harden` (which only ever touches `cli.base`, in place,
//! locally), this operates on a *different* repository: a fresh fork, not
//! the project isopod itself was invoked against. It exists because
//! `isopod check` can tell you A.8.15/A.8.16 are failing for lack of
//! `traci_trace` evidence, but fixing that on someone else's project
//! means proposing the change, not applying it unasked.
//!
//! Kaptaind has no GitHub PR API — verified against its full CLI surface
//! (`release`, `branch`, `integrate`, `pull`, `aoc`, ...) and by grepping
//! its source for pull-request handling: nothing. It only produces
//! governed local commits. So the division of labour here is: kaptaind
//! governs the commit (an Aim-of-Change session gives it a real generated
//! message and an audit-trail entry), and `gh` does the fork, push, and
//! PR — the only tool in this pipeline that actually talks to GitHub's
//! pull-request endpoint.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct RemoteHardenArgs {
    /// `owner/repo` of the upstream project to harden.
    pub remote: String,
    pub branch: Option<String>,
    /// Where to clone the fork. Defaults to a process-scoped temp dir so
    /// concurrent runs never collide.
    pub work_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RemoteHardenReport {
    pub owner: String,
    pub repo: String,
    pub branch: String,
    pub work_dir: PathBuf,
    pub files_written: Vec<String>,
    pub committed: bool,
    pub pushed: bool,
    pub pr_url: Option<String>,
}

const DEFAULT_BRANCH: &str = "isopod/iso27001-a8-15-a8-16-logging-hardening";

const TRACI_TOML_TEMPLATE: &str = r#"# Added by `isopod harden` to establish ISO27001-A.8.15 (Logging) and
# A.8.16 (Monitoring) evidence: observability enforcement, not just intent.
[analysis]
fail_on = "error"
trace_window = 6
production_only = false
require_correlation_id = true
correlation_fields = ["correlation_id", "request_id", "trace_id"]
ignore = ["target", ".git", ".kaptaind", ".traci"]
enabled_rules = ["TRC001", "TRC002", "TRC003", "TRC004", "TRC005", "TRC006", "TRC007", "TRC008"]

[watch]
interval_ms = 750

[daemon]
state_dir = ".traci"

[notifications]
enabled = true
console = true
min_severity = "error"

[ui]
color = "auto"
emoji = true
animate = true
"#;

const TRACI_WORKFLOW_TEMPLATE: &str = r#"# Added by `isopod harden` for ISO27001-A.8.15/A.8.16 evidence: every
# push and PR is continuously checked for observability regressions,
# rather than relying on a one-off local scan.
name: traci
on: [push, pull_request]
jobs:
  observability:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install traci
        run: cargo install traci --locked
      - name: Check observability posture
        run: traci check . --format json --fail-on error
"#;

pub fn harden_remote(args: RemoteHardenArgs) -> Result<RemoteHardenReport> {
    let (owner, repo) = args
        .remote
        .split_once('/')
        .with_context(|| format!("--remote must be owner/repo, got {:?}", args.remote))?;
    let branch = args.branch.unwrap_or_else(|| DEFAULT_BRANCH.to_string());
    let work_dir = args.work_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("isopod-harden-{repo}-{}", std::process::id()))
    });

    fork_and_clone(owner, repo, &work_dir)?;
    checkout_branch(&work_dir, &branch)?;
    let files_written = apply_traci_hardening(&work_dir)?;
    if files_written.is_empty() {
        bail!("nothing to harden: {owner}/{repo} already has traci.toml and a traci CI workflow");
    }
    let committed = governed_commit(&work_dir, owner, repo)?;
    let pushed = committed && push_branch(&work_dir, &branch)?;
    let pr_url = if pushed {
        Some(open_pr(&work_dir, owner, repo, &branch)?)
    } else {
        None
    };

    Ok(RemoteHardenReport {
        owner: owner.to_string(),
        repo: repo.to_string(),
        branch,
        work_dir,
        files_written,
        committed,
        pushed,
        pr_url,
    })
}

fn fork_and_clone(owner: &str, repo: &str, work_dir: &Path) -> Result<()> {
    if work_dir.exists() {
        bail!(
            "work dir {} already exists; pass --work-dir to choose an empty one",
            work_dir.display()
        );
    }
    if let Some(parent) = work_dir.parent() {
        std::fs::create_dir_all(parent).context("create work dir parent")?;
    }
    run(
        Command::new("gh")
            .args([
                "repo",
                "fork",
                &format!("{owner}/{repo}"),
                "--clone",
                "--remote",
            ])
            .arg("--")
            .arg(work_dir),
        "gh repo fork",
    )
}

fn checkout_branch(work_dir: &Path, branch: &str) -> Result<()> {
    run(
        Command::new("git")
            .current_dir(work_dir)
            .args(["checkout", "-b", branch]),
        "git checkout -b",
    )
}

/// Writes the minimum baseline needed for a project to be observably
/// ISO27001-A.8.15/A.8.16 compliant: a `traci.toml` declaring enforcement,
/// and a CI workflow that actually runs it on every change. Never
/// overwrites a file that already exists there — same guarantee
/// `web_assurance::apply` makes for local hardening.
fn apply_traci_hardening(project: &Path) -> Result<Vec<String>> {
    let mut written = Vec::new();

    let traci_toml = project.join("traci.toml");
    if !traci_toml.exists() {
        std::fs::write(&traci_toml, TRACI_TOML_TEMPLATE).context("write traci.toml")?;
        written.push("traci.toml".to_string());
    }

    let workflow_dir = project.join(".github/workflows");
    let workflow_path = workflow_dir.join("traci.yml");
    if !workflow_path.exists() {
        std::fs::create_dir_all(&workflow_dir).context("create .github/workflows")?;
        std::fs::write(&workflow_path, TRACI_WORKFLOW_TEMPLATE)
            .context("write .github/workflows/traci.yml")?;
        written.push(".github/workflows/traci.yml".to_string());
    }

    Ok(written)
}

/// Commit via a kaptaind Aim-of-Change session when the fork has kaptaind
/// configured, so the commit gets a real generated message and an audit
/// trail entry instead of a generic one. Falls back to a plain `git
/// commit` when kaptaind isn't set up for this project — hardening
/// shouldn't be blocked on the target having adopted kaptaind.
fn governed_commit(work_dir: &Path, owner: &str, repo: &str) -> Result<bool> {
    run(
        Command::new("git").current_dir(work_dir).args([
            "add",
            "traci.toml",
            ".github/workflows/traci.yml",
        ]),
        "git add",
    )?;

    let has_kaptaind = work_dir.join("kaptaind.toml").exists();
    if has_kaptaind {
        let intent = format!("isopod harden: ISO27001-A.8.15/A.8.16 logging & monitoring evidence for {owner}/{repo}");
        let started = Command::new("kaptaind-cli")
            .current_dir(work_dir)
            .args(["aoc", "start", &intent])
            .status();
        if matches!(started, Ok(s) if s.success()) {
            let shipped = Command::new("kaptaind-cli")
                .current_dir(work_dir)
                .args(["aoc", "ship"])
                .status();
            if matches!(shipped, Ok(s) if s.success()) {
                return Ok(true);
            }
            tracing::warn!("kaptaind aoc ship failed; falling back to a plain git commit");
        } else {
            tracing::warn!("kaptaind aoc start failed; falling back to a plain git commit");
        }
    }

    run(
        Command::new("git").current_dir(work_dir).args([
            "commit",
            "-m",
            "isopod harden: add traci-enforced ISO27001-A.8.15/A.8.16 logging & monitoring evidence",
        ]),
        "git commit",
    )
    .map(|_| true)
}

fn push_branch(work_dir: &Path, branch: &str) -> Result<bool> {
    run(
        Command::new("git")
            .current_dir(work_dir)
            .args(["push", "-u", "origin", branch]),
        "git push",
    )
    .map(|_| true)
}

fn open_pr(work_dir: &Path, owner: &str, repo: &str, branch: &str) -> Result<String> {
    let body = format!(
        "Adds `traci.toml` and a CI workflow that runs `traci check` on every push/PR, \
         establishing continuous evidence for ISO27001-A.8.15 (Logging) and A.8.16 \
         (Monitoring) rather than a one-off local scan.\n\n\
         Opened automatically by `isopod harden --remote {owner}/{repo}`."
    );
    let output = Command::new("gh")
        .current_dir(work_dir)
        .args([
            "pr",
            "create",
            "--repo",
            &format!("{owner}/{repo}"),
            "--head",
            branch,
            "--title",
            "Add traci-enforced ISO27001-A.8.15/A.8.16 logging & monitoring evidence",
            "--body",
            &body,
        ])
        .output()
        .context("run gh pr create")?;
    if !output.status.success() {
        bail!(
            "gh pr create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run(cmd: &mut Command, label: &str) -> Result<()> {
    let status = cmd.status().with_context(|| format!("run {label}"))?;
    if !status.success() {
        bail!("{label} exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_repo(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        assert!(Command::new("git")
            .current_dir(dir)
            .args(["init", "-q"])
            .status()
            .unwrap()
            .success());
    }

    #[test]
    fn apply_traci_hardening_writes_config_and_workflow_once() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());

        let written = apply_traci_hardening(dir.path()).unwrap();
        assert_eq!(
            written,
            vec![
                "traci.toml".to_string(),
                ".github/workflows/traci.yml".to_string()
            ]
        );
        assert!(dir.path().join("traci.toml").exists());
        assert!(dir.path().join(".github/workflows/traci.yml").exists());

        // Never overwrites: a second pass on an already-hardened project
        // has nothing left to do.
        let written_again = apply_traci_hardening(dir.path()).unwrap();
        assert!(written_again.is_empty());
    }

    #[test]
    fn apply_traci_hardening_respects_existing_traci_toml() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        std::fs::write(dir.path().join("traci.toml"), "# custom, do not touch\n").unwrap();

        let written = apply_traci_hardening(dir.path()).unwrap();
        assert_eq!(written, vec![".github/workflows/traci.yml".to_string()]);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("traci.toml")).unwrap(),
            "# custom, do not touch\n"
        );
    }

    #[test]
    fn governed_commit_falls_back_to_plain_git_without_kaptaind() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        Command::new("git")
            .current_dir(dir.path())
            .args(["config", "user.email", "test@example.com"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["config", "user.name", "test"])
            .status()
            .unwrap();
        apply_traci_hardening(dir.path()).unwrap();

        let committed = governed_commit(dir.path(), "acme", "widgets").unwrap();
        assert!(committed);
        let log = Command::new("git")
            .current_dir(dir.path())
            .args(["log", "--oneline"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&log.stdout).contains("isopod harden"));
    }
}
