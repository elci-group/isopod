// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Web-project assurance: inventory, assess, plan, harden, and verify.
//!
//! The first implementation deliberately limits itself to deterministic,
//! repository-local evidence. Runtime probes can later emit the same evidence
//! and assessment types without changing the planner or reporters.

use crate::runtime::{ProbeStatus, RuntimeProbeReport};
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const SCAN_REPORT: &str = "web-scan.json";
const ASSESSMENT_REPORT: &str = "web-assessment.json";
const PLAN_REPORT: &str = "web-hardening-plan.json";
const RUNTIME_REPORT: &str = "web-runtime.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceState {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotApplicable,
    Unknown,
    UnableToVerify,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebEvidence {
    pub evidence_type: String,
    pub target: String,
    pub observation: String,
    pub provenance: String,
    pub confidence: f32,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebInventory {
    pub project_root: String,
    pub scanned_at: DateTime<Utc>,
    pub project_kind: String,
    pub frameworks: Vec<String>,
    pub manifests: Vec<String>,
    pub lockfiles: Vec<String>,
    pub ci_configuration: Vec<String>,
    pub deployment_configuration: Vec<String>,
    pub evidence: Vec<WebEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAssessment {
    pub id: String,
    pub requirement: String,
    pub applicability: String,
    pub evidence: Vec<WebEvidence>,
    pub confidence: f32,
    pub current_state: AssuranceState,
    pub desired_state: String,
    pub severity: String,
    pub risk: String,
    pub remediation_cost: String,
    pub verification_method: String,
    pub remediation_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentReport {
    pub project_root: String,
    pub assessed_at: DateTime<Utc>,
    pub controls: Vec<WebAssessment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningAction {
    pub id: String,
    pub title: String,
    pub description: String,
    pub phase: String,
    pub severity: String,
    pub leverage: usize,
    pub estimated_minutes: u32,
    pub resolves: Vec<String>,
    pub change: Option<FileChange>,
    pub verification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub operation: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningPlan {
    pub project_root: String,
    pub generated_at: DateTime<Utc>,
    pub actions: Vec<HardeningAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    pub action_id: String,
    pub path: Option<String>,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebVerification {
    pub action_id: String,
    pub status: String,
    pub method: String,
    pub observation: String,
}

pub fn scan(root: &Path) -> anyhow::Result<WebInventory> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let mut manifests = BTreeSet::new();
    let mut lockfiles = BTreeSet::new();
    let mut ci = BTreeSet::new();
    let mut deployment = BTreeSet::new();
    let mut frameworks = BTreeSet::new();

    for entry in WalkDir::new(&root)
        .max_depth(5)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !ignored(e.path(), &root))
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let relative = path
            .strip_prefix(&root)
            .with_context(|| format!("derive project-relative path for {}", path.display()))?;
        let rel = relative.to_string_lossy().replace('\\', "/");
        let name = entry.file_name().to_string_lossy();
        match name.as_ref() {
            "Cargo.toml" | "package.json" | "pyproject.toml" | "requirements.txt" | "go.mod"
            | "Gemfile" => {
                manifests.insert(rel.clone());
            }
            "Cargo.lock" | "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock" | "uv.lock"
            | "poetry.lock" | "go.sum" | "Gemfile.lock" => {
                lockfiles.insert(rel.clone());
            }
            "Dockerfile" | "compose.yaml" | "compose.yml" | "docker-compose.yml" | "Procfile"
            | "fly.toml" | "vercel.json" | "netlify.toml" => {
                deployment.insert(rel.clone());
            }
            _ => {}
        }
        if rel.starts_with(".github/workflows/") || rel == ".gitlab-ci.yml" || rel == "Jenkinsfile"
        {
            ci.insert(rel.clone());
        }
        detect_frameworks(path, &mut frameworks);
    }

    let evidence = vec![
        evidence(
            "source_analysis",
            "project manifests",
            format!("{} manifest(s) found", manifests.len()),
            &root,
            if manifests.is_empty() { 0.6 } else { 0.98 },
        ),
        evidence(
            "source_analysis",
            "dependency lockfiles",
            format!("{} lockfile(s) found", lockfiles.len()),
            &root,
            0.98,
        ),
        evidence(
            "source_analysis",
            "CI configuration",
            format!("{} CI configuration file(s) found", ci.len()),
            &root,
            0.95,
        ),
        evidence(
            "source_analysis",
            "deployment configuration",
            format!(
                "{} deployment configuration file(s) found",
                deployment.len()
            ),
            &root,
            0.9,
        ),
    ];

    let project_kind = if frameworks.is_empty() {
        "web-capability-unknown"
    } else {
        "web-project"
    };
    Ok(WebInventory {
        project_root: root.display().to_string(),
        scanned_at: Utc::now(),
        project_kind: project_kind.to_string(),
        frameworks: frameworks.into_iter().collect(),
        manifests: manifests.into_iter().collect(),
        lockfiles: lockfiles.into_iter().collect(),
        ci_configuration: ci.into_iter().collect(),
        deployment_configuration: deployment.into_iter().collect(),
        evidence,
    })
}

pub fn assess(inventory: &WebInventory) -> AssessmentReport {
    assess_with_runtime(inventory, None)
}

pub fn assess_with_runtime(
    inventory: &WebInventory,
    runtime: Option<&RuntimeProbeReport>,
) -> AssessmentReport {
    let root = Path::new(&inventory.project_root);
    let web_known = !inventory.frameworks.is_empty();
    let runtime = runtime.filter(|report| report.project_root == inventory.project_root);
    let mut controls = Vec::new();
    controls.push(control(
        "WEB-SUPPLY-001",
        "Dependency resolution is locked",
        "Projects with dependency manifests",
        !inventory.manifests.is_empty(),
        !inventory.lockfiles.is_empty(),
        if inventory.manifests.is_empty() {
            AssuranceState::NotApplicable
        } else if inventory.lockfiles.is_empty() {
            AssuranceState::NonCompliant
        } else {
            AssuranceState::Compliant
        },
        "high",
        "Unpinned dependency resolution weakens reproducibility and supply-chain assurance.",
        "medium",
        "Re-scan and confirm a recognised lockfile is committed.",
        None,
        inventory.evidence.get(1).cloned(),
    ));
    controls.push(file_control(
        root,
        "WEB-OPS-001",
        "Automated dependency update policy exists",
        ".github/dependabot.yml",
        "medium",
        "Stale vulnerable dependencies may remain undiscovered.",
        "low",
        "dependabot",
    ));
    controls.push(file_control(
        root,
        "WEB-GOV-001",
        "A vulnerability disclosure policy exists",
        "SECURITY.md",
        "medium",
        "Researchers and users lack a safe, explicit reporting route.",
        "low",
        "security_policy",
    ));
    controls.push(control(
        "WEB-CI-001",
        "A CI pipeline provides build-time assurance",
        "All production web projects",
        true,
        !inventory.ci_configuration.is_empty(),
        if inventory.ci_configuration.is_empty() {
            AssuranceState::PartiallyCompliant
        } else {
            AssuranceState::Compliant
        },
        "medium",
        "Security and compliance regressions may reach production without an automated gate.",
        "medium",
        "Re-scan and confirm recognised CI configuration is present.",
        None,
        inventory.evidence.get(2).cloned(),
    ));
    let header_checks: Vec<_> = runtime
        .into_iter()
        .flat_map(|report| &report.routes)
        .flat_map(|route| &route.checks)
        .filter(|check| check.id.starts_with("HEADER-"))
        .collect();
    let headers_verified = !header_checks.is_empty();
    let headers_compliant = headers_verified
        && header_checks
            .iter()
            .all(|check| check.status == ProbeStatus::Pass);
    let runtime_evidence = runtime.map(|report| WebEvidence {
        evidence_type: "runtime_probe".to_string(),
        target: report.target_origin.clone(),
        observation: format!(
            "{} route(s) probed; runtime status {:?}",
            report.routes.len(),
            report.status
        ),
        provenance: "isopod runtime probe".to_string(),
        confidence: 0.99,
        observed_at: report.completed_at,
    });
    controls.push(control(
        "WEB-HTTP-001",
        "Production responses apply security headers centrally",
        "HTTP-serving applications",
        web_known,
        headers_compliant,
        if headers_compliant {
            AssuranceState::Compliant
        } else if headers_verified {
            AssuranceState::NonCompliant
        } else if web_known {
            AssuranceState::UnableToVerify
        } else {
            // No web framework was detected, so there is no HTTP-serving
            // surface for this control to govern (e.g. a local CLI tool) —
            // that's a scoping fact, not missing evidence. Reporting
            // `Unknown` here previously left every non-web project stuck
            // below isopod's 80% assessment-coverage grading threshold
            // forever, since `Unknown` counts against coverage while
            // `NotApplicable` doesn't.
            AssuranceState::NotApplicable
        },
        "high",
        "Missing or inconsistent headers increase browser-side attack exposure.",
        "medium",
        "Probe representative production routes and assert CSP, HSTS, X-Content-Type-Options, and Referrer-Policy.",
        Some("security_headers"),
        runtime_evidence.clone(),
    ));
    let runtime_state = runtime.map_or_else(
        || {
            if web_known {
                AssuranceState::UnableToVerify
            } else {
                // Same scoping fact as WEB-HTTP-001 above: nothing is
                // deployed to probe when no web framework was detected.
                AssuranceState::NotApplicable
            }
        },
        |report| match report.status {
            ProbeStatus::Pass => AssuranceState::Compliant,
            ProbeStatus::Partial => AssuranceState::PartiallyCompliant,
            ProbeStatus::Fail => AssuranceState::NonCompliant,
            ProbeStatus::UnableToVerify => AssuranceState::UnableToVerify,
        },
    );
    controls.push(control(
        "WEB-RUNTIME-001",
        "The deployed service is independently probed",
        "Deployed web applications",
        web_known,
        runtime.is_some_and(|report| report.status == ProbeStatus::Pass),
        runtime_state,
        "medium",
        "Source configuration alone cannot prove deployed behaviour.",
        "low",
        "Run the runtime scanner against an explicitly authorised target.",
        None,
        runtime_evidence,
    ));
    AssessmentReport {
        project_root: inventory.project_root.clone(),
        assessed_at: Utc::now(),
        controls,
    }
}

pub fn recommend(report: &AssessmentReport) -> HardeningPlan {
    let unresolved = |key: &str| {
        report.controls.iter().any(|c| {
            c.remediation_key.as_deref() == Some(key)
                && c.current_state != AssuranceState::Compliant
                && c.current_state != AssuranceState::NotApplicable
        })
    };
    let mut actions = Vec::new();
    if unresolved("security_policy") {
        actions.push(HardeningAction {
            id: "HARDEN-GOV-001".to_string(),
            title: "Add a vulnerability disclosure policy".to_string(),
            description: "Create a non-destructive SECURITY.md baseline with supported-version and private-reporting guidance.".to_string(),
            phase: "immediate".to_string(),
            severity: "medium".to_string(),
            leverage: 1,
            estimated_minutes: 10,
            resolves: vec!["WEB-GOV-001".to_string()],
            change: Some(FileChange {
                path: "SECURITY.md".to_string(),
                operation: "create_if_missing".to_string(),
                content: security_policy(),
            }),
            verification: "Confirm SECURITY.md exists and contains a vulnerability reporting section.".to_string(),
        });
    }
    if unresolved("dependabot") {
        actions.push(HardeningAction {
            id: "HARDEN-SUPPLY-001".to_string(),
            title: "Enable automated dependency update review".to_string(),
            description: "Create a conservative weekly Dependabot configuration for each detected package ecosystem.".to_string(),
            phase: "immediate".to_string(),
            severity: "medium".to_string(),
            leverage: 2,
            estimated_minutes: 10,
            resolves: vec!["WEB-OPS-001".to_string(), "WEB-SUPPLY-001".to_string()],
            change: Some(FileChange {
                path: ".github/dependabot.yml".to_string(),
                operation: "create_if_missing".to_string(),
                content: dependabot_config(Path::new(&report.project_root)),
            }),
            verification: "Confirm .github/dependabot.yml exists and contains at least one package ecosystem.".to_string(),
        });
    }
    if unresolved("security_headers") {
        actions.push(HardeningAction {
            id: "HARDEN-HTTP-001".to_string(),
            title: "Centralise browser security headers".to_string(),
            description: "Add framework-specific response middleware after confirming the deployed framework and CSP requirements.".to_string(),
            phase: "structural".to_string(),
            severity: "high".to_string(),
            leverage: 4,
            estimated_minutes: 30,
            resolves: vec!["WEB-HTTP-001".to_string()],
            change: None,
            verification: "Probe representative HTTPS routes and validate the required header policy.".to_string(),
        });
    }
    actions.sort_by(|a, b| b.leverage.cmp(&a.leverage).then_with(|| a.id.cmp(&b.id)));
    HardeningPlan {
        project_root: report.project_root.clone(),
        generated_at: Utc::now(),
        actions,
    }
}

pub fn apply(plan: &HardeningPlan) -> Vec<ApplyResult> {
    let root = Path::new(&plan.project_root);
    plan.actions
        .iter()
        .filter_map(|action| {
            let change = action.change.as_ref()?;
            let path = root.join(&change.path);
            if path.exists() {
                return Some(ApplyResult {
                    action_id: action.id.clone(),
                    path: Some(change.path.clone()),
                    status: "skipped".to_string(),
                    detail: "existing file was not overwritten".to_string(),
                });
            }
            let result = path
                .parent()
                .map(std::fs::create_dir_all)
                .transpose()
                .and_then(|_| std::fs::write(&path, &change.content));
            Some(match result {
                Ok(()) => ApplyResult {
                    action_id: action.id.clone(),
                    path: Some(change.path.clone()),
                    status: "applied".to_string(),
                    detail: "file created".to_string(),
                },
                Err(error) => {
                    tracing::error!(
                        action_id = %action.id,
                        path = %change.path,
                        error = %error,
                        "hardening action failed"
                    );
                    ApplyResult {
                        action_id: action.id.clone(),
                        path: Some(change.path.clone()),
                        status: "failed".to_string(),
                        detail: error.to_string(),
                    }
                }
            })
        })
        .collect()
}

pub fn verify(plan: &HardeningPlan) -> Vec<WebVerification> {
    let root = Path::new(&plan.project_root);
    plan.actions
        .iter()
        .map(|action| match &action.change {
            Some(change) => {
                let path = root.join(&change.path);
                let present = path.is_file();
                WebVerification {
                    action_id: action.id.clone(),
                    status: if present { "pass" } else { "fail" }.to_string(),
                    method: action.verification.clone(),
                    observation: if present {
                        format!("{} exists", change.path)
                    } else {
                        format!("{} is missing", change.path)
                    },
                }
            }
            None => WebVerification {
                action_id: action.id.clone(),
                status: "unknown".to_string(),
                method: action.verification.clone(),
                observation: "manual or runtime verification required".to_string(),
            },
        })
        .collect()
}

pub fn write_report<T: Serialize>(
    reports_dir: &Path,
    name: &str,
    value: &T,
) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(reports_dir)?;
    let path = reports_dir.join(name);
    std::fs::write(&path, serde_json::to_vec_pretty(value)?)?;
    Ok(path)
}

pub fn read_inventory(reports_dir: &Path) -> anyhow::Result<WebInventory> {
    Ok(serde_json::from_slice(&std::fs::read(
        reports_dir.join(SCAN_REPORT),
    )?)?)
}

pub fn read_assessment(reports_dir: &Path) -> anyhow::Result<AssessmentReport> {
    Ok(serde_json::from_slice(&std::fs::read(
        reports_dir.join(ASSESSMENT_REPORT),
    )?)?)
}

pub fn read_plan(reports_dir: &Path) -> anyhow::Result<HardeningPlan> {
    Ok(serde_json::from_slice(&std::fs::read(
        reports_dir.join(PLAN_REPORT),
    )?)?)
}

pub fn read_runtime_report(reports_dir: &Path) -> anyhow::Result<RuntimeProbeReport> {
    Ok(serde_json::from_slice(&std::fs::read(
        reports_dir.join(RUNTIME_REPORT),
    )?)?)
}

pub fn read_runtime_report_optional(
    reports_dir: &Path,
) -> anyhow::Result<Option<RuntimeProbeReport>> {
    let path = reports_dir.join(RUNTIME_REPORT);
    if !path.exists() {
        tracing::debug!(path = %path.display(), "runtime report not present");
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&std::fs::read(&path)?)?))
}

pub const fn scan_report_name() -> &'static str {
    SCAN_REPORT
}
pub const fn assessment_report_name() -> &'static str {
    ASSESSMENT_REPORT
}
pub const fn plan_report_name() -> &'static str {
    PLAN_REPORT
}
pub const fn runtime_report_name() -> &'static str {
    RUNTIME_REPORT
}

fn ignored(path: &Path, root: &Path) -> bool {
    if path == root {
        return false;
    }
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        matches!(
            n,
            ".git" | "target" | "node_modules" | ".isopod" | "dist" | "build"
        )
    })
}

fn detect_frameworks(path: &Path, frameworks: &mut BTreeSet<String>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if name == "Cargo.toml" {
        for (needle, framework) in [
            ("axum", "Axum"),
            ("actix-web", "Actix Web"),
            ("rocket", "Rocket"),
        ] {
            if text.contains(needle) {
                frameworks.insert(framework.to_string());
            }
        }
    } else if name == "package.json" {
        for (needle, framework) in [
            ("next", "Next.js"),
            ("express", "Express"),
            ("@nestjs/core", "NestJS"),
            ("vite", "Vite"),
        ] {
            if text.contains(needle) {
                frameworks.insert(framework.to_string());
            }
        }
    } else if matches!(name, "pyproject.toml" | "requirements.txt") {
        for (needle, framework) in [
            ("django", "Django"),
            ("fastapi", "FastAPI"),
            ("flask", "Flask"),
        ] {
            if text.to_lowercase().contains(needle) {
                frameworks.insert(framework.to_string());
            }
        }
    }
}

fn evidence(
    kind: &str,
    target: &str,
    observation: String,
    root: &Path,
    confidence: f32,
) -> WebEvidence {
    WebEvidence {
        evidence_type: kind.to_string(),
        target: target.to_string(),
        observation,
        provenance: root.display().to_string(),
        confidence,
        observed_at: Utc::now(),
    }
}

#[allow(clippy::too_many_arguments)]
fn control(
    id: &str,
    requirement: &str,
    applicability: &str,
    applicable: bool,
    satisfied: bool,
    state: AssuranceState,
    severity: &str,
    risk: &str,
    cost: &str,
    verification: &str,
    remediation_key: Option<&str>,
    evidence: Option<WebEvidence>,
) -> WebAssessment {
    WebAssessment {
        id: id.to_string(),
        requirement: requirement.to_string(),
        applicability: applicability.to_string(),
        evidence: evidence.into_iter().collect(),
        confidence: if !applicable || satisfied { 0.95 } else { 0.7 },
        current_state: state,
        desired_state: "compliant with independently verifiable evidence".to_string(),
        severity: severity.to_string(),
        risk: risk.to_string(),
        remediation_cost: cost.to_string(),
        verification_method: verification.to_string(),
        remediation_key: remediation_key.map(str::to_string),
    }
}

#[allow(clippy::too_many_arguments)]
fn file_control(
    root: &Path,
    id: &str,
    requirement: &str,
    relative: &str,
    severity: &str,
    risk: &str,
    cost: &str,
    key: &str,
) -> WebAssessment {
    let present = root.join(relative).is_file();
    control(
        id,
        requirement,
        "All maintained web projects",
        true,
        present,
        if present {
            AssuranceState::Compliant
        } else {
            AssuranceState::NonCompliant
        },
        severity,
        risk,
        cost,
        &format!("Confirm {relative} exists and is reviewable."),
        Some(key),
        Some(evidence(
            "source_analysis",
            relative,
            if present {
                "file present"
            } else {
                "file absent"
            }
            .to_string(),
            root,
            0.99,
        )),
    )
}

fn security_policy() -> String {
    "# Security Policy\n\n## Supported versions\n\nSecurity fixes are provided for the latest supported release.\n\n## Reporting a vulnerability\n\nPlease report suspected vulnerabilities privately to the project maintainers. Do not open a public issue containing exploit details, credentials, or personal data. Include affected versions, reproduction steps, and potential impact. The maintainers will acknowledge the report and coordinate remediation and disclosure.\n".to_string()
}

fn dependabot_config(root: &Path) -> String {
    let mut ecosystems = Vec::new();
    if root.join("Cargo.toml").is_file() {
        ecosystems.push("cargo");
    }
    if root.join("package.json").is_file() {
        ecosystems.push("npm");
    }
    if root.join("go.mod").is_file() {
        ecosystems.push("gomod");
    }
    if root.join("requirements.txt").is_file() || root.join("pyproject.toml").is_file() {
        ecosystems.push("pip");
    }
    if ecosystems.is_empty() {
        ecosystems.push("github-actions");
    }
    let updates = ecosystems
        .iter()
        .map(|ecosystem| format!("  - package-ecosystem: \"{ecosystem}\"\n    directory: \"/\"\n    schedule:\n      interval: \"weekly\""))
        .collect::<Vec<_>>()
        .join("\n");
    format!("version: 2\nupdates:\n{updates}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_assess_plan_apply_verify_closed_loop() {
        let temp = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            temp.path().join("Cargo.toml"),
            "[dependencies]\naxum = \"0.7\"\n",
        )
        .expect("manifest");
        std::fs::write(temp.path().join("Cargo.lock"), "# lock").expect("lockfile");
        let inventory = scan(temp.path()).expect("scan");
        assert_eq!(inventory.project_kind, "web-project");
        let report = assess(&inventory);
        assert!(report
            .controls
            .iter()
            .any(|c| c.current_state == AssuranceState::UnableToVerify));
        let plan = recommend(&report);
        assert!(plan
            .actions
            .windows(2)
            .all(|w| w[0].leverage >= w[1].leverage));
        let results = apply(&plan);
        assert!(results.iter().any(|r| r.status == "applied"));
        let verified = verify(&plan);
        assert!(verified.iter().any(|r| r.status == "pass"));
        assert!(verified.iter().any(|r| r.status == "unknown"));
    }

    // Regression test: a non-web CLI project (no framework markers) has no
    // HTTP surface and nothing deployed to probe. WEB-HTTP-001 and
    // WEB-RUNTIME-001 must report NotApplicable, not Unknown — Unknown
    // counts against isopod's 80% assessment-coverage grading threshold, so
    // every CLI-only project (e.g. this portfolio's own Rust tools) was
    // permanently ungraded by two controls that could never resolve.
    // Surfaced by running `isopod assess` against oip, a clipboard CLI tool.
    #[test]
    fn non_web_project_marks_http_and_runtime_controls_not_applicable() {
        let temp = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            temp.path().join("Cargo.toml"),
            "[dependencies]\nclap = \"4\"\n",
        )
        .expect("manifest");
        let inventory = scan(temp.path()).expect("scan");
        assert!(inventory.frameworks.is_empty());
        let report = assess(&inventory);
        let state_of = |id: &str| {
            report
                .controls
                .iter()
                .find(|c| c.id == id)
                .map(|c| c.current_state.clone())
        };
        assert_eq!(
            state_of("WEB-HTTP-001"),
            Some(AssuranceState::NotApplicable)
        );
        assert_eq!(
            state_of("WEB-RUNTIME-001"),
            Some(AssuranceState::NotApplicable)
        );
        assert!(!report
            .controls
            .iter()
            .any(|c| c.current_state == AssuranceState::Unknown));
    }

    // Regression test: `recommend()`'s HARDEN-HTTP-001 branch checked only
    // "does a WEB-HTTP-001 control exist", ignoring `current_state` — unlike
    // every other action, which goes through the `unresolved()` helper. That
    // meant a CLI tool with no HTTP framework (see the test above) still got
    // told to "Centralise browser security headers" / "confirm the deployed
    // framework", nonsensical advice for a project with no server at all.
    // Surfaced by running `isopod harden` against verity, a Rust CLI tool.
    #[test]
    fn non_web_project_is_not_recommended_http_hardening() {
        let temp = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            temp.path().join("Cargo.toml"),
            "[dependencies]\nclap = \"4\"\n",
        )
        .expect("manifest");
        let inventory = scan(temp.path()).expect("scan");
        let report = assess(&inventory);
        let plan = recommend(&report);
        assert!(!plan.actions.iter().any(|a| a.id == "HARDEN-HTTP-001"));
    }

    #[test]
    fn apply_never_overwrites_existing_files() {
        let temp = tempfile::tempdir().expect("temp dir");
        std::fs::write(temp.path().join("SECURITY.md"), "custom").expect("policy");
        let plan = HardeningPlan {
            project_root: temp.path().display().to_string(),
            generated_at: Utc::now(),
            actions: vec![HardeningAction {
                id: "test".to_string(),
                title: "test".to_string(),
                description: "test".to_string(),
                phase: "immediate".to_string(),
                severity: "low".to_string(),
                leverage: 1,
                estimated_minutes: 1,
                resolves: vec![],
                change: Some(FileChange {
                    path: "SECURITY.md".to_string(),
                    operation: "create_if_missing".to_string(),
                    content: "replacement".to_string(),
                }),
                verification: "file exists".to_string(),
            }],
        };
        assert_eq!(apply(&plan)[0].status, "skipped");
        assert_eq!(
            std::fs::read_to_string(temp.path().join("SECURITY.md")).expect("read"),
            "custom"
        );
    }
}
