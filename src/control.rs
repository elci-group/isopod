// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Control Engine — declarative YAML packs, deterministic evaluation.
//!
//! Loads `ControlSet` from `controls/*.yaml` and evaluates `ControlResult`
//! per control. See `docs/controls.md` for the pack format and thresholds.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ControlStatus {
    Pass,
    Fail,
    Unknown,
    Warning,
}

impl std::fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::Unknown => write!(f, "UNKNOWN"),
            Self::Warning => write!(f, "WARNING"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub framework: String,
    pub requirements: Vec<String>,
    /// Evidence artifact types accepted for this control. Defaulted so a
    /// pack written before this field existed still parses (degraded: it
    /// will accept no evidence) instead of failing the whole file.
    #[serde(default)]
    pub evidence_types: Vec<String>,
    pub severity_missing: String,
    pub severity_degraded: String,
    pub evaluation_hint: Option<String>,
    /// Optional custom evaluation expression (stored for future engine use).
    #[serde(default)]
    pub evaluation_expr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFile {
    pub framework: String,
    pub version: Option<String>,
    pub controls: Vec<Control>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResult {
    pub id: String,
    pub title: String,
    pub framework: String,
    pub status: ControlStatus,
    pub evidence_count: usize,
    pub confidence: f32,
    pub last_checked: DateTime<Utc>,
    pub reason: Option<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkSummary {
    pub framework: String,
    pub total: usize,
    pub passing: usize,
    pub failing: usize,
    pub warning: usize,
    pub unknown: usize,
    pub score: u8,
}

/// Aggregate control results by framework.
pub fn framework_summary(results: &[ControlResult]) -> Vec<FrameworkSummary> {
    use std::collections::HashMap;
    let mut map: HashMap<String, (usize, usize, usize, usize)> = HashMap::new();
    for r in results {
        let entry = map.entry(r.framework.clone()).or_default();
        match r.status {
            ControlStatus::Pass => entry.0 += 1,
            ControlStatus::Fail => entry.1 += 1,
            ControlStatus::Warning => entry.2 += 1,
            ControlStatus::Unknown => entry.3 += 1,
        }
    }
    let mut out: Vec<FrameworkSummary> = map
        .into_iter()
        .map(|(framework, (passing, failing, warning, unknown))| {
            let total = passing + failing + warning + unknown;
            let score = if total > 0 {
                (passing as f32 / total as f32 * 100.0).round() as u8
            } else {
                0
            };
            FrameworkSummary {
                framework,
                total,
                passing,
                failing,
                warning,
                unknown,
                score,
            }
        })
        .collect();
    out.sort_by(|a, b| a.framework.cmp(&b.framework));
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ControlSet {
    pub controls: Vec<Control>,
    /// Framework → version, populated from control pack files.
    pub versions: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequirementOutcome {
    Met,
    NotMet,
    Unsupported,
}

/// Evaluate a requirement using an explicit registry.
///
/// A requirement without a registered evaluator is never inferred from the
/// mere presence of broadly related evidence. It remains unsupported so the
/// caller can report that the control is unable to be verified.
fn evaluate_requirement(
    req: &str,
    control: &Control,
    evidence: &[crate::evidence::Evidence],
) -> RequirementOutcome {
    const RETENTION_EVIDENCE_COUNT: usize = 2;

    let met = match req {
        "audit_logs_enabled" => Some(evidence.iter().any(|e| {
            e.artifact_type.to_string() == "audit_log"
                && e.metadata
                    .get("audit_logs_present")
                    .and_then(|v| v.as_bool())
                    == Some(true)
        })),
        "logs_retained" => Some(
            evidence
                .iter()
                .filter(|e| e.artifact_type.to_string() == "audit_log")
                .count()
                >= RETENTION_EVIDENCE_COUNT,
        ),
        "encryption_at_rest" => Some(evidence.iter().any(|e| {
            e.artifact_type.to_string() == "encryption_state"
                && e.metadata.get("encrypted_mounts").and_then(|v| v.as_bool()) == Some(true)
        })),
        "certificate_valid" => Some(evidence.iter().any(|e| {
            e.artifact_type.to_string() == "certificate"
                && e.metadata
                    .get("ca_bundle_present")
                    .and_then(|v| v.as_bool())
                    == Some(true)
        })),
        "branch_protection" => Some(evidence.iter().any(|e| {
            e.artifact_type.to_string() == "git_branch_protection"
                && e.metadata.get("protected_hint").and_then(|v| v.as_bool()) == Some(true)
        })),
        "access_reviewed" => Some(
            evidence
                .iter()
                .any(|e| e.artifact_type.to_string() == "access_review"),
        ),
        req if is_registered_metadata_requirement(req) => Some(evidence.iter().any(|e| {
            let allowed = control
                .evidence_types
                .iter()
                .any(|kind| kind == &e.artifact_type.to_string());
            allowed && e.metadata.get(req).and_then(|value| value.as_bool()) == Some(true)
        })),
        _ => None,
    };
    match met {
        Some(true) => RequirementOutcome::Met,
        Some(false) => RequirementOutcome::NotMet,
        None => RequirementOutcome::Unsupported,
    }
}

fn is_registered_metadata_requirement(requirement: &str) -> bool {
    matches!(
        requirement,
        "policy_documented"
            | "policy_approved"
            | "policy_reviewed"
            | "acceptable_use_documented"
            | "handling_procedures"
            | "access_policy_documented"
            | "review_evidence"
            | "release_metadata"
            | "backups_enabled"
            | "backups_tested"
            | "backups_retained"
            | "logs_protected"
            | "access_monitored"
            | "monitoring_enabled"
            | "anomaly_detection"
            | "encryption_in_transit"
            | "security_tests"
            | "acceptance_criteria"
            | "supplier_security"
            | "provenance_tracked"
            | "access_provisioning"
            | "privileged_monitored"
            | "screening_performed"
    )
}

impl ControlSet {
    pub fn from_yaml_str(s: &str) -> anyhow::Result<Self> {
        let file: ControlFile = serde_yaml::from_str(s)?;
        let mut versions = std::collections::HashMap::new();
        if let Some(v) = file.version {
            versions.insert(file.framework.clone(), v);
        }
        Ok(Self {
            controls: file.controls,
            versions,
        })
    }

    pub fn from_yaml_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&text)
    }

    /// Canonical packs shipped inside the binary. Used to self-heal a
    /// `controls_dir` whose on-disk copy is missing or fails to parse (e.g.
    /// a stale provisioning snapshot from before a schema change), so a
    /// broken install degrades to a known-good pack instead of silently
    /// evaluating zero controls.
    fn embedded_packs() -> &'static [(&'static str, &'static str)] {
        &[
            ("iso27001", include_str!("../controls/iso27001.yaml")),
            ("iso27002", include_str!("../controls/iso27002.yaml")),
        ]
    }

    /// Load every `*.yaml`/`*.yml` file in `dir`. A file that fails to parse
    /// is skipped but logged loudly (`tracing::warn!`) — never silently
    /// dropped, since a compliance engine that can't explain why a control
    /// pack disappeared is itself the kind of observability gap ISO27001-A.8.15
    /// and A.8.16 exist to catch.
    pub fn load_dir(dir: &std::path::Path) -> Self {
        let mut out = Vec::new();
        let mut versions = std::collections::HashMap::new();
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().and_then(|e| e.to_str()) == Some("yaml")
                        || p.extension().and_then(|e| e.to_str()) == Some("yml")
                    {
                        match Self::from_yaml_file(&p) {
                            Ok(set) => {
                                out.extend(set.controls);
                                versions.extend(set.versions);
                            }
                            Err(e) => {
                                tracing::error!(
                                    path = %p.display(),
                                    error = %e,
                                    "control pack failed to parse; skipping (0 controls contributed from this file)"
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "controls_dir unreadable");
            }
        }
        Self {
            controls: out,
            versions,
        }
    }

    /// `load_dir`, then self-heal: for each embedded canonical framework
    /// pack that contributed either zero controls from `dir` (missing
    /// file, or a parse failure already logged by `load_dir`) or only
    /// controls with no `evidence_types` (a pre-`evidence_types` snapshot,
    /// which now parses thanks to that field's `#[serde(default)]` but
    /// can never be matched against any evidence — a silent dead pack
    /// that's worse than a loud failure), fall back to the binary-embedded
    /// copy so a stale or absent on-disk pack degrades to a known-good
    /// default instead of a permanent 0-evidence posture. When the on-disk
    /// file exists but was the reason for the fallback, it is rewritten
    /// with the embedded copy so subsequent runs no longer need to heal.
    pub fn load_dir_self_healing(dir: &std::path::Path) -> Self {
        let mut set = Self::load_dir(dir);
        for (framework, text) in Self::embedded_packs() {
            let framework_controls: Vec<_> = set
                .controls
                .iter()
                .filter(|c| &c.framework == framework)
                .collect();
            let healthy = !framework_controls.is_empty()
                && framework_controls
                    .iter()
                    .any(|c| !c.evidence_types.is_empty());
            if healthy {
                continue;
            }
            set.controls.retain(|c| &c.framework != framework);
            match Self::from_yaml_str(text) {
                Ok(fallback) => {
                    tracing::warn!(
                        framework = %framework,
                        dir = %dir.display(),
                        "no valid controls loaded for this framework from controls_dir; \
                         falling back to the embedded canonical pack"
                    );
                    let path = dir.join(format!("{framework}.yaml"));
                    if path.exists() {
                        if let Err(e) = std::fs::write(&path, text) {
                            tracing::warn!(path = %path.display(), error = %e, "failed to self-heal stale control pack on disk");
                        } else {
                            tracing::info!(path = %path.display(), "self-healed stale control pack from embedded copy");
                        }
                    }
                    set.controls.extend(fallback.controls);
                    set.versions.extend(fallback.versions);
                }
                Err(e) => {
                    tracing::error!(framework = %framework, error = %e, "embedded canonical control pack failed to parse; this is a build-time defect");
                }
            }
        }
        set
    }

    pub fn version_for(&self, framework: &str) -> Option<&str> {
        self.versions.get(framework).map(|s| s.as_str())
    }

    /// Evaluate a control given evidence count and simple heuristics.
    /// Real evaluation would inspect evidence content; this provides deterministic
    /// baseline that callers can override.
    pub fn evaluate(
        &self,
        evidence_for_control: &[(String, Vec<crate::evidence::Evidence>)],
    ) -> Vec<ControlResult> {
        let now = Utc::now();
        self.controls
            .iter()
            .map(|c| {
                let evidence = evidence_for_control
                    .iter()
                    .find(|(id, _)| id == &c.id)
                    .map(|(_, v)| v.as_slice())
                    .unwrap_or(&[]);

                // Simple rule engine:
                // - no evidence => UNKNOWN (or FAIL if severity missing high and requirement critical)
                // - confidence avg < 0.5 => FAIL
                // - requirement keywords trigger heuristics
                let status;
                let mut reason = None;
                let mut confidence = 0.0f32;

                if evidence.is_empty() {
                    status = ControlStatus::Unknown;
                    reason = Some("No evidence collected".to_string());
                } else {
                    let avg: f32 =
                        evidence.iter().map(|e| e.confidence).sum::<f32>() / evidence.len() as f32;
                    confidence = avg;
                    // check for stale evidence (> 90 days)
                    let stale_cutoff = now - chrono::Duration::days(90);
                    let stale = evidence.iter().all(|e| e.timestamp < stale_cutoff);
                    if stale {
                        status = ControlStatus::Warning;
                        reason = Some("Evidence stale (>90d)".to_string());
                        confidence *= 0.7;
                    } else if avg < 0.5 {
                        status = ControlStatus::Fail;
                        reason = Some("Confidence below threshold".to_string());
                    } else if avg < 0.75 {
                        status = ControlStatus::Warning;
                        reason = Some("Degraded confidence".to_string());
                    } else {
                        status = ControlStatus::Pass;
                    }
                }

                // Requirement-based evaluation: any unsatisfied keyword forces FAIL.
                let mut unmet_requirements = Vec::new();
                let mut unsupported_requirements = Vec::new();
                if !evidence.is_empty() {
                    for req in &c.requirements {
                        match evaluate_requirement(req, c, evidence) {
                            RequirementOutcome::Met => {}
                            RequirementOutcome::NotMet => unmet_requirements.push(req.as_str()),
                            RequirementOutcome::Unsupported => {
                                unsupported_requirements.push(req.as_str());
                            }
                        }
                    }
                }
                let status = if !unsupported_requirements.is_empty() {
                    reason = Some(format!(
                        "No evaluator registered for requirement(s): {}",
                        unsupported_requirements.join(", ")
                    ));
                    ControlStatus::Unknown
                } else if !unmet_requirements.is_empty() {
                    reason = Some(format!(
                        "Requirement(s) not met: {}",
                        unmet_requirements.join(", ")
                    ));
                    ControlStatus::Fail
                } else {
                    status
                };

                let remediation = match status {
                    ControlStatus::Fail => Some(format!(
                        "Address {} — {} (severity: {})",
                        c.id, c.title, c.severity_missing
                    )),
                    ControlStatus::Warning => Some(format!(
                        "Review {} — {} (severity: {})",
                        c.id, c.title, c.severity_degraded
                    )),
                    ControlStatus::Unknown => {
                        Some(format!("Collect evidence for {} — {}", c.id, c.title))
                    }
                    ControlStatus::Pass => None,
                };

                ControlResult {
                    id: c.id.clone(),
                    title: c.title.clone(),
                    framework: c.framework.clone(),
                    status,
                    evidence_count: evidence.len(),
                    confidence,
                    last_checked: now,
                    reason,
                    remediation,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{ArtifactType, Evidence};

    fn sample_control() -> ControlSet {
        ControlSet {
            controls: vec![Control {
                id: "ISO27001-A.8.15".to_string(),
                title: "Logging".to_string(),
                description: Some("Audit logging".to_string()),
                framework: "iso27001".to_string(),
                requirements: vec![
                    "audit_logs_enabled".to_string(),
                    "logs_retained".to_string(),
                ],
                evidence_types: vec!["audit_log".to_string(), "service_state".to_string()],
                severity_missing: "high".to_string(),
                severity_degraded: "medium".to_string(),
                evaluation_hint: None,
                evaluation_expr: None,
            }],
            versions: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn unknown_without_evidence() {
        let cs = sample_control();
        let res = cs.evaluate(&[]);
        assert_eq!(res[0].status, ControlStatus::Unknown);
    }

    #[test]
    fn pass_with_high_confidence() {
        let cs = sample_control();
        let raw = serde_json::json!({"audit_logs_present": true});
        let mut ev1 = Evidence::new("test", ArtifactType::AuditLog, b"logs1", 0.95)
            .with_control("ISO27001-A.8.15");
        ev1.metadata = raw.clone();
        let mut ev2 = Evidence::new("test2", ArtifactType::AuditLog, b"logs2", 0.95)
            .with_control("ISO27001-A.8.15");
        ev2.metadata = raw;
        let res = cs.evaluate(&[("ISO27001-A.8.15".to_string(), vec![ev1, ev2])]);
        assert_eq!(res[0].status, ControlStatus::Pass);
    }

    #[test]
    fn fail_when_retention_requirement_unmet() {
        let cs = sample_control();
        let raw = serde_json::json!({"audit_logs_present": true});
        let mut ev = Evidence::new("test", ArtifactType::AuditLog, b"logs", 0.95)
            .with_control("ISO27001-A.8.15");
        ev.metadata = raw;
        let res = cs.evaluate(&[("ISO27001-A.8.15".to_string(), vec![ev])]);
        assert_eq!(res[0].status, ControlStatus::Fail);
        assert!(res[0].reason.as_ref().unwrap().contains("logs_retained"));
    }

    #[test]
    fn unknown_requirement_is_never_satisfied_by_unrelated_evidence() {
        let control = Control {
            id: "CUSTOM-1".to_string(),
            title: "Custom".to_string(),
            description: None,
            framework: "custom".to_string(),
            requirements: vec!["unregistered_claim".to_string()],
            evidence_types: vec!["documentation".to_string()],
            severity_missing: "high".to_string(),
            severity_degraded: "medium".to_string(),
            evaluation_hint: None,
            evaluation_expr: None,
        };
        let set = ControlSet {
            controls: vec![control],
            versions: std::collections::HashMap::new(),
        };
        let evidence = Evidence::new("test", ArtifactType::Documentation, b"document", 0.99)
            .with_control("CUSTOM-1");
        let result = set.evaluate(&[("CUSTOM-1".to_string(), vec![evidence])]);
        assert_eq!(result[0].status, ControlStatus::Unknown);
        assert!(result[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("No evaluator registered")));
    }

    #[test]
    fn fail_when_audit_logs_disabled() {
        let cs = sample_control();
        let raw = serde_json::json!({"audit_logs_present": false});
        let mut ev1 = Evidence::new("test", ArtifactType::AuditLog, b"logs1", 0.3)
            .with_control("ISO27001-A.8.15");
        ev1.metadata = raw.clone();
        let mut ev2 = Evidence::new("test2", ArtifactType::AuditLog, b"logs2", 0.3)
            .with_control("ISO27001-A.8.15");
        ev2.metadata = raw;
        let res = cs.evaluate(&[("ISO27001-A.8.15".to_string(), vec![ev1, ev2])]);
        assert_eq!(res[0].status, ControlStatus::Fail);
    }

    #[test]
    fn loads_framework_version() {
        let yaml = r#"
framework: iso27001
version: "2022"
controls: []
"#;
        let cs = ControlSet::from_yaml_str(yaml).unwrap();
        assert_eq!(cs.version_for("iso27001"), Some("2022"));
    }

    #[test]
    fn framework_summary_aggregates_results() {
        let results = vec![
            ControlResult {
                id: "C1".to_string(),
                title: "One".to_string(),
                framework: "iso27001".to_string(),
                status: ControlStatus::Pass,
                evidence_count: 1,
                confidence: 0.9,
                last_checked: Utc::now(),
                reason: None,
                remediation: None,
            },
            ControlResult {
                id: "C2".to_string(),
                title: "Two".to_string(),
                framework: "iso27002".to_string(),
                status: ControlStatus::Fail,
                evidence_count: 0,
                confidence: 0.0,
                last_checked: Utc::now(),
                reason: None,
                remediation: None,
            },
        ];
        let summary = framework_summary(&results);
        assert_eq!(summary.len(), 2);
        let iso27001 = summary.iter().find(|s| s.framework == "iso27001").unwrap();
        assert_eq!(iso27001.passing, 1);
        assert_eq!(iso27001.score, 100);
        let iso27002 = summary.iter().find(|s| s.framework == "iso27002").unwrap();
        assert_eq!(iso27002.failing, 1);
        assert_eq!(iso27002.score, 0);
    }
}
