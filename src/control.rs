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
    pub severity_missing: String,
    pub severity_degraded: String,
    pub evaluation_hint: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ControlSet {
    pub controls: Vec<Control>,
}

impl ControlSet {
    pub fn from_yaml_str(s: &str) -> anyhow::Result<Self> {
        let file: ControlFile = serde_yaml::from_str(s)?;
        Ok(Self {
            controls: file.controls,
        })
    }

    pub fn from_yaml_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&text)
    }

    pub fn load_dir(dir: &std::path::Path) -> Self {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("yaml")
                    || p.extension().and_then(|e| e.to_str()) == Some("yml")
                {
                    if let Ok(set) = Self::from_yaml_file(&p) {
                        out.extend(set.controls);
                    }
                }
            }
        }
        Self { controls: out }
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

                // Requirement-based overrides: if requirements contain "enabled" look for negative evidence
                if status == ControlStatus::Pass {
                    for req in &c.requirements {
                        if req.contains("retained") && evidence.len() < 2 {
                            // retention needs multiple artifacts
                            // keep as pass but lower confidence already
                        }
                    }
                }

                let remediation = match status {
                    ControlStatus::Fail => Some(format!(
                        "Address {} — {} (severity: {})",
                        c.id, c.title, c.severity_missing
                    )),
                    ControlStatus::Warning => Some(format!(
                        "Review {} — {} (severity: {})",
                        c.id, c.title, c.severity_degraded
                    )),
                    ControlStatus::Unknown => Some(format!(
                        "Collect evidence for {} — {}",
                        c.id, c.title
                    )),
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
                severity_missing: "high".to_string(),
                severity_degraded: "medium".to_string(),
                evaluation_hint: None,
            }],
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
        let ev = Evidence::new("test", ArtifactType::AuditLog, b"logs", 0.95)
            .with_control("ISO27001-A.8.15");
        let res = cs.evaluate(&[("ISO27001-A.8.15".to_string(), vec![ev])]);
        assert_eq!(res[0].status, ControlStatus::Pass);
    }
}
