//! Remediation — Advisory / Assisted / Autonomous playbooks.
//! See `docs/controls.md`.

use crate::control::ControlResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RemediationMode {
    Advisory,
    Assisted,
    Autonomous,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub control_id: String,
    pub mode: RemediationMode,
    pub title: String,
    pub description: String,
    pub actions: Vec<String>,
    pub severity: String,
}

impl RemediationMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "assisted" => Self::Assisted,
            "autonomous" => Self::Autonomous,
            _ => Self::Advisory,
        }
    }
}

pub fn for_result(result: &ControlResult, mode: RemediationMode) -> Option<Remediation> {
    if result.status == crate::control::ControlStatus::Pass {
        return None;
    }
    let severity = match result.status {
        crate::control::ControlStatus::Fail => "high",
        crate::control::ControlStatus::Warning => "medium",
        crate::control::ControlStatus::Unknown => "medium",
        crate::control::ControlStatus::Pass => "low",
    }
    .to_string();

    let (title, description, actions) = match result.id.as_str() {
        id if id.contains("A.8.15") => (
            "Enable and verify audit logging".to_string(),
            "Audit logs missing or degraded — enable centralised logging, verify retention, and restrict access.".to_string(),
            vec![
                "Ensure auditd / cloud audit logs enabled".to_string(),
                "Configure log retention >= 1 year".to_string(),
                "Enable log integrity monitoring".to_string(),
            ],
        ),
        id if id.contains("A.9.2") => (
            "Access review overdue".to_string(),
            "No access review recorded in required window — schedule review and revoke stale grants.".to_string(),
            vec![
                "Run access review for all privileged roles".to_string(),
                "Revoke inactive accounts".to_string(),
                "Enable periodic review automation".to_string(),
            ],
        ),
        _ => (
            format!("Remediate {}", result.id),
            result
                .reason
                .clone()
                .unwrap_or_else(|| "Control not satisfied".to_string()),
            vec![result
                .remediation
                .clone()
                .unwrap_or_else(|| "Collect required evidence".to_string())],
        ),
    };

    let mut remediation = Remediation {
        control_id: result.id.clone(),
        mode: mode.clone(),
        title,
        description,
        actions: actions.clone(),
        severity,
    };

    // Mode-specific augmentation
    match mode {
        RemediationMode::Assisted => {
            remediation.actions.push("Create pull request / ticket (assisted)".to_string());
        }
        RemediationMode::Autonomous => {
            remediation
                .actions
                .push("Execute approved remediation workflow (autonomous)".to_string());
        }
        RemediationMode::Advisory => {}
    }

    Some(remediation)
}

pub fn for_results(
    results: &[ControlResult],
    mode: RemediationMode,
) -> Vec<Remediation> {
    results
        .iter()
        .filter_map(|r| for_result(r, mode.clone()))
        .collect()
}
