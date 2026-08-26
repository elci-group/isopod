// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Drift Detection — PASS→FAIL transitions with severity scoring.
//! See `docs/controls.md`.

use crate::control::ControlStatus;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvent {
    pub id: String,
    pub control_id: String,
    pub previous: ControlStatus,
    pub current: ControlStatus,
    pub cause: Option<String>,
    pub severity: String,
    pub timestamp: DateTime<Utc>,
}

impl DriftEvent {
    pub fn new(
        control_id: impl Into<String>,
        previous: ControlStatus,
        current: ControlStatus,
        cause: Option<String>,
        severity: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            control_id: control_id.into(),
            previous,
            current,
            cause,
            severity: severity.into(),
            timestamp: Utc::now(),
        }
    }
}

/// Detect drifts by comparing previous and current control results.
pub fn detect(
    previous: &[crate::control::ControlResult],
    current: &[crate::control::ControlResult],
) -> Vec<DriftEvent> {
    let mut out = Vec::new();
    let prev_map: std::collections::HashMap<_, _> =
        previous.iter().map(|r| (r.id.as_str(), r)).collect();
    for curr in current {
        if let Some(prev) = prev_map.get(curr.id.as_str()) {
            if prev.status != curr.status {
                let severity = match (&prev.status, &curr.status) {
                    (ControlStatus::Pass, ControlStatus::Fail) => "HIGH",
                    (ControlStatus::Pass, ControlStatus::Warning) => "MEDIUM",
                    (ControlStatus::Pass, ControlStatus::Unknown) => "MEDIUM",
                    (ControlStatus::Warning, ControlStatus::Fail) => "HIGH",
                    _ => "LOW",
                };
                let cause = curr
                    .reason
                    .clone()
                    .or_else(|| Some(format!("{} -> {}", prev.status, curr.status)));
                out.push(DriftEvent::new(
                    curr.id.clone(),
                    prev.status.clone(),
                    curr.status.clone(),
                    cause,
                    severity,
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{ControlResult, ControlStatus};
    use chrono::Utc;

    fn mk(id: &str, status: ControlStatus) -> ControlResult {
        ControlResult {
            id: id.to_string(),
            title: "t".to_string(),
            framework: "iso27001".to_string(),
            status,
            evidence_count: 1,
            confidence: 0.9,
            last_checked: Utc::now(),
            reason: None,
            remediation: None,
        }
    }

    #[test]
    fn detects_pass_to_fail() {
        let prev = vec![mk("A.1", ControlStatus::Pass)];
        let curr = vec![mk("A.1", ControlStatus::Fail)];
        let drifts = detect(&prev, &curr);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].severity, "HIGH");
    }

    #[test]
    fn no_drift_when_same() {
        let prev = vec![mk("A.1", ControlStatus::Pass)];
        let curr = vec![mk("A.1", ControlStatus::Pass)];
        assert!(detect(&prev, &curr).is_empty());
    }
}
