// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Framework-independent assurance primitives.
//!
//! This module is the boundary between organisational reality and framework
//! projections. Collectors produce [`EvidenceClaim`] values, canonical
//! controls consume them, and framework requirements map onto those controls.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How an evidence claim was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceClassification {
    Observed,
    Verified,
    Derived,
    Attested,
    Declared,
    Inferred,
    Unknown,
    Contradicted,
    Stale,
}

/// Formal strength of evidence, ordered from no evidence to trusted attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EvidenceLevel {
    Unknown = 0,
    Declared = 1,
    Documented = 2,
    Derived = 3,
    Observed = 4,
    Verified = 5,
    Attested = 6,
}

impl EvidenceLevel {
    #[must_use]
    pub const fn score(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub fn factor(self) -> f32 {
        f32::from(self.score()) / f32::from(EvidenceLevel::Attested.score())
    }
}

/// Explicit lifecycle and effectiveness state of a canonical control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssuranceControlState {
    NotAssessed,
    Unknown,
    NotApplicable,
    Planned,
    Partial,
    Implemented,
    Effective,
    Failed,
    Expired,
    Exception,
    CompensatingControl,
    Contradicted,
}

impl AssuranceControlState {
    #[must_use]
    pub const fn effectiveness_factor(self) -> f32 {
        match self {
            Self::Effective => 1.0,
            Self::Implemented => 0.8,
            Self::CompensatingControl => 0.65,
            Self::Partial => 0.5,
            Self::Exception => 0.4,
            Self::Planned => 0.2,
            Self::NotAssessed
            | Self::Unknown
            | Self::NotApplicable
            | Self::Failed
            | Self::Expired
            | Self::Contradicted => 0.0,
        }
    }

    #[must_use]
    pub const fn is_assessed(self) -> bool {
        !matches!(self, Self::NotAssessed | Self::Unknown)
    }

    #[must_use]
    pub const fn is_unresolved(self) -> bool {
        matches!(
            self,
            Self::NotAssessed
                | Self::Unknown
                | Self::Planned
                | Self::Partial
                | Self::Failed
                | Self::Expired
                | Self::Exception
                | Self::Contradicted
        )
    }
}

/// A normalized, immutable claim suitable for graph ingestion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceClaim {
    pub evidence_id: String,
    pub source: String,
    pub source_type: String,
    pub collector: String,
    pub timestamp: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub hash: String,
    pub confidence: EvidenceLevel,
    pub provenance: Vec<String>,
    pub scope: String,
    pub subject: String,
    pub claim: String,
    pub raw_value: serde_json::Value,
    pub normalised_value: serde_json::Value,
    pub classification: EvidenceClassification,
    #[serde(default)]
    pub framework_relevance: Vec<String>,
}

impl EvidenceClaim {
    /// Evidence is current only inside its explicit validity window and when it
    /// has not already been classified as stale.
    #[must_use]
    pub fn is_current_at(&self, at: DateTime<Utc>) -> bool {
        self.classification != EvidenceClassification::Stale
            && match self.valid_from {
                Some(start) => at >= start,
                None => true,
            }
            && match self.valid_until {
                Some(end) => at <= end,
                None => true,
            }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MappingStrength {
    Satisfies,
    PartiallySatisfies,
    Supports,
}

/// A contextual mapping, deliberately not represented as one-to-one equivalence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequirementMapping {
    pub framework: String,
    pub requirement: String,
    pub strength: MappingStrength,
    pub rationale: String,
    #[serde(default)]
    pub scope_conditions: Vec<String>,
}

/// The reusable primitive evaluated once and projected into many frameworks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalControl {
    pub id: String,
    pub version: String,
    pub statement: String,
    pub importance: f32,
    pub critical: bool,
    #[serde(default)]
    pub mappings: Vec<RequirementMapping>,
}

impl CanonicalControl {
    /// Return deterministic, de-duplicated framework requirements affected by
    /// this control.
    #[must_use]
    pub fn affected_requirements(&self) -> Vec<String> {
        self.mappings
            .iter()
            .map(|mapping| format!("{}:{}", mapping.framework, mapping.requirement))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FrameworkLifecycle {
    Draft,
    Active,
    Deprecated,
    Superseded,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkManifest {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub license: String,
    pub effective_date: String,
    pub supersedes: Option<String>,
    pub hash: String,
    pub signature: Option<String>,
    pub compatibility: String,
    pub lifecycle: FrameworkLifecycle,
}

impl FrameworkManifest {
    /// Validate install policy without pretending to cryptographically verify
    /// the signature. Signature verification belongs to the registry adapter.
    pub fn validate_for_install(&self, allow_unsigned: bool) -> Result<(), ManifestError> {
        if self.name.trim().is_empty()
            || self.version.trim().is_empty()
            || self.publisher.trim().is_empty()
            || self.license.trim().is_empty()
            || self.compatibility.trim().is_empty()
        {
            return Err(ManifestError::MissingRequiredMetadata);
        }
        if self.hash.len() != 64 || !self.hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ManifestError::InvalidHash);
        }
        let unsigned = match self.signature.as_deref() {
            Some(signature) => signature.is_empty(),
            None => true,
        };
        if !allow_unsigned && unsigned {
            return Err(ManifestError::Unsigned);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    MissingRequiredMetadata,
    InvalidHash,
    Unsigned,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRequiredMetadata => formatter.write_str("missing required metadata"),
            Self::InvalidHash => formatter.write_str("hash must be a 64-character hex digest"),
            Self::Unsigned => formatter.write_str("enterprise framework pack is unsigned"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// A detected disagreement for the same scoped claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceContradiction {
    pub scope: String,
    pub subject: String,
    pub claim: String,
    pub evidence_ids: Vec<String>,
    pub distinct_values: usize,
    pub preferred_evidence_id: Option<String>,
}

/// Detect current evidence values that disagree. The preferred item is only a
/// triage hint based on evidence level; resolving the contradiction remains an
/// explicit assessment decision.
#[must_use]
pub fn detect_contradictions(
    evidence: &[EvidenceClaim],
    at: DateTime<Utc>,
) -> Vec<EvidenceContradiction> {
    let mut grouped: BTreeMap<(&str, &str, &str), Vec<&EvidenceClaim>> = BTreeMap::new();
    for item in evidence.iter().filter(|item| item.is_current_at(at)) {
        grouped
            .entry((&item.scope, &item.subject, &item.claim))
            .or_default()
            .push(item);
    }

    grouped
        .into_iter()
        .filter_map(|((scope, subject, claim), mut items)| {
            items.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
            let values = items
                .iter()
                .map(|item| canonical_json(&item.normalised_value))
                .collect::<BTreeSet<_>>();
            if values.len() < 2 {
                return None;
            }

            let highest = items.iter().map(|item| item.confidence).max()?;
            let strongest = items
                .iter()
                .filter(|item| item.confidence == highest)
                .collect::<Vec<_>>();
            let preferred_evidence_id =
                (strongest.len() == 1).then(|| strongest[0].evidence_id.clone());
            Some(EvidenceContradiction {
                scope: scope.to_owned(),
                subject: subject.to_owned(),
                claim: claim.to_owned(),
                evidence_ids: items
                    .into_iter()
                    .map(|item| item.evidence_id.clone())
                    .collect(),
                distinct_values: values.len(),
                preferred_evidence_id,
            })
        })
        .collect()
}

/// Return stale or expired evidence in stable identifier order.
#[must_use]
pub fn stale_evidence(evidence: &[EvidenceClaim], at: DateTime<Utc>) -> Vec<String> {
    let mut ids = evidence
        .iter()
        .filter(|item| !item.is_current_at(at))
        .map(|item| item.evidence_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlAssessment {
    pub control_id: String,
    pub state: AssuranceControlState,
    pub importance: f32,
    pub evidence_level: EvidenceLevel,
    pub effectiveness: f32,
    pub freshness: f32,
    pub critical: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureReport {
    /// `None` means there is no assessable control population.
    pub score: Option<u8>,
    pub coverage: u8,
    pub evidence_confidence: u8,
    pub critical_unresolved: bool,
    pub total_controls: usize,
    pub assessed_controls: usize,
    pub unknown_controls: usize,
    pub not_applicable_controls: usize,
}

/// Calculate a weighted posture without allowing unknown controls or weak
/// evidence to count as success. Any unresolved critical control caps the
/// aggregate score so a healthy-looking average cannot hide a blocker.
#[must_use]
pub fn calculate_posture(assessments: &[ControlAssessment]) -> PostureReport {
    let relevant = assessments
        .iter()
        .filter(|item| item.state != AssuranceControlState::NotApplicable)
        .collect::<Vec<_>>();
    let total_weight = relevant
        .iter()
        .map(|item| item.importance.clamp(0.0, 1.0))
        .sum::<f32>();
    let earned = relevant
        .iter()
        .map(|item| {
            item.importance.clamp(0.0, 1.0)
                * item.state.effectiveness_factor()
                * item.evidence_level.factor()
                * item.effectiveness.clamp(0.0, 1.0)
                * item.freshness.clamp(0.0, 1.0)
        })
        .sum::<f32>();
    let assessed_controls = relevant
        .iter()
        .filter(|item| item.state.is_assessed())
        .count();
    let critical_unresolved = relevant
        .iter()
        .any(|item| item.critical && item.state.is_unresolved());
    let mut score = (total_weight > 0.0).then(|| percent(earned / total_weight));
    if critical_unresolved {
        score = score.map(|value| value.min(59));
    }
    let evidence_confidence = if total_weight > 0.0 {
        let confidence = relevant
            .iter()
            .map(|item| item.importance.clamp(0.0, 1.0) * item.evidence_level.factor())
            .sum::<f32>();
        percent(confidence / total_weight)
    } else {
        0
    };

    PostureReport {
        score,
        coverage: if relevant.is_empty() {
            0
        } else {
            percent(assessed_controls as f32 / relevant.len() as f32)
        },
        evidence_confidence,
        critical_unresolved,
        total_controls: assessments.len(),
        assessed_controls,
        unknown_controls: relevant
            .iter()
            .filter(|item| {
                matches!(
                    item.state,
                    AssuranceControlState::Unknown | AssuranceControlState::NotAssessed
                )
            })
            .count(),
        not_applicable_controls: assessments
            .iter()
            .filter(|item| item.state == AssuranceControlState::NotApplicable)
            .count(),
    }
}

/// Resolve memorable profile names without treating them as separate engines.
#[must_use]
pub fn canonical_framework_id(value: &str) -> &str {
    match value {
        "fort" => "soc2",
        "citadel" => "iso27001",
        "compass" => "nist-csf",
        "cardwall" => "pci-dss",
        "arsenal" => "nist-800-53",
        "hedge" => "cyber-essentials",
        "aegis" => "iso42001",
        other => other,
    }
}

fn percent(value: f32) -> u8 {
    (value.clamp(0.0, 1.0) * 100.0).round() as u8
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let sorted = map
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json(value)))
                .collect::<BTreeMap<_, _>>();
            serde_json::to_string(&sorted).unwrap_or_default()
        }
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 10, hour, 0, 0)
            .single()
            .expect("valid fixture timestamp")
    }

    fn claim(id: &str, value: serde_json::Value, level: EvidenceLevel) -> EvidenceClaim {
        EvidenceClaim {
            evidence_id: id.to_owned(),
            source: "fixture".to_owned(),
            source_type: "identity_provider".to_owned(),
            collector: "isopod-fixture".to_owned(),
            timestamp: at(8),
            observed_at: at(8),
            valid_from: None,
            valid_until: Some(at(10)),
            hash: "a".repeat(64),
            confidence: level,
            provenance: vec!["fixture://identity/roles/admin".to_owned()],
            scope: "tenant/acme/production".to_owned(),
            subject: "role/admin".to_owned(),
            claim: "mfa_required".to_owned(),
            raw_value: value.clone(),
            normalised_value: value,
            classification: EvidenceClassification::Observed,
            framework_relevance: vec!["soc2".to_owned(), "iso27001".to_owned()],
        }
    }

    #[test]
    fn contradiction_is_explicit_and_deterministic() {
        let declared = claim(
            "E-DECLARED",
            serde_json::json!(true),
            EvidenceLevel::Declared,
        );
        let observed = claim(
            "E-OBSERVED",
            serde_json::json!(false),
            EvidenceLevel::Observed,
        );
        let conflicts = detect_contradictions(&[observed, declared], at(9));
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].evidence_ids, vec!["E-DECLARED", "E-OBSERVED"]);
        assert_eq!(
            conflicts[0].preferred_evidence_id.as_deref(),
            Some("E-OBSERVED")
        );
    }

    #[test]
    fn identical_values_do_not_conflict() {
        let left = claim(
            "E-1",
            serde_json::json!({"required": true}),
            EvidenceLevel::Observed,
        );
        let right = claim(
            "E-2",
            serde_json::json!({"required": true}),
            EvidenceLevel::Verified,
        );
        assert!(detect_contradictions(&[left, right], at(9)).is_empty());
    }

    #[test]
    fn expired_evidence_is_stale_and_not_used_for_conflicts() {
        let expired = claim("E-OLD", serde_json::json!(false), EvidenceLevel::Verified);
        let current = claim("E-NEW", serde_json::json!(true), EvidenceLevel::Observed);
        assert_eq!(
            stale_evidence(std::slice::from_ref(&expired), at(11)),
            vec!["E-OLD"]
        );
        assert!(detect_contradictions(&[expired, current], at(11)).is_empty());
    }

    #[test]
    fn critical_unknown_caps_posture_and_reduces_coverage() {
        let report = calculate_posture(&[
            ControlAssessment {
                control_id: "identity-mfa".to_owned(),
                state: AssuranceControlState::Unknown,
                importance: 1.0,
                evidence_level: EvidenceLevel::Unknown,
                effectiveness: 0.0,
                freshness: 0.0,
                critical: true,
            },
            ControlAssessment {
                control_id: "logging".to_owned(),
                state: AssuranceControlState::Effective,
                importance: 1.0,
                evidence_level: EvidenceLevel::Attested,
                effectiveness: 1.0,
                freshness: 1.0,
                critical: false,
            },
        ]);
        assert_eq!(report.score, Some(50));
        assert_eq!(report.coverage, 50);
        assert!(report.critical_unresolved);
    }

    #[test]
    fn no_assessable_controls_is_ungraded() {
        let report = calculate_posture(&[ControlAssessment {
            control_id: "out-of-scope".to_owned(),
            state: AssuranceControlState::NotApplicable,
            importance: 1.0,
            evidence_level: EvidenceLevel::Unknown,
            effectiveness: 0.0,
            freshness: 0.0,
            critical: false,
        }]);
        assert_eq!(report.score, None);
        assert_eq!(report.coverage, 0);
    }

    #[test]
    fn canonical_control_reuses_one_control_across_frameworks() {
        let control = CanonicalControl {
            id: "identity-mfa".to_owned(),
            version: "1.0.0".to_owned(),
            statement: "Privileged identities require phishing-resistant MFA".to_owned(),
            importance: 1.0,
            critical: true,
            mappings: vec![
                RequirementMapping {
                    framework: "soc2".to_owned(),
                    requirement: "CC6.1".to_owned(),
                    strength: MappingStrength::Supports,
                    rationale: "Privileged access restriction".to_owned(),
                    scope_conditions: Vec::new(),
                },
                RequirementMapping {
                    framework: "iso27001".to_owned(),
                    requirement: "A.5.17".to_owned(),
                    strength: MappingStrength::PartiallySatisfies,
                    rationale: "Authentication information protection".to_owned(),
                    scope_conditions: Vec::new(),
                },
            ],
        };
        assert_eq!(
            control.affected_requirements(),
            vec!["iso27001:A.5.17", "soc2:CC6.1"]
        );
    }

    #[test]
    fn unsigned_enterprise_pack_is_rejected_by_default() {
        let manifest = FrameworkManifest {
            name: "soc2".to_owned(),
            version: "2026.1".to_owned(),
            publisher: "example".to_owned(),
            license: "proprietary".to_owned(),
            effective_date: "2026-01-01".to_owned(),
            supersedes: None,
            hash: "a".repeat(64),
            signature: None,
            compatibility: ">=0.3".to_owned(),
            lifecycle: FrameworkLifecycle::Active,
        };
        assert_eq!(
            manifest.validate_for_install(false),
            Err(ManifestError::Unsigned)
        );
        assert!(manifest.validate_for_install(true).is_ok());
    }

    #[test]
    fn framework_aliases_are_metadata_not_binaries() {
        assert_eq!(canonical_framework_id("fort"), "soc2");
        assert_eq!(canonical_framework_id("aegis"), "iso42001");
        assert_eq!(canonical_framework_id("gdpr"), "gdpr");
    }
}
