// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Evidence Engine — immutable, hash-verified artifacts.
//!
//! Every compliance claim maps to an `Evidence` record. Observations from
//! observers are normalized into `Evidence` with SHA-256 hashing, timestamps,
//! and confidence scores. See `docs/evidence.md` for the lifecycle.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Immutable evidence record — every compliance claim maps to this.
/// See `docs/evidence.md` for the full lifecycle and tamper detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub artifact_type: ArtifactType,
    pub content_hash: String,
    pub confidence: f32,
    /// Optional content preview / path
    pub artifact_path: Option<String>,
    pub control_id: Option<String>,
    pub provenance: Option<String>,
    pub metadata: serde_json::Value,
    /// ID of the previous evidence record for the same control/source, if any.
    pub previous_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    GitCommit,
    GitBranchProtection,
    SystemPatch,
    ServiceState,
    FilePermission,
    NetworkExposure,
    EncryptionState,
    BackupRecord,
    AccessReview,
    AuditLog,
    DeploymentHistory,
    Certificate,
    Documentation,
    TraciTrace,
    DreamseqHistory,
    JeenomeBehaviour,
    KaptaindRelease,
    HellhoundHealth,
    DeliverMilestone,
    Other(String),
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::GitCommit => "git_commit",
            Self::GitBranchProtection => "git_branch_protection",
            Self::SystemPatch => "system_patch",
            Self::ServiceState => "service_state",
            Self::FilePermission => "file_permission",
            Self::NetworkExposure => "network_exposure",
            Self::EncryptionState => "encryption_state",
            Self::BackupRecord => "backup_record",
            Self::AccessReview => "access_review",
            Self::AuditLog => "audit_log",
            Self::DeploymentHistory => "deployment_history",
            Self::Certificate => "certificate",
            Self::Documentation => "documentation",
            Self::TraciTrace => "traci_trace",
            Self::DreamseqHistory => "dreamseq_history",
            Self::JeenomeBehaviour => "jeenome_behaviour",
            Self::KaptaindRelease => "kaptaind_release",
            Self::HellhoundHealth => "hellhound_health",
            Self::DeliverMilestone => "deliver_milestone",
            Self::Other(name) => name,
        };
        f.write_str(name)
    }
}

impl Evidence {
    pub fn new(
        source: impl Into<String>,
        artifact_type: ArtifactType,
        content: &[u8],
        confidence: f32,
    ) -> Self {
        let hash = hash_bytes(content);
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source: source.into(),
            timestamp: Utc::now(),
            artifact_type,
            content_hash: hash,
            confidence: confidence.clamp(0.0, 1.0),
            artifact_path: None,
            control_id: None,
            provenance: None,
            metadata: serde_json::Value::Null,
            previous_id: None,
        }
    }

    pub fn with_control(mut self, control_id: impl Into<String>) -> Self {
        self.control_id = Some(control_id.into());
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.artifact_path = Some(path.into());
        self
    }

    pub fn with_previous_id(mut self, previous_id: impl Into<String>) -> Self {
        self.previous_id = Some(previous_id.into());
        self
    }
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(hasher.finalize())
}

pub fn hash_str(s: &str) -> String {
    hash_bytes(s.as_bytes())
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Normalizer pipeline: Observation -> Evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub source: String,
    pub artifact_type: ArtifactType,
    pub raw: serde_json::Value,
    pub collected_at: DateTime<Utc>,
    pub confidence_hint: Option<f32>,
}

impl Observation {
    pub fn new(
        source: impl Into<String>,
        artifact_type: ArtifactType,
        raw: serde_json::Value,
    ) -> Self {
        Self {
            source: source.into(),
            artifact_type,
            raw,
            collected_at: Utc::now(),
            confidence_hint: None,
        }
    }

    /// Derive a confidence score from the observation's own content.
    /// Returns a value in the 0.0–1.0 range.
    pub fn score_confidence(&self) -> f32 {
        match self.artifact_type {
            ArtifactType::AuditLog => {
                if self.raw.get("audit_logs_present").and_then(|v| v.as_bool()) == Some(true) {
                    0.92
                } else {
                    0.3
                }
            }
            ArtifactType::ServiceState => match self.raw.get("active").and_then(|v| v.as_bool()) {
                Some(true) => 0.9,
                Some(false) => 0.2,
                None => 0.5,
            },
            ArtifactType::GitBranchProtection => {
                if self.raw.get("protected_hint").and_then(|v| v.as_bool()) == Some(true) {
                    0.9
                } else {
                    0.4
                }
            }
            ArtifactType::EncryptionState => {
                if self.raw.get("encrypted_mounts").and_then(|v| v.as_bool()) == Some(true) {
                    0.9
                } else {
                    0.5
                }
            }
            ArtifactType::FilePermission => {
                if let Some(mode) = self.raw.get("mode").and_then(|v| v.as_str()) {
                    // mode is an octal string like "644"
                    if u32::from_str_radix(mode.trim_start_matches("0o"), 8).unwrap_or(0o777)
                        <= 0o644
                    {
                        0.9
                    } else {
                        0.5
                    }
                } else {
                    0.5
                }
            }
            ArtifactType::Certificate => {
                if self.raw.get("ca_bundle_present").and_then(|v| v.as_bool()) == Some(true) {
                    0.9
                } else {
                    0.3
                }
            }
            ArtifactType::SystemPatch => match self.raw.get("hint").and_then(|v| v.as_str()) {
                Some("package_manager_logs_found") => 0.85,
                _ => 0.5,
            },
            ArtifactType::GitCommit | ArtifactType::DeploymentHistory => {
                let count = self
                    .raw
                    .get("recent_commits")
                    .or_else(|| self.raw.get("merges"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if count >= 5 {
                    0.88
                } else if count >= 1 {
                    0.7
                } else {
                    0.4
                }
            }
            ArtifactType::TraciTrace
            | ArtifactType::DreamseqHistory
            | ArtifactType::JeenomeBehaviour
            | ArtifactType::KaptaindRelease
            | ArtifactType::HellhoundHealth
            | ArtifactType::DeliverMilestone => 0.85,
            _ => 0.7,
        }
    }

    pub fn into_evidence(self, confidence: f32) -> Evidence {
        let bytes = serde_json::to_vec(&self.raw).unwrap_or_default();
        let mut ev = Evidence::new(self.source, self.artifact_type, &bytes, confidence);
        ev.timestamp = self.collected_at;
        ev.metadata = self.raw;
        ev
    }
}

/// Result of verifying an evidence record against its artifact file and sidecar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationStatus {
    Ok,
    Missing,
    Mismatch,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Missing => write!(f, "MISSING"),
            Self::Mismatch => write!(f, "MISMATCH"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub id: String,
    pub status: VerificationStatus,
    pub expected: String,
    pub actual: Option<String>,
    pub artifact_path: Option<String>,
}

/// Verify a single evidence record by re-hashing its artifact file.
pub fn verify_evidence(ev: &Evidence, evidence_dir: &std::path::Path) -> VerificationResult {
    let artifact_rel = ev
        .artifact_path
        .clone()
        .unwrap_or_else(|| format!("artifacts/{}.json", ev.id));
    let artifact_path = evidence_dir.join(&artifact_rel);
    if !artifact_path.exists() {
        return VerificationResult {
            id: ev.id.clone(),
            status: VerificationStatus::Missing,
            expected: ev.content_hash.clone(),
            actual: None,
            artifact_path: Some(artifact_rel),
        };
    }
    let actual = match std::fs::read(&artifact_path) {
        Ok(bytes) => hash_bytes(&bytes),
        Err(error) => {
            tracing::warn!(
                evidence_id = %ev.id,
                path = %artifact_path.display(),
                error = %error,
                "evidence artifact could not be read"
            );
            return VerificationResult {
                id: ev.id.clone(),
                status: VerificationStatus::Missing,
                expected: ev.content_hash.clone(),
                actual: None,
                artifact_path: Some(artifact_rel),
            };
        }
    };
    let status = if actual == ev.content_hash {
        VerificationStatus::Ok
    } else {
        VerificationStatus::Mismatch
    };
    VerificationResult {
        id: ev.id.clone(),
        status,
        expected: ev.content_hash.clone(),
        actual: Some(actual),
        artifact_path: Some(artifact_rel),
    }
}

/// In-memory evidence store trait; persistent impl lives in store.rs
pub trait EvidenceStore: Send + Sync {
    fn insert(&self, evidence: &Evidence) -> anyhow::Result<()>;
    fn list(&self, control_id: Option<&str>, limit: usize) -> anyhow::Result<Vec<Evidence>>;
    fn count(&self) -> anyhow::Result<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_deterministic() {
        assert_eq!(hash_str("hello"), hash_str("hello"));
        assert_ne!(hash_str("hello"), hash_str("world"));
    }

    #[test]
    fn evidence_confidence_clamped() {
        let e = Evidence::new("test", ArtifactType::AuditLog, b"data", 2.0);
        assert_eq!(e.confidence, 1.0);
        let e2 = Evidence::new("test", ArtifactType::AuditLog, b"data", -1.0);
        assert_eq!(e2.confidence, 0.0);
    }

    #[test]
    fn verify_ok_when_artifact_matches() {
        let dir = std::env::temp_dir().join(format!("isopod-verify-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("artifacts")).unwrap();
        let raw = serde_json::json!({"audit_logs_present": true});
        let obs = Observation::new("test", ArtifactType::AuditLog, raw);
        let ev = obs
            .into_evidence(0.9)
            .with_path(format!("artifacts/{}.json", uuid::Uuid::new_v4()));
        let artifact_path = dir.join(ev.artifact_path.as_ref().unwrap());
        std::fs::write(&artifact_path, ev.metadata.to_string()).unwrap();
        let res = verify_evidence(&ev, &dir);
        assert_eq!(res.status, VerificationStatus::Ok);
        assert_eq!(res.actual, Some(ev.content_hash));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_missing_when_artifact_absent() {
        let dir = std::env::temp_dir().join(format!("isopod-verify-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let ev = Evidence::new("test", ArtifactType::AuditLog, b"data", 0.9);
        let res = verify_evidence(&ev, &dir);
        assert_eq!(res.status, VerificationStatus::Missing);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn confidence_scoring_covers_supported_artifacts() {
        let cases = [
            (
                ArtifactType::AuditLog,
                serde_json::json!({"audit_logs_present": true}),
                0.92,
            ),
            (ArtifactType::AuditLog, serde_json::json!({}), 0.3),
            (
                ArtifactType::ServiceState,
                serde_json::json!({"active": true}),
                0.9,
            ),
            (
                ArtifactType::ServiceState,
                serde_json::json!({"active": false}),
                0.2,
            ),
            (ArtifactType::ServiceState, serde_json::json!({}), 0.5),
            (
                ArtifactType::GitBranchProtection,
                serde_json::json!({"protected_hint": true}),
                0.9,
            ),
            (
                ArtifactType::EncryptionState,
                serde_json::json!({"encrypted_mounts": true}),
                0.9,
            ),
            (
                ArtifactType::FilePermission,
                serde_json::json!({"mode": "600"}),
                0.9,
            ),
            (
                ArtifactType::FilePermission,
                serde_json::json!({"mode": "777"}),
                0.5,
            ),
            (
                ArtifactType::Certificate,
                serde_json::json!({"ca_bundle_present": true}),
                0.9,
            ),
            (
                ArtifactType::SystemPatch,
                serde_json::json!({"hint": "package_manager_logs_found"}),
                0.85,
            ),
            (
                ArtifactType::GitCommit,
                serde_json::json!({"recent_commits": 5}),
                0.88,
            ),
            (
                ArtifactType::GitCommit,
                serde_json::json!({"recent_commits": 1}),
                0.7,
            ),
            (ArtifactType::GitCommit, serde_json::json!({}), 0.4),
            (ArtifactType::TraciTrace, serde_json::json!({}), 0.85),
            (ArtifactType::Documentation, serde_json::json!({}), 0.7),
        ];
        for (artifact_type, raw, expected) in cases {
            let observation = Observation::new("test", artifact_type, raw);
            assert!(
                (observation.score_confidence() - expected).abs() < 0.0001,
                "unexpected score for {:?}",
                observation.artifact_type
            );
        }
    }

    #[test]
    fn evidence_builders_and_artifact_names_are_stable() {
        let evidence = Evidence::new("source", ArtifactType::Other("custom".into()), b"x", 0.5)
            .with_control("CTRL-1")
            .with_path("artifacts/x.json")
            .with_previous_id("previous");
        assert_eq!(evidence.control_id.as_deref(), Some("CTRL-1"));
        assert_eq!(evidence.previous_id.as_deref(), Some("previous"));
        assert_eq!(evidence.artifact_type.to_string(), "custom");
        assert_eq!(VerificationStatus::Ok.to_string(), "OK");
        assert_eq!(VerificationStatus::Mismatch.to_string(), "MISMATCH");
    }

    #[test]
    fn verification_detects_modified_artifact() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("artifacts")).unwrap();
        let evidence = Evidence::new("test", ArtifactType::AuditLog, b"expected", 0.9)
            .with_path("artifacts/changed.json");
        std::fs::write(dir.path().join("artifacts/changed.json"), b"changed").unwrap();
        let result = verify_evidence(&evidence, dir.path());
        assert_eq!(result.status, VerificationStatus::Mismatch);
        assert!(result.actual.is_some());
    }
}
