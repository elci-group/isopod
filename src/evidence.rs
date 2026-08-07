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
        match self {
            Self::Other(s) => write!(f, "{}", s),
            _ => write!(f, "{}", serde_json::to_string(self).unwrap().trim_matches('"')),
        }
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
    pub fn new(source: impl Into<String>, artifact_type: ArtifactType, raw: serde_json::Value) -> Self {
        Self {
            source: source.into(),
            artifact_type,
            raw,
            collected_at: Utc::now(),
            confidence_hint: None,
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
}
