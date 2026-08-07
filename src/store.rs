use crate::evidence::{ArtifactType, Evidence};
use anyhow::Context;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let s = Self {
            conn: Mutex::new(conn),
        };
        s.migrate()?;
        Ok(s)
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let s = Self {
            conn: Mutex::new(conn),
        };
        s.migrate()?;
        Ok(s)
    }

    fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                confidence REAL NOT NULL,
                artifact_path TEXT,
                control_id TEXT,
                provenance TEXT,
                metadata TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_control ON evidence(control_id);
            CREATE INDEX IF NOT EXISTS idx_evidence_time ON evidence(timestamp);
            CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence(content_hash);

            CREATE TABLE IF NOT EXISTS control_results (
                id TEXT PRIMARY KEY,
                framework TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence_count INTEGER NOT NULL,
                confidence REAL NOT NULL,
                last_checked TEXT NOT NULL,
                reason TEXT,
                remediation TEXT
            );

            CREATE TABLE IF NOT EXISTS drift_events (
                id TEXT PRIMARY KEY,
                control_id TEXT NOT NULL,
                previous TEXT NOT NULL,
                current TEXT NOT NULL,
                cause TEXT,
                severity TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    pub fn insert_evidence(&self, ev: &Evidence) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO evidence (id, source, timestamp, artifact_type, content_hash, confidence, artifact_path, control_id, provenance, metadata) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                ev.id,
                ev.source,
                ev.timestamp.to_rfc3339(),
                serde_json::to_string(&ev.artifact_type).unwrap(),
                ev.content_hash,
                ev.confidence,
                ev.artifact_path,
                ev.control_id,
                ev.provenance,
                serde_json::to_string(&ev.metadata).unwrap(),
            ],
        ).context("insert evidence")?;
        // also write hash file if state dir available (best-effort)
        Ok(())
    }

    pub fn list_evidence(
        &self,
        control_id: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Evidence>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = if control_id.is_some() {
            conn.prepare("SELECT id, source, timestamp, artifact_type, content_hash, confidence, artifact_path, control_id, provenance, metadata FROM evidence WHERE control_id = ?1 ORDER BY timestamp DESC LIMIT ?2")?
        } else {
            conn.prepare("SELECT id, source, timestamp, artifact_type, content_hash, confidence, artifact_path, control_id, provenance, metadata FROM evidence ORDER BY timestamp DESC LIMIT ?1")?
        };

        let rows = if let Some(cid) = control_id {
            stmt.query_map(params![cid, limit as i64], row_to_evidence)?
        } else {
            stmt.query_map(params![limit as i64], row_to_evidence)?
        };

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn count_evidence(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM evidence", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    pub fn evidence_by_control(&self) -> anyhow::Result<Vec<(String, Vec<Evidence>)>> {
        let all = self.list_evidence(None, 100_000)?;
        let mut map: std::collections::HashMap<String, Vec<Evidence>> = std::collections::HashMap::new();
        for ev in all {
            if let Some(cid) = ev.control_id.clone() {
                map.entry(cid).or_default().push(ev);
            }
        }
        Ok(map.into_iter().collect())
    }

    pub fn upsert_control_result(&self, r: &crate::control::ControlResult) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO control_results (id, framework, title, status, evidence_count, confidence, last_checked, reason, remediation) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                r.id,
                r.framework,
                r.title,
                r.status.to_string(),
                r.evidence_count as i64,
                r.confidence,
                r.last_checked.to_rfc3339(),
                r.reason,
                r.remediation,
            ],
        )?;
        Ok(())
    }

    pub fn list_control_results(&self) -> anyhow::Result<Vec<crate::control::ControlResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, framework, title, status, evidence_count, confidence, last_checked, reason, remediation FROM control_results ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            let status_s: String = row.get(3)?;
            let status = match status_s.as_str() {
                "PASS" => crate::control::ControlStatus::Pass,
                "FAIL" => crate::control::ControlStatus::Fail,
                "WARNING" => crate::control::ControlStatus::Warning,
                _ => crate::control::ControlStatus::Unknown,
            };
            let ts_s: String = row.get(6)?;
            let ts = ts_s.parse::<DateTime<Utc>>().unwrap_or_else(|_| Utc::now());
            Ok(crate::control::ControlResult {
                id: row.get(0)?,
                framework: row.get(1)?,
                title: row.get(2)?,
                status,
                evidence_count: row.get::<_, i64>(4)? as usize,
                confidence: row.get(5)?,
                last_checked: ts,
                reason: row.get(7)?,
                remediation: row.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_control_result(&self, id: &str) -> anyhow::Result<Option<crate::control::ControlResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, framework, title, status, evidence_count, confidence, last_checked, reason, remediation FROM control_results WHERE id = ?1")?;
        let res = stmt
            .query_row(params![id], |row| {
                let status_s: String = row.get(3)?;
                let status = match status_s.as_str() {
                    "PASS" => crate::control::ControlStatus::Pass,
                    "FAIL" => crate::control::ControlStatus::Fail,
                    "WARNING" => crate::control::ControlStatus::Warning,
                    _ => crate::control::ControlStatus::Unknown,
                };
                let ts_s: String = row.get(6)?;
                let ts = ts_s.parse::<DateTime<Utc>>().unwrap_or_else(|_| Utc::now());
                Ok(crate::control::ControlResult {
                    id: row.get(0)?,
                    framework: row.get(1)?,
                    title: row.get(2)?,
                    status,
                    evidence_count: row.get::<_, i64>(4)? as usize,
                    confidence: row.get(5)?,
                    last_checked: ts,
                    reason: row.get(7)?,
                    remediation: row.get(8)?,
                })
            })
            .optional()?;
        Ok(res)
    }

    pub fn insert_drift(&self, e: &crate::drift::DriftEvent) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO drift_events (id, control_id, previous, current, cause, severity, timestamp) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                e.id,
                e.control_id,
                e.previous.to_string(),
                e.current.to_string(),
                e.cause,
                e.severity,
                e.timestamp.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_drifts(&self, limit: usize) -> anyhow::Result<Vec<crate::drift::DriftEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, control_id, previous, current, cause, severity, timestamp FROM drift_events ORDER BY timestamp DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let prev_s: String = row.get(2)?;
            let curr_s: String = row.get(3)?;
            let ts_s: String = row.get(6)?;
            let ts = ts_s.parse::<DateTime<Utc>>().unwrap_or_else(|_| Utc::now());
            Ok(crate::drift::DriftEvent {
                id: row.get(0)?,
                control_id: row.get(1)?,
                previous: match prev_s.as_str() {
                    "PASS" => crate::control::ControlStatus::Pass,
                    "FAIL" => crate::control::ControlStatus::Fail,
                    "WARNING" => crate::control::ControlStatus::Warning,
                    _ => crate::control::ControlStatus::Unknown,
                },
                current: match curr_s.as_str() {
                    "PASS" => crate::control::ControlStatus::Pass,
                    "FAIL" => crate::control::ControlStatus::Fail,
                    "WARNING" => crate::control::ControlStatus::Warning,
                    _ => crate::control::ControlStatus::Unknown,
                },
                cause: row.get(4)?,
                severity: row.get(5)?,
                timestamp: ts,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

fn row_to_evidence(row: &rusqlite::Row<'_>) -> rusqlite::Result<Evidence> {
    let ts_s: String = row.get(2)?;
    let ts = ts_s.parse::<DateTime<Utc>>().unwrap_or_else(|_| Utc::now());
    let at_s: String = row.get(3)?;
    let at: ArtifactType = serde_json::from_str(&at_s).unwrap_or(ArtifactType::Other(at_s));
    let meta_s: String = row.get(9)?;
    let meta: serde_json::Value = serde_json::from_str(&meta_s).unwrap_or(serde_json::Value::Null);
    Ok(Evidence {
        id: row.get(0)?,
        source: row.get(1)?,
        timestamp: ts,
        artifact_type: at,
        content_hash: row.get(4)?,
        confidence: row.get(5)?,
        artifact_path: row.get(6)?,
        control_id: row.get(7)?,
        provenance: row.get(8)?,
        metadata: meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{ArtifactType, Evidence};

    #[test]
    fn roundtrip() {
        let s = Store::open_in_memory().unwrap();
        let ev = Evidence::new("git", ArtifactType::GitCommit, b"abc", 0.9)
            .with_control("ISO27001-A.8.15");
        s.insert_evidence(&ev).unwrap();
        assert_eq!(s.count_evidence().unwrap(), 1);
        let list = s.list_evidence(Some("ISO27001-A.8.15"), 10).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].content_hash, ev.content_hash);
    }
}
