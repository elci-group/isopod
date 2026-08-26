// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Store — SQLite persistence for evidence, results, and drift.
//! See `docs/architecture.md` and `docs/evidence.md`.

use crate::evidence::{ArtifactType, Evidence};
use anyhow::Context;
use chrono::{DateTime, Utc};
use rusqlite::types::Type;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    fn connection(&self) -> anyhow::Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|error| anyhow::anyhow!("SQLite connection mutex was poisoned: {error}"))
    }

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
        let conn = self.connection()?;
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
                metadata TEXT,
                previous_id TEXT
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

            CREATE TABLE IF NOT EXISTS control_result_history (
                id TEXT PRIMARY KEY,
                control_id TEXT NOT NULL,
                framework TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence_count INTEGER NOT NULL,
                confidence REAL NOT NULL,
                last_checked TEXT NOT NULL,
                reason TEXT,
                remediation TEXT,
                recorded_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_control_result_history_control ON control_result_history(control_id);
            CREATE INDEX IF NOT EXISTS idx_control_result_history_time ON control_result_history(recorded_at);

            CREATE TABLE IF NOT EXISTS webhook_events (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                delivered_at TEXT,
                status TEXT NOT NULL,
                error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_webhook_events_status ON webhook_events(status);

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
        let previous_id_exists = {
            let mut statement = conn.prepare("PRAGMA table_info(evidence)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "previous_id" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !previous_id_exists {
            conn.execute("ALTER TABLE evidence ADD COLUMN previous_id TEXT", [])
                .context("add evidence.previous_id column")?;
        }
        Ok(())
    }

    pub fn insert_evidence(&self, ev: &Evidence) -> anyhow::Result<()> {
        let conn = self.connection()?;
        let artifact_type =
            serde_json::to_string(&ev.artifact_type).context("serialize evidence artifact type")?;
        let metadata =
            serde_json::to_string(&ev.metadata).context("serialize evidence metadata")?;
        conn.execute(
            "INSERT OR REPLACE INTO evidence (id, source, timestamp, artifact_type, content_hash, confidence, artifact_path, control_id, provenance, metadata, previous_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                ev.id,
                ev.source,
                ev.timestamp.to_rfc3339(),
                artifact_type,
                ev.content_hash,
                ev.confidence,
                ev.artifact_path,
                ev.control_id,
                ev.provenance,
                metadata,
                ev.previous_id,
            ],
        ).context("insert evidence")?;
        Ok(())
    }

    pub fn list_evidence(
        &self,
        control_id: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Evidence>> {
        let conn = self.connection()?;
        let mut stmt = if control_id.is_some() {
            conn.prepare("SELECT id, source, timestamp, artifact_type, content_hash, confidence, artifact_path, control_id, provenance, metadata, previous_id FROM evidence WHERE control_id = ?1 ORDER BY timestamp DESC LIMIT ?2")?
        } else {
            conn.prepare("SELECT id, source, timestamp, artifact_type, content_hash, confidence, artifact_path, control_id, provenance, metadata, previous_id FROM evidence ORDER BY timestamp DESC LIMIT ?1")?
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
        let conn = self.connection()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM evidence", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    pub fn list_evidence_before(&self, cutoff: DateTime<Utc>) -> anyhow::Result<Vec<Evidence>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT id, source, timestamp, artifact_type, content_hash, confidence, artifact_path, control_id, provenance, metadata, previous_id FROM evidence WHERE timestamp < ?1 ORDER BY timestamp DESC",
        )?;
        let rows = stmt.query_map(params![cutoff.to_rfc3339()], row_to_evidence)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn delete_evidence(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.connection()?;
        conn.execute("DELETE FROM evidence WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn has_evidence_with_hash(&self, hash: &str) -> anyhow::Result<bool> {
        let conn = self.connection()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM evidence WHERE content_hash = ?1",
            params![hash],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn latest_evidence_for_control_source(
        &self,
        control_id: Option<&str>,
        source: &str,
    ) -> anyhow::Result<Option<Evidence>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT id, source, timestamp, artifact_type, content_hash, confidence, artifact_path, control_id, provenance, metadata, previous_id FROM evidence WHERE source = ?1 AND control_id IS ?2 ORDER BY timestamp DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![source, control_id], row_to_evidence)?;
        Ok(rows.next().transpose()?)
    }

    pub fn evidence_by_control(&self) -> anyhow::Result<Vec<(String, Vec<Evidence>)>> {
        let all = self.list_evidence(None, 100_000)?;
        let mut map: std::collections::HashMap<String, Vec<Evidence>> =
            std::collections::HashMap::new();
        for ev in all {
            if let Some(cid) = ev.control_id.clone() {
                map.entry(cid).or_default().push(ev);
            }
        }
        Ok(map.into_iter().collect())
    }

    pub fn upsert_control_result(&self, r: &crate::control::ControlResult) -> anyhow::Result<()> {
        let conn = self.connection()?;
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

    pub fn insert_control_result_history(
        &self,
        r: &crate::control::ControlResult,
    ) -> anyhow::Result<()> {
        let conn = self.connection()?;
        let recorded = Utc::now();
        let history_id = format!("{}-{}", r.id, recorded.timestamp_millis());
        conn.execute(
            "INSERT INTO control_result_history (id, control_id, framework, title, status, evidence_count, confidence, last_checked, reason, remediation, recorded_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                history_id,
                r.id,
                r.framework,
                r.title,
                r.status.to_string(),
                r.evidence_count as i64,
                r.confidence,
                r.last_checked.to_rfc3339(),
                r.reason,
                r.remediation,
                recorded.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_control_result_history(
        &self,
        control_id: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<crate::control::ControlResult>> {
        let conn = self.connection()?;
        let mut stmt = if control_id.is_some() {
            conn.prepare("SELECT control_id, framework, title, status, evidence_count, confidence, last_checked, reason, remediation FROM control_result_history WHERE control_id = ?1 ORDER BY recorded_at DESC LIMIT ?2")?
        } else {
            conn.prepare("SELECT control_id, framework, title, status, evidence_count, confidence, last_checked, reason, remediation FROM control_result_history ORDER BY recorded_at DESC LIMIT ?1")?
        };
        let rows = if let Some(cid) = control_id {
            stmt.query_map(params![cid, limit as i64], history_row_to_result)?
        } else {
            stmt.query_map(params![limit as i64], history_row_to_result)?
        };
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn list_control_results(&self) -> anyhow::Result<Vec<crate::control::ControlResult>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT id, framework, title, status, evidence_count, confidence, last_checked, reason, remediation FROM control_results ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            let status_s: String = row.get(3)?;
            let status = parse_control_status(3, &status_s)?;
            let ts_s: String = row.get(6)?;
            let ts = parse_timestamp(6, &ts_s)?;
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

    pub fn get_control_result(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<crate::control::ControlResult>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT id, framework, title, status, evidence_count, confidence, last_checked, reason, remediation FROM control_results WHERE id = ?1")?;
        let res = stmt
            .query_row(params![id], |row| {
                let status_s: String = row.get(3)?;
                let status = parse_control_status(3, &status_s)?;
                let ts_s: String = row.get(6)?;
                let ts = parse_timestamp(6, &ts_s)?;
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
        let conn = self.connection()?;
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

    pub fn insert_webhook_event(&self, event: &crate::webhook::WebhookEvent) -> anyhow::Result<()> {
        let conn = self.connection()?;
        let status = serde_json::to_string(&event.status).context("serialize webhook status")?;
        conn.execute(
            "INSERT INTO webhook_events (id, url, payload, created_at, delivered_at, status, error) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                event.id,
                event.url,
                event.payload.to_string(),
                event.created_at.to_rfc3339(),
                event.delivered_at.map(|t| t.to_rfc3339()),
                status,
                event.error,
            ],
        )?;
        Ok(())
    }

    pub fn list_pending_webhook_events(
        &self,
        limit: usize,
    ) -> anyhow::Result<Vec<crate::webhook::WebhookEvent>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT id, url, payload, created_at, delivered_at, status, error FROM webhook_events WHERE status = '\"pending\"' ORDER BY created_at ASC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], row_to_webhook_event)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn mark_webhook_event(
        &self,
        id: &str,
        status: crate::webhook::WebhookStatus,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.connection()?;
        let delivered_at = if status == crate::webhook::WebhookStatus::Delivered {
            Some(Utc::now().to_rfc3339())
        } else {
            None
        };
        let status = serde_json::to_string(&status).context("serialize webhook status")?;
        conn.execute(
            "UPDATE webhook_events SET status = ?1, error = ?2, delivered_at = ?3 WHERE id = ?4",
            params![status, error, delivered_at, id],
        )?;
        Ok(())
    }

    pub fn list_drifts(&self, limit: usize) -> anyhow::Result<Vec<crate::drift::DriftEvent>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT id, control_id, previous, current, cause, severity, timestamp FROM drift_events ORDER BY timestamp DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let prev_s: String = row.get(2)?;
            let curr_s: String = row.get(3)?;
            let ts_s: String = row.get(6)?;
            let ts = parse_timestamp(6, &ts_s)?;
            Ok(crate::drift::DriftEvent {
                id: row.get(0)?,
                control_id: row.get(1)?,
                previous: parse_control_status(2, &prev_s)?,
                current: parse_control_status(3, &curr_s)?,
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

fn row_to_webhook_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<crate::webhook::WebhookEvent> {
    let payload: String = row.get(2)?;
    let created_at: String = row.get(3)?;
    let delivered_at: Option<String> = row.get(4)?;
    let status: String = row.get(5)?;
    let payload = parse_json_value(2, &payload)?;
    let created_at = parse_timestamp(3, &created_at)?;
    let delivered_at = delivered_at
        .map(|value| parse_timestamp(4, &value))
        .transpose()?;
    let status = serde_json::from_str(&status).map_err(|error| conversion_error(5, error))?;
    Ok(crate::webhook::WebhookEvent {
        id: row.get(0)?,
        url: row.get(1)?,
        payload,
        created_at,
        delivered_at,
        status,
        error: row.get(6)?,
    })
}

fn history_row_to_result(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::control::ControlResult> {
    let status_s: String = row.get(3)?;
    let status = parse_control_status(3, &status_s)?;
    let ts_s: String = row.get(6)?;
    let ts = parse_timestamp(6, &ts_s)?;
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
}

fn row_to_evidence(row: &rusqlite::Row<'_>) -> rusqlite::Result<Evidence> {
    let ts_s: String = row.get(2)?;
    let ts = parse_timestamp(2, &ts_s)?;
    let at_s: String = row.get(3)?;
    let at: ArtifactType =
        serde_json::from_str(&at_s).map_err(|error| conversion_error(3, error))?;
    let meta_s: String = row.get(9)?;
    let meta = parse_json_value(9, &meta_s)?;
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
        previous_id: row.get(10)?,
    })
}

fn parse_control_status(
    column: usize,
    value: &str,
) -> rusqlite::Result<crate::control::ControlStatus> {
    match value {
        "PASS" => Ok(crate::control::ControlStatus::Pass),
        "FAIL" => Ok(crate::control::ControlStatus::Fail),
        "WARNING" => Ok(crate::control::ControlStatus::Warning),
        "UNKNOWN" => Ok(crate::control::ControlStatus::Unknown),
        unexpected => {
            tracing::error!(
                column,
                status = unexpected,
                "invalid persisted control status"
            );
            Err(conversion_error(
                column,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid control status: {unexpected}"),
                ),
            ))
        }
    }
}

fn parse_timestamp(column: usize, value: &str) -> rusqlite::Result<DateTime<Utc>> {
    value
        .parse::<DateTime<Utc>>()
        .map_err(|error| conversion_error(column, error))
}

fn parse_json_value(column: usize, value: &str) -> rusqlite::Result<serde_json::Value> {
    serde_json::from_str(value).map_err(|error| conversion_error(column, error))
}

fn conversion_error(
    column: usize,
    error: impl std::error::Error + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
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

    #[test]
    fn control_result_history_roundtrip() {
        let s = Store::open_in_memory().unwrap();
        let r = crate::control::ControlResult {
            id: "ISO27001-A.8.15".to_string(),
            title: "Logging".to_string(),
            framework: "iso27001".to_string(),
            status: crate::control::ControlStatus::Pass,
            evidence_count: 2,
            confidence: 0.95,
            last_checked: Utc::now(),
            reason: None,
            remediation: None,
        };
        s.insert_control_result_history(&r).unwrap();
        let history = s
            .list_control_result_history(Some("ISO27001-A.8.15"), 10)
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, crate::control::ControlStatus::Pass);
    }
}
