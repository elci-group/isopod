# Evidence Model

> **Every claim must be provable.** Isopod never considers compliance achieved
> through configuration alone.

## Evidence record

```rust
pub struct Evidence {
    pub id: String,              // UUID v4, primary key
    pub source: String,          // "git", "system", "traci", "kaptaind", …
    pub timestamp: DateTime<Utc>,// collection time, RFC3339 in SQLite
    pub artifact_type: ArtifactType,
    pub content_hash: String,    // SHA-256 hex, tamper-evident
    pub confidence: f32,         // 0.0–1.0, clamped
    pub artifact_path: Option<String>,
    pub control_id: Option<String>, // e.g., "ISO27001-A.8.15"
    pub provenance: Option<String>,
    pub metadata: serde_json::Value, // raw observation JSON
}
```

`ArtifactType` (snake_case JSON):

`git_commit`, `git_branch_protection`, `system_patch`, `service_state`,
`file_permission`, `network_exposure`, `encryption_state`, `backup_record`,
`access_review`, `audit_log`, `deployment_history`, `certificate`, `documentation`,
`traci_trace`, `dreamseq_history`, `jeenome_behaviour`, `kaptaind_release`,
`hellhound_health`, `deliver_milestone`, `other(String)`.

## Lifecycle

```
raw signal (git log, /var/log/audit, kaptaind.toml)
  → Observation {source, artifact_type, raw JSON, collected_at, confidence_hint}
  → Normalizer: serialize raw → SHA-256 → Evidence {id, hash, confidence}
  → Control mapping (heuristic by artifact_type)
  → Store::insert_evidence (INSERT OR REPLACE, hash sidecar)
  → Control Engine groups by control_id → ControlResult
```

Example — Git branch protection:

```json
Observation {
  source: "git",
  artifact_type: "git_branch_protection",
  raw: {"branch":"main","protected_hint":false},
  collected_at: "2026-08-07T11:00:07Z"
}
→ Evidence {
  id: "f3dfccb5-…",
  content_hash: "a3f5… (SHA-256 of raw JSON)",
  confidence: 0.85,
  control_id: "ISO27001-A.8.9"
}
```

## Persistence

SQLite `evidence` table, indexed on `control_id`, `timestamp`, `content_hash`.
Hash sidecar at `evidence/hashes/<id>.sha256` enables offline verification:

```bash
sha256sum <(echo -n '{"branch":"main",…}') | diff - evidence/hashes/<id>.sha256
```

Artifacts are immutable — never updated, only superseded by newer evidence.
Staleness is evaluated by Control Engine (>90 days → WARN with 0.7× confidence).

## Querying

```bash
isopod evidence --limit 20
isopod evidence --control ISO27001-A.8.15 --limit 10
isopod evidence --json | jq '.[].content_hash'
```

API:

```
GET /evidence → {count, evidence: Evidence[]}
GET /evidence?control=ISO27001-A.8.15 (via CLI filter; API returns all, client filters)
```

Export includes all evidence:

```bash
isopod export ./audit  # → evidence.json + compliance.json + controls/*.yaml
```

## Confidence

Confidence is a local signal quality score, not a compliance guarantee.

- System audit logs present → 0.85–0.92
- Low-quality or inferred evidence → 0.3–0.5
- Stale evidence → ×0.7

Control Engine averages confidence per control; thresholds drive status (see `docs/controls.md`).

## Provenance

`provenance` and `metadata` preserve the raw observation for auditors. `source`
identifies the observer; `artifact_path` may hold a filesystem path when relevant.
All timestamps are `Utc::now()` at collection, serialized as RFC3339.

## Tamper detection

Isopod assumes the monitored host may become compromised. Evidence integrity is
first-class: hash sidecars are written at insert time; future verification can
re-hash content and compare. Roadmap includes signed envelopes and append-only
WAL with replication.
