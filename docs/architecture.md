# Architecture

Isopod is a **governance layer**, not a scanner. It inherits evidence graphs
from the existing telemetry ecosystem and derives compliance state from reality.

## Data flow

```
Observer Layer
  ├─ GitObserver       branch protection, commits, merges, review evidence
  ├─ SystemObserver    patch status, service state, audit logs, encryption, certs
  └─ Ecosystem         Traci, Dreamseq, Jeenome, Kaptaind, Hellhound, Deliver
          │
          ▼
     Observation {source, artifact_type, raw JSON, collected_at, confidence_hint}
          │
          ▼
   Evidence Engine (Normalizer)
     - SHA-256 content_hash (hex, tamper-evident sidecar)
     - UUID v4 id, Utc timestamp, confidence clamped 0.0–1.0
     - control mapping, provenance, metadata
     - immutable record persisted to SQLite + hash file
          │
          ▼
   Control Engine
     - Loads declarative YAML packs from controls/*.yaml
     - Groups evidence by control_id
     - Evaluates per control: UNKNOWN (no evidence), FAIL (<0.5), WARN (<0.75 or stale >90d with 0.7×), PASS
     - Emits ControlResult {status, evidence_count, confidence, reason, remediation}
          │
          ▼
   Drift Detection
     - Compares previous vs current ControlResult
     - Emits DriftEvent {previous, current, severity HIGH/MEDIUM/LOW, cause, timestamp}
     - HIGH for PASS→FAIL, MEDIUM for PASS→WARN/UNKNOWN
          │
          ▼
   Remediation Engine
     - Advisory (default): fix list per control, severity-tagged
     - Assisted: + "Create PR / ticket"
     - Autonomous: + "Execute approved workflow" (gated, Phase 4)
          │
          ▼
   Store + API + CLI
     SQLite state.db (evidence, control_results, drift_events) → `isopod status/evidence/drift/export` → Axum API
```

## Components

### Observer Layer (`src/observer/`)

All observers implement `Observer::collect() -> Vec<Observation>` (async, via `async-trait`).

- `GitObserver` — `git rev-parse`, `git log --oneline`, `git log --merges`. No network.
- `SystemObserver` — `/var/log/{audit,auth,secure}`, `systemctl is-active`, `/proc/mounts`, `/etc/passwd` perms, CA bundle. Read-only.
- `Ecosystem` — file-presence checks for `.traci`, `dreamseq.toml`, `.jeenome`, `kaptaind.toml/VERSION`, `.hellhound`, `deliver.toml`. Inherit, don't re-collect.

`CompositeObserver::with_defaults()` fans out to Git + System plus ecosystem sync checks. Failures are warned, not fatal.

### Evidence Engine (`src/evidence.rs`)

`Evidence {id, source, timestamp, artifact_type, content_hash, confidence, artifact_path, control_id, provenance, metadata}`.

- `ArtifactType` is `snake_case` JSON (git_commit, audit_log, traci_trace, etc., plus `Other(String)`).
- `hash_bytes` uses `sha2::Sha256` hex-encoded.
- `Observation::into_evidence(confidence)` serializes raw JSON to bytes, hashes, preserves timestamp.

Immutability: once inserted, evidence is never updated. Sidecar hash at `evidence/hashes/<id>.sha256` enables offline tamper detection.

### Control Engine (`src/control.rs`)

Declarative packs:

```yaml
framework: iso27001
version: "2022"
controls:
  - id: ISO27001-A.8.15
    title: Logging
    framework: iso27001
    requirements: [audit_logs_enabled, logs_retained]
    severity_missing: high
    severity_degraded: medium
```

`ControlSet::load_dir` reads all `*.yaml`/`*.yml` in `controls/`. `evaluate` groups evidence by `control_id`, computes average confidence, checks staleness, and assigns status. Requirement keywords are available for future constraint evaluation.

### Store (`src/store.rs`)

`rusqlite` (bundled) with three tables:

- `evidence (id PK, source, timestamp RFC3339, artifact_type JSON, content_hash, confidence, artifact_path, control_id, provenance, metadata JSON)` indexed on `control_id`, `timestamp`, `content_hash`.
- `control_results (id PK, framework, title, status, evidence_count, confidence, last_checked, reason, remediation)`
- `drift_events (id PK, control_id, previous, current, cause, severity, timestamp)`

All writes are `INSERT OR REPLACE`. Connections are `Mutex<Connection>` for Tokio compatibility (`spawn_blocking` not needed; SQLite is synchronous).

### Remediation (`src/remediation.rs`)

`RemediationMode::Advisory/Assisted/Autonomous`. `for_result` maps known control families (A.8.15 logging, A.9.2 access, etc.) to playbooks; unknown controls fall back to `reason`/`remediation` from evaluation.

### Style (`src/style.rs`)

TTY-aware ANSI (honours `NO_COLOR`, `ISOPOD_NO_COLOR`, `is_terminal()`). Helpers: `bold/dim/red/green/yellow/blue/cyan/magenta`, `status_with_icon`, `confidence_bar` (10-char block, colour by threshold), `banner`.

### Config (`src/config.rs`)

```yaml
state_dir: ~/.isopod
evidence_dir: ~/.isopod/evidence
controls_dir: ~/.isopod/controls
reports_dir: ~/.isopod/reports
interval_secs: 60
api_addr: 127.0.0.1:8787
frameworks: [iso27001]
```

`ensure_dirs` best-effort with sandbox fallback to `./.isopod` if `~` is read-only. `load_or_default` tries explicit path, then `~/.isopod/config.yaml`, then `Default`.

## Runtime

`daemon::Daemon::tick(base_path)` — single evaluation cycle. `run_forever` loops with `tokio::time::sleep(interval)`. API (`api::router`) is Axum with `GET /health`, `/compliance`, `/evidence`, `/drift`.

## Security considerations

- Observers are read-only, minimal privilege.
- Evidence is hashed; sidecars enable tamper detection. Future: signed envelopes.
- Store assumes monitored system may become compromised — integrity is first-class.
- No secrets are persisted in evidence. Encrypted artifacts are roadmap.

See `docs/configuration.md` and `docs/operations.md` for deployment.
