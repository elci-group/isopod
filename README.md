# Isopod — Web Assurance and Compliance Control Loop

> **Continuous evidence. Continuous evaluation. Continuous governance.**

[![Rust](https://img.shields.io/badge/Rust-1.74%2B-orange?logo=rust)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](Cargo.toml)
![Status: v0.2 Web Assurance](https://img.shields.io/badge/Status-v0.2%20Web%20Assurance-green)

**Docs:** [Architecture](docs/architecture.md) · [Configuration](docs/configuration.md) · [Evidence](docs/evidence.md) · [Controls](docs/controls.md) · [API](docs/api.md) · [Operations](docs/operations.md) · [isopod.d](docs/isopod-d.md) · [Development](docs/development.md)

Isopod determines what a web project needs to become compliant, secure, and
resilient—and records the evidence needed to demonstrate it. It combines a
continuous compliance daemon with a closed assurance loop:

**Detect → Map → Assess → Prioritise → Remediate → Verify → Reassess**

```bash
isopod scan                 # inventory source and build evidence
isopod assess               # evaluate six-state assurance controls
isopod recommend            # rank remediation by leverage and effort
isopod harden               # review a safe, deterministic proposal
isopod harden --apply       # create missing baselines; never overwrite
isopod verify --web         # independently check the resulting plan
```

```
isopod status

  isopod  ·  compliance nervous system

  ISO 27001  — Information Security Management
  ────────────────────────────────────────────────────
  Controls  14  Pass   3  Warn   0  Fail   0  Unknown  11
  Posture █████░░░░░░░░░░░░░░░░░░░ 21%

  Controls
  ID                     Status         Evidence   Confidence       Title
  ────────────────────────────────────────────────────────────────────────
  ISO27001-A.8.15        ● PASS         5          █████████░  85%  Logging
  ISO27001-A.8.26        ● PASS         2          █████████░  85%  Application security
  ISO27001-A.9.2         ● PASS         1          █████████░  85%  Access management
  …
```

---

## Why Isopod

**Evidence over assertions.** Every compliance claim must map to a measurable control, a content-hashed artifact, a timestamp, a confidence score, and a remediation path. No checklist theatre.

**Daemon, not scanner.** Isopod observes change as it happens — git, host, pipeline, and the evidence graphs your existing tools already produce.

**Framework-agnostic.** ISO 27001/27002/27017/27018/22301 today; SOC 2, NIST CSF, CIS, GDPR, HIPAA, and PCI DSS tomorrow. Controls are YAML; the engine is generic.

**Governance, not re-scanning.** Inherits evidence graphs from Traci (traceability), Dreamseq (semantic histories), Jeenome (behaviour), Kaptaind (releases), Hellhound (health), and Deliver (milestones).

---

## Principles

- **Evidence over assertions** — configuration declares intent; evidence proves reality.
- **Continuous** — posture updates automatically as system state changes.
- **Inherit, don’t rediscover** — Isopod is the governance layer above Traci, Dreamseq, Jeenome, Kaptaind, Hellhound, and Deliver. It consumes their evidence graphs instead of re-scanning.

## Architecture

```
Observer Layer ──► Evidence Engine ──► Control Engine ──► Drift Detection ──► Remediation Engine
      │                    │                    │                    │                     │
  Git / System /    Normalizer + SHA256    Declarative YAML      PASS→FAIL            Advisory /
  Network +         + provenance          control evaluation     + severity             Assisted /
  Ecosystem         + confidence          + confidence             detection         Autonomous
  (Traci · Dreamseq · Jeenome · Kaptaind · Hellhound · Deliver)

Store:  ~/.isopod/
        ├── evidence/{hashes,artifacts}   # immutable, hash-verified
        ├── controls/*.yaml               # declarative control packs
        ├── state.db                      # SQLite — results + drift history
        └── reports/                      # exported audit packages
```

**Pipeline:** `Observation → Normalizer → Evidence {id, source, timestamp, artifact_type, content_hash, confidence} → Control Mapping → Evaluation {PASS|FAIL|WARN|UNKNOWN, confidence} → Drift Event → Remediation`.

All evidence is immutable, SHA-256 hashed with sidecar files for tamper detection, and carries provenance.

---

## Ecosystem Integration

Isopod does not replace your telemetry — it **governs** it.

| Upstream | Evidence Isopod Inherits |
|---|---|
| **Traci** | Traceability & observability enforcement (TRC rules, span continuity) → `ISO27001-A.8.15` |
| **Dreamseq** | Semantic operational histories → `A.8.16` monitoring |
| **Jeenome** | System behavioural evidence (strace-derived) → `A.8.26` |
| **Kaptaind** | Version & release governance (`kaptaind.toml`, `VERSION`) → `A.8.29` |
| **Hellhound** | Daemon & service health → `A.8.16` |
| **Deliver** | Milestone verification (`deliver.toml`) → `A.8.30` |
| **Git** | Branch protection, commit history, review evidence → `A.8.9` |
| **System** | Patch status, service state, audit logs, encryption, certs → `A.8.15` / `A.9.2` |

Add a new framework by dropping a YAML file in `controls/` — no code change.

---

## Quickstart

```bash
cargo build --release
./target/release/isopod init
# → ✓ Initialized  state .isopod  controls .isopod/controls  db .isopod/state.db  seed 14 controls

./target/release/isopod status              # stylised human report (colours, bars, posture)
./target/release/isopod status --json       # machine-readable
./target/release/isopod check --json        # one-shot evaluation
./target/release/isopod evidence --limit 20 # audit-ready artifacts, confidence bars
./target/release/isopod drift               # PASS→FAIL transitions with severity
./target/release/isopod export ./audit      # compliance.json + evidence.json + controls/*.yaml

# Daemon + local API
./target/release/isopod daemon --interval 60 --api 127.0.0.1:8787
./target/release/isopod serve  --addr 127.0.0.1:8787
```

**Stylised output** uses ANSI colour when stdout is a TTY (PASS green, FAIL red, WARN yellow, UNKNOWN dim), confidence bars (`█████░░░░░ 85%`), and posture bars. Pass `--json` or pipe the output and colours are automatically disabled; set `NO_COLOR=1` to force plain text.

### API

```
GET /health      → {status:"ok", service:"isopod", version:"0.1.0"}
GET /compliance  → {framework, total, passing, failing, warning, unknown, controls[]}
GET /evidence    → {count, evidence[]}
GET /drift       → {drifts[]}
```

---

## CLI Reference

| Command | Purpose | Stylised? |
|---|---|---|
| `isopod init` | Seed `~/.isopod` and default control packs | `✓` banner + counts |
| `isopod scan [--json]` | Inventory framework, dependencies, CI, and deployment evidence | yes |
| `isopod assess [--json]` | Evaluate web controls with six explicit assurance states | yes |
| `isopod recommend [--json]` | Produce a leverage-ranked remediation plan | yes |
| `isopod harden [--apply] [--json]` | Propose or apply non-overwriting baseline changes | yes |
| `isopod verify --web [--json]` | Verify hardening actions; retain unknown for runtime checks | yes |
| `isopod status` | Human dashboard (header, posture bar, critical findings, table, remediation, drift) | yes |
| `isopod status --json` | Machine JSON for CI | no (raw JSON) |
| `isopod check` | One-shot collect→evaluate (exits 1 if any FAIL) | yes |
| `isopod evidence [--control ID] [--limit N]` | List artifacts with confidence bars and hash-verified hint | yes |
| `isopod drift` | Show `COMPLIANCE_DRIFT` events with severity colour | yes |
| `isopod export <dir>` | Audit package (`compliance.json`, `evidence.json`, `controls/*.yaml`) | `✓` summary |
| `isopod daemon [--interval 60] [--api ADDR]` | Long-running observer (Tokio interval) + API | logs |
| `isopod serve --addr 127.0.0.1:8787` | API only | — |

---

## Evidence Object

```rust
pub struct Evidence {
    pub id: String,              // UUID v4
    pub source: String,          // git, system, traci, …
    pub timestamp: DateTime<Utc>,// collection time
    pub artifact_type: ArtifactType,
    pub content_hash: String,    // SHA-256 hex
    pub confidence: f32,         // 0.0–1.0, clamped
    pub control_id: Option<String>,
    pub provenance: Option<String>,
    pub metadata: serde_json::Value,
}
```

Stored in SQLite, indexed by `control_id` and `timestamp`, with a hash sidecar at `evidence/hashes/<id>.sha256` for tamper detection. Ported via `state.db` and `export`.

## Control Definition

```yaml
# controls/iso27001.yaml
framework: iso27001
version: "2022"
controls:
  - id: ISO27001-A.8.15
    title: Logging
    framework: iso27001
    requirements: [audit_logs_enabled, logs_retained, access_monitored]
    severity_missing: high
    severity_degraded: medium
```

Evaluation: no evidence → `UNKNOWN`, avg confidence <0.5 → `FAIL`, <0.75 → `WARN`, stale (>90d) → `WARN` with 0.7× confidence, otherwise `PASS`. Each result carries `reason` and `remediation`.

## Drift Event

```
▸ Recent drift
  COMPLIANCE_DRIFT ISO27001-A.8.15  PASS → FAIL  HIGH  Logging service disabled
```

Persisted in `drift_events`, scored `HIGH` for `PASS→FAIL`, `MEDIUM` for `PASS→WARN/UNKNOWN`.

## Remediation

Three modes:

- **Advisory** (default) — human-readable fix list per failing control.
- **Assisted** — adds “Create pull request / ticket”.
- **Autonomous** — adds “Execute approved workflow” (gated, for future Phase 4).

```bash
isopod status  # shows advisory fixes inline
```

---

## Development Phases

- [x] **Phase 1 — Compliance Core** — daemon, evidence DB, control engine, stylised CLI, API, ISO 27001 pack
- [x] **Phase 2 — Web Assurance** — source/build inventory, six-state assessment, prioritised plans, safe hardening, closed-loop verification
- [ ] **Phase 3 — Infrastructure Compliance** — containers, cloud APIs, IAM, network (NetworkObserver)
- [ ] **Phase 4 — Autonomous Compliance** — auto-remediation, policy generation, forecasting, auditor assistant

---

## Security

- Minimal privileges, read-only observers, no secrets in evidence.
- Signed/hashed artifacts, sidecar tamper detection, SQLite WAL.
- Assumes the monitored system may become compromised — evidence integrity is first-class.
- Encrypted sensitive artifacts and secure update are roadmap items.

## Documentation

| Doc | Purpose |
|---|---|
| [Architecture](docs/architecture.md) | Pipeline, components, storage, security |
| [Configuration](docs/configuration.md) | `~/.isopod/config.yaml`, env vars, daemon interval |
| [Evidence](docs/evidence.md) | Evidence record, lifecycle, hashing, tamper detection |
| [Controls](docs/controls.md) | Pack format, evaluation thresholds, authoring new frameworks |
| [API](docs/api.md) | `GET /health`, `/compliance`, `/evidence`, `/drift` |
| [Operations](docs/operations.md) | One-shot, daemon, systemd, Docker, export, troubleshooting |
| [Development](docs/development.md) | Layout, style, tests, `goglz`, `kaptaind`, `deliver` |

Docs are revised with **goglz** (`goglz revise --directory .`) — Groq LLaMA 3.3 70B via `goglz.yaml` (purpose: clarity, scope: all Markdown, tone: professional & approachable, voice: active & direct). This README and all `docs/*.md` were produced with that pipeline and manually verified.

Run locally:

```bash
HOME=/tmp/home /tmp/goglz-target/debug/goglz revise --directory .  # requires GROQ_API_KEY in /tmp/home/.goglz
```

---

## License

MIT — see `Cargo.toml` and `LICENSE` (if present).
