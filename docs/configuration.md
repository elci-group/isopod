# Configuration

Isopod is local-first. All config is file-based; no registry or cloud dependency.

## Locations

```
~/.isopod/                 # default state_dir
├── config.yaml            # optional, overrides defaults
├── state.db               # SQLite
├── evidence/
│   ├── hashes/<id>.sha256 # tamper sidecars
│   └── artifacts/         # reserved for large blobs
├── controls/
│   ├── iso27001.yaml      # seeded defaults
│   └── iso27002.yaml
└── reports/               # export staging
```

In sandboxed or read-only `$HOME` (e.g., bwrap), Isopod falls back to `./.isopod` automatically.

## Config file

Create `~/.isopod/config.yaml` or pass `--config <path>`:

```yaml
state_dir: /var/lib/isopod
evidence_dir: /var/lib/isopod/evidence
controls_dir: /var/lib/isopod/controls
reports_dir: /var/lib/isopod/reports
interval_secs: 60
api_addr: "127.0.0.1:8787"   # null to disable API
frameworks: [iso27001, iso27002]
```

All paths are created with `ensure_dirs`. Unknown fields are ignored (serde).

## CLI flags

```
--config <path>   # explicit config file
--base <path>     # repository/host root to observe (default: .)
isopod init       # seed controls if empty
isopod daemon --interval 60 --api 127.0.0.1:8787
isopod serve  --addr 127.0.0.1:8787
```

Environment:

- `NO_COLOR=1` or `ISOPOD_NO_COLOR=1` — disable ANSI.
- `RUST_LOG=debug` — tracing filter (tracing-subscriber env-filter).

## Controls

Drop any `*.yaml`/`*.yml` into `controls/`. `ControlSet::load_dir` loads all packs and merges by `id` (last wins on duplicate).

```yaml
framework: iso27001
version: "2022"
controls:
  - id: ISO27001-A.8.15
    title: Logging
    description: Logs are produced, retained, protected, and analysed.
    framework: iso27001
    requirements: [audit_logs_enabled, logs_retained, access_monitored]
    severity_missing: high
    severity_degraded: medium
```

- `severity_missing` — used when status is `FAIL` (no evidence or confidence <0.5).
- `severity_degraded` — used for `WARN`/`UNKNOWN`.

See `docs/controls.md` for authoring new packs (SOC 2, NIST, etc.).

## API

`api_addr` may be `null` to disable the Axum server. When enabled, Isopod spawns `api::serve` on `daemon` start and on `serve`.

Endpoints are unauthenticated localhost-only by default. Put a reverse proxy in front for external exposure.

## Daemon interval

`interval_secs` is the `tokio::time::sleep` between `tick` cycles. `60` is a good default; lower values increase evidence volume but not CPU (observers are I/O-bound). Evidence is deduplicated by content hash, not timestamp.

## Kaptaind integration

`kaptaind.toml` is unrelated to Isopod's `config.yaml`. Kaptaind governs versioning; Isopod reads `kaptaind.toml`/`VERSION` as *evidence* for `A.8.29`. Isopod's own version lives in `Cargo.toml`/`VERSION` and is projected by `kaptaind-cli analyze` (e.g., Patch → v0.1.1).

## Goglz

`goglz.yaml` controls doc revision (Groq LLaMA 3.3 70B). It is not read by Isopod at runtime; it is a developer tool for `goglz revise`.
