# Changelog

All notable changes to Isopod are documented in this file.
Version bumps are managed by `kaptaind` based on change clustering.

## [0.2.0] - 2026-08-09

### Added
- Web Assurance closed loop: `scan`, `assess`, `recommend`, `harden`, and
  `verify --web`.
- Deterministic source/build inventory with framework, manifest, lockfile, CI,
  and deployment evidence.
- Six-state assurance assessments that distinguish unknown and unverifiable
  controls from demonstrated absence.
- Leverage-ranked hardening plans with effort, affected controls, and explicit
  verification methods.
- Safe `harden --apply` baseline actions that create missing files and never
  overwrite project-owned content.

### Fixed
- Restored webhook event deserialization and pending-event lookup in the
  SQLite store.

## [0.1.1] - 2026-08-07

### Added
- Continuous compliance daemon with SQLite-backed evidence store.
- Declarative ISO 27001/27002 control packs in `controls/`.
- Evidence collection from Git, system state, and ecosystem tools
  (Traci, Dreamseq, Jeenome, Kaptaind, Hellhound, Deliver).
- SHA-256 content hashing with `sha256sum -c` compatible sidecar files.
- Control evaluation engine with confidence scoring and staleness detection.
- Drift detection for PASS→FAIL transitions.
- Advisory remediation playbooks.
- Stylised CLI: `init`, `status`, `check`, `evidence`, `drift`, `export`,
  `daemon`, `serve`, `discover`, `provision`, `maintain`, `fleet`, `isopod-d`.
- Axum HTTP API: `/health`, `/compliance`, `/evidence`, `/drift`.
- Fleet daemon (`isopod-d`) for discover → provision → maintain cycles.
- GitHub Actions CI workflow with test, clippy, fmt, doc, and coverage jobs.

### Changed
- Hash sidecars now use `sha256sum -c` compatible format
  (`<hash>  artifacts/<id>.json`).
- Default control seeding and per-project config helpers centralized in
  `src/project.rs`.

### Fixed
- All Clippy warnings under `lints.clippy.all = "deny"`.
- Removed unused dependencies (`daemonize`, `globset`, `notify`, `regex`,
  `tower`, `tower-http`, `thiserror`).
- Documentation test counts and version references aligned with code.
