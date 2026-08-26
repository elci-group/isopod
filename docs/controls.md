# Controls

Controls are declarative. Isopod ships with ISO 27001/27002 packs; you can add
any framework by dropping YAML files into `controls/`.

## Pack format

```yaml
framework: iso27001
version: "2022"
controls:
  - id: ISO27001-A.8.15
    title: Logging
    description: Logs are produced, stored, protected, and analysed.
    framework: iso27001
    requirements:
      - audit_logs_enabled
      - logs_retained
      - logs_protected
      - access_monitored
    severity_missing: high      # used for FAIL
    severity_degraded: medium   # used for WARN/UNKNOWN
```

Fields:

- `id` — unique, used as primary key and for drift tracking. Use framework-native IDs.
- `title` / `description` — human-readable. `description` appears in remediation.
- `framework` — grouping key for `GET /compliance`.
- `requirements` — free-form strings. Current engine uses them as documentation and for future constraint evaluation (e.g., `retained` hints need ≥2 artifacts). No hard validation yet.
- `severity_missing` / `severity_degraded` — severity strings surfaced in drift events and remediation.

## Evaluation

`ControlSet::evaluate(grouped_evidence)` per control:

1. **No evidence** → `UNKNOWN` (`reason: "No evidence collected"`, confidence `0.0`)
2. **Stale** (all artifacts `timestamp < now - 90d`) → `WARNING` (`"Evidence stale (>90d)"`, confidence `×0.7`)
3. **Average confidence** `<0.5` → `FAIL` (`"Confidence below threshold"`), `<0.75` → `WARNING` (`"Degraded confidence"`), else `PASS`
4. **Remediation** populated for `FAIL`/`WARNING`/`UNKNOWN` with `severity_*` and control title.

Each result carries:

```rust
ControlResult {
  id, title, framework,
  status: Pass|Fail|Warning|Unknown,
  evidence_count, confidence, last_checked,
  reason: Option<String>,
  remediation: Option<String>,
}
```

Persisted to `control_results` and returned by `GET /compliance`.

## Adding a framework

Create `controls/soc2.yaml`:

```yaml
framework: soc2
version: "2017"
controls:
  - id: SOC2-CC6.1
    title: Logical access controls
    framework: soc2
    requirements: [access_provisioning, access_reviewed]
    severity_missing: high
    severity_degraded: medium
```

Run `isopod check` — the new controls appear in `isopod status` immediately. No code change. The same engine will group evidence mapped to `SOC2-CC6.1` (extend `daemon::map_observation_to_control` if you need new artifact→control mappings).

## Shipped packs

- `controls/iso27001.yaml` — 12 controls (A.5.1, A.5.10, A.5.15, A.8.9, A.8.13, A.8.15, A.8.16, A.8.26, A.8.29, A.8.30, A.9.2, A.6.1)
- `controls/iso27002.yaml` — 2 guidance controls (8.15.1, 8.26.1)

Future roadmap: `controls/soc2.yaml`, `controls/nist_csf.yaml`, `controls/gdpr.yaml`, etc. (see `docs/architecture.md`).

## Evidence mapping

`daemon::map_observation_to_control` currently:

- `audit_log`/`service_state` → `A.8.15` Logging
- `git_branch_protection`/`git_commit` → `A.8.9` Configuration management
- `file_permission`/`access_review` → `A.9.2` Access management
- `encryption_state`/`network_exposure` → `A.8.26` Application security
- `backup_record` → `A.8.13` Backups
- `certificate` → `A.8.26`
- `traci_trace` → `A.8.15`, `kaptaind_release` → `A.8.29`, `deliver_milestone` → `A.8.30`

Extend this function for new artifact types or frameworks.

## Severity and drift

Drift detection compares previous vs current `ControlResult.status`:

- `PASS → FAIL` → `HIGH`
- `PASS → WARN/UNKNOWN` or `WARN → FAIL` → `MEDIUM`
- others → `LOW`

Drift events are `COMPLIANCE_DRIFT` rows in `drift_events` and `isopod drift` output.

## Testing controls

```bash
isopod check --json | jq '.[] | select(.id=="ISO27001-A.8.15")'
isopod evidence --control ISO27001-A.8.15 --json | jq length
```

Unit tests in `src/control.rs` assert `UNKNOWN` without evidence and `PASS` with high-confidence evidence.
