# isopod.d — Fleet Provisioning Daemon

`isopod.d` is the **fleet counterpart** to the single-project `isopod` daemon.
Where `isopod daemon` watches one repository or host, `isopod.d` watches a
*forest* — a set of root directories — discovers every project, ensures each
has a valid `.isopod` installation, and keeps those installations healthy.

In short: **find projects without `.isopod`, generate it, and maintain it.**

## When to use what

| Command | Scope | Purpose |
|---|---|---|
| `isopod init` | one project | Seed `.isopod` in the current directory |
| `isopod status` | one project | Human/machines readable posture for that project |
| `isopod daemon` | one project | Periodic `tick` for that project + API |
| `isopod discover` | fleet | List tracked vs untracked projects under roots |
| `isopod provision` | fleet | Create `.isopod` for untracked projects |
| `isopod maintain` | fleet | Repair tracked projects (missing dirs, corrupted DB, stale controls) |
| `isopod fleet` | fleet | One-shot `discover → provision → maintain → tick` |
| `isopod isopod-d` / `isopod-d daemon` | fleet | Long-lived daemon, periodic fleet cycles |

`isopod-d` is also available as a standalone binary `isopod-d` with identical
flags (`isopod-d discover`, `isopod-d provision`, `isopod-d maintain`,
`isopod-d run`, `isopod-d daemon`) for systemd units that want a distinct
process name.

## Project discovery

A directory is a **project** if it contains at least one marker:

`.git`, `Cargo.toml`, `package.json`, `go.mod`, `pyproject.toml`, `pom.xml`,
`build.gradle`, `Makefile`, `CMakeLists.txt`, `.project`, `setup.py`, `poetry.lock`

Markers, ignore list, and max walk depth are configurable (`isopod-d --help`).

Ignored by default (never descended): `target`, `node_modules`, `.git`,
`.isopod`, `.kaptaind`, `.traci`, `.hg`, `.svn`, `vendor`, `dist`, `build`,
`__pycache__`, `.venv`, `venv`.

Discovery is via `walkdir` with `max_depth` (default 4). It is deterministic
and sorted, so `discover` output is stable for `diff` and CI.

```bash
isopod discover --roots ~/projects,/home/sal --depth 4
isopod discover --roots . --json | jq '.[] | select(.has_isopod==false)'
```

Stylised output shows `● tracked` (green) vs `○ untracked` (yellow) with markers.

## Provisioning (generation)

For each untracked project, `provision` creates:

```
<project>/.isopod/
├── evidence/{hashes,artifacts}/
├── controls/
│   ├── iso27001.yaml   # from isopod's embedded defaults (with header comments)
│   └── iso27002.yaml
├── reports/
└── state.db            # SQLite (evidence, control_results, drift_events)
```

Implementation (`src/provision.rs`): `Config` pointed at `<project>/.isopod`,
`ensure_dirs` (with sandbox fallback), `seed_controls` (idempotent), `Store::open`
to create tables. `provision_project` returns `{created, controls_seeded, error}`
and is idempotent — re-running on an already-provisioned project is a no-op.

```bash
isopod provision --roots ~/projects --dry-run        # preview
isopod provision --roots ~/projects                  # create
isopod provision --roots ~/projects --json | jq .
```

## Maintenance

For each tracked project, `maintain` checks:

- `.isopod` exists
- `evidence/`, `controls/`, `reports/`, `hashes/`, `artifacts` dirs exist
- `controls` contains at least one valid pack (re-seeds defaults if empty or all invalid)
- `state.db` exists and opens; if corrupted, removed and recreated
- Evidence `count`, hash sidecars re-created if missing

With `--fix` (default true), issues are auto-repaired and `fixed` is populated.
Without `--fix`, it only reports.

```bash
isopod maintain --roots . --depth 4
isopod maintain --roots . --no-fix --json | jq '.[] | select(.ok==false)'
```

After a fix, a second `maintain` should be clean — as demonstrated in tests
(`auto_fixes_missing_dirs`).

## Fleet cycle and ticks

`fleet` / `isopod-d run` does a full cycle:

1. **Discover** all projects under roots.
2. **Provision** all untracked.
3. **Maintain** all tracked (including newly provisioned).
4. **Tick** (optional `--tick`): for each project, run a compliance `tick`
   (`Daemon::tick`) to collect observations and update `control_results`.
   This keeps posture fresh without manual `isopod check` per project.

```bash
isopod fleet --roots ~/projects --tick --json | jq .
isopod-d run --roots ~/projects --tick --dry-run
```

## Daemon (`isopod.d`)

Periodic loop: `scan_interval_secs` (default 300) sleep between cycles.
Each cycle is `run_cycle` (discover→provision→maintain→tick) with tracing
`info!` summary (`discovered`, `untracked`, `provisioned`, `maintained`).

```bash
isopod isopod-d --roots ~/projects --interval 300 --tick
isopod-d daemon --roots ~/projects --interval 300 --tick --dry-run
# With custom roots and depth
isopod-d daemon --roots /home/sal,/srv/projects --depth 5 --interval 60
```

No PID file yet; run under `systemd` or `daemonize` (see `docs/operations.md`).

### Systemd for isopod.d

```ini
# /etc/systemd/system/isopod-d.service
[Unit]
Description=isopod.d fleet daemon
After=network.target

[Service]
User=isopod
ExecStart=/usr/local/bin/isopod-d daemon --roots /home/sal/projects --interval 300 --tick
Restart=on-failure
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now isopod-d
sudo journalctl -u isopod-d -f
```

### Watching vs polling

Current daemon is **polling** (periodic walk). A `notify`-based watch (filesystem
events, debounced) is reserved behind `#[cfg(feature="watch")]` for future
where low-latency reaction to `mkdir`/`git clone` is desired. Polling is the
source of truth; watch would be additive.

## Monitoring improvements beyond isopod.d

`isopod.d` improves monitoring in three ways:

1. **Coverage** — from one-project to fleet. No project is left untracked.
2. **Self-healing** — corrupted `state.db`, missing `controls`, deleted
   `evidence/hashes` are detected and repaired.
3. **Continuity** — with `--tick`, each cycle also updates compliance posture,
   so `isopod status` is warm when you need it, and `drift` reflects fleet
   reality.

Future roadmap: `NetworkObserver` maturity, cloud API observers, `isopod.d`
`notify` watch, Prometheus metrics from `GET /compliance`.

## Examples

```bash
# Initial fleet bootstrap on a new workstation
isopod discover --roots ~/ --depth 3
isopod fleet --roots ~/ --depth 3 --tick
isopod fleet --roots ~/ --depth 3 --json | jq '.provisioned | length'

# CI: ensure all repos under /srv are tracked, fail if any untracked remains
isopod discover --roots /srv --json | jq -e 'map(select(.has_isopod==false)) | length == 0'

# Dry-run preview for auditors
isopod-d run --roots /srv --dry-run --json | jq .
```

## Implementation notes

- `src/discover.rs` — `DiscoverConfig`, `discoveredProject`, `discover_projects` (WalkDir + ignore + marker).
- `src/provision.rs` — `provision_project`, `provision_projects`, `Config` per project, embedded defaults via `include_str!("../controls/...")`.
- `src/maintain.rs` — `maintain_project`, `maintain_projects`, health `MaintenanceReport`, auto-fix with re-seed and hash sidecar repair.
- `src/isopod_d.rs` — `IsopodDConfig`, `CycleReport`, `run_cycle`, `run_forever`, `TickResult`.
- `src/bin/isopod-d.rs` — standalone binary, stylised `render_discover/provision/maintain/cycle`, JSON modes.
- Main `isopod` CLI also exposes `discover/provision/maintain/fleet/isopod-d` for convenience (same code paths).

All outputs honour `NO_COLOR`/`ISOPOD_NO_COLOR` and `is_terminal()` via `src/style.rs`. JSON modes are machine-readable for `jq` and CI.
