# Operations

## Running

### One-shot (CI, audit)

```bash
isopod check              # stylised table, exits 1 if any FAIL
isopod check --json | jq . # machine-readable, pipe to policy engine
```

### Status dashboard

```bash
isopod status
isopod status --json > /tmp/compliance.json
isopod evidence --limit 20
isopod drift
isopod export ./audit-2026-08-07  # portable bundle
```

### Daemon

```bash
isopod daemon --interval 60 --api 127.0.0.1:8787
# logs via RUST_LOG=debug
```

`interval_secs` is the sleep between `tick` cycles. Evidence is content-hashed, so frequent ticks do not bloat the DB unless state changes.

### API only

```bash
isopod serve --addr 127.0.0.1:8787
```

## Systemd (example)

```ini
# /etc/systemd/system/isopod.service
[Unit]
Description=Isopod compliance daemon
After=network.target

[Service]
User=isopod
ExecStart=/usr/local/bin/isopod daemon --interval 60 --api 127.0.0.1:8787
Restart=on-failure
Environment=RUST_LOG=info
# State in /var/lib/isopod — set via config.yaml
# state_dir: /var/lib/isopod

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now isopod
sudo journalctl -u isopod -f
```

## Docker (example)

```dockerfile
FROM rust:1.74 as build
COPY . /src
WORKDIR /src
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=build /src/target/release/isopod /usr/local/bin/isopod
USER 1000
ENTRYPOINT ["isopod", "daemon", "--interval", "60", "--api", "0.0.0.0:8787"]
```

Mount a volume for `state_dir` to persist evidence across restarts.

## Host requirements

- Linux (systemd, `/proc/mounts`, `/var/log/*`); macOS fallback still reports `system_patch`/`certificate` but service checks via `systemctl` will be `unknown`.
- No root required for git/observer paths; audit log paths may need group read (add `isopod` to `adm`).
- `~/.isopod` must be writable; fallback to `./.isopod` in sandboxed envs.

## Exporting for audit

```bash
isopod export ./audit-2026-08-07
ls ./audit-2026-08-07
# compliance.json  evidence.json  iso27001.yaml  iso27002.yaml
tar czf audit-2026-08-07.tgz -C ./audit-2026-08-07 .
```

`compliance.json` holds `{results, drifts}`; `evidence.json` holds all artifacts with hashes. Auditors can re-hash artifacts and compare sidecars.

## Monitoring Isopod itself

- `GET /health` for liveness.
- `isopod drift` for posture changes; alert on `HIGH` severity.
- `Hellhound` can supervise Isopod as a daemon (see `docs/architecture.md` ecosystem).

## Upgrading

Isopod is governed by `Kaptaind` (`kaptaind.toml`, `VERSION`). `kaptaind-cli analyze` predicts semver bumps; `kaptaind` daemon auto-commits version bumps.

```bash
kaptaind-cli analyze
kaptaind --daemon   # watches for Kaptaind-managed versioning
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `No drift — posture stable` forever | No evidence yet | Run `isopod check` once, then `daemon` |
| `UNKNOWN` for all controls | No mapped evidence | Check `isopod evidence --limit 20` — if empty, base path wrong (`--base`) |
| `Read-only file system` on init | `$HOME` read-only (bwrap) | Uses `./.isopod` fallback automatically |
| Colours missing | Piped output or `NO_COLOR=1` | `isopod status` in TTY shows colours; `--json` never colours |
| `cargo test` 0 tests | Truncated output | `cargo test --offline` runs 14 lib tests |

Logs: `RUST_LOG=debug isopod daemon` shows `tick: collecting observations`, `COMPLIANCE_DRIFT`.

## Backup & restore

- Backup: `cp -a ~/.isopod/state.db ~/.isopod/state.db.bak` (SQLite, WAL mode).
- Restore: replace `state.db` while daemon is stopped.
- Full bundle: `isopod export` is the portable, auditor-ready restore point.
