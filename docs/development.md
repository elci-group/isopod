# Development

## Prerequisites

- Rust 1.74+ (`rustup default stable`)
- Linux or macOS (system observers degrade gracefully on macOS)
- `pkg-config`, `libsqlite3` (or use `rusqlite` bundled feature, already enabled)

## Setup

```bash
git clone https://github.com/elci-group/isopod.git
cd isopod
cargo build --offline   # deps are cached; offline works
cargo test --offline    # 14 lib tests
./target/debug/isopod status --json | jq .
```

## Project layout

```
.
├── Cargo.toml
├── src/
│   ├── lib.rs          crate root, re-exports
│   ├── main.rs         CLI (clap, stylised rendering)
│   ├── style.rs        TTY-aware ANSI helpers
│   ├── config.rs       local-first config + fallback
│   ├── evidence.rs     Evidence / Observation + SHA-256
│   ├── control.rs      ControlSet, evaluation
│   ├── store.rs        rusqlite Store
│   ├── drift.rs        DriftEvent, detect()
│   ├── remediation.rs  Advisory/Assisted/Autonomous
│   ├── daemon.rs       tick + run_forever
│   ├── api.rs          Axum router
│   └── observer/
│       ├── mod.rs      Observer trait, Composite, Ecosystem
│       ├── git.rs      GitObserver (git CLI)
│       └── system.rs   SystemObserver (systemctl, /proc, etc.)
├── controls/
│   ├── iso27001.yaml
│   └── iso27002.yaml
├── docs/
└── goglz.yaml          doc revision config (Groq LLaMA 3.3 70B)
```

Run `bart --json` or `bart --insights` for size profiling; `deckhand status` for artifact sizes.

## Style

- CLI output via `src/style.rs` — no external colour crate, manual ANSI, `is_terminal()` gated, `NO_COLOR` honoured. Keep tables aligned; ANSI codes are invisible for width — use `AsRef<str>` helpers.
- Docs: active voice, concise, examples first, consistent `kebab-case`/`snake_case`, no purple gradients or `bg-clip-text` (see `taste` skill).

## Testing

```bash
cargo test --offline
cargo test -- --nocapture  # see tracing
```

Tests in `evidence`, `control`, `drift`, `store` assert hashing, confidence clamping, `UNKNOWN` without evidence, `PASS` with high confidence, drift `HIGH` for `PASS→FAIL`.

## Linting

```
cargo clippy --offline -- -D warnings  # clippy deny in Cargo.toml lints
```

`lints.clippy.all = "deny"` and `lints.rust.unsafe_code = "forbid"` are set.

## Docs

- Rustdoc: `cargo doc --offline --open` (lib.rs and module docs).
- Markdown: `goglz revise --directory .` (requires `GROQ_API_KEY` in `~/.goglz` or `/tmp/home/.goglz` with `llama-3.3-70b-versatile`). Run as:
  ```bash
  HOME=/tmp/home /tmp/goglz-target/debug/goglz revise --directory .
  ```
  The current `README.md` was produced with that pipeline and manually verified.

## Versioning

Kaptaind governs versioning:

```bash
kaptaind-cli analyze          # dry-run, e.g., Patch → v0.1.1
kaptaind-cli log --limit 10
```

`VERSION` mirrors `Cargo.toml` `version`. Do not hand-edit `Cargo.lock` or `VERSION` for version bumps; let Kaptaind commit.

## Deliver

Before handoff:

```bash
deliver --file Cargo.toml --file src/main.rs --file README.md
bart --insights
deckhand status
cargo test --offline
```

`deliver` checks file existence + byte size; it is not a test runner.

## Adding a control pack

See `docs/controls.md`. Drop `controls/my.yaml`, run `isopod check`, verify in `isopod status`.

## Adding an observer

Implement `Observer` in `src/observer/my.rs`:

```rust
#[async_trait]
impl Observer for MyObserver {
  fn name(&self) -> &str { "my" }
  async fn collect(&self) -> anyhow::Result<Vec<Observation>> { … }
}
```

Register in `observer::CompositeObserver::with_defaults` and extend `daemon::map_observation_to_control`.

## API tests

Router is testable without network:

```rust
let store = Arc::new(Store::open_in_memory()?);
let app = isopod::api::router(store);
let req = Request::builder().uri("/health").body(Body::empty())?;
let res = app.oneshot(req).await?;
```

## Release

`cargo build --release` (LTO thin, stripped). Binary at `target/release/isopod` (70 MB debug, ~15 MB release stripped).

## Troubleshooting for contributors

- `Read-only file system` on `git add` in sandbox — Isopod's own `.git` is bwrap read-only; use `/tmp/isopod-repo` as writable clone (see `docs/operations.md`).
- `model_decommissioned` from Groq — update `~/.goglz` `groq.model` to `llama-3.3-70b-versatile`.
- `cargo build` spurious network error — use `--offline` (deps cached).
