// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
use clap::{Parser, Subcommand};
use isopod::config::Config;
use isopod::store::Store;
use isopod::style;
use std::path::PathBuf;
use std::sync::Arc;

mod cli_compliance;
mod cli_fleet;
mod cli_web;

#[derive(Parser, Debug)]
#[command(
    name = "isopod",
    version,
    about = "Isopod — autonomous compliance maintenance daemon"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[arg(long, global = true, default_value = ".")]
    base: PathBuf,

    #[arg(long, global = true, help = "Override controls directory")]
    controls: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize ~/.isopod directory and default controls
    Init,
    /// Probe an explicitly authorised deployed web target
    Probe {
        #[arg(long)]
        target: String,
        #[arg(long = "route")]
        routes: Vec<String>,
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        #[arg(long, help = "Permit plain HTTP for an authorised development target")]
        allow_http: bool,
        #[arg(
            long,
            help = "Permit private/loopback addresses for an authorised development target"
        )]
        allow_private: bool,
        #[arg(long)]
        fail_on_findings: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inventory a web project and persist source/build evidence
    Scan {
        #[arg(long)]
        json: bool,
    },
    /// Assess the web inventory using six-state assurance controls
    Assess {
        #[arg(long)]
        json: bool,
    },
    /// Generate a leverage-ranked web hardening plan
    Recommend {
        #[arg(long)]
        json: bool,
    },
    /// Propose safe hardening changes, or create missing files with --apply
    Harden {
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// One-shot compliance check
    Check {
        #[arg(long)]
        json: bool,
    },
    /// Show compliance status (like `isopod status`)
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Run as long-running daemon
    Daemon {
        #[arg(long, default_value = "60")]
        interval: u64,
        #[arg(long)]
        api: Option<String>,
    },
    /// List evidence
    Evidence {
        #[arg(long)]
        control: Option<String>,
        #[arg(long, default_value = "20")]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Show drift events
    Drift {
        #[arg(long)]
        json: bool,
    },
    /// Export audit package to directory
    Export { path: PathBuf },
    /// API server only
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        addr: String,
    },
    /// Verify evidence integrity against artifact files and hash sidecars
    Verify {
        #[arg(long)]
        id: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        json: bool,
        #[arg(long, help = "Verify the latest web hardening plan")]
        web: bool,
    },
    /// Prune evidence older than the retention window
    Prune {
        #[arg(long)]
        days: Option<u64>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show control result history
    History {
        #[arg(long)]
        control: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Discover projects (tracked vs untracked) — isopod.d discovery
    Discover {
        #[arg(long, value_delimiter = ',', default_value = ".")]
        roots: Vec<PathBuf>,
        #[arg(long, default_value_t = 4)]
        depth: usize,
        #[arg(long)]
        json: bool,
    },
    /// Provision .isopod for untracked projects — isopod.d generation
    Provision {
        #[arg(long, value_delimiter = ',', default_value = ".")]
        roots: Vec<PathBuf>,
        #[arg(long, default_value_t = 4)]
        depth: usize,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Maintain existing .isopod installations — isopod.d maintenance
    Maintain {
        #[arg(long, value_delimiter = ',', default_value = ".")]
        roots: Vec<PathBuf>,
        #[arg(long, default_value_t = 4)]
        depth: usize,
        #[arg(long, default_value_t = true)]
        fix: bool,
        #[arg(long)]
        json: bool,
    },
    /// Fleet cycle: discover → provision → maintain → optional tick (isopod.d)
    Fleet {
        #[arg(long, value_delimiter = ',', default_value = ".")]
        roots: Vec<PathBuf>,
        #[arg(long, default_value_t = 4)]
        depth: usize,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        tick: bool,
        #[arg(long)]
        json: bool,
    },
    /// Run isopod.d daemon (periodic fleet maintenance)
    #[command(name = "isopod-d")]
    IsopodD {
        #[arg(long, value_delimiter = ',', default_value = ".")]
        roots: Vec<PathBuf>,
        #[arg(long, default_value_t = 300)]
        interval: u64,
        #[arg(long, default_value_t = 4)]
        depth: usize,
        #[arg(long)]
        tick: bool,
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let mut config = Config::load_or_default(cli.config);
    if let Some(controls) = cli.controls {
        config.controls_dir = controls;
    }
    // Sandbox fallback: if home is read-only, use local .isopod
    if config
        .state_dir
        .starts_with(dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")))
        && std::fs::create_dir_all(&config.state_dir).is_err()
    {
        let fallback = PathBuf::from(".isopod");
        config.state_dir = fallback.clone();
        config.evidence_dir = fallback.join("evidence");
        config.controls_dir = fallback.join("controls");
        config.reports_dir = fallback.join("reports");
    }
    config.ensure_dirs()?;

    // Ensure controls exist — seed defaults if empty
    isopod::project::seed_controls(&config).map(|_| ())?;

    let store = Arc::new(Store::open(&config.db_path()).or_else(|_| {
        let fallback = PathBuf::from(".isopod/state.db");
        if let Some(p) = fallback.parent() {
            std::fs::create_dir_all(p)?;
        }
        Store::open(&fallback)
    })?);

    let cmd = cli.command.unwrap_or(Commands::Status { json: false });

    match cmd {
        Commands::Init => {
            isopod::project::seed_controls(&config).map(|_| ())?;
            println!("{}", style::banner());
            println!("{} {}", style::green("✓"), style::bold("Initialized"));
            println!(
                "  {} {}",
                style::dim("state   "),
                style::path(config.state_dir.display().to_string())
            );
            println!(
                "  {} {}",
                style::dim("controls"),
                style::path(config.controls_dir.display().to_string())
            );
            println!(
                "  {} {}",
                style::dim("db      "),
                style::path(config.db_path().display().to_string())
            );
            let count = isopod::control::ControlSet::load_dir(&config.controls_dir)
                .controls
                .len();
            println!(
                "  {} {} controls seeded",
                style::dim("seed    "),
                style::cyan(count.to_string())
            );
        }
        Commands::Probe {
            target,
            routes,
            timeout,
            allow_http,
            allow_private,
            fail_on_findings,
            json,
        } => {
            if cli_web::probe(
                &cli.base,
                &config,
                cli_web::ProbeArgs {
                    target,
                    routes,
                    timeout_secs: timeout,
                    allow_http,
                    allow_private,
                    fail_on_findings,
                    json,
                },
            )
            .await?
            {
                std::process::exit(1);
            }
        }
        Commands::Scan { json } => {
            cli_web::scan(&cli.base, &config, json)?;
        }
        Commands::Assess { json } => {
            cli_web::assess(&cli.base, &config, json)?;
        }
        Commands::Recommend { json } => {
            cli_web::recommend(&cli.base, &config, json)?;
        }
        Commands::Harden { apply, json } => {
            cli_web::harden(&cli.base, &config, apply, json)?;
        }
        Commands::Check { json } => {
            if cli_compliance::check(&cli.base, &config, store.clone(), json).await? {
                std::process::exit(1);
            }
        }
        Commands::Status { json } => {
            cli_compliance::status(&cli.base, &config, store.clone(), json).await?;
        }
        Commands::Daemon { interval, api } => {
            let mut daemon_config = config.clone();
            daemon_config.interval_secs = interval;
            let daemon = isopod::daemon::Daemon::new(daemon_config, store.clone());
            if let Some(addr) = api.or(config.api_addr.clone()) {
                let api_future = isopod::api::serve(
                    addr,
                    store,
                    daemon.controls.versions.clone(),
                    config.api_token.clone(),
                    config.api_rate_limit,
                );
                tokio::select! {
                    _ = daemon.run_forever(cli.base) => {}
                    result = api_future => result?,
                }
            } else {
                daemon.run_forever(cli.base).await;
            }
        }
        Commands::Evidence {
            control,
            limit,
            json,
        } => {
            let ev = store.list_evidence(control.as_deref(), limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ev)?);
            } else {
                println!(
                    "{} {}  {}",
                    style::bold("Evidence"),
                    style::dim(format!("({})", ev.len())),
                    style::dim("— audit-ready, hash-verified")
                );
                println!(
                    "{}",
                    style::dim(format!(
                        "{:<10} {:<20} {:<10} {:<14} {:<18} {}",
                        "ID", "Timestamp", "Source", "Confidence", "Type", "Control"
                    ))
                );
                println!("{}", style::dim("─".repeat(92)));
                for e in &ev {
                    let conf = style::confidence_bar(e.confidence);
                    let src = match e.source.as_str() {
                        "system" => style::blue(&e.source),
                        "git" => style::magenta(&e.source),
                        s if s.contains("traci") => style::cyan(s),
                        s => s.to_string(),
                    };
                    println!(
                        "  {}  {}  {:<10}  {}  {:<18}  {}",
                        style::dim(&e.id[..8]),
                        style::dim(e.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                        src,
                        conf,
                        style::dim(e.artifact_type.to_string()),
                        e.control_id
                            .clone()
                            .map(|c| style::id(&c))
                            .unwrap_or_else(|| style::dim("-"))
                    );
                }
                if ev.is_empty() {
                    println!(
                        "  {}",
                        style::dim("No evidence — run `isopod check` to collect")
                    );
                }
            }
        }
        Commands::Drift { json } => {
            let drifts = store.list_drifts(50)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&drifts)?);
            } else {
                if drifts.is_empty() {
                    println!(
                        "{} {}",
                        style::green("✓"),
                        style::dim("No drift — compliance posture stable")
                    );
                } else {
                    println!(
                        "{} {}  {}",
                        style::bold("Drift"),
                        style::dim(format!("({})", drifts.len())),
                        style::dim("— POSTURE CHANGED")
                    );
                    println!(
                        "{}",
                        style::dim(format!(
                            "{:<20} {:<18} {:<9} {:<9} {:<7} {}",
                            "Timestamp", "Control", "Previous", "Current", "Severity", "Cause"
                        ))
                    );
                    println!("{}", style::dim("─".repeat(96)));
                    for d in drifts {
                        let sev = match d.severity.as_str() {
                            "HIGH" => style::red(&d.severity),
                            "MEDIUM" => style::yellow(&d.severity),
                            _ => style::dim(&d.severity),
                        };
                        println!(
                            "  {}  {}  {} {} {}  {}  {}",
                            style::dim(d.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                            style::id(&d.control_id),
                            style::status(&d.previous),
                            style::dim("→"),
                            style::status(&d.current),
                            sev,
                            d.cause.unwrap_or_default()
                        );
                    }
                }
            }
        }
        Commands::Export { path } => {
            std::fs::create_dir_all(&path)?;
            let results = store.list_control_results()?;
            let evidence = store.list_evidence(None, 100_000)?;
            let drifts = store.list_drifts(1000)?;
            std::fs::write(
                path.join("compliance.json"),
                serde_json::to_string_pretty(
                    &serde_json::json!({"results": results, "drifts": drifts}),
                )?,
            )?;
            std::fs::write(
                path.join("evidence.json"),
                serde_json::to_string_pretty(&evidence)?,
            )?;
            // copy controls
            let mut copied = 0;
            for entry in std::fs::read_dir(&config.controls_dir)? {
                let entry = entry?;
                let dest = path.join(entry.file_name());
                std::fs::copy(entry.path(), dest)?;
                copied += 1;
            }
            println!(
                "{} {}",
                style::green("✓"),
                style::bold("Audit package exported")
            );
            println!(
                "  {} {}",
                style::dim("path      "),
                style::path(path.display().to_string())
            );
            println!(
                "  {} {} controls, {} evidence, {} drifts",
                style::dim("contains  "),
                style::cyan(results.len().to_string()),
                style::cyan(evidence.len().to_string()),
                style::cyan(drifts.len().to_string())
            );
            println!("  {} {} files", style::dim("controls  "), copied);
            println!(
                "  {} compliance.json  ·  evidence.json  ·  controls/*.yaml",
                style::dim("artifacts ")
            );
        }
        Commands::Serve { addr } => {
            let controls = isopod::control::ControlSet::load_dir(&config.controls_dir);
            isopod::api::serve(
                addr,
                store,
                controls.versions,
                config.api_token.clone(),
                config.api_rate_limit,
            )
            .await?;
        }
        Commands::Verify {
            id,
            limit,
            json,
            web,
        } => {
            if web {
                if cli_web::verify(&cli.base, &config, json)? {
                    std::process::exit(1);
                }
                return Ok(());
            }
            let evidence = if let Some(eid) = id {
                store
                    .list_evidence(None, limit)?
                    .into_iter()
                    .filter(|e| e.id == eid)
                    .collect::<Vec<_>>()
            } else {
                store.list_evidence(None, limit)?
            };
            let results: Vec<isopod::evidence::VerificationResult> = evidence
                .iter()
                .map(|e| isopod::evidence::verify_evidence(e, &config.evidence_dir))
                .collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                let ok = results
                    .iter()
                    .filter(|r| r.status == isopod::evidence::VerificationStatus::Ok)
                    .count();
                let mismatch = results
                    .iter()
                    .filter(|r| r.status == isopod::evidence::VerificationStatus::Mismatch)
                    .count();
                let missing = results
                    .iter()
                    .filter(|r| r.status == isopod::evidence::VerificationStatus::Missing)
                    .count();
                println!("{}", style::banner());
                println!();
                println!(
                    "  {}  {}",
                    style::bold("Verify"),
                    style::dim(format!(
                        "— {} checked, {} ok, {} mismatch, {} missing",
                        results.len(),
                        ok,
                        mismatch,
                        missing
                    ))
                );
                println!("  {}", style::dim("─".repeat(64)));
                if results.is_empty() {
                    println!("  {}", style::dim("No evidence to verify."));
                } else {
                    for r in results {
                        let status = match r.status {
                            isopod::evidence::VerificationStatus::Ok => {
                                style::green(r.status.to_string())
                            }
                            isopod::evidence::VerificationStatus::Mismatch => {
                                style::red(r.status.to_string())
                            }
                            isopod::evidence::VerificationStatus::Missing => {
                                style::yellow(r.status.to_string())
                            }
                        };
                        println!(
                            "  {} {}  {} {}",
                            status,
                            style::dim(&r.id[..8]),
                            style::dim("expected:"),
                            style::dim(&r.expected[..16])
                        );
                    }
                }
            }
        }
        Commands::Prune {
            days,
            dry_run,
            json,
        } => {
            if dry_run {
                let cutoff = if let Some(d) = days.or(config.retention_days.checked_add(0)) {
                    chrono::Utc::now() - chrono::Duration::days(d as i64)
                } else {
                    chrono::Utc::now()
                };
                let candidates = store.list_evidence_before(cutoff)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&candidates)?);
                } else {
                    println!("{}", style::banner());
                    println!();
                    println!(
                        "  {}  {}",
                        style::bold("Prune (dry-run)"),
                        style::dim(format!(
                            "{} evidence records would be pruned",
                            candidates.len()
                        ))
                    );
                }
            } else {
                let result = isopod::prune::prune_evidence_arc(&store, &config, days)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "deleted_evidence": result.deleted_evidence,
                            "deleted_artifacts": result.deleted_artifacts,
                            "deleted_sidecars": result.deleted_sidecars,
                        }))?
                    );
                } else {
                    println!("{}", style::banner());
                    println!();
                    println!("  {}  {}", style::bold("Prune"), style::dim("complete"));
                    println!(
                        "  {} {} evidence, {} artifacts, {} sidecars",
                        style::dim("deleted"),
                        style::cyan(result.deleted_evidence.to_string()),
                        style::cyan(result.deleted_artifacts.to_string()),
                        style::cyan(result.deleted_sidecars.to_string())
                    );
                }
            }
        }
        Commands::History {
            control,
            limit,
            json,
        } => {
            let history = store.list_control_result_history(control.as_deref(), limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&history)?);
            } else {
                println!("{}", style::banner());
                println!();
                println!(
                    "{} {}",
                    style::bold("Control result history"),
                    style::dim(format!("({})", history.len()))
                );
                println!(
                    "{}",
                    style::dim(format!(
                        "{:<20} {:<18} {:<9} {:<10} {}",
                        "Last checked", "Control", "Status", "Confidence", "Reason"
                    ))
                );
                println!("{}", style::dim("─".repeat(90)));
                for r in &history {
                    println!(
                        "  {}  {:<18} {:<9} {:<10} {}",
                        style::dim(r.last_checked.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                        style::id(&r.id),
                        style::status(&r.status),
                        style::confidence_bar(r.confidence),
                        r.reason.clone().unwrap_or_else(|| style::dim("-"))
                    );
                }
                if history.is_empty() {
                    println!(
                        "  {}",
                        style::dim("No history — run `isopod check` to generate results")
                    );
                }
            }
        }
        Commands::Discover { roots, depth, json } => {
            cli_fleet::discover(roots, depth, json)?;
        }
        Commands::Provision {
            roots,
            depth,
            dry_run,
            json,
        } => {
            cli_fleet::provision(roots, depth, dry_run, json).await?;
        }
        Commands::Maintain {
            roots,
            depth,
            fix,
            json,
        } => {
            cli_fleet::maintain(roots, depth, fix, json)?;
        }
        Commands::Fleet {
            roots,
            depth,
            dry_run,
            tick,
            json,
        } => {
            cli_fleet::fleet(roots, depth, dry_run, tick, json).await?;
        }
        Commands::IsopodD {
            roots,
            interval,
            depth,
            tick,
            dry_run,
        } => {
            cli_fleet::run_daemon(roots, interval, depth, tick, dry_run).await;
        }
    }

    Ok(())
}
