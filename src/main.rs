use clap::{Parser, Subcommand};
use isopod::config::Config;
use isopod::control::ControlStatus;
use isopod::remediation::RemediationMode;
use isopod::store::Store;
use isopod::style;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name="isopod", version, about="Isopod — autonomous compliance maintenance daemon")]
struct Cli {
    #[arg(long, global=true)]
    config: Option<PathBuf>,

    #[arg(long, global=true, default_value=".")]
    base: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize ~/.isopod directory and default controls
    Init,
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
        #[arg(long, default_value="60")]
        interval: u64,
        #[arg(long)]
        api: Option<String>,
    },
    /// List evidence
    Evidence {
        #[arg(long)]
        control: Option<String>,
        #[arg(long, default_value="20")]
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
    Export {
        path: PathBuf,
    },
    /// API server only
    Serve {
        #[arg(long, default_value="127.0.0.1:8787")]
        addr: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let mut config = Config::load_or_default(cli.config);
    // Sandbox fallback: if home is read-only, use local .isopod
    if config.state_dir.starts_with(dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))) {
        if std::fs::create_dir_all(&config.state_dir).is_err() {
            let fallback = PathBuf::from(".isopod");
            config.state_dir = fallback.clone();
            config.evidence_dir = fallback.join("evidence");
            config.controls_dir = fallback.join("controls");
            config.reports_dir = fallback.join("reports");
        }
    }
    let _ = config.ensure_dirs();

    // Ensure controls exist — seed defaults if empty
    let _ = seed_controls_if_needed(&config);

    let store = Arc::new(
        Store::open(&config.db_path())
            .or_else(|_| {
                let fallback = PathBuf::from(".isopod/state.db");
                if let Some(p) = fallback.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                Store::open(&fallback)
            })?,
    );

    let cmd = cli.command.unwrap_or(Commands::Status { json: false });

    match cmd {
        Commands::Init => {
            seed_controls_if_needed(&config)?;
            println!("{}", style::banner());
            println!("{} {}", style::green("✓"), style::bold("Initialized"));
            println!("  {} {}", style::dim("state   "), style::path(&config.state_dir.display().to_string()));
            println!("  {} {}", style::dim("controls"), style::path(&config.controls_dir.display().to_string()));
            println!("  {} {}", style::dim("db      "), style::path(&config.db_path().display().to_string()));
            let count = isopod::control::ControlSet::load_dir(&config.controls_dir).controls.len();
            println!("  {} {} controls seeded", style::dim("seed    "), style::cyan(&count.to_string()));
        }
        Commands::Check { json } => {
            let daemon = isopod::daemon::Daemon::new(config.clone(), store.clone());
            let results = daemon.tick(&cli.base).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                render_status(&results);
            }
            // exit code 1 if any failing
            if results.iter().any(|r| r.status == ControlStatus::Fail) {
                std::process::exit(1);
            }
        }
        Commands::Status { json } => {
            // If no results yet, run a tick implicitly
            let mut results = store.list_control_results()?;
            if results.is_empty() {
                let daemon = isopod::daemon::Daemon::new(config.clone(), store.clone());
                results = daemon.tick(&cli.base).await?;
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                render_status(&results);
                // also show remediations for failing
                let rems = isopod::remediation::for_results(&results, RemediationMode::Advisory);
                if !rems.is_empty() {
                    println!("\n{} {}", style::yellow("▸"), style::bold("Remediation — advisory"));
                    for r in rems.iter().take(5) {
                        let sev = match r.severity.as_str() {
                            "high" => style::red(&r.severity),
                            "medium" => style::yellow(&r.severity),
                            _ => style::dim(&r.severity),
                        };
                        println!("  {} {} {} {}", style::dim("─"), style::id(&r.control_id), style::bold(&r.title), format!("({sev})"));
                        println!("    {}", style::dim(&r.description));
                        for a in &r.actions {
                            println!("    {} {}", style::dim("·"), a);
                        }
                    }
                }
                let drifts = store.list_drifts(5)?;
                if !drifts.is_empty() {
                    println!("\n{} {}", style::red("▸"), style::bold("Recent drift"));
                    for d in drifts {
                        let sev = match d.severity.as_str() {
                            "HIGH" => style::red(&d.severity),
                            "MEDIUM" => style::yellow(&d.severity),
                            _ => style::dim(&d.severity),
                        };
                        println!(
                            "  {} {}  {} {} {}  {}  {}",
                            style::red("COMPLIANCE_DRIFT"),
                            style::id(&d.control_id),
                            style::status(&d.previous),
                            style::dim("→"),
                            style::status(&d.current),
                            sev,
                            d.cause.clone().unwrap_or_default()
                        );
                    }
                } else {
                    println!("\n{} {}", style::dim("─"), style::dim("No drift — posture stable"));
                }
            }
        }
        Commands::Daemon { interval, api } => {
            if interval != 60 {
                // override
                let mut cfg = config.clone();
                cfg.interval_secs = interval;
                let daemon = isopod::daemon::Daemon::new(cfg, store.clone());
                let api_addr = api.or(config.api_addr.clone());
                if let Some(addr) = api_addr {
                    let s = store.clone();
                    tokio::spawn(async move {
                        if let Err(e) = isopod::api::serve(addr, s).await {
                            eprintln!("api error: {e}");
                        }
                    });
                }
                daemon.run_forever(cli.base).await;
            } else {
                let daemon = isopod::daemon::Daemon::new(config.clone(), store.clone());
                if let Some(addr) = api.or(config.api_addr.clone()) {
                    let s = store.clone();
                    tokio::spawn(async move {
                        if let Err(e) = isopod::api::serve(addr, s).await {
                            eprintln!("api error: {e}");
                        }
                    });
                }
                daemon.run_forever(cli.base).await;
            }
        }
        Commands::Evidence { control, limit, json } => {
            let ev = store.list_evidence(control.as_deref(), limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ev)?);
            } else {
                println!("{} {}  {}", style::bold("Evidence"), style::dim(&format!("({})", ev.len())), style::dim("— audit-ready, hash-verified"));
                println!("{}", style::dim(&format!("{:<10} {:<20} {:<10} {:<14} {:<18} {}", "ID", "Timestamp", "Source", "Confidence", "Type", "Control")));
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
                        style::dim(&e.id[..8].to_string()),
                        style::dim(&e.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                        src,
                        conf,
                        style::dim(&e.artifact_type.to_string()),
                        e.control_id.clone().map(|c| style::id(&c)).unwrap_or_else(|| style::dim("-"))
                    );
                }
                if ev.is_empty() {
                    println!("  {}", style::dim("No evidence — run `isopod check` to collect"));
                }
            }
        }
        Commands::Drift { json } => {
            let drifts = store.list_drifts(50)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&drifts)?);
            } else {
                if drifts.is_empty() {
                    println!("{} {}", style::green("✓"), style::dim("No drift — compliance posture stable"));
                } else {
                    println!("{} {}  {}", style::bold("Drift"), style::dim(&format!("({})", drifts.len())), style::dim("— POSTURE CHANGED"));
                    println!("{}", style::dim(&format!("{:<20} {:<18} {:<9} {:<9} {:<7} {}", "Timestamp", "Control", "Previous", "Current", "Severity", "Cause")));
                    println!("{}", style::dim("─".repeat(96)));
                    for d in drifts {
                        let sev = match d.severity.as_str() {
                            "HIGH" => style::red(&d.severity),
                            "MEDIUM" => style::yellow(&d.severity),
                            _ => style::dim(&d.severity),
                        };
                        println!(
                            "  {}  {}  {} {} {}  {}  {}",
                            style::dim(&d.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
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
                serde_json::to_string_pretty(&serde_json::json!({"results": results, "drifts": drifts}))?,
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
            println!("{} {}", style::green("✓"), style::bold("Audit package exported"));
            println!("  {} {}", style::dim("path      "), style::path(&path.display().to_string()));
            println!("  {} {} controls, {} evidence, {} drifts", style::dim("contains  "), style::cyan(&results.len().to_string()), style::cyan(&evidence.len().to_string()), style::cyan(&drifts.len().to_string()));
            println!("  {} {} files", style::dim("controls  "), copied);
            println!("  {} compliance.json  ·  evidence.json  ·  controls/*.yaml", style::dim("artifacts "));
        }
        Commands::Serve { addr } => {
            isopod::api::serve(addr, store).await?;
        }
    }

    Ok(())
}

fn render_status(results: &[isopod::control::ControlResult]) {
    let total = results.len();
    let passing = results.iter().filter(|r| r.status == ControlStatus::Pass).count();
    let warning = results.iter().filter(|r| r.status == ControlStatus::Warning).count();
    let failing = results.iter().filter(|r| r.status == ControlStatus::Fail).count();
    let unknown = results.iter().filter(|r| r.status == ControlStatus::Unknown).count();

    // Header dashboard
    println!("{}", style::banner());
    println!();
    println!("  {}  {}", style::bold("ISO 27001"), style::dim("— Information Security Management"));
    println!("  {}", style::dim("─".repeat(52)));
    let pass_s = if passing > 0 { style::green(&passing.to_string()) } else { style::dim(&passing.to_string()) };
    let warn_s = if warning > 0 { style::yellow(&warning.to_string()) } else { style::dim(&warning.to_string()) };
    let fail_s = if failing > 0 { style::red(&failing.to_string()) } else { style::dim(&failing.to_string()) };
    let unk_s = style::dim(&unknown.to_string());
    println!("  {} {:>3}  {} {:>3}  {} {:>3}  {} {:>3}  {} {:>3}",
        style::dim("Controls"), style::cyan(&total.to_string()),
        style::green("Pass"), pass_s,
        style::yellow("Warn"), warn_s,
        style::red("Fail"), fail_s,
        style::dim("Unknown"), unk_s
    );
    // Score bar
    let score = if total > 0 { (passing as f32 / total as f32 * 100.0).round() as u8 } else { 0 };
    let bar_filled = (score as f32 / 100.0 * 24.0).round() as usize;
    let bar = format!("{}{}", "█".repeat(bar_filled), "░".repeat(24 - bar_filled));
    let bar_c = if score >= 80 { style::green(&bar) } else if score >= 50 { style::yellow(&bar) } else { style::red(&bar) };
    println!("  {} {} {}%", style::dim("Posture"), bar_c, style::bold(&score.to_string()));
    println!();

    // Critical findings first
    let critical: Vec<_> = results.iter().filter(|r| r.status == ControlStatus::Fail).collect();
    if !critical.is_empty() {
        println!("  {} {}", style::red("▸"), style::bold(&format!("Critical Findings ({}):", critical.len())));
        for c in critical {
            println!("    {} {} — {}", style::red("●"), style::id(&c.id), style::bold(&c.title));
            if let Some(reason) = &c.reason {
                println!("      {} {}", style::dim("reason:"), reason);
            }
            if let Some(rem) = &c.remediation {
                println!("      {} {}", style::dim("fix:"), rem);
            }
            println!("      {} {} artifacts  {} {}", style::dim("evidence:"), style::cyan(&c.evidence_count.to_string()), style::dim("confidence"), style::confidence_bar(c.confidence));
        }
        println!();
    }

    // Warning block
    let warnings: Vec<_> = results.iter().filter(|r| r.status == ControlStatus::Warning).collect();
    if !warnings.is_empty() {
        println!("  {} {}", style::yellow("▸"), style::bold(&format!("Warnings ({}):", warnings.len())));
        for w in warnings.iter().take(3) {
            println!("    {} {} — {} {}", style::yellow("●"), style::id(&w.id), w.title, style::dim(&format!("({} evidence)", w.evidence_count)));
        }
        if warnings.len() > 3 {
            println!("    {}", style::dim(&format!("… and {} more", warnings.len() - 3)));
        }
        println!();
    }

    // Table
    println!("  {}", style::bold("Controls"));
    println!("  {}", style::dim(&format!("{:<22} {:<14} {:<10} {:<16} {}", "ID", "Status", "Evidence", "Confidence", "Title")));
    println!("  {}", style::dim("─".repeat(88)));
    for r in results {
        let st = style::status_with_icon(&r.status);
        let conf = style::confidence_bar(r.confidence);
        let evidence = if r.evidence_count == 0 { style::dim(&r.evidence_count.to_string()) } else { style::cyan(&r.evidence_count.to_string()) };
        println!(
            "  {:<22} {:<14} {:<10} {:<16} {}",
            style::id(&r.id),
            st,
            evidence,
            conf,
            r.title
        );
    }
    println!();
    println!("  {}", style::dim("Run `isopod evidence --limit 20` for artifacts · `isopod drift` for posture changes · `isopod export ./audit` for audit package"));
}

fn seed_controls_if_needed(config: &Config) -> anyhow::Result<()> {
    if std::fs::read_dir(&config.controls_dir)?.next().is_none() {
        for (name, content) in default_controls() {
            let path = config.controls_dir.join(name);
            if !path.exists() {
                std::fs::write(path, content)?;
            }
        }
    }
    Ok(())
}

fn default_controls() -> Vec<(&'static str, &'static str)> {
    vec![
        ("iso27001.yaml", include_str!("../controls/iso27001.yaml")),
        ("iso27002.yaml", include_str!("../controls/iso27002.yaml")),
    ]
}
