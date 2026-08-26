// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! isopod.d — project discovery & provisioning daemon.

use clap::{Parser, Subcommand};
use isopod::discover::{DiscoverConfig, DEFAULT_IGNORE, DEFAULT_MARKERS};
use isopod::isopod_d::{run_cycle, run_forever, IsopodDConfig};
use isopod::style;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "isopod-d",
    version,
    about = "isopod.d — discovers projects without .isopod, provisions and maintains them"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Roots to scan (default: .)
    #[arg(long, global = true, value_delimiter = ',')]
    roots: Option<Vec<PathBuf>>,

    /// Max walk depth
    #[arg(long, global = true, default_value_t = 4)]
    depth: usize,

    /// Scan interval seconds (daemon mode)
    #[arg(long, global = true, default_value_t = 300)]
    interval: u64,

    /// Also run a compliance tick for each project after provision
    #[arg(long, global = true, default_value_t = false)]
    tick: bool,

    /// Dry run (don't create, just report)
    #[arg(long, global = true, default_value_t = false)]
    dry_run: bool,

    /// Output as JSON
    #[arg(long, global = true, default_value_t = false)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Discover projects (tracked vs untracked)
    Discover,
    /// Provision .isopod for untracked projects
    Provision,
    /// Maintain existing .isopod installations
    Maintain {
        /// Auto-fix issues
        #[arg(long, default_value_t = true)]
        fix: bool,
    },
    /// Run as daemon (periodic discover→provision→maintain)
    Daemon,
    /// One-shot cycle: discover + provision + maintain + optional tick
    Run,
}

fn build_config(cli: &Cli) -> IsopodDConfig {
    let roots = cli
        .roots
        .clone()
        .unwrap_or_else(|| vec![PathBuf::from(".")]);
    IsopodDConfig {
        roots,
        scan_interval_secs: cli.interval,
        run_tick: cli.tick,
        auto_fix: true,
        max_depth: cli.depth,
        markers: DEFAULT_MARKERS.iter().map(|s| s.to_string()).collect(),
        ignore: DEFAULT_IGNORE.iter().map(|s| s.to_string()).collect(),
        dry_run: cli.dry_run,
    }
}

fn discover_config(cli: &Cli) -> DiscoverConfig {
    let roots = cli
        .roots
        .clone()
        .unwrap_or_else(|| vec![PathBuf::from(".")]);
    DiscoverConfig {
        roots,
        markers: DEFAULT_MARKERS.iter().map(|s| s.to_string()).collect(),
        max_depth: cli.depth,
        ignore: DEFAULT_IGNORE.iter().map(|s| s.to_string()).collect(),
        require_marker: true,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let cmd = cli.command.as_ref().unwrap_or(&Commands::Run);

    match cmd {
        Commands::Discover => {
            let dc = discover_config(&cli);
            let projects = isopod::discover::discover_projects(&dc);
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &projects
                            .iter()
                            .map(|p| {
                                serde_json::json!({
                                    "path": p.path,
                                    "markers": p.markers,
                                    "has_isopod": p.has_isopod,
                                    "status": if p.has_isopod { "tracked" } else { "untracked" }
                                })
                            })
                            .collect::<Vec<_>>()
                    )?
                );
            } else {
                render_discover(&projects);
            }
        }
        Commands::Provision => {
            let cfg = build_config(&cli);
            let report = run_cycle(&cfg).await;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report.provisioned)?);
            } else {
                render_provision(&report.provisioned);
            }
        }
        Commands::Maintain { fix } => {
            let dc = discover_config(&cli);
            let tracked = isopod::discover::discover_tracked(&dc);
            let paths: Vec<PathBuf> = tracked.iter().map(|p| p.path.clone()).collect();
            let reports = isopod::maintain::maintain_projects(&paths, *fix);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            } else {
                render_maintain(&reports);
            }
        }
        Commands::Daemon => {
            let cfg = build_config(&cli);
            println!("{}", style::banner());
            println!(
                "{} {}",
                style::green("●"),
                style::bold("isopod.d daemon starting")
            );
            println!(
                "  {} {}",
                style::dim("roots   "),
                cfg.roots
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "  {} {}s",
                style::dim("interval"),
                style::cyan(cfg.scan_interval_secs.to_string())
            );
            println!(
                "  {} {}",
                style::dim("depth   "),
                style::cyan(cfg.max_depth.to_string())
            );
            if cfg.dry_run {
                println!(
                    "  {} {}",
                    style::yellow("mode    "),
                    style::yellow("dry-run")
                );
            }
            run_forever(cfg).await;
        }
        Commands::Run => {
            let cfg = build_config(&cli);
            let report = run_cycle(&cfg).await;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "discovered": report.discovered,
                        "untracked": report.untracked,
                        "tracked": report.tracked,
                        "provisioned": report.provisioned,
                        "maintained": report.maintained,
                        "ticks": report.ticks,
                    }))?
                );
            } else {
                render_cycle(&report);
            }
        }
    }

    Ok(())
}

fn render_discover(projects: &[isopod::discover::DiscoveredProject]) {
    println!("{}", style::banner());
    println!();
    let untracked = projects.iter().filter(|p| p.is_untracked()).count();
    let tracked = projects.len() - untracked;
    println!(
        "  {}  {}",
        style::bold("Discovery"),
        style::dim(format!(
            "— {} projects, {} untracked, {} tracked",
            projects.len(),
            untracked,
            tracked
        ))
    );
    println!("  {}", style::dim("─".repeat(64)));
    if projects.is_empty() {
        println!(
            "  {}",
            style::dim("No projects found. Check --roots and --depth.")
        );
        return;
    }
    println!(
        "  {}",
        style::dim(format!("{:<50} {:<16} {}", "Path", "Markers", "Status"))
    );
    println!("  {}", style::dim("─".repeat(84)));
    for p in projects {
        let status = if p.has_isopod {
            style::green("tracked")
        } else {
            style::yellow("untracked")
        };
        let markers = p.markers.join(",");
        let icon = if p.has_isopod {
            style::green("●")
        } else {
            style::yellow("○")
        };
        println!(
            "  {} {}  {:<50} {:<16} {}",
            icon,
            if p.has_isopod {
                style::dim("·")
            } else {
                style::yellow("·")
            },
            style::path(p.path.display().to_string()),
            style::dim(&markers),
            status
        );
    }
    println!();
    if untracked > 0 {
        println!(
            "  {} Run {} to provision untracked projects.",
            style::dim("→"),
            style::cyan("isopod-d provision")
        );
    }
    println!(
        "  {}",
        style::dim(
            "Run `isopod-d run --tick` for a full cycle (discover→provision→maintain→tick)."
        )
    );
}

fn render_provision(results: &[isopod::provision::ProvisionResult]) {
    println!("{}", style::banner());
    println!();
    if results.is_empty() {
        println!(
            "  {} {}",
            style::green("✓"),
            style::dim("No untracked projects to provision.")
        );
        return;
    }
    println!(
        "  {}  {}",
        style::bold("Provision"),
        style::dim(format!("— {} projects", results.len()))
    );
    println!("  {}", style::dim("─".repeat(64)));
    for r in results {
        if let Some(e) = &r.error {
            println!(
                "  {} {} {}",
                style::red("✗"),
                style::path(r.path.display().to_string()),
                style::red(e)
            );
        } else if r.created {
            println!(
                "  {} {} {}",
                style::green("✓"),
                style::path(r.path.display().to_string()),
                style::dim(format!("created, {} controls seeded", r.controls_seeded))
            );
        } else {
            println!(
                "  {} {} {}",
                style::dim("·"),
                style::path(r.path.display().to_string()),
                style::dim("already provisioned")
            );
        }
    }
}

fn render_maintain(reports: &[isopod::maintain::MaintenanceReport]) {
    println!("{}", style::banner());
    println!();
    if reports.is_empty() {
        println!(
            "  {} {}",
            style::green("✓"),
            style::dim("No tracked projects to maintain.")
        );
        return;
    }
    println!(
        "  {}  {}",
        style::bold("Maintain"),
        style::dim(format!("— {} projects", reports.len()))
    );
    println!("  {}", style::dim("─".repeat(64)));
    for r in reports {
        if r.ok {
            println!(
                "  {} {} {}",
                style::green("✓"),
                style::path(r.path.display().to_string()),
                style::dim(format!(
                    "ok, {} evidence, {} controls",
                    r.evidence_count, r.controls
                ))
            );
        } else {
            println!(
                "  {} {} {}",
                style::yellow("●"),
                style::path(r.path.display().to_string()),
                style::red("issues")
            );
            for iss in &r.issues {
                println!("    {} {}", style::red("·"), iss);
            }
            for fix in &r.fixed {
                println!("    {} {}", style::green("↳"), style::dim(fix));
            }
        }
    }
}

fn render_cycle(report: &isopod::isopod_d::CycleReport) {
    println!("{}", style::banner());
    println!();
    println!(
        "  {}  {}",
        style::bold("isopod.d cycle"),
        style::dim("— discover → provision → maintain")
    );
    println!("  {}", style::dim("─".repeat(64)));
    println!(
        "  {} {}  {} {}  {} {}",
        style::dim("Discovered"),
        style::cyan(report.discovered.to_string()),
        style::yellow("Untracked"),
        style::yellow(report.untracked.to_string()),
        style::green("Tracked"),
        style::green(report.tracked.to_string())
    );
    if !report.provisioned.is_empty() {
        let ok = report
            .provisioned
            .iter()
            .filter(|r| r.error.is_none())
            .count();
        let fail = report.provisioned.len() - ok;
        println!(
            "  {} {} provisioned {} ok{}",
            style::dim("Provision"),
            style::cyan(report.provisioned.len().to_string()),
            style::green(ok.to_string()),
            if fail > 0 {
                format!(" {}", style::red(format!("{} failed", fail)))
            } else {
                "".to_string()
            }
        );
        for r in &report.provisioned {
            if let Some(e) = &r.error {
                println!(
                    "    {} {} {}",
                    style::red("✗"),
                    style::path(r.path.display().to_string()),
                    style::dim(e)
                );
            } else {
                println!(
                    "    {} {}",
                    style::green("✓"),
                    style::path(r.path.display().to_string())
                );
            }
        }
    } else {
        println!(
            "  {} {}",
            style::dim("Provision"),
            style::dim("nothing to do")
        );
    }
    if !report.maintained.is_empty() {
        let ok = report.maintained.iter().filter(|r| r.ok).count();
        println!(
            "  {} {} maintained {} ok",
            style::dim("Maintain"),
            style::cyan(report.maintained.len().to_string()),
            style::green(ok.to_string())
        );
        for r in &report.maintained {
            if !r.ok {
                println!(
                    "    {} {} {}",
                    style::yellow("●"),
                    style::path(r.path.display().to_string()),
                    style::dim(r.issues.join("; "))
                );
            }
        }
    }
    if !report.ticks.is_empty() {
        println!(
            "  {} {} ticks",
            style::dim("Tick"),
            style::cyan(report.ticks.len().to_string())
        );
        for t in &report.ticks {
            if let Some(e) = &t.error {
                println!(
                    "    {} {} → {}",
                    style::red("✗"),
                    style::path(t.path.display().to_string()),
                    e
                );
            } else {
                println!(
                    "    {} {} → {} controls",
                    style::green("✓"),
                    style::path(t.path.display().to_string()),
                    t.controls.unwrap_or(0)
                );
            }
        }
    }
    println!();
    if report.untracked == 0 && report.maintained.iter().all(|r| r.ok) {
        println!(
            "  {} {}",
            style::green("✓"),
            style::bold("All projects provisioned and healthy.")
        );
    } else if report.untracked > 0 {
        println!(
            "  {} {} untracked projects provisioned. Re-run {} to verify.",
            style::green("✓"),
            report.untracked,
            style::cyan("isopod-d discover")
        );
    }
    println!(
        "  {}",
        style::dim("Run `isopod-d daemon` for continuous fleet maintenance.")
    );
}
