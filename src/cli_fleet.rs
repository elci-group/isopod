// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
use anyhow::Result;
use isopod::{discover, isopod_d, maintain, style};
use std::path::PathBuf;

fn discovery_config(roots: Vec<PathBuf>, depth: usize) -> discover::DiscoverConfig {
    discover::DiscoverConfig {
        roots,
        markers: discover::DEFAULT_MARKERS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        max_depth: depth,
        ignore: discover::DEFAULT_IGNORE
            .iter()
            .map(|s| s.to_string())
            .collect(),
        require_marker: true,
    }
}

fn daemon_config(
    roots: Vec<PathBuf>,
    depth: usize,
    interval: u64,
    tick: bool,
    dry_run: bool,
) -> isopod_d::IsopodDConfig {
    isopod_d::IsopodDConfig {
        roots,
        scan_interval_secs: interval,
        run_tick: tick,
        auto_fix: true,
        max_depth: depth,
        markers: discover::DEFAULT_MARKERS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        ignore: discover::DEFAULT_IGNORE
            .iter()
            .map(|s| s.to_string())
            .collect(),
        dry_run,
    }
}

pub fn discover(roots: Vec<PathBuf>, depth: usize, json: bool) -> Result<()> {
    let projects = discover::discover_projects(&discovery_config(roots, depth));
    if json {
        let values = projects
            .iter()
            .map(|p| {
                serde_json::json!({
                    "path": p.path, "markers": p.markers, "has_isopod": p.has_isopod,
                    "status": if p.has_isopod { "tracked" } else { "untracked" }
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&values)?);
        return Ok(());
    }
    let untracked = projects.iter().filter(|p| p.is_untracked()).count();
    println!(
        "{}\n\n  {}  {}",
        style::banner(),
        style::bold("Discovery"),
        style::dim(format!(
            "— {} projects, {} untracked, {} tracked",
            projects.len(),
            untracked,
            projects.len() - untracked
        ))
    );
    println!("  {}", style::dim("─".repeat(64)));
    if projects.is_empty() {
        println!(
            "  {}",
            style::dim("No projects found. Check --roots and --depth.")
        );
    }
    for project in projects {
        let (icon, state) = if project.has_isopod {
            (style::green("●"), style::green("tracked"))
        } else {
            (style::yellow("○"), style::yellow("untracked"))
        };
        println!(
            "  {} {}  {:<50} {:<16} {}",
            icon,
            style::dim("·"),
            style::path(project.path.display().to_string()),
            style::dim(project.markers.join(",")),
            state
        );
    }
    if untracked > 0 {
        println!(
            "\n  {} Run {} to provision.",
            style::dim("→"),
            style::cyan("isopod provision --roots .")
        );
    }
    Ok(())
}

pub async fn provision(roots: Vec<PathBuf>, depth: usize, dry_run: bool, json: bool) -> Result<()> {
    let report = isopod_d::run_cycle(&daemon_config(roots, depth, 300, false, dry_run)).await;
    if json {
        println!("{}", serde_json::to_string_pretty(&report.provisioned)?);
        return Ok(());
    }
    if report.provisioned.is_empty() {
        println!(
            "{} {}",
            style::green("✓"),
            style::dim("No untracked projects to provision.")
        );
        return Ok(());
    }
    println!(
        "{}\n\n  {}  {}",
        style::banner(),
        style::bold("Provision"),
        style::dim(format!("— {} projects", report.provisioned.len()))
    );
    for item in report.provisioned {
        if let Some(error) = item.error {
            println!(
                "  {} {} {}",
                style::red("✗"),
                style::path(item.path.display().to_string()),
                style::red(error)
            );
        } else if item.created {
            println!(
                "  {} {} {}",
                style::green("✓"),
                style::path(item.path.display().to_string()),
                style::dim(format!("created, {} controls", item.controls_seeded))
            );
        } else {
            println!(
                "  {} {} {}",
                style::dim("·"),
                style::path(item.path.display().to_string()),
                style::dim("already provisioned")
            );
        }
    }
    Ok(())
}

pub fn maintain(roots: Vec<PathBuf>, depth: usize, fix: bool, json: bool) -> Result<()> {
    let tracked = discover::discover_tracked(&discovery_config(roots, depth));
    let paths: Vec<PathBuf> = tracked.iter().map(|p| p.path.clone()).collect();
    let reports = maintain::maintain_projects(&paths, fix);
    if json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
        return Ok(());
    }
    if reports.is_empty() {
        println!(
            "{} {}",
            style::green("✓"),
            style::dim("No tracked projects to maintain.")
        );
        return Ok(());
    }
    println!(
        "{}\n\n  {}  {}",
        style::banner(),
        style::bold("Maintain"),
        style::dim(format!("— {} projects", reports.len()))
    );
    for report in reports {
        if report.ok {
            println!(
                "  {} {} {}",
                style::green("✓"),
                style::path(report.path.display().to_string()),
                style::dim(format!(
                    "ok, {} evidence, {} controls",
                    report.evidence_count, report.controls
                ))
            );
        } else {
            println!(
                "  {} {} {}",
                style::yellow("●"),
                style::path(report.path.display().to_string()),
                style::red("issues")
            );
            for issue in report.issues {
                println!("    {} {}", style::red("·"), issue);
            }
            for repaired in report.fixed {
                println!("    {} {}", style::green("↳"), style::dim(repaired));
            }
        }
    }
    Ok(())
}

pub async fn fleet(
    roots: Vec<PathBuf>,
    depth: usize,
    dry_run: bool,
    tick: bool,
    json: bool,
) -> Result<()> {
    let report = isopod_d::run_cycle(&daemon_config(roots, depth, 300, tick, dry_run)).await;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"discovered": report.discovered, "untracked": report.untracked, "tracked": report.tracked, "provisioned": report.provisioned, "maintained": report.maintained, "ticks": report.ticks})
            )?
        );
        return Ok(());
    }
    println!(
        "{}\n\n  {}  {}",
        style::banner(),
        style::bold("isopod.d fleet cycle"),
        style::dim("— discover → provision → maintain")
    );
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
        println!(
            "  {} {} provisioned",
            style::dim("Provision"),
            style::cyan(report.provisioned.len().to_string())
        );
    }
    if !report.maintained.is_empty() {
        println!(
            "  {} {} maintained {} ok",
            style::dim("Maintain"),
            style::cyan(report.maintained.len().to_string()),
            style::green(
                report
                    .maintained
                    .iter()
                    .filter(|r| r.ok)
                    .count()
                    .to_string()
            )
        );
    }
    if !report.ticks.is_empty() {
        println!(
            "  {} {} ticks",
            style::dim("Tick"),
            style::cyan(report.ticks.len().to_string())
        );
    }
    if report.untracked == 0 && report.maintained.iter().all(|r| r.ok) {
        println!(
            "\n  {} {}",
            style::green("✓"),
            style::bold("All projects provisioned and healthy.")
        );
    }
    Ok(())
}

pub async fn run_daemon(
    roots: Vec<PathBuf>,
    interval: u64,
    depth: usize,
    tick: bool,
    dry_run: bool,
) {
    let config = daemon_config(roots, depth, interval, tick, dry_run);
    println!(
        "{}\n{} {}",
        style::banner(),
        style::green("●"),
        style::bold("isopod.d daemon starting")
    );
    println!("  {} {}", style::dim("roots   "), join_paths(&config.roots));
    println!(
        "  {} {}s",
        style::dim("interval"),
        style::cyan(config.scan_interval_secs.to_string())
    );
    isopod_d::run_forever(config).await;
}

fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        dir
    }

    #[tokio::test]
    async fn fleet_commands_cover_empty_and_project_workflows() {
        let dir = project();
        let roots = vec![dir.path().to_path_buf()];
        discover(roots.clone(), 2, false).unwrap();
        discover(roots.clone(), 2, true).unwrap();
        provision(roots.clone(), 2, true, false).await.unwrap();
        provision(roots.clone(), 2, true, true).await.unwrap();
        maintain(roots.clone(), 2, false, false).unwrap();
        maintain(roots.clone(), 2, false, true).unwrap();
        fleet(roots.clone(), 2, true, false, false).await.unwrap();
        fleet(roots, 2, true, false, true).await.unwrap();
    }

    #[test]
    fn configurations_and_path_rendering_are_deterministic() {
        let roots = vec![PathBuf::from("one"), PathBuf::from("two")];
        assert_eq!(join_paths(&roots), "one, two");
        assert_eq!(discovery_config(roots.clone(), 3).max_depth, 3);
        assert_eq!(
            daemon_config(roots, 4, 90, true, true).scan_interval_secs,
            90
        );
    }
}
