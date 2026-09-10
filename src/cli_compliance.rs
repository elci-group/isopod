// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
use anyhow::Result;
use isopod::{
    config::Config,
    control::{self, ControlResult, ControlStatus},
    daemon::Daemon,
    remediation::{self, RemediationMode},
    store::Store,
    style,
};
use std::collections::BTreeSet;
use std::io::Write;
use std::time::Duration;
use std::{path::Path, sync::Arc};

const POSTURE_TRACK_WIDTH: usize = 32;
const POSTURE_CRAWL_FRAMES: u32 = 24;

/// Crawl a small isopod across a track towards `score` before printing the
/// posture line in place of it. No-ops when animation is disabled (piped
/// output, `NO_COLOR`, `ISOPOD_NO_ANIMATION`, `TERM=dumb`, ...).
fn animate_compliance_posture(score: f32) {
    if !style::animations_enabled() {
        return;
    }
    let target = (score / 100.0).clamp(0.0, 1.0);
    let mut stdout = std::io::stdout();
    for tick in 0..=POSTURE_CRAWL_FRAMES {
        let progress = target * tick as f32 / POSTURE_CRAWL_FRAMES as f32;
        let _ = write!(stdout, "\r  {}", render_isopod_crawl(progress));
        let _ = stdout.flush();
        std::thread::sleep(Duration::from_millis(28));
    }
    let _ = write!(stdout, "\r\x1b[2K");
    let _ = stdout.flush();
}

fn render_isopod_crawl(progress: f32) -> String {
    let position = (progress * POSTURE_TRACK_WIDTH as f32)
        .round()
        .clamp(0.0, POSTURE_TRACK_WIDTH as f32) as usize;
    format!(
        "{}🐛{}",
        "·".repeat(position),
        "·".repeat(POSTURE_TRACK_WIDTH.saturating_sub(position))
    )
}

pub async fn check(base: &Path, config: &Config, store: Arc<Store>, json: bool) -> Result<bool> {
    let results = Daemon::new(config.clone(), store).tick(base).await?;
    output_results(&results, json)?;
    Ok(has_failures(&results))
}

pub async fn assess(
    base: &Path,
    config: &Config,
    store: Arc<Store>,
    frameworks: &[String],
    json: bool,
) -> Result<bool> {
    let selected = frameworks
        .iter()
        .map(|framework| isopod::assurance::canonical_framework_id(framework).to_owned())
        .collect::<BTreeSet<_>>();
    let results = Daemon::new(config.clone(), store)
        .tick(base)
        .await?
        .into_iter()
        .filter(|result| selected.contains(&result.framework))
        .collect::<Vec<_>>();
    if results.is_empty() {
        anyhow::bail!(
            "none of the selected frameworks are installed: {}",
            selected.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    output_results(&results, json)?;
    Ok(has_failures(&results))
}

pub async fn status(base: &Path, config: &Config, store: Arc<Store>, json: bool) -> Result<()> {
    let mut results = store.list_control_results()?;
    if results.is_empty() {
        results = Daemon::new(config.clone(), store.clone())
            .tick(base)
            .await?;
    }
    output_results(&results, json)?;
    if json {
        return Ok(());
    }
    let remediations = remediation::for_results(&results, RemediationMode::Advisory);
    if !remediations.is_empty() {
        println!(
            "\n{} {}",
            style::yellow("▸"),
            style::bold("Remediation — advisory")
        );
        for item in remediations.iter().take(5) {
            let severity = match item.severity.as_str() {
                "high" => style::red(&item.severity),
                "medium" => style::yellow(&item.severity),
                _ => style::dim(&item.severity),
            };
            println!(
                "  {} {} {} ({severity})",
                style::dim("─"),
                style::id(&item.control_id),
                style::bold(&item.title)
            );
            println!("    {}", style::dim(&item.description));
            for action in &item.actions {
                println!("    {} {}", style::dim("·"), action);
            }
        }
    }
    let drifts = store.list_drifts(5)?;
    if drifts.is_empty() {
        println!(
            "\n{} {}",
            style::dim("─"),
            style::dim("No drift — posture stable")
        );
    } else {
        println!("\n{} {}", style::red("▸"), style::bold("Recent drift"));
        for drift in drifts {
            let severity = match drift.severity.as_str() {
                "HIGH" => style::red(&drift.severity),
                "MEDIUM" => style::yellow(&drift.severity),
                _ => style::dim(&drift.severity),
            };
            println!(
                "  {} {}  {} {} {}  {}  {}",
                style::red("COMPLIANCE_DRIFT"),
                style::id(&drift.control_id),
                style::status(&drift.previous),
                style::dim("→"),
                style::status(&drift.current),
                severity,
                drift.cause.unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn output_results(results: &[ControlResult], json: bool) -> Result<()> {
    let frameworks = control::framework_summary(results);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"frameworks": frameworks, "controls": results})
            )?
        );
    } else {
        render(results);
    }
    Ok(())
}

fn has_failures(results: &[ControlResult]) -> bool {
    results.iter().any(|r| r.status == ControlStatus::Fail)
}

fn render(results: &[ControlResult]) {
    let total = results.len();
    let passing = results
        .iter()
        .filter(|r| r.status == ControlStatus::Pass)
        .count();
    let warning = results
        .iter()
        .filter(|r| r.status == ControlStatus::Warning)
        .count();
    let failing = results
        .iter()
        .filter(|r| r.status == ControlStatus::Fail)
        .count();
    let unknown = results
        .iter()
        .filter(|r| r.status == ControlStatus::Unknown)
        .count();
    let score = if total == 0 {
        0.0
    } else {
        passing as f32 / total as f32 * 100.0
    };
    println!("{}\n", style::banner());
    animate_compliance_posture(score);
    println!(
        "  {}  {}%",
        style::bold("Compliance posture"),
        style::bold(format!("{score:.0}"))
    );
    println!(
        "  {} {}  {} {}  {} {}  {} {}",
        style::green("✓"),
        style::green(format!("{passing} passing")),
        style::yellow("●"),
        style::yellow(format!("{warning} warning")),
        style::red("✗"),
        style::red(format!("{failing} failing")),
        style::dim("?"),
        style::dim(format!("{unknown} unknown"))
    );
    println!("\n  {}", style::dim("─".repeat(78)));
    for result in results {
        println!(
            "  {:<20} {:<14} {}",
            style::id(&result.id),
            style::status_with_icon(&result.status),
            style::confidence_bar(result.confidence)
        );
        if let Some(reason) = &result.reason {
            println!("      {}", style::dim(reason));
        }
    }
    println!("  {}", style::dim("─".repeat(78)));
    let frameworks = control::framework_summary(results);
    if !frameworks.is_empty() {
        println!("\n  {}", style::bold("Framework coverage"));
        for framework in frameworks {
            let posture = framework
                .score
                .map_or_else(|| "ungraded".to_owned(), |score| format!("{score}%"));
            println!(
                "    {:<18} assessed {:>2}/{:<2}  coverage {:>3}%  posture {}",
                framework.framework,
                framework.assessed,
                framework.total,
                framework.coverage,
                posture
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn result(id: &str, status: ControlStatus) -> ControlResult {
        ControlResult {
            id: id.into(),
            title: id.into(),
            framework: "owasp".into(),
            status,
            evidence_count: 1,
            confidence: 0.9,
            last_checked: Utc::now(),
            reason: Some("reason".into()),
            remediation: Some("fix".into()),
        }
    }

    #[test]
    fn local_isopod_crawl_is_bounded() {
        assert_eq!(render_isopod_crawl(-1.0).matches('·').count(), 32);
        assert_eq!(
            render_isopod_crawl(0.5),
            "·".repeat(16) + "🐛" + &"·".repeat(16)
        );
        assert_eq!(render_isopod_crawl(2.0).matches('·').count(), 32);
    }

    #[test]
    fn rendering_and_json_cover_all_control_states() {
        let results = vec![
            result("PASS", ControlStatus::Pass),
            result("WARN", ControlStatus::Warning),
            result("FAIL", ControlStatus::Fail),
            result("UNKNOWN", ControlStatus::Unknown),
        ];
        output_results(&results, false).unwrap();
        output_results(&results, true).unwrap();
        assert!(has_failures(&results));
        assert!(!has_failures(&[result("PASS", ControlStatus::Pass)]));
    }

    #[tokio::test]
    async fn status_reads_persisted_results_without_running_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let config = Config {
            state_dir: state.clone(),
            evidence_dir: state.join("evidence"),
            controls_dir: state.join("controls"),
            reports_dir: state.join("reports"),
            interval_secs: 60,
            api_addr: None,
            api_token: None,
            api_rate_limit: 0,
            frameworks: vec!["owasp".into()],
            retention_days: 0,
        };
        config.ensure_dirs().unwrap();
        let store = Arc::new(Store::open(&config.db_path()).unwrap());
        store
            .upsert_control_result(&result("PASS", ControlStatus::Pass))
            .unwrap();
        status(dir.path(), &config, store.clone(), false)
            .await
            .unwrap();
        status(dir.path(), &config, store, true).await.unwrap();
    }
}
