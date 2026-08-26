// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
use anyhow::Result;
use isopod::{
    config::Config,
    runtime::{ProbeStatus, RuntimeProbeConfig, RuntimeProbeReport},
    style,
    web_assurance::{self, AssessmentReport, HardeningPlan},
};
use std::path::Path;

pub struct ProbeArgs {
    pub target: String,
    pub routes: Vec<String>,
    pub timeout_secs: u64,
    pub allow_http: bool,
    pub allow_private: bool,
    pub fail_on_findings: bool,
    pub json: bool,
}

pub async fn probe(base: &Path, config: &Config, args: ProbeArgs) -> Result<bool> {
    let project_root = base
        .canonicalize()
        .unwrap_or_else(|_| base.to_path_buf())
        .display()
        .to_string();
    let report = isopod::runtime::probe(&RuntimeProbeConfig {
        project_root,
        target: args.target,
        routes: args.routes,
        timeout_secs: args.timeout_secs,
        allow_http: args.allow_http,
        allow_private: args.allow_private,
    })
    .await?;
    let path = web_assurance::write_report(
        &config.reports_dir,
        web_assurance::runtime_report_name(),
        &report,
    )?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_runtime(&report);
        report_path(&path);
    }
    Ok(args.fail_on_findings && matches!(report.status, ProbeStatus::Fail))
}

pub fn scan(base: &Path, config: &Config, json: bool) -> Result<()> {
    let inventory = web_assurance::scan(base)?;
    let path = web_assurance::write_report(
        &config.reports_dir,
        web_assurance::scan_report_name(),
        &inventory,
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&inventory)?);
    } else {
        println!(
            "{}\n\n  {}  {}",
            style::banner(),
            style::bold("Web scan"),
            style::green("complete")
        );
        println!("  {} {}", style::dim("kind       "), inventory.project_kind);
        println!(
            "  {} {}",
            style::dim("frameworks "),
            list(&inventory.frameworks)
        );
        println!(
            "  {} {}",
            style::dim("manifests  "),
            inventory.manifests.len()
        );
        println!(
            "  {} {}",
            style::dim("lockfiles  "),
            inventory.lockfiles.len()
        );
        report_path(&path);
    }
    Ok(())
}

fn current_assessment(base: &Path, config: &Config) -> Result<AssessmentReport> {
    let inventory = web_assurance::scan(base)?;
    let runtime = web_assurance::read_runtime_report_optional(&config.reports_dir)?;
    web_assurance::write_report(
        &config.reports_dir,
        web_assurance::scan_report_name(),
        &inventory,
    )?;
    Ok(web_assurance::assess_with_runtime(
        &inventory,
        runtime.as_ref(),
    ))
}

pub fn assess(base: &Path, config: &Config, json: bool) -> Result<()> {
    let report = current_assessment(base, config)?;
    let path = web_assurance::write_report(
        &config.reports_dir,
        web_assurance::assessment_report_name(),
        &report,
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_assessment(&report);
        report_path(&path);
    }
    Ok(())
}

pub fn recommend(base: &Path, config: &Config, json: bool) -> Result<()> {
    let plan = web_assurance::recommend(&current_assessment(base, config)?);
    let path = web_assurance::write_report(
        &config.reports_dir,
        web_assurance::plan_report_name(),
        &plan,
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        render_plan(&plan);
        report_path(&path);
    }
    Ok(())
}

pub fn harden(base: &Path, config: &Config, apply: bool, json: bool) -> Result<()> {
    let plan = web_assurance::recommend(&current_assessment(base, config)?);
    let path = web_assurance::write_report(
        &config.reports_dir,
        web_assurance::plan_report_name(),
        &plan,
    )?;
    let results = if apply {
        web_assurance::apply(&plan)
    } else {
        Vec::new()
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"mode": if apply { "apply" } else { "proposal" }, "plan": plan, "results": results})
            )?
        );
    } else {
        render_plan(&plan);
        println!(
            "\n  {} {}",
            style::dim("mode"),
            if apply { "apply" } else { "proposal only" }
        );
        for result in results {
            println!(
                "  {} {} — {}",
                status(&result.status),
                result.action_id,
                result.detail
            );
        }
        report_path(&path);
        if !apply {
            println!(
                "  {}",
                style::dim("Re-run with --apply to create missing safe-baseline files.")
            );
        }
    }
    Ok(())
}

pub fn verify(base: &Path, config: &Config, json: bool) -> Result<bool> {
    let plan = web_assurance::read_plan(&config.reports_dir).or_else(|_| {
        let inventory = web_assurance::scan(base)?;
        Ok::<_, anyhow::Error>(web_assurance::recommend(&web_assurance::assess(&inventory)))
    })?;
    let results = web_assurance::verify(&plan);
    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        let pass = results.iter().filter(|r| r.status == "pass").count();
        let fail = results.iter().filter(|r| r.status == "fail").count();
        let unknown = results.iter().filter(|r| r.status == "unknown").count();
        println!(
            "{}\n\n  {} — {pass} pass, {fail} fail, {unknown} unknown",
            style::banner(),
            style::bold("Web verification")
        );
        for result in &results {
            println!(
                "  {} {} — {}",
                status(&result.status),
                result.action_id,
                result.observation
            );
        }
    }
    Ok(results.iter().any(|r| r.status == "fail"))
}

fn list(items: &[String]) -> String {
    if items.is_empty() {
        "none detected".into()
    } else {
        items.join(", ")
    }
}
fn status(value: &str) -> String {
    match value {
        "pass" | "applied" => style::green(value),
        "fail" | "error" => style::red(value),
        "unknown" | "skipped" => style::yellow(value),
        _ => style::dim(value),
    }
}
fn probe_status(value: &ProbeStatus) -> String {
    match value {
        ProbeStatus::Pass => style::green("PASS"),
        ProbeStatus::Partial => style::yellow("PARTIAL"),
        ProbeStatus::Fail => style::red("FAIL"),
        ProbeStatus::UnableToVerify => style::dim("UNKNOWN"),
    }
}
fn report_path(path: &Path) {
    println!(
        "\n  {} {}",
        style::dim("report"),
        style::path(path.display().to_string())
    );
}

fn render_runtime(report: &RuntimeProbeReport) {
    println!(
        "{}\n\n  {}  {}",
        style::banner(),
        style::bold("Runtime assurance probe"),
        probe_status(&report.status)
    );
    println!(
        "  {} {}\n  {} {}\n  {} {}",
        style::dim("target"),
        report.target_origin,
        style::dim("resolved"),
        report.resolved_addresses.join(", "),
        style::dim("routes"),
        report.routes.len()
    );
    for route in &report.routes {
        println!(
            "  {} {:<20} HTTP {} · {:.1}ms",
            probe_status(&route.status),
            route.url,
            route.status_code,
            route.timings_ms.total
        );
        for finding in &route.checks {
            println!(
                "    {} {} — {}",
                probe_status(&finding.status),
                finding.id,
                finding.observed.as_deref().unwrap_or("not observed")
            );
        }
    }
}

fn render_assessment(report: &AssessmentReport) {
    use web_assurance::AssuranceState;
    println!("{}\n\n  {}", style::banner(), style::bold("Web assurance"));
    println!(
        "  {} {}\n  {} {} controls\n",
        style::dim("project"),
        report.project_root,
        style::dim("scope"),
        report.controls.len()
    );
    for control in &report.controls {
        let state = match control.current_state {
            AssuranceState::Compliant => style::green("COMPLIANT"),
            AssuranceState::PartiallyCompliant => style::yellow("PARTIAL"),
            AssuranceState::NonCompliant => style::red("NON-COMPLIANT"),
            AssuranceState::NotApplicable => style::dim("N/A"),
            AssuranceState::Unknown => style::dim("UNKNOWN"),
            AssuranceState::UnableToVerify => style::yellow("UNABLE TO VERIFY"),
        };
        println!(
            "  {} {}  {}",
            state,
            style::id(&control.id),
            style::bold(&control.requirement)
        );
        println!("    {}", style::dim(&control.risk));
        println!(
            "    confidence {:.2} · severity {} · {}",
            control.confidence, control.severity, control.verification_method
        );
    }
}

fn render_plan(plan: &HardeningPlan) {
    println!(
        "{}\n\n  {} — {} action(s)",
        style::banner(),
        style::bold("Web hardening plan"),
        plan.actions.len()
    );
    for action in &plan.actions {
        println!(
            "\n  {} {}  {}",
            style::cyan(&action.phase),
            style::id(&action.id),
            style::bold(&action.title)
        );
        println!("    {}", action.description);
        println!(
            "    {} findings · {} min · severity {} · {}",
            action.leverage, action.estimated_minutes, action.severity, action.verification
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "# lock").unwrap();
        let state = dir.path().join(".isopod");
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
        (dir, config)
    }

    #[test]
    fn web_command_workflow_supports_json_and_human_output() {
        let (dir, config) = fixture();
        scan(dir.path(), &config, true).unwrap();
        scan(dir.path(), &config, false).unwrap();
        assess(dir.path(), &config, true).unwrap();
        assess(dir.path(), &config, false).unwrap();
        recommend(dir.path(), &config, true).unwrap();
        recommend(dir.path(), &config, false).unwrap();
        harden(dir.path(), &config, false, true).unwrap();
        harden(dir.path(), &config, false, false).unwrap();
        let _has_failures = verify(dir.path(), &config, false).unwrap();
        assert!(config
            .reports_dir
            .join(web_assurance::plan_report_name())
            .is_file());
    }

    #[test]
    fn display_helpers_cover_empty_and_all_statuses() {
        assert_eq!(list(&[]), "none detected");
        assert_eq!(list(&["one".into(), "two".into()]), "one, two");
        for value in [
            "pass", "applied", "fail", "error", "unknown", "skipped", "other",
        ] {
            assert!(!status(value).is_empty());
        }
        for value in [
            ProbeStatus::Pass,
            ProbeStatus::Partial,
            ProbeStatus::Fail,
            ProbeStatus::UnableToVerify,
        ] {
            assert!(!probe_status(&value).is_empty());
        }
    }
}
