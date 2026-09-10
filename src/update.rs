// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Self-update through Theosis, with the legacy direct Baby path retained as
//! an explicit fallback.

use anyhow::{anyhow, Context, Result};
use std::env;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMode {
    Check,
    Apply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRequest {
    pub mode: UpdateMode,
    pub reference: String,
    pub direct: bool,
    pub json: bool,
}

/// Reconcile the running binary with the configured Git ref.
///
/// Theosis is authoritative when installed: it prevents downgrades, pins the
/// remote commit, delegates installation to Baby, and verifies the result.
/// Applying an update falls back to the previous direct Baby workflow only
/// when Theosis is not installed. Check mode never mutates or falls back.
pub fn run(request: &UpdateRequest) -> Result<()> {
    if request.direct {
        return run_direct(request.json);
    }

    let executable = env::current_exe().context("failed to locate the running isopod binary")?;
    let install_dir = user_install_dir(&executable);
    let args = theosis_args(request, &executable, &install_dir);
    let status = Command::new("theosis").args(&args).status();

    match status {
        Ok(status) if theosis_status_is_success(status.code()) => Ok(()),
        Ok(status) => Err(anyhow!(
            "Theosis {} failed with exit code {}",
            mode_name(request.mode),
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string())
        )),
        Err(error) if error.kind() == ErrorKind::NotFound && request.mode == UpdateMode::Apply => {
            eprintln!("Theosis is not installed; falling back to direct Baby update.");
            run_direct(request.json)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Err(anyhow!(
            "Theosis is required for update checks; install `theosis` or run `isopod update` to use the direct fallback"
        )),
        Err(error) => Err(error).context("failed to execute Theosis"),
    }
}

fn theosis_args(request: &UpdateRequest, binary: &Path, install_dir: &Path) -> Vec<OsString> {
    let mut args = vec![
        OsString::from(mode_name(request.mode)),
        OsString::from("--remote"),
        OsString::from(env!("CARGO_PKG_REPOSITORY")),
        OsString::from("--ref"),
        OsString::from(&request.reference),
        OsString::from("--binary"),
        binary.as_os_str().to_owned(),
        OsString::from("--install-dir"),
        install_dir.as_os_str().to_owned(),
    ];
    if request.json {
        args.push(OsString::from("--json"));
    }
    args
}

fn mode_name(mode: UpdateMode) -> &'static str {
    match mode {
        UpdateMode::Check => "check",
        UpdateMode::Apply => "update",
    }
}

fn theosis_status_is_success(code: Option<i32>) -> bool {
    matches!(code, Some(0 | 10))
}

fn user_install_dir(executable: &Path) -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".local/bin"))
        .or_else(|| executable.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Clone the latest source and install it directly through Baby.
fn run_direct(json: bool) -> Result<()> {
    let repo_url = env!("CARGO_PKG_REPOSITORY");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let checkout_dir =
        env::temp_dir().join(format!("isopod-update-{}-{nonce}", std::process::id()));

    if checkout_dir.exists() {
        std::fs::remove_dir_all(&checkout_dir)
            .with_context(|| format!("failed to clean up {}", checkout_dir.display()))?;
    }

    if !json {
        println!("Cloning latest isopod from {repo_url}…");
    }
    let clone_status = Command::new("git")
        .args(["clone", "--depth", "1", repo_url])
        .arg(&checkout_dir)
        .status()
        .context("failed to run git clone")?;
    if !clone_status.success() {
        return Err(anyhow!("git clone of {repo_url} failed"));
    }

    if !json {
        println!("Installing with 'baby --user'…");
    }
    let install_result = Command::new("baby")
        .arg("--user")
        .current_dir(&checkout_dir)
        .status();

    let _ = std::fs::remove_dir_all(&checkout_dir);

    let install_status =
        install_result.context("failed to run 'baby --user' (is baby installed and on PATH?)")?;
    if !install_status.success() {
        return Err(anyhow!("'baby --user' install failed"));
    }

    if json {
        println!(r#"{{"backend":"baby","decision":"UPDATED"}}"#);
    } else {
        println!("isopod updated to the latest version");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theosis_arguments_are_stable() {
        let request = UpdateRequest {
            mode: UpdateMode::Check,
            reference: "release".to_owned(),
            direct: false,
            json: true,
        };
        let args = theosis_args(
            &request,
            Path::new("/opt/isopod/bin/isopod"),
            Path::new("/home/test/.local/bin"),
        );
        assert_eq!(
            args,
            [
                "check",
                "--remote",
                env!("CARGO_PKG_REPOSITORY"),
                "--ref",
                "release",
                "--binary",
                "/opt/isopod/bin/isopod",
                "--install-dir",
                "/home/test/.local/bin",
                "--json",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn local_newer_is_a_safe_theosis_outcome() {
        assert!(theosis_status_is_success(Some(0)));
        assert!(theosis_status_is_success(Some(10)));
        assert!(!theosis_status_is_success(Some(1)));
        assert!(!theosis_status_is_success(None));
    }

    #[test]
    fn install_dir_prefers_the_user_binary_directory() {
        let install_dir = user_install_dir(Path::new("/opt/isopod/bin/isopod"));
        if let Some(home) = dirs::home_dir() {
            assert_eq!(install_dir, home.join(".local/bin"));
        }
    }
}
