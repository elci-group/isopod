// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! SystemObserver — host posture via /var/log, systemctl, /proc.
//! Read-only, minimal privilege.

use crate::evidence::{ArtifactType, Observation};
use anyhow::Context;
use async_trait::async_trait;
use serde_json::json;
use std::process::Command;

pub struct SystemObserver;

#[async_trait]
impl super::Observer for SystemObserver {
    fn name(&self) -> &str {
        "system"
    }

    async fn collect(&self) -> anyhow::Result<Vec<Observation>> {
        let obs = tokio::task::spawn_blocking(collect_system_sync)
            .await
            .context("join system observer task")?;
        Ok(obs)
    }
}

fn collect_system_sync() -> Vec<Observation> {
    let mut out = Vec::new();

    let patch_hint = if std::path::Path::new("/var/log/apt/history.log").exists()
        || std::path::Path::new("/var/log/dnf.log").exists()
        || std::path::Path::new("/var/log/pacman.log").exists()
    {
        "package_manager_logs_found"
    } else {
        "no_package_logs"
    };
    out.push(Observation::new(
        "system",
        ArtifactType::SystemPatch,
        json!({"hint": patch_hint}),
    ));

    let services = ["sshd", "auditd", "rsyslog", "systemd-journald"];
    for svc in services {
        let active = match Command::new("systemctl").args(["is-active", svc]).output() {
            Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
            Err(error) => {
                tracing::warn!(service = svc, error = %error, "system service state could not be queried");
                "unknown".to_string()
            }
        };
        let running = active == "active";
        out.push(Observation::new(
            "system",
            ArtifactType::ServiceState,
            json!({"service": svc, "active": running, "state": active}),
        ));
    }

    let audit_exists = std::path::Path::new("/var/log/audit/audit.log").exists()
        || std::path::Path::new("/var/log/auth.log").exists()
        || std::path::Path::new("/var/log/secure").exists();
    out.push(Observation::new(
        "system",
        ArtifactType::AuditLog,
        json!({"audit_logs_present": audit_exists}),
    ));

    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let encrypted =
        mounts.contains("ecryptfs") || mounts.contains("dm-crypt") || mounts.contains("luks");
    out.push(Observation::new(
        "system",
        ArtifactType::EncryptionState,
        json!({"encrypted_mounts": encrypted, "preview": mounts.lines().take(3).collect::<Vec<_>>()}),
    ));

    if let Ok(meta) = std::fs::metadata("/etc/passwd") {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        out.push(Observation::new(
            "system",
            ArtifactType::FilePermission,
            json!({"path": "/etc/passwd", "mode": format!("{:o}", mode)}),
        ));
    }

    let cert_exists = std::path::Path::new("/etc/ssl/certs/ca-certificates.crt").exists();
    out.push(Observation::new(
        "system",
        ArtifactType::Certificate,
        json!({"ca_bundle_present": cert_exists}),
    ));

    out
}
