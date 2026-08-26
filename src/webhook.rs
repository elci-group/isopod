// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Webhook notification dispatcher for drift and compliance events.
//!
//! Events are persisted to the store and can be flushed asynchronously.
//! Production deployments can swap the dispatcher implementation.

use crate::drift::DriftEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A webhook payload waiting to be delivered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub id: String,
    pub url: String,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub status: WebhookStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebhookStatus {
    Pending,
    Delivered,
    Failed,
}

/// Abstraction over webhook delivery mechanisms.
#[async_trait::async_trait]
pub trait WebhookDispatcher: Send + Sync {
    async fn dispatch(&self, event: &WebhookEvent) -> anyhow::Result<()>;
}

/// Dispatcher that only logs the payload. Useful for tests and dry-runs.
pub struct LogDispatcher;

#[async_trait::async_trait]
impl WebhookDispatcher for LogDispatcher {
    async fn dispatch(&self, event: &WebhookEvent) -> anyhow::Result<()> {
        tracing::info!(
            event_id = %event.id,
            url = %event.url,
            payload = %event.payload,
            "webhook logged"
        );
        Ok(())
    }
}

/// Dispatcher that shells out to `curl` for actual HTTP delivery.
/// Supports http and https URLs as long as curl is installed.
pub struct CurlDispatcher;

#[async_trait::async_trait]
impl WebhookDispatcher for CurlDispatcher {
    async fn dispatch(&self, event: &WebhookEvent) -> anyhow::Result<()> {
        let body = event.payload.to_string();
        let output = tokio::process::Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                &body,
                &event.url,
            ])
            .output()
            .await?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!(
                event_id = %event.id,
                status = %output.status,
                "webhook delivery command failed"
            );
            Err(anyhow::anyhow!("curl failed: {stderr}"))
        }
    }
}

/// Build a webhook payload for a drift event.
pub fn drift_payload(event: &DriftEvent) -> serde_json::Value {
    serde_json::json!({
        "event": "drift",
        "control_id": event.control_id,
        "previous": event.previous.to_string(),
        "current": event.current.to_string(),
        "severity": event.severity,
        "cause": event.cause,
        "timestamp": event.timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn log_dispatcher_succeeds() {
        let dispatcher = LogDispatcher;
        let event = WebhookEvent {
            id: "evt-1".to_string(),
            url: "http://example.com".to_string(),
            payload: serde_json::json!({"test": true}),
            created_at: Utc::now(),
            delivered_at: None,
            status: WebhookStatus::Pending,
            error: None,
        };
        dispatcher.dispatch(&event).await.unwrap();
    }
}
