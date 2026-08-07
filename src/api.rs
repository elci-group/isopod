//! HTTP API — Axum router for health, compliance, evidence, drift.
//! See `docs/api.md`.

use crate::store::Store;
use axum::{extract::State, routing::get, Json, Router};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Store>,
}

pub fn router(store: Arc<Store>) -> Router {
    let state = ApiState { store };
    Router::new()
        .route("/health", get(health))
        .route("/compliance", get(compliance))
        .route("/evidence", get(evidence))
        .route("/drift", get(drift))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status":"ok","service":"isopod","version": crate::VERSION}))
}

async fn compliance(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let results = state.store.list_control_results().unwrap_or_default();
    let passing = results.iter().filter(|r| r.status == crate::control::ControlStatus::Pass).count();
    let failing = results.iter().filter(|r| r.status == crate::control::ControlStatus::Fail).count();
    let warning = results.iter().filter(|r| r.status == crate::control::ControlStatus::Warning).count();
    let unknown = results.iter().filter(|r| r.status == crate::control::ControlStatus::Unknown).count();
    Json(json!({
        "framework": "ISO27001",
        "total": results.len(),
        "passing": passing,
        "failing": failing,
        "warning": warning,
        "unknown": unknown,
        "controls": results,
    }))
}

async fn evidence(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let ev = state.store.list_evidence(None, 100).unwrap_or_default();
    Json(json!({"count": ev.len(), "evidence": ev}))
}

async fn drift(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let drifts = state.store.list_drifts(50).unwrap_or_default();
    Json(json!({"drifts": drifts}))
}

pub async fn serve(addr: String, store: Arc<Store>) -> anyhow::Result<()> {
    let app = router(store);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("isopod api listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
