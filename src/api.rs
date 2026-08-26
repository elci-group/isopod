// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! HTTP API — Axum router for health, compliance, evidence, drift.
//! See `docs/api.md`.

use crate::store::Store;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Store>,
    pub versions: HashMap<String, String>,
    pub token: Option<String>,
    pub rate_limiter: Option<RateLimiter>,
}

/// Simple fixed-window per-client rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    window: Duration,
    max_requests: u32,
    state: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
}

impl RateLimiter {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            window: Duration::from_secs(60),
            max_requests: max_requests_per_minute,
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns true if the request is allowed under the limit.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|poisoned| {
            tracing::error!(
                component = "rate_limiter",
                "mutex was poisoned; recovering guarded state"
            );
            poisoned.into_inner()
        });
        let entry = state.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) > self.window {
            *entry = (now, 1);
            return true;
        }
        if entry.1 >= self.max_requests {
            return false;
        }
        entry.1 += 1;
        true
    }
}

async fn auth_middleware(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(expected) = &state.token {
        let header = match request.headers().get(axum::http::header::AUTHORIZATION) {
            Some(value) => match value.to_str() {
                Ok(header) => Some(header),
                Err(error) => {
                    tracing::warn!(error = %error, path = %request.uri().path(), "invalid authorization header encoding");
                    None
                }
            },
            None => None,
        };
        let provided = header.and_then(|h| h.strip_prefix("Bearer "));
        if provided != Some(expected) {
            tracing::warn!(path = %request.uri().path(), method = %request.method(), "API authorization denied");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok(next.run(request).await)
}

async fn rate_limit_middleware(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(limiter) = &state.rate_limiter {
        let key = match request.headers().get(axum::http::header::AUTHORIZATION) {
            Some(value) => match value.to_str() {
                Ok(header) => header.to_string(),
                Err(error) => {
                    tracing::warn!(error = %error, path = %request.uri().path(), "invalid rate-limit identity encoding");
                    "invalid-header".to_string()
                }
            },
            None => "anonymous".to_string(),
        };
        if !limiter.allow(&key) {
            tracing::warn!(path = %request.uri().path(), method = %request.method(), "API rate limit exceeded");
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }
    Ok(next.run(request).await)
}

pub fn router(
    store: Arc<Store>,
    versions: HashMap<String, String>,
    token: Option<String>,
    rate_limit: u32,
) -> Router {
    let rate_limiter = if rate_limit > 0 {
        Some(RateLimiter::new(rate_limit))
    } else {
        None
    };
    let state = ApiState {
        store,
        versions,
        token,
        rate_limiter,
    };
    let protected = Router::new()
        .route("/compliance", get(compliance))
        .route("/evidence", get(evidence))
        .route("/drift", get(drift))
        .route_layer(from_fn_with_state(state.clone(), auth_middleware))
        .route_layer(from_fn_with_state(state.clone(), rate_limit_middleware));
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .merge(protected)
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status":"ok","service":"isopod","version": crate::VERSION}))
}

async fn compliance(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let results = state.store.list_control_results().unwrap_or_default();
    let passing = results
        .iter()
        .filter(|r| r.status == crate::control::ControlStatus::Pass)
        .count();
    let failing = results
        .iter()
        .filter(|r| r.status == crate::control::ControlStatus::Fail)
        .count();
    let warning = results
        .iter()
        .filter(|r| r.status == crate::control::ControlStatus::Warning)
        .count();
    let unknown = results
        .iter()
        .filter(|r| r.status == crate::control::ControlStatus::Unknown)
        .count();
    let frameworks = crate::control::framework_summary(&results);
    Json(json!({
        "framework": "ISO27001",
        "versions": state.versions,
        "total": results.len(),
        "passing": passing,
        "failing": failing,
        "warning": warning,
        "unknown": unknown,
        "frameworks": frameworks,
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

async fn metrics(State(state): State<ApiState>) -> impl IntoResponse {
    let results = state.store.list_control_results().unwrap_or_default();
    let evidence = state
        .store
        .list_evidence(None, 1_000_000)
        .unwrap_or_default();
    let drifts = state.store.list_drifts(1_000_000).unwrap_or_default();

    let passing = results
        .iter()
        .filter(|r| r.status == crate::control::ControlStatus::Pass)
        .count();
    let failing = results
        .iter()
        .filter(|r| r.status == crate::control::ControlStatus::Fail)
        .count();
    let warning = results
        .iter()
        .filter(|r| r.status == crate::control::ControlStatus::Warning)
        .count();
    let unknown = results
        .iter()
        .filter(|r| r.status == crate::control::ControlStatus::Unknown)
        .count();

    let mut out = String::new();
    out.push_str("# HELP isopod_controls_total Number of controls evaluated.\n");
    out.push_str("# TYPE isopod_controls_total gauge\n");
    out.push_str(&format!("isopod_controls_total {}\n", results.len()));
    out.push_str("# HELP isopod_controls_passing Number of controls passing.\n");
    out.push_str("# TYPE isopod_controls_passing gauge\n");
    out.push_str(&format!("isopod_controls_passing {}\n", passing));
    out.push_str("# HELP isopod_controls_failing Number of controls failing.\n");
    out.push_str("# TYPE isopod_controls_failing gauge\n");
    out.push_str(&format!("isopod_controls_failing {}\n", failing));
    out.push_str("# HELP isopod_controls_warning Number of controls warning.\n");
    out.push_str("# TYPE isopod_controls_warning gauge\n");
    out.push_str(&format!("isopod_controls_warning {}\n", warning));
    out.push_str("# HELP isopod_controls_unknown Number of controls unknown.\n");
    out.push_str("# TYPE isopod_controls_unknown gauge\n");
    out.push_str(&format!("isopod_controls_unknown {}\n", unknown));
    out.push_str("# HELP isopod_evidence_total Number of evidence records.\n");
    out.push_str("# TYPE isopod_evidence_total gauge\n");
    out.push_str(&format!("isopod_evidence_total {}\n", evidence.len()));
    out.push_str("# HELP isopod_drifts_total Number of drift events.\n");
    out.push_str("# TYPE isopod_drifts_total gauge\n");
    out.push_str(&format!("isopod_drifts_total {}\n", drifts.len()));
    ([("content-type", "text/plain; charset=utf-8")], out)
}

pub async fn serve(
    addr: String,
    store: Arc<Store>,
    versions: HashMap<String, String>,
    token: Option<String>,
    rate_limit: u32,
) -> anyhow::Result<()> {
    let app = router(store, versions, token, rate_limit);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(listen_address = %addr, "isopod API listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn health_is_unprotected() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let app = router(store, HashMap::new(), Some("secret".to_string()), 0);
        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_routes_require_token() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let app = router(store, HashMap::new(), Some("secret".to_string()), 0);
        let response = app
            .oneshot(Request::get("/compliance").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn protected_routes_accept_valid_token() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let app = router(store, HashMap::new(), Some("secret".to_string()), 0);
        let response = app
            .oneshot(
                Request::get("/compliance")
                    .header("Authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_prometheus_text() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let app = router(store, HashMap::new(), None, 0);
        let response = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("isopod_controls_total"));
    }

    #[tokio::test]
    async fn rate_limit_rejects_excess_requests() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let app = router(store, HashMap::new(), None, 2);
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(Request::get("/compliance").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let response = app
            .oneshot(Request::get("/compliance").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
