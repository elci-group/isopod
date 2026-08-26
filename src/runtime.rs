// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Bounded, explicitly authorised runtime assurance for web applications.
//!
//! Runtime probes never fetch response bodies. Targets must be HTTPS and
//! publicly routable unless the caller deliberately enables the corresponding
//! development overrides. DNS answers are validated and pinned into curl so a
//! hostname cannot be resolved a second time between policy and connection.

use axum::http::Uri;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;

const MAX_ROUTES: usize = 20;
const MAX_TIMEOUT_SECS: u64 = 30;
const MIN_HSTS_MAX_AGE: u64 = 15_552_000;
const META_MARKER: &str = "__ISOPOD_META__";

#[derive(Debug, Clone)]
pub struct RuntimeProbeConfig {
    pub project_root: String,
    pub target: String,
    pub routes: Vec<String>,
    pub timeout_secs: u64,
    pub allow_http: bool,
    pub allow_private: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Pass,
    Partial,
    Fail,
    UnableToVerify,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeProbeReport {
    pub project_root: String,
    pub target_origin: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub resolved_addresses: Vec<String>,
    pub routes: Vec<RouteProbe>,
    pub status: ProbeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteProbe {
    pub url: String,
    pub status_code: u16,
    pub http_version: String,
    pub remote_ip: String,
    pub tls_verified: Option<bool>,
    pub timings_ms: ProbeTimings,
    /// Deliberately restricted to non-secret security headers.
    pub security_headers: BTreeMap<String, String>,
    pub checks: Vec<RuntimeCheck>,
    pub status: ProbeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProbeTimings {
    pub dns: f64,
    pub connect: f64,
    pub tls: f64,
    pub total: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeCheck {
    pub id: String,
    pub requirement: String,
    pub observed: Option<String>,
    pub status: ProbeStatus,
}

#[derive(Debug, Clone)]
struct ValidatedTarget {
    origin: String,
    scheme: String,
    host: String,
    port: u16,
}

#[derive(Debug)]
struct CurlResponse {
    status_code: u16,
    remote_ip: String,
    scheme: String,
    ssl_verify_result: i64,
    http_version: String,
    timings: ProbeTimings,
    headers: BTreeMap<String, String>,
}

/// Probe an explicitly supplied target with bounded network activity.
#[tracing::instrument(
    name = "runtime_probe",
    skip(config),
    fields(target = %config.target, routes = config.routes.len())
)]
pub async fn probe(config: &RuntimeProbeConfig) -> anyhow::Result<RuntimeProbeReport> {
    let started_at = Utc::now();
    let target = validate_target(config)?;
    let routes = validate_routes(&config.routes)?;
    let addresses = resolve_target(&target).await?;
    if !config.allow_private {
        let rejected: Vec<_> = addresses
            .iter()
            .copied()
            .filter(|address| !is_public_ip(*address))
            .collect();
        anyhow::ensure!(
            rejected.is_empty(),
            "target resolves to a non-public address; use --allow-private only for an authorised development target"
        );
    }

    let pinned = addresses
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("target resolved to no addresses"))?;
    let timeout_secs = config.timeout_secs.clamp(1, MAX_TIMEOUT_SECS);
    let mut route_reports = Vec::with_capacity(routes.len());
    for route in routes {
        let url = format!("{}{}", target.origin, route);
        tracing::debug!(url = %url, pinned_ip = %pinned, "probing runtime route");
        let response = execute_curl(&target, &url, pinned, timeout_secs).await?;
        route_reports.push(evaluate_route(&url, &response));
    }
    let status = aggregate_status(route_reports.iter().map(|route| &route.status));
    tracing::info!(
        ?status,
        routes = route_reports.len(),
        "runtime probe completed"
    );
    Ok(RuntimeProbeReport {
        project_root: config.project_root.clone(),
        target_origin: target.origin,
        started_at,
        completed_at: Utc::now(),
        resolved_addresses: addresses.iter().map(ToString::to_string).collect(),
        routes: route_reports,
        status,
    })
}

fn validate_target(config: &RuntimeProbeConfig) -> anyhow::Result<ValidatedTarget> {
    let uri = Uri::from_str(&config.target)
        .map_err(|error| anyhow::anyhow!("invalid target URI: {error}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow::anyhow!("target must include an http or https scheme"))?;
    anyhow::ensure!(
        scheme == "https" || (scheme == "http" && config.allow_http),
        "runtime probes require HTTPS; use --allow-http only for an authorised development target"
    );
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("target must include a host"))?;
    anyhow::ensure!(
        !authority.as_str().contains('@'),
        "target user information is forbidden"
    );
    let path = uri.path();
    anyhow::ensure!(
        path.is_empty() || path == "/",
        "target must be an origin; provide paths with --route"
    );
    anyhow::ensure!(uri.query().is_none(), "target query strings are forbidden");
    let host = authority.host().to_string();
    anyhow::ensure!(!host.is_empty(), "target host is empty");
    let port = authority
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    let default_port = (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
    let origin = if default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    };
    Ok(ValidatedTarget {
        origin,
        scheme: scheme.to_string(),
        host,
        port,
    })
}

fn validate_routes(routes: &[String]) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(
        routes.len() <= MAX_ROUTES,
        "at most {MAX_ROUTES} routes may be probed"
    );
    let candidates = if routes.is_empty() {
        vec!["/".to_string()]
    } else {
        routes.to_vec()
    };
    let mut unique = BTreeSet::new();
    for route in candidates {
        anyhow::ensure!(route.starts_with('/'), "route must start with '/': {route}");
        anyhow::ensure!(
            !route.starts_with("//"),
            "scheme-relative routes are forbidden"
        );
        anyhow::ensure!(
            !route.contains('?') && !route.contains('#'),
            "route queries and fragments are forbidden"
        );
        anyhow::ensure!(
            !route.split('/').any(|segment| segment == ".."),
            "route traversal is forbidden"
        );
        unique.insert(route);
    }
    Ok(unique.into_iter().collect())
}

async fn resolve_target(target: &ValidatedTarget) -> anyhow::Result<Vec<IpAddr>> {
    if let Ok(address) = target.host.parse::<IpAddr>() {
        return Ok(vec![address]);
    }
    let host = target.host.clone();
    let port = target.port;
    let resolved = tokio::task::spawn_blocking(move || {
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|items| items.map(|socket| socket.ip()).collect::<BTreeSet<_>>())
    })
    .await
    .map_err(|error| anyhow::anyhow!("DNS resolver task failed: {error}"))??;
    anyhow::ensure!(!resolved.is_empty(), "target resolved to no addresses");
    Ok(resolved.into_iter().collect())
}

async fn execute_curl(
    target: &ValidatedTarget,
    url: &str,
    pinned: IpAddr,
    timeout_secs: u64,
) -> anyhow::Result<CurlResponse> {
    let resolve_address = match pinned {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    };
    let resolve = format!("{}:{}:{}", target.host, target.port, resolve_address);
    let timeout = timeout_secs.to_string();
    let protocols = if target.scheme == "https" {
        "=https"
    } else {
        "=http"
    };
    let write_out = format!(
        "\n{META_MARKER}\n%{{http_code}}\t%{{remote_ip}}\t%{{scheme}}\t%{{ssl_verify_result}}\t%{{time_namelookup}}\t%{{time_connect}}\t%{{time_appconnect}}\t%{{time_total}}\t%{{http_version}}\n"
    );
    let output = tokio::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--dump-header",
            "-",
            "--output",
            "/dev/null",
            "--max-redirs",
            "0",
            "--connect-timeout",
            &timeout,
            "--max-time",
            &timeout,
            "--proto",
            protocols,
            "--resolve",
            &resolve,
            "--user-agent",
            concat!("isopod/", env!("CARGO_PKG_VERSION")),
            "--write-out",
            &write_out,
            "--url",
            url,
        ])
        .output()
        .await
        .map_err(|error| anyhow::anyhow!("failed to execute curl: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.chars().take(1_000).collect::<String>();
        anyhow::bail!(
            "runtime probe failed with curl status {}: {detail}",
            output.status
        );
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| anyhow::anyhow!("curl returned non-UTF-8 headers: {error}"))?;
    parse_curl_output(&stdout)
}

fn parse_curl_output(output: &str) -> anyhow::Result<CurlResponse> {
    let (header_text, metadata) = output
        .rsplit_once(&format!("\n{META_MARKER}\n"))
        .ok_or_else(|| anyhow::anyhow!("curl output did not contain assurance metadata"))?;
    let fields: Vec<_> = metadata.trim().split('\t').collect();
    anyhow::ensure!(fields.len() == 9, "curl assurance metadata was incomplete");
    let mut headers = BTreeMap::new();
    for line in header_text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if is_allowlisted_header(&name) {
            headers.insert(name, value.trim().to_string());
        }
    }
    Ok(CurlResponse {
        status_code: fields[0]
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid HTTP status metadata: {error}"))?,
        remote_ip: fields[1].to_string(),
        scheme: fields[2].to_string(),
        ssl_verify_result: fields[3]
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid TLS verification metadata: {error}"))?,
        timings: ProbeTimings {
            dns: seconds_to_ms(fields[4])?,
            connect: seconds_to_ms(fields[5])?,
            tls: seconds_to_ms(fields[6])?,
            total: seconds_to_ms(fields[7])?,
        },
        http_version: fields[8].to_string(),
        headers,
    })
}

fn seconds_to_ms(value: &str) -> anyhow::Result<f64> {
    value
        .parse::<f64>()
        .map(|seconds| seconds * 1_000.0)
        .map_err(|error| anyhow::anyhow!("invalid timing metadata: {error}"))
}

fn evaluate_route(url: &str, response: &CurlResponse) -> RouteProbe {
    let https = response.scheme == "https";
    let tls_verified = https.then_some(response.ssl_verify_result == 0);
    let mut checks = vec![RuntimeCheck {
        id: "HTTP-STATUS".to_string(),
        requirement: "route responds without a server error".to_string(),
        observed: Some(response.status_code.to_string()),
        status: if response.status_code < 500 {
            ProbeStatus::Pass
        } else {
            ProbeStatus::Fail
        },
    }];
    checks.push(RuntimeCheck {
        id: "TLS-VERIFIED".to_string(),
        requirement: "certificate chain and hostname verify successfully".to_string(),
        observed: tls_verified.map(|value| value.to_string()),
        status: match tls_verified {
            Some(true) => ProbeStatus::Pass,
            Some(false) => ProbeStatus::Fail,
            None => ProbeStatus::Fail,
        },
    });
    checks.extend(header_checks(&response.headers, https));
    let status = aggregate_status(checks.iter().map(|check| &check.status));
    RouteProbe {
        url: url.to_string(),
        status_code: response.status_code,
        http_version: response.http_version.clone(),
        remote_ip: response.remote_ip.clone(),
        tls_verified,
        timings_ms: response.timings.clone(),
        security_headers: response.headers.clone(),
        checks,
        status,
    }
}

fn header_checks(headers: &BTreeMap<String, String>, https: bool) -> Vec<RuntimeCheck> {
    let csp = headers.get("content-security-policy");
    let hsts = headers.get("strict-transport-security");
    let nosniff = headers.get("x-content-type-options");
    let referrer = headers.get("referrer-policy");
    vec![
        check_header(
            "HEADER-CSP",
            "Content-Security-Policy is present",
            csp,
            csp.is_some_and(|value| !value.trim().is_empty()),
        ),
        check_header(
            "HEADER-HSTS",
            &format!("Strict-Transport-Security max-age is at least {MIN_HSTS_MAX_AGE}"),
            hsts,
            https && hsts.is_some_and(|value| hsts_is_sufficient(value)),
        ),
        check_header(
            "HEADER-NOSNIFF",
            "X-Content-Type-Options is nosniff",
            nosniff,
            nosniff.is_some_and(|value| value.eq_ignore_ascii_case("nosniff")),
        ),
        check_header(
            "HEADER-REFERRER",
            "Referrer-Policy avoids unsafe-url and legacy downgrade leakage",
            referrer,
            referrer.is_some_and(|value| referrer_policy_is_safe(value)),
        ),
    ]
}

fn check_header(
    id: &str,
    requirement: &str,
    observed: Option<&String>,
    passed: bool,
) -> RuntimeCheck {
    RuntimeCheck {
        id: id.to_string(),
        requirement: requirement.to_string(),
        observed: observed.cloned(),
        status: if passed {
            ProbeStatus::Pass
        } else {
            ProbeStatus::Fail
        },
    }
}

fn hsts_is_sufficient(value: &str) -> bool {
    value.split(';').any(|directive| {
        let Some(age) = directive.trim().strip_prefix("max-age=") else {
            return false;
        };
        match age.parse::<u64>() {
            Ok(age) => age >= MIN_HSTS_MAX_AGE,
            Err(error) => {
                tracing::debug!(value = %age, error = %error, "invalid HSTS max-age directive");
                false
            }
        }
    })
}

fn referrer_policy_is_safe(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    !normalized.is_empty()
        && normalized != "unsafe-url"
        && normalized != "no-referrer-when-downgrade"
}

fn is_allowlisted_header(name: &str) -> bool {
    matches!(
        name,
        "content-security-policy"
            | "strict-transport-security"
            | "x-content-type-options"
            | "referrer-policy"
            | "permissions-policy"
            | "cross-origin-opener-policy"
            | "cross-origin-resource-policy"
            | "cross-origin-embedder-policy"
    )
}

fn aggregate_status<'a>(statuses: impl Iterator<Item = &'a ProbeStatus>) -> ProbeStatus {
    let statuses: Vec<_> = statuses.collect();
    if statuses.is_empty() {
        return ProbeStatus::UnableToVerify;
    }
    if statuses.iter().any(|status| **status == ProbeStatus::Fail) {
        ProbeStatus::Fail
    } else if statuses
        .iter()
        .any(|status| **status == ProbeStatus::Partial)
    {
        ProbeStatus::Partial
    } else if statuses.iter().all(|status| **status == ProbeStatus::Pass) {
        ProbeStatus::Pass
    } else {
        ProbeStatus::UnableToVerify
    }
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast())
        }
        IpAddr::V6(address) => {
            let first_segment = address.segments()[0];
            let unique_local = first_segment & 0xfe00 == 0xfc00;
            let link_local = first_segment & 0xffc0 == 0xfe80;
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || unique_local
                || link_local)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(target: &str) -> RuntimeProbeConfig {
        RuntimeProbeConfig {
            project_root: "/project".to_string(),
            target: target.to_string(),
            routes: Vec::new(),
            timeout_secs: 5,
            allow_http: false,
            allow_private: false,
        }
    }

    #[test]
    fn validates_public_https_origin() {
        let target = validate_target(&config("https://example.com")).expect("valid target");
        assert_eq!(target.origin, "https://example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn rejects_http_without_explicit_override() {
        let error = validate_target(&config("http://example.com")).expect_err("http rejected");
        assert!(error.to_string().contains("require HTTPS"));
    }

    #[test]
    fn rejects_sensitive_or_ambiguous_target_components() {
        for target in [
            "https://user@example.com",
            "https://example.com/private",
            "https://example.com/?token=secret",
        ] {
            assert!(
                validate_target(&config(target)).is_err(),
                "accepted {target}"
            );
        }
    }

    #[test]
    fn routes_are_bounded_deduplicated_and_traversal_safe() {
        let routes =
            validate_routes(&["/health".to_string(), "/health".to_string()]).expect("valid routes");
        assert_eq!(routes, vec!["/health"]);
        assert!(validate_routes(&["/../admin".to_string()]).is_err());
        assert!(validate_routes(&["//attacker.example".to_string()]).is_err());
        assert!(validate_routes(&["/search?q=secret".to_string()]).is_err());
    }

    #[test]
    fn classifies_non_public_addresses() {
        for address in ["127.0.0.1", "10.0.0.1", "169.254.1.1", "::1", "fc00::1"] {
            assert!(!is_public_ip(address.parse().expect("IP address")));
        }
        assert!(is_public_ip("93.184.216.34".parse().expect("public IP")));
    }

    #[test]
    fn parses_and_evaluates_curl_evidence() {
        let fixture = concat!(
            "HTTP/2 200\r\n",
            "content-security-policy: default-src 'self'\r\n",
            "strict-transport-security: max-age=31536000; includeSubDomains\r\n",
            "x-content-type-options: nosniff\r\n",
            "referrer-policy: strict-origin-when-cross-origin\r\n",
            "set-cookie: secret=not-recorded\r\n",
            "\r\n__ISOPOD_META__\n",
            "200\t93.184.216.34\thttps\t0\t0.001\t0.010\t0.020\t0.030\t2\n"
        );
        let response = parse_curl_output(fixture).expect("curl evidence");
        assert!(!response.headers.contains_key("set-cookie"));
        let route = evaluate_route("https://example.com/", &response);
        assert_eq!(route.status, ProbeStatus::Pass);
        assert_eq!(route.timings_ms.total, 30.0);
    }

    #[test]
    fn missing_security_headers_fail_closed() {
        let fixture = "HTTP/1.1 200 OK\r\n\r\n__ISOPOD_META__\n200\t93.184.216.34\thttps\t0\t0\t0.01\t0.02\t0.03\t1.1\n";
        let response = parse_curl_output(fixture).expect("curl evidence");
        assert_eq!(
            evaluate_route("https://example.com/", &response).status,
            ProbeStatus::Fail
        );
    }
}
