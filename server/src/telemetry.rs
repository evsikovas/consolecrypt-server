// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Logging and metrics.
//!
//! * `tracing` JSON (default) or human-readable logs; filter via `CC_LOG` or
//!   `RUST_LOG` (default `info`). Spans carry request_id / user_id /
//!   device_id — never secrets.
//! * optional OpenTelemetry OTLP trace export (feature `otel`, enabled at
//!   runtime by `OTEL_EXPORTER_OTLP_ENDPOINT`);
//! * Prometheus metrics on a separate listener (`CC_METRICS_LISTEN`) so the
//!   public ingress never exposes them.

use crate::config::LogFormat;
use axum::extract::State;
use axum::routing::get;
use axum::Router;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

/// Default log filter: sqlx statement logging off (it is noisy; it never
/// contains bound values, but we keep logs lean).
const DEFAULT_FILTER: &str = "info,sqlx=warn";

/// Keeps exporters alive; flushes pending spans on drop.
#[derive(Debug, Default)]
pub struct TelemetryGuard {
    #[cfg(feature = "otel")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

/// Install the global subscriber: fmt (JSON or pretty) on stderr, plus an
/// OpenTelemetry OTLP exporter when `OTEL_EXPORTER_OTLP_ENDPOINT` is set
/// (HTTP/protobuf; standard `OTEL_*` variables apply). Span attributes are the
/// same non-secret fields as the logs (request_id, route, user/device UUIDs).
pub fn init_tracing(format: LogFormat) -> TelemetryGuard {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::Layer as _;

    let filter = EnvFilter::try_from_env("CC_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    let fmt_layer = match format {
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(false)
            .with_writer(std::io::stderr)
            .boxed(),
        LogFormat::Pretty => tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .boxed(),
    };
    #[allow(unused_mut)]
    let mut guard = TelemetryGuard::default();
    let registry = tracing_subscriber::registry().with(filter).with(fmt_layer);

    #[cfg(feature = "otel")]
    let registry = {
        let otel = match otel_provider() {
            Ok(Some(provider)) => {
                use opentelemetry::trace::TracerProvider as _;
                let tracer = provider.tracer("consolecrypt-server");
                guard.provider = Some(provider);
                Some(tracing_opentelemetry::layer().with_tracer(tracer))
            }
            Ok(None) => None,
            Err(err) => {
                eprintln!("OpenTelemetry disabled: {err}");
                None
            }
        };
        registry.with(otel)
    };

    // A second init (tests) is fine.
    let _ = registry.try_init();
    guard
}

#[cfg(feature = "otel")]
fn otel_provider() -> anyhow::Result<Option<opentelemetry_sdk::trace::SdkTracerProvider>> {
    let enabled = [
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    ]
    .iter()
    .any(|k| std::env::var(k).is_ok_and(|v| !v.trim().is_empty()));
    if !enabled {
        return Ok(None);
    }
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()?;
    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name("consolecrypt-server")
        .build();
    Ok(Some(
        opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build(),
    ))
}

pub fn install_metrics() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("cc_http_request_duration_seconds".into()),
            &[
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
        )?
        .set_buckets_for_metric(
            Matcher::Full("cc_db_duration_seconds".into()),
            &[
                0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            ],
        )?
        .install_recorder()?;
    describe();
    Ok(handle)
}

fn describe() {
    use metrics::{describe_counter, describe_gauge, describe_histogram};
    describe_counter!(
        "cc_http_requests_total",
        "HTTP requests by route/method/status"
    );
    describe_histogram!("cc_http_request_duration_seconds", "HTTP latency");
    describe_counter!(
        "cc_auth_failures_total",
        "Authentication failures by reason"
    );
    describe_counter!(
        "cc_rate_limited_total",
        "Requests rejected by rate limiters"
    );
    describe_gauge!("cc_ws_connections", "Open WebSocket connections");
    describe_counter!("cc_events_published_total", "Realtime events published");
    describe_counter!("cc_sync_push_mutations_total", "Pushed mutations by result");
    describe_counter!("cc_sync_pull_requests_total", "Pull requests by kind");
    describe_counter!("cc_sync_conflicts_total", "Push conflicts");
    describe_counter!(
        "cc_device_approvals_total",
        "Device approvals/attestations by result"
    );
    describe_counter!("cc_recovery_attempts_total", "Recovery operations by kind");
    describe_counter!("cc_vault_proof_failures_total", "Invalid vault access keys");
    describe_gauge!("cc_db_pool_connections", "DB pool connections by state");
    describe_histogram!(
        "cc_db_duration_seconds",
        "PostgreSQL latency of hot paths (auth_lookup, sync_push, sync_page)"
    );
    describe_counter!(
        "cc_password_hasher_busy_total",
        "Argon2 requests shed with 503"
    );
}

/// Serve `/metrics` on `addr` and refresh DB-pool gauges periodically.
pub async fn serve_metrics(addr: SocketAddr, handle: PrometheusHandle, pool: PgPool) {
    let upkeep = handle.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            upkeep.run_upkeep();
            let size = f64::from(pool.size());
            let idle = pool.num_idle() as f64;
            metrics::gauge!("cc_db_pool_connections", "state" => "total").set(size);
            metrics::gauge!("cc_db_pool_connections", "state" => "idle").set(idle);
        }
    });
    let app = Router::new()
        .route(
            cc_protocol::paths::ops::METRICS,
            get(|State(h): State<PrometheusHandle>| async move { h.render() }),
        )
        .with_state(handle);
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            tracing::info!(%addr, "metrics listening");
            if let Err(err) = axum::serve(listener, app).await {
                tracing::error!(error = %err, "metrics server failed");
            }
        }
        Err(err) => tracing::error!(error = %err, %addr, "cannot bind metrics listener"),
    }
}
