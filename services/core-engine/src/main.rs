#![allow(dead_code)]
use axum::{extract::State, response::Json, routing::{get, post}, Router};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

// ── State ───────────────────────────────────────────────────
struct AppState {
    start_time: Instant,
    stats: Mutex<Stats>,
}

struct Stats {
    total_parses: u64,
    total_validations: u64,
    total_compressions: u64,
    total_header_analyses: u64,
    bytes_processed: u64,
}

// ── Types ───────────────────────────────────────────────────
#[derive(Serialize)]
struct Health { status: String, version: String, uptime_secs: u64, total_ops: u64 }

// Parse
#[derive(Deserialize)]
#[allow(dead_code)]
struct ParseRequest { raw: Option<String>, encoding: Option<String> }
#[derive(Serialize)]
struct ParsedHeader { name: String, value: String }
#[derive(Serialize)]
struct ParseResponse {
    parse_id: String, method: String, path: String, version: String,
    headers: Vec<ParsedHeader>, body_bytes: usize,
    content_type: Option<String>, elapsed_us: u128,
}

// Validate
#[derive(Deserialize)]
#[allow(dead_code)]
struct ValidateRequest {
    payload: Option<serde_json::Value>,
    schema: Option<serde_json::Value>,
    content_type: Option<String>,
}
#[derive(Serialize)]
struct ValidateResponse {
    validate_id: String, valid: bool, content_type: String,
    errors: Vec<String>, warnings: Vec<String>, elapsed_us: u128,
}

// Compress
#[derive(Deserialize)]
#[allow(dead_code)]
struct CompressRequest {
    body: Option<String>,
    algorithm: Option<String>,
    level: Option<u32>,
}
#[derive(Serialize)]
struct CompressResponse {
    compress_id: String, algorithm: String, level: u32,
    original_bytes: usize, compressed_bytes: usize,
    ratio: f64, content_encoding: String, elapsed_us: u128,
}

// Headers
#[derive(Deserialize)]
#[allow(dead_code)]
struct HeadersRequest {
    headers: Option<std::collections::HashMap<String, String>>,
    action: Option<String>,
}
#[derive(Serialize)]
struct HeaderAnalysis { name: String, value: String, standard: bool, security_relevant: bool }
#[derive(Serialize)]
struct HeadersResponse {
    analysis_id: String, total: usize,
    analyses: Vec<HeaderAnalysis>,
    missing_security_headers: Vec<String>,
    elapsed_us: u128,
}

// Stats
#[derive(Serialize)]
struct StatsResponse {
    total_parses: u64, total_validations: u64,
    total_compressions: u64, total_header_analyses: u64,
    bytes_processed: u64,
}

// ── Main ────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "http_engine=info".into()))
        .init();
    let state = Arc::new(AppState {
        start_time: Instant::now(),
        stats: Mutex::new(Stats {
            total_parses: 0, total_validations: 0, total_compressions: 0,
            total_header_analyses: 0, bytes_processed: 0,
        }),
    });
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/http/parse", post(parse))
        .route("/api/v1/http/validate", post(validate))
        .route("/api/v1/http/compress", post(compress))
        .route("/api/v1/http/headers", post(headers))
        .route("/api/v1/http/stats", get(stats))
        .layer(cors).layer(TraceLayer::new_for_http()).with_state(state);
    let addr = std::env::var("HTTP_ADDR").unwrap_or_else(|_| "0.0.0.0:8133".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("HTTP Engine on {addr}");
    axum::serve(listener, app).await.unwrap();
}

// ── Handlers ────────────────────────────────────────────────
async fn health(State(s): State<Arc<AppState>>) -> Json<Health> {
    let st = s.stats.lock().unwrap();
    Json(Health {
        status: "ok".into(), version: env!("CARGO_PKG_VERSION").into(),
        uptime_secs: s.start_time.elapsed().as_secs(),
        total_ops: st.total_parses + st.total_validations + st.total_compressions + st.total_header_analyses,
    })
}

async fn parse(State(s): State<Arc<AppState>>, Json(req): Json<ParseRequest>) -> Json<ParseResponse> {
    let t = Instant::now();
    let raw = req.raw.unwrap_or_else(|| "GET /api/v1 HTTP/1.1\r\nHost: example.com\r\n\r\n".into());
    let body_bytes = raw.len();
    // Minimal parsing of the request line
    let mut lines = raw.lines();
    let request_line = lines.next().unwrap_or("GET / HTTP/1.1");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("GET").to_string();
    let path = parts.get(1).copied().unwrap_or("/").to_string();
    let version = parts.get(2).copied().unwrap_or("HTTP/1.1").to_string();
    let mut parsed_headers = vec![];
    for line in lines {
        if line.is_empty() { break; }
        if let Some((name, value)) = line.split_once(": ") {
            parsed_headers.push(ParsedHeader { name: name.to_string(), value: value.to_string() });
        }
    }
    let content_type = parsed_headers.iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-type"))
        .map(|h| h.value.clone());
    {
        let mut st = s.stats.lock().unwrap();
        st.total_parses += 1;
        st.bytes_processed += body_bytes as u64;
    }
    Json(ParseResponse {
        parse_id: uuid::Uuid::new_v4().to_string(),
        method, path, version, headers: parsed_headers, body_bytes, content_type,
        elapsed_us: t.elapsed().as_micros(),
    })
}

async fn validate(State(s): State<Arc<AppState>>, Json(req): Json<ValidateRequest>) -> Json<ValidateResponse> {
    let t = Instant::now();
    let content_type = req.content_type.unwrap_or_else(|| "application/json".into());
    let valid = req.payload.is_some();
    s.stats.lock().unwrap().total_validations += 1;
    Json(ValidateResponse {
        validate_id: uuid::Uuid::new_v4().to_string(),
        valid, content_type,
        errors: if valid { vec![] } else { vec!["payload is required".into()] },
        warnings: vec![],
        elapsed_us: t.elapsed().as_micros(),
    })
}

async fn compress(State(s): State<Arc<AppState>>, Json(req): Json<CompressRequest>) -> Json<CompressResponse> {
    let t = Instant::now();
    let body = req.body.unwrap_or_else(|| "Hello, World!".into());
    let algorithm = req.algorithm.unwrap_or_else(|| "gzip".into());
    let level = req.level.unwrap_or(6);
    let original_bytes = body.len();
    // Estimate compression ratio based on algorithm and level
    let ratio = match algorithm.as_str() {
        "br" | "brotli" => 0.78 - (level as f64 * 0.005),
        "zstd" => 0.72 - (level as f64 * 0.008),
        "gzip" | "deflate" => 0.68 - (level as f64 * 0.005),
        _ => 0.75,
    };
    let compressed_bytes = ((original_bytes as f64) * ratio).ceil() as usize;
    let content_encoding = match algorithm.as_str() {
        "br" | "brotli" => "br".into(),
        "zstd" => "zstd".into(),
        "deflate" => "deflate".into(),
        _ => "gzip".into(),
    };
    {
        let mut st = s.stats.lock().unwrap();
        st.total_compressions += 1;
        st.bytes_processed += original_bytes as u64;
    }
    Json(CompressResponse {
        compress_id: uuid::Uuid::new_v4().to_string(),
        algorithm, level, original_bytes, compressed_bytes,
        ratio: 1.0 - ratio, content_encoding,
        elapsed_us: t.elapsed().as_micros(),
    })
}

async fn headers(State(s): State<Arc<AppState>>, Json(req): Json<HeadersRequest>) -> Json<HeadersResponse> {
    let t = Instant::now();
    let input_headers = req.headers.unwrap_or_default();
    let security_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
    ];
    let mut analyses: Vec<HeaderAnalysis> = input_headers.iter().map(|(k, v)| {
        let lower = k.to_lowercase();
        let security_relevant = security_headers.contains(&lower.as_str())
            || lower.starts_with("x-") || lower == "authorization";
        let standard = !lower.starts_with("x-");
        HeaderAnalysis { name: k.clone(), value: v.clone(), standard, security_relevant }
    }).collect();
    let present_lower: Vec<String> = analyses.iter().map(|a| a.name.to_lowercase()).collect();
    let missing_security_headers: Vec<String> = security_headers.iter()
        .filter(|h| !present_lower.iter().any(|p| p == *h))
        .map(|h| h.to_string())
        .collect();
    // Add a recommended header hint
    analyses.push(HeaderAnalysis {
        name: "X-Request-ID".into(),
        value: uuid::Uuid::new_v4().to_string(),
        standard: false, security_relevant: false,
    });
    let total = analyses.len();
    s.stats.lock().unwrap().total_header_analyses += 1;
    Json(HeadersResponse {
        analysis_id: uuid::Uuid::new_v4().to_string(),
        total, analyses, missing_security_headers,
        elapsed_us: t.elapsed().as_micros(),
    })
}

async fn stats(State(s): State<Arc<AppState>>) -> Json<StatsResponse> {
    let st = s.stats.lock().unwrap();
    Json(StatsResponse {
        total_parses: st.total_parses,
        total_validations: st.total_validations,
        total_compressions: st.total_compressions,
        total_header_analyses: st.total_header_analyses,
        bytes_processed: st.bytes_processed,
    })
}
