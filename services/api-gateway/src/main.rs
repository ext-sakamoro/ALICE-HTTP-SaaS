#![allow(dead_code)]
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Json, Response},
    routing::{any, get},
    Router,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

struct AppState {
    core_url: String,
    jwt_secret: String,
    rate_limiters: DashMap<String, TokenBucket>,
    start_time: Instant,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max: f64, rate: f64) -> Self {
        Self { tokens: max, max_tokens: max, refill_rate: rate, last_refill: Instant::now() }
    }
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
        if self.tokens >= 1.0 { self.tokens -= 1.0; true } else { false }
    }
}

#[derive(Serialize)]
struct Health { status: String, version: String, uptime_secs: u64 }

#[derive(Serialize)]
struct Err { error: String, #[serde(skip_serializing_if = "Option::is_none")] details: Option<String> }

#[derive(Serialize)]
struct LicenseInfo { license: String, source_code: String, notice: String }

#[derive(Deserialize, Serialize, Clone)]
struct Claims { sub: String, email: Option<String>, role: Option<String>, exp: usize }

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "api_gateway=info,tower_http=info".into()),
        )
        .init();
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.into());
    let state = Arc::new(AppState {
        core_url: env("CORE_ENGINE_URL", "http://core-engine:8133"),
        jwt_secret: env("JWT_SECRET", "dev-secret-change-me"),
        rate_limiters: DashMap::new(),
        start_time: Instant::now(),
    });
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    let public = Router::new()
        .route("/health", get(health))
        .route("/license", get(license_handler));
    let api = Router::new()
        .route("/api/v1/{*p}", any(proxy_core))
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        .layer(middleware::from_fn_with_state(state.clone(), rate_mw));
    let app = Router::new()
        .merge(public)
        .merge(api)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    let addr = std::env::var("GATEWAY_ADDR").unwrap_or_else(|_| "0.0.0.0:8132".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("HTTP API Gateway on {addr}");
    axum::serve(listener, app).await.unwrap();
}

async fn health(State(s): State<Arc<AppState>>) -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_secs: s.start_time.elapsed().as_secs(),
    })
}

async fn license_handler() -> (HeaderMap, Json<LicenseInfo>) {
    let mut h = HeaderMap::new();
    h.insert("X-License", "AGPL-3.0-or-later".parse().unwrap());
    (h, Json(LicenseInfo {
        license: "AGPL-3.0-or-later".into(),
        source_code: "https://github.com/ext-sakamoro/ALICE-HTTP-SaaS".into(),
        notice: "SaaS operators must publish complete service source code under AGPL-3.0.".into(),
    }))
}

async fn auth_mw(
    State(s): State<Arc<AppState>>, mut req: Request, next: Next,
) -> Result<Response, (StatusCode, Json<Err>)> {
    let auth = req.headers().get("Authorization").and_then(|h| h.to_str().ok()).map(|s| s.to_string());
    let api_key = req.headers().get("X-API-Key").and_then(|h| h.to_str().ok()).map(|s| s.to_string());
    if let Some(a) = &auth {
        if let Some(token) = a.strip_prefix("Bearer ") {
            let mut val = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
            val.validate_aud = false;
            match jsonwebtoken::decode::<Claims>(
                token,
                &jsonwebtoken::DecodingKey::from_secret(s.jwt_secret.as_bytes()),
                &val,
            ) {
                Ok(data) => { req.extensions_mut().insert(data.claims); return Ok(next.run(req).await); }
                Err(e) => return Err((StatusCode::UNAUTHORIZED, Json(Err { error: "Invalid token".into(), details: Some(e.to_string()) }))),
            }
        }
    }
    if api_key.is_some() {
        req.extensions_mut().insert(Claims { sub: "api-key-user".into(), email: None, role: Some("api".into()), exp: usize::MAX });
        return Ok(next.run(req).await);
    }
    Err((StatusCode::UNAUTHORIZED, Json(Err { error: "Auth required".into(), details: Some("Provide Bearer token or X-API-Key".into()) })))
}

async fn rate_mw(
    State(s): State<Arc<AppState>>, req: Request, next: Next,
) -> Result<Response, (StatusCode, Json<Err>)> {
    let uid = req.extensions().get::<Claims>().map(|c| c.sub.clone()).unwrap_or_else(|| "anon".into());
    let ok = {
        let mut e = s.rate_limiters.entry(uid).or_insert_with(|| TokenBucket::new(20000.0, 20000.0 / 3600.0));
        e.try_consume()
    };
    if !ok { return Err((StatusCode::TOO_MANY_REQUESTS, Json(Err { error: "Rate limit exceeded".into(), details: None }))); }
    Ok(next.run(req).await)
}

async fn forward(url: &str, req: Request) -> Result<Response, (StatusCode, Json<Err>)> {
    let client = reqwest::Client::new();
    let path = req.uri().path().to_owned();
    let q = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    let method = req.method().clone();
    let hdrs = req.headers().clone();
    let body = axum::body::to_bytes(req.into_body(), 100 * 1024 * 1024).await
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(Err { error: "Body read fail".into(), details: Some(e.to_string()) })))?;
    let mut r = client.request(method, format!("{url}{path}{q}"));
    for (k, v) in hdrs.iter() { if k != "host" { r = r.header(k, v); } }
    let resp = r.body(body).send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(Err { error: "Upstream unavailable".into(), details: Some(e.to_string()) })))?;
    let st = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let rh = resp.headers().clone();
    let rb = resp.bytes().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(Err { error: "Read fail".into(), details: Some(e.to_string()) })))?;
    let mut b = Response::builder().status(st);
    for (k, v) in rh.iter() { b = b.header(k, v); }
    b.body(Body::from(rb))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(Err { error: "Build fail".into(), details: Some(e.to_string()) })))
}

async fn proxy_core(
    State(s): State<Arc<AppState>>, req: Request,
) -> Result<Response, (StatusCode, Json<Err>)> {
    forward(&s.core_url, req).await
}
