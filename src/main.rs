use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, time::{Duration, Instant}};

use axum::{
    body::Body,
    extract::{Json, State},
    http::{header::CONTENT_TYPE, Request, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use prometheus::{Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::RwLock};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    store: Arc<RwLock<HashMap<String, RefreshEntry>>>,
    config: Arc<Config>,
    metrics: Arc<Metrics>,
}

#[derive(Debug, Clone)]
struct Config {
    issuer: String,
    audience: String,
    id_token_ttl_seconds: i64,
    refresh_token_ttl_seconds: i64,
    refresh_cleanup_interval_seconds: u64,
    refresh_store_max_size: usize,
    vm_push_url: Option<String>,
    vm_push_interval_seconds: u64,
    bind_addr: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

struct Metrics {
    registry: Registry,
    requests_total: IntCounterVec,
    request_duration_seconds: HistogramVec,
    in_flight_requests: IntGauge,
}

#[derive(Debug, Clone)]
struct RefreshEntry {
    sub: String,
    exp: i64,
}

#[derive(Debug, Deserialize)]
struct IssueTokenRequest {
    subject: String,
}

#[derive(Debug, Deserialize)]
struct RefreshTokenRequest {
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct ValidateTokenRequest {
    id_token: String,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    token_type: &'static str,
    id_token: String,
    refresh_token: String,
    expires_in: i64,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct ValidateTokenResponse {
    valid: bool,
    claims: IdTokenClaims,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdTokenClaims {
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    exp: i64,
    jti: String,
}

#[tokio::main]
async fn main() {
    init_tracing();
    let config = Arc::new(read_config());
    let metrics = Arc::new(init_metrics());

    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
        config: Arc::clone(&config),
        metrics: Arc::clone(&metrics),
    };
    spawn_refresh_cleanup(Arc::clone(&state.store), Arc::clone(&state.config));
    spawn_vm_metrics_push(Arc::clone(&state.config), Arc::clone(&state.metrics));

    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_endpoint))
        .route("/auth/token", post(issue_token))
        .route("/auth/refresh", post(refresh_token))
        .route("/auth/validate", post(validate_token))
        .layer(from_fn_with_state(state.clone(), metrics_middleware))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = config
        .bind_addr
        .parse()
        .expect("BIND_ADDR must be a valid socket address");
    let listener = TcpListener::bind(addr).await.expect("bind failed");
    info!("auth emulator listening on {}", addr);

    axum::serve(listener, app).await.expect("server failed");
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

async fn metrics_endpoint(State(state): State<AppState>) -> Response {
    match render_metrics(&state.metrics) {
        Ok(payload) => (
            StatusCode::OK,
            [(CONTENT_TYPE, "text/plain; version=0.0.4")],
            payload,
        )
            .into_response(),
        Err(err) => {
            warn!("failed to render metrics: {}", err);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to render metrics",
            )
            .into_response()
        }
    }
}

async fn metrics_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let started = Instant::now();
    state.metrics.in_flight_requests.inc();

    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();
    let elapsed = started.elapsed().as_secs_f64();

    state
        .metrics
        .requests_total
        .with_label_values(&[&method, &path, &status])
        .inc();
    state
        .metrics
        .request_duration_seconds
        .with_label_values(&[&method, &path, &status])
        .observe(elapsed);
    state.metrics.in_flight_requests.dec();

    response
}

async fn issue_token(
    State(state): State<AppState>,
    Json(payload): Json<IssueTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    if payload.subject.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "subject cannot be empty",
        ));
    }

    let now = Utc::now().timestamp();
    let id_exp = now + state.config.id_token_ttl_seconds;
    let refresh_exp = now + state.config.refresh_token_ttl_seconds;

    let id_token = build_id_token(&state.config, payload.subject.clone(), now, id_exp)?;
    let refresh_token = Uuid::new_v4().to_string();

    {
        let mut store = state.store.write().await;
        evict_expired_tokens(&mut store, now);
        if store.len() >= state.config.refresh_store_max_size {
            return Err(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_overloaded",
                "refresh token store is full",
            ));
        }
        store.insert(
            refresh_token.clone(),
            RefreshEntry {
                sub: payload.subject,
                exp: refresh_exp,
            },
        );
    }

    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            token_type: "Bearer",
            id_token,
            refresh_token,
            expires_in: state.config.id_token_ttl_seconds,
        }),
    ))
}

async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let now = Utc::now().timestamp();
    let (id_token, new_refresh_token) = {
        let mut store = state.store.write().await;
        evict_expired_tokens(&mut store, now);

        let entry = match store.remove(&payload.refresh_token) {
            Some(entry) => entry,
            None => {
                return Err(error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_grant",
                    "refresh token is unknown",
                ));
            }
        };

        if entry.exp <= now {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_grant",
                "refresh token has expired",
            ));
        }

        let id_exp = now + state.config.id_token_ttl_seconds;
        let new_refresh_exp = now + state.config.refresh_token_ttl_seconds;
        let id_token = build_id_token(&state.config, entry.sub.clone(), now, id_exp)?;
        let new_refresh_token = Uuid::new_v4().to_string();

        if store.len() >= state.config.refresh_store_max_size {
            return Err(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_overloaded",
                "refresh token store is full",
            ));
        }

        store.insert(
            new_refresh_token.clone(),
            RefreshEntry {
                sub: entry.sub,
                exp: new_refresh_exp,
            },
        );

        (id_token, new_refresh_token)
    };

    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            token_type: "Bearer",
            id_token,
            refresh_token: new_refresh_token,
            expires_in: state.config.id_token_ttl_seconds,
        }),
    ))
}

async fn validate_token(
    State(state): State<AppState>,
    Json(payload): Json<ValidateTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    if payload.id_token.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "id_token cannot be empty",
        ));
    }

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.set_issuer(&[state.config.issuer.as_str()]);
    validation.set_audience(&[state.config.audience.as_str()]);

    let token_data = decode::<IdTokenClaims>(
        &payload.id_token,
        &state.config.decoding_key,
        &validation,
    )
    .map_err(|e| {
        info!("id_token validation failed: {}", e);
        error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "id_token is invalid",
        )
    })?;

    Ok((
        StatusCode::OK,
        Json(ValidateTokenResponse {
            valid: true,
            claims: token_data.claims,
        }),
    ))
}

fn build_id_token(
    config: &Config,
    sub: String,
    iat: i64,
    exp: i64,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let claims = IdTokenClaims {
        iss: config.issuer.clone(),
        aud: config.audience.clone(),
        sub,
        iat,
        exp,
        jti: Uuid::new_v4().to_string(),
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &config.encoding_key,
    )
    .map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            format!("failed to encode id_token: {e}"),
        )
    })
}

fn read_config() -> Config {
    let issuer = env::var("TOKEN_ISSUER").unwrap_or_else(|_| "auth-emulator".to_owned());
    let audience = env::var("TOKEN_AUDIENCE").unwrap_or_else(|_| "sample-client".to_owned());
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let signing_secret = env::var("TOKEN_SIGNING_SECRET")
        .unwrap_or_else(|_| "local-dev-signing-secret-change-me".to_owned());

    let id_token_ttl_seconds = parse_ttl("ID_TOKEN_TTL_SECONDS", 300);
    let refresh_token_ttl_seconds = parse_ttl("REFRESH_TOKEN_TTL_SECONDS", 3600);
    let refresh_cleanup_interval_seconds = parse_u64("REFRESH_CLEANUP_INTERVAL_SECONDS", 60);
    let refresh_store_max_size = parse_usize("REFRESH_STORE_MAX_SIZE", 100_000);
    let vm_push_url = env::var("VM_PUSH_URL")
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty());
    let vm_push_interval_seconds = parse_u64("VM_PUSH_INTERVAL_SECONDS", 15);

    Config {
        issuer,
        audience,
        id_token_ttl_seconds,
        refresh_token_ttl_seconds,
        refresh_cleanup_interval_seconds,
        refresh_store_max_size,
        vm_push_url,
        vm_push_interval_seconds,
        bind_addr,
        encoding_key: EncodingKey::from_secret(signing_secret.as_bytes()),
        decoding_key: DecodingKey::from_secret(signing_secret.as_bytes()),
    }
}

fn parse_ttl(name: &str, default_value: i64) -> i64 {
    match env::var(name) {
        Ok(value) => value
            .parse::<i64>()
            .ok()
            .filter(|v| *v > 0)
            .unwrap_or(default_value),
        Err(_) => default_value,
    }
}

fn parse_u64(name: &str, default_value: u64) -> u64 {
    match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .ok()
            .filter(|v| *v > 0)
            .unwrap_or(default_value),
        Err(_) => default_value,
    }
}

fn parse_usize(name: &str, default_value: usize) -> usize {
    match env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .ok()
            .filter(|v| *v > 0)
            .unwrap_or(default_value),
        Err(_) => default_value,
    }
}

fn evict_expired_tokens(store: &mut HashMap<String, RefreshEntry>, now: i64) {
    store.retain(|_, entry| entry.exp > now);
}

fn init_metrics() -> Metrics {
    let registry = Registry::new_custom(None, None).expect("failed to create metrics registry");
    let requests_total = IntCounterVec::new(
        Opts::new("http_requests_total", "Total HTTP requests"),
        &["method", "path", "status"],
    )
    .expect("failed to create requests counter");
    let request_duration_seconds = HistogramVec::new(
        HistogramOpts::new("http_request_duration_seconds", "HTTP request duration in seconds"),
        &["method", "path", "status"],
    )
    .expect("failed to create duration histogram");
    let in_flight_requests =
        IntGauge::new("http_requests_in_flight", "In-flight HTTP requests").expect("gauge init");

    registry
        .register(Box::new(requests_total.clone()))
        .expect("register requests_total");
    registry
        .register(Box::new(request_duration_seconds.clone()))
        .expect("register request_duration_seconds");
    registry
        .register(Box::new(in_flight_requests.clone()))
        .expect("register in_flight_requests");

    Metrics {
        registry,
        requests_total,
        request_duration_seconds,
        in_flight_requests,
    }
}

fn render_metrics(metrics: &Metrics) -> Result<String, String> {
    let encoder = TextEncoder::new();
    let gathered = metrics.registry.gather();
    let mut buf = Vec::new();
    encoder
        .encode(&gathered, &mut buf)
        .map_err(|e| format!("encode failed: {e}"))?;
    String::from_utf8(buf).map_err(|e| format!("utf8 conversion failed: {e}"))
}

fn spawn_refresh_cleanup(store: Arc<RwLock<HashMap<String, RefreshEntry>>>, config: Arc<Config>) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(config.refresh_cleanup_interval_seconds);
        loop {
            tokio::time::sleep(interval).await;
            let now = Utc::now().timestamp();
            let mut guard = store.write().await;
            evict_expired_tokens(&mut guard, now);
        }
    });
}

fn spawn_vm_metrics_push(config: Arc<Config>, metrics: Arc<Metrics>) {
    let Some(url) = config.vm_push_url.clone() else {
        return;
    };

    tokio::spawn(async move {
        let client = Client::new();
        let interval = Duration::from_secs(config.vm_push_interval_seconds);

        loop {
            tokio::time::sleep(interval).await;
            let payload = match render_metrics(&metrics) {
                Ok(payload) => payload,
                Err(err) => {
                    warn!("skip VM push; failed to render metrics: {}", err);
                    continue;
                }
            };

            let result = client
                .post(&url)
                .header(CONTENT_TYPE.as_str(), "text/plain; version=0.0.4")
                .body(payload)
                .send()
                .await;

            if let Err(err) = result {
                warn!("failed to push metrics to VictoriaMetrics: {}", err);
            }
        }
    });
}

fn error_response(
    status: StatusCode,
    error: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error,
            message: message.into(),
        }),
    )
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_emulator=info,tower_http=info".into()),
        )
        .with_target(false)
        .compact()
        .init();
}
