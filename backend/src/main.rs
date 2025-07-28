use axum::{routing::{get, post}, Router, Json};
use serde::Serialize;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use rate_limit::RateLimitLayer;
mod db;
mod auth;
use db::init_db_pool;
use auth::{register, login, setup_2fa, verify_2fa, request_password_reset, confirm_password_reset, request_email_verification, confirm_email_verification};
use auth::AdminGuard;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn admin_ping(_admin: AdminGuard) -> &'static str { "pong" }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let pool = init_db_pool().await?;
    let app = Router::new()
        .route("/health", get(health))
        .route("/admin/ping", get(admin_ping))
        .nest(
            "/auth",
            Router::new()
                .layer(RateLimitLayer::new(10, 5)) // burst 10, 5 req/sec per IP+path
                .route("/register", post(register))
                .route("/login", post(login))
                .route("/2fa/setup", post(setup_2fa))
                .route("/2fa/verify", post(verify_2fa))
                .route("/password-reset/request", post(request_password_reset))
                .route("/password-reset/confirm", post(confirm_password_reset))
                .route("/email/verify/request", post(request_email_verification))
                .route("/email/verify/confirm", post(confirm_email_verification))
                .route("/logout", post(logout))
                .route("/logout-all", post(logout_all))
                .nest("/keys", auth::key_routes())
        )
        .nest(
            "/admin",
            Router::new().route(
                "/users/:id/sessions/revoke",
                post(auth::admin_revoke_user_sessions),
            ),
        )
        .with_state(pool.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
} 