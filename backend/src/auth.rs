use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::{Utc, Duration};
use argon2::{password_hash::{SaltString, PasswordHash, PasswordHasher, PasswordVerifier, rand_core::OsRng}, Argon2};
use jsonwebtoken::{encode, decode, DecodingKey, Validation, EncodingKey, Header};
use async_trait::async_trait;
use axum::{extract::{FromRequestParts, TypedHeader}, http::request::Parts};
use axum_extra::headers::{Authorization, authorization::Bearer};
use data_encoding::BASE32_NOPAD;
use oath::{totp_raw_now};
use axum_extra::headers::UserAgent;
use std::net::IpAddr;
use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use rand::Rng;
use crate::keys::{current_key, jwks, rotate_keys};
use jsonwebtoken::{Algorithm};
use axum::Json;
use serde_json::json;
use std::sync::RwLock;
use std::sync::RwLockReadGuard;
use std::sync::RwLockWriteGuard;
use axum::extract::Path;

// ---------------------- Password utils ----------------------
fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}

fn verify_password(hash: &str, password: &str) -> bool {
    if let Ok(parsed) = PasswordHash::new(hash) {
        Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
    } else {
        false
    }
}

// ---------------------- JWT ----------------------
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    session_id: String,
    exp: usize,
}

fn jwt_secret() -> String {
    std::env::var("JWT_SECRET").expect("JWT_SECRET must be set")
}

// ---------------------- Payloads ----------------------
#[derive(Debug, Deserialize)]
pub struct RegisterPayload {
    pub email: String,
    pub password: String,
    pub invitation_code: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct LoginPayload {
    pub email: String,
    pub password: String,
    pub otp: Option<String>,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
}

// ---------------------- Logout Responses ----------------------
#[derive(Serialize)]
struct LogoutResponse { message: &'static str }

// ---------------------- Auth extractor ----------------------

pub struct AuthUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub roles: Vec<String>,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract Pool state
        let pool = if let Some(pool) = parts.extensions.get::<PgPool>() {
            pool.clone()
        } else {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "PgPool missing".into()));
        };

        // Authorization header
        let TypedHeader(Authorization(bearer)) = TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
            .await
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Missing auth header".into()))?;

        let header = jsonwebtoken::decode_header(bearer.token())
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token".into()))?;
        let kid = header.kid.ok_or((StatusCode::UNAUTHORIZED, "No kid".into()))?;
        let decoding_key = crate::keys::decoding_key(&kid).ok_or((StatusCode::UNAUTHORIZED, "Unknown kid".into()))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["exp", "sub", "session_id"]);
        let token_data = decode::<Claims>(
            bearer.token(),
            &decoding_key,
            &validation,
        ).map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token".into()))?;

        let claims = token_data.claims;
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid sub".into()))?;
        let session_id = Uuid::parse_str(&claims.session_id).map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid session".into()))?;

        // Validate session not expired and user active
        let rows = sqlx::query(
            "SELECT u.is_active, array_agg(r.name) AS roles
             FROM users u
             LEFT JOIN user_roles ur ON ur.user_id = u.id
             LEFT JOIN roles r ON r.id = ur.role_id
             WHERE u.id = $1
             GROUP BY u.is_active"
        )
            .bind(user_id)
            .fetch_optional(&pool)
            .await
            .map_err(internal_error)?;

        let row = rows.ok_or((StatusCode::UNAUTHORIZED, "User not found".into()))?;
        let is_active: bool = row.get("is_active");
        if !is_active {
            return Err((StatusCode::UNAUTHORIZED, "User inactive".into()));
        }

        // Session validation
        let session_valid: (i64,) = sqlx::query_as("SELECT COUNT(1) FROM sessions WHERE id = $1 AND user_id = $2 AND expires_at > NOW()")
            .bind(session_id)
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .map_err(internal_error)?;

        if session_valid.0 == 0 {
            return Err((StatusCode::UNAUTHORIZED, "Session invalid or expired".into()));
        }

        let roles: Vec<String> = row.try_get::<Vec<String>, _>("roles").unwrap_or_else(|_| vec![]);

        Ok(AuthUser { user_id, session_id, roles })
    }
}

// ---------------------- Role guard extractors ----------------------

pub struct AdminGuard(pub AuthUser);

#[async_trait]
impl<S> FromRequestParts<S> for AdminGuard
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = AuthUser::from_request_parts(parts, state).await?;
        if auth.roles.iter().any(|r| r == "admin") {
            Ok(AdminGuard(auth))
        } else {
            Err((StatusCode::FORBIDDEN, "Admin role required".into()))
        }
    }
}

// ---------------------- 2FA helpers ----------------------

fn generate_totp_secret() -> String {
    let bytes: [u8; 32] = rand::random();
    BASE32_NOPAD.encode(&bytes)
}

fn verify_totp(secret: &str, code: &str) -> bool {
    let secret_bytes = match BASE32_NOPAD.decode(secret.as_bytes()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if let Ok(expected) = totp_raw_now(&secret_bytes, 6, 0, 30) {
        return format!("{:06}", expected) == code;
    }
    false
}

fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

// ---------------------- Email & Password reset helpers ----------------------
fn generate_token() -> Uuid { Uuid::new_v4() }

fn send_email_stub(to: &str, subject: &str, body: &str) {
    tracing::info!(%to, %subject, %body, "[EMAIL STUB]");
}

// ---------------------- Payloads for new flows ----------------------
#[derive(Deserialize)]
pub struct EmailRequestPayload { email: String }

#[derive(Deserialize)]
pub struct TokenPasswordPayload { token: Uuid, new_password: String }

#[derive(Deserialize)]
pub struct TokenPayload { token: Uuid }

// ---------------------- Handlers ----------------------

pub async fn register(
    State(pool): State<PgPool>,
    Json(payload): Json<RegisterPayload>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Check if email already exists
    let exists: (i64,) = sqlx::query_as("SELECT COUNT(1) FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_one(&pool)
        .await
        .map_err(internal_error)?;

    if exists.0 > 0 {
        return Err((StatusCode::CONFLICT, "Email already registered".into()));
    }

    let password_hash = hash_password(&payload.password).map_err(internal_error)?;
    let user_id = Uuid::new_v4();

    sqlx::query("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(&payload.email)
        .bind(&password_hash)
        .execute(&pool)
        .await
        .map_err(internal_error)?;

    // Handle invitation code if provided
    if let Some(code) = payload.invitation_code {
        sqlx::query("UPDATE invitations SET invitee_id = $1, accepted_at = NOW() WHERE code = $2 AND invitee_id IS NULL")
            .bind(user_id)
            .bind(code)
            .execute(&pool)
            .await
            .map_err(internal_error)?;
    }

    Ok((StatusCode::CREATED, Json(RegisterResponse { id: user_id })))
}

pub async fn login(
    State(pool): State<PgPool>,
    ConnectInfo(client_addr): ConnectInfo<std::net::SocketAddr>,
    user_agent: Option<TypedHeader<UserAgent>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<LoginPayload>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Fetch user
    let row = sqlx::query("SELECT id, password_hash FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(&pool)
        .await
        .map_err(internal_error)?;

    let (user_id, stored_hash): (Uuid, String) = match row {
        Some(r) => (r.get("id"), r.get("password_hash")),
        None => return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".into())),
    };

    if !verify_password(&stored_hash, &payload.password) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".into()));
    }

    // Check email verification
    let is_verified: bool = sqlx::query_scalar("SELECT is_verified FROM users WHERE id=$1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .map_err(internal_error)?;

    if !is_verified {
        return Err((StatusCode::UNAUTHORIZED, "Email not verified".into()));
    }

    // 2FA check
    let (totp_enabled, totp_secret): (bool, Option<String>) = sqlx::query_as("SELECT totp_enabled, totp_secret FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .map_err(internal_error)?;

    if totp_enabled {
        let otp = payload.otp.as_ref().ok_or((StatusCode::UNAUTHORIZED, "OTP required".into()))?;
        if !totp_secret.as_ref().map(|sec| verify_totp(sec, otp)).unwrap_or(false) {
            return Err((StatusCode::UNAUTHORIZED, "Invalid OTP".into()));
        }
    }

    // Create session
    let session_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::days(30);

    let ip: Option<IpAddr> = Some(client_addr.ip());
    let ua_str = user_agent.as_ref().map(|ua| ua.to_string()).unwrap_or_default();

    sqlx::query("INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(session_id)
        .bind(user_id)
        .bind(ip)
        .bind(ua_str)
        .bind(expires_at)
        .execute(&pool)
        .await
        .map_err(internal_error)?;

    // Device fingerprint tracking
    if let Some(fp) = headers.get("x-device-fingerprint").and_then(|v| v.to_str().ok()) {
        sqlx::query("INSERT INTO device_fingerprints (user_id, fingerprint) VALUES ($1, $2) ON CONFLICT (user_id, fingerprint) DO UPDATE SET last_seen_at = NOW()")
            .bind(user_id)
            .bind(fp)
            .execute(&pool)
            .await
            .ok();
    }

    let claims = Claims {
        sub: user_id.to_string(),
        session_id: session_id.to_string(),
        exp: expires_at.timestamp() as usize,
    };

    let mut header = Header::new(Algorithm::RS256);
    let keypair = current_key();
    header.kid = Some(keypair.kid.clone());
    let token = encode(
        &header,
        &claims,
        &keypair.encoding,
    ).map_err(internal_error)?;

    Ok(Json(LoginResponse { token }))
}

// Request password reset
pub async fn request_password_reset(
    State(pool): State<PgPool>,
    Json(payload): Json<EmailRequestPayload>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let row = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(&pool)
        .await
        .map_err(internal_error)?;
    if let Some(row) = row {
        let user_id: Uuid = row.get("id");
        let token = generate_token();
        let expires = Utc::now() + Duration::hours(1);
        sqlx::query("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1,$2,$3)")
            .bind(user_id)
            .bind(token)
            .bind(expires)
            .execute(&pool)
            .await
            .map_err(internal_error)?;
        send_email_stub(&payload.email, "Password reset", &format!("Your reset token: {}", token));
    }
    Ok(StatusCode::NO_CONTENT)
}

// Confirm password reset
pub async fn confirm_password_reset(
    State(pool): State<PgPool>,
    Json(payload): Json<TokenPasswordPayload>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let now = Utc::now();
    let row = sqlx::query("SELECT user_id FROM password_reset_tokens WHERE token=$1 AND used=false AND expires_at > $2")
        .bind(payload.token)
        .bind(now)
        .fetch_optional(&pool)
        .await
        .map_err(internal_error)?;
    let user_id: Uuid = match row { Some(r) => r.get("user_id"), None => return Err((StatusCode::BAD_REQUEST, "Invalid token".into())) };

    let new_hash = hash_password(&payload.new_password).map_err(internal_error)?;
    let mut tx = pool.begin().await.map_err(internal_error)?;
    sqlx::query("UPDATE users SET password_hash=$1 WHERE id=$2")
        .bind(new_hash)
        .bind(user_id)
        .execute(&mut tx)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE password_reset_tokens SET used=true WHERE token=$1")
        .bind(payload.token)
        .execute(&mut tx)
        .await
        .map_err(internal_error)?;
    tx.commit().await.map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

// Request email verification
pub async fn request_email_verification(
    State(pool): State<PgPool>,
    auth: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // fetch email
    let row = sqlx::query("SELECT email, is_verified FROM users WHERE id=$1")
        .bind(auth.user_id)
        .fetch_one(&pool)
        .await
        .map_err(internal_error)?;
    let email: String = row.get("email");
    let is_verified: bool = row.get("is_verified");
    if is_verified {
        return Ok(StatusCode::NO_CONTENT);
    }
    let token = generate_token();
    let expires = Utc::now() + Duration::hours(24);
    sqlx::query("INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1,$2,$3)")
        .bind(auth.user_id)
        .bind(token)
        .bind(expires)
        .execute(&pool)
        .await
        .map_err(internal_error)?;
    send_email_stub(&email, "Verify email", &format!("Verification token: {}", token));
    Ok(StatusCode::NO_CONTENT)
}

// Confirm email verification
pub async fn confirm_email_verification(
    State(pool): State<PgPool>,
    Json(payload): Json<TokenPayload>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let now = Utc::now();
    let row = sqlx::query("SELECT user_id FROM email_verification_tokens WHERE token=$1 AND used=false AND expires_at>$2")
        .bind(payload.token)
        .bind(now)
        .fetch_optional(&pool)
        .await
        .map_err(internal_error)?;
    let user_id: Uuid = match row { Some(r) => r.get("user_id"), None => return Err((StatusCode::BAD_REQUEST, "Invalid token".into())) };
    let mut tx = pool.begin().await.map_err(internal_error)?;
    sqlx::query("UPDATE users SET is_verified=true WHERE id=$1")
        .bind(user_id)
        .execute(&mut tx)
        .await
        .map_err(internal_error)?;
    sqlx::query("UPDATE email_verification_tokens SET used=true WHERE token=$1")
        .bind(payload.token)
        .execute(&mut tx)
        .await
        .map_err(internal_error)?;
    tx.commit().await.map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

// Logout current session
pub async fn logout(
    State(pool): State<PgPool>,
    auth: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    sqlx::query("DELETE FROM sessions WHERE id=$1")
        .bind(auth.session_id)
        .execute(&pool)
        .await
        .map_err(internal_error)?;
    Ok(Json(LogoutResponse { message: "Logged out" }))
}

// Logout all sessions
pub async fn logout_all(
    State(pool): State<PgPool>,
    auth: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    sqlx::query("DELETE FROM sessions WHERE user_id=$1")
        .bind(auth.user_id)
        .execute(&pool)
        .await
        .map_err(internal_error)?;
    Ok(Json(LogoutResponse { message: "All sessions revoked" }))
}

// Admin revoke all sessions for a user
pub async fn admin_revoke_user_sessions(
    State(pool): State<PgPool>,
    _admin: AdminGuard,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    sqlx::query("DELETE FROM sessions WHERE user_id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .map_err(internal_error)?;
    Ok(Json(LogoutResponse { message: "User sessions revoked" }))
}

// ---------------------- 2FA Endpoints ----------------------

#[derive(Serialize)]
struct TwoFASetupResponse {
    secret: String,
    otpauth_uri: String,
}

pub async fn setup_2fa(
    State(pool): State<PgPool>,
    auth: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Generate secret and store
    let secret = generate_totp_secret();
    sqlx::query("UPDATE users SET totp_secret = $1 WHERE id = $2")
        .bind(&secret)
        .bind(auth.user_id)
        .execute(&pool)
        .await
        .map_err(internal_error)?;

    let uri = format!(
        "otpauth://totp/ChatBotPro:{}?secret={}&issuer=ChatBotPro",
        auth.user_id, secret
    );

    Ok(Json(TwoFASetupResponse { secret, otpauth_uri: uri }))
}

#[derive(Deserialize)]
struct VerifyOTP {
    code: String,
}

pub async fn verify_2fa(
    State(pool): State<PgPool>,
    auth: AuthUser,
    Json(payload): Json<VerifyOTP>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Fetch secret
    let row = sqlx::query("SELECT totp_secret FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_optional(&pool)
        .await
        .map_err(internal_error)?;

    let secret: String = row.ok_or((StatusCode::BAD_REQUEST, "No secret setup".into()))?.get("totp_secret");

    if verify_totp(&secret, &payload.code) {
        sqlx::query("UPDATE users SET totp_enabled = TRUE WHERE id = $1")
            .bind(auth.user_id)
            .execute(&pool)
            .await
            .map_err(internal_error)?;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::BAD_REQUEST, "Invalid code".into()))
    }
} 

#[derive(Serialize)]
struct JwksResponse { keys: Vec<crate::keys::Jwk> }

pub async fn jwks_endpoint() -> impl IntoResponse {
    Json(JwksResponse { keys: jwks() })
}

// Rotate keys (admin only)
pub async fn rotate_signing_key(_admin: AdminGuard) -> impl IntoResponse {
    let kp = rotate_keys();
    Json(json!({"kid": kp.kid}))
} 

// ------------------- Key management endpoints -------------------

use crate::auth::AdminGuard; // ensure imported earlier.

pub fn key_routes() -> axum::Router<PgPool> {
    use axum::{routing::get, routing::post, Router};
    Router::new()
        .route("/jwks.json", get(jwks_endpoint))
        .route("/rotate", post(rotate_signing_key))
} 