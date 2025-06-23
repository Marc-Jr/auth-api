use axum::extract::State;
use axum::{http::StatusCode, response::IntoResponse, Json};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use utoipa::{OpenApi, ToSchema};

use crate::middleware::auth::Claims;
use crate::models::user::RegisterRequest;
use crate::models::{LoginRequest, LoginResponse, Role, User};
use crate::AppState;

#[derive(OpenApi)]
#[openapi(
    paths(login, register),
    components(schemas(LoginRequest, LoginResponse, RegisterRequest))
)]
pub struct AuthApi;

#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials")
    )
)]
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let users = state.users.lock().unwrap();
    let user = users.iter().find(|u| u.email == payload.email);
    if let Some(user) = user {
        if verify(&payload.password, &user.password).unwrap_or(false) {
            let claims = Claims {
                sub: user.email.clone(),
                role: user.role.clone(),
                exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
            };
            let config = state.config.clone();
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(config.jwt_secret.as_ref()),
            )
            .unwrap();
            return (StatusCode::OK, Json(LoginResponse { token })).into_response();
        }
    }
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "Invalid credentials"})),
    )
        .into_response()
}

#[utoipa::path(
    post,
    path = "/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Registration successful"),
        (status = 400, description = "Bad request")
    )
)]
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    if payload.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Password cannot be empty"})),
        )
            .into_response();
    }
    let mut users = state.users.lock().unwrap();
    if users.iter().any(|u| u.email == payload.email) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Email already exists"})),
        )
            .into_response();
    }
    let hashed_password = hash(&payload.password, DEFAULT_COST).unwrap();
    let new_user = User {
        id: users.len() as i32 + 1,
        email: payload.email.clone(),
        first_name: payload.first_name.clone(),
        last_name: payload.last_name.clone(),
        password: hashed_password,
        role: Role::User,
    };
    users.push(new_user);
   return  (
        StatusCode::CREATED,
        Json(json!({"message": "User Registered Successfully"})),
    )
        .into_response()
}
