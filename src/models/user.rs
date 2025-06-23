use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub password: String, // Hashed in production
    pub role: Role,
    pub first_name: String,
    pub last_name: String,
    
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq)]
pub enum Role {
    Admin,
    User,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub email:  String, 
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterResponse {
    pub id: u32,
    pub first_name: String,
    pub last_name: String,
    pub email: String,

}