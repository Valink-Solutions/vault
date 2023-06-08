use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CreateClientResponse {
    pub client_id: String,
    pub client_secret: String,
    pub name: String,
    pub redirect_uri: String,
    pub grant_types: String,
    pub scope: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub authorization_code: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenResponse {
    pub auth_token: String,
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub auth_token: String,
    pub refresh_token: String,
}