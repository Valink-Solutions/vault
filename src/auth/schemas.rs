use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::database::models::User;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenDetails {
    pub token: Option<String>,
    pub token_uuid: Uuid,
    pub user_id: Uuid,
    pub expires_in: Option<i64>,
    pub scope: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub token_uuid: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub client_id: String,
    pub scope: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeCreateClientQuery {
    pub client_name: Option<String>,
    pub response_type: String,
    pub grant_types: Option<String>,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AcceptedAuthorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub state: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    pub redirect_uri: String,
    pub grant_types: String,
    pub scope: String,
}

#[derive(Debug, Deserialize)]
pub struct AcceptedCreateClientAuthorization {
    pub client_name: String,
    pub redirect_uri: String,
    pub grant_types: String,
    pub scopes: String,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub user: User,
    pub scope: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePassword {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct TradeTokenQuery {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApiKeyTradeTokenQuery {
    pub grant_type: String,
    pub api_key: Option<String>,
    pub api_key_secret: Option<String>,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeTokenQuery {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Expiry {
    Thirty,
    Sixty,
    Ninety,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKey {
    pub name: String,
    pub expiry: Expiry,
    pub scopes: Vec<String>,
}
