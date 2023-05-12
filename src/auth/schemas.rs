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

#[derive(Debug, Deserialize)]
pub struct AcceptedAuthorization {
    pub client_id: String,
    pub scopes: String,
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
