use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct OAuthClient {
    pub client_id: Uuid,
    pub client_secret: String,
    pub name: String,
    pub redirect_uri: Option<String>,
    pub grant_types: Option<String>,
    pub scope: Option<String>,
    pub user_id: Option<Uuid>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct OAuthAuthorizationToken {
    pub code: String,
    pub client_id: Uuid,
    pub redirect_uri: Option<String>,
    pub user_id: Uuid,
    pub expires: NaiveDateTime,
    pub scope: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct OAuthAccessToken {
    pub access_token: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub expires: NaiveDateTime,
    pub scope: String,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct OAuthRefreshToken {
    pub refresh_token: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub expires: NaiveDateTime,
    pub scope: String,
}
