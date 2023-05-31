use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct ApiKey {
    pub key_id: Uuid,
    pub name: String,
    pub key_secret_hash: String,
    pub scope: Option<String>,
    pub expires: NaiveDateTime,
    pub user_id: Uuid,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct FilteredApiKey {
    pub name: String,
    pub scope: Option<String>,
    pub expires: NaiveDateTime,
    pub user_id: Option<Uuid>,
}
