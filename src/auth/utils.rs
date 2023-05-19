use secrecy::ExposeSecret;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::{
    configuration::AdminSettings,
    database::models::{FilteredUser, User},
};

pub async fn create_vault_client_if_not_exists(
    pool: &Pool<Postgres>,
    base_url: String,
    settings: AdminSettings,
) -> Result<(), sqlx::Error> {
    let name = "Vault Backend";
    let redirect_uri = base_url;
    let grant_types = "authorization_code,refresh_token";
    let scope = "read,write";

    let client_uuid = Uuid::parse_str(&settings.client_id).unwrap();

    let existing_client = sqlx::query!(
        r#"
        SELECT client_id FROM oauth_clients WHERE client_id = $1
        "#,
        client_uuid
    )
    .fetch_optional(pool)
    .await?;

    if existing_client.is_none() {
        let _ = sqlx::query!(
            r#"
            INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uri, grant_types, scope)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            client_uuid,
            settings.client_secret.expose_secret(),
            name,
            redirect_uri,
            grant_types,
            scope,
        )
        .execute(pool)
        .await?;
    }

    Ok(())
}

pub fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        username: user.username.to_string(),
        email: user.email.to_string(),
        role: user.role.to_owned(),
        createdAt: user.created_at.unwrap(),
        updatedAt: user.updated_at.unwrap(),
    }
}
