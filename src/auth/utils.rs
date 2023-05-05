use sqlx::{Pool, Postgres};
use std::env;
use uuid::Uuid;

pub async fn create_vault_client_if_not_exists(pool: &Pool<Postgres>) -> Result<(), sqlx::Error> {
    let client_id = env::var("CLIENT_ID").expect("FIRST_PARTY_CLIENT_ID is not set");
    let client_secret = env::var("CLIENT_SECRET").expect("FIRST_PARTY_CLIENT_SECRET is not set");

    let name = "Vault Backend";
    let redirect_uri = env::var("APP_DOMAIN").expect("APP_DOMAIN is not set");
    let grant_types = "authorization_code,refresh_token";
    let scope = "read,write";

    let client_uuid = Uuid::parse_str(&client_id).unwrap();

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
            client_secret,
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
