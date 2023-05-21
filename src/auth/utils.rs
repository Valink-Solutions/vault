use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use secrecy::ExposeSecret;
use sqlx::{Pool, Postgres, Row};
use uuid::Uuid;

use crate::{
    configuration::AdminSettings,
    database::models::{FilteredUser, User},
};

pub async fn create_vault_admin_if_not_exists(
    pool: &Pool<Postgres>,
    base_url: String,
    settings: AdminSettings,
) -> Result<(), sqlx::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(settings.password.expose_secret().as_bytes(), &salt)
        .expect("Error while hashing password");

    let email_exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(settings.email.to_lowercase().clone())
        .fetch_one(pool)
        .await
        .unwrap()
        .get(0);

    let user = if email_exists {
        sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE email = $1",
            settings.email.to_lowercase()
        )
        .fetch_one(pool)
        .await
        .unwrap()
    } else {
        sqlx::query_as!(
            User,
            "INSERT INTO users (id,username,email,password_hash,role,created_at,updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING *",
            uuid::Uuid::new_v4(),
            "admin".to_string(),
            settings.email.to_lowercase(),
            hashed_password.to_string(),
            "admin",
            chrono::Utc::now().naive_utc()
        )
        .fetch_one(pool)
        .await
        .unwrap()
    };

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
            INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uri, grant_types, scope, user_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            client_uuid,
            settings.client_secret.expose_secret(),
            name,
            redirect_uri,
            grant_types,
            scope,
            user.id
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
