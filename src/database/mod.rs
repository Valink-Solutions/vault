use log::info;
use sqlx::{migrate::MigrateDatabase, AnyConnection, Connection};

use crate::configuration::DatabaseSettings;

pub async fn check_for_migrations(settings: DatabaseSettings) -> Result<(), sqlx::Error> {
    if !sqlx::Any::database_exists(&settings.url).await? {
        info!("Creating database...");
        sqlx::Any::create_database(&settings.url).await?;
    }

    info!("Running migrations...");

    let mut conn: AnyConnection = AnyConnection::connect(&settings.url).await?;

    sqlx::migrate!()
        .run(&mut conn)
        .await
        .expect("Error while running database migrations!");

    Ok(())
}

pub mod models;
