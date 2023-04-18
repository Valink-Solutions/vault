use sqlx::{migrate::MigrateDatabase, AnyConnection, Connection};
use log::info;

pub async fn check_for_migrations() -> Result<(), sqlx::Error> {
    let uri = dotenvy::var("DATABASE_URL")
        .unwrap_or("sqlite:vault.db".to_string());

    if !sqlx::Any::database_exists(&uri).await? {
        info!("Creating database...");
        sqlx::Any::create_database(&uri).await?;
    }

    info!("Running migrations...");

    let mut conn: AnyConnection = AnyConnection::connect(&uri).await?;

    sqlx::migrate!()
        .run(&mut conn)
        .await
        .expect("Error while running database migrations!");

    Ok(())
}