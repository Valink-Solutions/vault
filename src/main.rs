use actix_web::{web, App, HttpServer};
use log::info;
use sqlx::any::AnyPoolOptions;
use vault::database::check_for_migrations;
use std::env;
use env_logger::Env;
use std::time::Duration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    dotenvy::dotenv().ok();

    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .init();

    let database_url = env::var("DATABASE_URL").unwrap_or("sqlite:vault.db".to_string());

    check_for_migrations()
        .await
        .expect("An error occurred while running migrations.");

    let pool = AnyPoolOptions::new()
        .min_connections(0)
        .max_connections(16)
        .max_lifetime(Some(Duration::from_secs(60 * 60)))
        .connect(&database_url)
        .await
        .expect("Error Creating database connection");

    info!("Starting the vault HTTP Server");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}