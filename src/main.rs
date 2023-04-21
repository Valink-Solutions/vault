use actix_web::{middleware::Logger, web, App, HttpServer};
use env_logger::Env;
use log::info;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use vault::database::check_for_migrations;
use vault::object::create_object_store;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let database_url = env::var("DATABASE_URL").expect("No Database URL");

    check_for_migrations()
        .await
        .expect("An error occurred while running migrations.");

    let pool = PgPoolOptions::new()
        .min_connections(0)
        .max_connections(16)
        .max_lifetime(Some(Duration::from_secs(60 * 60)))
        .connect(&database_url)
        .await
        .expect("Error Creating database connection");

    let object_store = Arc::new(create_object_store().expect("Failed to create object store"));

    info!("Starting the vault HTTP Server");

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .configure(vault::routes::auth_config)
            .configure(vault::routes::worlds_config)
            .configure(vault::routes::versions_config)
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(object_store.clone()))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
