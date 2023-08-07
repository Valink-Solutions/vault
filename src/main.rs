use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use env_logger::Env;
use log::info;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use vault::utilities::RedisPool;
// use std::time::Duration;
use r2d2::Pool;
use r2d2_redis::RedisConnectionManager;
use tera::Tera;
use vault::auth::utils::create_vault_admin_if_not_exists;
use vault::configuration::get_configuration;
use vault::database::check_for_migrations;
use vault::object::create_object_store;
use vault::scopes::Scopes;
use vault::tasks::{delete_queued_worlds, TaskRunner};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let configuration = get_configuration().expect("Failed to read configuration.");

    let port = match env::var("PORT") {
        Ok(port) => port,
        Err(_) => configuration.application.port.to_string(),
    };

    let address = format!("{}:{}", configuration.application.host, port);

    check_for_migrations(configuration.database.clone())
        .await
        .expect("An error occurred while running migrations.");

    let manager = RedisConnectionManager::new(configuration.redis.url.clone()).unwrap();
    let redis_pool: RedisPool = Pool::builder()
        .build(manager)
        .expect("Failed to create Redis pool.");

    let scopes = Scopes::new();

    create_vault_admin_if_not_exists(
        configuration.database.url.clone(),
        configuration.application.base_url.clone(),
        configuration.admin.clone(),
        scopes.clone(),
    )
    .await
    .expect("An error occurred while running migrations.");

    let postgres_pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        // .min_connections(4)
        // .max_connections(16)
        // .max_lifetime(Some(Duration::from_secs(30 * 60)))
        .connect_lazy(&configuration.database.url)
        .expect("Error Creating database connection");

    let object_store = Arc::new(
        create_object_store(configuration.storage.clone()).expect("Failed to create object store"),
    );

    let runner = TaskRunner::new();

    let cloned_pool = postgres_pool.clone();
    let cloned_obj_store = object_store.clone();
    runner.run_task(std::time::Duration::from_secs(30 * 60), move || {
        let inner_cloned_pool = cloned_pool.clone();
        let inner_obj_store = cloned_obj_store.clone();

        async move {
            delete_queued_worlds(&inner_cloned_pool, &inner_obj_store).await;
        }
    });

    info!("Starting ChunkVault's vault HTTP Server at {}", address);

    HttpServer::new(move || {
        let tera = match Tera::new("templates/**/*.html") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };

        App::new()
            .wrap(Logger::default())
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_header()
                    .allow_any_method()
                    .max_age(3600)
                    .send_wildcard(),
            )
            .configure(vault::routes::auth_config)
            .configure(vault::routes::dashboard_config)
            .configure(vault::routes::worlds_config)
            .configure(vault::routes::versions_config)
            .app_data(web::Data::new(postgres_pool.clone()))
            .app_data(web::Data::new(redis_pool.clone()))
            .app_data(web::Data::new(object_store.clone()))
            .app_data(web::Data::new(tera.clone()))
            .app_data(web::Data::new(configuration.clone()))
            .app_data(web::Data::new(scopes.clone()))
            .service(actix_files::Files::new("/static", "./static").show_files_listing())
            .service(vault::routes::init_handshake)
    })
    .bind(address)?
    .run()
    .await
}
