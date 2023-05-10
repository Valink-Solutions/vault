use actix_web::{middleware::Logger, web, App, HttpServer};
use env_logger::Env;
use log::info;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tera::Tera;
use vault::auth::utils::create_vault_client_if_not_exists;
use vault::database::check_for_migrations;
use vault::object::create_object_store;
use vault::tasks::{
    delete_old_access_tokens, delete_old_refresh_tokens, delete_queued_worlds, TaskRunner,
};

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

    create_vault_client_if_not_exists(&pool.clone())
        .await
        .expect("An error occurred while running migrations.");

    let object_store = Arc::new(create_object_store().expect("Failed to create object store"));

    let runner = TaskRunner::new();

    let cloned_pool = pool.clone();
    runner.run_task(std::time::Duration::from_secs(15 * 60), move || {
        let inner_cloned_pool = cloned_pool.clone();

        async move {
            delete_old_access_tokens(&inner_cloned_pool).await;
        }
    });

    let cloned_pool = pool.clone();
    runner.run_task(std::time::Duration::from_secs(15 * 60), move || {
        let inner_cloned_pool = cloned_pool.clone();

        async move {
            delete_old_refresh_tokens(&inner_cloned_pool).await;
        }
    });

    let cloned_pool = pool.clone();
    let cloned_obj_store = object_store.clone();
    runner.run_task(std::time::Duration::from_secs(30 * 60), move || {
        let inner_cloned_pool = cloned_pool.clone();
        let inner_obj_store = cloned_obj_store.clone();

        async move {
            delete_queued_worlds(&inner_cloned_pool, &inner_obj_store).await;
        }
    });

    info!("Starting the vault HTTP Server");

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
            .configure(vault::routes::auth_config)
            .configure(vault::routes::worlds_config)
            .configure(vault::routes::versions_config)
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(object_store.clone()))
            .app_data(web::Data::new(tera.clone()))
            .service(actix_files::Files::new("/static", "./static").show_files_listing())
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
