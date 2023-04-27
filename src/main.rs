use actix_web::{middleware::Logger, web, App, HttpServer};
use env_logger::Env;
use futures::StreamExt;
use log::{info, warn};
use object_store::path::Path;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use vault::database::check_for_migrations;
use vault::object::create_object_store;
use vault::runner;

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

    let mut runner = runner::TaskRunner::new();

    let cloned_pool = pool.clone();
    runner.run_task(std::time::Duration::from_secs(15 * 60), move || {
        let inner_cloned_pool = cloned_pool.clone();

        async move {
            info!("Starting old session deletion.");

            let result = sqlx::query!(
                "
                DELETE FROM sessions
                WHERE expires_at < $1
                ",
                chrono::Utc::now().naive_utc()
            )
            .execute(&inner_cloned_pool)
            .await;

            match result {
                Ok(_) => info!("Successfully deleted old session records."),
                Err(e) => warn!("Failed to delete old records from sessions: {:?}", e),
            }
        }
    });

    let cloned_pool = pool.clone();
    let cloned_obj_store = object_store.clone();
    runner.run_task(std::time::Duration::from_secs(15 * 60), move || {
        let inner_cloned_pool = cloned_pool.clone();
        let inner_obj_store = cloned_obj_store.clone();

        async move {
            info!("Starting queued world deletion.");

            let result = sqlx::query!(
                "
                SELECT * FROM deleted_worlds
                "
            )
            .fetch_all(&inner_cloned_pool)
            .await;

            match result {
                Ok(worlds) => {
                    for world in worlds {
                        let prefix: Path = format!("{}/{}", world.user_id, world.world_id)
                            .try_into()
                            .unwrap();
                        match inner_obj_store.list(Some(&prefix)).await {
                            Ok(mut stream) => {
                                // let mut stream = stream.into_inner();
                                while let Some(item) = stream.next().await {
                                    match item {
                                        Ok(object_meta) => {
                                            // Perform desired operations on each ObjectMeta here
                                            println!("ObjectMeta: {:?}", object_meta);

                                            match inner_obj_store
                                                .delete(&object_meta.location)
                                                .await
                                            {
                                                Ok(_) => {}
                                                Err(e) => {
                                                    warn!("Failed to delete queued worlds: {:?}", e)
                                                }
                                            };
                                        }
                                        Err(e) => {
                                            eprintln!("Error processing item: {:?}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => warn!("Failed to delete queued worlds: {:?}", e),
                        }

                        match sqlx::query!(
                            "
                            DELETE FROM deleted_worlds
                            WHERE id = $1
                            ",
                            world.id
                        )
                        .execute(&inner_cloned_pool)
                        .await
                        {
                            Ok(_) => {}
                            Err(e) => warn!("Failed to delete queued world: {:?}", e),
                        };
                    }
                }
                Err(e) => warn!("Failed to delete queued worlds: {:?}", e),
            }

            info!("Successfully deleted queued worlds.")
        }
    });

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
