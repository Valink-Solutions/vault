pub mod runner;

use std::sync::Arc;

use futures::StreamExt;
use log::{info, warn};
use object_store::{path::Path, ObjectStore};
pub use runner::TaskRunner;

pub async fn delete_old_access_tokens(pool: &sqlx::PgPool) {
    info!("Starting old session deletion.");

    let result = sqlx::query!(
        "
        DELETE FROM oauth_access_tokens
        WHERE expires < $1
        ",
        chrono::Utc::now().naive_utc()
    )
    .execute(pool)
    .await;

    match result {
        Ok(_) => info!("Successfully deleted old session records."),
        Err(e) => warn!("Failed to delete old records from sessions: {:?}", e),
    }
}

pub async fn delete_old_refresh_tokens(pool: &sqlx::PgPool) {
    info!("Starting old session deletion.");

    let result = sqlx::query!(
        "
        DELETE FROM oauth_refresh_tokens
        WHERE expires < $1
        ",
        chrono::Utc::now().naive_utc()
    )
    .execute(pool)
    .await;

    match result {
        Ok(_) => info!("Successfully deleted old session records."),
        Err(e) => warn!("Failed to delete old records from sessions: {:?}", e),
    }
}

pub async fn delete_queued_worlds(pool: &sqlx::PgPool, object_store: &Arc<Box<dyn ObjectStore>>) {
    info!("Starting queued world deletion.");

    let result = sqlx::query!(
        "
        SELECT * FROM deleted_worlds
        "
    )
    .fetch_all(pool)
    .await;

    match result {
        Ok(worlds) => {
            for world in worlds {
                let prefix: Path = format!("{}/{}", world.user_id, world.world_id)
                    .try_into()
                    .unwrap();
                match object_store.list(Some(&prefix)).await {
                    Ok(mut stream) => {
                        // let mut stream = stream.into_inner();
                        while let Some(item) = stream.next().await {
                            match item {
                                Ok(object_meta) => {
                                    // Perform desired operations on each ObjectMeta here
                                    println!("ObjectMeta: {:?}", object_meta);

                                    match object_store.delete(&object_meta.location).await {
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
                .execute(pool)
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
