pub mod runner;

use std::sync::Arc;

use log::{info, warn};
pub use runner::TaskRunner;
use s3::Bucket;

pub async fn delete_queued_worlds(pool: &sqlx::PgPool, object_store: &Arc<Bucket>) {
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
                let prefix = format!("{}/{}", world.user_id, world.world_id);
                match object_store.list(prefix, Some("/".to_string())).await {
                    Ok(stream) => {
                        let mut stream = stream.into_iter();
                        while let Some(item) = stream.next() {
                            // Perform desired operations on each ObjectMeta here
                            println!("ObjectMeta: {:?}", item);

                            match object_store.delete_object(&item.name).await {
                                Ok(_) => {}
                                Err(e) => {
                                    warn!("Failed to delete queued worlds: {:?}", e)
                                }
                            };
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
