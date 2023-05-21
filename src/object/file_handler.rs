use log::info;
use object_store::{aws::AmazonS3Builder, local::LocalFileSystem, ObjectStore};

use crate::configuration::StorageSettings;

pub fn create_object_store(settings: StorageSettings) -> Result<Box<dyn ObjectStore>, String> {
    info!("Starting Object Storage Handler.");

    match settings.driver.as_str() {
        "s3" => {
            info!("Initializing s3 Compatible Storage Driver.");

            let s3 = AmazonS3Builder::new()
                .with_endpoint(settings.endpoint.expect("AWS_ENDPOINT must be set"))
                .with_region(settings.region.expect("AWS_REGION must be set"))
                .with_bucket_name(settings.bucket_name.expect("S3_BUCKET_NAME must be set"))
                .with_access_key_id(settings.access_key_id.expect("ACCESS_KEY_ID must be set"))
                .with_secret_access_key(settings.secret_key.expect("SECRET_KEY must be set"))
                .build()
                .unwrap();
            Ok(Box::new(s3))
        }
        "local" => {
            info!("Initializing Local Storage Driver.");
            let local =
                LocalFileSystem::new_with_prefix(settings.path.unwrap_or("./data".to_string()))
                    .unwrap();
            Ok(Box::new(local))
        }
        _ => Err(format!("Unknown storage type: {}", settings.driver)),
    }
}
