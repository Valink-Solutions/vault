use log::info;
use object_store::{aws::AmazonS3Builder, local::LocalFileSystem, ObjectStore};
use std::env;

pub fn create_object_store() -> Result<Box<dyn ObjectStore>, String> {
    info!("Starting Object Storage Handler.");

    let storage_type = env::var("STORAGE_TYPE").unwrap_or_else(|_| "local".to_string());

    match storage_type.as_str() {
        "s3" => {
            info!("Initializing s3 Compatible Storage Driver.");
            let region = env::var("AWS_REGION").expect("AWS_REGION must be set");
            let bucket_name = env::var("S3_BUCKET_NAME").expect("S3_BUCKET_NAME must be set");
            let access_key_id = env::var("ACCESS_KEY_ID").expect("ACCESS_KEY_ID must be set");
            let secret_key = env::var("SECRET_KEY").expect("SECRET_KEY must be set");

            let s3 = AmazonS3Builder::new()
                .with_region(region)
                .with_bucket_name(bucket_name)
                .with_access_key_id(access_key_id)
                .with_secret_access_key(secret_key)
                .build()
                .unwrap();
            Ok(Box::new(s3))
        }
        "local" => {
            info!("Initializing Local Storage Driver.");
            let local_path =
                env::var("LOCAL_STORAGE_PATH").unwrap_or_else(|_| "./data".to_string());
            let local = LocalFileSystem::new_with_prefix(local_path).unwrap();
            Ok(Box::new(local))
        }
        _ => Err(format!("Unknown storage type: {}", storage_type)),
    }
}
