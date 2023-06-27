use awsregion::Region;
use log::info;
use s3::creds::Credentials;
use s3::Bucket;

use crate::configuration::StorageSettings;

pub fn create_object_store(settings: StorageSettings) -> Result<Bucket, String> {
    info!("Starting Object Storage Handler.");

    let bucket = Bucket::new(
        &settings.bucket_name.expect("BUCKET_NAME must be set"),
        if settings.driver == "r2" {
            Region::R2 {
                account_id: settings.endpoint.expect("AWS_ENDPOINT must be set"),
            }
        } else {
            Region::Custom {
                region: settings.region.expect("REGION must be set"),
                endpoint: settings.endpoint.expect("ENDPOINT must be set"),
            }
        },
        Credentials::new(
            Some(&settings.access_key_id.expect("ACCESS_KEY_ID must be set")),
            Some(&settings.secret_key.expect("SECRET_KEY must be set")),
            None,
            None,
            None,
        )
        .expect("Unable to gain access credentials for object store."),
    )
    .expect("Unable to create object store.");

    Ok(bucket)
}
