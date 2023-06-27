use actix_multipart::form::{MultipartForm, tempfile::TempFile, text::Text, bytes::Bytes};
use r2d2::Pool;
use r2d2_redis::RedisConnectionManager;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct PageQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    // query: String,
}

#[derive(Deserialize)]
pub struct WorldVersionPath {
    pub world_id: String,
    pub version_id: String,
}

#[derive(Deserialize)]
pub struct WorldVersionPartQuery {
    pub part: Option<i64>,
}

#[derive(Deserialize)]
pub struct ChunkedWorldVersionPath {
    pub world_id: String,
    pub version_id: String,
    pub upload_id: String,
}

#[derive(Deserialize)]
pub struct ChunkedUploadQuery {
    pub part: Option<i64>,
    pub name: String,
    pub content_type: String,
}

#[derive(MultipartForm)]
pub struct ChunkedUploadForm {
    pub part: Text<Option<String>>,
    pub name: Text<String>,
    pub content_type: Text<String>,
    #[multipart(limit = "500 MB")]
    pub file: Bytes,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PartDeserialize {
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    #[serde(rename = "ETag")]
    pub etag: String,
}

pub type RedisPool = Pool<RedisConnectionManager>;
