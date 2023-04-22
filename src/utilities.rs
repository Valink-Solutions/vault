use serde::Deserialize;

#[derive(Deserialize)]
pub struct PageQuery {
    pub limit: i64,
    pub offset: i64,
    // query: String,
}

#[derive(Deserialize)]
pub struct VersionUploadPath {
    pub world_id: String,
    pub version_id: String,
}
