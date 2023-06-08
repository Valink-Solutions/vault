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

pub type RedisPool = Pool<RedisConnectionManager>;
