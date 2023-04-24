use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct World {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub seed: i64,
    pub version: i32,
    #[serde(rename = "createdAt")]
    pub created_at: Option<NaiveDateTime>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<NaiveDateTime>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct WorldVersion {
    pub id: Uuid,
    pub world_id: Uuid,
    pub version_number: i32,
    pub backup_path: String,
    pub game_mode: String,
    pub allow_cheats: bool,
    pub difficulty_locked: bool,
    pub spawn_x: i32,
    pub spawn_y: i32,
    pub spawn_z: i32,
    pub time: i64,
    pub size: i64,
    pub weather: String,
    pub hardcore: bool,
    pub command_blocks_enabled: bool,
    pub command_block_output: bool,
    pub do_daylight_cycle: bool,
    pub do_mob_spawning: bool,
    pub do_weather_cycle: bool,
    pub keep_inventory: bool,
    pub max_players: i32,
    pub difficulty: String,
    pub view_distance: i32,
    pub level_name: String,
    pub resource_pack: Option<String>,
    pub resource_pack_sha1: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct UpdateWorldVersionSchema {
    pub game_mode: Option<String>,
    pub allow_cheats: Option<bool>,
    pub difficulty_locked: Option<bool>,
    pub spawn_x: Option<i32>,
    pub spawn_y: Option<i32>,
    pub spawn_z: Option<i32>,
    pub time: Option<i64>,
    pub size: Option<i64>,
    pub weather: Option<String>,
    pub hardcore: Option<bool>,
    pub command_blocks_enabled: Option<bool>,
    pub command_block_output: Option<bool>,
    pub do_daylight_cycle: Option<bool>,
    pub do_mob_spawning: Option<bool>,
    pub do_weather_cycle: Option<bool>,
    pub keep_inventory: Option<bool>,
    pub max_players: Option<i32>,
    pub difficulty: Option<String>,
    pub view_distance: Option<i32>,
    pub level_name: Option<String>,
    pub resource_pack: Option<String>,
    pub resource_pack_sha1: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateWorldSchema {
    pub name: String,
    pub seed: i64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWorldSchema {
    pub name: Option<String>,
    pub seed: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateWorldVersionSchema {
    pub game_mode: String,
    pub allow_cheats: bool,
    pub difficulty_locked: bool,
    pub spawn_x: i32,
    pub spawn_y: i32,
    pub spawn_z: i32,
    pub time: i64,
    pub size: i64,
    pub weather: String,
    pub hardcore: bool,
    pub command_blocks_enabled: bool,
    pub command_block_output: bool,
    pub do_daylight_cycle: bool,
    pub do_mob_spawning: bool,
    pub do_weather_cycle: bool,
    pub keep_inventory: bool,
    pub max_players: i32,
    pub difficulty: String,
    pub view_distance: i32,
    pub level_name: String,
    pub resource_pack: Option<String>,
    pub resource_pack_sha1: Option<String>,
}
