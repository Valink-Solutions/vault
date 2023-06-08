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
    pub current_version: i32,
    pub edition: String,
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
    pub version: i32,
    pub backup_path: String,
    pub created_at: Option<NaiveDateTime>,
    pub difficulty: String,
    pub allow_cheats: bool,
    pub difficulty_locked: bool,
    pub spawn_x: i32,
    pub spawn_y: i32,
    pub spawn_z: i32,
    pub time: i64,
    pub weather: String,
    pub hardcore: bool,
    pub do_daylight_cycle: bool,
    pub do_mob_spawning: bool,
    pub do_weather_cycle: bool,
    pub keep_inventory: bool,
    pub size: i64,
    pub level_name: String,
    pub additional_data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpdateWorldVersionSchema {
    pub allow_cheats: Option<bool>,
    pub difficulty_locked: Option<bool>,
    pub spawn_x: Option<i32>,
    pub spawn_y: Option<i32>,
    pub spawn_z: Option<i32>,
    pub time: Option<i64>,
    pub size: Option<i64>,
    pub weather: Option<String>,
    pub hardcore: Option<bool>,
    pub do_daylight_cycle: Option<bool>,
    pub do_mob_spawning: Option<bool>,
    pub do_weather_cycle: Option<bool>,
    pub keep_inventory: Option<bool>,
    pub difficulty: Option<String>,
    pub level_name: Option<String>,
    pub additional_data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct CreateWorldSchema {
    pub name: String,
    pub seed: i64,
    pub edition: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWorldSchema {
    pub name: Option<String>,
    pub seed: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateWorldVersionSchema {
    pub allow_cheats: bool,
    pub difficulty_locked: bool,
    pub spawn_x: i32,
    pub spawn_y: i32,
    pub spawn_z: i32,
    pub time: i64,
    pub size: i64,
    pub weather: String,
    pub hardcore: bool,
    pub do_daylight_cycle: bool,
    pub do_mob_spawning: bool,
    pub do_weather_cycle: bool,
    pub keep_inventory: bool,
    pub difficulty: String,
    pub level_name: String,
    pub additional_data: Option<serde_json::Value>,
}
