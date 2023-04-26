use std::sync::Arc;

use actix_multipart::Multipart;
use actix_web::{delete, get, post, put, web, HttpResponse, Responder};
use futures_util::StreamExt as _;
use object_store::{path::Path, ObjectStore};
use serde_json::Value;
use sqlx::PgPool;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    auth::middleware::AuthMiddleware,
    database::models::{CreateWorldVersionSchema, UpdateWorldVersionSchema, World, WorldVersion},
    utilities::WorldVersionPath,
};

#[post("/{world_id}/versions")]
pub async fn create_new_world_version(
    world_id: web::Path<String>,
    body: web::Json<CreateWorldVersionSchema>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    let world_uuid = match Uuid::parse_str(&world_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    let query_result = sqlx::query_as!(World, "SELECT * FROM worlds WHERE id = $1", world_uuid)
        .fetch_optional(pool.as_ref())
        .await
        .unwrap();

    let world = match query_result {
        Some(world) => world,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format!("World: {} does not exist.", world_uuid.to_string())}));
        }
    };

    if world.user_id != auth_guard.user.id {
        if auth_guard.user.role != "admin" {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"status": "error", "message": "You are not authorized to access this world."}));
        }
    }

    let file_path = format!(
        "{}-{}-{}-{}.zip",
        world.user_id,
        world.id,
        world.current_version + 1,
        chrono::Utc::now().naive_utc()
    );

    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)}));
        }
    };

    let query_result = sqlx::query_as!(
        WorldVersion,
        r#"INSERT INTO world_versions (
            id,
            world_id,
            version,
            backup_path,
            game_mode,
            allow_cheats,
            difficulty_locked,
            spawn_x,
            spawn_y,
            spawn_z,
            time,
            size,
            weather,
            hardcore,
            do_daylight_cycle,
            do_mob_spawning,
            do_weather_cycle,
            keep_inventory,
            level_name,
            additional_data,
            difficulty,
            created_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
        )
        RETURNING *"#,
        uuid::Uuid::new_v4(),
        world.id,
        world.current_version + 1,
        file_path,
        body.game_mode.to_string(),
        body.allow_cheats,
        body.difficulty_locked,
        body.spawn_x,
        body.spawn_y,
        body.spawn_z,
        body.time,
        body.size,
        body.weather,
        body.hardcore,
        body.do_daylight_cycle,
        body.do_mob_spawning,
        body.do_weather_cycle,
        body.keep_inventory,
        body.level_name.to_string(),
        body.additional_data,
        body.difficulty,
        chrono::Utc::now().naive_utc()
    )
    .fetch_one(&mut transaction)
    .await;

    match query_result {
        Ok(world_version) => {
            match sqlx::query!(
                "UPDATE worlds SET current_version = $1 WHERE id = $2",
                world.current_version + 1,
                world.id
            )
            .execute(&mut transaction)
            .await
            {
                Ok(_) => {
                    match transaction.commit().await {
                        Ok(_) => {
                            let world_response = serde_json::json!({"status": "success","data": serde_json::json!({
                                "world": world,
                                "version": world_version
                            })});

                            return HttpResponse::Ok().json(world_response);
                        }
                        Err(e) => {
                            return HttpResponse::InternalServerError()
                                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)}));
                        }
                    };
                }
                Err(e) => {
                    return HttpResponse::InternalServerError().json(
                        serde_json::json!({"status": "error","message": format_args!("{:?}", e)}),
                    );
                }
            };
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)}));
        }
    }
}

#[get("/{world_id}/versions/{version_id}")]
pub async fn get_world_versions_by_uuid(
    path_info: web::Path<WorldVersionPath>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    let world_id = path_info.world_id.to_string();
    let version_id = path_info.version_id.to_string();

    let world_uuid = match Uuid::parse_str(&world_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    let version_uuid = match Uuid::parse_str(&version_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{}", e)}));
        }
    };

    let query_result = sqlx::query_as!(World, "SELECT * FROM worlds WHERE id = $1", world_uuid)
        .fetch_optional(pool.as_ref())
        .await
        .unwrap();

    let world = match query_result {
        Some(world) => world,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format!("World: {} does not exist.", world_uuid.to_string())}));
        }
    };

    if world.user_id != auth_guard.user.id {
        if auth_guard.user.role != "admin" {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"status": "error", "message": "You are not authorized to access this world."}));
        }
    }

    let version_result = sqlx::query_as!(
        WorldVersion,
        r#"
        SELECT *
        FROM world_versions
        WHERE id = $1
    "#,
        version_uuid
    )
    .fetch_one(pool.as_ref())
    .await;

    match version_result {
        Ok(version) => {
            let world_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "world": world,
                "version": version
            })});

            return HttpResponse::Ok().json(world_response);
        }
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{}", e)}));
        }
    };
}

#[put("/{world_id}/versions/{version_id}")]
pub async fn upload_world_version(
    path_info: web::Path<WorldVersionPath>,
    mut payload: Multipart,
    pool: web::Data<PgPool>,
    object_store: web::Data<Arc<Box<dyn ObjectStore>>>,
    auth_guard: AuthMiddleware,
) -> Result<HttpResponse, actix_web::Error> {
    let world_id = path_info.world_id.to_string();
    let version_id = path_info.version_id.to_string();

    let world_uuid = match Uuid::parse_str(&world_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)})));
        }
    };

    let version_uuid = match Uuid::parse_str(&version_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)})));
        }
    };

    let query_result = sqlx::query_as!(World, "SELECT * FROM worlds WHERE id = $1", world_uuid)
        .fetch_optional(pool.as_ref())
        .await
        .unwrap();

    let world = match query_result {
        Some(world) => world,
        None => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format!("World: {} does not exist.", world_uuid.to_string())})));
        }
    };

    let query_result = sqlx::query_as!(
        WorldVersion,
        "SELECT * FROM world_versions WHERE id = $1",
        version_uuid
    )
    .fetch_optional(pool.as_ref())
    .await
    .unwrap();

    let version = match query_result {
        Some(version) => version,
        None => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": "Invalid version id."})));
        }
    };

    if world.user_id != auth_guard.user.id {
        if auth_guard.user.role != "admin" {
            return Ok(HttpResponse::Unauthorized()
                .json(serde_json::json!({"status": "error", "message": "You are not authorized to access this world."})));
        }
    }

    let file_path: Path = version.backup_path.try_into().unwrap();

    let (_id, mut writer) = object_store.put_multipart(&file_path).await.unwrap();

    while let Some(item) = payload.next().await {
        let mut field = item?;

        // Field in turn is stream of *Bytes* object
        while let Some(chunk) = field.next().await {
            writer.write_all(&chunk?).await.unwrap();
        }
    }

    writer.flush().await.unwrap();
    writer.shutdown().await.unwrap();

    Ok(HttpResponse::Accepted()
        .json(serde_json::json!({"status": "success", "message": format!("Version: {} successfully uploaded.", version.version)})))
}

#[get("/{world_id}/versions/{version_id}/download")]
pub async fn download_world_by_version_uuid(
    path_info: web::Path<WorldVersionPath>,
    pool: web::Data<PgPool>,
    object_store: web::Data<Arc<Box<dyn ObjectStore>>>,
    auth_guard: AuthMiddleware,
) -> Result<HttpResponse, actix_web::Error> {
    let world_id = path_info.world_id.to_string();
    let version_id = path_info.version_id.to_string();

    let world_uuid = match Uuid::parse_str(&world_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)})));
        }
    };

    let version_uuid = match Uuid::parse_str(&version_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{}", e)})));
        }
    };

    let query_result = sqlx::query_as!(World, "SELECT * FROM worlds WHERE id = $1", world_uuid)
        .fetch_optional(pool.as_ref())
        .await
        .unwrap();

    let world = match query_result {
        Some(world) => world,
        None => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format!("World: {} does not exist.", world_uuid.to_string())})));
        }
    };

    let query_result = sqlx::query_as!(
        WorldVersion,
        "SELECT * FROM world_versions WHERE id = $1",
        version_uuid
    )
    .fetch_optional(pool.as_ref())
    .await
    .unwrap();

    let version = match query_result {
        Some(version) => version,
        None => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": "Invalid version id."})));
        }
    };

    if world.user_id != auth_guard.user.id {
        if auth_guard.user.role != "admin" {
            return Ok(HttpResponse::Unauthorized()
                .json(serde_json::json!({"status": "error", "message": "You are not authorized to access this world."})));
        }
    }

    let file_path: Path = version.backup_path.try_into().unwrap();
    let stream = object_store.get(&file_path).await.unwrap().into_stream();

    Ok(HttpResponse::Ok().streaming(stream))
}

#[get("/{world_id}/versions/{version_id}")]
pub async fn get_version_by_uuid(
    path_info: web::Path<WorldVersionPath>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    let world_id = path_info.world_id.to_string();
    let version_id = path_info.version_id.to_string();

    let world_uuid = match Uuid::parse_str(&world_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    let version_uuid = match Uuid::parse_str(&version_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{}", e)}));
        }
    };

    let query_result = sqlx::query_as!(World, "SELECT * FROM worlds WHERE id = $1", world_uuid)
        .fetch_optional(pool.as_ref())
        .await
        .unwrap();

    let world = match query_result {
        Some(world) => world,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format!("World: {} does not exist.", world_uuid.to_string())}));
        }
    };

    let query_result = sqlx::query_as!(
        WorldVersion,
        "SELECT * FROM world_versions WHERE id = $1",
        version_uuid
    )
    .fetch_optional(pool.as_ref())
    .await
    .unwrap();

    let version = match query_result {
        Some(version) => version,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": "Invalid version id."}));
        }
    };

    if world.user_id != auth_guard.user.id {
        if auth_guard.user.role != "admin" {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"status": "error", "message": "You are not authorized to access this world."}));
        }
    }

    HttpResponse::Ok().json(
        serde_json::json!({"status": "success","data": serde_json::json!({
            "world": world,
            "version": version
        })}),
    )
}

#[delete("/{world_id}/versions/{version_id}")]
pub async fn delete_world_version_by_uuid(
    path_info: web::Path<WorldVersionPath>,
    object_store: web::Data<Arc<Box<dyn ObjectStore>>>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    let world_id = path_info.world_id.to_string();
    let version_id = path_info.version_id.to_string();

    let world_uuid = match Uuid::parse_str(&world_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    let version_uuid = match Uuid::parse_str(&version_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{}", e)}));
        }
    };

    let query_result = sqlx::query_as!(World, "SELECT * FROM worlds WHERE id = $1", world_uuid)
        .fetch_optional(pool.as_ref())
        .await
        .unwrap();

    let world = match query_result {
        Some(world) => world,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format!("World: {} does not exist.", world_uuid.to_string())}));
        }
    };

    if world.user_id != auth_guard.user.id {
        if auth_guard.user.role != "admin" {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"status": "error", "message": "You are not authorized to access this world version."}));
        }
    }

    let query_result = sqlx::query_as!(
        WorldVersion,
        "SELECT * FROM world_versions WHERE id = $1",
        version_uuid
    )
    .fetch_optional(pool.as_ref())
    .await
    .unwrap();

    let version = match query_result {
        Some(version) => version,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format!("World: {} does not exist.", world_uuid.to_string())}));
        }
    };

    match sqlx::query!("DELETE FROM world_versions WHERE id = $1", version.id)
        .execute(pool.as_ref())
        .await
    {
        Ok(_) => {
            let file_path: Path = version.backup_path.try_into().unwrap();

            match object_store.delete(&file_path).await {
                Ok(_) => {}
                Err(e) => {
                    return HttpResponse::InternalServerError().json(
                        serde_json::json!({"status": "error", "message": format_args!("{}", e)}),
                    )
                }
            };

            HttpResponse::Accepted()
                .json(serde_json::json!({"status": "success","message": format!("World Version: {} deleted successfully.", version_uuid.to_string())}))
        }
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)})),
    }
}

#[put("/{world_id}/versions/{version_id}")]
async fn update_world_version_by_uuid(
    path_info: web::Path<WorldVersionPath>,
    body: web::Json<UpdateWorldVersionSchema>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    let world_id = path_info.world_id.to_string();
    let version_id = path_info.version_id.to_string();

    let world_uuid = match Uuid::parse_str(&world_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    let version_uuid = match Uuid::parse_str(&version_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{}", e)}));
        }
    };

    let query_result = sqlx::query_as!(World, "SELECT * FROM worlds WHERE id = $1", world_uuid)
        .fetch_optional(pool.as_ref())
        .await
        .unwrap();

    let world = match query_result {
        Some(world) => world,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format!("World: {} does not exist.", world_uuid.to_string())}));
        }
    };

    if world.user_id != auth_guard.user.id {
        if auth_guard.user.role != "admin" {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"status": "error", "message": "You are not authorized to access this world version."}));
        }
    }

    let query_result = sqlx::query_as!(
        WorldVersion,
        "SELECT * FROM world_versions WHERE id = $1",
        version_uuid
    )
    .fetch_optional(pool.as_ref())
    .await
    .unwrap();

    let version = match query_result {
        Some(version) => version,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format!("World: {} does not exist.", world_uuid.to_string())}));
        }
    };

    match sqlx::query_as!(
        WorldVersion,
        "UPDATE world_versions SET
            game_mode = $1,
            allow_cheats = $2,
            difficulty_locked = $3,
            spawn_x = $4,
            spawn_y = $5,
            spawn_z = $6,
            time = $7,
            size = $8,
            weather = $9,
            hardcore = $10,
            do_daylight_cycle = $11,
            do_mob_spawning = $12,
            do_weather_cycle = $13,
            keep_inventory = $14,
            level_name = $15,
            difficulty = $16,
            additional_data = $17
        WHERE id = $18 RETURNING *",
        body.game_mode.clone().unwrap_or(version.game_mode),
        body.allow_cheats.unwrap_or(version.allow_cheats),
        body.difficulty_locked.unwrap_or(version.difficulty_locked),
        body.spawn_x.unwrap_or(version.spawn_x),
        body.spawn_y.unwrap_or(version.spawn_y),
        body.spawn_z.unwrap_or(version.spawn_z),
        body.time.unwrap_or(version.time),
        body.size.unwrap_or(version.size),
        body.weather.clone().unwrap_or(version.weather),
        body.hardcore.unwrap_or(version.hardcore),
        body.do_daylight_cycle.unwrap_or(version.do_daylight_cycle),
        body.do_mob_spawning.unwrap_or(version.do_mob_spawning),
        body.do_weather_cycle.unwrap_or(version.do_weather_cycle),
        body.keep_inventory.unwrap_or(version.keep_inventory),
        body.level_name.clone().unwrap_or(version.level_name),
        body.difficulty.clone().unwrap_or(version.difficulty),
        body.additional_data
            .clone()
            .unwrap_or(version.additional_data.unwrap_or(Value::default())),
        version_uuid
    )
    .fetch_one(pool.as_ref())
    .await
    {
        Ok(world) => HttpResponse::Accepted().json(
            serde_json::json!({"status": "success","data": serde_json::json!({
                "world": world
            })}),
        ),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)})),
    }
}

pub fn versions_config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("versions"));
}
