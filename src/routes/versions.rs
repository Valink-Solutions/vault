use std::sync::Arc;

use actix_multipart::Multipart;
use actix_web::{delete, get, post, put, web, HttpResponse, Responder};
use futures_util::StreamExt as _;
use log::error;
use object_store::{path::Path, ObjectStore};
use serde_json::Value;
use sqlx::PgPool;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    auth::middleware::AuthMiddleware,
    database::models::{CreateWorldVersionSchema, UpdateWorldVersionSchema, World, WorldVersion},
    utilities::{PageQuery, WorldVersionPath},
};

#[post("/{world_id}/versions")]
pub async fn create_new_world_version(
    world_id: web::Path<String>,
    body: web::Json<CreateWorldVersionSchema>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    if !auth_guard.scope.contains(&String::from("backup:write")) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        }));
    };

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

    let query_result = sqlx::query_as!(
        WorldVersion,
        r#"INSERT INTO world_versions (
            id,
            world_id,
            version,
            backup_path,
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
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
        )
        RETURNING *"#,
        uuid::Uuid::new_v4(),
        world.id,
        world.current_version + 1,
        "",
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
    .fetch_one(pool.as_ref())
    .await;

    match query_result {
        Ok(world_version) => {
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
    }
}

#[get("/{world_id}/versions")]
pub async fn get_world_versions_by_uuid(
    world_id: web::Path<String>,
    query: web::Query<PageQuery>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    if !auth_guard.scope.contains(&String::from("backup:read")) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        }));
    };

    let world_id = world_id.into_inner();

    let world_uuid = match Uuid::parse_str(&world_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    let world_result = sqlx::query_as!(World, "SELECT * FROM worlds WHERE id = $1", world_uuid)
        .fetch_optional(pool.as_ref())
        .await
        .unwrap();

    let world = match world_result {
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

    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);

    let versions_result: Result<Vec<WorldVersion>, sqlx::Error> = sqlx::query_as!(
        WorldVersion,
        r#"
        SELECT *
        FROM world_versions
        WHERE world_id = $1
        LIMIT $2
        OFFSET $3
    "#,
        world_uuid,
        limit,
        offset
    )
    .fetch_all(pool.as_ref())
    .await;

    match versions_result {
        Ok(versions) => {
            let world_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "world": world,
                "versions": versions
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
    if !auth_guard.scope.contains(&String::from("backup:write")) {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        })));
    };

    const BUFFER_SIZE: usize = 5 * 1024 * 1024;

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

    let old_file_path = version.backup_path;

    if old_file_path.len() >= 1 {
        return Ok(HttpResponse::Conflict()
            .json(serde_json::json!({"status": "error", "message": "Version already has a file associated with it"})));
    }

    let file_path: Path = format!(
        "{}/{}/{}-{}.zip",
        world.user_id,
        world.id,
        version.id,
        chrono::Utc::now().naive_utc()
    )
    .try_into()
    .unwrap();

    let (id, mut writer) = object_store.put_multipart(&file_path).await.unwrap();

    let result = async {
        let mut buffer = Vec::with_capacity(BUFFER_SIZE);
        while let Some(item) = payload.next().await {
            let mut field = item?;

            while let Some(chunk) = field.next().await {
                let chunk = chunk?;
                let mut chunk_start = 0;
                while chunk_start < chunk.len() {
                    let chunk_end =
                        std::cmp::min(chunk_start + BUFFER_SIZE - buffer.len(), chunk.len());
                    buffer.extend_from_slice(&chunk[chunk_start..chunk_end]);
                    chunk_start = chunk_end;

                    if buffer.len() == BUFFER_SIZE {
                        writer.write(&buffer).await?;
                        buffer.clear();
                    }
                }
            }
        }

        if !buffer.is_empty() {
            writer.write_all(&buffer).await?;
        }

        writer.flush().await?;
        writer.shutdown().await?;

        Ok(())
    }
    .await;

    if let Err(e) = result {
        error!("Could not upload world file, aborting. {:?}", e);
        object_store.abort_multipart(&file_path, &id).await.unwrap();
        return Err(e);
    }

    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)})));
        }
    };

    match sqlx::query!(
        "UPDATE world_versions SET backup_path = $1 WHERE id = $2",
        file_path.to_string(),
        version.id
    )
    .execute(&mut transaction)
    .await
    {
        Ok(_) => {}
        Err(e) => {
            let _ = transaction.rollback().await;
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)})));
        }
    };

    match sqlx::query!(
        "UPDATE worlds SET current_version = $1 WHERE id = $2",
        world.current_version + 1,
        world.id
    )
    .execute(&mut transaction)
    .await
    {
        Ok(_) => {}
        Err(e) => {
            let _ = transaction.rollback().await;
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)})));
        }
    };

    match transaction.commit().await {
        Ok(_) => {
            Ok(HttpResponse::Accepted()
                .json(serde_json::json!({"status": "success", "message": format!("Version: {} successfully uploaded.", version.version)})))
        }
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)})));
        }
    }
}

#[get("/{world_id}/versions/{version_id}/download")]
pub async fn download_world_by_version_uuid(
    path_info: web::Path<WorldVersionPath>,
    pool: web::Data<PgPool>,
    object_store: web::Data<Arc<Box<dyn ObjectStore>>>,
    auth_guard: AuthMiddleware,
) -> Result<HttpResponse, actix_web::Error> {
    if !auth_guard.scope.contains(&String::from("backup:read")) {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        })));
    };

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
    if !auth_guard.scope.contains(&String::from("backup:write")) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        }));
    };

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
    if !auth_guard.scope.contains(&String::from("backup:write")) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        }));
    };

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
    if !auth_guard.scope.contains(&String::from("backup:write")) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        }));
    };

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
            allow_cheats = $1,
            difficulty_locked = $2,
            spawn_x = $3,
            spawn_y = $4,
            spawn_z = $5,
            time = $6,
            size = $7,
            weather = $8,
            hardcore = $9,
            do_daylight_cycle = $10,
            do_mob_spawning = $11,
            do_weather_cycle = $12,
            keep_inventory = $13,
            level_name = $14,
            difficulty = $15,
            additional_data = $16
        WHERE id = $17 RETURNING *",
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
