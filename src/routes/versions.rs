use std::sync::Arc;

use actix_multipart::Multipart;
use actix_web::{delete, get, patch, post, put, web, HttpResponse, Responder};
use futures_util::StreamExt as _;
use log::error;
use r2d2_redis::redis::Commands;
use s3::{serde_types::Part, Bucket};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::middleware::AuthMiddleware,
    database::models::{CreateWorldVersionSchema, UpdateWorldVersionSchema, World, WorldVersion},
    utilities::{
        ChunkedUploadQuery, ChunkedWorldVersionPath, PageQuery, PartDeserialize, RedisPool,
        WorldVersionPath,
    },
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
    object_store: web::Data<Arc<Bucket>>,
    auth_guard: AuthMiddleware,
) -> Result<HttpResponse, actix_web::Error> {
    if !auth_guard.scope.contains(&String::from("backup:write")) {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        })));
    };

    let object_store = object_store.into_inner();

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

    let file_path = format!(
        "{}/{}/{}-{}.zip",
        world.user_id,
        world.id,
        version.id,
        chrono::Utc::now().naive_utc()
    );

    let upload_id = match object_store
        .initiate_multipart_upload(&file_path, "application/octet-stream")
        .await
    {
        Ok(response) => response.upload_id,
        Err(e) => {
            error!("{:?}", e);
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{:?}", e)})));
        }
    };

    let mut part_number = 1;
    let mut etags = Vec::new();

    match payload.next().await {
        Some(item) => {
            let mut field = item.unwrap();
            let mut bytes = Vec::new();
            while let Some(chunk) = field.next().await {
                match chunk {
                    Ok(chunk) => {
                        bytes.extend_from_slice(&chunk);
                        if bytes.len() >= 5 * 1024 * 1024 {
                            // 5MB
                            let etag = match object_store
                                .put_multipart_chunk(
                                    bytes.clone(),
                                    &file_path,
                                    part_number,
                                    &upload_id,
                                    "application/octet-stream",
                                )
                                .await
                            {
                                Ok(etag) => etag,
                                Err(e) => {
                                    error!("{:?}", e);
                                    return Ok(HttpResponse::InternalServerError()
                                        .json(serde_json::json!({"status": "error", "message": "Failed to upload part"})));
                                }
                            };
                            etags.push(etag);
                            part_number += 1;
                            bytes.clear();
                        }
                    }
                    Err(e) => {
                        error!("{:?}", e);
                    }
                };
            }
            // Upload the last part if it's less than 5MB
            if !bytes.is_empty() {
                let etag = match object_store
                    .put_multipart_chunk(
                        bytes,
                        &file_path,
                        part_number,
                        &upload_id,
                        "application/octet-stream",
                    )
                    .await
                {
                    Ok(etag) => etag,
                    Err(e) => {
                        error!("{:?}", e);
                        return Ok(HttpResponse::InternalServerError()
                            .json(serde_json::json!({"status": "error", "message": "Failed to upload part"})));
                    }
                };
                etags.push(etag);
            }
        }
        None => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": "No file was provided"})));
        }
    };

    match object_store
        .complete_multipart_upload(&file_path, &upload_id, etags)
        .await
    {
        Ok(_) => {}
        Err(e) => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": format_args!("{:?}", e)})));
        }
    }

    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{}", e)})));
        }
    };

    match sqlx::query!(
        "UPDATE world_versions SET backup_path = $1 WHERE id = $2",
        file_path,
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
    object_store: web::Data<Arc<Bucket>>,
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

    let stream = object_store.get_object(&version.backup_path).await.unwrap();
    // let bytes = stream.bytes().map(|result| {
    //     Ok(actix_web::web::Bytes::from(result.to_vec()))
    // });

    let bytes = actix_web::web::Bytes::from(stream.bytes().to_owned());

    Ok(HttpResponse::Ok().body(bytes))
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
    object_store: web::Data<Arc<Bucket>>,
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
            match object_store.delete_object(&version.backup_path).await {
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

#[post("/{world_id}/versions/{version_id}/upload")]
pub async fn start_chunked_upload(
    path_info: web::Path<WorldVersionPath>,
    query: web::Query<ChunkedUploadQuery>,
    pool: web::Data<PgPool>,
    redis_pool: web::Data<RedisPool>,
    object_store: web::Data<Arc<Bucket>>,
    auth_guard: AuthMiddleware,
) -> Result<HttpResponse, actix_web::Error> {
    if !auth_guard.scope.contains(&String::from("backup:write")) {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        })));
    };

    let query = query.into_inner();

    let parts = query.part.unwrap_or(1);
    let content_type = query.content_type.unwrap_or("application/zip".to_string());

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

    let redis_upload_id = Uuid::new_v4().to_string();

    let created_at = chrono::Utc::now().naive_utc();

    let file_path = format!(
        "{}/{}/{}-{}.zip",
        world.user_id,
        world.id,
        version.id,
        created_at.clone()
    );

    let upload_id = match object_store
        .initiate_multipart_upload(&file_path, "application/zip")
        .await
    {
        Ok(response) => response.upload_id,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)})));
        }
    };

    let mut conn = redis_pool.get().unwrap();

    let data = serde_json::json!({
        "world_id": world.id.to_string(),
        "version_id": version.id.to_string(),
        "user_id": auth_guard.user.id.to_string(),
        "upload_id": upload_id,
        "file_path": file_path,
        "content_type": content_type,
        "num_parts": parts,
        "name": query.name,
        "created_at": created_at
    });

    match conn.set::<String, String, ()>(format!("upload:{}", redis_upload_id), data.to_string()) {
        Ok(_) => {}
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)})));
        }
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "Successfully started multipart upload",
        "upload_id": redis_upload_id,
    })))
}

#[put("/{world_id}/versions/{version_id}/upload/{upload_id}")]
pub async fn upload_chunk(
    path_info: web::Path<ChunkedWorldVersionPath>,
    query: web::Query<ChunkedUploadQuery>,
    mut payload: Multipart,
    redis_pool: web::Data<RedisPool>,
    object_store: web::Data<Arc<Bucket>>,
    auth_guard: AuthMiddleware,
) -> Result<HttpResponse, actix_web::Error> {
    if !auth_guard.scope.contains(&String::from("backup:write")) {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        })));
    };

    let mut conn = redis_pool.get().unwrap();

    let object_store = object_store.into_inner();

    let redis_upload_id = path_info.upload_id.to_string();

    let upload_data = match conn.get::<String, String>(format!("upload:{}", redis_upload_id)) {
        Ok(data) => {
            let data: serde_json::Value = serde_json::from_str(&data).unwrap();
            data
        }
        Err(e) => {
            error!("Error getting upload data from redis: {:?}", e);

            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error", "message": "Invalid upload id."})));
        }
    };

    let mut parts: Vec<Part> = match upload_data["parts"].as_array() {
        Some(parts) => {
            let parts_deserialized: Vec<PartDeserialize> = parts
                .into_iter()
                .map(|part| serde_json::from_value(part.to_owned()).unwrap())
                .collect();

            parts_deserialized
                .into_iter()
                .map(|part| Part {
                    part_number: part.part_number,
                    etag: part.etag,
                })
                .collect()
        }
        None => Vec::new(),
    };

    let part_number = query.part.unwrap_or(1) as u32;

    let file_name = upload_data.get("name").unwrap().as_str().unwrap();

    if file_name != query.name.as_str() {
        return Ok(HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "error", "message": "File name does not match."})));
    }

    let upload_id = upload_data.get("upload_id").unwrap().to_string();
    let file_path = upload_data.get("file_path").unwrap().to_string();
    let content_type = upload_data.get("content_type").unwrap().to_string();

    match payload.next().await {
        Some(item) => {
            let mut field = match item {
                Ok(field) => field,
                Err(e) => {
                    error!("Multipart field error: {:?}", e);

                    return Ok(HttpResponse::InternalServerError()
                        .json(serde_json::json!({"status": "error", "message": "Error reading file bytes."})));
                }
            };

            while let Some(chunk) = field.next().await {
                match chunk {
                    Ok(chunk) => {
                        if chunk.len() >= 5 * 1024 * 1024 {
                            match object_store
                                .put_multipart_chunk(
                                    chunk.to_vec(),
                                    &file_path,
                                    part_number,
                                    &upload_id,
                                    &content_type,
                                )
                                .await
                            {
                                Ok(returned_part) => {
                                    parts.push(returned_part);
                                }
                                Err(e) => {
                                    error!(
                                        "Error uploading part: {:?}, Part Number: {}",
                                        e, part_number
                                    );

                                    return Ok(HttpResponse::BadRequest()
                                        .json(serde_json::json!({"status": "error", "message": "Error uploading part."})));
                                }
                            };
                        }
                    }
                    Err(e) => {
                        error!("Multipart error getting bytes: {:?}", e);

                        return Ok(HttpResponse::InternalServerError()
                            .json(serde_json::json!({"status": "error", "message": "Error reading file bytes."})));
                    }
                };
            }
        }
        None => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": "No file was provided"})));
        }
    };

    let data = serde_json::json!({
        "world_id": upload_data["world_id"],
        "version_id": upload_data["version_id"],
        "user_id": upload_data["user_id"],
        "upload_id": upload_id,
        "file_path": file_path,
        "content_type": content_type,
        "num_parts": upload_data["num_parts"],
        "parts": parts,
        "name": upload_data["name"],
        "created_at": upload_data["created_at"],
    });

    match conn.set::<String, String, ()>(format!("upload:{}", redis_upload_id), data.to_string()) {
        Ok(_) => {}
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)})));
        }
    };

    Ok(HttpResponse::Accepted()
        .json(serde_json::json!({"status": "success", "message": format!("Version part: {} successfully uploaded.", part_number)})))
}

#[patch("/{world_id}/versions/{version_id}/upload/{upload_id}")]
pub async fn end_chunked_upload(
    path_info: web::Path<ChunkedWorldVersionPath>,
    query: web::Query<ChunkedUploadQuery>,
    redis_pool: web::Data<RedisPool>,
    pool: web::Data<PgPool>,
    object_store: web::Data<Arc<Bucket>>,
    auth_guard: AuthMiddleware,
) -> Result<HttpResponse, actix_web::Error> {
    if !auth_guard.scope.contains(&String::from("backup:write")) {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        })));
    };

    let mut conn = redis_pool.get().unwrap();

    let redis_upload_id = path_info.upload_id.to_string();

    let upload_data = match conn.get::<String, String>(format!("upload:{}", redis_upload_id)) {
        Ok(data) => {
            let data: serde_json::Value = serde_json::from_str(&data).unwrap();
            data
        }
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error", "message": format_args!("{:?}", e)})));
        }
    };

    let parts_deserialized: Vec<PartDeserialize> =
        serde_json::from_value(upload_data["parts"].to_owned())?;

    let parts: Vec<Part> = parts_deserialized
        .into_iter()
        .map(|part| Part {
            part_number: part.part_number,
            etag: part.etag,
        })
        .collect();

    let file_name = upload_data.get("name").unwrap().as_str().unwrap();

    if file_name != query.name {
        return Ok(HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "error", "message": "File name does not match."})));
    }

    let world_id = upload_data.get("world_id").unwrap().to_string();
    let version_id = upload_data.get("version_id").unwrap().to_string();
    let upload_id = upload_data.get("upload_id").unwrap().to_string();

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

    let backup_path = upload_data.get("file_path").unwrap().to_string();

    match object_store
        .complete_multipart_upload(&backup_path, &upload_id, parts)
        .await
    {
        Ok(_) => {}
        Err(e) => {
            error!("Error completing multipart upload: {:?}", e);

            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error", "message": "Error completing multipart upload."})));
        }
    }

    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{}", e)})));
        }
    };

    match sqlx::query!(
        "UPDATE world_versions SET backup_path = $1 WHERE id = $2",
        backup_path.to_string(),
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
        Ok(_) => {}
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)})));
        }
    }

    match conn.del::<String, ()>(format!("upload:{}", redis_upload_id)) {
        Ok(_) => {}
        Err(_) => {}
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "Successfully ended multipart upload"
    })))
}

#[delete("/{world_id}/versions/{version_id}/upload/{upload_id}")]
pub async fn abort_chunked_upload(
    path_info: web::Path<ChunkedWorldVersionPath>,
    pool: web::Data<PgPool>,
    redis_pool: web::Data<RedisPool>,
    object_store: web::Data<Arc<Bucket>>,
    auth_guard: AuthMiddleware,
) -> Result<HttpResponse, actix_web::Error> {
    if !auth_guard.scope.contains(&String::from("backup:write")) {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        })));
    };

    let mut conn = redis_pool.get().unwrap();

    let world_id = path_info.world_id.to_string();
    let version_id = path_info.version_id.to_string();
    let redis_upload_id = path_info.upload_id.to_string();

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

    let world = match sqlx::query_as!(World, "SELECT * FROM worlds WHERE id = $1", world_uuid)
        .fetch_optional(pool.as_ref())
        .await
        .unwrap()
    {
        Some(world) => world,
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "status": "fail",
                "message": format!("World: {} does not exist.", world_uuid.to_string())
            })));
        }
    };

    if world.user_id != auth_guard.user.id {
        if auth_guard.user.role != "admin" {
            return Ok(HttpResponse::Unauthorized()
                .json(serde_json::json!({"status": "error", "message": "You are not authorized to access this world."})));
        }
    }

    let version = match sqlx::query_as!(
        WorldVersion,
        "SELECT * FROM world_versions WHERE id = $1",
        version_uuid
    )
    .fetch_optional(pool.as_ref())
    .await
    .unwrap()
    {
        Some(version) => version,
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "status": "fail",
                "message": format!("Version: {} does not exist.", version_uuid.to_string())
            })));
        }
    };

    let upload_data = match conn.get::<String, String>(format!("upload:{}", redis_upload_id)) {
        Ok(data) => {
            let data: serde_json::Value = serde_json::from_str(&data).unwrap();
            data
        }
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error", "message": format_args!("{:?}", e)})));
        }
    };

    let upload_id = upload_data.get("upload_id").unwrap().to_string();

    let file_path = upload_data.get("file_path").unwrap().to_string();

    match object_store.abort_upload(&file_path, &upload_id).await {
        Ok(_) => {}
        Err(_) => {}
    };

    match sqlx::query!("DELETE FROM world_versions WHERE id = $1", version.id)
        .execute(pool.as_ref())
        .await
    {
        Ok(_) => {}
        Err(e) => {
            return Ok(HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error", "message": format_args!("{:?}", e)})));
        }
    }

    match conn.del::<String, ()>(format!("upload:{}", redis_upload_id)) {
        Ok(_) => {}
        Err(_) => {}
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "Successfully aborted multipart upload"
    })))
}

pub fn versions_config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("versions"));
}
