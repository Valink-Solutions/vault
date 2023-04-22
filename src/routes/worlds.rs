use std::sync::Arc;

use actix_multipart::Multipart;
use actix_web::{get, post, put, web, HttpResponse, Responder};
use futures_util::StreamExt as _;
use object_store::{path::Path, ObjectStore};
use sqlx::PgPool;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    auth::middleware::JwtMiddleware,
    database::models::{CreateWorldSchema, CreateWorldVersionSchema, World, WorldVersion},
    utilities::{PageQuery, VersionUploadPath},
};

#[post("/")]
pub async fn create_new_world(
    body: web::Json<CreateWorldSchema>,
    pool: web::Data<PgPool>,
    jwt_guard: JwtMiddleware,
) -> impl Responder {
    let query_result = sqlx::query_as!(
        World,
        "INSERT INTO worlds (id,user_id,name,seed,version,created_at,updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING *",
        uuid::Uuid::new_v4(),
        jwt_guard.user.id,
        body.name.to_string(),
        body.seed,
        0,
        chrono::Utc::now().naive_utc()
    )
    .fetch_one(pool.as_ref())
    .await;

    match query_result {
        Ok(world) => {
            let world_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "world": world
            })});

            return HttpResponse::Ok().json(world_response);
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)}));
        }
    }
}

#[get("/{world_id}")]
pub async fn get_world_by_uuid(
    world_id: web::Path<String>,
    pool: web::Data<PgPool>,
    jwt_guard: JwtMiddleware,
) -> impl Responder {
    let world_uuid = match Uuid::parse_str(&world_id) {
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

    match query_result {
        Some(world) => {
            if world.user_id != jwt_guard.user.id {
                if jwt_guard.user.role != "admin" {
                    return HttpResponse::Unauthorized()
                        .json(serde_json::json!({"status": "fail", "message": "You are not authorized to access this world."}));
                }
            }

            let world_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "world": world
            })});

            return HttpResponse::Ok().json(world_response);
        }
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": "Invalid world id."}));
        }
    };
}

#[post("/{world_id}/versions/")]
pub async fn create_new_world_version(
    world_id: web::Path<String>,
    body: web::Json<CreateWorldVersionSchema>,
    pool: web::Data<PgPool>,
    jwt_guard: JwtMiddleware,
) -> impl Responder {
    let world_uuid = match Uuid::parse_str(&world_id) {
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
                .json(serde_json::json!({"status": "fail", "message": "Invalid world id."}));
        }
    };

    if world.user_id != jwt_guard.user.id {
        if jwt_guard.user.role != "admin" {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"status": "fail", "message": "You are not authorized to access this world."}));
        }
    }

    let file_path = format!(
        "{}-{}-{}-{}.zip",
        world.user_id,
        world.id,
        world.version + 1,
        chrono::Utc::now().naive_utc()
    );

    let query_result = sqlx::query_as!(
        WorldVersion,
        r#"INSERT INTO world_versions (
            id,
            world_id,
            version_number,
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
            command_blocks_enabled,
            command_block_output,
            do_daylight_cycle,
            do_mob_spawning,
            do_weather_cycle,
            keep_inventory,
            max_players,
            view_distance,
            level_name,
            resource_pack,
            resource_pack_sha1,
            difficulty,
            created_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27
        )
        RETURNING *"#,
        uuid::Uuid::new_v4(),
        world.id,
        world.version + 1,
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
        body.command_blocks_enabled,
        body.command_block_output,
        body.do_daylight_cycle,
        body.do_mob_spawning,
        body.do_weather_cycle,
        body.keep_inventory,
        body.max_players,
        body.view_distance,
        body.level_name.to_string(),
        body.resource_pack,
        body.resource_pack_sha1,
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

#[get("/{world_id}/versions/")]
pub async fn get_world_versions_by_uuid(
    world_id: web::Path<String>,
    query: web::Query<PageQuery>,
    pool: web::Data<PgPool>,
    jwt_guard: JwtMiddleware,
) -> impl Responder {
    let world_uuid = match Uuid::parse_str(&world_id) {
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
                .json(serde_json::json!({"status": "fail", "message": "Invalid world id."}));
        }
    };

    if world.user_id != jwt_guard.user.id {
        if jwt_guard.user.role != "admin" {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"status": "fail", "message": "You are not authorized to access this world."}));
        }
    }

    let limit = query.limit;
    let offset = query.offset;

    let versions_result: Result<Vec<WorldVersion>, sqlx::Error> = sqlx::query_as!(
        WorldVersion,
        r#"
        SELECT *
        FROM world_versions
        WHERE world_id = $1
        ORDER BY version_number
        LIMIT $2
        OFFSET $3
    "#,
        world.id,
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
    path_info: web::Path<VersionUploadPath>,
    mut payload: Multipart,
    pool: web::Data<PgPool>,
    object_store: web::Data<Arc<Box<dyn ObjectStore>>>,
    jwt_guard: JwtMiddleware,
) -> Result<HttpResponse, actix_web::Error> {
    let world_id = path_info.world_id.to_string();
    let version_id = path_info.version_id.to_string();

    let world_uuid = match Uuid::parse_str(&world_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            return Ok(HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{}", e)})));
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
                .json(serde_json::json!({"status": "fail", "message": "Invalid world id."})));
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

    if world.user_id != jwt_guard.user.id {
        if jwt_guard.user.role != "admin" {
            return Ok(HttpResponse::Unauthorized()
                .json(serde_json::json!({"status": "fail", "message": "You are not authorized to access this world."})));
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
        .json(serde_json::json!({"status": "success", "message": format!("Version: {} successfully uploaded.", version.version_number)})))
}

pub fn worlds_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("worlds")
            .service(create_new_world)
            .service(get_world_by_uuid)
            .service(create_new_world_version)
            .service(get_world_versions_by_uuid)
            .service(upload_world_version),
    );
}
