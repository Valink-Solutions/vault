use actix_web::{delete, get, post, put, web, HttpResponse, Responder};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::middleware::AuthMiddleware,
    database::models::{CreateWorldSchema, UpdateWorldSchema, World},
    utilities::PageQuery,
};

use super::versions::{
    create_new_world_version, delete_world_version_by_uuid, download_world_by_version_uuid,
    get_world_versions_by_uuid, update_world_version_by_uuid, upload_world_version,
};

#[get("")]
async fn get_worlds_for_current_user(
    query: web::Query<PageQuery>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    if !auth_guard.scope.contains(&"world:read".to_string()) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        }));
    };

    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);

    let world_result: Result<Vec<World>, sqlx::Error> = sqlx::query_as!(
        World,
        r#"
        SELECT *
        FROM worlds
        WHERE user_id = $1
        LIMIT $2
        OFFSET $3
    "#,
        auth_guard.user.id,
        limit,
        offset
    )
    .fetch_all(pool.as_ref())
    .await;

    match world_result {
        Ok(worlds) => {
            if worlds.len() > 0 {
                return HttpResponse::Ok().json(
                    serde_json::json!({"status": "success","data": serde_json::json!({
                        "worlds": worlds
                    })}),
                );
            } else {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"status": "fail","message": "User currently has no worlds."}));
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)}));
        }
    }
}

#[post("")]
async fn create_new_world(
    body: web::Json<CreateWorldSchema>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    if !auth_guard.scope.contains(&String::from("world:write")) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "fail",
            "message": "You do not have the permissions to access this route"
        }));
    };

    let query_result = sqlx::query_as!(
        World,
        "INSERT INTO worlds (id,user_id,name,seed,edition,current_version,created_at,updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $7) RETURNING *",
        uuid::Uuid::new_v4(),
        auth_guard.user.id,
        body.name.to_string(),
        body.seed,
        body.edition.to_lowercase(),
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
async fn get_world_by_uuid(
    world_id: web::Path<String>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    if !auth_guard.scope.contains(&String::from("world:read")) {
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

    match query_result {
        Some(world) => {
            if world.user_id != auth_guard.user.id {
                if auth_guard.user.role != "admin" {
                    return HttpResponse::Unauthorized()
                        .json(serde_json::json!({"status": "error", "message": "You are not authorized to access this world."}));
                }
            }

            let world_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "world": world
            })});

            return HttpResponse::Ok().json(world_response);
        }
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": format!("World: {} does not exist.", world_uuid.to_string())}));
        }
    };
}

#[put("/{world_id}")]
async fn update_world_by_uuid(
    world_id: web::Path<String>,
    body: web::Json<UpdateWorldSchema>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    if !auth_guard.scope.contains(&String::from("world:write")) {
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

    match sqlx::query_as!(
        World,
        "UPDATE worlds SET name = $1, seed = $2, updated_at = $3 WHERE id = $4 RETURNING *",
        body.name.clone().unwrap_or(world.name),
        body.seed.unwrap_or(world.seed),
        chrono::Utc::now().naive_utc(),
        world_uuid
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

#[delete("/{world_id}")]
async fn delete_world_by_uuid(
    world_id: web::Path<String>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    if !auth_guard.scope.contains(&String::from("world:write")) {
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

    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)}));
        }
    };

    match sqlx::query!("DELETE FROM worlds WHERE id = $1", world_uuid)
        .execute(&mut transaction)
        .await
    {
        Ok(_) => {
            match sqlx::query!(
                "INSERT INTO deleted_worlds (world_id,user_id) VALUES ($1, $2)",
                world.id,
                world.user_id
            )
            .execute(&mut transaction)
            .await
            {
                Ok(_) => {
                    match transaction.commit().await {
                        Ok(_) => {
                           return HttpResponse::Accepted()
                                .json(serde_json::json!({"status": "success","message": format!("World: {} deleted successfully.", world_uuid.to_string())}))
                        }
                        Err(e) => {
                            return HttpResponse::InternalServerError()
                                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)}));
                        }
                    };
                }
                Err(e) => {
                    let _ = transaction.rollback().await;
                    return HttpResponse::InternalServerError().json(
                        serde_json::json!({"status": "error","message": format_args!("{:?}", e)}),
                    );
                }
            };
        }
        Err(e) => {
            let _ = transaction.rollback().await;
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}))
        }
    }
}

pub fn worlds_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("worlds")
            .service(create_new_world)
            .service(get_world_by_uuid)
            .service(create_new_world_version)
            .service(get_world_versions_by_uuid)
            .service(upload_world_version)
            .service(download_world_by_version_uuid)
            .service(get_worlds_for_current_user)
            .service(update_world_by_uuid)
            .service(delete_world_by_uuid)
            .service(update_world_version_by_uuid)
            .service(delete_world_version_by_uuid),
    );
}
