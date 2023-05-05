use std::env;

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    auth::{
        middleware::AuthMiddleware,
        token::{generate_jwt_token, generate_token},
    },
    database::models::{
        CreateClientRequest, FilteredUser, LoginUserSchema, OAuthClient, RegisterUserSchema, User,
    },
};

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        username: user.username.to_string(),
        email: user.email.to_string(),
        role: user.role.to_owned(),
        createdAt: user.created_at.unwrap(),
        updatedAt: user.updated_at.unwrap(),
    }
}

#[post("/register")]
async fn register_user(
    body: web::Json<RegisterUserSchema>,
    pool: web::Data<PgPool>,
) -> impl Responder {
    let exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(body.email.to_owned())
        .fetch_one(pool.as_ref())
        .await
        .unwrap()
        .get(0);

    if exists {
        return HttpResponse::Conflict().json(
            serde_json::json!({"status": "fail","message": "User with that email already exists"}),
        );
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .expect("Error while hashing password");

    let query_result = sqlx::query_as!(
        User,
        "INSERT INTO users (id,username,email,password_hash,role,created_at,updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING *",
        uuid::Uuid::new_v4(),
        body.name.to_string(),
        body.email.to_string().to_lowercase(),
        hashed_password.to_string(),
        "user",
        chrono::Utc::now().naive_utc()
    )
    .fetch_one(pool.as_ref())
    .await;

    match query_result {
        Ok(user) => {
            let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "user": filter_user_record(&user)
            })});

            return HttpResponse::Ok().json(user_response);
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)}));
        }
    }
}

#[post("/login")]
async fn login_user(body: web::Json<LoginUserSchema>, pool: web::Data<PgPool>) -> impl Responder {
    let query_result = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = $1",
        body.email.to_string().to_lowercase()
    )
    .fetch_optional(pool.as_ref())
    .await
    .unwrap();

    let user = match query_result {
        Some(user) => user,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": "Invalid email."}));
        }
    };

    let parsed_hash = PasswordHash::new(&user.password_hash).unwrap();

    let is_valid = Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed_hash)
        .is_ok();

    if !is_valid {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "fail", "message": "Invalid password."}));
    }

    // let access_token = generate_token(64);
    let client_id = env::var("CLIENT_ID").expect("FIRST_PARTY_CLIENT_ID is not set");

    let client_uuid = Uuid::parse_str(&client_id).unwrap();

    let access_token_details =
        match generate_jwt_token(user.id, client_uuid, "read,write".to_string(), 30) {
            Ok(token_details) => token_details,
            Err(e) => {
                return HttpResponse::BadGateway().json(
                    serde_json::json!({"status": "fail", "message": format_args!("{:?}", e)}),
                );
            }
        };

    let refresh_token = generate_token(64);

    match sqlx::query!(
        "INSERT INTO oauth_access_tokens (access_token,client_id,user_id,expires,scope) VALUES ($1, $2, $3, $4, $5)",
        access_token_details.clone().token_uuid,
        client_uuid,
        user.id,
        chrono::Utc::now().naive_utc() + chrono::Duration::minutes(30),
        "read,write"
    )
    .execute(pool.as_ref())
    .await
    {
        Ok(_) => {}
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    }

    match sqlx::query!(
        "INSERT INTO oauth_refresh_tokens (refresh_token,client_id,user_id,expires,scope) VALUES ($1, $2, $3, $4, $5)",
        refresh_token.clone(),
        client_uuid,
        user.id,
        chrono::Utc::now().naive_utc() + chrono::Duration::minutes(60),
        "read,write"
    )
    .execute(pool.as_ref())
    .await
    {
        Ok(_) => {}
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    }

    HttpResponse::Ok()
        .json(serde_json::json!({"status": "success", "access_token": access_token_details.token.unwrap(), "refresh_token": refresh_token}))
}

#[get("/refresh")]
async fn refresh_access_token(req: HttpRequest, pool: web::Data<PgPool>) -> impl Responder {
    let message = "could not refresh access token";

    let refresh_token = match req.headers().get("Authorization") {
        Some(header_value) => {
            if let Ok(auth_str) = header_value.to_str() {
                if auth_str.starts_with("Bearer ") {
                    auth_str[7..].to_string()
                } else {
                    return HttpResponse::Forbidden().json(
                        serde_json::json!({"status": "fail", "message": "Invalid token format"}),
                    );
                }
            } else {
                return HttpResponse::Forbidden().json(
                    serde_json::json!({"status": "fail", "message": "Invalid token format"}),
                );
            }
        }
        None => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"status": "fail", "message": message}));
        }
    };

    let query_result = sqlx::query!(
        "SELECT user_id FROM oauth_refresh_tokens WHERE refresh_token = $1",
        refresh_token
    )
    .fetch_one(pool.as_ref())
    .await;

    let user_id = match query_result {
        Ok(user) => user.user_id,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "fail", "message": message}));
        }
    };

    let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_optional(pool.as_ref())
        .await
        .unwrap();

    if query_result.is_none() {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"status": "fail", "message": "the user belonging to this token no logger exists"}));
    }

    let user = query_result.unwrap();

    let client_id = env::var("CLIENT_ID").expect("FIRST_PARTY_CLIENT_ID is not set");

    let client_uuid = Uuid::parse_str(&client_id).unwrap();

    let access_token_details =
        match generate_jwt_token(user.id, client_uuid, "read,write".to_string(), 30) {
            Ok(token_details) => token_details,
            Err(e) => {
                return HttpResponse::BadGateway().json(
                    serde_json::json!({"status": "fail", "message": format_args!("{:?}", e)}),
                );
            }
        };

    let new_refresh_token = generate_token(64);

    match sqlx::query!(
        "INSERT INTO oauth_access_tokens (access_token,client_id,user_id,expires,scope) VALUES ($1, $2, $3, $4, $5)",
        access_token_details.token_uuid.clone(),
        client_uuid,
        user.id,
        chrono::Utc::now().naive_utc() + chrono::Duration::minutes(60),
        "read,write"
    )
    .execute(pool.as_ref())
    .await
    {
        Ok(_) => {}
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    }

    match sqlx::query!(
        "INSERT INTO oauth_refresh_tokens (refresh_token,client_id,user_id,expires,scope) VALUES ($1, $2, $3, $4, $5)",
        new_refresh_token.clone(),
        client_uuid,
        user.id,
        chrono::Utc::now().naive_utc() + chrono::Duration::minutes(60),
        "read,write"
    )
    .execute(pool.as_ref())
    .await
    {
        Ok(_) => {}
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    }

    HttpResponse::Ok()
        .json(serde_json::json!({"status": "success", "access_token": access_token_details.token.unwrap(), "refresh_token": new_refresh_token}))
}

#[get("/users/me")]
async fn get_me_handler(auth_guard: AuthMiddleware) -> impl Responder {
    let json_response = serde_json::json!({
        "status":  "success",
        "data": serde_json::json!({
            "user": filter_user_record(&auth_guard.user)
        })
    });

    HttpResponse::Ok().json(json_response)
}

#[post("/create-client")]
async fn create_new_client(
    data: web::Json<CreateClientRequest>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    let oauth_client = match sqlx::query_as!(
        OAuthClient,
        "INSERT INTO oauth_clients (client_id,client_secret,name,redirect_uri,grant_types,scope,user_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        Uuid::new_v4(),
        generate_token(64),
        data.name.clone(),
        data.redirect_uri.clone(),
        data.grant_types.clone(),
        data.scope.clone(),
        auth_guard.user.id
    )
    .fetch_one(pool.as_ref())
    .await
    {
        Ok(oauth_client) => oauth_client,
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    HttpResponse::Ok().json(serde_json::json!(oauth_client))
}

pub fn auth_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("auth")
            .service(register_user)
            .service(login_user)
            .service(refresh_access_token)
            .service(get_me_handler)
            .service(create_new_client),
    );
}
