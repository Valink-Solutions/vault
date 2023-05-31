use std::env;

use actix_web::{
    cookie::{time, Cookie, SameSite},
    get, patch, post, web, HttpRequest, HttpResponse, Responder,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose, Engine as _};
use secrecy::ExposeSecret;
use sqlx::{PgPool, Row};
use url::Url;
use uuid::Uuid;

use crate::{
    auth::{
        middleware::{check_for_user, AuthMiddleware},
        schemas::{
            AcceptedAuthorization, AcceptedCreateClientAuthorization, CreateApiKey,
            CreateClientRequest, LoginQuery, RevokeTokenQuery, TradeTokenQuery, UpdatePassword,
        },
        token::{generate_jwt_token, generate_token, verify_jwt_token},
        utils::filter_user_record,
    },
    configuration::Settings,
    database::models::{
        ApiKey, LoginUserSchema, OAuthAuthorizationToken, OAuthClient, RegisterUserSchema, User,
    },
    scopes::Scopes,
};

#[post("/register")]
async fn register_user(
    body: web::Either<web::Json<RegisterUserSchema>, web::Form<RegisterUserSchema>>,
    pool: web::Data<PgPool>,
    tmpl: web::Data<tera::Tera>,
) -> impl Responder {
    let mut ctx = tera::Context::new();

    let RegisterUserSchema {
        username,
        email,
        confirm_email,
        password,
        confirm_password,
    } = match body {
        web::Either::Left(json) => json.into_inner(),
        web::Either::Right(form) => form.into_inner(),
    };

    if username.len() <= 0 || email.len() <= 0 || password.len() <= 7 {
        ctx.insert("error", "Do not leave fields blank.");
        let rendered_html = match tmpl
            .render("components/register_form.html", &ctx)
            .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))
        {
            Ok(data) => data,
            Err(e) => {
                return HttpResponse::InternalServerError().json(
                    serde_json::json!({"status": "error","message": format_args!("{:?}", e)}),
                );
            }
        };

        return HttpResponse::Ok()
            .content_type("text/html")
            .body(rendered_html);
    }

    if email != confirm_email {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "fail", "message": "Emails do not match"}));
    }

    if password != confirm_password {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "fail", "message": "Passwords do not match"}));
    }

    let email_exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(email.to_owned())
        .fetch_one(pool.as_ref())
        .await
        .unwrap()
        .get(0);

    let username_exists: bool =
        sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
            .bind(username.to_owned())
            .fetch_one(pool.as_ref())
            .await
            .unwrap()
            .get(0);

    if email_exists {
        ctx.insert("error", "User with that email already exists");
        let rendered_html = match tmpl
            .render("components/register_form.html", &ctx)
            .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))
        {
            Ok(data) => data,
            Err(e) => {
                return HttpResponse::InternalServerError().json(
                    serde_json::json!({"status": "error","message": format_args!("{:?}", e)}),
                );
            }
        };

        return HttpResponse::Ok()
            .content_type("text/html")
            .body(rendered_html);
        // return HttpResponse::Conflict().json(
        //     serde_json::json!({"status": "fail","message": "User with that email already exists"}),
        // );
    }

    if username_exists {
        ctx.insert(
            "error",
            &format!("User with username '{}' already exists", username),
        );
        let rendered_html = match tmpl
            .render("components/register_form.html", &ctx)
            .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))
        {
            Ok(data) => data,
            Err(e) => {
                return HttpResponse::InternalServerError().json(
                    serde_json::json!({"status": "error","message": format_args!("{:?}", e)}),
                );
            }
        };

        return HttpResponse::Ok()
            .content_type("text/html")
            .body(rendered_html);
        // return HttpResponse::Conflict().json(
        //     serde_json::json!({"status": "fail", "message": format!("User with username '{}' already exists", username)}),
        // );
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("Error while hashing password");

    let query_result = sqlx::query_as!(
        User,
        "INSERT INTO users (id,username,email,password_hash,role,created_at,updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING *",
        uuid::Uuid::new_v4(),
        username.to_string(),
        email.to_string().to_lowercase(),
        hashed_password.to_string(),
        "user",
        chrono::Utc::now().naive_utc()
    )
    .fetch_one(pool.as_ref())
    .await;

    match query_result {
        Ok(user) => {
            let _user_response = serde_json::json!({"status": "success","data": serde_json::json!({
                "user": filter_user_record(&user)
            })});

            let rendered_html = match tmpl
                .render("components/register_success.html", &ctx)
                .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))
            {
                Ok(data) => data,
                Err(e) => {
                    return HttpResponse::InternalServerError().json(
                        serde_json::json!({"status": "error","message": format_args!("{:?}", e)}),
                    );
                }
            };

            return HttpResponse::Ok()
                .content_type("text/html")
                .body(rendered_html);
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)}));
        }
    }
}

#[post("/login")]
async fn login_user(
    body: web::Either<web::Json<LoginUserSchema>, web::Form<LoginUserSchema>>,
    pool: web::Data<PgPool>,
    query: web::Query<LoginQuery>,
    settings: web::Data<Settings>,
) -> impl Responder {
    let LoginUserSchema { email, password } = match body {
        web::Either::Left(json) => json.into_inner(),
        web::Either::Right(form) => form.into_inner(),
    };

    let query_result = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = $1",
        email.to_lowercase()
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
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    if !is_valid {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "fail", "message": "Invalid password."}));
    }

    // let access_token = generate_token(64);
    let client_id = settings.admin.client_id.clone();

    let client_uuid = Uuid::parse_str(&client_id).unwrap();

    let client_scope = match sqlx::query!(
        "SELECT scope FROM oauth_clients WHERE client_id = $1",
        client_uuid
    )
    .fetch_one(pool.as_ref())
    .await
    {
        Ok(row) => row
            .scope
            .unwrap_or("read-worlds,write-worlds,delete-worlds".to_string()),
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "fail", "message": "Please try again later."}));
        }
    };

    let access_token_details = match generate_jwt_token(
        user.id,
        client_uuid,
        client_scope.clone(),
        30,
        settings.application.private_key.expose_secret().clone(),
        settings.application.base_url.clone(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            return HttpResponse::BadGateway()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{:?}", e)}));
        }
    };

    let refresh_token = generate_token(64);

    match sqlx::query!(
        "INSERT INTO oauth_access_tokens (access_token,client_id,user_id,expires,scope) VALUES ($1, $2, $3, $4, $5)",
        access_token_details.clone().token_uuid,
        client_uuid,
        user.id,
        chrono::Utc::now().naive_utc() + chrono::Duration::minutes(30),
        client_scope
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
        client_scope
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

    let access_token = access_token_details.token.unwrap();

    match query.redirect_uri.to_owned() {
        Some(redirect_uri) => {
            return HttpResponse::Found()
                .append_header(("Location", redirect_uri))
                .cookie(
                    Cookie::build("access_token", &access_token)
                        // .domain(env::var("APP_DOMAIN").unwrap_or("localhost:8080".to_string()))
                        .path("/")
                        .secure(true)
                        .same_site(SameSite::Strict)
                        .max_age(time::Duration::minutes(30))
                        .finish(),
                )
                .cookie(
                    Cookie::build("refresh_token", &refresh_token)
                        // .domain(env::var("APP_DOMAIN").unwrap_or("localhost:8080".to_string()))
                        .path("/")
                        .secure(true)
                        .same_site(SameSite::Strict)
                        .max_age(time::Duration::minutes(60))
                        .finish(),
                )
                .finish();
        }
        None => {
            return HttpResponse::Ok()
                .cookie(
                    Cookie::build("access_token", &access_token)
                        // .domain(env::var("APP_DOMAIN").unwrap_or("localhost:8080".to_string()))
                        .path("/")
                        .secure(true)
                        .same_site(SameSite::Strict)
                        .max_age(time::Duration::minutes(30))
                        .finish()
                )
                .cookie(
                    Cookie::build("refresh_token", &refresh_token)
                        // .domain(env::var("APP_DOMAIN").unwrap_or("localhost:8080".to_string()))
                        .path("/")
                        .secure(true)
                        .same_site(SameSite::Strict)
                        .max_age(time::Duration::minutes(60))
                        .finish()
                )
                .json(serde_json::json!({"status": "success", "access_token": access_token, "refresh_token": refresh_token}));
        }
    }
}

#[get("/refresh")]
async fn refresh_access_token(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
) -> impl Responder {
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

    let access_token_details = match generate_jwt_token(
        user.id,
        client_uuid,
        "world:read,world:write,backup:read,backup:write,user:read".to_string(),
        30,
        settings.application.private_key.expose_secret().clone(),
        settings.application.base_url.clone(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            return HttpResponse::BadGateway()
                .json(serde_json::json!({"status": "fail", "message": format_args!("{:?}", e)}));
        }
    };

    let new_refresh_token = generate_token(64);

    match sqlx::query!(
        "INSERT INTO oauth_access_tokens (access_token,client_id,user_id,expires,scope) VALUES ($1, $2, $3, $4, $5)",
        access_token_details.token_uuid.clone(),
        client_uuid,
        user.id,
        chrono::Utc::now().naive_utc() + chrono::Duration::minutes(30),
        "world:read,world:write,backup:read,backup:write,user:read"
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
        "world:read,world:write,backup:read,backup:write,user:read"
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

#[patch("/users/update-password")]
async fn update_current_user_password(
    data: web::Form<UpdatePassword>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
) -> impl Responder {
    let UpdatePassword {
        current_password,
        new_password,
    } = data.into_inner();

    let parsed_hash = PasswordHash::new(&auth_guard.user.password_hash).unwrap();

    let is_valid = Argon2::default()
        .verify_password(current_password.as_bytes(), &parsed_hash)
        .is_ok();

    if !is_valid {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "fail", "message": "Invalid password."}));
    }

    let salt = SaltString::generate(&mut OsRng);

    let hashed_password = Argon2::default()
        .hash_password(new_password.as_bytes(), &salt)
        .expect("Error while hashing password");

    match sqlx::query!(
        "UPDATE users SET password_hash = $1 WHERE id = $2",
        hashed_password.to_string(),
        auth_guard.user.id
    )
    .execute(pool.as_ref())
    .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "Password updated successfully"
        })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "fail",
            "message": "Password updated successfully"
        })),
    }
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

#[post("/authorize")]
async fn get_authorization_token(
    authorization_info: web::Form<AcceptedAuthorization>,
    pool: web::Data<PgPool>,
    req: HttpRequest,
) -> impl Responder {
    let user = match check_for_user(&pool, req).await {
        Ok(info) => info.user,
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    let authorization_info = authorization_info.into_inner();

    let client_uuid = Uuid::parse_str(&authorization_info.client_id).unwrap();

    let client = match sqlx::query_as!(
        OAuthClient,
        "SELECT * FROM oauth_clients WHERE client_id = $1",
        client_uuid
    )
    .fetch_one(pool.as_ref())
    .await
    {
        Ok(client) => client,
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    let authorization_code = generate_token(64);

    match sqlx::query!(
        "INSERT INTO oauth_authorization_codes (code,client_id,redirect_uri,user_id,expires,scope) VALUES ($1,$2,$3,$4,$5,$6)",
        authorization_code,
        client.client_id,
        client.redirect_uri,
        user.id,
        chrono::Utc::now().naive_utc() + chrono::Duration::minutes(30),
        authorization_info.scopes
    )
    .execute(pool.as_ref())
    .await {
        Ok(_) => {},
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    }

    let redirection_response = if authorization_info.state.is_some() {
        let query = &[
            ("code", authorization_code),
            ("state", authorization_info.state.unwrap_or("".to_string())),
        ];

        format!(
            "{}?{}",
            authorization_info.redirect_uri,
            serde_urlencoded::to_string(query).unwrap()
        )
    } else {
        let query = &[("code", authorization_code)];

        format!(
            "{}?{}",
            authorization_info.redirect_uri,
            serde_urlencoded::to_string(query).unwrap()
        )
    };

    HttpResponse::Found()
        .append_header(("Location", redirection_response))
        .finish()
}

#[post("/token")]
async fn get_access_tokens(
    query: web::Either<web::Json<TradeTokenQuery>, web::Query<TradeTokenQuery>>,
    pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
    req: HttpRequest,
) -> impl Responder {
    let info = match query {
        web::Either::Left(data) => data.into_inner(),
        web::Either::Right(data) => data.into_inner(),
    };

    let mut client_id = info.client_id;
    let mut client_secret = info.client_secret;

    if client_id.is_none() {
        let auth_header = req.headers().get("Authorization");
        if let Some(auth_header) = auth_header {
            if let Ok(auth_header) = auth_header.to_str() {
                if auth_header.starts_with("Basic ") {
                    let encoded_credentials = &auth_header[6..];
                    if let Ok(decoded_credentials) =
                        general_purpose::STANDARD.decode(encoded_credentials)
                    {
                        let credentials = String::from_utf8_lossy(&decoded_credentials);
                        if let Some(separator_index) = credentials.find(':') {
                            client_id = Some(credentials[..separator_index].to_owned());
                            client_secret = Some(credentials[(separator_index + 1)..].to_owned());
                        }
                    }
                }
            }
        }
    }

    if let (Some(client_id), Some(client_secret)) = (client_id, client_secret) {
        let client_uuid = Uuid::parse_str(&client_id).unwrap();

        let client = match sqlx::query_as!(
            OAuthClient,
            "SELECT * FROM oauth_clients WHERE client_id = $1",
            client_uuid
        )
        .fetch_one(pool.as_ref())
        .await
        {
            Ok(client) => client,
            Err(_) => {
                return HttpResponse::UnprocessableEntity()
                    .json(serde_json::json!({"status": "error", "message": "Invalid client id"}));
            }
        };

        let auth_code = match sqlx::query_as!(
            OAuthAuthorizationToken,
            "SELECT * FROM oauth_authorization_codes WHERE code = $1",
            info.code
        )
        .fetch_one(pool.as_ref())
        .await
        {
            Ok(auth_code) => auth_code,
            Err(_) => {
                return HttpResponse::UnprocessableEntity().json(
                    serde_json::json!({"status": "error", "message": "Invalid authorization code"}),
                );
            }
        };

        if auth_code.client_id != client.client_id {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": "Client does not match authorization code"}));
        }

        if client_secret != client.client_secret {
            return HttpResponse::UnprocessableEntity().json(
                serde_json::json!({"status": "error", "message": "Client secret is incorrect"}),
            );
        }

        let info_url = Url::parse(&info.redirect_uri).expect("Failed to parse info.redirect_uri");
        let auth_code_url = Url::parse(&auth_code.redirect_uri.unwrap())
            .expect("Failed to parse auth_code.redirect_uri");

        if info_url.scheme() != auth_code_url.scheme()
            || info_url.host_str() != auth_code_url.host_str()
            || info_url.port() != auth_code_url.port()
        {
            return HttpResponse::UnprocessableEntity().json(
                serde_json::json!({"status": "error", "message": "Redirect URI is unverified"}),
            );
        }

        // if info.redirect_uri != auth_code.redirect_uri.unwrap() {
        //     return HttpResponse::UnprocessableEntity()
        //         .json(serde_json::json!({"status": "error", "message": "Redirect URI is unverified"}));
        // }

        let mut transaction = match pool.begin().await {
            Ok(transaction) => transaction,
            Err(e) => {
                return HttpResponse::InternalServerError().json(
                    serde_json::json!({"status": "error","message": format_args!("{:?}", e)}),
                );
            }
        };

        let access_token_details = match generate_jwt_token(
            auth_code.user_id,
            client_uuid,
            auth_code.scope.clone().unwrap(),
            30,
            settings.application.private_key.expose_secret().clone(),
            settings.application.base_url.clone(),
        ) {
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
            auth_code.user_id,
            chrono::Utc::now().naive_utc() + chrono::Duration::minutes(30),
            auth_code.scope.clone().unwrap()
        )
        .execute(&mut transaction)
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
            auth_code.user_id,
            chrono::Utc::now().naive_utc() + chrono::Duration::minutes(60),
            auth_code.scope.clone().unwrap()
        )
        .execute(&mut transaction)
        .await
        {
            Ok(_) => {}
            Err(e) => {
                return HttpResponse::UnprocessableEntity()
                    .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
            }
        }

        match sqlx::query!(
            "DELETE FROM oauth_authorization_codes WHERE code = $1",
            auth_code.code
        )
        .execute(&mut transaction)
        .await
        {
            Ok(_) => match transaction.commit().await {
                Ok(_) => {
                    let accept_header = req.headers().get("Accept");

                    let time = (chrono::Utc::now() + chrono::Duration::minutes(30)).timestamp();

                    match accept_header {
                        Some(header) => {
                            if header.to_str().unwrap() == "application/json".to_string() {
                                HttpResponse::Ok().json(serde_json::json!({
                                    "token_type": "Bearer",
                                    "access_token": access_token_details.token.unwrap(),
                                    "refresh_token": refresh_token,
                                    "expires_in": time,
                                    "scope": auth_code.scope.clone().unwrap()
                                }))
                            } else {
                                HttpResponse::Ok().json(serde_json::json!({
                                    "token_type": "Bearer",
                                    "access_token": access_token_details.token.unwrap(),
                                    "refresh_token": refresh_token,
                                    "expires_in": time,
                                    "scope": auth_code.scope.clone().unwrap()
                                }))
                            }
                        }
                        None => {
                            let params = &[
                                ("token_type", "Bearer"),
                                ("access_token", &access_token_details.token.unwrap()),
                                ("refresh_token", &refresh_token),
                                ("expires_in", &time.to_string()),
                                ("scope", &auth_code.scope.clone().unwrap()),
                            ];

                            HttpResponse::Ok().body(serde_urlencoded::to_string(params).unwrap())
                        }
                    }
                }
                Err(_) => {
                    return HttpResponse::InternalServerError()
                            .json(serde_json::json!({"status": "error","message": "Unable to grant access tokens at this time"}));
                }
            },
            Err(_) => {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"status": "error","message": "Unable to grant access tokens at this time"}));
            }
        }
    } else {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"status": "error","message": "Unable to grant access tokens at this time"}));
    }
}

#[post("/revoke")]
async fn revoke_token(
    pool: web::Data<PgPool>,
    query: web::Query<RevokeTokenQuery>,
    _auth_guard: AuthMiddleware,
    settings: web::Data<Settings>,
) -> impl Responder {
    let info = query.into_inner();

    match info.token_type_hint {
        Some(type_hint) => {
            if type_hint == "access_token".to_string() {
                let access_token_details = match verify_jwt_token(
                    &info.token,
                    settings.application.public_key.expose_secret().clone(),
                ) {
                    Ok(token_details) => token_details,
                    Err(_) => {
                        return HttpResponse::BadRequest().json(serde_json::json!({
                            "status": "error",
                            "message": "Access token is invalid."
                        }))
                    }
                };

                match sqlx::query!(
                    "DELETE FROM oauth_access_tokens WHERE access_token = $1",
                    access_token_details.token_uuid
                )
                .execute(pool.as_ref())
                .await
                {
                    Ok(result) => {
                        if result.rows_affected() == 0 {
                            return HttpResponse::NotFound().json(serde_json::json!({
                                "status": "error",
                                "message": "Access token does not exist."
                            }));
                        }
                    }
                    Err(_) => {
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "status": "error",
                            "message": "Error revoking access token, try again later."
                        }))
                    }
                }
            } else {
                match sqlx::query!(
                    "DELETE FROM oauth_refresh_tokens WHERE refresh_token = $1",
                    info.token
                )
                .execute(pool.as_ref())
                .await
                {
                    Ok(result) => {
                        if result.rows_affected() == 0 {
                            return HttpResponse::NotFound().json(serde_json::json!({
                                "status": "error",
                                "message": "Refresh token does not exist."
                            }));
                        }
                    }
                    Err(_) => {
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "status": "error",
                            "message": "Error revoking refresh token, try again later."
                        }))
                    }
                }
            }
        }
        None => {
            match sqlx::query!(
                "DELETE FROM oauth_refresh_tokens WHERE refresh_token = $1",
                info.token
            )
            .execute(pool.as_ref())
            .await
            {
                Ok(result) => {
                    if !result.rows_affected() == 0 {
                        return HttpResponse::Ok().finish();
                    }
                }
                Err(_) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "status": "error",
                        "message": "Error revoking refresh token, try again later."
                    }))
                }
            }

            let access_token_details = match verify_jwt_token(
                &info.token,
                settings.application.public_key.expose_secret().clone(),
            ) {
                Ok(token_details) => token_details,
                Err(_) => return HttpResponse::Ok().finish(),
            };

            match sqlx::query!(
                "DELETE FROM oauth_access_tokens WHERE access_token = $1",
                access_token_details.token_uuid
            )
            .execute(pool.as_ref())
            .await
            {
                Ok(result) => {
                    if !result.rows_affected() == 0 {
                        return HttpResponse::Ok().finish();
                    }
                }
                Err(_) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "status": "error",
                        "message": "Error revoking access token, try again later."
                    }))
                }
            }
        }
    }

    HttpResponse::Ok().finish()
}

#[post("/authorize/create-client")]
async fn create_client_authorization_token(
    authorization_info: web::Form<AcceptedCreateClientAuthorization>,
    pool: web::Data<PgPool>,
    req: HttpRequest,
) -> impl Responder {
    let user = match check_for_user(&pool, req).await {
        Ok(info) => info.user,
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    let info = authorization_info.into_inner();

    let client_uuid = Uuid::new_v4();

    let client = match sqlx::query_as!(
        OAuthClient,
        "INSERT INTO oauth_clients (client_id,client_secret,name,redirect_uri,grant_types,scope,user_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        client_uuid,
        generate_token(64),
        info.client_name.clone(),
        info.redirect_uri.clone(),
        info.grant_types.clone(),
        info.scopes.clone(),
        user.id
    )
    .fetch_one(pool.as_ref())
    .await
    {
        Ok(client) => client,
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    let authorization_code = generate_token(64);

    match sqlx::query!(
        "INSERT INTO oauth_authorization_codes (code,client_id,redirect_uri,user_id,expires,scope) VALUES ($1,$2,$3,$4,$5,$6)",
        authorization_code,
        client.client_id,
        client.redirect_uri,
        user.id,
        chrono::Utc::now().naive_utc() + chrono::Duration::minutes(30),
        info.scopes
    )
    .execute(pool.as_ref())
    .await {
        Ok(_) => {},
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    }

    let query = &[
        ("code", authorization_code),
        ("client_id", client.client_id.to_string()),
        ("client_secret", client.client_secret),
        ("state", info.state.unwrap_or("".to_string())),
    ];

    let redirection_response = format!(
        "{}?{}",
        client.redirect_uri.unwrap(),
        serde_urlencoded::to_string(query).unwrap()
    );

    HttpResponse::Found()
        .append_header(("Location", redirection_response))
        .finish()
}

#[get("/handshake")]
pub async fn init_handshake(
    settings: web::Data<Settings>,
    scopes: web::Data<Scopes>,
) -> impl Responder {
    let scope_keys = scopes.data.clone();

    HttpResponse::Ok()
        .json(serde_json::json!({
            "authorization_endpoint": format!("{}/auth/authorize", settings.application.base_url),
            "token_endpoint": format!("{}/auth/token", settings.application.base_url),
            "client_creation_endpoint": format!("{}/auth/authorize/create-client", settings.application.base_url),
            "scopes_supported": scope_keys,
            "grant_types_supported": ["authorization_code", "client_credentials"],
            "response_types_supported": ["code", "token"],
            "access_token_lifetime": settings.application.access_token_lifetime,
            "refresh_token_lifetime": settings.application.refresh_token_lifetime
        }))
}

#[post("/create_api_key")]
pub async fn create_api_key(
    data: web::Either<web::Json<CreateApiKey>, web::Form<CreateApiKey>>,
    pool: web::Data<PgPool>,
    auth_guard: AuthMiddleware,
    scopes: web::Data<Scopes>,
) -> impl Responder {
    let api_data: CreateApiKey = match data {
        web::Either::Left(data) => data.into_inner(),
        web::Either::Right(data) => data.into_inner(),
    };

    let key_secret = generate_token(64);

    let salt = SaltString::generate(&mut OsRng);
    let key_secret_hash = Argon2::default()
        .hash_password(key_secret.as_bytes(), &salt)
        .expect("Error while hashing password");

    let new_key = match sqlx::query_as!(
        ApiKey,
        "INSERT INTO api_keys (key_id,name,key_secret_hash,scope,expires,user_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
        Uuid::new_v4(),
        api_data.name,
        key_secret_hash.to_string(),
        scopes.vec_as_str(api_data.scopes),
        chrono::Utc::now().naive_utc() + chrono::Duration::days(30),
        Some(auth_guard.user.id)
    ).fetch_one(pool.as_ref())
    .await
    {
        Ok(api_key) => api_key,
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    };

    let api_key = format!(
        "cv_{}",
        general_purpose::STANDARD.encode([new_key.key_id.to_string(), key_secret].join(" "))
    );

    HttpResponse::Ok().json(serde_json::json!({
        "status": "sucess",
        "data": {
            "api_key": api_key,
            "epxires": new_key.expires,
            "scopes": new_key.scope
        }
    }))
}
