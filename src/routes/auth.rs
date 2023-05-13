use std::env;

use actix_web::{
    cookie::{time, Cookie, SameSite},
    get, patch, post, web, Error, HttpRequest, HttpResponse, Responder,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    auth::{
        middleware::{check_for_user, AuthMiddleware},
        schemas::{
            AcceptedAuthorization, AuthorizeQuery, LoginQuery, RevokeTokenQuery, TradeTokenQuery,
            UpdatePassword,
        },
        token::{generate_jwt_token, generate_token, verify_jwt_token},
    },
    database::models::{
        CreateClientRequest, FilteredUser, LoginUserSchema, OAuthAuthorizationToken, OAuthClient,
        RegisterUserSchema, User,
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
    let client_id = env::var("CLIENT_ID").expect("FIRST_PARTY_CLIENT_ID is not set");

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

    let access_token_details =
        match generate_jwt_token(user.id, client_uuid, client_scope.clone(), 30) {
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
                        .path("/auth")
                        .secure(true)
                        .same_site(SameSite::Strict)
                        .max_age(time::Duration::minutes(30))
                        .finish(),
                )
                .cookie(
                    Cookie::build("refresh_token", &refresh_token)
                        // .domain(env::var("APP_DOMAIN").unwrap_or("localhost:8080".to_string()))
                        .path("/auth")
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
                        .path("/auth")
                        .secure(true)
                        .same_site(SameSite::Strict)
                        .max_age(time::Duration::minutes(30))
                        .finish()
                )
                .cookie(
                    Cookie::build("refresh_token", &refresh_token)
                        // .domain(env::var("APP_DOMAIN").unwrap_or("localhost:8080".to_string()))
                        .path("/auth")
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

#[get("/login")]
async fn get_login_page(
    tmpl: web::Data<tera::Tera>,
    query: web::Query<LoginQuery>,
) -> Result<HttpResponse, Error> {
    let mut ctx = tera::Context::new();
    match query.redirect_uri.to_owned() {
        Some(redirect_uri) => {
            let params = &[("redirect_uri", redirect_uri)];

            ctx.insert(
                "login_url",
                &format!(
                    "/auth/login?{}",
                    serde_urlencoded::to_string(params).unwrap()
                ),
            )
        }
        None => ctx.insert("login_url", "/auth/login"),
    }
    let rendered_html = tmpl
        .render("login.html", &ctx)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered_html))
}

#[get("/register")]
async fn get_register_page(tmpl: web::Data<tera::Tera>) -> Result<HttpResponse, Error> {
    let ctx = tera::Context::new();
    let rendered_html = tmpl
        .render("register.html", &ctx)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered_html))
}

#[get("/authorize")]
async fn get_authorization_page(
    tmpl: web::Data<tera::Tera>,
    pool: web::Data<PgPool>,
    query: web::Query<AuthorizeQuery>,
    req: HttpRequest,
) -> Result<HttpResponse, Error> {
    let mut ctx = tera::Context::new();

    let info = query.into_inner();

    match check_for_user(&pool, req).await {
        Ok(_) => {}
        Err(_) => {
            let params = &[(
                "redirect_uri",
                &format!(
                    "/auth/authorize?{}",
                    serde_urlencoded::to_string(&info).unwrap()
                ),
            )];

            let redirect_uri = format!(
                "/auth/login?{}",
                serde_urlencoded::to_string(params).unwrap()
            );

            ctx.insert("login_url", &redirect_uri);

            let rendered_html = tmpl
                .render("login.html", &ctx)
                .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;

            return Ok(HttpResponse::Ok()
                .content_type("text/html")
                .body(rendered_html));

            // return Ok(HttpResponse::SeeOther()
            //     .append_header(("Location", redirect_uri))
            //     .finish()
            // )
        }
    };

    let client_uuid = Uuid::parse_str(&info.client_id).unwrap();

    let client = sqlx::query!(
        "SELECT name,scope FROM oauth_clients WHERE client_id = $1",
        client_uuid
    )
    .fetch_one(pool.as_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    ctx.insert("app_name", &client.name);
    ctx.insert("client_id", &info.client_id);
    ctx.insert(
        "scopes",
        &serde_json::json!(&client
            .scope
            .unwrap_or("read,write".to_string())
            .split(',')
            .map(|s| s.to_string())
            .collect::<Vec<String>>()),
    );

    let rendered_html = tmpl
        .render("authorize.html", &ctx)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered_html))
}

#[post("/authorize")]
async fn get_authorization_token(
    authization_info: web::Form<AcceptedAuthorization>,
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

    let authization_info = authization_info.into_inner();

    let client_uuid = Uuid::parse_str(&authization_info.client_id).unwrap();

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
        authization_info.scopes
    )
    .execute(pool.as_ref())
    .await {
        Ok(_) => {},
        Err(e) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({"status": "error", "message": format_args!("{}", e)}));
        }
    }

    let query = &[("code", authorization_code)];

    let redirection_response = format!(
        "{}?{}",
        client.redirect_uri.unwrap(),
        serde_urlencoded::to_string(query).unwrap()
    );

    HttpResponse::Found()
        .append_header(("Location", redirection_response))
        .finish()
}

#[post("/token")]
async fn get_access_tokens(
    query: web::Query<TradeTokenQuery>,
    pool: web::Data<PgPool>,
) -> impl Responder {
    let info = query.into_inner();

    let client_id = Uuid::parse_str(&info.client_id).unwrap();

    let client = match sqlx::query_as!(
        OAuthClient,
        "SELECT * FROM oauth_clients WHERE client_id = $1",
        client_id
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

    if info.client_secret != client.client_secret {
        return HttpResponse::UnprocessableEntity()
            .json(serde_json::json!({"status": "error", "message": "Client secret is incorrect"}));
    }

    if info.redirect_uri != auth_code.redirect_uri.unwrap() {
        return HttpResponse::UnprocessableEntity()
            .json(serde_json::json!({"status": "error", "message": "Redirect URI is unverified"}));
    }

    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "error","message": format_args!("{:?}", e)}));
        }
    };

    let access_token_details = match generate_jwt_token(
        auth_code.user_id,
        client_id,
        auth_code.scope.clone().unwrap(),
        30,
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
        client_id,
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
        client_id,
        auth_code.user_id,
        chrono::Utc::now().naive_utc() + chrono::Duration::minutes(60),
        auth_code.scope.unwrap()
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
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "token_type": "Bearer",
                "access_token": access_token_details.token.unwrap(),
                "refresh_token": refresh_token,
                "expires": (chrono::Utc::now() + chrono::Duration::minutes(30)).timestamp()
            })),
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
}

#[post("/revoke")]
async fn revoke_token(
    pool: web::Data<PgPool>,
    query: web::Query<RevokeTokenQuery>,
    _auth_guard: AuthMiddleware,
) -> impl Responder {
    let info = query.into_inner();

    match info.token_type_hint {
        Some(type_hint) => {
            if type_hint == "access_token".to_string() {
                let access_token_details = match verify_jwt_token(&info.token) {
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

            let access_token_details = match verify_jwt_token(&info.token) {
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

pub fn auth_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("auth")
            .service(get_authorization_page)
            .service(register_user)
            .service(get_register_page)
            .service(login_user)
            .service(get_login_page)
            .service(refresh_access_token)
            .service(get_me_handler)
            .service(create_new_client)
            .service(get_authorization_token)
            .service(get_access_tokens)
            .service(revoke_token)
            .service(update_current_user_password),
    );
}
