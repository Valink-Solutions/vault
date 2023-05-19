use actix_web::{get, web, Error, HttpRequest, HttpResponse};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{
    middleware::check_for_user,
    schemas::{AuthorizeCreateClientQuery, AuthorizeQuery, LoginQuery},
};

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

#[get("/authorize/create-client")]
async fn get_create_client_authorization_page(
    tmpl: web::Data<tera::Tera>,
    pool: web::Data<PgPool>,
    query: web::Query<AuthorizeCreateClientQuery>,
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
                    "/auth/authorize/create-client?{}",
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

    ctx.insert(
        "app_name",
        &info
            .client_name
            .unwrap_or("Third-Party Application".to_string()),
    );
    ctx.insert("redirect_uri", &info.redirect_uri);
    ctx.insert(
        "grant_types",
        &info
            .grant_types
            .unwrap_or("access_token,refresh_token".to_string()),
    );
    ctx.insert("state", &info.state);
    ctx.insert(
        "scopes",
        &serde_json::json!(&info
            .scope
            .split(',')
            .map(|s| s.to_string())
            .collect::<Vec<String>>()),
    );

    let rendered_html = tmpl
        .render("authorize_client.html", &ctx)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered_html))
}
