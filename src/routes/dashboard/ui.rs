use actix_web::{get, web, Error, HttpRequest, HttpResponse};
use sqlx::PgPool;

use crate::{
    auth::{middleware::check_for_user, utils::filter_user_record},
    database::models::World,
};

#[get("")]
async fn get_dashboard(
    tmpl: web::Data<tera::Tera>,
    pool: web::Data<PgPool>,
    req: HttpRequest,
) -> Result<HttpResponse, Error> {
    let mut ctx = tera::Context::new();

    let user_info = match check_for_user(&pool, req).await {
        Ok(user_info) => user_info,
        Err(_) => {
            let params = &[("redirect_uri", "/dashboard")];

            let redirect_uri = format!(
                "/auth/login?{}",
                serde_urlencoded::to_string(params).unwrap()
            );

            return Ok(HttpResponse::SeeOther()
                .append_header(("Location", redirect_uri))
                .finish());
        }
    };

    let limit = 100;
    let offset = 0;

    let world_result: Result<Vec<World>, sqlx::Error> = sqlx::query_as!(
        World,
        r#"
        SELECT *
        FROM worlds
        WHERE user_id = $1
        LIMIT $2
        OFFSET $3
    "#,
        user_info.user.id,
        limit,
        offset
    )
    .fetch_all(pool.as_ref())
    .await;

    ctx.insert(
        "user",
        &serde_json::json!(filter_user_record(&user_info.user)),
    );

    match world_result {
        Ok(worlds) => {
            ctx.insert("worlds", &serde_json::json!(worlds));
        }
        Err(_) => {}
    }

    let rendered_html = tmpl
        .render("dashboard.html", &ctx)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Template error"))?;

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(rendered_html))
}
