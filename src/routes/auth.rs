use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use sqlx::{Any, Pool};

use crate::database::models::{LoginUserSchema, RegisterUserSchema};

#[post("/register")]
async fn register_user(
    _body: web::Json<RegisterUserSchema>,
    _pool: web::Data<Pool<Any>>,
) -> impl Responder {
    HttpResponse::Ok().body("registered")
}

#[post("/login")]
async fn login_user(
    _body: web::Json<LoginUserSchema>,
    _pool: web::Data<Pool<Any>>,
) -> impl Responder {
    HttpResponse::Ok().body("logged in")
}

#[get("/refresh")]
async fn refresh_access_token(_req: HttpRequest, _pool: web::Data<Pool<Any>>) -> impl Responder {
    HttpResponse::Ok().body("token refreshed")
}

pub fn auth_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("auth")
            .service(register_user)
            .service(login_user)
            .service(refresh_access_token),
    );
}
