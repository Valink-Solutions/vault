use actix_web::web;

pub fn versions_config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("versions"));
}
