use actix_web::web;

pub fn worlds_config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("worlds"));
}
