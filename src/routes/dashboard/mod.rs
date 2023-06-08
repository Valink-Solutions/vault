use actix_web::web;

use self::ui::get_dashboard;

pub mod ui;

pub fn dashboard_config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("dashboard").service(get_dashboard));
}
