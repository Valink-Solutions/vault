use actix_web::web;

use self::{
    api::{
        create_api_key, create_client_authorization_token, create_new_client, get_access_tokens,
        get_authorization_token, get_me_handler, login_user, refresh_access_token, register_user,
        revoke_token, update_current_user_password,
    },
    ui::{
        get_authorization_page, get_create_client_authorization_page, get_login_page,
        get_register_page,
    },
};

pub mod api;
pub mod ui;

pub use self::api::init_handshake;

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
            .service(update_current_user_password)
            .service(get_create_client_authorization_page)
            .service(create_client_authorization_token)
            .service(create_api_key),
    );
}
