use core::fmt;
use std::future::{ready, Ready};

use actix_web::error::{ErrorInternalServerError, ErrorUnauthorized};
use actix_web::{dev::Payload, Error as ActixWebError};
use actix_web::{web, FromRequest, HttpRequest};
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use base64::{engine::general_purpose, Engine as _};
use futures::executor::block_on;
use futures::{future::BoxFuture, FutureExt};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::configuration::Settings;
use crate::database::models::User;
use crate::scopes::Scopes;

use super::schemas::UserInfo;
use super::token::verify_jwt_token;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    status: String,
    message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthMiddleware {
    pub user: User,
    pub scope: Vec<String>,
}

impl FromRequest for AuthMiddleware {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let pool: web::Data<PgPool> = req.app_data::<web::Data<PgPool>>().unwrap().clone();
        let settings: web::Data<Settings> = req.app_data::<web::Data<Settings>>().unwrap().clone();
        let scopes: web::Data<Scopes> = req.app_data::<web::Data<Scopes>>().unwrap().clone();

        let access_token = match req.headers().get("Authorization") {
            Some(header_value) => {
                if let Ok(auth_str) = header_value.to_str() {
                    if auth_str.starts_with("Bearer ") || auth_str.starts_with("ApiKey ") {
                        auth_str[7..].to_string()
                    } else {
                        let json_error = ErrorResponse {
                            status: "fail".to_string(),
                            message: "Invalid token format".to_string(),
                        };
                        return ready(Err(ErrorUnauthorized(json_error)));
                    }
                } else {
                    let json_error = ErrorResponse {
                        status: "fail".to_string(),
                        message: "Invalid token format".to_string(),
                    };
                    return ready(Err(ErrorUnauthorized(json_error)));
                }
            }
            None => {
                let json_error = ErrorResponse {
                    status: "fail".to_string(),
                    message: "You are not logged in, please provide token".to_string(),
                };
                return ready(Err(ErrorUnauthorized(json_error)));
            }
        };

        let user_result: BoxFuture<Result<(Uuid, Option<String>), ()>> = if access_token
            .starts_with("cv_")
        {
            let decoded_vec =
                match general_purpose::STANDARD.decode(access_token.strip_prefix("cv_").unwrap()) {
                    Ok(decoded_string) => decoded_string,
                    Err(_) => {
                        let json_error = ErrorResponse {
                            status: "fail".to_string(),
                            message: "Invalid token".to_string(),
                        };
                        return ready(Err(ErrorUnauthorized(json_error)));
                    }
                };

            let decoded_key = String::from_utf8(decoded_vec).unwrap();

            let pool_ref = pool.clone();

            async move {
                let key_parts: Vec<&str> = decoded_key.splitn(2, |c| c == ' ').collect();
                let key_id = Uuid::parse_str(&key_parts[0]).unwrap();
                let key_secret = key_parts[1];

                let result = sqlx::query!(
                    "SELECT user_id, scope, key_secret_hash FROM api_keys WHERE key_id = $1",
                    key_id
                )
                .fetch_optional(pool_ref.as_ref())
                .await;

                match result {
                    Ok(Some(row)) => {
                        let parsed_hash = PasswordHash::new(&row.key_secret_hash).unwrap();

                        let is_valid = Argon2::default()
                            .verify_password(key_secret.as_bytes(), &parsed_hash)
                            .is_ok();

                        if !is_valid {
                            Err(())
                        } else {
                            Ok((row.user_id, row.scope))
                        }
                    }
                    Ok(None) => Err(()),
                    Err(_) => Err(()),
                }
            }
            .boxed()
        } else {
            let access_token_details = match verify_jwt_token(
                &access_token,
                settings.application.public_key.expose_secret().clone(),
            ) {
                Ok(token_details) => token_details,
                Err(e) => {
                    let json_error = ErrorResponse {
                        status: "fail".to_string(),
                        message: format!("{:?}", e),
                    };
                    return ready(Err(ErrorUnauthorized(json_error)));
                }
            };

            let pool_ref = pool.clone();

            async move {
                let result = sqlx::query!(
                    "SELECT user_id, scope FROM oauth_access_tokens WHERE access_token = $1",
                    access_token_details.token_uuid
                )
                .fetch_optional(pool_ref.as_ref())
                .await;

                match result {
                    Ok(Some(row)) => Ok((row.user_id, row.scope)),
                    Ok(None) => Err(()),
                    Err(_) => Err(()),
                }
            }
            .boxed()
        };

        let user_exists_result = async move {
            let (user_id, scope) = match user_result.await {
                Ok((user_id, scope)) => (user_id, scope),
                Err(_) => {
                    let json_error = ErrorResponse {
                        status: "fail".to_string(),
                        message: "Access token is invalid or expired".to_string(),
                    };

                    return Err(ErrorUnauthorized(json_error));
                }
            };

            let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
                .fetch_optional(pool.as_ref())
                .await;

            match query_result {
                Ok(Some(user)) => Ok((user, scope)),
                Ok(None) => {
                    let json_error = ErrorResponse {
                        status: "fail".to_string(),
                        message: "the user belonging to this token no longer exists".to_string(),
                    };
                    Err(ErrorUnauthorized(json_error))
                }
                Err(_) => {
                    let json_error = ErrorResponse {
                        status: "error".to_string(),
                        message: "Failed to check user existence".to_string(),
                    };
                    Err(ErrorInternalServerError(json_error))
                }
            }
        };

        match block_on(user_exists_result) {
            Ok((user, scope)) => ready(Ok(AuthMiddleware {
                user,
                scope: scopes.validated_keys_vec(
                    scope
                        .unwrap_or("".to_string())
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect(),
                ),
            })),
            Err(error) => ready(Err(error)),
        }
    }
}

pub async fn check_for_user(
    pool: &sqlx::PgPool,
    req: HttpRequest,
) -> Result<UserInfo, ActixWebError> {
    let access_token = match req.cookie("access_token") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            let json_error = ErrorResponse {
                status: "fail".to_string(),
                message: "User does not have access to this route.".to_string(),
            };

            return Err(ErrorUnauthorized(json_error));
        }
    };

    let settings: web::Data<Settings> = req.app_data::<web::Data<Settings>>().unwrap().clone();

    let access_token_details = match verify_jwt_token(
        &access_token,
        settings.application.public_key.expose_secret().clone(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            let json_error = ErrorResponse {
                status: "fail".to_string(),
                message: format!("{:?}", e),
            };

            return Err(ErrorUnauthorized(json_error));
        }
    };

    let result = match sqlx::query!(
        "SELECT user_id FROM oauth_access_tokens WHERE access_token = $1",
        access_token_details.token_uuid
    )
    .fetch_optional(pool)
    .await
    {
        Ok(row) => row.unwrap(),
        Err(_) => {
            let json_error = ErrorResponse {
                status: "fail".to_string(),
                message: "the user belonging to this token no logger exists".to_string(),
            };
            return Err(ErrorUnauthorized(json_error));
        }
    };

    let user_id = result.user_id;

    let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_optional(pool)
        .await;

    let user = match query_result {
        Ok(Some(user)) => user,
        Ok(None) => {
            let json_error = ErrorResponse {
                status: "fail".to_string(),
                message: "the user belonging to this token no logger exists".to_string(),
            };
            return Err(ErrorUnauthorized(json_error));
        }
        Err(_) => {
            let json_error = ErrorResponse {
                status: "error".to_string(),
                message: "Faled to check user existence".to_string(),
            };
            return Err(ErrorInternalServerError(json_error));
        }
    };

    Ok(UserInfo {
        user,
        scope: access_token_details
            .scope
            .to_string()
            .split(',')
            .map(|s| s.to_string())
            .collect(),
    })
}
