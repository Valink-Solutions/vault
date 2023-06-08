use core::fmt;
use std::future::{ready, Ready};

use actix_web::error::{ErrorInternalServerError, ErrorUnauthorized};
use actix_web::{dev::Payload, Error as ActixWebError};
use actix_web::{web, FromRequest, HttpRequest};
use futures::executor::block_on;
use futures::{future::BoxFuture, FutureExt};
use r2d2_redis::redis::Commands;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::configuration::Settings;
use crate::database::models::{OAuthAccessToken, User};
use crate::scopes::Scopes;
use crate::utilities::RedisPool;

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
        let redis_pool: web::Data<RedisPool> =
            req.app_data::<web::Data<RedisPool>>().unwrap().clone();
        let settings: web::Data<Settings> = req.app_data::<web::Data<Settings>>().unwrap().clone();
        let scopes: web::Data<Scopes> = req.app_data::<web::Data<Scopes>>().unwrap().clone();

        let access_token = match req.headers().get("Authorization") {
            Some(header_value) => {
                if let Ok(auth_str) = header_value.to_str() {
                    if auth_str.starts_with("Bearer ") {
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

        let mut conn = redis_pool.get().unwrap();

        let user_result: BoxFuture<Result<(Uuid, Option<String>), ()>> = async move {
            let result = conn.get::<_, String>(format!(
                "oauth_access_token:{}",
                access_token_details.token_uuid
            ));

            match result {
                Ok(data) => {
                    let access_obj: OAuthAccessToken = serde_json::from_str(&data).unwrap();

                    Ok((access_obj.user_id, Some(access_obj.scope)))
                }
                Err(_) => Err(()),
            }
        }
        .boxed();

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
    let redis_pool: web::Data<RedisPool> = req.app_data::<web::Data<RedisPool>>().unwrap().clone();

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

    let mut conn = redis_pool.get().unwrap();

    let result = conn.get::<_, String>(format!(
        "oauth_access_token:{}",
        access_token_details.token_uuid
    ));

    let access_obj = match result {
        Ok(data) => {
            let access_obj: OAuthAccessToken = serde_json::from_str(&data).unwrap();

            access_obj
        }
        Err(_) => {
            let json_error = ErrorResponse {
                status: "error".to_string(),
                message: "Faled to check user existence".to_string(),
            };
            return Err(ErrorInternalServerError(json_error));
        }
    };

    let user_id = access_obj.user_id;

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
        scope: access_obj.scope.split(',').map(|s| s.to_string()).collect(),
    })
}
