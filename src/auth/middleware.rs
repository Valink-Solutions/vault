use core::fmt;
use std::future::{ready, Ready};

use actix_web::error::{ErrorInternalServerError, ErrorUnauthorized};
use actix_web::{dev::Payload, Error as ActixWebError};
use actix_web::{web, FromRequest, HttpRequest};
use futures::executor::block_on;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::database::models::User;

use super::token;

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
    pub access_token_uuid: uuid::Uuid,
}

impl FromRequest for AuthMiddleware {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let pool: web::Data<PgPool> = req.app_data::<web::Data<PgPool>>().unwrap().clone();

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

        let access_token_details = match token::verify_jwt_token(&access_token) {
            Ok(token_details) => token_details,
            Err(e) => {
                let json_error = ErrorResponse {
                    status: "fail".to_string(),
                    message: format!("{:?}", e),
                };
                return ready(Err(ErrorUnauthorized(json_error)));
            }
        };

        let access_token_uuid =
            uuid::Uuid::parse_str(&access_token_details.token_uuid.to_string()).unwrap();

        let pool_ref = pool.clone();

        let user_id_result = async move {
            let result = sqlx::query!(
                "SELECT user_id FROM sessions WHERE token_uuid = $1",
                access_token_uuid
            )
            .fetch_optional(pool_ref.as_ref())
            .await;

            match result {
                Ok(Some(row)) => Ok(row.user_id),
                Ok(None) => Err(()),
                Err(_) => Err(()),
            }
        };

        let user_exists_result = async move {
            let user_id = user_id_result.await.ok();

            let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
                .fetch_optional(pool.as_ref())
                .await;

            match query_result {
                Ok(Some(user)) => Ok(user),
                Ok(None) => {
                    let json_error = ErrorResponse {
                        status: "fail".to_string(),
                        message: "the user belonging to this token no logger exists".to_string(),
                    };
                    Err(ErrorUnauthorized(json_error))
                }
                Err(_) => {
                    let json_error = ErrorResponse {
                        status: "error".to_string(),
                        message: "Faled to check user existence".to_string(),
                    };
                    Err(ErrorInternalServerError(json_error))
                }
            }
        };

        match block_on(user_exists_result) {
            Ok(user) => ready(Ok(AuthMiddleware {
                access_token_uuid,
                user,
            })),
            Err(error) => ready(Err(error)),
        }
    }
}
