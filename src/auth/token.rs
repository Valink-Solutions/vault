use super::schemas::{TokenClaims, TokenDetails};
use std::env;
use std::fs::File;
use std::io::Read;
use uuid::Uuid;

use rand::Rng;
use std::iter;

pub fn generate_jwt_token(
    user_id: uuid::Uuid,
    client_id: uuid::Uuid,
    scope: String,
    ttl: i64,
) -> Result<TokenDetails, jsonwebtoken::errors::Error> {
    let pem_path = env::var("PRIVATE_KEY_PATH").expect("PRIVATE_KEY_PATH not set");

    let now = chrono::Utc::now();
    let mut token_details = TokenDetails {
        user_id,
        token_uuid: Uuid::new_v4(),
        expires_in: Some((now + chrono::Duration::minutes(ttl)).timestamp()),
        scope: scope.clone(),
        token: None,
    };

    let claims = TokenClaims {
        sub: token_details.user_id.to_string(),
        token_uuid: token_details.token_uuid.to_string(),
        iss: env::var("APP_DOMAIN").expect("APP_DOMAIN is not set"),
        aud: env::var("APP_DOMAIN").expect("APP_DOMAIN is not set"),
        exp: token_details.expires_in.unwrap(),
        iat: now.timestamp(),
        scope: scope,
        client_id: client_id.to_string(),
    };

    let mut pem_file = File::open(pem_path).expect("Unable to open .pem file");
    let mut pem_data = Vec::new();
    pem_file
        .read_to_end(&mut pem_data)
        .expect("Unable to read .pem file");

    // let pem: Pem = parse(pem_data).expect("Unable to parse .pem file");

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(&pem_data)?,
    )?;
    token_details.token = Some(token);
    Ok(token_details)
}

pub fn verify_jwt_token(token: &str) -> Result<TokenDetails, jsonwebtoken::errors::Error> {
    let pem_path = env::var("PUBLIC_KEY_PATH").expect("PUBLIC_KEY_PATH not set");

    let mut pem_file = File::open(pem_path).expect("Unable to open .pem file");
    let mut pem_data = Vec::new();
    pem_file
        .read_to_end(&mut pem_data)
        .expect("Unable to read .pem file");

    // let pem = pem::parse(pem_data).expect("Unable to parse .pem file");

    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);

    let decoded = jsonwebtoken::decode::<TokenClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_rsa_pem(&pem_data)?,
        &validation,
    )?;

    let user_id = Uuid::parse_str(decoded.claims.sub.as_str()).unwrap();
    let token_uuid = Uuid::parse_str(decoded.claims.token_uuid.as_str()).unwrap();

    Ok(TokenDetails {
        token: None,
        token_uuid,
        user_id,
        scope: decoded.claims.scope,
        expires_in: None,
    })
}

pub fn generate_token(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let token: String = iter::repeat_with(|| rng.gen_range(0..256))
        .map(|b| format!("{:02x}", b))
        .take(length / 2)
        .collect();
    token
}
