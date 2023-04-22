use super::schemas::{TokenClaims, TokenDetails};
use std::env;
use std::fs::File;
use std::io::Read;
use uuid::Uuid;

pub fn generate_jwt_token(
    user_id: uuid::Uuid,
    ttl: i64,
) -> Result<TokenDetails, jsonwebtoken::errors::Error> {
    let pem_path = env::var("PRIVATE_KEY_PATH").expect("PRIVATE_KEY_PATH not set");

    let now = chrono::Utc::now();
    let mut token_details = TokenDetails {
        user_id,
        token_uuid: Uuid::new_v4(),
        expires_in: Some((now + chrono::Duration::minutes(ttl)).timestamp()),
        token: None,
    };

    let claims = TokenClaims {
        sub: token_details.user_id.to_string(),
        token_uuid: token_details.token_uuid.to_string(),
        exp: token_details.expires_in.unwrap(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
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
        expires_in: None,
    })
}