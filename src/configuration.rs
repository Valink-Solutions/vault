use secrecy::Secret;
use serde_aux::field_attributes::deserialize_number_from_string;
use std::convert::{TryFrom, TryInto};

#[derive(serde::Deserialize, Clone)]
pub struct Settings {
    pub admin: AdminSettings,
    pub application: ApplicationSettings,
    pub database: DatabaseSettings,
    pub storage: StorageSettings,
}

#[derive(serde::Deserialize, Clone)]
pub struct ApplicationSettings {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub host: String,
    pub base_url: String,
    pub private_key: String,
    pub public_key: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub access_token_lifetime: u32,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub refresh_token_lifetime: u32,
}

#[derive(serde::Deserialize, Clone)]
pub struct DatabaseSettings {
    pub url: String,
}

#[derive(serde::Deserialize, Clone)]
pub struct AdminSettings {
    pub email: String,
    pub password: Secret<String>,
    pub client_id: String,
    pub client_secret: Secret<String>,
}

#[derive(serde::Deserialize, Clone)]
pub struct StorageSettings {
    pub driver: String,
    pub path: Option<String>,
    pub region: Option<String>,
    pub bucket_name: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_key: Option<String>,
}

pub fn get_configuration() -> Result<Settings, config::ConfigError> {
    let base_path = std::env::current_dir().expect("Failed to determine the current directory");
    let configuration_directory = base_path.join("configuration");

    // Detect the running environment.
    // Default to `local` if unspecified.
    let environment: Environment = std::env::var("APP_ENVIRONMENT")
        .unwrap_or_else(|_| "local".into())
        .try_into()
        .expect("Failed to parse APP_ENVIRONMENT.");
    let environment_filename = format!("{}.yaml", environment.as_str());
    let settings = config::Config::builder()
        .add_source(config::File::from(
            configuration_directory.join("base.yaml"),
        ))
        .add_source(config::File::from(
            configuration_directory.join(environment_filename),
        ))
        // Add in settings from environment variables (with a prefix of APP and '__' as separator)
        // E.g. `APP_APPLICATION__PORT=5001 would set `Settings.application.port`
        .add_source(
            config::Environment::with_prefix("APP")
                .prefix_separator("_")
                .separator("__"),
        )
        .build()?;

    settings.try_deserialize::<Settings>()
}

/// The possible runtime environment for our application.
pub enum Environment {
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Production => "production",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "{} is not a supported environment. Use either `local` or `production`.",
                other
            )),
        }
    }
}
