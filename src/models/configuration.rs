#[derive(Deserialize)]
pub struct AppSettings {
    pub logging: LoggingSettings,
    pub db: DatabaseSettings,
    pub oauth: OauthSettings,
}

#[derive(Debug, Deserialize)]
pub struct LoggingSettings {
    pub time_format: String,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseSettings {
    pub host: String,
    pub port: u32,
    pub user: String,
    pub pass: String,
    pub db_name: String,
    pub pool_size: u32
}

#[derive(Debug, Deserialize)]
pub struct OauthSettings {
    pub access_token_ttl: i64,
    pub refresh_token_ttl: i64,
}