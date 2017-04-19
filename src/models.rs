use persistence::*;
use chrono::datetime::DateTime;
use chrono::offset::utc::UTC;

#[derive(Builder, Debug, Serialize, Deserialize, Identifiable, Queryable, Associations)]
#[builder(setter(into))]
#[table_name="clients"]
pub struct Client {
  pub id: i32,
  pub identifier: String,
  pub secret: String,
  pub response_type: String
}

#[derive(Builder, Debug, Serialize, Deserialize, Identifiable, Queryable, Associations)]
#[builder(setter(into))]
#[table_name="grant_types"]
pub struct GrantType {
  pub id: i32,
  pub name: String
}

#[derive(Builder, Debug, Serialize, Deserialize, Identifiable, Queryable, Associations)]
#[builder(setter(into))]
#[table_name="client_redirect_uris"]
pub struct ClientRedirectURI {
  pub id: i32,
  pub client_id: i32,
  pub redirect_uri: String
}

#[derive(Builder, Debug, Serialize, Deserialize, Identifiable, Queryable, Associations)]
#[builder(setter(into))]
#[table_name="access_tokens"]
pub struct AccessToken {
  pub id: i32,
  pub client_id: i32,
  pub grant_id: i32,
  pub token: String,
  pub scope: String,
  pub refresh_token: Option<String>,
  pub expires_at: DateTime<UTC>,
  pub issued_at: DateTime<UTC>,
  pub refresh_expires_at: Option<DateTime<UTC>>
}

#[derive(Builder, Debug, Serialize, Deserialize, Insertable)]
#[builder(setter(into))]
#[table_name="access_tokens"]
pub struct NewAccessToken {
  pub client_id: i32,
  pub grant_id: i32,
  pub token: String,
  pub scope: String,
  pub refresh_token: Option<String>,
  pub expires_at: Option<DateTime<UTC>>,
  pub issued_at: DateTime<UTC>,
  pub refresh_expires_at: Option<DateTime<UTC>>
}

#[derive(Builder, Debug, Serialize, Deserialize, Identifiable, Queryable, Associations)]
#[builder(setter(into))]
#[table_name="auth_codes"]
pub struct AuthCode {
  pub id: i32,
  pub client_id: i32,
  pub name: String,
  pub scope: String,
  pub expires_at: DateTime<UTC>,
  pub issued_at: DateTime<UTC>,
  pub redirect_uri: String,
  pub user_id: i32
}

// The structs below represent request and response objects, and are not
// directly part of the OAuth 2.0 Specification.

#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct AuthCodeResponse {
}

#[derive(FromForm, Serialize, Deserialize)]
pub struct ClientCredentialsRequest {
  pub grant_type: String,
  pub client_id: String,
  pub client_secret: String,
  pub scope: String
}

#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct AccessTokenResponse {
  pub token_type: String,
  pub expires_in: i64,
  pub access_token: String
}

#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct OAuth2Error {
  pub message: String,
  pub status: i64
}

#[derive(Builder, Debug, FromForm, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct IntrospectionRequest {
  pub token: String,
  pub token_type_hint: Option<String>
}

#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct IntrospectionResponse {
  pub active: bool,
  pub scope: Option<String>,
  pub client_id: Option<String>,
  pub exp: Option<i64>,
  pub iat: Option<i64>
}
