use persistence::*;
use chrono::datetime::DateTime;
use chrono::offset::utc::UTC;
use uuid::Uuid;

#[derive(Builder, Debug, Serialize, Deserialize, Identifiable, Queryable, Associations)]
#[builder(setter(into))]
#[table_name="clients"]
pub struct Client {
  pub id: i32,
  pub identifier: String,
  pub secret: String,
	pub salt: String,
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
  pub token: Uuid,
  pub client_id: i32,
  pub grant_id: i32,
  pub scope: String,
  pub issued_at: DateTime<UTC>,
  pub expires_at: DateTime<UTC>
}

#[derive(Builder, Debug, Serialize, Deserialize, Insertable)]
#[builder(setter(into))]
#[table_name="access_tokens"]
pub struct NewAccessToken {
  pub client_id: i32,
  pub grant_id: i32,
  pub scope: String,
  pub issued_at: DateTime<UTC>,
  pub expires_at: DateTime<UTC>
}

#[derive(Builder, Debug, Serialize, Deserialize, Identifiable, Queryable, Associations)]
#[builder(setter(into))]
#[table_name="refresh_tokens"]
pub struct RefreshToken {
  pub id: i32,
  pub token: Uuid,
  pub client_id: i32,
  pub scope: String,
  pub issued_at: DateTime<UTC>,
  pub expires_at: Option<DateTime<UTC>>
}

#[derive(Builder, Debug, Serialize, Deserialize, Insertable)]
#[builder(setter(into))]
#[table_name="refresh_tokens"]
pub struct NewRefreshToken {
  pub client_id: i32,
  pub scope: String,
  pub issued_at: DateTime<UTC>,
  pub expires_at: Option<DateTime<UTC>>
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

#[derive(Builder, Debug, Serialize, Deserialize, Insertable)]
#[builder(setter(into))]
#[table_name="auth_codes"]
pub struct NewAuthCode {
  pub client_id: i32,
  pub name: String,
  pub scope: String,
  pub expires_at: DateTime<UTC>,
  //pub issued_at: DateTime<UTC>,
  pub redirect_uri: String,
  pub user_id: i32
}
