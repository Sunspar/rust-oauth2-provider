#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct AuthCodeResponse {
}

// See: https://tools.ietf.org/html/rfc6749#section-5.1
#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct AccessTokenResponse {
  pub token_type: String,
  pub expires_in: i64,
  pub access_token: String,
  pub scope: String,
  refresh_token: Option<String>
  // pub refresh_token: String,
}

// See: https://tools.ietf.org/html/rfc6749#section-5.2
#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct OAuth2Error {
  pub error: String
}

#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct IntrospectionOkResponse {
  pub active: bool,
  pub scope: Option<String>,
  pub client_id: Option<String>,
  pub exp: Option<i64>,
  pub iat: Option<i64>
}

#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct IntrospectionErrResponse {
  pub active: bool
}