#[derive(FromForm, Serialize)]
pub struct AccessTokenRequest {
  pub grant_type: Option<String>,
  pub client_id: Option<String>,
  pub client_secret: Option<String>,
  pub scope: Option<String>,
  pub refresh_token: Option<String>,
  pub code: Option<String>
}

#[derive(Builder, Debug, FromForm, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct IntrospectionRequest {
  pub token: String,
  pub token_type_hint: Option<String>
}