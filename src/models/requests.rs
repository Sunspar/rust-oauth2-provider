#[derive(Builder, Clone, Debug, Deserialize, FromForm, Serialize)]
pub struct AccessTokenRequest {
  pub grant_type: Option<String>,
  pub scope: Option<String>,
  pub refresh_token: Option<String>,
  pub code: Option<String>
}

#[derive(Builder, Clone, Debug, Deserialize, FromForm)]
pub struct IntrospectionRequest {
  pub token: String,
  pub token_type_hint: Option<String>
}
