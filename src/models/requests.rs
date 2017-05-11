use std::fmt;

#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
pub struct AccessTokenRequest {
  pub grant_type: Option<String>,
  pub scope: Option<String>,
  pub refresh_token: Option<String>,
  pub code: Option<String>
}

#[derive(Builder, Clone, Debug, Deserialize)]
pub struct IntrospectionRequest {
  pub token: String,
  pub token_type_hint: Option<String>
}

#[derive(Builder, Clone, Deserialize)]
#[builder(setter(into))]
pub struct AuthorizationToken {
	pub user: String,
	pub pass: String
}

impl fmt::Debug for AuthorizationToken {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "AuthorizationToken {{ user: {}, pass: [REDACTED] }}", self.user)
	}
}