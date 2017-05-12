use iron::status;

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
  pub refresh_token: Option<String>,
  pub refresh_expires_in: Option<i64>
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

// See: https://tools.ietf.org/html/rfc6749#section-5.2
#[derive(Builder, Debug, Serialize)]
#[builder(setter(into))]
pub struct OAuth2ErrorResponse {
  pub error: String
}

pub enum OAuth2Error {
	InvalidRequest,
	InvalidClient,
	InvalidGrant,
	UnauthorizedClient,
	UnsupportedGrantType,
	InvalidScope
}

impl OAuth2Error {
	pub fn to_response(&self) -> (status::Status, OAuth2ErrorResponse) {
		match *self {
			OAuth2Error::InvalidRequest       => (status::BadRequest,   self.generate_struct("invalid_request")),
			OAuth2Error::InvalidClient        => (status::Unauthorized, self.generate_struct("invalid_client")),
			OAuth2Error::InvalidGrant         => (status::BadRequest,   self.generate_struct("invalid_grant")),
			OAuth2Error::UnauthorizedClient   => (status::BadRequest,   self.generate_struct("unauthorized_client")),
			OAuth2Error::UnsupportedGrantType => (status::BadRequest,   self.generate_struct("unsupported_grant_type")),
			OAuth2Error::InvalidScope         => (status::BadRequest,   self.generate_struct("invalid_scope"))
		}
	}

	fn generate_struct(&self, msg: &str) -> OAuth2ErrorResponse {
		OAuth2ErrorResponseBuilder::default()
			.error(msg)
			.build()
			.unwrap()
	}
}
