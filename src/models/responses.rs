use rocket::http::{ContentType, Status};
use rocket::response::Result as RocketResult;
use rocket::response::{Response, Responder};
use std::io::Cursor;
use serde_json;
use rocket::http::hyper::header::{CacheControl, CacheDirective, Pragma};

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

impl<'r> Responder<'r> for AccessTokenResponse {
  fn respond(self) -> RocketResult<'r> {
    Response::build()
      .raw_header("Content-Type", "application/json")
      .raw_header("Cache-Control", "no-cache, no-store")
      .raw_header("Pragma", "no-cache")
      .status(Status::Ok)
      .sized_body(Cursor::new(serde_json::to_string(&self).expect("Failed to serialize the AccessTokenResponse.")))
      .ok()
  }
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

impl<'r> Responder<'r> for IntrospectionOkResponse {
  fn respond(self) -> RocketResult<'r> {
    Response::build()
      .header(ContentType::JSON)
      .header(CacheControl(vec![CacheDirective::NoCache, CacheDirective::NoStore]))
      .header(Pragma::NoCache)
      .status(Status::Ok)
      .sized_body(Cursor::new(serde_json::to_string(&self).expect("Failed to serialize the IntrospectionOkResponse.")))
      .ok()
  }
}

#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct IntrospectionErrResponse {
  pub active: bool
}

impl<'r> Responder<'r> for IntrospectionErrResponse {
  fn respond(self) -> RocketResult<'r> {
    Response::build()
      .header(ContentType::JSON)
      .header(CacheControl(vec![CacheDirective::NoCache, CacheDirective::NoStore]))
      .header(Pragma::NoCache)
      .status(Status::Ok)
      .sized_body(Cursor::new(serde_json::to_string(&self).expect("Failed to serialize the IntrospectionErrResponse.")))
      .ok()
  }
}

#[derive(Debug)]
pub enum OAuth2ErrorResponse {
  InvalidRequest,
  InvalidClient,
  InvalidGrant,
  UnauthorizedClient,
  UnsupportedGrantType,
  InvalidScope
}

impl OAuth2ErrorResponse {
  pub fn message(&self) -> &'static str {
    match *self {
      OAuth2ErrorResponse::InvalidRequest       => "invalid_request",
      OAuth2ErrorResponse::InvalidClient        => "invalid_client",
      OAuth2ErrorResponse::InvalidGrant         => "invalid_grant",
      OAuth2ErrorResponse::UnauthorizedClient   => "unauthorized_client",
      OAuth2ErrorResponse::UnsupportedGrantType => "unsupported_grant_type",
      OAuth2ErrorResponse::InvalidScope         => "invalid_scope"
    }
  }
}

impl<'r> Responder<'r> for OAuth2ErrorResponse {
  fn respond(self) -> RocketResult<'r> {
    let mut response = Response::build();
    response
      .header(ContentType::JSON)
      .header(CacheControl(vec![CacheDirective::NoCache, CacheDirective::NoStore]))
      .header(Pragma::NoCache);

    match self {
      OAuth2ErrorResponse::InvalidClient => {
        response
          .raw_header("WWW-Authenticate", "Basic")
          .status(Status::Unauthorized);
      },
      _ => {
        response.status(Status::BadRequest);
      }
    }

    let json = json!({
      "error": self.message()
    });

    response
      .sized_body(Cursor::new(json.to_string()))
      .ok()
  }
}
