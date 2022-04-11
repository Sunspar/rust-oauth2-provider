use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::{Responder, Response, Result};
use serde_json::{self, json};
use std::io::Cursor;

#[derive(Debug)]
pub enum OAuth2ErrorResponse {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
}

impl OAuth2ErrorResponse {
    pub fn message(&self) -> &'static str {
        match *self {
            OAuth2ErrorResponse::InvalidRequest => "invalid_request",
            OAuth2ErrorResponse::InvalidClient => "invalid_client",
            OAuth2ErrorResponse::InvalidGrant => "invalid_grant",
            OAuth2ErrorResponse::UnauthorizedClient => "unauthorized_client",
            OAuth2ErrorResponse::UnsupportedGrantType => "unsupported_grant_type",
            OAuth2ErrorResponse::InvalidScope => "invalid_scope",
        }
    }
}

impl<'r> Responder<'r, 'r> for OAuth2ErrorResponse {
    fn respond_to(self, _req: &Request) -> Result<'r> {
        let mut response = Response::build();
        response
            .header(ContentType::JSON)
            .raw_header("Cache-Control", "max-age=0, no-cache, no-store")
            .raw_header("Pragma", "no-cache");

        match self {
            OAuth2ErrorResponse::InvalidClient => {
                response
                    .raw_header("WWW-Authenticate", "Basic")
                    .status(Status::Unauthorized);
            }
            _ => {
                response.status(Status::BadRequest);
            }
        }

        // TODO: Use serde::Deserialize here instead of this
        let json = json!({
      "error": self.message()
    });

        response.sized_body(None, Cursor::new(json.to_string())).ok()
    }
}
