use rocket::Request;
use rocket::http::{ContentType, Status};
use rocket::http::hyper::header::{CacheControl, CacheDirective, Pragma};
use rocket::response::{Responder, Response};
use rocket::response::Result as RocketResult;
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

impl<'r> Responder<'r> for OAuth2ErrorResponse {
    fn respond_to(self, _req: &Request) -> RocketResult<'r> {
        let mut response = Response::build();
        response
            .header(ContentType::JSON)
            .header(CacheControl(vec![
                CacheDirective::NoCache,
                CacheDirective::NoStore,
            ]))
            .header(Pragma::NoCache);

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

        let json = json!({
      "error": self.message()
    });

        response.sized_body(Cursor::new(json.to_string())).ok()
    }
}
