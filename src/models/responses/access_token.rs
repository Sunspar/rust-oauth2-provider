use rocket::Request;
use rocket::http::Status;
use rocket::response::{Responder, Response};
use rocket::response::Result as RocketResult;
use serde_json;
use std::io::Cursor;

// See: https://tools.ietf.org/html/rfc6749#section-5.1
#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct AccessTokenResponse {
    pub token_type: String,
    pub expires_in: i64,
    pub access_token: String,
    pub scope: String,
    pub refresh_token: Option<String>,
    pub refresh_expires_in: Option<i64>,
}

impl<'r> Responder<'r> for AccessTokenResponse {
    fn respond_to(self, _req: &Request) -> RocketResult<'r> {
        Response::build()
            .raw_header("Content-Type", "application/json")
            .raw_header("Cache-Control", "no-cache, no-store")
            .raw_header("Pragma", "no-cache")
            .status(Status::Ok)
            .sized_body(Cursor::new(serde_json::to_string(&self).unwrap()))
            .ok()
    }
}
