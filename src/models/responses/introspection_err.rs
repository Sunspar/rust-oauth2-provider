use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::{Responder, Response, Result};
use serde_json;
use std::io::Cursor;

#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct IntrospectionErrResponse {
    pub active: bool,
}

impl<'r> Responder<'r, 'r> for IntrospectionErrResponse {
    fn respond_to(self, _req: &Request) -> Result<'r> {
        Response::build()
            .header(ContentType::JSON)
            .raw_header("Cache-Control", "max-age=0, no-cache, no-store")
            .raw_header("Pragma", "no-cache")
            .status(Status::Ok)
            .sized_body(None, Cursor::new(serde_json::to_string(&self).unwrap()))
            .ok()
    }
}
