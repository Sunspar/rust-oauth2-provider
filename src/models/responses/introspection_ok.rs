use rocket::Request;
use rocket::http::{ContentType, Status};
use rocket::http::hyper::header::{CacheControl, CacheDirective, Pragma};
use rocket::response::{Responder, Response};
use rocket::response::Result as RocketResult;
use serde_json;
use std::io::Cursor;

#[derive(Builder, Debug, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct IntrospectionOkResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
}

impl<'r> Responder<'r> for IntrospectionOkResponse {
    fn respond_to(self, _req: &Request) -> RocketResult<'r> {
        Response::build()
            .header(ContentType::JSON)
            .header(CacheControl(vec![
                CacheDirective::NoCache,
                CacheDirective::NoStore,
            ]))
            .header(Pragma::NoCache)
            .status(Status::Ok)
            .sized_body(Cursor::new(serde_json::to_string(&self).unwrap()))
            .ok()
    }
}
