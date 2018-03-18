use base64;
use rocket::Outcome::{self, Failure, Success};
use rocket::Request;
use rocket::http::{Header, Status};
use rocket::request::FromRequest;
use std::convert::From;
use std::fmt;

#[derive(Builder, Clone, Deserialize)]
#[builder(setter(into))]
pub struct AuthorizationToken {
    pub user: String,
    pub pass: String,
}

impl fmt::Debug for AuthorizationToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "AuthorizationToken {{ user: {}, pass: [REDACTED] }}",
            self.user
        )
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for AuthorizationToken {
    type Error = ();

    fn from_request(req: &'a Request<'r>) -> Outcome<Self, (Status, ()), ()> {
        // TODO: clean this up
        // Check for two parts when splitting components and user/pass as may return HTTP 500 Enforce an authorization
        // header...
        let components_vec = match req.headers().get_one("Authorization") {
            Some(v) => v,
            None => return Failure((Status::Unauthorized, ())),
        };

        // That has two parts, the first of which is "Basic" ...
        let components = components_vec.split(' ').collect::<Vec<&str>>();
        let base64_value = match components[0] {
            "Basic" => components[1],
            _ => return Failure((Status::Unauthorized, ())),
        };

        // where the second part is a base 64 string...
        let decoded_value = match base64::decode(base64_value) {
            Ok(decoded) => decoded,
            Err(_) => return Failure((Status::Unauthorized, ())),
        };

        // which maps down to valid UTF8 characters, of the form XXXXXXX:YYYYYYY
        match String::from_utf8(decoded_value) {
            Ok(decoded_str) => {
                let parts = decoded_str.split(':').collect::<Vec<&str>>();
                Success(AuthorizationToken {
                    user: parts[0].to_owned(),
                    pass: parts[1].to_owned(),
                })
            }
            Err(_) => Failure((Status::Unauthorized, ())),
        }
    }
}

impl From<AuthorizationToken> for Header<'static> {
    fn from(token: AuthorizationToken) -> Header<'static> {
        println!(
            "{}",
            base64::encode(&format!("{}:{}", token.user, token.pass))
        );
        Header::new(
            "Authorization",
            format!(
                "Basic {}",
                base64::encode(&format!("{}:{}", token.user, token.pass))
            ),
        )
    }
}
