use std::convert::From;
use rocket::http::{Header, Status};
use std::fmt;
use rocket::request::FromRequest;
use rocket::Request;
use rocket::Outcome::{self, Success, Failure};
use base64;

#[derive(Builder, Clone, Deserialize)]
#[builder(setter(into))]
pub struct  AuthorizationToken {
  pub user: String,
  pub pass: String
}

impl fmt::Debug for AuthorizationToken {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "AuthorizationToken {{ user: {}, pass: [REDACTED] }}", self.user)
  }
}

impl <'a, 'r> FromRequest<'a, 'r> for AuthorizationToken {
  type Error = ();

  fn from_request(req: &'a Request<'r>) -> Outcome<Self, (Status,()), ()> {
    // TODO: Check for two parts when splitting components and user/pass as may return HTTP 500
    match req.headers().get_one("Authorization") {
      Some(v) => {
        let components: Vec<&str> = v.split(' ').collect();
        match components[0] {
          "Basic" => {
            match base64::decode(components[1]) {
              Ok(decoded) => {
                match String::from_utf8(decoded) {
                  Ok(decoded_str) => {
                    let parts: Vec<&str> = decoded_str.split(':').collect();
                    Success(AuthorizationToken {
                      user: parts[0].to_owned(),
                      pass: parts[1].to_owned()
                    })
                  },
                  Err(_) => {
                    Failure((Status::Unauthorized, ()))
                  }
                }
              },
              Err(_) => {
                Failure((Status::Unauthorized, ()))
              }
            }
          },
          _ => {
            Failure((Status::Unauthorized, ()))
          }
        }
      },
      None => {
        Failure((Status::Unauthorized, ()))
      }
    }
  }
}

impl From<AuthorizationToken> for Header<'static> {
  fn from(token: AuthorizationToken) -> Header<'static> {
    println!("{}", base64::encode(&format!("{}:{}", token.user, token.pass)));
    Header::new("Authorization", format!("Basic {}", base64::encode(&format!("{}:{}", token.user, token.pass))))
  }
}