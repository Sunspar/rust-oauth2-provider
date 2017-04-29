use rocket::Request;
use rocket::http::Status;
use rocket::http::hyper::header::{Authorization, Basic};
use rocket::Outcome::{self, Success, Forward, Failure};
use rocket::request::FromRequest;
use base64;

#[derive(Builder, Debug, FromForm)]
#[builder(setter(into))]
pub struct AuthorizationToken {
	pub token_type: String,
	pub user: String,
	pub pass: String
}

impl <'a, 'r> FromRequest<'a, 'r> for AuthorizationToken {
	type Error = ();

	fn from_request(req: &'a Request<'r>) -> Outcome<Self, (Status,()), ()> {
		let header = req.headers().get_one("Authorization");

		match header {
			None => {
				Failure((Status::Unauthorized, ()))
			},
			Some(v) => {
				let components: Vec<&str> = v.split(' ').collect();
				let token_type = components[0];
				match base64::decode(components[1]) {
					Err(why) => {
						Failure((Status::Unauthorized, ()))
					},
					Ok(decoded) => {
						match String::from_utf8(decoded) {
							Err(why) => {
								Failure((Status::Unauthorized, ()))
							},
							Ok(decoded_str) => {
								let parts: Vec<&str> = decoded_str.split(':').collect();
								Success(AuthorizationToken {
									token_type: token_type.to_owned(),
									user: parts[0].to_owned(),
									pass: parts[1].to_owned()
								})
							}
						}
					}
				}
			}
		}
	}
}