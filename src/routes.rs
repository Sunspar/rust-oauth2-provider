use chrono::offset::utc::UTC;
use diesel::prelude::*;
use rocket::Request;
use rocket::http::hyper::header::{Authorization, Basic};
use rocket::request::Form;
use rocket_contrib::JSON;
use uuid::Uuid;

use models::db::*;
use models::requests::*;
use models::responses::*;
use persistence::*;
use utils;
use utils::rocket_extras::AuthorizationToken;


#[error(401)]
pub fn unauthorized_request(req: &Request) -> JSON<OAuth2Error> {
	JSON(utils::oauth_error("invalid_request"))
}

#[get("/authorize")]
pub fn authorize() -> String {
  "Not implemented yet. :(".to_string()
}

#[post("/token", data = "<form>")]
pub fn token_request<'r>(form: Form<AccessTokenRequest>, auth_token: AuthorizationToken) -> Result<JSON<AccessTokenResponse>, JSON<OAuth2Error>> {
	let request = form.into_inner();
  let ref conn = *DB_POOL.get().unwrap();

  let result = match request.grant_type.clone() {
    Some(gt) => {
      match gt.as_str() {
        "client_credentials" => utils::token::client_credentials(conn, request),
        "refresh_token"      => utils::token::refresh_token(conn, request),
        "authorization_code" => utils::token::authorization_code(conn, request),
        _                    => Err(utils::oauth_error("unsupported_grant_type"))
      }
    },
    None => Err(utils::oauth_error("unsupported_grant_type"))
  };

  match result {
    Ok(r) => Ok(JSON(r)),
    Err(r) => Err(JSON(r))
  }
}

#[post("/introspection", data = "<form>")]
pub fn token_introspection(form: Form<IntrospectionRequest>) -> Result<JSON<IntrospectionOkResponse>, JSON<IntrospectionErrResponse>> {
  let request = form.into_inner();
  let conn = &*DB_POOL.get().unwrap();
  let token_as_uuid = match Uuid::parse_str(&request.token) {
    Ok(i) => i,
    Err(_) => return Err(JSON(utils::introspection_error()))
  };
  let opt_access_token: QueryResult<AccessToken> = access_tokens::table
    .filter(access_tokens::token.eq(token_as_uuid))
    .first(conn);
  // No token  -->  not active
  if let Err(_) = opt_access_token {
    return Err(JSON(utils::introspection_error()))
  }
  let access_token = opt_access_token.unwrap();
  // expires_at <= Now  -->  not active
  if access_token.expires_at.signed_duration_since(UTC::now()).num_seconds() <= 0 {
    return Err(JSON(utils::introspection_error()))
  }
  // Token exists and expires in the future. We're good!
  let opt_client: QueryResult<Client> = clients::table
    .filter(clients::id.eq(access_token.client_id))
    .first(conn);
  if let Err(_) = opt_client {
    return Err(JSON(utils::introspection_error()))
  }
  let client = opt_client.unwrap();
  // That means that for our current implementation, the token itself is valid.
  return Ok(JSON(IntrospectionOkResponseBuilder::default()
    .active(true)
    .scope(Some(access_token.scope))
    .client_id(Some(client.identifier))
    .exp(Some(access_token.expires_at.timestamp()))
    .iat(Some(access_token.issued_at.timestamp()))
    .build()
    .unwrap()))
}