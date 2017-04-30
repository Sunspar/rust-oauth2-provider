use chrono::offset::utc::UTC;
use diesel::prelude::*;
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
pub fn unauthorized_request() -> JSON<OAuth2Error> {
	JSON(utils::oauth_error("invalid_request"))
}

#[get("/authorize")]
pub fn authorize() -> String {
  "Not implemented yet. :(".to_string()
}

#[post("/token", data = "<form>")]
pub fn token_request(form: Form<AccessTokenRequest>, auth: AuthorizationToken) -> Result<JSON<AccessTokenResponse>, JSON<OAuth2Error>> {
	let request = form.into_inner();
  let ref conn = *DB_POOL.get().unwrap();

  let result = match request.grant_type.clone() {
    Some(gt) => {
      match gt.as_str() {
        "client_credentials" => utils::token::client_credentials(conn, request, auth),
        "refresh_token"      => utils::token::refresh_token(conn, request, auth),
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

#[post("/introspect", data = "<form>")]
pub fn token_introspection(form: Form<IntrospectionRequest>, auth: AuthorizationToken) -> Result<JSON<IntrospectionOkResponse>, JSON<IntrospectionErrResponse>> {
  let request = form.into_inner();
	let conn = &*DB_POOL.get().unwrap();

	// Ensure client is valid at all
	let client = match utils::check_client_credentials(conn, auth.user, auth.pass) {
    Ok(c) => c,
    Err(_) => return Err(JSON(utils::introspection_error()))
  };

	// Tokens are always UUIDs
	// No token  -->  not active
  let token_as_uuid = match Uuid::parse_str(&request.token) {
    Ok(i) => i,
    Err(_) => return Err(JSON(utils::introspection_error()))
  };
  let opt_access_token: QueryResult<AccessToken> = access_tokens::table
    .filter(access_tokens::token.eq(token_as_uuid))
    .first(conn);
  let access_token = match opt_access_token {
		Ok(at) => at,
		Err(_) => return Err(JSON(utils::introspection_error()))
	};

	// Make sure the authenticated client owns this token
	if client.id != access_token.client_id {
		return Err(JSON(utils::introspection_error()))
	}

  // expires_at <= Now  -->  not active
  if access_token.expires_at.signed_duration_since(UTC::now()).num_seconds() <= 0 {
    return Err(JSON(utils::introspection_error()))
  }


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