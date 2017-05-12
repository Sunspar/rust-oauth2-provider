use chrono::offset::utc::UTC;
use diesel::prelude::*;
use iron::prelude::*;
use iron::status;
use serde_json;
use uuid::Uuid;

use models::db::*;
use models::responses::*;
use persistence::*;
use utils;
use web;

pub fn authorize(_req: &mut Request) -> IronResult<Response> {
  trace!("Entering the authorize handler.");
  Ok(Response::with((status::Ok, "Not yet implemented.")))
}

/// Handler for the POST /oauth/token request.
pub fn token(req: &mut Request) -> IronResult<Response> {
  trace!("Entering the token handler.");
  let ref conn = *DB_POOL.get().unwrap();
  trace!("Successfully grabbed connection from the database connection pool.");
  let request = match web::utils::extract_access_token_request(req) {
    Ok(r) => r,
    Err(why) => {
      let response = why.to_response();
      return Ok(Response::with((response.0, serde_json::to_string(&response.1).unwrap())))
    }
  };
  trace!("request: {:?}", request);
  let auth = match web::utils::extract_auth_credentials(req) {
    Some(at) => at,
    None => {
      let response = OAuth2Error::InvalidClient.to_response();
      warn!("{}", response.0);
      return Ok(Response::with((response.0, serde_json::to_string(&response.1).unwrap())))
    }
  };
  trace!("token() auth: {:?}", auth);
  let result = match request.grant_type.clone() {
    None => Err(OAuth2Error::UnsupportedGrantType),
    Some(gt) => {
      match gt.as_str() {
        "client_credentials" => utils::token::client_credentials(conn, request, auth.clone()),
        "refresh_token"      => utils::token::refresh_token(conn, request, auth.clone()),
        _                    => Err(OAuth2Error::UnsupportedGrantType)
      }
    }
  };
  match result {
    Ok(r) => {
      info!("Client [{}] generated new access token.", auth.user);
      Ok(Response::with((status::Ok, serde_json::to_string(&r).unwrap())))
    },
    Err(r) => {
      debug!("Error during token generation: {:?}", r.to_response());
      info!("Client [{}] failed to generate new access token.", auth.user);
      let response = r.to_response();
      Ok(Response::with((response.0, serde_json::to_string(&response.1).unwrap())))
    }
  }
}

/// Handler for the POST /oauth/introspect request.
pub fn introspect(req: &mut Request) -> IronResult<Response> {
  trace!("Entering the introspection handler.");
  let ref conn = *DB_POOL.get().unwrap();
  trace!("Received database connection from the database connection pool.");
  let auth = match web::utils::extract_auth_credentials(req) {
    Some(at) => at,
    None => {
      let response = OAuth2Error::InvalidClient.to_response();
      return Ok(Response::with((response.0, serde_json::to_string(&response.1).unwrap())))
    }
  };
  trace!("auth: {:?}", auth);
  let request = match web::utils::extract_introspection_request(req) {
    Ok(r) => r,
    Err(_) => {
      debug!("client mismatch during introspection.");
      return Ok(Response::with((status::Ok, serde_json::to_string(&utils::introspection_error()).unwrap())))
    }
  };
  trace!("request: {:?}", request);
  // Ensure client is valid at all
  let client = match utils::check_client_credentials(conn, &auth.user, &auth.pass) {
    Ok(c) => c,
    Err(_) => return Ok(Response::with((status::Ok, serde_json::to_string(&utils::introspection_error()).unwrap())))
  };
  trace!("client: {:?}", client);
  // Tokens are always UUIDs
  // No token  -->  not active
  let token_as_uuid = match Uuid::parse_str(&request.token) {
    Ok(i) => i,
    Err(_) =>return Ok(Response::with((status::Ok, serde_json::to_string(&utils::introspection_error()).unwrap())))
  };
  trace!("token uuid: {:?}", token_as_uuid.to_string());
  let opt_access_token: QueryResult<AccessToken> = access_tokens::table
    .filter(access_tokens::token.eq(token_as_uuid))
    .first(conn);
  let access_token = match opt_access_token {
    Ok(at) => {
      debug!("access token successfully generated.");
      at
    },
    Err(why) => {
      debug!("no token generated: {:?}", why);
      return Ok(Response::with((status::Ok, serde_json::to_string(&utils::introspection_error()).unwrap())))
    }
  };
  // Make sure the authenticated client owns this token
  if client.id != access_token.client_id {
    debug!("Client ID mismatch.");
    return Ok(Response::with((status::Ok, serde_json::to_string(&utils::introspection_error()).unwrap())))
  }
  // expires_at <= Now  -->  not active
  if access_token.expires_at.signed_duration_since(UTC::now()).num_seconds() <= 0 {
    debug!("Token is expired.");
    return Ok(Response::with((status::Ok, serde_json::to_string(&utils::introspection_error()).unwrap())))
  }
  // That means that for our current implementation, the token itself is valid.
  let response = IntrospectionOkResponseBuilder::default()
    .active(true)
    .scope(Some(access_token.scope))
    .client_id(Some(client.identifier))
    .exp(Some(access_token.expires_at.timestamp()))
    .iat(Some(access_token.issued_at.timestamp()))
    .build()
    .unwrap();
  debug!("Token is valid: {:?}", response);
  info!("Client [{}] introspected on token [{}]", response.client_id.clone().unwrap(), request.token);
  Ok(Response::with((status::Ok, serde_json::to_string(&response).unwrap())))
}
