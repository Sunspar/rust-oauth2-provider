pub mod token;

use chrono::Duration;
use chrono::offset::utc::UTC;
use diesel;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use std::env;
use std::ops::Add;
use persistence::*;
use models::db::*;
use models::requests::*;
use models::responses::*;
use uuid::Uuid;

/// Generates an OAuth2Error struct.
///
/// Returns: OAuth2Error --- the OAuth2Error struct to serialize and send back to the caller.
pub fn oauth_error(message: &str) -> OAuth2Error {
  OAuth2ErrorBuilder::default()
    .error(message)
    .build()
    .unwrap()
}

/// Generates an IntrospectionErrResponse struct.
///
/// Returns: IntrospectionErrResponse --- A standard error response struct when introspection determines that the 
///                                       associated AccessToken is not valid.
pub fn introspection_error() -> IntrospectionErrResponse {
  IntrospectionErrResponseBuilder::default()
    .active(false)
    .build()
    .unwrap()
}

/// Validates the client credentials passed in.
///
/// Returns: Result<Client, &str>
/// - Ok(Client) --- The client credentials are valid, and map to the resulting Client object.
/// - Err(&str)  --- The error message that should get sent back to the caller as part of the OAuth2Error response.
fn check_client_credentials<'r>(conn: &PgConnection, client_id: &'r str, client_secret: &'r str) -> Result<Client, &'r str> {
  let opt_client: QueryResult<Client> = clients::table
    .filter(clients::identifier.eq(client_id))
    .filter(clients::secret.eq(client_secret))
    .first(conn);
  match opt_client {
    Ok(client) => Ok(client),
    Err(_) => Err("invalid_client")
  }
}

/// Validates the Grant Type passed in.
///
/// Returns: Result<Grant, &str>
/// - Ok(GrantType) --- the grant type is valid, and supported.
/// - Err(&str)     --- The error message that should get sent back to the caller as part of the OAuth2Error response.
fn check_grant_type<'r>(conn: &PgConnection, grant_type: &'r str) -> Result<GrantType, &'r str> {
  let opt: QueryResult<GrantType> = grant_types::table
    .filter(grant_types::name.eq(grant_type))
    .first(conn);
  match opt {
    Err(_) => Err("invalid_grant"),
    Ok(g) => Ok(g)
  }
}


fn check_refresh_token<'r>(conn: &PgConnection, rt: Option<String>) -> Result<AccessToken, &'r str> {
  if rt.is_none() {
    return Err("invalid_request")
  }
  let refresh_token = match Uuid::parse_str(&rt.unwrap()) {
    Ok(i) => i,
    Err(_) => return Err("invalid_request")
  };
  let token = access_tokens::table
    .filter(access_tokens::refresh_token.eq(refresh_token))
    .order(access_tokens::issued_at.desc())
    .first(conn);
  match token {
    Ok(at) => Ok(at),
    Err(_) => Err("invalid request")
  }
}

fn check_scope<'r>(_conn: &PgConnection, req: AccessTokenRequest, at: AccessToken) -> Result<String, String> {
  let old_scopes: Vec<&str> = at.scope.split(' ').collect();
  let request_scopes = match req.scope {
    Some(a) => a,
    None => String::new()
  };
  let request_scopes_list: Vec<&str> = request_scopes.split(' ').collect();
  for s in &request_scopes_list {
    if !old_scopes.contains(&s) {
      return Err("invalid_request".to_string())
    }
  }
  Ok(request_scopes.clone())
}

/// Generates an AccessToken.
///
/// Returns: AccessToken --- the AccessToken to send back to the caller
pub fn generate_token(conn: &PgConnection, c: &Client, g: &GrantType, scope: &str, rt: Option<String>) -> AccessToken {
  let token_length = env::var("ACCESS_TOKEN_LENGTH").unwrap().parse::<u64>().unwrap();
  let token_ttl = env::var("ACCESS_TOKEN_TTL").unwrap().parse::<i64>().unwrap();
  let expiry = UTC::now().add(Duration::seconds(token_ttl));
  let refresh_token = match rt {
    Some(val) => val,
    None => String::new()
  };
  let new_access_token = NewAccessTokenBuilder::default()
    .client_id(c.id)
    .grant_id(g.id)
    .scope(scope.clone())
    .expires_at(expiry)
    .issued_at(UTC::now())
    .refresh_expires_at(None)
    .build()
    .unwrap();
  diesel::insert(&new_access_token)
    .into(access_tokens::table)
    .get_result::<AccessToken>(conn)
    .unwrap()
}

/// Generates an AccessTokenResponse.
///
/// Returns: AccessTokenResponse --- the access token response object that should be sent to the caller.
pub fn generate_token_response(at: AccessToken) -> AccessTokenResponse {
  let access_token = at.token.hyphenated().to_string();
  let refresh_token = at.refresh_token.hyphenated().to_string();
  AccessTokenResponseBuilder::default()
    .token_type("Bearer")
    .expires_in(at.expires_at.signed_duration_since(UTC::now()).num_seconds())
    .access_token(access_token)
    .refresh_token(refresh_token)
    .scope(at.scope)
    .build()
    .unwrap()
}