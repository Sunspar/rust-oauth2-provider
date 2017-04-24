pub mod token;

use base64;
use chrono::Duration;
use chrono::offset::utc::UTC;
use diesel;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use rand::Rng;
use rand::os::OsRng;
use std::env;
use std::ops::Add;
use persistence::*;
use models::db::*;
use models::responses::*;

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


/// Generates an AccessToken.
///
/// Returns: AccessToken --- the AccessToken to send back to the caller
pub fn generate_token(conn: &PgConnection, c: &Client, g: &GrantType, scope: &str) -> AccessToken {
  let token_length = env::var("ACCESS_TOKEN_LENGTH").unwrap().parse::<u64>().unwrap();
  let expiry = UTC::now().add(Duration::weeks(1));
  let new_access_token = NewAccessTokenBuilder::default()
    .client_id(c.id)
    .grant_id(g.id)
    .token(generate_token_string(token_length))
    .scope(scope.clone())
    .refresh_token(None)
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
  AccessTokenResponseBuilder::default()
    .token_type("Bearer")
    .expires_in(at.expires_at.signed_duration_since(UTC::now()).num_seconds())
    .access_token(at.token)
    .scope(at.scope)
    .build()
    .unwrap()
}

/// Generates a "random" 
///
/// Returns:
///   A 32-character &str of base64 characters.
pub fn generate_token_string(length: u64) -> String {
  let mapping_table = vec![
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 
    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '-', '_' 
  ];

  let mut rng = OsRng::new().unwrap();
  let mut token = String::with_capacity(length as usize);

  for idx in 0..length {
    // gen_range(x,y) fetches values from [x,y), so by using 64 we have access to [0,63].
    token.push(mapping_table[rng.gen_range(0 as usize, length as usize)]);
  }
  token
}




