pub mod rocket_extras;
pub mod token;

use bcrypt;
use chrono::Duration;
use chrono::offset::utc::UTC;
use diesel;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use std::env;
use std::ops::Add;
use persistence::*;
use models::db::*;
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
pub fn check_client_credentials<'r>(conn: &PgConnection, client_id: String, client_secret: String) -> Result<Client, &'r str> {
  let opt_client: QueryResult<Client> = clients::table
    .filter(clients::identifier.eq(client_id))
    .first(conn);
	let unverified_client = match opt_client {
		Ok(c) => c,
		Err(_) => return Err("invalid_client")
	};

	//println!("{:?}", bcrypt::hash("abcd1234", 8));

	// Check the hashed client_secret against the user provided secret + the clients marked salt
	if let Err(_) = bcrypt::verify(&client_secret, &unverified_client.secret) {
		return Err("invalid_client");
	}

	Ok(unverified_client)
}

/// Validates the Grant Type passed in.
///
/// Returns: Result<GrantType, &str>
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

/// Validates a Refresh Token, ensuring the client owns the token.
///
/// Returns: Result<RefreshToken, &str>
/// - Ok(RefreshToken) --- the token itself, if valid
/// - Err(&str)        --- The error message, if invalid
fn check_refresh_token<'r>(conn: &PgConnection, client: &Client, token: String) -> Result<RefreshToken, &'r str> {
  let refresh_token = match Uuid::parse_str(&token) {
    Ok(i) => i,
    Err(_) => return Err("invalid_request")
  };

  let token = refresh_tokens::table
    .filter(refresh_tokens::token.eq(refresh_token))
		.filter(refresh_tokens::client_id.eq(client.id))
    .order(refresh_tokens::issued_at.desc())
    .first(conn);

  match token {
    Ok(t) => Ok(t),
    Err(_) => Err("invalid_request")
  }
}

/// Validates a Scope list.
///
/// Returns: Result<String, String>
/// - Ok(String)  --- The valid subset of scopes (i.e the scopes that appear in both the original request, and the existing token)
/// - Err(String) --- The error message, when invalid
fn check_scope(_conn: &PgConnection, req: String, prev: String) -> Result<String, String> {
  let old_scopes: Vec<&str> = prev.split(' ').collect();
  let request_scopes: Vec<&str> = req.split(' ').collect();

  for s in &request_scopes {
    if !old_scopes.contains(&s) {
      return Err("invalid_request".to_string())
    }
  }

  Ok(request_scopes.join(" "))
}

/// Generates an AccessToken.
///
/// Returns: AccessToken --- the AccessToken to send back to the caller
pub fn generate_access_token(conn: &PgConnection, c: &Client, g: &GrantType, scope: &str) -> AccessToken {
  let token_ttl = env::var("ACCESS_TOKEN_TTL").unwrap().parse::<i64>().unwrap();
  let expiry = UTC::now().add(Duration::seconds(token_ttl));

  let new_token = NewAccessTokenBuilder::default()
    .client_id(c.id)
    .grant_id(g.id)
    .scope(scope.clone())
    .issued_at(UTC::now())
    .expires_at(expiry)
    .build()
    .unwrap();

  let res = diesel::insert(&new_token)
    .into(access_tokens::table)
    .get_result::<AccessToken>(conn);

  res.unwrap()
}

/// Generates a Refresh Token.
///
/// Returns: RefreshToken --- A refresh Token for the given client, allowing callers to generate a new
///                           access token using the stored scope.
pub fn generate_refresh_token(conn: &PgConnection, c: &Client, s: &str) -> RefreshToken {
  let token_ttl = env::var("REFRESH_TOKEN_TTL").unwrap().parse::<i64>();

  let expiry = match token_ttl {
    Ok(-1)  => None,
    Ok(val) => Some(UTC::now().add(Duration::seconds(val))),
    Err(_)  => panic!("REFRESH_TOKEN_TTL is not a parseable int.")
  };

  let new_token = NewRefreshTokenBuilder::default()
    .client_id(c.id)
    .scope(s.clone())
    .issued_at(UTC::now())
    .expires_at(expiry)
    .build()
    .unwrap();

  diesel::insert(&new_token)
    .into(refresh_tokens::table)
    .get_result::<RefreshToken>(conn)
    .unwrap()
}

/// Generates an AccessTokenResponse.
///
/// Returns: AccessTokenResponse --- the access token response object that should be sent to the caller.
pub fn generate_token_response(at: AccessToken, rt: Option<RefreshToken>) -> AccessTokenResponse {
  let access_token = at.token.hyphenated().to_string();
  let mut builder = AccessTokenResponseBuilder::default();

  builder
    .token_type("Bearer")
    .expires_in(at.expires_at.signed_duration_since(UTC::now()).num_seconds())
    .access_token(access_token)
    .scope(at.scope);

  match rt {
    Some(refresh_token) => {
      builder.refresh_token(refresh_token.token.hyphenated().to_string());
      match refresh_token.expires_at {
        Some(expiry) => builder.refresh_expires_in(Some(expiry.signed_duration_since(UTC::now()).num_seconds())),
        None => builder.refresh_expires_in(None)
      }
    },
    None => {
      builder
        .refresh_token(None)
        .refresh_expires_in(None)
    }
  };

  builder
    .build()
    .unwrap()
}

pub fn get_grant_type_by_name(conn: &PgConnection, name: &str)  -> GrantType {
  grant_types::table
    .filter(grant_types::name.eq(name))
    .first(conn)
    .unwrap()
}
