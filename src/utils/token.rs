//! The utils::authorization module holds logic surrounding validating and processing various
//! OAuth 2.0 Token retrieval requests. In particular, there should be one function designed to handle
//! a particular grant type request. Stylistically these functions are named after the grant type they
//! are processing, and conform to the following function signature, which gives them access to the 
//! underlying datastore as well as the entire request data sent by the caller.

use diesel::pg::PgConnection;
use models::requests::*;
use models::responses::*;
use utils;

/// Processes a `client_credentials` request, and returns a Result on whether or not it was successful.
///
/// Returns: Result<AccessTokenResponse, OAuth2Error>
///          - Ok(AccessTokenResponse) if the request was accepted
///          - Err(OAuth2Error) prefilled with an error message if something went wrong.
pub fn client_credentials(conn: &PgConnection, req: AccessTokenRequest, auth: AuthorizationToken) -> Result<AccessTokenResponse, OAuth2Error> {
  // Client Credentials requests uses the following fields:
  // - (R) scope: The scopes for which this token should be valid.
  if req.scope.is_none() {
    return Err(OAuth2Error::InvalidRequest);
  }
  let client = match utils::check_client_credentials(conn, auth.user, auth.pass) {
    Ok(c) => c,
    Err(_) => return Err(OAuth2Error::InvalidClient)
  };
  let grant_type = match utils::check_grant_type(conn, &req.grant_type.unwrap()) {
    Ok(g) => g,
    Err(_) => return Err(OAuth2Error::UnsupportedGrantType)
  };
  let scope = &req.scope.unwrap();
  let at = utils::generate_access_token(conn, &client, &grant_type, scope);
  let rt = utils::generate_refresh_token(conn, &client, scope);
  Ok(utils::generate_token_response(at, Some(rt)))
}

/// Processes a `refresh_token` request, and returns a Result on whether or not it was successful.
///
/// Returns: Result<AccessTokenResponse, OAuth2Error>
///          - Ok(AccessTokenResponse) if the request was accepted
///          - Err(OAuth2Error) prefilled with an error message if something went wrong.
pub fn refresh_token(conn: &PgConnection, req: AccessTokenRequest, auth: AuthorizationToken) ->  Result<AccessTokenResponse, OAuth2Error> {
  // Refresh Token requests uses the following fields:
  // - (R) grant_type: Should always be "refresh_token", but we expect that to have been previously verified for this request.
  // - (R) refresh_token: The refresh token a client was given when they initially requested an access token.
  // - (O) scope: A scope to request, if you require a REDUCED set of scopes than what was originally used to generate the first token.

	// If we arent given the required params in the payload, we can immediately respond with `invalid_request`
  if req.refresh_token.is_none() || req.scope.is_none() {
    return Err(OAuth2Error::InvalidRequest);
  }

	// Fetch the building blocks using request data. This means the client, refresh token, and scope.
	// For the client and refresh token, we should be able to get hits out of the database.
	let client = match utils::check_client_credentials(conn, auth.user, auth.pass) {
    Ok(c) => c,
    Err(_) => return Err(OAuth2Error::InvalidClient)
  };

  let refresh_token = match utils::check_refresh_token(conn, &client, req.refresh_token.clone().unwrap()) {
    Ok(record) => record,
    Err(_) => return Err(OAuth2Error::InvalidRequest)
  };

  let scope = match utils::check_scope(conn, req.scope.unwrap(), refresh_token.scope.clone()) {
    Ok(s) => s,
    Err(_) => return Err(OAuth2Error::InvalidScope)
  };

	// The request appears valid. Generate an access token and reply with it.
  let grant_type = utils::get_grant_type_by_name(conn, "refresh_token");
  let access_token = utils::generate_access_token(conn, &client, &grant_type, &scope);
  Ok(utils::generate_token_response(access_token, Some(refresh_token)))
}





