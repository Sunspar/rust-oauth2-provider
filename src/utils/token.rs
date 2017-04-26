//! The utils::authorization module holds logic surrounding validating and processing various
//! OAuth 2.0 Token retrieval requests. In particular, there should be one function designed to handle
//! a particular grant type request. Stylistically these functions are named after the grant type they
//! are processing, and conform to the following function signature, which gives them access to the 
//! underlying datastore as well as the entire request data sent by the caller.
//
//! &PGConnection, AccessTokenRequest -> Result<AccessTokenResponse, OAuth2Error>

use utils;
use models::requests::*;
use models::responses::*;
use diesel::pg::PgConnection;

/// Processes an `authorization_code` request, and returns a Result on whether or not it was successful.
///
/// Returns: Result<AccessTokenResponse, OAuth2Error>
///          - Ok(AccessTokenResponse) if the request was accepted
///          - Err(OAuth2Error) prefilled with an error message if something went wrong.
pub fn authorization_code(conn: &PgConnection, req: AccessTokenRequest) ->  Result<AccessTokenResponse, OAuth2Error> {
  // Authorization Code requess use the following fields:
  // - (R) grant_type: Should always be "authorization_code", and is expected to have been previously confirmed.
  // - (R) client_id: The client identifier of a previously created Client.
  // - (R) client_secret: The client secret of a previously created Client.
  // - (R) code: The authorization code given to the client after authorization
  // - (O) redirect_uri: The redirect uri sent during the authorization stage, if one was sent.

  if req.client_id.is_none() || req.client_secret.is_none() || req.code.is_none() {
    return Err(utils::oauth_error("invalid_request"));
  }
  let client = match utils::check_client_credentials(conn, &req.client_id.unwrap(), &req.client_secret.unwrap()) {
    Ok(c) => c,
    Err(msg) => return Err(utils::oauth_error(&msg))
  };
  let grant_type = match utils::check_grant_type(conn, &req.grant_type.unwrap()) {
    Ok(g) => g,
    Err(msg) => return Err(utils::oauth_error(&msg))
  };
  
  // As this is stubbed out for now, we return the unsupported grant error message.
  Err(utils::oauth_error("unsupported_grant_type"))
}

/// Processes a `client_credentials` request, and returns a Result on whether or not it was successful.
///
/// Returns: Result<AccessTokenResponse, OAuth2Error>
///          - Ok(AccessTokenResponse) if the request was accepted
///          - Err(OAuth2Error) prefilled with an error message if something went wrong.
pub fn client_credentials(conn: &PgConnection, req: AccessTokenRequest) -> Result<AccessTokenResponse, OAuth2Error> {
  // Client Credentials requests uses the following fields:
  // - (R) client_id: The client identifier of a previously created Client.
  // - (R) client_secret: The client secret of a previously created Client.
  // - (R) scope: The scopes for which this token should be valid.
  if req.client_id.is_none() || req.client_secret.is_none() || req.scope.is_none() {
    return Err(utils::oauth_error("invalid_request"));
  }
  let client = match utils::check_client_credentials(conn, &req.client_id.unwrap(), &req.client_secret.unwrap()) {
    Ok(c) => c,
    Err(msg) => return Err(utils::oauth_error(&msg))
  };
  let grant_type = match utils::check_grant_type(conn, &req.grant_type.unwrap()) {
    Ok(g) => g,
    Err(msg) => return Err(utils::oauth_error(&msg))
  };
  let token = utils::generate_token(conn, &client, &grant_type, &req.scope.unwrap(), None);
  Ok(utils::generate_token_response(token))
}

/// Processes a `refresh_token` request, and returns a Result on whether or not it was successful.
///
/// Returns: Result<AccessTokenResponse, OAuth2Error>
///          - Ok(AccessTokenResponse) if the request was accepted
///          - Err(OAuth2Error) prefilled with an error message if something went wrong.
pub fn refresh_token(conn: &PgConnection, req: AccessTokenRequest) ->  Result<AccessTokenResponse, OAuth2Error> {
  // Refresh Token requests uses the following fields:
  // - (R) grant_type: Should always be "refresh_token", but we expect that to have been previously verified for this request.
  // - (R) refresh_token: The refresh token a client was given when they initially requested an access token.
  // - (O) scope: A scope to request, if you require a REDUCED set of scopes than what was originally used to generate the first token.

  let access_token = match utils::check_refresh_token(conn, req.refresh_token.clone()) {
    Ok(record) => record,
    Err(msg) => return Err(utils::oauth_error(&msg))
  };
  let scopes = match utils::check_scope(conn, req, access_token) {
    Ok(s) => s,
    Err(msg) => return Err(utils::oauth_error(&msg))
  };

  // TODO: Find access token by refresh_token value.
  // 2. If Some(AccessToken), take scope as sA, and request scope as sB
  //    Then each space-delimited string in sB must be in the set of space-delimited terms from sA.
  // 3. If (2) is true, generate a new access token, and return it
  //    Else return an error message.

  // As this is stubbed out for now, we return the unsupported grant error message.
  Err(utils::oauth_error("unsupported_grant_type"))
}





