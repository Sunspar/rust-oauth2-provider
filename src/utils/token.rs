//! The utils::authorization module holds logic surrounding validating and processing various
//! OAuth 2.0 Token retrieval requests. In particular, there should be one function designed to handle
//! a particular grant type request. Stylistically these functions are named after the grant type they
//! are processing, and conform to the following function signature, which gives them access to the 
//! underlying datastore as well as the entire request data sent by the caller.

use diesel::pg::PgConnection;
use models::requests::*;
use models::responses::*;
use utils;
use web::headers::AuthorizationToken;

/// Processes a `client_credentials` request, and returns a Result on whether or not it was successful.
///
/// Returns: Result<AccessTokenResponse, OAuth2Error>
///          - Ok(AccessTokenResponse) if the request was accepted
///          - Err(OAuth2Error) prefilled with an error message if something went wrong.
pub fn client_credentials(
    conn: &PgConnection,
    req: AccessTokenRequest,
    auth: AuthorizationToken)
    -> Result<AccessTokenResponse, OAuth2ErrorResponse> {
  // Requests missing a scope are pretty bogus
  if req.scope.is_none() {
    return Err(OAuth2ErrorResponse::InvalidRequest);
  }
  
  // Ensure the client information from the request is valid
  let client = match utils::check_client_credentials(conn, &auth.user, &auth.pass) {
    Ok(c) => c,
    Err(e) => return Err(e)
  };

  // Is the client a `confidential` client?
  // TODO: This works for now but we should do something better than string checks directly.
  if client.response_type != "confidential" {
    return Err(OAuth2ErrorResponse::UnauthorizedClient);
  }

  // Ensure valid grant type
  let req_grant_type = &req.grant_type.expect("Client Credentials token requests are expected to have a grant type.");
  let grant_type = match utils::check_grant_type(conn, req_grant_type) {
    Ok(g) => g,
    Err(e) => return Err(e)
  };

  let scope = &req.scope.expect("Client Credentials token requests are expected to have a scope.");
  let at = utils::generate_access_token(conn, &client, &grant_type, scope);
  let rt = utils::generate_refresh_token(conn, &client, scope);
  Ok(utils::generate_token_response(at, Some(rt)))
}

/// Processes a `refresh_token` request, and returns a Result on whether or not it was successful.
///
/// Returns: Result<AccessTokenResponse, OAuth2Error>
///          - Ok(AccessTokenResponse) if the request was accepted
///          - Err(OAuth2Error) prefilled with an error message if something went wrong.
pub fn refresh_token(
    conn: &PgConnection, 
    req: AccessTokenRequest,
    auth: AuthorizationToken) 
    ->  Result<AccessTokenResponse, OAuth2ErrorResponse> {
  // If we arent given the required params in the payload, we can immediately respond with `invalid_request`
  if req.refresh_token.is_none() || req.scope.is_none() {
    return Err(OAuth2ErrorResponse::InvalidRequest);
  }

  // Fetch the building blocks using request data. This means the client, refresh token, and scope.
  // For the client and refresh token, we should be able to get hits out of the database.
  let client = match utils::check_client_credentials(conn, &auth.user, &auth.pass) {
    Ok(c) => c,
    Err(_) => return Err(OAuth2ErrorResponse::InvalidClient)
  };

  let req_refresh_token = &req
    .refresh_token
    .expect("Refresh Token token requests are expected to have a refresh_token.")
    .clone();

  let refresh_token = match utils::check_refresh_token(conn, &client, req_refresh_token) {
    Ok(record) => record,
    Err(_) => return Err(OAuth2ErrorResponse::InvalidRequest)
  };

  let req_scope = &req.scope.expect("Refresh Token token requests are expected to have a scope.");
  let scope = match utils::check_scope(conn, req_scope, &refresh_token.scope.clone()) {
    Ok(s) => s,
    Err(_) => return Err(OAuth2ErrorResponse::InvalidScope)
  };

  // The request appears valid. Generate an access token and reply with it.
  let grant_type = utils::get_grant_type_by_name(conn, "refresh_token");
  let access_token = utils::generate_access_token(conn, &client, &grant_type, &scope);
  Ok(utils::generate_token_response(access_token, Some(refresh_token)))
}
