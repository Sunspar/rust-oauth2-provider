pub mod token;

use bcrypt;
use chrono::Duration;
use chrono::offset::Utc;
use diesel;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use std::ops::Add;
use uuid::Uuid;

use crate::SETTINGS;
use crate::models::responses::introspection_err::{IntrospectionErrResponse, IntrospectionErrResponseBuilder};
use crate::models::responses::oauth2_error::OAuth2ErrorResponse;
use crate::models::responses::access_token::{AccessTokenResponse, AccessTokenResponseBuilder};
use crate::models::db::*;
use crate::persistence::*;

/// Generates an IntrospectionErrResponse struct.
///
/// Returns: IntrospectionErrResponse --- A standard error response struct when
/// introspection determines that the
/// associated AccessToken is not valid.
pub fn introspection_error() -> IntrospectionErrResponse {
    IntrospectionErrResponseBuilder::default()
        .active(false)
        .build()
        .unwrap()
}

/// Validates the client credentials passed in.
///
/// Returns: Result<Client, OAuth2Error>
/// - Ok(Client)       --- The client credentials are valid, and map to the
/// resulting Client object. - Err(OAuth2Error) --- The Error value
pub fn check_client_credentials<'a>(
    conn: &PgConnection,
    client_id: &'a str,
    client_secret: &'a str,
) -> Result<Client, OAuth2ErrorResponse> {
    trace!("Checking client credentials...");

    let opt_client: QueryResult<Client> = clients::table
        .filter(clients::identifier.eq(client_id))
        .first(conn);

    trace!("Client result: {:?}", &opt_client);

    let unverified_client = opt_client.map_err(|_| OAuth2ErrorResponse::InvalidClient)?;

    // Check the hashed client_secret against the user provided secret + the
    // clients marked salt
    let result_verified_client = bcrypt::verify(&client_secret, &unverified_client.secret);
    trace!(
        "Attempted to verify client. Underlying result is: {:?}",
        &result_verified_client
    );
    result_verified_client.map_err(|_| OAuth2ErrorResponse::InvalidClient)?;

    Ok(unverified_client)
}

/// Validates the Grant Type passed in.
///
/// Returns: Result<GrantType, OAuth2Error>
/// - Ok(GrantType)    --- the grant type is valid, and supported.
/// - Err(OAuth2Error) --- The Error value
fn check_grant_type<'r>(
    conn: &PgConnection,
    grant_type: &'r str,
) -> Result<GrantType, OAuth2ErrorResponse> {
    let opt: QueryResult<GrantType> = grant_types::table
        .filter(grant_types::name.eq(grant_type))
        .first(conn);

    opt.map_err(|_| OAuth2ErrorResponse::InvalidGrant)
}

/// Validates a Refresh Token, ensuring the client owns the token.
///
/// Returns: Result<RefreshToken, OAuth2Error>
/// - Ok(RefreshToken) --- the token itself, if valid
/// - Err(OAuth2Error) --- The Error value
fn check_refresh_token<'a>(
    conn: &PgConnection,
    client: &Client,
    token: &'a str,
) -> Result<RefreshToken, OAuth2ErrorResponse> {
    let refresh_token = Uuid::parse_str(&token).map_err(|_| OAuth2ErrorResponse::InvalidRequest)?;

    let token = refresh_tokens::table
        .filter(refresh_tokens::token.eq(refresh_token))
        .filter(refresh_tokens::client_id.eq(client.id))
        .order(refresh_tokens::issued_at.desc())
        .first(conn);

    token.map_err(|_| OAuth2ErrorResponse::InvalidRequest)
}

/// Validates a Scope list.
///
/// Returns: Result<String, OAuth2Error>
/// - Ok(String)       --- The valid subset of scopes (i.e the scopes that
/// appear in both the original request, and the
/// existing token) - Err(OAuth2Error) --- The Error value
fn check_scope<'a>(
    _conn: &PgConnection,
    req: &'a str,
    prev: &'a str,
) -> Result<String, OAuth2ErrorResponse> {
    let old_scopes: Vec<&str> = prev.split(' ').collect();
    let request_scopes: Vec<&str> = req.split(' ').collect();

    for s in &request_scopes {
        if !old_scopes.contains(&s) {
            return Err(OAuth2ErrorResponse::InvalidScope);
        }
    }

    Ok(request_scopes.join(" "))
}

/// Generates an AccessToken.
///
/// Returns: AccessToken --- the AccessToken to send back to the caller
pub fn generate_access_token(
    conn: &PgConnection,
    c: &Client,
    g: &GrantType,
    scope: &str,
) -> AccessToken {
    let token_ttl = SETTINGS.oauth.access_token_ttl;
    let expiry = Utc::now().naive_utc().add(Duration::seconds(token_ttl));

    let new_token = NewAccessTokenBuilder::default()
        .client_id(c.id)
        .grant_id(g.id)
        .scope(scope.clone())
        .issued_at(Utc::now().naive_utc())
        .expires_at(expiry)
        .build()
        .unwrap(); // TODO: remove unwrap

    let res = diesel::insert_into(access_tokens::table)
        .values(&new_token)
        .get_result::<AccessToken>(conn);

    res.unwrap() // TODO: remove unwrap
}

/// Generates a Refresh Token.
///
/// Returns: RefreshToken --- A refresh Token for the given client, allowing
/// callers to generate a new access token using the
/// stored scope.
pub fn generate_refresh_token(conn: &PgConnection, c: &Client, s: &str) -> RefreshToken {
    let token_ttl = SETTINGS.oauth.refresh_token_ttl;
    let expiry = match token_ttl {
        -1 => None,
        val => Some(Utc::now().naive_utc().add(Duration::seconds(val))),
    };

    let new_token = NewRefreshTokenBuilder::default()
        .client_id(c.id)
        .scope(s.clone())
        .issued_at(Utc::now().naive_utc())
        .expires_at(expiry)
        .build()
        .unwrap(); // TODO: remove unwrap

    diesel::insert_into(refresh_tokens::table)
        .values(&new_token)
        .get_result::<RefreshToken>(conn)
        .unwrap() // TODO: remove unwrap
}

/// Generates an AccessTokenResponse.
///
/// Returns: AccessTokenResponse --- the access token response object that
/// should be sent to the caller.
pub fn generate_token_response(at: AccessToken, rt: Option<RefreshToken>) -> AccessTokenResponse {
    let access_token = at.token.to_hyphenated().to_string();
    let mut builder = AccessTokenResponseBuilder::default();

    builder
        .token_type("Bearer")
        .expires_in(
            at.expires_at
                .signed_duration_since(Utc::now().naive_utc())
                .num_seconds(),
        )
        .access_token(access_token)
        .scope(at.scope);

    match rt {
        Some(refresh_token) => {
            builder.refresh_token(refresh_token.token.to_hyphenated().to_string());
            match refresh_token.expires_at {
                Some(expiry) => builder.refresh_expires_in(Some(
                    expiry
                        .signed_duration_since(Utc::now().naive_utc())
                        .num_seconds(),
                )),
                None => builder.refresh_expires_in(None),
            }
        }
        None => builder.refresh_token(None).refresh_expires_in(None),
    };

    builder.build().unwrap() // TODO: remove unwrap
}

pub fn get_grant_type_by_name(conn: &PgConnection, name: &str) -> GrantType {
    grant_types::table
        .filter(grant_types::name.eq(name))
        .first(conn)
        .unwrap() // TODO: remove unwrap
}
