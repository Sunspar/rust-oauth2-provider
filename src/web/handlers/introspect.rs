use DB_POOL;
use chrono::offset::Utc;
use diesel::prelude::*;
use models::db::*;
use models::requests::introspect::IntrospectionRequest;
use models::responses::introspection_err::IntrospectionErrResponse;
use models::responses::introspection_ok::{IntrospectionOkResponse, IntrospectionOkResponseBuilder};
use persistence::*;
use rocket::request::Form;
use utils;
use uuid::Uuid;
use web::headers::authorization_token::AuthorizationToken;

#[post("/oauth/introspect", data = "<req>")]
pub fn post(
    req: Option<Form<IntrospectionRequest>>,
    auth: Option<AuthorizationToken>,
) -> Result<IntrospectionOkResponse, IntrospectionErrResponse> {
    debug!("Checking validitity of a supposed auth token.");
    let auth_token = auth.ok_or(utils::introspection_error())?;

    trace!("Introspect endpoint request: {:?}", req);
    let request = req.map(|v| v.into_inner())
        .ok_or(utils::introspection_error())?;

    trace!("Attempting to get DB connection.");
    let conn = &*DB_POOL.get().unwrap(); // TODO: remove unwrap
    trace!("DB connection successfully established.");

    trace!("authenticating client credentials: {:?}", &auth_token);
    let client = utils::check_client_credentials(&conn, &auth_token.user, &auth_token.pass)
        .map_err(|_| utils::introspection_error())?;

    // Tokens are always UUIDs
    // No token  -->  not active
    trace!("Parsing token into UUID: {:?}", &request.token);
    let token_as_uuid = Uuid::parse_str(&request.token).map_err(|_| utils::introspection_error())?;

    let opt_token: QueryResult<AccessToken> = access_tokens::table
        .filter(access_tokens::token.eq(token_as_uuid))
        .first(conn);

    trace!("Access Token from DB: {:?}", opt_token);
    let access_token = opt_token.map_err(|_| utils::introspection_error())?;

    // Make sure the authenticated client owns this token
    if client.id != access_token.client_id {
        debug!("Client ID mismatch.");
        return Err(utils::introspection_error());
    }

    // expires_at <= Now  -->  not active
    if access_token
        .expires_at
        .signed_duration_since(Utc::now().naive_utc())
        .num_seconds() <= 0
    {
        debug!("Token is expired.");
        return Err(utils::introspection_error());
    }

    // That means that for our current implementation, the token itself is valid.
    let response = IntrospectionOkResponseBuilder::default()
        .active(true)
        .scope(Some(access_token.scope))
        .client_id(Some(client.identifier))
        .exp(Some(access_token.expires_at.timestamp()))
        .iat(Some(access_token.issued_at.timestamp()))
        .build()
        .unwrap(); // TODO: remove unwrap
    debug!("Token is valid: {:?}", response);
    info!(
        "Client [{}] introspected on token [{}]",
        response.client_id.clone().unwrap(),
        request.token
    );

    Ok(response)
}
