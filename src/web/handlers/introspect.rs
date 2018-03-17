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
    let auth_token = match auth {
        Some(at) => {
            trace!("Authentication token looks okay: {:?}", at);
            at
        }
        None => {
            trace!("Malformed Authorization header caused the authentication token guard to fail.");
            return Err(utils::introspection_error());
        }
    };

    let request = match req {
        Some(ir) => {
            let res = ir.into_inner();
            trace!("Request seems okay: {:?}", res);
            res
        }
        None => {
            trace!("Request extraction failed. Most likely the user sent an invalid form body.");
            return Err(utils::introspection_error());
        }
    };

    let conn = &*DB_POOL.get().unwrap();

    // Ensure client is valid at all
    let client = match utils::check_client_credentials(&conn, &auth_token.user, &auth_token.pass) {
        Ok(c) => {
            trace!("Client authenticated successfully.");
            c
        }
        Err(_) => {
            trace!("Client not authenticated -- most likely typo in user or pass.");
            return Err(utils::introspection_error());
        }
    };

    // Tokens are always UUIDs
    // No token  -->  not active
    let token_as_uuid = match Uuid::parse_str(&request.token) {
        Ok(i) => {
            trace!("Token was parsable as UUID. Token: {:?}", i);
            i
        }
        Err(_) => {
            trace!(
                "Token was not parsable into UUID. Token: {:?}",
                request.token
            );
            return Err(utils::introspection_error());
        }
    };

    let opt_access_token: QueryResult<AccessToken> = access_tokens::table
        .filter(access_tokens::token.eq(token_as_uuid))
        .first(&*conn);
    let access_token = match opt_access_token {
        Ok(at) => {
            debug!("access token successfully generated.");
            at
        }
        Err(why) => {
            debug!("no token generated: {:?}", why);
            return Err(utils::introspection_error());
        }
    };

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
        .unwrap();
    debug!("Token is valid: {:?}", response);
    info!(
        "Client [{}] introspected on token [{}]",
        response.client_id.clone().unwrap(),
        request.token
    );

    Ok(response)
}
