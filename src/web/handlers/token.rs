use DB_POOL;
use models::requests::access_token::AccessTokenRequest;
use models::responses::access_token::AccessTokenResponse;
use models::responses::oauth2_error::OAuth2ErrorResponse;
use rocket::request::Form;
use utils;
use web::headers::authorization_token::AuthorizationToken;

#[post("/oauth/token", data = "<req>")]
pub fn post(
    req: Option<Form<AccessTokenRequest>>,
    auth: Option<AuthorizationToken>,
) -> Result<AccessTokenResponse, OAuth2ErrorResponse> {
    trace!("Entering the token handler.");
    let auth_token = match auth {
        Some(at) => {
            trace!("Token successfully extracted: {:?}", at);
            at
        }
        None => {
            trace!("Malformed Authorization header caused the authentication token guard to fail.");
            return Err(OAuth2ErrorResponse::InvalidClient);
        }
    };

    let request = match req {
        Some(atr) => {
            let res = atr.into_inner();
            trace!("Request seems okay. {:?}", res);
            res
        }
        None => {
            trace!("Request extraction failed. Most likely the user sent an invalid form body.");
            return Err(OAuth2ErrorResponse::InvalidRequest);
        }
    };

    let conn = &*DB_POOL.get().unwrap();
    trace!("Successfully grabbed connection from the database connection pool.");

    let result = match request.grant_type.clone() {
        None => Err(OAuth2ErrorResponse::UnsupportedGrantType),
        Some(gt) => match gt.as_str() {
            "client_credentials" => {
                utils::token::client_credentials(conn, request, auth_token.clone())
            }
            "refresh_token" => utils::token::refresh_token(conn, request, auth_token.clone()),
            _ => Err(OAuth2ErrorResponse::UnsupportedGrantType),
        },
    };

    match result {
        Ok(r) => {
            info!("Client [{}] generated new access token.", auth_token.user);
            Ok(r)
        }
        Err(r) => {
            debug!("Error during token generation: {:?}", r);
            info!(
                "Client [{}] failed to generate new access token.",
                auth_token.user
            );
            Err(r)
        }
    }
}
