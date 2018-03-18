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
    debug!("Auth token from request: {:?}", &auth);
    let auth_token = auth.ok_or(OAuth2ErrorResponse::InvalidClient)?;

    trace!("Extracting access token");
    debug!("token request: {:?}", &req);
    let request = req.map(|v| v.into_inner())
        .ok_or(OAuth2ErrorResponse::InvalidRequest)?;

    let conn = &*DB_POOL.get().unwrap(); // TODO: remove unwrap
    trace!("Successfully grabbed connection from the database connection pool.");

    let grant_type = request
        .grant_type
        .clone()
        .ok_or(OAuth2ErrorResponse::UnsupportedGrantType)?;

    let result = match grant_type.as_str() {
        "client_credentials" => utils::token::client_credentials(conn, request, auth_token.clone()),
        "refresh_token" => utils::token::refresh_token(conn, request, auth_token.clone()),
        _ => Err(OAuth2ErrorResponse::UnsupportedGrantType),
    };
    trace!("auth token endpoint response: {:?}", result);
    result
}
