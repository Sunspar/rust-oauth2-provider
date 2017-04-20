use chrono::Duration;
use chrono::offset::utc::UTC;
use diesel;
use diesel::prelude::*;
use rocket::request::Form;
use rocket_contrib::JSON;
use std::ops::Add;
use models::*;
use persistence::*;
use diesel::pg::PgConnection;

#[get("/authorize")]
pub fn authorize() -> String {
  "Not implemented yet. :(".to_string()
}

#[post("/token", data = "<form>")]
pub fn token_request(form: Form<AccessTokenRequest>) -> Result<JSON<AccessTokenResponse>, JSON<OAuth2Error>> {
  let input = form.into_inner();
  let ref conn = *DB_POOL.get().unwrap();
  match client_credentials(conn, input) {
    Ok(atr) => Ok(JSON(atr)),
    Err(atr) => Err(JSON(atr))
  }
}

#[post("/introspection", data = "<form>")]
pub fn token_introspection(form: Form<IntrospectionRequest>) -> Result<JSON<IntrospectionOkResponse>, JSON<IntrospectionErrResponse>> {
  let request = form.into_inner();
  let conn = &*DB_POOL.get().unwrap();
  let opt_access_token: QueryResult<AccessToken> = access_tokens::table
    .filter(access_tokens::token.eq(&request.token))
    .first(conn);

  // No token  -->  not active
  if let Err(_) = opt_access_token {
    return Err(JSON(introspection_error()))
  }
  let access_token = opt_access_token.unwrap();

  // expires_at <= Now  -->  not active
  if access_token.expires_at.signed_duration_since(UTC::now()).num_seconds() <= 0 {
    return Err(JSON(introspection_error()))
  }

  // Token exists and expires in the future. We're good!
  let opt_client: QueryResult<Client> = clients::table
    .filter(clients::id.eq(access_token.client_id))
    .first(conn);
  if let Err(_) = opt_client {
    return Err(JSON(introspection_error()))
  }
  let client = opt_client.unwrap();

  // That means that for our current implementation, the token itself is valid.
  return Ok(JSON(IntrospectionOkResponseBuilder::default()
    .active(true)
    .scope(Some(access_token.scope))
    .client_id(Some(client.identifier))
    .exp(Some(access_token.expires_at.timestamp()))
    .iat(Some(access_token.issued_at.timestamp()))
    .build()
    .unwrap()))
}

/// Determines whether or not the request represents a `client_credentials` grant, and if so, whether or not
/// it contains the necessary parts.
fn client_credentials(conn: &PgConnection, req: AccessTokenRequest) -> Result<AccessTokenResponse, OAuth2Error> {
  // client_credentials needs the following fields:
  // - client_id
  // - client_secret
  // - scope
  if req.client_id.is_none() || req.client_secret.is_none() || req.scope.is_none() {
    return Err(oauth_error("invalid_request"));
  }
  let client = match check_client_credentials(conn, &req.client_id.unwrap(), &req.client_secret.unwrap()) {
    Ok(c) => c,
    Err(msg) => return Err(oauth_error(&msg))
  };
  let grant_type = match check_grant_type(conn, &req.grant_type.unwrap()) {
    Ok(g) => g,
    Err(msg) => return Err(oauth_error(&msg))
  };
  let token = generate_token(conn, &client, &grant_type, &req.scope.unwrap());
  Ok(generate_token_response(token))
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
    Ok(g) => {
      if grant_type == "client_credentials" {
        Ok(g)
      } else {
        Err("unsupported_grant_type")
      }
    }
  }
}

/// Generates an AccessToken.
///
/// Returns: AccessToken --- the AccessToken to send back to the caller
fn generate_token(conn: &PgConnection, c: &Client, g: &GrantType, scope: &str) -> AccessToken {
  let expiry = UTC::now().add(Duration::weeks(1));
  let new_access_token = NewAccessTokenBuilder::default()
    .client_id(c.id)
    .grant_id(g.id)
    .token("abab1212")
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
fn generate_token_response(at: AccessToken) -> AccessTokenResponse {
  AccessTokenResponseBuilder::default()
    .token_type("Bearer")
    .expires_in(at.expires_at.signed_duration_since(UTC::now()).num_seconds())
    .access_token(at.token)
    .scope(at.scope)
    .build()
    .unwrap()
}

/// Generates an OAuth2Error struct.
///
/// Returns: OAuth2Error --- the OAuth2Error struct to serialize and send back to the caller.
fn oauth_error(message: &str) -> OAuth2Error {
  OAuth2ErrorBuilder::default()
    .error(message)
    .build()
    .unwrap()
}


/// Generates an IntrospectionErrResponse struct.
///
/// Returns: IntrospectionErrResponse --- A standard error response struct when introspection determines that the 
///                                       associated AccessToken is not valid.
fn introspection_error() -> IntrospectionErrResponse {
  IntrospectionErrResponseBuilder::default()
    .active(false)
    .build()
    .unwrap()
}