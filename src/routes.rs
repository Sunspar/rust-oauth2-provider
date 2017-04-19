use chrono::Duration;
use chrono::offset::utc::UTC;
use diesel;
use diesel::prelude::*;
use rocket::request::Form;
use rocket_contrib::JSON;
use std::ops::Add;
use models::*;
use persistence::*;

#[get("/authorize")]
pub fn authorize_get() -> String {
  "Not implemented yet. :(".to_string()
}

#[post("/token", data = "<form>")]
pub fn generate_token(form: Form<ClientCredentialsRequest>) -> Result<JSON<AccessTokenResponse>, JSON<OAuth2Error>> {
  let input: ClientCredentialsRequest = form.into_inner();
  let conn = &*DB_POOL.get().unwrap();

  // Does the client exist?
  let opt_client: QueryResult<Client> = clients::table
    .filter(clients::identifier.eq(&input.client_id))
    .filter(clients::secret.eq(input.client_secret.clone()))
    .first(conn);
  if let Err(_) = opt_client {
    return Err(JSON(OAuth2ErrorBuilder::default()
      .status(404)
      .message("Client not found.")
      .build()
      .unwrap()))
  }
  let client = opt_client.unwrap();

  // Is the grant type valid?
  let opt_grant_type: QueryResult<GrantType> = grant_types::table
    .filter(grant_types::name.eq(&input.grant_type))
    .first(conn);
  if let Err(_) = opt_grant_type {
    return Err(JSON(OAuth2ErrorBuilder::default()
      .status(400)
      .message("Invalid Grant Type. The provider currently only accepts `client_credentials`.")
      .build()
      .unwrap()))
  }
  let grant_type = opt_grant_type.unwrap();
  if "client_credentials" != grant_type.name {
    return Err(JSON(OAuth2ErrorBuilder::default()
      .status(400)
      .message("Invalid Grant Type. The provider currently only accepts `client_credentials`.")
      .build()
      .unwrap()))
  }

  // TODO: Does the spec say we should return an existing token, if its valid?

  // Initialize the access token ...
  let expiry = UTC::now().add(Duration::weeks(1));
  let new_access_token = NewAccessTokenBuilder::default()
    .client_id(client.id)
    .grant_id(grant_type.id)
    .token("abab1212")
    .scope(input.scope)
    .refresh_token(None)
    .expires_at(expiry)
    .issued_at(UTC::now())
    .refresh_expires_at(None)
    .build()
    .unwrap();
  let access_token = diesel::insert(&new_access_token)
    .into(access_tokens::table)
    .get_result::<AccessToken>(conn)
    .unwrap();
  let valid_duration = expiry.signed_duration_since(UTC::now()).num_seconds();

  //... and send it to the client.
  Ok(JSON(AccessTokenResponseBuilder::default()
    .token_type("Bearer")
    .expires_in(valid_duration)
    .access_token(access_token.token)
    .build()
    .unwrap()))
}

#[post("/introspection", data = "<form>")]
pub fn introspection(form: Form<IntrospectionRequest>) -> JSON<IntrospectionResponse> {
  let request = form.into_inner();
  let conn = &*DB_POOL.get().unwrap();
  let opt_access_token: QueryResult<AccessToken> = access_tokens::table
    .filter(access_tokens::token.eq(&request.token))
    .first(conn);

  // No token  -->  not active
  if let Err(_) = opt_access_token {
    return JSON(IntrospectionResponseBuilder::default()
      .active(false)
      .scope(None)
      .client_id(None)
      .exp(None)
      .iat(None)
      .build()
      .unwrap())
  }
  let access_token = opt_access_token.unwrap();

  // expires_at <= Now  -->  not active
  if access_token.expires_at.signed_duration_since(UTC::now()).num_seconds() <= 0 {
    return JSON(IntrospectionResponseBuilder::default()
      .active(false)
      .scope(None)
      .client_id(None)
      .exp(None)
      .iat(None)
      .build()
      .unwrap())
  }

  // Token exists and expires in the future. We're good!
  let opt_client: QueryResult<Client> = clients::table
    .filter(clients::id.eq(access_token.client_id))
    .first(conn);
  if let Err(_) = opt_client {
    return JSON(IntrospectionResponseBuilder::default()
      .active(false)
      .scope(None)
      .client_id(None)
      .exp(None)
      .iat(None)
      .build()
      .unwrap())
  }
  let client = opt_client.unwrap();

  // That means that for our current implementation, the token itself is valid.
  return JSON(IntrospectionResponseBuilder::default()
    .active(true)
    .scope(Some(access_token.scope))
    .client_id(Some(client.identifier))
    .exp(Some(access_token.expires_at.timestamp()))
    .iat(Some(access_token.issued_at.timestamp()))
    .build()
    .unwrap())
}
