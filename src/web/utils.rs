//! The web::utils module holds helper functions that act as reusable components useful to have when interacting
//! with an iron::Request struct.

use iron::prelude::*;
use iron::headers::{Authorization, Basic};
use urlencoded::UrlEncodedBody;

use models::requests::*;
use models::responses::*;

/// Attepmts to extract an AuthorizationToken from the incoming Request
pub fn extract_auth_credentials(req: &mut Request) -> Option<AuthorizationToken> {
	trace!("Extracting authentication credentials from Basic Authorization header.");
	match req.headers.get::<Authorization<Basic>>() {
		None => {
			debug!("No credentials could be extracted from the request headers!");
			None
		},
		Some(h) => {
			debug!("Credentials found.");
			Some(AuthorizationTokenBuilder::default()
				.user(h.username.clone())
				.pass(h.password.clone().unwrap())
				.build()
				.unwrap())
		}
	}
}

/// Attempts to extract an AccessTokenRequest from the incoming Request.
pub fn extract_access_token_request(req: &mut Request) -> Result<AccessTokenRequest, OAuth2Error> {
	trace!("Entering extract_access_token_request.");
	let atr_map = match req.get_ref::<UrlEncodedBody>() {
		Ok(map) => map,
		Err(_) => return Err(OAuth2Error::InvalidRequest)
	};
	trace!("Extracted url encoded body: {:?}", atr_map);
	let refresh_token = match atr_map.get("refresh_token") {
		Some(array) => Some(array[0].clone()),
		None => None
	};
	trace!("refresh_token: {:?}", refresh_token);
	let scope = match atr_map.get("scope") {
		Some(array) => Some(array[0].clone()),
		None => None
	};
	trace!("scope: {:?}", scope);
	let grant_type = match atr_map.get("grant_type") {
		Some(array) => Some(array[0].clone()),
		None => None
	};
	trace!("grant_type: {:?}", grant_type);
	let atr = AccessTokenRequestBuilder::default()
		.refresh_token(refresh_token)
		.scope(scope)
		.grant_type(grant_type)
		.code(None)
		.build();
	match atr {
		Ok(v) => {
			debug!("Access token was successfully extracted: {:?}", v);
			Ok(v)
		},
		Err(why) => {
			debug!("Failed to extract access token: {:?}", why);
			Err(OAuth2Error::InvalidRequest)
		}
	}
}

/// Attempts to extract an IntrospectionRequest from the incoming Request.
pub fn extract_introspection_request(req: &mut Request) -> Result<IntrospectionRequest, OAuth2Error> {
	trace!("extracting introspection request struct from request body.");
	trace!("extracting map from url encoded body of request");
	let ir_map = match req.get_ref::<UrlEncodedBody>() {
		Ok(map) => map,
		Err(_) => return Err(OAuth2Error::InvalidRequest)
	};
	trace!("request data map: {:?}", ir_map);
	trace!("converting token");
	let token = match ir_map.get("token") {
		Some(a) => a[0].clone(),
		None => return Err(OAuth2Error::InvalidRequest)
	};
	trace!("token is: {:?}", token);
	trace!("converting token type hint");
	let token_type_hint = match ir_map.get("token_type_hint") {
		Some(a) => Some(a[0].clone()),
		None => None
	};
	trace!("token_type_hint is: {:?}", token_type_hint);
	trace!("building introspection request object");
	let introspection_request = IntrospectionRequestBuilder::default()
		.token(token)
		.token_type_hint(token_type_hint)
		.build();
	trace!("testing introspection request object");
	match introspection_request {
		Ok(v) => {
			debug!("Introspection request is well-formed. Request={:?}", v);
			Ok(v)
		},
		Err(why) => {
			debug!("Error during introspection request conversion: {:?}", why);
			Err(OAuth2Error::InvalidRequest)
		}
	}
}