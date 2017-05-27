use dotenv;
use rocket;
use rocket::{Response, Rocket};
use rocket::testing::MockRequest;
use rocket::http::{ContentType, Status};
use rocket::http::Method;
use serde_json;

use models::responses::*;
use web::headers::AuthorizationToken;

// Mounts routes and initializes a Rocket instance for the test cases.
fn rocket() -> Rocket {
  dotenv::dotenv().ok();
  rocket::ignite()
    .mount("/", routes![
      super::web::routes::token,
      super::web::routes::introspect])
}

/// Sets up the common request and rocket stuff for /oauth/token tests
fn common_mock_token<'a>() -> MockRequest<'a> {
  let request = MockRequest::new(Method::Post, "/oauth/token");
  request.header(ContentType::Form)
}

// Sets up the common request and rocket stuff for /oauth/introspect tests
fn common_mock_introspect<'a>() -> MockRequest<'a> {
  let request = MockRequest::new(Method::Post, "/oauth/introspect");
  request.header(ContentType::Form)
}

// Issues a valid client_credentials /oauth/token request, tests the response, and returns the ATR.
fn fetch_access_token_for_client(rocket: &mut Rocket, at: &AuthorizationToken) -> AccessTokenResponse {
  let mut request = common_mock_token();
  request = request.body(&format!("scope={}&grant_type={}", "all+generics+test-scope", "client_credentials"));
  request.add_header(at.clone());
  let mut response = request.dispatch_with(rocket);

  assert_headers(&response, false);
  assert_eq!(response.status(), Status::Ok, "Incorrect response code.");

  let body = response
    .body()
    .and_then(|b| b.into_string())
    .expect("Response body was not converted into a String value.");

  let atr = serde_json::from_str::<AccessTokenResponse>(body.as_str());
  assert!(atr.is_ok(), "JSON response was not deserializable into an AccessTokenResponse: {:?}", atr);
  atr.expect("Failed to deserialize the AccessToken.")
}

// Helper which performs response header assertions
fn assert_headers(response: &Response, www_header_expected: bool) {
  if www_header_expected {
    // Ensure the WWW-Authenticate header is set to the proper value, and set exactly once.
    let www_authenticate_headers: Vec<&str> = response.header_values("WWW-Authenticate").collect();
    assert_eq!(www_authenticate_headers.len(), 1, "WWW-Authenticate Headers: {:?}", www_authenticate_headers);
    assert_eq!(www_authenticate_headers[0], "Basic", "Incorrect WWW-Authenticate value.");
  }

  // Ensure the Cache-Control header is set to the proper value, and is set exactly once.
  let cache_control_headers: Vec<&str> = response.header_values("Cache-Control").collect();
  assert_eq!(cache_control_headers.len(), 1, "Cache-Control Headers: {:?}", cache_control_headers);
  assert_eq!(cache_control_headers[0], "no-cache, no-store", "Incorrect Cache-Control value.");

  // Ensure the Pragma header is set to the proper value, and is set exactly once.
  let pragma_headers: Vec<&str> = response.header_values("Pragma").collect();
  assert_eq!(pragma_headers.len(), 1, "Pragma Headers: {:?}", pragma_headers);
  assert_eq!(pragma_headers[0], "no-cache", "Incorrect Pragma value.");
}

fn assert_introspect_err_valid(response: &mut Response) {
  let body = response
    .body()
    .and_then(|b| b.into_string())
    .expect("Response body was not converted into a String value.");
    
  let ier = serde_json::from_str::<IntrospectionErrResponse>(body.as_str())
    .expect("Response was not deserializable in to an IntrospectionErrResponse struct");
  assert_eq!(ier.active, false);
}

#[test]
// Token Request, Client Credentials, Missing Auth Header
fn token_missing_auth_header() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_token();
  request = request.body(&format!("scope={}&grant_type={}", "all+generics+test-scope", "client_credentials"));
  let response = request.dispatch_with(&rocket);
  
  assert_headers(&response, true);
  assert_eq!(response.status(), Status::Unauthorized, "Incorrect response code.");
}

#[test]
// Token, Client Credentials, Malformed Auth Header
fn token_client_malformed_auth_header() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_token();
  request = request.body(&format!("scope={}&grant_type={}", "all+generics+test-scope", "client_credentials"));
  request.add_header(AuthorizationToken { user: "abcd".to_string(), pass: "".to_string() });
  let response = request.dispatch_with(&rocket);
  
  assert_headers(&response, true);
  assert_eq!(response.status(), Status::Unauthorized, "Incorrect response code.");
}

#[test]
// Token, Client Credentials, Non-Confidential Client
fn token_client_non_confidential_client() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_token();
  request = request.body(&format!("scope={}&grant_type={}", "all+generics+test-scope", "client_credentials"));
  request.add_header(AuthorizationToken { user: "abcd4321".to_string(), pass: "abcd1234".to_string() });
  let response = request.dispatch_with(&rocket);
  
  assert_headers(&response, false);
  assert_eq!(response.status(), Status::BadRequest, "Incorrect response code.");
}

#[test]
// Token, Client Credentials, Missing Params
fn token_client_missing_params() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_token();
  request = request.body(&format!("scope={}", "all+generics+test-scope"));
  request.add_header(AuthorizationToken { user: "abcd1234".to_string(), pass: "abcd1234".to_string() });
  let response = request.dispatch_with(&rocket);
  
  assert_headers(&response, false);
  assert_eq!(response.status(), Status::BadRequest, "Incorrect response code.");
}

#[test]
// Token, Client Credentials, Proper Request
fn token_client_proper_request() {
  // Prepare and issue the request
  let mut rocket = rocket();
  let mut request = common_mock_token();
  request = request.body(&format!("scope={}&grant_type={}", "all+generics+test-scope", "client_credentials"));
  request.add_header(AuthorizationToken { user: "abcd1234".to_string(), pass: "abcd1234".to_string() });
  let mut response = request.dispatch_with(&mut rocket);
  
  assert_headers(&response, false);
  assert_eq!(response.status(), Status::Ok, "Incorrect response code.");

  let body = response
    .body()
    .and_then(|b| b.into_string())
    .expect("Response body was not converted into a String value.");
    
  let atr = serde_json::from_str::<AccessTokenResponse>(body.as_str());
  assert!(atr.is_ok(), "JSON response was not deserializable into an AccessTokenResponse: {:?}", atr);

}

#[test]
// Token, Refresh Token, Missing Auth Header
fn token_refresh_missing_auth_header() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_token();
  request = request.body(&format!("scope={}&grant_type={}&refresh_token={}", "all+generics+test-scope", "refresh_token", "effb66ba-6990-4314-9fd5-b140ac9482ee"));
  let response = request.dispatch_with(&rocket);
  
  assert_headers(&response, true);
  assert_eq!(response.status(), Status::Unauthorized, "Incorrect response code.");
}

#[test]
// Token, Refresh Token, Malformed Auth Header
fn token_refresh_malformed_auth_header() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_token();
  request = request.body(&format!("scope={}&grant_type={}&refresh_token={}", "all+generics+test-scope", "refresh_token", "effb66ba-6990-4314-9fd5-b140ac9482ee"));
  request.add_header(AuthorizationToken { user: "abcd".to_string(), pass: "".to_string() });
  let response = request.dispatch_with(&rocket);
  
  assert_headers(&response, true);
  assert_eq!(response.status(), Status::Unauthorized, "Incorrect response code.");
}

#[test]
// Token, Refresh Token, Non-Confidential client
fn token_refresh_not_confidential_client() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_token();
  request = request.body(&format!("scope={}&grant_type={}&refresh_token={}", "all+generics+test-scope", "refresh_token", "effb66ba-6990-4314-9fd5-b140ac9482ee"));
  request.add_header(AuthorizationToken { user: "abcd4321".to_string(), pass: "abcd1234".to_string() });
  let response = request.dispatch_with(&rocket);
  assert_headers(&response, false);
  assert_eq!(response.status(), Status::BadRequest, "Incorrect response code.");
}

#[test]
// Token, Refresh Token, Missing Params
fn token_refresh_missing_params() {
  // First, we need a valid token by issuing an initial Client Credentials /oauth/token request
  let auth_token = AuthorizationToken { user: "abcd1234".to_string(), pass: "abcd1234".to_string() };
  let mut rocket = rocket();
  let atr = fetch_access_token_for_client(&mut rocket, &auth_token);
  let refresh_token = atr.refresh_token.expect("The test expects to find a refresh token.");
  let mut request = common_mock_token();
  request = request.body(&format!("grant_type={}&refresh_token={}", "refresh_token",refresh_token));
  request.add_header(auth_token);
  let response = request.dispatch_with(&rocket);
  
  assert_headers(&response, false);
  assert_eq!(response.status(), Status::BadRequest, "Incorrect response code.");
}

#[test]
// Token, Refresh Token, Missing Refresh Token in Request
fn token_refresh_missing_refresh_token() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_token();
  request = request.body(&format!("scope={}&grant_type={}", "all+generics+test-scope", "refresh_token"));
  request.add_header(AuthorizationToken { user: "abcd1234".to_string(), pass: "abcd1234".to_string() });
  let response = request.dispatch_with(&rocket);
  
  assert_headers(&response, false);
  assert_eq!(response.status(), Status::BadRequest, "Incorrect response code.");
}

#[test]
// Token, Refresh Token, Invalid Refresh Token in Request
fn token_refresh_invalid_token_in_request() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_token();
  request = request.body(&format!("scope={}&grant_type={}&refresh_token={}", "all+generics+test-scope", "refresh_token", "12345678-1234-1234-1234-123456789012"));
  request.add_header(AuthorizationToken { user: "abcd1234".to_string(), pass: "abcd1234".to_string() });
  let ref mut response = request.dispatch_with(&rocket);
  assert_headers(&response, false);
  assert_eq!(response.status(), Status::BadRequest, "Incorrect response code.");
}

#[test]
// Token, Refresh Token, Proper Request
fn token_refresh_proper_request() {
  // First, we need a valid token by issuing an initial Client Credentials /oauth/token request
  let ref auth_token = AuthorizationToken { user: "abcd1234".to_string(), pass: "abcd1234".to_string() };
  let ref mut rocket = rocket();
  let atr = fetch_access_token_for_client(rocket, auth_token);
  let refresh_token = atr.refresh_token.expect("The test expects to find a refresh token.");
  // Use the refresh token to make the request we're ultimately testing
  let mut rt_request = common_mock_token();
  rt_request = rt_request.body(&format!("grant_type={}&refresh_token={}&scope={}", "refresh_token", refresh_token, "all"));
  rt_request.add_header(AuthorizationToken { user: "abcd1234".to_string(), pass: "abcd1234".to_string() });
  let mut rt_response = rt_request.dispatch_with(rocket);
  
  assert_headers(&rt_response, false);
  assert_eq!(rt_response.status(), Status::Ok, "Incorrect response code.");

  let body = rt_response
    .body()
    .and_then(|b| b.into_string())
    .expect("Response body was not converted into a String value.");
    
  let atr = serde_json::from_str::<AccessTokenResponse>(body.as_str());
  assert!(atr.is_ok(), "JSON response was not deserializable into an AccessTokenResponse: {:?}", atr);
}

#[test]
// Introspect, Missing Auth Header
fn introspect_missing_auth_header() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_introspect();
  request = request.body(&format!("token={}", "8858caff-67bf-4860-8abb-ccf1c8f18192"));
  let mut response = request.dispatch_with(&rocket);

  assert_headers(&response, false);
  assert_eq!(response.status(), Status::Ok, "Incorrect response code.");
  assert_introspect_err_valid(&mut response);
}

#[test]
// Introspect, Malformed Auth Header
fn introspect_malformed_auth_header() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_introspect();
  request.add_header(AuthorizationToken { user: "abcd1234".to_string(), pass: "".to_string() });
  request = request.body(&format!("token={}", "12345678-1234-1234-1234-123456789012"));
  let mut response = request.dispatch_with(&rocket);
  
  assert_headers(&response, false);
  assert_eq!(response.status(), Status::Ok, "Incorrect response code.");
  assert_introspect_err_valid(&mut response);
}

#[test]
// Introspect, Invalid Token
fn introspect_invalid_token() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_introspect();
  request.add_header(AuthorizationToken { user: "abcd1234".to_string(), pass: "abcd1234".to_string() });
  request = request.body(&format!("token={}", "12345678-1234-1234-1234-123456789012"));
  let mut response = request.dispatch_with(&rocket);
  
  assert_headers(&response, false);
  assert_eq!(response.status(), Status::Ok, "Incorrect response code.");
  assert_introspect_err_valid(&mut response);
}

#[test]
// Introspect, Missing Token
fn introspect_missing_token() {
  // Set up the Rocket instance and an initial MockRequest
  let rocket = rocket();
  let mut request = common_mock_introspect();
  request.add_header(AuthorizationToken { user: "abcd1234".to_string(), pass: "".to_string() });
  request = request.body("");
  let mut response = request.dispatch_with(&rocket);
  
  assert_headers(&response, false);
  assert_eq!(response.status(), Status::Ok, "Incorrect response code.");
  assert_introspect_err_valid(&mut response);
}

#[test]
// Introspect, Client Mismatch
fn introspect_client_mismatch() {
  // First generate a valid AccessToken to use
  let auth_token_one = AuthorizationToken { user: "abcd1234".to_string(), pass: "abcd1234".to_string() };
  let auth_token_two = AuthorizationToken { user: "abcd4321".to_string(), pass: "abcd1234".to_string() };
  let mut rocket = rocket();
  let atr = fetch_access_token_for_client(&mut rocket, &auth_token_one);
  let access_token = atr.access_token;
  let mut i_request = common_mock_introspect();
  i_request = i_request.body(&format!("token={}", access_token));
  i_request.add_header(auth_token_two);
  let mut response = i_request.dispatch_with(&rocket);

  assert_headers(&response, false);
  assert_eq!(response.status(), Status::Ok, "Incorrect response code.");
  assert_introspect_err_valid(&mut response);
}

#[test]
// Introspect, Proper Request
fn introspect_proper_request() {
  // First generate a valid AccessToken to use
  let auth_token = AuthorizationToken { user: "abcd1234".to_string(), pass: "abcd1234".to_string() };
  let mut rocket = rocket();
  let atr = fetch_access_token_for_client(&mut rocket, &auth_token);
  let access_token = atr.access_token;
  let mut i_request = common_mock_introspect();
  i_request = i_request.body(&format!("token={}", access_token));
  i_request.add_header(auth_token);
  let mut response = i_request.dispatch_with(&rocket);

  assert_headers(&response, false);
  assert_eq!(response.status(), Status::Ok, "Incorrect response code.");

  let body = response
    .body()
    .and_then(|b| b.into_string())
    .expect("Response body was not converted into a String value.");
    
  let atr = serde_json::from_str::<IntrospectionOkResponse>(body.as_str())
    .expect("Response was not deserializable in to an IntrospectionOkResponse struct");
}