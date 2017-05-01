# Rust OAuth 2.0 Provider

This project is intended to provide a basic, standalone, and eventually RFC compliant OAuth 2.0 Provider implementation in [Rust](https://www.rust-lang.org).

It is backed by the [Rocket](https://github.com/SergioBenitez/Rocket) framework, a lightweight HTTP web framework based on [Hyper](https://github.com/hyperium/hyper).

If you discover a deviation from the relevant RFCs that is not already documented below, please open an issue. We will note it by adding it to the known deviations sections of this readme, and work to resolve the difference.

Of particular note is the fact that clients must be manually created.

## Setup Notes
As a user able to install extensions, install the "uuid-ossp" extension. You can do this by:
```
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```


## Environment Variables
### The .env File
This application makes use of a file named `.env` in order to provide runtime configuration for thinks like hosted port, exiory timeframes, etc.
Currently there are a lot of `unwrap()`s, so you'll want to double check the values you're providing match the documentation below.

### Variables Used
| Name | Required? | Type | Description |
| :-: | :-: | :-: | :-: |
| DATABASE_URL | Yes | String | The postgres:// url to the database. Include user and password in the url. |
| ACCESS_TOKEN_TTL | Yes | Signed Integer |  The amount of time (in seconds) that access tokens are valid for. |
| REFRESH_TOKEN_TTL | Yes | Signed Integer | The amount of time (in seconds) that refresh tokens are valid for. You may use -1 to ensure they never expire. |
| ROCKET_HOST | No | IP | The ip to bind to. May also be things like localhost. |
| ROCKET_PORT| No | Unsigned Integer | The port to bind Rocket to when starting the web server. |

## Client Creation
Currently client creation needs to happen manually. This means that you need to insert rows for the `clients` table and possibly `client_redirect_uris` table.

Client identifier and secrets are really just `VARCHAR(256)`es, although the project assumes that the secret stored in the database is encrypted using bcrypt with a cost of 15.

A command-line tool is in the works to be able to quickly add clients without having to fiddle with the database.

## Relevant RFCs
- [RFC 6749](https://tools.ietf.org/html/rfc6749) which describes the OAuth 2.0 Specification
- [RFC 6750](https://tools.ietf.org/html/rfc6750) which describes Bearer Token usage
- [RFC 7662](https://tools.ietf.org/html/rfc7662) which describes the introspection endpoint

### Known Deviations
#### RFC 6749
- No check to ensure that `client_credentials` grant is only used by confidential clients
- remove the client credentials from the token request, as we're instead forcing users to use the standard header only. We can add this back as a feature later on
- The following headers are missing where appropriate:
    - `Cache-Control: no-store`
    - `Pragma: no-cache`
    - `Content-Type: application/json;charset=UTF-8`
- document `refresh_expires_in` on token responses, as its not a standard field.
- Check if clients need scopes associated with them, and if they do we need to verify scope requests for tokens against their client's scope as well
- Modify the routes so that most error conditions trigger 400's instead and respond wit the appropriate OAuth2Error message
- No support for the authorization_code, implicit or client_password grant types
- We do not currently support client application creation via any accessible mechanism
- redirection endpoint remains unimplemented, as the grant type that requires it is also missing
- We are not currently validating redirect_uri redirections as the appropriate grant(s) are not supported yet
- Not all optional fields are available
- missing the `WWW-Authenticate` header in the response when an invalid client is detected

#### RFC 6750
- Consider the form-encoded authentication alongside the authorization header

#### RFC 7662
- Not all optional fields are available (2.2)

## License
Licensed under any of the following licenses, whichever better aligns with your needs:
 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## Contribution
Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.