# Rust OAuth 2.0 Provider

This project is intended to provide a basic, standalone, and eventually RFC compliant OAuth 2.0 Provider implementation in [Rust](https://www.rust-lang.org).

It is backed by the [Rocket](https://github.com/SergioBenitez/Rocket) framework, a lightweight HTTP web framework based on [Hyper](https://github.com/hyperium/hyper).

If you discover a deviation from the relevant RFCs that is not already documented below, please open an issue. We will note it by adding it to the known deviations sections of this readme, and work to resolve the difference.

Of particular note is the fact that clients must be manually created.

## Setup Notes
As a superuser, install the "uuid-ossp" extension. You can do this by:

```
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

## Relevant RFCs
- [RFC 6749](https://tools.ietf.org/html/rfc6749) which describes the OAuth 2.0 Specification
- [RFC 6750](https://tools.ietf.org/html/rfc6750) which describes Bearer Token usage
- [RFC 7662](https://tools.ietf.org/html/rfc7662) which describes the introspection endpoint

### Known Deviations
#### RFC 6749
- No support for the authorization_code, implicit or client_password grant types
- we currently dont have scenarios where `invalid_scope` or `unauthorized_grant` errors are returned (§ 5.1)
- Not all optional fields are available
- We do not currently support client application creation via any accessible mechanism
- We are not currently validating redirect_uri redirections as the appropriate grant(s) are not supported yet
- redirection endpoint remains unimplemented, as the grant type that requires it is also missing

#### RFC 6750
- havent even looked at it yet!

#### RFC 7662
- Introspection does not validate calling client (§ 2.1)
    - does not 401 if the credentials or token provided are invalid
- Not all optional fields are available
- Not all error messages are used where appropriate

## License
Licensed under any of the following licenses, whichever better aligns with your needs:
 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## Contribution
Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.