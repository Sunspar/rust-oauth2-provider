# Rust OAuth 2.0 Provider

This project is intended to provide a basic, standalone, and eventually [RFC 6749](https://tools.ietf.org/html/rfc6749) / [RFC 7662](https://tools.ietf.org/html/rfc7662) compliant OAuth 2.0 Provider implementation in [Rust](https://www.rust-lang.org).

It is backed by the [Rocket](https://github.com/SergioBenitez/Rocket) framework, a lightweight HTTP server based on [Hyper](https://github.com/hyperium/hyper).

If you discover a deviation from the aforementioned RFCS that is not already documented below, please open an issue. We will note it by adding it to the known deviations sections of this readme, and may or may not start work to fix the issue.

Of particular note is the fact that clients must be manually created, and that the only grant type currently supported is `client_credentials`.

## Known Deviations from RFC 6749

- Currently, we only support the client_credentials grant type
- error response messages may not conform to the RFC completely
- Not all optional fields are available
- We do not currently support client application creation via any accessible mechanism
- We are not currently validating redirect_uri redirections as the appropriate grant(s) are not supported yet

## Known Deviations From RFC 7662

- Introspection does not provide the client creator
- Not all optional fields are available


# Contribution Notice

This project is licensed under the MIT license, a copy of which is available alongside this repository in the AUTHORS.md file. Unless expressly stated otherwise, any contributions to this project will automatically be licensed under this license.