# Rust OAuth 2.0 Provider

This project is intended to provide a standalone, and eventually RFC compliant OAuth 2.0 Provider implementation in [Rust](https://www.rust-lang.org).

It is backed by the [Rocket](https://github.com/SergioBenitez/rocket) framework, a web framework based on [Hyper](https://github.com/hyperium/hyper).

If you discover a deviation from the relevant RFCs that is not already documented below, please open an issue.

## Setup Notes
### Rust Compiler
This project currently uses Rocket as the framework for dealing with HTTP calls. As a result, rust-oauth2-provider requires a nightly rust compiler, because ROcket uses functionality only available on nightly compilers.

rust-oauth2-provider _should_ work with any versions of the nightly compiler that Rocket have chosen to support -- if you find this to not be the case, please open an issue with your compile log and see if you can narrow down what specifically may be tripping you up.

As a general rule, I try to use the latest nightly compiler (when I remember to update) so try that first as we might inadvertently introduce something that is broken on specific nightly compilers.

Once Rocket is able to work with stable Rust, I'll revisit support for older compiler releases/editions alongside the current stable, and nightlies.

### Database Support
While the system _is technically_ set up to be database agnostic from a query perspective (thanks, diesel!), development is performed and tested against PostgreSQL 9.5, and there are currently no features for selecting the specific database backend. This is likely to come soon as I move to support more databases (to make it easier to integrate with your existing stack).

#### PostgreSQL
Make sure you're using _at least_ PostgreSQL 9.5. It will likely work with older versions, but I've done no testing to ensure that it does.

As a user able to install PostgreSQL extensions, install the "uuid-ossp" extension. You can do this by:

```
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

## Configuration
### config.toml
The application makes use of a custom TOML file (and related structs) to provide global settings values for the system.
See the config.sample.toml file for more details.

### Rocket -- Rocket.toml
As the project uses Rocket, you can configure rocket-specific things using the `rocket.toml` file. We dont include one as for now we're just using the defaults.

## Client Creation
Currently client creation needs to happen manually. This means that you need to insert rows for the `clients` table and possibly `client_redirect_uris` table. You can look at the `extras/test-clients.sql` file for exact commands to run. Note that the secret for both test accounts is `abcd1234`, and that the bcrypt has has been pre-computed for you. Client identifier and secrets are really just `VARCHAR(256)`es, although the project expects the database to store bcrypt hashes for secrets.

## RFCs
- [RFC 6749](https://tools.ietf.org/html/rfc6749) which describes the OAuth 2.0 Specification
- [RFC 6750](https://tools.ietf.org/html/rfc6750) which describes Bearer Token usage
- [RFC 7662](https://tools.ietf.org/html/rfc7662) which describes the introspection endpoint

### Known Deviations
#### RFC 6749
- SSL support missing at the web framework level
- codify client tyles ("confidental" / "public") better
- (2.3.1) support for `client_id` / `client_secret` to auth via post params
- (3.1) authorization endpoint and associated form are not implemented
- redirect endpoint is not implemented
- unregistered clients are out of scope for this providers
- (3.3) clients require an initial scope when created -- requests without a scope should use this entire value
- (4.1) support for the `Authorization Code` grant
- (4.2) support for the `Implicit` grant
- (4.3) support for the `Resource Owner Password Credentials` grant
- no check to ensure that confidential clients are always authenticated (because for now, the system flat out refuses you if you dont auth in the header)
- loosen auth header requirements for refresh tokens and non-`confidential` clients
- we need to document `refresh_expires_in` on token responses, as its not a standard field.
- Check if clients need scopes associated with them, and if they do we need to verify scope requests for tokens against their client's scope as well
- We do not currently support client application creation via any client facing mechanism (manual db entry required)

#### RFC 6750
- SSL support missing at the web framework level
- Support for the token in the post body (2.2)
- Support for URI param passing is missing and not intended for inclusion (2.3)

#### RFC 7662
- requests should support the `token_type_hint`, and use that to narrow down the search if provided
- ok response missing `username` field
- ok response is missing the `token_type` field
- ok response is missing the `nbf` field

## Security Notice
A custom fmt::Debug implementation exists for Client in order to make sure that client secrets arent accidentally leaked during logging.

## License
Licensed under any of the following licenses, whichever better aligns with your needs:
 - Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 - MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.