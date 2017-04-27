- Validate that success responses for `client_credentials` and `refresh_token` are appropriate
- validate that error responses for `client_credentials` and `refresh_token` are appropriate
- Begin validating client credentials if presented
    - error if the client type sugests we have to validate and we cant due to missing credentials
- Examing remaining grant types
- Perform an actual cleanup and refactoring of `utils/mod.rs` as  Im kind of shoving everything in the closet in an attempt to tidy the rest of the room up

- Eventually, we need to support the authorize endpoint
