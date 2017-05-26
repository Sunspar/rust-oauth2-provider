-- example HTTP POST script which demonstrates setting the
-- HTTP method, body, and adding a header

-- wrk file for benchmarking the token endpoint using the abcd1234:abcd1234 client from the test-clients SQL file.
-- Run this benchmark file with something like:
-- `wrk -t12 -c300 -d30s -s external/wrk-token.lua http://localhost:8000/oauth/token`

wrk.method = "POST"
wrk.body   = "scope=all+generics+test-scope&grant_type=client_credentials"
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
wrk.headers["Authorization"] = "Basic YWJjZDEyMzQ6YWJjZDEyMzQ="
