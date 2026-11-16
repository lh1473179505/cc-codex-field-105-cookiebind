# sparkacl

Spark submit admit: user/master + jar prefix allow.

## admit

`python -m sparkacl admit` (or `sparkacl.engine.admit_job`) verifies a signed
Spark submit against a key ring, an app policy and a used-nonce store.

Signed line: `v1|{kid}|{app}|{user}|{master}|{jars}|{iat}|{nonce}` with an
HMAC-SHA256 signature (hex-decoded key secret, base64url without padding).

A job is allowed only when all of the following hold:

- the kid exists, the key is active and the HMAC signature verifies;
- `iat` is within `clock_skew_seconds` / `max_age_seconds` of `now`;
- the app is known and binds the submitted user and master;
- the jar URI matches an app `jar_prefixes` entry and no
  `jar_deny_substrings` (e.g. `..`, blocking path traversal) appears;
- the nonce is not already recorded in the store.

Only an `allow` decision records the nonce; a `deny` never writes the store
(CLI exits 1, allow exits 0).
