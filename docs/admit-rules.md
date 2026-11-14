# nestedjwt admit rules

Outer JWS wraps inner JWS in payload.jwt. Headers/payloads are
base64url(JSON with sort_keys and compact separators).

## Verify order

1. Split outer; verify HS256 with outer kid; typ must be allowed_outer_typ; outer kid not revoked.
2. Decode outer payload; take nested jwt string **raw** (no re-serialize).
3. Verify inner HS256 with inner kid; typ allowed; inner kid not revoked.
4. If `require_cnf_jkt_match_inner_key`, outer.cnf.jkt must equal first 32 hex of SHA256(inner key secret bytes).
5. aud/azp exact allow; scope must be in allowed_scopes (single string in fixtures).
6. If inner header has `crit`, every member must be in allowed_crit and present as header param; unknown crit => `crit_unknown`.
7. now within inner iat/exp ± skew; outer exp also checked.
8. nonce from outer payload (also duplicated in token.json) — replay store; write only allow.

Inner key thumbprint for active key: `352302489bc2fcf025cf00cda8308033`.
