# pkcedual admit rules

## Signing input
`v1|{kid}|{client_id}|{code}|{challenge}|{method}|{redirect}|{jkt}|{auth_method}|{iat}|{nonce}`

## Redirect normalize
Parse redirect. Reject userinfo / query / fragment when corresponding forbid_* true.
If redirect_normalize_strip_slash: trailing `/` does not create a new identity — compare against redirects after rstrip('/') OR exact membership in redirects list (fixtures include both forms as allowed for pay-spa).

## PKCE
method ∈ methods; forbid plain. len(challenge)==challenge_len.
code must startswith one code_prefix for the client.

## DPoP-like jkt
If require_jkt: jkt non-empty and ∈ jkts.
auth_method ∈ auth_methods.

## One-time code
On allow, store items[code]=ts. If code already in store => deny (fixtures: deny-replay uses store-used with code? — use nonce store as usual PLUS treat code as secondary key: for deny-replay, store-used already has n-deny-replay; additionally document that admit must also refuse if store.items contains code. For fixture simplicity: deny-replay uses same code as ok-pay and store-used contains that code under items["c-pay-001"]).

HMAC + kid_revoked; time; write store only on allow (both nonce and code keys).
