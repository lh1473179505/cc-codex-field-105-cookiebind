# fido2reg admit rules

## Signing
`v1|{kid}|{rp_id}|{user_id}|{aaguid}|{uv}|{iat}|{nonce}`

rp ∈ rps; aaguid ∈ aaguids; user_id startswith user_prefix; if require_uv then uv==1; HMAC+revoke; time; nonce allow-only.
