# pgpclear admit rules

## Signing
`v1|{kid}|{key_fp}|{algo}|{hash}|{body_sha256}|{iat}|{nonce}`

fp ∈ fps; algo/hash ∈ lists; if forbid_md5 and hash==md5 deny; body_sha256 length; HMAC+revoke; time; nonce allow-only.
