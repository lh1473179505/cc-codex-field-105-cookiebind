# minisign admit rules

Select `artifacts[artifact_id]`, then `keys[public_key]` beneath that artifact. `signature` is the Minisign artifact-signature fixture and must exactly occur in the selected public key's `signatures`; a backup key's signature is not valid for the primary key. The outer request authentication value is the separately generated `sig` and must not be confused with this field.

`canonical_digest` is exactly `digest_hex_length` lowercase hexadecimal characters and equals the artifact's canonical SHA-256. Integer `artifact_size` lies within that artifact's inclusive `size_min..size_max`; size limits do not carry across artifacts.

`trusted_comment` is one printable-ASCII line no longer than `trusted_comment_length_max`, contains no control characters, and starts with one prefix from the selected public key's `trusted_comment_prefixes`. The comment therefore binds both artifact and key context. Sign all fields in order, enforce active-key HMAC and iat age/skew, and persist nonce/store only for allow.
