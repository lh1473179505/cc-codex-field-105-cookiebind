# cspframe admit rules

## Signing
`v1|{kid}|{site}|{frame_ancestors}|{sandbox}|{script_mode}|{iat}|{nonce}`

site ∈ sites; every ancestor token ∈ ancestors_allow (space-separated); forbid `*` if forbid_star_ancestor; if sandbox_required then sandbox==1; script_mode ∈ script_modes and not unsafe-inline when forbid_unsafe_inline_script; HMAC+revoke; time; nonce allow-only.
