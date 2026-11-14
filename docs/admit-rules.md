# ldapgate admit rules

Offline LDAP search request gate. No network.

## Signing

`v1|{kid}|{bind_dn}|{base_dn}|{filter}|{scope}|{nonce}` UTF-8 HMAC-SHA256 base64url.

## Gates

1. HMAC + kid revoke.
2. `bind_dn` endswith `allowed_bind_dn_suffix` (exact suffix, case-sensitive as stored).
3. `base_dn` endswith `allowed_base_dn_suffix`.
4. If `require_bind_under_base`, bind_dn must end with base_dn (bind under search base).
5. scope in allowed_scopes.
6. filter length <= max; nesting depth (count of nested `(&` / `(|` openings) <= max_filter_depth.
7. Attribute names used in filter must be in allowed_attributes (parse simple `(attr=value)` tokens; ignore `&` `|` `!` parentheses).
8. Any forbidden_filter_tokens substring => `filter_injection`.
9. Nonce replay; write only on allow.

Note: shallow substring allow on DN that ignores suffix boundaries must fail deny-bind-escape.
