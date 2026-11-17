# smbshare admit rules

user must be an exact member of the selected global group, and that group must occur in the selected share's groups. share selects its own server, UNC root, folder prefixes and security requirements; authorization on another share is irrelevant.

unc_path is a canonical backslash-separated UNC string. It starts with `unc_root + "\"`, names exactly the selected server/share, and the relative remainder starts with one folder_prefixes entry. Empty components, `.`/`..`, forward slashes, NUL and encoded separators are invalid. A lookalike UNC prefix does not establish a path boundary.

signing and encryption are JSON booleans equal to the share requirements, and dialect is an exact member of dialects. Every field is signed in the declared order. HMAC, key status, iat and replay gates apply before any allow-only nonce write; deny never saves store.
