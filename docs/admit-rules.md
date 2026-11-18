# buildkit admit rules

Resolve `builds[build].targets[target].secrets[secret_id]` as one nested selection. A secret known to another build or target is not authorized for the selected release stage. No secret value is part of this request; only the registered mount descriptor is admitted.

`mount_path` is an absolute canonical path beneath `mount_root`, exactly equal to the selected secret's path, with no empty, `.` or `..` component and none of `path_deny_substrings`. Do not normalize a dangerous path into the allowed location. `mode`, `uid` and `gid` are JSON integers exactly equal to the registered permission tuple; mode is the numeric octal permission value, so decimal 256 represents 0400.

`required` is a JSON boolean equal to the secret requirement. `cache_sharing` and `cache_key` must exactly match the same secret's cache policy. A broadly valid sharing mode such as shared cannot replace locked or private, and a cache key from another build is invalid.

The HMAC line includes every identity, mount, permission and cache field in declared order. Check active signing key, iat age/skew and nonce replay independently. Persist nonce/store only for a complete allow; denied mounts leave store unchanged.
