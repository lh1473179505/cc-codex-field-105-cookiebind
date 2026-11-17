# uefidb admit rules

db selects policy.dbs[db]. owner_guid is a canonical lowercase UUID string, is not in forbidden_owner_guids, and exactly equals the selected database owner_guid. cert_digest is exactly digest_hex_len lowercase hexadecimal characters; when forbid_zero_digest is true, an all-zero digest is invalid.

action belongs to the selected db actions. append is an integer in append_values and exactly equals append_by_action[action], so add/remove semantics cannot be interchanged. auth belongs to both the selected db auth_methods and auth_by_action[action]; an authentication method valid at only one layer or for another action is insufficient. The HMAC line covers all fields. Enforce key status, iat and replay checks, consuming nonce and writing store only on allow.
