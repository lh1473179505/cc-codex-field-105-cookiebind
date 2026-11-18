# trivyconf admit rules

`target` is an exact key in `targets`; do not resolve a filesystem path or image reference to another spelling. `scanners` and `severities` are unique, case-sensitive string arrays whose ordered contents must exactly equal the selected target's arrays. Missing required scanners, additional scanners and added lower severities are invalid.

`ignore_rules` is an array with unique `id` values. Each item is an object with exactly `id`, `expired_at` and `statement`, and must equal one complete entry in the target's `ignore_rules_allowed`. The ID must also match `ignore_id_pattern`, and expired_at must use exact canonical UTC `YYYY-MM-DDTHH:MM:SSZ` syntax. Every `ignore_rules_required` ID must be present; an empty list is valid only when no ignore is required.

`offline_db` has exactly `offline_db_keys` and must equal the target's complete object. In particular, `skip_update` is the JSON boolean true, the DB directory is target-specific, and the repository cannot be borrowed from another configuration. No online fallback is permitted.

Preserve scanner, severity and ignore order and serialize nested object keys in sorted order for HMAC. Require an active key, fresh iat under the configured limits and an unused nonce; only allow writes nonce/store.
