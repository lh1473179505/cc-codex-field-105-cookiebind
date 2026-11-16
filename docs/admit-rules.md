# acmeordr admit rules

Account selection binds contact, allowed challenges and identifier suffixes. A non-wildcard identifier is either exactly an allowed suffix or a DNS name ending in `.` plus that suffix. Wildcards use exactly one leading `*.` and no other wildcard character. Reject empty labels, uppercase names and duplicates.

wildcard must equal whether identifiers contain wildcards. Mixed wildcard/non-wildcard orders are forbidden when configured. Any wildcard requires dns-01; challenge must also belong to the account. key_auth_sha256 is exactly 64 lowercase hex characters. Check HMAC, key status and iat before consuming a nonce on allow only; deny preserves store bytes.
