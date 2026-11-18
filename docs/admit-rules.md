# natsjwt admit rules

issuer selects an operator and account is resolved only beneath that operator. signing_key must be an exact member of the selected account's signing_keys; an active key belonging to another account or operator is invalid. Account and key names are case-sensitive exact strings.

claims is a JSON object with keys restricted to claims_allowed and every claims_required entry present with its exact value, including sub equal to account. permissions has exactly publish and subscribe sections, each with exactly allow and deny string arrays. Those complete arrays must equal the account policy in their declared order; missing deny entries, added subjects and omitted sections are not equivalent.

expires_in is a JSON integer in the account's inclusive expiry range, not a boolean or numeric string. Recursively sorted object keys and array order enter the signed representation along with all fields. HMAC uses an active key, iat must satisfy max_age_seconds=600 with clock_skew_seconds=60, and nonce must be unused. Only allow consumes nonce and saves store.
