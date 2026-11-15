# falcorule admit rules

## Signing
`v1|{kid}|{rule_id}|{priority}|{condition}|{output}|{iat}|{nonce}`

rule_id startswith one prefix; priority allow; reject condition_deny_substrings; every non-literal token in condition must be in condition_allow_tokens (split on spaces); output fields csv ⊆ output_allow; HMAC+revoke; time; nonce allow-only.
