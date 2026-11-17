# cronbindx admit rules

## Signing
`v1|{kid}|{user}|{schedule}|{shell}|{cmd}|{cwd}|{env}|{umask}|{iat}|{nonce}`

## Schedule
Exactly schedule_fields tokens. hour(index1) ∈ sched_hours; dow(index4) ∈ sched_dows; reject `*` dow if forbid_wildcard_dow.

## Cross binds
shell ∈ shells; cmd startswith prefixes and reject deny substrings; cwd ∈ cwd_allow.
env is comma-separated names; every name ∈ env_allow and rejects env_deny_substrings; umask ∈ umask_allow.

HMAC+revoke; time; nonce allow-only.
