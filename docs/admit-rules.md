# cgroupx admit rules

## Signing input
`v1|{kid}|{path}|{controllers_csv}|{memory_max}|{cpu_weight}|{iat}|{nonce}`

## Path / controllers
Reject path deny substrings; path startswith path_allow_prefixes.
Every controller ∈ controllers_allow; controllers_required ⊆ controllers.
memory_max/cpu_weight within min/max; HMAC+revoke; time; nonce allow-only.
