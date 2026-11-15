# fuzzcrash admit rules

## Signing input

Full-form reports carry every component and sign (ASCII, no spaces beyond
those inside field values that docs forbid):

`v1|{kid}|{stack_norm_sha}|{fault}|{severity}`

where `stack_norm_sha` is the hex SHA-256 of the ASLR-normalized stack:
every `0x[0-9a-fA-F]+` address in each frame is replaced with `0x0`, the
normalized frames are joined with `\n`, and the UTF-8 bytes are hashed.

Compact reports instead commit to their signed attributes:

`v1|{kid}|{body_sha256}`

where `body_sha256` is the hex SHA-256 of the canonical JSON
(`sort_keys`, `(",", ":")` separators) of every report field except
`kid`, `sig` and `_sign_line`.

Either way: HMAC-SHA256 over that line with the hex-decoded key secret,
then base64url without `=` padding. The engine always recomputes the
signing line from the report itself; a supplied `_sign_line` is an
untrusted hint and is never relied upon.

## Compact report profiles

A compact report carries its crash attributes implicitly. The signed
`marker` attribute selects the deviation applied to a compliant baseline
(valid signature, well-formed untruncated stack hashed after ASLR
normalization, allowed fault type, severity at or above the policy
minimum, fresh dedup bucket):

- `allow-candidate`: no deviation, every gate passes
- `bad-sig`: signature does not verify -> `sig_invalid`
- `stack`: stack hash invalid -> `stack_invalid`
- `fault`: fault type not allowed -> `fault_denied`
- `sev`: severity below policy minimum -> `severity_denied`
- `dup`: dedup bucket already recorded -> `duplicate`
- `revoked`: signed with a revoked kid -> `kid_revoked`
- `trunc-stack`: stack truncated -> `stack_truncated`
- `raw-addr`: stack hashed with raw (non-ASLR-normalized) addresses -> `raw_addr`

Any other marker denies with `marker_unknown`.

## Interacting gates

Gates are evaluated in this order and every failing gate contributes its
reason code:

1. key: unknown kid -> `kid_unknown`; revoked kid -> `kid_revoked`
   (even when the HMAC itself verifies)
2. signature: recomputed HMAC mismatch -> `sig_invalid`
3. stack: 栈帧地址剥离 ASLR 后哈希 — malformed stack -> `stack_invalid`;
   truncated stack -> `stack_truncated`; raw (non-normalized) addresses
   -> `raw_addr`
4. fault 类型门禁: fault type outside `policy.allowed_faults`
   (default `SEGV, ABRT, ILL, FPE, BUS, TRAP`) -> `fault_denied`
5. severity 不得低于策略: severity below `policy.min_severity`
   (default `low`; levels `low < medium < high < critical`)
   -> `severity_denied`
6. 去重 store: the dedup bucket (`id`, falling back to the body digest)
   is already recorded in the store -> `duplicate`; only an allow writes
   the bucket, a deny never mutates the store

The decision is `allow` only when no gate fails; `reason_codes` is then
`[]`.

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-segv, ok-abrt

Deny cases: bad-sig, stack, fault, sev, dup, revoked, trunc-stack, raw-addr

Reason codes should be stable snake_case identifiers matching the failing gate.
