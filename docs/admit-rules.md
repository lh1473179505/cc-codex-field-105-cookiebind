# buildahx admit rules

Select `builds[build]` and treat it as the sole source of all remaining gates. `context` is an absolute canonical path exactly equal to the build's registered directory, with none of `context_deny_substrings` and no `.`/`..` components. A sibling build context or a path made safe only by cleaning is invalid.

`base_image` must exactly equal the build's digest-pinned reference, including registry, repository, algorithm and lowercase digest. A mutable tag is never equivalent. `args` is an object whose complete key/value mapping exactly equals the registered args; extra proxy settings, missing values and host-environment substitutions are denied.

`secret` is an object with exactly `secret_keys` and exact registered `id`, absolute `path` and integer `mode`. Do not accept a different path or looser mode for a valid secret ID. `isolation` exactly equals the build's configured backend; do not substitute another isolation mode based on local availability.

Serialize args and secret with sorted keys in the complete signing line. Require active-key HMAC, iat freshness/skew and unused nonce, with nonce/store written only on allow. A denied build has no state-changing side effect.
