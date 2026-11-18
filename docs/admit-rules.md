# tokenxchg admit rules

The client policy enumerates subject and actor token types, audience, scopes and whether delegation is required. actor_type=none is valid only where delegation is disabled. delegation must be 1 exactly when required and 0 for non-delegated exchanges. scope is unique, bounded and a subset of the client list; audience must be exact.

Verify HMAC-SHA-256 over the exact signing line in the documented field order. Reject unknown/revoked keys and stale or future iat values. A nonce is consumed only after every gate allows; every deny leaves store unchanged.
