# Destination continuity

Push sequence numbers are monotonic integers and define recovery order.
Transaction identifiers are opaque; their spelling carries no ordering
semantics. Aborted packs are retained for diagnostics but cannot move a
destination. Rebuilding a context uses the same destination sequence as
a normal push.

The legacy resolver returns `dir://sha256:<digest>` and snapshot keys
remain sorted tag names. After recovery, a destination must resolve to
the highest committed sequence, never the highest lexical transaction
string or an aborted candidate.
