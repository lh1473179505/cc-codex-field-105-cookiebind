# Snapshot and delta convergence

A full snapshot describes the complete current set for its generation, not an
additional batch to union with historical output. A record explicitly present
in a newer snapshot is restored; an absent record gains no new lease from an
old cache entry. Revocation and restoration therefore apply to identities, not
to display rows.

A committed snapshot establishes the lower bound for later incremental sequence numbers. A late retransmission must not overwrite a newer recovery. A fingerprint accelerates equivalent work but does not define membership in the authoritative result set.

The state machine distinguishes the initial baseline, active deltas, revoked
state and recovery. Journal append, visibility changes and progress updates are
one logical commit even though this offline implementation stores them in
memory. Readers never advance these transitions.
