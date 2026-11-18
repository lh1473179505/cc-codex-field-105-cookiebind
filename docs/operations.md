# Operational recovery notes

semgrepr accepts snapshot and incremental operations through its application API
and through JSON batch documents. Recovery can follow more than one revoke.
Workers may retransmit completed delta batches, so duplicate and out-of-order
delivery are normal rather than exceptional.

Diagnostics may run before, between, or after writer operations. A diagnostic
run must not make a subsequent retry newer, and a successful cache lookup must
not make an absent authoritative object visible. The combination fixture
covers baseline -> delta -> revocations -> recovery -> late retransmission.
