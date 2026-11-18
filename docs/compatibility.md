# ICE integration
SDP restart opens a new candidate generation. Candidates gathered earlier may remain
in a remote peer's retry tail but must not become routes in the restarted session.
The route diagnostic retains `(generation, address)` pairs. ice-journal-1 records
attempted keys for support tickets; `applied` in a session snapshot means connected
routes, not merely attempted connections. A mixed-generation batch has no atomic
transport operation, so successful current-generation routes must survive a peer error.
