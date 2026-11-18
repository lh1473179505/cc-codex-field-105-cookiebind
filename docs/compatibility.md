# Session capture notes
Fragment streams belong to the handshake epoch that created them. Migration starts
a new stream namespace; old final fragments cannot complete into the new session.
Existing diagnostics expose `(session, message)` completion keys and `(session, text)`
messages. ws-capture-1 omits partial fragments, so their original tail may be replayed.
Inspection must not consume a fragment or alter a handshake epoch.
