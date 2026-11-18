# Resume compatibility
Last-Event-ID progress means a successfully written contiguous prefix, not the highest
attempted sequence. Authorization is evaluated for each subscription attempt; a
revoked token cannot use a replay to extend an old stream. sse-resume-1 snapshots are
shared by recovery workers and retain both fields. Audit rows stay `(event_id, data)`
pairs, and taking an audit snapshot must not flush the buffer.
