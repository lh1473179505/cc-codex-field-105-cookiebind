# mTLS route compatibility
In-flight sessions may outlive a peer-certificate rotation, but the first durable
wire write must observe the post-rotation trust epoch. `legacy_pairs` is consumed
by an older collector and returns `(peer, payload)` only. `mtls-1` snapshots omit
staged sessions; `accepted` therefore means durable wire success, not intent.
