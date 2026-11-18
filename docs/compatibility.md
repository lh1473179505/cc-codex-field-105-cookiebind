# Byte stream migration
A stream's delivered offset describes bytes successfully handed to the peer, while
flow credit describes received byte extent; they are intentionally different facts.
conn-1 snapshots omit out-of-order fragments, so the sender may retransmit them.
Duplicate packets with identical offset and data are harmless. Peer writes preserve
`(stream_id, bytes)` rows and are not rolled back by connection migration.
