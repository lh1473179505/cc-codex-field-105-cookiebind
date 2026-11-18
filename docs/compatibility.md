# Trigger replay notes
Watermarks are scoped by channel. A close record commits the channel's complete
prefix, including late records; unrelated channels stay independent. Reports keep
`(channel, sequence, payload)` rows. trigger-1 snapshots intentionally omit pending
records and can only be safely combined with a replay tail containing that prefix.
