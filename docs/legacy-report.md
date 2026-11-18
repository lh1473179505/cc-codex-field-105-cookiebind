# Existing report and audit consumers

The `scan-v1` object retains `schema`, `phase`, `generation`, `items` and
`revoked`. Each item retains `id`, `scope`, `fingerprint`, `value`,
`generation` and `sequence`; consumers rely on stable identity sorting and on
`value` remaining the current domain value rather than a presentation mask.

Report and audit calls are observational. They do not append journal entries,
change the public state token, consume a pending delta, or alter later report
output. The audit envelope additionally exposes an immutable copy of operation
history. Cache warmup is permitted only when it cannot change any observed
result or public state.
