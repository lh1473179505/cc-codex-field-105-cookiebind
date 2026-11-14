# canarytok

Offline canary-token admission tool. `inspect` summarizes an input object;
`admit` enforces the gates in `docs/admit-rules.md` (signature, channel
allowlist, env binding, token dedup, time window, key revocation) and emits
a report per `docs/report-schema.md`. Standard library only.
