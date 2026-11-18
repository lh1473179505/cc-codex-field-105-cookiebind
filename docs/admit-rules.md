# webrtcic admit rules

session_id selects the complete ICE/DTLS session. ufrag is an exact session string within the global length bounds. dtls_fingerprint is exactly 32 colon-separated uppercase hexadecimal bytes and equals one configured SHA-256 fingerprint for that session; case normalization and cross-session fingerprints are invalid.

candidate is an object with exactly foundation, component, transport, priority, address, port and type. Numeric fields are JSON integers, transport equals protocol, and protocol belongs to the session protocols. candidate.type selects address_cidrs and ports beneath that session: address is parsed by `ipaddress.ip_address` and contained in the type's network, while port is an exact allowed integer. A server-reflexive address cannot be used for a host candidate.

All candidate keys are rendered deterministically and signed together with ufrag, fingerprint and protocol. HMAC key status, 600-second iat age, 60-second future skew and nonce freshness are mandatory. Only an allow consumes nonce or saves store.
