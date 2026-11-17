# syslogtls admit rules

receiver selects the complete TLS syslog policy. peer_cn must be an exact key in identities and peer_spiffe must be an exact member of the URI list beneath that same CN. Merely presenting another valid identity from the receiver does not satisfy the CN/SPIFFE binding.

facility, severity and message_length are JSON integers, not numeric strings or booleans. facility and severity are exact members of their receiver lists. app is an exact case-sensitive member of apps. message_length lies within the receiver's inclusive minimum and maximum.

The signed representation covers the peer identity pair, numeric values and every other field in the declared order. HMAC key status, iat freshness/skew and replay checks remain separate gates. nonce and store are changed only for allow.
