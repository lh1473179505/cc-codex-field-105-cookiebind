# grpcmeta admit rules

## Signing input
`v1|{kid}|{authority}|{method}|{deadline_ms}|{peer_cn}|{iat}|{nonce}`

## Method safety
Reject if method contains deny substrings (`..`,`//`,`Admin`). Then require method_allow_prefixes.

## CN bind
peer_cn must endswith one of peer_cn_suffixes AND endswith authority_cn_bind[authority].

## Gates
authority allowlist; deadline range; HMAC+revoke; time; nonce allow-only.
