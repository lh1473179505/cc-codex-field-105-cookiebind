# rediscmd admit rules

## Signing input
`v1|{kid}|{cmd}|{key}|{channel}|{arity}|{iat}|{nonce}`

## Key safety
Reject key containing deny substrings. Then require key_allow_prefixes.

## Gates
cmd allowlist; arity must equal cmd_arity[cmd];
if publish_requires_channel and cmd==PUBLISH: channel non-empty and startswith channel_allow_prefixes;
HMAC+revoke; time; nonce allow-only.
