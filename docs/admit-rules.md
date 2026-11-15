# nomadjob admit rules

## Signing input
`v1|{kid}|{job}|{driver}|{network}|{volume}|{image}|{iat}|{nonce}`

## Bind
job ∈ jobs; driver/network ∈ job tables; volume startswith volume_prefixes and reject deny substrings;
image startswith image_prefixes; if network ∈ forbid_privileged_network_for[job] => deny;
HMAC+revoke; time; nonce allow-only.
