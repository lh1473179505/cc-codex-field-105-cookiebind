# tunmesh admit rules

## Signing input
`v1|{kid}|{pubkey}|{endpoint_host}|{endpoint_ip}|{allowed_ips_csv}|{keepalive}|{psk_hash}|{iat}|{nonce}`

## CIDR subset
For each allowed_ip CIDR A and peer pool P: network(A) must be subnet of P
(`ipaddress.ip_network(A).subnet_of(ipaddress.ip_network(P))`).
String prefix checks are insufficient (e.g. `10.10.0.0/24` vs `10.10.1.0/24`).

## Gates
1. HMAC + kid_revoked.
2. pubkey ∈ peers; endpoint_host endswith peers[pubkey].endpoint_suffix.
3. endpoint_ip ∈ one of endpoint_ip_cidrs.
4. every allowed_ips subnet_of peer pool; none overlaps/equals denied_cidrs (reject if A.subnet_of(D) or D.subnet_of(A) or A==D for any denied D — fixtures use A subnet of denied or exact default route).
   Practical fixture rule: reject if allowed network is contained in any denied_cidrs OR equals 0.0.0.0/0.
5. keepalive in [min,max].
6. if require_psk: psk_hash must equal psk_hashes[pubkey].
7. time + nonce allow-only.

## Compatibility
inspect echo-only; deny does not write store.

## Reason codes
Short-circuit at the first failed gate; every deny report carries exactly one code:

1. `unknown_kid`, `kid_revoked`, `bad_signature`
2. `unknown_pubkey`, `bad_endpoint_suffix`
3. `bad_endpoint_ip`
4. `default_route`, `denied_cidr`, `outside_pool`
5. `bad_keepalive`
6. `bad_psk`
7. `iat_out_of_window`, `nonce_replay`

The nonce is inserted into `store.items` only when the final decision is allow.
Default-route entries inside `denied_cidrs` (prefix length 0) only match an
allowed network that is itself a default route; non-default denied CIDRs use the
symmetric overlap test (equal, `subnet_of` in either direction).
