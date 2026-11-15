# helmrel admit rules

## Signing input
`v1|{kid}|{release}|{chart}|{version}|{ns}|{values_sha256}|{kube}|{iat}|{nonce}`

## Chart bind
chart ∈ charts; version ∈ charts[chart].versions; ns ∈ charts[chart].ns ∩ allowed_ns;
kube must be semver >= charts[chart].kube_min (compare major.minor.patch tuples).
values_sha256 length; release lowercase DNS-1123; HMAC+revoke; time; nonce allow-only.
