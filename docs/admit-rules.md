# ciliumnet admit rules

## Signing
`v1|{kid}|{endpoint}|{direction}|{cidr}|{port}|{proto}|{iat}|{nonce}`

Use ipaddress: cidr must be subnet_of one of direction cidrs (egress_cidrs/ingress_cidrs). Reject if cidr subnet_of any denied_cidrs or equals default route. port/proto allowlists; HMAC+revoke; time; nonce allow-only.
