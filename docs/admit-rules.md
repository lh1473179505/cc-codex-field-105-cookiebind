# nfsexport admit rules

export_path is an absolute canonical slash-separated path and an exact key in exports. Empty components, repeated slashes, backslashes, NUL and `.`/`..` components are invalid; a dangerous path is not made valid by normalization. The selected export supplies every remaining business rule.

root_squash and anon_uid/anon_gid must exactly equal the export values. client_cidr is parsed with `ipaddress.ip_network(strict=True)`, must have no host bits, must be a subnet of a configured client_supernets network, and cannot be a default route when forbidden. permissions is a unique ordered string list, a subset of permissions_allowed and a superset of permissions_required.

The complete ordered field sequence is signed; permissions are comma-joined without reordering. HMAC/key status, iat window and replay checks are independent gates. Only an allow may consume nonce or save store.
