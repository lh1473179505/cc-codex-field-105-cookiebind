# SPIFFE wire compatibility
A batch may be staged under one trust bundle generation, but the first channel
delivery after a trust-domain migration must refuse packets whose SPIFFE IDs are
outside the new bundle. `audit_rows` keeps a `domain` field derived from the
SPIFFE ID host segment for a legacy SIEM. `spiffe-1` journals do not store open
batches; `done` is durable delivery only.
