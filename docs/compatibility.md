# Spool interoperability
Existing transactions can outlive an ACL refresh, but revocation must be observed
before their first durable append. `delivery_view` is used by a legacy consumer
and returns rows as `(epoch, payload)` pairs. `spool-1` snapshots contain no staged
transactions; recovery therefore relies on `done` describing durable writes only.
