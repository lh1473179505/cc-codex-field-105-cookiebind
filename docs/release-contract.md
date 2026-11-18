# Store closure durability

A valid registration and its content path form one durable unit.
Rollback may remove uncommitted content only after removing its
registration; recovery cannot mark a path valid merely because a row
exists. Closure import follows the same publication boundary.

Legacy bundles retain `format: 1`, sorted entries, `/nix/store/` path
prefixes, and `sha256` digest fields. A failed generation cannot appear
in that bundle. Replaying an aborted generation must be idempotent and
must not delete a content-identical path owned by an older generation.
