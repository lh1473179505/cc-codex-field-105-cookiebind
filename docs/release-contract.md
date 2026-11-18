# Build journal semantics

A multi-layer build is one transaction. Individual layer seals and blob
writes may be durable before the whole build commits, but an aborted
build contributes no layer after restart. Full-image import has the
same atomic boundary as incremental commit.

Journal replay is idempotent and preserves committed order. Version-one
inspection returns `schemaVersion` and `Layers`, including the capital
L, and never exposes working-copy layers. A rollback restores the exact
previous ordered list rather than filtering by content digest.
