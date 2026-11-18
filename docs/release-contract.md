# Target publication continuity

Target aliases and the generation counter become visible together at
seal time. A staged or aborted target must not be returned by the old
client, even if its content blob is already present. Snapshot import
follows the same rule as an incremental batch.

Version-one listings remain sorted path strings, and target paths are
not normalized into different delegation identities. Recovery can
finish a sealed generation or discard a staged one; it cannot expose a
mixture of generations.
