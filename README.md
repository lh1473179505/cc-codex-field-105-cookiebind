# nixstore

A Nix-like content store with signed path registration, closure release, rollback, recovery, and legacy bundles.

Everything is local and uses only the Python standard library. `python repro.py`
runs the existing failure sequence without network access. The tests use
`unittest` and exercise composed release, recovery, and legacy-consumer flows.
