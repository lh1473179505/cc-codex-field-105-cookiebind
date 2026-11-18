# kustomizex

Content-addressed overlay rendering with signed release epochs, a reusable render cache, rollback, and audit export.

Everything is local and uses only the Python standard library. `python repro.py`
runs the existing failure sequence without network access. The tests use
`unittest` and exercise composed release, recovery, and legacy-consumer flows.
