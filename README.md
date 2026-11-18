# jsonnetx

Jsonnet-style import closures and multi-output publication with content snapshots, rollback, recovery, and legacy files.

Everything is local and uses only the Python standard library. `python repro.py`
runs the existing failure sequence without network access. The tests use
`unittest` and exercise composed release, recovery, and legacy-consumer flows.
