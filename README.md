# ocilayout

An OCI image layout with content blobs, staged multi-platform index updates, rollback, and legacy descriptors.

Everything is local and uses only the Python standard library. `python repro.py`
runs the existing failure sequence without network access. The tests use
`unittest` and exercise composed release, recovery, and legacy-consumer flows.
