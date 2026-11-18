# tufrole

TUF-style role rotation with epoch-pinned transactions, signed envelopes, snapshots, and recovery.

Everything is local and uses only the Python standard library. `python repro.py`
runs the existing failure sequence without network access. The tests use
`unittest` and exercise composed release, recovery, and legacy-consumer flows.
