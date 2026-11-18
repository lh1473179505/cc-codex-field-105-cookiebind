# tuftarget

Content-addressed target delegation with staged target aliases and full-snapshot import.

Everything is local and uses only the Python standard library. `python repro.py`
runs the existing failure sequence without network access. The tests use
`unittest` and exercise composed release, recovery, and legacy-consumer flows.
